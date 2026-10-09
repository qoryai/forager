package proxy

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qoryai/forager/link"
)

// The bounds of a secret a [Listener] serves a run by: at least 128 bits written out
// in base64, at most what fits a preamble the listener reads.
const (
	minSecret = 22
	maxSecret = 256
)

// RefusedRelay is the listener's report of a connection it refused: one that did not
// open with the preamble in time, opened with one longer than any secret, or named a
// secret no live run holds. It is today's session's text, and names nothing the
// connection sent.
const RefusedRelay = "a connection to the proxy that was not the run's relay was refused"

// errSecret refuses a secret [Listener.Register] cannot serve a run by. It never names
// the secret.
var errSecret = errors.New("a run's proxy secret is at least 22 and at most 256 printable characters, with no space")

// NewSecret makes a run's proxy secret: 32 bytes from crypto/rand, base64url without
// padding.
func NewSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Listener is one listener that serves many runs: every connection opens with
// [link.RelayPreamble], a space, the run's secret and a newline, and is handed, after
// that line, to the [Proxy] registered under the secret. A connection that sends no
// such line in time, or names a secret no live run holds, is closed unanswered, and
// report hears of it without the secret.
type Listener struct {
	ln     net.Listener
	report func(string)
	// wait is how long a connection has to send its preamble.
	wait atomic.Int64

	mu   sync.RWMutex
	runs map[[sha256.Size]byte]*registered
	// pending are the connections whose preamble is still being read, closed by Close.
	pending map[net.Conn]struct{}
	closed  bool
	wg      sync.WaitGroup
}

// registered is a run the listener serves: its secret, compared in full in constant
// time, and its proxy.
type registered struct {
	secret []byte
	p      *Proxy
}

// NewListener listens on addr, host:port; an empty addr is [link.Loopback]. report,
// when set, hears of every connection refused. Close stops it.
func NewListener(addr string, report func(string)) (*Listener, error) {
	if addr == "" {
		addr = link.Loopback
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &Listener{ln: ln, report: report, runs: map[[sha256.Size]byte]*registered{}, pending: map[net.Conn]struct{}{}}
	l.wait.Store(int64(preambleWait))
	l.wg.Add(1)
	go l.accept()
	return l, nil
}

// Addr is the address the listener listens on, host:port.
func (l *Listener) Addr() string { return l.ln.Addr().String() }

// Register serves the connections that open with secret by p, a proxy [New] made. It
// refuses a secret out of bounds, one a live run holds already, and a closed listener.
func (l *Listener) Register(secret string, p *Proxy) error {
	if !validSecret(secret) {
		return errSecret
	}
	if p == nil || p.in == nil {
		return errors.New("a run's proxy on a shared listener is one proxy.New made")
	}
	key := sha256.Sum256([]byte(secret))
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return net.ErrClosed
	}
	if _, ok := l.runs[key]; ok {
		return errors.New("the secret is a live run's already")
	}
	l.runs[key] = &registered{secret: []byte(secret), p: p}
	return nil
}

// Unregister refuses secret from now on. The connections its run has open are the
// run's proxy's: [Proxy.Close] ends them as it does for a proxy with its own listener.
func (l *Listener) Unregister(secret string) {
	key := sha256.Sum256([]byte(secret))
	l.mu.Lock()
	defer l.mu.Unlock()
	if r, ok := l.runs[key]; ok && subtle.ConstantTimeCompare(r.secret, []byte(secret)) == 1 {
		delete(l.runs, key)
	}
}

// Close stops the listener and closes every connection whose preamble it is still
// reading. The registered proxies are their runs' to close.
func (l *Listener) Close() error {
	l.mu.Lock()
	l.closed = true
	for c := range l.pending {
		c.Close()
	}
	l.mu.Unlock()
	err := l.ln.Close()
	l.wg.Wait()
	return err
}

// Serve reads the preamble of a connection another listener accepted, the gateway's one
// address, and hands c to the run it names, or closes it, as for a connection of the
// listener's own. With guardedOnly, a secret whose run's proxy is not guarded
// ([Proxy.Guarded]) names no run: a connection from another machine never reaches a
// proxy that may dial this one's own addresses. Close closes c while its preamble is
// read.
func (l *Listener) Serve(c net.Conn, guardedOnly bool) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		c.Close()
		return
	}
	l.pending[c] = struct{}{}
	l.wg.Add(1)
	l.mu.Unlock()
	go l.dispatch(c, guardedOnly)
}

// Lookup is the proxy of the live run whose secret is secret, or nil: the secret's
// digest picks the one candidate, and the secret itself is compared in full in constant
// time. With guardedOnly, a run whose proxy is not guarded is none. It never logs or
// reports the secret.
func (l *Listener) Lookup(secret string, guardedOnly bool) *Proxy {
	return l.find([]byte(secret), guardedOnly)
}

// find is the proxy registered under secret, or nil.
func (l *Listener) find(secret []byte, guardedOnly bool) *Proxy {
	key := sha256.Sum256(secret)
	l.mu.RLock()
	reg, ok := l.runs[key]
	l.mu.RUnlock()
	if !ok || subtle.ConstantTimeCompare(reg.secret, secret) != 1 {
		return nil
	}
	if guardedOnly && !reg.p.Guarded() {
		return nil
	}
	return reg.p
}

// accept hands every connection to its own goroutine, so a peer that sends nothing
// holds up no one else.
func (l *Listener) accept() {
	defer l.wg.Done()
	var backoff time.Duration
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// What http.Server does for a failed accept, such as one out of descriptors.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			c.Close()
			return
		}
		l.pending[c] = struct{}{}
		l.wg.Add(1)
		l.mu.Unlock()
		go l.dispatch(c, false)
	}
}

// dispatch reads c's preamble and hands c to the run it names, or closes it.
func (l *Listener) dispatch(c net.Conn, guardedOnly bool) {
	defer l.wg.Done()
	p, r, why := l.open(c, guardedOnly)
	l.mu.Lock()
	delete(l.pending, c)
	l.mu.Unlock()
	if p == nil {
		c.Close()
		if l.report != nil {
			l.report(why)
		}
		return
	}
	p.in.deliver(&relayed{Conn: c, r: r})
}

// open reads the preamble within the listener's wait, and finds the run whose secret
// it names: the secret's digest picks the one candidate, and the secret itself is
// compared in full in constant time. It reads nothing past the newline but into r.
func (l *Listener) open(c net.Conn, guardedOnly bool) (*Proxy, *bufio.Reader, string) {
	c.SetReadDeadline(time.Now().Add(time.Duration(l.wait.Load())))
	defer c.SetReadDeadline(time.Time{})
	want := link.RelayPreamble + " "
	r := bufio.NewReaderSize(c, 512)
	line := make([]byte, 0, len(want)+maxSecret+1)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, nil, RefusedRelay
		}
		if b == '\n' {
			break
		}
		if len(line) == cap(line)-1 {
			return nil, nil, RefusedRelay
		}
		line = append(line, b)
	}
	if len(line) < len(want) || string(line[:len(want)]) != want {
		return nil, nil, RefusedRelay
	}
	p := l.find(line[len(want):], guardedOnly)
	if p == nil {
		return nil, nil, RefusedRelay
	}
	return p, r, ""
}

// validSecret reports whether s is within the bounds a listener reads: printable
// ASCII without space, of a length between minSecret and maxSecret.
func validSecret(s string) bool {
	if len(s) < minSecret || len(s) > maxSecret {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// relayed is a connection past its preamble: what the listener read beyond the line
// is read first. It hides CloseWrite, as today's gate does: a tunnel through it is
// never half-closed.
type relayed struct {
	net.Conn
	r *bufio.Reader
}

func (c *relayed) Read(b []byte) (int, error) { return c.r.Read(b) }

// inbox is the listener of a proxy [New] made: the connections a [Listener] hands it.
type inbox struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newInbox() *inbox {
	return &inbox{conns: make(chan net.Conn), done: make(chan struct{})}
}

// deliver hands c to the proxy, or closes it once the proxy is closed.
func (b *inbox) deliver(c net.Conn) {
	select {
	case b.conns <- c:
	case <-b.done:
		c.Close()
	}
}

// Accept is the next connection handed over.
func (b *inbox) Accept() (net.Conn, error) {
	select {
	case c := <-b.conns:
		select {
		case <-b.done:
			c.Close()
			return nil, net.ErrClosed
		default:
			return c, nil
		}
	case <-b.done:
		return nil, net.ErrClosed
	}
}

// Close stops Accept; a connection handed over from then on is closed.
func (b *inbox) Close() error {
	b.once.Do(func() { close(b.done) })
	return nil
}

// Addr is the inbox's own: it has no address on the network.
func (b *inbox) Addr() net.Addr { return inboxAddr{} }

// inboxAddr is the inbox's address, which names no place on the network.
type inboxAddr struct{}

// Network is the inbox's kind, "proxy".
func (inboxAddr) Network() string { return "proxy" }
func (inboxAddr) String() string  { return "shared" }
