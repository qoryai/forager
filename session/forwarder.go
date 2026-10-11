package session

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qoryai/forager/link"
)

// dialWait is how long the forwarder has to reach the gateway's proxy for one
// connection.
const dialWait = 10 * time.Second

// forwarder is the run's own listener on this machine: every connection it accepts it
// copies, byte for byte, to the gateway's proxy. Without a wall it opens each with the
// relay's preamble and the run's proxy secret first; behind a wall the wall's relay
// writes the preamble itself, and the forwarder passes on what arrives as it is.
// Without a wall, on one machine as behind a separate gateway, the first request of
// every connection must carry the password of the agent's proxy URL, a secret the
// session made for this run's forwarder alone, which the forwarder takes off; the
// connection carries that one request, so the password of every request is checked
// before the request is passed on.
//
// Behind a separate gateway it reaches the gateway's one address over TLS, each
// connection bound to a key the run key names and opened with the relay's preamble and
// the run key, which the link's proxy dial writes: behind a wall, every connection must
// first open with the relay's preamble and the hop secret the session gave the wall's
// relay, which the forwarder takes off.
//
// The secrets are held in memory alone: never in a file or a report, and in an
// environment only as that password, in the unwalled agent's proxy URL.
type forwarder struct {
	ln  net.Listener
	way forwarding
	// ctx ends when the forwarder is closed, so a dial to the proxy in flight ends
	// with it.
	ctx  context.Context
	stop context.CancelFunc

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	// waiting are the accepted connections yet to show the hop or the password, the
	// one that has waited longest first; at most [maxWaiting].
	waiting []net.Conn
	closed  bool
	wg      sync.WaitGroup
}

// maxWaiting is the most connections a forwarder holds at once that are yet to show
// the hop or the password; one more closes the one that has waited longest.
const maxWaiting = 128

// forwarding is where a forwarder sends what it accepts, and with which secrets.
type forwarding struct {
	// dial opens one connection to the gateway's proxy: behind a separate gateway, bound
	// and opened with the run key.
	dial func(context.Context) (net.Conn, error)
	// secret, when set, is written in the relay's preamble at the start of every
	// connection to the proxy.
	secret string
	// hop, when set, is the secret every accepted connection must open with, in the
	// relay's preamble, before anything reaches the proxy; the preamble is not passed
	// on.
	hop string
	// password, when set, is the password of the proxy URL [forwarder.Env] gives, which
	// the first request of every accepted connection must carry in its one
	// Proxy-Authorization, Basic, before anything reaches the proxy; the header is not
	// passed on. A connection then carries that one request: a CONNECT and its tunnel,
	// or one plain request and its reply, so every plain request is checked; a plain
	// request that asks for an upgrade the proxy answers with 101 makes it a tunnel.
	password string
	// headWait is how long a connection has to send its first request's head when the
	// password is set; zero is [link.PreambleWait], as long as a preamble has.
	headWait time.Duration
}

// listenForwarder listens on addr, host:port, and forwards to target, the gateway's
// proxy address on this machine. A non-empty secret is written in the relay's preamble
// at the start of every connection, and a non-empty password is what the first request
// of every accepted connection must carry.
func listenForwarder(addr, target, secret, password string) (*forwarder, error) {
	var d net.Dialer
	return listenForwarding(addr, forwarding{
		dial:     func(ctx context.Context) (net.Conn, error) { return d.DialContext(ctx, "tcp", target) },
		secret:   secret,
		password: password,
	})
}

// listenForwarding listens on addr, host:port, and forwards each connection the way
// says.
func listenForwarding(addr string, way forwarding) (*forwarder, error) {
	for _, s := range []string{way.secret, way.hop, way.password} {
		if s == "" {
			continue
		}
		if err := link.CheckSecret(s); err != nil {
			return nil, fmt.Errorf("the gateway's proxy secret: %w", err)
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	f := &forwarder{ln: ln, way: way, conns: map[net.Conn]struct{}{}}
	f.ctx, f.stop = context.WithCancel(context.Background())
	f.wg.Add(1)
	go f.accept()
	return f, nil
}

// Addr is the address the forwarder listens on, host:port with the port it got.
func (f *forwarder) Addr() string { return f.ln.Addr().String() }

// Env is the variables that point a program at the forwarder: its address, and the
// password of the proxy URL when it has one.
func (f *forwarder) Env() []string {
	u := url.URL{Scheme: "http", Host: f.Addr()}
	if f.way.password != "" {
		// The user name is ignored; the password is the forwarder's own.
		u.User = url.UserPassword(proxyUser, f.way.password)
	}
	return link.ProxyEnv(u.String())
}

// proxyUser is the user name of an unwalled agent's proxy URL, which the forwarder
// ignores.
const proxyUser = "qory"

// newForwarderSecret makes a secret of this run's forwarder alone: 32 bytes from
// crypto/rand, base64url without padding. Behind a wall and a separate gateway it is the
// hop secret the wall's relay opens every connection with, so the run key is in no file
// of the wall's; without a wall it is the password of the agent's proxy URL, so no other
// process of the machine reaches the gateway through the forwarder.
func newForwarderSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func (f *forwarder) accept() {
	defer f.wg.Done()
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		if !f.track(c) {
			c.Close()
			return
		}
		if f.way.hop != "" || f.way.password != "" {
			f.await(c)
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer f.untrack(c)
			f.serve(c)
		}()
	}
}

// track lists a connection, so Close ends it; false once the forwarder is closed.
func (f *forwarder) track(c net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.conns[c] = struct{}{}
	return true
}

// untrack takes a connection off the list, and off the waiting list, and closes it.
func (f *forwarder) untrack(c net.Conn) {
	f.mu.Lock()
	delete(f.conns, c)
	f.admitLocked(c)
	f.mu.Unlock()
	c.Close()
}

// await lists c as yet to show the hop or the password, closing the connection that has
// waited longest when [maxWaiting] already wait.
func (f *forwarder) await(c net.Conn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.waiting) == maxWaiting {
		f.waiting[0].Close()
		f.waiting = slices.Delete(f.waiting, 0, 1)
	}
	f.waiting = append(f.waiting, c)
}

// admit takes c off the waiting list, once it has shown the hop or the password, and
// reports whether it was on it: false once a newer connection has closed it.
func (f *forwarder) admit(c net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.admitLocked(c)
}

func (f *forwarder) admitLocked(c net.Conn) bool {
	i := slices.Index(f.waiting, c)
	if i >= 0 {
		f.waiting = slices.Delete(f.waiting, i, i+1)
	}
	return i >= 0
}

// serve copies one connection to the proxy and back, each direction until its end,
// which it passes on as a half close.
func (f *forwarder) serve(c net.Conn) {
	if f.way.hop != "" {
		// Nothing reaches the proxy from a connection that is not the run's relay.
		c.SetReadDeadline(time.Now().Add(link.PreambleWait))
		if ok, err := link.ReadRelayPreamble(c, f.way.hop); !ok || err != nil {
			return
		}
		c.SetReadDeadline(time.Time{})
		if f.way.password == "" && !f.admit(c) {
			return
		}
	}
	var src io.Reader = c
	// plain is the one plain request of a connection the password let in.
	var plain *proxied
	if f.way.password != "" {
		// Nothing reaches the proxy from a connection that is not the run's agent.
		wait := f.way.headWait
		if wait == 0 {
			wait = link.PreambleWait
		}
		c.SetReadDeadline(time.Now().Add(wait))
		head, rest, ok := readProxyLogin(c, f.way.password)
		if !ok {
			return
		}
		c.SetReadDeadline(time.Time{})
		if !f.admit(c) {
			return
		}
		if err := checkRequestLine(head); err != nil {
			// A request line the check refuses gets a 400 here, and nothing of it
			// reaches the proxy.
			badRequest(c, err)
			return
		}
		if connectHead(head) {
			// The tunnel goes on as it is; a proxy that refuses it closes the connection
			// rather than reading a second request.
			src = io.MultiReader(bytes.NewReader(closingHead(head)), rest)
		} else if plain = plainRequest(head, rest); plain == nil {
			return
		}
	}
	ctx, cancel := context.WithTimeout(f.ctx, dialWait)
	up, err := f.way.dial(ctx)
	cancel()
	if err != nil {
		return
	}
	if !f.track(up) {
		up.Close()
		return
	}
	defer f.untrack(up)
	if f.way.secret != "" {
		up.SetWriteDeadline(time.Now().Add(link.PreambleWait))
		if _, err := io.WriteString(up, link.RelayLine(f.way.secret)); err != nil {
			return
		}
		up.SetWriteDeadline(time.Time{})
	}
	if plain != nil {
		passPlain(c, up, plain)
		return
	}
	pipe(c, up, src, up, f.way.password != "")
}

// pipe copies fromAgent to up and fromProxy, what up sends, to c, each direction until
// its end, which it passes on as a half close. With closeUp, the end of what up sends
// closes up before it is passed on, so nothing the agent sends after it reaches the
// proxy: after a refused CONNECT, say, a request with the password in it.
func pipe(c, up net.Conn, fromAgent, fromProxy io.Reader, closeUp bool) {
	done := make(chan struct{}, 2)
	half := func(dst net.Conn) {
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go func() {
		io.Copy(up, fromAgent)
		half(up)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(c, fromProxy)
		if closeUp {
			up.Close()
		}
		half(c)
		done <- struct{}{}
	}()
	<-done
	<-done
}

// passPlain writes p, the one plain request of the agent's connection c, to up, the
// proxy, and passes on its reply until the proxy ends it; nothing more of the agent's
// goes on, so a request after it on the connection, with the password in its
// Proxy-Authorization, never reaches the proxy. The proxy's side is not half closed,
// which would end the request at a proxy that reads on; an agent that goes away, or
// ends its side, while the reply is awaited closes it instead. A request that asks for
// an upgrade the proxy answers with 101 makes the connection a tunnel; an agent that
// sends anything after it, or ends its side, before the proxy's reply is read gets no
// reply: the connection closes, as it does when the reply's head runs past
// [maxReplyHead] bytes.
func passPlain(c, up net.Conn, p *proxied) {
	if p.upgrade {
		if err := p.req.WriteProxy(up); err != nil {
			return
		}
		// WriteProxy has read the request's body: whatever the agent sends now is early.
		stop := watchAgent(c, p.from, up, false)
		head := &io.LimitedReader{R: up, N: maxReplyHead}
		r := bufio.NewReader(head)
		resp, err := http.ReadResponse(r, p.req)
		if early := stop(); early || err != nil {
			return
		}
		// The bound is the head's alone: the tunnel, or the reply's body, has none.
		head.N = math.MaxInt64
		if resp.StatusCode == http.StatusSwitchingProtocols {
			if err := writeResponseHead(c, resp); err != nil {
				return
			}
			pipe(c, up, p.from, r, true)
			return
		}
		// Any other answer is the request's alone, and the connection ends with it.
		resp.Close = true
		resp.Header.Del("Connection")
		resp.Header.Del("Keep-Alive")
		stop = watchAgent(c, p.from, up, true)
		resp.Write(c)
		stop()
		return
	}
	replied := make(chan struct{})
	go func() {
		io.Copy(c, up)
		close(replied)
	}()
	if err := p.req.WriteProxy(up); err != nil {
		up.Close()
		<-replied
		return
	}
	stop := watchAgent(c, p.from, up, true)
	<-replied
	stop()
}

// watchAgent closes up when the agent's connection c, read through from, ends or fails,
// until stop is called. With discard, what the agent sends meanwhile is read and
// dropped; without it, the first byte the agent sends closes up as the end does. stop
// reports whether the watch closed up, or, without discard, whether from holds a byte
// of the agent's.
func watchAgent(c net.Conn, from *bufio.Reader, up net.Conn, discard bool) (stop func() bool) {
	var stopped, closed atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := from.Peek(1); err != nil || !discard {
				if !stopped.Load() {
					up.Close()
					closed.Store(true)
				}
				return
			}
			from.Discard(from.Buffered())
		}
	}()
	return func() bool {
		stopped.Store(true)
		c.SetReadDeadline(time.Now())
		<-done
		c.SetReadDeadline(time.Time{})
		return closed.Load() || !discard && from.Buffered() > 0
	}
}

// writeResponseHead writes the status line and the header of resp to w.
func writeResponseHead(w io.Writer, resp *http.Response) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/%d.%d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status)
	resp.Header.Write(&b)
	b.WriteString("\r\n")
	_, err := w.Write(b.Bytes())
	return err
}

// maxReplyHead is the most bytes of the proxy's reply to an upgrade the forwarder reads
// for the reply's head.
const maxReplyHead = 64 << 10

// maxProxyLine is the longest line of the first request's head the forwarder reads,
// maxProxyLines the most lines, and maxProxyHead the most bytes of the whole head.
const (
	maxProxyLine  = 8 << 10
	maxProxyLines = 100
	maxProxyHead  = 16 << 10
)

// readProxyLogin reads the head of the first request of a connection, up to its empty
// line, and reports whether it carries exactly one Proxy-Authorization, Basic, whose
// password is password, compared in constant time; the user name is ignored. It
// returns the head without that header, and the reader that holds what follows it. A
// head with a line longer than [maxProxyLine] bytes, more than [maxProxyLines] lines or
// more than [maxProxyHead] bytes in all is refused.
func readProxyLogin(c io.Reader, password string) (head []byte, rest *bufio.Reader, ok bool) {
	r := bufio.NewReaderSize(c, maxProxyLine)
	var out bytes.Buffer
	logins, size := 0, 0
	for i := 0; ; i++ {
		line, err := r.ReadSlice('\n')
		size += len(line)
		if err != nil || i == maxProxyLines || size > maxProxyHead {
			return nil, nil, false
		}
		if i > 0 {
			if l := bytes.TrimRight(line, "\r\n"); len(l) == 0 {
				out.Write(line)
				break
			} else if name, value, found := bytes.Cut(l, []byte(":")); found && strings.EqualFold(string(name), "Proxy-Authorization") {
				logins++
				if !proxyLogin(string(bytes.TrimSpace(value)), password) {
					return nil, nil, false
				}
				continue
			}
		}
		out.Write(line)
	}
	if logins != 1 {
		return nil, nil, false
	}
	return out.Bytes(), r, true
}

// The texts of the forwarder's 400 to a request line it refuses. The origin-form and
// CONNECT texts are the gateway's proxy's own.
var (
	errAbsoluteForm  = errors.New("the proxy takes an absolute-form request target")
	errConnectTarget = errors.New("CONNECT takes host:port")
	errVersion       = errors.New("the proxy takes HTTP/1.0 or HTTP/1.1")
)

// checkRequestLine checks the request line of head, a request's head: a method, a
// target and HTTP/1.0 or HTTP/1.1, each after a single space; for a CONNECT, a target
// of host:port, its port from 1 to 65535, with no path, user or query ('/', '@', '?'
// or '#'); for any other method, a CONNECT in other case among them, an absolute-form
// target, with a scheme and a host. Its error is the text of the forwarder's 400.
func checkRequestLine(head []byte) error {
	line, _, _ := bytes.Cut(head, []byte("\n"))
	method, rest, ok1 := strings.Cut(string(bytes.TrimSuffix(line, []byte("\r"))), " ")
	target, version, ok2 := strings.Cut(rest, " ")
	if !ok1 || !ok2 || version != "HTTP/1.0" && version != "HTTP/1.1" {
		return errVersion
	}
	if method == http.MethodConnect {
		_, portText, err := net.SplitHostPort(target)
		port, perr := strconv.Atoi(portText)
		if err != nil || perr != nil || port < 1 || port > 65535 || strings.ContainsAny(target, "/@?#") {
			return errConnectTarget
		}
		return nil
	}
	if u, err := url.ParseRequestURI(target); err != nil || u.Scheme == "" || u.Host == "" {
		return errAbsoluteForm
	}
	return nil
}

// badRequest answers the agent's connection c with a 400 whose body is err's text and
// a newline, as plain text, and Connection: close.
func badRequest(c net.Conn, err error) {
	body := err.Error() + "\n"
	c.SetWriteDeadline(time.Now().Add(link.PreambleWait))
	fmt.Fprintf(c, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: %d\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n\r\n%s", len(body), body)
}

// connectHead reports whether head, a request's head, is a CONNECT's.
func connectHead(head []byte) bool {
	return bytes.HasPrefix(head, []byte(http.MethodConnect+" "))
}

// closingHead is head, a request's head up to its empty line, with Connection: close
// before that line.
func closingHead(head []byte) []byte {
	end := len(head) - 1
	if end > 0 && head[end-1] == '\r' {
		end--
	}
	out := make([]byte, 0, len(head)+len("Connection: close\r\n"))
	out = append(out, head[:end]...)
	out = append(out, "Connection: close\r\n"...)
	return append(out, head[end:]...)
}

// proxied is the one plain request of a connection the password let in.
type proxied struct {
	req *http.Request
	// from holds what the agent sends after the request's head: its body, then whatever
	// follows.
	from *bufio.Reader
	// upgrade is whether the request asks for an upgrade: its Connection names upgrade
	// and it has an Upgrade.
	upgrade bool
}

// plainRequest reads the plain request whose head, without its Proxy-Authorization, is
// head, and whose body follows in rest, as the one request of its connection: with
// Connection: close, or Connection: Upgrade and its Upgrade when it asks for an
// upgrade, without Keep-Alive, Proxy-Connection and the other headers its Connection
// names, and with no User-Agent added where it had none. Its body is read from rest as
// it is written on. It is nil when the head is no request.
func plainRequest(head []byte, rest io.Reader) *proxied {
	from := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(head), rest), maxProxyLine)
	req, err := http.ReadRequest(from)
	if err != nil {
		return nil
	}
	var named []string
	for _, v := range req.Header.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				named = append(named, name)
			}
		}
	}
	upgrade := req.Header.Get("Upgrade") != "" && slices.ContainsFunc(named, func(n string) bool { return strings.EqualFold(n, "upgrade") })
	for _, name := range named {
		if !upgrade || !strings.EqualFold(name, "upgrade") {
			req.Header.Del(name)
		}
	}
	for _, name := range []string{"Keep-Alive", "Proxy-Connection", "Proxy-Authorization"} {
		req.Header.Del(name)
	}
	if _, ok := req.Header["User-Agent"]; !ok {
		// An empty User-Agent is written as none.
		req.Header["User-Agent"] = []string{""}
	}
	if upgrade {
		req.Header.Set("Connection", "Upgrade")
	} else {
		req.Header.Set("Connection", "close")
		req.Close = true
	}
	return &proxied{req: req, from: from, upgrade: upgrade}
}

// proxyLogin reports whether value, a Proxy-Authorization's, is Basic credentials whose
// password is password, compared in constant time.
func proxyLogin(value, password string) bool {
	scheme, cred, found := strings.Cut(value, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
	if err != nil {
		return false
	}
	_, got, found := strings.Cut(string(b), ":")
	return found && subtle.ConstantTimeCompare([]byte(got), []byte(password)) == 1
}

// Close stops listening, ends every dial in flight and every connection; it waits for
// them.
func (f *forwarder) Close() error {
	f.stop()
	f.mu.Lock()
	f.closed = true
	for c := range f.conns {
		c.Close()
	}
	f.mu.Unlock()
	err := f.ln.Close()
	f.wg.Wait()
	return err
}
