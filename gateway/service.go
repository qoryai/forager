package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// runIdentity is the run a request on the gateway's one address is for, as the
// gateway's [runAuth] decides it from the request's bearer value.
type runIdentity struct {
	// Key names the run: every request of a run opened with it carries one of the same
	// key.
	Key string
	// Expires is the latest the identity is accepted: what an ended run opened with it
	// left is kept until then.
	Expires time.Time
}

// runAuth decides the bearer value of every request of the contract on the gateway's
// one address, [Config.Listen]. The gateway hands it the value of the request's
// Authorization: Bearer, and never the header itself.
type runAuth interface {
	// authenticate returns the run the value is for, or an error that refuses it. The
	// error is never answered, logged or reported: every refusal is the same 401
	// unauthorized.
	authenticate(ctx context.Context, value string) (runIdentity, error)
}

// errUnauthorized is a bearer value the gateway refuses.
var errUnauthorized = errors.New("the gateway refused the request: unauthorized")

// refuseAll is the gateway's [runAuth] without a verifier: it refuses every bearer
// value, so nothing opens on the one address.
type refuseAll struct{}

func (refuseAll) authenticate(context.Context, string) (runIdentity, error) {
	return runIdentity{}, errUnauthorized
}

// identityKey is the key of a request's [runIdentity] in its context.
type identityKey struct{}

// identityOf is the run of the bearer value a request on the one address carried, when
// it came there.
func identityOf(ctx context.Context) (runIdentity, bool) {
	id, ok := ctx.Value(identityKey{}).(runIdentity)
	return id, ok
}

// side is the way a request of the contract reached the gateway: its local link, or
// its one address.
type side struct {
	// remote says the request came to the one address.
	remote bool
	// scheme is the one address's origin's scheme: https over TLS, http on a plain
	// loopback listener.
	scheme string
}

// localSide is the local link's.
var localSide = &side{}

// authorityPath is where in the gateway's directory its own certificate authority is
// kept.
func authorityPath(dir string) string { return filepath.Join(dir, "authority", "ca.pem") }

// checkService refuses a config whose one address cannot be served, before anything
// starts, and returns the certificate it serves, nil for none. It never reads the key's
// content into an error.
func checkService(cfg *Config) (*tls.Certificate, error) {
	if cfg.Listen == "" {
		if cfg.TLS != nil {
			return nil, errors.New("the gateway has a certificate and no address to serve it on")
		}
		return nil, nil
	}
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("the gateway's address %q is not host:port", cfg.Listen)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return nil, fmt.Errorf("the gateway's address %q is not host:port", cfg.Listen)
	}
	if cfg.TLS == nil && !loopbackHost(host) {
		return nil, fmt.Errorf("the gateway's address %s is not loopback, so it needs TLS: a certificate and its key", cfg.Listen)
	}
	if cfg.TLS == nil {
		return nil, nil
	}
	if cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "" {
		return nil, errors.New("the gateway's TLS needs a certificate file and a key file")
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("the gateway's certificate %s and key %s: %w", cfg.TLS.CertFile, cfg.TLS.KeyFile, err)
	}
	return &cert, nil
}

// loopbackHost reports whether an address's host is loopback: localhost, or a loopback
// address.
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// The bounds of what the one address reads of a connection before it knows where it
// goes: its first line, the relay's preamble or a request line, and a proxy request's
// head.
const (
	maxFirstLine = 8 << 10
	maxProxyHead = 64 << 10
)

// serviceIdle is how long a connection of the contract on the one address may stay
// open between requests: the session's client keeps one as long.
const serviceIdle = 90 * time.Second

// proxyRefusedText is what a proxy request reads of a 407, the same for every failure
// of its login.
const proxyRefusedText = "a live run's proxy secret is required as the proxy password"

// proxyRefused is the answer to a proxy request whose login no run accepts.
var proxyRefused = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"qory\"\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: " + strconv.Itoa(len(proxyRefusedText)) + "\r\nConnection: close\r\n\r\n" + proxyRefusedText

// proxyUnserved is the answer to a proxy request accepted for a run whose proxy the
// gateway may not serve another machine with.
const proxyUnserved = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

// service is the gateway's one address: every connection is routed by its first bytes,
// after the TLS handshake when there is TLS, to the relay's run, the proxy of the run
// whose proxy secret its login carries, or the contract.
type service struct {
	g     *Gateway
	ln    net.Listener
	tls   *tls.Config
	side  *side
	http  *http.Server
	queue *connQueue

	mu      sync.Mutex
	pending map[net.Conn]struct{}
	closed  bool
	wg      sync.WaitGroup
}

// startService listens on the config's address, with cert when not nil, and serves it.
// A plain listener whose address turns out not to be loopback is refused.
func (g *Gateway) startService(cert *tls.Certificate) (*service, error) {
	ln, err := net.Listen("tcp", g.cfg.Listen)
	if err != nil {
		return nil, err
	}
	if a, ok := ln.Addr().(*net.TCPAddr); cert == nil && (!ok || !a.IP.IsLoopback()) {
		ln.Close()
		return nil, fmt.Errorf("the gateway's address %s is not loopback, so it needs TLS: a certificate and its key", g.cfg.Listen)
	}
	s := &service{g: g, ln: ln, side: &side{remote: true, scheme: "http"}, queue: newConnQueue(ln.Addr()), pending: map[net.Conn]struct{}{}}
	if cert != nil {
		s.side.scheme = "https"
		s.tls = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}}
	}
	s.http = &http.Server{Handler: g.serviceHandler(s.side), ReadHeaderTimeout: link.PreambleWait, IdleTimeout: serviceIdle, ErrorLog: quietLog()}
	go s.http.Serve(s.queue)
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

// addr is the one address, host:port.
func (s *service) addr() string { return s.ln.Addr().String() }

// accept routes every connection in its own goroutine, so a peer that sends nothing
// holds up no one else.
func (s *service) accept() {
	defer s.wg.Done()
	var backoff time.Duration
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.pending[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.route(c)
	}
}

// route reads c's first bytes within [link.PreambleWait], the TLS handshake among
// them, and hands c on: a first line of [link.RelayPreamble] to the shared proxy's
// runs, guarded ones alone; a proxy request, CONNECT or an absolute-form target, to the
// proxy of the run whose proxy secret its login carries; anything else to the contract. What it read is
// read again by whoever it hands c to. A connection that sends nothing it can route in
// time is closed unanswered.
func (s *service) route(raw net.Conn) {
	defer s.wg.Done()
	handed := false
	defer func() {
		s.mu.Lock()
		delete(s.pending, raw)
		s.mu.Unlock()
		if !handed {
			raw.Close()
		}
	}()
	deadline := time.Now().Add(link.PreambleWait)
	raw.SetDeadline(deadline)
	c := raw
	if s.tls != nil {
		tc := tls.Server(raw, s.tls)
		ctx, cancel := context.WithDeadline(s.g.base, deadline)
		err := tc.HandshakeContext(ctx)
		cancel()
		if err != nil {
			return
		}
		c = tc
	}
	r := bufio.NewReaderSize(c, maxProxyHead)
	line, ok := peekThrough(r, maxFirstLine, func(b []byte) int {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			return i + 1
		}
		return -1
	})
	if !ok {
		return
	}
	switch {
	case bytes.HasPrefix(line, []byte(link.RelayPreamble+" ")):
		c.SetDeadline(time.Time{})
		s.g.proxies.Serve(&linkConn{Conn: c, r: r}, true)
		handed = true
	case proxyForm(line):
		handed = s.proxyRequest(c, r)
	default:
		c.SetDeadline(time.Time{})
		handed = s.queue.deliver(&linkConn{Conn: c, r: r})
	}
}

// peekThrough peeks at r until end finds the end of what it looks for in the bytes
// buffered, within limit bytes, and returns them, read again by r's next reader.
func peekThrough(r *bufio.Reader, limit int, end func([]byte) int) ([]byte, bool) {
	for {
		// What is buffered first, which a peek of it never waits for; then one more byte.
		b, _ := r.Peek(r.Buffered())
		if i := end(b); i >= 0 && i <= limit {
			return b[:i], true
		}
		if len(b) >= limit {
			return nil, false
		}
		if _, err := r.Peek(len(b) + 1); err != nil {
			return nil, false
		}
	}
}

// headEnd is the end of an HTTP request's head in b: the empty line after its fields,
// or -1.
func headEnd(b []byte) int {
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		return i + 4
	}
	if i := bytes.Index(b, []byte("\n\n")); i >= 0 {
		return i + 2
	}
	return -1
}

// proxyForm reports whether a request line is a proxy's: CONNECT, or a request-target
// in absolute form, neither a path nor *.
func proxyForm(line []byte) bool {
	parts := strings.Split(strings.TrimRight(string(line), "\r\n"), " ")
	if len(parts) != 3 {
		return false
	}
	return parts[0] == http.MethodConnect || (!strings.HasPrefix(parts[1], "/") && parts[1] != "*")
}

// proxyRequest hands c, whose first request is a proxy's, to the proxy of the run its
// login names: a live run's proxy secret as the password of its Proxy-Authorization, a
// session's run without a wall. A connection without one is answered 407 with
// Proxy-Authenticate, and closed. It reports whether c was handed on.
func (s *service) proxyRequest(c net.Conn, r *bufio.Reader) bool {
	head, ok := peekThrough(r, maxProxyHead, headEnd)
	if !ok {
		return false
	}
	first, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(head)))
	if err != nil {
		return false
	}
	px := s.login(first)
	if px == nil {
		answerAndLinger(c, proxyRefused)
		return false
	}
	if !px.Guarded() {
		// Never a connection from another machine to a proxy that may dial this one.
		s.g.report("a connection to the gateway's address was refused: the proxy of the run its login names is not guarded")
		answerAndLinger(c, proxyUnserved)
		return false
	}
	c.SetDeadline(time.Time{})
	px.ServeConn(&linkConn{Conn: c, r: r})
	return true
}

// lingerWait bounds how long a refused proxy request's connection is read after its
// answer, and lingerBytes how much of it.
const (
	lingerWait  = 500 * time.Millisecond
	lingerBytes = 64 << 10
)

// answerAndLinger writes a proxy request's refusal and closes the connection's writing
// side, TLS's close_notify then TCP's, then reads what the client still sends, at most
// lingerBytes for at most lingerWait, before the caller closes it: a connection closed
// with bytes unread is reset, and a reset can reach the client before the answer does.
func answerAndLinger(c net.Conn, answer string) {
	c.SetWriteDeadline(time.Now().Add(lingerWait))
	if _, err := io.WriteString(c, answer); err != nil {
		return
	}
	var raw net.Conn = c
	if tc, ok := c.(*tls.Conn); ok {
		tc.CloseWrite()
		raw = tc.NetConn()
	}
	if cw, ok := raw.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	c.SetReadDeadline(time.Now().Add(lingerWait))
	io.Copy(io.Discard, io.LimitReader(c, lingerBytes))
}

// login is the proxy of the live run whose proxy secret a proxy request's login carries
// as its password; nil when none.
func (s *service) login(first *http.Request) *proxy.Proxy {
	values := first.Header.Values("Proxy-Authorization")
	if len(values) != 1 {
		return nil
	}
	password, ok := basicPassword(values[0])
	if !ok {
		return nil
	}
	return s.g.proxies.Lookup(password, true)
}

// basicPassword is the password of a Proxy-Authorization value of the Basic scheme
// (RFC 7617): the user name is ignored.
func basicPassword(value string) (string, bool) {
	scheme, rest, ok := strings.Cut(value, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimLeft(rest, " "))
	if err != nil {
		return "", false
	}
	_, password, ok := strings.Cut(string(b), ":")
	return password, ok
}

// b64token is the value of an Authorization of the Bearer scheme, RFC 6750 §2.1.
var b64token = regexp.MustCompile(`^[A-Za-z0-9\-._~+/]+=*$`)

// bearer is the value of a request's Authorization values: one, of the Bearer scheme,
// in its syntax.
func bearer(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	scheme, rest, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	value := strings.TrimLeft(rest, " ")
	return value, b64token.MatchString(value)
}

// serviceHandler is the contract on the one address: every request's bearer value
// decided first, a request without one or with one refused answered 401 unauthorized
// with WWW-Authenticate: Bearer; then the link's handler, with the run's identity in the
// request's context and no Authorization left on it.
func (g *Gateway) serviceHandler(s *side) http.Handler {
	next := g.handler(s)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value, ok := bearer(r.Header.Values("Authorization"))
		if !ok {
			refuseUnauthorized(w)
			return
		}
		id, err := g.auth.authenticate(r.Context(), value)
		if err != nil {
			refuseUnauthorized(w)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, id))
		r.Header = r.Header.Clone()
		r.Header.Del("Authorization")
		next.ServeHTTP(w, r)
	})
}

// refuseUnauthorized answers a request whose bearer value is refused, or missing: 401
// unauthorized, with no names and nothing of why.
func refuseUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	refuse(w, http.StatusUnauthorized, accesskey.CodeUnauthorized, nil, accesskey.FromGateway, gatewayText(accesskey.CodeUnauthorized))
}

// proxyAddress is the shape of the discovery's proxy.address,
// link-discovery.schema.json.
var proxyAddress = regexp.MustCompile(`^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$`)

// discoveryOf is the discovery a request of the side is answered with, and its digest:
// on the local link the one made at the start; on the one address one on the origin
// the request names in its Host, the gateway's one address the client reached, whose
// proxy is the same address. A Host no discovery can name is no discovery.
func (g *Gateway) discoveryOf(s *side, r *http.Request) ([]byte, string, bool) {
	if !s.remote {
		return g.discovery, g.discoveryDigest, true
	}
	port := "443"
	if s.scheme == "http" {
		port = "80"
	}
	host, p, err := net.SplitHostPort(r.Host)
	if err != nil {
		host, p, err = net.SplitHostPort(r.Host + ":" + port)
	}
	address := net.JoinHostPort(host, p)
	if err != nil || host == "" || !proxyAddress.MatchString(address) {
		return nil, "", false
	}
	origin := s.scheme + "://" + r.Host
	b, _ := json.Marshal(server.LinkDiscovery{
		Version: 1,
		Events:  server.LinkEvents{URL: origin + eventsPath, Types: []string{"*"}, IntervalSeconds: g.interval},
		Run:     server.Endpoint{URL: origin + runPath},
		Proxy:   &server.LinkProxy{Address: address},
	})
	sum := sha256.Sum256(b)
	return b, "sha256=" + hex.EncodeToString(sum[:]), true
}

// close stops the one address: no connection is routed from now on, every connection
// still being routed is closed, and the contract's server is shut within ctx.
func (s *service) close(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	for c := range s.pending {
		c.Close()
	}
	s.mu.Unlock()
	err := s.ln.Close()
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	s.wg.Wait()
	if serr := s.http.Shutdown(ctx); serr != nil {
		s.http.Close()
	}
	s.queue.Close()
	return err
}

// connQueue is the listener of the contract's server on the one address: the
// connections the router hands it.
type connQueue struct {
	addr  net.Addr
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newConnQueue(addr net.Addr) *connQueue {
	return &connQueue{addr: addr, conns: make(chan net.Conn), done: make(chan struct{})}
}

// deliver hands c to the server, and reports whether it took it; once the queue is
// closed it takes none.
func (q *connQueue) deliver(c net.Conn) bool {
	select {
	case q.conns <- c:
		return true
	case <-q.done:
		return false
	}
}

// Accept is the next connection handed over.
func (q *connQueue) Accept() (net.Conn, error) {
	select {
	case c := <-q.conns:
		return c, nil
	case <-q.done:
		return nil, net.ErrClosed
	}
}

// Close stops Accept and deliver.
func (q *connQueue) Close() error {
	q.once.Do(func() { close(q.done) })
	return nil
}

// Addr is the one address.
func (q *connQueue) Addr() net.Addr { return q.addr }
