package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// side is the way a request of the contract reached the gateway: its local link, or
// its one address.
type side struct {
	// remote says the request came to the one address, on a bound connection.
	remote bool
	// scheme is the one address's origin's scheme, https.
	scheme string
}

// localSide is the local link's.
var localSide = &side{}

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
	_, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("the gateway's address %q is not host:port", cfg.Listen)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return nil, fmt.Errorf("the gateway's address %q is not host:port", cfg.Listen)
	}
	if cfg.TLS == nil {
		return nil, fmt.Errorf("the gateway's address %s needs TLS, a certificate and its key: every connection of the link there is bound to its TLS", cfg.Listen)
	}
	if cfg.Server == nil {
		return nil, fmt.Errorf("the gateway's address %s needs a server and a gateway's access key: the gateway attaches each run there", cfg.Listen)
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

// maxFirstLine is the bound of what the one address reads of a connection before it
// knows where it goes: its first line, the binding's or a request line, and on a bound
// connection the relay's preamble or a request line.
const maxFirstLine = 8 << 10

// serviceIdle is how long a connection of the contract on the one address may stay
// open between requests: the session's client keeps one as long.
const serviceIdle = 90 * time.Second

// service is the gateway's one address: every connection is routed by its first bytes,
// after the TLS handshake. One that opens with [link.BindWord] is an edge's: the
// gateway answers with its [link.BoundWord] line, and the connection then carries the
// link, or the relay's preamble with a run key for that run's proxy. Any other is the
// relay of the Server's four endpoints ([relay]).
type service struct {
	g     *Gateway
	ln    net.Listener
	tls   *tls.Config
	side  *side
	edge  *http.Server
	edgeQ *connQueue
	relay *relay

	mu      sync.Mutex
	pending map[net.Conn]struct{}
	closed  bool
	wg      sync.WaitGroup
}

// startService listens on the config's address with cert and serves it.
func (g *Gateway) startService(cert *tls.Certificate) (*service, error) {
	ln, err := net.Listen("tcp", g.cfg.Listen)
	if err != nil {
		return nil, err
	}
	s := &service{g: g, ln: ln, side: &side{remote: true, scheme: "https"}, edgeQ: newConnQueue(ln.Addr()), pending: map[net.Conn]struct{}{}}
	s.tls = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}}
	s.edge = &http.Server{Handler: g.edgeHandler(s.side), ReadHeaderTimeout: link.PreambleWait, IdleTimeout: serviceIdle, ErrorLog: quietLog(),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if b, ok := c.(*boundConn); ok {
				return context.WithValue(ctx, bindingKey{}, b.ekm)
			}
			return ctx
		}}
	s.relay = g.newRelay(ln.Addr())
	go s.edge.Serve(s.edgeQ)
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
// them, and hands c on: a first line of [link.BindWord] is bound ([service.bind]);
// anything else goes to the relay. What it read is read again by whoever it hands c to.
// A connection that sends nothing it can route in time is closed unanswered.
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
	tc := tls.Server(raw, s.tls)
	ctx, cancel := context.WithDeadline(s.g.base, deadline)
	err := tc.HandshakeContext(ctx)
	cancel()
	if err != nil {
		return
	}
	r := bufio.NewReaderSize(tc, maxFirstLine)
	line, ok := peekThrough(r, maxFirstLine, lineEnd)
	if !ok {
		return
	}
	if string(line) == link.BindWord+"\n" {
		r.Discard(len(line))
		handed = s.bind(tc, r)
		return
	}
	tc.SetDeadline(time.Time{})
	handed = s.relay.queue.deliver(&linkConn{Conn: tc, r: r})
}

// bind binds an edge's connection, whose [link.BindWord] line r has read: the gateway
// writes its [link.BoundWord] line, signed under its access key over the connection's
// exporter value, then reads the connection's next line within the same deadline. The
// relay's preamble with a run key goes to that run's proxy ([Gateway.relayRun]); any
// other line is the link's HTTP/1.1. It reports whether c was handed on.
func (s *service) bind(c *tls.Conn, r *bufio.Reader) bool {
	ekm, err := link.Binding(c.ConnectionState())
	if err != nil {
		return false
	}
	if _, err := io.WriteString(c, link.BoundLine(s.g.cfg.Server.AccessKey, ekm)); err != nil {
		return false
	}
	line, ok := peekThrough(r, maxFirstLine, lineEnd)
	if !ok {
		return false
	}
	if bytes.HasPrefix(line, []byte(link.RelayPreamble+" ")) {
		if len(line) > link.MaxRelayRunKey {
			return false
		}
		r.Discard(len(line))
		return s.g.relayRun(c, r, strings.TrimSuffix(strings.TrimPrefix(string(line), link.RelayPreamble+" "), "\n"))
	}
	c.SetDeadline(time.Time{})
	return s.edgeQ.deliver(&boundConn{linkConn: linkConn{Conn: c, r: r}, ekm: ekm})
}

// lineEnd is the end of the first line in b, its newline included, or -1.
func lineEnd(b []byte) int {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return i + 1
	}
	return -1
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

// boundConn is a bound connection of the link: what its binding read, and its exporter
// value, which signs every answer on it.
type boundConn struct {
	linkConn
	ekm []byte
}

// bindingKey is the key of a bound connection's exporter value in its requests'
// contexts.
type bindingKey struct{}

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

// edgeHandler is the link on the one address: every request's run key, its bearer
// value, decided first ([Gateway.admitRunKey]), a refusal answered with its code; then
// the link's handler, with the run key in the request's context and no Authorization
// left on it. Every answer is signed under the gateway's access key ([signedWriter]).
func (g *Gateway) edgeHandler(s *side) http.Handler {
	next := g.handler(s)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ekm, _ := r.Context().Value(bindingKey{}).([]byte)
		body := &capturedBody{r: r.Body, post: r.Method == http.MethodPost}
		r.Body = body
		sw := &signedWriter{w: w, key: g.cfg.Server.AccessKey, ekm: ekm, req: r, body: body, header: http.Header{}}
		defer sw.Flush()
		value, ok := bearer(r.Header.Values("Authorization"))
		k, ref := g.admitRunKey(value, ok)
		if ref != nil {
			refuse(sw, ref.Status, ref.Code, nil, ref.From, ref.Error())
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), runKeyKey{}, presented{raw: value, key: k}))
		r.Header = r.Header.Clone()
		r.Header.Del("Authorization")
		next.ServeHTTP(sw, r)
	})
}

// maxBound is the most of a request's body a bound answer's signature covers: a batch's
// bound, and one byte more, which no request the gateway answers in full carries.
const maxBound = maxBatch + 1

// capturedBody is a request's body on a bound connection, kept as it is read, so its
// answer's signature covers it: the body of a POST, nothing of a GET.
type capturedBody struct {
	r    io.ReadCloser
	post bool
	buf  bytes.Buffer
}

func (b *capturedBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if b.post && b.buf.Len() < maxBound {
		b.buf.Write(p[:min(n, maxBound-b.buf.Len())])
	}
	return n, err
}

// Close closes the request's body.
func (b *capturedBody) Close() error { return b.r.Close() }

// whole is the request's body, up to [maxBound]: what the handler read, then the rest;
// empty for a GET.
func (b *capturedBody) whole() []byte {
	if b.post && b.buf.Len() < maxBound {
		io.Copy(io.Discard, io.LimitReader(b, int64(maxBound-b.buf.Len())))
	}
	return b.buf.Bytes()
}

// signedWriter holds an answer on a bound connection until it is whole, then writes it
// with its X-Qory-Signature-Ed25519 under the gateway's key over the six lines of
// [link.Answer]. Flush writes what it holds, once; whatever is written after is
// dropped.
type signedWriter struct {
	w      http.ResponseWriter
	key    *accesskey.Key
	ekm    []byte
	req    *http.Request
	body   *capturedBody
	header http.Header
	status int
	buf    bytes.Buffer
	done   bool
}

// Header is the answer's fields, held until Flush.
func (s *signedWriter) Header() http.Header { return s.header }

// WriteHeader holds the answer's status, the first one written.
func (s *signedWriter) WriteHeader(status int) {
	if s.status == 0 {
		s.status = status
	}
}

func (s *signedWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	if s.done {
		return 0, http.ErrHandlerTimeout
	}
	return s.buf.Write(b)
}

// Flush signs and writes the answer held, once.
func (s *signedWriter) Flush() {
	if s.done {
		return
	}
	s.done = true
	if s.status == 0 {
		s.status = http.StatusOK
	}
	a := link.Answer{
		Status: s.status, Request: link.AnswerRequest(s.ekm, s.req.Method, s.req.RequestURI, s.body.whole()), Body: s.buf.Bytes(),
		Configuration: s.header.Get(server.HeaderConfiguration), RunConfiguration: s.header.Get(server.HeaderRunConfiguration),
	}
	h := s.w.Header()
	for k, v := range s.header {
		h[k] = v
	}
	h.Set(server.HeaderSignature, link.SignAnswer(s.key, a))
	s.w.WriteHeader(s.status)
	s.w.Write(s.buf.Bytes())
	if f, ok := s.w.(http.Flusher); ok {
		f.Flush()
	}
}

// proxyAddress is the shape of the discovery's proxy.address,
// link-discovery.schema.json.
var proxyAddress = regexp.MustCompile(`^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$`)

// discoveryOf is the discovery a request of the side is answered with, and its digest:
// on the local link the one made at the start; on the one address one on the origin
// the request names in its Host, the gateway's one address the client reached, whose
// proxy is the same address, and whose paths are under [link.RemotePrefix]. A Host no
// discovery can name is no discovery.
func (g *Gateway) discoveryOf(s *side, r *http.Request) ([]byte, string, bool) {
	if !s.remote {
		return g.discovery, g.discoveryDigest, true
	}
	host, p, err := net.SplitHostPort(r.Host)
	if err != nil {
		host, p, err = net.SplitHostPort(r.Host + ":443")
	}
	address := net.JoinHostPort(host, p)
	if err != nil || host == "" || !proxyAddress.MatchString(address) {
		return nil, "", false
	}
	origin := s.scheme + "://" + r.Host
	b, _ := json.Marshal(server.LinkDiscovery{
		Version: 1,
		Events:  server.LinkEvents{URL: origin + remoteEventsPath, Types: []string{"*"}, IntervalSeconds: g.interval},
		Run:     server.Endpoint{URL: origin + remoteRunPath},
		Proxy:   &server.LinkProxy{Address: address},
	})
	sum := sha256.Sum256(b)
	return b, "sha256=" + hex.EncodeToString(sum[:]), true
}

// close stops the one address: no connection is routed from now on, every connection
// still being routed is closed, and the link's and the relay's servers are shut within
// ctx.
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
	if serr := s.edge.Shutdown(ctx); serr != nil {
		s.edge.Close()
	}
	s.edgeQ.Close()
	s.relay.close(ctx)
	return err
}

// connQueue is the listener of a server on the one address: the connections the router
// hands it.
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
