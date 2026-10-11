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
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/runkey"
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

// maxRelayRunKey is the longest relay preamble with a run key, its newline included:
// [link.RelayPreamble], a space, a run key of at most [runkey.MaxLength] characters and
// a newline.
const maxRelayRunKey = len(link.RelayPreamble) + 1 + runkey.MaxLength + 1

// maxFirstLine is the bound of what the one address reads of a connection before it
// knows where it goes: its first line, the binding's or a request line, and on a bound
// connection the relay's preamble or a request line.
const maxFirstLine = 8 << 10

// serviceIdle is how long a connection of the contract on the one address may stay
// open between requests: the session's client keeps one as long.
const serviceIdle = 90 * time.Second

// The one address's bounds on the connections it holds whose run key it has not
// admitted: in all, of one source, an IPv4 address or an IPv6 /64, and of one IPv6 /48
// ([sourceOf]). A connection past any is closed as it is accepted, unanswered. One
// whose run key is admitted counts against none of them.
const (
	maxConns       = 4096
	maxSourceConns = 64
	maxBlockConns  = 256
)

// The link's bounds on the one address: how long a request may take to arrive whole,
// its body included, and the most its request line and fields may hold.
const (
	edgeReadWait  = 60 * time.Second
	edgeMaxHeader = 16 << 10
)

// The bounds of a request the one address refuses for its run key: the most of its body
// the gateway reads, which the refusal's signature covers, and how long it waits for it.
// A longer body, or one slower, closes the connection unanswered.
const (
	refusedBody = 64 << 10
	refusedWait = 10 * time.Second
)

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
	conns *connLimit

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
	s := &service{g: g, ln: ln, side: &side{remote: true, scheme: "https"}, edgeQ: newConnQueue(ln.Addr()), pending: map[net.Conn]struct{}{},
		conns: newConnLimit(maxConns, maxSourceConns, maxBlockConns)}
	s.tls = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}}
	// OPTIONS * goes to the handler too, which refuses it for its run key: no request
	// without one keeps a connection open.
	s.edge = &http.Server{Handler: g.edgeHandler(s.side), ReadHeaderTimeout: link.PreambleWait, ReadTimeout: edgeReadWait, MaxHeaderBytes: edgeMaxHeader,
		IdleTimeout: serviceIdle, DisableGeneralOptionsHandler: true, ErrorLog: quietLog(),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if b, ok := c.(*boundConn); ok {
				return context.WithValue(context.WithValue(ctx, bindingKey{}, b.ekm), admitKey{}, b.admit)
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
// holds up no one else. A connection past [maxConns], [maxSourceConns] of its source or
// [maxBlockConns] of its /48 whose run keys are not admitted is closed at once.
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
		source := sourceOf(c.RemoteAddr())
		if !s.conns.take(source) {
			c.Close()
			continue
		}
		c = &heldConn{Conn: c, release: func() { s.conns.give(source) }}
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
	if string(line) == link.BindLine {
		r.Discard(len(line))
		admit := func() {}
		if h, ok := raw.(*heldConn); ok {
			admit = h.admit
		}
		handed = s.bind(tc, r, admit)
		return
	}
	tc.SetDeadline(time.Time{})
	handed = s.relay.queue.deliver(&linkConn{Conn: tc, r: r})
}

// bind binds an edge's connection, whose [link.BindWord] line r has read: the gateway
// writes its [link.BoundWord] line, signed under its access key over the connection's
// exporter value, then reads the connection's next line within the same deadline. The
// relay's preamble with a run key goes to that run's proxy ([Gateway.relayRun]); any
// other line is the link's HTTP/1.1. admit lets go of c's count among the connections
// whose run keys are not admitted, once its run key is. It reports whether c was
// handed on.
func (s *service) bind(c *tls.Conn, r *bufio.Reader, admit func()) bool {
	cs := c.ConnectionState()
	if cs.Version != tls.VersionTLS13 {
		return false
	}
	ekm, err := cs.ExportKeyingMaterial(link.BindingLabel, []byte{}, link.BindingSize)
	if err != nil {
		return false
	}
	key := s.g.cfg.Server.AccessKey
	fp := key.Fingerprint()
	if _, err := io.WriteString(c, link.BoundLine(fp, base64.RawURLEncoding.EncodeToString(key.Sign(link.BindingMessage(ekm, fp))))); err != nil {
		return false
	}
	line, ok := peekThrough(r, maxFirstLine, lineEnd)
	if !ok {
		return false
	}
	if bytes.HasPrefix(line, []byte(link.RelayPreamble+" ")) {
		value, ok := relayRunKey(line)
		if !ok {
			return false
		}
		r.Discard(len(line))
		return s.g.relayRun(c, r, value, admit)
	}
	c.SetDeadline(time.Time{})
	return s.edgeQ.deliver(&boundConn{linkConn: linkConn{Conn: c, r: r}, ekm: ekm, admit: admit})
}

// relayRunKey is the run key of a line of the relay's preamble, its newline included,
// and whether the line is within [maxRelayRunKey]: a longer one holds no run key.
func relayRunKey(line []byte) (string, bool) {
	if len(line) > maxRelayRunKey {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(string(line), link.RelayPreamble+" "), "\n"), true
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

// linkConn reads through the reader its first bytes were read with, which may hold what
// comes after them.
type linkConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *linkConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// boundConn is a bound connection of the link: what its binding read, its exporter
// value, which signs every answer on it, and what lets go of its count once a run key
// is admitted on it.
type boundConn struct {
	linkConn
	ekm   []byte
	admit func()
}

// bindingKey is the key of a bound connection's exporter value in its requests'
// contexts.
type bindingKey struct{}

// admitKey is the key of a bound connection's admit in its requests' contexts.
type admitKey struct{}

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
// value, decided first ([Gateway.admitRunKey]), a refusal answered with its code and
// Connection: close, once its body is read within [refusedBody] and [refusedWait], and
// the connection closed unanswered when it is not; then, the connection admitted, the
// link's handler, with the run key in the request's context and no Authorization left
// on it. Every answer is signed under the gateway's access key ([signedWriter]).
func (g *Gateway) edgeHandler(s *side) http.Handler {
	next := g.handler(s)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ekm, _ := r.Context().Value(bindingKey{}).([]byte)
		body := &capturedBody{r: r.Body, post: r.Method == http.MethodPost}
		r.Body = body
		sw := &signedWriter{w: w, key: g.cfg.Server.AccessKey, ekm: ekm, req: r, body: body, header: http.Header{}}
		defer func() {
			// A handler that panics has no answer to sign: the connection is closed.
			if v := recover(); v != nil {
				panic(v)
			}
			sw.Flush()
		}()
		value, ok := bearer(r.Header.Values("Authorization"))
		k, ref := g.admitRunKey(value, ok)
		if ref != nil {
			if !readRefused(w, r, body) {
				// The answer's signature covers a body the gateway did not read whole: no
				// answer, and nothing more read, where net/http would read on before it
				// closes.
				http.NewResponseController(w).SetReadDeadline(time.Now())
				panic(http.ErrAbortHandler)
			}
			sw.header.Set("Connection", "close")
			refuse(sw, ref.Status, ref.Code, nil, ref.From, ref.Error())
			return
		}
		if admit, ok := r.Context().Value(admitKey{}).(func()); ok {
			admit()
		}
		r = r.WithContext(context.WithValue(r.Context(), runKeyKey{}, presented{raw: value, key: k}))
		r.Header = r.Header.Clone()
		r.Header.Del("Authorization")
		next.ServeHTTP(sw, r)
	})
}

// readRefused reads the body of a request refused for its run key, through body, within
// [refusedWait], and reports whether it is whole and at most [refusedBody].
func readRefused(w http.ResponseWriter, r *http.Request, body *capturedBody) bool {
	if r.ContentLength > refusedBody {
		return false
	}
	if r.ContentLength == 0 {
		return true
	}
	http.NewResponseController(w).SetReadDeadline(time.Now().Add(refusedWait))
	n, err := io.Copy(io.Discard, io.LimitReader(body, refusedBody+1))
	return err == nil && n <= refusedBody
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
// a separate gateway's answer, [accesskey.Answer] with Link set. Flush writes what it holds, once; whatever is written after is
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
	a := accesskey.Answer{
		Link: true, Status: s.status, RequestSignature: link.AnswerRequest(s.ekm, s.req.Method, s.req.RequestURI, s.body.whole()), Body: s.buf.Bytes(),
		Configuration: s.header.Get(server.HeaderConfiguration), RunConfiguration: s.header.Get(server.HeaderRunConfiguration),
	}
	h := s.w.Header()
	for k, v := range s.header {
		h[k] = v
	}
	h.Set(server.HeaderSignature, s.key.SignAnswer(a))
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
// proxy is the same address, and whose paths are under [link.RemotePathPrefix]. A Host no
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

// connSource is what a connection counts against: its source, an IPv4 address or an
// IPv6 /64, and for IPv6 its /48.
type connSource struct {
	key, block string
}

// sourceOf is what a connection from addr counts against: its IPv4 address, or the /64
// and the /48 of its IPv6 address, an IPv4 address mapped into IPv6 counted as IPv4.
func sourceOf(addr net.Addr) connSource {
	var a netip.Addr
	if t, ok := addr.(*net.TCPAddr); ok {
		a = t.AddrPort().Addr()
	} else if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
		a = ap.Addr()
	} else {
		return connSource{key: addr.String()}
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return connSource{key: a.String()}
	}
	return connSource{key: sourceKey(a), block: netip.PrefixFrom(a, 48).Masked().String()}
}

// addressSource is the source of addr, host:port, as [sourceOf] counts it.
func addressSource(addr string) string {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return addr
	}
	return sourceKey(ap.Addr())
}

// sourceKey is the source a's address counts as: itself for IPv4, its /64 for IPv6.
func sourceKey(a netip.Addr) string {
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	return netip.PrefixFrom(a, 64).Masked().String()
}

// connLimit counts the connections the one address holds whose run key it has not
// admitted: in all, by source and by IPv6 /48.
type connLimit struct {
	mu                sync.Mutex
	most, each, block int
	total             int
	by, blocks        map[string]int
}

func newConnLimit(most, each, block int) *connLimit {
	return &connLimit{most: most, each: each, block: block, by: map[string]int{}, blocks: map[string]int{}}
}

// take counts one more connection of s, and reports whether it is within the bounds;
// one that is not is not counted.
func (l *connLimit) take(s connSource) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.most || l.by[s.key] >= l.each || s.block != "" && l.blocks[s.block] >= l.block {
		return false
	}
	l.total++
	l.by[s.key]++
	if s.block != "" {
		l.blocks[s.block]++
	}
	return true
}

// give lets go of a connection of s that take counted.
func (l *connLimit) give(s connSource) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.by[s.key]--; l.by[s.key] <= 0 {
		delete(l.by, s.key)
	}
	if s.block != "" {
		if l.blocks[s.block]--; l.blocks[s.block] <= 0 {
			delete(l.blocks, s.block)
		}
	}
}

// heldConn is a connection the one address counts until its run key is admitted or it
// is closed, whichever comes first.
type heldConn struct {
	net.Conn
	once    sync.Once
	release func()
}

// admit lets go of the connection's count, once: its run key is admitted.
func (c *heldConn) admit() { c.once.Do(c.release) }

// Close closes the connection and lets go of its count, once.
func (c *heldConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
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
