package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"

	"github.com/qoryai/runner/internal/policy"
)

// AmbiguousPath is the rule a denial names when a request's path could be read two
// ways: not a path entry, the proxy's own refusal, in either mode.
const AmbiguousPath = "wall:ambiguous-path"

// Credential is one use of a token the runner holds for the session: the hosts it goes
// to, how it is set, and the paths of those hosts the run may ask for.
type Credential struct {
	// Name is the credential's name in the machine's configuration, for the record.
	Name  string
	Hosts []string
	// Scheme is bearer, basic or header; Username goes with basic, Header with header.
	Scheme, Username, Header string
	// Paths are the paths of the hosts the run may ask for; nil means every path.
	Paths []string
	// Token returns the token as it is now; it changes when it is renewed. Rejected is
	// told when the host answered 401, which is a reason to ask for another.
	Token    func() string
	Rejected func()
}

// Tool is a program of the machine's that serves hosts: the proxy hands every request
// to those hosts it lets through to the tool, on the Unix socket the tool listens on,
// and never dials the hosts themselves.
type Tool struct {
	// Name is the tool's name in the machine's configuration, for the record.
	Name  string
	Hosts []string
	// Socket is the path of the Unix socket the tool listens on.
	Socket string
	// transport reaches the socket.
	transport http.RoundTripper
}

// The headers the proxy sets on a request it hands to a tool. A request the session
// sends with a header of the prefix has it taken off first, so a tool reads these as the
// proxy's word.
const (
	// RequestIDHeader carries the proxy's id of the request, the request_id of its
	// egress event.
	RequestIDHeader = "Qory-Request-Id"
	// PathRuleHeader carries the path rule that let the request through, [NoPathRule]
	// when the host has path rules and under observe none covers the path; it is absent
	// when the host has none.
	PathRuleHeader = "Qory-Path-Rule"
	// NoPathRule is the path rule a tool is handed for a request observed and let
	// through that no rule covers: never a path, which starts with a slash.
	NoPathRule = "none"
	// headerPrefix is the prefix of every header that is the proxy's to set.
	headerPrefix = "Qory-"
)

// Terminate makes the proxy end the session's TLS itself for the hosts the credentials
// are for, the hosts with path rules and the hosts the tools serve, answering as each
// with a certificate of the run's authority, so it can read a request's path, set a
// credential on it or hand it to a tool. Every other host stays a tunnel it does not
// read. The session runner calls it once, before anything connects. The tools are the
// run's for as long as it lasts: a policy set later changes the paths and the
// credentials, never the tools, nor the node's paths set with [Proxy.NodePaths].
func (p *Proxy) Terminate(ca *CA, creds []Credential, paths map[string][]string, tools []Tool) {
	for i := range tools {
		sock := tools[i].Socket
		tools[i].transport = &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
			DisableCompression: true,
		}
	}
	p.term.Store(&terminator{p: p, ca: ca, creds: creds, paths: paths, node: p.node, tools: tools})
}

// NodePaths sets the path rules of the node's policy when it narrows a server's: a
// request to a host they list must match one of them as well as the policy's own when
// that lists the host too. They are fixed for the run; the caller sets them once,
// before [Proxy.Terminate].
func (p *Proxy) NodePaths(paths map[string][]string) { p.node = paths }

// Terminated reports the hosts, as configured, the proxy terminates TLS for: under the
// policy set last, when one was.
func (p *Proxy) Terminated() []string {
	t := p.term.Load()
	if t == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, c := range t.creds {
		for _, h := range c.Hosts {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	for _, tl := range t.tools {
		for _, h := range tl.Hosts {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	for _, side := range []map[string][]string{t.paths, t.node} {
		for h := range side {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}

type terminator struct {
	p     *Proxy
	ca    *CA
	creds []Credential
	paths map[string][]string
	// node are the node's path rules, which narrow paths.
	node  map[string][]string
	tools []Tool
}

// tool is the tool that serves the host, if one does.
func (t *terminator) tool(host string) *Tool {
	if t == nil {
		return nil
	}
	for i := range t.tools {
		if _, ok := policy.Match(t.tools[i].Hosts, host); ok {
			return &t.tools[i]
		}
	}
	return nil
}

// credential is the credential that is for the host, if one is.
func (t *terminator) credential(host string) *Credential {
	for i := range t.creds {
		if _, ok := policy.Match(t.creds[i].Hosts, host); ok {
			return &t.creds[i]
		}
	}
	return nil
}

// credentialName names the credential that is for the host, empty when none is.
func (t *terminator) credentialName(host string) string {
	if t == nil {
		return ""
	}
	if c := t.credential(host); c != nil {
		return c.Name
	}
	return ""
}

// rules are the path rules for the host of each side that lists it: the policy's, then
// the node's. A request must match an entry of each.
func (t *terminator) rules(host string) [][]string {
	var out [][]string
	for _, side := range []map[string][]string{t.paths, t.node} {
		for pattern, rules := range side {
			if _, ok := policy.Match([]string{pattern}, host); ok {
				out = append(out, rules)
				break
			}
		}
	}
	return out
}

// ruled reports whether either side has path rules for the host.
func (t *terminator) ruled(host string) bool { return len(t.rules(host)) > 0 }

// covers reports whether the host is one the proxy terminates.
func (t *terminator) covers(host string) bool {
	if t == nil {
		return false
	}
	return t.ruled(host) || t.credential(host) != nil || t.tool(host) != nil
}

// path decides one request's path. A path that could be read two ways is denied in
// either mode; a path that misses the rules of a side that lists its host is denied
// under enforce, with no rule. A path every such side matches has the narrowest entry
// that matched as its rule. The credential is set only on a path its own rules match,
// whatever the mode: observing is no reason to hand a credential to a path nobody
// configured.
func (t *terminator) path(host, escaped string) (clean, rule string, allowed, credentialed bool) {
	clean, ok := policy.CleanPath(escaped)
	if !ok {
		return escaped, AmbiguousPath, false, false
	}
	allowed, credentialed = true, true
	for _, rules := range t.rules(host) {
		r, ok := policy.MatchPath(rules, clean)
		switch {
		case !ok:
			allowed = false
		case rule == "" || policy.CoversPath(rule, r):
			rule = r
		}
	}
	if !allowed {
		rule = ""
	}
	if c := t.credential(host); c != nil && c.Paths != nil {
		r, ok := policy.MatchPath(c.Paths, clean)
		credentialed = ok
		if rule == "" || !ok {
			rule = r
		}
		allowed = allowed && ok
	}
	if !allowed && t.p.rules.Load().mode == policy.Observe {
		allowed = true
	}
	return clean, rule, allowed, credentialed
}

// serve ends the session's TLS on client as host and serves the requests inside it.
func (t *terminator) serve(ctx context.Context, client net.Conn, d Decision, authority string) {
	leaf, err := t.ca.leaf(d.Host)
	if err != nil {
		client.Close()
		return
	}
	// HTTP/1.1 only on this side: one request at a time is one decision at a time, and
	// every client that speaks to a proxy speaks it.
	conn := tls.Server(client, &tls.Config{Certificates: []tls.Certificate{*leaf}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// The host asked of upstream is the one the connection was opened to and
			// decided on, whatever Host the request names: a credential is for that host,
			// and another name behind the same address is another site.
			r.Out.URL.Scheme = "https"
			r.Out.URL.Host = strings.TrimSuffix(authority, ":443")
			r.Out.Host = ""
			// The request's own trailer, which the server fills once the body is read:
			// a copy made before that would carry none.
			r.Out.Trailer = r.In.Trailer
		},
		Transport:     t.p.upstream(),
		FlushInterval: -1,
		ErrorHandler:  t.failed,
		ModifyResponse: func(resp *http.Response) error {
			if d, ok := settle(resp.Request, resp, nil); ok {
				t.p.observe(d)
			}
			if c := t.credential(d.Host); c != nil && resp.StatusCode == http.StatusUnauthorized && c.Rejected != nil && resp.Request.Header.Get(setBy) == c.Name {
				c.Rejected()
			}
			return nil
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean, rule, allowed, credentialed := t.path(d.Host, r.URL.EscapedPath())
		req := d
		req.Method, req.RequestMethod, req.Path, req.PathRule = "HTTPS", r.Method, clean, rule
		req.Allowed, req.RequestID = allowed, newRequestID()
		tl := t.tool(d.Host)
		if tl != nil {
			req.Tool = tl.Name
		}
		c := t.credential(d.Host)
		r.Header.Del(setBy)
		if allowed && credentialed && c != nil && tl == nil {
			if name, value, ok := c.header(); ok {
				r.Header.Set(name, value)
				r.Header.Set(setBy, c.Name)
				req.Credential = c.Name
			}
		}
		if !allowed {
			req.Outcome = Refused
			t.p.observe(req)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			if rule == AmbiguousPath {
				fmt.Fprintf(w, "qory: %s %s%s denied by the wall: the path could be read two ways\n", r.Method, d.Host, clean)
				return
			}
			fmt.Fprintf(w, "qory: %s %s%s denied by policy (mode %s): no path rule of the run's covers it\n", r.Method, d.Host, clean, req.Mode)
			return
		}
		if tl != nil {
			t.toTool(w, r, req, tl)
			return
		}
		// The request is recorded once its outcome is known: when the response's
		// headers arrive, or when the transport fails.
		ctx := context.WithValue(t.p.dialContext(r.Context(), d), pendingKey{}, &pending{d: req})
		rp.ServeHTTP(w, r.WithContext(ctx))
	})
	ln := &once{conn: conn, done: make(chan struct{})}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: t.p.srv.ReadHeaderTimeout, ConnState: func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed || s == http.StateHijacked {
			ln.Close()
		}
	}}
	stop := context.AfterFunc(ctx, func() { srv.Close() })
	defer stop()
	srv.Serve(ln)
}

// pendingKey carries a request's decision, waiting for its outcome, in its context.
type pendingKey struct{}

// pending is a decision recorded once, whichever of the response and the error comes.
type pending struct {
	d    Decision
	once sync.Once
}

// settle returns the request's decision with its outcome, and the status of resp when
// the host or the tool answered, once: the first call for a request gets it, later
// ones get false.
func settle(r *http.Request, resp *http.Response, err error) (Decision, bool) {
	p, ok := r.Context().Value(pendingKey{}).(*pending)
	if !ok {
		return Decision{}, false
	}
	var d Decision
	done := false
	p.once.Do(func() {
		d, done = p.d, true
		if err != nil {
			d = failed(d, err)
		} else {
			d.Outcome = Connected
		}
		if resp != nil {
			d.Status = resp.StatusCode
		}
	})
	return d, done
}

// setBy marks, on the way upstream only, a request the proxy set a credential on; the
// transport takes it off again.
const setBy = "X-Qory-Credential-Set"

// header is the header that carries the token.
func (c *Credential) header() (string, string, bool) {
	token := c.Token()
	if token == "" {
		return "", "", false
	}
	switch c.Scheme {
	case "bearer":
		return "Authorization", "Bearer " + token, true
	case "basic":
		return "Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+token)), true
	case "header":
		return c.Header, token, true
	}
	return "", "", false
}

// upstream is the transport to the real hosts of terminated connections: verified
// against this machine's roots, dialled through the proxy's guarded dialler.
func (p *Proxy) upstream() http.RoundTripper {
	p.upOnce.Do(func() {
		p.up = &unmark{&http.Transport{Proxy: nil, DialContext: p.dial, ForceAttemptHTTP2: true, DisableCompression: true, TLSClientConfig: p.upstreamTLS}}
	})
	return p.up
}

// unmark takes the proxy's own mark off a request before it leaves.
type unmark struct{ rt http.RoundTripper }

// RoundTrip sends the request on without the mark.
func (u *unmark) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get(setBy) == "" {
		return u.rt.RoundTrip(r)
	}
	out := r.Clone(r.Context())
	out.Header.Del(setBy)
	// The trailer is filled once the body is read; a clone's copy would stay empty.
	out.Trailer = r.Trailer
	resp, err := u.rt.RoundTrip(out)
	if resp != nil {
		resp.Request = r
	}
	return resp, err
}

// once is a listener of the one connection it was made with.
type once struct {
	conn net.Conn
	mu   sync.Mutex
	used bool
	done chan struct{}
	shut sync.Once
}

// Accept hands the connection on, then waits for Close.
func (l *once) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.used {
		l.used = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}

// Close ends Accept.
func (l *once) Close() error {
	l.shut.Do(func() { close(l.done) })
	return nil
}

// Addr is the connection's.
func (l *once) Addr() net.Addr { return l.conn.LocalAddr() }

// plainPath decides a plain request's path by the policy's rules. No credential is ever
// set on a connection that is not encrypted.
func (t *terminator) plainPath(host, escaped string) (string, string, bool) {
	if t == nil {
		return "", "", true
	}
	if !t.ruled(host) && t.credential(host) == nil && t.tool(host) == nil {
		return "", "", true
	}
	clean, rule, allowed, _ := t.path(host, escaped)
	return clean, rule, allowed
}

// TrustUpstream sets the roots the proxy verifies a terminated host's own certificate
// against; nil means this machine's.
func (p *Proxy) TrustUpstream(roots *x509.CertPool) {
	p.upstreamTLS = &tls.Config{RootCAs: roots}
}

// failed records a request whose host or tool was not reached, and answers it.
func (t *terminator) failed(w http.ResponseWriter, r *http.Request, err error) {
	if d, ok := settle(r, nil, err); ok {
		t.p.observe(d)
		if !d.Allowed {
			deny(w, d)
			return
		}
	}
	http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
}

// toTool hands a request the proxy let through to the tool that serves its host, with
// the proxy's own headers, and records it once the tool answered or could not be
// reached. The request goes as the session sent it otherwise, placeholders included:
// what it names beyond its path is the tool's to check.
func (t *terminator) toTool(w http.ResponseWriter, r *http.Request, d Decision, tl *Tool) {
	rule := d.PathRule
	if t.ruled(d.Host) && rule == "" {
		// Observed and let through: the host has rules and none covers the path.
		rule = NoPathRule
	}
	host := strings.TrimSuffix(d.Host, ".")
	rp := &httputil.ReverseProxy{
		// Rewrite runs after the hop-by-hop headers are gone, those the session names
		// in Connection among them, so what is set here reaches the tool.
		Rewrite: func(pr *httputil.ProxyRequest) {
			// The host is the one the connection was decided on, whatever Host the
			// request names; the tool reads it to know which of its hosts was asked.
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = host
			pr.Out.Host = host
			scrub(pr.Out.Header)
			pr.Out.Header.Set(RequestIDHeader, d.RequestID)
			if rule != "" {
				pr.Out.Header.Set(PathRuleHeader, rule)
			}
			// The trailer is announced before the body and filled after it: the tool
			// gets one of its own, without the proxy's prefix, filled once the body is
			// read.
			pr.Out.Trailer = nil
			if in := pr.In.Trailer; in != nil && pr.Out.Body != nil {
				out := http.Header{}
				for name := range in {
					if !proxys(name) {
						out[name] = nil
					}
				}
				pr.Out.Trailer = out
				pr.Out.Body = &trailing{ReadCloser: pr.Out.Body, in: in, out: out}
			}
		},
		Transport:     tl.transport,
		FlushInterval: -1,
		ErrorHandler:  t.failed,
		ModifyResponse: func(resp *http.Response) error {
			if d, ok := settle(resp.Request, resp, nil); ok {
				t.p.observe(d)
			}
			return nil
		},
	}
	ctx := context.WithValue(r.Context(), pendingKey{}, &pending{d: d})
	rp.ServeHTTP(w, r.WithContext(ctx))
}

// proxys reports whether a header's name is one of the proxy's to set: its prefix in
// any case, with an underscore for a dash, which some servers read as the same name.
func proxys(name string) bool {
	return strings.HasPrefix(strings.ReplaceAll(strings.ToLower(name), "_", "-"), strings.ToLower(headerPrefix))
}

// scrub takes every header of the proxy's prefix off.
func scrub(h http.Header) {
	for name := range h {
		if proxys(name) {
			delete(h, name)
		}
	}
}

// trailing is a request body that copies the session's trailer to the tool's at its
// end, without the proxy's prefix: the server fills the one before the body ends, and
// the transport writes the other after.
type trailing struct {
	io.ReadCloser
	in, out http.Header
}

// Read reads the body, and copies the trailer at its end.
func (t *trailing) Read(b []byte) (int, error) {
	n, err := t.ReadCloser.Read(b)
	if err == io.EOF {
		for name, values := range t.in {
			if !proxys(name) {
				t.out[name] = values
			}
		}
	}
	return n, err
}

// newRequestID is a request's id: 16 random bytes, hex.
func newRequestID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
