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

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/routine"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// AmbiguousPath is the rule a denial names when a request's path could be read two
// ways: not a path entry, the proxy's own refusal, in either mode.
const AmbiguousPath = "wall:ambiguous-path"

// EchoMethod is the rule a denial names of a TRACE or a TRACK, which echo the
// request's headers back, to a host a credential is for: a refusal of the proxy's, in
// either mode, with a 405.
const EchoMethod = "wall:echo-method"

// Credential is one use of a credential the gateway holds for the session: the hosts it
// goes to, how it is set, and the paths of those hosts the run may request.
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
	// Value, for a credential from the server, returns a copy of its opened value's
	// bytes, which the proxy clears once the header is set, in place of Token; Stored
	// says the credential is the server's.
	Value  func() []byte
	Stored bool
	// Placeholder, for a model key, is its placeholder's value: the proxy sets the key
	// only on a request that carries it where the key goes, the header and the scheme
	// the key is set with. Empty for every other credential, which the proxy sets on
	// every request to its hosts.
	Placeholder string
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

// headerPrefix is the prefix of every header that is the proxy's to set, those of
// [link.RequestIDHeader] and [link.PathRuleHeader] among them. A request the session
// sends with a header of the prefix has it taken off first, so a tool reads these as
// the proxy's word.
const headerPrefix = "Qory-"

// Terminate makes the proxy end the session's TLS itself for the hosts the credentials
// are for, the hosts with path rules and the hosts the tools serve, answering as each
// with a certificate of the run's authority, so it can read a request's path, set a
// credential on it or hand it to a tool. Every other host stays a tunnel it does not
// read. The session calls it once, before anything connects. The tools are the
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
			IdleConnTimeout:    idleTimeout,
		}
	}
	p.term.Store(&terminator{p: p, ca: ca, creds: creds, paths: paths, node: p.node, tools: tools})
}

// NodePaths sets the sides of path rules beside the policy's, each held apart: the
// node's policy's when it narrows a server's, and those of a ceiling the node's policy
// was put under. A request to a host a side lists must match an entry of it as well as
// of every other side that lists the host, the policy's included. They are fixed for
// the run; the caller sets them once, before [Proxy.Terminate].
func (p *Proxy) NodePaths(sides ...map[string][]string) { p.node = sides }

// Terminated reports the hosts, as configured, the proxy terminates TLS for: under the
// policy set last, when one was. A credential's "*." pattern that is for no host by
// [policy.CredentialFor], such as "*.local", is left out.
func (p *Proxy) Terminated() []string {
	t := p.term.Load()
	if t == nil {
		return nil
	}
	return t.hosts()
}

// Terminating reports the hosts [Proxy.Terminated] reports once [Proxy.Terminate] is
// called with the credentials, the paths and the tools, after [Proxy.NodePaths]: the
// hosts the run's authority is made for.
func (p *Proxy) Terminating(creds []Credential, paths map[string][]string, tools []Tool) []string {
	return (&terminator{p: p, creds: creds, paths: paths, node: p.node, tools: tools}).hosts()
}

// Outside reports the first host the proxy would terminate under the paths and the
// credentials, as [Proxy.SetPolicy] sets them, that the authority's certificates are not
// good for, by [CA.Permits], and whether a credential is for it. It reports the
// credentials' hosts first; empty when there is none, or the proxy terminates nothing.
func (p *Proxy) Outside(paths map[string][]string, creds []Credential) (host string, credential bool) {
	t := p.term.Load()
	if t == nil || t.ca == nil {
		return "", false
	}
	nt := *t
	nt.paths, nt.creds = paths, creds
	inCreds := map[string]bool{}
	for _, c := range creds {
		for _, h := range c.Hosts {
			inCreds[h] = true
		}
	}
	var first string
	for _, h := range nt.hosts() {
		if t.ca.Permits(h) {
			continue
		}
		if inCreds[h] {
			return h, true
		}
		if first == "" {
			first = h
		}
	}
	return first, false
}

// hosts are the hosts, as configured, the terminator terminates TLS for.
func (t *terminator) hosts() []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range t.creds {
		for _, h := range c.Hosts {
			if !seen[h] && !privatePattern(h) {
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
	for _, side := range t.sides() {
		for h := range side {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}

// privatePattern reports whether entry is a "*." pattern that is for no host by
// [policy.CredentialFor]: the name one label below it, such as a.local for "*.local",
// has a form under [policy.Host] and is not for entry. The label a has no dot, so when
// that name is private, every name under the pattern ends as it does and is private.
func privatePattern(entry string) bool {
	suffix, ok := strings.CutPrefix(entry, "*.")
	if !ok {
		return false
	}
	name, ok := policy.Host("a." + suffix)
	return ok && !policy.CredentialFor([]string{entry}, name)
}

type terminator struct {
	p     *Proxy
	ca    *CA
	creds []Credential
	paths map[string][]string
	// node are the sides of path rules beside paths, which narrow them.
	node  []map[string][]string
	tools []Tool
}

// sides are the policy's path rules, then each side beside them.
func (t *terminator) sides() []map[string][]string {
	return append([]map[string][]string{t.paths}, t.node...)
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

// credential is the credential that is for the host, by [policy.CredentialFor], if one
// is.
func (t *terminator) credential(host string) *Credential {
	for i := range t.creds {
		if policy.CredentialFor(t.creds[i].Hosts, host) {
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
// each beside it. Of each side, the entry [policy.HostPaths] picks holds the host. A
// request must match an entry of each.
func (t *terminator) rules(host string) [][]string {
	var out [][]string
	for _, side := range t.sides() {
		if _, rules, ok := policy.HostPaths(side, host); ok {
			out = append(out, rules)
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
			if masked(r.In) != nil {
				// The value is replaced in the answer only where it can be read: in
				// an uncompressed body, whole, and on a connection that stays HTTP. A
				// range of the body could hold part of the value.
				r.Out.Header.Set("Accept-Encoding", "identity")
				for _, h := range []string{"Range", "If-Range", "Upgrade", "Connection"} {
					r.Out.Header.Del(h)
				}
			}
		},
		Transport:     t.p.upstream(),
		FlushInterval: -1,
		ErrorHandler:  t.failed,
		ModifyResponse: func(resp *http.Response) error {
			if d, ok := settle(resp.Request, resp, nil); ok {
				t.p.observe(d)
			}
			if c := t.credential(d.Host); c != nil && resp.StatusCode == http.StatusUnauthorized && c.Rejected != nil && resp.Request.Context().Value(keyedKey{}) == c.Name {
				c.Rejected()
			}
			if masked(resp.Request) == nil {
				return nil
			}
			// The request went upstream without its Upgrade: a connection that
			// switched could carry the value unread.
			if resp.StatusCode == http.StatusSwitchingProtocols {
				return errUnaskedSwitch
			}
			if coding := encoded(resp); coding != "" {
				clean, _ := policy.CleanPath(resp.Request.URL.EscapedPath())
				withheld(resp, coding, resp.Request.Method, d.Host, clean)
			}
			return nil
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The token first, then the path's decision.
		rated := t.p.take(r.Context())
		clean, rule, allowed, credentialed := t.path(d.Host, r.URL.EscapedPath())
		req := d
		req.Method, req.RequestMethod, req.Path, req.PathRule = "HTTPS", r.Method, clean, rule
		req.Allowed, req.RequestID = allowed, newRequestID()
		tl := t.tool(d.Host)
		if tl != nil {
			req.Tool = tl.Name
		}
		if rated != nil {
			t.p.limited(w, req, RateLimit, rated)
			return
		}
		c := t.credential(d.Host)
		if c != nil && (strings.EqualFold(r.Method, "TRACE") || strings.EqualFold(r.Method, "TRACK")) {
			req.Allowed, req.PathRule, req.Outcome = false, EchoMethod, Refused
			t.p.observe(req)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintf(w, "qory: use a method other than TRACE or TRACK on this host.\n"+
				"qory: %s %s%s denied by the gateway: this host gets a credential from the gateway, and the answer to TRACE or TRACK contains the request's headers\n", r.Method, d.Host, accesskey.ShownValue(clean, false))
			return
		}
		r.Header.Del(setBy)
		// Every answer from a host that gets a credential has its value replaced with
		// the placeholder, on a path that gets none as well: the host may send back a
		// value it received before.
		keyed := false
		var mask *masker
		if allowed && c != nil && tl == nil {
			v := c.secret()
			if credentialed && c.carries(r.Header) {
				if name, value, ok := c.header(v); ok {
					r.Header.Set(name, value)
					r.Header.Set(setBy, c.Name)
					req.Credential, keyed = c.Name, true
				}
			}
			mask = c.masker(v)
			clear(v)
		}
		if !allowed {
			req.Outcome = Refused
			t.p.observe(req)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			if rule == AmbiguousPath {
				fmt.Fprintf(w, "qory: %s %s%s denied by the gateway: the path could be read two ways\n", accesskey.ShownValue(r.Method, false), d.Host, accesskey.ShownValue(clean, false))
				return
			}
			fmt.Fprintf(w, "qory: %s %s%s denied by policy (mode %s): no path rule of the run's covers it\n", accesskey.ShownValue(r.Method, false), d.Host, accesskey.ShownValue(clean, false), req.Mode)
			return
		}
		if tl != nil {
			t.toTool(w, r, req, tl)
			return
		}
		// The request is recorded once its outcome is known: when the response's
		// headers arrive, or when the transport fails.
		ctx := context.WithValue(t.p.dialContext(r.Context(), d), pendingKey{}, &pending{d: req, mask: mask})
		if keyed {
			// In the context, since the session's Connection header can take any header
			// off the request before it reaches the transport, the mark among them.
			ctx = context.WithValue(ctx, keyedKey{}, req.Credential)
		}
		if mask == nil {
			rp.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		serveMasked(rp, w, r.WithContext(ctx), mask)
	})
	ln := &once{conn: conn, done: make(chan struct{})}
	srv := &http.Server{Handler: routine.Handler(t.p.reportPanic, handler), ReadHeaderTimeout: t.p.srv.ReadHeaderTimeout, ConnState: func(_ net.Conn, s http.ConnState) {
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
	// mask replaces the credential's value in the answer, when the host gets one.
	mask *masker
}

// masked is the masker of the request's answer, nil when its host gets no credential.
func masked(r *http.Request) *masker {
	if p, ok := r.Context().Value(pendingKey{}).(*pending); ok {
		return p.mask
	}
	return nil
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

// carries reports whether a request's headers carry the credential's placeholder as
// the credential sets its token, or the credential has none.
func (c *Credential) carries(h http.Header) bool {
	if c.Placeholder == "" {
		return true
	}
	name, value, ok := c.header([]byte(c.Placeholder))
	return ok && h.Get(name) == value
}

// secret is a copy of the credential's value as it is now, which the caller clears:
// a credential from the server's opened value, or the token. It is empty when there is
// none.
func (c *Credential) secret() []byte {
	if c.Value != nil {
		return c.Value()
	}
	return []byte(c.Token())
}

// header is the header that carries the value v, which stays the caller's to clear.
// Every buffer this builds is cleared before it returns.
// The header's value is a Go string, since http.Header holds strings: one copy per
// request that cannot be cleared, and the copies the transport makes as it writes the
// request, in its buffers. The request goes over HTTP/1.1 ([Proxy.upstream]), so no
// header compression's table keeps one.
func (c *Credential) header(v []byte) (string, string, bool) {
	if len(v) == 0 {
		return "", "", false
	}
	join := func(prefix string, b []byte) string {
		out := make([]byte, 0, len(prefix)+len(b))
		out = append(append(out, prefix...), b...)
		defer clear(out)
		return string(out)
	}
	switch c.Scheme {
	case "bearer":
		return "Authorization", join("Bearer ", v), true
	case "basic":
		pair := make([]byte, 0, len(c.Username)+1+len(v))
		pair = append(append(append(pair, c.Username...), ':'), v...)
		defer clear(pair)
		enc := make([]byte, base64.StdEncoding.EncodedLen(len(pair)))
		base64.StdEncoding.Encode(enc, pair)
		defer clear(enc)
		return "Authorization", join("Basic ", enc), true
	case "header":
		return c.Header, join("", v), true
	}
	return "", "", false
}

// upstream is the transport to the real hosts of terminated connections: verified
// against this machine's roots, dialled through the proxy's guarded dialler. A request
// the proxy set a credential on goes over HTTP/1.1 alone: over HTTP/2 the connection's
// header table (HPACK) would keep a copy of the credential for as long as it is open.
func (p *Proxy) upstream() http.RoundTripper {
	p.upOnce.Do(func() {
		h1 := new(http.Protocols)
		h1.SetHTTP1(true)
		p.up = &unmark{
			rt:    &http.Transport{Proxy: nil, DialContext: p.dialHost, ForceAttemptHTTP2: true, DisableCompression: true, TLSClientConfig: p.upstreamTLS.Clone(), IdleConnTimeout: idleTimeout},
			keyed: &http.Transport{Proxy: nil, DialContext: p.dialHost, Protocols: h1, DisableCompression: true, TLSClientConfig: p.upstreamTLS.Clone(), IdleConnTimeout: idleTimeout},
		}
	})
	return p.up
}

// keyedKey marks the context of a request the proxy set a credential on, with the
// credential's name.
type keyedKey struct{}

// unmark takes the proxy's own mark off a request before it leaves, and sends a
// request whose context has [keyedKey] by keyed.
type unmark struct{ rt, keyed http.RoundTripper }

// CloseIdleConnections closes the idle connections of both transports.
func (u *unmark) CloseIdleConnections() {
	closeIdle(u.rt)
	closeIdle(u.keyed)
}

// RoundTrip sends the request on without the mark.
func (u *unmark) RoundTrip(r *http.Request) (*http.Response, error) {
	rt := u.rt
	if r.Context().Value(keyedKey{}) != nil {
		rt = u.keyed
	}
	if r.Header.Get(setBy) == "" {
		return rt.RoundTrip(r)
	}
	out := r.Clone(r.Context())
	out.Header.Del(setBy)
	// The trailer is filled once the body is read; a clone's copy would stay empty.
	out.Trailer = r.Trailer
	resp, err := rt.RoundTrip(out)
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
	http.Error(w, "upstream: "+accesskey.ShownError(err).Error(), http.StatusBadGateway)
}

// toTool hands a request the proxy let through to the tool that serves its host, with
// the proxy's own headers, and records it once the tool answered or could not be
// reached. The request goes as the session sent it otherwise, placeholders included:
// what it names beyond its path is the tool's to check.
func (t *terminator) toTool(w http.ResponseWriter, r *http.Request, d Decision, tl *Tool) {
	rule := d.PathRule
	if t.ruled(d.Host) && rule == "" {
		// Observed and let through: the host has rules and none covers the path.
		rule = link.NoPathRule
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
			pr.Out.Header.Set(link.RequestIDHeader, d.RequestID)
			if rule != "" {
				pr.Out.Header.Set(link.PathRuleHeader, rule)
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
