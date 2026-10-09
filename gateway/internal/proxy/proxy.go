// Package proxy is the HTTP proxy the session is started behind.
//
// The proxy listens on a loopback port, or on the address a wall asks for, and the
// session's environment names it in the proxy variables, upper and lower case, with
// loopback in NO_PROXY so a local server still answers. Every connection through it is
// one [Decision] handed to an observer: a CONNECT tunnel, decided on its authority, or a
// plain request, decided on the authority of its absolute-form target. A host a deny
// entry matches is denied with 403 in either mode, and nothing is opened for it; past
// that, in observe mode every decision allows, and in enforce mode a host no allow
// entry matches is denied the same way. The session continues either way. A decision
// says what became of the connection as its outcome: dialled, or not dialled because
// it was refused, or dialled and failed.
//
// The policy the proxy decides by is the one it was started with until [Proxy.SetPolicy]
// replaces it: a run whose server sends a new run configuration reloads it this way,
// for new connections at once, and a tunnel open to a host the new policy denies is
// closed and recorded as refused.
//
// A proxy that serves an enclosure is guarded ([Proxy.Guard]): it dials from this
// machine on behalf of something that is not on it, so what is on this machine is not
// reached by default. The link-local range, which holds a cloud's metadata service, is
// refused whatever the policy says. This machine's own addresses, loopback and every
// address an interface holds, are refused unless an allow entry names the host itself,
// not a *. suffix over it: a local MCP server or model endpoint is reached through the
// proxy like everything else, decided and recorded, when the policy names it, in either
// mode. Without the guard the way around a wall is through the proxy.
//
// Behind a wall, for the hosts [Proxy.Terminate] is given, the proxy ends the session's
// TLS itself, reads each request's path and sets a credential on it, or hands it to the
// tool that serves the host. For every other host the proxy sees host names and ports
// and never the content of a TLS connection: a tunnel is a blind relay once
// established. Only a proxy-aware program is seen.
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// The outcomes of a connection, [Decision.Outcome].
const (
	// Connected says the dial succeeded.
	Connected = "connected"
	// DialFailed says the connection was allowed and the dial failed.
	DialFailed = "dial_failed"
	// Refused says nothing was dialled: the policy or the guard denied the connection,
	// or a reload closed it.
	Refused = "refused"
)

// Decision is one connection the session asked for and what the proxy did with it.
type Decision struct {
	Host string
	Port int
	// Method is "CONNECT" for a tunnel, "HTTP" for a plain request.
	Method  string
	Allowed bool
	// Rule is the deny or allow entry that matched, the guard's rule when the guard
	// refused, or empty when none did.
	Rule string
	// Mode is the policy mode the decision was made under.
	Mode policy.Mode
	// Outcome is [Connected], [DialFailed] or [Refused].
	Outcome string
	// RequestMethod, Path and PathRule are a request's inside a connection the proxy
	// terminates, where Method is "HTTPS", or a plain request's to a host with path
	// rules; Credential names the credential the proxy set on it, if it set one.
	RequestMethod, Path, PathRule, Credential string
	// Tool names the tool the proxy handed the request to, when the host is one a tool
	// serves.
	Tool string
	// RequestID is the proxy's own id of a request it read, the one a tool is handed as
	// [link.RequestIDHeader]; Status is the status the host or the tool answered it with,
	// zero when nothing answered.
	RequestID string
	Status    int
}

// rules is what the proxy decides by: the policy's mode, allow list and deny list, and
// the hosts a guarded proxy reaches on this machine. It is replaced whole, never
// changed.
type rules struct {
	mode  policy.Mode
	allow []string
	// deny is decided before allow and before the mode: a host it covers is denied in
	// either mode.
	deny []string
	// opened are the entries of the allow list that name a host, as its owner wrote
	// them: a *. suffix opens nothing on this machine.
	opened []string
}

// Proxy is a listening proxy.
type Proxy struct {
	rules   atomic.Pointer[rules]
	observe func(Decision)
	ln      net.Listener
	srv     *http.Server
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	wg      sync.WaitGroup
	guarded atomic.Bool
	// token, when set, is what every connection must open with; refused is told of one
	// that did not.
	token   atomic.Pointer[string]
	refused func()
	// term, when set, says which hosts the proxy terminates TLS for.
	term atomic.Pointer[terminator]
	// node are the node's path rules, set before term and fixed for the run.
	node        map[string][]string
	up          http.RoundTripper
	upOnce      sync.Once
	upstreamTLS *tls.Config
	// tunnels are the connections open through the proxy, by the decision that opened
	// each, so a reload can close what the new policy denies.
	tmu     sync.Mutex
	tunnels map[*tunnel]struct{}
}

// tunnel is one open connection: the decision that opened it and the ends to close.
type tunnel struct {
	d     Decision
	conns []net.Conn
	// terminated says the proxy ends the connection's TLS itself and sets the
	// credential for its host on the requests inside it.
	terminated bool
}

// GuardRule is the rule a guarded proxy's denial names in its decision: not an allow
// entry, the wall's own refusal.
const GuardRule = "wall:own-address"

// guardError is the guard's refusal at dial time, of a name that resolved to an
// address the guard does not dial.
type guardError struct{ msg string }

func (e *guardError) Error() string { return e.msg }

// Listen starts a proxy on addr, host:port, in the given mode with the given allow
// and deny lists, handing every decision to observe. An empty addr is [link.Loopback];
// port 0 is a port of the system's choosing. Close stops it.
func Listen(addr string, mode policy.Mode, allow, deny []string, observe func(Decision)) (*Proxy, error) {
	if err := mode.Validate(); err != nil {
		return nil, err
	}
	if addr == "" {
		addr = link.Loopback
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	p := &Proxy{observe: observe, ln: ln, tunnels: map[*tunnel]struct{}{}}
	p.rules.Store(&rules{mode: mode, allow: allow, deny: deny})
	gate := &gate{Listener: ln, p: p}
	// The guard checks the address a name resolved to, at the moment of the connection,
	// so a name that resolves to this machine is refused like the address itself.
	d := &net.Dialer{Timeout: 30 * time.Second, ControlContext: func(ctx context.Context, _, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil || !p.guarded.Load() {
			return nil
		}
		switch ip := net.ParseIP(host); {
		case linkLocal(ip):
			return &guardError{host + " is a link-local address; the wall refuses it"}
		case own(ip) && ctx.Value(namedKey{}) == nil:
			return &guardError{host + " is this machine's own address and no allow entry names the host; the wall refuses it"}
		}
		return nil
	}}
	p.dial = d.DialContext
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 30 * time.Second}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.srv.Serve(gate)
	}()
	return p, nil
}

// Addr is the address the proxy listens on, host:port.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// URL is the proxy's URL for the proxy variables.
func (p *Proxy) URL() string { return "http://" + p.Addr() }

// Env returns the variables that point a program at the proxy, by the address it
// listens on.
func (p *Proxy) Env() []string { return link.ProxyEnv(p.URL()) }

// Close stops the listener and every tunnel.
func (p *Proxy) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := p.srv.Shutdown(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		err = p.srv.Close()
	}
	p.wg.Wait()
	return err
}

// Guard makes the proxy refuse the link-local range, and this machine's own addresses
// unless the host is one of names: the entries of the policy's allow list, as its
// owner wrote them. Entries that are *. suffixes are ignored. The session calls
// Guard once, before it starts anything behind a wall; a policy set later brings its
// own names.
func (p *Proxy) Guard(names []string) {
	r := *p.rules.Load()
	r.opened = opened(names)
	p.rules.Store(&r)
	p.guarded.Store(true)
}

// opened are the entries of an allow list that name a host itself.
func opened(names []string) []string {
	var out []string
	for _, n := range names {
		if !strings.HasPrefix(n, "*.") {
			out = append(out, n)
		}
	}
	return out
}

// Terminates reports whether [Proxy.Terminate] was called: whether the proxy has the
// run's authority, without which it holds no host to paths and sets no credential.
func (p *Proxy) Terminates() bool { return p.term.Load() != nil }

// SetPolicy replaces the policy the proxy decides by: the mode, the allow list and the
// deny list for every decision from now on, the guard's names with them when the
// proxy is guarded,
// and, in one step with them, the path rules and the credentials of the hosts it
// terminates. Without a terminator, [Proxy.Terminates], paths and credentials are not
// applied, and the caller must not pass a policy that relies on them. A tunnel open to
// a host the new policy denies is closed, and the decisions that denied them are
// returned, refused, for the caller to record: the caller writes the policy's own event
// first and these after it. A terminated connection to a host whose credential is
// another one now, or none, is closed as well and not recorded, since nothing was
// denied: the next connection carries what the new policy selects.
func (p *Proxy) SetPolicy(mode policy.Mode, allow, deny []string, paths map[string][]string, creds []Credential) (refused []Decision) {
	r := &rules{mode: mode, allow: allow, deny: deny}
	if p.guarded.Load() {
		r.opened = opened(allow)
	}
	before := p.term.Load()
	var after *terminator
	if before != nil {
		nt := *before
		nt.paths, nt.creds = paths, creds
		after = &nt
	}
	// The terminator first: a connection decided under the new rules finds the new
	// credentials, never the old ones.
	if after != nil {
		p.term.Store(after)
	}
	p.rules.Store(r)
	p.tmu.Lock()
	open := make([]*tunnel, 0, len(p.tunnels))
	for t := range p.tunnels {
		open = append(open, t)
	}
	p.tmu.Unlock()
	for _, t := range open {
		d := p.decide(t.d.Method, t.d.Host, t.d.Port)
		switch {
		case !d.Allowed:
			refused = append(refused, d)
		case t.terminated && before.credentialName(t.d.Host) != after.credentialName(t.d.Host):
		default:
			continue
		}
		for _, c := range t.conns {
			c.Close()
		}
	}
	return refused
}

// track remembers an open connection until untrack.
func (p *Proxy) track(d Decision, terminated bool, conns ...net.Conn) *tunnel {
	t := &tunnel{d: d, conns: conns, terminated: terminated}
	p.tmu.Lock()
	p.tunnels[t] = struct{}{}
	p.tmu.Unlock()
	return t
}

// untrack forgets a connection that ended.
func (p *Proxy) untrack(t *tunnel) {
	p.tmu.Lock()
	delete(p.tunnels, t)
	p.tmu.Unlock()
}

// namedKey marks the context of a connection whose host an allow entry names itself.
type namedKey struct{}

// named reports whether the policy's owner named the host, which alone opens this
// machine to an enclosure, and the connection is one the allow list lets through.
func (p *Proxy) named(host string, allowed bool) bool {
	_, ok := policy.Match(p.rules.Load().opened, host)
	return ok && allowed
}

// linkLocal reports whether ip is in the range a guarded proxy never dials.
func linkLocal(ip net.IP) bool {
	return ip != nil && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast())
}

// own reports whether ip is this machine's: loopback, unspecified, or an address one of
// its interfaces holds.
func own(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// decide applies the guard, the deny list, and then the mode and the allow list to a
// host. The guard decides here what it can without resolving, a literal address and
// localhost, so the denial is in the record; a name that resolves to such an address
// is refused when dialled. A host the deny list covers is denied in either mode, with
// the entry as its rule, before the mode and the allow list are consulted. A denied
// decision is refused; an allowed one has no outcome until it is dialled.
func (p *Proxy) decide(method, host string, port int) Decision {
	r := p.rules.Load()
	rule, ok := policy.Match(r.allow, host)
	d := Decision{Host: strings.ToLower(host), Port: port, Method: method, Mode: r.mode}
	if p.guarded.Load() {
		ip := net.ParseIP(host)
		local := strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") || own(ip)
		if linkLocal(ip) || (local && !p.named(host, ok)) {
			d.Rule, d.Outcome = GuardRule, Refused
			return d
		}
	}
	if denied, ok := policy.Match(r.deny, host); ok {
		d.Rule, d.Outcome = denied, Refused
		return d
	}
	d.Allowed, d.Rule = ok || r.mode == policy.Observe, rule
	if !d.Allowed {
		d.Outcome = Refused
	}
	return d
}

// failed fills in a decision whose dial or request failed: the guard's refusal at dial
// time is a denial by the guard, a dial that failed is one, and any other failure came
// after the dial.
func failed(d Decision, err error) Decision {
	var ge *guardError
	var op *net.OpError
	switch {
	case errors.As(err, &ge):
		d.Allowed, d.Rule, d.Outcome = false, GuardRule, Refused
	case errors.As(err, &op) && op.Op == "dial":
		d.Outcome = DialFailed
	default:
		d.Outcome = Connected
	}
	return d
}

// ServeHTTP handles one proxy request: a CONNECT, or a plain request with an
// absolute-form target. Anything else is a 400.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	if r.URL.Host == "" || r.URL.Scheme == "" {
		http.Error(w, "the proxy takes an absolute-form request target", http.StatusBadRequest)
		return
	}
	host := r.URL.Hostname()
	port, err := portOf(r.URL.Port(), r.URL.Scheme)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d := p.decide("HTTP", host, port)
	d.RequestID = newRequestID()
	term := p.term.Load()
	if d.Allowed {
		if clean, rule, ok := term.plainPath(d.Host, r.URL.EscapedPath()); clean != "" {
			d.RequestMethod, d.Path, d.PathRule, d.Allowed = r.Method, clean, rule, ok
			if !ok {
				d.Outcome = Refused
			}
		}
	}
	// A tool is named on a request the proxy decided by path, handed to the tool or
	// refused by a rule; a host the policy refuses reaches no tool, as a tunnel's does not.
	var tl *Tool
	if d.Path != "" {
		if tl = term.tool(d.Host); tl != nil {
			d.Tool = tl.Name
		}
	}
	if !d.Allowed {
		p.observe(d)
		deny(w, d)
		return
	}
	if tl != nil {
		// A tool is reached on its socket whatever the scheme; the host is never dialled.
		term.toTool(w, r, d, tl)
		return
	}
	out := r.Clone(p.dialContext(r.Context(), d))
	out.RequestURI = ""
	out.Host = r.URL.Host
	for _, h := range hopByHop {
		out.Header.Del(h)
	}
	resp, err := p.transport().RoundTrip(out)
	if err != nil {
		d = failed(d, err)
		p.observe(d)
		if !d.Allowed {
			deny(w, d)
			return
		}
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	d.Outcome, d.Status = Connected, resp.StatusCode
	p.observe(d)
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// connect opens a tunnel, or refuses it with a 403 before anything is dialled.
func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	host, portText, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "CONNECT takes host:port", http.StatusBadRequest)
		return
	}
	port, err := portOf(portText, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d := p.decide(http.MethodConnect, host, port)
	if !d.Allowed {
		p.observe(d)
		deny(w, d)
		return
	}
	if p.term.Load().covers(d.Host) {
		// A terminated connection is recorded request by request instead.
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		client, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		// Tracked before the client hears 200: a reload that lands once the client has
		// the line, and before the tunnel is on the list, would otherwise miss it.
		t := p.track(d, true, client)
		defer p.untrack(t)
		if _, err := buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err == nil {
			err = buf.Flush()
		}
		if err != nil || buf.Reader.Buffered() > 0 {
			client.Close()
			return
		}
		p.term.Load().serve(context.WithoutCancel(r.Context()), client, d, net.JoinHostPort(host, portText))
		return
	}
	upstream, err := p.dial(p.dialContext(r.Context(), d), "tcp", net.JoinHostPort(host, portText))
	if err != nil {
		d = failed(d, err)
		p.observe(d)
		if !d.Allowed {
			deny(w, d)
			return
		}
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	d.Outcome = Connected
	p.observe(d)
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	// Tracked before the client hears 200, for the same reason as above.
	t := p.track(d, false, client, upstream)
	defer p.untrack(t)
	if _, err := buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err == nil {
		err = buf.Flush()
	}
	if err != nil {
		client.Close()
		upstream.Close()
		return
	}
	relay(client, upstream, buf.Reader.Buffered(), buf.Reader)
}

// relay copies both ways and closes both ends when either side closes.
func relay(client, upstream net.Conn, buffered int, r io.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if buffered > 0 {
			io.CopyN(upstream, r, int64(buffered))
		}
		io.Copy(upstream, client)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		io.Copy(client, upstream)
		closeWrite(client)
	}()
	wg.Wait()
	client.Close()
	upstream.Close()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

// dialContext carries into the dial whether the policy names the host, which is what
// lets a guarded proxy reach this machine for it.
func (p *Proxy) dialContext(ctx context.Context, d Decision) context.Context {
	if p.named(d.Host, d.Rule != "") {
		return context.WithValue(ctx, namedKey{}, true)
	}
	return ctx
}

// deny answers a refused connection: 403 with one line naming the host and the mode.
func deny(w http.ResponseWriter, d Decision) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	if d.Rule == GuardRule {
		fmt.Fprintf(w, "qory: egress to %s:%d denied by the gateway: link-local addresses are never reached through it, and the gateway's own machine only for a host the policy's allow list names\n", d.Host, d.Port)
		return
	}
	fmt.Fprintf(w, "qory: egress to %s:%d denied by policy (mode %s)\n", d.Host, d.Port, d.Mode)
}

func portOf(text, scheme string) (int, error) {
	if text == "" {
		switch scheme {
		case "https":
			return 443, nil
		case "http":
			return 80, nil
		}
		return 0, errors.New("no port")
	}
	n, err := strconv.Atoi(text)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", text)
	}
	return n, nil
}

var hopByHop = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// transport forwards plain requests upstream, directly and never through another proxy.
func (p *Proxy) transport() *http.Transport {
	return &http.Transport{Proxy: nil, DialContext: p.dial, DisableCompression: true}
}
