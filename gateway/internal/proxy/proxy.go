// Package proxy is the HTTP proxy the session is started behind.
//
// The proxy listens on a loopback port, or on the address a wall asks for, and the
// session's environment names it in the proxy variables, upper and lower case, with
// loopback in NO_PROXY so a local server still answers. Every connection through it is
// one [Decision] handed to an observer: a CONNECT tunnel, decided on its authority, or a
// plain request, decided on the authority of its absolute-form target. A host is
// decided and dialled in the form [policy.Host] gives it, a name with no search domain
// added: rooted, with one trailing dot, or, a name of one label the hosts file holds,
// at the addresses the file gives it ([Proxy.dialHost]). A host without that form is
// refused with 403 in either mode before any list is read, with the rule [HostForm]. A
// host an allow_first entry matches exactly is allowed in either mode, before the deny
// list and the allow list are read ([Proxy.AllowFirst]). Past that, a host a deny entry
// matches is denied with 403 in either mode, and nothing is opened for it; then, in
// observe mode every decision allows, and in enforce mode a host no allow entry matches
// is denied the same way. The session continues either way. A decision says what
// became of the connection as its outcome: connected, refused, or allowed and the dial
// failed; no address the guard refuses is dialled.
//
// The policy the proxy decides by is the one it was started with until [Proxy.SetPolicy]
// replaces it: a run whose server sends a new run configuration reloads it this way,
// for new connections at once, and a tunnel open to a host the new policy denies is
// closed and recorded as refused.
//
// A run's limits ([Proxy.SetLimits]) bound what one run takes of a gateway that other
// runs share: the connections it has open at once, refused with 429 at once past the
// limit, and the requests it sends a second, a token bucket a request waits up to
// [RateWait] on before it is refused with 429. A refusal is recorded at most once a
// second per limit, with the rule [ConnectionLimit] or [RateLimit].
//
// A proxy that serves an enclosure is guarded ([Proxy.Guard]): it dials from this
// machine on behalf of something that is not on it, so what is on this machine is not
// reached by default. The link-local range, which holds a cloud's metadata service, and
// the cloud metadata addresses outside it ([metadataAddrs]) are refused whatever the
// policy says. This machine's own addresses, loopback and every address an interface
// holds, and the private network addresses ([privateRanges]) are refused unless one of
// the guard's names is the host itself, not a *. suffix over it, and the allow list or
// the allow_first list allows the host. The gateway takes the names from the node's
// policy alone: a local MCP server or model endpoint is reached through the proxy like
// everything else, decided and recorded, in either mode, when the node's policy names
// it and the run's allow list or the allow_first list allows it. Under a session's
// narrowing of a policy that observes, the gateway passes no name, and none of these
// addresses is reached. A reload after which the policy no longer opens these addresses
// to a host closes the connections to that host ([Proxy.SetPolicyOpening]). Without the
// guard the way around a wall is through the proxy.
//
// Behind a wall, for the hosts [Proxy.Terminate] is given, the proxy ends the session's
// TLS itself, reads each request's path and sets a credential on it, or hands it to the
// tool that serves the host. In what a host that gets a credential answers, the
// credential's value is replaced with the placeholder. For every other host the proxy sees host names and ports
// and never the content of a TLS connection: a tunnel is a blind relay once
// established. Only a proxy-aware program is seen.
//
// One run's proxy listens on its own address ([Listen]), or many runs share one
// [Listener]: each run's proxy is made without a listener ([New]) and registered under
// the run's secret ([NewSecret]), every connection opens with [link.RelayPreamble] and
// that secret, and is served by that run's proxy alone. A connection that names no live
// run's secret is closed unanswered.
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/routine"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// The outcomes of a connection, [Decision.Outcome].
const (
	// Connected says the dial succeeded.
	Connected = "connected"
	// DialFailed says the connection was allowed and the dial failed.
	DialFailed = "dial_failed"
	// Refused says the policy or the guard denied the connection, or a reload closed it;
	// no address the guard refuses is dialled.
	Refused = "refused"
)

// Decision is one connection the session asked for and what the proxy did with it.
type Decision struct {
	Host string
	Port int
	// Method is "CONNECT" for a tunnel, "HTTP" for a plain request.
	Method  string
	Allowed bool
	// Rule is the allow_first, deny or allow entry that matched, the guard's rule when
	// the guard refused, [HostForm] or [PlainRequest] when the proxy refused, or empty
	// when none did.
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

// rules is what the proxy decides by: the policy's mode, allow_first list, allow list
// and deny list, and the hosts a guarded proxy reaches on this machine or at a private
// network address. It is replaced whole, never changed.
type rules struct {
	mode  policy.Mode
	allow []string
	// first is decided before deny, allow and the mode: a host an entry matches
	// exactly is allowed in either mode.
	first []string
	// deny is decided before allow and before the mode, after first: a host it covers
	// and first does not list is denied in either mode.
	deny []string
	// opened are the guard's names that name a host itself, which the gateway takes
	// from the node's policy's allow list: a *. suffix opens nothing on this machine or
	// at a private network address, and a host is opened only when the allow list or
	// the allow_first list matches it as well.
	opened []string
}

// Proxy is one run's proxy: listening on its own address ([Listen]), or served the
// run's connections by a [Listener] shared with other runs ([New]).
type Proxy struct {
	rules   atomic.Pointer[rules]
	observe func(Decision)
	// ln is the proxy's own listener, from [Listen]; in is where a [Listener] hands a
	// proxy [New] made its connections. One of the two is set.
	ln      net.Listener
	in      *inbox
	srv     *http.Server
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	hosts   func(ctx context.Context, name string) ([]netip.Addr, error)
	wg      sync.WaitGroup
	guarded atomic.Bool
	// token, when set, is what every connection must open with; refused is told of one
	// that did not.
	token   atomic.Pointer[string]
	refused func()
	// term, when set, says which hosts the proxy terminates TLS for.
	term atomic.Pointer[terminator]
	// node are the sides of path rules beside the policy's, set before term and fixed
	// for the run.
	node        []map[string][]string
	up          http.RoundTripper
	upOnce      sync.Once
	upstreamTLS *tls.Config
	// tunnels are the connections open through the proxy, by the decision that opened
	// each, so a reload can close what the new policy denies.
	tmu     sync.Mutex
	tunnels map[*tunnel]struct{}
	// shut says Close has closed the tunnels: one tracked after is closed at once.
	shut bool
	// dialled are the connections dialled for one of the guard's names, so a reload
	// that takes the name's opening away can close them, idle or in use.
	dialled map[*namedConn]struct{}
	// stopped ends with Close, and with it the requests a terminated tunnel sends on.
	stopped context.Context
	stop    context.CancelFunc
	// panics, when set, gets a panic of the proxy's goroutines ([Proxy.ReportPanics]).
	panics atomic.Pointer[func(string)]
	// limits, when set, are the run's limits and counters ([Proxy.SetLimits]).
	limits atomic.Pointer[limiter]
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

// HostForm is the rule a denial names when the host has no form [policy.Host] gives: not
// an allow or deny entry, the proxy's refusal, in either mode.
const HostForm = "wall:host-form"

// PlainRequest is the rule a denial names of a plain request, http:// or an
// absolute-form https:// sent without CONNECT, to a host a credential is for and the
// policy allows: the proxy
// sets the credential, and replaces it in answers, only inside a CONNECT it
// terminates. A refusal of the proxy's, in either mode, before anything is sent.
const PlainRequest = "wall:plain-request"

// guardError is the guard's refusal at dial time, of a name that resolved to an
// address the guard does not dial.
type guardError struct{ msg string }

func (e *guardError) Error() string { return e.msg }

// Listen starts a proxy on addr, host:port, in the given mode with the given allow
// and deny lists, handing every decision to observe. An empty addr is [link.Loopback];
// port 0 is a port of the system's choosing. Close stops it.
func Listen(addr string, mode policy.Mode, allow, deny []string, observe func(Decision)) (*Proxy, error) {
	p, err := newProxy(mode, allow, deny, observe)
	if err != nil {
		return nil, err
	}
	if addr == "" {
		addr = link.Loopback
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	p.ln = ln
	p.serve(&gate{Listener: ln, p: p})
	return p, nil
}

// New makes one run's proxy, in the given mode with the given allow and deny lists,
// handing every decision to observe, without a listener of its own: it serves the
// connections a [Listener] hands it once it is registered there under the run's
// secret. It has no address, so Addr, URL and Env are empty. Close stops it.
func New(mode policy.Mode, allow, deny []string, observe func(Decision)) (*Proxy, error) {
	p, err := newProxy(mode, allow, deny, observe)
	if err != nil {
		return nil, err
	}
	p.in = newInbox()
	p.serve(p.in)
	return p, nil
}

// newProxy makes a proxy that serves nothing yet.
func newProxy(mode policy.Mode, allow, deny []string, observe func(Decision)) (*Proxy, error) {
	if err := mode.Validate(); err != nil {
		return nil, err
	}
	p := &Proxy{observe: observe, tunnels: map[*tunnel]struct{}{}, dialled: map[*namedConn]struct{}{}}
	p.stopped, p.stop = context.WithCancel(context.Background())
	p.rules.Store(&rules{mode: mode, allow: allow, deny: deny})
	// The guard checks the address a name resolved to, at the moment of the connection,
	// so a name that resolves to this machine is refused like the address itself.
	d := &net.Dialer{Timeout: 30 * time.Second, ControlContext: func(ctx context.Context, _, address string, _ syscall.RawConn) error {
		return p.guard(ctx, address)
	}}
	p.dial = d.DialContext
	p.hosts = hostsFile
	// A panic is reported without its value, which net/http would log.
	p.srv = &http.Server{Handler: routine.Handler(p.reportPanic, p), ReadHeaderTimeout: 30 * time.Second}
	return p, nil
}

// guard is the wall's check of the address a connection is about to dial, host:port:
// nil when it may be dialled. An unguarded proxy dials every address. Behind a wall the
// address is judged as itself, an IPv6 address without its zone, and one that does not
// read as an address is refused, never dialled unjudged. An address that carries an
// IPv4 address ([carried]) is also judged by that IPv4 address, and refused where it
// would be; an address with more than one position for it, by each.
func (p *Proxy) guard(ctx context.Context, address string) error {
	if !p.guarded.Load() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return &guardError{address + " does not read as an address; the gateway refuses it"}
	}
	ip := unzoned(host)
	if ip == nil {
		return &guardError{host + " does not read as an address; the gateway refuses it"}
	}
	if err := judge(ctx, host, ip); err != nil {
		return err
	}
	// A link-local or metadata address first, which no name opens: the error for one
	// is the error it gets inside 64:ff9b::/96, whatever the other positions read.
	inside := carried(ip)
	opened := context.WithValue(ctx, namedKey{}, true)
	for _, v4 := range inside {
		if err := judge(opened, v4.String(), v4); err != nil {
			return err
		}
	}
	for _, v4 := range inside {
		if err := judge(ctx, v4.String(), v4); err != nil {
			return err
		}
	}
	return nil
}

// judge is the guard's refusal of ip, written as host, or nil when it may be dialled.
func judge(ctx context.Context, host string, ip net.IP) error {
	switch {
	case linkLocal(ip):
		return &guardError{host + " is a link-local address; the gateway refuses it"}
	case metadata(ip):
		return &guardError{"Use another host: the gateway refuses the cloud metadata address " + host}
	case own(ip) && ctx.Value(namedKey{}) == nil:
		return &guardError{host + " is this machine's address and no allow entry lists the host by name; the gateway refuses it"}
	case private(ip) && ctx.Value(namedKey{}) == nil:
		return &guardError{"List the host by name in the allow list of the node's policy: " + host + " is a private network address, and the gateway dials one only for a host listed there by name"}
	}
	return nil
}

// carriers are the IPv6 ranges whose addresses the guard also judges by an IPv4 address
// inside them, each with the bytes of the address that IPv4 address is read from:
//   - ::/96, the IPv4-compatible addresses; ::ffff:0:0:0/96, the IPv4-translated ones;
//     and 64:ff9b::/96, the well-known NAT64 prefix: the last 32 bits.
//   - 2002::/16, 6to4 (RFC 3056): bits 16 to 47.
//   - 64:ff9b:1::/48, the local-use NAT64 prefix (RFC 8215): each position RFC 6052,
//     section 2.2, defines for an IPv4 address after a prefix of 48, 56, 64 or 96 bits,
//     with bits 64 to 71, the u octet, skipped.
//
// An IPv4 address mapped into IPv6, ::ffff:0:0/96, is judged as IPv4 already.
var carriers = []struct {
	prefix netip.Prefix
	at     [][4]int
}{
	{netip.MustParsePrefix("::/96"), [][4]int{{12, 13, 14, 15}}},
	{netip.MustParsePrefix("::ffff:0:0:0/96"), [][4]int{{12, 13, 14, 15}}},
	{netip.MustParsePrefix("64:ff9b::/96"), [][4]int{{12, 13, 14, 15}}},
	{netip.MustParsePrefix("2002::/16"), [][4]int{{2, 3, 4, 5}}},
	{netip.MustParsePrefix("64:ff9b:1::/48"), [][4]int{{6, 7, 9, 10}, {7, 9, 10, 11}, {9, 10, 11, 12}, {12, 13, 14, 15}}},
}

// carried are the IPv4 addresses inside ip, one per position, when ip is in one of
// [carriers], or none. :: and ::1 carry none: they are this machine's as they are.
func carried(ip net.IP) []net.IP {
	a, ok := netip.AddrFromSlice(ip)
	if !ok || !a.Is6() || a.Is4In6() || a.IsUnspecified() || a.IsLoopback() {
		return nil
	}
	b := a.As16()
	for _, c := range carriers {
		if !c.prefix.Contains(a) {
			continue
		}
		out := make([]net.IP, 0, len(c.at))
		for _, at := range c.at {
			out = append(out, net.IPv4(b[at[0]], b[at[1]], b[at[2]], b[at[3]]))
		}
		return out
	}
	return nil
}

// unzoned is the IP address host reads as once any zone, from its first %, is cut off,
// or nil when it reads as none.
func unzoned(host string) net.IP {
	host, _, _ = strings.Cut(host, "%")
	return net.ParseIP(host)
}

// serve serves the proxy's connections from ln until Close.
func (p *Proxy) serve(ln net.Listener) {
	p.wg.Add(1)
	routine.Go(p.reportPanic, func() {
		defer p.wg.Done()
		p.srv.Serve(ln)
	})
}

// ReportPanics sets where a panic of the proxy's goroutines is reported: the gateway
// passes its report under the run's id. Unset, the report goes to standard error.
func (p *Proxy) ReportPanics(report func(string)) { p.panics.Store(&report) }

// reportPanic reports a panic of the proxy's goroutines where [Proxy.ReportPanics] set
// when the panic came.
func (p *Proxy) reportPanic(line string) {
	if r := p.panics.Load(); r != nil {
		(*r)(line)
		return
	}
	routine.Stderr(line)
}

// Addr is the address the proxy listens on, host:port, or empty for a proxy [New]
// made, which a [Listener] hands its connections to.
func (p *Proxy) Addr() string {
	if p.ln == nil {
		return ""
	}
	return p.ln.Addr().String()
}

// URL is the proxy's URL for the proxy variables, or empty for a proxy without an
// address of its own.
func (p *Proxy) URL() string {
	if p.ln == nil {
		return ""
	}
	return "http://" + p.Addr()
}

// Env returns the variables that point a program at the proxy, by the address it
// listens on, or none for a proxy without an address of its own.
func (p *Proxy) Env() []string {
	if p.ln == nil {
		return nil
	}
	return link.ProxyEnv(p.URL())
}

// Close stops the listener and every tunnel: both ends of each connection the proxy
// relays, and the client's end of each it terminates, with the requests it sends on
// for it. A tunnel the proxy would track after Close is closed at once.
func (p *Proxy) Close() error {
	p.tmu.Lock()
	p.shut = true
	open := make([]*tunnel, 0, len(p.tunnels))
	for t := range p.tunnels {
		open = append(open, t)
	}
	p.tmu.Unlock()
	p.stop()
	for _, t := range open {
		for _, c := range t.conns {
			c.Close()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := p.srv.Shutdown(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		err = p.srv.Close()
	}
	p.wg.Wait()
	// No pooled connection outlives the run: one to a terminated host may have carried
	// the run's credential. A connection that goes idle later is closed as it does.
	closeIdle(p.upstream())
	if t := p.term.Load(); t != nil {
		for _, tl := range t.tools {
			closeIdle(tl.transport)
		}
	}
	return err
}

// idleTimeout is how long a pooled upstream connection waits for the next request
// before it is closed; the run's end closes every idle one at once ([Proxy.Close]).
const idleTimeout = 90 * time.Second

// closeIdle closes rt's idle connections, when it has any to close.
func closeIdle(rt http.RoundTripper) {
	if c, ok := rt.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// Guard makes the proxy refuse the link-local range and the cloud metadata addresses
// outside it ([metadataAddrs]), and this machine's addresses and the private network
// addresses ([privateRanges]) unless the host is one of names and the allow list or
// the allow_first list allows it. The gateway passes entries of the node's policy's
// allow list, as its owner wrote them, never a server's policy's. Entries that are *.
// suffixes are ignored. The session calls Guard once, before it starts anything behind
// a wall; a policy set later brings its own names.
func (p *Proxy) Guard(names []string) {
	r := *p.rules.Load()
	r.opened = opened(names)
	p.rules.Store(&r)
	p.guarded.Store(true)
}

// AllowFirst sets the allow_first list the proxy decides by, before it serves a
// connection: a host an entry matches exactly ([policy.Exact]) is allowed in either
// mode before the deny list and the allow list are read, with the entry as its rule.
// The guard, the host's form, the limits and the path rules still apply.
// [Proxy.SetPolicyOpening] replaces it with the rest of the policy.
func (p *Proxy) AllowFirst(entries []string) {
	r := *p.rules.Load()
	r.first = entries
	p.rules.Store(&r)
}

// Guarded reports whether [Proxy.Guard] was called.
func (p *Proxy) Guarded() bool { return p.guarded.Load() }

// ServeConn hands c to a proxy [New] made, as a [Listener] hands it a connection past
// its preamble: the proxy reads c's first request from its first byte. A proxy with a
// listener of its own takes none, and c is closed.
func (p *Proxy) ServeConn(c net.Conn) {
	if p.in == nil {
		c.Close()
		return
	}
	p.in.deliver(c)
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
// deny list for every decision from now on, with no allow_first list, the guard's
// names with them when the proxy is guarded, and, in one step with them, the path rules and the credentials of the hosts it
// terminates. Without a terminator, [Proxy.Terminates], paths and credentials are not
// applied, and the caller must not pass a policy that relies on them. A tunnel open to
// a host the new policy denies is closed, and the decisions that denied them are
// returned, refused, for the caller to record: the caller writes the policy's own event
// first and these after it. A terminated connection to a host whose credential is
// another one now, or none, is closed as well and not recorded, since nothing was
// denied: the next connection carries what the new policy selects. So is a connection
// to a host whose path rules are other ones now: the next connection is held to the
// new rules. A host whose path rules are equal keeps its connections. A guarded proxy
// also closes, without a record, the tunnels to a host for which the new policy no
// longer opens this machine's addresses and the private network addresses
// ([rules.opens]), and every connection dialled for that host, idle or in use: the next
// one is judged by the guard under the new policy. A host that keeps its opening, or
// keeps none, keeps its connections.
func (p *Proxy) SetPolicy(mode policy.Mode, allow, deny []string, paths map[string][]string, creds []Credential) (refused []Decision) {
	return p.SetPolicyOpening(mode, nil, allow, deny, allow, paths, creds)
}

// SetPolicyOpening is [Proxy.SetPolicy] with the allow_first list, first, and with
// the guard's names apart from the allow list: names, which the gateway takes from the
// node's policy's allow list, alone open this machine's addresses and the private
// network addresses when the proxy is guarded, and only for a host the allow list or
// first allows as well.
func (p *Proxy) SetPolicyOpening(mode policy.Mode, first, allow, deny, names []string, paths map[string][]string, creds []Credential) (refused []Decision) {
	r := &rules{mode: mode, allow: allow, first: first, deny: deny}
	if p.guarded.Load() {
		r.opened = opened(names)
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
	old := p.rules.Swap(r)
	p.tmu.Lock()
	open := make([]*tunnel, 0, len(p.tunnels))
	for t := range p.tunnels {
		open = append(open, t)
	}
	// A connection put on the list after this finds the new rules when it is dialled
	// ([Proxy.dialHost]).
	var closing []*namedConn
	for c := range p.dialled {
		if !r.opens(c.host) {
			closing = append(closing, c)
		}
	}
	p.tmu.Unlock()
	for _, c := range closing {
		c.Close()
	}
	for _, t := range open {
		d := p.decide(t.d.Method, t.d.Host, t.d.Port)
		switch {
		case !d.Allowed:
			refused = append(refused, d)
		case t.terminated && before.credentialName(t.d.Host) != after.credentialName(t.d.Host):
		case !before.samePaths(after, t.d.Host):
		case old.opens(t.d.Host) && !r.opens(t.d.Host):
		default:
			continue
		}
		for _, c := range t.conns {
			c.Close()
		}
	}
	return refused
}

// opens reports whether the rules open this machine's addresses and the private
// network addresses to host: one of the guard's names is the host itself, and the
// allow_first list or the allow list lets the host through, the deny list for the
// allow list's part.
func (r *rules) opens(host string) bool {
	if _, ok := policy.Match(r.opened, host); !ok {
		return false
	}
	if _, ok := policy.Exact(r.first, host); ok {
		return true
	}
	if _, ok := policy.Match(r.deny, host); ok {
		return false
	}
	_, ok := policy.Match(r.allow, host)
	return ok
}

// namedConn is a connection dialled for one of the guard's names, on the proxy's list
// until it is closed.
type namedConn struct {
	net.Conn
	host string
	p    *Proxy
	once sync.Once
}

// Close closes the connection and takes it off the list.
func (c *namedConn) Close() error {
	c.once.Do(func() {
		c.p.tmu.Lock()
		delete(c.p.dialled, c)
		c.p.tmu.Unlock()
	})
	return c.Conn.Close()
}

// CloseWrite closes the connection's writing side, when it has one, as [relay] does at
// the end of a copy.
func (c *namedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// track remembers an open connection until untrack; after Close, it closes its ends
// instead.
func (p *Proxy) track(d Decision, terminated bool, conns ...net.Conn) *tunnel {
	t := &tunnel{d: d, conns: conns, terminated: terminated}
	p.tmu.Lock()
	shut := p.shut
	if !shut {
		p.tunnels[t] = struct{}{}
	}
	p.tmu.Unlock()
	if shut {
		for _, c := range conns {
			c.Close()
		}
	}
	return t
}

// untrack forgets a connection that ended.
func (p *Proxy) untrack(t *tunnel) {
	p.tmu.Lock()
	delete(p.tunnels, t)
	p.tmu.Unlock()
}

// namedKey marks the context of a connection whose host is one of the guard's names,
// with the host as decided.
type namedKey struct{}

// named reports whether the host is one of the guard's names, which alone open this
// machine and the private network addresses to an enclosure, and the connection is
// one the allow list or the allow_first list lets through.
func (p *Proxy) named(host string, allowed bool) bool {
	_, ok := policy.Match(p.rules.Load().opened, host)
	return ok && allowed
}

// linkLocal reports whether ip is in the range a guarded proxy never dials.
func linkLocal(ip net.IP) bool {
	return ip != nil && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast())
}

// metadataAddrs are the addresses outside the link-local ranges where a cloud serves
// its instance metadata, each from the provider's documentation:
//   - 100.100.100.200, Alibaba Cloud ECS: alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata
//   - 192.0.0.192, Oracle Cloud Compute Classic: docs.oracle.com/en/cloud/cloud-at-customer/occ-get-started/retrieve-predefined-instance-metadata.html
//   - fd00:ec2::254, AWS EC2 over IPv6: docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
//   - fd20:ce::254, Google Compute Engine over IPv6: docs.cloud.google.com/compute/docs/metadata/querying-metadata
//   - 168.63.129.16, Azure WireServer: learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16
//   - fd00:ec2::23, AWS EKS Pod Identity Agent over IPv6: docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
//   - fd00:a9fe:a9fe::1, Akamai (Linode) Metadata service over IPv6: techdocs.akamai.com/cloud-computing/docs/access-the-metadata-service-api
//   - fd00:42::42, Scaleway Instance metadata API over IPv6: scaleway.com/en/developers/api/instance/
//
// The private ranges around them ([privateRanges]) are dialled only for one of the
// guard's names, and these addresses never.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("100.100.100.200"),
	netip.MustParseAddr("192.0.0.192"),
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("fd20:ce::254"),
	netip.MustParseAddr("168.63.129.16"),
	netip.MustParseAddr("fd00:ec2::23"),
	netip.MustParseAddr("fd00:a9fe:a9fe::1"),
	netip.MustParseAddr("fd00:42::42"),
}

// metadata reports whether ip is one of [metadataAddrs], which a guarded proxy never
// dials, whatever the policy lists. An IPv4 address mapped into IPv6 counts as the IPv4
// address; [carried] covers the other IPv6 forms of one.
func metadata(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return slices.Contains(metadataAddrs, a.Unmap())
}

// privateRanges are the private network ranges a guarded proxy dials only for one of
// the guard's names: 10/8, 172.16/12 and 192.168/16 (RFC 1918), 100.64/10, the shared
// address space (RFC 6598), 0/8, "this network" (RFC 791), 198.18/15, the benchmarking
// range (RFC 2544), 240/4, the reserved range with the broadcast address in it
// (RFC 1112), fc00::/7, the unique local IPv6 addresses (RFC 4193), and fec0::/10, the
// site-local IPv6 addresses (RFC 3879).
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fec0::/10"),
}

// private reports whether ip is in one of [privateRanges]. An IPv4 address mapped into
// IPv6 counts as the IPv4 address; [carried] covers the other IPv6 forms of one.
func private(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	for _, r := range privateRanges {
		if r.Contains(a) {
			return true
		}
	}
	return false
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

// decide applies the host's form, the guard, the allow_first list, the deny list, and
// then the mode and the allow list to a host. A host without the form [policy.Host]
// gives is refused in either mode before anything else is read; past that, the decision's host is that
// form, the one dialled as [Proxy.dialHost] says. The guard decides here what it can
// without resolving, a literal address and localhost, so the denial is in the record; a
// name that resolves to such an address is refused when dialled, by the address
// dialled: the one the name resolved to, or the one the hosts file gave it. A host an
// allow_first entry matches exactly is allowed in either mode, with the entry as its
// rule, before the deny list is read. Past that, a host the deny list covers is denied
// in either mode, with the entry as its rule, before the mode and the allow list are
// consulted. A denied decision is refused; an allowed one has no outcome until it is
// dialled.
func (p *Proxy) decide(method, host string, port int) Decision {
	r := p.rules.Load()
	// A host without the form is recorded as sent.
	d := Decision{Host: host, Port: port, Method: method, Mode: r.mode}
	host, formed := policy.Host(host)
	if !formed {
		d.Rule, d.Outcome = HostForm, Refused
		return d
	}
	d.Host = host
	rule, ok := policy.Match(r.allow, host)
	first, lifted := policy.Exact(r.first, host)
	if lifted {
		rule, ok = first, true
	}
	if p.guarded.Load() {
		ip := net.ParseIP(host)
		local := strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") || own(ip) || private(ip)
		if linkLocal(ip) || metadata(ip) || (local && !p.named(host, ok)) {
			d.Rule, d.Outcome = GuardRule, Refused
			return d
		}
	}
	if denied, ok := policy.Match(r.deny, host); ok && !lifted {
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
	if host == "" {
		http.Error(w, "the proxy takes an absolute-form request target", http.StatusBadRequest)
		return
	}
	port, err := portOf(r.URL.Port(), r.URL.Scheme)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// A host is decided as sent: one percent-encoded is taken undecoded, and so has no
	// form.
	authority := r.RequestURI
	if _, rest, ok := strings.Cut(authority, "://"); ok {
		authority = rest
	}
	if i := strings.IndexAny(authority, "/?#"); i >= 0 {
		authority = authority[:i]
	}
	if h := sent(authority); strings.Contains(h, "%") {
		host = h
	}
	// Every request takes a token first, one the policy denies too, so the policy it is
	// decided by is the one in force once it has its token.
	rated := p.take(r.Context())
	d := p.decide("HTTP", host, port)
	d.RequestID = newRequestID()
	term := p.term.Load()
	// A plain request to a host that gets a credential is refused before its path is
	// read, in either mode; one past the rate limit gets its 429 below.
	if rated == nil && d.Allowed && term.credentialName(d.Host) != "" {
		clean, ok := policy.CleanPath(r.URL.EscapedPath())
		if !ok {
			clean = r.URL.EscapedPath()
		}
		d.Allowed, d.Rule, d.Outcome = false, PlainRequest, Refused
		d.RequestMethod, d.Path = r.Method, clean
		p.observe(d)
		deny(w, d)
		return
	}
	// The path is decided under the mode the host was decided under, which the answer
	// and the record give.
	if d.Allowed {
		if clean, rule, ok := term.plainPath(d.Host, r.URL.EscapedPath(), d.Mode); clean != "" {
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
	if rated != nil {
		p.limited(w, d, RateLimit, rated)
		return
	}
	// Only a request the policy allows is a connection in flight.
	if !d.Allowed {
		p.observe(d)
		deny(w, d)
		return
	}
	if !p.hold() {
		p.limited(w, d, ConnectionLimit, nil)
		return
	}
	defer p.release()
	if tl != nil {
		// A tool is reached on its socket whatever the scheme; the host is never dialled.
		term.toTool(w, r, d, tl)
		return
	}
	out := r.Clone(p.dialContext(r.Context(), d))
	out.RequestURI = ""
	// The host asked of upstream is the one decided on, in its form.
	out.URL.Host = d.Host
	if r.URL.Port() != "" {
		out.URL.Host = net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
	} else if strings.Contains(d.Host, ":") {
		out.URL.Host = "[" + d.Host + "]"
	}
	out.Host = out.URL.Host
	for _, h := range hopByHop {
		out.Header.Del(h)
	}
	// The transport is the request's alone, and its connection closes once the request
	// ends: deferred before the body's close, it runs after it.
	tr := p.transport()
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(out)
	if err != nil {
		d = failed(d, err)
		p.observe(d)
		if !d.Allowed {
			deny(w, d)
			return
		}
		http.Error(w, "upstream: "+accesskey.ShownError(err).Error(), http.StatusBadGateway)
		return
	}
	d.Outcome, d.Status = Connected, resp.StatusCode
	p.observe(d)
	defer resp.Body.Close()
	// The request went upstream without its Upgrade, so a 101 answers no upgrade it
	// asked for: the host's connection is closed, and the client's after a 502.
	if resp.StatusCode == http.StatusSwitchingProtocols {
		w.Header().Set("Connection", "close")
		http.Error(w, "upstream: "+errUnaskedSwitch.Error(), http.StatusBadGateway)
		return
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// connect opens a tunnel, or refuses it with a 403: a denial by the decision, before
// anything is dialled, or the guard's at dial time.
func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	host, portText, err := net.SplitHostPort(r.Host)
	if err != nil || host == "" {
		http.Error(w, "CONNECT takes host:port", http.StatusBadRequest)
		return
	}
	if h := sent(r.RequestURI); strings.Contains(h, "%") {
		host = h
	}
	port, err := portOf(portText, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// The token first, then the decision: a reload during the wait is the policy the
	// tunnel is decided by.
	rated := p.take(r.Context())
	d := p.decide(http.MethodConnect, host, port)
	if rated != nil {
		p.limited(w, d, RateLimit, rated)
		return
	}
	if !d.Allowed {
		p.observe(d)
		deny(w, d)
		return
	}
	// The tunnel is one of the run's connections until it closes, blind or terminated.
	if !p.hold() {
		p.limited(w, d, ConnectionLimit, nil)
		return
	}
	defer p.release()
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
		// net/http does not close a hijacked connection, after a panic either.
		defer client.Close()
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
		// Past the hijack, the request's context is not the tunnel's: the tunnel lasts
		// until either end closes it, or Close.
		ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
		defer cancel()
		defer context.AfterFunc(p.stopped, cancel)()
		p.term.Load().serve(ctx, client, d, net.JoinHostPort(d.Host, strconv.Itoa(d.Port)))
		return
	}
	upstream, err := p.dialHost(p.dialContext(r.Context(), d), "tcp", net.JoinHostPort(d.Host, strconv.Itoa(d.Port)))
	if err != nil {
		d = failed(d, err)
		p.observe(d)
		if !d.Allowed {
			deny(w, d)
			return
		}
		http.Error(w, "upstream: "+accesskey.ShownError(err).Error(), http.StatusBadGateway)
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
	// Closed after a panic too, as above.
	defer client.Close()
	defer upstream.Close()
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
	relay(p.reportPanic, client, upstream, buf.Reader.Buffered(), buf.Reader)
}

// sent is the host of an authority as sent: without user information, port and
// brackets, and not decoded.
func sent(authority string) string {
	authority = authority[strings.LastIndex(authority, "@")+1:]
	if host, _, err := net.SplitHostPort(authority); err == nil {
		return host
	}
	return strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]")
}

// relay copies both ways and closes both ends when either side closes. A panic of either
// copy closes both ends too, and report gets it.
func relay(report func(string), client, upstream net.Conn, buffered int, r io.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)
	routine.Go(report, func() {
		defer wg.Done()
		if buffered > 0 {
			io.CopyN(upstream, r, int64(buffered))
		}
		io.Copy(upstream, client)
		closeWrite(upstream)
	}, client, upstream)
	routine.Go(report, func() {
		defer wg.Done()
		io.Copy(client, upstream)
		closeWrite(client)
	}, client, upstream)
	wg.Wait()
	client.Close()
	upstream.Close()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

// dialHost dials addr, host:port, through the proxy's dialler with a host name rooted:
// a trailing dot, so the resolver resolves the name as decided and adds no search
// domain. A name of one label the hosts file holds is dialled at the addresses the file
// gives it, in its order, and is rooted only when the file does not hold it: Go's
// resolver keeps such a name without a dot and would not find it rooted. An IP address
// is dialled as given. A failed lookup names the host as decided, without the dot.
// Every connection to a host the session asked for is dialled here.
//
// A connection dialled for one of the guard's names ([Proxy.dialContext]) is on the
// proxy's list until it closes, for [Proxy.SetPolicyOpening] to close. When the policy
// in force no longer opens the host, the address is judged without the name, before
// the dial and again once the connection is on the list: a reload during the dial may
// have passed the list before the connection was on it.
func (p *Proxy) dialHost(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _ := ctx.Value(namedKey{}).(string)
	if host == "" {
		return p.dialAt(ctx, network, addr)
	}
	unnamed := context.WithValue(ctx, namedKey{}, nil)
	if !p.rules.Load().opens(host) {
		return p.dialAt(unnamed, network, addr)
	}
	c, err := p.dialAt(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	nc := &namedConn{Conn: c, host: host, p: p}
	p.tmu.Lock()
	p.dialled[nc] = struct{}{}
	p.tmu.Unlock()
	if p.rules.Load().opens(host) {
		return nc, nil
	}
	nc.Close()
	return p.dialAt(unnamed, network, addr)
}

// dialAt is [Proxy.dialHost] for one connection, with no list.
func (p *Proxy) dialAt(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || strings.HasSuffix(host, ".") {
		return p.dial(ctx, network, addr)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return p.dial(ctx, network, addr)
	}
	if !strings.Contains(host, ".") {
		if ips, err := p.hosts(ctx, host); err == nil && len(ips) > 0 {
			var first error
			for _, ip := range ips {
				c, err := p.dial(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return c, nil
				}
				if first == nil {
					first = err
				}
				if ctx.Err() != nil {
					break
				}
			}
			return nil, first
		}
	}
	c, err := p.dial(ctx, network, net.JoinHostPort(host+".", port))
	if err != nil {
		err = unrooted(err, host)
	}
	return c, err
}

// noNameServer is how [hostsOnly] dials a name server: it reaches none.
var noNameServer = func(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("the hosts file alone is read")
}

// hostsOnly is a resolver that reaches no name server, so only the hosts file answers
// it.
var hostsOnly = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
	return noNameServer(ctx, network, address)
}}

// hostsFile returns the addresses the hosts file gives name, the name looked up exactly
// as written, or an error when it gives none. The addresses come as the resolver gives
// them: an IPv4 address mapped into IPv6, and no zone.
func hostsFile(ctx context.Context, name string) ([]netip.Addr, error) {
	return hostsOnly.LookupNetIP(ctx, "ip", name)
}

// unrooted is err with the lookup error in it naming host instead of host rooted. The
// lookup error may be shared with other lookups of the name, so it is copied, never
// changed.
func unrooted(err error, host string) error {
	switch e := err.(type) {
	case *net.OpError:
		if inner := unrooted(e.Err, host); inner != e.Err {
			op := *e
			op.Err = inner
			return &op
		}
	case *net.DNSError:
		if e.Name == host+"." {
			dns := *e
			dns.Name = host
			return &dns
		}
	}
	return err
}

// dialContext carries into the dial whether the host is one of the guard's names,
// which is what lets a guarded proxy reach this machine or a private network address
// for it.
func (p *Proxy) dialContext(ctx context.Context, d Decision) context.Context {
	if p.named(d.Host, d.Rule != "") {
		return context.WithValue(ctx, namedKey{}, d.Host)
	}
	return ctx
}

// deny answers a refused connection: 403 with one line naming the host and the mode,
// or, for [PlainRequest], two lines, the fix first.
func deny(w http.ResponseWriter, d Decision) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	if d.Rule == HostForm {
		host := strconv.QuoteToASCII(d.Host)
		if accesskey.ContainsSecret(d.Host) {
			host = accesskey.ShownValue(d.Host, false)
		}
		fmt.Fprintf(w, "qory: egress to %s:%d denied by the gateway: the host is neither a name of ASCII letters, digits, hyphens and dots nor an IP address in canonical form\n", host, d.Port)
		return
	}
	if d.Rule == PlainRequest {
		fmt.Fprintf(w, "qory: send requests to this host as https:// through CONNECT.\n"+
			"qory: %s %s%s denied by the gateway: the gateway sets this host's credential, and masks it in answers, only on https:// requests through CONNECT\n",
			accesskey.ShownValue(d.RequestMethod, false), d.Host, accesskey.ShownValue(d.Path, false))
		return
	}
	if d.Rule == GuardRule {
		fmt.Fprintf(w, "qory: egress to %s:%d denied by the gateway: to reach the gateway's machine or a private network address, list the host itself, not a *. pattern, in the allow list of the node's policy, and allow it in the run's policy; the gateway reaches either only for such a host, and never a link-local or cloud metadata address\n", d.Host, d.Port)
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
		return 0, fmt.Errorf("invalid port %s", accesskey.ShownValue(text, true))
	}
	return n, nil
}

var hopByHop = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// transport forwards plain requests upstream, directly and never through another proxy.
func (p *Proxy) transport() *http.Transport {
	return &http.Transport{Proxy: nil, DialContext: p.dialHost, DisableCompression: true, IdleConnTimeout: idleTimeout}
}
