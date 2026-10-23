package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/qoryai/forager/policy"
)

// origins are a plain origin and a TLS one that answer as any host, each recording the
// Host header it was asked, and the TLS one the server name each handshake sent.
type origins struct {
	plain, secure *httptest.Server
	mu            sync.Mutex
	hosts, names  []string
	up            *CA
}

func newOrigins(t *testing.T) *origins {
	t.Helper()
	o := &origins{}
	up, err := NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	o.up = up
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.hosts = append(o.hosts, r.Host)
		o.mu.Unlock()
		io.WriteString(w, "origin")
	})
	o.plain = httptest.NewServer(handler)
	t.Cleanup(o.plain.Close)
	o.secure = httptest.NewUnstartedServer(handler)
	o.secure.Config.ErrorLog = log.New(io.Discard, "", 0)
	// A handshake that sends no server name, as one to an address does, gets the
	// certificate for 127.0.0.2.
	address, err := up.leaf("127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	o.secure.TLS = &tls.Config{
		Certificates: []tls.Certificate{*address},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			o.mu.Lock()
			o.names = append(o.names, hello.ServerName)
			o.mu.Unlock()
			return nil, nil
		},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return up.leaf(hello.ServerName) },
	}
	o.secure.StartTLS()
	t.Cleanup(o.secure.Close)
	return o
}

// take returns the Host headers and the server names seen since the last take.
func (o *origins) take() (hosts, names []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	hosts, names = o.hosts, o.names
	o.hosts, o.names = nil, nil
	return hosts, names
}

// hostsEntries is a hosts file for a test: the addresses of each name it holds, and
// every name it was asked for.
type hostsEntries struct {
	mu     sync.Mutex
	names  map[string][]netip.Addr
	looked []string
}

func (h *hostsEntries) lookup(_ context.Context, name string) ([]netip.Addr, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.looked = append(h.looked, name)
	if ips, ok := h.names[name]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// take returns the names asked for since the last take.
func (h *hostsEntries) take() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.looked
	h.looked = nil
	return out
}

// rootedProxy is a proxy in observe mode, terminating key.example, 127.0.0.2 and vault,
// every dial recorded and connected to the origin for its port, the TLS origin trusted
// as every host, and a hosts file that holds no name.
func rootedProxy(t *testing.T) (*Proxy, *dials, *decisions, *origins, *CA) {
	t.Helper()
	o := newOrigins(t)
	seen := &decisions{}
	p, err := Listen("", policy.Observe, nil, nil, seen.observe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	rec := &dials{plain: o.plain.Listener.Addr().String(), secure: o.secure.Listener.Addr().String()}
	p.dial = rec.dial
	p.hosts = (&hostsEntries{}).lookup
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(o.up.PEM())
	p.TrustUpstream(roots)
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	p.Terminate(ca, nil, map[string][]string{"key.example": {"/*"}, "127.0.0.2": {"/*"}, "vault": {"/*"}}, nil)
	return p, rec, seen, o, ca
}

// raw sends one request line through the proxy with the Host header host and returns
// the status and the body. A CONNECT's tunnel is closed once it is answered.
func raw(t *testing.T, p *Proxy, line, host string) (int, string) {
	t.Helper()
	c, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", line, host)
	method, _, _ := strings.Cut(line, " ")
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
	if err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	if method == http.MethodConnect && resp.StatusCode == http.StatusOK {
		return resp.StatusCode, ""
	}
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// terminated opens a CONNECT to authority, which the proxy terminates, and sends gets
// GET requests inside it with the Host header host, returning each status and body.
func terminated(t *testing.T, p *Proxy, ca *CA, authority, host string, gets int) []string {
	t.Helper()
	c, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT %s: %v %v", authority, resp, err)
	}
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	name, _, _ := net.SplitHostPort(authority)
	inner := tls.Client(c, &tls.Config{RootCAs: trusted, ServerName: name})
	ibr := bufio.NewReader(inner)
	var out []string
	for range gets {
		fmt.Fprintf(inner, "GET /x HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		resp, err := http.ReadResponse(ibr, nil)
		if err != nil {
			t.Fatalf("GET inside CONNECT %s: %v", authority, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		out = append(out, fmt.Sprintf("%d %s", resp.StatusCode, b))
	}
	return out
}

// TestAHostNameIsDialledRootedAndDecidedAsGiven pins that, with a hosts file that holds
// no name, every connection the proxy opens to a host name dials the name rooted, with
// one trailing dot, so the resolver adds no search domain, in each of the four ways a
// host reaches the proxy, while the
// server name a TLS handshake sends, the Host header the host is asked, the decision
// recorded and the connection a terminated host's requests share all keep the name as
// decided, without the dot. An IP address is dialled as written.
func TestAHostNameIsDialledRootedAndDecidedAsGiven(t *testing.T) {
	p, rec, seen, o, ca := rootedProxy(t)
	for _, c := range []struct {
		host, authority, decided, dial string
	}{
		{"kit.example", "kit.example", "kit.example", "kit.example."},
		{"KIT.example.", "KIT.example.", "kit.example", "kit.example."},
		{"localhost", "localhost", "localhost", "localhost."},
		{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"},
		{"[::1]", "[::1]", "::1", "[::1]"},
	} {
		// A plain request: dialled rooted, the Host header as decided.
		if code, body := raw(t, p, "GET http://"+c.authority+"/x", "ignored.example"); code != 200 || body != "origin" {
			t.Errorf("plain %s: %d %q", c.host, code, body)
		}
		if d := rec.take(); len(d) != 1 || d[0] != c.dial+":80" {
			t.Errorf("plain %s dialled %v, want %s:80", c.host, d, c.dial)
		}
		want := c.decided
		if strings.Contains(want, ":") {
			want = "[" + want + "]"
		}
		if hosts, _ := o.take(); len(hosts) != 1 || hosts[0] != want {
			t.Errorf("plain %s: the host was asked as %v, want %s", c.host, hosts, want)
		}
		if d := seen.at(-1); d.Host != c.decided || d.Method != "HTTP" || d.Outcome != Connected {
			t.Errorf("plain %s: decision %+v", c.host, d)
		}

		// An https request in absolute form: dialled rooted, the server name as decided.
		// The origin's certificate is not one this machine trusts, so the answer is a 502;
		// what matters is the dial and the handshake.
		raw(t, p, "GET https://"+c.authority+"/x", "ignored.example")
		if d := rec.take(); len(d) != 1 || d[0] != c.dial+":443" {
			t.Errorf("https %s dialled %v, want %s:443", c.host, d, c.dial)
		}
		wantName := c.decided
		if net.ParseIP(c.decided) != nil {
			// No server name is sent for an address.
			wantName = ""
		}
		if _, names := o.take(); len(names) != 1 || names[0] != wantName {
			t.Errorf("https %s: server names %q, want %q", c.host, names, wantName)
		}
		if d := seen.at(-1); d.Host != c.decided || d.Method != "HTTP" {
			t.Errorf("https %s: decision %+v", c.host, d)
		}

		// A CONNECT the proxy relays: dialled rooted, recorded as decided.
		if code, _ := raw(t, p, "CONNECT "+c.authority+":443", c.authority+":443"); code != 200 {
			t.Errorf("CONNECT %s: %d", c.host, code)
		}
		if d := rec.take(); len(d) != 1 || d[0] != c.dial+":443" {
			t.Errorf("CONNECT %s dialled %v, want %s:443", c.host, d, c.dial)
		}
		if d := seen.at(-1); d.Host != c.decided || d.Method != http.MethodConnect || d.Outcome != Connected {
			t.Errorf("CONNECT %s: decision %+v", c.host, d)
		}
		o.take()
	}

	// A CONNECT the proxy terminates: its requests go to the host dialled rooted, once
	// for both, with the server name and the Host header as decided, whatever Host the
	// session names, and are recorded as decided.
	for _, c := range []struct {
		authority, decided, dial, name string
	}{
		{"key.example:443", "key.example", "key.example.:443", "key.example"},
		{"KEY.example.:443", "key.example", "key.example.:443", "key.example"},
		{"127.0.0.2:443", "127.0.0.2", "127.0.0.2:443", ""},
	} {
		n := seen.count()
		got := terminated(t, p, ca, c.authority, "another.example", 2)
		for i, g := range got {
			if g != "200 origin" {
				t.Errorf("terminated %s, request %d: %s", c.authority, i, g)
			}
		}
		if d := rec.take(); len(d) != 1 || d[0] != c.dial {
			t.Errorf("terminated %s dialled %v, want %s once", c.authority, d, c.dial)
		}
		hosts, names := o.take()
		if len(hosts) != 2 || hosts[0] != c.decided || hosts[1] != c.decided {
			t.Errorf("terminated %s: the host was asked as %v, want %s", c.authority, hosts, c.decided)
		}
		if len(names) != 1 || names[0] != c.name {
			t.Errorf("terminated %s: server names %q, want %q", c.authority, names, c.name)
		}
		if seen.count() != n+2 {
			t.Fatalf("terminated %s: %d decisions, want 2", c.authority, seen.count()-n)
		}
		for i := n; i < n+2; i++ {
			if d := seen.at(i); d.Host != c.decided || d.Method != "HTTPS" || d.Outcome != Connected || d.Status != 200 {
				t.Errorf("terminated %s: decision %+v", c.authority, d)
			}
		}
		// The next tunnel to the host dials again: the upstream connection is the
		// first tunnel's no longer, and every dial is rooted.
		p.upstream().(*unmark).rt.(*http.Transport).CloseIdleConnections()
	}
}

// failingDial fails every dial as the system dialler fails a lookup: an operation
// error around a lookup error naming the host it was handed. Each lookup error is kept,
// to show it is never changed.
type failingDial struct {
	mu     sync.Mutex
	errors []*net.DNSError
}

func (f *failingDial) dial(_ context.Context, network, addr string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(addr)
	dns := &net.DNSError{Err: "no such host", Name: host, Server: "192.0.2.53:53", IsNotFound: true}
	f.mu.Lock()
	f.errors = append(f.errors, dns)
	f.mu.Unlock()
	return nil, &net.OpError{Op: "dial", Net: network, Err: dns}
}

// TestAFailedLookupNamesTheHostAsDecided pins that the answer to a connection whose
// host name did not resolve, and the decision recorded for it, name the host as decided,
// without the trailing dot it was dialled with, in each of the four ways a host reaches
// the proxy, and that the lookup error, which other lookups of the name may share, is
// not changed.
func TestAFailedLookupNamesTheHostAsDecided(t *testing.T) {
	p, _, seen, _, ca := rootedProxy(t)
	f := &failingDial{}
	p.dial = f.dial
	want := "lookup kit.example on 192.0.2.53:53: no such host"
	for _, line := range []string{"GET http://kit.example/x", "GET https://kit.example/x", "CONNECT kit.example:443"} {
		code, body := raw(t, p, line, "kit.example")
		if code != http.StatusBadGateway || !strings.Contains(body, want) || strings.Contains(body, "kit.example.") {
			t.Errorf("%s: %d %q, want 502 naming %q", line, code, body, want)
		}
		if d := seen.at(-1); d.Host != "kit.example" || d.Outcome != DialFailed {
			t.Errorf("%s: decision %+v", line, d)
		}
	}
	got := terminated(t, p, ca, "key.example:443", "key.example", 1)
	want = "lookup key.example on 192.0.2.53:53: no such host"
	if len(got) != 1 || !strings.HasPrefix(got[0], "502 ") || !strings.Contains(got[0], want) || strings.Contains(got[0], "key.example.") {
		t.Errorf("terminated: %q, want 502 naming %q", got, want)
	}
	if d := seen.at(-1); d.Host != "key.example" || d.Outcome != DialFailed {
		t.Errorf("terminated: decision %+v", d)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.errors) == 0 {
		t.Fatal("nothing was dialled")
	}
	for _, e := range f.errors {
		if !strings.HasSuffix(e.Name, ".") {
			t.Errorf("a lookup error was changed: %q", e.Name)
		}
	}
}

// TestUnrootedChangesOnlyTheRootedName pins that only a lookup error naming the host
// rooted is given the host as decided, and every other error passes as it came.
func TestUnrootedChangesOnlyTheRootedName(t *testing.T) {
	other := &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "kit.example.corp."}}
	if got := unrooted(other, "kit.example"); got != error(other) {
		t.Errorf("another name: %v", got)
	}
	refused := &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}, Err: errors.New("connect: connection refused")}
	if got := unrooted(refused, "kit.example"); got != error(refused) {
		t.Errorf("a refused connection: %v", got)
	}
	guard := &net.OpError{Op: "dial", Net: "tcp", Err: &guardError{msg: "no"}}
	if got := unrooted(guard, "kit.example"); got != error(guard) {
		t.Errorf("the guard's refusal: %v", got)
	}
	bare := &net.DNSError{Err: "no such host", Name: "kit.example."}
	if got := unrooted(bare, "kit.example"); got.Error() != "lookup kit.example: no such host" || bare.Name != "kit.example." {
		t.Errorf("a bare lookup error: %v, kept %q", got, bare.Name)
	}
}

// TestLocalNamesResolveAsBefore pins, with this machine's resolver, that localhost and a
// name under .localhost, dialled rooted, still reach this machine: through a proxy
// without a wall, and behind one when an allow entry names the host, and that behind a
// wall a name under .localhost no entry names is refused when dialled, by the wall's
// rule.
func TestLocalNamesResolveAsBefore(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "local") }))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	if _, err := net.DefaultResolver.LookupHost(context.Background(), "app.localhost."); err != nil {
		t.Skipf("app.localhost. does not resolve here: %v", err)
	}
	get := func(p *Proxy, seen *decisions, host string) (int, string, Decision) {
		code, body := raw(t, p, "GET http://"+host+":"+port+"/x", host)
		return code, body, seen.at(-1)
	}
	open := &decisions{}
	p, err := Listen("", policy.Observe, nil, nil, open.observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, host := range []string{"localhost", "app.localhost"} {
		if code, body, d := get(p, open, host); code != 200 || body != "local" || d.Host != host || d.Outcome != Connected {
			t.Errorf("no wall, %s: %d %q %+v", host, code, body, d)
		}
	}
	walled := &decisions{}
	g, err := Listen("", policy.Enforce, []string{"localhost", "app.localhost", "other.localhost"}, nil, walled.observe)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.Guard([]string{"localhost", "app.localhost"})
	for _, host := range []string{"localhost", "app.localhost"} {
		if code, body, d := get(g, walled, host); code != 200 || body != "local" || d.Host != host || d.Outcome != Connected || d.Rule != host {
			t.Errorf("behind a wall, named %s: %d %q %+v", host, code, body, d)
		}
	}
	if code, body, d := get(g, walled, "other.localhost"); code != 403 || d.Rule != GuardRule || d.Outcome != Refused || d.Host != "other.localhost" || strings.Contains(body, "other.localhost.") {
		t.Errorf("behind a wall, unnamed other.localhost: %d %q %+v", code, body, d)
	}
}

// TestAOneLabelNameIsDialledAtTheAddressesOfTheHostsFile pins that a name of one label
// the hosts file holds is dialled at the addresses the file gives it, in its order, and
// not rooted, in each of the four ways a host reaches the proxy, with the server name,
// the Host header and the decision as decided; that one the file does not hold is
// dialled rooted; and that a name of more labels is dialled rooted without asking the
// file.
func TestAOneLabelNameIsDialledAtTheAddressesOfTheHostsFile(t *testing.T) {
	p, rec, seen, o, ca := rootedProxy(t)
	hosts := &hostsEntries{names: map[string][]netip.Addr{
		"db":    {netip.MustParseAddr("127.0.0.1")},
		"vault": {netip.MustParseAddr("127.0.0.1")},
		// The first refuses, and the next is dialled.
		"pair": {netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("::1")},
	}}
	p.hosts = hosts.lookup
	p.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "192.0.2.1:") {
			rec.mu.Lock()
			rec.dialled = append(rec.dialled, addr)
			rec.mu.Unlock()
			return nil, &net.OpError{Op: "dial", Net: network, Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1")}, Err: errors.New("connect: connection refused")}
		}
		return rec.dial(ctx, network, addr)
	}
	for _, c := range []struct {
		host   string
		dial   []string
		looked []string
	}{
		{"db", []string{"127.0.0.1"}, []string{"db"}},
		{"DB.", []string{"127.0.0.1"}, []string{"db"}},
		{"pair", []string{"192.0.2.1", "[::1]"}, []string{"pair"}},
		{"absent", []string{"absent."}, []string{"absent"}},
		{"kit.example", []string{"kit.example."}, nil},
	} {
		decided := strings.TrimSuffix(strings.ToLower(c.host), ".")
		for _, rq := range []struct{ line, port string }{
			{"GET http://" + c.host + "/x", "80"},
			{"GET https://" + c.host + "/x", "443"},
			{"CONNECT " + c.host + ":443", "443"},
		} {
			raw(t, p, rq.line, c.host)
			var want []string
			for _, d := range c.dial {
				want = append(want, d+":"+rq.port)
			}
			if d := rec.take(); strings.Join(d, " ") != strings.Join(want, " ") {
				t.Errorf("%s dialled %v, want %v", rq.line, d, want)
			}
			if l := hosts.take(); strings.Join(l, " ") != strings.Join(c.looked, " ") {
				t.Errorf("%s asked the hosts file for %v, want %v", rq.line, l, c.looked)
			}
			hostsSeen, names := o.take()
			switch {
			case strings.HasPrefix(rq.line, "GET http:"):
				if len(hostsSeen) != 1 || hostsSeen[0] != decided {
					t.Errorf("%s: the host was asked as %v, want %s", rq.line, hostsSeen, decided)
				}
			case strings.HasPrefix(rq.line, "GET https:"):
				if len(names) != 1 || names[0] != decided {
					t.Errorf("%s: server names %q, want %q", rq.line, names, decided)
				}
			}
			if d := seen.at(-1); d.Host != decided || (d.Outcome != Connected && !strings.HasPrefix(rq.line, "GET https:")) {
				t.Errorf("%s: decision %+v", rq.line, d)
			}
		}
	}
	// The terminated one-label host: dialled at the file's address, once for both
	// requests, with the server name and the Host header as decided.
	got := terminated(t, p, ca, "vault:443", "another.example", 2)
	if len(got) != 2 || got[0] != "200 origin" || got[1] != "200 origin" {
		t.Errorf("terminated vault: %q", got)
	}
	if d := rec.take(); len(d) != 1 || d[0] != "127.0.0.1:443" {
		t.Errorf("terminated vault dialled %v, want 127.0.0.1:443 once", d)
	}
	hostsSeen, names := o.take()
	if len(hostsSeen) != 2 || hostsSeen[0] != "vault" || hostsSeen[1] != "vault" || len(names) != 1 || names[0] != "vault" {
		t.Errorf("terminated vault: the host was asked as %v, server names %q", hostsSeen, names)
	}
	if d := seen.at(-1); d.Host != "vault" || d.Method != "HTTPS" || d.Outcome != Connected {
		t.Errorf("terminated vault: decision %+v", d)
	}
}

// TestAOneLabelNameFailsAsBefore pins the answers when a one-label name is not reached:
// every address the hosts file gives refused, the error names the address as the
// dialler does; not in the file and not resolved, the lookup error names the host as
// decided, without the dot.
func TestAOneLabelNameFailsAsBefore(t *testing.T) {
	p, _, seen, _, _ := rootedProxy(t)
	p.hosts = (&hostsEntries{names: map[string][]netip.Addr{"db": {netip.MustParseAddr("192.0.2.1")}}}).lookup
	f := &failingDial{}
	p.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "192.0.2.1:") {
			return nil, &net.OpError{Op: "dial", Net: network, Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80}, Err: errors.New("connect: connection refused")}
		}
		return f.dial(ctx, network, addr)
	}
	for _, c := range []struct{ line, want string }{
		{"GET http://db/x", "upstream: dial tcp 192.0.2.1:80: connect: connection refused"},
		{"GET http://absent/x", "upstream: dial tcp: lookup absent on 192.0.2.53:53: no such host"},
		{"CONNECT absent:443", "upstream: dial tcp: lookup absent on 192.0.2.53:53: no such host"},
	} {
		code, body := raw(t, p, c.line, "x")
		if code != http.StatusBadGateway || strings.TrimSpace(body) != c.want {
			t.Errorf("%s: %d %q, want 502 %q", c.line, code, body, c.want)
		}
		if d := seen.at(-1); d.Outcome != DialFailed || strings.HasSuffix(d.Host, ".") {
			t.Errorf("%s: decision %+v", c.line, d)
		}
	}
}

// TestTheWallChecksTheAddressOfTheHostsFile pins that behind a wall a one-label name the
// hosts file gives this machine's address is refused when dialled, by the wall's rule,
// unless an allow entry names it, and one it gives a link-local address is refused
// whatever the policy says, as for a name the resolver gives such an address.
func TestTheWallChecksTheAddressOfTheHostsFile(t *testing.T) {
	hits := 0
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; io.WriteString(w, "local") }))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	file := (&hostsEntries{names: map[string][]netip.Addr{
		"db":   {netip.MustParseAddr("127.0.0.1")},
		"meta": {netip.MustParseAddr("169.254.169.254")},
		// A zoned address is judged by the address alone.
		"zlink":  {netip.MustParseAddr("fe80::1%lo0")},
		"zcoded": {netip.MustParseAddr("fe80::1%25lo0")},
		"zloop":  {netip.MustParseAddr("::1%lo0")},
	}}).lookup
	for _, c := range []struct {
		mode        policy.Mode
		allow, open []string
		host        string
		status      int
		rule        string
	}{
		{policy.Observe, nil, nil, "db", 403, GuardRule},
		{policy.Enforce, []string{"*.example", "db"}, []string{"*.example"}, "db", 403, GuardRule},
		{policy.Enforce, []string{"db"}, []string{"db"}, "db", 200, "db"},
		{policy.Observe, []string{"meta"}, []string{"meta"}, "meta", 403, GuardRule},
		{policy.Observe, nil, nil, "zlink", 403, GuardRule},
		{policy.Observe, []string{"zlink"}, []string{"zlink"}, "zlink", 403, GuardRule},
		{policy.Observe, nil, nil, "zcoded", 403, GuardRule},
		{policy.Observe, nil, nil, "zloop", 403, GuardRule},
		{policy.Enforce, []string{"*.example", "zloop"}, []string{"*.example"}, "zloop", 403, GuardRule},
	} {
		seen := &decisions{}
		p, err := Listen("", c.mode, c.allow, nil, seen.observe)
		if err != nil {
			t.Fatal(err)
		}
		p.hosts = file
		p.Guard(c.open)
		before := hits
		code, body := raw(t, p, "GET http://"+c.host+":"+port+"/x", c.host)
		d := seen.at(-1)
		if code != c.status || d.Rule != c.rule || d.Host != c.host || strings.Contains(body, c.host+".") {
			t.Errorf("%s %v %s: %d %q, decision %+v", c.mode, c.open, c.host, code, body, d)
		}
		if c.status == 403 && (d.Allowed || d.Outcome != Refused || hits != before) {
			t.Errorf("%s %v %s: reached this machine, decision %+v", c.mode, c.open, c.host, d)
		}
		p.Close()
	}
}

// errPassed ends a test dial the guard let through, before anything is connected.
var errPassed = errors.New("the guard let the address through")

// passedDial is a dialler whose every connection is checked by p's guard, as the
// proxy's dialler checks it, at the address the system's dialler is about to connect
// to, and then ends with errPassed: nothing is connected. It records each address the
// guard let through.
type passedDial struct {
	mu     sync.Mutex
	passed []string
}

func (r *passedDial) dialler(p *Proxy) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second, ControlContext: func(ctx context.Context, _, address string, _ syscall.RawConn) error {
		if err := p.guard(ctx, address); err != nil {
			return err
		}
		r.mu.Lock()
		r.passed = append(r.passed, address)
		r.mu.Unlock()
		return errPassed
	}}
	return d.DialContext
}

func (r *passedDial) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.passed
	r.passed = nil
	return out
}

// TestTheWallJudgesAZonedAddressByTheAddress pins that behind a wall an IPv6 address
// with a zone is judged as the address without it: refused when that address would be,
// a zoned link-local or loopback address among them, and let through when it would be;
// that an address that does not read as one is refused; and that without a wall
// nothing is refused.
func TestTheWallJudgesAZonedAddressByTheAddress(t *testing.T) {
	p, err := Listen("", policy.Observe, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	named := context.WithValue(context.Background(), namedKey{}, true)
	plain := context.Background()
	for _, address := range []string{"nonsense%lo0:80", "[zz::1%lo0]:80", "[%lo0]:80", "[]:80", "fe80::1%lo0", "no-port"} {
		if err := p.guard(plain, address); err != nil {
			t.Errorf("no wall, %s: refused: %v", address, err)
		}
	}
	p.Guard(nil)

	// At the guard: each zoned address is judged as the address without its zone.
	pairs := [][2]string{
		{"fe80::1%lo0", "fe80::1"},
		{"fe80::1%25lo0", "fe80::1"},
		{"fe80::1%eth0", "fe80::1"},
		{"fe80::1%1", "fe80::1"},
		{"ff02::1%lo0", "ff02::1"},
		{"::1%lo0", "::1"},
		{"::1%25lo0", "::1"},
		{"::%lo0", "::"},
		{"2001:db8::1%eth0", "2001:db8::1"},
		{"2001:db8::1%25eth0", "2001:db8::1"},
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() == nil {
			pairs = append(pairs, [2]string{n.IP.String() + "%lo0", n.IP.String()})
		}
	}
	for _, pair := range pairs {
		for _, ctx := range []context.Context{plain, named} {
			zoned := p.guard(ctx, net.JoinHostPort(pair[0], "80"))
			bare := p.guard(ctx, net.JoinHostPort(pair[1], "80"))
			if (zoned == nil) != (bare == nil) {
				t.Errorf("%s judged %v, %s judged %v", pair[0], zoned, pair[1], bare)
			}
		}
	}
	for _, c := range []struct {
		address string
		ctx     context.Context
		refused bool
	}{
		{"[fe80::1%lo0]:80", plain, true},
		{"[fe80::1%lo0]:80", named, true},
		{"[fe80::1%25lo0]:80", plain, true},
		{"[::1%lo0]:80", plain, true},
		{"[::1%lo0]:80", named, false},
		{"[2001:db8::1%eth0]:80", plain, false},
		// An address that does not read as one is refused.
		{"[nonsense%lo0]:80", plain, true},
		{"[zz::1%lo0]:80", named, true},
		{"[%lo0]:80", named, true},
		{"[]:80", named, true},
		{"fe80::1%lo0", named, true},
		{"no-port", named, true},
	} {
		err := p.guard(c.ctx, c.address)
		var ge *guardError
		if c.refused != (err != nil) || (err != nil && !errors.As(err, &ge)) {
			t.Errorf("%s (named %v): %v, want refused %v", c.address, c.ctx == named, err, c.refused)
		}
	}

	// Through the system's dialler: a zoned address reaches the guard with its zone,
	// and is judged by the address; a refused one is never connected.
	rec := &passedDial{}
	dial := rec.dialler(p)
	for _, c := range []struct {
		address string
		passed  bool
	}{
		{"[fe80::1%lo0]:80", false},
		{"[fe80::1%25lo0]:80", false},
		{"[::1%lo0]:80", false},
		{"[2001:db8::1%eth0]:80", true},
	} {
		_, err := dial(plain, "tcp", c.address)
		var ge *guardError
		switch got := rec.take(); {
		case c.passed && (len(got) != 1 || got[0] != c.address || !errors.Is(err, errPassed)):
			t.Errorf("%s: passed %v, %v; want it let through at %s", c.address, got, err, c.address)
		case !c.passed && (len(got) != 0 || !errors.As(err, &ge)):
			t.Errorf("%s: passed %v, %v; want the wall's refusal", c.address, got, err)
		}
	}
}

// TestTheWallJudgesAZonedAddressOfTheHostsFile pins that behind a wall a one-label name
// the hosts file gives a zoned address is judged by the address without the zone: a
// zoned link-local or loopback address is refused by the wall's rule and never
// connected, and a zoned ordinary address is dialled as the file gives it.
func TestTheWallJudgesAZonedAddressOfTheHostsFile(t *testing.T) {
	file := (&hostsEntries{names: map[string][]netip.Addr{
		"zlink":   {netip.MustParseAddr("fe80::1%lo0")},
		"zcoded":  {netip.MustParseAddr("fe80::1%25lo0")},
		"zloop":   {netip.MustParseAddr("::1%lo0")},
		"zglobal": {netip.MustParseAddr("2001:db8::1%eth0")},
	}}).lookup
	for _, c := range []struct {
		host, passed string
	}{
		{"zlink", ""},
		{"zcoded", ""},
		{"zloop", ""},
		{"zglobal", "[2001:db8::1%eth0]:80"},
	} {
		seen := &decisions{}
		p, err := Listen("", policy.Observe, nil, nil, seen.observe)
		if err != nil {
			t.Fatal(err)
		}
		rec := &passedDial{}
		p.dial = rec.dialler(p)
		p.hosts = file
		p.Guard(nil)
		code, _ := raw(t, p, "GET http://"+c.host+"/x", c.host)
		d := seen.at(-1)
		got := rec.take()
		if c.passed == "" {
			if code != 403 || d.Rule != GuardRule || d.Allowed || d.Outcome != Refused || len(got) != 0 {
				t.Errorf("%s: %d, decision %+v, passed %v; want the wall's refusal", c.host, code, d, got)
			}
		} else if len(got) != 1 || got[0] != c.passed || d.Rule == GuardRule || d.Outcome != DialFailed {
			t.Errorf("%s: %d, decision %+v, passed %v; want it dialled at %s", c.host, code, d, got, c.passed)
		}
		p.Close()
	}
}

// TestTheHostsFileAloneAnswers pins that the lookup a one-label name is first given
// reads the hosts file and reaches no name server: localhost is found without one, and
// a name no hosts file holds is not resolved, the name server it would ask never
// reached.
func TestTheHostsFileAloneAnswers(t *testing.T) {
	if _, err := noNameServer(context.Background(), "udp", "192.0.2.53:53"); err == nil {
		t.Fatal("the hosts-only resolver reached a name server")
	}
	var mu sync.Mutex
	asked := 0
	kept := noNameServer
	noNameServer = func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		asked++
		mu.Unlock()
		return kept(ctx, network, address)
	}
	t.Cleanup(func() { noNameServer = kept })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if ips, err := hostsFile(ctx, "no-such-name.invalid"); err == nil {
		t.Errorf("no-such-name.invalid was resolved: %v", ips)
	}
	mu.Lock()
	if asked == 0 {
		t.Error("a name outside the hosts file was looked up without the hosts-only dial")
	}
	asked = 0
	mu.Unlock()
	ips, err := hostsFile(ctx, "localhost")
	if err != nil {
		t.Skipf("the hosts file here holds no localhost: %v", err)
	}
	loop := false
	for _, ip := range ips {
		loop = loop || ip.Unmap().IsLoopback()
	}
	mu.Lock()
	defer mu.Unlock()
	if !loop || asked != 0 {
		t.Errorf("localhost: %v, a name server asked %d times", ips, asked)
	}
}

// TestTheFirstFailureOfTheHostsFileAddressesIsTheAnswer pins that when no address the
// hosts file gives a one-label name connects, the failure of the first is the answer:
// behind a wall, the first refused by the wall and the next failing to connect is the
// wall's denial, recorded as refused.
func TestTheFirstFailureOfTheHostsFileAddressesIsTheAnswer(t *testing.T) {
	seen := &decisions{}
	p, err := Listen("", policy.Observe, nil, nil, seen.observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.Guard(nil)
	p.hosts = (&hostsEntries{names: map[string][]netip.Addr{
		"db": {netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1")},
	}}).lookup
	guarded := p.dial
	var mu sync.Mutex
	var dialled []string
	p.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialled = append(dialled, addr)
		mu.Unlock()
		if strings.HasPrefix(addr, "192.0.2.1:") {
			return nil, &net.OpError{Op: "dial", Net: network, Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80}, Err: errors.New("connect: connection refused")}
		}
		return guarded(ctx, network, addr)
	}
	code, body := raw(t, p, "GET http://db/x", "db")
	d := seen.at(-1)
	if code != http.StatusForbidden || d.Rule != GuardRule || d.Outcome != Refused || d.Allowed || d.Host != "db" {
		t.Errorf("%d %q, decision %+v", code, body, d)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(dialled, " ") != "127.0.0.1:80 192.0.2.1:80" {
		t.Errorf("dialled %v, want both in order", dialled)
	}
}
