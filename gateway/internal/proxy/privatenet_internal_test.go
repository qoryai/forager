package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/forager/policy"
)

// resolvingDial is a dialler that resolves a name as the system's dialler does, from
// names, checks each address with p's guard, as the system's dialler hands it to the
// guard, and connects an address the guard lets through to origin. It records each
// address it connected.
type resolvingDial struct {
	mu        sync.Mutex
	names     map[string][]netip.Addr
	origin    string
	connected []string
}

func (r *resolvingDial) dialler(p *Proxy) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		var at []string
		if a, err := netip.ParseAddr(host); err == nil {
			at = []string{net.JoinHostPort(a.Unmap().String(), port)}
		} else {
			ips, ok := r.names[host]
			if !ok {
				return nil, &net.OpError{Op: "dial", Net: network, Err: &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}}
			}
			for _, ip := range ips {
				at = append(at, net.JoinHostPort(ip.Unmap().String(), port))
			}
		}
		var first error
		for _, a := range at {
			if err := p.guard(ctx, a); err != nil {
				if first == nil {
					first = &net.OpError{Op: "dial", Net: network, Err: err}
				}
				continue
			}
			r.mu.Lock()
			r.connected = append(r.connected, a)
			r.mu.Unlock()
			var nd net.Dialer
			return nd.DialContext(ctx, network, r.origin)
		}
		return nil, first
	}
}

func (r *resolvingDial) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.connected
	r.connected = nil
	return out
}

// TestTheWallDialsAPrivateAddressOnlyForAGuardName pins that behind a wall a private
// network address, 10/8, 172.16/12, 192.168/16, 100.64/10 or fc00::/7, is refused by the
// wall's rule, in either mode, with the guard's 403, recorded as refused and never
// connected, unless one of the guard's names is the host itself and the allow list
// allows it: then it is connected. That holds for a literal address, for a name the
// hosts file or a name server resolves to one, and for an IPv6 address that carries one
// in its last 32 bits. A *. guard name over the host opens nothing.
func TestTheWallDialsAPrivateAddressOnlyForAGuardName(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "origin") }))
	defer origin.Close()
	file := &hostsEntries{names: map[string][]netip.Addr{
		"nas":    {netip.MustParseAddr("192.168.1.20")},
		"nat64":  {netip.MustParseAddr("64:ff9b::a01:203")},
		"compat": {netip.MustParseAddr("::ac10:505")},
	}}
	resolved := map[string][]netip.Addr{
		"svc.corp.example.": {netip.MustParseAddr("100.64.1.1")},
		"v6.corp.example.":  {netip.MustParseAddr("fd12::5")},
	}
	// An IPv6 address that carries an IPv4 one is not in canonical form as a host, so
	// the hosts file gives it.
	for _, host := range []string{"10.1.2.3", "172.16.5.5", "192.168.1.20", "100.64.1.1", "fd12::5",
		"nas", "nat64", "compat", "svc.corp.example", "v6.corp.example"} {
		authority := net.JoinHostPort(host, "80")
		for _, j := range []struct {
			name    string
			mode    policy.Mode
			allow   []string
			open    []string
			refused bool
		}{
			{"observe, no name", policy.Observe, nil, nil, true},
			{"enforce, allowed, no name", policy.Enforce, []string{host}, nil, true},
			{"enforce, allowed, a *. name over it", policy.Enforce, []string{host, "*.corp.example"}, []string{"*.corp.example"}, true},
			{"enforce, named and allowed", policy.Enforce, []string{host}, []string{host}, false},
			{"observe, named, no allow entry", policy.Observe, nil, []string{host}, true},
			{"observe, named and allowed", policy.Observe, []string{host}, []string{host}, false},
		} {
			for _, line := range []string{"CONNECT " + authority, "GET http://" + authority + "/x"} {
				seen := &decisions{}
				p, err := Listen("", j.mode, j.allow, nil, seen.observe)
				if err != nil {
					t.Fatal(err)
				}
				rec := &resolvingDial{names: resolved, origin: origin.Listener.Addr().String()}
				p.dial = rec.dialler(p)
				p.hosts = file.lookup
				p.Guard(j.open)
				code, body := raw(t, p, line, authority)
				d := seen.at(-1)
				got := rec.take()
				p.Close()
				if j.refused {
					if code != 403 || body != refusal(host) || d.Rule != GuardRule || d.Allowed || d.Outcome != Refused || len(got) != 0 {
						t.Errorf("%s, %s: %d %q, decision %+v, connected %v; want the wall's refusal", j.name, line, code, body, d, got)
					}
					continue
				}
				plain := strings.HasPrefix(line, "GET")
				if code != 200 || (plain && body != "origin") || len(got) != 1 || d.Rule == GuardRule || !d.Allowed || d.Outcome != Connected {
					t.Errorf("%s, %s: %d %q, decision %+v, connected %v; want it connected", j.name, line, code, body, d, got)
				}
			}
		}
	}
}

// refusal is the guard's 403 for host on port 80.
func refusal(host string) string {
	return "qory: egress to " + host + ":80 denied by the gateway: to reach the gateway's machine or a private network address, list the host itself, not a *. pattern, in the allow list of the node's policy, and allow it in the run's policy; the gateway reaches either only for such a host, and never a link-local or cloud metadata address\n"
}

// TestTheGuardsErrorForAPrivateAddressStartsWithTheFix pins the guard's error for a
// private network address, the address an IPv6 address carries named as the IPv4
// address, and that a named host passes.
func TestTheGuardsErrorForAPrivateAddressStartsWithTheFix(t *testing.T) {
	p, err := Listen("", policy.Observe, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.Guard(nil)
	named := context.WithValue(context.Background(), namedKey{}, true)
	for address, shown := range map[string]string{
		"10.0.0.1":        "10.0.0.1",
		"fd12::5":         "fd12::5",
		"64:ff9b::a00:1":  "10.0.0.1",
		"::ffff:0:c0a8:1": "192.168.0.1",
		"::6440:1":        "100.64.0.1",
		"fd12::5%eth0":    "fd12::5%eth0",
	} {
		err := p.guard(context.Background(), net.JoinHostPort(address, "80"))
		var ge *guardError
		want := "List the host by name in the allow list of the node's policy: " + shown + " is a private network address, and the gateway dials one only for a host listed there by name"
		if !errors.As(err, &ge) || err.Error() != want {
			t.Errorf("%s: %v, want %q", address, err, want)
		}
		if err := p.guard(named, net.JoinHostPort(address, "80")); err != nil {
			t.Errorf("%s named: %v, want it let through", address, err)
		}
	}
}
