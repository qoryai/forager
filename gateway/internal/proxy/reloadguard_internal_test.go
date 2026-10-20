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
	"testing"
	"time"

	"github.com/qoryai/forager/policy"
)

// guardedName is a guarded proxy whose one guard name, db.corp.example, resolves to the
// private address 10.1.2.3, with dials going to origin. It terminates db.corp.example
// when terminate is set.
type guardedName struct {
	p       *Proxy
	rec     *resolvingDial
	seen    *decisions
	trusted *x509.CertPool
	paths   map[string][]string
}

func newGuardedName(t *testing.T, mode policy.Mode, first, allow []string, origin string, upstream *CA) *guardedName {
	t.Helper()
	seen := &decisions{}
	p, err := Listen("", mode, allow, nil, seen.observe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	rec := &resolvingDial{names: map[string][]netip.Addr{"db.corp.example.": {netip.MustParseAddr("10.1.2.3")}}, origin: origin}
	p.dial = rec.dialler(p)
	p.Guard([]string{"db.corp.example"})
	p.AllowFirst(first)
	g := &guardedName{p: p, rec: rec, seen: seen}
	if upstream == nil {
		return g
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(upstream.PEM())
	p.TrustUpstream(roots)
	g.paths = map[string][]string{"db.corp.example": {"/*"}}
	ca, err := NewCA("test", p.Terminating(nil, g.paths, nil))
	if err != nil {
		t.Fatal(err)
	}
	p.Terminate(ca, nil, g.paths, nil)
	g.trusted = x509.NewCertPool()
	g.trusted.AppendCertsFromPEM(ca.PEM())
	return g
}

// tlsOrigin is a TLS server for db.corp.example under its own authority.
func tlsOrigin(t *testing.T, h http.Handler) (*httptest.Server, *CA) {
	t.Helper()
	up, err := NewCA("upstream", []string{"db.corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewUnstartedServer(h)
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return up.leaf(hello.ServerName) }}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	return origin, up
}

// open sends a CONNECT for db.corp.example:port through the proxy and returns the
// tunnel, or the status of a refusal.
func (g *guardedName) open(t *testing.T, port int) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	c, err := net.Dial("tcp", g.p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "CONNECT db.corp.example:%d HTTP/1.1\r\nHost: db.corp.example:%d\r\n\r\n", port, port)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	return c, br, resp.StatusCode
}

// terminated opens a tunnel the proxy terminates and returns a sender of GET requests
// inside it, each returning the status, or an error once the tunnel is closed.
func (g *guardedName) terminated(t *testing.T) func() (int, error) {
	t.Helper()
	c, _, code := g.open(t, 443)
	if code != http.StatusOK {
		t.Fatalf("CONNECT: %d", code)
	}
	tc := tls.Client(c, &tls.Config{ServerName: "db.corp.example", RootCAs: g.trusted})
	br := bufio.NewReader(tc)
	return func() (int, error) {
		if _, err := fmt.Fprintf(tc, "GET /x HTTP/1.1\r\nHost: db.corp.example\r\n\r\n"); err != nil {
			return 0, err
		}
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
		if err != nil {
			return 0, err
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, nil
	}
}

// reloads are reloads that take the guard name's opening away from db.corp.example,
// and those that keep it, from a policy that opens it by the allow list or by the
// allow_first list.
var reloads = []struct {
	name       string
	mode       policy.Mode
	first      []string
	allow      []string
	reload     func(*guardedName)
	closes     bool
	newRefusal bool
}{
	{"enforce, the reload drops the guard name", policy.Enforce, nil, []string{"db.corp.example"}, func(g *guardedName) {
		g.p.SetPolicyOpening(policy.Enforce, nil, []string{"db.corp.example"}, nil, nil, g.paths, nil)
	}, true, true},
	{"observe, the reload drops the guard name", policy.Observe, nil, []string{"db.corp.example"}, func(g *guardedName) {
		g.p.SetPolicyOpening(policy.Observe, nil, []string{"db.corp.example"}, nil, nil, g.paths, nil)
	}, true, true},
	{"observe, the reload drops the allow entry", policy.Observe, nil, []string{"db.corp.example"}, func(g *guardedName) {
		g.p.SetPolicyOpening(policy.Observe, nil, nil, nil, []string{"db.corp.example"}, g.paths, nil)
	}, true, true},
	{"observe, the reload drops the allow_first entry", policy.Observe, []string{"db.corp.example"}, nil, func(g *guardedName) {
		g.p.SetPolicyOpening(policy.Observe, nil, nil, nil, []string{"db.corp.example"}, g.paths, nil)
	}, true, true},
	{"enforce, the reload keeps the guard name", policy.Enforce, nil, []string{"db.corp.example"}, func(g *guardedName) {
		g.p.SetPolicyOpening(policy.Enforce, nil, []string{"db.corp.example", "other.example"}, nil, []string{"db.corp.example"}, g.paths, nil)
	}, false, false},
	{"observe, the reload moves the entry to allow_first", policy.Observe, nil, []string{"db.corp.example"}, func(g *guardedName) {
		g.p.SetPolicyOpening(policy.Observe, []string{"db.corp.example"}, nil, nil, []string{"db.corp.example"}, g.paths, nil)
	}, false, false},
}

// TestAReloadThatTakesTheGuardNameAwayClosesItsConnections pins that behind a wall a
// reload after which the policy no longer opens a guard name, by the guard names, the
// allow list or the allow_first list, in either mode, closes the terminated tunnels to
// the host and the pooled connections dialled for it: the tunnel's next request fails,
// and a new tunnel's request is judged by the guard again, refused, with nothing
// dialled. A reload that keeps the opening keeps the tunnel and the pooled connection.
func TestAReloadThatTakesTheGuardNameAwayClosesItsConnections(t *testing.T) {
	for _, c := range reloads {
		t.Run(c.name, func(t *testing.T) {
			origin, up := tlsOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "origin") }))
			g := newGuardedName(t, c.mode, c.first, c.allow, origin.Listener.Addr().String(), up)
			send := g.terminated(t)
			if code, err := send(); code != http.StatusOK || err != nil {
				t.Fatalf("before the reload: %d %v", code, err)
			}
			if got := g.rec.take(); len(got) != 1 || !strings.HasPrefix(got[0], "10.1.2.3:") {
				t.Fatalf("before the reload, dialled %v; want 10.1.2.3", got)
			}
			c.reload(g)
			code, err := send()
			switch {
			case c.closes && err == nil:
				t.Errorf("the open tunnel answered %d after the reload; want it closed", code)
			case !c.closes && (err != nil || code != http.StatusOK):
				t.Errorf("the open tunnel after the reload: %d %v; want 200", code, err)
			}
			if !c.closes {
				if got := g.rec.take(); len(got) != 0 {
					t.Errorf("the open tunnel dialled %v after the reload; want the pooled connection", got)
				}
			}
			code, err = g.terminated(t)()
			got := g.rec.take()
			switch {
			case c.newRefusal && (err != nil || code != http.StatusForbidden || len(got) != 0 || g.seen.at(-1).Rule != GuardRule || g.seen.at(-1).Outcome != Refused):
				t.Errorf("a new tunnel after the reload: %d %v, dialled %v, decision %+v; want the guard's refusal with nothing dialled", code, err, got, g.seen.at(-1))
			case !c.newRefusal && (err != nil || code != http.StatusOK || len(got) != 0):
				t.Errorf("a new tunnel after the reload: %d %v, dialled %v; want 200 on the pooled connection", code, err, got)
			}
		})
	}
}

// TestAReloadThatTakesTheGuardNameAwayClosesABlindTunnel pins the same for a tunnel the
// proxy relays without reading it.
func TestAReloadThatTakesTheGuardNameAwayClosesABlindTunnel(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "origin") }))
	defer origin.Close()
	for _, c := range reloads {
		t.Run(c.name, func(t *testing.T) {
			g := newGuardedName(t, c.mode, c.first, c.allow, origin.Listener.Addr().String(), nil)
			conn, br, code := g.open(t, 80)
			if code != http.StatusOK {
				t.Fatalf("CONNECT: %d", code)
			}
			if got := g.rec.take(); len(got) != 1 || !strings.HasPrefix(got[0], "10.1.2.3:") {
				t.Fatalf("dialled %v; want 10.1.2.3", got)
			}
			c.reload(g)
			fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: db.corp.example\r\n\r\n")
			resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
			switch {
			case c.closes && err == nil:
				t.Errorf("the open tunnel answered %d after the reload; want it closed", resp.StatusCode)
			case !c.closes && (err != nil || resp.StatusCode != http.StatusOK):
				t.Errorf("the open tunnel after the reload: %v %v; want 200", resp, err)
			}
		})
	}
}

// TestAReloadThatTakesTheGuardNameAwayClosesARequestInFlight pins that the reload also
// closes a connection dialled for the host that a request is using: the host sees the
// connection close before it answers, for a request in a terminated tunnel and for a
// plain request.
func TestAReloadThatTakesTheGuardNameAwayClosesARequestInFlight(t *testing.T) {
	for _, terminate := range []bool{true, false} {
		t.Run(fmt.Sprintf("terminated=%v", terminate), func(t *testing.T) {
			arrived, ended := make(chan struct{}, 1), make(chan bool, 1)
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				arrived <- struct{}{}
				select {
				case <-r.Context().Done():
					ended <- true
				case <-time.After(5 * time.Second):
					ended <- false
				}
			})
			var g *guardedName
			if terminate {
				origin, up := tlsOrigin(t, h)
				g = newGuardedName(t, policy.Enforce, nil, []string{"db.corp.example"}, origin.Listener.Addr().String(), up)
				go g.terminated(t)()
			} else {
				origin := httptest.NewServer(h)
				defer origin.Close()
				g = newGuardedName(t, policy.Enforce, nil, []string{"db.corp.example"}, origin.Listener.Addr().String(), nil)
				go func() {
					c, err := net.Dial("tcp", g.p.Addr())
					if err != nil {
						return
					}
					defer c.Close()
					c.SetDeadline(time.Now().Add(10 * time.Second))
					fmt.Fprintf(c, "GET http://db.corp.example/x HTTP/1.1\r\nHost: db.corp.example\r\n\r\n")
					io.ReadAll(c)
				}()
			}
			select {
			case <-arrived:
			case <-time.After(5 * time.Second):
				t.Fatal("the request did not reach the host")
			}
			g.p.SetPolicyOpening(policy.Enforce, nil, []string{"db.corp.example"}, nil, nil, g.paths, nil)
			if !<-ended {
				t.Error("the host's connection stayed open for 5 s after the reload; want it closed")
			}
		})
	}
}

// TestAReloadDuringTheDialOfAGuardNameClosesTheConnection pins that a reload that takes
// the guard name's opening away while the connection to the host is being dialled,
// before the connection is on the proxy's list, closes that connection: the dial
// returns after the reload, the CONNECT gets the guard's refusal, and the list is empty.
func TestAReloadDuringTheDialOfAGuardNameClosesTheConnection(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "origin") }))
	defer origin.Close()
	g := newGuardedName(t, policy.Enforce, nil, []string{"db.corp.example"}, origin.Listener.Addr().String(), nil)
	inner := g.p.dial
	var first net.Conn
	g.p.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := inner(ctx, network, addr)
		if first == nil && err == nil {
			first = c
			g.p.SetPolicyOpening(policy.Enforce, nil, []string{"db.corp.example"}, nil, nil, nil, nil)
		}
		return c, err
	}
	_, _, code := g.open(t, 80)
	if code != http.StatusForbidden || g.seen.at(-1).Rule != GuardRule || g.seen.at(-1).Outcome != Refused {
		t.Errorf("CONNECT after a reload during the dial: %d, decision %+v; want the guard's refusal", code, g.seen.at(-1))
	}
	if got := g.rec.take(); len(got) != 1 || !strings.HasPrefix(got[0], "10.1.2.3:") {
		t.Errorf("dialled %v; want 10.1.2.3 once, before the reload", got)
	}
	if first == nil {
		t.Fatal("the dial made no connection")
	}
	if _, err := first.Write([]byte("GET / HTTP/1.0\r\n\r\n")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("the connection dialled before the reload: write %v; want it closed", err)
	}
	if n := dialledCount(g.p); n != 0 {
		t.Errorf("the list has %d entries; want 0", n)
	}
}

// TestAReloadBeforeTheDialOfAGuardNameDialsNothing pins that a reload that takes the
// guard name's opening away after the connection's decision and before its dial dials
// nothing at the host's private address: the dial gets the guard's refusal, and the
// list is empty.
func TestAReloadBeforeTheDialOfAGuardNameDialsNothing(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "origin") }))
	defer origin.Close()
	g := newGuardedName(t, policy.Enforce, nil, []string{"db.corp.example"}, origin.Listener.Addr().String(), nil)
	ctx := g.p.dialContext(context.Background(), Decision{Host: "db.corp.example", Rule: "db.corp.example", Allowed: true})
	g.p.SetPolicyOpening(policy.Enforce, nil, []string{"db.corp.example"}, nil, nil, nil, nil)
	c, err := g.p.dialHost(ctx, "tcp", "db.corp.example:80")
	if err == nil {
		c.Close()
	}
	var ge *guardError
	if !errors.As(err, &ge) {
		t.Errorf("dial after a reload before it: %v; want the guard's refusal", err)
	}
	if got := g.rec.take(); len(got) != 0 {
		t.Errorf("dialled %v; want nothing", got)
	}
	if n := dialledCount(g.p); n != 0 {
		t.Errorf("the list has %d entries; want 0", n)
	}
}

// dialledCount is the number of connections on p's list of connections dialled for a
// guard name.
func dialledCount(p *Proxy) int {
	p.tmu.Lock()
	defer p.tmu.Unlock()
	return len(p.dialled)
}
