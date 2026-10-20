package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/policy"
)

// TestAReloadDuringTheDialOfATunnelClosesIt pins a reload that lands while the proxy
// dials the host of a tunnel it passes TLS through, before the tunnel is on the
// proxy's list: a reload that gives the host a credential with no paths, and one that
// denies the host, close the tunnel once the dial returns. The denial is recorded,
// refused.
func TestAReloadDuringTheDialOfATunnelClosesIt(t *testing.T) {
	creds := []Credential{{Name: "product", Hosts: []string{"localhost"}, Scheme: "bearer", Token: func() string { return "fake-token" }}}
	for _, c := range []struct {
		name    string
		reload  func(*Proxy)
		refused bool
	}{
		{"the reload gives the host a credential", func(p *Proxy) {
			p.SetPolicy(policy.Enforce, []string{"localhost"}, nil, nil, creds)
		}, false},
		{"the reload denies the host", func(p *Proxy) {
			p.SetPolicy(policy.Enforce, nil, nil, nil, nil)
		}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
			defer origin.Close()
			_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
			seen := &decisions{}
			p, err := Listen("", policy.Enforce, []string{"localhost"}, nil, seen.observe)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			ca, err := NewCA("test")
			if err != nil {
				t.Fatal(err)
			}
			p.Terminate(ca, nil, nil, nil)
			inner := p.dial
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			p.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
				once.Do(func() { close(entered) })
				<-release
				return inner(ctx, network, addr)
			}
			conn, err := net.Dial("tcp", p.Addr())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			fmt.Fprintf(conn, "CONNECT localhost:%s HTTP/1.1\r\nHost: localhost:%s\r\n\r\n", port, port)
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("the proxy dialled nothing")
			}
			c.reload(p)
			close(release)
			// The proxy closes the tunnel before it writes the 200 line, so reading the
			// answer fails, and not at the deadline. After a 200, the next read must fail.
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
			if err == nil {
				resp.Body.Close()
				_, err = br.ReadByte()
			}
			var ne net.Error
			if err == nil || errors.As(err, &ne) && ne.Timeout() {
				t.Errorf("the tunnel dialled during the reload is still open: %v", err)
			}
			if last := seen.at(-1); c.refused && (last.Allowed || last.Outcome != Refused) {
				t.Errorf("the last decision is %+v; want the reload's denial, refused", last)
			}
		})
	}
}

// TestAReloadAndTheRecheckRecordADenialOnce pins a tunnel that a reload denying its host
// lists and that [Proxy.recheck] finds denied as well: it is closed and recorded
// refused once, by the reload when the reload lists it first, and by the observer when
// the recheck runs between the reload's switch to the new rules and its list.
func TestAReloadAndTheRecheckRecordADenialOnce(t *testing.T) {
	for _, c := range []struct {
		name         string
		recheckFirst bool
	}{
		{"the reload lists the tunnel first", false},
		{"the recheck runs first", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			seen := &decisions{}
			p, err := Listen("", policy.Enforce, []string{"localhost"}, nil, seen.observe)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			old, term := p.rules.Load(), p.term.Load()
			d := p.decide(http.MethodConnect, "localhost", 443)
			if !d.Allowed {
				t.Fatalf("decision %+v; want it allowed", d)
			}
			client, far := net.Pipe()
			defer far.Close()
			tn := p.track(d, false, client)
			defer p.untrack(tn)
			var refused []Decision
			if c.recheckFirst {
				// The reload's switch to the new rules, before its list.
				p.rules.Store(&rules{mode: policy.Enforce})
			} else {
				refused = p.SetPolicy(policy.Enforce, nil, nil, nil, nil)
			}
			if p.recheck(tn, term, old) {
				t.Error("recheck kept the tunnel to a denied host open")
			}
			if c.recheckFirst {
				refused = p.SetPolicy(policy.Enforce, nil, nil, nil, nil)
			}
			observed := 0
			for i := range seen.count() {
				if seen.at(i).Outcome == Refused {
					observed++
				}
			}
			if len(refused)+observed != 1 {
				t.Errorf("the reload returned %d refusals and the observer got %d; want 1 in all", len(refused), observed)
			}
			far.SetDeadline(time.Now().Add(2 * time.Second))
			var ne net.Error
			if _, err := far.Read(make([]byte, 1)); err == nil || errors.As(err, &ne) && ne.Timeout() {
				t.Errorf("the tunnel is still open: %v", err)
			}
		})
	}
}
