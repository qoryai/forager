package proxy_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// reports collects what a listener reports.
type reports struct {
	mu   sync.Mutex
	seen []string
	ch   chan string
}

func newReports() *reports { return &reports{ch: make(chan string, 1024)} }

func (r *reports) report(s string) {
	r.mu.Lock()
	r.seen = append(r.seen, s)
	r.mu.Unlock()
	r.ch <- s
}

// none fails the test when any report names one of secrets.
func (r *reports) none(t *testing.T, secrets ...string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.seen {
		for _, secret := range secrets {
			if strings.Contains(s, secret) {
				t.Errorf("a report names a secret: %q", s)
			}
		}
	}
}

// wait waits for the next report and returns it.
func (r *reports) wait(t *testing.T) string {
	t.Helper()
	select {
	case s := <-r.ch:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("nothing reported")
		return ""
	}
}

// relayClient is a client that reaches the shared listener with secret's preamble on
// every connection, as the wall's relay would.
func relayClient(t *testing.T, l *proxy.Listener, secret string) *http.Client {
	t.Helper()
	u, err := url.Parse("http://" + l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{
		Proxy:             http.ProxyURL(u),
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if _, err := io.WriteString(c, link.RelayPreamble+" "+secret+"\n"); err != nil {
				c.Close()
				return nil, err
			}
			return c, nil
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// raw opens a connection to l, writes open and a request, and returns all it answers.
func raw(t *testing.T, l *proxy.Listener, open string) string {
	t.Helper()
	c, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(c, open+"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(c)
	return string(b)
}

func secret(t *testing.T) string {
	t.Helper()
	s, err := proxy.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newRun(t *testing.T, mode policy.Mode, allow []string, observe func(proxy.Decision)) *proxy.Proxy {
	t.Helper()
	p, err := proxy.New(mode, allow, nil, observe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func newListener(t *testing.T, r *reports) *proxy.Listener {
	t.Helper()
	l, err := proxy.NewListener("", r.report)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// TestNewSecretIsLongAndFresh pins the secret: 32 random bytes in base64url, one per
// call.
func TestNewSecretIsLongAndFresh(t *testing.T) {
	a, b := secret(t), secret(t)
	if len(a) != 43 || a == b {
		t.Fatalf("secrets %q and %q", a, b)
	}
	if strings.ContainsAny(a, "+/= \n") {
		t.Fatalf("secret %q is not base64url without padding", a)
	}
}

// TestListenerKeepsRunsApart pins dispatch: two runs on one port, each connection is
// decided by its own run's policy and told to its own run's observer alone.
func TestListenerKeepsRunsApart(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "plain "+r.URL.Path) }))
	defer origin.Close()
	r := newReports()
	l := newListener(t, r)
	var oa, ob observer
	a := newRun(t, policy.Enforce, []string{"127.0.0.1"}, oa.observe)
	b := newRun(t, policy.Enforce, []string{"example.invalid"}, ob.observe)
	sa, sb := secret(t), secret(t)
	if err := l.Register(sa, a); err != nil {
		t.Fatal(err)
	}
	if err := l.Register(sb, b); err != nil {
		t.Fatal(err)
	}
	if a.Addr() != "" || a.URL() != "" || a.Env() != nil {
		t.Errorf("a proxy on a shared listener has an address of its own: %q %q %v", a.Addr(), a.URL(), a.Env())
	}

	resp, err := relayClient(t, l, sa).Get(origin.URL + "/a")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "plain /a" {
		t.Fatalf("run a: %d %q", resp.StatusCode, body)
	}
	// A tunnel, through the same port, is the same run's.
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secure "+r.URL.Path) }))
	defer secure.Close()
	ca := relayClient(t, l, sa)
	ca.Transport.(*http.Transport).TLSClientConfig = secure.Client().Transport.(*http.Transport).TLSClientConfig
	resp, err = ca.Get(secure.URL + "/t")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "secure /t" {
		t.Fatalf("run a's tunnel: %q", body)
	}
	resp, err = relayClient(t, l, sb).Get(origin.URL + "/b")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("run b: %d, want its own policy's 403", resp.StatusCode)
	}

	if seen := oa.all(); len(seen) != 2 || !seen[0].Allowed || seen[0].Rule != "127.0.0.1" || seen[1].Method != "CONNECT" || seen[1].Outcome != proxy.Connected {
		t.Errorf("run a observed %+v", seen)
	}
	if seen := ob.all(); len(seen) != 1 || seen[0].Allowed || seen[0].Outcome != proxy.Refused {
		t.Errorf("run b observed %+v", seen)
	}
	r.none(t, sa, sb)
}

// TestListenerRefusesWhatNamesNoLiveRun pins the refusals: no preamble, a wrong
// secret, the secret of a run that ended, a line longer than any secret and a peer
// that sends nothing are each closed unanswered and reported, without the secret; the
// live run is served throughout.
func TestListenerRefusesWhatNamesNoLiveRun(t *testing.T) {
	r := newReports()
	l := newListener(t, r)
	l.SetWait(300 * time.Millisecond)
	live, ended := secret(t), secret(t)
	if err := l.Register(live, newRun(t, policy.Observe, nil, func(proxy.Decision) {})); err != nil {
		t.Fatal(err)
	}
	if err := l.Register(ended, newRun(t, policy.Observe, nil, func(proxy.Decision) {})); err != nil {
		t.Fatal(err)
	}
	l.Unregister(ended)
	wrong := secret(t)

	if got := raw(t, l, link.RelayPreamble+" "+live+"\n"); !strings.HasPrefix(got, "HTTP/1.1 400") {
		t.Errorf("the live run's secret was answered %q, want its proxy's refusal of a request that names no target", got)
	}
	for _, c := range []struct{ name, open, want string }{
		{"no preamble", "", proxy.RefusedRelay},
		{"another word", "QORY-RELAX " + live + "\n", proxy.RefusedRelay},
		{"wrong secret", link.RelayPreamble + " " + wrong + "\n", proxy.RefusedRelay},
		{"a prefix of the secret", link.RelayPreamble + " " + live[:30] + "\n", proxy.RefusedRelay},
		{"ended run", link.RelayPreamble + " " + ended + "\n", proxy.RefusedRelay},
		{"overlong", link.RelayPreamble + " " + strings.Repeat("a", 300) + "\n", proxy.RefusedRelay},
	} {
		if got := raw(t, l, c.open); got != "" {
			t.Errorf("%s: answered %q", c.name, got)
		}
		if got := r.wait(t); got != c.want {
			t.Errorf("%s: reported %q, want %q", c.name, got, c.want)
		}
	}

	// A peer that sends nothing, and one that stops halfway, are closed when the wait
	// is over.
	for _, open := range []string{"", link.RelayPreamble + " " + live[:10]} {
		c, err := net.Dial("tcp", l.Addr())
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, open)
		c.SetDeadline(time.Now().Add(5 * time.Second))
		start := time.Now()
		if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Errorf("a slow peer read %d bytes, %v", n, err)
		}
		if time.Since(start) > 4*time.Second {
			t.Error("a slow peer was not closed when its wait was over")
		}
		c.Close()
		if got := r.wait(t); got != proxy.RefusedRelay {
			t.Errorf("slow peer: reported %q", got)
		}
	}
	r.none(t, live, ended, wrong)
}

// TestRegisterRefusesSecretsItCannotServe pins Register's bounds, its refusal of a
// secret twice, of a proxy with a listener of its own, and that its errors never name
// the secret.
func TestRegisterRefusesSecretsItCannotServe(t *testing.T) {
	l := newListener(t, newReports())
	p := newRun(t, policy.Observe, nil, func(proxy.Decision) {})
	s := secret(t)
	for _, bad := range []string{"", "short-secret", s + " " + s, s + "\n", strings.Repeat("a", 257)} {
		if err := l.Register(bad, p); err == nil {
			t.Errorf("registered %q", bad)
		} else if bad != "" && strings.Contains(err.Error(), bad) {
			t.Errorf("the refusal names the secret: %v", err)
		}
	}
	if err := l.Register(s, p); err != nil {
		t.Fatal(err)
	}
	if err := l.Register(s, newRun(t, policy.Observe, nil, func(proxy.Decision) {})); err == nil || strings.Contains(err.Error(), s) {
		t.Errorf("a live run's secret registered again: %v", err)
	}
	own, err := proxy.Listen("", policy.Observe, nil, nil, func(proxy.Decision) {})
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	if err := l.Register(secret(t), own); err == nil {
		t.Error("registered a proxy with a listener of its own")
	}
}

// TestClosedRunRefusesItsConnections pins the end of a run: once its proxy is closed,
// a connection that still names its secret is closed unanswered, and the listener
// serves the other runs as before.
func TestClosedRunRefusesItsConnections(t *testing.T) {
	l := newListener(t, newReports())
	done, other := secret(t), secret(t)
	p := newRun(t, policy.Observe, nil, func(proxy.Decision) {})
	if err := l.Register(done, p); err != nil {
		t.Fatal(err)
	}
	if err := l.Register(other, newRun(t, policy.Observe, nil, func(proxy.Decision) {})); err != nil {
		t.Fatal(err)
	}
	p.Close()
	if got := raw(t, l, link.RelayPreamble+" "+done+"\n"); got != "" {
		t.Errorf("a closed run's proxy answered %q", got)
	}
	if got := raw(t, l, link.RelayPreamble+" "+other+"\n"); !strings.HasPrefix(got, "HTTP/1.1 400") {
		t.Errorf("the other run was answered %q", got)
	}
}

// TestListenerUnderConcurrentRuns pins dispatch with runs registering, connecting,
// ending and strangers connecting all at once: every run sees its own decisions and
// no one else's.
func TestListenerUnderConcurrentRuns(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.URL.Path) }))
	defer origin.Close()
	r := newReports()
	l := newListener(t, r)
	go func() {
		for range r.ch {
		}
	}()
	const runs, requests = 16, 4
	var wg sync.WaitGroup
	secrets := make(chan string, runs)
	for i := range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var o observer
			p, err := proxy.New(policy.Enforce, []string{"127.0.0.1"}, nil, o.observe)
			if err != nil {
				t.Error(err)
				return
			}
			defer p.Close()
			s, err := proxy.NewSecret()
			if err != nil {
				t.Error(err)
				return
			}
			secrets <- s
			if err := l.Register(s, p); err != nil {
				t.Error(err)
				return
			}
			c := relayClient(t, l, s)
			for j := range requests {
				path := fmt.Sprintf("/run%d/%d", i, j)
				resp, err := c.Get(origin.URL + path)
				if err != nil {
					t.Error(err)
					return
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if string(body) != path {
					t.Errorf("run %d asked for %s and got %q", i, path, body)
				}
			}
			l.Unregister(s)
			o.mu.Lock()
			defer o.mu.Unlock()
			if len(o.seen) != requests {
				t.Errorf("run %d observed %d decisions, want %d", i, len(o.seen), requests)
			}
		}()
	}
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range requests {
				c, err := net.Dial("tcp", l.Addr())
				if err != nil {
					t.Error(err)
					return
				}
				c.SetDeadline(time.Now().Add(10 * time.Second))
				fmt.Fprintf(c, "%s %s\nGET %s/ HTTP/1.1\r\nHost: x\r\n\r\n", link.RelayPreamble, strings.Repeat("x", 43), origin.URL)
				if b, _ := io.ReadAll(c); len(b) != 0 {
					t.Errorf("a stranger was answered %q", b)
				}
				c.Close()
			}
		}()
	}
	wg.Wait()
	close(secrets)
	var all []string
	for s := range secrets {
		all = append(all, s)
	}
	r.none(t, all...)
}
