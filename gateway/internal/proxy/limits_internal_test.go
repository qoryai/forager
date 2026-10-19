package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// fakeTime is a clock that moves only when a test moves it, and a wait that records
// what it was asked to wait and returns at once.
type fakeTime struct {
	mu    sync.Mutex
	at    time.Time
	waits []time.Duration
}

func newFakeTime() *fakeTime { return &fakeTime{at: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)} }

func (f *fakeTime) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.at
}

func (f *fakeTime) advance(d time.Duration) {
	f.mu.Lock()
	f.at = f.at.Add(d)
	f.mu.Unlock()
}

func (f *fakeTime) wait(_ context.Context, d time.Duration) bool {
	f.mu.Lock()
	f.waits = append(f.waits, d)
	f.mu.Unlock()
	return true
}

func (f *fakeTime) waited() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.waits...)
}

// limit sets l on p with the fake clock and wait of f.
func limit(p *Proxy, l Limits, f *fakeTime) {
	p.limits.Store(newLimiter(l, f.now, f.wait))
}

// holder is a loopback origin that keeps every connection open until its client closes
// it, and counts the connections it has.
type holder struct {
	ln net.Listener
	mu sync.Mutex
	n  int
}

func newHolder(t *testing.T) *holder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &holder{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			h.mu.Lock()
			h.n++
			h.mu.Unlock()
			go func() {
				io.Copy(io.Discard, c)
				c.Close()
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return h
}

// answer is what the proxy answered a CONNECT or a request.
type answer struct {
	status     int
	retryAfter string
	body       string
}

// connect sends a CONNECT to target on a new connection to addr, after preamble when
// it is not empty, and returns the answer and, for a 200, the open tunnel.
func connect(t *testing.T, addr, preamble, target string) (answer, net.Conn) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c, preamble+"CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	a := answer{status: resp.StatusCode, retryAfter: resp.Header.Get("Retry-After")}
	if resp.StatusCode == http.StatusOK {
		return a, c
	}
	b, _ := io.ReadAll(resp.Body)
	a.body = string(b)
	c.Close()
	return a, nil
}

// get sends a plain GET of rawURL through the proxy at proxyAddr.
func get(t *testing.T, proxyAddr, rawURL string) answer {
	t.Helper()
	u, _ := url.Parse("http://" + proxyAddr)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true}}
	resp, err := c.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return answer{status: resp.StatusCode, retryAfter: resp.Header.Get("Retry-After"), body: string(b)}
}

// refusals are the decisions seen whose rule is rule.
func (o *decisions) refusals(rule string) []Decision {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []Decision
	for _, d := range o.seen {
		if d.Rule == rule {
			out = append(out, d)
		}
	}
	return out
}

const connectionText = "qory: retry once one of this run's connections closes. The run has 2 connections open through the gateway, the most gateway.run_limits.connections allows.\n"

// TestTheConnectionLimitRefusesTheNextAndFreesASlotOnClose pins the connection limit:
// with 2 tunnels open, the next CONNECT and a plain request are refused at once with
// 429, Retry-After: 1 and the text with the limit, and nothing is dialled for them; once
// one tunnel closes, the next CONNECT opens. A refusal is denied and refused with
// wall:connection-limit.
func TestTheConnectionLimitRefusesTheNextAndFreesASlotOnClose(t *testing.T) {
	origin := newHolder(t)
	seen := &decisions{}
	p, err := Listen("", policy.Enforce, []string{"127.0.0.1"}, nil, seen.observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ft := newFakeTime()
	limit(p, Limits{Connections: 2, RequestsPerSecond: 1000, Burst: 1000}, ft)
	target := origin.ln.Addr().String()
	var open []net.Conn
	for range 2 {
		a, c := connect(t, p.Addr(), "", target)
		if a.status != http.StatusOK {
			t.Fatalf("a tunnel under the limit: %+v", a)
		}
		open = append(open, c)
	}
	a, _ := connect(t, p.Addr(), "", target)
	if a.status != http.StatusTooManyRequests || a.retryAfter != "1" || a.body != connectionText {
		t.Errorf("the third tunnel: %+v", a)
	}
	if a := get(t, p.Addr(), "http://"+target+"/"); a.status != http.StatusTooManyRequests || a.retryAfter != "1" || a.body != connectionText {
		t.Errorf("a plain request at the limit: %+v", a)
	}
	origin.mu.Lock()
	if origin.n != 2 {
		t.Errorf("the origin has %d connections, want 2", origin.n)
	}
	origin.mu.Unlock()
	got := seen.refusals(ConnectionLimit)
	if len(got) != 1 {
		t.Fatalf("%d refusals recorded in one second, want 1: %+v", len(got), got)
	}
	if d := got[0]; d.Allowed || d.Outcome != Refused || d.Method != http.MethodConnect || d.Host != "127.0.0.1" {
		t.Errorf("the refusal %+v", d)
	}
	open[0].Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a, c := connect(t, p.Addr(), "", target)
		if a.status == http.StatusOK {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no slot after a tunnel closed: %+v", a)
		}
		time.Sleep(10 * time.Millisecond)
	}
	open[1].Close()
}

// TestTheRateLimitWaitsThenRefuses pins the rate limit at 1 a second and a burst of 1,
// with the clock stopped: the first request passes at once, the next five wait 1 to 5
// seconds for their tokens and pass, the seventh waits 5 seconds and is refused with
// 429, Retry-After: 1 and the text with the rate; once the bucket has gained a token, a
// request passes with no wait.
func TestTheRateLimitWaitsThenRefuses(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	seen := &decisions{}
	p, err := Listen("", policy.Enforce, []string{"127.0.0.1"}, nil, seen.observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ft := newFakeTime()
	limit(p, Limits{Connections: 10, RequestsPerSecond: 1, Burst: 1}, ft)
	for i := range 6 {
		if a := get(t, p.Addr(), origin.URL); a.status != http.StatusOK {
			t.Fatalf("request %d: %+v", i+1, a)
		}
	}
	want := []time.Duration{time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second, 5 * time.Second}
	if got := ft.waited(); len(got) != len(want) || got[0] != want[0] || got[4] != want[4] {
		t.Errorf("waits %v, want %v", got, want)
	}
	a := get(t, p.Addr(), origin.URL)
	text := "qory: retry in 1 second. This run's requests came faster than 1 a second, the most gateway.run_limits.requests_per_second allows, and this request waited 5 seconds.\n"
	if a.status != http.StatusTooManyRequests || a.retryAfter != "1" || a.body != text {
		t.Errorf("the seventh request: %+v", a)
	}
	if got := ft.waited(); len(got) != 6 || got[5] != RateWait {
		t.Errorf("the refused request's wait: %v", got)
	}
	got := seen.refusals(RateLimit)
	if len(got) != 1 || got[0].Allowed || got[0].Outcome != Refused || got[0].Method != "HTTP" || got[0].RequestID == "" || got[0].Status != 0 {
		t.Errorf("the refusal %+v", got)
	}
	// The five reservations ahead are paid back by 6 seconds; the seventh's refusal took
	// none.
	ft.advance(7 * time.Second)
	if a := get(t, p.Addr(), origin.URL); a.status != http.StatusOK {
		t.Errorf("a request once a token is there: %+v", a)
	}
	if got := ft.waited(); len(got) != 6 {
		t.Errorf("the request after the refusal waited: %v", got)
	}
}

// TestARefusalIsRecordedOnceASecondPerLimit pins the record of the refusals: at one
// moment three refusals by the connection limit are one decision, and one by the rate
// limit is another; a second later the next refusal is recorded again.
func TestARefusalIsRecordedOnceASecondPerLimit(t *testing.T) {
	origin := newHolder(t)
	seen := &decisions{}
	p, err := Listen("", policy.Observe, nil, nil, seen.observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ft := newFakeTime()
	limit(p, Limits{Connections: 1, RequestsPerSecond: 1, Burst: 2}, ft)
	target := origin.ln.Addr().String()
	a, held := connect(t, p.Addr(), "", target)
	if a.status != http.StatusOK {
		t.Fatalf("the first tunnel: %+v", a)
	}
	defer held.Close()
	// Tokens: the burst of 2 holds the tunnel's and one more, then each waits.
	for range 3 {
		if a, _ := connect(t, p.Addr(), "", target); a.status != http.StatusTooManyRequests {
			t.Fatalf("a tunnel at the limit: %+v", a)
		}
	}
	if n := len(seen.refusals(ConnectionLimit)); n != 1 {
		t.Errorf("%d connection refusals recorded at one moment, want 1", n)
	}
	// The bucket is far behind now: the next request is refused by the rate.
	for range 6 {
		connect(t, p.Addr(), "", target)
	}
	if n := len(seen.refusals(RateLimit)); n != 1 {
		t.Errorf("%d rate refusals recorded at one moment, want 1", n)
	}
	ft.advance(time.Second)
	connect(t, p.Addr(), "", target)
	if n := len(seen.refusals(RateLimit)) + len(seen.refusals(ConnectionLimit)); n != 3 {
		t.Errorf("%d refusals recorded after a second, want 3", n)
	}
}

// TestARequestInsideATerminatedTunnelTakesAToken pins what the rate counts: the
// CONNECT of a terminated tunnel takes a token, and so does each request inside it, so
// with a burst of 2 the second request inside waits for its token.
func TestARequestInsideATerminatedTunnelTakesAToken(t *testing.T) {
	up, err := NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "origin") }))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return up.leaf(hello.ServerName) }}
	origin.StartTLS()
	defer origin.Close()
	seen := &decisions{}
	p, err := Listen("", policy.Observe, nil, nil, seen.observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.dial = (&dials{plain: origin.Listener.Addr().String(), secure: origin.Listener.Addr().String()}).dial
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(up.PEM())
	p.TrustUpstream(roots)
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	p.Terminate(ca, []Credential{{Name: "bearer", Hosts: []string{"api.example"}, Scheme: "bearer", Token: func() string { return "t-0001" }}}, nil, nil)
	ft := newFakeTime()
	limit(p, Limits{Connections: 10, RequestsPerSecond: 1, Burst: 2}, ft)
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	proxyURL, _ := url.Parse(p.URL())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}}
	defer client.CloseIdleConnections()
	for range 2 {
		resp, err := client.Get("https://api.example/v1/models")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("a request inside the tunnel: %d", resp.StatusCode)
		}
	}
	if got := ft.waited(); len(got) != 1 || got[0] != time.Second {
		t.Errorf("waits %v, want one of 1s: the CONNECT and the first request took the burst", got)
	}
}

// TestTwoRunsDoNotShareCounters pins that each run's proxy on a shared listener has
// counters of its own: run A at its limit of 1 connection refuses its next tunnel, and
// run B opens one; A's empty bucket refuses A's request and not B's.
func TestTwoRunsDoNotShareCounters(t *testing.T) {
	origin := newHolder(t)
	l, err := NewListener("", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	type run struct {
		p        *Proxy
		preamble string
	}
	runs := map[string]run{}
	for _, name := range []string{"a", "b"} {
		p, err := New(policy.Observe, nil, nil, (&decisions{}).observe)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		limit(p, Limits{Connections: 1, RequestsPerSecond: 1, Burst: 2}, newFakeTime())
		secret, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Register(secret, p); err != nil {
			t.Fatal(err)
		}
		runs[name] = run{p: p, preamble: link.RelayPreamble + " " + secret + "\n"}
	}
	target := origin.ln.Addr().String()
	a, heldA := connect(t, l.Addr(), runs["a"].preamble, target)
	if a.status != http.StatusOK {
		t.Fatalf("A's first tunnel: %+v", a)
	}
	defer heldA.Close()
	if a, _ := connect(t, l.Addr(), runs["a"].preamble, target); a.status != http.StatusTooManyRequests || !strings.Contains(a.body, "1 connections open") {
		t.Errorf("A's second tunnel: %+v", a)
	}
	a, heldB := connect(t, l.Addr(), runs["b"].preamble, target)
	if a.status != http.StatusOK {
		t.Fatalf("B's tunnel while A is at its limit: %+v", a)
	}
	defer heldB.Close()
	// A's bucket runs dry: with the clock stopped, its seventh request past the burst is
	// refused by the rate.
	rated := false
	for range 10 {
		if a, _ := connect(t, l.Addr(), runs["a"].preamble, target); strings.Contains(a.body, "requests came faster") {
			rated = true
			break
		}
	}
	if !rated {
		t.Fatal("A's requests were never refused by the rate")
	}
	// B's bucket still has a token: its next tunnel is refused by its connection limit,
	// at once.
	if a, _ := connect(t, l.Addr(), runs["b"].preamble, target); a.status != http.StatusTooManyRequests || !strings.Contains(a.body, "1 connections open") {
		t.Errorf("B's second tunnel: %+v", a)
	}
}
