package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/server"
)

const routeRun = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"

// routeURL is the run's URL of path under the route.
func routeURL(path string) string { return link.RunAPIURL(routeRun) + path }

// route is one proxy with the route on a listener of the test, with the decisions it
// wrote and a count of the requests it signed and sent.
type route struct {
	p    *Proxy
	a    *RunAPI
	sent atomic.Int32

	mu        sync.Mutex
	decisions []Decision
}

// startRoute starts a proxy with the route, with a's fields set. send is a's Send, and
// the default returns an empty 200.
func startRoute(t *testing.T, a *RunAPI, send func(ctx context.Context, method, path string, body []byte, file bool) (*server.RunAPIAnswer, error)) *route {
	t.Helper()
	r := &route{a: a}
	p, err := Listen("127.0.0.1:0", policy.Enforce, nil, nil, func(d Decision) {
		r.mu.Lock()
		r.decisions = append(r.decisions, d)
		r.mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	r.p = p
	a.RunID = routeRun
	if a.Limits == nil {
		a.Limits = &RunAPILimits{}
	}
	a.Send = func(ctx context.Context, method, path string, body []byte, file bool) (*server.RunAPIAnswer, error) {
		r.sent.Add(1)
		if send == nil {
			return &server.RunAPIAnswer{Status: http.StatusOK, Header: http.Header{}}, nil
		}
		return send(ctx, method, path, body, file)
	}
	p.SetRunAPI(a)
	return r
}

// client is an HTTP client through the proxy.
func (r *route) client() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: r.p.Addr()}), DisableKeepAlives: true}}
}

// status sends the request and returns the status, the error code and the Retry-After.
func (r *route) status(t *testing.T, method, path string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(method, routeURL(path), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc struct {
		Error string `json:"error"`
	}
	b, _ := io.ReadAll(resp.Body)
	json.Unmarshal(b, &doc)
	return resp.StatusCode, doc.Error, resp.Header.Get("Retry-After")
}

// limited fails the test unless the request gets the route's 429.
func (r *route) limited(t *testing.T, what, method, path string) {
	t.Helper()
	if status, code, retry := r.status(t, method, path); status != http.StatusTooManyRequests || code != "rate_limited" || retry != "1" {
		t.Errorf("%s: %d %s, Retry-After %q", what, status, code, retry)
	}
}

// heldSends is a Send whose requests wait until release closes, or their context ends.
func heldSends(entered chan<- struct{}, release <-chan struct{}) func(ctx context.Context, method, path string, body []byte, file bool) (*server.RunAPIAnswer, error) {
	return func(ctx context.Context, _, _ string, _ []byte, _ bool) (*server.RunAPIAnswer, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return &server.RunAPIAnswer{Status: http.StatusOK, Header: http.Header{}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// hold starts n requests that r holds in Send, and returns once all are there.
func (r *route) hold(t *testing.T, wg *sync.WaitGroup, entered <-chan struct{}, n int, method, path string) {
	t.Helper()
	for range n {
		wg.Go(func() { r.status(t, method, path) })
	}
	for range n {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("a request did not reach Send")
		}
	}
}

// TestTheTargetReadsTheRawTargetAndTheParsedOne pins the two checks of a query apart:
// target refuses a raw target with a query where the path starts, whatever the parsed URL
// contains, and a parsed URL with a query, whatever the raw target contains.
func TestTheTargetReadsTheRawTargetAndTheParsedOne(t *testing.T) {
	a := &RunAPI{RunID: routeRun}
	path := strings.TrimPrefix(routeURL("/work-item"), "http://"+link.RunAPIHost)
	request := func(raw string, u url.URL) *http.Request {
		u.Scheme, u.Host = "http", link.RunAPIHost
		return &http.Request{Method: http.MethodGet, RequestURI: raw, URL: &u, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}
	}
	if _, ok := a.target(request(routeURL("/work-item"), url.URL{Path: path})); !ok {
		t.Fatal("the request of a shape is outside")
	}
	for what, r := range map[string]*http.Request{
		"a raw query before the path":     request("http://"+link.RunAPIHost+"?"+path, url.URL{Path: path}),
		"a raw fragment before the path":  request("http://"+link.RunAPIHost+"#"+path, url.URL{Path: path}),
		"port 80 and a raw query":         request("http://"+link.RunAPIHost+":80?x="+path, url.URL{Path: path}),
		"no path":                         request("http://"+link.RunAPIHost, url.URL{Path: path}),
		"a raw query that is the path":    request("http://"+link.RunAPIHost+"?"+strings.TrimPrefix(path, "/"), url.URL{Path: path}),
		"a raw fragment that is the path": request("http://"+link.RunAPIHost+"#"+strings.TrimPrefix(path, "/"), url.URL{Path: path}),
		"a parsed query":                  request(routeURL("/work-item"), url.URL{Path: path, RawQuery: "x=1"}),
		"a parsed empty query":            request(routeURL("/work-item"), url.URL{Path: path, ForceQuery: true}),
		"a raw query after the path":      request(routeURL("/work-item?x=1"), url.URL{Path: path}),
		"a raw fragment after the path":   request(routeURL("/work-item#x"), url.URL{Path: path}),
	} {
		if _, ok := a.target(r); ok {
			t.Errorf("%s reached a shape", what)
		}
	}
}

// TestTheRoutesRate pins 10 requests a second for a run: the eleventh in a second is a
// 429 with Retry-After: 1 and nothing sent, and the tokens come back with time.
func TestTheRoutesRate(t *testing.T) {
	f := newFakeTime()
	r := startRoute(t, &RunAPI{now: f.now}, nil)
	for range RunAPIRate {
		if status, _, _ := r.status(t, http.MethodGet, "/work-item"); status != http.StatusOK {
			t.Fatalf("a request within the rate: %d", status)
		}
	}
	r.limited(t, "the eleventh", http.MethodGet, "/work-item")
	if got := r.sent.Load(); got != RunAPIRate {
		t.Errorf("%d requests sent", got)
	}
	f.advance(time.Second)
	if status, _, _ := r.status(t, http.MethodGet, "/work-item"); status != http.StatusOK {
		t.Errorf("a second later: %d", status)
	}
}

// TestRequestsOutsideTheShapesSpendNoRouteToken pins that a 404 takes no token of the
// route's bucket, so a program that probes does not stop the run's work.
func TestRequestsOutsideTheShapesSpendNoRouteToken(t *testing.T) {
	r := startRoute(t, &RunAPI{now: newFakeTime().now}, nil)
	for range 3 * RunAPIRate {
		if status, code, _ := r.status(t, http.MethodGet, "/diagnostics"); status != http.StatusNotFound || code != "not_found" {
			t.Fatalf("%d %s", status, code)
		}
	}
	if status, _, _ := r.status(t, http.MethodGet, "/work-item"); status != http.StatusOK {
		t.Errorf("%d", status)
	}
}

// TestFourInFlightPerRun pins the run's limit of requests in flight: a 429 with nothing
// sent at the fifth, and the next request passes once one ends.
func TestFourInFlightPerRun(t *testing.T) {
	entered, release := make(chan struct{}, RunAPIInFlight), make(chan struct{})
	r := startRoute(t, &RunAPI{}, heldSends(entered, release))
	var wg sync.WaitGroup
	r.hold(t, &wg, entered, RunAPIInFlight, http.MethodGet, "/work-item")
	r.limited(t, "the fifth", http.MethodGet, "/work-item")
	if got := r.sent.Load(); got != RunAPIInFlight {
		t.Errorf("%d requests sent", got)
	}
	close(release)
	wg.Wait()
	if status, _, _ := r.status(t, http.MethodGet, "/work-item"); status != http.StatusOK {
		t.Errorf("after the four: %d", status)
	}
}

// heldPosts is a Send that holds a POST as [heldSends] does and answers any other request.
func heldPosts(entered chan<- struct{}, release <-chan struct{}) func(ctx context.Context, method, path string, body []byte, file bool) (*server.RunAPIAnswer, error) {
	held := heldSends(entered, release)
	return func(ctx context.Context, method, path string, body []byte, file bool) (*server.RunAPIAnswer, error) {
		if method == http.MethodPost {
			return held(ctx, method, path, body, file)
		}
		return &server.RunAPIAnswer{Status: http.StatusOK, Header: http.Header{}}, nil
	}
}

// TestOnePostInFlightPerRun pins the run's limit of POSTs: a second POST of the run is a
// 429 with nothing sent, a GET passes, and the next POST passes once the first ends.
func TestOnePostInFlightPerRun(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	r := startRoute(t, &RunAPI{}, heldPosts(entered, release))
	var wg sync.WaitGroup
	r.hold(t, &wg, entered, 1, http.MethodPost, "/artifacts")
	r.limited(t, "the second POST", http.MethodPost, "/verdict")
	if status, _, _ := r.status(t, http.MethodGet, "/work-item"); status != http.StatusOK {
		t.Errorf("a GET: %d", status)
	}
	if got := r.sent.Load(); got != 2 {
		t.Errorf("%d requests sent", got)
	}
	close(release)
	wg.Wait()
	if status, _, _ := r.status(t, http.MethodPost, "/verdict"); status != http.StatusOK {
		t.Errorf("after the first POST: %d", status)
	}
}

// TestEightArtifactSendsPerGateway pins the gateway's send slots across its runs: a ninth
// POST artifacts waits, then gets a 429 with nothing sent, while a POST verdict and a GET
// pass, since neither takes a slot.
func TestEightArtifactSendsPerGateway(t *testing.T) {
	const wait = 100 * time.Millisecond
	limits := &RunAPILimits{queueWait: wait}
	entered, release := make(chan struct{}, RunAPIArtifactSends), make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(release)
		wg.Wait()
	}()
	for range RunAPIArtifactSends {
		startRoute(t, &RunAPI{Limits: limits}, heldSends(entered, release)).hold(t, &wg, entered, 1, http.MethodPost, "/artifacts")
	}
	ninth := startRoute(t, &RunAPI{Limits: limits}, nil)
	start := time.Now()
	ninth.limited(t, "the ninth", http.MethodPost, "/artifacts")
	if d := time.Since(start); d < wait {
		t.Errorf("the ninth waited %v", d)
	}
	if got := ninth.sent.Load(); got != 0 {
		t.Errorf("%d requests sent", got)
	}
	if status, _, _ := ninth.status(t, http.MethodPost, "/verdict"); status != http.StatusOK {
		t.Errorf("a POST verdict: %d", status)
	}
	if status, _, _ := ninth.status(t, http.MethodGet, "/work-item"); status != http.StatusOK {
		t.Errorf("a GET: %d", status)
	}
}

// TestAPostGetsASendSlotThatEnds pins the wait for a slot: a ninth POST artifacts passes
// when a slot ends inside the wait.
func TestAPostGetsASendSlotThatEnds(t *testing.T) {
	limits := &RunAPILimits{}
	entered, release := make(chan struct{}, RunAPIArtifactSends), make(chan struct{})
	var wg sync.WaitGroup
	for range RunAPIArtifactSends {
		startRoute(t, &RunAPI{Limits: limits}, heldSends(entered, release)).hold(t, &wg, entered, 1, http.MethodPost, "/artifacts")
	}
	ninth := startRoute(t, &RunAPI{Limits: limits}, nil)
	done := make(chan int, 1)
	go func() {
		status, _, _ := ninth.status(t, http.MethodPost, "/artifacts")
		done <- status
	}()
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if status := <-done; status != http.StatusOK {
		t.Errorf("the ninth: %d", status)
	}
}

// TestAStalledBodyHoldsOnlyItsRun pins what a stalled body costs: its run's POST and none
// of the gateway's slots, so another run's verdict and artifacts pass during the stall,
// with more runs stalled than the gateway has slots.
func TestAStalledBodyHoldsOnlyItsRun(t *testing.T) {
	limits := &RunAPILimits{}
	var stalled []*route
	for range RunAPIArtifactSends + 1 {
		r := startRoute(t, &RunAPI{Limits: limits}, nil)
		c, err := net.Dial("tcp", r.p.Addr())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 1000\r\n\r\n{", routeURL("/artifacts"), link.RunAPIHost)
		stalled = append(stalled, r)
	}
	for _, r := range stalled {
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
			r.a.mu.Lock()
			posting := r.a.posting
			r.a.mu.Unlock()
			if posting {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("no stalled POST reached the route")
			}
		}
	}
	if got := len(limits.slots); got != 0 {
		t.Errorf("the stalled bodies hold %d send slots", got)
	}
	other := startRoute(t, &RunAPI{Limits: limits}, nil)
	for _, path := range []string{"/verdict", "/artifacts"} {
		if status, _, _ := other.status(t, http.MethodPost, path); status != http.StatusOK {
			t.Errorf("another run's POST %s: %d", path, status)
		}
	}
	if got := other.sent.Load(); got != 2 {
		t.Errorf("%d requests sent", got)
	}
	stalled[0].limited(t, "the stalled run's second POST", http.MethodPost, "/verdict")
}

// TestTheGatewaysBucket pins the bucket: the burst passes with no wait, each next request
// waits longer than the one before, up to 5 seconds, and the one after that is refused
// with nothing taken.
func TestTheGatewaysBucket(t *testing.T) {
	f := newFakeTime()
	l := &RunAPILimits{now: f.now, sleep: f.wait}
	take := func() error { return l.take(context.Background()) }
	for range RunAPIGatewayRate {
		if err := take(); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.waited(); len(got) != 0 {
		t.Fatalf("the burst waited: %v", got)
	}
	const waiters = 5 * RunAPIGatewayRate
	for range waiters {
		if err := take(); err != nil {
			t.Fatal(err)
		}
	}
	got := f.waited()
	if len(got) != waiters {
		t.Fatalf("%d waits", len(got))
	}
	for i, d := range got {
		if want := time.Duration(i+1) * time.Second / RunAPIGatewayRate; (d - want).Abs() > time.Microsecond {
			t.Errorf("wait %d is %v, want %v", i, d, want)
		}
	}
	if err := take(); !errors.Is(err, errRunAPIBusy) {
		t.Errorf("past the wait: %v", err)
	}
	f.advance(time.Second)
	if err := take(); err != nil {
		t.Errorf("a second later: %v", err)
	}
}

// TestAWaitForAGatewayTokenEndsWithItsContext pins a request that stops waiting: it gives
// its token back.
func TestAWaitForAGatewayTokenEndsWithItsContext(t *testing.T) {
	f := newFakeTime()
	l := &RunAPILimits{now: f.now, sleep: func(context.Context, time.Duration) bool { return false }}
	for range RunAPIGatewayRate {
		if err := l.take(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.take(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("%v", err)
	}
	if l.tokens != 0 {
		t.Errorf("%v tokens", l.tokens)
	}
}

// TestTheGatewayCapsSignedRequests pins the cap across runs: 13 runs at their 10 requests
// a second sign the burst and 5 seconds of tokens and no more, and past that every one of
// the five requests is the route's 429, with nothing sent and no send slot kept.
func TestTheGatewayCapsSignedRequests(t *testing.T) {
	f := newFakeTime()
	limits := &RunAPILimits{now: f.now, sleep: f.wait}
	total := int32(0)
	for range 13 {
		r := startRoute(t, &RunAPI{Limits: limits, now: f.now}, nil)
		for range RunAPIRate {
			r.status(t, http.MethodGet, "/work-item")
		}
		total += r.sent.Load()
	}
	if want := int32(6 * RunAPIGatewayRate); total != want {
		t.Errorf("%d requests signed, want %d", total, want)
	}
	got := f.waited()
	if len(got) != 5*RunAPIGatewayRate || (got[len(got)-1]-5*time.Second).Abs() > time.Microsecond {
		t.Errorf("%d waits, the last %v", len(got), got[len(got)-1])
	}
	r := startRoute(t, &RunAPI{Limits: limits, now: f.now}, nil)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/work-item"},
		{http.MethodGet, "/artifacts"},
		{http.MethodGet, "/artifacts/v/files/f"},
		{http.MethodPost, "/artifacts"},
		{http.MethodPost, "/verdict"},
	} {
		r.limited(t, c.method+" "+c.path, c.method, c.path)
	}
	if got := r.sent.Load(); got != 0 {
		t.Errorf("%d requests sent", got)
	}
	if got := len(limits.slots); got != 0 {
		t.Errorf("%d send slots kept", got)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.decisions {
		if d.Allowed || d.Outcome != Refused || d.Status != http.StatusTooManyRequests || d.Rule != RunAPIRule {
			t.Errorf("a decision: %+v", d)
		}
	}
}

// rawStatus writes req on one connection and returns the status line.
func rawStatus(t *testing.T, r *route, req string) string {
	t.Helper()
	c, err := net.Dial("tcp", r.p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, req)
	line, _ := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(line)
}

// TestNothingOutlivesARequest pins every slot's end: after each way a request ends, the
// run's count, its POST, the gateway's send slot and the run's one connection are free,
// so one more request passes.
func TestNothingOutlivesARequest(t *testing.T) {
	f := newFakeTime()
	limits := &RunAPILimits{now: f.now, sleep: f.wait}
	mode := make(chan func() (*server.RunAPIAnswer, error), 1)
	a := &RunAPI{Limits: limits, now: f.now, postWait: 50 * time.Millisecond}
	r := startRoute(t, a, func(context.Context, string, string, []byte, bool) (*server.RunAPIAnswer, error) {
		select {
		case m := <-mode:
			return m()
		default:
			return &server.RunAPIAnswer{Status: http.StatusOK, Header: http.Header{}}, nil
		}
	})
	limit(r.p, Limits{Connections: 1}, f)
	free := func(what string) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
			f.advance(time.Second)
			a.mu.Lock()
			idle := a.inFlight == 0 && !a.posting
			a.mu.Unlock()
			if !idle || len(limits.slots) != 0 {
				continue
			}
			if status, _, _ := r.status(t, http.MethodGet, "/work-item"); status == http.StatusOK {
				return
			}
		}
		t.Errorf("%s: a slot outlives the request", what)
	}
	fails := func(err error) func() (*server.RunAPIAnswer, error) {
		return func() (*server.RunAPIAnswer, error) { return nil, err }
	}
	post := func(path string) string {
		return "POST " + routeURL(path) + " HTTP/1.1\r\nHost: " + link.RunAPIHost + "\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}"
	}
	get := func(path string) string {
		return "GET " + routeURL(path) + " HTTP/1.1\r\nHost: " + link.RunAPIHost + "\r\nConnection: close\r\n\r\n"
	}
	for _, c := range []struct {
		what, request string
		answer        func() (*server.RunAPIAnswer, error)
	}{
		{what: "a POST artifacts", request: post("/artifacts")},
		{what: "a POST verdict", request: post("/verdict")},
		{what: "a POST artifacts with no answer", request: post("/artifacts"), answer: fails(errors.New("no answer"))},
		{what: "an unverified POST", request: post("/artifacts"), answer: fails(server.ErrRunAPIUnverified)},
		{what: "a POST over the bound", request: post("/verdict"), answer: fails(server.ErrRunAPITooLarge)},
		{what: "a GET with no answer", request: get("/work-item"), answer: fails(errors.New("no answer"))},
		{what: "a body that ends early", request: "POST " + routeURL("/verdict") + " HTTP/1.1\r\nHost: " + link.RunAPIHost + "\r\nContent-Length: 10\r\n\r\n{"},
		{what: "a body over its limit", request: "POST " + routeURL("/verdict") + " HTTP/1.1\r\nHost: " + link.RunAPIHost + "\r\nTransfer-Encoding: chunked\r\n\r\n20000\r\n" + strings.Repeat("a", 0x20000) + "\r\n0\r\n\r\n"},
		{what: "a file that fails", request: get("/artifacts/v/files/f"), answer: func() (*server.RunAPIAnswer, error) {
			return &server.RunAPIAnswer{Status: http.StatusOK, Header: http.Header{}, File: io.NopCloser(failing{errors.New("cut")})}, nil
		}},
	} {
		if c.answer != nil {
			mode <- c.answer
		}
		if line := rawStatus(t, r, c.request); line == "" {
			t.Errorf("%s: no status", c.what)
		}
		free(c.what)
	}
}

// endless is a file with no end, whose Close closes closed.
type endless struct {
	closed chan struct{}
	once   sync.Once
}

func (e *endless) Read(p []byte) (int, error) { return len(p), nil }

func (e *endless) Close() error {
	e.once.Do(func() { close(e.closed) })
	return nil
}

// TestAStalledReaderOfAFileTimesOut pins the write deadline: a caller that stops reading
// a file ends at the file's time, with a 503 in the record and the file closed.
func TestAStalledReaderOfAFileTimesOut(t *testing.T) {
	file := &endless{closed: make(chan struct{})}
	r := startRoute(t, &RunAPI{fileWait: 100 * time.Millisecond}, func(context.Context, string, string, []byte, bool) (*server.RunAPIAnswer, error) {
		return &server.RunAPIAnswer{Status: http.StatusOK, Header: http.Header{}, File: file}, nil
	})
	c, err := net.Dial("tcp", r.p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", routeURL("/artifacts/v/files/f"), link.RunAPIHost)
	select {
	case <-file.closed:
	case <-time.After(30 * time.Second):
		t.Fatal("the stream outlived its write deadline")
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		r.mu.Lock()
		n := len(r.decisions)
		var status int
		if n == 1 {
			status = r.decisions[0].Status
		}
		r.mu.Unlock()
		if n == 1 && status != http.StatusServiceUnavailable {
			t.Fatalf("status %d", status)
		}
		if n == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d decisions", n)
		}
	}
}

// TestARefusalOfTheRunsBucketIsRecordedOnceASecond pins the record of a request the run's
// bucket refuses: every such request gets the 429, and one decision a second is written.
func TestARefusalOfTheRunsBucketIsRecordedOnceASecond(t *testing.T) {
	f := newFakeTime()
	r := startRoute(t, &RunAPI{now: f.now, Limits: &RunAPILimits{now: f.now, sleep: f.wait}}, nil)
	limit(r.p, Limits{Connections: 16, RequestsPerSecond: 1, Burst: 1}, f)
	refusals := func() int {
		r.mu.Lock()
		defer r.mu.Unlock()
		n := 0
		for _, d := range r.decisions {
			if d.Status == http.StatusTooManyRequests {
				n++
			}
		}
		return n
	}
	for range 6 {
		if status, _, _ := r.status(t, http.MethodGet, "/work-item"); status != http.StatusOK {
			t.Fatalf("%d", status)
		}
	}
	for range 3 {
		r.limited(t, "past the bucket", http.MethodGet, "/work-item")
	}
	if got := refusals(); got != 1 {
		t.Errorf("%d refusals recorded in a second", got)
	}
	f.advance(time.Second)
	if status, _, _ := r.status(t, http.MethodGet, "/work-item"); status != http.StatusOK {
		t.Fatalf("a second later: %d", status)
	}
	for range 3 {
		r.limited(t, "past the bucket again", http.MethodGet, "/work-item")
	}
	if got := refusals(); got != 2 {
		t.Errorf("%d refusals recorded in two seconds", got)
	}
}

// TestTheRunsLimitsApply pins the run's take and hold on the route: past the run's
// bucket, and at the run's connections, a request is the route's 429 with nothing sent.
func TestTheRunsLimitsApply(t *testing.T) {
	t.Run("the bucket", func(t *testing.T) {
		r := startRoute(t, &RunAPI{}, nil)
		f := newFakeTime()
		limit(r.p, Limits{Connections: 8, RequestsPerSecond: 1, Burst: 1}, f)
		if status, _, _ := r.status(t, http.MethodGet, "/work-item"); status != http.StatusOK {
			t.Fatalf("the first: %d", status)
		}
		for range 7 {
			r.status(t, http.MethodGet, "/work-item")
		}
		r.limited(t, "past the bucket", http.MethodGet, "/work-item")
		if got := r.sent.Load(); got > 7 {
			t.Errorf("%d requests sent", got)
		}
	})
	t.Run("the connections", func(t *testing.T) {
		entered, release := make(chan struct{}, 1), make(chan struct{})
		r := startRoute(t, &RunAPI{}, heldSends(entered, release))
		limit(r.p, Limits{Connections: 1}, newFakeTime())
		var wg sync.WaitGroup
		defer func() {
			close(release)
			wg.Wait()
		}()
		r.hold(t, &wg, entered, 1, http.MethodGet, "/work-item")
		r.limited(t, "the second", http.MethodGet, "/work-item")
	})
}

// TestTheRoutesTimes pins the defaults, and that a POST and a file end with their
// context: a Send that runs out of time is a 503.
func TestTheRoutesTimes(t *testing.T) {
	a := &RunAPI{}
	if got := a.wait(runAPITarget{post: true}); got != 60*time.Second {
		t.Errorf("a POST has %s", got)
	}
	if got := a.wait(runAPITarget{file: true}); got != 10*time.Minute {
		t.Errorf("a file has %s", got)
	}
	if got := a.wait(runAPITarget{}); got != 60*time.Second {
		t.Errorf("a GET has %s", got)
	}
	entered, release := make(chan struct{}, 2), make(chan struct{})
	defer close(release)
	r := startRoute(t, &RunAPI{postWait: 50 * time.Millisecond, fileWait: 50 * time.Millisecond}, heldSends(entered, release))
	for method, path := range map[string]string{http.MethodPost: "/verdict", http.MethodGet: "/artifacts/v/files/f"} {
		if status, code, _ := r.status(t, method, path); status != http.StatusServiceUnavailable || code != "unavailable" {
			t.Errorf("%s %s: %d %s", method, path, status, code)
		}
	}
}

// TestAStalledBodyTimesOut pins a POST whose body stops: a 503 with Connection: close at
// its time, and nothing sent.
func TestAStalledBodyTimesOut(t *testing.T) {
	r := startRoute(t, &RunAPI{postWait: 50 * time.Millisecond}, nil)
	c, err := net.Dial("tcp", r.p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "POST "+routeURL("/verdict")+" HTTP/1.1\r\nHost: "+link.RunAPIHost+"\r\nContent-Length: 10\r\n\r\n{")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !resp.Close {
		t.Errorf("%d, close %v", resp.StatusCode, resp.Close)
	}
	if got := r.sent.Load(); got != 0 {
		t.Errorf("%d requests sent", got)
	}
}

// TestAFileThatEndsBadlyIsAbortedOnEachError pins the abort: the bytes read before a
// failure reach the caller, then a read error, and the decision is 502 for a failed
// digest, 503 for any other failure.
func TestAFileThatEndsBadlyIsAbortedOnEachError(t *testing.T) {
	for _, c := range []struct {
		what   string
		err    error
		status int
	}{{"a failed digest", server.ErrRunAPIUnverified, http.StatusBadGateway}, {"a failed stream", errors.New("the stream failed"), http.StatusServiceUnavailable}} {
		r := startRoute(t, &RunAPI{}, func(context.Context, string, string, []byte, bool) (*server.RunAPIAnswer, error) {
			return &server.RunAPIAnswer{Status: http.StatusOK, Header: http.Header{"Content-Length": {"4"}},
				File: io.NopCloser(io.MultiReader(strings.NewReader("byte"), failing{c.err}))}, nil
		})
		resp, err := r.client().Get(routeURL("/artifacts/v/files/f"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.ContentLength != -1 || string(b) != "byte" || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("%s: %d, length %d, %q, %v", c.what, resp.StatusCode, resp.ContentLength, b, err)
		}
		r.mu.Lock()
		d := r.decisions
		r.mu.Unlock()
		if len(d) != 1 || d[0].Status != c.status || d[0].Channel != ChannelRunAPI {
			t.Errorf("%s: decisions %+v", c.what, d)
		}
	}
}

// failing is a reader that returns err.
type failing struct{ err error }

func (f failing) Read([]byte) (int, error) { return 0, f.err }

// TestClosingTheProxyEndsARequest pins that a run's close ends a request in flight: the
// send's context ends, and the request does not outlive the proxy.
func TestClosingTheProxyEndsARequest(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	defer close(release)
	var ended atomic.Bool
	send := heldSends(entered, release)
	r := startRoute(t, &RunAPI{}, func(ctx context.Context, method, path string, body []byte, file bool) (*server.RunAPIAnswer, error) {
		defer ended.Store(true)
		return send(ctx, method, path, body, file)
	})
	var wg sync.WaitGroup
	wg.Go(func() {
		if resp, err := r.client().Get(routeURL("/work-item")); err == nil {
			resp.Body.Close()
		}
	})
	<-entered
	r.p.Close()
	wg.Wait()
	for deadline := time.Now().Add(5 * time.Second); !ended.Load(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the request outlived the proxy")
		}
	}
}

// TestTheRouteSignsNothingOutsideTheShapes pins that a request outside the shapes never
// reaches Send, which is the one place a request is signed.
func TestTheRouteSignsNothingOutsideTheShapes(t *testing.T) {
	r := startRoute(t, &RunAPI{}, nil)
	for _, target := range []string{"/attach", "/outcome", "/reload", "/diagnostics", "", "/work-item?x=1", "/artifacts/../work-item", "/artifacts/a%2Fb/files/f", "/artifacts/v/files/a%5Cb", "//work-item"} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			c, err := net.Dial("tcp", r.p.Addr())
			if err != nil {
				t.Fatal(err)
			}
			io.WriteString(c, method+" "+routeURL(target)+" HTTP/1.1\r\nHost: "+link.RunAPIHost+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			c.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s %s: %d", method, target, resp.StatusCode)
			}
		}
	}
	if got := r.sent.Load(); got != 0 {
		t.Errorf("%d requests were signed and sent", got)
	}
}

// TestALongTargetIsOutside pins the bound on a target: 4 KiB passes, and one byte more is
// the route's 404, with nothing signed and no path of the caller's in the decision.
func TestALongTargetIsOutside(t *testing.T) {
	r := startRoute(t, &RunAPI{}, nil)
	get := func(target string) string {
		return rawStatus(t, r, "GET "+target+" HTTP/1.1\r\nHost: "+link.RunAPIHost+"\r\nConnection: close\r\n\r\n")
	}
	prefix := routeURL("/artifacts/v/files/")
	fits := prefix + strings.Repeat("a", maxRunAPITarget-len(prefix))
	if line := get(fits); !strings.Contains(line, "200") {
		t.Fatalf("a target of 4 KiB: %s", line)
	}
	for _, target := range []string{fits + "a", prefix + strings.Repeat("a", 900_000)} {
		if line := get(target); !strings.Contains(line, "404") {
			t.Errorf("a target of %d bytes: %s", len(target), line)
		}
	}
	if got := r.sent.Load(); got != 1 {
		t.Errorf("%d requests sent", got)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.decisions) != 3 || r.decisions[1].Path != runAPIOutside || r.decisions[2].Path != runAPIOutside {
		t.Fatalf("%d decisions", len(r.decisions))
	}
	if want := "/v1/runs/" + routeRun + "/artifacts/v/files/" + strings.Repeat("a", maxRunAPITarget-len(prefix)); r.decisions[0].Path != want {
		t.Errorf("the accepted path %q", r.decisions[0].Path)
	}
}

// TestARecordHasNoEncodedSecret pins the mask over decoded segments: a secret that a
// percent escape hides is in its phrase in an accepted request's path, and a refused
// request's path is the fixed word.
func TestARecordHasNoEncodedSecret(t *testing.T) {
	r := startRoute(t, &RunAPI{}, nil)
	const zeros = "00000000000000000000000000000000"
	encoded := "q%61k_" + zeros
	get := func(target string) {
		rawStatus(t, r, "GET "+target+" HTTP/1.1\r\nHost: "+link.RunAPIHost+"\r\nConnection: close\r\n\r\n")
	}
	get(routeURL("/artifacts/v%201/files/" + encoded))
	get(routeURL("/artifacts/" + encoded + "/files/f"))
	get("http://" + link.RunAPIHost + "/anything/" + encoded)
	get(routeURL("/" + encoded))
	shown := accesskey.ShownValue("qak_"+zeros, false)
	base := "/v1/runs/" + routeRun
	want := []string{base + "/artifacts/v%201/files/" + shown, base + "/artifacts/" + shown + "/files/f", runAPIOutside, runAPIOutside}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.decisions) != len(want) {
		t.Fatalf("%d decisions", len(r.decisions))
	}
	for i, d := range r.decisions {
		if d.Path != want[i] {
			t.Errorf("decision %d: %q, want %q", i, d.Path, want[i])
		}
		if decoded, err := url.PathUnescape(d.Path); err != nil || accesskey.ContainsSecret(decoded) {
			t.Errorf("decision %d decodes to %q, %v", i, decoded, err)
		}
	}
}
