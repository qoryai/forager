package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	if a.Posts == nil {
		a.Posts = &RunAPIPosts{}
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

// TestEightPostsInFlightPerGateway pins the gateway's limit across its runs: a ninth POST
// from a third run is a 429 with nothing sent, while a GET passes.
func TestEightPostsInFlightPerGateway(t *testing.T) {
	posts := &RunAPIPosts{}
	entered, release := make(chan struct{}, RunAPIPostsInFlight), make(chan struct{})
	first := startRoute(t, &RunAPI{Posts: posts}, heldSends(entered, release))
	second := startRoute(t, &RunAPI{Posts: posts}, heldSends(entered, release))
	third := startRoute(t, &RunAPI{Posts: posts}, nil)
	var wg sync.WaitGroup
	defer func() {
		close(release)
		wg.Wait()
	}()
	first.hold(t, &wg, entered, RunAPIInFlight, http.MethodPost, "/artifacts")
	second.hold(t, &wg, entered, RunAPIInFlight, http.MethodPost, "/verdict")
	third.limited(t, "the ninth POST", http.MethodPost, "/verdict")
	if got := third.sent.Load(); got != 0 {
		t.Errorf("%d requests sent", got)
	}
	if status, _, _ := third.status(t, http.MethodGet, "/work-item"); status != http.StatusOK {
		t.Errorf("a GET: %d", status)
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

// TestADecisionKeepsThePathBounded pins the bound on what a decision contains.
func TestADecisionKeepsThePathBounded(t *testing.T) {
	r := startRoute(t, &RunAPI{}, nil)
	c, err := net.Dial("tcp", r.p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET "+routeURL("/"+strings.Repeat("a", 8192))+" HTTP/1.1\r\nHost: "+link.RunAPIHost+"\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.decisions) != 1 || len(r.decisions[0].Path) != maxRunAPIShown || resp.StatusCode != http.StatusNotFound {
		t.Errorf("%d, %d decisions: %s", resp.StatusCode, len(r.decisions), strconv.Itoa(len(r.decisions[0].Path)))
	}
}
