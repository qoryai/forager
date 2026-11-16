package session_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/session"
)

// The tests of this file pin the route to link.QoryHost, OpenSpec.QoryRoute, from the
// session's side: QORY_HOST_URL in a session's launch and not in the setup, a request
// that reaches the handler without a wall, on one machine and behind a separate gateway,
// and behind a wall, the gate between sessions, and the gateway's denial of the host
// in a run with no route.

// routeRuntime is the runtime of a route test: it writes HTTP_PROXY and QORY_HOST_URL,
// or unset, a line each, to the file FAKE_ROUTE_ENV names, then waits up to 2 minutes
// for the file FAKE_ROUTE_DONE names, and exits 0.
func routeRuntime() int {
	host, ok := os.LookupEnv(session.EnvQoryHost)
	if !ok {
		host = "unset"
	}
	out := os.Getenv("FAKE_ROUTE_ENV")
	if err := os.WriteFile(out+".part", []byte(os.Getenv("HTTP_PROXY")+"\n"+host+"\n"), 0o600); err != nil {
		return 1
	}
	if err := os.Rename(out+".part", out); err != nil {
		return 1
	}
	for end := time.Now().Add(2 * time.Minute); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(os.Getenv("FAKE_ROUTE_DONE")); err == nil {
			return 0
		}
	}
	return 2
}

// recorder is a route's handler that records the requests it gets and answers 201 with
// text/plain and "made".
type recorder struct {
	mu   sync.Mutex
	reqs []string
}

func (h *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.reqs = append(h.reqs, fmt.Sprintf("%s %s?%s session=%s type=%s body=%s", r.Method, r.URL.Path, r.URL.RawQuery,
		r.Header.Get(link.QorySessionHeader), r.Header.Get("Content-Type"), b))
	h.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusCreated)
	io.WriteString(w, "made")
}

func (h *recorder) got() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.reqs)
}

// routeSession is a run of the route test's runtime, with one session that runs until
// end is called.
type routeSession struct {
	r *session.Run
	// proxy is the launch's HTTP_PROXY, and host its QORY_HOST_URL, or unset.
	proxy, host string
	done        string
	results     chan *session.Result
}

// startRouteSession opens a run of sp with h as its route, nil for none, joins one
// session of the route test's runtime and returns once the runtime wrote its
// environment.
func startRouteSession(t *testing.T, sp runSpec, h http.Handler) *routeSession {
	t.Helper()
	dir := t.TempDir()
	envFile, done := filepath.Join(dir, "env"), filepath.Join(dir, "done")
	sp.Env = append(sp.Env, "FAKE_ROUTE_ENV="+envFile, "FAKE_ROUTE_DONE="+done)
	sp.Forwarder = nil
	sp.QoryRoute = h
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	s := &routeSession{r: r, done: done, results: make(chan *session.Result, 1)}
	go func() {
		res, err := r.Join(ctx, sp.SessionSpec)
		if err != nil {
			t.Errorf("the join: %v", err)
		}
		s.results <- res
	}()
	waitFor(t, func() bool {
		b, err := os.ReadFile(envFile)
		if err != nil {
			return false
		}
		s.proxy, s.host, _ = strings.Cut(strings.TrimSuffix(string(b), "\n"), "\n")
		return true
	})
	return s
}

// end lets the runtime exit and closes the run, and returns the session's result. The
// gateway must have taken every event of the run, the route's decisions among them: a
// batch it refused would have closed the run.
func (s *routeSession) end(t *testing.T) *session.Result {
	t.Helper()
	os.WriteFile(s.done, nil, 0o600)
	res := <-s.results
	closed, err := s.r.Close(context.Background(), session.Outcome{State: event.StateSucceeded})
	if err != nil {
		t.Errorf("the close: %v", err)
	} else if closed.RunClosed || closed.Undelivered != 0 || closed.State != event.StateSucceeded {
		t.Errorf("the close %+v", closed)
	}
	return res
}

// client is a client through the launch's proxy.
func (s *routeSession) client(t *testing.T) *http.Client {
	t.Helper()
	u, err := url.Parse(s.proxy)
	if err != nil || u.Host == "" {
		t.Fatalf("the launch's HTTP_PROXY %q", s.proxy)
	}
	return throughProxy(u)
}

// postTests posts to the route through c and returns the status and the body.
func postTests(t *testing.T, c *http.Client) (int, string) {
	t.Helper()
	resp, err := c.Post(link.QoryHostURL+"/tests?suite=unit", "application/json", strings.NewReader(`{"run":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// routeDecisions are the dev.qory.run.egress of evs for the route's host, as
// "<method> <channel> <decision> <status> <rule>".
func routeDecisions(evs []map[string]any) []string {
	var out []string
	for _, e := range ofType(evs, event.RunEgress) {
		if d := data(e); d["host"] == link.QoryHost {
			out = append(out, fmt.Sprint(d["method"], " ", d["channel"], " ", d["decision"], " ", d["status"], " ", d["rule"]))
		}
	}
	return out
}

// routeWithoutAWall pins the route through an unwalled session's forwarder, with sp
// set up for a gateway: the launch has QORY_HOST_URL; a POST reaches the handler with
// its query, Content-Type, body and session number and returns the handler's answer; a
// CONNECT to the host and a request to another host reach no handler; and the session's
// record has the route's decision, which the gateway took.
func routeWithoutAWall(t *testing.T, sp runSpec) *session.Result {
	t.Helper()
	h := &recorder{}
	s := startRouteSession(t, sp, h)
	if s.host != link.QoryHostURL {
		t.Errorf("QORY_HOST_URL is %q", s.host)
	}
	c := s.client(t)
	if status, body := postTests(t, c); status != http.StatusCreated || body != "made" {
		t.Errorf("the route answered %d %q", status, body)
	}
	if resp, err := c.Get("https://" + link.QoryHost + "/tests"); err == nil {
		resp.Body.Close()
		t.Errorf("a CONNECT to the route's host got %d", resp.StatusCode)
	}
	if resp, err := c.Get("http://other.example/tests"); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("another host got %d", resp.StatusCode)
		}
	}
	res := s.end(t)
	if want := []string{`POST /tests?suite=unit session=1 type=application/json body={"run":true}`}; !slices.Equal(h.got(), want) {
		t.Errorf("the handler got %q, want %q", h.got(), want)
	}
	if res == nil || res.RunClosed || res.State != event.StateSucceeded {
		t.Fatalf("the session's result %+v", res)
	}
	if got := routeDecisions(events(t, res)); !slices.Contains(got, "HTTP qory_host allowed 201 wall:qory-host") {
		t.Errorf("the session's record has %q", got)
	}
	return res
}

// TestTheRouteWorksWithoutAWallOnOneMachine pins the route at a real gateway on this
// machine: the gateway takes the session's decision of the route into the run's
// record, and denies the CONNECT to the host with wall:qory-host.
func TestTheRouteWorksWithoutAWallOnOneMachine(t *testing.T) {
	sp := spec(t)
	rg := startGateway(t, &sp, gateway.Config{Version: "test", Heartbeat: time.Second,
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example", link.QoryHost}}}})
	res := routeWithoutAWall(t, sp)
	if d := rg.close(t); d != (gateway.Delivery{}) {
		t.Errorf("delivery %+v", d)
	}
	got := routeDecisions(record(t, res))
	want := []string{"HTTP qory_host allowed 201 wall:qory-host", "CONNECT <nil> denied <nil> wall:qory-host"}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("the gateway's record has %q, want %q", got, want)
	}
}

// TestTheRouteWorksWithoutAWallBehindASeparateGateway pins the route behind a separate
// gateway: the session's decision of the route goes over the link, and the gateway
// takes it, so the run does not end with batch_refused.
func TestTheRouteWorksWithoutAWallBehindASeparateGateway(t *testing.T) {
	sp := spec(t)
	separateRun(t, &sp)
	routeWithoutAWall(t, sp)
}

// relayedRoute sends a GET to the route through the walled run's forwarder at addr, as
// the wall's relay does, with proxyURL's password in its Proxy-Authorization, none for
// an empty one, and returns the status, the forwarder's code, empty for an answer of the
// handler's or the proxy's, and the body.
func relayedRoute(t *testing.T, addr, token, proxyURL string) (int, string, string) {
	t.Helper()
	login := ""
	if u, err := url.Parse(proxyURL); err == nil && u.User != nil {
		password, _ := u.User.Password()
		login = "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+password)) + "\r\n"
	}
	// The connection stays open for the answer: a program that ends its side of it
	// before the answer gets none from the proxy.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, link.RelayLine(token)+"GET "+link.QoryHostURL+"/tests HTTP/1.1\r\nHost: "+link.QoryHost+"\r\n"+login+"\r\n")
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	raw, _ := io.ReadAll(c)
	out := string(raw)
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(out)), nil)
	if err != nil {
		t.Fatalf("no answer in %q", out)
	}
	b, _ := io.ReadAll(resp.Body)
	code := ""
	if i := strings.Index(string(b), `"error":"`); i >= 0 {
		code, _, _ = strings.Cut(string(b)[i+len(`"error":"`):], `"`)
	}
	return resp.StatusCode, code, string(b)
}

// TestTheRouteWorksBehindAWallAndIsClosedBetweenSessions pins the route through a walled
// run's forwarder: the session's launch gets a proxy URL with a password, which the
// wall writes inside, and QORY_HOST_URL; during the session a request with that
// password reaches the handler, and one without it goes to the gateway's proxy; after
// the session the request with the password gets 503 session_not_running.
func TestTheRouteWorksBehindAWallAndIsClosedBetweenSessions(t *testing.T) {
	sp, g := specGateway(t)
	w := &openWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	h := &recorder{}
	s := startRouteSession(t, sp, h)
	defer s.r.Close(context.Background(), session.Outcome{State: event.StateSucceeded})
	addr, token := s.r.WallProxy()
	if u, err := url.Parse(s.proxy); err != nil || u.User == nil {
		t.Fatalf("the launch's proxy URL %q has no password", s.proxy)
	}
	if status, code, body := relayedRoute(t, addr, token, s.proxy); status != http.StatusCreated || code != "" || body != "made" {
		t.Errorf("during the session: %d %s %q", status, code, body)
	}
	if status, _, body := relayedRoute(t, addr, token, ""); status != http.StatusOK || body != "ok" || !slices.Contains(g.Proxied(), "GET "+link.QoryHostURL+"/tests") {
		t.Errorf("without the password: %d %q, the proxy got %q", status, body, g.Proxied())
	}
	os.WriteFile(s.done, nil, 0o600)
	if res := <-s.results; res == nil || res.State != event.StateSucceeded {
		t.Fatalf("the session's result %+v", res)
	}
	if got, want := entriesOf(w.got.Env, session.EnvQoryHost), []string{session.EnvQoryHost + "=" + link.QoryHostURL}; !slices.Equal(got, want) {
		t.Errorf("the enclosure's environment has %v, want %v", got, want)
	}
	if status, code, _ := relayedRoute(t, addr, token, s.proxy); status != http.StatusServiceUnavailable || code != "session_not_running" {
		t.Errorf("after the session: %d %s", status, code)
	}
	if got := h.got(); len(got) != 1 || !strings.HasPrefix(got[0], "GET /tests? session=1") {
		t.Errorf("the handler got %q", got)
	}
}

// TestTheSetupContainerNeverReachesTheRoute pins the run's setup: the setup container's
// environment has no QORY_HOST_URL and no proxy password, and while a session runs, a
// request from the setup container, which shares the wall's relay, goes to the gateway's
// proxy and reaches no handler; the session's request, with its password, does.
func TestTheSetupContainerNeverReachesTheRoute(t *testing.T) {
	sp, g := specGateway(t)
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	h := &recorder{}
	sp.QoryRoute = h
	sp.Forwarder = nil
	dir := t.TempDir()
	envFile, done := filepath.Join(dir, "env"), filepath.Join(dir, "done")
	sp.Env = append(sp.Env, "FAKE_ROUTE_ENV="+envFile, "FAKE_ROUTE_DONE="+done)
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
		t.Fatal(err)
	}
	if got := entriesOf(w.setup.Env, session.EnvQoryHost); len(got) != 0 || w.setup.ProxyPassword != "" {
		t.Errorf("the setup container's environment has %v, its password %q", got, w.setup.ProxyPassword)
	}
	results := make(chan error, 1)
	go func() {
		_, err := r.Join(ctx, sp.SessionSpec)
		results <- err
	}()
	var proxy string
	waitFor(t, func() bool {
		b, err := os.ReadFile(envFile)
		proxy, _, _ = strings.Cut(string(b), "\n")
		return err == nil
	})
	if status, _, body := relayedRoute(t, w.setup.Proxy, w.setup.ProxyToken, ""); status != http.StatusOK || body != "ok" || !slices.Contains(g.Proxied(), "GET "+link.QoryHostURL+"/tests") {
		t.Errorf("a request of the setup container during the session: %d %q, the proxy got %q", status, body, g.Proxied())
	}
	if got := h.got(); len(got) != 0 {
		t.Errorf("the handler got %q from the setup container", got)
	}
	if status, _, body := relayedRoute(t, w.setup.Proxy, w.setup.ProxyToken, proxy); status != http.StatusCreated || body != "made" {
		t.Errorf("the session's request: %d %q", status, body)
	}
	os.WriteFile(done, nil, 0o600)
	if err := <-results; err != nil {
		t.Fatal(err)
	}
}

// TestASessionWithNoRuntimeGetsNoRoute pins a session with no runtime, such as a host
// step's, in a run with a route: its launch has no QORY_HOST_URL, and its request to the
// host goes to the gateway's proxy and reaches no handler.
func TestASessionWithNoRuntimeGetsNoRoute(t *testing.T) {
	sp, g := specGateway(t)
	sp.Runtime, sp.Args = nil, nil
	h := &recorder{}
	s := startRouteSession(t, sp, h)
	if s.host != "unset" {
		t.Errorf("QORY_HOST_URL is %q", s.host)
	}
	resp, err := s.client(t).Get(link.QoryHostURL + "/tests")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(b) != "ok" || !slices.Contains(g.Proxied(), "GET "+link.QoryHostURL+"/tests") {
		t.Errorf("the request got %d %q, the proxy got %q", resp.StatusCode, b, g.Proxied())
	}
	s.end(t)
	if got := h.got(); len(got) != 0 {
		t.Errorf("the handler got %q", got)
	}
}

// TestARecordedPathHasNoSecretOfTheRun pins the run's masker on the route's record: a
// request whose path contains a secret of the run reaches the handler with that path,
// and the record's path has the masker's replacement in its place.
func TestARecordedPathHasNoSecretOfTheRun(t *testing.T) {
	const secret = "run-secret-value-0123456789"
	sp, _ := specGateway(t)
	sp.Masker = mask.New()
	if err := sp.Masker.AddSecret([]byte(secret)); err != nil {
		t.Fatal(err)
	}
	h := &recorder{}
	s := startRouteSession(t, sp, h)
	resp, err := s.client(t).Get(link.QoryHostURL + "/keys/" + secret + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	res := s.end(t)
	if got := h.got(); len(got) != 1 || !strings.Contains(got[0], "/keys/"+secret+"/x") {
		t.Errorf("the handler got %q", got)
	}
	var paths []string
	for _, e := range ofType(events(t, res), event.RunEgress) {
		if d := data(e); d["host"] == link.QoryHost {
			paths = append(paths, fmt.Sprint(d["path"]))
		}
	}
	if len(paths) != 1 || strings.Contains(paths[0], secret) || paths[0] != "/keys/"+mask.Secret+"/x" {
		t.Errorf("the record's paths %q", paths)
	}
}

// TestACallersQoryHostURLIsReserved pins that a value of QORY_HOST_URL a caller passes
// into a wall is variable_reserved, in a run with a route and in one with none: at a
// join, from --env, wall.env and what the run inherits.
func TestACallersQoryHostURLIsReserved(t *testing.T) {
	const forged = session.EnvQoryHost + "=http://forged.example"
	for what, set := range map[string]func(sp *runSpec){
		"--env":                 func(sp *runSpec) { sp.Variables.Run = []string{forged} },
		"wall.env":              func(sp *runSpec) { sp.Variables.Machine = []string{forged} },
		"what the run inherits": func(sp *runSpec) { sp.Env = append(sp.Env, forged) },
	} {
		for _, routed := range []bool{true, false} {
			t.Run(fmt.Sprint(what, " ", routed), func(t *testing.T) {
				sp, _ := specGateway(t, "FAKE_EXIT=0")
				if routed {
					sp.QoryRoute = &recorder{}
				}
				sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
				set(&sp)
				_, err := run(context.Background(), sp)
				var ref *session.Refusal
				if !errors.As(err, &ref) || ref.Code != "variable_reserved" || !slices.Contains(ref.Names, session.EnvQoryHost) {
					t.Errorf("%v, want variable_reserved", err)
				}
			})
		}
	}
}

// TestARunWithNoRouteHasTheGatewaysDenial pins a run with no OpenSpec.QoryRoute at a
// real gateway: the launch has no QORY_HOST_URL, even one it inherits, and a request to
// the host goes to the gateway's proxy, which denies it with wall:qory-host, though the
// policy lists the host.
func TestARunWithNoRouteHasTheGatewaysDenial(t *testing.T) {
	sp := spec(t, session.EnvQoryHost+"=http://forged.example")
	rg := startGateway(t, &sp, gateway.Config{Version: "test", Heartbeat: time.Second,
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "observe", Allow: []string{link.QoryHost}}}})
	s := startRouteSession(t, sp, nil)
	if s.host != "unset" {
		t.Errorf("QORY_HOST_URL is %q", s.host)
	}
	resp, err := s.client(t).Get(link.QoryHostURL + "/tests")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "QORY_HOST_URL") {
		t.Errorf("the request got %d %q", resp.StatusCode, b)
	}
	res := s.end(t)
	rg.close(t)
	if got, want := routeDecisions(record(t, res)), []string{"HTTP <nil> denied <nil> wall:qory-host"}; !slices.Equal(got, want) {
		t.Errorf("the gateway's record has %q, want %q", got, want)
	}
}
