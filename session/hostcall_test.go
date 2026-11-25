package session_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
)

// The tests of this file pin the link's host calls from the session's side,
// [session.Run.NextSession], [session.Run.PushedCommits], [session.Run.Findings] and
// [session.Run.PostFindings], at a real gateway on one machine and behind a separate one,
// and that no container reaches any.

// hostCallLog is a fake Qory Apiary's side of the host calls: the bodies of the requests
// it got, by their name, next-session, pushed-commits, GET findings and POST findings, and
// its answer: a signed 200 with nextAnswer to next-session, findingsAnswer to GET findings
// and postedAnswer to POST findings, a signed 204 to pushed-commits, or refusal, signed
// with its status, when set.
type hostCallLog struct {
	mu      sync.Mutex
	got     map[string][][]byte
	refusal *hostCallRefusal
}

// hostCallRefusal is a signed refusal a fake Qory Apiary returns for a host call.
type hostCallRefusal struct {
	status     int
	body       string
	retryAfter string
}

// nextAnswer is the fake Qory Apiary's answer to a next-session request.
const nextAnswer = `{"next":"session","session":2,"workflow":"write-acceptance-checks","time_limit_minutes":60,"full_suite":false,"inputs":{"version":1}}`

// findingsAnswer is the fake Qory Apiary's answer to a GET findings request, longer than
// any other answer of the link, and postedAnswer to a POST findings request.
var findingsAnswer = `{"bases":[],"findings":[` + strings.Repeat(" ", 3<<20) + `]}`

const postedAnswer = `{"created":{"r1":"f1"},"open_blocking":{"build":1}}`

// serve writes the answer for r when it is a host call, signed by signer, and reports
// whether it was one.
func (l *hostCallLog) serve(signer *accesskey.Key, w http.ResponseWriter, r *http.Request) bool {
	rest, ok := strings.CutPrefix(r.URL.Path, "/v1/runs/")
	if !ok {
		return false
	}
	_, path, _ := strings.Cut(rest, "/")
	switch {
	case path == "findings" && (r.Method == http.MethodGet || r.Method == http.MethodPost):
		path = r.Method + " " + path
	case r.Method != http.MethodPost || path != "next-session" && path != "pushed-commits":
		return false
	}
	body, _ := io.ReadAll(r.Body)
	l.mu.Lock()
	if l.got == nil {
		l.got = map[string][][]byte{}
	}
	l.got[path] = append(l.got[path], body)
	ref := l.refusal
	l.mu.Unlock()
	status, out := http.StatusOK, []byte(nextAnswer)
	switch {
	case ref != nil:
		status, out = ref.status, []byte(ref.body)
		if ref.retryAfter != "" {
			w.Header().Set("Retry-After", ref.retryAfter)
		}
	case path == "pushed-commits":
		status, out = http.StatusNoContent, nil
	case path == "GET findings":
		out = []byte(findingsAnswer)
	case path == "POST findings":
		out = []byte(postedAnswer)
	}
	w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: status, RequestSignature: r.Header.Get(server.HeaderSignature), Body: out}))
	if len(out) > 0 {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	w.Write(out)
	return true
}

// count is the number of host calls the fake got.
func (l *hostCallLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, got := range l.got {
		n += len(got)
	}
	return n
}

// last is the body of the last request name the fake got, nil for none.
func (l *hostCallLog) last(name string) []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	if got := l.got[name]; len(got) > 0 {
		return got[len(got)-1]
	}
	return nil
}

// refuse sets the fake's answer to every host call: a signed refusal, or none.
func (l *hostCallLog) refuse(ref *hostCallRefusal) {
	l.mu.Lock()
	l.refusal = ref
	l.mu.Unlock()
}

// hostCallsOf are the host calls of r by their name, each with a body for a POST.
func hostCallsOf(r *session.Run) map[string]func(context.Context, []byte) ([]byte, error) {
	return map[string]func(context.Context, []byte) ([]byte, error){
		"next-session": r.NextSession, "pushed-commits": r.PushedCommits, "POST findings": r.PostFindings,
		"GET findings": func(ctx context.Context, _ []byte) ([]byte, error) { return r.Findings(ctx) },
	}
}

// nextBody and pushedBody are a next-session and a pushed-commits request.
const (
	nextBody   = `{"session":1,"state":"succeeded","reason":null}`
	pushedBody = `{"repositories":[{"system":"git.example","path":"example-org/app","commit":"0123456789abcdef0123456789abcdef01234567"}]}`
)

// sendsHostCalls pins the host calls through a run's life, with sp set up for a run
// with a control plane whose host calls l records: from the open, during a join, a
// refusal of Qory Apiary's from apiary, which is not [session.ErrRunClosed], and not
// after the close, when nothing is sent and the error wraps [session.ErrRunClosed]. No
// error contains secret.
func sendsHostCalls(t *testing.T, sp runSpec, l *hostCallLog, secret string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	var errs []error
	check := func(what string) {
		t.Helper()
		got, err := r.NextSession(ctx, []byte(nextBody))
		if err != nil || string(got) != nextAnswer || string(l.last("next-session")) != nextBody {
			t.Errorf("%s: next-session %q, %v; the control plane got %q", what, got, err, l.last("next-session"))
		}
		got, err = r.PushedCommits(ctx, []byte(pushedBody))
		if err != nil || len(got) != 0 || string(l.last("pushed-commits")) != pushedBody {
			t.Errorf("%s: pushed-commits %q, %v; the control plane got %q", what, got, err, l.last("pushed-commits"))
		}
		got, err = r.Findings(ctx)
		if err != nil || string(got) != findingsAnswer || len(l.last("GET findings")) != 0 {
			t.Errorf("%s: GET findings %d bytes, %v; the control plane got %q", what, len(got), err, l.last("GET findings"))
		}
		// The largest body, which the answer's signature behind a separate gateway covers.
		posted := bytes.Repeat([]byte("p"), server.MaxPostFindingsRequest)
		got, err = r.PostFindings(ctx, posted)
		if err != nil || string(got) != postedAnswer || !bytes.Equal(l.last("POST findings"), posted) {
			t.Errorf("%s: POST findings %q, %v; the control plane got %d bytes", what, got, err, len(l.last("POST findings")))
		}
	}
	check("after the open")

	l.refuse(&hostCallRefusal{status: http.StatusConflict, body: `{"error":"run_ended","message":"Start a new run to record pushed commits."}`})
	_, err = r.PushedCommits(ctx, []byte(pushedBody))
	var ref *accesskey.Refusal
	if !errors.As(err, &ref) || ref.Status != http.StatusConflict || ref.Code != "run_ended" || ref.From != accesskey.FromApiary || err.Error() != "Start a new run to record pushed commits." || errors.Is(err, session.ErrRunClosed) {
		t.Errorf("a signed 409: %v (%+v)", err, ref)
	}
	errs = append(errs, err)
	_, err = r.PostFindings(ctx, []byte(`{}`))
	if !errors.As(err, &ref) || ref.Status != http.StatusConflict || ref.From != accesskey.FromApiary || errors.Is(err, session.ErrRunClosed) {
		t.Errorf("POST findings: a signed 409: %v (%+v)", err, ref)
	}
	l.refuse(&hostCallRefusal{status: http.StatusTooManyRequests, body: `{"error":"rate_limited"}`, retryAfter: "7"})
	_, err = r.Findings(ctx)
	if !errors.As(err, &ref) || ref.Status != http.StatusTooManyRequests || ref.From != accesskey.FromApiary || ref.RetryAfter != 7*time.Second {
		t.Errorf("GET findings: a signed 429: %v (%+v)", err, ref)
	}
	l.refuse(nil)
	sent := l.count()
	for _, n := range []int{server.MaxPostFindingsRequest + 1, server.MaxPostFindingsRequest + 2, 64 << 20} {
		var ke *server.GatewayKeyError
		_, err = r.PostFindings(ctx, make([]byte, n))
		if err == nil || !strings.HasSuffix(err.Error(), "so nothing was sent.") || errors.As(err, &ke) || errors.Is(err, session.ErrRunClosed) {
			t.Errorf("POST findings: a body of %d bytes: %v", n, err)
		}
		errs = append(errs, err)
	}
	if l.count() != sent {
		t.Errorf("the control plane got %d POST findings over the limit", l.count()-sent)
	}
	_, err = r.NextSession(ctx, bytes.Repeat([]byte(" "), server.MaxNextSessionRequest+1))
	if !errors.As(err, &ref) || ref.Status != http.StatusRequestEntityTooLarge || ref.From != accesskey.FromGateway || errors.Is(err, session.ErrRunClosed) {
		t.Errorf("a body over the limit: %v (%+v)", err, ref)
	}
	errs = append(errs, err)

	done := make(chan *session.Result, 1)
	go func() {
		res, _ := r.Join(ctx, sp.SessionSpec)
		done <- res
	}()
	waitFor(t, func() bool {
		return len(ofType(events(t, &session.Result{Dir: r.Dir()}), event.SessionStarted)) == 1
	})
	check("during the join")
	cancel()
	<-done
	if _, err := r.Close(context.Background(), session.Outcome{State: event.StateCancelled}); err != nil {
		t.Fatal(err)
	}
	sent = l.count()
	for _, call := range hostCallsOf(r) {
		_, err := call(context.Background(), []byte(`{}`))
		if !errors.Is(err, session.ErrRunClosed) || !strings.HasPrefix(err.Error(), "Open another run to send the ") {
			t.Errorf("after the close: %v", err)
		}
		errs = append(errs, err)
	}
	if l.count() != sent {
		t.Errorf("the control plane got %d host calls after the close", l.count()-sent)
	}
	for _, err := range errs {
		if err != nil && secret != "" && strings.Contains(err.Error(), secret) {
			t.Errorf("an error contains the run key: %v", err)
		}
	}
}

// TestHostCallsOnOneMachine pins the host calls at a real gateway on the machine.
func TestHostCallsOnOneMachine(t *testing.T) {
	c := newControl(t)
	sp := spec(t)
	sleeps(&sp, 30*time.Second)
	sp.Timeout = 20 * time.Second
	sp.RunID = event.NewRunID()
	startGateway(t, &sp, gateway.Config{Server: c.server(), Heartbeat: time.Second})
	sendsHostCalls(t, sp, &c.hostCalls, "")
}

// TestHostCallsBehindASeparateGateway pins the host calls behind a separate gateway,
// with the run key, which no error and no line of the gateway's log contains.
func TestHostCallsBehindASeparateGateway(t *testing.T) {
	sp := spec(t)
	sleeps(&sp, 30*time.Second)
	sp.Timeout = 20 * time.Second
	a := separateRun(t, &sp)
	key := sp.Gateway.(session.RemoteGateway).RunKey
	sendsHostCalls(t, sp, &a.hostCalls, key)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, l := range a.reports {
		if strings.Contains(l, key) {
			t.Errorf("a line of the gateway's log contains the run key: %s", l)
		}
	}
}

// TestFindingsCallsInARunAPICheck pins the findings calls inside the check of
// Run.SetRunAPICheck while a Join runs, on one machine and behind a separate gateway: the
// check of a program's POST reads and sends findings, and each call returns well within
// the check's time.
func TestFindingsCallsInARunAPICheck(t *testing.T) {
	for _, separate := range []bool{false, true} {
		t.Run(fmt.Sprintf("separate %v", separate), func(t *testing.T) {
			sp := spec(t)
			sleeps(&sp, 30*time.Second)
			sp.Timeout = 20 * time.Second
			var l *hostCallLog
			if separate {
				l = &separateRun(t, &sp).hostCalls
			} else {
				c := newControl(t)
				l = &c.hostCalls
				sp.RunID = event.NewRunID()
				startGateway(t, &sp, gateway.Config{Server: c.server(), Heartbeat: time.Second})
			}
			sp.Wall, sp.Image = &setupWall{}, "example.com/agent:1"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close(context.Background(), session.Outcome{State: event.StateCancelled})
			var read, posted []byte
			var readErr, postErr error
			if err := r.SetRunAPICheck(func(ctx context.Context, _ session.RunAPIRequest) (*session.RunAPIRefusal, error) {
				ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				read, readErr = r.Findings(ctx)
				posted, postErr = r.PostFindings(ctx, []byte(`{"events":[]}`))
				return &session.RunAPIRefusal{Status: http.StatusUnprocessableEntity, Code: "push_checks_failed", Message: "Fix the findings, then push again."}, nil
			}); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				r.Join(ctx, sp.SessionSpec)
			}()
			waitFor(t, func() bool {
				return len(ofType(events(t, &session.Result{Dir: r.Dir()}), event.SessionStarted)) == 1
			})
			addr, token := r.WallProxy()
			out := relayed(t, addr, token, fmt.Sprintf("POST %s/artifacts HTTP/1.1\r\nHost: %s\r\nContent-Length: 2\r\n\r\n{}", link.RunAPIURL(r.ID()), link.RunAPIHost))
			cancel()
			<-done
			if !strings.HasPrefix(out, "HTTP/1.1 422 ") {
				t.Errorf("the checked POST got %q", out)
			}
			if readErr != nil || string(read) != findingsAnswer {
				t.Errorf("Findings in the check: %d bytes, %v", len(read), readErr)
			}
			if postErr != nil || string(posted) != postedAnswer || string(l.last("POST findings")) != `{"events":[]}` {
				t.Errorf("PostFindings in the check: %q, %v", posted, postErr)
			}
		})
	}
}

// TestHostCallsWithNoControlPlane pins a run with no control plane: every host call
// returns an error that starts with the fix and is not [session.ErrRunClosed], with
// nothing sent to the gateway.
func TestHostCallsWithNoControlPlane(t *testing.T) {
	sp := spec(t)
	startGateway(t, &sp, gateway.Config{})
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateCancelled})
	for _, call := range hostCallsOf(r) {
		got, err := call(ctx, []byte(`{}`))
		if got != nil || err == nil || !strings.HasPrefix(err.Error(), "Open the run with a control plane to send the ") || errors.Is(err, session.ErrRunClosed) {
			t.Errorf("%q %v", got, err)
		}
		// The gateway's 404 for a run with no control plane is a refusal: the session's
		// error, with nothing sent, is none.
		if ref := (*accesskey.Refusal)(nil); errors.As(err, &ref) {
			t.Errorf("the error is the gateway's refusal %+v, not the session's", ref)
		}
	}
}

// closedHostCalls fails the test unless every host call of r returns an error that wraps
// [session.ErrRunClosed] and starts with the fix, with nothing sent: the text is that of
// the check before the send, which a sent call never returns.
func closedHostCalls(t *testing.T, what string, r *session.Run) {
	t.Helper()
	for name, call := range hostCallsOf(r) {
		got, err := call(context.Background(), []byte(`{}`))
		want := "Open another run to send the " + name + " request: this run is closed."
		if got != nil || !errors.Is(err, session.ErrRunClosed) || err.Error() != want {
			t.Errorf("%s: %s: %q %v", what, name, got, err)
		}
	}
}

// TestHostCallsInAClosedRun pins the host calls in a run with a control plane, at a
// fake gateway, once the run is closed but before Close returns: while Close sends the
// run's last batch, which has dev.qory.run.exited, and once the gateway closed the run
// with a 410 to a batch. Each returns an error that wraps [session.ErrRunClosed], with
// nothing sent.
func TestHostCallsInAClosedRun(t *testing.T) {
	t.Run("the close began", func(t *testing.T) {
		sp, g := specGateway(t)
		hasRunAPI(g)
		ctx := context.Background()
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		var called atomic.Bool
		g.OnBatch(func(evs []map[string]any) linktest.Reply {
			if len(ofType(evs, event.RunExited)) > 0 && !called.Swap(true) {
				closedHostCalls(t, "during the close", r)
			}
			return linktest.Reply{Status: http.StatusOK}
		})
		if _, err := r.Close(ctx, session.Outcome{State: event.StateCancelled}); err != nil {
			t.Fatal(err)
		}
		if !called.Load() {
			t.Error("the gateway got no batch with run.exited")
		}
	})
	t.Run("the gateway closed the run", func(t *testing.T) {
		sp, g := specGateway(t)
		hasRunAPI(g)
		g.SetInterval(1)
		ctx := context.Background()
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close(ctx, session.Outcome{State: event.StateCancelled})
		// The next heartbeat's batch gets the 410 that closes the run.
		var gave410 atomic.Bool
		g.OnBatch(func([]map[string]any) linktest.Reply {
			gave410.Store(true)
			return *gone("stopped", "cancelled", "no_longer_needed")
		})
		for deadline := time.Now().Add(15 * time.Second); !gave410.Load(); time.Sleep(20 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the gateway got no batch to return the 410 to")
			}
		}
		waitFor(t, func() bool {
			_, _, err := r.RunAPI()
			return err != nil && strings.HasPrefix(err.Error(), "Open another run to reach the run API")
		})
		closedHostCalls(t, "after the gateway's 410", r)
	})
}

// reachesNoHostCall fails the test unless no request of c, a client of a container's
// way out, reaches a host call of the run runID: the run API route returns 404 for
// each, and the proxy 403 for the local link's paths and the one address's.
func reachesNoHostCall(t *testing.T, what string, c *http.Client, runID, oneAddress string) {
	t.Helper()
	var urls []string
	for _, path := range []string{"/next-session", "/pushed-commits", "/findings"} {
		urls = append(urls, link.RunAPIURL(runID)+path, server.LocalOrigin+"/v1/run-configuration/"+runID+path)
		if oneAddress != "" {
			urls = append(urls, "https://"+oneAddress+"/qory-link/run-configuration/"+runID+path, "http://"+oneAddress+"/qory-link/run-configuration/"+runID+path)
		}
	}
	for _, u := range urls {
		methods := []string{http.MethodPost}
		if strings.HasSuffix(u, "/findings") {
			methods = append(methods, http.MethodGet)
		}
		for _, method := range methods {
			req, err := http.NewRequest(method, u, strings.NewReader(nextBody))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := c.Do(req)
			if err != nil {
				// An https URL goes through a CONNECT, whose 403 is the client's error.
				if !strings.HasPrefix(u, "https://") || !strings.Contains(err.Error(), "Forbidden") {
					t.Errorf("%s: %s %s: %v", what, method, u, err)
				}
				continue
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			switch {
			case strings.HasPrefix(u, link.RunAPIURL(runID)):
				if resp.StatusCode != http.StatusNotFound || !bytes.Contains(b, []byte(`"not_found"`)) {
					t.Errorf("%s: %s %s: %d %s, want the route's 404", what, method, u, resp.StatusCode, b)
				}
			case resp.StatusCode != http.StatusForbidden:
				t.Errorf("%s: %s %s: %d %s, want the proxy's 403", what, method, u, resp.StatusCode, b)
			}
		}
	}
}

// TestNoContainerReachesAHostCallThroughTheSession pins that a program behind a wall,
// through the wall's relay, and a program on the host through the host proxy, reach
// neither host call: on one machine under an enforce policy that allows no host, and
// behind a separate gateway with no policy, where the guard of the machine's addresses
// refuses localhost and the one address. The control plane gets no host call.
func TestNoContainerReachesAHostCallThroughTheSession(t *testing.T) {
	for _, separate := range []bool{false, true} {
		name := "one machine"
		if separate {
			name = "separate gateway"
		}
		t.Run(name, func(t *testing.T) {
			sp := spec(t)
			var l *hostCallLog
			oneAddress := ""
			if separate {
				a := separateRun(t, &sp)
				l = &a.hostCalls
				oneAddress = a.oneAddress
			} else {
				c := newControl(t)
				l = &c.hostCalls
				sp.RunID = event.NewRunID()
				startGateway(t, &sp, gateway.Config{Server: c.server(), Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{}}}})
			}
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close(ctx, session.Outcome{State: event.StateCancelled})
			reachesNoHostCall(t, "the wall's relay", throughRelay(t, r), sp.RunID, oneAddress)
			h, err := r.HostProxy()
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(h.ProxyURL)
			if err != nil {
				t.Fatal(err)
			}
			reachesNoHostCall(t, "the host proxy", throughProxy(u), sp.RunID, oneAddress)
			if n := l.count(); n != 0 {
				t.Errorf("the control plane got %d host calls", n)
			}
		})
	}
}

// TestNoEngineProxyReachesAHostCall pins the engine proxy's forwarder at a real gateway
// on one machine, under an enforce policy that allows no host: a request through it,
// as a container the engine starts sends it, reaches neither host call, and the control
// plane gets no host call.
func TestNoEngineProxyReachesAHostCall(t *testing.T) {
	t.Cleanup(session.SetEngineCertsDir(t.TempDir()))
	roots := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(roots, []byte(machineRoots), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.SetMachineBundles([]string{roots}))
	c := newControl(t)
	sp := spec(t)
	sp.RunID = event.NewRunID()
	startGateway(t, &sp, gateway.Config{Server: c.server(), Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{}}}})
	sp.EngineProxy = &session.EngineProxy{Addr: freeLoopback(t), Password: enginePassword}
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateCancelled})
	step, err := r.StartStep(event.StepFetch, "fetch example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	stop, err := r.EngineProxy([]string{"registry.example"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse("http://qory:" + enginePassword + "@" + sp.EngineProxy.Addr)
	if err != nil {
		t.Fatal(err)
	}
	reachesNoHostCall(t, "the engine proxy", throughProxy(u), sp.RunID, "")
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	step.Exit(event.StateSucceeded, 0)
	if n := c.hostCalls.count(); n != 0 {
		t.Errorf("the control plane got %d host calls", n)
	}
}
