package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/link"
)

// The tests of this file pin the walled forwarder with the run's check of its run API,
// Run.SetRunAPICheck: what goes on, what the program gets, and what never reaches the
// gateway's proxy.

const (
	checkRunID  = "run_f1xt0re00000000000000000e"
	checkHop    = "hop-secret-0123456789abcdefghijklmnopqrstuv"
	checkSecret = "proxy-secret-0123456789abcdefghijklmnopqrst"
)

// checkTarget is the target of a POST under the run's path.
func checkTarget(path string) string { return link.RunAPIURL(checkRunID) + path }

// checkCalls records the calls of a check and returns what answer gives.
type checkCalls struct {
	mu     sync.Mutex
	calls  []RunAPIRequest
	answer func(ctx context.Context, req RunAPIRequest) (*RunAPIRefusal, error)
}

func (k *checkCalls) check(ctx context.Context, req RunAPIRequest) (*RunAPIRefusal, error) {
	k.mu.Lock()
	k.calls = append(k.calls, req)
	k.mu.Unlock()
	if k.answer == nil {
		return nil, nil
	}
	return k.answer(ctx, req)
}

func (k *checkCalls) got() []RunAPIRequest {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.calls)
}

// checkedForwarder starts a walled forwarder behind a separate gateway, with the hop and
// the proxy's secret, to target, with the check k.
func checkedForwarder(t *testing.T, target string, k *runAPICheck) *forwarder {
	t.Helper()
	f, err := listenForwarding("127.0.0.1:0", forwarding{dial: dialTCP(target), secret: checkSecret, hop: checkHop, check: k})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// relaySend opens a connection to f as the wall's relay does, with the hop, writes what,
// and returns all that f writes back until it closes the connection, or 5 seconds pass.
// It runs in any goroutine: a failed dial is an error of t and an empty reply.
func relaySend(t *testing.T, f *forwarder, what string) string {
	t.Helper()
	c, err := net.Dial("tcp", f.Addr())
	if err != nil {
		t.Error(err)
		return ""
	}
	defer c.Close()
	go io.WriteString(c, link.RelayLine(checkHop)+what)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c)
	return string(b)
}

// replyOf reads the last reply of out, after any 100 Continue: its status and body.
func replyOf(t *testing.T, out string) (*http.Response, string) {
	t.Helper()
	r := bufio.NewReader(strings.NewReader(out))
	for {
		resp, err := http.ReadResponse(r, nil)
		if err != nil {
			t.Fatalf("no reply in %q: %v", out, err)
		}
		if resp.StatusCode == http.StatusContinue {
			continue
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("the reply's body in %q: %v", out, err)
		}
		return resp, string(b)
	}
}

// post is a POST's head and body, with Host and Content-Length.
func post(target, body string, header ...string) string {
	h := "POST " + target + " HTTP/1.1\r\nHost: " + link.RunAPIHost + "\r\n"
	for _, l := range header {
		h += l + "\r\n"
	}
	return h + fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)) + body
}

// TestTheCheckLetsAPostGoOnAsSent pins a POST that the check lets pass: the check gets the
// path after the run's id, decoded and escaped again, the header without hop-by-hop and
// Proxy- headers, and the whole body; the proxy gets the bytes the program sent, after
// the relay's preamble with the proxy's secret, with Connection: close added to the head,
// whatever the check does to the body it got; and the program gets the proxy's reply.
func TestTheCheckLetsAPostGoOnAsSent(t *testing.T) {
	p := startProxyStandIn(t, checkSecret, nil)
	k := &checkCalls{answer: func(_ context.Context, req RunAPIRequest) (*RunAPIRefusal, error) {
		req.Body[0] = 'X'
		return nil, nil
	}}
	f := checkedForwarder(t, p.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID})
	const body = `{"artifacts":[{"name":"report.md"}]}`
	for _, target := range []string{checkTarget("/artifacts"), "http://" + link.RunAPIHost + "/v1/%72uns/" + checkRunID + "/%61rtifacts"} {
		head, _, _ := strings.Cut(post(target, body, "Content-Type: application/json", "Connection: keep-alive, X-Hop", "X-Hop: 1",
			"Proxy-Authorization: Basic eDp5", "Proxy-Other: 1", "X-Qory-Push: 1"), "\r\n\r\n")
		out := relaySend(t, f, head+"\r\n\r\n"+body)
		resp, got := replyOf(t, out)
		if resp.StatusCode != http.StatusOK || got != fmt.Sprintf("ok %d", len(body)) {
			t.Errorf("%s: the program got %q", target, out)
		}
		raw, _ := p.seen()
		want := link.RelayLine(checkSecret) + head + "\r\nConnection: close\r\n\r\n" + body
		if len(raw) == 0 || raw[len(raw)-1] != want {
			t.Errorf("%s: the proxy got %q\nwant %q", target, raw, want)
		}
	}
	calls := k.got()
	if len(calls) != 2 {
		t.Fatalf("the check ran %d times", len(calls))
	}
	for _, c := range calls {
		if c.Path != "/artifacts" || string(c.Body[1:]) != body[1:] {
			t.Errorf("the check got %q, %q", c.Path, c.Body)
		}
		var names []string
		for name := range c.Header {
			names = append(names, name)
		}
		slices.Sort(names)
		if want := []string{"Content-Length", "Content-Type", "X-Qory-Push"}; !slices.Equal(names, want) {
			t.Errorf("the check got the headers %q, want %q", names, want)
		}
	}
}

// TestARefusedPostGetsTheChecksReply pins a refusal: the program gets its status and the
// gateway's JSON shape, with the findings when there are some, Content-Length and
// Connection: close, and the connection closes; nothing reaches the proxy.
func TestARefusedPostGetsTheChecksReply(t *testing.T) {
	u := startUpstream(t)
	for name, c := range map[string]struct {
		refusal *RunAPIRefusal
		want    string
	}{
		"findings": {&RunAPIRefusal{Status: 422, Code: "push_checks_failed", Message: "Fix the failing checks, then push again:\nmake test exited 2.", Findings: []string{"make test: 2 failures", "make lint"}},
			`{"error":"push_checks_failed","message":"Fix the failing checks, then push again:\nmake test exited 2.","findings":["make test: 2 failures","make lint"]}`},
		"no findings": {&RunAPIRefusal{Status: 409, Code: "conflict", Message: "Pull first."},
			`{"error":"conflict","message":"Pull first."}`},
	} {
		t.Run(name, func(t *testing.T) {
			k := &checkCalls{answer: func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) { return c.refusal, nil }}
			f := checkedForwarder(t, u.ln.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID})
			out := relaySend(t, f, post(checkTarget("/artifacts"), `{"artifacts":[]}`))
			resp, body := replyOf(t, out)
			if resp.StatusCode != c.refusal.Status || body != c.want || resp.Header.Get("Content-Type") != "application/json" ||
				resp.ContentLength != int64(len(c.want)) || !resp.Close {
				t.Errorf("the program got %q", out)
			}
		})
	}
	time.Sleep(100 * time.Millisecond)
	if opened, received := u.seen(); opened != 0 {
		t.Errorf("the proxy got %d connections, %q", opened, received)
	}
}

// TestACheckThatFailsGetsA503 pins the 503 of a check that returns an error, panics,
// returns a refusal with no code, a 407 or a status outside 400 to 499, returns a hold
// for a POST to /artifacts, outlasts its 90 seconds, here shortened, whether it watches its context or
// not, or runs as the run closes; a panic is a Report line, and nothing reaches the
// proxy.
func TestACheckThatFailsGetsA503(t *testing.T) {
	const want = `{"error":"push_check_unavailable","message":"Run the push again: the check before the push did not finish."}`
	u := startUpstream(t)
	closed, closeRun := context.WithCancel(context.Background())
	for name, answer := range map[string]func(ctx context.Context, req RunAPIRequest) (*RunAPIRefusal, error){
		"an error": func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) {
			return nil, errors.New("the checks did not start")
		},
		"a panic": func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) { panic("the check broke") },
		"a 200":   func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) { return &RunAPIRefusal{Status: 200}, nil },
		"a 500": func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) {
			return &RunAPIRefusal{Status: 500, Code: "broken", Message: "Retry."}, nil
		},
		"a 399": func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) {
			return &RunAPIRefusal{Status: 399, Code: "odd", Message: "Retry."}, nil
		},
		"a 407": func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) {
			return &RunAPIRefusal{Status: http.StatusProxyAuthRequired, Code: "credentials", Message: "Sign in."}, nil
		},
		"no code": func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) {
			return &RunAPIRefusal{Status: http.StatusUnprocessableEntity, Message: "Fix the tests."}, nil
		},
		"a refusal and an error": func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) {
			return &RunAPIRefusal{Status: 422}, errors.New("half done")
		},
		"the deadline": func(ctx context.Context, _ RunAPIRequest) (*RunAPIRefusal, error) {
			<-ctx.Done()
			return nil, nil
		},
		"the deadline, unwatched": func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) {
			time.Sleep(2 * time.Second)
			return nil, nil
		},
		"a hold of another path": func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) {
			return nil, ErrRunAPIHold
		},
		"a wrapped hold of another path": func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) {
			return nil, fmt.Errorf("kept: %w", ErrRunAPIHold)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var reports []string
			var mu sync.Mutex
			k := &checkCalls{answer: answer}
			f := checkedForwarder(t, u.ln.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID, wait: 200 * time.Millisecond,
				report: func(l string) { mu.Lock(); reports = append(reports, l); mu.Unlock() }})
			start := time.Now()
			out := relaySend(t, f, post(checkTarget("/artifacts"), "{}"))
			resp, body := replyOf(t, out)
			if resp.StatusCode != http.StatusServiceUnavailable || body != want || !resp.Close {
				t.Errorf("the program got %q", out)
			}
			if d := time.Since(start); d > 1500*time.Millisecond {
				t.Errorf("the reply took %v", d)
			}
			mu.Lock()
			defer mu.Unlock()
			if panicked := name == "a panic"; panicked != (len(reports) == 1) || panicked && !strings.Contains(reports[0], "panicked: the check broke") {
				t.Errorf("the reports %q", reports)
			}
		})
	}
	t.Run("the run's close", func(t *testing.T) {
		started := make(chan struct{})
		k := &checkCalls{answer: func(ctx context.Context, _ RunAPIRequest) (*RunAPIRefusal, error) {
			close(started)
			<-ctx.Done()
			return nil, nil
		}}
		f := checkedForwarder(t, u.ln.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID, done: closed})
		go func() {
			<-started
			closeRun()
		}()
		resp, body := replyOf(t, relaySend(t, f, post(checkTarget("/verdict"), "{}")))
		if resp.StatusCode != http.StatusServiceUnavailable || body != want {
			t.Errorf("the program got %d %q", resp.StatusCode, body)
		}
	})
	time.Sleep(100 * time.Millisecond)
	if opened, received := u.seen(); opened != 0 {
		t.Errorf("the proxy got %d connections, %q", opened, received)
	}
}

// TestAHoldAfterTheContextEndedIsNoHold pins a hold that the check returns once its
// context ended: the call returns the context's error and never the hold, whichever of
// the two the call reads first. The check ends the parent context, then returns the
// hold, 2000 times.
func TestAHoldAfterTheContextEndedIsNoHold(t *testing.T) {
	held := 0
	for range 2000 {
		ctx, cancel := context.WithCancel(context.Background())
		k := &runAPICheck{runID: checkRunID, check: func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) {
			cancel()
			return nil, ErrRunAPIHold
		}}
		_, err := k.call(ctx, RunAPIRequest{Path: "/verdict"})
		cancel()
		if errors.Is(err, ErrRunAPIHold) {
			held++
		}
		if err == nil {
			t.Fatal("a call returned no error")
		}
	}
	if held != 0 {
		t.Errorf("%d of 2000 calls returned the hold", held)
	}
}

// heldVerdict is the exact body of the 202 for a held verdict.
const heldVerdict = `{"version":1,"artifact":{"type":"verdict","name":"main","version":null}}`

// TestAHeldVerdictGetsA202AndGoesNowhere pins a hold of a POST to /verdict, with
// ErrRunAPIHold or an error that wraps it: the check gets the whole body as sent, the
// program gets a 202 with the body of a stored verdict and null for the artifact's
// version, as JSON with Content-Length and Connection: close, and nothing reaches the
// proxy. A hold after the check's context ended gets the 503, and a verdict that the
// check lets pass still goes on.
func TestAHeldVerdictGetsA202AndGoesNowhere(t *testing.T) {
	p := startProxyStandIn(t, checkSecret, nil)
	const body = `{"verdict":"passed","points":[{"text":"Add a test."}]}`
	for name, hold := range map[string]error{
		"the hold":       ErrRunAPIHold,
		"a wrapped hold": fmt.Errorf("held for the end check: %w", ErrRunAPIHold),
	} {
		t.Run(name, func(t *testing.T) {
			k := &checkCalls{answer: func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) { return nil, hold }}
			f := checkedForwarder(t, p.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID})
			out := relaySend(t, f, post(checkTarget("/verdict"), body, "Content-Type: application/json"))
			resp, got := replyOf(t, out)
			if resp.StatusCode != http.StatusAccepted || got != heldVerdict || resp.Header.Get("Content-Type") != "application/json" ||
				resp.ContentLength != int64(len(heldVerdict)) || !resp.Close {
				t.Errorf("the program got %q", out)
			}
			if calls := k.got(); len(calls) != 1 || calls[0].Path != "/verdict" || string(calls[0].Body) != body {
				t.Errorf("the check got %+v", calls)
			}
		})
	}
	time.Sleep(100 * time.Millisecond)
	if raw, _ := p.seen(); len(raw) != 0 {
		t.Errorf("the proxy got %q", raw)
	}

	// A hold after the check's context ended is a check that outlasted it.
	late := &checkCalls{answer: func(ctx context.Context, _ RunAPIRequest) (*RunAPIRefusal, error) {
		<-ctx.Done()
		return nil, ErrRunAPIHold
	}}
	f := checkedForwarder(t, p.Addr().String(), &runAPICheck{check: late.check, runID: checkRunID, wait: 200 * time.Millisecond})
	if resp, got := replyOf(t, relaySend(t, f, post(checkTarget("/verdict"), body))); resp.StatusCode != http.StatusServiceUnavailable ||
		!strings.Contains(got, `"push_check_unavailable"`) {
		t.Errorf("a late hold got %d %q", resp.StatusCode, got)
	}
	time.Sleep(100 * time.Millisecond)
	if raw, _ := p.seen(); len(raw) != 0 {
		t.Errorf("the proxy got %q", raw)
	}

	pass := &checkCalls{}
	f = checkedForwarder(t, p.Addr().String(), &runAPICheck{check: pass.check, runID: checkRunID})
	if resp, got := replyOf(t, relaySend(t, f, post(checkTarget("/verdict"), body))); resp.StatusCode != http.StatusOK || got != fmt.Sprintf("ok %d", len(body)) {
		t.Errorf("a passed verdict got %d %q", resp.StatusCode, got)
	}
	if _, requests := p.seen(); len(requests) != 1 || !strings.HasSuffix(requests[0], "/verdict "+body) {
		t.Errorf("the proxy got %q", requests)
	}
}

// TestTheCheckGetsHeldVerdictsInOrder pins the order of held verdicts: verdicts that
// reach the forwarder one after another, while the check of the first runs, are checked
// one at a time in that order, each gets the 202, and none reaches the proxy.
func TestTheCheckGetsHeldVerdictsInOrder(t *testing.T) {
	u := startUpstream(t)
	release := make(chan struct{})
	var mu sync.Mutex
	running, most := 0, 0
	k := &checkCalls{answer: func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) {
		mu.Lock()
		running++
		most = max(most, running)
		mu.Unlock()
		<-release
		mu.Lock()
		running--
		mu.Unlock()
		return nil, ErrRunAPIHold
	}}
	f := checkedForwarder(t, u.ln.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID})
	const n = 4
	outs := make(chan string, n)
	var sent []string
	for i := range n {
		body := fmt.Sprintf(`{"verdict":"escalate","points":[{"text":"point %d"}]}`, i)
		sent = append(sent, body)
		go func() { outs <- relaySend(t, f, post(checkTarget("/verdict"), body)) }()
		// Each verdict reaches the forwarder before the next one.
		time.Sleep(150 * time.Millisecond)
	}
	if got := len(k.got()); got != 1 {
		t.Errorf("%d checks started while the first ran", got)
	}
	close(release)
	for range n {
		if resp, body := replyOf(t, <-outs); resp.StatusCode != http.StatusAccepted || body != heldVerdict {
			t.Errorf("a verdict got %d %q", resp.StatusCode, body)
		}
	}
	var checked []string
	for _, c := range k.got() {
		checked = append(checked, string(c.Body))
	}
	if !slices.Equal(checked, sent) {
		t.Errorf("the check got %q\nwant %q", checked, sent)
	}
	if most != 1 {
		t.Errorf("%d checks ran at once", most)
	}
	time.Sleep(100 * time.Millisecond)
	if opened, received := u.seen(); opened != 0 {
		t.Errorf("the proxy got %d connections, %q", opened, received)
	}
}

// TestACheckedPostOverItsLimitGetsA413 pins the gateway's limits: a Content-Length over
// 64 KiB on /verdict, or over 32 MiB on /artifacts or another path, gets the gateway's 413
// at once, before any body, and neither the check nor the proxy gets anything; a body at
// the limit goes on.
func TestACheckedPostOverItsLimitGetsA413(t *testing.T) {
	u := startUpstream(t)
	k := &checkCalls{}
	f := checkedForwarder(t, u.ln.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID})
	for path, limit := range map[string]int64{"/verdict": link.MaxRunAPIVerdict, "/artifacts": link.MaxRunAPIArtifacts, "/attach": link.MaxRunAPIArtifacts} {
		head := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", checkTarget(path), link.RunAPIHost, limit+1)
		resp, body := replyOf(t, relaySend(t, f, head))
		want := fmt.Sprintf(`{"error":"payload_too_large","message":"Shrink the body to at most %d bytes: the run API takes no more on this path."}`, limit)
		if resp.StatusCode != http.StatusRequestEntityTooLarge || body != want {
			t.Errorf("%s: the program got %d %q", path, resp.StatusCode, body)
		}
	}
	if calls := k.got(); len(calls) != 0 {
		t.Errorf("the check ran for %d requests", len(calls))
	}
	time.Sleep(100 * time.Millisecond)
	if opened, _ := u.seen(); opened != 0 {
		t.Errorf("the proxy got %d connections", opened)
	}
	p := startProxyStandIn(t, checkSecret, nil)
	f = checkedForwarder(t, p.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID})
	body := strings.Repeat("v", int(link.MaxRunAPIVerdict))
	if resp, got := replyOf(t, relaySend(t, f, post(checkTarget("/verdict"), body))); resp.StatusCode != http.StatusOK || got != fmt.Sprintf("ok %d", len(body)) {
		t.Errorf("a verdict at the limit: %d %q", resp.StatusCode, got)
	}
}

// TestACheckedPostTheForwarderCannotReadGetsA400 pins the POSTs to the run API's host that
// the forwarder and the gateway's proxy could read differently, or that have no length
// before their body: each gets a 400, and neither the check nor the proxy gets anything.
func TestACheckedPostTheForwarderCannotReadGetsA400(t *testing.T) {
	u := startUpstream(t)
	k := &checkCalls{}
	f := checkedForwarder(t, u.ln.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID})
	target := checkTarget("/artifacts")
	host := "Host: " + link.RunAPIHost + "\r\n"
	t.Run("each", func(t *testing.T) {
		for name, what := range map[string]string{
			"chunked":                   "POST " + target + " HTTP/1.1\r\n" + host + "Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
			"chunked and a length":      "POST " + target + " HTTP/1.1\r\n" + host + "Transfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
			"another Transfer-Encoding": "POST " + target + " HTTP/1.1\r\n" + host + "Content-Length: 2\r\nTransfer-Encoding: identity\r\n\r\n{}",
			"two lengths":               "POST " + target + " HTTP/1.1\r\n" + host + "Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
			"a list of lengths":         "POST " + target + " HTTP/1.1\r\n" + host + "Content-Length: 2, 2\r\n\r\n{}",
			"a signed length":           "POST " + target + " HTTP/1.1\r\n" + host + "Content-Length: +2\r\n\r\n{}",
			"a folded line":             "POST " + target + " HTTP/1.1\r\n" + host + "X-Note: a\r\n Content-Length: 2\r\nContent-Length: 0\r\n\r\n{}",
			"a bare LF":                 "POST " + target + " HTTP/1.1\r\n" + host + "X-Note: a\nContent-Length: 2\r\n\r\n{}",
			"a bare CR":                 "POST " + target + " HTTP/1.1\r\n" + host + "X-Note: a\rContent-Length: 2\r\n\r\n{}",
			"a bare LF to end":          "POST " + target + " HTTP/1.1\r\n" + host + "Content-Length: 2\r\n\n{}",
			"a space before the colon":  "POST " + target + " HTTP/1.1\r\n" + host + "Content-Length : 2\r\n\r\n{}",
			"a control character":       "POST " + target + " HTTP/1.1\r\n" + host + "X-Note: a\x00b\r\nContent-Length: 2\r\n\r\n{}",
			"two hosts":                 "POST " + target + " HTTP/1.1\r\n" + host + host + "Content-Length: 2\r\n\r\n{}",
			"no host":                   "POST " + target + " HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
			"another host":              "POST " + target + " HTTP/1.1\r\nHost: api.example\r\nContent-Length: 2\r\n\r\n{}",
			"the host for another":      "POST http://api.example/upload HTTP/1.1\r\n" + host + "Content-Length: 2\r\n\r\n{}",
			"the host with a port":      post("http://"+link.RunAPIHost+":80/v1/runs/"+checkRunID+"/artifacts", "{}"),
			"the host in capitals":      post("http://RUN-API.qory.invalid/v1/runs/"+checkRunID+"/artifacts", "{}"),
			"the host with a dot":       post("http://"+link.RunAPIHost+"./v1/runs/"+checkRunID+"/artifacts", "{}"),
			"a user":                    post("http://agent@"+link.RunAPIHost+"/v1/runs/"+checkRunID+"/artifacts", "{}"),
			"https":                     post("https://"+link.RunAPIHost+"/v1/runs/"+checkRunID+"/artifacts", "{}"),
			"HTTP/1.0":                  "POST " + target + " HTTP/1.0\r\n" + host + "Content-Length: 2\r\n\r\n{}",
			"post in lower case":        "post " + target + " HTTP/1.1\r\n" + host + "Content-Length: 2\r\n\r\n{}",
			"an encoded host":           post("http://run-api%2Eqory.invalid/v1/runs/"+checkRunID+"/artifacts", "{}"),
			"origin-form":               "POST /v1/runs/" + checkRunID + "/artifacts HTTP/1.1\r\n" + host + "Content-Length: 2\r\n\r\n{}",
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				out := relaySend(t, f, what)
				if !strings.HasPrefix(out, "HTTP/1.1 400 Bad Request\r\n") {
					t.Errorf("the program got %q", out)
				}
				// The forwarder reads a request line as it does without a wall; past it, a POST
				// to the run API gets the gateway's JSON shape.
				if name == "origin-form" || name == "an encoded host" {
					return
				}
				if _, body := replyOf(t, out); !strings.HasPrefix(body, `{"error":"bad_request","message":"Send `) {
					t.Errorf("the program got the body %q", body)
				}
			})
		}
	})
	if calls := k.got(); len(calls) != 0 {
		t.Errorf("the check ran for %d requests", len(calls))
	}
	time.Sleep(100 * time.Millisecond)
	if opened, received := u.seen(); opened != 0 {
		t.Errorf("the proxy got %d connections, %q", opened, received)
	}
}

// TestACheckedPostWhoseBodyStallsGoesNowhere pins the body's wait: a body shorter than its
// Content-Length closes the connection once the wait, here shortened, passes, and neither
// the check nor the proxy gets anything.
func TestACheckedPostWhoseBodyStallsGoesNowhere(t *testing.T) {
	u := startUpstream(t)
	k := &checkCalls{}
	f := checkedForwarder(t, u.ln.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID, bodyWait: 200 * time.Millisecond})
	c, err := net.Dial("tcp", f.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	head := "POST " + checkTarget("/artifacts") + " HTTP/1.1\r\nHost: " + link.RunAPIHost + "\r\nContent-Length: 10\r\n\r\n12345"
	io.WriteString(c, link.RelayLine(checkHop)+head)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if b, err := io.ReadAll(c); err != nil || len(b) != 0 {
		t.Errorf("the program got %q, %v", b, err)
	}
	if opened, _ := u.seen(); opened != 0 || len(k.got()) != 0 {
		t.Errorf("the proxy got %d connections, the check %d calls", opened, len(k.got()))
	}
}

// TestACheckedPostThatExpectsAContinueGetsOne pins Expect: 100-continue: the forwarder
// writes a 100 Continue before it reads the body, and the program that waits for it gets
// the reply.
func TestACheckedPostThatExpectsAContinueGetsOne(t *testing.T) {
	p := startProxyStandIn(t, checkSecret, nil)
	k := &checkCalls{}
	f := checkedForwarder(t, p.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID})
	c, err := net.Dial("tcp", f.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, link.RelayLine(checkHop)+"POST "+checkTarget("/artifacts")+" HTTP/1.1\r\nHost: "+link.RunAPIHost+"\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	for _, want := range []string{"HTTP/1.1 100 Continue\r\n", "\r\n"} {
		if line, err := r.ReadString('\n'); err != nil || line != want {
			t.Fatalf("the program got %q, %v; want %q", line, err, want)
		}
	}
	io.WriteString(c, "{}")
	rest, _ := io.ReadAll(r)
	if resp, body := replyOf(t, string(rest)); resp.StatusCode != http.StatusOK || body != "ok 2" {
		t.Errorf("the program got %q", rest)
	}
}

// TestTheCheckPassesOtherRequestsUnchecked pins what the check never gets: a GET to the
// run API, a POST to another host, a POST to the run API outside the run's path, and a
// CONNECT, each through to the proxy, the CONNECT as sent with Connection: close.
func TestTheCheckPassesOtherRequestsUnchecked(t *testing.T) {
	k := &checkCalls{answer: func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) {
		return &RunAPIRefusal{Status: 422, Code: "refused", Message: "No."}, nil
	}}
	p := startProxyStandIn(t, checkSecret, nil)
	f := checkedForwarder(t, p.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID})
	other := "http://" + link.RunAPIHost + "/v1/runs/run_f1xt0re00000000000000000f/artifacts"
	for _, what := range []string{
		"GET " + checkTarget("/work-item") + " HTTP/1.1\r\nHost: " + link.RunAPIHost + "\r\n\r\n",
		"POST http://api.example/upload HTTP/1.1\r\nHost: api.example\r\nContent-Length: 2\r\n\r\n{}",
		post(other, "{}"),
		post("http://"+link.RunAPIHost+"/v1/runs/"+checkRunID, "{}"),
	} {
		if resp, body := replyOf(t, relaySend(t, f, what)); resp.StatusCode != http.StatusOK || !strings.HasPrefix(body, "ok ") {
			line, _, _ := strings.Cut(what, "\r\n")
			t.Errorf("%s: the program got %d %q", line, resp.StatusCode, body)
		}
	}
	_, requests := p.seen()
	want := []string{"GET " + checkTarget("/work-item") + " ", "POST http://api.example/upload {}", "POST " + other + " {}", "POST " + link.RunAPIURL(checkRunID) + " {}"}
	if !slices.Equal(requests, want) {
		t.Errorf("the proxy got %q\nwant %q", requests, want)
	}
	if calls := k.got(); len(calls) != 0 {
		t.Errorf("the check ran for %d requests", len(calls))
	}

	u := startUpstream(t)
	f = checkedForwarder(t, u.ln.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID})
	const connect = "CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\n\r\n"
	c, err := net.Dial("tcp", f.Addr())
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, link.RelayLine(checkHop)+connect+"tunnel bytes")
	c.(*net.TCPConn).CloseWrite()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	io.ReadAll(c)
	c.Close()
	want = []string{link.RelayLine(checkSecret) + "CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\nConnection: close\r\n\r\ntunnel bytes"}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, received := u.seen(); slices.Equal(received, want) {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("the proxy got %q\nwant %q", received, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestTheCheckTakesOneRequestAConnection pins a second request on a connection: after a
// POST that the check lets pass, or after a GET, a POST pipelined on the same connection
// never reaches the check or the proxy.
func TestTheCheckTakesOneRequestAConnection(t *testing.T) {
	k := &checkCalls{}
	p := startProxyStandIn(t, checkSecret, nil)
	f := checkedForwarder(t, p.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID})
	second := post(checkTarget("/verdict"), `{"verdict":"second"}`)
	for _, first := range []string{
		post(checkTarget("/artifacts"), `{"first":1}`),
		"GET " + checkTarget("/work-item") + " HTTP/1.1\r\nHost: " + link.RunAPIHost + "\r\n\r\n",
	} {
		out := relaySend(t, f, first+second)
		if n := strings.Count(out, "HTTP/1.1 "); n != 1 {
			t.Errorf("the program got %d replies: %q", n, out)
		}
	}
	_, requests := p.seen()
	want := []string{"POST " + checkTarget("/artifacts") + ` {"first":1}`, "GET " + checkTarget("/work-item") + " "}
	if !slices.Equal(requests, want) {
		t.Errorf("the proxy got %q\nwant %q", requests, want)
	}
	if calls := k.got(); len(calls) != 1 || calls[0].Path != "/artifacts" {
		t.Errorf("the check got %v", calls)
	}
}

// TestTheWalledForwarderWithoutACheckPassesBytesAsTheyCome pins a walled forwarder with no
// check set, as the run opens it on one machine and behind a separate gateway: a
// connection that carries a POST to the run API, a GET whose head is over the checked
// forwarder's limits, and a chunked POST, kept alive, reaches the proxy byte for byte,
// after the relay's preamble.
func TestTheWalledForwarderWithoutACheckPassesBytesAsTheyCome(t *testing.T) {
	sent := post(checkTarget("/artifacts"), `{"artifacts":[]}`) +
		"GET " + checkTarget("/work-item") + " HTTP/1.1\r\nHost: " + link.RunAPIHost + "\r\nX-Large: " + strings.Repeat("a", 2*maxProxyLine) + "\r\n\r\n" +
		"POST " + checkTarget("/artifacts") + " HTTP/1.1\r\nHost: " + link.RunAPIHost + "\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
	for name, way := range map[string]struct {
		way     forwarding
		relayed string
	}{
		"one machine":        {forwarding{checkRelay: checkSecret}, link.RelayLine(checkSecret)},
		"a separate gateway": {forwarding{secret: checkSecret, hop: checkHop}, link.RelayLine(checkHop)},
	} {
		t.Run(name, func(t *testing.T) {
			u := startUpstream(t)
			way.way.dial = dialTCP(u.ln.Addr().String())
			f, err := listenForwarding("127.0.0.1:0", way.way)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			c, err := net.Dial("tcp", f.Addr())
			if err != nil {
				t.Fatal(err)
			}
			io.WriteString(c, way.relayed+sent)
			c.(*net.TCPConn).CloseWrite()
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			io.ReadAll(c)
			c.Close()
			want := []string{link.RelayLine(checkSecret) + sent}
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, received := u.seen(); slices.Equal(received, want) {
					return
				} else if time.Now().After(deadline) {
					t.Fatalf("the proxy got %q\nwant %q", received, want)
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

// TestTheCheckOnOneMachineTakesTheRelaysPreamble pins the walled forwarder on one machine,
// as the run opens it, once setCheck set the check: a connection without the relay's
// preamble and the run's proxy secret closes with nothing sent on, and one with them
// reaches the proxy after the same preamble.
func TestTheCheckOnOneMachineTakesTheRelaysPreamble(t *testing.T) {
	p := startProxyStandIn(t, checkSecret, nil)
	k := &checkCalls{}
	f, err := listenForwarding("127.0.0.1:0", forwarding{dial: dialTCP(p.Addr().String()), checkRelay: checkSecret})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.setCheck(&runAPICheck{check: k.check, runID: checkRunID}); err != nil {
		t.Fatal(err)
	}
	what := post(checkTarget("/artifacts"), "{}")
	send := func(preamble string) string {
		c, err := net.Dial("tcp", f.Addr())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		go io.WriteString(c, preamble+what)
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(c)
		return string(b)
	}
	if out := send(link.RelayLine(checkHop)); out != "" {
		t.Errorf("another secret got %q", out)
	}
	if resp, body := replyOf(t, send(link.RelayLine(checkSecret))); resp.StatusCode != http.StatusOK || body != "ok 2" {
		t.Errorf("the relay got %d %q", resp.StatusCode, body)
	}
	raw, _ := p.seen()
	if want := link.RelayLine(checkSecret) + strings.Replace(what, "\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1); len(raw) != 1 || raw[0] != want {
		t.Errorf("the proxy got %q\nwant %q", raw, want)
	}
	if len(k.got()) != 1 {
		t.Errorf("the check ran %d times", len(k.got()))
	}
}

// TestRunAPIPathReadsAsTheGateway pins the path the check gets, against the gateway
// route's reading of a target: under the run's id, each segment decoded and escaped
// again; outside it, empty.
func TestRunAPIPathReadsAsTheGateway(t *testing.T) {
	for raw, want := range map[string]string{
		"/v1/runs/" + checkRunID + "/artifacts":       "/artifacts",
		"/v1/runs/" + checkRunID + "/verdict?x=1":     "/verdict",
		"/%76%31/runs/" + checkRunID + "/%76erdict":   "/verdict",
		"/v1/runs/" + checkRunID + "/a%20b/c":         "/a%20b/c",
		"/v1/runs/" + checkRunID:                      "",
		"/v1/runs/" + checkRunID + "/":                "/",
		"/v1/runs/run_other/artifacts":                "",
		"/v1/runs/" + checkRunID + "/%zz":             "",
		"/v2/runs/" + checkRunID + "/artifacts":       "",
		"/v1/runs/" + checkRunID + "/artifacts#frag":  "/artifacts",
		"/v1//runs/" + checkRunID + "/artifacts":      "",
		"/v1/runs/" + checkRunID + "/artifacts/../ok": "/artifacts/../ok",
	} {
		if got := runAPIPath(raw, checkRunID); got != want {
			t.Errorf("%s: %q, want %q", raw, got, want)
		}
	}
}

// TestTheCheckTakesOnePostAtATime pins the run's one slot: a second POST's check starts
// only once the first's returns, and a POST that waits longer than a check has, here
// shortened, behind a POST whose body does not come, gets the 503 with nothing sent on.
func TestTheCheckTakesOnePostAtATime(t *testing.T) {
	p := startProxyStandIn(t, checkSecret, nil)
	release := make(chan struct{})
	var mu sync.Mutex
	running, most := 0, 0
	k := &checkCalls{answer: func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) {
		mu.Lock()
		running++
		most = max(most, running)
		mu.Unlock()
		<-release
		mu.Lock()
		running--
		mu.Unlock()
		return nil, nil
	}}
	f := checkedForwarder(t, p.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID})
	outs := make(chan string, 2)
	for range 2 {
		go func() { outs <- relaySend(t, f, post(checkTarget("/artifacts"), "{}")) }()
	}
	time.Sleep(300 * time.Millisecond)
	if n := len(k.got()); n != 1 {
		t.Errorf("%d checks started while the first ran", n)
	}
	close(release)
	for range 2 {
		if resp, body := replyOf(t, <-outs); resp.StatusCode != http.StatusOK || body != "ok 2" {
			t.Errorf("a POST got %d %q", resp.StatusCode, body)
		}
	}
	if most != 1 {
		t.Errorf("%d checks ran at once", most)
	}

	// A body that does not come holds the slot.
	u := startUpstream(t)
	slow := &checkCalls{}
	f = checkedForwarder(t, u.ln.Addr().String(), &runAPICheck{check: slow.check, runID: checkRunID, wait: 300 * time.Millisecond})
	go relaySend(t, f, "POST "+checkTarget("/artifacts")+" HTTP/1.1\r\nHost: "+link.RunAPIHost+"\r\nContent-Length: 2\r\n\r\n")
	time.Sleep(100 * time.Millisecond)
	resp, body := replyOf(t, relaySend(t, f, post(checkTarget("/verdict"), "{}")))
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, `"push_check_unavailable"`) {
		t.Errorf("the waiting POST got %d %q", resp.StatusCode, body)
	}
	if opened, _ := u.seen(); opened != 0 || len(slow.got()) != 0 {
		t.Errorf("the proxy got %d connections, the check %d calls", opened, len(slow.got()))
	}
}

// TestTheCheckClosesAConnectionWithNoHead pins the head's wait with a check: a
// connection that sends no head in time, here shortened, closes with nothing sent on.
func TestTheCheckClosesAConnectionWithNoHead(t *testing.T) {
	u := startUpstream(t)
	f, err := listenForwarding("127.0.0.1:0", forwarding{dial: dialTCP(u.ln.Addr().String()), secret: checkSecret, hop: checkHop,
		headWait: 200 * time.Millisecond, check: &runAPICheck{check: (&checkCalls{}).check, runID: checkRunID}})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := net.Dial("tcp", f.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, link.RelayLine(checkHop)+"POST "+checkTarget("/artifacts")+" HTTP/1.1\r\n")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if b, _ := io.ReadAll(c); len(b) != 0 || time.Since(start) > 3*time.Second {
		t.Errorf("the program got %q after %v", b, time.Since(start))
	}
	if opened, _ := u.seen(); opened != 0 {
		t.Errorf("the proxy got %d connections", opened)
	}
}

// TestAProgramThatKeepsSendingAfterARefusalHoldsBackNoCheck pins the slot's release at
// the check's return: while a program that got a refusal still sends a byte every 100
// milliseconds, another POST's check runs and its reply comes at once.
func TestAProgramThatKeepsSendingAfterARefusalHoldsBackNoCheck(t *testing.T) {
	p := startProxyStandIn(t, checkSecret, nil)
	k := &checkCalls{answer: func(_ context.Context, req RunAPIRequest) (*RunAPIRefusal, error) {
		if string(req.Body) == `{"first":1}` {
			return &RunAPIRefusal{Status: http.StatusUnprocessableEntity, Code: "push_checks_failed", Message: "Fix the tests."}, nil
		}
		return nil, nil
	}}
	f := checkedForwarder(t, p.Addr().String(), &runAPICheck{check: k.check, runID: checkRunID})
	c, err := net.Dial("tcp", f.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, link.RelayLine(checkHop)+post(checkTarget("/artifacts"), `{"first":1}`))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err != nil || resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("the first POST got %v, %v", resp, err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
				if _, err := io.WriteString(c, "x"); err != nil {
					return
				}
			}
		}
	}()
	start := time.Now()
	resp, body := replyOf(t, relaySend(t, f, post(checkTarget("/artifacts"), `{"second":2}`)))
	if resp.StatusCode != http.StatusOK || body != "ok 12" || time.Since(start) > 2*time.Second {
		t.Errorf("the second POST got %d %q after %v", resp.StatusCode, body, time.Since(start))
	}
}

// TestTheCheckWritesAReplyToAHeadItCannotPass pins a request with a check that is not a
// POST to the run API: a head over the limits gets a 431 and a head net/http does not
// read gets a 400, each in plain text, and nothing reaches the proxy.
func TestTheCheckWritesAReplyToAHeadItCannotPass(t *testing.T) {
	u := startUpstream(t)
	f := checkedForwarder(t, u.ln.Addr().String(), &runAPICheck{check: (&checkCalls{}).check, runID: checkRunID})
	get := "GET http://api.example/ HTTP/1.1\r\nHost: api.example\r\n"
	for name, c := range map[string]struct {
		what   string
		status int
	}{
		"a long line":     {get + "X-Long: " + strings.Repeat("a", maxProxyLine) + "\r\n\r\n", http.StatusRequestHeaderFieldsTooLarge},
		"too many lines":  {get + strings.Repeat("X-Line: a\r\n", maxProxyLines) + "\r\n", http.StatusRequestHeaderFieldsTooLarge},
		"too many bytes":  {get + strings.Repeat("X-Line: "+strings.Repeat("a", 400)+"\r\n", 50) + "\r\n", http.StatusRequestHeaderFieldsTooLarge},
		"a line no colon": {get + "No colon here\r\n\r\n", http.StatusBadRequest},
		"a bad length":    {get + "Content-Length: abc\r\n\r\n", http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			out := relaySend(t, f, c.what)
			resp, body := replyOf(t, out)
			if resp.StatusCode != c.status || resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" || !strings.HasPrefix(body, "S") {
				t.Errorf("the program got %q", out)
			}
		})
	}
	time.Sleep(100 * time.Millisecond)
	if opened, _ := u.seen(); opened != 0 {
		t.Errorf("the proxy got %d connections", opened)
	}
}

// TestAConnectionDuringSetCheckIsRefusedOrChecked pins setCheck against connections that
// show the relay's preamble while it runs, on a forwarder as the run opens it on one
// machine: either the call fails, as a connection showed the preamble before it, or every
// request of every connection is checked, so each POST to the run API gets the check's
// refusal and nothing reaches the proxy. The rounds go on until both happened, at most
// 400 of them. Run it with -race.
func TestAConnectionDuringSetCheckIsRefusedOrChecked(t *testing.T) {
	const conns = 4
	what := post(checkTarget("/artifacts"), "{}")
	var refused, checked int
	for n := 0; n < 400 && (refused == 0 || checked == 0); n++ {
		u := startUpstream(t)
		k := &checkCalls{answer: func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) {
			return &RunAPIRefusal{Status: http.StatusUnprocessableEntity, Code: "push_checks_failed", Message: "Fix the checks."}, nil
		}}
		f, err := listenForwarding("127.0.0.1:0", forwarding{dial: dialTCP(u.ln.Addr().String()), checkRelay: checkSecret})
		if err != nil {
			t.Fatal(err)
		}
		outs := make([]string, conns)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range conns {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				c, err := net.Dial("tcp", f.Addr())
				if err != nil {
					t.Error(err)
					return
				}
				defer c.Close()
				io.WriteString(c, link.RelayLine(checkSecret)+what)
				c.(*net.TCPConn).CloseWrite()
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				b, _ := io.ReadAll(c)
				outs[i] = string(b)
			}()
		}
		close(start)
		// The waits differ, so some calls come before the first preamble and some after
		// it.
		time.Sleep(time.Duration(n%10) * 100 * time.Microsecond)
		err = f.setCheck(&runAPICheck{check: k.check, runID: checkRunID})
		wg.Wait()
		f.Close()
		if err != nil {
			if !errors.Is(err, errCheckShown) {
				t.Fatalf("setCheck returned %v", err)
			}
			refused++
			continue
		}
		checked++
		if opened, received := u.seen(); opened != 0 {
			t.Fatalf("with the check set, the proxy got %d connections: %q", opened, received)
		}
		for _, out := range outs {
			if !strings.HasPrefix(out, "HTTP/1.1 422 Unprocessable Entity\r\n") {
				t.Fatalf("with the check set, a connection got %q", out)
			}
		}
		if n := len(k.got()); n != conns {
			t.Fatalf("the check ran %d times, want %d", n, conns)
		}
	}
	if refused == 0 || checked == 0 {
		t.Fatalf("setCheck failed %d times and checked every connection %d times; want both", refused, checked)
	}
	t.Logf("setCheck failed %d times and checked every connection %d times", refused, checked)
}

// waitShown waits until a connection showed f the relay's preamble.
func waitShown(t *testing.T, f *forwarder) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		shown := f.shown
		f.mu.Unlock()
		if shown {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no connection showed the relay's preamble")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSetCheckIsRefusedOnceAConnectionShowedThePreamble pins that setCheck fails after a
// connection showed the relay's preamble, on one machine and behind a separate gateway,
// and after the close, and that a check passed to listenForwarding counts as set.
func TestSetCheckIsRefusedOnceAConnectionShowedThePreamble(t *testing.T) {
	u := startUpstream(t)
	k := &runAPICheck{check: (&checkCalls{}).check, runID: checkRunID}
	for name, way := range map[string]struct {
		way      forwarding
		preamble string
	}{
		"one machine":        {forwarding{checkRelay: checkSecret}, link.RelayLine(checkSecret)},
		"a separate gateway": {forwarding{secret: checkSecret, hop: checkHop}, link.RelayLine(checkHop)},
	} {
		t.Run(name, func(t *testing.T) {
			way.way.dial = dialTCP(u.ln.Addr().String())
			f, err := listenForwarding("127.0.0.1:0", way.way)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			c, err := net.Dial("tcp", f.Addr())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			io.WriteString(c, way.preamble)
			waitShown(t, f)
			if err := f.setCheck(k); !errors.Is(err, errCheckShown) {
				t.Errorf("after a connection showed the preamble: %v", err)
			}
			f.Close()
			if err := f.setCheck(k); !errors.Is(err, errCheckClosed) {
				t.Errorf("after the close: %v", err)
			}
		})
	}
	g := checkedForwarder(t, u.ln.Addr().String(), k)
	if err := g.setCheck(k); !errors.Is(err, errCheckSet) {
		t.Errorf("with a check set: %v", err)
	}
}

// TestAStrayConnectionLeavesSetCheckFree pins that a connection without the relay's
// preamble changes nothing, on one machine and behind a separate gateway: one that sends
// nothing stays unread, one with another secret is closed with nothing sent on, and
// setCheck then succeeds, so a POST of a connection with the preamble is checked.
func TestAStrayConnectionLeavesSetCheckFree(t *testing.T) {
	for name, way := range map[string]struct {
		way             forwarding
		preamble, wrong string
	}{
		"one machine":        {forwarding{checkRelay: checkSecret}, link.RelayLine(checkSecret), link.RelayLine(checkHop)},
		"a separate gateway": {forwarding{secret: checkSecret, hop: checkHop}, link.RelayLine(checkHop), link.RelayLine(checkSecret)},
	} {
		t.Run(name, func(t *testing.T) {
			u := startUpstream(t)
			way.way.dial = dialTCP(u.ln.Addr().String())
			f, err := listenForwarding("127.0.0.1:0", way.way)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			silent, err := net.Dial("tcp", f.Addr())
			if err != nil {
				t.Fatal(err)
			}
			defer silent.Close()
			wrong, err := net.Dial("tcp", f.Addr())
			if err != nil {
				t.Fatal(err)
			}
			defer wrong.Close()
			io.WriteString(wrong, way.wrong+"GET http://api.example/ HTTP/1.1\r\nHost: api.example\r\n\r\n")
			wrong.SetReadDeadline(time.Now().Add(5 * time.Second))
			// The close may reset the connection, as the forwarder read none of the GET.
			if b, err := io.ReadAll(wrong); len(b) != 0 || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("the wrong preamble got %q, %v; want the connection closed", b, err)
			}
			// The silent connection is accepted, and waits for its preamble.
			deadline := time.Now().Add(5 * time.Second)
			for {
				f.mu.Lock()
				waiting := len(f.waiting)
				f.mu.Unlock()
				if waiting == 1 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("%d connections wait for their preamble, want 1", waiting)
				}
				time.Sleep(10 * time.Millisecond)
			}
			k := &checkCalls{answer: func(context.Context, RunAPIRequest) (*RunAPIRefusal, error) {
				return &RunAPIRefusal{Status: http.StatusUnprocessableEntity, Code: "push_checks_failed", Message: "Fix the checks."}, nil
			}}
			if err := f.setCheck(&runAPICheck{check: k.check, runID: checkRunID}); err != nil {
				t.Fatal(err)
			}
			c, err := net.Dial("tcp", f.Addr())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			io.WriteString(c, way.preamble+post(checkTarget("/artifacts"), "{}"))
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if b, _ := io.ReadAll(c); !strings.HasPrefix(string(b), "HTTP/1.1 422 Unprocessable Entity\r\n") {
				t.Errorf("the POST after the call got %q", b)
			}
			if opened, received := u.seen(); opened != 0 {
				t.Errorf("the proxy got %d connections: %q", opened, received)
			}
		})
	}
}
