package gateway_test

import (
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/runcredential"
	"github.com/qoryai/forager/server"
)

// starter is the introspection endpoint of a test's run's starter: a run credential is
// active until the test gives it another answer, and every ask is counted, an ask at a
// runtime's exit apart.
type starter struct {
	mu      sync.Mutex
	answers map[string]starterAnswer
	asks    map[string]int
	exits   map[string]int
	// held, when set, holds every ask at a runtime's exit open until it is closed;
	// heldAsked is closed at the first such ask.
	held, heldAsked chan struct{}
	heldOnce        sync.Once
}

type starterAnswer struct {
	a   runcredential.Answer
	err error
}

func newStarter() *starter {
	return &starter{answers: map[string]starterAnswer{}, asks: map[string]int{}, exits: map[string]int{}}
}

// set makes the starter answer a for the run credential, or err.
func (st *starter) set(credential string, a runcredential.Answer, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.answers[credential] = starterAnswer{a, err}
}

// ends makes the starter answer that the run credential is no longer active, with the
// outcome and the reason given, each empty for none.
func (st *starter) ends(credential, outcome, reason string) {
	st.set(credential, runcredential.Answer{Outcome: outcome, Reason: reason}, nil)
}

// hold holds the asks at a runtime's exit open until the release is closed.
func (st *starter) hold() (asked, release chan struct{}) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.held, st.heldAsked = make(chan struct{}), make(chan struct{})
	return st.heldAsked, st.held
}

func (st *starter) answer(_, credential string, now bool) (runcredential.Answer, error) {
	st.mu.Lock()
	if now {
		st.exits[credential]++
	} else {
		st.asks[credential]++
	}
	held, asked := st.held, st.heldAsked
	st.mu.Unlock()
	if now && held != nil {
		st.heldOnce.Do(func() { close(asked) })
		<-held
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	a, ok := st.answers[credential]
	if !ok {
		return runcredential.Answer{Active: true}, nil
	}
	return a.a, a.err
}

// atExit is how many asks at a runtime's exit the starter was asked of the run
// credential.
func (st *starter) atExit(credential string) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.exits[credential]
}

// startStarting starts a gateway on the one address whose run credentials it verifies
// under the example issuer, with introspection answered by st, each answer kept for
// cache.
func startStarting(t *testing.T, cfg gateway.Config, st *starter, cache time.Duration) *service {
	t.Helper()
	if cfg.RunCredentials == nil {
		cfg.RunCredentials = realIssuers(t, true)
	}
	if cfg.Policy == nil {
		cfg.Policy = enforce127
	}
	gateway.SetStarter(&cfg, st.answer, cache)
	return startVerifying(t, cfg, nil, 0)
}

// outcome is the session's ask at its runtime's exit, a GET of the run's outcome with
// the run credential and the run's secret: the status, the body and the headers.
func (r *sessionRun) outcome(t *testing.T, credential string) (int, []byte, http.Header) {
	t.Helper()
	return r.outcomeAt(t, credential, "/v1/run-configuration/"+r.a.RunID+"/outcome")
}

// outcomeAt is a GET of path with the run credential and the run's secret.
func (r *sessionRun) outcomeAt(t *testing.T, credential, path string) (int, []byte, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, r.s.url(path), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(server.HeaderRunSecret, r.a.RunSecret)
	resp, err := r.s.client(credential).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

// validOutcomeAnswer fails the test unless b is valid under
// link-outcome-answer.schema.json.
func validOutcomeAnswer(t *testing.T, b []byte) {
	t.Helper()
	schema, err := contracts.Compile("link-outcome-answer.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := contracts.Decode("answer.json", b)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Errorf("the outcome answer %s: %v", b, err)
	}
}

// exitedWith is the session's dev.qory.run.exited of the run with the data given, and
// its duration.
func exitedWith(runID string, data map[string]any) map[string]any {
	d := map[string]any{"duration_ms": 5}
	for k, v := range data {
		d[k] = v
	}
	return ev(runID, event.RunExited, d)
}

// TestTheAskAtTheExit pins the answer of the one address to the session's ask at its
// runtime's exit: a 200 whose body is the starter's outcome and reason when it answers
// that the run credential is no longer active with an outcome, and {} when it answers
// active, inactive with no outcome, with no answer, or with one that is not valid. The
// starter is asked past the answer it keeps, once per run: a later ask of the run is
// the answer stored, whatever the starter says by then.
func TestTheAskAtTheExit(t *testing.T) {
	for _, c := range []struct {
		name   string
		answer runcredential.Answer
		err    error
		body   string
	}{
		{"active", runcredential.Answer{Active: true}, nil, `{}`},
		{"no outcome", runcredential.Answer{}, nil, `{}`},
		{"an outcome and a reason", runcredential.Answer{Outcome: "failed", Reason: "checks_failed"}, nil, `{"state":"failed","reason":"checks_failed"}`},
		{"an outcome with no reason", runcredential.Answer{Outcome: "succeeded"}, nil, `{"state":"succeeded"}`},
		{"no answer", runcredential.Answer{}, runcredential.ErrIssuerUnreachable, `{}`},
		{"no valid answer", runcredential.Answer{}, answerInvalid("the introspection endpoint answered status 500"), `{}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := newStarter()
			s := startStarting(t, gateway.Config{}, st, time.Hour)
			cred := credentialFor("rk-0001")
			r := s.openSession(t, cred, server.LinkRunRequest{})
			// A reload: the starter's answer active, kept for an hour.
			if status, b := r.reload(t, cred, r.a.RunID); status != http.StatusOK {
				t.Fatalf("a reload: %d %s", status, b)
			}
			st.set(cred, c.answer, c.err)
			status, b, header := r.outcome(t, cred)
			if status != http.StatusOK || string(b) != c.body || header.Get("Content-Type") != server.LinkContentType {
				t.Errorf("the ask: %d %q %q", status, b, header.Get("Content-Type"))
			}
			validOutcomeAnswer(t, b)
			if n := st.atExit(cred); n != 1 {
				t.Errorf("the starter was asked %d times at the exit; want 1, past the answer it keeps", n)
			}
			// The starter's answer changes: a later ask is the answer stored.
			st.ends(cred, "cancelled", "no_longer_needed")
			if status, again, _ := r.outcome(t, cred); status != http.StatusOK || string(again) != c.body {
				t.Errorf("a later ask: %d %q; want %q", status, again, c.body)
			}
			if n := st.atExit(cred); n != 1 {
				t.Errorf("the starter was asked %d times at the exit after a later ask", n)
			}
		})
	}
}

// TestAsksAtTheExitShareOneAsk pins asks at a runtime's exit made while the starter is
// being asked: the starter is asked once, and every ask gets its answer.
func TestAsksAtTheExitShareOneAsk(t *testing.T) {
	st := newStarter()
	s := startStarting(t, gateway.Config{}, st, time.Hour)
	cred := credentialFor("rk-0001")
	r := s.openSession(t, cred, server.LinkRunRequest{})
	st.ends(cred, "succeeded", "all_checks_passed")
	asked, release := st.hold()
	const n = 6
	bodies := make(chan string, n)
	for range n {
		go func() {
			status, b, _ := r.outcome(t, cred)
			if status != http.StatusOK {
				t.Errorf("an ask: %d %s", status, b)
			}
			bodies <- string(b)
		}()
	}
	<-asked
	// Every ask reaches the gateway before the starter answers.
	time.Sleep(300 * time.Millisecond)
	close(release)
	for range n {
		if b := <-bodies; b != `{"state":"succeeded","reason":"all_checks_passed"}` {
			t.Errorf("an ask's answer %q", b)
		}
	}
	if got := st.atExit(cred); got != 1 {
		t.Errorf("the starter was asked %d times at the exit; want 1", got)
	}
}

// TestTheAskAtTheExitIsOfTheOneAddress pins where the ask at a runtime's exit is: on
// the one address, a GET of exactly <run path>/<run id>/outcome; the local link, which
// has no starter, answers it with 400 invalid_request; a path that only begins or ends
// so is no ask, and the starter is not asked at the exit.
func TestTheAskAtTheExitIsOfTheOneAddress(t *testing.T) {
	st := newStarter()
	s := startStarting(t, gateway.Config{}, st, time.Hour)
	cred := credentialFor("rk-0001")
	r := s.openSession(t, cred, server.LinkRunRequest{})
	for _, path := range []string{
		"/v1/run-configuration/" + r.a.RunID + "/outcome/",
		"/v1/run-configuration/" + r.a.RunID + "/outcomes",
		"/v1/run-configuration/" + r.a.RunID + "/outcome/x",
		"/v1/run-configuration/" + r.a.RunID + "/x/outcome",
		"/v1/run-configuration//outcome",
		"/v1/run-configuration/outcome",
		"/v1/outcome",
	} {
		if status, b, _ := r.outcomeAt(t, cred, path); status == http.StatusOK {
			t.Errorf("%s: answered: %d %s", path, status, b)
		}
	}
	if n := st.atExit(cred); n != 0 {
		t.Errorf("the starter was asked %d times at the exit", n)
	}
	resp, b := do(t, r.s.client(cred), http.MethodPost, r.s.url("/v1/run-configuration/"+r.a.RunID+"/outcome"), "", "")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a POST of the outcome: %d %s", resp.StatusCode, b)
	}
	// Decided as a reload is: another run key's run credential is refused, and so is an
	// ask without the run's secret; a run that ended is its 410.
	otherKey := credentialFor("rk-0002")
	s.secrets = append(s.secrets, otherKey)
	if status, b, _ := r.outcome(t, otherKey); status != http.StatusUnauthorized || refusalOf(b)["error"] != "run_credential_refused" {
		t.Errorf("another run key's run credential: %d %s", status, b)
	}
	resp, b = do(t, r.s.client(cred), http.MethodGet, r.s.url("/v1/run-configuration/"+r.a.RunID+"/outcome"), "", "")
	if resp.StatusCode != http.StatusUnauthorized || refusalOf(b)["error"] != "run_credential_refused" {
		t.Errorf("an ask without the run's secret: %d %s", resp.StatusCode, b)
	}
	if n := st.atExit(cred); n != 0 {
		t.Errorf("the starter was asked %d times at the exit of a refused ask", n)
	}
	if status, b := r.post(t, cred, exited(r.a.RunID)); status != http.StatusAccepted {
		t.Fatalf("the run's run.exited: %d %s", status, b)
	}
	status, b, _ := r.outcome(t, cred)
	gone(t, "an ask of a run that ended", status, b, "run_closed")

	// The local link.
	h := start(t, gateway.Config{})
	a := h.open(server.LinkRunRequest{})
	req, _ := http.NewRequest(http.MethodGet, server.LocalOrigin+"/v1/run-configuration/"+a.RunID+"/outcome", nil)
	req.Header.Set(server.HeaderRunSecret, a.RunSecret)
	lresp, err := raw(t, h.g.LocalLink()).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	lb, _ := io.ReadAll(lresp.Body)
	lresp.Body.Close()
	if lresp.StatusCode != http.StatusBadRequest || refusalOf(lb)["error"] != "invalid_request" {
		t.Errorf("the local link: %d %s", lresp.StatusCode, lb)
	}
	if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
		t.Errorf("the local link's run after the ask: %+v", d)
	}
}

// endedAs checks a 410 of the gateway's of a run its starter ended: stopped, with the
// state and the reason, and the message that says them.
func endedAs(t *testing.T, what string, status int, b []byte, state, reason, words string) {
	t.Helper()
	gone(t, what, status, b, "stopped")
	r := refusalOf(b)
	want := "the run has ended: " + state
	if words != "" {
		want += ", " + words
	}
	got, hasReason := r["reason"]
	if r["state"] != state || hasReason != (reason != "") || (reason != "" && got != reason) || r["message"] != want {
		t.Errorf("%s: the 410 %v; want %s, %q, %q", what, r, state, reason, want)
	}
}

// recordEnds checks the gateway's record of the run ends with a dev.qory.run.exited of
// the state and the reason, and the exit_code given, nil for none.
func recordEnds(t *testing.T, s *service, runID, state, reason string, exitCode any) {
	t.Helper()
	rec := s.record(runID)
	last := rec[len(rec)-1]
	got, hasReason := last.Data["reason"]
	if last.Type != event.RunExited || last.Data["state"] != state || hasReason != (reason != "") || (reason != "" && got != reason) || last.Data["exit_code"] != exitCode {
		t.Errorf("run %s: the record ends %+v; want %s, %q", runID, last, state, reason)
	}
	validEvents(t, rec)
}

// TestARunEndingAsItsStarterSaid pins a run whose starter answered the ask at its
// runtime's exit that its run credential is no longer active: the run is ending. While
// its window is open the gateway takes the run's batches until one ends it with a
// dev.qory.run.exited of the answer, the starter's outcome and reason, or, when it gave
// no outcome, one the runtime's exit decides. A run.exited otherwise, and a reload, end
// the run as the starter said and are its 410: the starter's outcome and reason, or
// cancelled and stopped.
func TestARunEndingAsItsStarterSaid(t *testing.T) {
	type step struct {
		reload bool
		evs    func(id string) []map[string]any
		status int
	}
	for _, c := range []struct {
		name            string
		outcome, reason string
		steps           []step
		// the gateway's end: its state and reason, the 410's words; an empty state for
		// the session's own run.exited, which ends the record.
		state, endReason, words string
		sessionEnd              map[string]any
	}{
		{name: "its own run.exited", outcome: "failed", reason: "checks_failed",
			steps: []step{
				{evs: func(id string) []map[string]any { return []map[string]any{heartbeat(id)} }, status: http.StatusAccepted},
				{evs: func(id string) []map[string]any {
					return []map[string]any{exitedWith(id, map[string]any{"state": "failed", "exit_code": 0, "reason": "checks_failed"})}
				}, status: http.StatusAccepted},
			},
			sessionEnd: map[string]any{"state": "failed", "reason": "checks_failed"}},
		{name: "its own run.exited, an outcome with no reason", outcome: "succeeded",
			steps: []step{{evs: func(id string) []map[string]any {
				return []map[string]any{exitedWith(id, map[string]any{"state": "succeeded", "exit_code": 1})}
			}, status: http.StatusAccepted}},
			sessionEnd: map[string]any{"state": "succeeded"}},
		{name: "its own run.exited, no outcome",
			steps: []step{{evs: func(id string) []map[string]any {
				return []map[string]any{exitedWith(id, map[string]any{"state": "succeeded", "exit_code": 0})}
			}, status: http.StatusAccepted}},
			sessionEnd: map[string]any{"state": "succeeded"}},
		{name: "a run.exited of the runtime's exit, an outcome given", outcome: "succeeded", reason: "all_checks_passed",
			steps: []step{{evs: func(id string) []map[string]any {
				return []map[string]any{exitedWith(id, map[string]any{"state": "failed", "exit_code": 1})}
			}}},
			state: "succeeded", endReason: "all_checks_passed", words: "all checks passed"},
		{name: "a run.exited of another reason", outcome: "failed", reason: "checks_failed",
			steps: []step{{evs: func(id string) []map[string]any {
				return []map[string]any{exitedWith(id, map[string]any{"state": "failed", "exit_code": 0, "reason": "no_longer_needed"})}
			}}},
			state: "failed", endReason: "checks_failed", words: "checks failed"},
		{name: "a run.exited without the reason", outcome: "failed", reason: "checks_failed",
			steps: []step{{evs: func(id string) []map[string]any {
				return []map[string]any{exitedWith(id, map[string]any{"state": "failed", "exit_code": 1})}
			}}},
			state: "failed", endReason: "checks_failed", words: "checks failed"},
		{name: "a run.exited with a reason, no outcome",
			steps: []step{{evs: func(id string) []map[string]any {
				return []map[string]any{exitedWith(id, map[string]any{"state": "failed", "exit_code": 0, "reason": "checks_failed"})}
			}}},
			state: "cancelled", endReason: "stopped", words: "no outcome given"},
		{name: "a reload", outcome: "cancelled", reason: "no_longer_needed",
			steps: []step{{reload: true}},
			state: "cancelled", endReason: "no_longer_needed", words: "no longer needed"},
		{name: "a reload, no outcome",
			steps: []step{{reload: true}},
			state: "cancelled", endReason: "stopped", words: "no outcome given"},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := newStarter()
			s := startStarting(t, gateway.Config{}, st, time.Hour)
			cred := credentialFor("rk-0001")
			r := s.openSession(t, cred, server.LinkRunRequest{})
			st.ends(cred, c.outcome, c.reason)
			if status, b, _ := r.outcome(t, cred); status != http.StatusOK {
				t.Fatalf("the ask: %d %s", status, b)
			}
			var status int
			var b []byte
			for i, step := range c.steps {
				if step.reload {
					status, b = r.reload(t, cred, r.a.RunID)
				} else {
					status, b = r.post(t, cred, step.evs(r.a.RunID)...)
				}
				if step.status != 0 && status != step.status {
					t.Fatalf("step %d: %d %s", i, status, b)
				}
			}
			if c.state != "" {
				endedAs(t, "the request", status, b, c.state, c.endReason, c.words)
				status, b = r.post(t, cred, heartbeat(r.a.RunID))
				endedAs(t, "a later batch", status, b, c.state, c.endReason, c.words)
				line := "run " + r.a.RunID + ": its run credential is no longer valid; the run ends: " + c.state + ", " + c.words
				if got := s.reportsWith("its run credential is no longer valid"); !slices.Equal(got, []string{line}) {
					t.Errorf("reports %q; want %q", got, line)
				}
			} else {
				status, b = r.reload(t, cred, r.a.RunID)
				gone(t, "a reload after the run.exited", status, b, "run_closed")
				if r := refusalOf(b); r["message"] != "the run has ended" || r["state"] != nil || r["reason"] != nil {
					t.Errorf("the 410 after the run.exited %v", r)
				}
				if got := s.reportsWith("the run ends"); len(got) != 0 {
					t.Errorf("reports %q", got)
				}
			}
			// The run key is held: a run request of it is refused.
			if status, b := s.tryOpenWith(t, credentialFor("rk-0001"), server.LinkRunRequest{}); status != http.StatusUnauthorized {
				t.Errorf("a run request of the run key: %d %s", status, b)
			}
			d := s.close()
			if c.state != "" {
				recordEnds(t, s, r.a.RunID, c.state, c.endReason, float64(-1))
				if !d.RunClosed || d.ClosedReason != "stopped" || d.State != c.state || d.Reason != c.endReason {
					t.Errorf("delivery %+v", d)
				}
			} else {
				reason, _ := c.sessionEnd["reason"].(string)
				rec := s.record(r.a.RunID)
				recordEnds(t, s, r.a.RunID, c.sessionEnd["state"].(string), reason, rec[len(rec)-1].Data["exit_code"])
				if exited := slices.DeleteFunc(rec, func(l recorded) bool { return l.Type != event.RunExited }); len(exited) != 1 {
					t.Errorf("run.exited %+v", exited)
				}
				if d.RunClosed || d.ClosedReason != "" || d.State != "" || d.Reason != "" {
					t.Errorf("delivery %+v", d)
				}
			}
		})
	}
}

// TestTheWindowOfARunEndingCloses pins the end of a run whose starter answered the ask
// at its runtime's exit that its run credential is no longer active, and whose session
// sends no run.exited: when the window closes the gateway ends the run itself as the
// starter said, never session_lost though the session sent nothing for longer than the
// gateway waits, and never credential_expired though the run credential's exp passed
// inside the window. A request after it is the 410 of that end.
func TestTheWindowOfARunEndingCloses(t *testing.T) {
	for _, c := range []struct {
		name, outcome, reason string
		state, endReason      string
		words                 string
	}{
		{"an outcome", "failed", "checks_failed", "failed", "checks_failed", "checks failed"},
		{"no outcome", "", "", "cancelled", "stopped", "no outcome given"},
	} {
		t.Run(c.name, func(t *testing.T) {
			issuers := realIssuers(t, true)
			none := runcredential.Duration(0)
			issuers[0].Leeway = &none
			cfg := gateway.Config{RunCredentials: issuers}
			gateway.SetExitWindow(&cfg, 3*time.Second)
			gateway.SetQuiet(&cfg, 500*time.Millisecond)
			st := newStarter()
			s := startStarting(t, cfg, st, time.Hour)
			exp := time.Now().Add(2 * time.Second)
			cred := mint(issuerKey(), "rk-0001", exp, nil)
			r := s.openSession(t, cred, server.LinkRunRequest{})
			st.ends(cred, c.outcome, c.reason)
			asked := time.Now()
			if status, b, _ := r.outcome(t, cred); status != http.StatusOK {
				t.Fatalf("the ask: %d %s", status, b)
			}
			// Past the quiet period and the run credential's exp, inside the window: the
			// run is still ending.
			time.Sleep(time.Until(exp.Add(200 * time.Millisecond)))
			if rec := s.record(r.a.RunID); rec[len(rec)-1].Type == event.RunExited {
				t.Fatalf("the run ended inside the window: %+v", rec[len(rec)-1])
			}
			eventually(t, "the window's end", func() bool {
				rec := s.record(r.a.RunID)
				return rec[len(rec)-1].Type == event.RunExited
			})
			if took := time.Since(asked); took < 3*time.Second {
				t.Errorf("the run ended %s after the answer, before its window closed", took)
			}
			line := "run " + r.a.RunID + ": its run credential is no longer valid; the run ends: " + c.state + ", " + c.words
			if got := s.reportsWith("the run ends"); !slices.Equal(got, []string{line}) {
				t.Errorf("reports %q; want %q", got, line)
			}
			status, b := r.post(t, credentialFor("rk-0001"), heartbeat(r.a.RunID))
			endedAs(t, "a batch after the window", status, b, c.state, c.endReason, c.words)
			d := s.close()
			recordEnds(t, s, r.a.RunID, c.state, c.endReason, float64(-1))
			if !d.RunClosed || d.ClosedReason != "stopped" || d.State != c.state || d.Reason != c.endReason {
				t.Errorf("delivery %+v", d)
			}
		})
	}
}

// TestTheStartersAnswerAtTheExitEndsTheRunKeysOtherRuns pins the answer at a runtime's
// exit that the run credential is no longer active against the run key's other runs:
// the gateway holds the run key with the starter's outcome and reason, a live session's
// run of it ends at its next request, which is the 410 of that outcome and reason, and
// a client's run of it ends at its next connection, refused 407; each record ends with
// that outcome and reason; a run request of the run key is refused, and so it is after
// a restart, whose refused run keys keep the outcome and the reason.
func TestTheStartersAnswerAtTheExitEndsTheRunKeysOtherRuns(t *testing.T) {
	o := origin(t)
	dir := t.TempDir()
	st := newStarter()
	s := startStarting(t, gateway.Config{Dir: dir}, st, 0)
	first := credentialFor("rk-0001")
	second := mint(issuerKey(), "rk-0001", time.Now().Add(2*time.Hour), nil)
	s.secrets = append(s.secrets, first, second)
	asking := s.openSession(t, first, server.LinkRunRequest{})
	other := s.openSession(t, second, server.LinkRunRequest{})
	reloaded := s.openSession(t, second, server.LinkRunRequest{})
	if status, _, err := get(s.clientWith(second), o.URL); err != nil || status != http.StatusOK {
		t.Fatalf("the client's run: %d %v", status, err)
	}
	var client string
	for _, id := range runsIn(t, s.dir) {
		if id != asking.a.RunID && id != other.a.RunID && id != reloaded.a.RunID {
			client = id
		}
	}
	st.ends(first, "failed", "checks_failed")
	if status, b, _ := asking.outcome(t, first); status != http.StatusOK || string(b) != `{"state":"failed","reason":"checks_failed"}` {
		t.Fatalf("the ask: %d %s", status, b)
	}
	status, b := other.post(t, second, heartbeat(other.a.RunID))
	endedAs(t, "a batch of another run of the run key", status, b, "failed", "checks_failed", "checks failed")
	status, b = reloaded.reload(t, second, reloaded.a.RunID)
	endedAs(t, "a reload of another run of the run key", status, b, "failed", "checks_failed", "checks failed")
	status, b = other.reload(t, second, other.a.RunID)
	endedAs(t, "a later reload", status, b, "failed", "checks_failed", "checks failed")
	if status, _, err := get(s.clientWith(second), o.URL); err != nil || status != http.StatusProxyAuthRequired {
		t.Errorf("a client's connection after the answer: %d %v", status, err)
	}
	// The run that asked is still ending: its own run.exited of the answer ends it.
	if status, b := asking.post(t, first, exitedWith(asking.a.RunID, map[string]any{"state": "failed", "exit_code": 2, "reason": "checks_failed"})); status != http.StatusAccepted {
		t.Errorf("the asking run's run.exited: %d %s", status, b)
	}
	if status, b := s.tryOpenWith(t, second, server.LinkRunRequest{}); status != http.StatusUnauthorized {
		t.Errorf("a run request of the run key: %d %s", status, b)
	}
	s.close()
	for _, id := range []string{other.a.RunID, reloaded.a.RunID} {
		recordEnds(t, s, id, "failed", "checks_failed", float64(-1))
	}
	recordEnds(t, s, client, "failed", "checks_failed", nil)
	recordEnds(t, s, asking.a.RunID, "failed", "checks_failed", float64(2))

	ended, err := runcredential.OpenEnded(dir)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, reason, ok := ended.Outcome(exampleIssuer, "rk-0001", time.Now()); !ok || outcome != "failed" || reason != "checks_failed" {
		t.Errorf("the refused run keys hold %q %q %v", outcome, reason, ok)
	}
	again := startStarting(t, gateway.Config{Dir: dir}, st, 0)
	again.secrets = append(again.secrets, first, second)
	if status, b := again.tryOpenWith(t, second, server.LinkRunRequest{}); status != http.StatusUnauthorized {
		t.Errorf("a run request after a restart: %d %s", status, b)
	}
}

// TestTheStartersOutcomeAtARequest pins the starter's answer that a run credential is
// no longer active with an outcome, at a request of a session's live run: the request
// and every later one get the 410 of that outcome and reason, the record ends with
// them, and the run key's other live runs end so at their next request, the hold's
// outcome kept though a later answer gives another.
func TestTheStartersOutcomeAtARequest(t *testing.T) {
	st := newStarter()
	s := startStarting(t, gateway.Config{}, st, 0)
	first := credentialFor("rk-0001")
	second := mint(issuerKey(), "rk-0001", time.Now().Add(2*time.Hour), nil)
	s.secrets = append(s.secrets, first, second)
	r := s.openSession(t, first, server.LinkRunRequest{})
	other := s.openSession(t, second, server.LinkRunRequest{})
	st.ends(first, "succeeded", "all_checks_passed")
	st.ends(second, "cancelled", "no_longer_needed")
	status, b := r.reload(t, first, r.a.RunID)
	endedAs(t, "the reload", status, b, "succeeded", "all_checks_passed", "all checks passed")
	status, b = r.post(t, first, heartbeat(r.a.RunID))
	endedAs(t, "a later batch", status, b, "succeeded", "all_checks_passed", "all checks passed")
	status, b = other.post(t, second, heartbeat(other.a.RunID))
	endedAs(t, "another run of the run key", status, b, "succeeded", "all_checks_passed", "all checks passed")
	if got := s.reportsWith("the run ends"); !slices.Equal(got, []string{"run " + r.a.RunID + ": its run credential is no longer valid; the run ends: succeeded, all checks passed"}) {
		t.Errorf("reports %q", got)
	}
	s.close()
	recordEnds(t, s, r.a.RunID, "succeeded", "all_checks_passed", float64(-1))
	recordEnds(t, s, other.a.RunID, "succeeded", "all_checks_passed", float64(-1))
}

// TestAClientsRunEndsAsItsStarterSaid pins a client's run whose starter answers that its
// run credential is no longer active with an outcome: the run ends with that outcome and
// reason, with no exit_code, and its next connection is refused 407.
func TestAClientsRunEndsAsItsStarterSaid(t *testing.T) {
	o := origin(t)
	host := strings.TrimPrefix(o.URL, "http://")
	st := newStarter()
	s := startStarting(t, gateway.Config{}, st, 100*time.Millisecond)
	cred := credentialFor("rk-0001")
	s.secrets = append(s.secrets, cred)
	code, _, text, conn := connectWith(t, s, loginHead(host, cred))
	if code != http.StatusOK {
		t.Fatalf("the first connection: %d %q", code, text)
	}
	defer conn.Close()
	ids := runsIn(t, s.dir)
	if len(ids) != 1 {
		t.Fatalf("runs %v", ids)
	}
	st.ends(cred, "failed", "checks_failed")
	eventually(t, "the run's end", func() bool {
		rec := s.record(ids[0])
		return rec[len(rec)-1].Type == event.RunExited
	})
	if code, _, text, _ := connectWith(t, s, loginHead(host, cred)); code != http.StatusProxyAuthRequired {
		t.Errorf("a later connection: %d %q", code, text)
	}
	if got := s.reportsWith("the run ends"); !slices.Equal(got, []string{"run " + ids[0] + ": its run credential is no longer valid; the run ends: failed, checks failed"}) {
		t.Errorf("reports %q", got)
	}
	s.close()
	recordEnds(t, s, ids[0], "failed", "checks_failed", nil)
}

// TestTheHoldOfAnOutcomeRunsToTheLatestExp pins the hold of a run key whose run ended
// with its starter's outcome: like the starter's end with none, it lasts to the latest
// exp of the run key's run credentials, one the run presented after the starter's answer
// at its exit among them, not to the exp held when the starter answered.
func TestTheHoldOfAnOutcomeRunsToTheLatestExp(t *testing.T) {
	var ahead atomic.Int64
	cfg := gateway.Config{}
	gateway.SetClock(&cfg, func() time.Time { return time.Now().Add(time.Duration(ahead.Load())) })
	gateway.SetExitWindow(&cfg, time.Second)
	st := newStarter()
	s := startStarting(t, cfg, st, 0)
	now := time.Now()
	first := mint(issuerKey(), "rk-0001", now.Add(time.Hour), nil)
	later := mint(issuerKey(), "rk-0001", now.Add(3*time.Hour), nil)
	probe := mint(issuerKey(), "rk-0001", now.Add(time.Hour+time.Minute), nil)
	s.secrets = append(s.secrets, first, later, probe)
	r := s.openSession(t, first, server.LinkRunRequest{})
	st.ends(first, "failed", "checks_failed")
	if status, b, _ := r.outcome(t, first); status != http.StatusOK {
		t.Fatalf("the ask: %d %s", status, b)
	}
	// Inside the window, a batch with a run credential of a later exp.
	if status, b := r.post(t, later, heartbeat(r.a.RunID)); status != http.StatusAccepted {
		t.Fatalf("a batch inside the window: %d %s", status, b)
	}
	eventually(t, "the window's end", func() bool {
		rec := s.record(r.a.RunID)
		return rec[len(rec)-1].Type == event.RunExited
	})
	// Past the first exp and its leeway, the later one holds the run key.
	ahead.Store(int64(time.Hour + 10*time.Minute))
	if status, b := s.tryOpenWith(t, probe, server.LinkRunRequest{}); status != http.StatusUnauthorized {
		t.Errorf("past the first exp: %d %s", status, b)
	}
	ahead.Store(int64(3*time.Hour + 10*time.Minute))
	if status, b := s.tryOpenWith(t, probe, server.LinkRunRequest{}); status != http.StatusOK {
		t.Errorf("past the latest exp: %d %s", status, b)
	}
}

// TestTheLinkRefusesARunExitedBeyondItsSchema pins the rules of a session's
// dev.qory.run.exited that its schema cannot say, with no outcome from the starter: every
// fixtures/invalid/link-batch-beyond-schema-* batch of the contract, sent as the run's,
// is refused, and the run ends failed, batch_refused.
func TestTheLinkRefusesARunExitedBeyondItsSchema(t *testing.T) {
	names, err := fs.Glob(contracts.FS, "fixtures/invalid/link-batch-beyond-schema-*.json")
	if err != nil || len(names) == 0 {
		t.Fatalf("fixtures %v %v", names, err)
	}
	h := start(t, gateway.Config{})
	for _, name := range names {
		b, err := fs.ReadFile(contracts.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		var evs []map[string]any
		if err := json.Unmarshal(b, &evs); err != nil {
			t.Fatal(err)
		}
		a := h.open(server.LinkRunRequest{})
		if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
			t.Fatalf("%s: the first batch: %+v", name, d)
		}
		for _, e := range evs {
			e["id"], e["subject"], e["source"] = event.NewID(), a.RunID, event.Source(a.RunID)
		}
		if d := h.post(evs...); d.Status != http.StatusBadRequest || d.Code != "invalid_request" || d.End != "batch_refused" {
			t.Errorf("%s: %+v", name, d)
		}
		rec := h.record(a.RunID)
		if last := rec[len(rec)-1]; last.Type != event.RunExited || last.Data["state"] != "failed" || last.Data["reason"] != "batch_refused" {
			t.Errorf("%s: the record ends %+v", name, last)
		}
	}
}

// TestTheRunExitedTheRuntimesExitDecides pins a session's dev.qory.run.exited with no
// outcome from the starter: succeeded with exit_code 0, failed with any other exit
// status or a signal, both with no reason, and cancelled with timeout are taken; any
// other is refused, and the run ends failed, batch_refused, its reason in the report.
func TestTheRunExitedTheRuntimesExitDecides(t *testing.T) {
	h := start(t, gateway.Config{})
	for _, c := range []struct {
		data map[string]any
		why  string // empty when the batch is taken
	}{
		{map[string]any{"state": "succeeded", "exit_code": 0}, ""},
		{map[string]any{"state": "failed", "exit_code": 1}, ""},
		{map[string]any{"state": "failed", "exit_code": -1, "signal": "SIGKILL"}, ""},
		{map[string]any{"state": "cancelled", "exit_code": -1, "signal": "SIGTERM", "reason": "timeout"}, ""},
		{map[string]any{"state": "failed", "exit_code": 0}, "a run.exited failed whose runtime exited 0"},
		{map[string]any{"state": "succeeded", "exit_code": 1}, "a run.exited succeeded whose runtime did not exit 0"},
		{map[string]any{"state": "succeeded", "exit_code": -1, "signal": "SIGTERM"}, "a run.exited succeeded whose runtime did not exit 0"},
		{map[string]any{"state": "succeeded", "exit_code": 0, "reason": "all_checks_passed"}, "a run.exited with a reason the gateway decides"},
		{map[string]any{"state": "failed", "exit_code": 1, "reason": "checks_failed"}, "a run.exited with a reason the gateway decides"},
		{map[string]any{"state": "cancelled", "exit_code": 0}, "a run.exited of a state the runtime's exit does not decide"},
	} {
		a := h.open(server.LinkRunRequest{})
		if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
			t.Fatalf("%v: the first batch: %+v", c.data, d)
		}
		d := h.post(exitedWith(a.RunID, c.data))
		if c.why == "" {
			if !d.Accepted() {
				t.Errorf("%v: %+v", c.data, d)
			}
			continue
		}
		if d.Status != http.StatusBadRequest || d.End != "batch_refused" {
			t.Errorf("%v: %+v", c.data, d)
		}
		line := "run " + a.RunID + ": the gateway refused a batch of its session's, " + c.why + "; the run ends: failed"
		if !h.reported(line) {
			t.Errorf("%v: not reported: %s", c.data, line)
		}
	}
}
