package gateway_test

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"runtime"
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
	// slow, when set, is how long every ask but one at a runtime's exit takes.
	slow time.Duration
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
	held, asked, slow := st.held, st.heldAsked, st.slow
	st.mu.Unlock()
	if !now {
		time.Sleep(slow)
	}
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
// the answer stored. A later ask is decided as a reload is, though: after an answer
// that the run credential is still active, or none, a starter that has ended the run
// key since makes it the 410 as the starter said; after an answer that it is no longer
// active, the run's window takes it.
func TestTheAskAtTheExit(t *testing.T) {
	for _, c := range []struct {
		name     string
		answer   runcredential.Answer
		err      error
		body     string
		inactive bool
	}{
		{"active", runcredential.Answer{Active: true}, nil, `{}`, false},
		{"no outcome", runcredential.Answer{}, nil, `{}`, true},
		{"an outcome and a reason", runcredential.Answer{Outcome: "failed", Reason: "checks_failed"}, nil, `{"state":"failed","reason":"checks_failed"}`, true},
		{"an outcome with no reason", runcredential.Answer{Outcome: "succeeded"}, nil, `{"state":"succeeded"}`, true},
		{"no answer", runcredential.Answer{}, runcredential.ErrIssuerUnreachable, `{}`, false},
		{"no valid answer", runcredential.Answer{}, answerInvalid("the introspection endpoint answered status 500"), `{}`, false},
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
			// The starter answers active again: a later ask is the answer stored.
			st.set(cred, runcredential.Answer{Active: true}, nil)
			if status, again, _ := r.outcome(t, cred); status != http.StatusOK || string(again) != c.body {
				t.Errorf("a later ask: %d %q; want %q", status, again, c.body)
			}
			// The starter ends the run key: a later ask is the 410 as it said, unless the
			// window of the answer at the exit takes it.
			st.ends(cred, "cancelled", "no_longer_needed")
			status, again, _ := r.outcome(t, cred)
			if c.inactive {
				if status != http.StatusOK || string(again) != c.body {
					t.Errorf("a later ask inside the window: %d %q; want %q", status, again, c.body)
				}
			} else {
				endedAs(t, "a later ask after the starter's end", status, again, "cancelled", "no_longer_needed", "no longer needed")
			}
			if n := st.atExit(cred); n != 1 {
				t.Errorf("the starter was asked %d times at the exit after later asks", n)
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
		{name: "a reload, an outcome with no reason", outcome: "succeeded",
			steps: []step{{reload: true}},
			state: "succeeded"},
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
				line := "run " + r.a.RunID + ": its run credential is no longer valid; the run ends: " + c.state
				if c.words != "" {
					line += ", " + c.words
				}
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
// at its exit among them, not to the exp held when the starter answered, whether the
// window ends the run or the session's own run.exited does.
func TestTheHoldOfAnOutcomeRunsToTheLatestExp(t *testing.T) {
	for _, ownExit := range []bool{false, true} {
		name := "the window closes"
		if ownExit {
			name = "its own run.exited"
		}
		t.Run(name, func(t *testing.T) {
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
			if ownExit {
				if status, b := r.post(t, first, exitedWith(r.a.RunID, map[string]any{"state": "failed", "exit_code": 0, "reason": "checks_failed"})); status != http.StatusAccepted {
					t.Fatalf("the run.exited inside the window: %d %s", status, b)
				}
			}
			eventually(t, "the run's end", func() bool {
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
		})
	}
}

// TestLaterAsksAtTheExitAreDecidedAsReloads pins the asks at a runtime's exit after the
// one that asked the starter, outside a window: each is decided as a reload is, so a
// run key the starter ended since is the 410 as it said; and none renews the run, so a
// session that asks only that is lost after the gateway's quiet time.
func TestLaterAsksAtTheExitAreDecidedAsReloads(t *testing.T) {
	start := func(t *testing.T) (*starter, *service, *sessionRun, string) {
		t.Helper()
		cfg := gateway.Config{}
		gateway.SetQuiet(&cfg, 300*time.Millisecond)
		st := newStarter()
		s := startStarting(t, cfg, st, 0)
		cred := credentialFor("rk-0001")
		r := s.openSession(t, cred, server.LinkRunRequest{})
		if status, b, _ := r.outcome(t, cred); status != http.StatusOK || string(b) != `{}` {
			t.Fatalf("the ask: %d %s", status, b)
		}
		return st, s, r, cred
	}
	t.Run("the starter ends the run key", func(t *testing.T) {
		st, s, r, cred := start(t)
		st.ends(cred, "", "")
		status, b, _ := r.outcome(t, cred)
		endedAs(t, "the next ask", status, b, "cancelled", "stopped", "no outcome given")
		s.close()
		recordEnds(t, s, r.a.RunID, "cancelled", "stopped", float64(-1))
	})
	t.Run("asks renew nothing", func(t *testing.T) {
		_, _, r, cred := start(t)
		for i := range 20 {
			time.Sleep(100 * time.Millisecond)
			status, b, _ := r.outcome(t, cred)
			if status == http.StatusGone {
				gone(t, "an ask", status, b, "session_lost")
				return
			}
			if i == 19 {
				t.Errorf("20 asks 100 ms apart kept the run past a quiet time of 300 ms: %d %s", status, b)
			}
		}
	})
}

// TestTheWindowClosesBeforeItsTimer pins a run whose window has closed before its timer
// ends it: the gateway's quiet time or the run credential's exp that comes then ends the
// run as its starter said, never session_lost nor credential_expired.
func TestTheWindowClosesBeforeItsTimer(t *testing.T) {
	for _, c := range []struct {
		name  string
		quiet time.Duration
		exp   time.Duration
	}{
		{"the quiet time", 1500 * time.Millisecond, time.Hour},
		{"the run credential's exp", time.Hour, 3 * time.Second},
	} {
		t.Run(c.name, func(t *testing.T) {
			issuers := realIssuers(t, true)
			none := runcredential.Duration(0)
			issuers[0].Leeway = &none
			cfg := gateway.Config{RunCredentials: issuers}
			// The window closes well before the quiet time or the exp, which is whole
			// seconds; its timer comes 5 seconds after.
			gateway.SetExitWindow(&cfg, 500*time.Millisecond)
			gateway.SetWindowEndLate(&cfg, 5*time.Second)
			gateway.SetQuiet(&cfg, c.quiet)
			st := newStarter()
			s := startStarting(t, cfg, st, time.Hour)
			cred := mint(issuerKey(), "rk-0001", time.Now().Add(c.exp), nil)
			r := s.openSession(t, cred, server.LinkRunRequest{})
			st.ends(cred, "failed", "checks_failed")
			asked := time.Now()
			if status, b, _ := r.outcome(t, cred); status != http.StatusOK {
				t.Fatalf("the ask: %d %s", status, b)
			}
			eventually(t, "the run's end", func() bool {
				rec := s.record(r.a.RunID)
				return rec[len(rec)-1].Type == event.RunExited
			})
			if took := time.Since(asked); took > 4*time.Second {
				t.Errorf("the run ended %s after the answer, at its window's timer", took)
			}
			line := "run " + r.a.RunID + ": its run credential is no longer valid; the run ends: failed, checks failed"
			if got := s.reportsWith("the run ends"); !slices.Equal(got, []string{line}) {
				t.Errorf("reports %q; want %q", got, line)
			}
			s.close()
			recordEnds(t, s, r.a.RunID, "failed", "checks_failed", float64(-1))
		})
	}
}

// TestABatchWhileTheStarterIsAskedAtTheExit pins a batch of the session's while its ask
// at the runtime's exit is being answered, the starter answering the batch's check that
// the run credential is no longer active: the ask's answer decides, so the batch is
// taken in the run's window, and the session's run.exited of its runtime's exit ends
// the run, not the starter's end with no outcome.
func TestABatchWhileTheStarterIsAskedAtTheExit(t *testing.T) {
	st := newStarter()
	s := startStarting(t, gateway.Config{}, st, 0)
	cred := credentialFor("rk-0001")
	r := s.openSession(t, cred, server.LinkRunRequest{})
	st.ends(cred, "", "")
	asked, release := st.hold()
	answered := make(chan string, 1)
	go func() {
		_, b, _ := r.outcome(t, cred)
		answered <- string(b)
	}()
	<-asked
	posted := make(chan string, 1)
	go func() {
		status, b := r.post(t, cred, heartbeat(r.a.RunID))
		posted <- fmt.Sprintf("%d %s", status, b)
	}()
	// The batch reaches the gateway while the starter is asked at the exit.
	time.Sleep(300 * time.Millisecond)
	close(release)
	if b := <-answered; b != `{}` {
		t.Errorf("the ask: %s", b)
	}
	if got := <-posted; !strings.HasPrefix(got, "202 ") {
		t.Errorf("the batch while the starter is asked: %s", got)
	}
	if status, b := r.post(t, cred, exitedWith(r.a.RunID, map[string]any{"state": "succeeded", "exit_code": 0})); status != http.StatusAccepted {
		t.Errorf("the run.exited: %d %s", status, b)
	}
	s.close()
	recordEnds(t, s, r.a.RunID, "succeeded", "", float64(0))
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
		eventually(t, name+": the record's end", func() bool {
			rec := h.record(a.RunID)
			return rec[len(rec)-1].Type == event.RunExited
		})
		rec := h.record(a.RunID)
		if last := rec[len(rec)-1]; last.Data["state"] != "failed" || last.Data["reason"] != "batch_refused" {
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

// TestARunIsNotLostWhileItsStarterIsAsked pins the ask at a runtime's exit against the
// gateway's quiet period: while the starter is asked, longer than the session may send
// nothing, the run is not lost, and the session's run.exited after the answer is taken.
func TestARunIsNotLostWhileItsStarterIsAsked(t *testing.T) {
	cfg := gateway.Config{}
	gateway.SetQuiet(&cfg, 300*time.Millisecond)
	st := newStarter()
	s := startStarting(t, cfg, st, time.Hour)
	cred := credentialFor("rk-0001")
	r := s.openSession(t, cred, server.LinkRunRequest{})
	asked, release := st.hold()
	answered := make(chan []byte, 1)
	go func() {
		_, b, _ := r.outcome(t, cred)
		answered <- b
	}()
	<-asked
	time.Sleep(time.Second)
	close(release)
	if b := <-answered; string(b) != `{}` {
		t.Errorf("the ask: %s", b)
	}
	if status, b := r.post(t, cred, exitedWith(r.a.RunID, map[string]any{"state": "succeeded", "exit_code": 0})); status != http.StatusAccepted {
		t.Errorf("the run.exited after the answer: %d %s", status, b)
	}
	if got := s.reportsWith("sent nothing"); len(got) != 0 {
		t.Errorf("reports %q", got)
	}
}

// TestTheWordsOfARunsEnd pins the words a person reads of each ending, in a 410's
// message and a report line: those of Forager's codes, quiet with its quiet period, a
// starter's code with spaces for its underscores, and the state alone with no reason.
func TestTheWordsOfARunsEnd(t *testing.T) {
	for _, c := range []struct {
		state, reason string
		quiet         int
		want          string
	}{
		{"cancelled", "timeout", 0, "cancelled, time limit reached"},
		{"cancelled", "quiet", 1800, "cancelled, no activity for 30 minutes"},
		{"cancelled", "quiet", 3600, "cancelled, no activity for 1 hour"},
		{"cancelled", "quiet", 90, "cancelled, no activity for 90 seconds"},
		{"cancelled", "credential_expired", 0, "cancelled, permission to run expired"},
		{"cancelled", "stopped", 0, "cancelled, no outcome given"},
		{"failed", "session_lost", 0, "failed, stopped responding"},
		{"failed", "gateway_lost", 0, "failed, end not recorded"},
		{"failed", "batch_refused", 0, "failed, events refused"},
		{"failed", "credential_check_unreachable", 0, "failed, couldn't check whether the run may go on: no answer"},
		{"failed", "credential_check_invalid", 0, "failed, couldn't check whether the run may go on: unreadable answer"},
		{"succeeded", "all_checks_passed", 0, "succeeded, all checks passed"},
		{"failed", "", 0, "failed"},
	} {
		if got := gateway.EndWords(c.state, c.reason, c.quiet); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.state, c.reason, got, c.want)
		}
	}
}

// TestARunIsSparedAFailedCheckAfterItsExit pins a run credential that could not be
// checked, its endpoint unreachable or its answer not valid, against the run whose
// session asked at its runtime's exit: from the start of that ask, while it is made and
// for the window after its answer, its program has finished, and no request of the run
// ends it so; a batch, a reload and a batch with its run.exited go on as if it were
// checked, the run.exited decided against the answer stored. Before the ask, and for
// the run key's other runs, the check ends the run as ever; an answer that the run
// credential is no longer active ends it as the starter said. The starter's answers are
// not kept, so each request asks it.
func TestARunIsSparedAFailedCheckAfterItsExit(t *testing.T) {
	unreachable := runcredential.ErrIssuerUnreachable
	invalid := answerInvalid("the introspection endpoint answered status 500")
	exited := func(id string) map[string]any {
		return exitedWith(id, map[string]any{"state": "succeeded", "exit_code": 0})
	}
	for _, c := range []struct {
		name string
		ask  bool
		// answer is the starter's after the ask, err its error.
		answer runcredential.Answer
		err    error
		reload bool
		evs    func(id string) map[string]any
		// code is the 410's, empty for a request that goes on.
		code string
	}{
		{"its run.exited, no answer", true, runcredential.Answer{}, unreachable, false, exited, ""},
		{"its run.exited, no valid answer", true, runcredential.Answer{}, invalid, false, exited, ""},
		{"a heartbeat, no answer", true, runcredential.Answer{}, unreachable, false, heartbeat, ""},
		{"a heartbeat, no valid answer", true, runcredential.Answer{}, invalid, false, heartbeat, ""},
		{"a reload, no answer", true, runcredential.Answer{}, unreachable, true, nil, ""},
		{"a heartbeat before the ask", false, runcredential.Answer{}, unreachable, false, heartbeat, "credential_check_unreachable"},
		{"its run.exited before the ask", false, runcredential.Answer{}, invalid, false, exited, "credential_check_invalid"},
		{"its run.exited, the run credential no longer active", true, runcredential.Answer{}, nil, false, exited, "stopped"},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := newStarter()
			s := startStarting(t, gateway.Config{}, st, 0)
			cred := credentialFor("rk-0001")
			r := s.openSession(t, cred, server.LinkRunRequest{})
			if c.ask {
				if status, b, _ := r.outcome(t, cred); status != http.StatusOK || string(b) != `{}` {
					t.Fatalf("the ask: %d %s", status, b)
				}
			}
			st.set(cred, c.answer, c.err)
			var status int
			var b []byte
			if c.reload {
				status, b = r.reload(t, cred, r.a.RunID)
			} else {
				status, b = r.post(t, cred, c.evs(r.a.RunID))
			}
			if c.code == "" {
				if want := map[bool]int{false: http.StatusAccepted, true: http.StatusOK}[c.reload]; status != want {
					t.Fatalf("the request: %d %s", status, b)
				}
				if got := s.reportsWith("the run ends"); len(got) != 0 {
					t.Errorf("reports %q", got)
				}
				return
			}
			gone(t, "the request", status, b, c.code)
			s.close()
			rec := s.record(r.a.RunID)
			if last := rec[len(rec)-1]; last.Type != event.RunExited || last.Data["reason"] != c.code {
				t.Errorf("the record ends %+v", last)
			}
		})
	}
}

// TestTheSpareOfAFailedCheckIsBounded pins how long a run whose session asked at its
// runtime's exit is spared a run credential that could not be checked: while the ask is
// made, however long, and for the window after its answer, 30 seconds and here a
// second; after that the check ends the run as ever. The run key's other run is never
// spared.
func TestTheSpareOfAFailedCheckIsBounded(t *testing.T) {
	if gateway.ExitWindow != 30*time.Second {
		t.Errorf("the window is %s; want 30s", gateway.ExitWindow)
	}
	cfg := gateway.Config{}
	gateway.SetExitWindow(&cfg, time.Second)
	st := newStarter()
	s := startStarting(t, cfg, st, 0)
	cred := credentialFor("rk-0001")
	r := s.openSession(t, cred, server.LinkRunRequest{})
	other := s.openSession(t, cred, server.LinkRunRequest{})
	asked, release := st.hold()
	answered := make(chan string, 1)
	go func() {
		_, b, _ := r.outcome(t, cred)
		answered <- string(b)
	}()
	<-asked
	st.set(cred, runcredential.Answer{}, runcredential.ErrIssuerUnreachable)
	// While the ask is made: spared.
	if status, b := r.post(t, cred, heartbeat(r.a.RunID)); status != http.StatusAccepted {
		t.Errorf("a heartbeat while the ask is made: %d %s", status, b)
	}
	close(release)
	if b := <-answered; b != `{}` {
		t.Errorf("the ask: %s", b)
	}
	answeredAt := time.Now()
	// Inside the window after the answer: spared.
	if status, b := r.post(t, cred, heartbeat(r.a.RunID)); status != http.StatusAccepted {
		t.Errorf("a heartbeat inside the window: %d %s", status, b)
	}
	// The run key's other run: not spared.
	status, b := other.post(t, cred, heartbeat(other.a.RunID))
	gone(t, "the other run's heartbeat", status, b, "credential_check_unreachable")
	// Past the window: the check ends the run.
	time.Sleep(time.Until(answeredAt.Add(1200 * time.Millisecond)))
	status, b = r.post(t, cred, heartbeat(r.a.RunID))
	gone(t, "a heartbeat past the window", status, b, "credential_check_unreachable")
	s.close()
	recordEnds(t, s, r.a.RunID, "failed", "credential_check_unreachable", float64(-1))
}

// TestAnExpiredRunCredentialInsideTheWindow pins a request inside a run's window whose
// run credential's exp has passed: the run ends then as its starter answered at its
// exit, and the request gets that 410, never credential_expired.
func TestAnExpiredRunCredentialInsideTheWindow(t *testing.T) {
	issuers := realIssuers(t, true)
	none := runcredential.Duration(0)
	issuers[0].Leeway = &none
	st := newStarter()
	s := startStarting(t, gateway.Config{RunCredentials: issuers}, st, time.Hour)
	cred := mint(issuerKey(), "rk-0001", time.Now().Add(time.Hour), nil)
	expired := mint(issuerKey(), "rk-0001", time.Now().Add(-2*time.Second), map[string]any{"iat": time.Now().Add(-time.Minute).Unix()})
	s.secrets = append(s.secrets, cred, expired)
	r := s.openSession(t, cred, server.LinkRunRequest{})
	st.ends(cred, "failed", "checks_failed")
	if status, b, _ := r.outcome(t, cred); status != http.StatusOK {
		t.Fatalf("the ask: %d %s", status, b)
	}
	status, b := r.post(t, expired, heartbeat(r.a.RunID))
	endedAs(t, "a batch with an expired run credential", status, b, "failed", "checks_failed", "checks failed")
	if got := s.reportsWith("expired"); len(got) != 0 {
		t.Errorf("reports %q", got)
	}
	s.close()
	recordEnds(t, s, r.a.RunID, "failed", "checks_failed", float64(-1))
}

// TestARunIsNotLostWhileItsRunCredentialIsChecked pins a request of the session's whose
// run credential the starter is slow to answer, longer than the gateway's quiet period:
// the request is the session's while it waits, so the run is not lost, and it goes on.
func TestARunIsNotLostWhileItsRunCredentialIsChecked(t *testing.T) {
	cfg := gateway.Config{}
	gateway.SetQuiet(&cfg, 300*time.Millisecond)
	st := newStarter()
	s := startStarting(t, cfg, st, 0)
	cred := credentialFor("rk-0001")
	r := s.openSession(t, cred, server.LinkRunRequest{})
	st.mu.Lock()
	st.slow = time.Second
	st.mu.Unlock()
	if status, b := r.post(t, cred, heartbeat(r.a.RunID)); status != http.StatusAccepted {
		t.Errorf("a heartbeat checked for a second: %d %s", status, b)
	}
	if got := s.reportsWith("sent nothing"); len(got) != 0 {
		t.Errorf("reports %q", got)
	}
}

// asked is how many asks the starter was asked of the run credential, those at a
// runtime's exit apart.
func (st *starter) asked(credential string) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.asks[credential]
}

// TestAQuietClientsRunLearnsItsStartersEnd pins a client's run with no connection: the
// gateway asks the starter of its run credential once per heartbeat interval, and does
// with the answer what a connection's check does. Inactive with an outcome ends the run
// with that outcome and reason, inactive with none cancelled and stopped, each within
// about one interval, and holds the run key: a later connection is refused, 407. No
// answer, or none that is valid, ends it failed, credential_check_unreachable or
// credential_check_invalid, and holds nothing: the next connection opens a new run once
// the starter answers active. Each end has the operator's line, and a run.exited with no
// exit_code.
func TestAQuietClientsRunLearnsItsStartersEnd(t *testing.T) {
	o := origin(t)
	host := strings.TrimPrefix(o.URL, "http://")
	for _, c := range []struct {
		name          string
		answer        runcredential.Answer
		err           error
		state, reason string
		report        string
		held          bool
	}{
		{"an outcome", runcredential.Answer{Outcome: "succeeded", Reason: "all_checks_passed"}, nil, "succeeded", "all_checks_passed",
			"its run credential is no longer valid; the run ends: succeeded, all checks passed", true},
		{"no outcome", runcredential.Answer{}, nil, "cancelled", "stopped",
			"its run credential is no longer valid; the run ends: cancelled, no outcome given", true},
		{"no answer", runcredential.Answer{}, runcredential.ErrIssuerUnreachable, "failed", "credential_check_unreachable",
			"its run credential could not be checked: the introspection endpoint could not be reached; the run ends: failed", false},
		{"no valid answer", runcredential.Answer{}, answerInvalid("the introspection endpoint answered status 401"), "failed", "credential_check_invalid",
			"its run credential could not be checked: the introspection endpoint answered status 401; the run ends: failed", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := newStarter()
			s := startStarting(t, gateway.Config{Heartbeat: time.Second}, st, 0)
			cred := credentialFor("rk-0001")
			s.secrets = append(s.secrets, cred)
			code, _, text, conn := connectWith(t, s, loginHead(host, cred))
			if code != http.StatusOK {
				t.Fatalf("the first connection: %d %q", code, text)
			}
			conn.Close()
			ids := runsIn(t, s.dir)
			if len(ids) != 1 {
				t.Fatalf("runs %v", ids)
			}
			st.set(cred, c.answer, c.err)
			said := time.Now()
			eventually(t, "the run's end", func() bool {
				rec := s.record(ids[0])
				return rec[len(rec)-1].Type == event.RunExited
			})
			if took := time.Since(said); took > 2500*time.Millisecond {
				t.Errorf("the run ended %s after the starter's answer; want about one heartbeat interval", took)
			}
			if got := s.reportsWith("the run ends"); !slices.Equal(got, []string{"run " + ids[0] + ": " + c.report}) {
				t.Errorf("reports %q", got)
			}
			if c.held {
				if code, _, text, _ := connectWith(t, s, loginHead(host, cred)); code != http.StatusProxyAuthRequired {
					t.Errorf("a later connection: %d %q", code, text)
				}
			} else {
				noHold(t, s.dir)
				st.set(cred, runcredential.Answer{Active: true}, nil)
				code, _, text, conn := connectWith(t, s, loginHead(host, cred))
				if code != http.StatusOK {
					t.Errorf("once the starter answers active: %d %q", code, text)
				} else {
					conn.Close()
				}
				if got := runsIn(t, s.dir); len(got) != 2 {
					t.Errorf("runs %v", got)
				}
			}
			s.close()
			recordEnds(t, s, ids[0], c.state, c.reason, nil)
		})
	}
}

// TestABusyClientsRunIsNotAskedMore pins a client's run whose connections are checked in
// every heartbeat interval: the gateway asks the starter of its run credential for its
// connections alone, never once more for the interval.
func TestABusyClientsRunIsNotAskedMore(t *testing.T) {
	o := origin(t)
	host := strings.TrimPrefix(o.URL, "http://")
	st := newStarter()
	s := startStarting(t, gateway.Config{Heartbeat: time.Second}, st, 0)
	cred := credentialFor("rk-0001")
	s.secrets = append(s.secrets, cred)
	connections := 0
	for until := time.Now().Add(3500 * time.Millisecond); time.Now().Before(until); time.Sleep(200 * time.Millisecond) {
		code, _, text, conn := connectWith(t, s, loginHead(host, cred))
		if code != http.StatusOK {
			t.Fatalf("connection %d: %d %q", connections+1, code, text)
		}
		conn.Close()
		connections++
	}
	if got := runsIn(t, s.dir); len(got) != 1 {
		t.Fatalf("runs %v", got)
	}
	rec := s.record(runsIn(t, s.dir)[0])
	if !slices.Contains(types(rec), event.RunHeartbeat) {
		t.Errorf("no heartbeat in %v", types(rec))
	}
	if got := st.asked(cred); got != connections {
		t.Errorf("the starter was asked %d times for %d connections", got, connections)
	}
}

// TestTheAsksOfAQuietClientsRunEndWithIt pins the asks of a client's run with no
// connection: once the run ends, quiet here, between two heartbeats, the starter is
// asked of its run credential no more, and the run leaves nothing running that asks.
func TestTheAsksOfAQuietClientsRunEndWithIt(t *testing.T) {
	o := origin(t)
	host := strings.TrimPrefix(o.URL, "http://")
	st := newStarter()
	s := startStarting(t, gateway.Config{Heartbeat: time.Second, Runs: gateway.RunsConfig{Quiet: 1500 * time.Millisecond}}, st, 0)
	cred := credentialFor("rk-0001")
	s.secrets = append(s.secrets, cred)
	code, _, text, conn := connectWith(t, s, loginHead(host, cred))
	if code != http.StatusOK {
		t.Fatalf("the first connection: %d %q", code, text)
	}
	conn.Close()
	ids := runsIn(t, s.dir)
	if len(ids) != 1 {
		t.Fatalf("runs %v", ids)
	}
	eventually(t, "the quiet end", func() bool {
		rec := s.record(ids[0])
		return rec[len(rec)-1].Type == event.RunExited
	})
	before := st.asked(cred)
	if before != 2 {
		t.Errorf("the starter was asked %d times before the quiet end; want once at the open and once at the first heartbeat", before)
	}
	eventually(t, "the run's keeping to stop", func() bool { return !keeping() })
	time.Sleep(2500 * time.Millisecond)
	if got := st.asked(cred); got != before {
		t.Errorf("the starter was asked %d times after the run ended", got-before)
	}
	if keeping() {
		t.Error("a run's keeping goes on after its end")
	}
	s.close()
	recordEnds(t, s, ids[0], "cancelled", "quiet", nil)
}

// keeping reports whether a goroutine keeps a client's run.
func keeping() bool {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Contains(string(buf[:n]), "(*linkRun).keep(")
		}
		buf = make([]byte, 2*len(buf))
	}
}
