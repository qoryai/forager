package session_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/session"
)

// keyStop is the gateway's answer to a batch that stops the session at the model key
// limit.
var keyStop = linktest.Reply{Status: 200, Body: map[string]any{"stop": map[string]any{"reason": "model_key_limit"}}}

// hasLog reports whether the batch contains a dev.qory.run.log whose bytes, decoded,
// contain text.
func hasLog(evs []map[string]any, text string) bool {
	for _, e := range ofType(evs, event.RunLog) {
		b, _ := base64.StdEncoding.DecodeString(fmt.Sprint(data(e)["bytes"]))
		if strings.Contains(string(b), text) {
			return true
		}
	}
	return false
}

// TestAStopInABatchsAnswerStopsTheRuntime pins the gateway's stop, model_key_limit, in
// its answer to a batch behind a separate gateway: the session stops the runtime as at
// the time limit, writes session.exited paused with model_key_limit and the
// runtime's exit code, reports it, and the run stays open for its close, paused with
// model_key_limit and the last session's exit code.
func TestAStopInABatchsAnswerStopsTheRuntime(t *testing.T) {
	file := filepath.Join(t.TempDir(), "pid")
	sp, g, reports := remoteSpec(t, 0)
	sp.Args = []string{"-c", fmt.Sprintf(`trap 'exit 143' TERM; echo $$ > %q; echo working; while :; do sleep 0.05; done`, file)}
	sp.StopGrace = 5 * time.Second
	g.OnBatch(func(evs []map[string]any) linktest.Reply {
		if hasLog(evs, "working") {
			return keyStop
		}
		return linktest.Reply{Status: 200}
	})
	res, closed, err := runClosed(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "paused" || res.Reason != "model_key_limit" || res.ExitCode != 143 || res.TimedOut || res.Cancelled || res.RunClosed {
		t.Errorf("result %+v", res)
	}
	if state, reason, code := endedWith(t, res); state != "paused" || reason != "model_key_limit" || code != 143 {
		t.Errorf("session.exited %s %s %d", state, reason, code)
	}
	if closed.State != "paused" || closed.Reason != "model_key_limit" || closed.ExitCode != 143 {
		t.Errorf("the close %+v", closed)
	}
	if !slices.Contains(reports(), "the runtime was stopped and the run pauses: every model key of the run is at its provider's limit or at its Use up to percentage, or the gateway could not send a refused request again with the next key (a request over 8 MiB, or a key whose credential does not cover the path)") {
		t.Errorf("reports %q", reports())
	}
	if own, posted := exitedOf(t, res, g); posted == nil || own["reason"] != "model_key_limit" || posted["reason"] != "model_key_limit" {
		t.Errorf("run.exited %v, posted %v", own, posted)
	}
}

// TestAStopThatComesAsTheRuntimeExitsStillSetsTheReason pins the batch the session posts
// after a runtime that exited by itself: the answer to it, which comes after the exit,
// has stop, and session.exited is paused with model_key_limit and exit code 0.
func TestAStopThatComesAsTheRuntimeExitsStillSetsTheReason(t *testing.T) {
	sp, g, _ := remoteSpec(t, 0)
	sp.Args = []string{"-c", "echo last; exit 0"}
	g.OnBatch(func(evs []map[string]any) linktest.Reply {
		if hasLog(evs, "last") {
			time.Sleep(300 * time.Millisecond)
			return keyStop
		}
		return linktest.Reply{Status: 200}
	})
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "paused" || res.Reason != "model_key_limit" || res.ExitCode != 0 {
		t.Errorf("result %+v", res)
	}
	if state, reason, code := endedWith(t, res); state != "paused" || reason != "model_key_limit" || code != 0 {
		t.Errorf("session.exited %s %s %d", state, reason, code)
	}
}

// TestAStopWithNoRuntimeRunningChangesNothing pins a stop in the answer to a batch after
// the session's runtime exited and its session.exited was written: the next session is
// not stopped by it.
func TestAStopWithNoRuntimeRunningChangesNothing(t *testing.T) {
	sp, g, _ := remoteSpec(t, 0)
	var mu sync.Mutex
	stops := 0
	g.OnBatch(func(evs []map[string]any) linktest.Reply {
		if len(ofType(evs, event.SessionExited)) > 0 {
			mu.Lock()
			stops++
			mu.Unlock()
			return keyStop
		}
		return linktest.Reply{Status: 200}
	})
	r, err := session.Open(context.Background(), opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		res, err := r.Join(context.Background(), sp.SessionSpec)
		if err != nil {
			t.Fatal(err)
		}
		if res.State != "succeeded" || res.Reason != "" {
			t.Errorf("session %d: %+v", i+1, res)
		}
	}
	if _, err := r.Close(context.Background(), session.Outcome{State: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if stops != 2 {
		t.Errorf("%d stops answered; want 2", stops)
	}
}

// TestTheCloseTakesModelKeyLimitOnlyAfterSuchASession pins the outcomes with
// model_key_limit the close returns an error for: one that is not paused, one of a run whose last
// session ended otherwise, and one of a run with no join.
func TestTheCloseTakesModelKeyLimitOnlyAfterSuchASession(t *testing.T) {
	sp, _, _ := remoteSpec(t, 0)
	r, err := session.Open(context.Background(), opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	limit := session.Outcome{State: "paused", Reason: "model_key_limit", ExitCode: 0}
	if _, err := r.Close(context.Background(), limit); err == nil || !strings.Contains(err.Error(), "after a last session that ended with model_key_limit") {
		t.Errorf("a run with no join: %v", err)
	}
	if _, err := r.Join(context.Background(), sp.SessionSpec); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(context.Background(), limit); err == nil {
		t.Error("a run whose last session succeeded: closed with model_key_limit")
	}
	if _, err := r.Close(context.Background(), session.Outcome{State: "failed", Reason: "model_key_limit"}); err == nil {
		t.Error("closed failed with model_key_limit")
	}
	if _, err := r.Close(context.Background(), session.Outcome{State: "cancelled", Reason: "model_key_limit"}); err == nil {
		t.Error("closed cancelled with model_key_limit")
	}
	if _, err := r.Close(context.Background(), session.Outcome{State: "succeeded"}); err != nil {
		t.Fatal(err)
	}
}

// TestTheCloseTakesPausedOnlyWithModelKeyLimit pins the outcomes of a run whose last
// session ended paused with model_key_limit: the close returns an error for cancelled with
// model_key_limit, and for paused with no reason, with timeout or with a starter's code,
// and writes paused with model_key_limit.
func TestTheCloseTakesPausedOnlyWithModelKeyLimit(t *testing.T) {
	sp, g, _ := remoteSpec(t, 0)
	sp.Args = []string{"-c", "echo last; exit 0"}
	g.OnBatch(func(evs []map[string]any) linktest.Reply {
		if hasLog(evs, "last") {
			return keyStop
		}
		return linktest.Reply{Status: 200}
	})
	r, err := session.Open(context.Background(), opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Join(context.Background(), sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != event.StatePaused || res.Reason != event.ReasonModelKeyLimit {
		t.Fatalf("result %+v", res)
	}
	for _, o := range []session.Outcome{
		{State: event.StateCancelled, Reason: event.ReasonModelKeyLimit},
		{State: event.StatePaused},
		{State: event.StatePaused, Reason: event.ReasonTimeout, ExitCode: 124},
		{State: event.StatePaused, Reason: "checks_failed"},
	} {
		if _, err := r.Close(context.Background(), o); err == nil {
			t.Errorf("closed %+v", o)
		}
	}
	closed, err := r.Close(context.Background(), session.Outcome{State: event.StatePaused, Reason: event.ReasonModelKeyLimit, ExitCode: res.ExitCode})
	if err != nil {
		t.Fatal(err)
	}
	if closed.State != event.StatePaused || closed.Reason != event.ReasonModelKeyLimit {
		t.Errorf("the close %+v", closed)
	}
}

// stopWith is the gateway's answer to a batch that stops the session with reason.
func stopWith(reason string) linktest.Reply {
	return linktest.Reply{Status: 200, Body: map[string]any{"stop": map[string]any{"reason": reason}}}
}

// TestAStopForAKeyOutAfterA401EndsTheSession pins the two stops for a model key the
// provider returned 401 for: model_key_switch ends the session paused and
// model_key_unauthorized failed, whatever the runtime's exit status, 0 included; the
// session reports each, and the close takes each with its state, after that session.
func TestAStopForAKeyOutAfterA401EndsTheSession(t *testing.T) {
	for _, c := range []struct {
		reason, state, report string
		exit                  int
	}{
		{"model_key_switch", "paused", "the runtime was stopped and the run pauses: the model provider returned 401 (unauthorized) for the session's model key, and the run continues with another key of the run", 0},
		{"model_key_switch", "paused", "", 3},
		{"model_key_unauthorized", "failed", "Renew or replace the run's model keys: every model key of the run is out of use, the model provider returned 401 (unauthorized) for at least one of them, and no key renewal returned a value the provider accepts. The runtime was stopped and the run fails", 0},
		{"model_key_unauthorized", "failed", "", 3},
	} {
		t.Run(fmt.Sprintf("%s %d", c.reason, c.exit), func(t *testing.T) {
			sp, g, reports := remoteSpec(t, 0)
			sp.Args = []string{"-c", fmt.Sprintf("echo last; exit %d", c.exit)}
			g.OnBatch(func(evs []map[string]any) linktest.Reply {
				if hasLog(evs, "last") {
					return stopWith(c.reason)
				}
				return linktest.Reply{Status: 200}
			})
			res, closed, err := runClosed(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if res.State != c.state || res.Reason != c.reason || res.ExitCode != c.exit {
				t.Errorf("result %+v", res)
			}
			if state, reason, code := endedWith(t, res); state != c.state || reason != c.reason || code != c.exit {
				t.Errorf("session.exited %s %s %d", state, reason, code)
			}
			if closed.State != c.state || closed.Reason != c.reason || closed.ExitCode != c.exit {
				t.Errorf("the close %+v", closed)
			}
			if c.report != "" && !slices.Contains(reports(), c.report) {
				t.Errorf("reports %q", reports())
			}
			if own, posted := exitedOf(t, res, g); posted == nil || own["reason"] != c.reason || posted["reason"] != c.reason || own["state"] != c.state {
				t.Errorf("run.exited %v, posted %v", own, posted)
			}
		})
	}
}

// TestTheCloseTakesAKeyReasonOnlyAfterSuchASession pins model_key_switch and
// model_key_unauthorized at the close: each only with its state, paused and failed,
// after a last session that ended with that reason, never after one that ended with
// the other.
func TestTheCloseTakesAKeyReasonOnlyAfterSuchASession(t *testing.T) {
	for _, c := range []struct{ reason, state, other string }{
		{"model_key_switch", "paused", "model_key_unauthorized"},
		{"model_key_unauthorized", "failed", "model_key_switch"},
	} {
		t.Run(c.reason, func(t *testing.T) {
			sp, g, _ := remoteSpec(t, 0)
			sp.Args = []string{"-c", "echo last; exit 0"}
			g.OnBatch(func(evs []map[string]any) linktest.Reply {
				if hasLog(evs, "last") {
					return stopWith(c.reason)
				}
				return linktest.Reply{Status: 200}
			})
			r, err := session.Open(context.Background(), opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Close(context.Background(), session.Outcome{State: c.state, Reason: c.reason}); err == nil {
				t.Error("a run with no join closed with", c.reason)
			}
			res, err := r.Join(context.Background(), sp.SessionSpec)
			if err != nil {
				t.Fatal(err)
			}
			if res.Reason != c.reason {
				t.Fatalf("result %+v", res)
			}
			for _, o := range []session.Outcome{
				{State: "succeeded", Reason: c.reason},
				{State: "cancelled", Reason: c.reason},
				{State: map[string]string{"paused": "failed", "failed": "paused"}[c.state], Reason: c.reason},
				{State: map[string]string{"model_key_switch": "paused", "model_key_unauthorized": "failed"}[c.other], Reason: c.other},
				{State: "paused", Reason: "model_key_limit"},
			} {
				if _, err := r.Close(context.Background(), o); err == nil {
					t.Errorf("closed %+v", o)
				}
			}
			closed, err := r.Close(context.Background(), session.Outcome{State: c.state, Reason: c.reason, ExitCode: res.ExitCode})
			if err != nil {
				t.Fatal(err)
			}
			if closed.State != c.state || closed.Reason != c.reason {
				t.Errorf("the close %+v", closed)
			}
		})
	}
}

// TestTheStopIsReadBeforeTheExitOfASilentRuntime pins the batch before
// dev.qory.session.exited: a runtime that writes nothing and exits 0 after the
// gateway's proxy passed a refusal, here the file flag the runtime makes, still ends
// paused with model_key_switch. The session posts a heartbeat after the exit, whose
// answer has the stop, before the batch with dev.qory.session.exited, whose answer has
// no stop: the gateway takes the stop back once it accepts that event.
func TestTheStopIsReadBeforeTheExitOfASilentRuntime(t *testing.T) {
	flag := filepath.Join(t.TempDir(), "refused")
	sp, g, _ := remoteSpec(t, 0)
	sp.Args = []string{"-c", fmt.Sprintf("sleep 0.3; : > %q; exit 0", flag)}
	var mu sync.Mutex
	var order []string
	g.OnBatch(func(evs []map[string]any) linktest.Reply {
		mu.Lock()
		defer mu.Unlock()
		if slices.Contains(order, "exited") {
			return linktest.Reply{Status: 200}
		}
		if len(ofType(evs, event.SessionExited)) > 0 {
			order = append(order, "exited")
			return linktest.Reply{Status: 200}
		}
		if _, err := os.Stat(flag); err == nil {
			order = append(order, "stop")
			return stopWith(event.ReasonModelKeySwitch)
		}
		return linktest.Reply{Status: 200}
	})
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "paused" || res.Reason != "model_key_switch" || res.ExitCode != 0 {
		t.Errorf("result %+v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) < 2 || order[0] != "stop" || order[len(order)-1] != "exited" {
		t.Errorf("batches after the runtime's flag %q; want an answer with the stop, then the batch with session.exited", order)
	}
}
