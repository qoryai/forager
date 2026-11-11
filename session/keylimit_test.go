package session_test

import (
	"context"
	"encoding/base64"
	"fmt"
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
	if !slices.ContainsFunc(reports(), func(l string) bool { return strings.Contains(l, "model provider's limit") }) {
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
