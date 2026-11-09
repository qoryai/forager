package gateway_test

import (
	"encoding/json"
	"io/fs"
	"maps"
	"net/http"
	"testing"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/server"
)

// exitedWith is the session's dev.qory.run.exited of the run with the data given, and
// its duration.
func exitedWith(runID string, data map[string]any) map[string]any {
	d := map[string]any{"duration_ms": 5}
	for k, v := range data {
		d[k] = v
	}
	return ev(runID, event.RunExited, d)
}

// TestTheLinkRefusesARunExitedBeyondItsSchema pins the rules of a session's
// dev.qory.run.exited that its schema cannot say: every
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

// TestTheRunExitedIsTheClosesOutcome pins a session's dev.qory.run.exited, the
// close's: any state, with no reason, timeout or interrupted, no_session only in a run
// with no join, and image_missing, image_user_root, image_access_denied,
// image_rate_limited, image_registry_unreachable, workflow_not_in_harness,
// read_needs_wall, read_needs_setup_outside, read_needs_no_nested_docker and
// read_needs_setup_removed only failed with exit_code -1 in a run with no join, are
// taken; a reason the gateway decides, or a starter's, is refused, and the run ends
// failed, batch_refused, its reason in the report.
func TestTheRunExitedIsTheClosesOutcome(t *testing.T) {
	h := start(t, gateway.Config{})
	for _, c := range []struct {
		data map[string]any
		join bool
		why  string // empty when the batch is taken
	}{
		{map[string]any{"state": "succeeded", "exit_code": 0}, false, ""},
		{map[string]any{"state": "failed", "exit_code": 0}, false, ""},
		{map[string]any{"state": "succeeded", "exit_code": 1}, false, ""},
		{map[string]any{"state": "cancelled", "exit_code": 0}, false, ""},
		{map[string]any{"state": "failed", "exit_code": -1, "signal": "SIGKILL"}, false, ""},
		{map[string]any{"state": "cancelled", "exit_code": 124, "reason": "timeout"}, false, ""},
		{map[string]any{"state": "cancelled", "exit_code": -1, "reason": "interrupted"}, false, ""},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "no_session"}, false, ""},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "no_session"}, true, "a run.exited no_session of a run with a join"},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "image_missing"}, false, ""},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "image_missing"}, true, "a run.exited image_missing of a run with a join"},
		{map[string]any{"state": "failed", "exit_code": 0, "reason": "image_missing"}, false, "a run.exited image_missing that is not failed with exit_code -1"},
		{map[string]any{"state": "succeeded", "exit_code": -1, "reason": "image_missing"}, false, "a run.exited image_missing that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "reason": "image_missing"}, false, "a run.exited image_missing that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "image_user_root"}, false, ""},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "image_user_root"}, true, "a run.exited image_user_root of a run with a join"},
		{map[string]any{"state": "failed", "exit_code": 0, "reason": "image_user_root"}, false, "a run.exited image_user_root that is not failed with exit_code -1"},
		{map[string]any{"state": "cancelled", "exit_code": -1, "reason": "image_user_root"}, false, "a run.exited image_user_root that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "image_access_denied"}, false, ""},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "image_access_denied"}, true, "a run.exited image_access_denied of a run with a join"},
		{map[string]any{"state": "failed", "exit_code": 0, "reason": "image_access_denied"}, false, "a run.exited image_access_denied that is not failed with exit_code -1"},
		{map[string]any{"state": "cancelled", "exit_code": -1, "reason": "image_access_denied"}, false, "a run.exited image_access_denied that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "image_rate_limited"}, false, ""},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "image_rate_limited"}, true, "a run.exited image_rate_limited of a run with a join"},
		{map[string]any{"state": "failed", "exit_code": 0, "reason": "image_rate_limited"}, false, "a run.exited image_rate_limited that is not failed with exit_code -1"},
		{map[string]any{"state": "cancelled", "exit_code": -1, "reason": "image_rate_limited"}, false, "a run.exited image_rate_limited that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "image_registry_unreachable"}, false, ""},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "image_registry_unreachable"}, true, "a run.exited image_registry_unreachable of a run with a join"},
		{map[string]any{"state": "failed", "exit_code": 0, "reason": "image_registry_unreachable"}, false, "a run.exited image_registry_unreachable that is not failed with exit_code -1"},
		{map[string]any{"state": "cancelled", "exit_code": -1, "reason": "image_registry_unreachable"}, false, "a run.exited image_registry_unreachable that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "workflow_not_in_harness"}, false, ""},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "workflow_not_in_harness"}, true, "a run.exited workflow_not_in_harness of a run with a join"},
		{map[string]any{"state": "failed", "exit_code": 1, "reason": "workflow_not_in_harness"}, false, "a run.exited workflow_not_in_harness that is not failed with exit_code -1"},
		{map[string]any{"state": "succeeded", "exit_code": -1, "reason": "workflow_not_in_harness"}, false, "a run.exited workflow_not_in_harness that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "reason": "workflow_not_in_harness"}, false, "a run.exited workflow_not_in_harness that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "read_needs_wall"}, false, ""},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "read_needs_wall"}, true, "a run.exited read_needs_wall of a run with a join"},
		{map[string]any{"state": "failed", "exit_code": 0, "reason": "read_needs_wall"}, false, "a run.exited read_needs_wall that is not failed with exit_code -1"},
		{map[string]any{"state": "cancelled", "exit_code": -1, "reason": "read_needs_wall"}, false, "a run.exited read_needs_wall that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "reason": "read_needs_wall"}, false, "a run.exited read_needs_wall that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "read_needs_setup_outside"}, false, ""},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "read_needs_setup_outside"}, true, "a run.exited read_needs_setup_outside of a run with a join"},
		{map[string]any{"state": "failed", "exit_code": 0, "reason": "read_needs_setup_outside"}, false, "a run.exited read_needs_setup_outside that is not failed with exit_code -1"},
		{map[string]any{"state": "cancelled", "exit_code": -1, "reason": "read_needs_setup_outside"}, false, "a run.exited read_needs_setup_outside that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "reason": "read_needs_setup_outside"}, false, "a run.exited read_needs_setup_outside that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "read_needs_no_nested_docker"}, false, ""},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "read_needs_no_nested_docker"}, true, "a run.exited read_needs_no_nested_docker of a run with a join"},
		{map[string]any{"state": "failed", "exit_code": 0, "reason": "read_needs_no_nested_docker"}, false, "a run.exited read_needs_no_nested_docker that is not failed with exit_code -1"},
		{map[string]any{"state": "cancelled", "exit_code": -1, "reason": "read_needs_no_nested_docker"}, false, "a run.exited read_needs_no_nested_docker that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "reason": "read_needs_no_nested_docker"}, false, "a run.exited read_needs_no_nested_docker that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "read_needs_setup_removed"}, false, ""},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "read_needs_setup_removed"}, true, "a run.exited read_needs_setup_removed of a run with a join"},
		{map[string]any{"state": "failed", "exit_code": 0, "reason": "read_needs_setup_removed"}, false, "a run.exited read_needs_setup_removed that is not failed with exit_code -1"},
		{map[string]any{"state": "cancelled", "exit_code": -1, "reason": "read_needs_setup_removed"}, false, "a run.exited read_needs_setup_removed that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "reason": "read_needs_setup_removed"}, false, "a run.exited read_needs_setup_removed that is not failed with exit_code -1"},
		{map[string]any{"state": "failed", "exit_code": 130, "reason": "interrupted"}, false, "one link-batch.schema.json refuses"},
		{map[string]any{"state": "cancelled", "exit_code": -1, "reason": "timeout"}, false, "one link-batch.schema.json refuses"},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "session_lost"}, false, "one link-batch.schema.json refuses"},
		{map[string]any{"state": "succeeded", "exit_code": 0, "reason": "all_checks_passed"}, false, "a run.exited with a reason the gateway decides"},
		{map[string]any{"state": "failed", "exit_code": 1, "reason": "checks_failed"}, false, "a run.exited with a reason the gateway decides"},
	} {
		a := h.open(server.LinkRunRequest{})
		if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
			t.Fatalf("%v: the first batch: %+v", c.data, d)
		}
		if c.join {
			n := h.joined(a.RunID)
			if d := h.post(sessionStarted(a.RunID, n), sessionExited(a.RunID, n)); !d.Accepted() {
				t.Fatalf("%v: the session: %+v", c.data, d)
			}
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
		line := "run " + a.RunID + ": the gateway refused a batch from the run's session, " + c.why + "; the run ends: failed"
		if !h.reported(line) {
			t.Errorf("%v: not reported: %s", c.data, line)
		}
	}
}

// TestTheSessionExitedTheRuntimesExitDecides pins a session's
// dev.qory.session.exited: succeeded with exit_code 0, failed with any other exit
// status or a signal, both with no reason, cancelled with timeout or with interrupted,
// whatever the exit status or the signal, a refused join's, failed with -1 and a code
// the session decides, and a failure at the join after the session.started, failed
// with -1 and no reason, or the wall's refusal's code, are taken; any other is refused,
// and the run ends failed, batch_refused.
func TestTheSessionExitedTheRuntimesExitDecides(t *testing.T) {
	h := start(t, gateway.Config{})
	for _, c := range []struct {
		data map[string]any
		ok   bool
	}{
		{map[string]any{"state": "succeeded", "exit_code": 0}, true},
		{map[string]any{"state": "failed", "exit_code": 1}, true},
		{map[string]any{"state": "failed", "exit_code": -1, "signal": "SIGKILL"}, true},
		{map[string]any{"state": "cancelled", "exit_code": -1, "signal": "SIGTERM", "reason": "timeout"}, true},
		{map[string]any{"state": "cancelled", "exit_code": 130, "reason": "interrupted"}, true},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "mount_mode_conflict"}, true},
		// A failure at the join before the runtime starts, with no code and with the
		// wall's refusal's.
		{map[string]any{"state": "failed", "exit_code": -1}, true},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "image_user_root"}, true},
		{map[string]any{"state": "succeeded", "exit_code": -1}, false},
		{map[string]any{"state": "failed", "exit_code": 0}, false},
		{map[string]any{"state": "succeeded", "exit_code": 1}, false},
		{map[string]any{"state": "cancelled", "exit_code": 0}, false},
		{map[string]any{"state": "failed", "exit_code": 130, "reason": "interrupted"}, false},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "session_lost"}, false},
		{map[string]any{"state": "succeeded", "exit_code": -1, "reason": "mount_mode_conflict"}, false},
		// The enclosure's measure, on a runtime's exit alone, each a whole number of 0
		// or more.
		{map[string]any{"state": "succeeded", "exit_code": 0, "peak_memory_bytes": 4096, "cpu_time_ms": 12}, true},
		{map[string]any{"state": "failed", "exit_code": 137, "cpu_time_ms": 0}, true},
		{map[string]any{"state": "failed", "exit_code": -1, "peak_memory_bytes": 4096}, false},
		{map[string]any{"state": "failed", "exit_code": -1, "reason": "image_user_root", "cpu_time_ms": 1}, false},
		{map[string]any{"state": "succeeded", "exit_code": 0, "peak_memory_bytes": -1}, false},
		{map[string]any{"state": "succeeded", "exit_code": 0, "cpu_time_ms": 1.5}, false},
	} {
		a := h.open(server.LinkRunRequest{})
		n := h.joined(a.RunID)
		if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied), sessionStarted(a.RunID, n)); !d.Accepted() {
			t.Fatalf("%v: the first batch: %+v", c.data, d)
		}
		data := map[string]any{"session": n, "duration_ms": 5}
		maps.Copy(data, c.data)
		d := h.post(ev(a.RunID, event.SessionExited, data))
		if c.ok != d.Accepted() || (!c.ok && (d.Status != http.StatusBadRequest || d.End != "batch_refused")) {
			t.Errorf("%v: %+v", c.data, d)
		}
	}
}

// TestTheSessionExitedKeepsTheMeasure pins that the gateway records a session's
// peak_memory_bytes and cpu_time_ms as the session sent them.
func TestTheSessionExitedKeepsTheMeasure(t *testing.T) {
	h := start(t, gateway.Config{})
	a := h.open(server.LinkRunRequest{})
	n := h.joined(a.RunID)
	if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied), sessionStarted(a.RunID, n)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	data := map[string]any{"session": n, "state": "succeeded", "exit_code": 0, "duration_ms": 5, "peak_memory_bytes": 8589934592, "cpu_time_ms": 61250}
	if d := h.post(ev(a.RunID, event.SessionExited, data)); !d.Accepted() {
		t.Fatalf("session.exited: %+v", d)
	}
	for _, e := range h.record(a.RunID) {
		if e.Type == event.SessionExited {
			if e.Data["peak_memory_bytes"] != float64(8589934592) || e.Data["cpu_time_ms"] != float64(61250) {
				t.Errorf("the record's session.exited: %v", e.Data)
			}
			return
		}
	}
	t.Error("no session.exited in the record")
}

// TestTheWordsOfARunsEnd pins the words a person reads of each ending, in a 410's
// message and a report line: those of Forager's codes, another code with spaces for its
// underscores, and the state alone with no reason.
func TestTheWordsOfARunsEnd(t *testing.T) {
	for _, c := range []struct {
		state, reason string
		want          string
	}{
		{"cancelled", "timeout", "cancelled, time limit reached"},
		{"failed", "session_lost", "failed, stopped responding"},
		{"failed", "gateway_lost", "failed, end not recorded"},
		{"failed", "batch_refused", "failed, events refused"},
		{"succeeded", "all_checks_passed", "succeeded, all checks passed"},
		{"failed", "", "failed"},
	} {
		if got := gateway.EndWords(c.state, c.reason); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.state, c.reason, got, c.want)
		}
	}
}
