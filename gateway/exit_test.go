package gateway_test

import (
	"encoding/json"
	"io/fs"
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

// TestTheRunExitedTheRuntimesExitDecides pins a session's dev.qory.run.exited:
// succeeded with exit_code 0, failed with any other exit
// status or a signal, both with no reason, and cancelled with timeout or with
// interrupted, whatever the exit status or the signal, are taken; any other is refused,
// and the run ends failed, batch_refused, its reason in the report.
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
		{map[string]any{"state": "cancelled", "exit_code": 0, "reason": "interrupted"}, ""},
		{map[string]any{"state": "cancelled", "exit_code": 130, "reason": "interrupted"}, ""},
		{map[string]any{"state": "cancelled", "exit_code": -1, "signal": "SIGKILL", "reason": "interrupted"}, ""},
		{map[string]any{"state": "failed", "exit_code": 130, "reason": "interrupted"}, "one link-batch.schema.json refuses"},
		{map[string]any{"state": "succeeded", "exit_code": 0, "reason": "interrupted"}, "one link-batch.schema.json refuses"},
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
		line := "run " + a.RunID + ": the gateway refused a batch from the run's session, " + c.why + "; the run ends: failed"
		if !h.reported(line) {
			t.Errorf("%v: not reported: %s", c.data, line)
		}
	}
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
