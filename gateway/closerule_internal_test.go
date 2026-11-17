package gateway

import "testing"

// TestCloseRuleRefusesAReservedReasonAfterAJoin pins closeRule for a reserved code the
// schema of a session's batch refuses before closeRule runs: stopped, failed, after a
// join, is a reason the gateway decides, and no starter's reason.
func TestCloseRuleRefusesAReservedReasonAfterAJoin(t *testing.T) {
	data := map[string]any{"state": "failed", "exit_code": float64(-1), "reason": "stopped"}
	if got, want := closeRule(data, true, ""), "a run.exited with a reason the gateway decides"; got != want {
		t.Errorf("closeRule(%v, joined) = %q; want %q", data, got, want)
	}
}
