package gateway

import "testing"

// TestCloseRuleRefusesAReservedReasonAfterAJoin pins closeRule for a reserved code the
// schema of a session's batch refuses before closeRule runs: stopped, failed, after a
// join and in a run with no join, is a reason the gateway decides, and no starter's
// reason.
func TestCloseRuleRefusesAReservedReasonAfterAJoin(t *testing.T) {
	data := map[string]any{"state": "failed", "exit_code": float64(-1), "reason": "stopped"}
	want := "a run.exited with a reason the gateway decides"
	if got := closeRule(data, true, ""); got != want {
		t.Errorf("closeRule(%v, joined) = %q; want %q", data, got, want)
	}
	if got := closeRule(data, false, ""); got != want {
		t.Errorf("closeRule(%v, no join) = %q; want %q", data, got, want)
	}
}
