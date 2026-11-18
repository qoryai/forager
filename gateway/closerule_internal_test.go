package gateway

import "testing"

// TestCloseRuleTakesEachKeyStopWithItsState pins closeRule's state check of the three
// reasons of a stop in a batch's answer, which link-batch.schema.json also makes: each
// reason with its state alone, after a last session with the same reason.
func TestCloseRuleTakesEachKeyStopWithItsState(t *testing.T) {
	for _, c := range []struct{ reason, state, want string }{
		{"model_key_limit", "paused", ""},
		{"model_key_switch", "paused", ""},
		{"model_key_unauthorized", "failed", ""},
		{"model_key_limit", "failed", "a run.exited model_key_limit that is not paused"},
		{"model_key_switch", "failed", "a run.exited model_key_switch that is not paused"},
		{"model_key_unauthorized", "paused", "a run.exited model_key_unauthorized that is not failed"},
	} {
		data := map[string]any{"state": c.state, "exit_code": float64(1), "reason": c.reason}
		if got := closeRule(data, true, c.reason); got != c.want {
			t.Errorf("%s %s: %q; want %q", c.state, c.reason, got, c.want)
		}
	}
}
