package server

import (
	"strings"
	"testing"
)

// TestAnOutcomeSendsAPhraseForASecret pins an outcome's body and error: a reason that
// contains qak_ or qrk_ in any case is sent as the name's phrase, a state outside the
// three prints the value's phrase, and a clean reason is sent as it is.
func TestAnOutcomeSendsAPhraseForASecret(t *testing.T) {
	for reason, want := range map[string]string{"qak_x": "(a name that contains an access key secret)", "a.QRK_y": "(a name that contains a run key)", "stopped": "stopped"} {
		b, err := Outcome{State: "failed", Reason: reason, Time: "2026-10-11T12:00:00Z"}.body()
		if err != nil || !strings.Contains(string(b), `"reason":"`+want+`"`) {
			t.Errorf("%s: %s, %v", reason, b, err)
		}
	}
	_, err := Outcome{State: "qak_done"}.body()
	if want := "the outcome: the state (a value that contains an access key secret) is not succeeded, failed or cancelled"; err == nil || err.Error() != want {
		t.Errorf("a state: %v, want %s", err, want)
	}
}
