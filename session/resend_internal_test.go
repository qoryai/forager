package session

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/qoryai/forager/event"
)

// TestASessionExitedOfAGatewaysEndIsNotOwed pins what of session.jsonl a resend owes
// the gateway: a session.exited whose reason is the code of a gateway's 410, like such
// a run.exited, is the session's line alone and never owed, even when delivered.log
// does not say stopped; a session.exited with another reason is owed.
func TestASessionExitedOfAGatewaysEndIsNotOwed(t *testing.T) {
	var lines []recordedLine
	for i, l := range []string{
		`{"type":"dev.qory.session.exited","sequence":"1","data":{"state":"failed","reason":"session_lost"}}`,
		`{"type":"dev.qory.run.exited","sequence":"2","data":{"state":"failed","reason":"session_lost"}}`,
		`{"type":"dev.qory.session.exited","sequence":"3","data":{"state":"succeeded"}}`,
	} {
		var line recordedLine
		if err := json.Unmarshal([]byte(l), &line); err != nil {
			t.Fatal(i, err)
		}
		lines = append(lines, line)
	}
	var owed []string
	for _, l := range owedOf(lines, map[string]bool{}, false) {
		owed = append(owed, l.Type+" "+l.Sequence)
	}
	if want := []string{event.SessionExited + " 3"}; !slices.Equal(owed, want) {
		t.Errorf("owed %q, want %q", owed, want)
	}
}
