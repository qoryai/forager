package gateway

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway/internal/stream"
)

// TestASessionStartedWhileAnotherJoinIsOpen pins the batch check of a
// dev.qory.session.started while another join of the run is open, with or without its
// dev.qory.session.started: the link refuses it. The join route refuses a join while
// another one is open, so only a run with two open joins, made here, reaches the check.
func TestASessionStartedWhileAnotherJoinIsOpen(t *testing.T) {
	runID := event.NewRunID()
	sessionStarted := func(n int) map[string]any {
		return map[string]any{
			"specversion": "1.0", "id": event.NewID(), "source": event.Source(runID), "type": event.SessionStarted, "subject": runID,
			"time": time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00"), "dataschema": event.DataSchema(event.SessionStarted),
			"data": map[string]any{"session": n, "runtime": "bare", "command": "true", "args": []string{}, "dir": "/work", "interactive": false},
		}
	}
	for _, firstStarted := range []bool{false, true} {
		lr := &linkRun{id: runID, seen: map[string]bool{}, joins: []*join{
			{session: 1, accepted: true, started: firstStarted},
			{session: 2, accepted: true},
		}}
		body, err := json.Marshal([]map[string]any{sessionStarted(2)})
		if err != nil {
			t.Fatal(err)
		}
		evs, err := stream.DecodeBatch(body)
		if err != nil {
			t.Fatal(err)
		}
		if why := lr.check(body, evs); why != "a session.started while another session runs" {
			t.Errorf("session 1 started %v: %q", firstStarted, why)
		}
	}
}
