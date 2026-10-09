package event_test

import (
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
)

// TestEventsValidateAgainstTheContract pins that what the emitter makes is what the
// envelope schema accepts, for a run type and for a session type.
func TestEventsValidateAgainstTheContract(t *testing.T) {
	schema, err := contracts.Compile("event.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	e := event.NewEmitter(event.NewRunID(), func() time.Time { return time.Unix(1_800_000_000, 5_000_000) })
	for _, ev := range []*event.Event{
		e.Make(event.RunHeartbeat, map[string]any{"elapsed_seconds": 30, "interval_seconds": 30}),
		e.Make("dev.qory.session.ended", map[string]any{"session_id": "s1", "reason": "other"}),
	} {
		b, err := ev.JSON()
		if err != nil {
			t.Fatal(err)
		}
		doc, err := contracts.Decode("event.json", b)
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("%s: %v\n%s", ev.Type, err, b)
		}
	}
	if e.Sequence() != 2 {
		t.Errorf("sequence %d, want 2", e.Sequence())
	}
}

// TestSequenceIsPaddedAndContiguous pins the sequence format the receiver sorts on.
func TestSequenceIsPaddedAndContiguous(t *testing.T) {
	e := event.NewEmitter(event.NewRunID(), nil)
	for i, want := range []string{"0000000001", "0000000002", "0000000003"} {
		if got := e.Make(event.RunHeartbeat, nil).Sequence; got != want {
			t.Errorf("event %d: sequence %s, want %s", i, got, want)
		}
	}
}

// TestIDsHaveTheirVersions pins that a run id is a version 7 UUID and an event id a
// version 4, and that both sort and compare as strings.
func TestIDsHaveTheirVersions(t *testing.T) {
	v7 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	v4 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	first := event.NewRunID()
	time.Sleep(2 * time.Millisecond)
	second := event.NewRunID()
	if !v7.MatchString(first) || !v7.MatchString(second) {
		t.Errorf("run ids %s %s are not version 7", first, second)
	}
	if first >= second {
		t.Errorf("run ids do not sort by time: %s then %s", first, second)
	}
	if id := event.NewID(); !v4.MatchString(id) {
		t.Errorf("event id %s is not version 4", id)
	}
}

// TestTimeIsUTCMilliseconds pins the time format the contract states.
func TestTimeIsUTCMilliseconds(t *testing.T) {
	loc := time.FixedZone("east", 3600)
	e := event.NewEmitter(event.NewRunID(), func() time.Time { return time.Date(2026, 9, 16, 13, 0, 0, 7_000_000, loc) })
	ev := e.Make(event.RunHeartbeat, nil)
	if ev.Time != "2026-09-16T12:00:00.007Z" {
		t.Errorf("time %s", ev.Time)
	}
	var m map[string]any
	b, _ := ev.JSON()
	if err := json.Unmarshal(b, &m); err != nil || m["data"] != nil {
		t.Errorf("nil data encodes as %v", m["data"])
	}
}
