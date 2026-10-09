package event_test

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
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

// TestReasonsAndOpenersAreTheContracts pins the constants of run.started's opened_by and
// credential to the enums of their schema, in the schema's order, and Forager's reasons
// of run.exited to its open code: each matches the reason's pattern and is named in its
// description among the reserved codes, beside the three old names Forager never writes.
func TestReasonsAndOpenersAreTheContracts(t *testing.T) {
	for _, c := range []struct {
		schema, member string
		want           []string
	}{
		{"events/run.started.schema.json", "opened_by", []string{event.OpenedBySession, event.OpenedByGateway}},
		{"events/run.started.schema.json", "credential", []string{event.CredentialStarter, event.CredentialNone}},
	} {
		doc, err := contracts.Document(c.schema)
		if err != nil {
			t.Fatal(err)
		}
		member := doc.(map[string]any)["properties"].(map[string]any)[c.member].(map[string]any)
		if got := fmt.Sprint(member["enum"]); got != fmt.Sprint(c.want) {
			t.Errorf("%s %s: the schema's enum is %s; the constants are %v", c.schema, c.member, got, c.want)
		}
	}
	doc, err := contracts.Document("events/run.exited.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	reason := doc.(map[string]any)["properties"].(map[string]any)["reason"].(map[string]any)
	if _, ok := reason["enum"]; ok {
		t.Error("run.exited's reason holds an enum; it is an open code")
	}
	pattern := regexp.MustCompile(reason["pattern"].(string))
	description := reason["description"].(string)
	for _, code := range []string{event.ReasonTimeout, event.ReasonRunClosed, event.ReasonGatewayLost,
		event.ReasonSessionLost, event.ReasonQuiet, event.ReasonCredentialExpired, event.ReasonStopped,
		event.ReasonBatchRefused, event.ReasonCredentialCheckUnreachable, event.ReasonCredentialCheckInvalid,
		"run_ended_at_issuer", "issuer_unreachable", "issuer_answer_invalid"} {
		if !pattern.MatchString(code) {
			t.Errorf("run.exited's reason pattern refuses %s", code)
		}
		if !regexp.MustCompile(`\b` + code + `\b`).MatchString(description) {
			t.Errorf("run.exited's reason description does not name %s", code)
		}
	}
	state := doc.(map[string]any)["properties"].(map[string]any)["state"].(map[string]any)
	if got, want := fmt.Sprint(state["enum"]), fmt.Sprint([]string{event.StateSucceeded, event.StateFailed, event.StateCancelled}); got != want {
		t.Errorf("run.exited's state enum is %s; the constants are %s", got, want)
	}
}

// TestTheReservedCodesAreTheContracts pins event.Reserved to the reserved codes the
// schema of run.exited names in its reason's description, and those link-batch.schema.json
// refuses beside timeout, and event.StarterReason to the reason's pattern less them: a
// starter's code is any other code.
func TestTheReservedCodesAreTheContracts(t *testing.T) {
	doc, err := contracts.Document("events/run.exited.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	reason := doc.(map[string]any)["properties"].(map[string]any)["reason"].(map[string]any)
	description := reason["description"].(string)
	_, rest, _ := strings.Cut(description, "Forager's own codes are reserved: ")
	listed, _, _ := strings.Cut(rest, ", which Forager never writes")
	var want []string
	for _, w := range regexp.MustCompile(`[a-z][a-z0-9_]+_[a-z0-9_]+|\btimeout\b|\bquiet\b|\bstopped\b`).FindAllString(listed, -1) {
		want = append(want, w)
	}
	if len(want) != 13 {
		t.Fatalf("the description names %d reserved codes: %v", len(want), want)
	}
	for _, code := range want {
		if !event.Reserved(code) || event.StarterReason(code) {
			t.Errorf("%s is reserved, and no starter's", code)
		}
	}
	pattern := regexp.MustCompile(reason["pattern"].(string))
	for _, code := range []string{"all_checks_passed", "checks_failed", "no_longer_needed", "a", "a" + strings.Repeat("b", 63),
		"", "A", "1a", "_a", "a-b", "a b", "a" + strings.Repeat("b", 64), "a\n", "\u00e9t\u00e9"} {
		if got, want := event.StarterReason(code), pattern.MatchString(code) && !slices.Contains(want, code); got != want {
			t.Errorf("StarterReason(%q) = %v, want %v", code, got, want)
		}
		if event.Reserved(code) {
			t.Errorf("%q is reserved", code)
		}
	}
	batch, err := contracts.Document("link-batch.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(batch)
	m := regexp.MustCompile(`\{"not":\{"enum":\[([^\]]*)\]\}\}`).FindSubmatch(b)
	if m == nil {
		t.Fatal("link-batch.schema.json refuses no list of reasons")
	}
	var refused []string
	json.Unmarshal([]byte("["+string(m[1])+"]"), &refused)
	refused = append(refused, event.ReasonTimeout)
	slices.Sort(refused)
	sorted := slices.Sorted(slices.Values(want))
	if !slices.Equal(refused, sorted) {
		t.Errorf("link-batch.schema.json refuses %v beside timeout; the reserved codes are %v", refused, sorted)
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

// TestNumberSharesTheSequenceWithMake pins that an event made unnumbered, or made
// elsewhere, takes the next sequence of the run when it is numbered, in the order of
// the calls, and keeps its own id and time.
func TestNumberSharesTheSequenceWithMake(t *testing.T) {
	e := event.NewEmitter(event.NewRunID(), nil)
	held := e.Unnumbered(event.RunEgress, map[string]any{"host": "example.com"})
	if held.Sequence != "" || held.ID == "" || held.Time == "" {
		t.Fatalf("unnumbered %+v", held)
	}
	first := e.Make(event.RunStarted, nil)
	id := held.ID
	e.Number(held)
	other := &event.Event{ID: "x", Type: "dev.qory.session.started"}
	e.Number(other)
	if first.Sequence != "0000000001" || held.Sequence != "0000000002" || other.Sequence != "0000000003" || held.ID != id {
		t.Errorf("sequences %s %s %s", first.Sequence, held.Sequence, other.Sequence)
	}
	if e.Sequence() != 3 {
		t.Errorf("sequence %d, want 3", e.Sequence())
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
