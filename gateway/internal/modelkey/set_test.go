package modelkey_test

import (
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway/internal/modelkey"
)

// twoGroups is a set of two key groups on the clock now, whose keys interleave in the
// run configuration's order: claude and claude-2, and codex and codex-2, in the order
// claude, codex, claude-2, codex-2.
func twoGroups(now func() time.Time) (*modelkey.Set, *modelkey.Group, *modelkey.Group) {
	claude := modelkey.New([]modelkey.Key{{Name: "claude", PauseFor: time.Hour}, {Name: "claude-2", PauseFor: time.Hour}}, "claude", now)
	codex := modelkey.New([]modelkey.Key{{Name: "codex", PauseFor: time.Hour}, {Name: "codex-2", PauseFor: time.Hour}}, "", now)
	codex.SetFormat(modelkey.FormatOpenAIResponses)
	return modelkey.NewSet([]*modelkey.Group{claude, codex}, []string{"claude", "codex", "claude-2", "codex-2"}), claude, codex
}

// TestTheGroupsOfASetKeepTheirStateApart pins two key groups of one run: a key belongs
// to its group alone; a limit refusal in one group switches that group's active key
// and leaves the other's; a pass and a stop of one group leave the other running; and
// a group with every key in cooldown stops with model_key_limit while the other group
// has a usable key.
func TestTheGroupsOfASetKeepTheirStateApart(t *testing.T) {
	at := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	s, claude, codex := twoGroups(func() time.Time { return at })
	if s.Of("claude-2") != claude || s.Of("codex") != codex || s.Of("forge") != nil || !s.Has("codex-2") || s.Has("forge") {
		t.Fatalf("Of and Has do not find each key's group")
	}
	if claude.Active() != "claude" || codex.Active() != "codex" {
		t.Errorf("active keys %s and %s; want claude and codex", claude.Active(), codex.Active())
	}
	if next, ok := claude.Refused("claude", http.Header{}, ""); next != "claude-2" || !ok {
		t.Errorf("after claude's refusal: %s, %v; want claude-2", next, ok)
	}
	if codex.Active() != "codex" || codex.Passed() {
		t.Errorf("the codex group after claude's refusal: active %s, passed %v", codex.Active(), codex.Passed())
	}
	claude.Refused("claude-2", http.Header{}, "")
	claude.Pass()
	if reason, ok := claude.Stop(); reason != event.ReasonModelKeyLimit || !ok {
		t.Errorf("the claude stop %q, %v; want model_key_limit", reason, ok)
	}
	if _, ok := codex.Stop(); ok || !s.Passed() {
		t.Errorf("the codex group has a stop %v, or the set is not passed %v", ok, s.Passed())
	}
	if name, ok := codex.Pick(); name != "codex" || !ok {
		t.Errorf("the codex group: %s, %v; want codex usable", name, ok)
	}
	s.Resume()
	if s.Passed() || claude.Passed() {
		t.Errorf("Resume of the set left a pass")
	}
}

// TestASetReportsTheWindowsOfEveryGroup pins the aggregates the reporter and the
// renewer read: the windows of every group in the run configuration's order of the
// keys, a change count that is the sum of the groups', a merge that each group takes
// for its keys alone, and the keys out of use after a 401 of every group in that order,
// with Pending, Renewed and Revoked routed to the key's group.
func TestASetReportsTheWindowsOfEveryGroup(t *testing.T) {
	at := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	s, claude, codex := twoGroups(func() time.Time { return at })
	pokes := 0
	s.OnChange(func() { pokes++ })
	codex.Refused("codex-2", http.Header{}, "")
	claude.Refused("claude", http.Header{}, "")
	ws, changes := s.Snapshot()
	var got []string
	for _, w := range ws {
		got = append(got, w.Credential)
	}
	if !slices.Equal(got, []string{"claude", "codex-2"}) || changes != claude.Changes()+codex.Changes() || changes != 2 || pokes != 2 || s.Changes() != 2 {
		t.Errorf("windows %v, changes %d, pokes %d; want claude then codex-2, 2 and 2", got, changes, pokes)
	}
	s.Merge([]modelkey.Window{{Credential: "codex", Window: "five_hour", Status: modelkey.StatusRejected, CooldownUntil: at.Add(time.Hour), ObservedAt: at}})
	if _, ok := codex.Pick(); ok {
		t.Errorf("the codex group has a usable key after the merge put codex in cooldown")
	}
	if name, ok := claude.Pick(); name != "claude-2" || !ok {
		t.Errorf("the claude group: %s, %v; want claude-2", name, ok)
	}

	codex.Reject("codex", true)
	claude.Reject("claude-2", false)
	var unauth []string
	for _, u := range s.Unauthorized() {
		unauth = append(unauth, u.Credential)
	}
	if !slices.Equal(unauth, []string{"codex", "claude-2"}) || !s.Pending("codex") || s.Pending("claude-2") {
		t.Errorf("Unauthorized %v, codex pending %v, claude-2 pending %v; want codex then claude-2, codex alone pending", unauth, s.Pending("codex"), s.Pending("claude-2"))
	}
	s.Renewed("codex")
	s.Revoked("forge")
	if s.Pending("codex") || len(s.Unauthorized()) != 1 {
		t.Errorf("after codex's renewal: pending %v, %v", s.Pending("codex"), s.Unauthorized())
	}
	fresh, claude2, codex2 := twoGroups(func() time.Time { return at })
	fresh.Restore([]modelkey.Unauthorized{{Credential: "claude-2", At: at, Out: true}, {Credential: "codex", At: at}})
	if !codex2.Pending("codex") || claude2.Pending("claude-2") || len(fresh.Unauthorized()) != 2 {
		t.Errorf("Restore: %v", fresh.Unauthorized())
	}
}

// TestANilSetHasNoGroup pins the set of a run with no key group.
func TestANilSetHasNoGroup(t *testing.T) {
	var s *modelkey.Set
	if s.Of("model") != nil || s.Has("model") || s.Passed() || s.Unauthorized() != nil || s.Pending("model") || s.Groups() != nil {
		t.Errorf("a nil set has a group")
	}
	s.Resume()
	s.Merge(nil)
	s.Revoked("model")
	if ws, n := s.Snapshot(); ws != nil || n != 0 {
		t.Errorf("Snapshot %v, %d", ws, n)
	}
}

// TestJoinChoiceAtStartsAtTheNamedKey pins the join choice of a group no session used:
// the named key, or the group's next usable key when the named key is in cooldown,
// with no key made active.
func TestJoinChoiceAtStartsAtTheNamedKey(t *testing.T) {
	at := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	g := modelkey.New([]modelkey.Key{{Name: "a", PauseFor: time.Hour}, {Name: "b", PauseFor: time.Hour}, {Name: "c", PauseFor: time.Hour}}, "", func() time.Time { return at })
	if got := g.JoinChoiceAt("b"); got != "b" || g.Active() != "a" {
		t.Errorf("JoinChoiceAt b: %s, active %s; want b with a still active", got, g.Active())
	}
	g.Refused("b", http.Header{}, "")
	if got := g.JoinChoiceAt("b"); got != "a" {
		t.Errorf("JoinChoiceAt b in cooldown: %s; want a, the next usable key", got)
	}
	if got := g.JoinChoiceAt("forge"); got != g.JoinChoice() {
		t.Errorf("JoinChoiceAt of no key %s; want JoinChoice %s", got, g.JoinChoice())
	}
}
