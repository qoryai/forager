package modelkey_test

import (
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/modelkey"
)

// TestAKeyOutLeavesTheGroup pins Out: the active key out makes the next key active,
// a key out is never picked again, also after the others cool, a name of no key changes
// nothing, and with every key out Pick reports false and the active key stays.
func TestAKeyOutLeavesTheGroup(t *testing.T) {
	at := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	keys := []modelkey.Key{{Name: "one", PauseFor: time.Hour}, {Name: "two", PauseFor: time.Hour}, {Name: "three", PauseFor: time.Hour}}
	g := modelkey.New(keys, "one", func() time.Time { return at })
	g.Out("one")
	g.Out("none-such")
	if name, ok := g.Pick(); name != "two" || !ok {
		t.Fatalf("Pick after one is out: %s, %v; want two", name, ok)
	}
	if next, ok := g.Refused("two", nil, ""); next != "three" || !ok {
		t.Fatalf("after two cools: %s, %v; want three", next, ok)
	}
	g.Out("three")
	if name, ok := g.Pick(); name != "three" || ok {
		t.Errorf("Pick with one and three out and two cooling: %s, %v; want three and false", name, ok)
	}
	at = at.Add(2 * time.Hour)
	if name, ok := g.Pick(); name != "two" || !ok {
		t.Errorf("Pick once two's cooldown ended: %s, %v; want two", name, ok)
	}
	g.Out("two")
	if name, ok := g.Pick(); name != "two" || ok {
		t.Errorf("Pick with every key out: %s, %v; want two and false", name, ok)
	}
}
