package modelkey_test

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/modelkey"
)

// TestA401TakesTheKeyOutOfUse pins Reject, Renewed and Revoked: a key whose value
// renews has its renewal pending and is not picked meanwhile; a renewal's value puts it
// back; a refused renewal takes it out for the run, and a later renewal changes
// nothing; a key whose value does not renew is out at once; a second 401 keeps the time
// of the first; and a name of no key changes nothing.
func TestA401TakesTheKeyOutOfUse(t *testing.T) {
	g, c := group(t)
	g.Reject("model", true)
	if !g.Pending("model") {
		t.Fatal("a key that renews has no renewal pending after a 401")
	}
	if name, ok := g.Pick(); name != "model-2" || !ok {
		t.Fatalf("Pick after model's 401: %s, %v; want model-2", name, ok)
	}
	c.now = c.now.Add(time.Minute)
	g.Reject("model", true)
	if got := g.Unauthorized(); !reflect.DeepEqual(got, []modelkey.Unauthorized{{Credential: "model", At: start}}) {
		t.Errorf("after a second 401: %+v; want model at the first 401's time", got)
	}
	g.Renewed("model")
	if g.Pending("model") || g.Unauthorized() != nil {
		t.Errorf("after the renewal's value: pending %v, unauthorized %+v", g.Pending("model"), g.Unauthorized())
	}
	g.SetActive("model")
	if name, ok := g.Pick(); name != "model" || !ok {
		t.Errorf("Pick once model is back: %s, %v", name, ok)
	}

	g.Reject("model-2", true)
	g.Revoked("model-2")
	g.Renewed("model-2")
	g.Reject("model-3", false)
	g.Reject("none-such", false)
	at := c.now
	want := []modelkey.Unauthorized{{Credential: "model-2", At: at, Out: true}, {Credential: "model-3", At: at, Out: true}}
	if got := g.Unauthorized(); !reflect.DeepEqual(got, want) {
		t.Errorf("after model-2's refused renewal and model-3's 401: %+v; want %+v", got, want)
	}
	if g.Pending("model-2") || g.Pending("model-3") {
		t.Error("a key out has a renewal pending")
	}
	if g.JoinKey() != "model" {
		t.Errorf("JoinKey with model-2 and model-3 out: %s; want model", g.JoinKey())
	}
	g.Revoked("model")
	if got := g.Unauthorized(); len(got) != 2 {
		t.Errorf("Revoked of a key with no 401 changed it: %+v", got)
	}
}

// TestUnauthorizedHooksComeInOrder pins OnUnauthorized and OnChange: one call of each
// per change, with the list after it, and none for a call that changes nothing.
func TestUnauthorizedHooksComeInOrder(t *testing.T) {
	g, _ := group(t)
	var lists [][]modelkey.Unauthorized
	changes := 0
	g.OnUnauthorized(func(l []modelkey.Unauthorized) { lists = append(lists, l) })
	g.OnChange(func() { changes++ })
	g.Reject("model", true)
	g.Reject("model", true)
	g.Renewed("model-2")
	g.Revoked("model")
	g.Revoked("model")
	if len(lists) != 2 || changes != 2 {
		t.Fatalf("%d lists and %d changes; want 2 of each", len(lists), changes)
	}
	if lists[0][0].Out || !lists[1][0].Out {
		t.Errorf("the lists %+v; want model waiting, then out", lists)
	}
}

// TestUnauthorizedListsAtMostSixKeys pins the cap of the report's unauthorized: the
// first 6 keys by the order of the group.
func TestUnauthorizedListsAtMostSixKeys(t *testing.T) {
	var keys []modelkey.Key
	var names []string
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		keys = append(keys, modelkey.Key{Name: n, PauseFor: time.Hour})
		names = append(names, n)
	}
	g := modelkey.New(keys, "a", func() time.Time { return start })
	for _, n := range slices.Backward(names) {
		g.Reject(n, false)
	}
	var got []string
	for _, u := range g.Unauthorized() {
		got = append(got, u.Credential)
	}
	if !slices.Equal(got, names[:6]) {
		t.Errorf("unauthorized %v; want %v", got, names[:6])
	}
}

// TestTheStopsReason pins Stop's reason for both formats: model_key_unauthorized once a
// 401 took the last key out; model_key_switch after a passed 401 of openai-responses
// with a key usable; model_key_limit after a passed 401 with every other key cooling
// or waiting for a renewal, after a passed 401 of anthropic-messages with a key usable,
// and after a limit refusal. No stop before a pass.
func TestTheStopsReason(t *testing.T) {
	for _, c := range []struct {
		what, format string
		do           func(g *modelkey.Group)
		want         string
	}{
		{"every key out by a 401", modelkey.FormatOpenAIResponses, func(g *modelkey.Group) {
			g.Reject("model", false)
			g.Reject("model-2", false)
			g.Reject("model-3", true)
			g.Revoked("model-3")
			g.PassRejected()
		}, "model_key_unauthorized"},
		{"every key out by a 401", modelkey.FormatAnthropicMessages, func(g *modelkey.Group) {
			g.Out("model")
			g.Reject("model-2", false)
			g.Reject("model-3", false)
			g.PassRejected()
		}, "model_key_unauthorized"},
		{"a 401 with another key usable", modelkey.FormatOpenAIResponses, func(g *modelkey.Group) {
			g.Reject("model", false)
			g.PassRejected()
		}, "model_key_switch"},
		{"a 401 with another key usable", modelkey.FormatAnthropicMessages, func(g *modelkey.Group) {
			g.Reject("model", false)
			g.PassRejected()
		}, "model_key_limit"},
		{"one key out and one cooling", modelkey.FormatOpenAIResponses, func(g *modelkey.Group) {
			g.Refused("model-2", nil, "")
			g.Reject("model-3", true)
			g.Reject("model", false)
			g.PassRejected()
		}, "model_key_limit"},
		{"one key out and one cooling", modelkey.FormatAnthropicMessages, func(g *modelkey.Group) {
			g.Refused("model-2", nil, "")
			g.Reject("model", false)
			g.Reject("model-3", false)
			g.PassRejected()
		}, "model_key_limit"},
		{"a limit refusal, then a 401", modelkey.FormatOpenAIResponses, func(g *modelkey.Group) {
			g.Refused("model", nil, "")
			g.Pass()
			g.Reject("model-2", false)
			g.PassRejected()
		}, "model_key_limit"},
	} {
		g, _ := group(t)
		g.SetFormat(c.format)
		if _, ok := g.Stop(); ok {
			t.Fatalf("%s, %s: a stop before a pass", c.what, c.format)
		}
		c.do(g)
		if got, ok := g.Stop(); !ok || got != c.want {
			t.Errorf("%s, %s: Stop %q, %v; want %q", c.what, c.format, got, ok, c.want)
		}
	}
}

// TestTheStopsReasonHoldsUntilResume pins the reason Stop fixes: later changes of the
// keys keep it, the hook of OnStop gets it once, Resume clears it, and PassWith fixes a
// reason with no call of the hook.
func TestTheStopsReasonHoldsUntilResume(t *testing.T) {
	g, _ := group(t)
	g.SetFormat(modelkey.FormatOpenAIResponses)
	var stops []string
	g.OnStop(func(r string) { stops = append(stops, r) })
	g.Reject("model", true)
	g.PassRejected()
	if r, _ := g.Stop(); r != "model_key_switch" {
		t.Fatalf("the first stop %q", r)
	}
	g.Revoked("model")
	g.Reject("model-2", false)
	g.Reject("model-3", false)
	if r, _ := g.Stop(); r != "model_key_switch" {
		t.Errorf("a stop after the keys went out %q; want the first reason", r)
	}
	g.Resume()
	if _, ok := g.Stop(); ok {
		t.Error("a stop after Resume")
	}
	g.PassWith("model_key_limit")
	if r, ok := g.Stop(); !ok || r != "model_key_limit" {
		t.Errorf("after PassWith: %q, %v", r, ok)
	}
	if !slices.Equal(stops, []string{"model_key_switch"}) {
		t.Errorf("the hook got %v; want the first reason once", stops)
	}
	var none *modelkey.Group
	none.PassRejected()
	none.PassWith("model_key_limit")
	if _, ok := none.Stop(); ok || none.Unauthorized() != nil {
		t.Error("a nil group has a stop or unauthorized keys")
	}
}

// TestRestoreGivesBackTheKeysOfTheRecord pins Restore: each key with its time, out or
// with its renewal pending, a name of no key left out, and a key out for no account
// claim kept as it is.
func TestRestoreGivesBackTheKeysOfTheRecord(t *testing.T) {
	g, _ := group(t)
	g.Out("model-3")
	at := start.Add(-time.Minute)
	g.Restore([]modelkey.Unauthorized{{Credential: "model", At: at, Out: true}, {Credential: "model-2", At: at}, {Credential: "model-3", At: at}, {Credential: "none-such", At: at}})
	want := []modelkey.Unauthorized{{Credential: "model", At: at, Out: true}, {Credential: "model-2", At: at}}
	if got := g.Unauthorized(); !reflect.DeepEqual(got, want) {
		t.Errorf("after Restore: %+v; want %+v", got, want)
	}
	if !g.Pending("model-2") || g.Pending("model") {
		t.Error("Restore did not keep model-2 waiting and model out")
	}
	if _, ok := g.Pick(); ok {
		t.Error("a key is usable after Restore")
	}
}
