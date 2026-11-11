package run_test

import (
	"context"
	"io/fs"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/sealed"
)

// fixture is the contract's fixture at path.
func fixture(t *testing.T, path string) string {
	t.Helper()
	b, err := fs.ReadFile(contracts.FS, path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestTheKeyGroupSharesTheStartKeysPlaceholder pins the key group of the contract's
// fixture of three API credentials of one provider: the group is the three in the
// order of credentials, each set with the start key's placeholder, with its
// schedule_resets_at and pause_for_s; the host credential is outside it.
func TestTheKeyGroupSharesTheStartKeysPlaceholder(t *testing.T) {
	doc := fixture(t, "fixtures/run-configuration/model-keys.json")
	r, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, doc, digest('1')),
		Secrets: (&controlPlane{answer: harnessValue}).fetch})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := r.Held().Group; !slices.Equal(got, []string{"model", "model-2", "model-3"}) {
		t.Errorf("Group %v; want model, model-2 and model-3", got)
	}
	placeholder := link.KeyPlaceholder("model")
	for _, u := range r.Uses() {
		want := placeholder
		if u.Name == "forge" {
			want = ""
		}
		if u.Placeholder != want {
			t.Errorf("%s: placeholder %q; want %q", u.Name, u.Placeholder, want)
		}
	}
	schedule := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	want := []modelkey.Key{
		{Name: "model", ScheduleResetsAt: schedule, PauseFor: 5 * time.Hour},
		{Name: "model-2", PauseFor: 5 * time.Hour},
		{Name: "model-3", ScheduleResetsAt: time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC), PauseFor: 5 * time.Hour},
	}
	if got := r.ModelKeys(); !slices.EqualFunc(got, want, func(a, b modelkey.Key) bool {
		return a.Name == b.Name && a.ScheduleResetsAt.Equal(b.ScheduleResetsAt) && a.PauseFor == b.PauseFor
	}) {
		t.Errorf("ModelKeys %+v; want %+v", got, want)
	}
}

// TestAKeyOfAnotherEndpointIsOutsideTheGroup pins that an API credential with another
// endpoint, or another auth, keeps the placeholder of that key.
func TestAKeyOfAnotherEndpointIsOutsideTheGroup(t *testing.T) {
	doc := `{"version":1,"model_credential":"model","credentials":[` +
		`{"name":"model","format":"anthropic-messages","endpoint":"https://api.model.example/anthropic","auth":{"scheme":"bearer","oauth":true},"pause_for_s":60},` +
		`{"name":"api-key","format":"anthropic-messages","endpoint":"https://api.model.example/anthropic","auth":{"scheme":"header","header":"x-api-key"}},` +
		`{"name":"other","format":"anthropic-messages","endpoint":"https://api.other.example/anthropic","auth":{"scheme":"bearer","oauth":true}}]}`
	r, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, doc, digest('1')),
		Secrets: (&controlPlane{answer: harnessValue}).fetch})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := r.Held().Group; !slices.Equal(got, []string{"model"}) {
		t.Errorf("Group %v; want model alone", got)
	}
	for _, u := range r.Uses() {
		if want := link.KeyPlaceholder(u.Name); u.Placeholder != want {
			t.Errorf("%s: placeholder %q; want %q", u.Name, u.Placeholder, want)
		}
	}
}

// cooldown is the cooldown of key name in a group of keys on a clock at at, after a
// limit refusal of name with no reset, and its source.
func cooldown(t *testing.T, keys []modelkey.Key, name string, at time.Time) (time.Duration, string) {
	t.Helper()
	g := modelkey.New(keys, keys[0].Name, func() time.Time { return at })
	g.Refused(name, http.Header{}, "")
	for _, w := range g.Windows() {
		if w.Credential == name && w.Window == modelkey.WindowKey {
			return w.CooldownUntil.Sub(at), w.Source
		}
	}
	t.Fatalf("%s has no window key after a refusal", name)
	return 0, ""
}

// TestAKeyWithoutPauseForHasTheDefaultCooldown pins the cooldown of a key with no
// pause_for_s after a limit refusal with no reset: 1 hour for a subscription, auth with
// oauth, and 1 minute for an API key; a key with pause_for_s keeps it. A run
// configuration of one API key with no pause_for_s, as a control plane before
// pause_for_s sends it, opens.
func TestAKeyWithoutPauseForHasTheDefaultCooldown(t *testing.T) {
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	keys := func(doc string) []modelkey.Key {
		t.Helper()
		r, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, doc, digest('1')),
			Secrets: (&controlPlane{answer: harnessValue}).fetch})
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		return r.ModelKeys()
	}
	subscription := keys(fixture(t, "fixtures/run-configuration/model-keys-no-pause-for.json"))
	if len(subscription) != 2 || subscription[0].PauseFor != 5*time.Hour || subscription[1].PauseFor != time.Hour {
		t.Errorf("ModelKeys %+v; want pause_for_s 18000 on model and 1 hour on model-2", subscription)
	}
	if d, source := cooldown(t, subscription, "model-2", at); d != time.Hour || source != modelkey.SourcePauseFor {
		t.Errorf("model-2 cools for %v from %s; want 1h from pause_for", d, source)
	}
	entry := func(name string) string {
		return `{"name":"` + name + `","format":"anthropic-messages","endpoint":"https://api.model.example/anthropic","auth":{"scheme":"header","header":"x-api-key"}}`
	}
	api := keys(`{"version":1,"model_credential":"model","credentials":[` + entry("model") + `,` + entry("model-2") + `]}`)
	if len(api) != 2 || api[0].PauseFor != time.Minute || api[1].PauseFor != time.Minute {
		t.Errorf("ModelKeys %+v; want 1 minute on both API keys", api)
	}
	if d, source := cooldown(t, api, "model", at); d != time.Minute || source != modelkey.SourcePauseFor {
		t.Errorf("model cools for %v from %s; want 1m0s from pause_for", d, source)
	}
	one := keys(`{"version":1,"credentials":[` + entry("model") + `]}`)
	if len(one) != 1 || one[0].PauseFor != time.Minute {
		t.Errorf("ModelKeys %+v; want one API key with 1 minute", one)
	}
}

// TestAPauseForBelowOneIsRefused pins a pause_for_s of 0 on a key of the group, which
// fails the schema too: the run is refused, run_configuration_invalid with the key's
// name, before any secrets request.
func TestAPauseForBelowOneIsRefused(t *testing.T) {
	doc := fixture(t, "fixtures/invalid/run-configuration-credentials-api-pause-for-zero.json")
	s := &controlPlane{answer: harnessValue}
	_, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, doc, digest('1')), Secrets: s.fetch})
	code, names := refusalOf(err)
	if code != refusal.RunConfigurationInvalid || !slices.Equal(names, []string{"model"}) ||
		!strings.HasPrefix(err.Error(), `set pause_for_s on the model key "model" to a value from 1 to 604800, or remove it for the default cooldown: pause_for_s is 0`) {
		t.Errorf("Open: %v; want model refused", err)
	}
	if len(s.calls) != 0 {
		t.Errorf("%d secrets requests; want none", len(s.calls))
	}
}

// TestAKeyGroupInCooldownAtTheClaim pins the fixture of a key group with a chosen key and
// a key in cooldown at the claim: the keys have resets_at, cooldown_until and chosen;
// a start key in cooldown is refused, and so are two chosen keys, each
// run_configuration_invalid with the key's name and before any secrets request.
func TestAKeyGroupInCooldownAtTheClaim(t *testing.T) {
	doc := fixture(t, "fixtures/run-configuration/model-keys-cooling.json")
	r, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, doc, digest('1')),
		Secrets: (&controlPlane{answer: harnessValue}).fetch})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	keys := r.ModelKeys()
	if len(keys) != 3 || !keys[0].Chosen || keys[1].Chosen || !keys[1].ResetsAt.Equal(time.Date(2026, 11, 10, 14, 0, 0, 0, time.UTC)) ||
		!keys[2].CooldownUntil.Equal(time.Date(2026, 11, 10, 16, 30, 0, 0, time.UTC)) || !keys[0].CooldownUntil.IsZero() {
		t.Errorf("ModelKeys %+v", keys)
	}
	for _, c := range []struct{ fixture, name, line string }{
		{"run-configuration-beyond-schema-model-keys-start-cooling.json", "model", `set model_credential to a model key out of cooldown: the start key "model" is in cooldown until 2099-01-01T00:00:00Z`},
		{"run-configuration-beyond-schema-model-keys-two-chosen.json", "model-2", `set chosen on one model key of the key group: "model" and "model-2" both have it`},
	} {
		s := &controlPlane{answer: harnessValue}
		_, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, fixture(t, "fixtures/invalid/"+c.fixture), digest('1')), Secrets: s.fetch})
		code, names := refusalOf(err)
		if code != refusal.RunConfigurationInvalid || !slices.Equal(names, []string{c.name}) || err == nil || !strings.HasPrefix(err.Error(), c.line) {
			t.Errorf("%s: %v; want %s", c.fixture, err, c.line)
		}
		if len(s.calls) != 0 {
			t.Errorf("%s: %d secrets requests; want none", c.fixture, len(s.calls))
		}
	}
}

// TestTheCheckAndTheProxyShareTheGroup pins one decision of the key group: a key whose
// header differs from the start key's in case alone, and whose start answer sets it on
// two apply items, is in the group the proxy sets, and the check of pause_for_s covers
// it too.
func TestTheCheckAndTheProxyShareTheGroup(t *testing.T) {
	entry := func(name, header, pause string) string {
		return `{"name":"` + name + `","format":"anthropic-messages","endpoint":"https://api.model.example/anthropic","auth":{"scheme":"header","header":"` + header + `"}` + pause + `}`
	}
	doc := `{"version":1,"model_credential":"model","credentials":[` + entry("model", "x-api-key", `,"pause_for_s":60`) + `,` + entry("model-2", "X-Api-Key", `,"pause_for_s":0`) + `]}`
	_, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, doc, digest('1')), Secrets: (&controlPlane{answer: harnessValue}).fetch})
	if code, names := refusalOf(err); code != refusal.RunConfigurationInvalid || !slices.Equal(names, []string{"model-2"}) {
		t.Errorf("Open with model-2's pause_for_s 0: %v; want model-2 refused", err)
	}
	doc = `{"version":1,"model_credential":"model","credentials":[` + entry("model", "x-api-key", `,"pause_for_s":60`) + `,` + entry("model-2", "X-Api-Key", `,"pause_for_s":60`) + `]}`
	// The start's answer sets model-2 on two items of narrower paths: the group stays
	// the entries'.
	two := func(name string, call int) (answer, error) {
		a, err := harnessValue(name, call)
		if name == "model-2" {
			item := func(path string) sealed.Apply {
				return sealed.Apply{Hosts: []string{"api.model.example"}, Scheme: "header", Header: "X-Api-Key", Paths: []string{path}}
			}
			a.apply = []sealed.Apply{item("/anthropic/v1/messages"), item("/anthropic/v1/files")}
		}
		return a, err
	}
	r, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, doc, digest('1')), Secrets: (&controlPlane{answer: two}).fetch})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := r.Held().Group; !slices.Equal(got, []string{"model", "model-2"}) {
		t.Errorf("Group %v; want model and model-2", got)
	}
	if got := r.MessagesPath(); got != "/anthropic/v1/messages" {
		t.Errorf("MessagesPath %q; want /anthropic/v1/messages", got)
	}
}
