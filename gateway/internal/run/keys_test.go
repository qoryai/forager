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

// oneGroup is the set of the one key group g.
func oneGroup(g *modelkey.Group) *modelkey.Set {
	return modelkey.NewSet([]*modelkey.Group{g}, g.Names())
}

// modelKeys are the keys of every key group of r, [run.Run.KeyGroups], in the order of
// the groups.
func modelKeys(r *run.Run) []modelkey.Key {
	var out []modelkey.Key
	for _, g := range r.KeyGroups() {
		out = append(out, g.Keys...)
	}
	return out
}

// keysOf are the names of the keys of the key group of name, of
// [credential.Held.Groups]; nil when name is in none.
func keysOf(r *run.Run, name string) []string {
	for _, g := range r.Held().Groups {
		if slices.Contains(g.Keys, name) {
			return g.Keys
		}
	}
	return nil
}

// TestTheKeyGroupSharesItsFirstKeysPlaceholder pins the key group of the contract's
// fixture of three API credentials of one provider: the group is the three in the
// order of credentials, each set with the placeholder of the group's first key, model,
// with its schedule_resets_at and pause_for_s; the host credential is outside it.
func TestTheKeyGroupSharesItsFirstKeysPlaceholder(t *testing.T) {
	doc := fixture(t, "fixtures/run-configuration/model-keys.json")
	r, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, doc, digest('1')),
		Secrets: (&controlPlane{answer: harnessValue}).fetch})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := keysOf(r, "model"); !slices.Equal(got, []string{"model", "model-2", "model-3"}) {
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
	if got := modelKeys(r); !slices.EqualFunc(got, want, func(a, b modelkey.Key) bool {
		return a.Name == b.Name && a.ScheduleResetsAt.Equal(b.ScheduleResetsAt) && a.PauseFor == b.PauseFor
	}) {
		t.Errorf("the keys %+v; want %+v", got, want)
	}
}

// TestEachGroupHasThePlaceholderOfItsFirstKey pins the key groups of API credentials
// with three group values, whose keys differ in auth or endpoint between groups: the
// groups follow the group member alone, in the order of their first key, and each key
// is set with the placeholder of its group's first key, so two groups never share one.
// A run whose start key is in one group has key groups of the others too, each with its
// format and stream path.
func TestEachGroupHasThePlaceholderOfItsFirstKey(t *testing.T) {
	doc := `{"version":1,"model_credential":"model","credentials":[` +
		`{"name":"model","group":"anthropic","format":"anthropic-messages","endpoint":"https://api.model.example/anthropic","auth":{"scheme":"bearer","oauth":true},"pause_for_s":60},` +
		`{"name":"api-key","group":"anthropic-api","format":"anthropic-messages","endpoint":"https://api.model.example/anthropic","auth":{"scheme":"header","header":"x-api-key"}},` +
		`{"name":"other","group":"other","format":"openai-responses","endpoint":"https://api.other.example/v1","auth":{"scheme":"bearer"}},` +
		`{"name":"other-2","group":"other","format":"openai-responses","endpoint":"https://api.other.example/v1","auth":{"scheme":"bearer"}}]}`
	r, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, doc, digest('1')),
		Secrets: (&controlPlane{answer: harnessValue}).fetch})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var got []string
	for _, g := range r.Held().Groups {
		got = append(got, g.Name+"="+strings.Join(g.Keys, ","))
	}
	if want := []string{"anthropic=model", "anthropic-api=api-key", "other=other,other-2"}; !slices.Equal(got, want) {
		t.Errorf("Groups %q; want %q", got, want)
	}
	want := map[string]string{"model": link.KeyPlaceholder("model"), "api-key": link.KeyPlaceholder("api-key"),
		"other": link.KeyPlaceholder("other"), "other-2": link.KeyPlaceholder("other")}
	for _, u := range r.Uses() {
		if u.Placeholder != want[u.Name] {
			t.Errorf("%s: placeholder %q; want %q", u.Name, u.Placeholder, want[u.Name])
		}
	}
	got = nil
	for _, g := range r.KeyGroups() {
		got = append(got, g.Name+" "+g.Format+" "+g.Stream)
	}
	if want := []string{"anthropic anthropic-messages /anthropic/v1/messages", "anthropic-api anthropic-messages /anthropic/v1/messages", "other openai-responses /v1/responses"}; !slices.Equal(got, want) {
		t.Errorf("KeyGroups %q; want %q", got, want)
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
		return modelKeys(r)
	}
	subscription := keys(fixture(t, "fixtures/run-configuration/model-keys-no-pause-for.json"))
	if len(subscription) != 2 || subscription[0].PauseFor != 5*time.Hour || subscription[1].PauseFor != time.Hour {
		t.Errorf("the keys %+v; want pause_for_s 18000 on model and 1 hour on model-2", subscription)
	}
	if d, source := cooldown(t, subscription, "model-2", at); d != time.Hour || source != modelkey.SourcePauseFor {
		t.Errorf("model-2 cools for %v from %s; want 1h from pause_for", d, source)
	}
	entry := func(name string) string {
		return `{"name":"` + name + `","group":"anthropic","format":"anthropic-messages","endpoint":"https://api.model.example/anthropic","auth":{"scheme":"header","header":"x-api-key"}}`
	}
	api := keys(`{"version":1,"model_credential":"model","credentials":[` + entry("model") + `,` + entry("model-2") + `]}`)
	if len(api) != 2 || api[0].PauseFor != time.Minute || api[1].PauseFor != time.Minute {
		t.Errorf("the keys %+v; want 1 minute on both API keys", api)
	}
	if d, source := cooldown(t, api, "model", at); d != time.Minute || source != modelkey.SourcePauseFor {
		t.Errorf("model cools for %v from %s; want 1m0s from pause_for", d, source)
	}
	one := keys(`{"version":1,"credentials":[` + entry("model") + `]}`)
	if len(one) != 1 || one[0].PauseFor != time.Minute {
		t.Errorf("the keys %+v; want one API key with 1 minute", one)
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

// TestAKeyGroupInCooldownAtTheClaim pins the fixture of a key group with a key in
// cooldown at the claim: the keys have resets_at and cooldown_until; a start key in
// cooldown is refused, and so are two keys of one group with two endpoints, each run_configuration_invalid with the key's
// name and before any secrets request.
func TestAKeyGroupInCooldownAtTheClaim(t *testing.T) {
	doc := fixture(t, "fixtures/run-configuration/model-keys-cooling.json")
	r, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, doc, digest('1')),
		Secrets: (&controlPlane{answer: harnessValue}).fetch})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	keys := modelKeys(r)
	if len(keys) != 3 || !keys[1].ResetsAt.Equal(time.Date(2026, 11, 10, 14, 0, 0, 0, time.UTC)) ||
		!keys[2].CooldownUntil.Equal(time.Date(2026, 11, 10, 16, 30, 0, 0, time.UTC)) || !keys[0].CooldownUntil.IsZero() {
		t.Errorf("the keys %+v", keys)
	}
	for _, c := range []struct{ fixture, name, line string }{
		{"run-configuration-beyond-schema-model-keys-start-cooling.json", "model", `set model_credential to a model key out of cooldown: the start key "model" is in cooldown until 2099-01-01T00:00:00Z`},
		{"run-configuration-beyond-schema-model-keys-group-mixed.json", "model-2", "run configuration https://apiary.example/v1/run-configuration: Give the keys of group \"anthropic\" one format, endpoint and auth.\nThe credentials \"model\" and \"model-2\" differ in endpoint"},
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

// TestAKeyGroupWithUseUpTo pins the fixture of a key group whose keys have
// use_up_to_percent and use_up_to_windows: each key of ModelKeys has them. Each fixture
// of a use_up_to_percent outside 1 to 99, of one of the two members without the other,
// of 12 windows, of a window twice and of a window in upper case fails the schema too,
// and the gateway refuses it, run_configuration_invalid with the key's name and before
// any secrets request.
func TestAKeyGroupWithUseUpTo(t *testing.T) {
	doc := fixture(t, "fixtures/run-configuration/model-keys-use-up-to.json")
	r, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, doc, digest('1')),
		Secrets: (&controlPlane{answer: harnessValue}).fetch})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	keys := modelKeys(r)
	if len(keys) != 2 || keys[0].UseUpToPercent != 90 || !slices.Equal(keys[0].UseUpToWindows, []string{"five_hour", "seven_day"}) ||
		keys[1].UseUpToPercent != 80 || !slices.Equal(keys[1].UseUpToWindows, []string{"five_hour"}) {
		t.Errorf("the keys %+v; want 90 of five_hour and seven_day on model, 80 of five_hour on model-2", keys)
	}
	for _, c := range []struct{ fixture, line string }{
		{"zero", `set use_up_to_percent on the model key "model" to a value from 1 to 99, or remove it and use_up_to_windows to use the key up to its limit: use_up_to_percent is 0`},
		{"hundred", `set use_up_to_percent on the model key "model" to a value from 1 to 99, or remove it and use_up_to_windows to use the key up to its limit: use_up_to_percent is 100`},
		{"no-windows", `set use_up_to_windows on the model key "model" to the limit windows use_up_to_percent applies to, or remove use_up_to_percent: the key has use_up_to_percent 90 and no use_up_to_windows`},
		{"windows-empty", `set use_up_to_windows on the model key "model" to the limit windows use_up_to_percent applies to, or remove use_up_to_percent: the key has use_up_to_percent 90 and no use_up_to_windows`},
		{"windows-alone", `set use_up_to_percent on the model key "model" to a value from 1 to 99, or remove use_up_to_windows: the key has use_up_to_windows and no use_up_to_percent`},
		{"twelve-windows", `list at most 11 windows in use_up_to_windows of the model key "model": it lists 12`},
		{"window-twice", `list each window once in use_up_to_windows of the model key "model": "five_hour" is there twice`},
		{"window-upper-case", `set each window in use_up_to_windows of the model key "model" to 1 to 64 of a-z, 0-9 and underscore, starting with a letter, such as five_hour: window 1 is "Five_Hour"`},
	} {
		s := &controlPlane{answer: harnessValue}
		path := "fixtures/invalid/run-configuration-credentials-api-use-up-to-" + c.fixture + ".json"
		_, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, fixture(t, path), digest('1')), Secrets: s.fetch})
		code, names := refusalOf(err)
		if code != refusal.RunConfigurationInvalid || !slices.Equal(names, []string{"model"}) || err == nil || !strings.HasPrefix(err.Error(), c.line) {
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
		return `{"name":"` + name + `","group":"anthropic","format":"anthropic-messages","endpoint":"https://api.model.example/anthropic","auth":{"scheme":"header","header":"` + header + `"}` + pause + `}`
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
	if got := keysOf(r, "model"); !slices.Equal(got, []string{"model", "model-2"}) {
		t.Errorf("Group %v; want model and model-2", got)
	}
	if groups := r.KeyGroups(); len(groups) != 1 || groups[0].Format != "anthropic-messages" || groups[0].Stream != "/anthropic/v1/messages" {
		t.Errorf("KeyGroups %+v; want one of anthropic-messages and /anthropic/v1/messages", groups)
	}
}
