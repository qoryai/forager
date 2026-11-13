package codex_test

import (
	"reflect"
	"slices"
	"testing"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/codex"
	"github.com/qoryai/forager/session/runtimes/runtimetest"
)

func TestCodexIsARuntime(t *testing.T) {
	rt, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	if rt.Name() != codex.Name || rt.Version() != "0.167.2" || !rt.ReadsOutput() || rt.Stop().Signal != "SIGINT" {
		t.Errorf("name %q, version %q, reads output %v, stop %+v", rt.Name(), rt.Version(), rt.ReadsOutput(), rt.Stop())
	}
	runtimetest.Conforms(t, rt)
	runtimetest.Replays(t, rt, contracts.FS, "runtimes/codex/fixtures")
}

// TestCodexReadsItsKeyFromOpenAIAPIKey pins the model section: the Responses format,
// the model id as --model, the effort in model_reasoning_effort with its seven values,
// the endpoint in the provider's base_url, and OPENAI_API_KEY for an API key and for a
// subscription login's token alike. Codex has no resume until its transcript can lie
// outside the runtime's home.
func TestCodexReadsItsKeyFromOpenAIAPIKey(t *testing.T) {
	rt, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	m, ok := rt.(runtimes.Model).Model()
	if !ok {
		t.Fatal("no model section")
	}
	want := runtimes.ModelPlaces{
		Formats: []string{"openai-responses"},
		Model:   runtimes.Place{Flag: "--model"},
		Effort: &runtimes.Effort{Run: runtimes.ValuedPlace{Place: runtimes.Place{Setting: "model_reasoning_effort"},
			Values: []string{"none", "low", "medium", "high", "xhigh", "max", "ultra"}}},
		Endpoint: runtimes.Endpoint{Setting: "model_providers.qory.base_url"},
		Keys: []runtimes.Key{
			{Format: "openai-responses", Auth: runtimes.Auth{Scheme: "bearer"}, Variable: "OPENAI_API_KEY"},
			{Format: "openai-responses", Auth: runtimes.Auth{Scheme: "bearer", OAuth: true}, Variable: "OPENAI_API_KEY"},
		},
	}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("model %+v; want %+v", m, want)
	}
	if _, ok := rt.(runtimes.Resumes); ok {
		if _, has := rt.(runtimes.Resumes).Resume(); has {
			t.Error("Codex has a resume; its transcript lies outside the runtime's home")
		}
	}
}

// TestCodexDeniesTheVariablesThatMoveItsRequests pins the denies that move requests,
// give Codex another key, change its trust of TLS or move its home, and that
// denied-variables.json lists both variables Codex reads a model key from, so a value
// a server or a machine passes for either is left out.
func TestCodexDeniesTheVariablesThatMoveItsRequests(t *testing.T) {
	rt, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	denies := rt.(runtimes.Secrets).Secrets().Denies
	for _, name := range []string{"OPENAI_BASE_URL", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN", "CODEX_CA_CERTIFICATE", "CODEX_HOME",
		"CODEX_SQLITE_HOME", "CODEX_REFRESH_TOKEN_URL_OVERRIDE", "CODEX_EXEC_SERVER_URL", "CODEX_INTERNAL_ORIGINATOR_OVERRIDE"} {
		if !slices.Contains(denies, name) {
			t.Errorf("denies %v has no %s", denies, name)
		}
	}
	if slices.Contains(denies, "OPENAI_API_KEY") {
		t.Error("denies OPENAI_API_KEY, the variable of its keys")
	}
	for _, name := range []string{"OPENAI_API_KEY", "CODEX_API_KEY"} {
		if !slices.Contains(contracts.ModelKeyNames(), name) {
			t.Errorf("denied-variables.json's model_keys has no %s", name)
		}
	}
}

// TestCodexPassesTheProviderQoryAsConfigPairs pins the config: --config and the
// provider qory with the off settings, and the pairs the session passes with a start
// key's endpoint, sorted by key, each a TOML value.
func TestCodexPassesTheProviderQoryAsConfigPairs(t *testing.T) {
	rt, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	c, ok := rt.(runtimes.Configs).Config()
	if !ok || c.Flag != "--config" {
		t.Fatalf("config %+v, %v", c, ok)
	}
	args, err := runtimes.ConfigArgs(c, map[string]any{"model_providers.qory.base_url": "https://api.model.example/v1"})
	if err != nil {
		t.Fatal(err)
	}
	var pairs []string
	for i, a := range args {
		if i%2 == 0 {
			if a != "--config" {
				t.Fatalf("argument %d is %q; want --config: %q", i, a, args)
			}
			continue
		}
		pairs = append(pairs, a)
	}
	want := []string{
		`analytics.enabled=false`,
		`check_for_update_on_startup=false`,
		`features.apps=false`,
		`features.plugins=false`,
		`feedback.enabled=false`,
		`model_provider="qory"`,
		`model_providers.qory.base_url="https://api.model.example/v1"`,
		`model_providers.qory.env_key="OPENAI_API_KEY"`,
		`model_providers.qory.name="qory"`,
		`model_providers.qory.wire_api="responses"`,
		`otel.metrics_exporter="none"`,
		`web_search="disabled"`,
	}
	if !slices.Equal(pairs, want) {
		t.Errorf("pairs\n%q\nwant\n%q", pairs, want)
	}
}
