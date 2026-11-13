package codex_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/session/internal/parents"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/claude"
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
// set another key for Codex, change its trust of TLS or move its home, and that
// denied-variables.json lists both variables Codex reads a model key from, so a value
// a server or a machine passes for either is left out.
func TestCodexDeniesTheVariablesThatMoveItsRequests(t *testing.T) {
	rt, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	denies := rt.(runtimes.Secrets).Secrets().Denies
	for _, name := range []string{"OPENAI_BASE_URL", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN", "CODEX_CA_CERTIFICATE", "CODEX_HOME",
		"CODEX_SQLITE_HOME", "CODEX_REFRESH_TOKEN_URL_OVERRIDE", "CODEX_EXEC_SERVER_URL", "CODEX_INTERNAL_ORIGINATOR_OVERRIDE",
		"CODEX_EXEC_SERVER_NOISE_REGISTRY_URL", "CODEX_EXEC_SERVER_NOISE_ENVIRONMENT_ID", "CODEX_EXEC_SERVER_NOISE_AUTH_TOKEN",
		"CODEX_EXEC_SERVER_NOISE_CHATGPT_ACCOUNT_ID"} {
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
		`otel.exporter="none"`,
		`otel.metrics_exporter="none"`,
		`otel.trace_exporter="none"`,
		`web_search="disabled"`,
	}
	if !slices.Equal(pairs, want) {
		t.Errorf("pairs\n%q\nwant\n%q", pairs, want)
	}
}

// TestCodexMapsItsTurnsWithTheThreadID pins the rules: thread.started is a
// dev.qory.runtime.started from startup with the thread's id; turn.completed and
// turn.failed, which contain no thread id, take it from that start, and each event's
// data passes the contract's schema for its type; an error line, which Codex prints for
// each retry too, maps to nothing.
func TestCodexMapsItsTurnsWithTheThreadID(t *testing.T) {
	rt, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	const id = "01a1d1f8-0000-7000-8000-00000000f1a3"
	var got []runtimes.Event
	m := parents.New(rt, func(e runtimes.Event) { got = append(got, e) }, parents.Real)
	for i, r := range []map[string]any{
		{"type": "thread.started", "thread_id": id},
		{"type": "turn.started"},
		{"type": "error", "message": "Reconnecting... 1/5 (stream disconnected before completion)"},
		{"type": "turn.completed", "usage": map[string]any{"input_tokens": 1, "output_tokens": 1}},
		{"type": "turn.failed", "error": map[string]any{"message": "unexpected status 401 Unauthorized"}},
	} {
		m.Handle(runtimes.Record{Source: runtimes.SourceOutput, Record: r, Line: i + 1})
	}
	m.Close()
	want := []struct {
		typ  string
		data map[string]any
	}{
		{"dev.qory.runtime.started", map[string]any{"session_id": id, "source": "startup", "line": 1}},
		{"dev.qory.runtime.turn_finished", map[string]any{"session_id": id, "line": 4}},
		{"dev.qory.runtime.turn_failed", map[string]any{"session_id": id, "error": "unknown", "message": "unexpected status 401 Unauthorized", "line": 5}},
	}
	if len(got) != len(want) {
		t.Fatalf("events %+v; want %d, and none for the error line", got, len(want))
	}
	for i, w := range want {
		if got[i].Type != w.typ || !reflect.DeepEqual(got[i].Data, w.data) {
			t.Errorf("event %d: %s %v; want %s %v", i, got[i].Type, got[i].Data, w.typ, w.data)
		}
		schema, err := contracts.Compile("events/" + strings.TrimPrefix(w.typ, "dev.qory.") + ".schema.json")
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(roundTrip(t, got[i].Data)); err != nil {
			t.Errorf("event %d: %s data: %v", i, w.typ, err)
		}
	}
	if events := rt.Map(runtimes.Record{Source: runtimes.SourceOutput, Record: map[string]any{"type": "error", "message": "unexpected status 401 Unauthorized"}}); len(events) != 0 {
		t.Errorf("an error line maps to %+v; want nothing", events)
	}
}

// roundTrip is v as JSON decodes it, the form the schema validates.
func roundTrip(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCodexRefusesArgumentsThatChangeItsSettings pins the check of Codex's launch
// arguments. The join fails on these with an error that starts with the fix, contains
// the flag and contains no value: each form of --config and -c that sets a fixed key,
// the endpoint's setting, any setting at, under or above model_providers, profile,
// profiles, projects or responses_api_metadata, or one of the addresses of OpenAI and
// ChatGPT; --ignore-user-config; features.connectors, the
// legacy name of apps, in a pair and in --enable or --disable; --enable and --disable
// of a fixed feature; and every form of --oss, --search, --local-provider, --profile
// and -p. Ordinary arguments, a flag after --, and Claude Code with the same arguments
// pass.
func TestCodexRefusesArgumentsThatChangeItsSettings(t *testing.T) {
	rt, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	c := rt.(runtimes.ArgsChecker)
	const v = "value-not-shown"
	for _, r := range []struct {
		flag string
		args []string
	}{
		{"--config", []string{"--config", "model_provider=" + v}},
		{"--config", []string{"--config=web_search=" + v}},
		{"--config", []string{"--config", "model_providers.qory.base_url=" + v}},
		{"--config", []string{"--config", "model_providers.qory={base_url=\"" + v + "\"}"}},
		{"--config", []string{"--config", "model_providers.qory.supports_websockets=true"}},
		{"-c", []string{"-c", "model_providers.qory.http_headers.x=\"" + v + "\""}},
		{"--config", []string{"--config=model_providers.other.base_url=" + v}},
		{"-c", []string{"-c", "model_providers={}"}},
		{"--config", []string{"--config", "otel.exporter={otlp-http={endpoint=\"" + v + "\"}}"}},
		{"-c", []string{"-c", "otel.trace_exporter=statsig"}},
		{"-c", []string{"-c", "features.connectors=true"}},
		{"--config", []string{"--config=features.connectors=true"}},
		{"--enable", []string{"--enable", "connectors"}},
		{"--enable", []string{"--enable=connectors"}},
		{"--disable", []string{"--disable", "connectors"}},
		{"-c", []string{"-c", "openai_base_url=" + v}},
		{"--config", []string{"--config", "chatgpt_base_url=" + v}},
		{"-c", []string{"-cexperimental_realtime_ws_base_url=" + v}},
		{"--config", []string{"--config", "experimental_realtime_webrtc_call_base_url=" + v}},
		{"-c", []string{"-c", "profile=" + v}},
		{"-c", []string{"-c", "projects./work.trust_level=\"trusted\""}},
		{"-c", []string{"-c", "projects={\"/work\"={trust_level=\"trusted\"}}"}},
		{"--config", []string{"--config=projects./" + v + ".trust_level=\"trusted\""}},
		{"-c", []string{"-c", "responses_api_metadata.x=\"" + v + "\""}},
		{"--config", []string{"--config", "responses_api_metadata={x=\"" + v + "\"}"}},
		{"--ignore-user-config", []string{"--ignore-user-config"}},
		{"--ignore-user-config", []string{"--ignore-user-config=true"}},
		{"--config", []string{"--config", "profiles." + v + ".model_provider=\"openai\""}},
		{"-c", []string{"-c", "model_provider=" + v}},
		{"-c", []string{"-cmodel_providers.qory.env_key=" + v}},
		{"-c", []string{"-c=analytics.enabled=" + v}},
		{"-c", []string{"-c", " otel.metrics_exporter = " + v}},
		{"--enable", []string{"--enable", "plugins"}},
		{"--enable", []string{"--enable=apps"}},
		{"--disable", []string{"--disable", "plugins"}},
		{"--oss", []string{"--oss"}},
		{"--search", []string{"--search"}},
		{"--local-provider", []string{"--local-provider", v}},
		{"--local-provider", []string{"--local-provider=" + v}},
		{"--profile", []string{"--profile", v}},
		{"--profile", []string{"--profile=" + v}},
		{"-p", []string{"-p", v}},
		{"-p", []string{"-p" + v}},
		{"-p", []string{"-p=" + v}},
	} {
		args := slices.Concat([]string{"exec", "--json"}, r.args, []string{"Say hi"})
		err := c.CheckArgs(args)
		if err == nil || !strings.HasPrefix(err.Error(), "remove ") || !strings.Contains(err.Error(), r.flag) || strings.Contains(err.Error(), v) {
			t.Errorf("%q: %v; want a refusal that starts with the fix, names %s and contains no value", args, err, r.flag)
		}
	}
	ordinary := []string{"exec", "--json", "--skip-git-repo-check", "--sandbox", "danger-full-access", "--model", "gpt-x",
		"--config", "model_reasoning_effort=\"high\"", "-c", "model=\"gpt-x\"", "--enable", "undo", "-c", "model_provider_note=x",
		"--config", "experimental_realtime_base_url=x", "-c", "features.connectors_extra=true", "--", "--oss", "-p", "x"}
	if err := c.CheckArgs(ordinary); err != nil {
		t.Errorf("%q: %v; want no refusal", ordinary, err)
	}
	cl, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.(runtimes.ArgsChecker).CheckArgs([]string{"-p", "Say hi", "--config", "model_provider=x", "--profile", "x"}); err != nil {
		t.Errorf("Claude Code: %v; want no refusal", err)
	}
}
