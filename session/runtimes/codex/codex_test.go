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
	if rt.Name() != codex.Name || !rt.ReadsOutput() || rt.Stop().Signal != "SIGINT" {
		t.Errorf("name %q, reads output %v, stop %+v", rt.Name(), rt.ReadsOutput(), rt.Stop())
	}
	if r, ok := rt.(runtimes.InstallRequired); !ok || r.InstallRequired() {
		t.Error("Codex requires an installed folder; want a session that starts it from the image")
	}
	runtimetest.Conforms(t, rt)
	runtimetest.Replays(t, rt, contracts.FS, "runtimes/codex/fixtures")
}

// TestCodexReadsItsKeyFromOpenAIAPIKey pins the model section: the Responses format,
// the model id as --model, an agent's model id in the key model of its TOML file, the
// effort in model_reasoning_effort with its seven values, an agent's effort in the key
// model_reasoning_effort of its TOML file with the same values, the endpoint in the
// provider's base_url, and OPENAI_API_KEY for an API key and for a subscription
// login's token alike.
func TestCodexReadsItsKeyFromOpenAIAPIKey(t *testing.T) {
	rt, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	m, ok := rt.(runtimes.Model).Model()
	if !ok {
		t.Fatal("no model section")
	}
	efforts := []string{"none", "low", "medium", "high", "xhigh", "max", "ultra"}
	want := runtimes.ModelPlaces{
		Formats: []string{"openai-responses"},
		Model:   runtimes.Place{Flag: "--model"},
		Agent:   &runtimes.AgentKey{TOML: "model"},
		Effort: &runtimes.Effort{
			Run:   runtimes.ValuedPlace{Place: runtimes.Place{Setting: "model_reasoning_effort"}, Values: efforts},
			Agent: &runtimes.AgentPlace{TOML: "model_reasoning_effort", Values: efforts},
		},
		Endpoint: runtimes.Endpoint{Setting: "model_providers.qory.base_url"},
		Keys: []runtimes.Key{
			{Format: "openai-responses", Auth: runtimes.Auth{Scheme: "bearer"}, Variable: "OPENAI_API_KEY"},
			{Format: "openai-responses", Auth: runtimes.Auth{Scheme: "bearer", OAuth: true}, Variable: "OPENAI_API_KEY"},
		},
	}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("model %+v; want %+v", m, want)
	}
}

// TestCodexResumesItsRolloutBelowCodexHome pins the resume: the rollout below
// ${CODEX_HOME}/sessions/ in dated directories, CODEX_HOME the home variable, no hook
// path, and resume <thread id> after exec, right before the launch's last argument.
func TestCodexResumesItsRolloutBelowCodexHome(t *testing.T) {
	rt, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	rs, ok := rt.(runtimes.Resumes).Resume()
	want := runtimes.Resume{HomeVar: "CODEX_HOME", Prefix: "${CODEX_HOME}/sessions/", Path: "${CODEX_HOME}/sessions/*/*/*/rollout-*-{session_id}.jsonl",
		Args: []string{"resume", "{session_id}"}, After: "exec", Place: runtimes.PlaceBeforeLast}
	if !ok || !reflect.DeepEqual(rs, want) {
		t.Errorf("resume %+v, %v; want %+v", rs, ok, want)
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
// provider qory with the off settings, and the pairs the session passes with a default
// model provider credential's endpoint, sorted by key, each a TOML value.
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
// of a fixed feature; every form of --oss, --search, --local-provider, --profile
// and -p; every form of --dangerously-bypass-hook-trust and --remote; and each form of
// --config and -c that sets a key at, under or above skills or cloud.skills. Ordinary
// arguments, cloud.other, a flag after --, and Claude Code with the same arguments
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
		{"--dangerously-bypass-hook-trust", []string{"--dangerously-bypass-hook-trust"}},
		{"--dangerously-bypass-hook-trust", []string{"--dangerously-bypass-hook-trust=" + v}},
		{"--remote", []string{"--remote", "ws://" + v + ":1"}},
		{"--remote", []string{"--remote=ws://" + v + ":1"}},
		{"--config", []string{"--config", "skills.config=[{path=\"" + v + "\"}]"}},
		{"--config", []string{"--config=skills={}"}},
		{"-c", []string{"-c", "skills=" + v}},
		{"-c", []string{"-cskills." + v + "=true"}},
		{"-c", []string{"-c=skills.x=" + v}},
		{"--config", []string{"--config", "cloud.skills=" + v}},
		{"-c", []string{"-c", "cloud.skills.x=" + v}},
		{"-c", []string{"-c", "cloud={skills=\"" + v + "\"}"}},
		{"--config", []string{"--config=cloud={}"}},
	} {
		args := slices.Concat([]string{"exec", "--json"}, r.args, []string{"Say hi"})
		err := c.CheckArgs(args)
		if err == nil || !strings.HasPrefix(err.Error(), "remove ") || !strings.Contains(err.Error(), r.flag) || strings.Contains(err.Error(), v) {
			t.Errorf("%q: %v; want a refusal that starts with the fix, names %s and contains no value", args, err, r.flag)
		}
	}
	for args, want := range map[string]string{
		"--dangerously-bypass-hook-trust": "remove --dangerously-bypass-hook-trust from the launch's arguments\nit lets Codex run hooks that have no trust stored for them",
		"--remote=ws://x:1":               "remove --remote from the launch's arguments\nit connects Codex to a remote app server, so the work runs outside the session",
		"-cskills={}":                     "remove the -c that sets skills from the launch's arguments\nit changes the skills Codex loads, which the composer places below CODEX_HOME",
	} {
		if err := c.CheckArgs([]string{"exec", args, "Say hi"}); err == nil || err.Error() != want {
			t.Errorf("%s: %v; want %s", args, err, want)
		}
	}
	ordinary := []string{"exec", "--json", "--skip-git-repo-check", "--sandbox", "danger-full-access", "--model", "gpt-x",
		"--config", "model_reasoning_effort=\"high\"", "-c", "model=\"gpt-x\"", "--enable", "undo", "-c", "model_provider_note=x",
		"--config", "experimental_realtime_base_url=x", "-c", "features.connectors_extra=true", "-c", "cloud.other=1", "-c", "skills_extra=1",
		"-c", "features.unified_exec=false", "-c", "features.unified_exec_tty_extra=true", "--enable", "unified_exec", "-c", "features.hooks_extra=1",
		"--remote-auth-token-env", "X", "--", "--oss", "-p", "x", "--remote", "ws://x:1", "--dangerously-bypass-hook-trust"}
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

// TestCodexRefusesTheFeaturesOfItsHooks pins the features that decide whether Codex
// runs the run's hooks before each tool call: unified_exec_tty, hooks and codex_hooks,
// the legacy name of hooks. With the contract's descriptor and with a descriptor
// without config, the join fails on each form of --config and -c that sets one, with
// spaces around the key and as the table form features.<name>.enabled, and on
// --enable and --disable of one, with the fix on the first line, at most 100
// characters, and the cause on the second. Other features, a key that only starts
// with a name, the effort pair a composer passes, and a flag after -- pass. A pair
// whose value is a table is in [TestCodexNamesTheKeyATableSets].
func TestCodexRefusesTheFeaturesOfItsHooks(t *testing.T) {
	contract, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	bare, err := codex.Described("codex.yaml", []byte("version: 1\nruntime: codex\nsources: {output: {format: jsonl}}\n"+
		"rules: [{source: output, match: {type: thread.started}, type: dev.qory.runtime.started, data: {session_id: thread_id}, set: {source: startup}}]\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bare.(runtimes.Configs).Config(); ok {
		t.Fatal("the bare descriptor has config")
	}
	const cause = "the setting can turn off the hooks Codex runs before each tool call, or make Codex run no hook for a command sent to a shell with a terminal"
	for name, rt := range map[string]runtimes.Runtime{"the contract's descriptor": contract, "a descriptor without config": bare} {
		c := rt.(runtimes.ArgsChecker)
		for _, feature := range []string{"unified_exec_tty", "hooks", "codex_hooks"} {
			key := "features." + feature
			for _, r := range []struct {
				flag string
				args []string
			}{
				{"--config", []string{"--config", key + "=true"}},
				{"--config", []string{"--config=" + key + "=false"}},
				{"-c", []string{"-c", key + "=true"}},
				{"-c", []string{"-c" + key + "=true"}},
				{"-c", []string{"-c=" + key + "=true"}},
				{"-c", []string{"-c", " " + key + " = true"}},
				{"-c", []string{"-c", key + ".enabled=true"}},
				{"--config", []string{"--config", key + "={enabled=true}"}},
				{"--enable", []string{"--enable", feature}},
				{"--enable", []string{"--enable=" + feature}},
				{"--disable", []string{"--disable", feature}},
				{"--disable", []string{"--disable=" + feature}},
			} {
				args := slices.Concat([]string{"exec", "--json"}, r.args, []string{"Say hi"})
				want := "remove the " + r.flag + " that sets " + key + " from the launch's arguments\n" + cause
				err := c.CheckArgs(args)
				if err == nil || err.Error() != want {
					t.Errorf("%s, %q: %v; want %s", name, args, err, want)
					continue
				}
				if first, _, _ := strings.Cut(err.Error(), "\n"); len(first) > 100 {
					t.Errorf("%s, %q: the first line has %d characters; want 100 at most", name, args, len(first))
				}
			}
		}
		ordinary := []string{"exec", "--json", "--enable", "undo", "--disable", "undo", "--enable=unified_exec",
			"--config", "model_reasoning_effort=\"high\"", "-c", "features.unified_exec=false", "-c", "features.unified_exec_tty_extra=true",
			"-c", "features.hooks_extra=1", "-c", "hooks_note=x", "--", "--enable", "hooks", "-c", "features.hooks=false", "Say hi"}
		if err := c.CheckArgs(ordinary); err != nil {
			t.Errorf("%s, %q: %v; want no refusal", name, ordinary, err)
		}
	}
}

// TestCodexNamesTheKeyATableSets pins the error for a --config or -c pair whose value
// is an inline table, with the contract's descriptor and with a descriptor without
// config: it contains the key that the table sets, at any depth, through quoted and
// dotted keys, and not the key above it or another setting of the session's. A table
// that sets no such key, an empty table, and a table that does not parse are refused
// as their pair's key is, with the setting below it. With the contract's descriptor,
// config.flag's check of each pair's key comes before Codex's check, so a --config
// table at features, which is above the session's setting features.plugins, gets the
// error of features.plugins, as a --config pair below features.plugins does.
func TestCodexNamesTheKeyATableSets(t *testing.T) {
	contract, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	bare, err := codex.Described("codex.yaml", []byte("version: 1\nruntime: codex\nsources: {output: {format: jsonl}}\n"+
		"rules: [{source: output, match: {type: thread.started}, type: dev.qory.runtime.started, data: {session_id: thread_id}, set: {source: startup}}]\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	const hookCause = "\nthe setting can turn off the hooks Codex runs before each tool call, or make Codex run no hook for a command sent to a shell with a terminal"
	hook := func(flag, key string) string {
		return "remove the " + flag + " that sets " + key + " from the launch's arguments" + hookCause
	}
	reserved := func(flag, key string) string {
		return "remove the " + flag + " that sets " + key + " from the launch's arguments\nthe session sets that setting for Codex, or the setting changes where Codex sends its requests"
	}
	skill := func(flag, key string) string {
		return "remove the " + flag + " that sets " + key + " from the launch's arguments\nit changes the skills Codex loads, which the composer places below CODEX_HOME"
	}
	// sessionKey is the error for a pair that sets a setting the session passes: for
	// --config, config.flag, the check of config.flag's; for -c, Codex's.
	sessionKey := func(flag, key string) string {
		if flag == "-c" {
			return reserved(flag, key)
		}
		return "remove the --config pair that sets " + key + " from the launch's arguments\nthe session sets " + key + ", and a later pair overrides the session's value"
	}
	// features is the error, with the contract's descriptor, for a pair whose value is a
	// table at features that sets key: for --config, config.flag's check comes first,
	// and the pair's key, features, is above the session's setting features.plugins.
	features := func(flag, key string) string {
		if flag == "--config" {
			return sessionKey(flag, "features.plugins")
		}
		return hook(flag, key)
	}
	for _, flag := range []string{"-c", "--config"} {
		for _, r := range []struct {
			pair           string
			contract, bare string
		}{
			{"features={hooks=false}", features(flag, "features.hooks"), hook(flag, "features.hooks")},
			{" features = { hooks = false } ", features(flag, "features.hooks"), hook(flag, "features.hooks")},
			{"features={undo=true, codex_hooks=false}", features(flag, "features.codex_hooks"), hook(flag, "features.codex_hooks")},
			{`features={"hooks"=false}`, features(flag, "features.hooks"), hook(flag, "features.hooks")},
			{"features={'unified_exec_tty'=true}", features(flag, "features.unified_exec_tty"), hook(flag, "features.unified_exec_tty")},
			{"features={hooks={enabled=false}}", features(flag, "features.hooks"), hook(flag, "features.hooks")},
			{"features={hooks.enabled=false}", features(flag, "features.hooks"), hook(flag, "features.hooks")},
			{"features={hooks . enabled=false}", features(flag, "features.hooks"), hook(flag, "features.hooks")},
			{`features={note="a,}b", list=[1, {x=2}], hooks=false}`, features(flag, "features.hooks"), hook(flag, "features.hooks")},
			{"model_providers={qory={base_url=\"x\"}}", sessionKey(flag, "model_providers.qory.base_url"), reserved(flag, "model_providers")},
			{"cloud={skills={x=1}}", skill(flag, "cloud.skills"), skill(flag, "cloud.skills")},
			{"features={apps=true}", sessionKey(flag, "features.apps"), hook(flag, "features.unified_exec_tty")},
			{"features={undo=true}", sessionKey(flag, "features.plugins"), hook(flag, "features.unified_exec_tty")},
			{"features={}", sessionKey(flag, "features.plugins"), hook(flag, "features.unified_exec_tty")},
			{"features={hooks=", sessionKey(flag, "features.plugins"), hook(flag, "features.unified_exec_tty")},
			{"features={hooks=false} trailing", sessionKey(flag, "features.plugins"), hook(flag, "features.unified_exec_tty")},
			{"features={hooks=false}}", sessionKey(flag, "features.plugins"), hook(flag, "features.unified_exec_tty")},
			{`features={"h\u006Foks"=false}`, features(flag, "features.hooks"), hook(flag, "features.hooks")},
		} {
			for name, rt := range map[string]runtimes.Runtime{"the contract's descriptor": contract, "a descriptor without config": bare} {
				want := r.contract
				if rt == bare {
					want = r.bare
				}
				args := []string{"exec", "--json", flag, r.pair, "Say hi"}
				if err := rt.(runtimes.ArgsChecker).CheckArgs(args); err == nil || err.Error() != want {
					t.Errorf("%s, %q: %v; want %s", name, args, err, want)
				}
			}
		}
	}
	// A --config pair that sets a session key gets the error of config.flag's check
	// whether its value is a table above the key or a key below it.
	for _, pair := range []string{"features={undo=true}", "features.plugins.x=1", "features.plugins=true"} {
		args := []string{"exec", "--json", "--config", pair, "Say hi"}
		if err := contract.(runtimes.ArgsChecker).CheckArgs(args); err == nil || err.Error() != sessionKey("--config", "features.plugins") {
			t.Errorf("%q: %v; want %s", args, err, sessionKey("--config", "features.plugins"))
		}
	}
}

// TestCodexRefusalsHaveTheFixWithin100Characters pins the first line of each refusal,
// for each key of the contract's descriptor, the longest reserved settings of Codex's
// check, the skills settings and the hook features, and each flag that Codex's check
// returns an error for: it starts with remove, has at most 100 characters, and the
// cause is on a second line.
func TestCodexRefusalsHaveTheFixWithin100Characters(t *testing.T) {
	rt, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	c, _ := rt.(runtimes.Configs).Config()
	keys := []string{"model_providers.qory.base_url", "experimental_realtime_x_base_url", "responses_api_metadata",
		"chatgpt_base_url", "cloud.skills", "features.unified_exec_tty", "features.codex_hooks"}
	for k := range c.Fixed {
		keys = append(keys, k)
	}
	var cases [][]string
	for _, flag := range []string{"--config", "-c"} {
		for _, k := range keys {
			cases = append(cases, []string{flag, k + "=1"}, []string{flag, k + "={x=1}"})
		}
	}
	cases = append(cases, []string{"--local-provider", "x"}, []string{"--profile", "x"}, []string{"-px"},
		[]string{"--oss"}, []string{"--search"}, []string{"--ignore-user-config"}, []string{"--dangerously-bypass-hook-trust"},
		[]string{"--remote", "ws://x:1"}, []string{"--enable", "plugins"}, []string{"--disable", "hooks"})
	for _, args := range cases {
		err := rt.(runtimes.ArgsChecker).CheckArgs(slices.Concat([]string{"exec", "--json"}, args, []string{"Say hi"}))
		if err == nil {
			t.Errorf("%q: no refusal", args)
			continue
		}
		first, cause, ok := strings.Cut(err.Error(), "\n")
		if !strings.HasPrefix(first, "remove ") || len(first) > 100 || !ok || cause == "" {
			t.Errorf("%q: %q; want the fix on a first line of at most 100 characters and the cause on a second", args, err)
		}
	}
}

// TestCodexReadsTheFormsAsCodex0169Does pins the check of argument forms by how
// Codex 0.169.0 (rust-v0.169.0, d32063f96c2d) parses them, with the contract's
// descriptor and with a descriptor without config. Paths are below codex-rs/; clap is
// 4.5.58 (Cargo.lock:1774-1775).
func TestCodexReadsTheFormsAsCodex0169Does(t *testing.T) {
	contract, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	bare, err := codex.Described("codex.yaml", []byte("version: 1\nruntime: codex\nsources: {output: {format: jsonl}}\n"+
		"rules: [{source: output, match: {type: thread.started}, type: dev.qory.runtime.started, data: {session_id: thread_id}, set: {source: startup}}]\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	const hookCause = "\nthe setting can turn off the hooks Codex runs before each tool call, or make Codex run no hook for a command sent to a shell with a terminal"
	for _, r := range []struct {
		args []string
		// want is the error, empty for none.
		want string
	}{
		// Codex trims the key as a whole and splits it on each dot as it is written
		// (utils/cli/src/config_override.rs:55-57, config/src/overrides.rs:22): a
		// quoted part keeps its quotes, so these set the feature "hooks" with its
		// quotes, which Codex ignores with a warning (features/src/lib.rs:825). They
		// set no hook feature.
		{args: []string{"-c", `features."hooks"=false`}},
		{args: []string{"-c", "features.'hooks'=false"}},
		// Codex compares keys and feature names in their case (features/src/lib.rs:935,
		// legacy.rs:61): Codex ignores the key Features
		// (config/src/config_toml.rs:164-166 has no serde deny_unknown_fields).
		{args: []string{"-c", "Features.Hooks=false"}},
		{args: []string{"--config", "features.HOOKS=false"}},
		// Codex trims only the whole key (config_override.rs:57), so the parts are
		// "features " and " hooks", keys that Codex ignores.
		{args: []string{"-c", "features . hooks=false"}},
		// A space before the = is trimmed with the key, which sets features.hooks.
		{args: []string{"-c", "features.hooks =false"}, want: "remove the -c that sets features.hooks from the launch's arguments" + hookCause},
		// --enable and --disable take one feature each, with no delimiter
		// (cli/src/main.rs:971, 975), and Codex exits with Unknown feature flag:
		// hooks,undo for a name outside its list of features (main.rs:1008-1011).
		{args: []string{"--enable", "hooks,undo"}},
		{args: []string{"--disable=undo,hooks"}},
		// Codex sets no infer_long_args, so clap 4.5.58 matches a long flag only as it
		// is written (clap_builder/src/parser/parser.rs:799-815), and clap exits with an
		// unexpected-argument error for each of these.
		{args: []string{"--enab", "hooks"}},
		{args: []string{"--disab", "hooks"}},
		{args: []string{"--conf", "features.hooks=false"}},
		{args: []string{"--conf=features.hooks=false"}},
		// A -- right after -c ends the flags with -c left without a value (clap
		// parser.rs:130-145), and clap exits with an error that --config requires a
		// value (parser.rs:1341-1352). The check reads -- as the value of -c and reads
		// on, so a pair after it is refused.
		{args: []string{"-c", "--"}},
		{args: []string{"-c", "--", "-c", "features.hooks=false"}, want: "remove the -c that sets features.hooks from the launch's arguments" + hookCause},
		// After --, clap reads each argument as a positional one (parser.rs:130-145),
		// the prompt of codex exec (exec/src/cli.rs:89-90): -c sets nothing.
		{args: []string{"--", "-c", "features.hooks=false"}},
	} {
		for name, rt := range map[string]runtimes.Runtime{"the contract's descriptor": contract, "a descriptor without config": bare} {
			args := slices.Concat([]string{"exec", "--json"}, r.args, []string{"Say hi"})
			err := rt.(runtimes.ArgsChecker).CheckArgs(args)
			if (err == nil) != (r.want == "") || (err != nil && err.Error() != r.want) {
				t.Errorf("%s, %q: %v; want %q", name, args, err, r.want)
			}
		}
	}
}
