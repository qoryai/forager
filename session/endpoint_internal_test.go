package session

import (
	"slices"
	"testing"

	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/claude"
	"github.com/qoryai/forager/session/runtimes/codex"
)

// TestAnEndpointSettingSetsNoVariable pins that the start key of a runtime whose
// descriptor has its model endpoint in a setting sets no endpoint variable: the key's
// variable gets its placeholder, keyed.Endpoint stays empty, and keyed.Setting and
// keyed.URL are the setting and the key's endpoint, where a runtime whose endpoint is
// a variable gets VARIABLE=<endpoint> and no setting.
func TestAnEndpointSettingSetsNoVariable(t *testing.T) {
	described := func(endpoint string) runtimes.Runtime {
		t.Helper()
		d := "version: 1\nruntime: r\nruntime_version: \"1\"\nsources:\n  output: {format: jsonl}\n" +
			"model:\n  formats: [openai-responses]\n  model: {flag: --model}\n  endpoint: " + endpoint + "\n" +
			"  keys: [{format: openai-responses, auth: {scheme: bearer}, variable: R_API_KEY}]\n" +
			"rules:\n  - source: output\n    match: {type: start}\n    type: dev.qory.runtime.started\n    data: {session_id: session_id}\n"
		rt, err := runtimes.Described("r.yaml", []byte(d), nil)
		if err != nil {
			t.Fatal(err)
		}
		return rt
	}
	creds := []server.LinkCredentialHosts{{Name: "model", Hosts: []string{"api.model.example"},
		Auth: &server.Auth{Scheme: "bearer"}, Format: "openai-responses", Endpoint: "https://api.model.example/v1"}}
	for _, c := range []struct{ endpoint, want, setting, url string }{
		{"{setting: providers.r.base_url}", "", "providers.r.base_url", "https://api.model.example/v1"},
		{"{variable: R_BASE_URL}", "R_BASE_URL=https://api.model.example/v1", "", ""},
	} {
		_, _, key, err := chosen(described(c.endpoint), false, creds, nil, "")
		if err != nil {
			t.Fatalf("%s: %v", c.endpoint, err)
		}
		if key.Endpoint != c.want || key.Variable == "" || key.endpointName() != (map[bool]string{true: "R_BASE_URL"})[c.want != ""] ||
			key.Setting != c.setting || key.URL != c.url {
			t.Errorf("%s: key %+v; want Endpoint %q, Setting %q, URL %q and a Variable", c.endpoint, key, c.want, c.setting, c.url)
		}
	}
}

// TestConfigPairsGoBeforeTheLaunchsArguments pins configArgs: Codex gets its fixed
// settings and the start key's endpoint as --config pairs right after the command,
// before the subcommand, and its fixed settings alone in a run without a start key;
// a runtime without config, Claude Code, gets its arguments as they are.
func TestConfigPairsGoBeforeTheLaunchsArguments(t *testing.T) {
	cx, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	creds := []server.LinkCredentialHosts{{Name: "model", Hosts: []string{"api.model.example"},
		Auth: &server.Auth{Scheme: "bearer", OAuth: true}, Format: "openai-responses", Endpoint: "https://api.model.example/v1"}}
	_, _, key, err := chosen(cx, false, creds, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	launch := []string{"exec", "--json", "--model", "gpt-test", "Say hi"}
	got, err := configArgs(cx, key, launch)
	if err != nil {
		t.Fatal(err)
	}
	n := len(got) - len(launch)
	if n != 28 || !slices.Equal(got[n:], launch) || got[0] != "--config" {
		t.Fatalf("args %q; want 14 --config pairs, then %q", got, launch)
	}
	if !slices.Contains(got[:n], `model_providers.qory.base_url="https://api.model.example/v1"`) || !slices.Contains(got[:n], `model_provider="qory"`) {
		t.Errorf("args %q have no endpoint or no provider", got)
	}
	got, err = configArgs(cx, keyed{}, launch)
	if err != nil || len(got) != 26+len(launch) || slices.ContainsFunc(got, func(a string) bool { return a == `model_providers.qory.base_url="https://api.model.example/v1"` }) {
		t.Errorf("without a start key: %q, %v; want the 13 fixed pairs alone", got, err)
	}
	cl, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := configArgs(cl, keyed{}, launch); err != nil || !slices.Equal(got, launch) {
		t.Errorf("Claude Code: %q, %v; want the arguments as they are", got, err)
	}
	if got, err := configArgs(runtimes.Bare("amp"), key, launch); err != nil || !slices.Equal(got, launch) {
		t.Errorf("a bare runtime: %q, %v; want the arguments as they are", got, err)
	}
}
