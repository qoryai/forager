package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/session/runtimes"
)

// The Claude Code descriptor's three model-key variables.
const (
	apiKeyVariable    = "ANTHROPIC_API_KEY"
	authTokenVariable = "ANTHROPIC_AUTH_TOKEN"
	oauthVariable     = "CLAUDE_CODE_OAUTH_TOKEN"
)

// modelKeys are the names of a model_key_missing refusal for Claude Code, in the order
// of its descriptor's model.keys.
var modelKeys = []string{apiKeyVariable, authTokenVariable, oauthVariable}

// modelEndpoint is the endpoint of the API credentials of these tests.
const modelEndpoint = "https://api.model.example/anthropic"

// apiKey is a run answer's credential_hosts entry for an API credential: its name,
// format, endpoint and auth, the endpoint's host as its one host, and no placeholder.
// auth is a scheme, header:name for a header, header alone for x-api-key, or oauth for
// a bearer with oauth.
func apiKey(name, format, endpoint, auth string) map[string]any {
	u, err := url.Parse(endpoint)
	if err != nil {
		panic(err)
	}
	scheme, header, _ := strings.Cut(auth, ":")
	a := map[string]any{"scheme": scheme}
	switch scheme {
	case "header":
		if header == "" {
			header = "x-api-key"
		}
		a["header"] = header
	case "oauth":
		a["scheme"], a["oauth"] = "bearer", true
	case "basic":
		a["username"] = "x"
	}
	return map[string]any{"name": name, "hosts": []string{u.Hostname()}, "placeholders": []string{}, "auth": a, "format": format, "endpoint": endpoint}
}

// model is the API credential model, an Anthropic Messages key in x-api-key.
func model() map[string]any {
	return apiKey("model", "anthropic-messages", modelEndpoint, "header")
}

// sealed is a run answer's credential_hosts entry for a host credential from the
// server: its name, hosts, placeholders and a bearer.
func sealed(name, host string, placeholders ...string) map[string]any {
	return map[string]any{"name": name, "hosts": []string{host}, "placeholders": append([]string{}, placeholders...), "auth": map[string]any{"scheme": "bearer"}}
}

// answeringWith makes the gateway's run answer carry credential_hosts and
// placeholders.
func answeringWith(g *linktest.Fake, hosts []map[string]any, placeholders []string) {
	answeringDefault(g, hosts, placeholders, "")
}

// answeringDefault is answeringWith with default_model_provider_credential_name set to
// defaultName, when defaultName is not empty.
func answeringDefault(g *linktest.Fake, hosts []map[string]any, placeholders []string, defaultName string) {
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["credential_hosts"] = hosts
		if placeholders != nil {
			a["placeholders"] = placeholders
		}
		if defaultName != "" {
			a["default_model_provider_credential_name"] = defaultName
		}
		return linktest.Reply{Status: 200, Body: a}
	})
}

// credentialVariables is the credential_variables member of the run's policy_applied,
// as credential=name lines; nil when the record has none.
func credentialVariables(t *testing.T, res *session.Result) []string {
	t.Helper()
	pa := joinApplied(events(t, res))
	if len(pa) != 1 {
		t.Fatalf("policy_applied events: %v", pa)
	}
	list, ok := data(pa[0])["credential_variables"].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, item := range list {
		e := item.(map[string]any)
		out = append(out, e["credential"].(string)+"="+e["name"].(string))
	}
	return out
}

// joinRefusedOnLink fails the test unless every dev.qory.session.exited the link got,
// one at least, is failed with -1 and code as its reason, and the link got no
// dev.qory.session.started.
func joinRefusedOnLink(t *testing.T, g *linktest.Fake, code string) {
	t.Helper()
	exited := ofType(g.Events(), "dev.qory.session.exited")
	if len(exited) == 0 {
		t.Errorf("the link got no session.exited; want one, failed, -1, %s", code)
	}
	for _, e := range exited {
		if data(e)["reason"] != code || data(e)["state"] != "failed" || data(e)["exit_code"] != float64(-1) {
			t.Errorf("the link got %v; want session.exited, failed, -1, %s", e, code)
		}
	}
	if started := ofType(g.Events(), "dev.qory.session.started"); len(started) != 0 {
		t.Errorf("the link got %v; want no session.started", started)
	}
}

// refusedWith fails the test unless err is a refusal of code with names and detail.
func refusedWith(t *testing.T, err error, code string, names []string, detail string) {
	t.Helper()
	var r *session.Refusal
	if !errors.As(err, &r) || r.Code != code || !slices.Equal(r.Names, names) {
		t.Fatalf("%v, want %s for %q", err, code, names)
	}
	if r.Detail != detail {
		t.Errorf("the refusal reads\n %q\nwant\n %q", r.Detail, detail)
	}
}

// TestTheDefaultCredentialChoosesTheVariable pins the variable an API credential gets
// for Claude Code, by its descriptor's model.keys: an Anthropic Messages key in the
// header x-api-key, compared without case, goes into ANTHROPIC_API_KEY, a bearer into
// ANTHROPIC_AUTH_TOKEN, and a bearer with oauth into CLAUDE_CODE_OAUTH_TOKEN. The
// chosen variable reaches the agent as the key's placeholder, which contains the key's
// name, and the other two do not. ANTHROPIC_BASE_URL reaches the agent as the key's
// endpoint, and the run's value of it is left out as fixed: the record's entry has from
// fixed, for the key's endpoint, and the run's value lost. The record has the
// credential's variable in credential_variables. A run without a wall is the same.
func TestTheDefaultCredentialChoosesTheVariable(t *testing.T) {
	for _, tc := range []struct {
		auth, want string
		walled     bool
	}{
		{"header", apiKeyVariable, true},
		{"header:X-Api-Key", apiKeyVariable, true},
		{"bearer", authTokenVariable, true},
		{"oauth", oauthVariable, true},
		{"header", apiKeyVariable, false},
		{"oauth", oauthVariable, false},
	} {
		t.Run(fmt.Sprintf("%s walled %v", tc.auth, tc.walled), func(t *testing.T) {
			sp, g := specGateway(t)
			out := dumpsEnv(t, &sp)
			if tc.walled {
				sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			}
			sp.Variables.Run = []string{endpointVariable + "=https://evil.example"}
			answeringWith(g, []map[string]any{apiKey("model", "anthropic-messages", modelEndpoint, tc.auth)}, nil)
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			env := envOf(t, out)
			for _, name := range modelKeys {
				value, ok := env[name]
				if name == tc.want && value != link.KeyPlaceholder("model") {
					t.Errorf("%s=%q reached the agent %v; want the key's placeholder", name, value, ok)
				}
				if name != tc.want && ok {
					t.Errorf("%s=%q reached the agent", name, value)
				}
			}
			if got := env[endpointVariable]; got != modelEndpoint {
				t.Errorf("%s=%q; want the key's endpoint", endpointVariable, got)
			}
			b, _ := json.Marshal(endpointEntry(t, res))
			if want := `{"from":"fixed","lost":[{"from":"run","why":"fixed"}],"name":"` + endpointVariable + `"}`; string(b) != want {
				t.Errorf("the record's entry %s, want %s", b, want)
			}
			if got, want := credentialVariables(t, res), []string{"model=" + tc.want}; !slices.Equal(got, want) {
				t.Errorf("credential_variables %q, want %q", got, want)
			}
		})
	}
}

// TestTheKeysEndpointTakesThePlaceOfEveryOther pins that, behind a wall, a value of
// ANTHROPIC_BASE_URL from the server, the run, the machine, the harness's defaults or
// its computed values does not reach the agent beside an API credential: the agent
// gets the key's endpoint alone, the image's value is set over, and the record's entry
// has from fixed, for the key's endpoint, and the value lost as fixed.
func TestTheKeysEndpointTakesThePlaceOfEveryOther(t *testing.T) {
	for _, source := range []string{"apiary", "run", "machine", "harness", "fixed"} {
		t.Run(source, func(t *testing.T) {
			w := &imageWall{env: []string{endpointVariable + "=https://image.invalid/"}}
			sp, g := specGateway(t)
			out := dumpsEnv(t, &sp)
			sp.Wall, sp.Image = w, "example.com/agent:1"
			passed := []string{endpointVariable + "=https://api.model.example/other"}
			var vars map[string]any
			switch source {
			case "apiary":
				vars = map[string]any{endpointVariable: map[string]any{"value": "https://api.model.example/other"}}
			case "run":
				sp.Variables.Run = passed
			case "machine":
				sp.Variables.Machine = passed
			case "harness":
				sp.LaunchDefaults = passed
			case "fixed":
				sp.LaunchFixed = passed
			}
			answering(g, []map[string]any{model()}, vars)
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if got := endpointLines(t, out); !slices.Equal(got, []string{endpointVariable + "=" + modelEndpoint}) {
				t.Errorf("the agent's environment has %q; want the key's endpoint alone", got)
			}
			if got := entriesOf(w.got.Env, endpointVariable); !slices.Equal(got, []string{endpointVariable + "=" + modelEndpoint}) {
				t.Errorf("the wall's environment has %q; want the key's endpoint alone", got)
			}
			b, _ := json.Marshal(endpointEntry(t, res))
			if want := `{"from":"fixed","lost":[{"from":"` + source + `","why":"fixed"}],"name":"` + endpointVariable + `"}`; string(b) != want {
				t.Errorf("the record's entry %s, want %s", b, want)
			}
		})
	}
}

// TestADefaultCredentialTheRuntimeDoesNotReadIsRefused pins an API credential for which
// the runtime's descriptor lists no key: a runtime with no model section, here the bare
// runtime set by name in the spec, unlike a spec with no runtime, a format the
// descriptor lists no key for, and an auth no key of the format has, by its scheme, its
// header's name or its oauth, a header's name that contains qak_ being the value's
// phrase. Each is run_configuration_invalid with the credential's name, before the
// runtime starts.
func TestADefaultCredentialTheRuntimeDoesNotReadIsRefused(t *testing.T) {
	const ways = "it reads anthropic-messages keys as the header x-api-key, a bearer or a bearer with oauth"
	for _, tc := range []struct {
		what, format, auth string
		bare               bool
		detail             string
	}{
		{"a runtime without a model section", "anthropic-messages", "header", true,
			`run a runtime whose descriptor lists a key for anthropic-messages, the API of the model key "model": the descriptor of the runtime codex has no model section`},
		{"another format", "openai-chat", "bearer", false,
			`give the model key "model" a provider whose API the runtime claude reads keys for: the descriptor of the runtime lists keys for anthropic-messages, and the key's API is openai-chat`},
		{"another header", "anthropic-messages", "header:x-model-key", false,
			`set the auth of the model key "model" to one the runtime claude reads: ` + ways + `, and the key's auth is the header x-model-key`},
		{"a header that contains qak_", "anthropic-messages", "header:qak_0123456789abcdef", false,
			`set the auth of the model key "model" to one the runtime claude reads: ` + ways + `, and the key's auth is the header (a value that contains an access key secret)`},
		{"the basic scheme", "anthropic-messages", "basic", false,
			`set the auth of the model key "model" to one the runtime claude reads: ` + ways + `, and the key's auth is the basic scheme`},
	} {
		t.Run(tc.what, func(t *testing.T) {
			sp, g := specGateway(t)
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			if tc.bare {
				sp.Runtime = runtimes.Bare("codex")
			}
			answeringWith(g, []map[string]any{apiKey("model", tc.format, modelEndpoint, tc.auth)}, nil)
			_, err := run(context.Background(), sp)
			refusedWith(t, err, "run_configuration_invalid", []string{"model"}, tc.detail)
			joinRefusedOnLink(t, g, "run_configuration_invalid")
		})
	}
}

// TestEachJoinChecksItsDefaultCredentialAgainstItsRuntime pins the check of a default
// model provider credential at each join, against the joining session's runtime alone.
// The run has two API credentials: model, of anthropic-messages, the run's default
// model provider credential, and codex-key, of openai-responses, for which Claude Code
// lists no key. The run opens, and session 1, of Claude Code with model, starts.
// Session 2, of Codex, joins with codex-key and starts. Session 3, of Claude Code,
// joins with codex-key: the join is refused, run_configuration_invalid with codex-key's
// name, and its dev.qory.session.exited is failed with exit code -1 and that reason.
// Session 4, of Claude Code with model, joins and starts after it.
func TestEachJoinChecksItsDefaultCredentialAgainstItsRuntime(t *testing.T) {
	sp, g := specGateway(t)
	answeringDefault(g, []map[string]any{model(), apiKey("codex-key", "openai-responses", "https://api.openai.example/v1", "bearer")}, nil, "model")
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatalf("the open: %v", err)
	}
	claude := func(key string) session.SessionSpec {
		s := sp.SessionSpec
		s.ModelProviderCredentialName = key
		return s
	}
	codexSession := codexSpec(t, false, filepath.Join(t.TempDir(), "codex-home"), "").SessionSpec
	codexSession.ModelProviderCredentialName = "codex-key"
	for i, s := range []session.SessionSpec{claude(""), codexSession} {
		res, err := r.Join(ctx, s)
		if err != nil || res.State != event.StateSucceeded {
			t.Fatalf("session %d: %+v, %v; want it to start and succeed", i+1, res, err)
		}
	}
	_, err = r.Join(ctx, claude("codex-key"))
	refusedWith(t, err, "run_configuration_invalid", []string{"codex-key"},
		`give the model key "codex-key" a provider whose API the runtime claude reads keys for: the descriptor of the runtime lists keys for anthropic-messages, and the key's API is openai-responses`)
	if res, err := r.Join(ctx, claude("model")); err != nil || res.State != event.StateSucceeded {
		t.Fatalf("session 4: %+v, %v; want it to start and succeed", res, err)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range ofType(g.Events(), event.SessionExited) {
		d := data(e)
		got = append(got, fmt.Sprintf("%v %v %v %v", d["session"], d["state"], d["exit_code"], d["reason"]))
	}
	want := []string{"1 succeeded 0 <nil>", "2 succeeded 0 <nil>", "3 failed -1 run_configuration_invalid", "4 succeeded 0 <nil>"}
	if !slices.Equal(got, want) {
		t.Errorf("the link got session.exited %q; want %q", got, want)
	}
	if started := ofType(g.Events(), event.SessionStarted); len(started) != 3 {
		t.Errorf("the link got %d session.started; want 3, for sessions 1, 2 and 4", len(started))
	}
}

// TestASessionWithNoRuntimeHasNoDefaultCredential pins a session whose spec has no
// runtime in a run with model keys: one key, behind a wall and without one, and two
// keys and a default_model_provider_credential_name. AgentEnv and the join pass, the
// program's environment has no model key's variable, no endpoint variable and no key's
// placeholder, and the record has no credential_variables.
func TestASessionWithNoRuntimeHasNoDefaultCredential(t *testing.T) {
	keys := []map[string]any{model(), apiKey("backup", "anthropic-messages", "https://backup.model.example", "bearer")}
	for _, tc := range []struct {
		what        string
		keys        []map[string]any
		defaultName string
		walled      bool
	}{
		{"one key, walled", keys[:1], "", true},
		{"one key, unwalled", keys[:1], "", false},
		{"two keys and a default_model_provider_credential_name", keys, "backup", true},
	} {
		t.Run(tc.what, func(t *testing.T) {
			ctx := context.Background()
			sp, g := specGateway(t)
			out := dumpsEnv(t, &sp)
			sp.Runtime, sp.RuntimeInstall = nil, nil
			if tc.walled {
				sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			}
			answeringDefault(g, tc.keys, nil, tc.defaultName)
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			agentEnv, err := r.AgentEnv(sp.SessionSpec)
			if err != nil {
				t.Fatal(err)
			}
			res, err := r.Join(ctx, sp.SessionSpec)
			if _, cerr := r.Close(ctx, outcomeOf(res, err)); cerr != nil && err == nil {
				t.Fatal(cerr)
			}
			if err != nil {
				t.Fatal(err)
			}
			placeholders := []string{link.KeyPlaceholder("model"), link.KeyPlaceholder("backup")}
			check := func(where string, env map[string]string) {
				for name, value := range env {
					if slices.Contains(modelKeys, name) || name == endpointVariable || slices.Contains(placeholders, value) {
						t.Errorf("%s has %s=%q; want no model key's variable, endpoint or placeholder", where, name, value)
					}
				}
			}
			check("the program's environment", envOf(t, out))
			fromAgentEnv := map[string]string{}
			for _, kv := range agentEnv {
				name, value, _ := strings.Cut(kv, "=")
				fromAgentEnv[name] = value
			}
			check("AgentEnv", fromAgentEnv)
			if got := credentialVariables(t, res); got != nil {
				t.Errorf("credential_variables %q, want none", got)
			}
		})
	}
}

// TestTheJoinRequestAsksForAModelKeyWithARuntime pins the join request's model_key:
// true for a session with a runtime, the Claude Code descriptor or the bare runtime
// set by name, and false for a session whose spec has no runtime.
func TestTheJoinRequestAsksForAModelKeyWithARuntime(t *testing.T) {
	for _, tc := range []struct {
		what    string
		runtime func(t *testing.T) runtimes.Runtime
		want    bool
	}{
		{"Claude Code", claudeCode, true},
		{"the bare runtime by name", func(*testing.T) runtimes.Runtime { return runtimes.Bare("sh") }, true},
		{"no runtime", func(*testing.T) runtimes.Runtime { return nil }, false},
	} {
		t.Run(tc.what, func(t *testing.T) {
			sp, g := specGateway(t)
			dumpsEnv(t, &sp)
			if sp.Runtime = tc.runtime(t); sp.Runtime == nil {
				sp.RuntimeInstall = nil
			}
			if _, err := run(context.Background(), sp); err != nil {
				t.Fatal(err)
			}
			joins := g.Joins()
			if len(joins) != 1 || joins[0].Request.ModelKey != tc.want {
				t.Fatalf("join requests %+v; want one with model_key %v", joins, tc.want)
			}
		})
	}
}

// TestASessionWithNoRuntimeNamesNoModelKey pins a spec with no runtime and a
// ModelProviderCredentialName: AgentEnv and Join each refuse it with the fix first, the
// name through accesskey.ShownName, and no join request is sent. The fake gateway
// answers such a join request 400 invalid_request, as the gateway does.
func TestASessionWithNoRuntimeNamesNoModelKey(t *testing.T) {
	ctx := context.Background()
	sp, g := specGateway(t)
	dumpsEnv(t, &sp)
	sp.Runtime, sp.ModelProviderCredentialName = nil, "backup"
	answeringDefault(g, []map[string]any{model(), apiKey("backup", "anthropic-messages", "https://backup.model.example", "bearer")}, nil, "model")
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	const want = "Set SessionSpec.Runtime, or leave SessionSpec.ModelProviderCredentialName empty.\nA session with no runtime starts with no model key, and the spec sets ModelProviderCredentialName to \"backup\""
	if _, err := r.AgentEnv(sp.SessionSpec); err == nil || err.Error() != want {
		t.Errorf("AgentEnv: %v\nwant %s", err, want)
	}
	res, err := r.Join(ctx, sp.SessionSpec)
	if err == nil || err.Error() != want {
		t.Errorf("Join: %v\nwant %s", err, want)
	}
	if joins := g.Joins(); len(joins) != 0 {
		t.Errorf("join requests %+v; want none", joins)
	}
	k, err := server.NewLocalLink(g.Local(), "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	var ref *accesskey.Refusal
	if _, err := k.Join(ctx, server.LocalOrigin+"/v1/run-configuration", r.ID(), server.LinkJoinRequest{Passes: []string{}, ModelProviderCredentialName: "backup"}); !errors.As(err, &ref) || ref.Status != 400 || ref.Code != "invalid_request" {
		t.Errorf("the fake's answer to model_key false and a model_provider_credential_name: %v", err)
	}
	r.Close(ctx, outcomeOf(res, err))
}

// TestTheNameChoosesTheDefaultCredential pins a run with two API credentials: the one
// default_model_provider_credential_name names is the default model provider
// credential, whose variable gets its placeholder and whose endpoint the runtime gets;
// the other gets no variable. Each key's placeholder differs. An answer without
// default_model_provider_credential_name, or with one that names no API credential of
// the run, is run_configuration_invalid.
func TestTheNameChoosesTheDefaultCredential(t *testing.T) {
	keys := []map[string]any{model(), apiKey("backup", "anthropic-messages", "https://backup.model.example", "bearer")}
	if link.KeyPlaceholder("model") == link.KeyPlaceholder("backup") {
		t.Fatal("two model keys have one placeholder")
	}
	for _, walled := range []bool{true, false} {
		t.Run(fmt.Sprintf("walled %v", walled), func(t *testing.T) {
			sp, g := specGateway(t)
			out := dumpsEnv(t, &sp)
			if walled {
				sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			}
			answeringDefault(g, keys, nil, "backup")
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			env := envOf(t, out)
			if env[authTokenVariable] != link.KeyPlaceholder("backup") || env[endpointVariable] != "https://backup.model.example" {
				t.Errorf("%s=%q and %s=%q; want backup's placeholder and endpoint", authTokenVariable, env[authTokenVariable], endpointVariable, env[endpointVariable])
			}
			if value, ok := env[apiKeyVariable]; ok {
				t.Errorf("%s=%q reached the agent", apiKeyVariable, value)
			}
			if got, want := credentialVariables(t, res), []string{"backup=" + authTokenVariable}; !slices.Equal(got, want) {
				t.Errorf("credential_variables %q, want %q", got, want)
			}
		})
	}
	for _, tc := range []struct {
		what, defaultName string
		names             []string
		detail            string
	}{
		{"no default_model_provider_credential_name", "", nil,
			"Set default_model_provider_credential_name, or give the run one model key.\nThe run has the model keys model, backup"},
		{"a name of no model key", "forge", []string{"forge"},
			"Set default_model_provider_credential_name to one of the run's model keys.\nThe run has the model keys model, backup, and no model key \"forge\""},
	} {
		t.Run(tc.what, func(t *testing.T) {
			sp, g := specGateway(t)
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			answeringDefault(g, append(slices.Clone(keys), sealed("forge", "api.github.com", "GITHUB_TOKEN")), []string{"GITHUB_TOKEN"}, tc.defaultName)
			_, err := run(context.Background(), sp)
			refusedWith(t, err, "run_configuration_invalid", tc.names, tc.detail)
		})
	}
}

// TestAPlaceholderGoesOnlyIntoACredentialsVariable pins that a placeholder goes only
// into a variable for a credential: a placeholder of a host credential from the server
// that is a variable Claude Code denies, lists among its model overrides or reserves,
// or reads its model endpoint from, or that is a model key's variable, is
// run_configuration_invalid with the credential's name; a machine credential with a
// model key's variable among its placeholders is too, with forager.yaml's fix. One of
// the run's placeholders that Claude Code denies, or that is a model key's variable, is
// run_configuration_invalid with the placeholder's name. A tool's placeholder,
// GITHUB_TOKEN, passes beside the default model provider credential.
func TestAPlaceholderGoesOnlyIntoACredentialsVariable(t *testing.T) {
	machine := func(name string, placeholders ...string) map[string]any {
		return map[string]any{"name": name, "hosts": []string{"llm.example"}, "placeholders": placeholders}
	}
	for _, tc := range []struct {
		what         string
		hosts        []map[string]any
		placeholders []string
		runtime      func(runtimes.Runtime) runtimes.Runtime
		names        []string
		detail       string
	}{
		{"a variable the runtime denies", []map[string]any{model(), sealed("forge", "api.github.com", "CLAUDE_CONFIG_DIR")}, []string{"CLAUDE_CONFIG_DIR"}, nil, []string{"forge"},
			`remove CLAUDE_CONFIG_DIR from the placeholders of the credential "forge" in the run configuration: the descriptor of the runtime claude lists it in denies, and a placeholder goes only into a variable for a credential`},
		{"a model override", []map[string]any{model(), sealed("forge", "api.github.com", "ANTHROPIC_MODEL")}, []string{"ANTHROPIC_MODEL"}, nil, []string{"forge"},
			`remove ANTHROPIC_MODEL from the placeholders of the credential "forge" in the run configuration: the descriptor of the runtime claude lists it in its model overrides, and a placeholder goes only into a variable for a credential`},
		{"the model endpoint's variable", []map[string]any{model(), sealed("forge", "api.github.com", endpointVariable)}, []string{endpointVariable},
			func(rt runtimes.Runtime) runtimes.Runtime { return &allowsEndpoint{Runtime: rt} }, []string{"forge"},
			`remove ANTHROPIC_BASE_URL from the placeholders of the credential "forge" in the run configuration: the descriptor of the runtime claude has it as its model endpoint's variable, and a placeholder goes only into a variable for a credential`},
		{"a variable the runtime reserves", []map[string]any{model(), sealed("forge", "api.github.com", "MODEL_SESSION")}, []string{"MODEL_SESSION"},
			func(rt runtimes.Runtime) runtimes.Runtime { return &reservesSession{Runtime: rt} }, []string{"forge"},
			`remove MODEL_SESSION from the placeholders of the credential "forge" in the run configuration: the descriptor of the runtime claude lists it in reserves, and a placeholder goes only into a variable for a credential`},
		{"a model key's variable of a host credential", []map[string]any{sealed("model", "api.anthropic.com", apiKeyVariable)}, []string{apiKeyVariable}, nil, []string{"model"},
			`remove ANTHROPIC_API_KEY from the placeholders of the credential "model" in the run configuration: the runtime claude reads a model key from it, and only a credential with an API sets it`},
		{"a second key in another credential", []map[string]any{model(), sealed("forge", "api.github.com", oauthVariable)}, []string{oauthVariable}, nil, []string{"forge"},
			`remove CLAUDE_CODE_OAUTH_TOKEN from the placeholders of the credential "forge" in the run configuration: the runtime claude reads a model key from it, and only a credential with an API sets it`},
		{"a model key's variable of a machine credential", []map[string]any{machine("machine-model", apiKeyVariable)}, []string{apiKeyVariable}, nil, []string{"machine-model"},
			`remove ANTHROPIC_API_KEY from the placeholders of the credential "machine-model" in forager.yaml: the runtime claude reads a model key from it, and only a model key sets it; a model key has format, endpoint and auth`},
		{"a key among the run's placeholders", []map[string]any{model()}, []string{oauthVariable}, nil, []string{oauthVariable},
			`remove CLAUDE_CODE_OAUTH_TOKEN from the placeholders of the machine's tools in forager.yaml: the runtime claude reads a model key from it, and only a credential with an API sets it`},
		{"a machine credential's override", []map[string]any{model(), machine("machine-helper", "ANTHROPIC_MODEL")}, []string{"ANTHROPIC_MODEL"}, nil, []string{"ANTHROPIC_MODEL"},
			`remove ANTHROPIC_MODEL from the placeholders of the machine's credentials and tools in forager.yaml: the descriptor of the runtime claude lists it in its model overrides, and a placeholder goes only into a variable for a credential`},
	} {
		t.Run(tc.what, func(t *testing.T) {
			sp, g := specGateway(t)
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			if tc.runtime != nil {
				sp.Runtime = tc.runtime(sp.Runtime)
			}
			answeringWith(g, tc.hosts, tc.placeholders)
			_, err := run(context.Background(), sp)
			refusedWith(t, err, "run_configuration_invalid", tc.names, tc.detail)
		})
	}
	t.Run("a tool's placeholder", func(t *testing.T) {
		sp, g := specGateway(t)
		out := dumpsEnv(t, &sp)
		sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		answeringWith(g, []map[string]any{model(), sealed("forge", "api.github.com", "GITHUB_TOKEN")}, []string{"GITHUB_TOKEN"})
		res, err := run(context.Background(), sp)
		if err != nil {
			t.Fatal(err)
		}
		env := envOf(t, out)
		if env["GITHUB_TOKEN"] != link.Placeholder || env[apiKeyVariable] != link.KeyPlaceholder("model") {
			t.Errorf("GITHUB_TOKEN=%q and %s=%q; want the placeholder and the key's placeholder", env["GITHUB_TOKEN"], apiKeyVariable, env[apiKeyVariable])
		}
		if got, want := credentialVariables(t, res), []string{"model=" + apiKeyVariable, "forge=GITHUB_TOKEN"}; !slices.Equal(got, want) {
			t.Errorf("credential_variables %q, want %q", got, want)
		}
	})
}

// reservesSession is Claude Code with a descriptor that reserves MODEL_SESSION.
type reservesSession struct{ runtimes.Runtime }

func (p *reservesSession) Secrets() runtimes.Declarations {
	d := p.Runtime.(runtimes.Secrets).Secrets()
	d.Reserves = append(slices.Clone(d.Reserves), "MODEL_SESSION")
	return d
}

func (p *reservesSession) Model() (runtimes.ModelPlaces, bool) {
	return p.Runtime.(runtimes.Model).Model()
}

// allowsEndpoint is Claude Code with a descriptor whose denies leave out its model
// endpoint's variable.
type allowsEndpoint struct{ runtimes.Runtime }

func (p *allowsEndpoint) Secrets() runtimes.Declarations {
	d := p.Runtime.(runtimes.Secrets).Secrets()
	d.Denies = slices.DeleteFunc(slices.Clone(d.Denies), func(n string) bool { return n == endpointVariable })
	return d
}

func (p *allowsEndpoint) Model() (runtimes.ModelPlaces, bool) {
	return p.Runtime.(runtimes.Model).Model()
}

// TestTheChosenVariableIsAPlaceholder pins that the chosen variable is one of the run's
// placeholders for all that follows: a value the run or the machine passes for it is
// placeholder_conflict, and the runtime's preparation gets it among the placeholders,
// which is what Claude Code's approval script keys on.
func TestTheChosenVariableIsAPlaceholder(t *testing.T) {
	for _, source := range []string{"run", "machine"} {
		t.Run("a value from the "+source, func(t *testing.T) {
			sp, g := specGateway(t)
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			passed := []string{apiKeyVariable + "=sk-ant-a-key-of-the-test"}
			if source == "run" {
				sp.Variables.Run = passed
			} else {
				sp.Variables.Machine = passed
			}
			answeringWith(g, []map[string]any{model()}, nil)
			_, err := run(context.Background(), sp)
			var r *session.Refusal
			if !errors.As(err, &r) || r.Code != "placeholder_conflict" || !slices.Equal(r.Names, []string{apiKeyVariable}) {
				t.Fatalf("%v, want placeholder_conflict for %s", err, apiKeyVariable)
			}
		})
	}
	t.Run("the preparation", func(t *testing.T) {
		sp, g := specGateway(t, "FAKE_EXIT=0")
		rec := &recordsPrepare{Runtime: claudeCode(t)}
		sp.Runtime = rec
		sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		answeringWith(g, []map[string]any{model()}, nil)
		if _, err := run(context.Background(), sp); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(rec.got.Placeholders, apiKeyVariable) {
			t.Errorf("the preparation got the placeholders %q; want %s among them", rec.got.Placeholders, apiKeyVariable)
		}
	})
}

// recordsPrepare is a runtime that records what its preparation is given.
type recordsPrepare struct {
	runtimes.Runtime
	got runtimes.Attach
}

func (p *recordsPrepare) Prepare(a runtimes.Attach) (runtimes.Launch, error) {
	p.got = a
	return p.Runtime.Prepare(a)
}

func (p *recordsPrepare) Secrets() runtimes.Declarations {
	return p.Runtime.(runtimes.Secrets).Secrets()
}

func (p *recordsPrepare) Model() (runtimes.ModelPlaces, bool) {
	return p.Runtime.(runtimes.Model).Model()
}

// TestAWalledRunNeedsAModelKey pins the session's check that a walled run whose gateway
// holds credentials for it has a model key for its runtime: an API credential. A run
// without credential_hosts is not checked, nor is a run without a wall: its runtime may
// use the developer's login. A value the harness or the runtime's preparation sets to
// empty is no model key, and neither is a value of one of the model keys' variables from
// the run or the machine, which the deny list's model_keys leave out. The refusal is
// model_key_missing with the model keys' variables, and quotes no value.
func TestAWalledRunNeedsAModelKey(t *testing.T) {
	forge := sealed("forge", "api.github.com", "GITHUB_TOKEN")
	for _, tc := range []struct {
		what    string
		walled  bool
		hosts   []map[string]any
		edit    func(*runSpec)
		refused bool
	}{
		{"walled, no model key", true, []map[string]any{forge}, nil, true},
		{"walled, a key the harness sets to empty", true, []map[string]any{forge}, func(sp *runSpec) {
			sp.LaunchFixed = append(sp.LaunchFixed, authTokenVariable+"=")
		}, true},
		{"walled, a key the preparation sets to empty", true, []map[string]any{forge}, func(sp *runSpec) {
			sp.Runtime = &preparesEmpty{Runtime: sp.Runtime}
		}, true},
		{"unwalled, only a forge credential", false, []map[string]any{forge}, nil, false},
		{"unwalled, no credential_hosts", false, nil, nil, false},
		{"unwalled, an API credential", false, []map[string]any{forge, model()}, nil, false},
		{"walled, no credential_hosts", true, nil, nil, false},
		{"walled, an API credential", true, []map[string]any{forge, model()}, nil, false},
		{"walled, a value from the machine", true, []map[string]any{forge}, func(sp *runSpec) {
			sp.Variables.Machine = []string{apiKeyVariable + "=sk-ant-a-key-of-the-test"}
		}, true},
		{"walled, a value from the run", true, []map[string]any{forge}, func(sp *runSpec) {
			sp.Variables.Run = []string{oauthVariable + "=sk-ant-oat-a-key-of-the-test"}
		}, true},
	} {
		t.Run(tc.what, func(t *testing.T) {
			sp, g := specGateway(t, "FAKE_EXIT=0")
			if tc.walled {
				sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			}
			if tc.edit != nil {
				tc.edit(&sp)
			}
			if tc.hosts == nil {
				answering(g, nil, nil)
			} else {
				answeringWith(g, tc.hosts, []string{"GITHUB_TOKEN"})
			}
			_, err := run(context.Background(), sp)
			if !tc.refused {
				if err != nil {
					t.Fatalf("%v, want the run", err)
				}
				return
			}
			refusedWith(t, err, "model_key_missing", modelKeys,
				"give the run a model key for the runtime claude, in the run configuration or in forager.yaml: the gateway holds credentials for the run, and none of them is a model key; a model key has format, endpoint and auth")
			if strings.Contains(err.Error(), "sk-ant") {
				t.Errorf("the refusal quotes a value: %v", err)
			}
			joinRefusedOnLink(t, g, "model_key_missing")
		})
	}
}

// preparesEmpty is a runtime whose preparation sets ANTHROPIC_AUTH_TOKEN to empty.
type preparesEmpty struct{ runtimes.Runtime }

func (p *preparesEmpty) Prepare(a runtimes.Attach) (runtimes.Launch, error) {
	l, err := p.Runtime.Prepare(a)
	l.Env = append(slices.Clone(l.Env), authTokenVariable+"=")
	return l, err
}

func (p *preparesEmpty) Secrets() runtimes.Declarations {
	return p.Runtime.(runtimes.Secrets).Secrets()
}

func (p *preparesEmpty) Model() (runtimes.ModelPlaces, bool) {
	return p.Runtime.(runtimes.Model).Model()
}

// TestTheRecordOfCredentialVariablesHoldsNoSecret pins that credential_variables has a
// name's phrase in place of a credential's name or a placeholder that contains an
// access key secret or a run key, and keeps the others as they are.
func TestTheRecordOfCredentialVariablesHoldsNoSecret(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	secret := "qak_0123456789abcdef"
	answeringWith(g, []map[string]any{
		model(),
		sealed("helper", "helper.example", secret),
		sealed("qrk_forge", "api.github.com", "GITHUB_TOKEN"),
	}, []string{secret, "GITHUB_TOKEN"})
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"model=" + apiKeyVariable, "helper=(a name that contains an access key secret)", "(a name that contains a run key)=GITHUB_TOKEN"}
	if got := credentialVariables(t, res); !slices.Equal(got, want) {
		t.Errorf("credential_variables %q, want %q", got, want)
	}
}

// TestAnInheritedKeyAndEndpointGiveWayToTheDefaultCredential pins that, without a wall,
// values the run inherits of the default model provider credential's variable and of
// ANTHROPIC_BASE_URL do not reach the agent: the key's placeholder and its endpoint are
// set over them.
func TestAnInheritedKeyAndEndpointGiveWayToTheDefaultCredential(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0", apiKeyVariable+"=sk-fake-inherited", endpointVariable+"=https://other.example")
	out := dumpsEnv(t, &sp)
	answeringWith(g, []map[string]any{model(), sealed("forge", "api.github.com", "GITHUB_TOKEN")}, []string{"GITHUB_TOKEN"})
	if _, err := run(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	env := envOf(t, out)
	if env[apiKeyVariable] != link.KeyPlaceholder("model") || env[endpointVariable] != modelEndpoint {
		t.Errorf("%s=%q and %s=%q; want the key's placeholder and endpoint", apiKeyVariable, env[apiKeyVariable], endpointVariable, env[endpointVariable])
	}
}

// variableEntry is the entry of the run's policy_applied variables for name, nil when
// the record lists none.
func variableEntry(t *testing.T, res *session.Result, name string) map[string]any {
	t.Helper()
	pa := joinApplied(events(t, res))
	if len(pa) != 1 {
		t.Fatalf("policy_applied events: %v", pa)
	}
	list, _ := data(pa[0])["variables"].([]any)
	for _, item := range list {
		if e := item.(map[string]any); e["name"] == name {
			return e
		}
	}
	return nil
}

// TestOtherKeyVariablesDoNotReachTheRuntime pins that, beside a default model provider
// credential, a value of each other model-key variable of Claude Code reaches the agent
// from no source: the server, the run, the machine, the harness's defaults and its
// computed values, the inherited environment and, behind a wall, the image. Behind a
// wall each name is unset inside. The record has each value lost as fixed, with no
// from. It runs once for a default model provider credential in ANTHROPIC_API_KEY, and
// once for a bearer default model provider credential in ANTHROPIC_AUTH_TOKEN, whose
// others include ANTHROPIC_API_KEY.
func TestOtherKeyVariablesDoNotReachTheRuntime(t *testing.T) {
	const value = "sk-fake-dev-token"
	for _, key := range []struct{ auth, variable string }{{"header", apiKeyVariable}, {"bearer", authTokenVariable}} {
		var others []string
		for _, k := range modelKeys {
			if k != key.variable {
				others = append(others, k)
			}
		}
		withValue := func() []string {
			out := make([]string, len(others))
			for i, k := range others {
				out[i] = k + "=" + value
			}
			return out
		}
		for _, source := range []string{"apiary", "run", "machine", "harness", "fixed", "shell", "image"} {
			for _, walled := range []bool{true, false} {
				if source == "image" && !walled {
					continue
				}
				t.Run(fmt.Sprintf("%s default %s walled %v", source, key.auth, walled), func(t *testing.T) {
					var env []string
					if source == "shell" {
						env = withValue()
					}
					sp, g := specGateway(t, env...)
					out := dumpsEnv(t, &sp)
					w := &imageWall{}
					if source == "image" {
						w.env = withValue()
					}
					if walled {
						sp.Wall, sp.Image = w, "example.com/agent:1"
					}
					var vars map[string]any
					switch source {
					case "apiary":
						vars = map[string]any{}
						for _, k := range others {
							vars[k] = map[string]any{"value": value}
						}
					case "run":
						sp.Variables.Run = withValue()
					case "machine":
						sp.Variables.Machine = withValue()
					case "harness":
						sp.LaunchDefaults = withValue()
					case "fixed":
						sp.LaunchFixed = withValue()
					}
					answering(g, []map[string]any{apiKey("model", "anthropic-messages", modelEndpoint, key.auth)}, vars)
					res, err := run(context.Background(), sp)
					if err != nil {
						t.Fatal(err)
					}
					got := envOf(t, out)
					if got[key.variable] != link.KeyPlaceholder("model") {
						t.Errorf("%s=%q; want the default model provider credential's placeholder", key.variable, got[key.variable])
					}
					var names []string
					if walled {
						names, _ = unsetIn(t, w.got)
					}
					for _, k := range others {
						if v, ok := got[k]; ok {
							t.Errorf("%s=%q reached the agent", k, v)
						}
						if walled && (!slices.Contains(names, k) || slices.Contains(entriesOf(w.got.Env, k), k+"="+value)) {
							t.Errorf("unset %q, the wall's environment %q; want %s unset and not set", names, entriesOf(w.got.Env, k), k)
						}
						if source == "image" {
							continue
						}
						b, _ := json.Marshal(variableEntry(t, res, k))
						if want := `{"lost":[{"from":"` + source + `","why":"fixed"}],"name":"` + k + `"}`; string(b) != want {
							t.Errorf("the record's entry %s, want %s", b, want)
						}
					}
				})
			}
		}
	}
}

// TestAPreparationsOtherKeyVariablesDoNotReachTheRuntime pins that, beside a default
// model provider credential in ANTHROPIC_API_KEY, a value the runtime's preparation
// sets for ANTHROPIC_AUTH_TOKEN or CLAUDE_CODE_OAUTH_TOKEN does not reach the agent,
// with or without a wall. Behind a wall each name is unset inside and not set.
func TestAPreparationsOtherKeyVariablesDoNotReachTheRuntime(t *testing.T) {
	others := []string{authTokenVariable, oauthVariable}
	for _, walled := range []bool{true, false} {
		t.Run(fmt.Sprintf("walled %v", walled), func(t *testing.T) {
			sp, g := specGateway(t)
			out := dumpsEnv(t, &sp)
			sp.Runtime = &preparesKeys{Runtime: sp.Runtime, keys: others}
			w := &imageWall{}
			if walled {
				sp.Wall, sp.Image = w, "example.com/agent:1"
			}
			answering(g, []map[string]any{model()}, nil)
			if _, err := run(context.Background(), sp); err != nil {
				t.Fatal(err)
			}
			got := envOf(t, out)
			if got[apiKeyVariable] != link.KeyPlaceholder("model") {
				t.Errorf("%s=%q; want the default model provider credential's placeholder", apiKeyVariable, got[apiKeyVariable])
			}
			var names []string
			if walled {
				names, _ = unsetIn(t, w.got)
			}
			for _, k := range others {
				if v, ok := got[k]; ok {
					t.Errorf("%s=%q reached the agent", k, v)
				}
				if walled && (!slices.Contains(names, k) || len(entriesOf(w.got.Env, k)) > 0) {
					t.Errorf("unset %q, the wall's environment %q; want %s unset and not set", names, entriesOf(w.got.Env, k), k)
				}
			}
		})
	}
}

// preparesKeys is a runtime whose preparation sets each of keys to a fake value.
type preparesKeys struct {
	runtimes.Runtime
	keys []string
}

func (p *preparesKeys) Prepare(a runtimes.Attach) (runtimes.Launch, error) {
	l, err := p.Runtime.Prepare(a)
	l.Env = slices.Clone(l.Env)
	for _, k := range p.keys {
		l.Env = append(l.Env, k+"=sk-fake-prepared")
	}
	return l, err
}

func (p *preparesKeys) Secrets() runtimes.Declarations {
	return p.Runtime.(runtimes.Secrets).Secrets()
}

func (p *preparesKeys) Model() (runtimes.ModelPlaces, bool) {
	return p.Runtime.(runtimes.Model).Model()
}

// TestTheSettingsEnvSetsNoModelKeyVariable pins that the run's settings.json keeps no
// value of a Claude Code model-key variable, of a forge token's variable or of
// ANTHROPIC_BASE_URL from the env object of the --settings file, which Claude Code
// applies over its environment, and keeps the other members and the hooks, with or
// without a default model provider credential, and that the env sets the descriptor's
// fixed variable. The run reports a line for each forge token's or model key's name it
// leaves out, apart from the default model provider credential's variables.
func TestTheSettingsEnvSetsNoModelKeyVariable(t *testing.T) {
	env := map[string]any{
		authTokenVariable:    "sk-fake-auth-token",
		oauthVariable:        "sk-fake-oauth-token",
		apiKeyVariable:       "sk-fake-api-key",
		"ANTHROPIC_BASE_URL": "https://settings.invalid/anthropic",
		"QORY_TEST_KEPT":     "kept",
		"GH_TOKEN":           "ghp_" + strings.Repeat("x", 36),
	}
	line := func(name, kind string) string {
		return "Move " + name + " to the gateway's credentials in forager.yaml: the run leaves out the value that the env of --settings passes, since denied-variables.json lists it as a " + kind + "."
	}
	for _, c := range []struct {
		name  string
		hosts []map[string]any
		lines []string
	}{
		{"default model provider credential", []map[string]any{model()}, []string{line("GH_TOKEN", "forge token")}},
		{"no default model provider credential", nil, []string{line(apiKeyVariable, "model key"), line(authTokenVariable, "model key"),
			line(oauthVariable, "model key"), line("GH_TOKEN", "forge token")}},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp, g := specGateway(t)
			var reported []string
			sp.Report = func(l string) {
				if strings.HasPrefix(l, "Move ") {
					reported = append(reported, l)
				}
			}
			passed := filepath.Join(t.TempDir(), "launch-settings.json")
			b, _ := json.Marshal(map[string]any{"env": env, "permissions": map[string]any{"allow": []string{"Bash"}}})
			if err := os.WriteFile(passed, b, 0o644); err != nil {
				t.Fatal(err)
			}
			sp.Args = []string{"--settings", passed}
			answering(g, c.hosts, nil)
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			b, _ = os.ReadFile(filepath.Join(res.SessionDir, "settings.json"))
			var doc struct {
				Env         map[string]any `json:"env"`
				Permissions map[string]any `json:"permissions"`
				Hooks       map[string]any `json:"hooks"`
			}
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			if got, want := must(json.Marshal(doc.Env)), `{"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC":"1","CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL":"1","CLAUDE_CODE_MAX_RETRIES":"15","DISABLE_AUTOUPDATER":"1","QORY_TEST_KEPT":"kept"}`; string(got) != want {
				t.Errorf("env is %s, want %s", got, want)
			}
			if !slices.Equal(reported, c.lines) {
				t.Errorf("the run reported\n%q\nwant\n%q", reported, c.lines)
			}
			if doc.Permissions == nil || len(doc.Hooks) == 0 || !strings.Contains(string(b), os.Args[0]) {
				t.Errorf("settings.json without the launch's permissions or the hooks:\n%s", b)
			}
		})
	}
}

// TestTheSettingsCopyKeepsNoCredentialHelper pins that, beside an OAuth default model
// provider credential, the run's settings.json keeps none of apiKeyHelper,
// awsAuthRefresh, awsCredentialExport, gcpAuthRefresh and modelOverrides from the
// --settings file: Claude Code ranks the key helper's output above
// CLAUDE_CODE_OAUTH_TOKEN, and the others set cloud credentials or model ids. Without a
// default model provider credential the copy keeps them.
func TestTheSettingsCopyKeepsNoCredentialHelper(t *testing.T) {
	helpers := map[string]any{
		"apiKeyHelper":        "/bin/echo sk-fake-helper-key",
		"awsAuthRefresh":      "/bin/true",
		"awsCredentialExport": "/bin/true",
		"gcpAuthRefresh":      "/bin/true",
		"modelOverrides":      map[string]any{"claude-fake": "fake-provider-model"},
	}
	for _, c := range []struct {
		name  string
		hosts []map[string]any
		kept  bool
	}{
		{"oauth default model provider credential", []map[string]any{apiKey("model", "anthropic-messages", modelEndpoint, "oauth")}, false},
		{"no default model provider credential", nil, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp, g := specGateway(t)
			passed := filepath.Join(t.TempDir(), "launch-settings.json")
			doc := map[string]any{"permissions": map[string]any{"allow": []string{"Bash"}}}
			for k, v := range helpers {
				doc[k] = v
			}
			if err := os.WriteFile(passed, must(json.Marshal(doc)), 0o644); err != nil {
				t.Fatal(err)
			}
			sp.Args = []string{"--settings", passed}
			answering(g, c.hosts, nil)
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(filepath.Join(res.SessionDir, "settings.json"))
			var got map[string]any
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatal(err)
			}
			for name, want := range helpers {
				v, ok := got[name]
				switch {
				case c.kept && string(must(json.Marshal(v))) != string(must(json.Marshal(want))):
					t.Errorf("%s is %v, want %v", name, v, want)
				case !c.kept && ok:
					t.Errorf("%s is %v in the run's settings.json", name, v)
				}
			}
			if got["permissions"] == nil || got["hooks"] == nil {
				t.Errorf("settings.json without the launch's permissions or the hooks:\n%s", b)
			}
		})
	}
}

// TestTheSettingsEnvSetsNoDeniedVariable pins that the run's settings.json keeps no
// value of a variable Claude Code's descriptor denies, in any case, from the env object
// of the --settings file, walled or not, and behind a wall none of a variable of its
// model overrides either, as the session leaves those names out of the process
// environment. Without a wall an override's value is kept. The env also sets the
// descriptor's fixed variables.
func TestTheSettingsEnvSetsNoDeniedVariable(t *testing.T) {
	env := map[string]any{
		"CLAUDE_CONFIG_DIR":        "/settings/config",
		"anthropic_custom_headers": "X-Fake: 1",
		"ANTHROPIC_MODEL":          "fake-model",
		"QORY_TEST_KEPT":           "kept",
	}
	for _, c := range []struct {
		name   string
		walled bool
		want   map[string]any
	}{
		{"walled", true, map[string]any{nonessential: "1", marketplace: "1", maxRetries: "15", autoUpdater: "1", "QORY_TEST_KEPT": "kept"}},
		{"unwalled", false, map[string]any{"ANTHROPIC_MODEL": "fake-model", nonessential: "1", marketplace: "1", maxRetries: "15", autoUpdater: "1", "QORY_TEST_KEPT": "kept"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp, g := specGateway(t)
			if c.walled {
				sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			}
			passed := filepath.Join(t.TempDir(), "launch-settings.json")
			if err := os.WriteFile(passed, must(json.Marshal(map[string]any{"env": env})), 0o644); err != nil {
				t.Fatal(err)
			}
			sp.Args = []string{"--settings", passed}
			answering(g, nil, nil)
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(filepath.Join(res.SessionDir, "settings.json"))
			var doc struct {
				Env map[string]any `json:"env"`
			}
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			if got, want := must(json.Marshal(doc.Env)), must(json.Marshal(c.want)); string(got) != string(want) {
				t.Errorf("env is %s, want %s", got, want)
			}
		})
	}
}
