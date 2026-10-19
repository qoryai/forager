package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

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

// modelKeys are the names of a model_key_missing refusal for Claude Code.
var modelKeys = []string{apiKeyVariable, authTokenVariable, oauthVariable}

// sealed is a run answer's credential_hosts entry for a credential from the server:
// its name, hosts and placeholders, and its key_form and auth when keyForm is not
// empty.
func sealed(name, host, keyForm, scheme string, placeholders ...string) map[string]any {
	e := map[string]any{"name": name, "hosts": []string{host}, "placeholders": append([]string{}, placeholders...)}
	if keyForm != "" {
		auth := map[string]any{"scheme": scheme}
		if scheme == "header" {
			auth["header"] = "x-api-key"
		}
		e["key_form"], e["auth"] = keyForm, auth
	}
	return e
}

// answeringWith makes the gateway's run answer carry credential_hosts and
// placeholders.
func answeringWith(g *linktest.Fake, hosts []map[string]any, placeholders []string) {
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["credential_hosts"] = hosts
		if placeholders != nil {
			a["placeholders"] = placeholders
		}
		return linktest.Reply{Status: 200, Body: a}
	})
}

// credentialVariables is the credential_variables member of the run's policy_applied,
// as credential=name lines; nil when the record has none.
func credentialVariables(t *testing.T, res *session.Result) []string {
	t.Helper()
	pa := ofType(events(t, res), "dev.qory.run.policy_applied")
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

// TestTheKeyFormChoosesTheVariable pins the variable a credential from the server with
// key_form gets for Claude Code, by its key_form and auth.scheme: api_key in a header
// is ANTHROPIC_API_KEY, api_key as a bearer ANTHROPIC_AUTH_TOKEN, and access_token as a
// bearer CLAUDE_CODE_OAUTH_TOKEN. The credential lists no placeholder. The chosen
// variable reaches the agent as the placeholder, the other two do not, the run's
// ANTHROPIC_BASE_URL for the credential's host is kept, and the record has the
// credential's variable in credential_variables.
func TestTheKeyFormChoosesTheVariable(t *testing.T) {
	for _, tc := range []struct{ keyForm, scheme, want string }{
		{"api_key", "header", apiKeyVariable},
		{"api_key", "bearer", authTokenVariable},
		{"access_token", "bearer", oauthVariable},
	} {
		t.Run(tc.keyForm+" as "+tc.scheme, func(t *testing.T) {
			sp, g := specGateway(t)
			out := dumpsEnv(t, &sp)
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			sp.Variables.Run = []string{endpointVariable + "=https://openrouter.ai/api"}
			answeringWith(g, []map[string]any{sealed("model", "openrouter.ai", tc.keyForm, tc.scheme)}, nil)
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			env := envOf(t, out)
			for _, name := range modelKeys {
				value, ok := env[name]
				if name == tc.want && value != link.Placeholder {
					t.Errorf("%s=%q reached the agent %v; want the placeholder", name, value, ok)
				}
				if name != tc.want && ok {
					t.Errorf("%s=%q reached the agent", name, value)
				}
			}
			if got := env[endpointVariable]; got != "https://openrouter.ai/api" {
				t.Errorf("%s=%q; want the run's value", endpointVariable, got)
			}
			b, _ := json.Marshal(endpointEntry(t, res))
			if want := `{"from":"run","kept":{"credential":"model","why":"endpoint_covered"},"lost":[],"name":"` + endpointVariable + `"}`; string(b) != want {
				t.Errorf("the record's entry %s, want %s", b, want)
			}
			if got, want := credentialVariables(t, res), []string{"model=" + tc.want}; !slices.Equal(got, want) {
				t.Errorf("credential_variables %q, want %q", got, want)
			}
		})
	}
}

// TestAKeyFormTheRuntimeDoesNotReadIsRefused pins a credential from the server whose
// key_form and auth.scheme no declaration of the runtime's takes: access_token in a
// header for Claude Code, and any key_form for a runtime that declares no model key,
// each run_configuration_invalid with the credential's name, before the runtime starts.
func TestAKeyFormTheRuntimeDoesNotReadIsRefused(t *testing.T) {
	for _, tc := range []struct {
		what    string
		bare    bool
		keyForm string
		scheme  string
		detail  string
	}{
		{"access_token in a header", false, "access_token", "header",
			`give the credential "model" in Qory Apiary's run configuration a key_form and auth.scheme that the runtime claude reads: api_key in a header for ANTHROPIC_API_KEY, access_token as a bearer for CLAUDE_CODE_OAUTH_TOKEN, or api_key as a bearer for ANTHROPIC_AUTH_TOKEN; the credential has access_token in a header`},
		{"a runtime without a model key", true, "api_key", "header",
			`leave key_form out of the credential "model" in Qory Apiary's run configuration, or run a runtime that reads a model key: the runtime codex declares no variable for one`},
	} {
		t.Run(tc.what, func(t *testing.T) {
			sp, g := specGateway(t)
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			if tc.bare {
				sp.Runtime = runtimes.Bare("codex")
			}
			answeringWith(g, []map[string]any{sealed("model", "api.anthropic.com", tc.keyForm, tc.scheme)}, nil)
			_, err := session.Run(context.Background(), sp)
			var r *session.Refusal
			if !errors.As(err, &r) || r.Code != "run_configuration_invalid" || !slices.Equal(r.Names, []string{"model"}) {
				t.Fatalf("%v, want run_configuration_invalid for model", err)
			}
			if r.Detail != tc.detail {
				t.Errorf("the refusal reads\n %q\nwant\n %q", r.Detail, tc.detail)
			}
		})
	}
}

// TestAKeyFormCredentialsPlaceholders pins the both-members rule: a placeholder of
// another variable the runtime declares is run_configuration_invalid, the chosen
// variable listed as a placeholder too is set once, and a placeholder the runtime does
// not declare stays beside the chosen one.
func TestAKeyFormCredentialsPlaceholders(t *testing.T) {
	t.Run("another declared variable", func(t *testing.T) {
		sp, g := specGateway(t)
		sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		answeringWith(g, []map[string]any{sealed("model", "api.anthropic.com", "api_key", "header", oauthVariable)}, []string{oauthVariable})
		_, err := session.Run(context.Background(), sp)
		var r *session.Refusal
		if !errors.As(err, &r) || r.Code != "run_configuration_invalid" || !slices.Equal(r.Names, []string{"model"}) {
			t.Fatalf("%v, want run_configuration_invalid for model", err)
		}
		want := `remove CLAUDE_CODE_OAUTH_TOKEN from the placeholders of the credential "model" in Qory Apiary's run configuration: its key_form api_key and auth.scheme header choose ANTHROPIC_API_KEY for the runtime claude, and a model key goes into one variable`
		if r.Detail != want {
			t.Errorf("the refusal reads\n %q\nwant\n %q", r.Detail, want)
		}
	})
	for _, tc := range []struct {
		what         string
		placeholders []string
		want         []string
	}{
		{"the chosen variable", []string{apiKeyVariable}, []string{"model=" + apiKeyVariable}},
		{"a variable the runtime does not declare", []string{"MODEL_HELPER"}, []string{"model=MODEL_HELPER", "model=" + apiKeyVariable}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			sp, g := specGateway(t)
			w := &openWall{}
			sp.Wall, sp.Image = w, "example.com/agent:1"
			out := dumpsEnv(t, &sp)
			answeringWith(g, []map[string]any{sealed("model", "api.anthropic.com", "api_key", "header", tc.placeholders...)}, tc.placeholders)
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			env := envOf(t, out)
			for _, name := range append(tc.placeholders, apiKeyVariable) {
				if env[name] != link.Placeholder {
					t.Errorf("%s=%q; want the placeholder", name, env[name])
				}
			}
			if got := entriesOf(w.got.Env, apiKeyVariable); len(got) != 1 {
				t.Errorf("the wall's environment has %q; want one entry", got)
			}
			if got := credentialVariables(t, res); !slices.Equal(got, tc.want) {
				t.Errorf("credential_variables %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTheChosenVariableIsAPlaceholder pins that the chosen variable is one of the run's
// placeholders for all that follows: a value the run or the machine passes for it is
// placeholder_conflict, and the runtime's preparation gets it among the placeholders,
// which is what Claude Code's approval script keys on.
func TestTheChosenVariableIsAPlaceholder(t *testing.T) {
	hosts := []map[string]any{sealed("model", "api.anthropic.com", "api_key", "header")}
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
			answeringWith(g, hosts, nil)
			_, err := session.Run(context.Background(), sp)
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
		answeringWith(g, hosts, nil)
		if _, err := session.Run(context.Background(), sp); err != nil {
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

// TestAWalledRunNeedsAModelKey pins the session's check that a walled run whose
// gateway holds credentials for it has a model key for its runtime: a credential whose
// placeholder is one of the runtime's model-key variables and whose hosts cover the
// runtime's model host, api.anthropic.com for Claude Code or the host of the
// endpoint's value that reaches the runtime, or a value the run or the machine passes
// for one of the variables. A walled run without credential_hosts, and a run without a
// wall, are not checked. A model key for another host is in
// [TestTheModelKeyRefusalNamesTheFix].
func TestAWalledRunNeedsAModelKey(t *testing.T) {
	forge := sealed("forge", "api.github.com", "", "", "GITHUB_TOKEN")
	for _, tc := range []struct {
		what    string
		walled  bool
		hosts   []map[string]any
		edit    func(*session.Spec)
		refused bool
	}{
		{"walled, no model key", true, []map[string]any{forge}, nil, true},
		{"walled, a model credential with no placeholder", true, []map[string]any{forge, sealed("model", "api.anthropic.com", "", "")}, nil, true},
		{"unwalled", false, []map[string]any{forge}, nil, false},
		{"walled, no credential_hosts", true, nil, nil, false},
		{"walled, a machine credential", true, modelAndForge, nil, false},
		{"walled, a sealed key_form credential", true, []map[string]any{forge, sealed("model", "api.anthropic.com", "access_token", "bearer")}, nil, false},
		{"walled, a value from the machine", true, []map[string]any{forge}, func(sp *session.Spec) {
			sp.Variables.Machine = []string{apiKeyVariable + "=sk-ant-a-key-of-the-test"}
		}, false},
		{"walled, a value from the run", true, []map[string]any{forge}, func(sp *session.Spec) {
			sp.Variables.Run = []string{oauthVariable + "=sk-ant-oat-a-key-of-the-test"}
		}, false},
		{"walled, the endpoint the run inherits", true, []map[string]any{sealed("model", "10.0.0.5", "", "", apiKeyVariable)}, func(sp *session.Spec) {
			sp.Env = append(sp.Env, endpointVariable+"=https://10.0.0.5:4443")
		}, false},
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
				answeringWith(g, tc.hosts, nil)
			}
			_, err := session.Run(context.Background(), sp)
			if !tc.refused {
				if err != nil {
					t.Fatalf("%v, want the run", err)
				}
				return
			}
			var r *session.Refusal
			if !errors.As(err, &r) || r.Code != "model_key_missing" || !slices.Equal(r.Names, modelKeys) {
				t.Fatalf("%v, want model_key_missing for %q", err, modelKeys)
			}
			want := "give the run a model key for the runtime claude: a credential for api.anthropic.com with a placeholder of ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN, on this machine or in Qory Apiary's run configuration, or a value of one of these variables from the run or the machine; the gateway holds credentials for the run, and none of them is a model key for api.anthropic.com"
			if r.Detail != want {
				t.Errorf("the refusal reads\n %q\nwant\n %q", r.Detail, want)
			}
			if strings.Contains(err.Error(), "sk-ant") {
				t.Errorf("the refusal quotes a value: %v", err)
			}
			refusals := ofType(g.Events(), "dev.qory.run.refused")
			if len(refusals) != 1 || data(refusals[0])["code"] != "model_key_missing" {
				t.Errorf("the link got %v; want one run.refused, model_key_missing", refusals)
			}
		})
	}
}

// TestTheModelKeyRefusalNamesTheFix pins the text of model_key_missing by what the
// runtime sends its model requests to. A value of the endpoint's variable with no host
// Forager reads, here an http URL the run inherits, is covered by no credential, and
// the text names the endpoint as the fix, not a credential the run has. A value the
// endpoint rule leaves out does not reach the runtime: the inherited value counts, or,
// when there is none, the descriptor's host, and a model credential for it is the
// run's model key. The text offers a value only of a variable that no credential sets
// a placeholder in, that the gateway does not reserve, that the deny list does not
// match, and that neither the harness nor Forager sets: a value of it from the run
// reaches the runtime.
func TestTheModelKeyRefusalNamesTheFix(t *testing.T) {
	forge := sealed("forge", "api.github.com", "", "", "GITHUB_TOKEN")
	const keyFix = "a credential with a placeholder of ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN"
	for _, tc := range []struct {
		what         string
		inherited    string
		run          []string
		hosts        []map[string]any
		placeholders []string
		reserved     []string
		deny         []string
		fixed        []string
		runtime      func(runtimes.Runtime) runtimes.Runtime
		names        []string
		want         string
	}{
		{
			what:      "an endpoint with no host Forager reads",
			inherited: "http://litellm.internal:4000",
			hosts:     []map[string]any{forge},
			want:      "set ANTHROPIC_BASE_URL to an https URL, with no user name or password, whose host " + keyFix + " covers, or give the run a value of one of these variables from the run or the machine: the value of ANTHROPIC_BASE_URL that reaches the runtime claude has no host that Forager reads, so no credential counts as its model key",
		},
		{
			what:         "an endpoint with no host Forager reads and a model credential's placeholder",
			inherited:    "http://litellm.internal:4000",
			hosts:        []map[string]any{sealed("model", "litellm.internal", "", "", apiKeyVariable)},
			placeholders: []string{apiKeyVariable},
			want:         "set ANTHROPIC_BASE_URL to an https URL, with no user name or password, whose host " + keyFix + " covers, or give the run a value of CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN from the run or the machine: the value of ANTHROPIC_BASE_URL that reaches the runtime claude has no host that Forager reads, so no credential counts as its model key",
		},
		{
			// The run's https value is not covered, so the endpoint rule leaves it
			// out, and the inherited value is the one that reaches the runtime.
			what:         "an inherited endpoint with no host Forager reads and a dropped run value",
			inherited:    "http://litellm.internal:4000",
			run:          []string{endpointVariable + "=https://evil.example"},
			hosts:        modelAndForge,
			placeholders: []string{apiKeyVariable, "GITHUB_TOKEN"},
			want:         "set ANTHROPIC_BASE_URL to an https URL, with no user name or password, whose host " + keyFix + " covers, or give the run a value of CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN from the run or the machine: the value of ANTHROPIC_BASE_URL that reaches the runtime claude has no host that Forager reads, so no credential counts as its model key",
		},
		{
			what:         "an endpoint with no host Forager reads and every model key a placeholder",
			inherited:    "http://litellm.internal:4000",
			hosts:        []map[string]any{sealed("model", "litellm.internal", "", "", modelKeys...)},
			placeholders: modelKeys,
			want:         "set ANTHROPIC_BASE_URL to an https URL, with no user name or password, whose host " + keyFix + " covers: the value of ANTHROPIC_BASE_URL that reaches the runtime claude has no host that Forager reads, so no credential counts as its model key",
		},
		{
			what:     "a model key the gateway reserves",
			hosts:    []map[string]any{forge},
			reserved: []string{authTokenVariable},
			want:     "give the run a model key for the runtime claude: a credential for api.anthropic.com with a placeholder of ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN, on this machine or in Qory Apiary's run configuration, or a value of ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN from the run or the machine; the gateway holds credentials for the run, and none of them is a model key for api.anthropic.com",
		},
		{
			what:  "a model key the node denies",
			hosts: []map[string]any{forge},
			deny:  []string{"claude_code_*"},
			want:  "give the run a model key for the runtime claude: a credential for api.anthropic.com with a placeholder of ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN, on this machine or in Qory Apiary's run configuration, or a value of ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN from the run or the machine; the gateway holds credentials for the run, and none of them is a model key for api.anthropic.com",
		},
		{
			what:    "a model key the runtime denies",
			hosts:   []map[string]any{forge},
			runtime: func(rt runtimes.Runtime) runtimes.Runtime { return &deniesKey{Runtime: rt} },
			want:    "give the run a model key for the runtime claude: a credential for api.anthropic.com with a placeholder of ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN, on this machine or in Qory Apiary's run configuration, or a value of ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN from the run or the machine; the gateway holds credentials for the run, and none of them is a model key for api.anthropic.com",
		},
		{
			what:    "a model key among the runtime's model overrides",
			hosts:   []map[string]any{forge},
			runtime: func(rt runtimes.Runtime) runtimes.Runtime { return &deniesKey{Runtime: rt, inOverrides: true} },
			want:    "give the run a model key for the runtime claude: a credential for api.anthropic.com with a placeholder of ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN, on this machine or in Qory Apiary's run configuration, or a value of ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN from the run or the machine; the gateway holds credentials for the run, and none of them is a model key for api.anthropic.com",
		},
		{
			what:  "a model key the harness sets to empty",
			hosts: []map[string]any{forge},
			fixed: []string{authTokenVariable + "="},
			want:  "give the run a model key for the runtime claude: a credential for api.anthropic.com with a placeholder of ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN, on this machine or in Qory Apiary's run configuration, or a value of ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN from the run or the machine; the gateway holds credentials for the run, and none of them is a model key for api.anthropic.com",
		},
		{
			what:    "a model key the runtime's preparation sets to empty",
			hosts:   []map[string]any{forge},
			runtime: func(rt runtimes.Runtime) runtimes.Runtime { return &preparesEmpty{Runtime: rt} },
			want:    "give the run a model key for the runtime claude: a credential for api.anthropic.com with a placeholder of ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN, on this machine or in Qory Apiary's run configuration, or a value of ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN from the run or the machine; the gateway holds credentials for the run, and none of them is a model key for api.anthropic.com",
		},
		{
			what:    "a model key in a variable Forager sets",
			hosts:   []map[string]any{forge},
			runtime: func(rt runtimes.Runtime) runtimes.Runtime { return &runIDKey{Runtime: rt} },
			names:   []string{apiKeyVariable, authTokenVariable, oauthVariable, "QORY_RUN_ID"},
			want:    "give the run a model key for the runtime claude: a credential for api.anthropic.com with a placeholder of ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN, ANTHROPIC_AUTH_TOKEN or QORY_RUN_ID, on this machine or in Qory Apiary's run configuration, or a value of ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN from the run or the machine; the gateway holds credentials for the run, and none of them is a model key for api.anthropic.com",
		},
		{
			what:         "a model credential for another host",
			hosts:        []map[string]any{sealed("model", "llm.example", "", "", apiKeyVariable)},
			placeholders: []string{apiKeyVariable},
			want:         "give the run a model key for the runtime claude: a credential for api.anthropic.com with a placeholder of ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN, on this machine or in Qory Apiary's run configuration, or a value of CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN from the run or the machine; the gateway holds credentials for the run, and none of them is a model key for api.anthropic.com",
		},
		{
			what:         "every model key a placeholder of a credential for another host",
			hosts:        []map[string]any{sealed("model", "llm.example", "", "", modelKeys...)},
			placeholders: modelKeys,
			want:         "give the run a model key for the runtime claude: a credential for api.anthropic.com with a placeholder of ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN, on this machine or in Qory Apiary's run configuration; the gateway holds credentials for the run, and none of them is a model key for api.anthropic.com",
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			env := []string{"FAKE_EXIT=0"}
			if tc.inherited != "" {
				env = append(env, endpointVariable+"="+tc.inherited)
			}
			sp, g := specGateway(t, env...)
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			sp.Variables.Run, sp.Variables.Deny = tc.run, tc.deny
			sp.LaunchFixed = append(sp.LaunchFixed, tc.fixed...)
			if tc.runtime != nil {
				sp.Runtime = tc.runtime(sp.Runtime)
			}
			g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
				a := linktest.RunAnswer(req)
				a["credential_hosts"] = tc.hosts
				if tc.placeholders != nil {
					a["placeholders"] = tc.placeholders
				}
				if tc.reserved != nil {
					a["reserved"] = tc.reserved
				}
				return linktest.Reply{Status: 200, Body: a}
			})
			_, err := session.Run(context.Background(), sp)
			var r *session.Refusal
			names := modelKeys
			if tc.names != nil {
				names = tc.names
			}
			if !errors.As(err, &r) || r.Code != "model_key_missing" || !slices.Equal(r.Names, names) {
				t.Fatalf("%v, want model_key_missing for %q", err, names)
			}
			if strings.Contains(err.Error(), "probe") {
				t.Errorf("the refusal quotes the trial's value: %v", err)
			}
			if r.Detail != tc.want {
				t.Errorf("the refusal reads\n %q\nwant\n %q", r.Detail, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		what    string
		hosts   []map[string]any
		refused bool
	}{
		{"a dropped endpoint and a model credential for the descriptor's host", modelAndForge, false},
		{"a dropped endpoint and no model credential", []map[string]any{forge}, true},
	} {
		t.Run(tc.what, func(t *testing.T) {
			sp, g := specGateway(t, "FAKE_EXIT=0")
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			sp.Variables.Run = []string{endpointVariable + "=https://evil.example"}
			answeringWith(g, tc.hosts, nil)
			_, err := session.Run(context.Background(), sp)
			if !tc.refused {
				if err != nil {
					t.Fatalf("%v, want the run", err)
				}
				return
			}
			var r *session.Refusal
			if !errors.As(err, &r) || r.Code != "model_key_missing" || !strings.Contains(r.Detail, "a credential for api.anthropic.com") {
				t.Fatalf("%v, want model_key_missing for api.anthropic.com", err)
			}
		})
	}
}

// TestTheRecordOfCredentialVariablesHoldsNoSecret pins that credential_variables leaves
// out an entry whose credential's name or placeholder contains an access key secret or
// a run key, and keeps the others.
func TestTheRecordOfCredentialVariablesHoldsNoSecret(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	secret := "qak_0123456789abcdef"
	answeringWith(g, []map[string]any{
		sealed("model", "api.anthropic.com", "", "", apiKeyVariable, secret),
		sealed("qrk_forge", "api.github.com", "", "", "GITHUB_TOKEN"),
	}, []string{apiKeyVariable, secret, "GITHUB_TOKEN"})
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := credentialVariables(t, res), []string{"model=" + apiKeyVariable}; !slices.Equal(got, want) {
		t.Errorf("credential_variables %q, want %q", got, want)
	}
}

// deniesKey is a runtime whose descriptor lists ANTHROPIC_AUTH_TOKEN in its denies, or
// with inOverrides in its model overrides.
type deniesKey struct {
	runtimes.Runtime
	inOverrides bool
}

func (p *deniesKey) Secrets() runtimes.Declarations {
	d := p.Runtime.(runtimes.Secrets).Secrets()
	if !p.inOverrides {
		d.Denies = append(slices.Clone(d.Denies), authTokenVariable)
	}
	return d
}

func (p *deniesKey) Model() (runtimes.ModelPlaces, bool) {
	m, ok := p.Runtime.(runtimes.Model).Model()
	if p.inOverrides {
		m.Overrides = append(slices.Clone(m.Overrides), authTokenVariable)
	}
	return m, ok
}

// runIDKey is a runtime that declares a model key in QORY_RUN_ID, a variable Forager
// sets in every run.
type runIDKey struct{ runtimes.Runtime }

func (p *runIDKey) Secrets() runtimes.Declarations {
	d := p.Runtime.(runtimes.Secrets).Secrets()
	d.Declares = append(slices.Clone(d.Declares), runtimes.Declaration{
		ID: "run-id", Title: "A key in the run's id", Name: "QORY_RUN_ID",
		Hosts: []string{"api.anthropic.com"}, Auth: runtimes.Auth{Scheme: "bearer"}, KeyForm: "api_key",
	})
	return d
}

func (p *runIDKey) Model() (runtimes.ModelPlaces, bool) {
	return p.Runtime.(runtimes.Model).Model()
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
