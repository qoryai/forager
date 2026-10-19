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
// its name, hosts and placeholders, and, when keyVariables is not empty, its
// key_variables, the names keyVariables separates with commas, and its auth: auth is
// a scheme, or header:name for a header, with header alone for x-api-key.
func sealed(name, host, keyVariables, auth string, placeholders ...string) map[string]any {
	e := map[string]any{"name": name, "hosts": []string{host}, "placeholders": append([]string{}, placeholders...)}
	if keyVariables != "" {
		scheme, header, _ := strings.Cut(auth, ":")
		a := map[string]any{"scheme": scheme}
		if scheme == "header" {
			if header == "" {
				header = "x-api-key"
			}
			a["header"] = header
		}
		e["key_variables"], e["auth"] = strings.Split(keyVariables, ","), a
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

// TestTheKeyVariablesChooseTheVariable pins the variable a credential from the server
// with key_variables gets for Claude Code: the one of them that Claude Code declares,
// with the same auth. ANTHROPIC_API_KEY in the header x-api-key, compared without case,
// ANTHROPIC_AUTH_TOKEN as a bearer, and CLAUDE_CODE_OAUTH_TOKEN as a bearer; a name
// Claude Code does not declare, such as another runtime's, is passed over. The
// credential lists no placeholder. The chosen variable reaches the agent as the
// placeholder, the other two do not, the run's ANTHROPIC_BASE_URL for the credential's
// host is kept, and the record has the credential's variable in credential_variables.
func TestTheKeyVariablesChooseTheVariable(t *testing.T) {
	for _, tc := range []struct{ keyVariables, auth, want string }{
		{apiKeyVariable, "header", apiKeyVariable},
		{apiKeyVariable, "header:X-Api-Key", apiKeyVariable},
		{authTokenVariable, "bearer", authTokenVariable},
		{oauthVariable, "bearer", oauthVariable},
		{"OPENAI_API_KEY," + authTokenVariable, "bearer", authTokenVariable},
	} {
		t.Run(tc.keyVariables+" "+tc.auth, func(t *testing.T) {
			sp, g := specGateway(t)
			out := dumpsEnv(t, &sp)
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			sp.Variables.Run = []string{endpointVariable + "=https://openrouter.ai/api"}
			answeringWith(g, []map[string]any{sealed("model", "openrouter.ai", tc.keyVariables, tc.auth)}, nil)
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
			if _, ok := env["OPENAI_API_KEY"]; ok {
				t.Error("OPENAI_API_KEY reached the agent")
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

// TestKeyVariablesTheRuntimeDoesNotTakeAreRefused pins a credential from the server
// whose key_variables do not choose one variable of the runtime's: none of them
// declared, by Claude Code or by a runtime that declares no variable for a key; two of
// them declared; or the one declared with another auth, by its scheme or its header's
// name. Each is run_configuration_invalid with the credential's name, before the
// runtime starts.
func TestKeyVariablesTheRuntimeDoesNotTakeAreRefused(t *testing.T) {
	for _, tc := range []struct {
		what         string
		bare         bool
		keyVariables string
		auth         string
		detail       string
	}{
		{"no name Claude Code declares", false, "OPENAI_API_KEY", "bearer",
			`add one of ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_AUTH_TOKEN to the key_variables of the credential "model" in Qory Apiary's run configuration: the runtime claude reads a key from these variables, and the credential's key_variables are OPENAI_API_KEY`},
		{"a runtime without a variable for a key", true, "OPENAI_API_KEY,MODEL_API_KEY", "bearer",
			`run a runtime that reads a key from one of the key_variables of the credential "model" in Qory Apiary's run configuration, or remove its key_variables: the runtime codex declares no variable for a key, and the credential's key_variables are OPENAI_API_KEY and MODEL_API_KEY`},
		{"two names Claude Code declares", false, apiKeyVariable + "," + authTokenVariable, "bearer",
			`keep only one of ANTHROPIC_API_KEY and ANTHROPIC_AUTH_TOKEN in the key_variables of the credential "model" in Qory Apiary's run configuration: the runtime claude reads a key from each of them, and a key goes into one variable`},
		{"another scheme", false, authTokenVariable, "header",
			`set the auth of the credential "model" in Qory Apiary's run configuration to a bearer, or list another variable in its key_variables: the runtime claude sends the key in ANTHROPIC_AUTH_TOKEN as a bearer, and the credential's auth is set to the header x-api-key`},
		{"another header", false, apiKeyVariable, "header:authorization",
			`set the auth of the credential "model" in Qory Apiary's run configuration to the header x-api-key, or list another variable in its key_variables: the runtime claude sends the key in ANTHROPIC_API_KEY as the header x-api-key, and the credential's auth is set to the header authorization`},
	} {
		t.Run(tc.what, func(t *testing.T) {
			sp, g := specGateway(t)
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			if tc.bare {
				sp.Runtime = runtimes.Bare("codex")
			}
			answeringWith(g, []map[string]any{sealed("model", "api.anthropic.com", tc.keyVariables, tc.auth)}, nil)
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

// TestAPlaceholderGoesOnlyIntoACredentialsVariable pins that a placeholder goes only
// into a variable for a credential: a placeholder of a credential from the
// server that is a variable Claude Code denies, lists among its model overrides or
// reads its model endpoint from, or a key's variable its key_variables did not choose,
// another credential's included, is run_configuration_invalid with the credential's
// name; one of the run's placeholders that Claude Code denies, or that is a key's
// variable no credential has, is run_configuration_invalid with the placeholder's name.
// A tool's placeholder, GITHUB_TOKEN, passes.
func TestAPlaceholderGoesOnlyIntoACredentialsVariable(t *testing.T) {
	model := sealed("model", "api.anthropic.com", apiKeyVariable, "header")
	plain := func(name, host string, placeholders ...string) map[string]any {
		e := sealed(name, host, "", "", placeholders...)
		e["auth"] = map[string]any{"scheme": "bearer"}
		return e
	}
	machine := func(placeholders ...string) map[string]any {
		return map[string]any{"name": "machine-model", "hosts": []string{"llm.example"}, "placeholders": placeholders}
	}
	for _, tc := range []struct {
		what         string
		hosts        []map[string]any
		placeholders []string
		runtime      func(runtimes.Runtime) runtimes.Runtime
		names        []string
		detail       string
	}{
		{"a variable the runtime denies", []map[string]any{plain("forge", "api.github.com", "CLAUDE_CONFIG_DIR")}, []string{"CLAUDE_CONFIG_DIR"}, nil, []string{"forge"},
			`remove CLAUDE_CONFIG_DIR from the placeholders of the credential "forge" in Qory Apiary's run configuration: the runtime claude denies it, and a placeholder goes only into a variable for a credential`},
		{"a model override", []map[string]any{plain("forge", "api.github.com", "ANTHROPIC_MODEL")}, []string{"ANTHROPIC_MODEL"}, nil, []string{"forge"},
			`remove ANTHROPIC_MODEL from the placeholders of the credential "forge" in Qory Apiary's run configuration: the runtime claude lists it among its model overrides, and a placeholder goes only into a variable for a credential`},
		{"the model endpoint's variable", []map[string]any{plain("forge", "api.github.com", endpointVariable)}, []string{endpointVariable},
			func(rt runtimes.Runtime) runtimes.Runtime { return &allowsEndpoint{Runtime: rt} }, []string{"forge"},
			`remove ANTHROPIC_BASE_URL from the placeholders of the credential "forge" in Qory Apiary's run configuration: the runtime claude reads its model endpoint from it, and a placeholder goes only into a variable for a credential`},
		{"a key's variable without key_variables", []map[string]any{plain("model", "api.anthropic.com", apiKeyVariable)}, []string{apiKeyVariable}, nil, []string{"model"},
			`list ANTHROPIC_API_KEY in the key_variables of the credential "model" in Qory Apiary's run configuration instead of its placeholders: the runtime claude reads a key from it, and a key's variable gets a credential's placeholder only through key_variables`},
		{"a second key in another credential", []map[string]any{model, plain("forge", "api.github.com", oauthVariable)}, []string{oauthVariable}, nil, []string{"forge"},
			`list CLAUDE_CODE_OAUTH_TOKEN in the key_variables of the credential "forge" in Qory Apiary's run configuration instead of its placeholders: the runtime claude reads a key from it, and a key's variable gets a credential's placeholder only through key_variables`},
		{"a second key among the run's placeholders", []map[string]any{model}, []string{oauthVariable}, nil, []string{oauthVariable},
			`remove CLAUDE_CODE_OAUTH_TOKEN from the placeholders of the machine's tools in forager.yaml, or give it to a credential: the runtime claude reads a key from it, and no credential of the run has it among its placeholders`},
		{"a machine credential's override", []map[string]any{model, machine("ANTHROPIC_MODEL")}, []string{"ANTHROPIC_MODEL"}, nil, []string{"ANTHROPIC_MODEL"},
			`remove ANTHROPIC_MODEL from the placeholders of the machine's credentials and tools in forager.yaml: the runtime claude lists it among its model overrides, and a placeholder goes only into a variable for a credential`},
	} {
		t.Run(tc.what, func(t *testing.T) {
			sp, g := specGateway(t)
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			if tc.runtime != nil {
				sp.Runtime = tc.runtime(sp.Runtime)
			}
			answeringWith(g, tc.hosts, tc.placeholders)
			_, err := session.Run(context.Background(), sp)
			var r *session.Refusal
			if !errors.As(err, &r) || r.Code != "run_configuration_invalid" || !slices.Equal(r.Names, tc.names) {
				t.Fatalf("%v, want run_configuration_invalid for %q", err, tc.names)
			}
			if r.Detail != tc.detail {
				t.Errorf("the refusal reads\n %q\nwant\n %q", r.Detail, tc.detail)
			}
		})
	}
	t.Run("a tool's placeholder", func(t *testing.T) {
		sp, g := specGateway(t)
		out := dumpsEnv(t, &sp)
		sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		answeringWith(g, []map[string]any{model, plain("forge", "api.github.com", "GITHUB_TOKEN")}, []string{"GITHUB_TOKEN"})
		res, err := session.Run(context.Background(), sp)
		if err != nil {
			t.Fatal(err)
		}
		env := envOf(t, out)
		for _, name := range []string{"GITHUB_TOKEN", apiKeyVariable} {
			if env[name] != link.Placeholder {
				t.Errorf("%s=%q; want the placeholder", name, env[name])
			}
		}
		if got, want := credentialVariables(t, res), []string{"model=" + apiKeyVariable, "forge=GITHUB_TOKEN"}; !slices.Equal(got, want) {
			t.Errorf("credential_variables %q, want %q", got, want)
		}
	})
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

// TestAKeyVariablesCredentialsPlaceholders pins the both-members rule: a placeholder of
// another variable the runtime declares is run_configuration_invalid, the chosen
// variable listed as a placeholder too is set once, and a placeholder the runtime does
// not declare stays beside the chosen one.
func TestAKeyVariablesCredentialsPlaceholders(t *testing.T) {
	t.Run("another declared variable", func(t *testing.T) {
		sp, g := specGateway(t)
		sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		answeringWith(g, []map[string]any{sealed("model", "api.anthropic.com", apiKeyVariable, "header", oauthVariable)}, []string{oauthVariable})
		_, err := session.Run(context.Background(), sp)
		var r *session.Refusal
		if !errors.As(err, &r) || r.Code != "run_configuration_invalid" || !slices.Equal(r.Names, []string{"model"}) {
			t.Fatalf("%v, want run_configuration_invalid for model", err)
		}
		want := `remove CLAUDE_CODE_OAUTH_TOKEN from the placeholders of the credential "model" in Qory Apiary's run configuration: ANTHROPIC_API_KEY is the variable of its key_variables that the runtime claude declares, and a key goes into one variable`
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
			answeringWith(g, []map[string]any{sealed("model", "api.anthropic.com", apiKeyVariable, "header", tc.placeholders...)}, tc.placeholders)
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
	hosts := []map[string]any{sealed("model", "api.anthropic.com", apiKeyVariable, "header")}
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
		{"walled, a sealed credential with key_variables", true, []map[string]any{forge, sealed("model", "api.anthropic.com", oauthVariable, "bearer")}, nil, false},
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
		Hosts: []string{"api.anthropic.com"}, Auth: runtimes.Auth{Scheme: "bearer"},
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
