package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
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
	answeringStart(g, hosts, placeholders, "")
}

// answeringStart is answeringWith with model_credential set to start, when start is not
// empty.
func answeringStart(g *linktest.Fake, hosts []map[string]any, placeholders []string, start string) {
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["credential_hosts"] = hosts
		if placeholders != nil {
			a["placeholders"] = placeholders
		}
		if start != "" {
			a["model_credential"] = start
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

// TestTheStartKeyChoosesTheVariable pins the variable an API credential gets for Claude
// Code, by its descriptor's model.keys: an Anthropic Messages key in the header
// x-api-key, compared without case, goes into ANTHROPIC_API_KEY, a bearer into
// ANTHROPIC_AUTH_TOKEN, and a bearer with oauth into CLAUDE_CODE_OAUTH_TOKEN. The
// chosen variable reaches the agent as the key's placeholder, which contains the key's
// name, and the other two do not. ANTHROPIC_BASE_URL reaches the agent as the key's
// endpoint, and the run's value of it is left out as fixed: the record's entry has
// from fixed, for the key's endpoint, and the run's value lost. The record has the
// credential's variable in credential_variables. A run without a wall is the same.
func TestTheStartKeyChoosesTheVariable(t *testing.T) {
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
			res, err := session.Run(context.Background(), sp)
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
			res, err := session.Run(context.Background(), sp)
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

// TestAStartKeyTheRuntimeDoesNotReadIsRefused pins an API credential for which the
// runtime's descriptor lists no key: a runtime with no model section, a format the
// descriptor lists no key for, and an auth no key of the format has, by its scheme,
// its header's name or its oauth, a header's name that contains qak_ being the value's
// phrase. Each is run_configuration_invalid with the credential's name, before the
// runtime starts.
func TestAStartKeyTheRuntimeDoesNotReadIsRefused(t *testing.T) {
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
			_, err := session.Run(context.Background(), sp)
			refusedWith(t, err, "run_configuration_invalid", []string{"model"}, tc.detail)
			if refusals := ofType(g.Events(), "dev.qory.run.refused"); len(refusals) != 1 {
				t.Errorf("the link got %v; want one run.refused", refusals)
			}
		})
	}
}

// TestModelCredentialChoosesTheStartKey pins a run with two API credentials: the one
// model_credential names is the start key, whose variable gets its placeholder and
// whose endpoint the runtime gets; the other gets no variable. Each key's placeholder
// differs. An answer without model_credential, or with one that names no API
// credential of the run, is run_configuration_invalid.
func TestModelCredentialChoosesTheStartKey(t *testing.T) {
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
			answeringStart(g, keys, nil, "backup")
			res, err := session.Run(context.Background(), sp)
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
		what, start string
		names       []string
		detail      string
	}{
		{"no model_credential", "", nil,
			`set model_credential in the run configuration, or give the run one model key: the run has the model keys model, backup`},
		{"a name of no model key", "forge", []string{"forge"},
			`set model_credential in the run configuration to one of the run's model keys, model, backup: the run has no model key "forge"`},
	} {
		t.Run(tc.what, func(t *testing.T) {
			sp, g := specGateway(t)
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			answeringStart(g, append(slices.Clone(keys), sealed("forge", "api.github.com", "GITHUB_TOKEN")), []string{"GITHUB_TOKEN"}, tc.start)
			_, err := session.Run(context.Background(), sp)
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
// GITHUB_TOKEN, passes beside the start key.
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
			`remove CLAUDE_CONFIG_DIR from the placeholders of the credential "forge" in Qory Apiary's run configuration: the descriptor of the runtime claude lists it in denies, and a placeholder goes only into a variable for a credential`},
		{"a model override", []map[string]any{model(), sealed("forge", "api.github.com", "ANTHROPIC_MODEL")}, []string{"ANTHROPIC_MODEL"}, nil, []string{"forge"},
			`remove ANTHROPIC_MODEL from the placeholders of the credential "forge" in Qory Apiary's run configuration: the descriptor of the runtime claude lists it in its model overrides, and a placeholder goes only into a variable for a credential`},
		{"the model endpoint's variable", []map[string]any{model(), sealed("forge", "api.github.com", endpointVariable)}, []string{endpointVariable},
			func(rt runtimes.Runtime) runtimes.Runtime { return &allowsEndpoint{Runtime: rt} }, []string{"forge"},
			`remove ANTHROPIC_BASE_URL from the placeholders of the credential "forge" in Qory Apiary's run configuration: the descriptor of the runtime claude has it as its model endpoint's variable, and a placeholder goes only into a variable for a credential`},
		{"a variable the runtime reserves", []map[string]any{model(), sealed("forge", "api.github.com", "MODEL_SESSION")}, []string{"MODEL_SESSION"},
			func(rt runtimes.Runtime) runtimes.Runtime { return &reservesSession{Runtime: rt} }, []string{"forge"},
			`remove MODEL_SESSION from the placeholders of the credential "forge" in Qory Apiary's run configuration: the descriptor of the runtime claude lists it in reserves, and a placeholder goes only into a variable for a credential`},
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
			_, err := session.Run(context.Background(), sp)
			refusedWith(t, err, "run_configuration_invalid", tc.names, tc.detail)
		})
	}
	t.Run("a tool's placeholder", func(t *testing.T) {
		sp, g := specGateway(t)
		out := dumpsEnv(t, &sp)
		sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		answeringWith(g, []map[string]any{model(), sealed("forge", "api.github.com", "GITHUB_TOKEN")}, []string{"GITHUB_TOKEN"})
		res, err := session.Run(context.Background(), sp)
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
		answeringWith(g, []map[string]any{model()}, nil)
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

// TestAWalledRunNeedsAModelKey pins the session's check that a walled run whose gateway
// holds credentials for it has a model key for its runtime: an API credential, or a
// value of one of the model keys' variables from the run or the machine. A run without
// credential_hosts is not checked, nor is a run without a wall: its runtime may use the
// developer's login. A value the harness or the runtime's preparation sets to empty is
// no model key. The refusal is model_key_missing with the model keys' variables, and
// quotes no value.
func TestAWalledRunNeedsAModelKey(t *testing.T) {
	forge := sealed("forge", "api.github.com", "GITHUB_TOKEN")
	for _, tc := range []struct {
		what    string
		walled  bool
		hosts   []map[string]any
		edit    func(*session.Spec)
		refused bool
	}{
		{"walled, no model key", true, []map[string]any{forge}, nil, true},
		{"walled, a key the harness sets to empty", true, []map[string]any{forge}, func(sp *session.Spec) {
			sp.LaunchFixed = append(sp.LaunchFixed, authTokenVariable+"=")
		}, true},
		{"walled, a key the preparation sets to empty", true, []map[string]any{forge}, func(sp *session.Spec) {
			sp.Runtime = &preparesEmpty{Runtime: sp.Runtime}
		}, true},
		{"unwalled, only a forge credential", false, []map[string]any{forge}, nil, false},
		{"unwalled, no credential_hosts", false, nil, nil, false},
		{"unwalled, an API credential", false, []map[string]any{forge, model()}, nil, false},
		{"walled, no credential_hosts", true, nil, nil, false},
		{"walled, an API credential", true, []map[string]any{forge, model()}, nil, false},
		{"walled, a value from the machine", true, []map[string]any{forge}, func(sp *session.Spec) {
			sp.Variables.Machine = []string{apiKeyVariable + "=sk-ant-a-key-of-the-test"}
		}, false},
		{"walled, a value from the run", true, []map[string]any{forge}, func(sp *session.Spec) {
			sp.Variables.Run = []string{oauthVariable + "=sk-ant-oat-a-key-of-the-test"}
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
				answeringWith(g, tc.hosts, []string{"GITHUB_TOKEN"})
			}
			_, err := session.Run(context.Background(), sp)
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
			refusals := ofType(g.Events(), "dev.qory.run.refused")
			if len(refusals) != 1 || data(refusals[0])["code"] != "model_key_missing" {
				t.Errorf("the link got %v; want one run.refused, model_key_missing", refusals)
			}
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
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"model=" + apiKeyVariable, "helper=(a name that contains an access key secret)", "(a name that contains a run key)=GITHUB_TOKEN"}
	if got := credentialVariables(t, res); !slices.Equal(got, want) {
		t.Errorf("credential_variables %q, want %q", got, want)
	}
}

// TestAnInheritedKeyAndEndpointGiveWayToTheStartKey pins that, without a wall, values
// the run inherits of the start key's variable and of ANTHROPIC_BASE_URL do not reach
// the agent: the key's placeholder and its endpoint are set over them.
func TestAnInheritedKeyAndEndpointGiveWayToTheStartKey(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0", apiKeyVariable+"=sk-fake-inherited", endpointVariable+"=https://other.example")
	out := dumpsEnv(t, &sp)
	answeringWith(g, []map[string]any{model(), sealed("forge", "api.github.com", "GITHUB_TOKEN")}, []string{"GITHUB_TOKEN"})
	if _, err := session.Run(context.Background(), sp); err != nil {
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
	pa := ofType(events(t, res), "dev.qory.run.policy_applied")
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

// TestOtherKeyVariablesDoNotReachTheRuntime pins that, beside a start key, a value of
// each other model-key variable of Claude Code reaches the agent from no source: the
// server, the run, the machine, the harness's defaults and its computed values, the
// inherited environment and, behind a wall, the image. Behind a wall each name is unset
// inside. The record has each value lost as fixed, with no from. It runs once for a
// start key in ANTHROPIC_API_KEY, and once for a bearer start key in
// ANTHROPIC_AUTH_TOKEN, whose others include ANTHROPIC_API_KEY.
func TestOtherKeyVariablesDoNotReachTheRuntime(t *testing.T) {
	const value = "sk-fake-dev-token"
	for _, start := range []struct{ auth, variable string }{{"header", apiKeyVariable}, {"bearer", authTokenVariable}} {
		var others []string
		for _, k := range modelKeys {
			if k != start.variable {
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
				t.Run(fmt.Sprintf("%s start %s walled %v", source, start.auth, walled), func(t *testing.T) {
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
					answering(g, []map[string]any{apiKey("model", "anthropic-messages", modelEndpoint, start.auth)}, vars)
					res, err := session.Run(context.Background(), sp)
					if err != nil {
						t.Fatal(err)
					}
					got := envOf(t, out)
					if got[start.variable] != link.KeyPlaceholder("model") {
						t.Errorf("%s=%q; want the start key's placeholder", start.variable, got[start.variable])
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

// TestAPreparationsOtherKeyVariablesDoNotReachTheRuntime pins that, beside a start key
// in ANTHROPIC_API_KEY, a value the runtime's preparation sets for ANTHROPIC_AUTH_TOKEN
// or CLAUDE_CODE_OAUTH_TOKEN does not reach the agent, with or without a wall. Behind a
// wall each name is unset inside and not set.
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
			if _, err := session.Run(context.Background(), sp); err != nil {
				t.Fatal(err)
			}
			got := envOf(t, out)
			if got[apiKeyVariable] != link.KeyPlaceholder("model") {
				t.Errorf("%s=%q; want the start key's placeholder", apiKeyVariable, got[apiKeyVariable])
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
