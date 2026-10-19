package session_test

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
)

// endpointVariable is the Claude Code descriptor's model.endpoint.variable.
const endpointVariable = "ANTHROPIC_BASE_URL"

// modelAndForge are a run answer's credential_hosts: the model credential, whose
// placeholder the Claude Code runtime declares, and a forge credential, whose
// placeholder it does not.
var modelAndForge = []map[string]any{
	{"name": "model", "hosts": []string{"api.anthropic.com"}, "placeholders": []string{"ANTHROPIC_API_KEY"}},
	{"name": "forge", "hosts": []string{"api.github.com"}, "placeholders": []string{"GITHUB_TOKEN"}},
}

// answering makes the gateway's run answer carry credential_hosts, when hosts is not
// nil, and the server's variables of vars, when it is not nil.
func answering(g *linktest.Fake, hosts []map[string]any, vars map[string]any) {
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		if hosts != nil {
			a["credential_hosts"] = hosts
		}
		if vars != nil {
			a["variables"] = vars
		}
		return linktest.Reply{Status: 200, Body: a}
	})
}

// endpointEntry is the entry of the run's policy_applied variables for the endpoint's
// variable, nil when the record lists none. events validates every event against its
// schema.
func endpointEntry(t *testing.T, res *session.Result) map[string]any {
	t.Helper()
	pa := ofType(events(t, res), "dev.qory.run.policy_applied")
	if len(pa) != 1 {
		t.Fatalf("policy_applied events: %v", pa)
	}
	list, _ := data(pa[0])["variables"].([]any)
	for _, item := range list {
		if e := item.(map[string]any); e["name"] == endpointVariable {
			return e
		}
	}
	return nil
}

// TestAWalledRunKeepsACoveredEndpoint pins the endpoint rule end to end, behind a wall,
// for a value of the endpoint's variable from the server, the run (--env), the machine
// (wall.env), the harness's defaults and its computed values: a value whose host is a
// host of the run's model credential reaches the agent and is not unset, and the
// record has kept with the credential's name; any other value does not reach the
// agent, the name is unset inside, so the image's value does not reach it either, and
// the record has the reason. A forge credential's host does not count, and an answer
// without credential_hosts covers no host. Every event validates against its schema.
func TestAWalledRunKeepsACoveredEndpoint(t *testing.T) {
	for _, tc := range []struct {
		what, value string
		hosts       []map[string]any
		why         string
	}{
		{"covered", "https://api.anthropic.com", modelAndForge, ""},
		{"uncovered", "https://evil.example", modelAndForge, "endpoint_uncovered"},
		{"a forge credential's host", "https://api.github.com", modelAndForge, "endpoint_uncovered"},
		{"no credential_hosts", "https://api.anthropic.com", nil, "endpoint_uncovered"},
		{"http", "http://api.anthropic.com", modelAndForge, "endpoint_unreadable"},
		{"user information", "https://a@api.anthropic.com", modelAndForge, "endpoint_unreadable"},
	} {
		for _, source := range []string{"apiary", "run", "machine", "harness", "fixed"} {
			t.Run(tc.what+" from "+source, func(t *testing.T) {
				w := &imageWall{env: []string{endpointVariable + "=https://image.invalid/"}}
				sp, g := specGateway(t)
				out := dumpsEnv(t, &sp)
				sp.Wall, sp.Image = w, "example.com/agent:1"
				passed := []string{endpointVariable + "=" + tc.value}
				var vars map[string]any
				switch source {
				case "apiary":
					vars = map[string]any{endpointVariable: map[string]any{"value": tc.value}}
				case "run":
					sp.Variables.Run = passed
				case "machine":
					sp.Variables.Machine = passed
				case "harness":
					sp.LaunchDefaults = passed
				case "fixed":
					sp.LaunchFixed = passed
				}
				answering(g, tc.hosts, vars)
				res, err := session.Run(context.Background(), sp)
				if err != nil {
					t.Fatal(err)
				}
				if res.ExitCode != 0 {
					t.Fatalf("exit %d", res.ExitCode)
				}
				names, _ := unsetIn(t, w.got)
				value, reached := envOf(t, out)[endpointVariable]
				entry := endpointEntry(t, res)
				if tc.why == "" {
					if !reached || value != tc.value || slices.Contains(names, endpointVariable) {
						t.Errorf("%s=%q reached the agent %v, unset %q; want %q, not unset", endpointVariable, value, reached, names, tc.value)
					}
					// A computed value is listed beside another source's alone.
					if source == "fixed" {
						if entry != nil {
							t.Errorf("the record lists %v", entry)
						}
						return
					}
					b, _ := json.Marshal(entry)
					if want := `{"from":"` + source + `","kept":{"credential":"model","why":"endpoint_covered"},"lost":[],"name":"` + endpointVariable + `"}`; string(b) != want {
						t.Errorf("the record's entry %s, want %s", b, want)
					}
					return
				}
				if reached || !slices.Contains(names, endpointVariable) {
					t.Errorf("%s=%q reached the agent %v, unset %q; want it unset", endpointVariable, value, reached, names)
				}
				b, _ := json.Marshal(entry)
				if want := `{"lost":[{"from":"` + source + `","why":"` + tc.why + `"}],"name":"` + endpointVariable + `"}`; string(b) != want {
					t.Errorf("the record's entry %s, want %s", b, want)
				}
			})
		}
	}
}

// endpointLines are the lines of what dumpsEnv wrote that set the endpoint's variable,
// in order.
func endpointLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, endpointVariable+"=") {
			out = append(out, line)
		}
	}
	return out
}

// TestAWalledRunChecksEveryComputedEndpoint pins the harness's computed values of the
// endpoint's variable behind a wall: when one of two is uncovered, neither reaches the
// wall or the agent and the name is unset; when both are covered, the environment the
// wall gets and the agent's each have the last one alone; and a kept computed value that wins over the run's is recorded with
// from fixed and kept, an entry the schema accepts.
func TestAWalledRunChecksEveryComputedEndpoint(t *testing.T) {
	for _, tc := range []struct {
		what  string
		fixed []string
		run   string
		lines []string
		entry string
	}{
		{"an uncovered one first", []string{endpointVariable + "=https://evil.example", endpointVariable + "=https://api.anthropic.com"}, "",
			nil, `{"lost":[{"from":"fixed","why":"endpoint_uncovered"}],"name":"` + endpointVariable + `"}`},
		{"both covered", []string{endpointVariable + "=https://api.anthropic.com/v1", endpointVariable + "=https://api.anthropic.com"}, "",
			[]string{endpointVariable + "=https://api.anthropic.com"}, "null"},
		{"a kept one over the run's", []string{endpointVariable + "=https://api.anthropic.com"}, "https://evil.example",
			[]string{endpointVariable + "=https://api.anthropic.com"},
			`{"from":"fixed","kept":{"credential":"model","why":"endpoint_covered"},"lost":[{"from":"run","why":"endpoint_uncovered"}],"name":"` + endpointVariable + `"}`},
	} {
		t.Run(tc.what, func(t *testing.T) {
			w := &imageWall{env: []string{endpointVariable + "=https://image.invalid/"}}
			sp, g := specGateway(t)
			out := dumpsEnv(t, &sp)
			sp.Wall, sp.Image = w, "example.com/agent:1"
			sp.LaunchFixed = tc.fixed
			if tc.run != "" {
				sp.Variables.Run = []string{endpointVariable + "=" + tc.run}
			}
			answering(g, modelAndForge, nil)
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if got := entriesOf(w.got.Env, endpointVariable); !slices.Equal(got, tc.lines) {
				t.Errorf("the wall's environment has %q, want %q", got, tc.lines)
			}
			if got := endpointLines(t, out); !slices.Equal(got, tc.lines) {
				t.Errorf("the agent's environment has %q, want %q", got, tc.lines)
			}
			names, _ := unsetIn(t, w.got)
			if slices.Contains(names, endpointVariable) != (tc.lines == nil) {
				t.Errorf("unset %q; want %s among them %v", names, endpointVariable, tc.lines == nil)
			}
			if b, _ := json.Marshal(endpointEntry(t, res)); string(b) != tc.entry {
				t.Errorf("the record's entry %s, want %s", b, tc.entry)
			}
		})
	}
}

// TestTheEndpointsCredentialIsShownByName pins that a model credential whose name
// contains qak_ is recorded in kept as the phrase in its place.
func TestTheEndpointsCredentialIsShownByName(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	sp.Variables.Run = []string{endpointVariable + "=https://api.anthropic.com"}
	answering(g, []map[string]any{{"name": "qak_model", "hosts": []string{"api.anthropic.com"}, "placeholders": []string{"CLAUDE_CODE_OAUTH_TOKEN"}}}, nil)
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	kept, _ := endpointEntry(t, res)["kept"].(map[string]any)
	if kept["credential"] != "(a name that contains an access key secret)" {
		t.Errorf("kept %v, want the phrase for the credential", kept)
	}
}

// TestAnUnwalledRunDeniesTheEndpoint pins that without a wall the endpoint's variable
// is denied, whatever credential_hosts the answer has: the run's covered
// value does not reach the agent, and the record has no kept.
func TestAnUnwalledRunDeniesTheEndpoint(t *testing.T) {
	sp, g := specGateway(t)
	out := dumpsEnv(t, &sp)
	sp.Variables.Run = []string{endpointVariable + "=https://api.anthropic.com"}
	answering(g, modelAndForge, nil)
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := envOf(t, out)[endpointVariable]; ok {
		t.Errorf("%s=%q reached the agent", endpointVariable, value)
	}
	b, _ := json.Marshal(endpointEntry(t, res))
	if want := `{"lost":[{"from":"run","why":"denied"}],"name":"` + endpointVariable + `"}`; string(b) != want {
		t.Errorf("the record's entry %s, want %s", b, want)
	}
}
