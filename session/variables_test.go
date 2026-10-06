package session_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/runner/session"
)

// serveDocument makes the control serve a run configuration document as it is.
func (c *control) serveDocument(doc, digest string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.run, c.digest = []byte(doc), digest
}

// dumpsEnv makes the spec's runtime write its environment to a file and returns the
// file's path.
func dumpsEnv(t *testing.T, sp *session.Spec) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "env")
	sp.Command, sp.Args = "/bin/sh", []string{"-c", `env > "$0"`, out}
	sp.Forwarder = nil
	return out
}

// envOf reads what dumpsEnv wrote, by name.
func envOf(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		name, value, _ := strings.Cut(line, "=")
		out[name] = value
	}
	return out
}

// variablesApplied is the variables member of the run's policy_applied.
func variablesApplied(t *testing.T, res *session.Result) map[string]string {
	t.Helper()
	pa := ofType(events(t, res), "dev.qory.run.policy_applied")
	if len(pa) != 1 {
		t.Fatalf("policy_applied events: %v", pa)
	}
	v, ok := data(pa[0])["variables"].(map[string]any)
	if !ok {
		t.Fatalf("policy_applied without variables: %v", data(pa[0]))
	}
	out := map[string]string{}
	for k, list := range v {
		out[k] = fmt.Sprint(list)
	}
	return out
}

// serverVariables is a run configuration with variables of every kind the runner
// treats apart: two it applies, one the node's deny entry covers, one the runtime
// denies, one the built-in list denies, and one the node sets as well.
const serverVariables = `{"version":1,"variables":{"NODE_ENV":"test","APP_REGION":"eu-west-1",` +
	`"ANTHROPIC_BASE_URL":"https://elsewhere.example","PATH":"/nowhere","LOG_LEVEL":"server"}}`

// TestVariablesReachTheAgentAndDeniedOnesDoNot runs the server's variables end to end:
// behind a wall, and without one when the node accepts them, the variables the run
// applies are in the agent's environment, a denied one is not, the node's own variable
// for a name the server sets is left out, and its others are added; behind a wall the
// runtime's declared and reserved variables are there empty. Without a wall, and
// without accept, none of the server's is there and the node's own are. The record
// lists each by name and contains no value.
func TestVariablesReachTheAgentAndDeniedOnesDoNot(t *testing.T) {
	for _, tc := range []struct {
		name     string
		walled   bool
		unwalled string
	}{
		{"walled", true, ""},
		{"unwalled and accept", false, session.UnwalledAccept},
		{"unwalled", false, ""},
		{"unwalled and ignore", false, session.UnwalledIgnore},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newControl(t)
			c.serveDocument(serverVariables, "sha256="+strings.Repeat("1", 64))
			sp := spec(t, nil)
			out := dumpsEnv(t, &sp)
			sp.Server = c.server()
			sp.Variables = session.Variables{Own: []string{"LOG_LEVEL=node", "EDITOR=vi"}, Deny: []string{"APP_*"}, Unwalled: tc.unwalled}
			if tc.walled {
				sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			}
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if res.ExitCode != 0 {
				t.Fatalf("exit %d", res.ExitCode)
			}
			env := envOf(t, out)
			applied := variablesApplied(t, res)
			if tc.walled || tc.unwalled == session.UnwalledAccept {
				if env["NODE_ENV"] != "test" || env["LOG_LEVEL"] != "server" || env["EDITOR"] != "vi" {
					t.Errorf("the applied variables: NODE_ENV=%q LOG_LEVEL=%q EDITOR=%q", env["NODE_ENV"], env["LOG_LEVEL"], env["EDITOR"])
				}
				if _, ok := env["APP_REGION"]; ok || env["ANTHROPIC_BASE_URL"] != "" || env["PATH"] == "/nowhere" {
					t.Errorf("a denied variable reached the agent: APP_REGION=%q ANTHROPIC_BASE_URL=%q PATH=%q", env["APP_REGION"], env["ANTHROPIC_BASE_URL"], env["PATH"])
				}
				want := map[string]string{"names": "[EDITOR LOG_LEVEL NODE_ENV]", "denied": "[ANTHROPIC_BASE_URL APP_REGION PATH]", "unwalled": "[]", "node_ignored": "[LOG_LEVEL]"}
				if !mapsEqual(applied, want) {
					t.Errorf("policy_applied variables %v, want %v", applied, want)
				}
			} else {
				if _, ok := env["NODE_ENV"]; ok || env["LOG_LEVEL"] != "node" || env["EDITOR"] != "vi" {
					t.Errorf("an unwalled run that ignores the server: NODE_ENV=%q LOG_LEVEL=%q EDITOR=%q", env["NODE_ENV"], env["LOG_LEVEL"], env["EDITOR"])
				}
				want := map[string]string{"names": "[EDITOR LOG_LEVEL]", "denied": "[]", "unwalled": "[ANTHROPIC_BASE_URL APP_REGION LOG_LEVEL NODE_ENV PATH]", "node_ignored": "[]"}
				if !mapsEqual(applied, want) {
					t.Errorf("policy_applied variables %v, want %v", applied, want)
				}
			}
			for _, name := range []string{"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN"} {
				value, ok := env[name]
				if tc.walled != ok || value != "" {
					t.Errorf("%s: %q, set %v; want set and empty behind a wall alone", name, value, ok)
				}
			}
			record, _ := os.ReadFile(filepath.Join(res.Dir, "events.jsonl"))
			for _, value := range []string{"eu-west-1", "elsewhere.example", "/nowhere"} {
				if strings.Contains(string(record), value) {
					t.Errorf("the record contains the value %q", value)
				}
			}
		})
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestWhatARunPassesInIsChecked pins the refusals of a run's own environment end to
// end, each a session.Refusal with its code and names and no value: behind a wall, a
// QORY_ variable of the node's and a variable a credential is read from are
// variable_reserved, and a value for a credential's placeholder is
// placeholder_conflict.
func TestWhatARunPassesInIsChecked(t *testing.T) {
	t.Setenv("MODEL_SOURCE", "the-credential-held-outside")
	secret := "a-value-no-error-quotes"
	for _, tc := range []struct {
		name  string
		edit  func(*session.Spec)
		code  string
		names []string
	}{
		{"a QORY_ variable", func(sp *session.Spec) { sp.Variables.Own = []string{"QORY_SERVER_SECRET=" + secret} }, "variable_reserved", []string{"QORY_SERVER_SECRET"}},
		{"what a credential is read from", func(sp *session.Spec) { sp.LaunchEnv = []string{"MODEL_SOURCE=" + secret} }, "variable_reserved", []string{"MODEL_SOURCE"}},
		{"a placeholder", func(sp *session.Spec) {
			sp.Policy = &session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "observe"}, Credentials: []session.PolicyCredential{{Name: "model"}}}
			sp.Variables.Own = []string{"MODEL_TOKEN=" + secret}
		}, "placeholder_conflict", []string{"MODEL_TOKEN"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp := spec(t, nil)
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			sp.Credentials = []session.Credential{{Name: "model", Env: "MODEL_SOURCE", Hosts: []string{"api.model.example"}, Scheme: "bearer", Placeholders: []string{"MODEL_TOKEN"}}}
			tc.edit(&sp)
			_, err := session.Run(context.Background(), sp)
			var r *session.Refusal
			if !errors.As(err, &r) || r.Code != tc.code || !slices.Equal(r.Names, tc.names) {
				t.Fatalf("%v, want %s %q", err, tc.code, tc.names)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("the error quotes a value: %v", err)
			}
		})
	}
	// Without a wall the node's own environment is the developer's, a key included.
	sp := spec(t, nil, "ANTHROPIC_API_KEY="+secret, "QORY_SERVER_SECRET="+secret)
	if res, err := session.Run(context.Background(), sp); err != nil || res.ExitCode != 0 {
		t.Errorf("an unwalled run with the developer's environment: %v", err)
	}
}

// TestTheNodesPolicyNarrowsTheServers runs a server's policy beside the node's end to
// end: a host the server allows and the node does not is denied, the record reports
// the hosts both allow and the node's policy by its digest, and a run configuration
// without a policy leaves the node's in force with the run configuration's URL and
// digest beside it.
func TestTheNodesPolicyNarrowsTheServers(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	c := newControl(t)
	digest := "sha256=" + strings.Repeat("1", 64)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1","localhost"]}}`, digest)
	node := &session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "enforce", Allow: []string{"127.0.0.1"}}}
	sp := spec(t, node, "FAKE_ALLOWED_URL="+origin.URL+"/allowed", "FAKE_DENIED_URL="+strings.Replace(origin.URL, "127.0.0.1", "localhost", 1)+"/denied")
	sp.Server = c.server()
	res, err := runWithSettingsEnv(t, sp)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	pa := data(ofType(evs, "dev.qory.run.policy_applied")[0])
	np, _ := pa["node_policy"].(map[string]any)
	if pa["source"] != "fetched" || fmt.Sprint(pa["allow"]) != "[127.0.0.1]" || pa["run_configuration"] != digest || np == nil || !regexp.MustCompile(`^sha256=[0-9a-f]{64}$`).MatchString(fmt.Sprint(np["digest"])) {
		t.Errorf("policy_applied %v", pa)
	}
	decisions := map[string]string{}
	for _, e := range ofType(evs, "dev.qory.run.egress") {
		decisions[fmt.Sprint(data(e)["host"])] = fmt.Sprint(data(e)["decision"])
	}
	if decisions["127.0.0.1"] != "allowed" || decisions["localhost"] != "denied" {
		t.Errorf("egress %v", decisions)
	}

	c.serveDocument(`{"version":1,"variables":{"NODE_ENV":"test"}}`, digest)
	sp = spec(t, node)
	sp.Server = c.server()
	res, err = session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	pa = data(ofType(events(t, res), "dev.qory.run.policy_applied")[0])
	if pa["source"] != "config" || fmt.Sprint(pa["allow"]) != "[127.0.0.1]" || pa["run_configuration"] != digest || pa["url"] != c.srv.URL+"/v1/run-configuration" || pa["node_policy"] != nil {
		t.Errorf("policy_applied without a server's policy %v", pa)
	}
}

// TestANarrowingThatRefusesIsNoRun pins the refusals of narrowing and of the run
// configuration end to end: a tool the server selects that the node's policy does not
// list is tool_unknown, a server's image other than the node's is image_unknown, and a
// variable the schema refuses is run_configuration_invalid, whose error contains no
// value.
func TestANarrowingThatRefusesIsNoRun(t *testing.T) {
	for _, tc := range []struct {
		name, doc string
		node      *session.Policy
		code      string
	}{
		{"a tool", `{"version":1,"security_policy":{"version":1,"egress":{"mode":"observe"},"tools":[{"name":"files"}]}}`,
			&session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "observe"}, Tools: []session.PolicyTool{}}, "tool_unknown"},
		{"an image", `{"version":1,"security_policy":{"version":1,"egress":{"mode":"observe"},"image":"with-docker"}}`,
			&session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "observe"}, Image: "base"}, "image_unknown"},
		{"a variable", `{"version":1,"variables":{"GREETING":"a-value-no-error-quotes\nand more"}}`, nil, "run_configuration_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newControl(t)
			c.serveDocument(tc.doc, "sha256="+strings.Repeat("1", 64))
			sp := spec(t, tc.node)
			sp.Server = c.server()
			sp.Wall, sp.Image = &openWall{}, "base"
			sp.Images = []session.Image{{Name: "base", Ref: "example.com/base:1"}, {Name: "with-docker", Ref: "example.com/docker:1", Runtime: "sysbox-runc", Docker: true}}
			sp.Tools = []session.Tool{{Name: "files", Command: []string{os.Args[0], toolMode}, Serves: []string{"files.internal"}}}
			_, err := session.Run(context.Background(), sp)
			var r *session.Refusal
			if !errors.As(err, &r) || r.Code != tc.code {
				t.Fatalf("%v, want %s", err, tc.code)
			}
			if strings.Contains(err.Error(), "a-value-no-error-quotes") {
				t.Errorf("the error quotes a value: %v", err)
			}
		})
	}
}

// TestAWalledRunPassesTheRuntimesKeyItLists pins the walled run that passes the
// runtime's credential as a node variable, as wall.env and --env do: the value reaches
// the agent as passed, and the runtime's other declared and reserved variables, which
// neither a placeholder nor the run sets, are there empty.
func TestAWalledRunPassesTheRuntimesKeyItLists(t *testing.T) {
	sp := spec(t, nil)
	out := dumpsEnv(t, &sp)
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	sp.Variables.Own = []string{"CLAUDE_CODE_OAUTH_TOKEN=a-fake-credential"}
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d", res.ExitCode)
	}
	env := envOf(t, out)
	if env["CLAUDE_CODE_OAUTH_TOKEN"] != "a-fake-credential" {
		t.Errorf("CLAUDE_CODE_OAUTH_TOKEN=%q, want the value the run passed", env["CLAUDE_CODE_OAUTH_TOKEN"])
	}
	for _, name := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"} {
		if value, ok := env[name]; !ok || value != "" {
			t.Errorf("%s: %q, set %v; want set and empty", name, value, ok)
		}
	}
}
