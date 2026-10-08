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
	"time"

	"github.com/qoryai/runner/session"
	"github.com/qoryai/runner/session/runtimes"
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

// variablesApplied is the variables member of the run's policy_applied, one line per
// name: the name, the source that won after <- when one did, and each loss as
// source:why.
func variablesApplied(t *testing.T, res *session.Result) []string {
	t.Helper()
	pa := ofType(events(t, res), "dev.qory.run.policy_applied")
	if len(pa) != 1 {
		t.Fatalf("policy_applied events: %v", pa)
	}
	list, ok := data(pa[0])["variables"].([]any)
	if !ok {
		t.Fatalf("policy_applied without variables: %v", data(pa[0]))
	}
	out := []string{}
	for _, item := range list {
		e := item.(map[string]any)
		line := fmt.Sprint(e["name"])
		if from, ok := e["from"]; ok {
			line += "<-" + fmt.Sprint(from)
		}
		for _, l := range e["lost"].([]any) {
			loss := l.(map[string]any)
			line += " " + fmt.Sprint(loss["from"]) + ":" + fmt.Sprint(loss["why"])
		}
		out = append(out, line)
	}
	return out
}

// lines is an Applied as variablesApplied writes the record.
func lines(applied session.Applied) []string {
	out := []string{}
	for _, v := range applied {
		line := v.Name
		if v.From != "" {
			line += "<-" + v.From
		}
		for _, l := range v.Lost {
			line += " " + l.From + ":" + l.Why
		}
		out = append(out, line)
	}
	return out
}

// serverVariables is a run configuration with variables of every kind the runner
// treats apart: one it applies, one the node's deny entry covers, one the runtime
// denies, one the built-in list denies, one the run sets as well, one the harness
// computes, and one the runtime declares.
const serverVariables = `{"version":1,"variables":{"NODE_ENV":{"value":"test"},"APP_REGION":{"value":"eu-west-1"},` +
	`"ANTHROPIC_BASE_URL":{"value":"https://elsewhere.example"},"PATH":{"value":"/nowhere"},"LOG_LEVEL":{"value":"server"},` +
	`"CODEX_HOME":{"value":"/server/home"},"ANTHROPIC_AUTH_TOKEN":{"value":"server-credential"}}}`

// TestVariablesReachTheAgentByRung runs the sources of the variables end to end:
// behind a wall, and without one when the node accepts the server's, the value of the
// highest source of each name is in the agent's environment and every value that lost
// is not, the record lists each name with its source and its losses and no value, and
// OnVariables receives the same once, before the agent starts. Behind a wall the
// runtime's declared variables nothing applies are there empty. Without a wall, and
// without accept, none of the server's is there and the run's own apply.
func TestVariablesReachTheAgentByRung(t *testing.T) {
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
			sp := spec(t, nil, "EDITOR=shell", "SHELL_ONLY=kept")
			out := dumpsEnv(t, &sp)
			sp.Server, sp.Heartbeat = c.server(), time.Second
			sp.LaunchFixed = []string{"CODEX_HOME=/computed/home", "DOCKER_HOST=unix:///computed/docker.sock"}
			sp.LaunchDefaults = []string{"HARNESS_PROFILE=nextjs", "BUILD_NUMBER=0", "LOG_LEVEL=harness"}
			sp.Variables = session.Variables{
				Run:     []string{"LOG_LEVEL=run", "EDITOR=vi"},
				Machine: []string{"EDITOR=nano", "BUILD_NUMBER=7"},
				Deny:    []string{"APP_*"}, Unwalled: tc.unwalled,
			}
			var calls []session.Applied
			sp.OnVariables = func(a session.Applied) {
				if _, err := os.Stat(out); err == nil {
					t.Error("OnVariables was called after the agent started")
				}
				calls = append(calls, a)
			}
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
			record := variablesApplied(t, res)
			server := tc.walled || tc.unwalled == session.UnwalledAccept
			var want []string
			wantEnv := map[string]string{
				"CODEX_HOME": "/computed/home", "HARNESS_PROFILE": "nextjs", "BUILD_NUMBER": "7",
				"EDITOR": "vi", "SHELL_ONLY": "kept", "PATH": os.Getenv("PATH"),
			}
			if server {
				want = []string{
					"ANTHROPIC_AUTH_TOKEN apiary:denied", "ANTHROPIC_BASE_URL apiary:denied", "APP_REGION apiary:denied",
					"BUILD_NUMBER<-machine harness:overridden", "CODEX_HOME<-fixed apiary:fixed", "DOCKER_HOST fixed:denied",
					"EDITOR<-run machine:overridden shell:overridden", "HARNESS_PROFILE<-harness",
					"LOG_LEVEL<-apiary run:overridden harness:overridden", "NODE_ENV<-apiary", "PATH<-shell apiary:denied",
				}
				wantEnv["LOG_LEVEL"], wantEnv["NODE_ENV"] = "server", "test"
			} else {
				want = []string{
					"ANTHROPIC_AUTH_TOKEN apiary:unwalled", "ANTHROPIC_BASE_URL apiary:unwalled", "APP_REGION apiary:unwalled",
					"BUILD_NUMBER<-machine harness:overridden", "CODEX_HOME<-fixed apiary:unwalled", "DOCKER_HOST fixed:denied",
					"EDITOR<-run machine:overridden shell:overridden", "HARNESS_PROFILE<-harness",
					"LOG_LEVEL<-run apiary:unwalled harness:overridden", "NODE_ENV apiary:unwalled", "PATH<-shell apiary:unwalled",
				}
				wantEnv["LOG_LEVEL"] = "run"
			}
			if !slices.Equal(record, want) {
				t.Errorf("policy_applied variables\n%q\nwant\n%q", record, want)
			}
			if len(calls) != 1 || !slices.Equal(lines(calls[0]), want) {
				t.Errorf("OnVariables received %v, want once %q", calls, want)
			}
			for name, value := range wantEnv {
				if env[name] != value {
					t.Errorf("%s=%q, want %q", name, env[name], value)
				}
			}
			for _, name := range []string{"APP_REGION", "ANTHROPIC_BASE_URL", "DOCKER_HOST"} {
				if value, ok := env[name]; ok {
					t.Errorf("%s=%q reached the agent, a value that lost", name, value)
				}
			}
			if _, ok := env["NODE_ENV"]; !server && ok {
				t.Errorf("NODE_ENV=%q reached an unwalled run that ignores the server", env["NODE_ENV"])
			}
			for _, name := range []string{"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN"} {
				value, ok := env[name]
				if tc.walled != ok || value != "" {
					t.Errorf("%s: %q, set %v; want set and empty behind a wall alone", name, value, ok)
				}
			}
			events, _ := os.ReadFile(filepath.Join(res.Dir, "events.jsonl"))
			for _, value := range []string{"eu-west-1", "elsewhere.example", "/nowhere", "server-credential", "/server/home", "nextjs", "computed"} {
				if strings.Contains(string(events), value) {
					t.Errorf("the record contains the value %q", value)
				}
			}
		})
	}
}

// TestWhatARunPassesInIsChecked pins the refusals of a run's own environment end to
// end, before the variables are resolved, each a session.Refusal with its code and
// names and no value, and OnVariables not called: behind a wall, a QORY_ variable from
// the run, the machine or the harness, QORY_HARNESS_HOME among them, and a variable a
// credential is read from are variable_reserved, and in any run a value for a
// credential's placeholder from the run, the machine or the harness is
// placeholder_conflict.
func TestWhatARunPassesInIsChecked(t *testing.T) {
	t.Setenv("MODEL_SOURCE", "the-credential-held-outside")
	secret := "a-value-no-error-quotes"
	withCredential := func(sp *session.Spec) {
		sp.Policy = &session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "observe"}, Credentials: []session.PolicyCredential{{Name: "model"}}}
	}
	for _, tc := range []struct {
		name  string
		edit  func(*session.Spec)
		code  string
		names []string
	}{
		{"a QORY_ variable from --env", func(sp *session.Spec) { sp.Variables.Run = []string{"QORY_X=" + secret} }, "variable_reserved", []string{"QORY_X"}},
		{"a QORY_ variable from wall.env", func(sp *session.Spec) { sp.Variables.Machine = []string{"QORY_SERVER_SECRET=" + secret} }, "variable_reserved", []string{"QORY_SERVER_SECRET"}},
		{"the harness home from --env", func(sp *session.Spec) {
			sp.HarnessHome = "/home/agent/.qory"
			sp.Variables.Run = []string{"QORY_HARNESS_HOME=" + secret}
		}, "variable_reserved", []string{"QORY_HARNESS_HOME"}},
		{"what a credential is read from", func(sp *session.Spec) { sp.LaunchFixed = []string{"MODEL_SOURCE=" + secret} }, "variable_reserved", []string{"MODEL_SOURCE"}},
		{"a placeholder from --env", func(sp *session.Spec) {
			withCredential(sp)
			sp.Variables.Run = []string{"MODEL_TOKEN=" + secret}
		}, "placeholder_conflict", []string{"MODEL_TOKEN"}},
		{"a placeholder from wall.env", func(sp *session.Spec) {
			withCredential(sp)
			sp.Variables.Machine = []string{"MODEL_TOKEN=" + secret}
		}, "placeholder_conflict", []string{"MODEL_TOKEN"}},
		{"a placeholder from a harness default", func(sp *session.Spec) {
			withCredential(sp)
			sp.LaunchDefaults = []string{"MODEL_TOKEN=" + secret}
		}, "placeholder_conflict", []string{"MODEL_TOKEN"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp := spec(t, nil)
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			sp.Credentials = []session.Credential{{Name: "model", Env: "MODEL_SOURCE", Hosts: []string{"api.model.example"}, Scheme: "bearer", Placeholders: []string{"MODEL_TOKEN"}}}
			sp.OnVariables = func(session.Applied) { t.Error("OnVariables was called for a refused run") }
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

// TestTheHarnessHome pins QORY_HARNESS_HOME: the runner sets it to the spec's
// HarnessHome, with or without a wall; without a wall it wins over a value the run
// inherits, a value of the run's own is denied as any QORY_ name, and the record lists
// the name, fixed. Behind a wall a value the run passes is variable_reserved
// (TestWhatARunPassesInIsChecked). A home that is no absolute path, or holds a line
// feed or a NUL, is an error before anything starts.
func TestTheHarnessHome(t *testing.T) {
	for _, walled := range []bool{true, false} {
		sp := spec(t, nil)
		if walled {
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		} else {
			sp = spec(t, nil, "QORY_HARNESS_HOME=/inherited")
			sp.Variables.Run = []string{"QORY_HARNESS_HOME=/from-the-run"}
		}
		out := dumpsEnv(t, &sp)
		sp.HarnessHome = "/home/agent/.qory/harness"
		res, err := session.Run(context.Background(), sp)
		if err != nil {
			t.Fatal(err)
		}
		if got := envOf(t, out)["QORY_HARNESS_HOME"]; got != "/home/agent/.qory/harness" {
			t.Errorf("walled %v: QORY_HARNESS_HOME=%q", walled, got)
		}
		want := []string{}
		if !walled {
			want = []string{"QORY_HARNESS_HOME<-fixed run:denied shell:fixed"}
		}
		if got := variablesApplied(t, res); !slices.Equal(got, want) {
			t.Errorf("walled %v: the record %q, want %q", walled, got, want)
		}
	}
	for _, home := range []string{"relative/home", "/home/agent\n/x", "/home/\x00"} {
		sp := spec(t, nil)
		sp.HarnessHome = home
		_, err := session.Run(context.Background(), sp)
		var r *session.Refusal
		if err == nil || errors.As(err, &r) {
			t.Errorf("the harness home %q: %v, want an error that is no refusal", home, err)
		}
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
	sp.Server, sp.Heartbeat = c.server(), time.Second
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

	c.serveDocument(`{"version":1,"variables":{"NODE_ENV":{"value":"test"}}}`, digest)
	sp = spec(t, node)
	sp.Server, sp.Heartbeat = c.server(), time.Second
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
		{"a variable", `{"version":1,"variables":{"GREETING":{"value":"a-value-no-error-quotes\nand more"}}}`, nil, "run_configuration_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newControl(t)
			c.serveDocument(tc.doc, "sha256="+strings.Repeat("1", 64))
			sp := spec(t, tc.node)
			sp.Server, sp.Heartbeat = c.server(), time.Second
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
// runtime's credential as the machine's variable, as wall.env does: the value reaches
// the agent as passed, and the runtime's other declared and reserved variables, which
// neither a placeholder nor the run sets, are there empty.
func TestAWalledRunPassesTheRuntimesKeyItLists(t *testing.T) {
	sp := spec(t, nil)
	out := dumpsEnv(t, &sp)
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	sp.Variables.Machine = []string{"CLAUDE_CODE_OAUTH_TOKEN=a-fake-credential"}
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

// preparing is the Claude Code runtime with a preparation that sets one of the
// variables the runtime reserves.
type preparing struct{ runtimes.Runtime }

func (p preparing) Prepare(a runtimes.Attach) (runtimes.Launch, error) {
	l, err := p.Runtime.Prepare(a)
	l.Env = append(l.Env, "ANTHROPIC_AUTH_TOKEN=set-by-the-preparation")
	return l, err
}

func (p preparing) Secrets() runtimes.Declarations { return p.Runtime.(runtimes.Secrets).Secrets() }

// TestWhatThePreparationSetsIsNotEmptied pins that behind a wall a variable the
// runtime reserves and its preparation sets keeps the preparation's value, over a
// value the harness computes and one of the machine's, which the record lists as
// fixed, while the declared ones nothing sets are there empty.
func TestWhatThePreparationSetsIsNotEmptied(t *testing.T) {
	sp := spec(t, nil)
	out := dumpsEnv(t, &sp)
	sp.Runtime = preparing{claudeCode(t)}
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	sp.LaunchFixed = []string{"ANTHROPIC_AUTH_TOKEN=computed-by-the-harness"}
	sp.Variables.Machine = []string{"ANTHROPIC_AUTH_TOKEN=the-machines"}
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d", res.ExitCode)
	}
	env := envOf(t, out)
	if env["ANTHROPIC_AUTH_TOKEN"] != "set-by-the-preparation" {
		t.Errorf("ANTHROPIC_AUTH_TOKEN=%q, want the preparation's value", env["ANTHROPIC_AUTH_TOKEN"])
	}
	if got, want := variablesApplied(t, res), []string{"ANTHROPIC_AUTH_TOKEN<-fixed machine:fixed"}; !slices.Equal(got, want) {
		t.Errorf("the record %q, want %q", got, want)
	}
	for _, name := range []string{"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"} {
		if value, ok := env[name]; !ok || value != "" {
			t.Errorf("%s: %q, set %v; want set and empty", name, value, ok)
		}
	}
}

// TestTheRunsAndTheMachinesVariablesAreChecked pins the refusal of a run's or a
// machine's variable that cannot be one, before anything starts and without its value
// in the error: no equals sign, a name outside the grammar, a value with a carriage
// return, a line feed or a NUL.
func TestTheRunsAndTheMachinesVariablesAreChecked(t *testing.T) {
	value := "a-value-no-error-quotes"
	for _, set := range []func(*session.Spec, []string){
		func(sp *session.Spec, env []string) { sp.Variables.Run = env },
		func(sp *session.Spec, env []string) { sp.Variables.Machine = env },
	} {
		for _, entry := range []string{value, "BAD NAME=" + value, "1A=" + value, "A=" + value + "\r", "A=" + value + "\nB=c", "A=" + value + "\x00"} {
			sp := spec(t, nil)
			set(&sp, []string{entry})
			_, err := session.Run(context.Background(), sp)
			if err == nil {
				t.Errorf("%q was accepted", entry)
				continue
			}
			if strings.Contains(err.Error(), value) {
				t.Errorf("%q: the error quotes the value: %v", entry, err)
			}
		}
		sp := spec(t, nil)
		set(&sp, []string{"ONLY_A_NAME"})
		if _, err := session.Run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), "ONLY_A_NAME has no value") {
			t.Errorf("a name without a value: %v", err)
		}
	}
}
