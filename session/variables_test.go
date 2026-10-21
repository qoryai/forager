package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/wall"
)

// dumpsEnv makes the spec's runtime write its environment to a file and returns the
// file's path.
func dumpsEnv(t *testing.T, sp *runSpec) string {
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
	pa := joinApplied(events(t, res))
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

// serverVariables is a run configuration with variables of every kind the session
// treats apart: one it applies, one the node's deny entry covers, one the runtime
// denies, one the built-in list denies, one the run sets as well, one the harness
// computes, and one the runtime declares.
const serverVariables = `{"variables":{"NODE_ENV":{"value":"test"},"APP_REGION":{"value":"eu-west-1"},` +
	`"ANTHROPIC_BASE_URL":{"value":"https://elsewhere.example"},"PATH":{"value":"/nowhere"},"LOG_LEVEL":{"value":"server"},` +
	`"CODEX_HOME":{"value":"/server/home"},"ANTHROPIC_AUTH_TOKEN":{"value":"server-credential"}}}`

// answerVariables makes the gateway's run answer carry the variables of doc, a JSON
// object with the member variables as a run configuration has it.
func answerVariables(g *linktest.Fake, doc string) {
	var vars struct {
		Variables map[string]any `json:"variables"`
	}
	if err := json.Unmarshal([]byte(doc), &vars); err != nil {
		panic(err)
	}
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["variables"] = vars.Variables
		return linktest.Reply{Status: 200, Body: a}
	})
}

// TestVariablesReachTheAgentByRung runs the sources of the variables end to end:
// behind a wall, and without one when the node accepts the server's, the value of the
// highest source of each name is in the agent's environment and every value that lost
// is not, the record lists each name with its source and its losses and no value, and
// OnVariables receives the same once, before the agent starts. Behind a wall the
// runtime's declared variables nothing applies are unset there, and so is a name it
// denies whose value lost. Without a wall, and
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
			sp, g := specGateway(t, "EDITOR=shell", "SHELL_ONLY=kept")
			answerVariables(g, serverVariables)
			out := dumpsEnv(t, &sp)
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
			res, err := run(context.Background(), sp)
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
				// Behind a wall the endpoint rule leaves the server's endpoint out: the
				// answer has no credential_hosts.
				if tc.walled {
					want[1] = "ANTHROPIC_BASE_URL apiary:endpoint_uncovered"
				}
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
			// Behind a wall too, where they are unset inside.
			for _, name := range []string{"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN"} {
				if value, ok := env[name]; ok {
					t.Errorf("%s=%q reached the agent, which nothing sets it for", name, value)
				}
			}
			events, _ := os.ReadFile(filepath.Join(res.Dir, "session.jsonl"))
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
// the run, the machine or the harness, QORY_HARNESS_HOME among them, and a variable the
// gateway's answer reserves, what a credential is read from, are variable_reserved, and
// in any run a value for a placeholder the answer names from the run, the machine or
// the harness is placeholder_conflict. The run request names each, never a value.
func TestWhatARunPassesInIsChecked(t *testing.T) {
	t.Setenv("MODEL_SOURCE", "the-credential-held-outside")
	secret := "a-value-no-error-quotes"
	for _, tc := range []struct {
		name  string
		edit  func(*runSpec)
		code  string
		names []string
	}{
		{"a QORY_ variable from --env", func(sp *runSpec) { sp.Variables.Run = []string{"QORY_X=" + secret} }, "variable_reserved", []string{"QORY_X"}},
		{"a QORY_ variable from wall.env", func(sp *runSpec) { sp.Variables.Machine = []string{"QORY_SERVER_SECRET=" + secret} }, "variable_reserved", []string{"QORY_SERVER_SECRET"}},
		{"the harness home from --env", func(sp *runSpec) {
			sp.HarnessHome = "/home/agent/.qory"
			sp.Variables.Run = []string{"QORY_HARNESS_HOME=" + secret}
		}, "variable_reserved", []string{"QORY_HARNESS_HOME"}},
		{"what a credential is read from", func(sp *runSpec) { sp.LaunchFixed = []string{"MODEL_SOURCE=" + secret} }, "variable_reserved", []string{"MODEL_SOURCE"}},
		{"a placeholder from --env", func(sp *runSpec) {
			sp.Variables.Run = []string{"MODEL_TOKEN=" + secret}
		}, "placeholder_conflict", []string{"MODEL_TOKEN"}},
		{"a placeholder from wall.env", func(sp *runSpec) {
			sp.Variables.Machine = []string{"MODEL_TOKEN=" + secret}
		}, "placeholder_conflict", []string{"MODEL_TOKEN"}},
		{"a placeholder from a harness default", func(sp *runSpec) {
			sp.LaunchDefaults = []string{"MODEL_TOKEN=" + secret}
		}, "placeholder_conflict", []string{"MODEL_TOKEN"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp, g := specGateway(t)
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
				a := linktest.RunAnswer(req)
				a["placeholders"], a["reserved"] = []string{"MODEL_TOKEN"}, []string{"MODEL_SOURCE"}
				return linktest.Reply{Status: 200, Body: a}
			})
			sp.OnVariables = func(session.Applied) { t.Error("OnVariables was called for a refused run") }
			tc.edit(&sp)
			_, err := run(context.Background(), sp)
			var r *session.Refusal
			if !errors.As(err, &r) || r.Code != tc.code || !slices.Equal(r.Names, tc.names) {
				t.Fatalf("%v, want %s %q", err, tc.code, tc.names)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("the error quotes a value: %v", err)
			}
			for _, raw := range g.RawRequests() {
				if strings.Contains(string(raw), secret) {
					t.Errorf("the run request carries a value: %s", raw)
				}
			}
		})
	}
	// Without a wall the node's own environment is the developer's, a key included.
	sp := spec(t, "ANTHROPIC_API_KEY="+secret, "QORY_SERVER_SECRET="+secret)
	if res, err := run(context.Background(), sp); err != nil || res.ExitCode != 0 {
		t.Errorf("an unwalled run with the developer's environment: %v", err)
	}
}

// TestTheHarnessHome pins QORY_HARNESS_HOME: the session sets it to the spec's
// HarnessHome, with or without a wall; without a wall it wins over a value the run
// inherits, a value of the run's own is denied as any QORY_ name, and the record lists
// the name, fixed. Behind a wall a value the run passes is variable_reserved
// (TestWhatARunPassesInIsChecked). A home that is no absolute path, or holds a line
// feed or a NUL, is an error before anything starts.
func TestTheHarnessHome(t *testing.T) {
	for _, walled := range []bool{true, false} {
		sp := spec(t)
		if walled {
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		} else {
			sp = spec(t, "QORY_HARNESS_HOME=/inherited")
			sp.Variables.Run = []string{"QORY_HARNESS_HOME=/from-the-run"}
		}
		out := dumpsEnv(t, &sp)
		sp.HarnessHome = "/home/agent/.qory/harness"
		res, err := run(context.Background(), sp)
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
		sp := spec(t)
		sp.HarnessHome = home
		_, err := run(context.Background(), sp)
		var r *session.Refusal
		if err == nil || errors.As(err, &r) {
			t.Errorf("the harness home %q: %v, want an error that is no refusal", home, err)
		}
	}
}

// TestAWalledRunPassesTheRuntimesKeyItLists pins the walled run that passes the
// runtime's credential as the machine's variable, as wall.env does: the value reaches
// the agent as passed, and the runtime's other declared and reserved variables, which
// neither a placeholder nor the run sets, are unset there.
func TestAWalledRunPassesTheRuntimesKeyItLists(t *testing.T) {
	sp := spec(t)
	out := dumpsEnv(t, &sp)
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	sp.Variables.Machine = []string{"CLAUDE_CODE_OAUTH_TOKEN=a-fake-credential"}
	res, err := run(context.Background(), sp)
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
		if value, ok := env[name]; ok {
			t.Errorf("%s=%q reached the agent; want it unset", name, value)
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

// TestWhatThePreparationSetsIsNotUnset pins that behind a wall a variable the
// runtime reserves and its preparation sets keeps the preparation's value, over a
// value the harness computes and one of the machine's, which the record lists as
// fixed, while the declared ones nothing sets are unset there.
func TestWhatThePreparationSetsIsNotUnset(t *testing.T) {
	sp := spec(t)
	out := dumpsEnv(t, &sp)
	sp.Runtime = preparing{claudeCode(t)}
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	sp.LaunchFixed = []string{"ANTHROPIC_AUTH_TOKEN=computed-by-the-harness"}
	sp.Variables.Machine = []string{"ANTHROPIC_AUTH_TOKEN=the-machines"}
	res, err := run(context.Background(), sp)
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
		if value, ok := env[name]; ok {
			t.Errorf("%s=%q reached the agent; want it unset", name, value)
		}
	}
}

// TestTheRunsAndTheMachinesVariablesAreChecked pins the refusal of a run's or a
// machine's variable that cannot be one, before anything starts and without its value
// in the error: no equals sign, a name outside the grammar, a value with a carriage
// return, a line feed or a NUL.
func TestTheRunsAndTheMachinesVariablesAreChecked(t *testing.T) {
	value := "a-value-no-error-quotes"
	for _, set := range []func(*runSpec, []string){
		func(sp *runSpec, env []string) { sp.Variables.Run = env },
		func(sp *runSpec, env []string) { sp.Variables.Machine = env },
	} {
		for _, entry := range []string{value, "BAD NAME=" + value, "1A=" + value, "A=" + value + "\r", "A=" + value + "\nB=c", "A=" + value + "\x00"} {
			sp := spec(t)
			set(&sp, []string{entry})
			_, err := run(context.Background(), sp)
			if err == nil {
				t.Errorf("%q was accepted", entry)
				continue
			}
			if strings.Contains(err.Error(), value) {
				t.Errorf("%q: the error quotes the value: %v", entry, err)
			}
		}
		sp := spec(t)
		set(&sp, []string{"ONLY_A_NAME"})
		if _, err := run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), "ONLY_A_NAME has no value") {
			t.Errorf("a name without a value: %v", err)
		}
	}
}

// TestTheServersSystemAndRepositoriesReachTheAgent pins the two QORY_ names the
// server's variables may set, end to end: behind a wall the server's QORY_RUN_SYSTEM
// and QORY_RUN_REPOSITORIES are in the agent's environment, and the run's preparation
// sees them, while the server's QORY_RUN_KEY, a near miss and an access key's variable
// are not; the run's or the machine's value of either is variable_reserved.
func TestTheServersSystemAndRepositoriesReachTheAgent(t *testing.T) {
	const doc = `{"variables":{"QORY_RUN_SYSTEM":{"value":"a system"},"QORY_RUN_REPOSITORIES":{"value":"one two"},` +
		`"QORY_RUN_KEY":{"value":"x"},"QORY_RUN_SYSTEMX":{"value":"x"},"QORY_ACCESS_KEY_SECRET":{"value":"x"}}}`
	sp, g := specGateway(t)
	answerVariables(g, doc)
	out := dumpsEnv(t, &sp)
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	prepared := filepath.Join(sp.Dir, "prepared-env")
	sp.Preparation = []string{"/bin/sh", "-c", `env > "$0"`, prepared}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d", res.ExitCode)
	}
	for _, path := range []string{out, prepared} {
		env := envOf(t, path)
		if env["QORY_RUN_SYSTEM"] != "a system" || env["QORY_RUN_REPOSITORIES"] != "one two" {
			t.Errorf("%s: QORY_RUN_SYSTEM=%q QORY_RUN_REPOSITORIES=%q", filepath.Base(path), env["QORY_RUN_SYSTEM"], env["QORY_RUN_REPOSITORIES"])
		}
		for _, name := range []string{"QORY_RUN_KEY", "QORY_RUN_SYSTEMX", "QORY_ACCESS_KEY_SECRET"} {
			if _, ok := env[name]; ok {
				t.Errorf("%s: %s is in the environment", filepath.Base(path), name)
			}
		}
	}
	for _, set := range []func(*runSpec){
		func(sp *runSpec) { sp.Variables.Run = []string{"QORY_RUN_SYSTEM=x"} },
		func(sp *runSpec) { sp.Variables.Machine = []string{"QORY_RUN_REPOSITORIES=x"} },
	} {
		sp, g := specGateway(t)
		answerVariables(g, doc)
		sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		set(&sp)
		if _, err := run(context.Background(), sp); refusal(err) != "variable_reserved" {
			t.Errorf("a node's value: %v, want variable_reserved", err)
		}
	}
}

// refusedNames are the names of the one run.refused the run's record holds, failing the
// test unless there is one and it validates against run.refused.schema.json.
func refusedNames(t *testing.T, sp runSpec) []any {
	t.Helper()
	got := ofType(events(t, &session.Result{Dir: filepath.Join(sp.RunsDir, sp.RunID)}), "dev.qory.run.refused")
	if len(got) != 1 {
		t.Fatalf("run.refused %v, want one", got)
	}
	schema, err := contracts.Compile("events/run.refused.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(data(got[0])); err != nil {
		t.Errorf("the run.refused does not validate: %v", err)
	}
	names, _ := data(got[0])["names"].([]any)
	return names
}

// joinRefused fails the test unless the run's record has one dev.qory.session.exited
// whose reason is code, valid against its schema, no dev.qory.session.started and no
// dev.qory.run.refused: a refused join opened the run and started no session.
func joinRefused(t *testing.T, sp runSpec, code string) {
	t.Helper()
	evs := events(t, &session.Result{Dir: filepath.Join(sp.RunsDir, sp.RunID)})
	exited := ofType(evs, "dev.qory.session.exited")
	if len(exited) != 1 || data(exited[0])["reason"] != code {
		t.Fatalf("session.exited %v, want one with the reason %s", exited, code)
	}
	schema, err := contracts.Compile("events/session.exited.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(data(exited[0])); err != nil {
		t.Errorf("the session.exited does not validate: %v", err)
	}
	if got := ofType(evs, "dev.qory.session.started"); len(got) != 0 {
		t.Errorf("session.started %v, want none", got)
	}
	if got := ofType(evs, "dev.qory.run.refused"); len(got) != 0 {
		t.Errorf("run.refused %v, want none", got)
	}
}

// shownIn fails the test unless the error's text contains each of want, and neither
// qak_ nor qrk_ in any case.
func shownIn(t *testing.T, err error, want []any) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(err.Error(), w.(string)) {
			t.Errorf("the refusal %v does not contain %s", err, w)
		}
	}
	if low := strings.ToLower(err.Error()); strings.Contains(low, "qak_") || strings.Contains(low, "qrk_") {
		t.Errorf("the refusal prints a secret's prefix: %v", err)
	}
}

// TestAPlaceholderConflictSendsAPhraseForASecret pins the names of a
// placeholder_conflict at the join, the session's own and one of the gateway's: in the
// refusal's text a name that contains qak_ or qrk_ in any case is the name's phrase,
// the access key secret's when it contains both, a phrase two names give once, and a
// clean name is as it is. The record has the join's session.exited with the code, and
// no names.
func TestAPlaceholderConflictSendsAPhraseForASecret(t *testing.T) {
	const ak, rk = "(a name that contains an access key secret)", "(a name that contains a run key)"
	// want are the names of the gateway's refusal as the event sends them, in the
	// refusal's order; own are the session's, sorted as its refusal's names are, and
	// detail the names its refusal's detail lists, in the order of the names before.
	for _, c := range []struct {
		placeholders []string
		want, own    []any
		detail       string
	}{
		{[]string{"QAK_TOKEN"}, []any{ak}, []any{ak}, ak},
		{[]string{"qrk_token"}, []any{rk}, []any{rk}, rk},
		{[]string{"QRK_X_QAK_Y"}, []any{ak}, []any{ak}, ak},
		{[]string{"MODEL_TOKEN", "QAK_OTHER", "QAK_TOKEN", "QRK_TOKEN"}, []any{"MODEL_TOKEN", ak, rk}, []any{rk, ak, "MODEL_TOKEN"}, "MODEL_TOKEN, " + ak + ", " + rk},
		{[]string{"MODEL_TOKEN"}, []any{"MODEL_TOKEN"}, []any{"MODEL_TOKEN"}, "MODEL_TOKEN"},
	} {
		t.Run("the session's "+strings.Join(c.placeholders, ","), func(t *testing.T) {
			sp, g := specGateway(t)
			sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
				a := linktest.RunAnswer(req)
				a["placeholders"] = c.placeholders
				return linktest.Reply{Status: 200, Body: a}
			})
			for _, p := range c.placeholders {
				sp.Variables.Run = append(sp.Variables.Run, p+"=a-value")
			}
			_, err := run(context.Background(), sp)
			var r *session.Refusal
			if !errors.As(err, &r) || r.Code != "placeholder_conflict" {
				t.Fatalf("%v, want placeholder_conflict", err)
			}
			joinRefused(t, sp, "placeholder_conflict")
			// The refusal's text, its detail and its names, holds the phrases too.
			names := make([]string, len(c.own))
			for i, n := range c.own {
				names[i] = n.(string)
			}
			if want := "the run passes a value for " + c.detail + ", a placeholder of what the gateway holds outside the enclosure: placeholder_conflict: " + strings.Join(names, ", "); err.Error() != want {
				t.Errorf("the refusal:\n got %s\nwant %s", err, want)
			}
			if !slices.Equal(r.Names, names) {
				t.Errorf("the refusal's names %q, want %q", r.Names, names)
			}
		})
		t.Run("the gateway's "+strings.Join(c.placeholders, ","), func(t *testing.T) {
			sp, g := specGateway(t)
			sleeps(&sp, 0)
			sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
			g.OnJoin(func(linktest.Join) linktest.Reply {
				return linktest.Reply{Status: 403, Body: linktest.Refusal("placeholder_conflict", "gateway", c.placeholders...)}
			})
			_, err := run(context.Background(), sp)
			var r *session.Refusal
			if !errors.As(err, &r) || r.Code != "placeholder_conflict" {
				t.Fatalf("%v, want placeholder_conflict", err)
			}
			joinRefused(t, sp, "placeholder_conflict")
			shownIn(t, err, c.want)
		})
	}
}

// TestAppliedVariablesSendAPhraseForASecret pins the variables of the run's
// policy_applied: a variable's name that contains qak_ or qrk_ in any case is sent as
// the name's phrase, the access key secret's when it contains both, in the order of the
// names, two such names as two entries; the event validates against its schema; a
// clean name is sent as it is; and OnVariables and the agent's environment have every
// name as it is.
func TestAppliedVariablesSendAPhraseForASecret(t *testing.T) {
	const ak, rk = "(a name that contains an access key secret)", "(a name that contains a run key)"
	sp := spec(t)
	out := dumpsEnv(t, &sp)
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	sp.Variables.Run = []string{"PLAIN_ONE=a", "QAK_ONE=b", "qrk_two=c", "QRK_X_QAK_Y=d"}
	var calls []session.Applied
	sp.OnVariables = func(a session.Applied) { calls = append(calls, a) }
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"PLAIN_ONE<-run", ak + "<-run", ak + "<-run", rk + "<-run"}; !slices.Equal(variablesApplied(t, res), want) {
		t.Errorf("policy_applied variables %q, want %q", variablesApplied(t, res), want)
	}
	pa := joinApplied(events(t, res))
	schema, err := contracts.Compile("events/run.policy_applied.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(data(pa[0])); err != nil {
		t.Errorf("the policy_applied does not validate: %v", err)
	}
	vars, _ := json.Marshal(data(pa[0])["variables"])
	if lower := strings.ToLower(string(vars)); strings.Contains(lower, "qak_") || strings.Contains(lower, "qrk_") {
		t.Errorf("a secret's prefix in the variables: %s", vars)
	}
	if want := []string{"PLAIN_ONE<-run", "QAK_ONE<-run", "QRK_X_QAK_Y<-run", "qrk_two<-run"}; len(calls) != 1 || !slices.Equal(lines(calls[0]), want) {
		t.Errorf("OnVariables received %v, want once %q", calls, want)
	}
	env := envOf(t, out)
	for name, value := range map[string]string{"PLAIN_ONE": "a", "QAK_ONE": "b", "qrk_two": "c", "QRK_X_QAK_Y": "d"} {
		if env[name] != value {
			t.Errorf("%s=%q, want %q", name, env[name], value)
		}
	}
}

// TestARefusalOfAnyCodeSendsAPhraseForASecret pins the names of refusals of codes
// other than placeholder_conflict, the session's variable_reserved at the join and a
// gateway's tool_unknown in a run.refused: a name that contains qak_ or qrk_ in any
// case is the name's phrase, each phrase once, the event validates against its schema,
// and a clean name is as it is.
func TestARefusalOfAnyCodeSendsAPhraseForASecret(t *testing.T) {
	const ak, rk = "(a name that contains an access key secret)", "(a name that contains a run key)"
	for _, c := range []struct {
		names []string
		want  []any
	}{
		{[]string{"QORY_QAK_X"}, []any{ak}},
		// refusal.New sorts the names it is given, phrases among them.
		{[]string{"QORY_A", "QORY_QAK_X", "QORY_QAK_Y", "QORY_QRK_Z"}, []any{rk, ak, "QORY_A"}},
		{[]string{"QORY_A"}, []any{"QORY_A"}},
	} {
		t.Run("variable_reserved "+strings.Join(c.names, ","), func(t *testing.T) {
			sp, _ := specGateway(t)
			sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			for _, n := range c.names {
				sp.Variables.Run = append(sp.Variables.Run, n+"=a-value")
			}
			_, err := run(context.Background(), sp)
			var r *session.Refusal
			if !errors.As(err, &r) || r.Code != "variable_reserved" {
				t.Fatalf("%v, want variable_reserved", err)
			}
			joinRefused(t, sp, "variable_reserved")
			shownIn(t, err, c.want)
		})
	}
	for _, c := range []struct {
		names []string
		want  []any
	}{
		{[]string{"qak_tool"}, []any{ak}},
		{[]string{"files", "qak_a", "qrk_b", "qak_c"}, []any{"files", ak, rk}},
		{[]string{"files"}, []any{"files"}},
	} {
		t.Run("tool_unknown "+strings.Join(c.names, ","), func(t *testing.T) {
			sp, g := specGateway(t)
			sleeps(&sp, 0)
			sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
			g.OnRun(func(server.LinkRunRequest) linktest.Reply {
				return linktest.Reply{Status: 403, Body: linktest.Refusal("tool_unknown", "gateway", c.names...)}
			})
			_, err := run(context.Background(), sp)
			var r *session.Refusal
			if !errors.As(err, &r) || r.Code != "tool_unknown" {
				t.Fatalf("%v, want tool_unknown", err)
			}
			if got := refusedNames(t, sp); !slices.Equal(got, c.want) {
				t.Errorf("names %q, want %q", got, c.want)
			}
		})
	}
}

// TestARunStartedSendsAPhraseForASecret pins run.started's members of the run's: the
// directory as the value's phrase, and the image and its name, a label's key and value,
// and what the run is about's kind, title and subjects' titles as the name's phrase,
// when it contains qak_ or qrk_ in any case; a subject whose ref contains one is left out; the
// event validates against its schema; a clean value is sent as it is, and the wall and
// the agent have every value as it is.
func TestARunStartedSendsAPhraseForASecret(t *testing.T) {
	const ak, rk = "(a name that contains an access key secret)", "(a name that contains a run key)"
	for name, c := range map[string]struct {
		dir, image, ref, label, kind, title, subject string
		shown                                        map[string]any
	}{
		"prefixes": {"QAK_dir", "qak_base", "example.com/agent:qrk_1", "acme/qAk_x", "QRK_kind", "qrk_x qak_y", "QRK_t",
			map[string]any{"dir": "(a value that contains an access key secret)", "image": rk, "image_name": ak, "label": ak, "kind": rk, "title": ak, "subject": rk}},
		"clean": {"work", "base", "example.com/agent:1", "acme/shop", "fix", "A title", "An issue",
			map[string]any{"image": "example.com/agent:1", "image_name": "base", "label": "acme/shop", "kind": "fix", "title": "A title", "subject": "An issue"}},
	} {
		t.Run(name, func(t *testing.T) {
			w := &openWall{}
			sp, g := specGateway(t, "FAKE_EXIT=0")
			selecting(g, "")
			sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
			sp.Dir = filepath.Join(t.TempDir(), c.dir)
			if err := os.Mkdir(sp.Dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if c.shown["dir"] == nil {
				c.shown["dir"] = sp.Dir
			}
			sp.Wall, sp.Image, sp.Images = w, c.image, []session.Image{{Name: c.image, Ref: c.ref}}
			sp.Labels = map[string]string{"repository": c.label, "issue": "7", "qrk_key": "v"}
			sp.About = &session.About{Kind: c.kind, Title: c.title, Subjects: []session.Subject{{Type: "issue", Ref: "7", Title: c.subject}, {Type: "issue", Ref: "qak_ref"}}}
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			started := data(ofType(events(t, res), "dev.qory.run.started")[0])
			ses := data(ofType(events(t, res), "dev.qory.session.started")[0])
			for name, ev := range map[string]map[string]any{"run.started": started, "session.started": ses} {
				schema, err := contracts.Compile("events/" + name + ".schema.json")
				if err != nil {
					t.Fatal(err)
				}
				if err := schema.Validate(ev); err != nil {
					t.Errorf("the %s does not validate: %v", name, err)
				}
			}
			labels, _ := started["labels"].(map[string]any)
			about, _ := started["about"].(map[string]any)
			subjects, _ := about["subjects"].([]any)
			var subject map[string]any
			if len(subjects) == 1 {
				subject, _ = subjects[0].(map[string]any)
			}
			got := map[string]any{
				"dir": ses["dir"], "image": ses["image"], "image_name": ses["image_name"],
				"label": labels["repository"], "kind": about["kind"], "title": about["title"], "subject": subject["title"],
			}
			if !reflect.DeepEqual(got, c.shown) {
				t.Errorf("run.started %v, want %v", got, c.shown)
			}
			if labels["issue"] != "7" || labels[rk] != "v" || len(labels) != 3 || subject["type"] != "issue" || subject["ref"] != "7" {
				t.Errorf("run.started labels %v, subject %v", labels, subject)
			}
			if w.req.Image != c.ref || w.got.Dir != sp.Dir {
				t.Errorf("the wall was asked for %q in %q", w.req.Image, w.got.Dir)
			}
		})
	}
}

// TestARunStartedSendsAPhraseForASecretInAnArgument pins session.started's command and
// arguments: an argument that contains qak_ or qrk_ in any case is sent as the value's
// phrase, the event validates against its schema, and a clean argument is sent as it
// is; the runtime gets every argument as it is.
func TestARunStartedSendsAPhraseForASecretInAnArgument(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	selecting(g, "")
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	sp.Args = append(sp.Args, "--name", "qrk_arg")
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	started := data(ofType(events(t, res), "dev.qory.session.started")[0])
	schema, err := contracts.Compile("events/session.started.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(started); err != nil {
		t.Errorf("the session.started does not validate: %v", err)
	}
	args, _ := started["args"].([]any)
	if !slices.Contains(args, any("(a value that contains a run key)")) || !slices.Contains(args, any("--name")) {
		t.Errorf("session.started args %v", args)
	}
	b, _ := json.Marshal(started)
	if low := strings.ToLower(string(b)); strings.Contains(low, "qak_") || strings.Contains(low, "qrk_") {
		t.Errorf("session.started contains a secret's prefix: %s", b)
	}
}

// TestThePolicyAppliedSendsAPhraseForASecretInAHarnessHost pins policy_applied's
// harness_hosts: a host that contains qak_ or qrk_ in any case is sent as the value's
// phrase, in the record and in the batch, the event validates against its schema, and a
// clean host is sent as it is.
func TestThePolicyAppliedSendsAPhraseForASecretInAHarnessHost(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	sp.Declared = []string{"api.example", "qak_FAKE.example", "QRK_FAKE.example"}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := contracts.Compile("events/run.policy_applied.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	want := []any{"api.example", "(a value that contains an access key secret)", "(a value that contains a run key)"}
	for where, evs := range map[string][]map[string]any{"record": events(t, res), "batch": g.Events()} {
		pa := joinApplied(evs)
		if len(pa) == 0 {
			t.Fatalf("%s: no policy_applied", where)
		}
		applied := data(pa[0])
		if err := schema.Validate(applied); err != nil {
			t.Errorf("%s: the policy_applied does not validate: %v", where, err)
		}
		if hosts, _ := applied["harness_hosts"].([]any); !slices.Equal(hosts, want) {
			t.Errorf("%s: harness_hosts %v, want %v", where, applied["harness_hosts"], want)
		}
	}
}

// TestARunStartedSendsAnAboutThatPhrasingEmpties pins run.started's about when every
// member of it contains qak_ or qrk_ in a form that holds no phrase: it is sent, empty,
// as an about the caller passed is, and the event validates against its schema.
func TestARunStartedSendsAnAboutThatPhrasingEmpties(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	selecting(g, "")
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	sp.About = &session.About{Subjects: []session.Subject{{Type: "issue", Ref: "qak_FAKE"}}}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	started := data(ofType(events(t, res), "dev.qory.run.started")[0])
	schema, err := contracts.Compile("events/run.started.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(started); err != nil {
		t.Errorf("the run.started does not validate: %v", err)
	}
	if about, ok := started["about"].(map[string]any); !ok || len(about) != 0 {
		t.Errorf("run.started about %v, want an empty object", started["about"])
	}
}

// wrapFails is an open wall whose Wrap fails with err.
type wrapFails struct {
	openWall
	err error
}

func (w *wrapFails) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *wrapFails) Wrap(context.Context, wall.Launch) (wall.Launch, error) {
	return wall.Launch{}, w.err
}

// TestAWrapThatFailsPrintsAPhraseForASecretInAPath pins the error of a run whose wall
// cannot wrap the launch: an error that contains qak_ or qrk_ is the phrase, and still
// wraps the wall's error.
func TestAWrapThatFailsPrintsAPhraseForASecretInAPath(t *testing.T) {
	for _, p := range []string{"/tmp/qak_FAKE/env", "/tmp/QRK_FAKE/env"} {
		w := &wrapFails{err: &fs.PathError{Op: "open", Path: p, Err: fs.ErrPermission}}
		_, err := run(context.Background(), walledSpec(t, w))
		if err == nil {
			t.Fatalf("%s: the run started", p)
		}
		if low := strings.ToLower(err.Error()); strings.Contains(low, "qak_") || strings.Contains(low, "qrk_") || !errors.Is(err, fs.ErrPermission) {
			t.Errorf("%s: %q, want a phrase that wraps fs.ErrPermission", p, err)
		}
	}
}
