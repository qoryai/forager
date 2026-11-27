package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/session"
)

// agentNamesVariables is a run configuration with an AGENT_ name the agent gets, one
// whose rest is set without the prefix as well, a name without the prefix, a forge
// token by both names, a name whose rest is not a variable's name, and the run's system
// and repositories.
const agentNamesVariables = `{"variables":{"AGENT_ONLY":{"value":"agent-only"},"AGENT_TARGET":{"value":"agent-target"},` +
	`"TARGET":{"value":"setup-target"},"DEPLOY":{"value":"setup-deploy"},` +
	`"AGENT_GH_TOKEN":{"value":"a-fake-agent-token"},"GH_TOKEN":{"value":"a-fake-setup-token"},"AGENT_9X":{"value":"x"},` +
	`"QORY_RUN_SYSTEM":{"value":"tickets"},"QORY_RUN_REPOSITORIES":{"value":"github.com/example-org/app"}}}`

// asMap is NAME=value entries by name.
func asMap(env []string) map[string]string {
	out := map[string]string{}
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		out[name] = value
	}
	return out
}

// pick is the values of names in env, by name; a name env does not have is left out.
func pick(env map[string]string, names ...string) map[string]string {
	out := map[string]string{}
	for _, name := range names {
		if v, ok := env[name]; ok {
			out[name] = v
		}
	}
	return out
}

// agentNames are the names the agent's names tests read in an environment.
var agentNames = []string{"ONLY", "AGENT_ONLY", "TARGET", "AGENT_TARGET", "DEPLOY", "GH_TOKEN", "AGENT_GH_TOKEN", "AGENT_9X", "9X",
	"RUN_ONLY", "AGENT_RUN_ONLY", "MACHINE_PLAIN", "agent_lower", "AGENT_AGENT_TWICE", "AGENT_TWICE", "TWICE", "QORY_RUN_SYSTEM", "QORY_RUN_REPOSITORIES"}

// TestTheAgentGetsOnlyAgentNamesAndTheSetupEveryName pins AgentEnv, SetupEnv and a
// join of a walled run against one another. From the server, --env and wall.env, the
// agent gets AGENT_X as X, AGENT_AGENT_TWICE as AGENT_TWICE, and none of the names
// without the prefix, agent_lower among them, but the server's QORY_RUN_SYSTEM and
// QORY_RUN_REPOSITORIES. The setup container gets every name as passed, and AGENT_X as
// X when X is not set: the server's TARGET wins over its AGENT_TARGET. The forge
// token is left out under both names, and AGENT_9X reaches neither; the fix for the
// forge token is reported once however often SetupEnv is called. The join request
// passes the run's and the machine's AGENT_ names by both names, and policy_applied
// records the names as passed in given and the names left out as not_agent.
func TestTheAgentGetsOnlyAgentNamesAndTheSetupEveryName(t *testing.T) {
	ctx := context.Background()
	sp, g := specGateway(t)
	answerVariables(g, agentNamesVariables)
	out := dumpsEnv(t, &sp)
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	sp.Variables = session.Variables{
		Run:     []string{"AGENT_RUN_ONLY=run", "AGENT_AGENT_TWICE=twice"},
		Machine: []string{"MACHINE_PLAIN=machine", "agent_lower=lower"},
	}
	var reported []string
	sp.Report = func(l string) { reported = append(reported, l) }
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	agentEnv, err := r.AgentEnv(sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	agent := map[string]string{"ONLY": "agent-only", "TARGET": "agent-target", "RUN_ONLY": "run", "AGENT_TWICE": "twice",
		"QORY_RUN_SYSTEM": "tickets", "QORY_RUN_REPOSITORIES": "github.com/example-org/app"}
	if got := pick(asMap(agentEnv), agentNames...); !maps.Equal(got, agent) {
		t.Errorf("AgentEnv has %v, want %v", got, agent)
	}
	if len(reported) != 0 {
		t.Errorf("AgentEnv reported %q, want nothing", reported)
	}
	setupEnv, err := r.SetupEnv(sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	setup := map[string]string{"ONLY": "agent-only", "TARGET": "setup-target", "DEPLOY": "setup-deploy", "RUN_ONLY": "run", "AGENT_TWICE": "twice",
		"MACHINE_PLAIN": "machine", "agent_lower": "lower", "QORY_RUN_SYSTEM": "tickets", "QORY_RUN_REPOSITORIES": "github.com/example-org/app"}
	if got := pick(asMap(setupEnv), agentNames...); !maps.Equal(got, setup) {
		t.Errorf("SetupEnv has %v, want %v", got, setup)
	}
	defineSetup := "Define GH_TOKEN as a credential in the run configuration, not as a variable: the run leaves out the value that the server passes, since denied-variables.json lists it as a forge token."
	if !slices.Equal(reported, []string{defineSetup}) {
		t.Errorf("SetupEnv reported %q, want %q", reported, defineSetup)
	}
	if again, err := r.SetupEnv(sp.SessionSpec); err != nil || !slices.Equal(again, setupEnv) {
		t.Errorf("a second SetupEnv: %q, %v; want %q", again, err, setupEnv)
	}
	if len(reported) != 1 {
		t.Errorf("two SetupEnv calls reported %q, want %q once", reported, defineSetup)
	}
	reported = nil
	res, err := r.Join(ctx, sp.SessionSpec)
	if _, cerr := r.Close(ctx, outcomeOf(res, err)); cerr != nil {
		t.Fatal(cerr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if got := pick(envOf(t, out), agentNames...); !maps.Equal(got, agent) {
		t.Errorf("the agent has %v, want %v", got, agent)
	}
	want := []string{
		"Define AGENT_GH_TOKEN as a credential in the run configuration, not as a variable.\nThe agent's container would get it as GH_TOKEN, which denied-variables.json lists as a forge token.",
		"Rename AGENT_9X in the run configuration's variables: the run leaves it out of every container.",
	}
	var got []string
	for _, l := range reported {
		if strings.HasPrefix(l, "Define ") || strings.HasPrefix(l, "Move ") || strings.HasPrefix(l, "Rename ") || strings.HasPrefix(l, "Prefix ") {
			got = append(got, l)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("the join reported\n%q\nwant\n%q", got, want)
	}
	joins := g.Joins()
	if len(joins) != 1 {
		t.Fatalf("%d join requests, want 1", len(joins))
	}
	for _, name := range []string{"AGENT_AGENT_TWICE", "AGENT_TWICE", "AGENT_RUN_ONLY", "RUN_ONLY", "MACHINE_PLAIN", "agent_lower"} {
		if !slices.Contains(joins[0].Request.Passes, name) {
			t.Errorf("the join request passes %q, without %s", joins[0].Request.Passes, name)
		}
	}
	record := map[string]string{}
	for _, line := range appliedGiven(t, res) {
		name, _, _ := strings.Cut(line, " ")
		name, _, _ = strings.Cut(name, "<-")
		record[name] = line
	}
	for _, line := range []string{
		"AGENT_9X apiary:not_agent",
		"AGENT_TWICE<-run~AGENT_AGENT_TWICE",
		"DEPLOY apiary:not_agent",
		"GH_TOKEN apiary:not_agent apiary:denied~AGENT_GH_TOKEN",
		"MACHINE_PLAIN machine:not_agent",
		"ONLY<-apiary~AGENT_ONLY",
		"QORY_RUN_REPOSITORIES<-apiary",
		"QORY_RUN_SYSTEM<-apiary",
		"RUN_ONLY<-run~AGENT_RUN_ONLY",
		"TARGET<-apiary~AGENT_TARGET apiary:not_agent",
		"agent_lower machine:not_agent",
	} {
		name, _, _ := strings.Cut(line, " ")
		name, _, _ = strings.Cut(name, "<-")
		if record[name] != line {
			t.Errorf("policy_applied has %q for %s, want %q", record[name], name, line)
		}
	}
}

// appliedGiven is variablesApplied with each name a value was passed by after ~.
func appliedGiven(t *testing.T, res *session.Result) []string {
	t.Helper()
	pa := joinApplied(events(t, res))
	if len(pa) != 1 {
		t.Fatalf("policy_applied events: %v", pa)
	}
	b, err := json.Marshal(data(pa[0])["variables"])
	if err != nil {
		t.Fatal(err)
	}
	var list []struct {
		Name, From, Given string
		Lost              []struct{ From, Why, Given string }
	}
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, e := range list {
		line := e.Name
		if e.From != "" {
			line += "<-" + e.From
		}
		if e.Given != "" {
			line += "~" + e.Given
		}
		for _, l := range e.Lost {
			line += " " + l.From + ":" + l.Why
			if l.Given != "" {
				line += "~" + l.Given
			}
		}
		out = append(out, line)
	}
	return out
}

// TestAnUnwalledRunsSetupEnvIsItsAgentEnv pins an unwalled run to the names as passed:
// AgentEnv and SetupEnv return the same environment, AGENT_ONLY and TARGET under their
// names, and SetupEnv reports nothing.
func TestAnUnwalledRunsSetupEnvIsItsAgentEnv(t *testing.T) {
	ctx := context.Background()
	sp, g := specGateway(t)
	answerVariables(g, agentNamesVariables)
	sp.Variables = session.Variables{Run: []string{"AGENT_RUN_ONLY=run"}, Unwalled: session.UnwalledAccept}
	var reported []string
	sp.Report = func(l string) { reported = append(reported, l) }
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: "succeeded"})
	agentEnv, err := r.AgentEnv(sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	setupEnv, err := r.SetupEnv(sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(agentEnv, setupEnv) {
		t.Errorf("AgentEnv %q, SetupEnv %q", agentEnv, setupEnv)
	}
	want := map[string]string{"AGENT_ONLY": "agent-only", "AGENT_TARGET": "agent-target", "TARGET": "setup-target", "DEPLOY": "setup-deploy",
		"AGENT_9X": "x", "AGENT_RUN_ONLY": "run", "AGENT_GH_TOKEN": "a-fake-agent-token", "QORY_RUN_SYSTEM": "tickets", "QORY_RUN_REPOSITORIES": "github.com/example-org/app"}
	if got := pick(asMap(agentEnv), agentNames...); !maps.Equal(got, want) {
		t.Errorf("AgentEnv has %v, want %v", got, want)
	}
	for _, l := range reported {
		if strings.HasPrefix(l, "Define ") || strings.HasPrefix(l, "Rename ") {
			t.Errorf("an unwalled run reported %q", l)
		}
	}
}

// TestAnAgentNameIsRefusedByTheNameAsPassed pins the refusals of a walled run's --env
// and wall.env on the name a container gets, each citing the name as passed, in
// AgentEnv, SetupEnv and the join alike: AGENT_QORY_RUN_ID is variable_reserved, a
// value for the placeholder TOOL_TOKEN by AGENT_TOOL_TOKEN is placeholder_conflict, with
// TOOL_TOKEN too when the run passes it, and
// AGENT_ and AGENT_9X are errors whose first words are the fix.
func TestAnAgentNameIsRefusedByTheNameAsPassed(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		run, machine []string
		want         string
		names        []string
	}{
		{[]string{"AGENT_QORY_RUN_ID=x"}, nil, "variable_reserved", []string{"AGENT_QORY_RUN_ID"}},
		{nil, []string{"AGENT_TOOL_TOKEN=x"}, "placeholder_conflict", []string{"AGENT_TOOL_TOKEN"}},
		{[]string{"TOOL_TOKEN=y"}, []string{"AGENT_TOOL_TOKEN=x"}, "placeholder_conflict", []string{"AGENT_TOOL_TOKEN", "TOOL_TOKEN"}},
		{[]string{"AGENT_=x"}, nil, "Rename AGENT_: the agent's container would get no name after the prefix.", nil},
		{nil, []string{"AGENT_9X=x"}, "Rename AGENT_9X: the agent's container would get 9X, which is not a variable's name.", nil},
	} {
		for _, call := range []string{"AgentEnv", "SetupEnv", "Join"} {
			t.Run(fmt.Sprint(tc.run, tc.machine, call), func(t *testing.T) {
				sp, g := specGateway(t)
				answerAgentEnv(g, false)
				sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
				sp.Variables = session.Variables{Run: tc.run, Machine: tc.machine}
				r, err := session.Open(ctx, opened(sp))
				if err != nil {
					t.Fatal(err)
				}
				switch call {
				case "AgentEnv":
					_, err = r.AgentEnv(sp.SessionSpec)
				case "SetupEnv":
					_, err = r.SetupEnv(sp.SessionSpec)
				default:
					var res *session.Result
					res, err = r.Join(ctx, sp.SessionSpec)
					defer r.Close(ctx, outcomeOf(res, err))
				}
				if call != "Join" {
					defer r.Close(ctx, session.Outcome{State: "succeeded"})
				}
				if err == nil || !strings.Contains(refusal(err), tc.want) {
					t.Fatalf("%v, want %q", err, tc.want)
				}
				if tc.names == nil {
					if !strings.HasPrefix(err.Error(), "Rename ") {
						t.Errorf("%v, want the fix first", err)
					}
					return
				}
				var ref *session.Refusal
				if !errors.As(err, &ref) || !slices.Equal(ref.Names, tc.names) || !strings.Contains(err.Error(), tc.names[0]) {
					t.Errorf("%#v, want the names %q in the names and the text", err, tc.names)
				}
			})
		}
	}
}

// TestASetupInTheAgentsContainerListsTheNamesToPrefix pins the line of a walled join
// whose setup commands run in the agent's container: the command gets the agent's
// variables alone, and the run lists the names the server, --env and wall.env pass
// without AGENT_, but one whose AGENT_ value applies, one the deny list leaves out, and
// one whose AGENT_ value would be left out too: the harness's CODEX_HOME, a fixed name.
func TestASetupInTheAgentsContainerListsTheNamesToPrefix(t *testing.T) {
	codexHome := strings.Replace(agentNamesVariables, `{"variables":{`, `{"variables":{"CODEX_HOME":{"value":"/server"},`, 1)
	for _, tc := range []struct {
		server  string
		fixed   []string
		machine []string
		want    string
	}{
		{agentNamesVariables, nil, nil, "Prefix DEPLOY with AGENT_ for the setup in the agent's container.\nThat setup gets only the agent's variables, so the run leaves DEPLOY out of it."},
		{agentNamesVariables, nil, []string{"MACHINE_PLAIN=x"}, "Prefix these with AGENT_ for the setup in the agent's container: DEPLOY and MACHINE_PLAIN.\nThat setup sees only the agent's variables, so these are left out of it."},
		{codexHome, []string{"CODEX_HOME=/harness"}, []string{"CODEX_HOME=/machine"}, "Prefix DEPLOY with AGENT_ for the setup in the agent's container.\nThat setup gets only the agent's variables, so the run leaves DEPLOY out of it."},
	} {
		sp, g := specGateway(t)
		answerVariables(g, tc.server)
		sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		sp.LaunchFixed = tc.fixed
		sp.Variables.Machine = tc.machine
		prepared := filepath.Join(sp.Dir, "prepared-env")
		sp.SetupRunner = setupRunner
		sp.SessionSpec.Setup = []session.SetupCommand{{Name: "install", Args: []string{"/bin/sh", "-c", `env > "$0"`, prepared}}}
		var reported []string
		sp.Report = func(l string) { reported = append(reported, l) }
		res, err := run(context.Background(), sp)
		if err != nil {
			t.Fatal(err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("exit %d", res.ExitCode)
		}
		want := map[string]string{"ONLY": "agent-only", "TARGET": "agent-target", "QORY_RUN_SYSTEM": "tickets", "QORY_RUN_REPOSITORIES": "github.com/example-org/app"}
		if got := pick(envOf(t, prepared), agentNames...); !maps.Equal(got, want) {
			t.Errorf("the setup command has %v, want %v", got, want)
		}
		var lines []string
		for _, l := range reported {
			if strings.HasPrefix(l, "Prefix ") {
				lines = append(lines, l)
			}
		}
		if !slices.Equal(lines, []string{tc.want}) {
			t.Errorf("the run reported %q, want %q", lines, tc.want)
		}
	}
}

// TestAnAgentNameIsStrippedOnceInTheRenameLine pins the line for the server's AGENT_
// names whose rest is not a variable's name: AGENT_AGENT_9X reaches the agent as
// AGENT_9X, so the server's AGENT_9X gets no line, as every container has a variable of
// that name, while AGENT_8Y, which no container has, gets one.
func TestAnAgentNameIsStrippedOnceInTheRenameLine(t *testing.T) {
	sp, g := specGateway(t)
	answerVariables(g, `{"variables":{"AGENT_AGENT_9X":{"value":"a"},"AGENT_9X":{"value":"b"},"AGENT_8Y":{"value":"c"}}}`)
	out := dumpsEnv(t, &sp)
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	var reported []string
	sp.Report = func(l string) { reported = append(reported, l) }
	if _, err := run(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	if got := pick(envOf(t, out), "AGENT_9X", "AGENT_AGENT_9X", "9X", "AGENT_8Y", "8Y"); !maps.Equal(got, map[string]string{"AGENT_9X": "a"}) {
		t.Errorf("the agent has %v, want AGENT_9X=a alone", got)
	}
	var got []string
	for _, l := range reported {
		if strings.HasPrefix(l, "Rename ") {
			got = append(got, l)
		}
	}
	if want := []string{"Rename AGENT_8Y in the run configuration's variables: the run leaves it out of every container."}; !slices.Equal(got, want) {
		t.Errorf("the join reported %q, want %q", got, want)
	}
}
