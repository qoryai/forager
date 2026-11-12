package session_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/qoryai/forager/session"
)

// nonessential and marketplace are the variables the Claude Code descriptor's fixed
// sets to 1, and maxRetries the one it sets to 15.
const (
	nonessential = "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"
	marketplace  = "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL"
	maxRetries   = "CLAUDE_CODE_MAX_RETRIES"
)

// TestEveryClaudeCodeLaunchSetsTheFixedVariables pins the Claude Code descriptor's
// fixed end to end, through each source, for the first of its variables:
// CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC reaches the agent as 1,
// walled or not, though the image sets it empty, and CLAUDE_CODE_MAX_RETRIES as 15. Behind a wall, a value of it from the
// server, the run (--env), the machine (wall.env) or the harness's defaults is left
// out, and the record lists the name as fixed with that source lost as fixed; so is
// the inherited one when the run sets it too. A value the harness computes loses to it
// as well, and the record does not list it, as for every name of the preparation's.
// Without a wall, the server's value is left out as unwalled and the run's as fixed.
func TestEveryClaudeCodeLaunchSetsTheFixedVariables(t *testing.T) {
	for _, c := range []struct {
		source string
		want   []string
	}{
		{"none", []string{}},
		{"apiary", []string{nonessential + "<-fixed apiary:fixed"}},
		{"run", []string{nonessential + "<-fixed run:fixed"}},
		{"machine", []string{nonessential + "<-fixed machine:fixed"}},
		{"harness", []string{nonessential + "<-fixed harness:fixed"}},
		{"shell", []string{nonessential + "<-fixed run:fixed shell:fixed"}},
		{"computed", []string{}},
	} {
		t.Run(c.source, func(t *testing.T) {
			w := &imageWall{env: []string{nonessential + "="}}
			sp, g := specGateway(t)
			out := dumpsEnv(t, &sp)
			sp.Wall, sp.Image = w, "example.com/agent:1"
			passed := []string{nonessential + "=0"}
			switch c.source {
			case "apiary":
				doc, _ := json.Marshal(map[string]any{"variables": map[string]any{nonessential: map[string]any{"value": "0"}}})
				answerVariables(g, string(doc))
			case "run":
				sp.Variables.Run = passed
			case "machine":
				sp.Variables.Machine = passed
			case "harness":
				sp.LaunchDefaults = passed
			case "shell":
				sp.Env = append(sp.Env, passed...)
				sp.Variables.Run = passed
			case "computed":
				sp.LaunchFixed = passed
			}
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if res.ExitCode != 0 {
				t.Fatalf("exit %d", res.ExitCode)
			}
			if got := variablesApplied(t, res); !slices.Equal(got, c.want) {
				t.Errorf("policy_applied variables %q, want %q", got, c.want)
			}
			if got := entriesOf(w.got.Env, nonessential); !slices.Equal(got, []string{nonessential + "=1"}) {
				t.Errorf("the wall's environment has %q for %s, want it once, set to 1", got, nonessential)
			}
			if names, _ := unsetIn(t, w.got); slices.Contains(names, nonessential) {
				t.Errorf("%s is unset: %q", nonessential, names)
			}
			if got := envOf(t, out)[nonessential]; got != "1" {
				t.Errorf("%s=%q reached the agent, want 1", nonessential, got)
			}
			if got := envOf(t, out)[maxRetries]; got != "15" {
				t.Errorf("%s=%q reached the agent, want 15", maxRetries, got)
			}
		})
	}
	for _, c := range []struct {
		source string
		want   []string
	}{
		{"none", []string{}},
		{"apiary", []string{nonessential + "<-fixed apiary:unwalled"}},
		{"run", []string{nonessential + "<-fixed run:fixed"}},
		{"shell", []string{}},
	} {
		t.Run("unwalled "+c.source, func(t *testing.T) {
			sp, g := specGateway(t)
			out := dumpsEnv(t, &sp)
			sp.Variables.Unwalled = session.UnwalledIgnore
			switch c.source {
			case "apiary":
				doc, _ := json.Marshal(map[string]any{"variables": map[string]any{nonessential: map[string]any{"value": "0"}}})
				answerVariables(g, string(doc))
			case "run":
				sp.Variables.Run = []string{nonessential + "=0"}
			case "shell":
				sp.Env = append(sp.Env, nonessential+"=0")
			}
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if got := variablesApplied(t, res); !slices.Equal(got, c.want) {
				t.Errorf("policy_applied variables %q, want %q", got, c.want)
			}
			if got := envOf(t, out)[nonessential]; got != "1" {
				t.Errorf("%s=%q reached the agent, want 1", nonessential, got)
			}
			if got := envOf(t, out)[maxRetries]; got != "15" {
				t.Errorf("%s=%q reached the agent, want 15", maxRetries, got)
			}
		})
	}
}
