package session

import (
	"testing"

	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session/internal/variables"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/claude"
	"github.com/qoryai/forager/wall"
)

// anyWall is a wall that checkModelKey only tests for being set.
type anyWall struct{ wall.Wall }

// TestTheModelKeyTrialRunsOnlyForARefusal pins that checkModelKey calls passes, the
// trial resolution of a model key's variable, only when it refuses the run: never for
// a run that starts, and once per model key at most for one it refuses.
func TestTheModelKeyTrialRunsOnlyForARefusal(t *testing.T) {
	rt, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	forge := server.LinkCredentialHosts{Name: "forge", Hosts: []string{"api.github.com"}, Placeholders: []string{"GITHUB_TOKEN"}}
	model := server.LinkCredentialHosts{Name: "model", Hosts: []string{"api.anthropic.com"}, Placeholders: []string{"ANTHROPIC_API_KEY"}}
	for _, tc := range []struct {
		what    string
		env     []string
		set     []string
		creds   []server.LinkCredentialHosts
		refused bool
	}{
		{"a model credential", nil, nil, []server.LinkCredentialHosts{forge, model}, false},
		{"a value that reaches the runtime", nil, []string{"ANTHROPIC_API_KEY=k"}, []server.LinkCredentialHosts{forge}, false},
		{"no model key", nil, nil, []server.LinkCredentialHosts{forge}, true},
		{"an endpoint with no host Forager reads", []string{"ANTHROPIC_BASE_URL=http://litellm.internal:4000"}, nil, []server.LinkCredentialHosts{forge, model}, true},
	} {
		t.Run(tc.what, func(t *testing.T) {
			spec := Spec{Wall: anyWall{}, Env: tc.env}
			vars := variables.Resolved{Env: tc.set}
			trials := 0
			passes := func(string) bool { trials++; return true }
			err := checkModelKey(spec, rt, tc.creds, vars, runtimes.Launch{}, passes)
			if (err != nil) != tc.refused {
				t.Fatalf("%v, want refused %v", err, tc.refused)
			}
			if !tc.refused && trials != 0 {
				t.Errorf("%d trials for a run that starts, want 0", trials)
			}
			if tc.refused && (trials == 0 || trials > 3) {
				t.Errorf("%d trials for a refused run, want 1 to 3", trials)
			}
		})
	}
}
