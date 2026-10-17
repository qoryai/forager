package session_test

import (
	"context"
	"strings"
	"testing"

	"github.com/qoryai/forager/session"
)

// entriesOf are the entries of env for the name, in order.
func entriesOf(env []string, name string) []string {
	var out []string
	for _, kv := range env {
		if n, _, _ := strings.Cut(kv, "="); n == name {
			out = append(out, kv)
		}
	}
	return out
}

// TestADeniedNameIsEmptiedBehindAWall pins that behind a wall a name the runtime denies
// or the node's deny list removes, which nothing sets, goes to the wall empty, so an
// image's value for it does not show through; that a pattern of the deny list empties
// nothing; and that a name a source sets and wins with, or one the session sets for
// the run, keeps its value, once.
func TestADeniedNameIsEmptiedBehindAWall(t *testing.T) {
	w := &openWall{}
	sp := spec(t, "INHERITED_DENIED=from-the-shell")
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.Variables.Deny = []string{"APP_SECRET", "APP_*", "INHERITED_DENIED", "HTTPS_PROXY", session.EnvRunID}
	sp.Variables.Machine = []string{"APP_SECRET=the-machines"}
	if _, err := session.Run(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"APP_SECRET":        "APP_SECRET=",
		"CLAUDE_ENV_FILE":   "CLAUDE_ENV_FILE=",
		"CLAUDE_CODE_SHELL": "CLAUDE_CODE_SHELL=",
		"INHERITED_DENIED":  "INHERITED_DENIED=from-the-shell",
	} {
		if got := entriesOf(w.got.Env, name); len(got) != 1 || got[0] != want {
			t.Errorf("the wall's environment has %q for %s, want %q once", got, name, want)
		}
	}
	if got := entriesOf(w.got.Env, "APP_*"); len(got) != 0 {
		t.Errorf("a pattern was emptied: %q", got)
	}
	// The wall sets the proxy's names inside, and the session the run's id.
	if got := entriesOf(w.got.Env, "HTTPS_PROXY"); len(got) != 0 {
		t.Errorf("the wall's environment has %q for HTTPS_PROXY, which the wall sets", got)
	}
	if got := entriesOf(w.got.Env, session.EnvRunID); len(got) != 1 || strings.HasSuffix(got[0], "=") {
		t.Errorf("the wall's environment has %q for %s, want the session's value once", got, session.EnvRunID)
	}
}

// TestAFixedValueOfADeniedNameStays pins CLAUDE_CONFIG_DIR, which the Claude runtime
// denies and the built-in list does not: the harness's fixed value reaches the wall
// once and is never emptied; without one the name goes empty; and a value of the
// server's or the run's for it is still denied, so the wall gets it empty, never with
// that value.
func TestAFixedValueOfADeniedNameStays(t *testing.T) {
	const name = "CLAUDE_CONFIG_DIR"
	for _, tc := range []struct {
		what, fixed, want string
		passed            bool
	}{
		{"fixed", name + "=/tmp/agent-home", name + "=/tmp/agent-home", false},
		{"fixed, with the server's and the run's", name + "=/tmp/agent-home", name + "=/tmp/agent-home", true},
		{"none", "", name + "=", false},
		{"the server's and the run's alone", "", name + "=", true},
	} {
		w := &openWall{}
		sp, g := specGateway(t)
		sp.Wall, sp.Image = w, "example.com/agent:1"
		if tc.fixed != "" {
			sp.LaunchFixed = []string{tc.fixed}
		}
		if tc.passed {
			answerVariables(g, `{"variables":{"`+name+`":{"value":"/server/config"}}}`)
			sp.Variables.Run = []string{name + "=/run/config"}
		}
		if _, err := session.Run(context.Background(), sp); err != nil {
			t.Fatalf("%s: %v", tc.what, err)
		}
		if got := entriesOf(w.got.Env, name); len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s: the wall's environment has %q, want %q once", tc.what, got, tc.want)
		}
	}
}
