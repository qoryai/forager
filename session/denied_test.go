package session_test

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
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

// unsetIn reads the launch a walled run gave the wall: the helper's exec, as the
// spec's Exec names it, with the names it unsets, then -- and the launch it starts.
func unsetIn(t *testing.T, l wall.Launch) (names, launch []string) {
	t.Helper()
	if l.Command != os.Args[0] || len(l.Args) == 0 || l.Args[0] != "exec" {
		t.Fatalf("the launch does not start with the helper's exec: %s %q", l.Command, l.Args)
	}
	args := l.Args[1:]
	for len(args) >= 2 && args[0] == "--unset" {
		names, args = append(names, args[1]), args[2:]
	}
	if len(args) < 2 || args[0] != "--" {
		t.Fatalf("the helper's exec has no -- and launch: %q", l.Args)
	}
	return names, args[1:]
}

// imageWall is an open wall whose enclosure gives the launch the variables of env as
// an image's ENV does: each a name the run's environment holds no entry for.
type imageWall struct {
	openWall
	env []string
}

func (w *imageWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *imageWall) Wrap(ctx context.Context, l wall.Launch) (wall.Launch, error) {
	out, err := w.openWall.Wrap(ctx, l)
	for _, kv := range w.env {
		if name, _, _ := strings.Cut(kv, "="); len(entriesOf(out.Env, name)) == 0 {
			out.Env = append(out.Env, kv)
		}
	}
	return out, err
}

// TestAWalledLaunchStartsThroughTheHelpersExec pins that behind a wall the launch
// starts through the helper's exec, in front of everything else, with the runtime's
// declared, reserved and denied names that nothing sets, which the environment the wall
// gets holds no entry for, empty or not; that the launch after it is the one
// dev.qory.run.started records, which names no word of the helper's; and that the
// agent sees the names unset, though the enclosure gives each a value, as an image's
// ENV does.
func TestAWalledLaunchStartsThroughTheHelpersExec(t *testing.T) {
	w := &imageWall{env: []string{"ANTHROPIC_BASE_URL=https://image.invalid/", "CLAUDE_CONFIG_DIR=/image", "ANTHROPIC_API_KEY="}}
	sp := spec(t)
	out := dumpsEnv(t, &sp)
	sp.Wall, sp.Image = w, "example.com/agent:1"
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	names, launch := unsetIn(t, w.got)
	for _, name := range []string{"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CONFIG_DIR", "ANTHROPIC_BASE_URL"} {
		if !slices.Contains(names, name) {
			t.Errorf("%s is not unset: %q", name, names)
		}
	}
	for _, name := range names {
		if got := entriesOf(w.got.Env, name); len(got) != 0 {
			t.Errorf("the wall's environment has %q for %s, which is unset", got, name)
		}
	}
	started := data(ofType(events(t, res), "dev.qory.run.started")[0])
	recorded := append([]string{started["command"].(string)}, anyStrings(started["args"])...)
	if !slices.Equal(launch, recorded) {
		t.Errorf("the helper's exec starts %q, and the record says %q", launch, recorded)
	}
	if slices.Contains(recorded, "--unset") || slices.Contains(recorded, "exec") {
		t.Errorf("the record names the helper's words: %q", recorded)
	}
	env := envOf(t, out)
	for _, name := range names {
		if value, ok := env[name]; ok {
			t.Errorf("%s=%q reached the agent; want it unset", name, value)
		}
	}
	for _, kv := range w.env {
		if name, _, _ := strings.Cut(kv, "="); !slices.Contains(names, name) {
			t.Errorf("%s, which the enclosure sets, is not unset: %q", name, names)
		}
	}
}

// TestADeniedNameIsUnsetBehindAWall pins that behind a wall a name the runtime denies
// or the node's deny list removes, which nothing sets, is unset inside, so an image's
// value for it does not show through; that a pattern of the deny list unsets nothing;
// and that a name a source sets and wins with, or one the session or the wall sets for
// the run, keeps its value and is never unset.
func TestADeniedNameIsUnsetBehindAWall(t *testing.T) {
	w := &openWall{}
	sp := spec(t, "INHERITED_DENIED=from-the-shell")
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.Variables.Deny = []string{"APP_SECRET", "APP_*", "INHERITED_DENIED", "HTTPS_PROXY", session.EnvRunID}
	sp.Variables.Machine = []string{"APP_SECRET=the-machines"}
	if _, err := session.Run(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	names, _ := unsetIn(t, w.got)
	for _, name := range []string{"APP_SECRET", "CLAUDE_ENV_FILE", "CLAUDE_CODE_SHELL"} {
		if !slices.Contains(names, name) || len(entriesOf(w.got.Env, name)) != 0 {
			t.Errorf("%s: unset %q, the wall's environment %q; want it unset alone", name, names, entriesOf(w.got.Env, name))
		}
	}
	for _, name := range []string{"APP_*", "INHERITED_DENIED", "HTTPS_PROXY", session.EnvRunID} {
		if slices.Contains(names, name) {
			t.Errorf("%s is unset: %q", name, names)
		}
	}
	if got := entriesOf(w.got.Env, "INHERITED_DENIED"); !slices.Equal(got, []string{"INHERITED_DENIED=from-the-shell"}) {
		t.Errorf("the wall's environment has %q for INHERITED_DENIED, want the inherited value once", got)
	}
	if got := entriesOf(w.got.Env, session.EnvRunID); len(got) != 1 || strings.HasSuffix(got[0], "=") {
		t.Errorf("the wall's environment has %q for %s, want the session's value once", got, session.EnvRunID)
	}
}

// TestAFixedValueOfADeniedNameStays pins CLAUDE_CONFIG_DIR, which the Claude runtime
// denies and the built-in list does not: the harness's fixed value reaches the wall
// once and is never unset; without one the name is unset; and a value of the server's
// or the run's for it is still denied, so the wall never gets it with that value, and
// the name is unset.
func TestAFixedValueOfADeniedNameStays(t *testing.T) {
	const name = "CLAUDE_CONFIG_DIR"
	for _, tc := range []struct {
		what, fixed  string
		passed, gone bool
	}{
		{"fixed", name + "=/tmp/agent-home", false, false},
		{"fixed, with the server's and the run's", name + "=/tmp/agent-home", true, false},
		{"none", "", false, true},
		{"the server's and the run's alone", "", true, true},
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
		names, _ := unsetIn(t, w.got)
		got := entriesOf(w.got.Env, name)
		switch {
		case tc.gone && (!slices.Contains(names, name) || len(got) != 0):
			t.Errorf("%s: unset %q, the wall's environment %q; want it unset alone", tc.what, names, got)
		case !tc.gone && (slices.Contains(names, name) || !slices.Equal(got, []string{tc.fixed})):
			t.Errorf("%s: unset %q, the wall's environment %q; want %q once", tc.what, names, got, tc.fixed)
		}
	}
}

// TestExecIsAWallsAlone pins that a walled run needs the helper's exec, refused before
// anything starts without one, and that a run without a wall needs none and starts its
// launch as it is.
func TestExecIsAWallsAlone(t *testing.T) {
	sp, g := specGateway(t)
	sp.Wall, sp.Image, sp.Exec = &openWall{}, "example.com/agent:1", nil
	if _, err := session.Run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), "Exec") {
		t.Errorf("a walled run without Exec: %v", err)
	}
	if len(g.Requests()) > 0 {
		t.Error("the gateway was asked")
	}
	for _, exec := range [][]string{{""}, {os.Args[0], "a\x00b"}} {
		sp := spec(t)
		sp.Wall, sp.Image, sp.Exec = &openWall{}, "example.com/agent:1", exec
		if _, err := session.Run(context.Background(), sp); err == nil {
			t.Errorf("Exec %q was taken", exec)
		}
	}
	sp = spec(t, "FAKE_EXIT=0")
	sp.Exec = nil
	if res, err := session.Run(context.Background(), sp); err != nil || res.ExitCode != 0 {
		t.Errorf("a run without a wall and without Exec: %v, %+v", err, res)
	}
}

// settingWall is an open wall that sets the names it lists itself, as a [wall.Setter].
type settingWall struct {
	openWall
	sets []string
}

func (w *settingWall) Sets() []string { return w.sets }

// TestANameTheWallSetsIsNeverUnset pins that the helper's exec, which runs after the
// wall's programs, never unsets a name the wall sets: the nested daemon's DOCKER_CONFIG
// in a run with nested Docker, though the node's deny list names it, which a run
// without nested Docker unsets; and a name the runtime declares that the wall sets.
// DOCKER_CONFIG is the one exception to an image's ENV never setting a name that is
// unset: with nested Docker, wall.Nest keeps a non-empty value it finds, the image's
// included, in place of the wall's configuration, as the contract's §The wall says, so
// unsetting it after Nest would take the wall's value away and before would change
// that rule.
func TestANameTheWallSetsIsNeverUnset(t *testing.T) {
	for _, c := range []struct {
		image string
		unset bool
	}{{"with-docker", false}, {"base", true}} {
		w := &openWall{}
		sp, g := specGateway(t, "FAKE_EXIT=0")
		selecting(g, c.image)
		sp.Wall, sp.Image, sp.Images = w, "base", images
		sp.Variables.Deny = []string{"DOCKER_CONFIG"}
		if _, err := session.Run(context.Background(), sp); err != nil {
			t.Fatalf("%s: %v", c.image, err)
		}
		if names, _ := unsetIn(t, w.got); slices.Contains(names, "DOCKER_CONFIG") != c.unset {
			t.Errorf("%s: unset %q; want DOCKER_CONFIG among them %v", c.image, names, c.unset)
		}
	}
	w := &settingWall{sets: []string{"CLAUDE_CODE_OAUTH_TOKEN"}}
	sp := spec(t, "FAKE_EXIT=0")
	sp.Wall, sp.Image = w, "example.com/agent:1"
	if _, err := session.Run(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	names, _ := unsetIn(t, w.got)
	if slices.Contains(names, "CLAUDE_CODE_OAUTH_TOKEN") || !slices.Contains(names, "ANTHROPIC_API_KEY") {
		t.Errorf("unset %q; want the runtime's names but the one the wall sets", names)
	}
}

// authorityWall is an open wall that sets NODE_EXTRA_CA_CERTS for a run with an
// authority alone, as the Docker adapter sets its CA names.
type authorityWall struct{ openWall }

func (w *authorityWall) Sets() []string              { return []string{"NODE_EXTRA_CA_CERTS"} }
func (w *authorityWall) SetsWithAuthority() []string { return []string{"NODE_EXTRA_CA_CERTS"} }

// TestANameTheWallSetsWithAnAuthorityIsUnsetWithoutOne pins a name the wall sets only
// for a run with an authority, which the node's deny list names: a run without one
// unsets it, so an image's value does not show through, and a run with one leaves it
// to the wall.
func TestANameTheWallSetsWithAnAuthorityIsUnsetWithoutOne(t *testing.T) {
	for _, withAuthority := range []bool{false, true} {
		w := &authorityWall{}
		sp, g := specGateway(t, "FAKE_EXIT=0")
		if withAuthority {
			g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
				a := linktest.RunAnswer(req)
				a["certificate_authority"] = authority
				return linktest.Reply{Status: 200, Body: a}
			})
		}
		sp.Wall, sp.Image = w, "example.com/agent:1"
		sp.Variables.Deny = []string{"NODE_EXTRA_CA_CERTS"}
		if _, err := session.Run(context.Background(), sp); err != nil {
			t.Fatalf("an authority %v: %v", withAuthority, err)
		}
		if names, _ := unsetIn(t, w.got); slices.Contains(names, "NODE_EXTRA_CA_CERTS") == withAuthority {
			t.Errorf("an authority %v: unset %q", withAuthority, names)
		}
		if withAuthority && len(w.got.CA) == 0 {
			t.Error("the wall got no authority")
		}
	}
}

// TestAVariableThatAddsPluginsOrDirectoriesIsDenied pins the variables that lead
// Claude Code's plugin or settings loaders to a directory or a file past the checks of
// --plugin-dir and --add-dir: CLAUDE_CODE_PLUGIN_DIRS, CLAUDE_RELAUNCH_SESSION_ADD_DIRS,
// CLAUDE_CODE_PLUGIN_SEED_DIR, CLAUDE_CODE_PLUGIN_CACHE_DIR and
// CLAUDE_CODE_MANAGED_SETTINGS_PATH. The Claude runtime denies them, so a value of the
// server's, the run's or the machine's never reaches the wall, and the name is unset
// inside.
func TestAVariableThatAddsPluginsOrDirectoriesIsDenied(t *testing.T) {
	for _, name := range []string{"CLAUDE_CODE_PLUGIN_DIRS", "CLAUDE_RELAUNCH_SESSION_ADD_DIRS",
		"CLAUDE_CODE_PLUGIN_SEED_DIR", "CLAUDE_CODE_PLUGIN_CACHE_DIR", "CLAUDE_CODE_MANAGED_SETTINGS_PATH"} {
		t.Run(name, func(t *testing.T) {
			w := &openWall{}
			sp, g := specGateway(t)
			sp.Wall, sp.Image = w, "example.com/agent:1"
			answerVariables(g, `{"variables":{"`+name+`":{"value":"/server/plugins"}}}`)
			sp.Variables.Run = []string{name + "=/run/plugins"}
			sp.Variables.Machine = []string{name + "=/machine/plugins"}
			if _, err := session.Run(context.Background(), sp); err != nil {
				t.Fatal(err)
			}
			names, _ := unsetIn(t, w.got)
			if got := entriesOf(w.got.Env, name); !slices.Contains(names, name) || len(got) != 0 {
				t.Errorf("unset %q, the wall's environment %q; want it unset alone", names, got)
			}
		})
	}
}
