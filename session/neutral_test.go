package session_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// neutralRun is a run of the fake runtime, started through a script in the harness
// home, whose arguments contain the run directory, the harness home and the inputs
// directory, each as a whole argument and inside a -p prompt. The inputs directory is
// passed with a trailing slash.
type neutralRun struct {
	*sepRun
	runDir, home, inputs string
	harness              []session.HarnessSource
}

// newNeutralRun is a neutralRun at the gateway gw for the run runID, with its harness
// home at home and its inputs directory at inputs.
func newNeutralRun(t *testing.T, gw session.Gateway, runID, runsDir, home, inputs string) *neutralRun {
	t.Helper()
	r := &neutralRun{sepRun: newSepRun(t, gw), home: home, inputs: inputs,
		harness: []session.HarnessSource{{Source: "https://git.example/example-org/harness#main", Commit: strings.Repeat("a1", 20)}}}
	r.sp.RunsDir, r.sp.RunID = runsDir, runID
	r.runDir = filepath.Join(runsDir, runID)
	for _, d := range []string{home, inputs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(home, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "bin", "agent"), []byte("#!/bin/sh\nexec /bin/sh \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.sp.Command = filepath.Join(home, "bin", "agent")
	r.sp.HarnessHome, r.sp.InputsDir, r.sp.Harness = home, inputs+"/", r.harness
	r.sp.Args = append(r.sp.Args,
		"-p", "Read "+r.runDir+"/sessions/1/task.md, "+inputs+"/issue.md and "+home+"/CLAUDE.md, then work in "+r.sp.Dir+".",
		"--settings", home+"/settings.json", "--add-dir", inputs, "--log", r.runDir+"/x.log")
	return r
}

// TestARunWithARunKeyShowsNeutralValues pins dev.qory.run.started and
// dev.qory.session.started of a run with a run key: no host, dir /workspace, <run>,
// <home> and <inputs> in place of each occurrence of the run directory, the harness
// home and the inputs directory in the arguments, the longer path first where one
// contains the other, and no harness. No event contains the run directory, the
// harness home, the inputs directory or the host name. One
// line of Report has the values of this machine.
func TestARunWithARunKeyShowsNeutralValues(t *testing.T) {
	for _, c := range []struct {
		name string
		// layout is the runs directory, the harness home and the inputs directory
		// under the temporary directory base and the run directory of the run id.
		layout func(base, runID string) (runsDir, home, inputs string)
	}{
		{"apart", func(base, _ string) (string, string, string) {
			return filepath.Join(base, "runs"), filepath.Join(base, "cache", "homes", "app-1a2b"), filepath.Join(base, "pool", "in")
		}},
		{"home and inputs in the run directory", func(base, runID string) (string, string, string) {
			runs := filepath.Join(base, "runs")
			return runs, filepath.Join(runs, runID, "home"), filepath.Join(runs, runID, "in")
		}},
		{"run directory in the home", func(base, _ string) (string, string, string) {
			home := filepath.Join(base, "home")
			return filepath.Join(home, "runs"), home, filepath.Join(base, "in")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := startRemote(t)
			g.SetInterval(30)
			runID := event.NewRunID()
			key := g.RunKey(t, runID)
			runsDir, home, inputs := c.layout(t.TempDir(), runID)
			r := newNeutralRun(t, remoteGateway(g, key), runID, runsDir, home, inputs)
			r.sp.Env = append(r.sp.Env, session.EnvRunKey+"="+key)
			res, err := run(context.Background(), r.sp)
			if err != nil {
				t.Fatal(err)
			}
			evs := events(t, res)
			if started := ofType(evs, "dev.qory.run.started"); len(started) != 1 || data(started[0])["host"] != nil {
				t.Errorf("run.started %v", started)
			}
			started := sessionStarted(t, evs)
			want := []any{"-c", `env > "$0"; exec "$1"`, r.envFile, os.Args[0],
				"-p", "Read <run>/sessions/1/task.md, <inputs>/issue.md and <home>/CLAUDE.md, then work in " + r.sp.Dir + ".",
				"--settings", "<home>/settings.json", "--add-dir", "<inputs>", "--log", "<run>/x.log"}
			if started["dir"] != "/workspace" || started["command"] != "<home>/bin/agent" || fmt.Sprint(started["args"]) != fmt.Sprint(want) || started["harness"] != nil {
				t.Errorf("session.started %v\nwant args %q", started, want)
			}
			if posted := sessionStarted(t, g.Events()); fmt.Sprint(posted["args"]) != fmt.Sprint(want) || posted["harness"] != nil {
				t.Errorf("the link got session.started %v", posted)
			}
			record, err := os.ReadFile(filepath.Join(res.Dir, "session.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			host, _ := os.Hostname()
			for _, real := range []string{r.runDir, home, inputs, quoted(host)} {
				if strings.Contains(string(record), real) {
					t.Errorf("session.jsonl contains %s:\n%s", real, record)
				}
			}
			// The working directory is the prompt's text alone: the arguments are the
			// caller's, and only the three directories are written in their place.
			if n := strings.Count(string(record), r.sp.Dir); n != 1 {
				t.Errorf("session.jsonl contains the working directory %d times, want once, in the prompt", n)
			}
			line := fmt.Sprintf("session 1 starts on this machine: host %s, dir %q, home %q, inputs %q, command %q, args %q, harness %q at %s",
				host, r.sp.Dir, home, r.sp.InputsDir, r.sp.Command, r.sp.Args, r.harness[0].Source, r.harness[0].Commit)
			if !slices.Contains(r.reports, line) {
				t.Errorf("the reports %q\nwant %q", r.reports, line)
			}
		})
	}
}

// quoted is s as a JSON string, so the check for the host name matches a value and not
// a word of another one.
func quoted(s string) string { return `"` + s + `"` }

// TestALocalRunShowsTheValuesOfThisMachine pins a run without a run key: host,
// dir, the command and the arguments, and harness, as they are, and no line of
// Report for them.
func TestALocalRunShowsTheValuesOfThisMachine(t *testing.T) {
	sp, _ := specGateway(t, "FAKE_EXIT=0")
	base := t.TempDir()
	home, inputs := filepath.Join(base, "home"), filepath.Join(base, "in")
	for _, d := range []string{home, inputs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var reports []string
	sp.Report = func(l string) { reports = append(reports, l) }
	sp.HarnessHome, sp.InputsDir = home, inputs
	sp.Harness = []session.HarnessSource{{Source: "https://git.example/example-org/harness#main", Commit: strings.Repeat("a1", 20)}}
	sp.Args = append(sp.Args, "-p", "Read "+inputs+"/issue.md and "+home+"/CLAUDE.md.", "--add-dir", inputs)
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	host, _ := os.Hostname()
	if started := ofType(evs, "dev.qory.run.started"); len(started) != 1 || data(started[0])["host"] != host {
		t.Errorf("run.started %v, want host %s", started, host)
	}
	started := sessionStarted(t, evs)
	args := fmt.Sprint(started["args"])
	if started["dir"] != sp.Dir || started["command"] != os.Args[0] || !strings.Contains(args, "Read "+inputs+"/issue.md and "+home+"/CLAUDE.md.") ||
		!strings.Contains(args, "--add-dir "+inputs) || !strings.Contains(args, filepath.Join(res.SessionDir, "settings.json")) || started["harness"] == nil {
		t.Errorf("session.started %v", started)
	}
	for _, l := range reports {
		if strings.Contains(l, "starts on this machine") {
			t.Errorf("a local run reported %q", l)
		}
	}
}

// TestARelativeInputsDirectoryIsRefused pins the inputs directory's check, before the
// join request.
func TestARelativeInputsDirectoryIsRefused(t *testing.T) {
	sp, g := specGateway(t)
	sp.InputsDir = "pool/in"
	_, err := run(context.Background(), sp)
	if want := `set the inputs directory to an absolute path: "pool/in" is relative`; err == nil || err.Error() != want {
		t.Errorf("the run: %v, want %s", err, want)
	}
	if len(g.Joins()) != 0 {
		t.Error("a relative inputs directory reached the gateway's join")
	}
}

// TestARunWithARunKeyRefusesTheRootAsAPlace pins that a run with a run key refuses / as
// the harness home or the inputs directory before the join request, which a local run
// accepts.
func TestARunWithARunKeyRefusesTheRootAsAPlace(t *testing.T) {
	for _, c := range []struct{ home, inputs, want string }{
		{"/", "", "set the harness home to a directory below /: a run with a run key writes <home> in place of it in dev.qory.session.started, and / starts every path"},
		{"", "//", "set the inputs directory to a directory below /: a run with a run key writes <inputs> in place of it in dev.qory.session.started, and / starts every path"},
	} {
		sp, g, _ := remoteSpec(t, 0)
		sp.HarnessHome, sp.InputsDir = c.home, c.inputs
		if _, err := run(context.Background(), sp); err == nil || err.Error() != c.want {
			t.Errorf("home %q, inputs %q: %v, want %s", c.home, c.inputs, err, c.want)
		}
		if len(g.Joins()) != 0 {
			t.Errorf("home %q, inputs %q reached the gateway's join", c.home, c.inputs)
		}
	}
	sp, _ := specGateway(t, "FAKE_EXIT=0")
	sp.InputsDir = "/"
	if _, err := run(context.Background(), sp); err != nil {
		t.Errorf("a local run with / as its inputs: %v", err)
	}
}

// hookRun is a spec of the fake Claude Code runtime that runs the hooks of
// runtime.started, runtime.prompt_submitted and runtime.tool_started, each with the
// run directory, the harness home, the inputs directory and the working directory in
// it, behind the gateway that remote picks: a fake separate one with a run key, or a
// local one.
type hookRun struct {
	sp                          runSpec
	g                           *linktest.Fake
	runDir, home, inputs, input string
}

func newHookRun(t *testing.T, remote bool) *hookRun {
	t.Helper()
	sp, g := specGateway(t, "FAKE_EXIT=0")
	runID := event.NewRunID()
	if remote {
		g = startRemote(t)
		g.SetInterval(30)
		sp.Gateway = remoteGateway(g, g.RunKey(t, runID))
	}
	base := t.TempDir()
	h := &hookRun{g: g, runDir: filepath.Join(sp.RunsDir, runID), home: filepath.Join(base, "home"), inputs: filepath.Join(base, "in")}
	h.input = h.inputs + "/issue.md"
	sp.RunID, sp.HarnessHome, sp.InputsDir = runID, h.home, h.inputs
	line := func(m map[string]any) string { b, _ := json.Marshal(m); return string(b) }
	hooks := []string{
		line(map[string]any{"session_id": "fake", "hook_event_name": "SessionStart", "source": "startup", "cwd": sp.Dir + "/sub"}),
		line(map[string]any{"session_id": "fake", "hook_event_name": "UserPromptSubmit",
			"prompt": "Read " + h.input + " and " + h.home + "/CLAUDE.md in " + sp.Dir + ", and log to " + h.runDir + "/x.log."}),
		line(map[string]any{"session_id": "fake", "hook_event_name": "PreToolUse", "tool_name": "Read", "tool_use_id": "t1", "tool_input": map[string]any{"file_path": h.input}}),
	}
	sp.Env = append(sp.Env, "FAKE_SETTINGS="+filepath.Join(h.runDir, session.SessionsDir, "1", "settings.json"), "FAKE_HOOKS="+strings.Join(hooks, "\n"))
	h.sp = sp
	return h
}

// TestTheRuntimeEventsOfARunWithARunKeyShowNeutralPaths pins the runtime events of a run
// with a run key: cwd of runtime.started and prompt of runtime.prompt_submitted have
// /workspace for the working directory and <run>, <home> and <inputs>, in the record
// and on the link, and a tool's input keeps its path; and a local run's have the paths
// as the runtime wrote them.
func TestTheRuntimeEventsOfARunWithARunKeyShowNeutralPaths(t *testing.T) {
	for _, remote := range []bool{true, false} {
		h := newHookRun(t, remote)
		res, err := run(context.Background(), h.sp)
		if err != nil {
			t.Fatal(err)
		}
		cwd, prompt := h.sp.Dir+"/sub", "Read "+h.input+" and "+h.home+"/CLAUDE.md in "+h.sp.Dir+", and log to "+h.runDir+"/x.log."
		if remote {
			cwd, prompt = "/workspace/sub", "Read <inputs>/issue.md and <home>/CLAUDE.md in /workspace, and log to <run>/x.log."
		}
		for where, evs := range map[string][]map[string]any{"the record": events(t, res), "the link": h.g.Events()} {
			started, prompted, tools := ofType(evs, "dev.qory.runtime.started"), ofType(evs, "dev.qory.runtime.prompt_submitted"), ofType(evs, "dev.qory.runtime.tool_started")
			if len(started) != 1 || data(started[0])["cwd"] != cwd {
				t.Errorf("remote %v, %s: runtime.started %v, want cwd %s", remote, where, started, cwd)
			}
			if len(prompted) != 1 || data(prompted[0])["prompt"] != prompt {
				t.Errorf("remote %v, %s: runtime.prompt_submitted %v, want prompt %q", remote, where, prompted, prompt)
			}
			if len(tools) != 1 || fmt.Sprint(data(tools[0])["input"]) != fmt.Sprint(map[string]any{"file_path": h.input}) {
				t.Errorf("remote %v, %s: runtime.tool_started %v, want the input %s", remote, where, tools, h.input)
			}
		}
	}
}

// failingWrapWall is an open wall whose start fails with err.
type failingWrapWall struct {
	openWall
	err error
}

func (w *failingWrapWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *failingWrapWall) Wrap(context.Context, wall.Launch) (wall.Launch, error) {
	return wall.Launch{}, w.err
}

// TestAFailureLineOfARunWithARunKeyShowsNeutralPaths pins the stderr line of a wall's
// start that fails after session.started: in a run with a run key <run>, <home> and
// <inputs> in place of the paths, in the record and on the link; in a local run the
// paths as the failure has them.
func TestAFailureLineOfARunWithARunKeyShowsNeutralPaths(t *testing.T) {
	for _, remote := range []bool{true, false} {
		h := newHookRun(t, remote)
		text := func(run, home, inputs string) string {
			return "wall open: start: " + run + "/sessions/1 and " + home + "/bin and " + inputs + " are not shared\n"
		}
		h.sp.Wall, h.sp.Image = &failingWrapWall{err: errors.New(strings.TrimSuffix(text(h.runDir, h.home, h.inputs), "\n"))}, "example.com/agent:1"
		ctx := context.Background()
		r, err := session.Open(ctx, opened(h.sp))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Join(ctx, h.sp.SessionSpec); err == nil {
			t.Fatal("the wall's failure started the session")
		}
		closed, err := r.Close(ctx, session.Outcome{State: "failed", ExitCode: -1})
		if err != nil {
			t.Fatal(err)
		}
		want := text(h.runDir, h.home, h.inputs)
		if remote {
			want = text("<run>", "<home>", "<inputs>")
		}
		for where, evs := range map[string][]map[string]any{"the record": events(t, &session.Result{Dir: closed.Dir}), "the link": h.g.Events()} {
			var lines []string
			for _, e := range ofType(evs, "dev.qory.run.log") {
				if d := data(e); d["stream"] == "stderr" && d["session"] == float64(1) {
					b, _ := base64.StdEncoding.DecodeString(d["bytes"].(string))
					lines = append(lines, string(b))
				}
			}
			if !slices.Contains(lines, want) {
				t.Errorf("remote %v, %s: the session's stderr %q, want %q", remote, where, lines, want)
			}
		}
	}
}

// TestASetupRunnerFailureLineOfARunWithARunKeyShowsNeutralPaths pins the stderr line the
// setup runner inside the wall writes when it cannot start a setup command: in a run
// with a run key <inputs> in place of the inputs directory, in the record and on the
// link; in a local run the path as the failure has it. The line a setup command writes
// keeps its path in both.
func TestASetupRunnerFailureLineOfARunWithARunKeyShowsNeutralPaths(t *testing.T) {
	for _, remote := range []bool{true, false} {
		sp := preparedSpec(t, "true")
		g := (*linktest.Fake)(nil)
		runID := event.NewRunID()
		if remote {
			g = startRemote(t)
			g.SetInterval(30)
			sp.Gateway = remoteGateway(g, g.RunKey(t, runID))
		}
		inputs := filepath.Join(t.TempDir(), "in")
		sp.RunID, sp.InputsDir = runID, inputs
		said := inputs + "/notes.md\n"
		sp.SessionSpec.Setup = []session.SetupCommand{
			{Name: "say", Args: []string{"/bin/sh", "-c", "echo " + inputs + "/notes.md >&2"}},
			{Name: "install", Args: []string{inputs + "/missing-tool"}},
		}
		res, err := run(context.Background(), sp)
		if err != nil {
			t.Fatal(err)
		}
		missing := inputs + "/missing-tool"
		if remote {
			missing = "<inputs>/missing-tool"
		}
		lists := map[string][]map[string]any{"the record": events(t, res)}
		if remote {
			lists["the link"] = g.Events()
		}
		for where, evs := range lists {
			var lines []string
			for _, e := range ofType(evs, "dev.qory.run.log") {
				if d := data(e); d["stream"] == "stderr" && d["step"] != nil {
					b, _ := base64.StdEncoding.DecodeString(d["bytes"].(string))
					lines = append(lines, string(b))
				}
			}
			if !slices.Contains(lines, said) {
				t.Errorf("remote %v, %s: the setup's stderr %q lacks the command's line %q", remote, where, lines, said)
			}
			failure := false
			for _, l := range lines {
				failure = failure || (strings.Contains(l, missing) && l != said)
			}
			if !failure || remote && slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, inputs+"/missing-tool") }) {
				t.Errorf("remote %v, %s: the setup's stderr %q, want the runner's failure with %s", remote, where, lines, missing)
			}
		}
	}
}
