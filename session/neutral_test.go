package session_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/session"
)

// neutralRun is a run of the fake runtime whose arguments contain the run directory,
// the harness home and the inputs directory, in an argument of their own and inside a
// -p prompt.
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
	r.sp.HarnessHome, r.sp.InputsDir, r.sp.Harness = home, inputs, r.harness
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
// working directory, the harness home, the inputs directory or the host name. One
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
			if started["dir"] != "/workspace" || started["command"] != "/bin/sh" || fmt.Sprint(started["args"]) != fmt.Sprint(want) || started["harness"] != nil {
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
				host, r.sp.Dir, home, inputs, "/bin/sh", r.sp.Args, r.harness[0].Source, r.harness[0].Commit)
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
