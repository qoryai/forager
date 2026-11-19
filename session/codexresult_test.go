package session_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
)

// The fixture of Codex 0.167.2's rollouts (runtimes/codex/testdata/usage): launch 1's
// thread and its child, and launch 2's thread, launch 1's file with a turn appended.
const (
	usageThread  = "01a1f100-87f8-7123-a174-ba291730eec1"
	usageFixture = "runtimes/codex/testdata/usage"
	usageBelow   = "2026/11/18/rollout-2026-11-18T23-31-46-" + usageThread + ".jsonl"
)

// The usage of launch 1 and launch 2 by the stub's numbers, as
// runtimes/codex/rollout_test.go derives them: JSON numbers in the record.
var (
	usageLaunch1 = map[string]any{"input": 2222.0, "output": 4444.0, "cache_read": 1111.0, "cache_write": 2222.0}
	usageLaunch2 = map[string]any{"input": 20000.0, "output": 40000.0, "cache_read": 10000.0, "cache_write": 20000.0}
)

// usageScript stands in for codex exec --json: it prints thread.started with the
// fixture's thread unless started is false, copies the files of the fixture named in
// files to their places below $CODEX_HOME/sessions, the thread's appended to a restored
// file, prints a line pause-now for a test that pauses, and exits with exit.
func usageScript(t *testing.T, started bool, exit int, files ...string) string {
	t.Helper()
	abs, err := filepath.Abs(usageFixture)
	if err != nil {
		t.Fatal(err)
	}
	s := "#!/bin/sh\nd=\"$CODEX_HOME/sessions\"\nmkdir -p \"$d/2026/11/18\" \"$d/2026/11/19\"\n"
	if started {
		s += `echo '{"type":"thread.started","thread_id":"` + usageThread + `"}'` + "\n"
	}
	for _, f := range files {
		switch f {
		case "launch1-parent-rollout.jsonl":
			s += fmt.Sprintf("cat %q > \"$d/%s\"\n", filepath.Join(abs, f), usageBelow)
		case "launch1-child-rollout.jsonl":
			s += fmt.Sprintf("cat %q > \"$d/2026/11/19/rollout-2026-11-19T00-00-00-01a1f100-885b-7140-a145-b604ffe0117a.jsonl\"\n", filepath.Join(abs, f))
		case "launch2-parent-rollout.jsonl":
			// The restored file is launch 1's: the launch appends the rest.
			s += fmt.Sprintf("tail -c +%d %q >> \"$d/%s\"\n", fileSize(t, filepath.Join(abs, "launch1-parent-rollout.jsonl"))+1, filepath.Join(abs, f), usageBelow)
		}
	}
	return s + "echo pause-now\nsleep 0.3\nexit " + fmt.Sprint(exit) + "\n"
}

// fileSize is the size of the file at p.
func fileSize(t *testing.T, p string) int64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

// usageResult runs a Codex session of the script with CODEX_HOME in a new directory,
// and with paused not nil a resume of the fixture's thread whose transcript is paused;
// with stop, the gateway's answer to the batch with pause-now stops the session with
// model_key_limit. It returns the session's state and its dev.qory.runtime.result
// events, and fails the test unless each comes right before dev.qory.session.exited.
func usageResult(t *testing.T, script string, paused []byte, stop bool) (string, []map[string]any) {
	t.Helper()
	sp, g := codexSpecGateway(t, false, filepath.Join(t.TempDir(), "codex-home"), "")
	if err := os.WriteFile(sp.Command, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if paused != nil {
		g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
			a := linktest.RunAnswer(req)
			a["resume"] = map[string]any{"run_id": pausedRun, "session_id": usageThread, "path": "/previous/codex-home/sessions/" + usageBelow}
			return linktest.Reply{Status: 200, Body: a}
		})
		g.OnTranscript(func(string) linktest.Reply { return linktest.Reply{Status: 200, Body: paused} })
	}
	if stop {
		g.OnBatch(func(evs []map[string]any) linktest.Reply {
			if hasLog(evs, "pause-now") {
				return keyStop
			}
			return linktest.Reply{Status: 200}
		})
	}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	var results []map[string]any
	for i, e := range evs {
		if e["type"] != "dev.qory.runtime.result" {
			continue
		}
		results = append(results, data(e))
		if i+1 >= len(evs) || evs[i+1]["type"] != event.SessionExited {
			t.Errorf("dev.qory.runtime.result is not right before dev.qory.session.exited: %v", evs[i+1:])
		}
	}
	return res.State, results
}

// TestACodexLaunchWritesItsResult pins the dev.qory.runtime.result the session writes
// at the end of each launch of Codex, before dev.qory.session.exited, with no line,
// turns, duration or cost: success for one that succeeded, error_during_execution with
// is_error true for one that failed and with is_error false for one paused, each with
// the usage of the rollouts; launch 2, the resume of launch 1's restored thread, has
// its usage less launch 1's. A launch with no thread.started has none.
func TestACodexLaunchWritesItsResult(t *testing.T) {
	launch1 := []string{"launch1-parent-rollout.jsonl", "launch1-child-rollout.jsonl"}
	restored, err := os.ReadFile(filepath.Join(usageFixture, "launch1-parent-rollout.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name    string
		script  string
		paused  []byte
		stop    bool
		state   string
		outcome string
		isError bool
		usage   map[string]any
	}{
		{"succeeded", usageScript(t, true, 0, launch1...), nil, false, event.StateSucceeded, "success", false, usageLaunch1},
		{"failed", usageScript(t, true, 3, launch1...), nil, false, event.StateFailed, "error_during_execution", true, usageLaunch1},
		{"paused", usageScript(t, true, 0, launch1...), nil, true, event.StatePaused, "error_during_execution", false, usageLaunch1},
		{"resumed", usageScript(t, true, 0, "launch2-parent-rollout.jsonl"), restored, false, event.StateSucceeded, "success", false, usageLaunch2},
		{"no rollout", usageScript(t, true, 0), nil, false, event.StateSucceeded, "success", false, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			state, results := usageResult(t, c.script, c.paused, c.stop)
			want := map[string]any{"session_id": usageThread, "session": 1.0, "outcome": c.outcome, "is_error": c.isError}
			if c.usage != nil {
				want["usage"] = c.usage
			}
			if state != c.state || len(results) != 1 || !reflect.DeepEqual(results[0], want) {
				t.Errorf("the session ended %s with the results %v; want %s with %v", state, results, c.state, want)
			}
		})
	}
	t.Run("no thread", func(t *testing.T) {
		if _, results := usageResult(t, usageScript(t, false, 0, launch1...), nil, false); len(results) != 0 {
			t.Errorf("the results %v; want none", results)
		}
	})
}
