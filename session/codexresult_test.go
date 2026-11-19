package session_test

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
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

// usageRun is how [usageResult] runs a session: paused, when not nil, is the
// transcript of a paused run whose resume of the fixture's thread the session
// restores; stop, when not empty, is the reason of the gateway's stop in its answer to
// the batch with pause-now; timeout is the session's limit, and interrupt the time
// after which the caller's context ends, 0 for none.
type usageRun struct {
	// home is CODEX_HOME's name in a new directory, codex-home when empty.
	home               string
	paused             []byte
	stop               string
	timeout, interrupt time.Duration
}

// usageResult runs a Codex session of the script with CODEX_HOME in a new directory,
// as u has it. It returns the session's state and reason and its
// dev.qory.runtime.result events, and fails the test unless each comes right before
// dev.qory.session.exited, and unless every batch the gateway received passes
// link-batch.schema.json, whose events are those of event.schema.json without
// sequence. events checks the session's record against event.schema.json.
func usageResult(t *testing.T, script string, u usageRun) (*session.Result, []map[string]any) {
	t.Helper()
	sp, g := codexSpecGateway(t, false, filepath.Join(t.TempDir(), cmp.Or(u.home, "codex-home")), "")
	if err := os.WriteFile(sp.Command, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if u.paused != nil {
		g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
			a := linktest.RunAnswer(req)
			a["resume"] = map[string]any{"run_id": pausedRun, "session_id": usageThread, "path": "/previous/codex-home/sessions/" + usageBelow}
			return linktest.Reply{Status: 200, Body: a}
		})
		g.OnTranscript(func(string) linktest.Reply { return linktest.Reply{Status: 200, Body: u.paused} })
	}
	if u.stop != "" {
		g.OnBatch(func(evs []map[string]any) linktest.Reply {
			if hasLog(evs, "pause-now") {
				return stopWith(u.stop)
			}
			return linktest.Reply{Status: 200}
		})
	}
	sp.Timeout = u.timeout
	ctx := context.Background()
	if u.interrupt > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, u.interrupt)
		defer cancel()
	}
	res, err := run(ctx, sp)
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
	schema, err := contracts.Compile("link-batch.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, batch := range g.Batches() {
		b, err := json.Marshal(batch)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := contracts.Decode("batch.json", b)
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("a batch fails link-batch.schema.json, whose events are those of event.schema.json: %v\n%s", err, b)
		}
	}
	return res, results
}

// TestACodexLaunchWritesItsResult pins the dev.qory.runtime.result the session writes
// at the end of each launch of Codex, before dev.qory.session.exited, with no line,
// turns, duration or cost: success for one that succeeded; error_during_execution with
// is_error true for one that failed, timed out or was interrupted; and with is_error
// false for one paused with model_key_limit or model_key_switch; each with the usage of
// the rollouts. Launch 2, the resume of launch 1's restored thread, has its usage less
// launch 1's. A launch with no thread.started has none.
func TestACodexLaunchWritesItsResult(t *testing.T) {
	launch1 := []string{"launch1-parent-rollout.jsonl", "launch1-child-rollout.jsonl"}
	restored, err := os.ReadFile(filepath.Join(usageFixture, "launch1-parent-rollout.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	// waits is the script of launch 1 that ends as sleep 30, for a limit or an interrupt
	// to stop it.
	waits := strings.Replace(usageScript(t, true, 0, launch1...), "sleep 0.3\n", "exec sleep 30\n", 1)
	for _, c := range []struct {
		name          string
		script        string
		run           usageRun
		state, reason string
		outcome       string
		isError       bool
		usage         map[string]any
	}{
		{"succeeded", usageScript(t, true, 0, launch1...), usageRun{}, event.StateSucceeded, "", "success", false, usageLaunch1},
		{"failed", usageScript(t, true, 3, launch1...), usageRun{}, event.StateFailed, "", "error_during_execution", true, usageLaunch1},
		{"paused at model_key_limit", usageScript(t, true, 0, launch1...), usageRun{stop: "model_key_limit"}, event.StatePaused, "model_key_limit", "error_during_execution", false, usageLaunch1},
		{"paused at model_key_switch", usageScript(t, true, 0, launch1...), usageRun{stop: "model_key_switch"}, event.StatePaused, "model_key_switch", "error_during_execution", false, usageLaunch1},
		{"timed out", waits, usageRun{timeout: 2 * time.Second}, event.StateCancelled, "timeout", "error_during_execution", true, usageLaunch1},
		{"interrupted", waits, usageRun{interrupt: 2 * time.Second}, event.StateCancelled, "interrupted", "error_during_execution", true, usageLaunch1},
		{"resumed", usageScript(t, true, 0, "launch2-parent-rollout.jsonl"), usageRun{paused: restored}, event.StateSucceeded, "", "success", false, usageLaunch2},
		{"no rollout", usageScript(t, true, 0), usageRun{}, event.StateSucceeded, "", "success", false, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			res, results := usageResult(t, c.script, c.run)
			want := map[string]any{"session_id": usageThread, "session": 1.0, "outcome": c.outcome, "is_error": c.isError}
			if c.usage != nil {
				want["usage"] = c.usage
			}
			if res.State != c.state || res.Reason != c.reason || len(results) != 1 || !reflect.DeepEqual(results[0], want) {
				t.Errorf("the session ended %s, %s with the results %v; want %s, %s with %v", res.State, res.Reason, results, c.state, c.reason, want)
			}
		})
	}
	t.Run("no thread", func(t *testing.T) {
		if _, results := usageResult(t, usageScript(t, false, 0, launch1...), usageRun{}); len(results) != 0 {
			t.Errorf("the results %v; want none", results)
		}
	})
}

// TestACodexResultHasNoUsageAbove2To53 pins a launch whose two child agents have
// output_tokens 2^62 each, a sum beyond int64: the result has no usage, the session
// writes one dev.qory.run.log line that starts with the fix, and the batches pass
// link-batch.schema.json and the record event.schema.json ([usageResult]).
func TestACodexResultHasNoUsageAbove2To53(t *testing.T) {
	s := usageScript(t, true, 0, "launch1-parent-rollout.jsonl")
	for _, child := range []string{"0d000000-0000-4000-8000-000000000001", "0d000000-0000-4000-8000-000000000002"} {
		s = strings.Replace(s, "echo pause-now", fmt.Sprintf("printf '%%s\\n' '{\"type\":\"session_meta\",\"payload\":{\"id\":\"%s\",\"parent_thread_id\":\"%s\"}}' "+
			"'{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"output_tokens\":4611686018427387904}}}}' > \"$d/2026/11/19/rollout-x-%s.jsonl\"\necho pause-now", child, usageThread, child), 1)
	}
	res, results := usageResult(t, s, usageRun{})
	want := map[string]any{"session_id": usageThread, "session": 1.0, "outcome": "success", "is_error": false}
	if len(results) != 1 || !reflect.DeepEqual(results[0], want) {
		t.Errorf("the results %v; want %v", results, want)
	}
	if !hasLog(events(t, res), "Check the token counts in the rollouts of the launch.\n") {
		t.Error("no line with the fix")
	}
}

// TestACodexResultWithNoTranscriptHasNoUsage pins a launch for which the session reads
// no transcript, here a CODEX_HOME with a comma, which resume.prefix does not accept:
// the result has no usage, and the session writes one dev.qory.run.log line that
// starts with the fix.
func TestACodexResultWithNoTranscriptHasNoUsage(t *testing.T) {
	res, results := usageResult(t, usageScript(t, true, 0, "launch1-parent-rollout.jsonl"), usageRun{home: "codex,home"})
	want := map[string]any{"session_id": usageThread, "session": 1.0, "outcome": "success", "is_error": false}
	if len(results) != 1 || !reflect.DeepEqual(results[0], want) {
		t.Errorf("the results %v; want %v", results, want)
	}
	if !hasLog(events(t, res), "Let the session read Codex's transcript, which it needs to read the rollouts.\n") {
		t.Error("no line with the fix")
	}
}
