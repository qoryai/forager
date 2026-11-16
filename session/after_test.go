package session_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/session"
)

// afterSpec is preparedSpec with After, whose stop of the container's other processes
// the test binary's exec writes to the file stops in place of stopping them.
func afterSpec(t *testing.T, line string, after ...string) (runSpec, string) {
	t.Helper()
	stops := filepath.Join(t.TempDir(), "stops")
	sp := preparedSpec(t, line, "FAKE_AFTER_STOP="+stops)
	sp.After, sp.AfterTimeout = after, 10*time.Second
	return sp, stops
}

// afterOrder is the session's events from the runtime's exit on: the after step's
// start, logs and exit, and the session's exit.
func afterOrder(evs []map[string]any) []string {
	var out []string
	after := 0.0
	for _, e := range evs {
		d := data(e)
		switch e["type"] {
		case event.StepStarted:
			if d["kind"] == event.StepAfter {
				after = d["step"].(float64)
				out = append(out, "after started")
			}
		case event.RunLog:
			if d["step"] == after && after > 0 {
				out = append(out, fmt.Sprint("after log ", d["stream"], " session ", d["session"]))
			}
		case event.StepExited:
			if d["step"] == after {
				out = append(out, fmt.Sprint("after exited ", d["state"], " ", d["exit_code"], " ", d["reason"]))
			}
		case event.SessionExited:
			out = append(out, fmt.Sprint("session exited ", d["state"], " ", d["exit_code"]))
		}
	}
	return out
}

// TestAfterRunsOnceTheRuntimeExits pins SessionSpec.After: once the runtime exits, the
// helper's exec stops the container's other processes, runs After in the workspace
// with no input and git's settings, and stops them again; the session writes it as one
// after step, named after, with its lines, between the runtime and the session's exit,
// which keeps the runtime's status.
func TestAfterRunsOnceTheRuntimeExits(t *testing.T) {
	sp, stops := afterSpec(t, "echo runtime; exit 3",
		"/bin/sh", "-c", `echo committed; echo a warning >&2; env > after-env; cat > after-input; exit 4`)
	sp.Env = append(sp.Env, "GIT_DIR=/elsewhere", "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_VALUE_0=/hooks", "LD_PRELOAD=/lib/planted.so")
	sp.Stdin = strings.NewReader("for the runtime\n")
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 3 || res.State != event.StateFailed {
		t.Errorf("result %+v; want the runtime's exit 3", res)
	}
	all := steps(t, events(t, res))
	last := all[len(all)-1]
	if last.started["kind"] != event.StepAfter || last.started["name"] != "after" || last.exited["state"] != event.StateFailed || last.exited["exit_code"] != 4.0 {
		t.Fatalf("the last step %+v", last)
	}
	if _, ok := last.exited["reason"]; ok {
		t.Errorf("the after step's exit has a reason: %v", last.exited)
	}
	if last.logs["stdout"] != "committed\n" || last.logs["stderr"] != "a warning\n" {
		t.Errorf("the after step's lines %q", last.logs)
	}
	if want := (&session.AfterResult{Step: int(last.started["step"].(float64)), State: event.StateFailed, ExitCode: 4}); res.After == nil || *res.After != *want {
		t.Errorf("Result.After %+v, want %+v", res.After, want)
	}
	// The two streams' lines reach the session in either order.
	want := []string{"after started", "after log stderr session 1", "after log stdout session 1", "after exited failed 4 <nil>", "session exited failed 3"}
	got := afterOrder(events(t, res))
	if len(got) == len(want) {
		slices.Sort(got[1:3])
	}
	if !slices.Equal(got, want) {
		t.Errorf("the events %q, want %q", got, want)
	}
	if b, _ := os.ReadFile(stops); string(b) != "stop docker=false\nstop docker=false\n" {
		t.Errorf("the stops %q; want one before After and one after", b)
	}
	if b, err := os.ReadFile(filepath.Join(sp.Dir, "after-input")); err != nil || len(b) != 0 {
		t.Errorf("After's input %q, %v; want none", b, err)
	}
	b, err := os.ReadFile(filepath.Join(sp.Dir, "after-env"))
	if err != nil {
		t.Fatal(err)
	}
	env := strings.Split(strings.TrimSpace(string(b)), "\n")
	for _, kv := range []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_EDITOR=:", "GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_VALUE_0=/dev/null", "FAKE_RUNTIME=1"} {
		if !slices.Contains(env, kv) {
			t.Errorf("After's environment has no %s: %q", kv, env)
		}
	}
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if name == "GIT_DIR" || name == "LD_PRELOAD" || name == session.EnvSocket || kv == "GIT_CONFIG_VALUE_0=/hooks" {
			t.Errorf("After's environment has %s", kv)
		}
	}
}

// TestAfterStopsAtAfterTimeout pins After's limit: at AfterTimeout its process group
// gets SIGTERM, and the after step ends cancelled with timeout and the command's
// status.
func TestAfterStopsAtAfterTimeout(t *testing.T) {
	sp, _ := afterSpec(t, "exit 0", "/bin/sh", "-c", "exec sleep 30")
	sp.AfterTimeout = 300 * time.Millisecond
	start := time.Now()
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Errorf("the session took %s", took)
	}
	if res.After == nil || res.After.State != event.StateCancelled || res.After.Reason != event.ReasonTimeout || res.After.ExitCode != 143 {
		t.Errorf("Result.After %+v; want cancelled, timeout, 143", res.After)
	}
	if res.State != event.StateSucceeded || res.ExitCode != 0 {
		t.Errorf("result %+v; want the runtime's exit 0", res)
	}
	want := []string{"after started", "after exited cancelled 143 timeout", "session exited succeeded 0"}
	if got := afterOrder(events(t, res)); !slices.Equal(got, want) {
		t.Errorf("the events %q, want %q", got, want)
	}
}

// TestAfterRunsAfterTheRuntimesTimeout pins that a runtime stopped at the Timeout
// still gets After, past StopGrace: the session holds the launch while the after step
// runs.
func TestAfterRunsAfterTheRuntimesTimeout(t *testing.T) {
	sp, _ := afterSpec(t, "exec sleep 30", "/bin/sh", "-c", "sleep 1; echo done > after-ran")
	sp.Timeout, sp.StopGrace = 300*time.Millisecond, 200*time.Millisecond
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.Reason != event.ReasonTimeout {
		t.Errorf("result %+v; want timed out", res)
	}
	if res.After == nil || res.After.State != event.StateSucceeded || res.After.ExitCode != 0 {
		t.Errorf("Result.After %+v; want succeeded", res.After)
	}
	if b, err := os.ReadFile(filepath.Join(sp.Dir, "after-ran")); err != nil || string(b) != "done\n" {
		t.Errorf("After left %q, %v", b, err)
	}
}

// TestAfterFailsOnAProcessKilledForLackOfMemory pins out_of_memory: when oom_kill in
// the cgroup's memory.events rises while After runs, the step ends failed with the
// reason.
func TestAfterFailsOnAProcessKilledForLackOfMemory(t *testing.T) {
	root := t.TempDir()
	events := filepath.Join(root, "memory.events")
	if err := os.WriteFile(events, []byte("oom 0\noom_kill 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sp, _ := afterSpec(t, "exit 0", "/bin/sh", "-c", `printf 'oom 1\noom_kill 1\n' > "$1"`, "after", events)
	sp.Env = append(sp.Env, "FAKE_CGROUP_ROOT="+root)
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.After == nil || res.After.State != event.StateFailed || res.After.Reason != event.ReasonOutOfMemory || res.After.ExitCode != 0 {
		t.Errorf("Result.After %+v; want failed, out_of_memory", res.After)
	}
}

// TestAfterDoesNotRunOutsideAContainer pins the helper's exec's guard: outside a
// container's first program it stops no process, After does not start, and the after
// step fails with 125 and the reason as its line.
func TestAfterDoesNotRunOutsideAContainer(t *testing.T) {
	sp := preparedSpec(t, "exit 0")
	sp.After, sp.AfterTimeout = []string{"/bin/sh", "-c", "touch after-ran"}, 10*time.Second
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.After == nil || res.After.State != event.StateFailed || res.After.ExitCode != 125 {
		t.Errorf("Result.After %+v; want failed, 125", res.After)
	}
	all := steps(t, events(t, res))
	if last := all[len(all)-1]; !strings.HasPrefix(last.logs["stderr"], "Stop the container's other processes before After: ") {
		t.Errorf("the after step's lines %q", last.logs)
	}
	if _, err := os.Stat(filepath.Join(sp.Dir, "after-ran")); err == nil {
		t.Error("After ran")
	}
}

// TestNoAfterIsNoAfterStep pins a session with no After: no after step, and no
// Result.After.
func TestNoAfterIsNoAfterStep(t *testing.T) {
	res, err := run(context.Background(), preparedSpec(t, "exit 0"))
	if err != nil {
		t.Fatal(err)
	}
	if res.After != nil {
		t.Errorf("Result.After %+v", res.After)
	}
	for _, s := range steps(t, events(t, res)) {
		if s.started["kind"] == event.StepAfter {
			t.Errorf("an after step %+v", s)
		}
	}
}

// TestAfterNeedsAWallExecAndATimeout pins the specs of After that are no run.
func TestAfterNeedsAWallExecAndATimeout(t *testing.T) {
	for name, c := range map[string]struct {
		walled  bool
		exec    bool
		after   []string
		timeout time.Duration
		want    string
	}{
		"no wall":       {false, true, []string{"true"}, time.Second, "Open the run with a wall to run SessionSpec.After: After runs inside the wall's container, once every other process of it is stopped."},
		"no exec":       {true, false, []string{"true"}, time.Second, `Set SessionSpec.Exec to the helper's exec, such as {wall.HelperPath, "exec"}: a walled run starts every launch through it`},
		"no timeout":    {true, true, []string{"true"}, 0, "Set SessionSpec.AfterTimeout above zero: it is how long SessionSpec.After may run."},
		"empty program": {true, true, []string{"", "x"}, time.Second, "Give SessionSpec.After a program: its first word is empty."},
		"a NUL":         {true, true, []string{"true", "a\x00b"}, time.Second, "Remove the NUL from SessionSpec.After: no argument contains one."},
	} {
		t.Run(name, func(t *testing.T) {
			sp := preparedSpec(t, "touch runtime-ran")
			if !c.walled {
				sp.Wall, sp.Image, sp.Mounts = nil, "", nil
			}
			if !c.exec {
				sp.Exec = nil
			}
			sp.After, sp.AfterTimeout = c.after, c.timeout
			if _, err := run(context.Background(), sp); err == nil || err.Error() != c.want {
				t.Errorf("error %v, want %q", err, c.want)
			}
			if _, err := os.Stat(filepath.Join(sp.Dir, "runtime-ran")); err == nil {
				t.Error("the runtime started")
			}
		})
	}
}
