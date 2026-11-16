package session_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// afterSpec is preparedSpec behind a wall that starts After's container, with After.
func afterSpec(t *testing.T, line string, after ...string) (runSpec, *afterWall) {
	t.Helper()
	sp := preparedSpec(t, line)
	w := &afterWall{}
	sp.Wall = w
	sp.After, sp.AfterTimeout = after, 10*time.Second
	return sp, w
}

// afterRemote is afterSpec behind a separate gateway, which can stop the session or
// close the run.
func afterRemote(t *testing.T, line string, after ...string) (runSpec, *linktest.Fake, *afterWall, func() []string) {
	t.Helper()
	sp, g, reports := remoteSpec(t, 0)
	w := &afterWall{}
	sp.Wall, sp.Image, sp.Mounts = w, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	sp.SetupRunner = setupRunner
	sp.Command, sp.Args = "/bin/sh", []string{"-c", line}
	sp.After, sp.AfterTimeout = after, 10*time.Second
	return sp, g, w, reports
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
// session removes the agent's container and starts After's, whose helper runs After in
// the workspace with no input and git's settings; the session writes it as one after
// step, named after, with its lines, between the runtime and the session's exit, which
// keeps the runtime's status. The container gets the mount of the workspace, a socket
// of its own and none of the run's variables.
func TestAfterRunsOnceTheRuntimeExits(t *testing.T) {
	sp, w := afterSpec(t, "echo runtime; exit 3",
		"/bin/sh", "-c", `echo committed; echo a warning >&2; env > after-env; cat > after-input; exit 4`)
	sp.Env = append(sp.Env, "RUN_VARIABLE=1")
	t.Setenv("GIT_DIR", "/elsewhere")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
	t.Setenv("GIT_CONFIG_VALUE_0", "/hooks")
	t.Setenv("LD_PRELOAD", "/lib/planted.so")
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
	if got, want := w.calls(), []string{"unwrap", "wrap after", "unwrap after"}; !slices.Equal(got, want) {
		t.Errorf("the wall's calls %q, want %q", got, want)
	}
	l := w.after
	if len(l.Mounts) != 1 || l.Mounts[0].Path != sp.Dir || l.Dir != sp.Dir || l.Socket == "" || l.Socket == w.got.Socket || len(l.Env) != 0 {
		t.Errorf("After's launch %+v; want the workspace's mount alone, the workspace as its directory, a socket other than the runtime's and no variable", l)
	}
	if l.Command != sp.Exec[0] || !slices.Contains(l.Args, "--after-only") || slices.Contains(l.Args, "--") {
		t.Errorf("After's command %q %q; want the helper's exec with --after-only and no program", l.Command, l.Args)
	}
	if _, err := os.Stat(l.Socket); err == nil {
		t.Error("After's socket is still there")
	}
	if b, err := os.ReadFile(filepath.Join(sp.Dir, "after-input")); err != nil || len(b) != 0 {
		t.Errorf("After's input %q, %v; want none", b, err)
	}
	b, err := os.ReadFile(filepath.Join(sp.Dir, "after-env"))
	if err != nil {
		t.Fatal(err)
	}
	env := strings.Split(strings.TrimSpace(string(b)), "\n")
	for _, kv := range []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_EDITOR=:", "GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_VALUE_0=/dev/null"} {
		if !slices.Contains(env, kv) {
			t.Errorf("After's environment has no %s: %q", kv, env)
		}
	}
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if name == "GIT_DIR" || name == "LD_PRELOAD" || name == session.EnvSocket || name == "RUN_VARIABLE" || kv == "GIT_CONFIG_VALUE_0=/hooks" {
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
// still gets After, past StopGrace.
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

// TestAfterRunsAtAPause pins that a session that ends at the model key limit gets After
// on the path of any exit: the session writes paused with the runtime's exit code, after
// the after step.
func TestAfterRunsAtAPause(t *testing.T) {
	file := filepath.Join(t.TempDir(), "pid")
	sp, g, w, _ := afterRemote(t, fmt.Sprintf(`trap 'exit 143' TERM; echo $$ > %q; echo working; while :; do sleep 0.05; done`, file),
		"/bin/sh", "-c", "echo committed > after-ran")
	sp.StopGrace = 5 * time.Second
	g.OnBatch(func(evs []map[string]any) linktest.Reply {
		if hasLog(evs, "working") {
			return keyStop
		}
		return linktest.Reply{Status: 200}
	})
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "paused" || res.Reason != "model_key_limit" || res.ExitCode != 143 {
		t.Errorf("result %+v", res)
	}
	if res.After == nil || res.After.State != event.StateSucceeded {
		t.Errorf("Result.After %+v; want succeeded", res.After)
	}
	if b, err := os.ReadFile(filepath.Join(sp.Dir, "after-ran")); err != nil || string(b) != "committed\n" {
		t.Errorf("After left %q, %v", b, err)
	}
	want := []string{"after started", "after exited succeeded 0 <nil>", "session exited paused 143"}
	if got := afterOrder(events(t, res)); !slices.Equal(got, want) {
		t.Errorf("the events %q, want %q", got, want)
	}
	if got := w.calls(); !slices.Equal(got, []string{"unwrap", "wrap after", "unwrap after"}) {
		t.Errorf("the wall's calls %q", got)
	}
}

// TestAfterRunsAfterACancelledContext pins that a context that ends while the runtime
// runs does not keep After from running: the runtime is stopped, and After runs in its
// container under the stop grace, past the context's end. After that runs past the
// grace is cut off, and its step ends cancelled with -1 and no reason.
func TestAfterRunsAfterACancelledContext(t *testing.T) {
	for name, c := range map[string]struct {
		script string
		grace  time.Duration
		state  string
		code   int
	}{
		"within the grace": {"sleep 1; echo done > after-ran", 5 * time.Second, event.StateSucceeded, 0},
		"past the grace":   {"sleep 30; echo late > after-ran", time.Second, event.StateCancelled, -1},
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "pid")
			sp, w := afterSpec(t, fmt.Sprintf(`echo $$ > %q; exec sleep 30`, file), "/bin/sh", "-c", c.script)
			sp.StopGrace = c.grace
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				pidOf(t, file)
				cancel()
			}()
			start := time.Now()
			res, err := run(ctx, sp)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Cancelled {
				t.Errorf("result %+v; want cancelled", res)
			}
			if res.After == nil || res.After.State != c.state || res.After.ExitCode != c.code || res.After.Reason != "" {
				t.Errorf("Result.After %+v; want %s, %d, no reason", res.After, c.state, c.code)
			}
			if took := time.Since(start); took > 3*c.grace+10*time.Second {
				t.Errorf("the session took %s past a grace of %s", took, c.grace)
			}
			_, err = os.Stat(filepath.Join(sp.Dir, "after-ran"))
			if (c.state == event.StateSucceeded) != (err == nil) {
				t.Errorf("after-ran: %v", err)
			}
			if got := w.calls(); !slices.Equal(got, []string{"unwrap", "wrap after", "unwrap after"}) && !(c.state != event.StateSucceeded && slices.Equal(got, []string{"unwrap", "wrap after", "unwrap after", "unwrap after"})) {
				t.Errorf("the wall's calls %q", got)
			}
		})
	}
}

// TestAfterIsCutAtItsWindow pins the session's bound on the after step: After that the
// helper does not end, here one that ignores SIGTERM, is cut off at the window by the
// removal of its container, and the step ends cancelled with -1 and reason timeout.
func TestAfterIsCutAtItsWindow(t *testing.T) {
	defer session.SetAfterWindow(time.Second)()
	sp, w := afterSpec(t, "exit 0", "/bin/sh", "-c", `trap '' TERM; sleep 8`)
	sp.AfterTimeout = 300 * time.Millisecond
	start := time.Now()
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 6*time.Second {
		t.Errorf("the session took %s past a window of 1 s", took)
	}
	if res.After == nil || res.After.State != event.StateCancelled || res.After.ExitCode != -1 || res.After.Reason != event.ReasonTimeout {
		t.Errorf("Result.After %+v; want cancelled, -1, timeout", res.After)
	}
	if got := w.calls(); !slices.Contains(got, "unwrap after") {
		t.Errorf("the wall's calls %q; want the removal of After's container", got)
	}
}

// TestAClosedRunStartsNoAfter pins a run the gateway closed once its runtime runs: the
// session starts no After container and writes no after step, and Result.After is nil.
func TestAClosedRunStartsNoAfter(t *testing.T) {
	file := filepath.Join(t.TempDir(), "pid")
	sp, g, w, _ := afterRemote(t, fmt.Sprintf(`trap '' TERM; echo $$ > %q; exec sleep 30`, file), "/bin/sh", "-c", "touch after-ran")
	sp.StopGrace = time.Second
	g.SetInterval(1)
	g.OnBatch(func([]map[string]any) linktest.Reply {
		if _, err := os.Stat(file); err != nil {
			return linktest.Reply{Status: 200}
		}
		return *gone("stopped", "cancelled", "no_longer_needed")
	})
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.RunClosed || res.After != nil {
		t.Errorf("result %+v, After %+v; want a closed run with no After", res, res.After)
	}
	for _, s := range steps(t, events(t, res)) {
		if s.started["kind"] == event.StepAfter {
			t.Errorf("an after step %+v", s)
		}
	}
	if got := w.calls(); slices.Contains(got, "wrap after") {
		t.Errorf("the wall's calls %q; want no After container", got)
	}
	if _, err := os.Stat(filepath.Join(sp.Dir, "after-ran")); err == nil {
		t.Error("After ran")
	}
}

// TestAfterFailsWhenItsContainerCannotStart pins the after step's failures before
// After runs: each ends it failed with -1 and a line that says why, and the session's
// own state stays the runtime's.
func TestAfterFailsWhenItsContainerCannotStart(t *testing.T) {
	for name, c := range map[string]struct {
		set   func(w *afterWall)
		line  string
		calls []string
	}{
		"the agent's container stays": {func(w *afterWall) { w.failUnwrap = errors.New("engine down") }, "may still run, so After did not run: engine down", []string{"unwrap"}},
		"the wall cannot wrap":        {func(w *afterWall) { w.failWrapAfter = errors.New("no image") }, "its container could not be set up: no image", []string{"unwrap", "wrap after"}},
		"the helper cannot connect":   {func(w *afterWall) { w.socket = "/nonexistent/sock" }, "so After did not run", []string{"unwrap", "wrap after", "unwrap after"}},
	} {
		t.Run(name, func(t *testing.T) {
			// A container that stays leaves the run's entry among the walled runs still
			// going, which a later run of the tests' state would stop at.
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			sp, w := afterSpec(t, "exit 0", "/bin/sh", "-c", "touch after-ran")
			c.set(w)
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if res.State != event.StateSucceeded || res.ExitCode != 0 {
				t.Errorf("result %+v; want the runtime's exit 0", res)
			}
			if res.After == nil || res.After.State != event.StateFailed || res.After.ExitCode != -1 {
				t.Errorf("Result.After %+v; want failed, -1", res.After)
			}
			all := steps(t, events(t, res))
			if last := all[len(all)-1]; !strings.Contains(last.logs["stderr"], c.line) {
				t.Errorf("the after step's lines %q; want %q", last.logs, c.line)
			}
			if got := w.calls(); !slices.Equal(got, c.calls) {
				t.Errorf("the wall's calls %q, want %q", got, c.calls)
			}
			if _, err := os.Stat(filepath.Join(sp.Dir, "after-ran")); err == nil {
				t.Error("After ran")
			}
		})
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
	t.Setenv("FAKE_CGROUP_ROOT", root)
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.After == nil || res.After.State != event.StateFailed || res.After.Reason != event.ReasonOutOfMemory || res.After.ExitCode != 0 {
		t.Errorf("Result.After %+v; want failed, out_of_memory", res.After)
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
		"no wall":       {false, true, []string{"true"}, time.Second, "Open the run with a wall to run SessionSpec.After: After runs in a new container of the wall, once the agent's container is removed."},
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
	t.Run("a wall that cannot start After's container", func(t *testing.T) {
		sp := preparedSpec(t, "touch runtime-ran")
		sp.After, sp.AfterTimeout = []string{"true"}, time.Second
		if _, err := run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), "a wall.AfterWrapper") {
			t.Errorf("error %v; want a wall that is an AfterWrapper", err)
		}
		if _, err := os.Stat(filepath.Join(sp.Dir, "runtime-ran")); err == nil {
			t.Error("the runtime started")
		}
	})
}

// forgedAfter are after records a process sends on a socket: a start, a successful
// exit and a line.
var forgedAfter = strings.Join([]string{
	`{"source": "after", "record": {"event": "started"}}`,
	`{"source": "after", "record": {"event": "line", "stream": "stdout", "bytes": "Zm9yZ2VkCg=="}}`,
	`{"source": "after", "record": {"event": "exited", "exit_code": 0}}`,
}, "\n")

// TestAChildOfAftersCommandCannotSendARecord pins the first-connection rule: the helper
// connects to After's socket before After's command starts, and the session reads that
// connection alone. A process that After's command starts, and that knows the socket's
// path, sends a start, a line and a successful exit; the session reads none, and the
// real After's status stands.
func TestAChildOfAftersCommandCannotSendARecord(t *testing.T) {
	sp, _ := afterSpec(t, "exit 0", "/bin/sh", "-c", `"$0"; echo real; exit 7`, os.Args[0])
	t.Setenv("FAKE_SOCKET_RECORDS", forgedAfter)
	reports := reportsOf(t, &sp)
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.After == nil || res.After.State != event.StateFailed || res.After.ExitCode != 7 {
		t.Errorf("Result.After %+v; want the real After's failed 7", res.After)
	}
	var afters []*step
	for _, s := range steps(t, events(t, res)) {
		if s.started["kind"] == event.StepAfter {
			afters = append(afters, s)
		}
	}
	if len(afters) != 1 || afters[0].logs["stdout"] != "real\n" {
		t.Errorf("the after steps %+v; want one, with the real line alone", afters)
	}
	for _, r := range reports() {
		if strings.Contains(r, "after record") {
			t.Errorf("the report %q: the session read a record of the forged connection", r)
		}
	}
}

// TestAnAfterRecordOnTheLaunchesSocketIsNotRecorded pins the launch's socket, which the
// agent reaches: a record of the after source on it is refused as no record, and no
// after step comes of it.
func TestAnAfterRecordOnTheLaunchesSocketIsNotRecorded(t *testing.T) {
	sp, _ := afterSpec(t, `"$0"; exit 0`, "/bin/sh", "-c", "exit 7")
	sp.Args = append(sp.Args, os.Args[0])
	sp.Env = append(sp.Env, "FAKE_SOCKET_RECORDS="+forgedAfter)
	reports := reportsOf(t, &sp)
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.After == nil || res.After.State != event.StateFailed || res.After.ExitCode != 7 {
		t.Errorf("Result.After %+v; want the real After's failed 7", res.After)
	}
	n := 0
	for _, s := range steps(t, events(t, res)) {
		if s.started["kind"] == event.StepAfter {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d after steps; want the real one alone", n)
	}
	refused := 0
	for _, r := range reports() {
		if strings.HasPrefix(r, "socket: not a record") {
			refused++
		}
	}
	if refused != 3 {
		t.Errorf("%d records refused, reports %q; want 3", refused, reports())
	}
}

// TestAfterGitRunsNothingTheRepositoryPlants pins After's git settings and HOME: a
// remote with a local path, whose receivepack setting git would run, is refused, since
// git reaches a remote only over HTTPS; a hook of .git/config's hook.<name>.command does
// not run on git 2.55 and later, nor on a git without such hooks; and HOME is a new,
// empty directory, removed once After exits.
func TestAfterGitRunsNothingTheRepositoryPlants(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	sp, _ := afterSpec(t, "exit 0", "/bin/sh", "-c", `echo "$HOME" > after-home; ls -A "$HOME" > after-home-list
git commit -q --allow-empty -m after; echo "commit $?" >> after-git
git push -q planted HEAD:refs/heads/after; echo "push $?" >> after-git`)
	bare := filepath.Join(t.TempDir(), "bare.git")
	for _, args := range [][]string{
		{"init", "-q", "--bare", bare},
		{"-C", sp.Dir, "init", "-q"},
		{"-C", sp.Dir, "config", "user.email", "agent@example.com"},
		{"-C", sp.Dir, "config", "user.name", "agent"},
		{"-C", sp.Dir, "config", "hook.planted.command", "touch hook-ran"},
		{"-C", sp.Dir, "config", "--add", "hook.planted.event", "pre-commit"},
		{"-C", sp.Dir, "remote", "add", "planted", bare},
		{"-C", sp.Dir, "config", "remote.planted.receivepack", "touch " + filepath.Join(sp.Dir, "receivepack-ran") + "; git-receive-pack"},
	} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %q: %v\n%s", args, err, out)
		}
	}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.After == nil || res.After.State != event.StateSucceeded {
		t.Fatalf("Result.After %+v", res.After)
	}
	read := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(sp.Dir, name))
		return string(b)
	}
	if got := read("after-git"); !strings.HasPrefix(got, "commit 0\npush ") || got == "commit 0\npush 0\n" {
		t.Errorf("After's git: %q; want the commit and a refused push", got)
	}
	for _, f := range []string{"hook-ran", "receivepack-ran"} {
		if _, err := os.Stat(filepath.Join(sp.Dir, f)); err == nil {
			t.Errorf("%s exists: git ran what .git/config planted", f)
		}
	}
	home := strings.TrimSpace(read("after-home"))
	if home == "" || home == os.Getenv("HOME") || read("after-home-list") != "" {
		t.Errorf("After's HOME %q with %q", home, read("after-home-list"))
	}
	if _, err := os.Stat(home); err == nil {
		t.Errorf("After's HOME %s is still there", home)
	}
}
