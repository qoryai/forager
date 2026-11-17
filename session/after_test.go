package session_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
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
	sp.Runtime, sp.RuntimeInstall = nil, nil
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
// that no other container binds and none of the run's variables.
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
// helper does not end, here one that ignores SIGTERM for longer than AfterTimeout and
// the helper's SIGKILL 5 s later, is cut off at the window by the removal of its
// container, and the step ends cancelled with -1 and reason timeout. The helper's
// SIGKILL comes 35 s in, so a session that returns within 6 s was cut by the window.
func TestAfterIsCutAtItsWindow(t *testing.T) {
	defer session.SetAfterWindow(time.Second)()
	sp, w := afterSpec(t, "exit 0", "/bin/sh", "-c", `trap '' TERM; sleep 60`)
	sp.AfterTimeout = 30 * time.Second
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

// TestARunClosedDuringAfterCutsItAtOnce pins a run the gateway closes while After runs:
// After is cut off at once, not at the stop grace, the session reports the run closed,
// and After's command does not finish.
func TestARunClosedDuringAfterCutsItAtOnce(t *testing.T) {
	sp, g, w, _ := afterRemote(t, "exit 0", "/bin/sh", "-c", "sleep 30; echo late > after-ran")
	sp.StopGrace = 8 * time.Second
	g.SetInterval(1)
	g.OnBatch(func(evs []map[string]any) linktest.Reply {
		for _, e := range evs {
			if d, _ := e["data"].(map[string]any); e["type"] == event.StepStarted && d["kind"] == event.StepAfter {
				return *gone("stopped", "cancelled", "no_longer_needed")
			}
		}
		return linktest.Reply{Status: 200}
	})
	start := time.Now()
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.RunClosed {
		t.Errorf("result %+v; want a closed run", res)
	}
	if res.After == nil || res.After.State != event.StateCancelled || res.After.ExitCode != -1 {
		t.Errorf("Result.After %+v; want cancelled, -1: a run closed while After runs has an outcome", res.After)
	}
	if took := time.Since(start); took > 4*time.Second {
		t.Errorf("the session took %s after the close; want After cut at once, not at the grace of 8 s", took)
	}
	if got := w.calls(); !slices.Contains(got, "unwrap after") {
		t.Errorf("the wall's calls %q; want the removal of After's container", got)
	}
	if _, err := os.Stat(filepath.Join(sp.Dir, "after-ran")); err == nil {
		t.Error("After finished")
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
// state stays the runtime's.
func TestAfterFailsWhenItsContainerCannotStart(t *testing.T) {
	for name, c := range map[string]struct {
		set   func(w *afterWall)
		line  string
		calls []string
	}{
		"the agent's container stays": {func(w *afterWall) { w.failUnwrap = errors.New("engine down") }, "Close the run to remove the agent's container, which may still run.\nAfter did not run: the removal failed: engine down", []string{"unwrap"}},
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

// removalWall is an afterWall whose first Unwrap waits for its context to end and fails
// with its error, as a docker rm does that the window or a close cuts.
type removalWall struct {
	*afterWall
	n atomic.Int32
}

func (w *removalWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.afterWall.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *removalWall) Unwrap(ctx context.Context) error {
	w.note("unwrap")
	if w.n.Add(1) == 1 {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

// TestARemovalTheContextCutsIsTriedAgain pins the agent's container's removal that the
// end of its context cuts: the session does not keep that failure as the removal's
// result, reports no removal failed and flags no wall, and the removal at the session's
// end runs again and succeeds.
func TestARemovalTheContextCutsIsTriedAgain(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	file := filepath.Join(t.TempDir(), "pid")
	sp, aw := afterSpec(t, fmt.Sprintf(`echo $$ > %q; exec sleep 30`, file), "/bin/sh", "-c", "true")
	w := &removalWall{afterWall: aw}
	sp.Wall = w
	sp.StopGrace = 300 * time.Millisecond
	reports := reportsOf(t, &sp)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { pidOf(t, file); cancel() }()
	res, closed, err := runClosed(ctx, sp)
	if err != nil {
		t.Fatal(err)
	}
	if got := w.calls(); len(got) < 2 || got[0] != "unwrap" || got[1] != "unwrap" {
		t.Errorf("the wall's calls %q; want the removal, cut, then once more at the session's end", got)
	}
	if res.After == nil || res.After.State != event.StateCancelled {
		t.Errorf("Result.After %+v; want cancelled", res.After)
	}
	for _, r := range reports() {
		if strings.Contains(r, "removing the wall") {
			t.Errorf("the report %q: the session took a cut removal for a failed one", r)
		}
	}
	if closed != nil && closed.WallKept {
		t.Errorf("the close %+v; want the agent's container removed", closed)
	}
}

// TestARunClosedDuringTheRemovalIsTriedAgain pins the same retry for a run the gateway
// closes while the agent's container is removed.
func TestARunClosedDuringTheRemovalIsTriedAgain(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	sp, g, aw, _ := afterRemote(t, "exit 0", "/bin/sh", "-c", "true")
	w := &removalWall{afterWall: aw}
	sp.Wall = w
	g.SetInterval(1)
	g.OnBatch(func(evs []map[string]any) linktest.Reply {
		for _, e := range evs {
			if d, _ := e["data"].(map[string]any); e["type"] == event.StepStarted && d["kind"] == event.StepAfter {
				return *gone("stopped", "cancelled", "no_longer_needed")
			}
		}
		return linktest.Reply{Status: 200}
	})
	res, closed, err := runClosed(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.RunClosed {
		t.Errorf("result %+v; want a closed run", res)
	}
	if got := w.calls(); len(got) < 2 || got[0] != "unwrap" || got[1] != "unwrap" {
		t.Errorf("the wall's calls %q; want the removal, cut by the close, then once more at the session's end", got)
	}
	if closed != nil && closed.WallKept {
		t.Errorf("the close %+v; want the agent's container removed", closed)
	}
}

// neverStartsWall is an afterWall whose launch fails before the helper runs, as a docker
// run does that exits 125 with no container: Wrap returns a command that writes the
// engine's error line to stderr and exits 125, and starts neither the helper nor the
// program.
type neverStartsWall struct{ *afterWall }

const launchFailureLine = "docker: Error response from daemon: no such image: example.com/agent:1"

func (w *neverStartsWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.afterWall.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *neverStartsWall) Wrap(_ context.Context, l wall.Launch) (wall.Launch, error) {
	return wall.Launch{Command: "/bin/sh", Args: []string{"-c", "echo '" + launchFailureLine + "' >&2; exit 125"}, Dir: l.Dir}, nil
}

// TestAfterRunsWhenTheLaunchFailsBeforeAnyContainer pins a launch whose docker run
// exits 125 with no container: After still starts, on the unchanged workspace, and
// Result.After is not nil. The session's state is the launch's, failed with 125.
func TestAfterRunsWhenTheLaunchFailsBeforeAnyContainer(t *testing.T) {
	sp, aw := afterSpec(t, "exit 0", "/bin/sh", "-c", "touch after-ran")
	sp.Wall = &neverStartsWall{afterWall: aw}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 125 || res.State != event.StateFailed {
		t.Errorf("result %+v; want the launch's failed 125", res)
	}
	if res.After == nil || res.After.State != event.StateSucceeded {
		t.Errorf("Result.After %+v; want After to have run and succeeded", res.After)
	}
	if _, err := os.Stat(filepath.Join(sp.Dir, "after-ran")); err != nil {
		t.Errorf("After did not run: %v", err)
	}
	if got := aw.calls(); !slices.Equal(got, []string{"unwrap", "wrap after", "unwrap after"}) {
		t.Errorf("the wall's calls %q", got)
	}
}

// deadAfterWall is a neverStartsWall whose WrapAfter succeeds and whose After container
// fails as a docker run does that exits 125 with no container: it writes the engine's
// error line to stderr and exits 125, so the helper never runs and sends no record.
type deadAfterWall struct{ *neverStartsWall }

const afterFailureLine = "docker: Error response from daemon: cannot start the after container"

func (w *deadAfterWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.afterWall.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *deadAfterWall) WrapAfter(_ context.Context, l wall.Launch) (wall.Launch, error) {
	w.note("wrap after")
	return wall.Launch{Command: "/bin/sh", Args: []string{"-c", "echo '" + afterFailureLine + "' >&2; exit 125"}, Dir: l.Dir}, nil
}

// TestTheLaunchFailureComesBeforeAftersFailure pins the order of two failures: when the
// launch fails before any container exists and After's container cannot start either,
// the engine's error line of the launch reaches the terminal and the run's record
// before the after step's failure line, and the after step ends failed with -1. Two
// causes of After's failure: the wall cannot set the container up, and the container's
// docker run exits 125 with no record.
func TestTheLaunchFailureComesBeforeAftersFailure(t *testing.T) {
	for name, c := range map[string]struct {
		set   func(aw *afterWall) wall.Wall
		after string
	}{
		"the wall cannot set After's container up": {func(aw *afterWall) wall.Wall {
			aw.failWrapAfter = errors.New("no image")
			return &neverStartsWall{afterWall: aw}
		}, "After did not run: its container could not be set up"},
		"After's docker run exits 125 with no record": {func(aw *afterWall) wall.Wall {
			return &deadAfterWall{&neverStartsWall{afterWall: aw}}
		}, "After did not run to its end: the container ended with no exit status for After"},
	} {
		t.Run(name, func(t *testing.T) {
			sp, aw := afterSpec(t, "exit 0", "/bin/sh", "-c", "touch after-ran")
			sp.Wall = c.set(aw)
			var out syncBuffer
			sp.Stderr = &out
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if res.ExitCode != 125 {
				t.Errorf("result %+v; want the launch's 125", res)
			}
			if res.After == nil || res.After.State != event.StateFailed || res.After.ExitCode != -1 {
				t.Fatalf("Result.After %+v; want failed, -1", res.After)
			}
			text := out.String()
			launch, after := strings.Index(text, launchFailureLine), strings.Index(text, c.after)
			if launch < 0 || after < 0 || launch > after {
				t.Errorf("the terminal has the launch's line at %d and After's at %d; want the launch's first:\n%s", launch, after, text)
			}
			var order []string
			started := false
			for _, e := range events(t, res) {
				d := data(e)
				switch e["type"] {
				case event.RunLog:
					if b, _ := d["bytes"].(string); strings.Contains(b, base64.StdEncoding.EncodeToString([]byte(launchFailureLine))[:20]) && !started {
						order = append(order, "launch line")
					}
				case event.StepStarted:
					if d["kind"] == event.StepAfter {
						started = true
						order = append(order, "after started")
					}
				}
			}
			if !slices.Equal(order, []string{"launch line", "after started"}) {
				t.Errorf("the record has %q; want the launch's line before the after step", order)
			}
		})
	}
}

// TestAnAfterRunsWhenTheRuntimeExits125 pins that a runtime the helper started and that
// exits 125 by itself is no failed launch: it may have changed the workspace, and gets
// After.
func TestAnAfterRunsWhenTheRuntimeExits125(t *testing.T) {
	sp, _ := afterSpec(t, "exit 125", "/bin/sh", "-c", "touch after-ran")
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 125 || res.After == nil || res.After.State != event.StateSucceeded {
		t.Errorf("result %+v, After %+v; want the runtime's 125 and After succeeded", res, res.After)
	}
	if _, err := os.Stat(filepath.Join(sp.Dir, "after-ran")); err != nil {
		t.Errorf("After did not run: %v", err)
	}
}

// socketDirsWall is an afterWall that records, at each call that matters, how many
// socket directories of sessions, the qory-run-* directories of the temporary directory,
// exist.
type socketDirsWall struct {
	*afterWall
	at map[string]int
}

func (w *socketDirsWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.afterWall.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *socketDirsWall) count(call string) {
	dirs, _ := filepath.Glob(filepath.Join(os.TempDir(), "qory-run-*"))
	w.mu.Lock()
	w.at[call] = len(dirs)
	w.mu.Unlock()
}

func (w *socketDirsWall) Unwrap(ctx context.Context) error {
	w.count("unwrap")
	return w.afterWall.Unwrap(ctx)
}

func (w *socketDirsWall) WrapAfter(ctx context.Context, l wall.Launch) (wall.Launch, error) {
	w.count("wrap after")
	return w.afterWall.WrapAfter(ctx, l)
}

// TestAftersSocketIsMadeOnceTheAgentsContainerIsRemoved pins the order the README
// promises: when the wall removes the agent's container, no socket directory of the
// session exists, so no process of the agent's container could have seen After's; when
// the wall starts After's container, After's exists.
func TestAftersSocketIsMadeOnceTheAgentsContainerIsRemoved(t *testing.T) {
	// A short path: a socket's address has at most 104 bytes on macOS.
	tmp, err := os.MkdirTemp("", "s")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)
	t.Setenv("TMPDIR", tmp)
	sp, aw := afterSpec(t, "exit 0", "/bin/sh", "-c", "true")
	w := &socketDirsWall{afterWall: aw, at: map[string]int{}}
	sp.Wall = w
	if _, err := run(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.at["unwrap"] != 0 || w.at["wrap after"] != 1 {
		t.Errorf("socket directories at the agent's removal and at After's start: %d and %d; want 0 and 1", w.at["unwrap"], w.at["wrap after"])
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
		"no wall":       {false, true, []string{"true"}, time.Second, "Open the run with a wall to run SessionSpec.After.\nAfter runs in a new container of the wall, once the agent's container is removed."},
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
		if _, err := run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), "Use a wall that is a wall.AfterWrapper for SessionSpec.After.\n") {
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
// agent reaches: a record of the after source on it is skipped as no record, and no
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
		t.Errorf("%d records skipped, reports %q; want 3", refused, reports())
	}
}

// gitVersion returns the major and minor number of the git in PATH.
func gitVersion(t *testing.T) (major, minor int) {
	t.Helper()
	out, err := exec.Command("git", "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Sscanf(strings.TrimPrefix(string(out), "git version "), "%d.%d", &major, &minor); err != nil {
		t.Fatalf("git's version %q: %v", out, err)
	}
	return major, minor
}

// TestAfterGitRunsNothingTheRepositoryPlants pins After's git settings and HOME: a
// remote with a local path, whose receivepack setting git would run, fails, since
// git reaches a remote only over HTTPS; a hook in .git/hooks does not run; a hook of
// .git/config's hook.<name>.command does not run on git 2.55 and later, which has the
// setting that turns it off, hook.<event>.enabled (git 2.54 runs it: no setting turns
// config hooks off for every name, so the test does not look for it there); and HOME is
// a new, empty directory, removed once After exits.
func TestAfterGitRunsNothingTheRepositoryPlants(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	major, minor := gitVersion(t)
	configHooksOff := major > 2 || (major == 2 && minor >= 55)
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
	classic := filepath.Join(sp.Dir, ".git", "hooks", "pre-commit")
	if err := os.WriteFile(classic, []byte("#!/bin/sh\ntouch classic-hook-ran\n"), 0o755); err != nil {
		t.Fatal(err)
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
		t.Errorf("After's git: %q; want the commit and a failed push", got)
	}
	planted := []string{"classic-hook-ran", "receivepack-ran"}
	if configHooksOff {
		planted = append(planted, "hook-ran")
	}
	for _, f := range planted {
		if _, err := os.Stat(filepath.Join(sp.Dir, f)); err == nil {
			t.Errorf("%s exists: git ran what .git planted", f)
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

// setupAfterWall is a setupWall whose enclosure also removes the agent's container and
// starts After's, with the afterWall's calls in one order that includes the setup
// container's removal.
type setupAfterWall struct {
	setupWall
	aw *afterWall
}

func (w *setupAfterWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *setupAfterWall) RemoveSetup(ctx context.Context) error {
	w.aw.note("remove setup")
	return w.setupWall.RemoveSetup(ctx)
}

func (w *setupAfterWall) Unwrap(ctx context.Context) error { return w.aw.Unwrap(ctx) }

func (w *setupAfterWall) WrapAfter(ctx context.Context, l wall.Launch) (wall.Launch, error) {
	return w.aw.WrapAfter(ctx, l)
}

func (w *setupAfterWall) UnwrapAfter(ctx context.Context) error { return w.aw.UnwrapAfter(ctx) }

// afterWithSetup opens a run with a setup container, joins a session with After and
// returns the run, the result and the wall.
func afterWithSetup(t *testing.T, after string, removeErr error) (*session.Run, *session.Result, *setupAfterWall) {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	sp, aw := afterSpec(t, "exit 0", "/bin/sh", "-c", after)
	w := &setupAfterWall{aw: aw}
	w.removeErr = removeErr
	sp.Wall, sp.Image = w, "example.com/agent:1"
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
		t.Fatal(err)
	}
	res, err := r.Join(ctx, sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	return r, res, w
}

// TestAfterStartsOnceTheSetupContainerIsGone pins the setup container's removal before
// After: the session removes it before the agent's container and After's start, with the
// wall step "remove the setup container" ahead of the after step, and the run is then as
// one after Run.RemoveSetup: RemoveSetup returns nil and removes nothing again, and
// ContainerKept is false, so a push step can follow.
func TestAfterStartsOnceTheSetupContainerIsGone(t *testing.T) {
	r, res, w := afterWithSetup(t, "touch after-ran", nil)
	if res.After == nil || res.After.State != event.StateSucceeded {
		t.Fatalf("Result.After %+v; want succeeded", res.After)
	}
	if got, want := w.aw.calls(), []string{"remove setup", "unwrap", "wrap after", "unwrap after"}; !slices.Equal(got, want) {
		t.Errorf("the wall's calls %q, want %q", got, want)
	}
	var names []string
	for _, s := range steps(t, events(t, res)) {
		names = append(names, fmt.Sprint(s.started["kind"], " ", s.started["name"]))
	}
	if n := len(names); n < 2 || names[n-2] != "wall remove the setup container" || names[n-1] != "after after" {
		t.Errorf("the steps %q; want the removal's wall step, then the after step, last", names)
	}
	ctx := context.Background()
	if err := r.RemoveSetup(ctx); err != nil {
		t.Errorf("RemoveSetup after After: %v; want nil", err)
	}
	if w.removes != 1 {
		t.Errorf("the wall removed the setup container %d times, want 1", w.removes)
	}
	if r.ContainerKept() {
		t.Error("ContainerKept is true after the setup container's removal")
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
}

// TestAFailedSetupRemovalSkipsAfter pins a setup container that cannot be removed: After
// does not run and its step ends failed with a line, the wall's step ends failed too,
// ContainerKept is true, no session joins the run, and RemoveSetup tries the removal
// again.
func TestAFailedSetupRemovalSkipsAfter(t *testing.T) {
	r, res, w := afterWithSetup(t, "touch after-ran", errors.New("engine down"))
	if res.After == nil || res.After.State != event.StateFailed || res.After.ExitCode != -1 {
		t.Fatalf("Result.After %+v; want failed, -1", res.After)
	}
	all := steps(t, events(t, res))
	if last := all[len(all)-1]; !strings.Contains(last.logs["stderr"], "Close the run to remove the setup container, which may still run.\nAfter did not run: the removal failed: engine down") {
		t.Errorf("the after step's lines %q", last.logs)
	}
	if got, want := w.aw.calls(), []string{"remove setup", "unwrap"}; !slices.Equal(got, want) {
		t.Errorf("the wall's calls %q, want %q: the agent's container's removal at the session's end, and no After container", got, want)
	}
	if !r.ContainerKept() {
		t.Error("ContainerKept is false after a setup container that may still run")
	}
	ctx := context.Background()
	if err := r.RemoveSetup(ctx); err == nil || w.removes != 2 {
		t.Errorf("RemoveSetup: %v after %d removals; want an error and a second try", err, w.removes)
	}
	r.Close(ctx, session.Outcome{State: event.StateFailed})
}

// slowWriter sleeps before each write, as a terminal that cannot keep up does.
type slowWriter struct{ delay time.Duration }

func (w slowWriter) Write(p []byte) (int, error) {
	time.Sleep(w.delay)
	return len(p), nil
}

// TestAfterReadsEveryRecordBeforeItDecidesTheStepHasNoExit pins the drain of After's
// socket: with a terminal that takes 20 ms for each of 100 lines, the session reads the
// records long after After's container ended, and the step still has its exit, not the
// line "ended with no exit status". The socket's grace of 5 s is long enough to read them all.
func TestAfterReadsEveryRecordBeforeItDecidesTheStepHasNoExit(t *testing.T) {
	sp, _ := afterSpec(t, "exit 0", "/bin/sh", "-c", "i=0; while [ $i -lt 100 ]; do echo line $i; i=$((i+1)); done; exit 3")
	sp.SocketGrace = 5 * time.Second
	sp.Stdout = slowWriter{20 * time.Millisecond}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.After == nil || res.After.State != event.StateFailed || res.After.ExitCode != 3 {
		t.Fatalf("Result.After %+v; want failed with the command's 3", res.After)
	}
	all := steps(t, events(t, res))
	if got := all[len(all)-1].logs["stdout"]; strings.Count(got, "\n") != 100 {
		t.Errorf("the after step has %d lines, want 100", strings.Count(got, "\n"))
	}
	if strings.Contains(all[len(all)-1].logs["stderr"], "no exit status") {
		t.Errorf("the after step has the line %q", all[len(all)-1].logs["stderr"])
	}
}

// failingWall is an afterWall whose launch fails: with wrapErr set, Wrap returns it;
// otherwise Wrap returns a command that does not exist, so the process does not start.
type failingWall struct {
	*afterWall
	wrapErr error
}

func (w *failingWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.afterWall.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *failingWall) Wrap(_ context.Context, l wall.Launch) (wall.Launch, error) {
	if w.wrapErr != nil {
		return wall.Launch{}, w.wrapErr
	}
	return wall.Launch{Command: filepath.Join(l.Dir, "no-such-helper"), Dir: l.Dir}, nil
}

// TestJoinRunsNoAfterWhenTheLaunchCannotBeWrappedOrStarted pins the two early returns of
// a session with After: a wall whose Wrap fails, and a launch whose process does not
// start (ErrNotStarted). In both, Join returns an error and no Result, and the wall is
// asked for no After container.
func TestJoinRunsNoAfterWhenTheLaunchCannotBeWrappedOrStarted(t *testing.T) {
	for name, c := range map[string]struct {
		wrapErr error
		want    func(error) bool
	}{
		"the wall's Wrap fails":      {errors.New("no image"), func(err error) bool { return strings.Contains(err.Error(), "no image") }},
		"the process does not start": {nil, func(err error) bool { return errors.Is(err, session.ErrNotStarted) }},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			sp, aw := afterSpec(t, "exit 0", "/bin/sh", "-c", "touch after-ran")
			w := &failingWall{afterWall: aw, wrapErr: c.wrapErr}
			sp.Wall = w
			res, err := run(context.Background(), sp)
			if err == nil || !c.want(err) {
				t.Errorf("Join returned %v; want the launch's error", err)
			}
			if res != nil {
				t.Errorf("Join returned the result %+v; want none", res)
			}
			if got := w.calls(); slices.Contains(got, "wrap after") {
				t.Errorf("the wall's calls %q; want no After container", got)
			}
			if _, err := os.Stat(filepath.Join(sp.Dir, "after-ran")); err == nil {
				t.Error("After ran")
			}
		})
	}
}
