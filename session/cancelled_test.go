package session_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// shellSpec is a spec whose runtime is the shell script given, on the local link.
func shellSpec(t *testing.T, script string) session.Spec {
	t.Helper()
	sp := spec(t)
	sp.Forwarder = nil
	sp.Command, sp.Args = "sh", []string{"-c", script}
	return sp
}

// pidOf waits for the runtime to write its process id to the file, and returns it, or
// 0 after an error; it may be called from any goroutine.
func pidOf(t *testing.T, file string) int {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(file); err == nil && strings.HasSuffix(string(b), "\n") {
			pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil || pid <= 0 {
				t.Errorf("the runtime's process id %q: %v", b, err)
				return 0
			}
			return pid
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("the runtime wrote no process id to %s", file)
	return 0
}

// ended is the state and the exit code of the record's run.exited, which has no member
// of Cancelled's own.
func ended(t *testing.T, res *session.Result) (string, int) {
	t.Helper()
	state, _, code := endedWith(t, res)
	return state, code
}

// endedWith is the state, the reason and the exit code of the record's run.exited,
// which has no member of Cancelled's own.
func endedWith(t *testing.T, res *session.Result) (string, string, int) {
	t.Helper()
	exited := ofType(events(t, res), "dev.qory.run.exited")
	if len(exited) != 1 {
		t.Fatalf("run.exited %v", exited)
	}
	d := data(exited[0])
	if _, ok := d["cancelled"]; ok {
		t.Errorf("run.exited says %v", d)
	}
	code, _ := d["exit_code"].(float64)
	state, _ := d["state"].(string)
	reason, _ := d["reason"].(string)
	if signal, _ := d["signal"].(string); signal != res.Signal {
		t.Errorf("run.exited's signal %q, the result's %q", signal, res.Signal)
	}
	return state, reason, int(code)
}

// TestTheContextsEndWhileTheRuntimeRunsIsACancel pins Cancelled for a context that ends
// once the runtime runs, which the session stops: on its own, and in a wall. run.exited
// is cancelled with interrupted, with the signal that killed the runtime.
func TestTheContextsEndWhileTheRuntimeRunsIsACancel(t *testing.T) {
	for name, sp := range map[string]func(t *testing.T, script string) session.Spec{
		"unwalled": shellSpec,
		"walled": func(t *testing.T, script string) session.Spec {
			root := t.TempDir()
			sp := walledSpec(t, &openWall{})
			sp.Mounts, sp.Dir = []wall.Mount{{Path: root}}, root
			sp.Command, sp.Args = "sh", []string{"-c", script}
			return sp
		},
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "pid")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				pidOf(t, file)
				cancel()
			}()
			res, err := session.Run(ctx, sp(t, fmt.Sprintf(`echo $$ > %q; exec sleep 30`, file)))
			if err != nil {
				t.Fatal(err)
			}
			if !res.Cancelled || res.TimedOut || res.Signal != "SIGTERM" {
				t.Errorf("result %+v", res)
			}
			if state, reason, code := endedWith(t, res); state != "cancelled" || reason != "interrupted" || code != -1 {
				t.Errorf("run.exited %s %s %d", state, reason, code)
			}
			if res.State != "cancelled" || res.Reason != "interrupted" {
				t.Errorf("result %+v", res)
			}
		})
	}
}

// TestARuntimeThatLeavesAtItsOwnInterruptIsCancelled pins a Ctrl-C that reaches the
// runtime and the caller at once: the runtime leaves at its own SIGINT, not at the
// session's stop, which it ignores, and the context had ended when its exit was
// observed: cancelled with interrupted, and its own exit status.
func TestARuntimeThatLeavesAtItsOwnInterruptIsCancelled(t *testing.T) {
	file := filepath.Join(t.TempDir(), "pid")
	sp := shellSpec(t, fmt.Sprintf(`trap '' TERM; trap 'sleep 0.3; exit 130' INT; echo $$ > %q; while :; do sleep 0.05; done`, file))
	sp.StopGrace = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if pid := pidOf(t, file); pid > 0 {
			syscall.Kill(pid, syscall.SIGINT)
		}
		cancel()
	}()
	res, err := session.Run(ctx, sp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cancelled || res.TimedOut || res.ExitCode != 130 || res.Signal != "" {
		t.Errorf("result %+v", res)
	}
	if state, reason, code := endedWith(t, res); state != "cancelled" || reason != "interrupted" || code != 130 {
		t.Errorf("run.exited %s %s %d", state, reason, code)
	}
}

// TestAContextThatEndsAfterTheExitIsNoCancel pins a runtime that exits by itself
// behind a separate gateway, and a context that ends after its exit was observed:
// while the gateway is asked for the outcome, or while the sinks close. The run is not
// cancelled, and the result's state and exit code are run.exited's.
func TestAContextThatEndsAfterTheExitIsNoCancel(t *testing.T) {
	for name, c := range map[string]func(g *linktest.Fake, cancel context.CancelFunc){
		"the outcome ask": func(g *linktest.Fake, cancel context.CancelFunc) {
			g.OnOutcome(func(string) linktest.Reply {
				cancel()
				time.Sleep(200 * time.Millisecond)
				return linktest.Reply{Status: 200, Body: map[string]any{"state": "failed", "reason": "checks_failed"}}
			})
		},
		"the sink close": func(g *linktest.Fake, cancel context.CancelFunc) {
			g.OnBatch(func(evs []map[string]any) linktest.Reply {
				if len(ofType(evs, "dev.qory.run.exited")) > 0 {
					cancel()
					time.Sleep(200 * time.Millisecond)
				}
				return linktest.Reply{Status: 200}
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			sp, g, _ := remoteSpec(t, 0)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c(g, cancel)
			res, err := session.Run(ctx, sp)
			if err != nil {
				t.Fatal(err)
			}
			if ctx.Err() == nil {
				t.Fatal("the context did not end during the run")
			}
			if res.Cancelled || res.TimedOut || res.RunClosed || res.ExitCode != 0 {
				t.Errorf("result %+v", res)
			}
			if state, code := ended(t, res); state != res.State || code != res.ExitCode {
				t.Errorf("run.exited %s %d, the result %+v", state, code, res)
			}
		})
	}
}

// TestTheTimeLimitIsNoCancel pins the time limit: TimedOut, never Cancelled, also when
// the context ends after the limit, while the runtime has its grace to leave.
func TestTheTimeLimitIsNoCancel(t *testing.T) {
	sp := shellSpec(t, "sleep 30")
	sp.Timeout = 300 * time.Millisecond
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.Cancelled {
		t.Errorf("result %+v", res)
	}

	// The limit's clock starts before the runtime does: once the runtime has written
	// its id, the limit has fallen by 300ms later, and the context ends within the
	// grace that follows.
	file := filepath.Join(t.TempDir(), "pid")
	sp = shellSpec(t, fmt.Sprintf(`trap '' TERM; echo $$ > %q; exec sleep 30`, file))
	sp.Timeout, sp.StopGrace = 300*time.Millisecond, 3*time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		pidOf(t, file)
		time.Sleep(600 * time.Millisecond)
		cancel()
	}()
	if res, err = session.Run(ctx, sp); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil {
		t.Fatal("the context did not end during the run")
	}
	if !res.TimedOut || res.Cancelled || res.Signal != "SIGKILL" {
		t.Errorf("a context that ended within the limit's grace: %+v", res)
	}
}

// TestARunClosedBeforeTheContextEndsIsNoCancel pins a run the gateway closed with a
// 410 once its runtime runs: the run ended at the gateway, RunClosed, and is not
// cancelled, with the context alive, or ending while the runtime has its grace to
// leave.
func TestARunClosedBeforeTheContextEndsIsNoCancel(t *testing.T) {
	for name, ends := range map[string]bool{"the context alive": false, "the context ending in the grace": true} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "pid")
			sp, g, _ := remoteSpec(t, 0)
			sp.Args = []string{"-c", fmt.Sprintf(`trap '' TERM; echo $$ > %q; exec sleep 30`, file)}
			sp.StopGrace = 3 * time.Second
			g.SetInterval(1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var once sync.Once
			g.OnBatch(func([]map[string]any) linktest.Reply {
				if _, err := os.Stat(file); err != nil {
					return linktest.Reply{Status: 200}
				}
				if ends {
					once.Do(func() { time.AfterFunc(300*time.Millisecond, cancel) })
				}
				return *gone("stopped", "cancelled", "no_longer_needed")
			})
			res, err := session.Run(ctx, sp)
			if err != nil {
				t.Fatal(err)
			}
			if (ctx.Err() != nil) != ends {
				t.Fatalf("the context's end %v", ctx.Err())
			}
			if !res.RunClosed || res.Cancelled || res.TimedOut || res.Signal != "SIGKILL" || res.State != "cancelled" || res.Reason != "no_longer_needed" {
				t.Errorf("result %+v", res)
			}
			if state, reason, _ := endedWith(t, res); state != "cancelled" || reason != "no_longer_needed" {
				t.Errorf("run.exited %s %s", state, reason)
			}
		})
	}
}

// TestASignalFromElsewhereIsNoCancel pins a runtime killed from outside while the
// context lasts: not cancelled.
func TestASignalFromElsewhereIsNoCancel(t *testing.T) {
	file := filepath.Join(t.TempDir(), "pid")
	sp := shellSpec(t, fmt.Sprintf(`echo $$ > %q; exec sleep 30`, file))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	go func() {
		if pid := pidOf(t, file); pid > 0 {
			syscall.Kill(pid, syscall.SIGTERM)
		}
	}()
	res, err := session.Run(ctx, sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.Cancelled || res.TimedOut || res.Signal != "SIGTERM" {
		t.Errorf("result %+v", res)
	}
}

// TestANormalExitIsNeitherCancelledNorTimedOut pins a runtime that exits by itself
// within its limit, with the context alive.
func TestANormalExitIsNeitherCancelledNorTimedOut(t *testing.T) {
	sp := spec(t)
	sp.Timeout = time.Minute
	res, err := runWithSettingsEnv(t, sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.Cancelled || res.TimedOut || res.ExitCode != 0 || res.State != "succeeded" {
		t.Errorf("result %+v", res)
	}
}

// TestAStopFromWhereTheRunWasStartedIsInterrupted pins a Ctrl-C while the runtime runs,
// the context's end, however the runtime leaves at the session's stop: exit 0, its own
// 130 at the stop signal SIGINT, killed by SIGTERM, or killed by SIGKILL after the
// grace. Each is recorded cancelled with interrupted, the runtime's own exit status and
// signal kept, Run returns its result with no error, and Cancelled is true. Behind a
// separate gateway the same is posted, and nothing is asked.
func TestAStopFromWhereTheRunWasStartedIsInterrupted(t *testing.T) {
	for name, c := range map[string]struct {
		script, stop string
		grace        time.Duration
		code         int
		signal       string
		remote       bool
	}{
		"exit 0 at the stop":                   {script: `trap 'exit 0' TERM; echo $$ > %q; while :; do sleep 0.05; done`, code: 0},
		"exit 0 at the stop, behind a gateway": {script: `trap 'exit 0' TERM; echo $$ > %q; while :; do sleep 0.05; done`, code: 0, remote: true},
		"130 at its own SIGINT":                {script: `trap 'exit 130' INT; echo $$ > %q; while :; do sleep 0.05; done`, stop: "SIGINT", code: 130},
		"killed by SIGTERM":                    {script: `echo $$ > %q; exec sleep 30`, code: -1, signal: "SIGTERM"},
		"killed by SIGKILL":                    {script: `trap '' TERM; echo $$ > %q; while :; do sleep 0.05; done`, grace: 300 * time.Millisecond, code: -1, signal: "SIGKILL"},
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "pid")
			script := fmt.Sprintf(c.script, file)
			var sp session.Spec
			var g *linktest.Fake
			if c.remote {
				sp, g, _ = remoteSpec(t, 0)
				sp.Args = []string{"-c", script}
				g.OnOutcome(func(string) linktest.Reply {
					return linktest.Reply{Status: 200, Body: map[string]any{"state": "failed", "reason": "checks_failed"}}
				})
			} else {
				sp = shellSpec(t, script)
			}
			sp.StopSignal, sp.StopGrace = c.stop, c.grace
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				pidOf(t, file)
				cancel()
			}()
			res, err := session.Run(ctx, sp)
			if err != nil {
				t.Fatalf("Run returned %v", err)
			}
			if !res.Cancelled || res.TimedOut || res.RunClosed || res.State != "cancelled" || res.Reason != "interrupted" || res.ExitCode != c.code || res.Signal != c.signal {
				t.Errorf("result %+v, want cancelled interrupted with exit %d %q", res, c.code, c.signal)
			}
			if state, reason, code := endedWith(t, res); state != "cancelled" || reason != "interrupted" || code != c.code {
				t.Errorf("run.exited %s %s %d", state, reason, code)
			}
			if c.remote {
				if got := g.Outcomes(); len(got) != 0 {
					t.Errorf("the outcome was asked for %v", got)
				}
				posted := ofType(g.Events(), "dev.qory.run.exited")
				if len(posted) != 1 || data(posted[0])["state"] != "cancelled" || data(posted[0])["reason"] != "interrupted" {
					t.Errorf("the gateway received run.exited %v", posted)
				}
			}
		})
	}
}

// TestTheTimeLimitIsTheStopSignal pins the time limit's rule: a runtime the limit's
// stop signal reached is cancelled with timeout, TimedOut, also one that exits 0 at it,
// which Run returns as a result with no error; one that exited by itself before the
// limit's signal, whose output stayed open past the limit, is decided by its exit.
func TestTheTimeLimitIsTheStopSignal(t *testing.T) {
	for name, c := range map[string]struct {
		script        string
		state, reason string
		code          int
		timedOut      bool
	}{
		"exit 0 at the limit's stop":     {`trap 'exit 0' TERM; while :; do sleep 0.05; done`, "cancelled", "timeout", 0, true},
		"exit 3 before the limit's stop": {`(sleep 1) & exit 3`, "failed", "", 3, false},
	} {
		t.Run(name, func(t *testing.T) {
			sp := shellSpec(t, c.script)
			sp.Timeout = 300 * time.Millisecond
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatalf("Run returned %v", err)
			}
			if res.TimedOut != c.timedOut || res.Cancelled || res.State != c.state || res.Reason != c.reason || res.ExitCode != c.code || res.Signal != "" {
				t.Errorf("result %+v, want %s %q with exit %d", res, c.state, c.reason, c.code)
			}
			if state, reason, code := endedWith(t, res); state != c.state || reason != c.reason || code != c.code {
				t.Errorf("run.exited %s %s %d", state, reason, code)
			}
		})
	}
}

// TestAnExitWhoseOutputStaysOpenPastTheGrace pins a runtime that exits 0 by itself,
// with the context alive, while a descendant holds its standard output open past the
// stop grace: its exit is observed at the grace, succeeded with exit 0, Run returns its
// result with no error, run.exited is recorded, and Cancelled is false. What the
// descendant writes after the grace is not kept.
func TestAnExitWhoseOutputStaysOpenPastTheGrace(t *testing.T) {
	sp := shellSpec(t, `(sleep 1.5; echo late) & echo early; exit 0`)
	sp.StopGrace = 300 * time.Millisecond
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatalf("Run returned %v", err)
	}
	if res.State != "succeeded" || res.Reason != "" || res.ExitCode != 0 || res.Signal != "" || res.Cancelled || res.TimedOut {
		t.Errorf("result %+v", res)
	}
	if state, reason, code := endedWith(t, res); state != "succeeded" || reason != "" || code != 0 {
		t.Errorf("run.exited %s %q %d", state, reason, code)
	}
	var logged strings.Builder
	for _, e := range ofType(events(t, res), "dev.qory.run.log") {
		b, _ := base64.StdEncoding.DecodeString(fmt.Sprint(data(e)["bytes"]))
		logged.Write(b)
	}
	if !strings.Contains(logged.String(), "early") || strings.Contains(logged.String(), "late") {
		t.Errorf("the record's output %q", logged.String())
	}
}
