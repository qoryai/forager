package session_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// ended is the state and the exit code of the record's run.exited, which Cancelled
// leaves as they are.
func ended(t *testing.T, res *session.Result) (string, int) {
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
	return state, int(code)
}

// TestTheContextsEndWhileTheRuntimeRunsIsACancel pins Cancelled for a context that ends
// while the runtime runs, which the session stops: on its own, and in a wall.
func TestTheContextsEndWhileTheRuntimeRunsIsACancel(t *testing.T) {
	for name, sp := range map[string]func(t *testing.T) session.Spec{
		"unwalled": func(t *testing.T) session.Spec { return shellSpec(t, "sleep 30") },
		"walled": func(t *testing.T) session.Spec {
			root := t.TempDir()
			sp := walledSpec(t, &openWall{})
			sp.Mounts, sp.Dir = []wall.Mount{{Path: root}}, root
			sp.Command, sp.Args = "sh", []string{"-c", "sleep 30"}
			return sp
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			res, err := session.Run(ctx, sp(t))
			if err != nil {
				t.Fatal(err)
			}
			if !res.Cancelled || res.TimedOut || res.Signal != "SIGTERM" {
				t.Errorf("result %+v", res)
			}
			if state, code := ended(t, res); state != "failed" || code != -1 {
				t.Errorf("run.exited %s %d", state, code)
			}
		})
	}
}

// TestARuntimeThatLeavesAtItsOwnInterruptIsCancelled pins a Ctrl-C that reaches the
// runtime and the caller at once: the runtime leaves at its own SIGINT, not at the
// session's stop, which it ignores, and the context had ended when its exit was
// observed.
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
	if state, code := ended(t, res); state != "failed" || code != 130 {
		t.Errorf("run.exited %s %d", state, code)
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

	sp = shellSpec(t, "trap '' TERM; exec sleep 30")
	sp.Timeout, sp.StopGrace = 300*time.Millisecond, 1500*time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
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
