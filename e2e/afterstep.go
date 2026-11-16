package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/wall"
)

// modeLeaveJob is a runtime that leaves a job behind: it starts a process in a new
// session that writes jobFile after jobDelay, and exits 0 at once.
const modeLeaveJob = "leave-job"

// The job's file in the workspace, its delay, and the file After writes there.
const (
	jobFile   = "left-job.out"
	jobDelay  = 2 * time.Second
	afterOut  = "after-step.out"
	afterWait = 4 * time.Second
	// markerFile is the file the nested attack writes into the agent's container, at its
	// root.
	markerFile = "/after-marker"
)

// afterSocket is where After's container has its socket: the hook socket's directory
// of the Docker wall, and the name the session gives the socket.
const afterSocket = "/qory/hooks/sock"

// leaveJob is [modeLeaveJob]'s program. It prints an empty report, as the suite reads
// one from every runtime.
func leaveJob() int {
	cmd := exec.Command("/bin/sh", "-c", "sleep "+strings.TrimSuffix(jobDelay.String(), "s")+"; echo late > "+jobFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "leave-job:", err)
		return 1
	}
	fmt.Println(probePrefix + "{}")
	return 0
}

// block is [modeBlock]'s program. It prints an empty report, then waits for a signal
// that asks it to leave and exits 0.
func block() int {
	fmt.Println(probePrefix + "{}")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	<-ctx.Done()
	return 0
}

// forgeAfter is [modeForgeAfter]'s program: it connects to the socket at its argument
// and writes a start, a line and a successful exit of the after source, as a process of
// After's container that is told where the socket is.
func forgeAfter(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "forge-after: give the socket's path")
		return 2
	}
	conn, err := net.Dial("unix", args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "forge-after:", err)
		return 1
	}
	defer conn.Close()
	for _, rec := range []string{
		`{"source":"after","record":{"event":"started"}}`,
		`{"source":"after","record":{"event":"line","stream":"stdout","bytes":"Zm9yZ2VkCg=="}}`,
		`{"source":"after","record":{"event":"exited","exit_code":0}}`,
	} {
		if _, err := conn.Write([]byte(rec + "\n")); err != nil {
			fmt.Fprintln(os.Stderr, "forge-after:", err)
			return 1
		}
	}
	return 0
}

// attackAfter is [modeAttackAfter]'s program. It starts a container of the inner daemon,
// privileged, with the enclosure's root bound, writes markerFile through it, and exits 3
// when the file is not there, so the suite does not read a run whose attack did not take
// effect as one that After resisted. It prints an empty report.
func attackAfter() int {
	if err := importSelf(dockerClient(30 * time.Second)); err != nil {
		fmt.Fprintln(os.Stderr, "attack-after: the probe's image:", err)
		return 4
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		fmt.Fprintln(os.Stderr, "attack-after:", err)
		return 4
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, docker, "run", "--rm", "--privileged", "--mount", "type=bind,src=/,dst=/host", probeImage, "/probe", modeWrite, "/host"+markerFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "attack-after: %v: %s\n", err, out)
		return 4
	}
	if _, err := os.Stat(markerFile); err != nil {
		fmt.Fprintln(os.Stderr, "attack-after: the write through the inner container did not reach this container:", err)
		return 3
	}
	fmt.Println(probePrefix + "{}")
	return 0
}

// afterStartTime reads from events how long the after step took from its start to its
// first line: the removal of the agent's container, the start of After's container and
// the helper's start.
func afterStartTime(events []map[string]any) (time.Duration, error) {
	var started, firstLine time.Time
	step := 0.0
	read := func(e map[string]any) (time.Time, error) {
		s, _ := e["time"].(string)
		return time.Parse(time.RFC3339Nano, s)
	}
	for _, e := range events {
		d, _ := e["data"].(map[string]any)
		switch e["type"] {
		case event.StepStarted:
			if d["kind"] == event.StepAfter {
				step = d["step"].(float64)
				t, err := read(e)
				if err != nil {
					return 0, err
				}
				started = t
			}
		case event.RunLog:
			if step > 0 && d["step"] == step && firstLine.IsZero() {
				t, err := read(e)
				if err != nil {
					return 0, err
				}
				firstLine = t
			}
		}
	}
	if started.IsZero() || firstLine.IsZero() {
		return 0, errors.New("the record has no after step with a line")
	}
	return firstLine.Sub(started), nil
}

// afterStep checks SessionSpec.After: the runtime leaves a job that would write jobFile
// after jobDelay, and After, which waits afterWait first, writes alone to afterOut when
// jobFile does not exist by then, so the job did not outlive the agent's container into
// After's. A second run's After writes afterOut, then outlives AfterTimeout and does not
// write it again. A process of After's command that sends records to After's socket
// changes none of the after step's, and with nested Docker what the agent writes with
// the enclosure's root is not in After's container. The after step's records reach the
// session only where the socket crosses into the enclosure: After does not run
// without it, so each of these checks needs Options.Hooks.
func afterStep(t *testing.T, o Options, h hosts, outside string) {
	t.Run("After runs once every process the runtime left is gone", func(t *testing.T) {
		if !o.Hooks {
			t.Skip("the adapter does not bind the hook socket into the enclosure on this machine, so the after step's records do not reach the session")
		}
		script := "echo ready; sleep " + strings.TrimSuffix(afterWait.String(), "s") + "; if [ -e " + jobFile + " ]; then echo job > " + afterOut + "; else echo alone > " + afterOut + "; fi"
		r, err := runIn(t, o, variant{mode: modeLeaveJob, after: []string{"/bin/sh", "-c", script}, afterTimeout: time.Minute}, false, h, outside)
		if err != nil {
			t.Fatal(err)
		}
		if b, err := os.ReadFile(filepath.Join(r.dir, afterOut)); err != nil || string(b) != "alone\n" {
			t.Errorf("%s on this machine: %q, %v; want alone", afterOut, b, err)
		}
		if _, err := os.Stat(filepath.Join(r.dir, jobFile)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s on this machine: %v, want none: the job outlived the runtime", jobFile, err)
		}
		if a := r.res.After; a == nil || a.State != event.StateSucceeded || a.ExitCode != 0 {
			t.Errorf("Result.After %+v; want succeeded, 0\nstderr:\n%s", a, r.errs)
		}
		kinds := 0
		for _, e := range r.events {
			if d, _ := e["data"].(map[string]any); e["type"] == event.StepStarted && d["kind"] == event.StepAfter {
				kinds++
			}
		}
		if kinds != 1 {
			t.Errorf("%d after steps in the record, want 1", kinds)
		}
		took, err := afterStartTime(r.events)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("after step: %s from the step's start to After's first line (the agent's container's removal, After's container's start and the helper's start)", took)
	})
	t.Run("After stops at AfterTimeout", func(t *testing.T) {
		if !o.Hooks {
			t.Skip("the adapter does not bind the hook socket into the enclosure on this machine, so the after step's records do not reach the session")
		}
		script := "echo before > " + afterOut + "; sleep 60; echo late > " + afterOut
		start := time.Now()
		r, err := runIn(t, o, variant{mode: modeLeaveJob, after: []string{"/bin/sh", "-c", script}, afterTimeout: time.Second}, false, h, outside)
		if err != nil {
			t.Fatal(err)
		}
		if took := time.Since(start); took > 50*time.Second {
			t.Errorf("the run took %s", took)
		}
		if b, err := os.ReadFile(filepath.Join(r.dir, afterOut)); err != nil || string(b) != "before\n" {
			t.Errorf("%s on this machine: %q, %v; want before", afterOut, b, err)
		}
		if a := r.res.After; a == nil || a.State != event.StateCancelled || a.Reason != event.ReasonTimeout {
			t.Errorf("Result.After %+v; want cancelled, timeout", a)
		}
	})
	t.Run("a process of After's command cannot send a record of the after step", func(t *testing.T) {
		if !o.Hooks {
			t.Skip("the adapter does not bind the hook socket into the enclosure on this machine, so the after step's records do not reach the session")
		}
		after := []string{"/bin/sh", "-c", wall.HelperPath + " " + modeForgeAfter + " " + afterSocket + "; echo real; exit 3"}
		r, err := runIn(t, o, variant{mode: modeLeaveJob, after: after, afterTimeout: time.Minute}, false, h, outside)
		if err != nil {
			t.Fatal(err)
		}
		if a := r.res.After; a == nil || a.State != event.StateFailed || a.ExitCode != 3 {
			t.Fatalf("Result.After %+v; want the command's failed 3, not the forged success\nstderr:\n%s", a, r.errs)
		}
		var lines strings.Builder
		for _, e := range r.events {
			if d, _ := e["data"].(map[string]any); e["type"] == event.RunLog && d["step"] == float64(r.res.After.Step) {
				lines.WriteString(fmt.Sprint(d["bytes"]) + "\n")
			}
		}
		if strings.Contains(lines.String(), "Zm9yZ2VkCg==") {
			t.Errorf("the after step has the forged line: %q", lines.String())
		}
		t.Logf("the after step's lines, with the forging program's: %q", lines.String())
	})
	t.Run("After runs once the context of the join ends", func(t *testing.T) {
		if !o.Hooks {
			t.Skip("the adapter does not bind the hook socket into the enclosure on this machine, so the after step's records do not reach the session")
		}
		var cancelledAt time.Time
		script := "echo ready; echo done > " + afterOut
		r, err := runIn(t, o, variant{mode: modeBlock, after: []string{"/bin/sh", "-c", script}, afterTimeout: time.Minute, cancelAfter: 3 * time.Second, cancelledAt: &cancelledAt}, false, h, outside)
		if err != nil {
			t.Fatal(err)
		}
		if !r.res.Cancelled {
			t.Errorf("result %+v; want cancelled", r.res)
		}
		if a := r.res.After; a == nil || a.State != event.StateSucceeded || a.ExitCode != 0 {
			t.Errorf("Result.After %+v; want succeeded, 0\nstderr:\n%s", a, r.errs)
		}
		if b, err := os.ReadFile(filepath.Join(r.dir, afterOut)); err != nil || string(b) != "done\n" {
			t.Errorf("%s on this machine: %q, %v; want done", afterOut, b, err)
		}
		for _, e := range r.events {
			if e["type"] == event.SessionExited {
				ended, err := time.Parse(time.RFC3339Nano, fmt.Sprint(e["time"]))
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("session.exited %s after the context ended: the runtime's stop, the agent's container's removal, After's container's start and After", ended.Sub(cancelledAt))
			}
		}
	})
	t.Run("After's container gets nothing from the route to the caller", func(t *testing.T) {
		if !o.Hooks {
			t.Skip("the adapter does not bind the hook socket into the enclosure on this machine, so the after step's records do not reach the session")
		}
		var mu sync.Mutex
		var got []string
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			got = append(got, r.Method+" "+r.URL.Path)
			mu.Unlock()
			io.WriteString(w, "reached")
		})
		script := "wget -qO after-route.out -T 10 " + link.QoryHostURL + " 2> after-route.err; echo \"exit $?\" > " + afterOut
		r, err := runIn(t, o, variant{mode: modeLeaveJob, qoryRoute: handler, after: []string{"/bin/sh", "-c", script}, afterTimeout: time.Minute}, false, h, outside)
		if err != nil {
			t.Fatal(err)
		}
		if a := r.res.After; a == nil || a.State != event.StateSucceeded {
			t.Errorf("Result.After %+v; want succeeded", a)
		}
		if b, _ := os.ReadFile(filepath.Join(r.dir, "after-route.out")); strings.Contains(string(b), "reached") {
			t.Errorf("After's request got the handler's answer %q", b)
		}
		if b, err := os.ReadFile(filepath.Join(r.dir, afterOut)); err != nil || string(b) == "exit 0\n" {
			t.Errorf("%s on this machine: %q, %v; want a request that failed", afterOut, b, err)
		}
		mu.Lock()
		calls := slices.Clone(got)
		mu.Unlock()
		if len(calls) != 0 {
			t.Errorf("the handler got %q from After's container", calls)
		}
	})
	t.Run("the password the agent planted gets 403 or 503 from the route in After's container", func(t *testing.T) {
		if !o.Hooks {
			t.Skip("the adapter does not bind the hook socket into the enclosure on this machine, so the after step's records do not reach the session")
		}
		var mu sync.Mutex
		var got []string
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			got = append(got, r.Method+" "+r.URL.Path)
			mu.Unlock()
			io.WriteString(w, "reached")
		})
		after := []string{wall.HelperPath, modeAfterRoute}
		r, err := runIn(t, o, variant{mode: modePlantPassword, qoryRoute: handler, after: after, afterTimeout: time.Minute}, false, h, outside)
		if err != nil {
			t.Fatal(err)
		}
		if a := r.res.After; a == nil || a.State != event.StateSucceeded {
			t.Fatalf("Result.After %+v; want succeeded\nstderr:\n%s", a, r.errs)
		}
		// Without the password the gateway's proxy denies the route's host, 403. With the
		// agent's, the route answers that its session ended, 503.
		if b, err := os.ReadFile(filepath.Join(r.dir, afterRouteFile)); err != nil || string(b) != "403 503" {
			t.Errorf("After's requests without and with the agent's password got %q, %v; want \"403 503\"", b, err)
		}
		mu.Lock()
		calls := slices.Clone(got)
		mu.Unlock()
		if len(calls) != 0 {
			t.Errorf("the handler got %q from After's container", calls)
		}
	})
	t.Run("After's command cannot read or take the helper's descriptors", func(t *testing.T) {
		if !o.Hooks {
			t.Skip("the adapter does not bind the hook socket into the enclosure on this machine, so the after step's records do not reach the session")
		}
		r, err := runIn(t, o, variant{mode: modeLeaveJob, after: []string{wall.HelperPath, modeAfterInspect}, afterTimeout: time.Minute}, false, h, outside)
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(r.dir, afterInspectFile))
		if err != nil {
			t.Fatalf("the probe wrote no %s: %v\nstderr:\n%s", afterInspectFile, err, r.errs)
		}
		// The helper makes itself not dumpable, so /proc denies its environment and
		// descriptors to every other process of the container. ptrace and pidfd_getfd
		// may also be denied by the host's ptrace_scope setting, so only the first two are pinned.
		got := string(b)
		for _, name := range []string{"list the helper's descriptors", "read the helper's environment"} {
			if !strings.Contains(got, name+": denied\n") || strings.Contains(got, name+": allowed\n") {
				t.Errorf("the probe's output has no %q denied alone:\n%s", name, got)
			}
		}
		if strings.Contains(got, "no helper found") {
			t.Errorf("the probe found no helper:\n%s", got)
		}
		if a := r.res.After; a == nil || a.ExitCode != 3 {
			t.Errorf("Result.After %+v; want the command's 3, not the forged success", a)
		}
	})
	t.Run("what the agent writes with the enclosure's root is not in After's container", func(t *testing.T) {
		if !o.Hooks {
			t.Skip("the adapter does not bind the hook socket into the enclosure on this machine, so the after step's records do not reach the session")
		}
		if !o.Docker {
			t.Skip("the enclosure has no Docker of the agent's: the agent has no root in it")
		}
		script := "if [ -e " + markerFile + " ]; then echo planted > " + afterOut + "; else echo clean > " + afterOut + "; fi"
		r, err := runIn(t, o, variant{mode: modeAttackAfter, after: []string{"/bin/sh", "-c", script}, afterTimeout: time.Minute}, false, h, outside)
		if err != nil {
			t.Fatal(err)
		}
		if r.res.ExitCode != 0 {
			t.Fatalf("the attack did not take effect: the runtime exited %d\nstderr:\n%s", r.res.ExitCode, r.errs)
		}
		if b, err := os.ReadFile(filepath.Join(r.dir, afterOut)); err != nil || string(b) != "clean\n" {
			t.Errorf("%s on this machine: %q, %v; want clean", afterOut, b, err)
		}
		if a := r.res.After; a == nil || a.State != event.StateSucceeded || a.ExitCode != 0 {
			t.Errorf("Result.After %+v; want succeeded, 0", a)
		}
	})
}
