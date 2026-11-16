package e2e

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
)

// modeLeaveJob is a runtime that leaves a job behind: it starts a process in a session
// of its own that writes jobFile after jobDelay, and exits 0 at once.
const modeLeaveJob = "leave-job"

// The job's file in the workspace, its delay, and the file After writes there.
const (
	jobFile   = "left-job.out"
	jobDelay  = 2 * time.Second
	afterOut  = "after-step.out"
	afterWait = 4 * time.Second
)

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

// afterStep checks SessionSpec.After: the runtime leaves a job that would write jobFile
// after jobDelay, and After, which waits afterWait first, writes alone to afterOut when
// jobFile does not exist by then, so the job was stopped before After. A second run's
// After writes afterOut, then outlives AfterTimeout and does not write it again. The
// after step's records reach the session only where the socket crosses into the
// enclosure.
func afterStep(t *testing.T, o Options, h hosts, outside string) {
	t.Run("After runs once every process the runtime left is stopped", func(t *testing.T) {
		script := "sleep " + strings.TrimSuffix(afterWait.String(), "s") + "; if [ -e " + jobFile + " ]; then echo job > " + afterOut + "; else echo alone > " + afterOut + "; fi"
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
		if !o.Hooks {
			t.Skip("the adapter does not bind the hook socket into the enclosure on this machine, so the after step's records do not reach the session")
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
	})
	t.Run("After stops at AfterTimeout", func(t *testing.T) {
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
		if !o.Hooks {
			t.Skip("the adapter does not bind the hook socket into the enclosure on this machine, so the after step's records do not reach the session")
		}
		if a := r.res.After; a == nil || a.State != event.StateCancelled || a.Reason != event.ReasonTimeout {
			t.Errorf("Result.After %+v; want cancelled, timeout", a)
		}
	})
}
