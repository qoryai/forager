package session

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/forager/session/internal/descriptor"
	"github.com/qoryai/forager/session/internal/socket"
	"github.com/qoryai/forager/session/runtimes"
)

// runnerRecords runs RunSetupCommand with args against a socket of the test's and
// returns its exit status, what it wrote to stderr, and the records the socket read,
// each as event, then stream and the line's bytes or the exit code.
func runnerRecords(t *testing.T, args ...string) (int, string, []string) {
	t.Helper()
	l, err := socket.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []string
	go l.Serve(func(rec descriptor.Record) {
		mu.Lock()
		defer mu.Unlock()
		m := rec.Record
		line := fmt.Sprint(rec.Source, " ", m["command"], " ", m["event"])
		if b, ok := m["bytes"].(string); ok {
			raw, _ := base64.StdEncoding.DecodeString(b)
			line += fmt.Sprintf(" %s %q", m["stream"], raw)
		}
		if c, ok := m["exit_code"]; ok {
			line += fmt.Sprint(" ", c)
		}
		got = append(got, line)
	}, func(err error) { t.Errorf("socket: %v", err) })
	t.Setenv(EnvSocket, l.Path())
	var stderr bytes.Buffer
	code := RunSetupCommand(args, &stderr)
	l.Close()
	mu.Lock()
	defer mu.Unlock()
	return code, stderr.String(), got
}

// TestTheSetupRunnerReportsTheCommand pins the runner: a started record before the
// command runs, each line of its output with its stream, a long line in parts of 4096
// bytes and a last line without a break as it is, then its exit status, which is the
// runner's too.
func TestTheSetupRunnerReportsTheCommand(t *testing.T) {
	long := strings.Repeat("x", 5000)
	code, stderr, got := runnerRecords(t, "2", "--", "/bin/sh", "-c", `echo one; echo two >&2; printf '`+long+`\n'; printf last; exit 3`)
	if code != 3 || stderr != "" {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
	byStream := map[string][]string{}
	for _, g := range got[1 : len(got)-1] {
		parts := strings.SplitN(g, " ", 5)
		byStream[parts[3]] = append(byStream[parts[3]], parts[4])
	}
	want := map[string][]string{
		"stdout": {`"one\n"`, fmt.Sprintf("%q", long[:4096]), fmt.Sprintf("%q", long[4096:]+"\n"), `"last"`},
		"stderr": {`"two\n"`},
	}
	if len(got) < 2 || got[0] != "setup 2 started" || got[len(got)-1] != "setup 2 exited 3" || fmt.Sprint(byStream) != fmt.Sprint(want) {
		t.Errorf("the records %q", got)
	}
}

// TestTheSetupRunnersExitStatusIsAShells pins the runner's exit status for a command
// a signal ends, one it does not find, and arguments it cannot read.
func TestTheSetupRunnersExitStatusIsAShells(t *testing.T) {
	code, _, got := runnerRecords(t, "1", "--", "/bin/sh", "-c", "kill -TERM $$")
	if code != 128+15 || len(got) != 2 || got[1] != "setup 1 exited 143" {
		t.Errorf("a command a signal ends: exit %d, records %q", code, got)
	}
	code, _, got = runnerRecords(t, "1", "--", "no-such-program-anywhere")
	if code != 127 || len(got) != 3 || !strings.Contains(got[1], "no-such-program-anywhere") || got[2] != "setup 1 exited 127" {
		t.Errorf("a program it does not find: exit %d, records %q", code, got)
	}
	for _, args := range [][]string{nil, {"1"}, {"0", "--", "true"}, {"x", "--", "true"}, {"1", "true"}, {"1", "--"}, {"1", "--", ""}} {
		code, stderr, got := runnerRecords(t, args...)
		if code != 125 || stderr != "Start the setup command as preparation.sh does: its number from 1, then --, then the program and its arguments.\n" || len(got) != 0 {
			t.Errorf("%q: exit %d, stderr %q, records %q", args, code, stderr, got)
		}
	}
}

// TestTheSetupRunnerNeedsTheSocket pins that a runner with no socket to reach exits
// 125 with the line about the socket, and runs nothing.
func TestTheSetupRunnerNeedsTheSocket(t *testing.T) {
	ran := filepath.Join(t.TempDir(), "ran")
	missing := filepath.Join(t.TempDir(), "sock")
	for addr, shown := range map[string]string{missing: missing, "": `""`} {
		t.Setenv(EnvSocket, addr)
		var stderr bytes.Buffer
		code := RunSetupCommand([]string{"1", "--", "touch", ran}, &stderr)
		if want := "Run the setup command through QORY_RUN_SOCKET: the socket " + shown + " is not reachable.\n"; code != 125 || stderr.String() != want {
			t.Errorf("exit %d, stderr %q, want 125 and %q", code, stderr.String(), want)
		}
	}
	if matches, _ := filepath.Glob(ran); len(matches) != 0 {
		t.Error("the command ran with no socket to report on")
	}
}

// stopInScript writes the setup's script for commands into a directory of the test's,
// with `kill -TERM $$` written in front of the first line that starts with before, so
// the stop reaches the script exactly there, and runs it with a runtime that touches
// a file. It returns the script's exit status and whether the runtime ran.
func stopInScript(t *testing.T, before string, commands ...SetupCommand) (int, bool) {
	t.Helper()
	dir := t.TempDir()
	runner := []string{"/bin/sh", "-c", `shift 2; exec "$@"`, "runner"}
	launch, err := withSetup(dir, runner, commands, runtimes.Launch{Command: "touch", Args: []string{filepath.Join(dir, "runtime-ran")}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, PreparationScript)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(b), "\n"+before)
	if i < 0 {
		t.Fatalf("the script has no line that starts with %q:\n%s", before, b)
	}
	script := string(b[:i+1]) + "kill -TERM $$\n" + string(b[i+1:])
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	err = exec.Command(launch.Command, launch.Args...).Run()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	_, statErr := os.Stat(filepath.Join(dir, "runtime-ran"))
	return code, statErr == nil
}

// TestAStopAfterTheLastSetupCommandStartsNoRuntime pins that a stop that reaches the
// script after its last setup command's check and before its trap is reset starts no
// runtime: the script exits with the last command's status.
func TestAStopAfterTheLastSetupCommandStartsNoRuntime(t *testing.T) {
	code, ran := stopInScript(t, "trap - ", SetupCommand{Name: "install", Args: []string{"true"}})
	if ran || code != 0 {
		t.Errorf("exit %d; the runtime ran: %v", code, ran)
	}
}

// TestAStopBetweenSetupCommandsStartsNoMore pins that a stop that reaches the script
// between two setup commands starts neither the next command nor the runtime.
func TestAStopBetweenSetupCommandsStartsNoMore(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "second-ran")
	code, ran := stopInScript(t, "setup '/bin/sh' '-c' 'shift 2; exec \"$@\"' 'runner' 2 ",
		SetupCommand{Name: "install", Args: []string{"true"}},
		SetupCommand{Name: "start services", Args: []string{"touch", marker}})
	if _, err := os.Stat(marker); err == nil || ran || code != 0 {
		t.Errorf("exit %d; the runtime ran: %v; the second command ran: %v", code, ran, err == nil)
	}
}
