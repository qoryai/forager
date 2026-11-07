package session_test

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// helperExec runs the helper's exec, this test binary in its exec mode, with args and
// the environment env, and returns what it printed and its exit status.
func helperExec(t *testing.T, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"exec"}, args...)...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		return string(out), exit.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	return string(out), 0
}

// TestTheHelpersExecUnsetsTheNames pins the helper's exec: the names it is given are
// unset in the program it starts, found in PATH, and every other variable is as it was,
// an empty one included; the words after -- are the program's, an --unset among them.
func TestTheHelpersExecUnsetsTheNames(t *testing.T) {
	env := []string{"PATH=" + os.Getenv("PATH"), "GONE=image-value", "ALSO_GONE=", "KEPT=kept", "KEPT_EMPTY="}
	out, code := helperExec(t, env, "--unset", "GONE", "--unset", "ALSO_GONE", "--unset", "NEVER_SET", "--", "env")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for _, want := range []string{"KEPT=kept", "KEPT_EMPTY=", "PATH=" + os.Getenv("PATH")} {
		if !contains(lines, want) {
			t.Errorf("the program's environment lacks %s:\n%s", want, out)
		}
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "GONE=") || strings.HasPrefix(line, "ALSO_GONE=") || strings.HasPrefix(line, "NEVER_SET=") {
			t.Errorf("the program's environment has %s", line)
		}
	}
	if out, code := helperExec(t, env, "--unset", "GONE", "--", "echo", "--unset", "KEPT", "--"); code != 0 || strings.TrimSpace(out) != "--unset KEPT --" {
		t.Errorf("the program's words: exit %d, %q", code, out)
	}
}

// contains reports whether lines holds the line.
func contains(lines []string, line string) bool {
	for _, l := range lines {
		if l == line {
			return true
		}
	}
	return false
}

// TestTheHelpersExecRefusesWhatItCannotRun pins the helper's exec's failures, each
// with its reason and no program started: arguments it cannot read, and a name that is
// not a variable's, quoted nowhere, exit 2, a NUL, which no argument carries, being
// parseExec's test; a program it does not find, or finds only through . or an empty
// entry of PATH, 127; and one it cannot execute, a file without the execute bit, one
// that is no program and a directory, 126.
func TestTheHelpersExecRefusesWhatItCannotRun(t *testing.T) {
	env := []string{"PATH=" + os.Getenv("PATH")}
	for _, args := range [][]string{
		{"--unset", "A=value-not-shown", "--", "true"},
		{"--unset", "", "--", "true"},
		{"--unset", "1A", "--", "true"},
		{"--unset", "A-B", "--", "true"},
		{"--unset"},
		{"--unset", "A", "true"},
		{"--unset", "A", "--"},
		{"--unset", "A", "--", ""},
		{"--other", "--", "true"},
	} {
		out, code := helperExec(t, env, args...)
		if code != 2 || !strings.HasPrefix(out, "exec: ") || strings.Contains(out, "value-not-shown") {
			t.Errorf("%q: exit %d, %q; want 2 and a reason", args, code, out)
		}
	}
	if out, code := helperExec(t, env, "--", "no-such-program-walltest"); code != 127 || !strings.Contains(out, "not found") {
		t.Errorf("a program not found: exit %d, %q; want 127", code, out)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "here"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{".", ":" + os.Getenv("PATH")} {
		cmd := exec.Command(os.Args[0], "exec", "--", "here")
		cmd.Env, cmd.Dir = []string{"PATH=" + path}, dir
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 127 || !strings.Contains(string(out), "found only through .") {
			t.Errorf("a program found through PATH=%q: %v, %q; want 127", path, err, out)
		}
	}
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("#!/bin/sh\nexit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(dir, "garbage")
	if err := os.WriteFile(garbage, []byte{0, 1, 2, 3, 4, 5, 6, 7}, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, program := range []string{plain, garbage, dir} {
		if out, code := helperExec(t, env, "--", program); code != 126 || !strings.Contains(out, "cannot be executed") {
			t.Errorf("%s: exit %d, %q; want 126", filepath.Base(program), code, out)
		}
	}
}

// TestTheHelpersExecReturnsTheProgramsStatus pins the exit status of the helper's
// exec, which waits for the program: the program's code, and 128 and the signal's
// number for a program a signal ended, as a shell reports it.
func TestTheHelpersExecReturnsTheProgramsStatus(t *testing.T) {
	env := []string{"PATH=" + os.Getenv("PATH")}
	for _, c := range []struct {
		line string
		want int
	}{
		{"exit 0", 0},
		{"exit 7", 7},
		{"exit 255", 255},
		{"kill -KILL $$", 128 + 9},
		{"kill -TERM $$", 128 + 15},
		{"kill -INT $$", 128 + 2},
	} {
		if out, code := helperExec(t, env, "--", "sh", "-c", c.line); code != c.want {
			t.Errorf("%s: exit %d, %q; want %d", c.line, code, out, c.want)
		}
	}
}

// waitForFile waits up to 10 seconds for path to exist with content.
func waitForFile(t *testing.T, path string) {
	t.Helper()
	for range 200 {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s did not appear", path)
}

// signalScript traps each signal it is given with a line in $OUT, writes $READY, and
// exits 40 a moment after the first line.
const signalScript = `for s in "$@"; do trap "echo $s >> \"\$OUT\"" "$s"; done
echo ready > "$READY"
while [ ! -s "$OUT" ]; do sleep 0.05; done
sleep 0.3
exit 40`

// TestTheHelpersExecPassesSignalsOn pins that each signal a session or docker-init
// sends the helper's exec reaches the program once, and that the helper's exec still
// returns the program's status after it.
func TestTheHelpersExecPassesSignalsOn(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH, syscall.SIGALRM} {
		name := strings.TrimPrefix(unix.SignalName(sig), "SIG")
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			ready, out := filepath.Join(dir, "ready"), filepath.Join(dir, "out")
			cmd := exec.Command(os.Args[0], "exec", "--", "sh", "-c", signalScript, "sh", name)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "READY=" + ready, "OUT=" + out}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waitForFile(t, ready)
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			err := cmd.Wait()
			got, _ := os.ReadFile(out)
			if cmd.ProcessState.ExitCode() != 40 || string(got) != name+"\n" {
				t.Errorf("exit %d (%v), the program got %q; want 40 and %s once", cmd.ProcessState.ExitCode(), err, got, name)
			}
		})
	}
}

// terminalScript reports its process group and the terminal's foreground group in
// $PG, counts INT and WINCH in $OUT, writes $READY, and exits 40 plus the number of
// lines once it has one of each.
const terminalScript = `trap 'echo int >> "$OUT"' INT
trap 'echo winch >> "$OUT"' WINCH
ps -o pgid= -o tpgid= -p $$ > "$PG"
echo ready > "$READY"
while [ "$(grep -c . "$OUT" 2>/dev/null)" != 2 ]; do sleep 0.05; done
sleep 0.3
exit $((40 + $(grep -c . "$OUT")))`

// TestTheHelpersExecGivesTheProgramTheTerminal pins the helper's exec on a terminal:
// the program runs in a separate process group, which is the terminal's foreground
// group, so a resize and a Ctrl-C reach the program once each and the helper's exec
// not at all, and the helper's exec returns the program's status.
func TestTheHelpersExecGivesTheProgramTheTerminal(t *testing.T) {
	dir := t.TempDir()
	ready, out, pg := filepath.Join(dir, "ready"), filepath.Join(dir, "out"), filepath.Join(dir, "pg")
	cmd := exec.Command(os.Args[0], "exec", "--", "sh", "-c", terminalScript)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "READY=" + ready, "OUT=" + out, "PG=" + pg}
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	defer ptmx.Close()
	go io.Copy(io.Discard, ptmx)
	waitForFile(t, ready)
	if err := pty.Setsize(ptmx, &pty.Winsize{Cols: 100, Rows: 30}); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, out)
	if _, err := ptmx.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	got, _ := os.ReadFile(out)
	if cmd.ProcessState.ExitCode() != 42 || string(got) != "winch\nint\n" {
		t.Errorf("exit %d (%v), the program got %q; want 42 and one WINCH, then one INT", cmd.ProcessState.ExitCode(), err, got)
	}
	groups, _ := os.ReadFile(pg)
	f := strings.Fields(string(groups))
	if len(f) != 2 || f[0] != f[1] || f[0] == strconv.Itoa(cmd.Process.Pid) {
		t.Errorf("the program's process group and the terminal's foreground group: %q; want one group, not the helper's %d", groups, cmd.Process.Pid)
	}
}
