package session_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
