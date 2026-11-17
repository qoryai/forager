package session

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestParseExecReadsAfter pins Exec's After options: --after-only, --after-timeout and
// --after-word go together and take no program; the program of any other launch follows
// --, and no option of After goes with it.
func TestParseExecReadsAfter(t *testing.T) {
	opts, argv, err := parseExec([]string{"--after-only", "--after-timeout", "1500", "--after-word", "git", "--after-word", "--"})
	if err != nil || !opts.afterOnly || argv != nil {
		t.Fatalf("parseExec: %+v, %q, %v", opts, argv, err)
	}
	if want := (afterLaunch{words: []string{"git", "--"}, timeout: 1500 * time.Millisecond}); !slices.Equal(opts.after.words, want.words) || opts.after.timeout != want.timeout {
		t.Errorf("after %+v, want %+v", opts.after, want)
	}
	for _, args := range [][]string{
		{"--after-timeout", "1000", "--", "p"},
		{"--after-word", "git", "--", "p"},
		{"--after-only", "--after-timeout", "1000", "--after-word", "git", "--", "p"},
		{"--after-only", "--after-word", "git"},
		{"--after-only", "--after-timeout", "1000"},
		{"--after-only", "--after-timeout", "0", "--after-word", "git"},
		{"--after-only", "--after-timeout", "-5", "--after-word", "git"},
		{"--after-only", "--after-timeout", "1s", "--after-word", "git"},
		{"--after-only", "--after-timeout", "1000", "--after-word", ""},
		{"--after-only", "--after-timeout", "1000", "--after-word", "git", "--unset", "A"},
		{"--after-docker", "--", "p"},
		{"--after-only", "--after-timeout"},
		{"--after-word"},
	} {
		if _, _, err := parseExec(args); err == nil {
			t.Errorf("parseExec(%q) took it", args)
		}
	}
	// The options afterCommand writes are those parseExec reads.
	a := afterLaunch{words: []string{"/bin/sh", "-c", "git commit"}, timeout: 2 * time.Second}
	command, args := afterCommand([]string{"helper", "exec"}, a)
	opts, argv, err = parseExec(args[1:])
	if command != "helper" || err != nil || !opts.afterOnly || !slices.Equal(opts.after.words, a.words) || opts.after.timeout != a.timeout || argv != nil {
		t.Errorf("parseExec(%q): %+v, %q, %v", args, opts, argv, err)
	}
	// The launch of the runtime has no option of After.
	if _, args := withExec([]string{"helper", "exec"}, []string{"B"}, "runtime", nil); slices.ContainsFunc(args, func(w string) bool { return strings.HasPrefix(w, "--after") }) {
		t.Errorf("withExec: %q", args)
	}
}

// TestAfterEnvDropsGitsRedirections pins After's environment: no variable that points
// git elsewhere or makes a shell or the linker run a file, no PATH, no socket, and the
// settings that win over every configuration file.
func TestAfterEnvDropsGitsRedirections(t *testing.T) {
	env := afterEnv([]string{
		"HOME=/home/agent", "PATH=/tmp/bin", "GIT_DIR=/x", "GIT_WORK_TREE=/x", "GIT_INDEX_FILE=/x", "GIT_EXEC_PATH=/x",
		"GIT_CONFIG=/x", "GIT_CONFIG_PARAMETERS='core.hooksPath'='/x'", "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=core.hooksPath",
		"GIT_CONFIG_VALUE_0=/x", "GIT_SSH_COMMAND=/x", "GIT_ASKPASS=/x", "BASH_ENV=/x", "ENV=/x", "LD_PRELOAD=/x",
		"LD_LIBRARY_PATH=/x", EnvSocket + "=/x", "GIT_AUTHOR_NAME=agent", "NOEQUALS", "XDG_CONFIG_HOME=/x", "XDG_DATA_HOME=/x",
	}, "/empty")
	for _, kv := range env {
		if strings.HasSuffix(kv, "=/x") || strings.HasPrefix(kv, "PATH=") || kv == "NOEQUALS" || strings.Contains(kv, "'/x'") {
			t.Errorf("After's environment has %s", kv)
		}
	}
	if slices.Contains(env, "HOME=/home/agent") {
		t.Errorf("After's environment has the agent's HOME: %q", env)
	}
	for _, kv := range []string{"HOME=/empty", "GIT_AUTHOR_NAME=agent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat", "GIT_EDITOR=:", "GIT_CONFIG_COUNT=40", "GIT_CONFIG_KEY_0=core.hooksPath",
		"GIT_CONFIG_VALUE_0=/dev/null", "GIT_CONFIG_KEY_3=protocol.allow", "GIT_CONFIG_VALUE_3=never",
		"GIT_CONFIG_KEY_4=protocol.https.allow", "GIT_CONFIG_VALUE_4=always", "GIT_CONFIG_KEY_9=credential.helper", "GIT_CONFIG_VALUE_9=",
		"GIT_CONFIG_KEY_15=hook.pre-commit.enabled", "GIT_CONFIG_VALUE_15=false"} {
		if !slices.Contains(env, kv) {
			t.Errorf("After's environment has no %s: %q", kv, env)
		}
	}
}

// TestAfterPathKeepsDirectoriesTheUserCannotWrite pins After's PATH: an empty or
// relative entry, a directory the user can write or that lies under one, and one that
// does not exist are left out; with none left it is /usr/bin:/bin.
func TestAfterPathKeepsDirectoriesTheUserCannotWrite(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write every directory")
	}
	writable := t.TempDir()
	under := filepath.Join(writable, "bin")
	if err := os.Mkdir(under, 0o500); err != nil {
		t.Fatal(err)
	}
	got := afterPath(strings.Join([]string{"", ".", "bin", writable, under, "/nonexistent/bin", "/usr/bin", "/usr/bin/", "/bin"}, ":"), os.Getuid())
	if got != "/usr/bin:/bin" {
		t.Errorf("afterPath: %q, want /usr/bin:/bin", got)
	}
	if got := afterPath(writable, os.Getuid()); got != "/usr/bin:/bin" {
		t.Errorf("afterPath of a writable directory alone: %q", got)
	}
}

// TestAgentMayChangeADirectoryItOwns pins the agent's ~/.local/bin with mode 555 on it
// and every directory above it up to the home: no process can write it, but the agent
// owns it and may set its mode again, so After's PATH leaves it out, and a program in
// it does not run.
func TestAgentMayChangeADirectoryItOwns(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write every directory")
	}
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	program := filepath.Join(bin, "git")
	if err := os.WriteFile(program, []byte("#!/bin/sh\n"), 0o555); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{bin, filepath.Dir(bin), home} {
		if err := os.Chmod(d, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(d, 0o755) })
	}
	if unix.Access(bin, unix.W_OK) == nil {
		t.Fatal("the user can write the directory of mode 555")
	}
	for _, p := range []string{bin, program} {
		if !agentMayChange(p, os.Getuid()) {
			t.Errorf("%s of mode 555 that the agent owns counts as unchanged", p)
		}
	}
	if got := afterPath(bin+":/usr/bin", os.Getuid()); got != "/usr/bin" {
		t.Errorf("afterPath: %q, want /usr/bin", got)
	}
	if _, err := afterProgram(program, os.Getuid()); !errors.Is(err, errAgentProgram) {
		t.Errorf("afterProgram of the agent's file: %v", err)
	}
	if got, err := afterProgram("/bin/sh", os.Getuid()); err != nil || got == "" {
		t.Errorf("afterProgram of /bin/sh: %q, %v", got, err)
	}
}

// TestAgentMayChangeByMode pins the modes [agentMayChange] reads, as root, for an
// agent of another user: a directory writable by its group or by others, without the
// sticky bit, and a file writable by its group or by others, may be changed; the same
// directory with the sticky bit, and a file and a directory of mode 755 of another
// user, may not.
func TestAgentMayChangeByMode(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("only root makes files of another user")
	}
	const owner, agent = 4242, 4243
	root := t.TempDir()
	for name, c := range map[string]struct {
		dir  bool
		mode uint32
		want bool
	}{
		"group-writable directory": {true, 0o775, true},
		"other-writable directory": {true, 0o757, true},
		"sticky other-writable":    {true, 0o1777, false},
		"directory of mode 755":    {true, 0o755, false},
		"group-writable file":      {false, 0o775, true},
		"other-writable file":      {false, 0o757, true},
		"file of mode 755":         {false, 0o755, false},
	} {
		p := filepath.Join(root, strings.ReplaceAll(name, " ", "-"))
		var err error
		if c.dir {
			err = os.Mkdir(p, 0o700)
		} else {
			err = os.WriteFile(p, nil, 0o700)
		}
		if err == nil {
			err = os.Chown(p, owner, owner)
		}
		if err == nil {
			// unix.Chmod takes the sticky bit as the mode's 01000.
			err = unix.Chmod(p, c.mode)
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := agentMayChange(p, agent); got != c.want {
			t.Errorf("%s: agentMayChange %v, want %v", name, got, c.want)
		}
		if got := agentMayChange(p, owner); !got {
			t.Errorf("%s: the owner may not change it", name)
		}
	}
}

// TestOOMKillsReadsMemoryEvents pins the count After's out_of_memory compares.
func TestOOMKillsReadsMemoryEvents(t *testing.T) {
	root := t.TempDir()
	if _, ok := oomKills(root); ok {
		t.Error("a missing memory.events was read")
	}
	os.WriteFile(filepath.Join(root, "memory.events"), []byte("low 0\nhigh 0\nmax 3\noom 2\noom_kill 2\n"), 0o600)
	if n, ok := oomKills(root); !ok || n != 2 {
		t.Errorf("oomKills: %d, %v", n, ok)
	}
}

// TestAfterDoesNotRunWithoutTheSocket pins the helper's exec in its after-only mode: when
// it cannot connect to the session's socket, After does not run, so no push goes
// unrecorded, and the reason goes to stderr with the exit status 125.
func TestAfterDoesNotRunWithoutTheSocket(t *testing.T) {
	dir := t.TempDir()
	ran := filepath.Join(dir, "ran")
	touch, err := exec.LookPath("touch")
	if err != nil {
		t.Skip("no touch in PATH")
	}
	t.Setenv(EnvSocket, filepath.Join(dir, "no-socket"))
	// The helper runs in a process of the test binary, not the test's: on Linux it closes every descriptor above
	// 2 of the process it runs in, which the test's other tests need.
	cmd := exec.Command(os.Args[0], "exec", "--after-only", "--after-timeout", "1000", "--after-word", touch, "--after-word", ran)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err = cmd.Run()
	code := -1
	if exit := (*exec.ExitError)(nil); errors.As(err, &exit) {
		code = exit.ExitCode()
	}
	if _, err := os.Stat(ran); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("After ran (%v); want it not run", err)
	}
	if code != setupRunnerFailed || !strings.Contains(stderr.String(), "so After did not run") {
		t.Errorf("exit %d, stderr %q; want 125 and the reason After did not run", code, stderr.String())
	}
}
