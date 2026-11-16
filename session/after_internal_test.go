package session

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestParseExecReadsAfter pins Exec's After options: --after-timeout and --after-word
// go together, --after-docker needs them, and the program follows --.
func TestParseExecReadsAfter(t *testing.T) {
	opts, argv, err := parseExec([]string{"--unset", "A", "--after-timeout", "1500", "--after-word", "git", "--after-word", "--", "--after-docker", "--", "p"})
	if err != nil || !slices.Equal(opts.names, []string{"A"}) || !slices.Equal(argv, []string{"p"}) {
		t.Fatalf("parseExec: %+v, %q, %v", opts, argv, err)
	}
	if want := (afterLaunch{words: []string{"git", "--"}, timeout: 1500 * time.Millisecond, docker: true}); !slices.Equal(opts.after.words, want.words) || opts.after.timeout != want.timeout || !opts.after.docker {
		t.Errorf("after %+v, want %+v", opts.after, want)
	}
	for _, args := range [][]string{
		{"--after-timeout", "1000", "--", "p"},
		{"--after-word", "git", "--", "p"},
		{"--after-docker", "--", "p"},
		{"--after-timeout", "0", "--after-word", "git", "--", "p"},
		{"--after-timeout", "-5", "--after-word", "git", "--", "p"},
		{"--after-timeout", "1s", "--after-word", "git", "--", "p"},
		{"--after-timeout", "1000", "--after-word", "", "--", "p"},
		{"--after-timeout"},
		{"--after-word"},
	} {
		if _, _, err := parseExec(args); err == nil {
			t.Errorf("parseExec(%q) took it", args)
		}
	}
	// The options withExec writes are those parseExec reads.
	a := afterLaunch{words: []string{"/bin/sh", "-c", "git commit"}, timeout: 2 * time.Second, docker: true}
	_, args := withExec([]string{"helper", "exec"}, []string{"B"}, a, "runtime", []string{"--flag"})
	opts, argv, err = parseExec(args[1:])
	if err != nil || !slices.Equal(opts.after.words, a.words) || opts.after.timeout != a.timeout || !opts.after.docker || !slices.Equal(argv, []string{"runtime", "--flag"}) {
		t.Errorf("parseExec(%q): %+v, %q, %v", args, opts, argv, err)
	}
	if _, args := withExec([]string{"helper", "exec"}, nil, afterLaunch{}, "runtime", nil); slices.ContainsFunc(args, func(w string) bool { return strings.HasPrefix(w, "--after") }) {
		t.Errorf("withExec with no After: %q", args)
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
		"LD_LIBRARY_PATH=/x", EnvSocket + "=/x", "GIT_AUTHOR_NAME=agent", "NOEQUALS",
	})
	for _, kv := range env {
		if strings.HasSuffix(kv, "=/x") || strings.HasPrefix(kv, "PATH=") || kv == "NOEQUALS" || strings.Contains(kv, "'/x'") {
			t.Errorf("After's environment has %s", kv)
		}
	}
	for _, kv := range []string{"HOME=/home/agent", "GIT_AUTHOR_NAME=agent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat", "GIT_EDITOR=:", "GIT_CONFIG_COUNT=10", "GIT_CONFIG_KEY_0=core.hooksPath",
		"GIT_CONFIG_VALUE_0=/dev/null", "GIT_CONFIG_KEY_7=credential.helper", "GIT_CONFIG_VALUE_7="} {
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
	got := afterPath(strings.Join([]string{"", ".", "bin", writable, under, "/nonexistent/bin", "/usr/bin", "/usr/bin/", "/bin"}, ":"))
	if got != "/usr/bin:/bin" {
		t.Errorf("afterPath: %q, want /usr/bin:/bin", got)
	}
	if got := afterPath(writable); got != "/usr/bin:/bin" {
		t.Errorf("afterPath of a writable directory alone: %q", got)
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
