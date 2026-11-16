package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/qoryai/forager/session/internal/descriptor"
	"github.com/qoryai/forager/session/internal/socket"
	"golang.org/x/sys/unix"
)

// afterKillWait is how long After's process group gets between SIGTERM at
// AfterTimeout and SIGKILL: time for git to remove its index.lock.
const afterKillWait = 5 * time.Second

// stopOthersWait is how long Exec tries to stop the container's other processes
// before After: when one is still there by then, After does not start.
const stopOthersWait = 2 * time.Second

// stopProcesses is [stopOthers], or a test's stand-in.
var stopProcesses = stopOthers

// afterName is the name of a session's after step.
const afterName = "after"

// checkAfter refuses an After a session cannot have: one without a wall, with no
// AfterTimeout above zero, with an empty program, or with a NUL in a word. A wall
// needs Exec, which [checkExec] checks first.
func checkAfter(spec runSpec) error {
	switch {
	case len(spec.After) == 0:
		return nil
	case spec.Wall == nil:
		return errors.New("Open the run with a wall to run SessionSpec.After: After runs inside the wall's container, once every other process of it is stopped.")
	case spec.AfterTimeout <= 0:
		return errors.New("Set SessionSpec.AfterTimeout above zero: it is how long SessionSpec.After may run.")
	case spec.After[0] == "":
		return errors.New("Give SessionSpec.After a program: its first word is empty.")
	case slices.ContainsFunc(spec.After, func(w string) bool { return strings.ContainsRune(w, 0) }):
		return errors.New("Remove the NUL from SessionSpec.After: no argument contains one.")
	}
	return nil
}

// afterLaunch is what the session passes Exec of SessionSpec.After: its words as the
// enclosure has them, AfterTimeout, and whether the enclosure runs nested Docker.
type afterLaunch struct {
	words   []string
	timeout time.Duration
	docker  bool
}

// args are Exec's options for a: none when a has no words.
func (a afterLaunch) args() []string {
	if len(a.words) == 0 {
		return nil
	}
	out := []string{"--after-timeout", strconv.FormatInt(a.timeout.Milliseconds(), 10)}
	for _, w := range a.words {
		out = append(out, "--after-word", w)
	}
	if a.docker {
		out = append(out, "--after-docker")
	}
	return out
}

// The record of the after source: After started, wrote a line, or exited. A line has
// stream, stdout or stderr, and bytes in standard base64, and runner true on a line Exec
// writes in place of the command's output; an exit has exit_code, from 0 to 255, and
// reason, timeout or out_of_memory, when the command did not end by itself.
const (
	afterReasonTimeout   = "timeout"
	afterReasonOutOfMemo = "out_of_memory"
)

// runAfterStep runs After for [Exec] once the program exited and the measure was sent,
// and reports it to the socket at addr as records of the after source. When the first
// record cannot be sent, After still runs, with its output to stderr: what it leaves in
// the workspace counts, and the session sees no after step.
func runAfterStep(addr string, a afterLaunch, stderr io.Writer) {
	ctx := context.Background()
	record := func(m map[string]any) descriptor.Record {
		return descriptor.Record{Source: descriptor.SourceAfter, Record: m}
	}
	// Without the socket both streams go to stderr: the launch's stdout is the
	// runtime's, whose lines the session reads as the runtime's records.
	line := func(_ string, b []byte) { stderr.Write(b) }
	failed := func(b []byte) { stderr.Write(b) }
	var sender *setupSender
	if addr != "" && socket.Send(ctx, addr, []descriptor.Record{record(map[string]any{"event": setupStarted})}) == nil {
		sender = startSetupSender(ctx, addr)
		line = func(stream string, b []byte) {
			sender.send(record(map[string]any{"event": setupLine, "stream": stream, "bytes": encode(b)}))
		}
		failed = func(b []byte) {
			sender.send(record(map[string]any{"event": setupLine, "stream": "stderr", "bytes": encode(b), "runner": true}))
		}
	} else {
		fmt.Fprintln(stderr, "exec: the run socket does not reach the container, so the session records no after step; After runs, its output on stderr.")
	}
	code, reason := setupRunnerFailed, ""
	if err := stopProcesses(a.docker, stopOthersWait); err != nil {
		failed(fmt.Appendf(nil, "Stop the container's other processes before After: %v. After did not run.\n", err))
	} else {
		code, reason = runAfter(a, line, failed)
		// What After left running is stopped too: no process of it outlives the step.
		stopProcesses(a.docker, stopOthersWait)
	}
	if sender == nil {
		return
	}
	exited := map[string]any{"event": setupExited, "exit_code": code}
	if reason != "" {
		exited["reason"] = reason
	}
	sender.send(record(exited))
	if err := sender.close(); err != nil {
		fmt.Fprintf(stderr, "exec: the after step's records did not all reach the session: %v\n", err)
	}
}

// runAfter runs the words of a with no input, in a process group of its own, with
// [afterEnv]'s environment and [afterPath]'s PATH, hands line each line of its output
// and failed the line it writes when it cannot start or wait for the command, and
// returns its exit status as a shell reports it, with the reason: timeout when it ran
// past a.timeout, out_of_memory when the cgroup's oom_kill count rose while it ran.
func runAfter(a afterLaunch, line func(stream string, b []byte), failed func(b []byte)) (int, string) {
	before, counted := oomKills(cgroupRoot)
	path := afterPath(os.Getenv("PATH"))
	// LookPath reads the process's PATH: the command is found in the filtered one.
	os.Setenv("PATH", path)
	var mu sync.Mutex
	stdout := &setupLines{mu: &mu, stream: "stdout", line: line}
	stderr := &setupLines{mu: &mu, stream: "stderr", line: line}
	cmd := exec.Command(a.words[0], a.words[1:]...)
	cmd.Env = append(afterEnv(os.Environ()), "PATH="+path)
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = stdout, stderr, setupOutputGrace
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		failed(failureLine(err))
		switch {
		case errors.Is(err, exec.ErrNotFound), errors.Is(err, exec.ErrDot), errors.Is(err, os.ErrNotExist):
			return 127, ""
		default:
			return 126, ""
		}
	}
	pgid := cmd.Process.Pid
	// The signals go to the group only while its leader is not reaped, so they reach
	// no other process that took its number.
	var signalMu sync.Mutex
	waited, timedOut := false, false
	signalGroup := func(sig syscall.Signal) {
		signalMu.Lock()
		defer signalMu.Unlock()
		if !waited {
			if sig == syscall.SIGTERM {
				timedOut = true
			}
			syscall.Kill(-pgid, sig)
		}
	}
	term := time.AfterFunc(a.timeout, func() { signalGroup(syscall.SIGTERM) })
	kill := time.AfterFunc(a.timeout+afterKillWait, func() { signalGroup(syscall.SIGKILL) })
	err := cmd.Wait()
	signalMu.Lock()
	waited = true
	signalMu.Unlock()
	term.Stop()
	kill.Stop()
	stdout.flush()
	stderr.flush()
	code := 0
	var exit *exec.ExitError
	switch {
	case err == nil, errors.Is(err, exec.ErrWaitDelay):
	case errors.As(err, &exit):
		code = exit.ExitCode()
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			code = 128 + int(ws.Signal())
		}
	default:
		failed(failureLine(err))
		code = setupRunnerFailed
	}
	if timedOut {
		return code, afterReasonTimeout
	}
	if after, ok := oomKills(cgroupRoot); counted && ok && after > before {
		return code, afterReasonOutOfMemo
	}
	return code, ""
}

// afterDropped are the variables After does not get, by name or, ending in *, by
// prefix: those that point git at another repository, configuration, program or
// helper, and those that make a shell or the dynamic linker run a file first.
var afterDropped = []string{
	"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_EXEC_PATH", "GIT_CONFIG*", "GIT_SSH*",
	"GIT_ASKPASS", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR",
	"GIT_NAMESPACE", "GIT_PROXY_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_SEQUENCE_EDITOR",
	"BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", EnvSocket,
}

// afterConfig are the git settings After gets through GIT_CONFIG_COUNT, which win
// over every configuration file, the repository's .git/config included.
var afterConfig = [][2]string{
	{"core.hooksPath", "/dev/null"},
	{"core.fsmonitor", "false"},
	{"core.attributesFile", "/dev/null"},
	{"protocol.ext.allow", "never"},
	{"submodule.recurse", "false"},
	{"core.useReplaceRefs", "false"},
	{"core.commitGraph", "false"},
	{"credential.helper", ""},
	{"commit.gpgSign", "false"},
	{"tag.gpgSign", "false"},
}

// afterEnv is env, NAME=value entries, without PATH, [afterDropped] and an entry
// with no =, and with the variables that keep git from reading the system's and the
// user's configuration, from asking at the terminal, from starting a pager or an
// editor, and with [afterConfig].
func afterEnv(env []string) []string {
	var out []string
	for _, kv := range env {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "PATH" || slices.ContainsFunc(afterDropped, func(d string) bool {
			if p, prefix := strings.CutSuffix(d, "*"); prefix {
				return strings.HasPrefix(name, p)
			}
			return name == d
		}) {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat", "GIT_EDITOR=:",
		"GIT_CONFIG_COUNT="+strconv.Itoa(len(afterConfig)))
	for i, kv := range afterConfig {
		out = append(out, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]))
	}
	return out
}

// afterPath is path, a PATH, with only its absolute directories that exist and that
// the process's user cannot write, nor any directory above them: a program the agent
// placed is not found. /usr/bin:/bin when none is left.
func afterPath(path string) string {
	var kept []string
	for _, dir := range filepath.SplitList(path) {
		if dir == "" || !filepath.IsAbs(dir) || slices.Contains(kept, filepath.Clean(dir)) {
			continue
		}
		dir = filepath.Clean(dir)
		if st, err := os.Stat(dir); err != nil || !st.IsDir() || writableAbove(dir) {
			continue
		}
		kept = append(kept, dir)
	}
	if len(kept) == 0 {
		return "/usr/bin:/bin"
	}
	return strings.Join(kept, string(filepath.ListSeparator))
}

// writableAbove reports whether the process's user can write dir or a directory
// above it, up to /.
func writableAbove(dir string) bool {
	for {
		if unix.Access(dir, unix.W_OK) == nil {
			return true
		}
		up := filepath.Dir(dir)
		if up == dir {
			return false
		}
		dir = up
	}
}

// oomKills is the oom_kill count of memory.events under root, and whether it could be
// read.
func oomKills(root string) (int64, bool) {
	b, err := os.ReadFile(filepath.Join(root, "memory.events"))
	if err != nil {
		return 0, false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "oom_kill" {
			v, err := strconv.ParseInt(f[1], 10, 64)
			return v, err == nil
		}
	}
	return 0, false
}
