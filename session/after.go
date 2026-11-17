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

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/session/internal/descriptor"
	"github.com/qoryai/forager/session/internal/socket"
	"golang.org/x/sys/unix"
)

// afterName is the name of a session's after step.
const afterName = "after"

// checkAfter returns an error for an After a session cannot have: one without a wall, with no
// AfterTimeout above zero, with an empty program, or with a NUL in a word. A wall
// needs Exec, which [checkExec] checks first.
func checkAfter(spec runSpec) error {
	switch {
	case len(spec.After) == 0:
		return nil
	case spec.Wall == nil:
		return errors.New("Open the run with a wall to run SessionSpec.After.\nAfter runs in a new container of the wall, once the agent's container is removed.")
	case spec.AfterTimeout <= 0:
		return errors.New("Set SessionSpec.AfterTimeout above zero: it is how long SessionSpec.After may run.")
	case spec.After[0] == "":
		return errors.New("Give SessionSpec.After a program: its first word is empty.")
	case slices.ContainsFunc(spec.After, func(w string) bool { return strings.ContainsRune(w, 0) }):
		return errors.New("Remove the NUL from SessionSpec.After: no argument contains one.")
	}
	return nil
}

// afterLaunch is what the session passes the helper's exec of SessionSpec.After: its
// words as the After container has them, and AfterTimeout.
type afterLaunch struct {
	words   []string
	timeout time.Duration
}

// args are the exec options that run only After: --after-only, then --after-timeout and
// each word.
func (a afterLaunch) args() []string {
	out := []string{"--after-only", "--after-timeout", strconv.FormatInt(a.timeout.Milliseconds(), 10)}
	for _, w := range a.words {
		out = append(out, "--after-word", w)
	}
	return out
}

// afterCommand is the command of the After container: the helper's exec, helper, with
// a's options.
func afterCommand(helper []string, a afterLaunch) (string, []string) {
	return helper[0], append(slices.Clone(helper[1:]), a.args()...)
}

// The record of the after source: After wrote a line or exited. The session writes the
// start of the step itself, when it starts the container. A line has stream, stdout or
// stderr, and bytes in standard base64, and runner true on a line the helper writes in
// place of the command's output; an exit has exit_code, from 0 to 255, and reason,
// timeout or out_of_memory, when the command did not end by itself.
const (
	afterReasonTimeout   = "timeout"
	afterReasonOutOfMemo = "out_of_memory"
)

// execAfter is the helper's exec in its after-only mode, in the After container: it
// makes itself not dumpable, so no other process of the container reads its descriptors
// through /proc or traces it, connects to the session's socket at [EnvSocket] before
// After's command starts, and sends every record of the after source over that
// connection, which the session reads alone. It returns 0 once After ran and its exit
// was sent, and 125 when it cannot make itself not dumpable, cannot connect or cannot
// send, with the reason on stderr.
func execAfter(a afterLaunch, stderr io.Writer) int {
	if err := undumpable(); err != nil {
		fmt.Fprintf(stderr, "exec: allow prctl(PR_SET_DUMPABLE) in the wall's seccomp profile.\nThe helper could not make itself not dumpable (%v), so After did not run.\n", err)
		return setupRunnerFailed
	}
	// A descriptor the engine or an earlier process left open is closed first; the
	// connection made next is close-on-exec, so no process After starts has it.
	closeInherited()
	addr := os.Getenv(EnvSocket)
	if addr == "" {
		fmt.Fprintf(stderr, "exec: set %s to the session's socket.\nIt is not set, so After did not run.\n", EnvSocket)
		return setupRunnerFailed
	}
	conn, err := socket.Dial(context.Background(), addr)
	if err != nil {
		fmt.Fprintf(stderr, "exec: run the launch where the run socket reaches the container.\nThe connection could not be made (%v), so After did not run.\n", err)
		return setupRunnerFailed
	}
	defer conn.Close()
	record := func(m map[string]any) descriptor.Record {
		return descriptor.Record{Source: descriptor.SourceAfter, Record: m}
	}
	sender := startSetupSender(conn.Send)
	line := func(stream string, b []byte) {
		sender.send(record(map[string]any{"event": setupLine, "stream": stream, "bytes": encode(b)}))
	}
	failed := func(b []byte) {
		sender.send(record(map[string]any{"event": setupLine, "stream": "stderr", "bytes": encode(b), "runner": true}))
	}
	code, reason := runAfter(a, line, failed)
	exited := map[string]any{"event": setupExited, "exit_code": code}
	if reason != "" {
		exited["reason"] = reason
	}
	sender.send(record(exited))
	if err := sender.close(); err != nil {
		fmt.Fprintf(stderr, "exec: run the launch where the run socket reaches the container.\nThe after step's records did not all reach the session: %v\n", err)
		return setupRunnerFailed
	}
	return 0
}

// agentUser is the user After's program check treats as the agent's: the user the helper
// runs as, which behind a wall is never root, since a run with a root image does not start. A test
// running as root sets it to another user, since no file is safe from root.
var agentUser = os.Getuid

// runAfter runs the words of a with no input, in a new process group, with
// [afterEnv]'s environment and [afterPath]'s PATH, hands line each line of its output
// and failed the line it writes when it cannot start or wait for the command, and
// returns its exit status as a shell reports it, with the reason: timeout when it ran
// past a.timeout, out_of_memory when the cgroup's oom_kill count rose while it ran.
func runAfter(a afterLaunch, line func(stream string, b []byte), failed func(b []byte)) (int, string) {
	before, counted := oomKills(cgroupRoot)
	agent := agentUser()
	path := afterPath(os.Getenv("PATH"), agent)
	// LookPath reads the process's PATH: the command is found in the filtered one.
	os.Setenv("PATH", path)
	var mu sync.Mutex
	stdout := &setupLines{mu: &mu, stream: "stdout", line: line}
	stderr := &setupLines{mu: &mu, stream: "stderr", line: line}
	cmd := exec.Command(a.words[0], a.words[1:]...)
	program, err := afterProgram(a.words[0], agent)
	cmd.Path, cmd.Err = program, err
	home, removeHome, err := emptyHome()
	if err != nil {
		failed(failureLine(fmt.Errorf("Check that the temporary directory is writable and has room.\nAfter's empty HOME could not be made: %w", err)))
		return setupRunnerFailed, ""
	}
	defer removeHome()
	cmd.Env = append(afterEnv(os.Environ(), home), "PATH="+path)
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
	err = cmd.Wait()
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
// helper, those that make a shell or the dynamic linker run a file first, HOME, which
// After gets as an empty directory, and the XDG base directories, under which git and
// interpreters read files of the user's.
var afterDropped = []string{
	"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_EXEC_PATH", "GIT_CONFIG*", "GIT_SSH*",
	"GIT_ASKPASS", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR",
	"GIT_NAMESPACE", "GIT_PROXY_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_SEQUENCE_EDITOR",
	"BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", EnvSocket, "HOME", "XDG_*",
}

// hookEvents are the events of githooks(5). git 2.55 and later run no hook of
// .git/config's hook.<name>.command for an event whose hook.<event>.enabled is false.
// git 2.54.0 has no such setting: hook.<name>.enabled turns off one name, which After
// cannot list for a repository it does not know, so there those hooks run.
var hookEvents = []string{
	"applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
	"prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout", "post-merge",
	"pre-push", "pre-receive", "update", "proc-receive", "post-receive", "post-update",
	"reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite",
	"sendemail-validate", "fsmonitor-watchman", "p4-changelist", "p4-prepare-changelist",
	"p4-post-changelist", "p4-pre-submit", "post-index-change",
}

// afterConfig are the git settings After gets through GIT_CONFIG_COUNT, which win
// over every configuration file, the repository's .git/config included. git reaches
// a remote only over HTTPS: a local path or file:// URL would run the remote's
// receivepack or uploadpack setting, and ssh core.sshCommand.
var afterConfig = append([][2]string{
	{"core.hooksPath", "/dev/null"},
	{"core.fsmonitor", "false"},
	{"core.attributesFile", "/dev/null"},
	{"protocol.allow", "never"},
	{"protocol.https.allow", "always"},
	{"protocol.ext.allow", "never"},
	{"submodule.recurse", "false"},
	{"core.useReplaceRefs", "false"},
	{"core.commitGraph", "false"},
	{"credential.helper", ""},
	{"commit.gpgSign", "false"},
	{"tag.gpgSign", "false"},
}, hookSwitches()...)

// hookSwitches are hook.<event>.enabled false for each of hookEvents.
func hookSwitches() [][2]string {
	var out [][2]string
	for _, e := range hookEvents {
		out = append(out, [2]string{"hook." + e + ".enabled", "false"})
	}
	return out
}

// afterEnv is env, NAME=value entries, without PATH, [afterDropped] and an entry
// with no =, and with HOME set to home, the variables that keep git from reading the
// system's and the user's configuration, from asking at the terminal, from starting a
// pager or an editor, and with [afterConfig].
func afterEnv(env []string, home string) []string {
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
	out = append(out, "HOME="+home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat", "GIT_EDITOR=:",
		"GIT_CONFIG_COUNT="+strconv.Itoa(len(afterConfig)))
	for i, kv := range afterConfig {
		out = append(out, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]))
	}
	return out
}

// emptyHome makes After's HOME: a new directory under the system's temporary directory,
// empty and of mode 0500, so neither After nor a file the agent left there is in it,
// and nothing writes to it. remove removes it.
func emptyHome() (dir string, remove func(), err error) {
	dir, err = os.MkdirTemp("", "qory-after-home-")
	if err != nil {
		return "", nil, err
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		os.Remove(dir)
		return "", nil, err
	}
	return dir, func() { os.Remove(dir) }, nil
}

// afterPath is path, a PATH, with only its absolute directories that exist and that
// the agent's user, agent, could not have changed: [agentMayChange] is false for the
// directory and for every directory above it. A program the agent placed is not found.
// /usr/bin:/bin when none is left.
func afterPath(path string, agent int) string {
	var kept []string
	for _, dir := range filepath.SplitList(path) {
		if dir == "" || !filepath.IsAbs(dir) || slices.Contains(kept, filepath.Clean(dir)) {
			continue
		}
		dir = filepath.Clean(dir)
		if st, err := os.Stat(dir); err != nil || !st.IsDir() || changeableAbove(dir, agent) {
			continue
		}
		kept = append(kept, dir)
	}
	if len(kept) == 0 {
		return "/usr/bin:/bin"
	}
	return strings.Join(kept, string(filepath.ListSeparator))
}

// changeableAbove reports whether [agentMayChange] is true for p or for a directory
// above it, up to /.
func changeableAbove(p string, agent int) bool {
	for {
		if agentMayChange(p, agent) {
			return true
		}
		up := filepath.Dir(p)
		if up == p {
			return false
		}
		p = up
	}
}

// agentMayChange reports whether the user agent could have changed the file or
// directory at p, or replaced what it contains, or whether p cannot be read: p belongs
// to agent, who may set its mode, or is writable by its group or by others, but for a
// directory with the sticky bit, or, when the process runs as agent, the process may
// write it. A file or directory on a read-only mount cannot be changed: no process of
// the container may mount again.
func agentMayChange(p string, agent int) bool {
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		return true
	}
	if readOnlyMount(p) {
		return false
	}
	dir := st.Mode&unix.S_IFMT == unix.S_IFDIR
	switch {
	case int(st.Uid) == agent:
		return true
	case st.Mode&0o022 != 0 && !(dir && st.Mode&unix.S_ISVTX != 0):
		return true
	}
	return agent == os.Getuid() && unix.Access(p, unix.W_OK) == nil
}

// afterProgram is the file After's program, word, runs: [exec.LookPath]'s in the PATH
// of the process, with every link followed. It returns an error when the agent's user,
// agent, could have changed the file or a directory above it, [changeableAbove].
func afterProgram(word string, agent int) (string, error) {
	found, err := exec.LookPath(word)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(found)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(real) {
		if real, err = filepath.Abs(real); err != nil {
			return "", err
		}
	}
	if changeableAbove(real, agent) {
		return "", fmt.Errorf("%w.\n%s is a file the agent's user could have changed, or lies under such a directory, so After did not run", errAgentProgram, accesskey.ShownValue(real, false))
	}
	return real, nil
}

// errAgentProgram is the error of an After program the agent's user could have
// changed.
var errAgentProgram = errors.New("Use a program for After in a directory the agent's user cannot write")

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
