package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"os/signal"
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

// checkExec refuses an Exec a run cannot have: none behind a wall, one whose program is
// empty, and one with a NUL in a word.
func checkExec(spec runSpec) error {
	switch {
	case spec.Wall != nil && len(spec.Exec) == 0:
		return errors.New(`Set SessionSpec.Exec to the helper's exec, such as {wall.HelperPath, "exec"}: a walled run starts every launch through it`)
	case len(spec.Exec) > 0 && spec.Exec[0] == "":
		return errors.New("Exec's program is empty")
	case slices.ContainsFunc(spec.Exec, func(w string) bool { return strings.ContainsRune(w, 0) }):
		return errors.New("Exec holds a NUL, which no argument does")
	}
	return nil
}

// withExec is the launch of command and args started through the helper's exec, which
// unsets the names first, then starts the launch, measures the enclosure when it exits,
// and runs after's command when it has one. The session calls it only behind a wall.
func withExec(helper, unset []string, after afterLaunch, command string, args []string) (string, []string) {
	words := slices.Clone(helper[1:])
	for _, name := range unset {
		words = append(words, "--unset", name)
	}
	words = append(words, after.args()...)
	return helper[0], append(append(words, "--", command), args...)
}

// Exec is the program that starts a walled run's launch inside the enclosure: the
// caller's binary runs it there in a hidden mode, as it runs [Forward]. The session
// starts every walled launch through it, SessionSpec.Exec. Exec removes the names it
// is given from its environment: the names the run has that nothing sets and wins
// with, the runtime's declared, reserved and denied names, its model overrides and the
// node's denied ones. So a value the image gives one never reaches the runtime, and
// neither does an empty one, which a program may read as set. Every other variable
// stays as it is. Exec finds the program in PATH by [exec.LookPath] and does not run
// one found only through . or an empty entry of PATH, for which LookPath returns an
// error.
//
// Exec stays the program's parent and waits for it, so it can measure the enclosure
// once the program exits. Before it starts the program it closes every file descriptor
// above 2, apart from the Go runtime's poller, an eventpoll and an eventfd, which reach
// no file. It runs as the program does: the same user, groups and capabilities. It is
// not dumpable from its start, so no process of the agent's reads its /proc files or
// traces it. With nested Docker, [wall.Nest] executes Exec after it becomes the agent's
// user. Exec starts the program in a separate process group, as a shell starts a job.
// When its standard input is a terminal whose foreground group is Exec's, that group
// becomes the program's, so the terminal sends INT, QUIT, TSTP and WINCH to the program
// alone, once each. Exec never reads or writes the terminal while it waits. It passes
// each of HUP, INT, QUIT, ABRT, USR1, USR2, ALRM, TERM, CONT, TSTP, TTIN, TTOU and
// WINCH that reaches it, such as the stop signal docker-init passes on, to the program,
// except HUP or INT when its parent started it with that signal ignored: the program
// then inherits it ignored. A signal that reaches Exec after the program has exited
// changes nothing.
//
// When the program has exited and [EnvSocket] is set, Exec reads the enclosure's peak
// memory and CPU time from its cgroup v2 files and sends them to the session's socket
// as one record of the measure source: peak_memory_bytes from memory.peak, and
// cpu_time_ms from usage_usec in cpu.stat, divided by 1000. It reads them only when
// /sys/fs/cgroup/memory.max exists, which leaves out a host's root cgroup, cgroup v1
// and a host's cgroup seen without a cgroup namespace. A value it cannot read is left
// out of the record, and a record with no value is not sent.
//
// With --after-word, Exec first makes a random key, 32 bytes in hexadecimal, and sends
// it to the socket as a record of the after source with event key, before it starts
// the program: the socket's first record, sent while no process of the agent's runs.
// When the key cannot be sent, the program does not start and Exec returns 125, its
// reason written to stderr. The key is in no variable or argument. Once the program
// has exited, Exec runs SessionSpec.After, as its documentation says, and reports it
// to the socket as records of the after source, each with the key: that it started,
// each line of its output, and its exit status with the reason, timeout or
// out_of_memory, when it did not end by itself. Exec stops the container's other processes only when it is
// the container's first program: the child of pid 1, an engine's init program such as
// Docker's docker-init, in a pid namespace other than the machine's. Otherwise After
// does not start and its exit status is 125. Exec sends the first record, that After
// started, once it has stopped the other processes; when that record cannot be sent,
// After does not run and Exec writes the reason to stderr. Signals that reach Exec
// while After runs change nothing.
//
// Its arguments are --unset NAME, any number of times, then --after-timeout MS,
// --after-word WORD once for each word of After, and --after-docker when the
// enclosure runs nested Docker, or none of them, then -- and the program and its
// arguments, which no option of its reaches. A NAME is a variable's name: letters,
// digits and underscores, starting with a letter or an underscore. When a signal ended
// the program, Exec ends by the same signal once it has sent the measure, so its
// parent sees the end it saw when Exec executed the program in its place: docker-init
// exits 128 and the signal's number, and a session without Docker sees the signal.
// For a signal whose default action does not end a process, or when Exec outlives the
// signal, it returns 128 and the signal's number. Otherwise it returns the exit
// status, as a shell does: the program's, 2 for arguments it cannot read, 127 for a
// program it does not find, or finds only through . or an empty entry of PATH, 126
// for one it cannot execute, and 125 when it cannot make itself not dumpable, its
// reason written to stderr.
func Exec(args []string, stderr io.Writer) int {
	// From its start, no process of the agent's reads Exec's memory, environment or
	// descriptors, or traces it, After's key included: the program's execve makes the
	// program dumpable again, and Exec stays as it is.
	if err := undumpable(); err != nil {
		fmt.Fprintf(stderr, "exec: allow prctl(PR_SET_DUMPABLE) in the wall's seccomp profile: Exec could not make itself not dumpable (%v), so the program did not start.\n", err)
		return setupRunnerFailed
	}
	opts, argv, err := parseExec(args)
	names := opts.names
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	// The socket is the session's, whatever names the runtime has unset.
	addr := os.Getenv(EnvSocket)
	for _, name := range names {
		os.Unsetenv(name)
	}
	path, err := exec.LookPath(argv[0])
	// program is the program as its messages print it.
	program := accesskey.ShownValue(argv[0], false)
	switch {
	case errors.Is(err, exec.ErrDot):
		fmt.Fprintf(stderr, "exec: %s: found only through . or an empty entry of PATH, which is not run\n", program)
		return 127
	case errors.Is(err, fs.ErrPermission), errors.Is(err, syscall.EISDIR):
		fmt.Fprintf(stderr, "exec: %s: cannot be executed: %v\n", program, accesskey.ShownError(err))
		return 126
	case err != nil:
		fmt.Fprintf(stderr, "exec: %s: not found\n", program)
		return 127
	}
	var key string
	if len(opts.after.words) > 0 {
		opts.after.kept = startingProcesses()
		// The key reaches the session before the program starts, while no process of
		// the agent's runs in the container: the socket's first record is Exec's.
		if key, err = sendAfterKey(addr); err != nil {
			fmt.Fprintf(stderr, "exec: run the launch where the run socket reaches the container: After's key could not be sent (%v), so the program did not start.\n", err)
			return setupRunnerFailed
		}
	}
	closeInherited()
	notify := passedOn()
	code, sig, err := startAndWait(path, argv, notify)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		fmt.Fprintf(stderr, "exec: %s: not found: %v\n", program, accesskey.ShownError(err))
		return 127
	case err != nil:
		fmt.Fprintf(stderr, "exec: %s: cannot be executed: %v\n", program, accesskey.ShownError(err))
		return 126
	}
	if addr != "" {
		// A session that is gone, or a socket that does not reach the enclosure, loses
		// the measure and nothing else.
		sendMeasure(addr, cgroupRoot)
	}
	if len(opts.after.words) > 0 {
		// Exec keeps ignoring the signals, while After gets their default actions: a
		// signal Exec catches, unlike one it ignores, has its default action in a child.
		signal.Notify(make(chan os.Signal, 1), notify...)
		runAfterStep(addr, key, opts.after, stderr)
	}
	if sig != 0 && endsByDefault(sig) {
		raise(sig)
	}
	return code
}

// endsByDefault reports whether the default action of sig ends a process.
func endsByDefault(sig syscall.Signal) bool {
	switch sig {
	case syscall.SIGCHLD, syscall.SIGCONT, syscall.SIGURG, syscall.SIGWINCH,
		syscall.SIGSTOP, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU:
		return false
	}
	return true
}

// sendMeasure sends the measure of the cgroup v2 files under root, [readMeasure]'s, to
// the socket at addr as one record of the measure source; nothing when it has no
// member.
func sendMeasure(addr, root string) error {
	m := readMeasure(root)
	if len(m) == 0 {
		return nil
	}
	return socket.Send(context.Background(), addr, []descriptor.Record{{Source: descriptor.SourceMeasure, Record: m}})
}

// forwarded are the signals [Exec] passes on to the program: those docker-init passes
// on, without CHLD, PIPE, URG and the ones a fault raises, which concern Exec alone.
var forwarded = []os.Signal{
	syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGABRT, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGALRM,
	syscall.SIGTERM, syscall.SIGCONT, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU, syscall.SIGWINCH,
}

// passedOn are the signals of [forwarded] the process did not start with ignored.
func passedOn() []os.Signal {
	var notify []os.Signal
	for _, sig := range forwarded {
		// Go keeps HUP and INT ignored when the process started with them ignored, and
		// a program started here inherits that.
		if !signal.Ignored(sig) {
			notify = append(notify, sig)
		}
	}
	return notify
}

// startAndWait starts the program at path with argv and the process's environment and
// standard streams, passes on each of notify, the signals [passedOn] returns, until it
// exits, and returns its exit status: its code, or 128 and the number of the signal
// that ended it, with that signal. The error is that of the start: the program did not
// run.
func startAndWait(path string, argv []string, notify []os.Signal) (int, syscall.Signal, error) {
	sigs := make(chan os.Signal, 32)
	signal.Notify(sigs, notify...)
	// The program runs in a separate process group, as a shell's job does and as
	// docker-init starts it. In a group shared with Exec, a terminal's INT would reach
	// both, and Exec cannot distinguish it from an INT docker-init passes on, so the program
	// would get it twice. On the terminal the program's group is the foreground: Go
	// sets it in the child before the program starts, with signals blocked, so no TTOU
	// stops it.
	attr := &syscall.SysProcAttr{Setpgid: true}
	if foreground() {
		attr.Foreground, attr.Ctty = true, 0
	}
	if beforeStart != nil {
		beforeStart()
	}
	pid, err := syscall.ForkExec(path, argv, &syscall.ProcAttr{Env: os.Environ(), Files: []uintptr{0, 1, 2}, Sys: attr})
	if err != nil {
		signal.Stop(sigs)
		return 0, 0, err
	}
	var mu sync.Mutex
	reaped := false
	done := make(chan struct{})
	go func() {
		defer close(done)
		for sig := range sigs {
			mu.Lock()
			if !reaped {
				syscall.Kill(pid, sig.(syscall.Signal))
			}
			mu.Unlock()
		}
	}()
	// No signal is passed on once the program has exited: its pid may belong to
	// another process once it is reaped. Where exited cannot wait without reaping, a
	// signal may still be passed on between the reaping and the lock.
	stop := func() {
		mu.Lock()
		reaped = true
		mu.Unlock()
	}
	if exited(pid) {
		stop()
	}
	var ws syscall.WaitStatus
	for {
		_, err = syscall.Wait4(pid, &ws, 0, nil)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	stop()
	// A signal from now on, while Exec sends the measure, changes nothing: Exec ends
	// with the program's status. raise sets the default action of the one it sends.
	ignore(notify)
	signal.Stop(sigs)
	close(sigs)
	<-done
	if afterWait != nil {
		afterWait()
	}
	switch {
	case err != nil:
		// The child is no longer Exec's to wait for: no status is known.
		return 128, 0, nil
	case ws.Signaled():
		return 128 + int(ws.Signal()), ws.Signal(), nil
	}
	return ws.ExitStatus(), 0, nil
}

// foreground reports whether standard input is a terminal whose foreground process
// group is Exec's.
func foreground() bool {
	pgrp, err := unix.IoctlGetInt(0, unix.TIOCGPGRP)
	return err == nil && pgrp == syscall.Getpgrp()
}

// beforeStart, when set, runs just before the program starts, and afterWait once the
// program is reaped: a test's hooks.
var beforeStart, afterWait func()

// maxMeasure is the largest value of a measure, 2^53-1, which every JSON reader,
// JavaScript's included, reads exactly.
const maxMeasure = 1<<53 - 1

// cgroupRoot is where the enclosure's cgroup v2 files are.
var cgroupRoot = "/sys/fs/cgroup"

// readMeasure reads the enclosure's peak memory and CPU time from the cgroup v2 files
// under root: peak_memory_bytes from memory.peak and cpu_time_ms from the usage_usec
// line of cpu.stat, divided by 1000 and rounded down. It reads nothing when
// root/memory.max does not exist. A file it cannot read, or a value that is not a
// whole number from 0 to 2^53-1, leaves its member out.
func readMeasure(root string) map[string]any {
	if _, err := os.Stat(filepath.Join(root, "memory.max")); err != nil {
		return nil
	}
	m := map[string]any{}
	if b, err := os.ReadFile(filepath.Join(root, "memory.peak")); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && v >= 0 && v <= maxMeasure {
			m["peak_memory_bytes"] = v
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "cpu.stat")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "usage_usec" {
				if v, err := strconv.ParseInt(f[1], 10, 64); err == nil && v >= 0 && v/1000 <= maxMeasure {
					m["cpu_time_ms"] = v / 1000
				}
				break
			}
		}
	}
	return m
}

// execOptions are [Exec]'s options: the names to unset and SessionSpec.After.
type execOptions struct {
	names []string
	after afterLaunch
}

// parseExec reads [Exec]'s arguments: its options, and the program and its arguments
// after --. A name outside a variable's grammar is refused without being quoted, since
// what is not a name may hold a value.
func parseExec(args []string) (execOptions, []string, error) {
	var opts execOptions
	usage := errors.New("exec: want --unset NAME ... [--after-timeout MS --after-word WORD ... [--after-docker]] -- program [args]")
	timeout := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--unset":
			if i+1 == len(args) {
				return opts, nil, errors.New("exec: --unset needs a name")
			}
			i++
			if !variableShape.MatchString(args[i]) {
				return opts, nil, errors.New("exec: an --unset is not a variable's name: letters, digits and underscores, starting with a letter or an underscore, of at most 128")
			}
			opts.names = append(opts.names, args[i])
		case "--after-timeout":
			if i+1 == len(args) {
				return opts, nil, errors.New("exec: --after-timeout needs milliseconds")
			}
			i++
			ms, err := strconv.ParseInt(args[i], 10, 64)
			if err != nil || ms <= 0 || ms > math.MaxInt64/int64(time.Millisecond) {
				return opts, nil, errors.New("exec: --after-timeout is a whole number of milliseconds above 0")
			}
			opts.after.timeout, timeout = time.Duration(ms)*time.Millisecond, true
		case "--after-word":
			if i+1 == len(args) {
				return opts, nil, errors.New("exec: --after-word needs a word")
			}
			i++
			opts.after.words = append(opts.after.words, args[i])
		case "--after-docker":
			opts.after.docker = true
		case "--":
			switch {
			case i+1 == len(args) || args[i+1] == "":
				return opts, nil, errors.New("exec: want --unset NAME ... -- program [args]: the program is missing")
			case timeout != (len(opts.after.words) > 0), opts.after.docker && !timeout:
				return opts, nil, errors.New("exec: --after-timeout and --after-word go together, and --after-docker needs them")
			case timeout && opts.after.words[0] == "":
				return opts, nil, errors.New("exec: the first --after-word, After's program, is empty")
			}
			return opts, args[i+1:], nil
		default:
			return opts, nil, usage
		}
	}
	return opts, nil, errors.New("exec: want --unset NAME ... -- program [args]: -- is missing")
}
