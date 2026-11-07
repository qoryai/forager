package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

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
		return errors.New("a walled run starts every launch through Exec, the helper's exec, and the spec has none")
	case len(spec.Exec) > 0 && spec.Exec[0] == "":
		return errors.New("Exec's program is empty")
	case slices.ContainsFunc(spec.Exec, func(w string) bool { return strings.ContainsRune(w, 0) }):
		return errors.New("Exec holds a NUL, which no argument does")
	}
	return nil
}

// withExec is the launch of command and args started through the helper's exec, which
// unsets the names first, then starts the launch and measures the enclosure when it
// exits. The session calls it only behind a wall.
func withExec(helper, unset []string, command string, args []string) (string, []string) {
	words := slices.Clone(helper[1:])
	for _, name := range unset {
		words = append(words, "--unset", name)
	}
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
// one found only through . or an empty entry of PATH, which LookPath refuses.
//
// Exec stays the program's parent and waits for it, so it can measure the enclosure
// once the program exits. Before it starts the program it closes every file
// descriptor above 2, apart from the Go runtime's poller, an eventpoll and an eventfd,
// which reach no file. It runs as the program does: the same user, groups and
// capabilities. With nested Docker, [wall.Nest] executes Exec after it becomes the
// agent's user. Exec starts the program in a separate process group, as a shell
// starts a job. When its standard input is a terminal whose foreground group is
// Exec's, that group becomes the program's, so the terminal sends INT, QUIT, TSTP and
// WINCH to the program alone, once each. Exec never reads or writes the terminal while
// it waits. It passes each of HUP, INT, QUIT, ABRT, USR1, USR2, ALRM, TERM, CONT,
// TSTP, TTIN, TTOU and WINCH that reaches it, such as the stop signal docker-init
// passes on, to the program, except HUP or INT when its parent started it with that
// signal ignored: the program then inherits it ignored.
//
// When the program has exited and [EnvSocket] is set, Exec reads the enclosure's peak
// memory and CPU time from its cgroup v2 files and sends them to the session's socket
// as one record of the measure source: peak_memory_bytes from memory.peak, and
// cpu_time_ms from usage_usec in cpu.stat, divided by 1000. It reads them only when
// /sys/fs/cgroup/memory.max exists, which leaves out a host's root cgroup, cgroup v1
// and a host's cgroup seen without a cgroup namespace. A value it cannot read is left
// out of the record, and a record with no value is not sent.
//
// Its arguments are --unset NAME, any number of times, then -- and the program and
// its arguments, which no option of its reaches. A NAME is a variable's name: letters,
// digits and underscores, starting with a letter or an underscore. When a signal ended
// the program, Exec ends by the same signal once it has sent the measure, so its
// parent sees the end it saw when Exec executed the program in its place: docker-init
// exits 128 and the signal's number, and a session without Docker sees the signal.
// For a signal whose default action does not end a process, or when Exec outlives the
// signal, it returns 128 and the signal's number. Otherwise it returns the exit
// status, as a shell does: the program's, 2 for arguments it cannot read, 127 for a
// program it does not find, or finds only through . or an empty entry of PATH, and
// 126 for one it cannot execute, its reason written to stderr.
func Exec(args []string, stderr io.Writer) int {
	names, argv, err := parseExec(args)
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
	closeInherited()
	code, sig, err := startAndWait(path, argv)
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

// startAndWait starts the program at path with argv and the process's environment and
// standard streams, passes on each of [forwarded] until it exits, and returns its exit
// status: its code, or 128 and the number of the signal that ended it, with that
// signal. The error is that of the start: the program did not run.
func startAndWait(path string, argv []string) (int, syscall.Signal, error) {
	var notify []os.Signal
	for _, sig := range forwarded {
		// Go keeps HUP and INT ignored when the process started with them ignored, and
		// a program started here inherits that.
		if !signal.Ignored(sig) {
			notify = append(notify, sig)
		}
	}
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
	var ws syscall.WaitStatus
	for {
		_, err = syscall.Wait4(pid, &ws, 0, nil)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	mu.Lock()
	reaped = true
	mu.Unlock()
	signal.Stop(sigs)
	close(sigs)
	<-done
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

// cgroupRoot is where the enclosure's cgroup v2 files are.
var cgroupRoot = "/sys/fs/cgroup"

// readMeasure reads the enclosure's peak memory and CPU time from the cgroup v2 files
// under root: peak_memory_bytes from memory.peak and cpu_time_ms from the usage_usec
// line of cpu.stat, divided by 1000 and rounded down. It reads nothing when
// root/memory.max does not exist. A file it cannot read, or a value that is not a
// whole number of 0 or more, leaves its member out.
func readMeasure(root string) map[string]any {
	if _, err := os.Stat(filepath.Join(root, "memory.max")); err != nil {
		return nil
	}
	m := map[string]any{}
	if b, err := os.ReadFile(filepath.Join(root, "memory.peak")); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && v >= 0 {
			m["peak_memory_bytes"] = v
		}
	}
	if b, err := os.ReadFile(filepath.Join(root, "cpu.stat")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "usage_usec" {
				if v, err := strconv.ParseInt(f[1], 10, 64); err == nil && v >= 0 {
					m["cpu_time_ms"] = v / 1000
				}
				break
			}
		}
	}
	return m
}

// parseExec reads [Exec]'s arguments: the names to unset, and the program and its
// arguments after --. A name outside a variable's grammar is refused without being
// quoted, since what is not a name may hold a value.
func parseExec(args []string) ([]string, []string, error) {
	var names []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--unset":
			if i+1 == len(args) {
				return nil, nil, errors.New("exec: --unset needs a name")
			}
			i++
			if !variableShape.MatchString(args[i]) {
				return nil, nil, errors.New("exec: an --unset is not a variable's name: letters, digits and underscores, starting with a letter or an underscore, of at most 128")
			}
			names = append(names, args[i])
		case "--":
			if i+1 == len(args) || args[i+1] == "" {
				return nil, nil, errors.New("exec: want --unset NAME ... -- program [args]: the program is missing")
			}
			return names, args[i+1:], nil
		default:
			return nil, nil, errors.New("exec: want --unset NAME ... -- program [args]")
		}
	}
	return nil, nil, errors.New("exec: want --unset NAME ... -- program [args]: -- is missing")
}
