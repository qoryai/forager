package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"

	"github.com/qoryai/runner/session/internal/chunk"
	"github.com/qoryai/runner/session/runtimes"
)

// process is the runtime's process and where its streams go.
type process struct {
	command string
	args    []string
	env     []string
	dir     string
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
	// logs returns the chunk consumer for a stream.
	logs func(stream string) func([]byte)
	// stop is the signal that asks the process to leave, and grace how long it gets
	// after it before SIGKILL.
	stop  syscall.Signal
	grace time.Duration
	// output takes each JSON object the runtime prints as a line; nil when the
	// runtime has no output source.
	output func(map[string]any)
	// cols and rows size the pseudo-terminal, and resized is told each time that size
	// changes while the runtime runs. Neither means anything on pipes.
	cols, rows int
	resized    func(cols, rows int)
}

// The size a pseudo-terminal gets when Forager's own input is not a terminal, or
// its size is unknown: the size a terminal has always been assumed to have.
const (
	defaultCols = 80
	defaultRows = 24
)

// terminalSize is the size a run's pseudo-terminal starts with: the size of the terminal
// stdin is, or the default when stdin is not a terminal or its size is unknown.
func terminalSize(stdin io.Reader) (cols, rows int) {
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		if size, err := pty.GetsizeFull(f); err == nil && size.Cols > 0 && size.Rows > 0 {
			return int(size.Cols), int(size.Rows)
		}
	}
	return defaultCols, defaultRows
}

// exitStatus is how the runtime ended.
type exitStatus struct {
	code   int
	signal string
}

// DefaultStopGrace is how long the runtime gets after the stop signal before SIGKILL,
// when the context ends or the limit is reached, unless the spec names another.
const DefaultStopGrace = 10 * time.Second

// DefaultStopSignal is the signal that asks the runtime to leave, unless the spec names
// another.
const DefaultStopSignal = "SIGTERM"

// CheckStopSignal reports whether a spec may name the signal: SIGTERM, SIGINT, SIGHUP,
// SIGQUIT, SIGUSR1 or SIGUSR2, written that way. Empty is the default and passes. It is
// [runtimes.CheckStopSignal].
func CheckStopSignal(name string) error { return runtimes.CheckStopSignal(name) }

// newCmd builds the command with the context ending it: the stop signal, then SIGKILL
// after the grace.
func (p *process) newCmd(ctx context.Context) *exec.Cmd {
	cmd := exec.CommandContext(ctx, p.command, p.args...)
	cmd.Env = p.env
	cmd.Dir = p.dir
	cmd.Cancel = func() error { return cmd.Process.Signal(p.stop) }
	cmd.WaitDelay = p.grace
	return cmd
}

// runPipes runs the process on pipes: its input is stdin, its standard output goes to
// the terminal-less log as stdout, to the output source when there is one, and to
// stdout; its standard error to the log as stderr and to stderr.
func (p *process) runPipes(ctx context.Context) (exitStatus, error) {
	cmd := p.newCmd(ctx)
	cmd.Stdin = p.stdin
	out := chunk.New(p.logs("stdout"))
	errs := chunk.New(p.logs("stderr"))
	writers := []io.Writer{out, p.stdout}
	var lines *lineParser
	if p.output != nil {
		lines = &lineParser{on: p.output}
		writers = append(writers, lines)
	}
	cmd.Stdout = io.MultiWriter(writers...)
	cmd.Stderr = io.MultiWriter(errs, p.stderr)
	if err := cmd.Start(); err != nil {
		return exitStatus{}, fmt.Errorf("%w: %v", ErrNotStarted, err)
	}
	err := cmd.Wait()
	out.Flush()
	errs.Flush()
	if lines != nil {
		lines.flush()
	}
	return status(cmd, err)
}

// runPTY runs the process on a pseudo-terminal of the process's size: what it writes
// goes to the log as terminal, cut at the gap, and to stdout; what stdin holds goes to
// it; and when stdin is a terminal it is put in raw mode and its size is followed, each
// change reported.
func (p *process) runPTY(ctx context.Context) (exitStatus, error) {
	cmd := p.newCmd(ctx)
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(p.cols), Rows: uint16(p.rows)})
	if err != nil {
		return exitStatus{}, fmt.Errorf("%w: %v", ErrNotStarted, err)
	}
	defer ptmx.Close()
	log := chunk.NewTerminal(p.logs("terminal"), chunk.Gap)
	if f, ok := p.stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		apply := func(size *pty.Winsize) {
			// What was drawn before the resize is logged before it, whatever the gap
			// still holds; then the runtime learns the size, and the record does.
			log.Flush()
			pty.Setsize(ptmx, size)
			if p.resized != nil {
				p.resized(int(size.Cols), int(size.Rows))
			}
		}
		restore := attach(f, p.cols, p.rows, apply)
		defer restore()
	}
	go func() {
		io.Copy(ptmx, p.stdin)
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		io.Copy(io.MultiWriter(log, p.stdout), ptmx)
	}()
	err = cmd.Wait()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
	log.Flush()
	return status(cmd, err)
}

// attach puts a terminal in raw mode and follows its resizes until the returned
// function restores it: apply gets each size of the terminal that differs from the one
// before, cols by rows at first. The returned function waits for a resize in progress,
// so nothing is applied after it.
func attach(tty *os.File, cols, rows int, apply func(size *pty.Winsize)) func() {
	fd := int(tty.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		state = nil
	}
	resize := func() {
		size, err := pty.GetsizeFull(tty)
		if err != nil || size.Cols == 0 || size.Rows == 0 || (int(size.Cols) == cols && int(size.Rows) == rows) {
			return
		}
		cols, rows = int(size.Cols), int(size.Rows)
		apply(size)
	}
	// The terminal may have been resized between the start and here.
	resize()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range ch {
			resize()
		}
	}()
	return func() {
		signal.Stop(ch)
		close(ch)
		<-done
		if state != nil {
			term.Restore(fd, state)
		}
	}
}

// status turns Wait's error into the exit status.
func status(cmd *exec.Cmd, err error) (exitStatus, error) {
	if err == nil {
		return exitStatus{code: 0}, nil
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return exitStatus{}, err
	}
	st := exitStatus{code: exit.ExitCode()}
	if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		st.code = -1
		st.signal = "SIG" + signalName(ws.Signal())
	}
	return st, nil
}

func signalName(s syscall.Signal) string {
	switch s {
	case syscall.SIGKILL:
		return "KILL"
	case syscall.SIGTERM:
		return "TERM"
	case syscall.SIGINT:
		return "INT"
	case syscall.SIGHUP:
		return "HUP"
	case syscall.SIGQUIT:
		return "QUIT"
	case syscall.SIGUSR1:
		return "USR1"
	case syscall.SIGUSR2:
		return "USR2"
	}
	return fmt.Sprintf("%d", int(s))
}

// lineParser hands every line that is a JSON object to on, and ignores the rest.
type lineParser struct {
	on  func(map[string]any)
	buf bytes.Buffer
}

func (l *lineParser) Write(p []byte) (int, error) {
	l.buf.Write(p)
	for {
		i := bytes.IndexByte(l.buf.Bytes(), '\n')
		if i < 0 {
			return len(p), nil
		}
		line := make([]byte, i)
		copy(line, l.buf.Bytes()[:i])
		l.buf.Next(i + 1)
		l.line(line)
	}
}

func (l *lineParser) flush() {
	if l.buf.Len() > 0 {
		l.line(l.buf.Bytes())
		l.buf.Reset()
	}
}

func (l *lineParser) line(b []byte) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] != '{' {
		return
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err == nil && m != nil {
		l.on(m)
	}
}

func encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
