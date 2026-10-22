package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/session/internal/descriptor"
	"github.com/qoryai/forager/session/internal/socket"
	"github.com/qoryai/forager/session/runtimes"
)

// The events of a setup record: the command started, wrote a line, or exited. A
// setup record is the record member of a record of the setup source: command, the
// command's number in SessionSpec.Setup from 1, and event; a line has stream, stdout
// or stderr, and bytes, the line's bytes in standard base64; an exit has exit_code,
// from 0 to 255.
const (
	setupStarted = "started"
	setupLine    = "line"
	setupExited  = "exited"
)

// setupRecord is a setup record as the session reads it.
type setupRecord struct {
	command int
	event   string
	stream  string
	bytes   []byte
	code    int
}

// readSetupRecord reads m, the record member of a record of the setup source. A
// record of another shape is an error.
func readSetupRecord(m map[string]any) (setupRecord, error) {
	var rec setupRecord
	integer := func(v any, lowest, highest float64) (int, bool) {
		f, ok := v.(float64)
		if !ok || f != math.Trunc(f) || f < lowest || f > highest {
			return 0, false
		}
		return int(f), true
	}
	command, ok := integer(m["command"], 1, math.MaxInt32)
	if !ok {
		return rec, errors.New("not a setup record: its command is not a number from 1")
	}
	rec.command = command
	rec.event, _ = m["event"].(string)
	switch rec.event {
	case setupStarted:
	case setupLine:
		rec.stream, _ = m["stream"].(string)
		text, _ := m["bytes"].(string)
		b, err := base64.StdEncoding.DecodeString(text)
		if (rec.stream != "stdout" && rec.stream != "stderr") || err != nil {
			return rec, errors.New("not a setup record: a line has stream stdout or stderr and its bytes in base64")
		}
		rec.bytes = b
	case setupExited:
		if rec.code, ok = integer(m["exit_code"], 0, 255); !ok {
			return rec, errors.New("not a setup record: an exit has an exit_code from 0 to 255")
		}
	default:
		return rec, fmt.Errorf("not a setup record: its event is not started, line or exited but %s", accesskey.ShownValue(fmt.Sprint(m["event"]), true))
	}
	return rec, nil
}

// setupSteps writes a session's setup steps from the records of the setup source,
// under its lock: a step for each command of SessionSpec.Setup, in order, with the
// command's name, its lines and its exit status. The setup's steps follow the wall
// step one after another, and no other step starts while the session runs, so command
// k is step base+k. A step ends succeeded on exit status 0, cancelled on another once
// the session stops the launch, and failed otherwise. A record out of order, or one
// after the setup ended, is reported and not recorded.
type setupSteps struct {
	r        *Run
	session  int
	commands []SetupCommand
	// terminal writes a setup line, masked, to the user's terminal.
	terminal func(stream string, b []byte)
	// base is the number of the last step before the setup's, the wall step's.
	base int

	mu sync.Mutex
	// ready is true once the wall step ended and the launch started; stopping then
	// reports whether the session stops the launch.
	ready    bool
	stopping func() bool
	// next is the number of the next command that may start, from 1; open is the step
	// of the command that runs, nil for none.
	next int
	open *Step
	// ended is true once the last command exited, a command exited otherwise than 0,
	// or the session ended.
	ended bool
}

// newSetupSteps returns the setup steps of session n, whose setup is commands, once the
// session's last step before them has started; terminal gets each line of the steps.
func (r *Run) newSetupSteps(n int, commands []SetupCommand, terminal func(stream string, b []byte)) *setupSteps {
	return &setupSteps{r: r, session: n, commands: commands, terminal: terminal, base: r.steps, next: 1, ended: len(commands) == 0}
}

// setupTerminal writes a setup line to the user's terminal as the runtime's output
// reaches it: on pipes to stdout or stderr as its stream is; on a pseudo-terminal to
// stdout, each line break as the pseudo-terminal writes it, \r\n, since the
// terminal is in raw mode while the launch runs.
func setupTerminal(interactive bool, stdout, stderr io.Writer) func(stream string, b []byte) {
	return func(stream string, b []byte) {
		switch {
		case interactive:
			stdout.Write(bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")))
		case stream == "stderr":
			stderr.Write(b)
		default:
			stdout.Write(b)
		}
	}
}

// terminalWriter is w, a stream to the user's terminal, with each write under mu.
type terminalWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

// Write writes p to w under the lock.
func (l *terminalWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// start is called once the session's last step before the setup ended, as its launch
// starts: the setup's records are recorded from then on. stopping reports whether the session
// stops the launch, at its time limit, its context's end or the run's close.
func (s *setupSteps) start(stopping func() bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready, s.stopping = true, stopping
}

// handle writes the step event of rec, a record of the setup source, when rec comes in
// order; it reports a record that is not a setup record, comes out of order, or comes
// after the setup ended.
func (s *setupSteps) handle(rec runtimes.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		s.r.open.Report("a setup record arrived after the setup ended and is not recorded")
		return
	}
	got, err := readSetupRecord(rec.Record)
	if err != nil {
		s.r.open.Report("socket: " + err.Error())
		return
	}
	running := s.open != nil && got.command == s.next
	switch {
	case !s.ready || got.command > len(s.commands):
	case got.event == setupStarted && s.open == nil && got.command == s.next:
		s.open = s.r.startStep(event.StepSetup, s.commands[got.command-1].Name)
		return
	case got.event == setupLine && running:
		// The record has the line once, through the sink, and the terminal has it once,
		// masked the same way.
		masked := []byte(s.r.masker.Replace(string(got.bytes)))
		s.r.writeLog(got.stream, s.session, s.open.n, masked)
		s.terminal(got.stream, masked)
		return
	case got.event == setupExited && running:
		state := event.StateSucceeded
		switch {
		case got.code != 0 && s.stopping():
			state = event.StateCancelled
		case got.code != 0:
			state = event.StateFailed
		}
		s.open.end(state, got.code)
		s.open = nil
		s.next++
		s.ended = got.code != 0 || s.next > len(s.commands)
		return
	}
	s.r.open.Report(fmt.Sprintf("a setup record for step %d arrived out of order and is not recorded", s.base+got.command))
}

// finish ends the setup when the session ends: a step still open ends with -1,
// cancelled when the session was stopped, and failed otherwise. A record after it is
// reported and not recorded.
func (s *setupSteps) finish(stopped bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open != nil {
		state := event.StateFailed
		if stopped {
			state = event.StateCancelled
		}
		s.open.end(state, -1)
		s.open = nil
	}
	s.ended = true
}

// setupRunnerFailed is the exit status of [RunSetupCommand] when it cannot run the
// command or report it: 125, as env and timeout exit when they fail themselves.
const setupRunnerFailed = 125

// setupLineSize is the most bytes one line record contains: a longer line is sent in
// parts of this size, the size of a chunk of output.
const setupLineSize = 4096

// RunSetupCommand runs one setup command of SessionSpec.Setup inside the wall and
// reports it on the socket of QORY_RUN_SOCKET, as records of the setup source: that it
// started, each line of its output, and its exit status. The session writes the
// command's setup step from them, and each line to the user's terminal. The caller's binary runs it inside the enclosure in
// a hidden mode, SessionSpec.SetupRunner, as it runs [Exec]; the script of
// [PreparationScript] starts it once for each command.
//
// Its arguments are the command's number in SessionSpec.Setup, from 1, then --, then
// the program, found in PATH, and its arguments. The command runs with no input, in
// the runner's working directory and environment. TERM is passed on to it. INT, HUP,
// QUIT, USR1 and USR2 reach the runner without ending it and are not passed on: at any
// of them the script asks the runner to leave with TERM, and on a pseudo-terminal a
// terminal's INT reaches the command directly. Its output goes to the socket alone.
// It returns the exit status, as a shell reports it: the command's, 128 and the
// signal's number for a command a signal ended, 127 for a program it does not find and
// 126 for one it cannot execute.
// It returns 125, its reason written to stderr, for arguments it cannot read and for a
// socket it cannot reach; the command does not start when the first record cannot be
// sent, and runs to its end when a later one cannot.
func RunSetupCommand(args []string, stderr io.Writer) int {
	usage := func() int {
		fmt.Fprintln(stderr, "Start the setup command as preparation.sh does: its number from 1, then --, then the program and its arguments.")
		return setupRunnerFailed
	}
	if len(args) < 3 || args[1] != "--" || args[2] == "" {
		return usage()
	}
	n, err := strconv.Atoi(args[0])
	if err != nil || n < 1 {
		return usage()
	}
	addr := os.Getenv(EnvSocket)
	unreachable := func() int {
		shown := addr
		if shown == "" {
			shown = `""`
		}
		fmt.Fprintf(stderr, "Run setup outside the wall's container on this machine: the run socket %s does not reach the container, so setup inside cannot write its steps.\n", shown)
		return setupRunnerFailed
	}
	record := func(m map[string]any) descriptor.Record {
		m["command"] = n
		return descriptor.Record{Source: descriptor.SourceSetup, Record: m}
	}
	ctx := context.Background()
	if addr == "" || socket.Send(ctx, addr, []descriptor.Record{record(map[string]any{"event": setupStarted})}) != nil {
		return unreachable()
	}
	sender := startSetupSender(ctx, addr)
	line := func(stream string, b []byte) {
		sender.send(record(map[string]any{"event": setupLine, "stream": stream, "bytes": encode(b)}))
	}
	code := runSetup(args[2:], line)
	sender.send(record(map[string]any{"event": setupExited, "exit_code": code}))
	if sender.close() != nil {
		return unreachable()
	}
	return code
}

// setupOutputGrace is how long the runner reads a command's output after the command
// exits: a process the command leaves running with its output open, such as a service
// it starts, has its output cut off then.
const setupOutputGrace = time.Second

// runSetup runs the program and arguments of words with no input, passes TERM on to it,
// hands line every line of its output, and returns its exit status as
// a shell reports it.
func runSetup(words []string, line func(stream string, b []byte)) int {
	var mu sync.Mutex
	stdout := &setupLines{mu: &mu, stream: "stdout", line: line}
	stderr := &setupLines{mu: &mu, stream: "stderr", line: line}
	cmd := exec.Command(words[0], words[1:]...)
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = stdout, stderr, setupOutputGrace
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
	defer signal.Stop(signals)
	if err := cmd.Start(); err != nil {
		line("stderr", failureLine(err))
		switch {
		case errors.Is(err, exec.ErrNotFound), errors.Is(err, exec.ErrDot), errors.Is(err, fs.ErrNotExist):
			return 127
		default:
			return 126
		}
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-signals:
				if sig == syscall.SIGTERM {
					cmd.Process.Signal(sig)
				}
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	stdout.flush()
	stderr.flush()
	var exit *exec.ExitError
	switch {
	case err == nil, errors.Is(err, exec.ErrWaitDelay):
		return 0
	case errors.As(err, &exit):
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return exit.ExitCode()
	default:
		line("stderr", failureLine(err))
		return setupRunnerFailed
	}
}

// setupLines hands line each line written to it, its line break included, a line
// longer than setupLineSize in parts of that size; flush hands it what is left. mu is
// shared by a command's two streams, so their lines reach line one at a time.
type setupLines struct {
	mu     *sync.Mutex
	stream string
	line   func(stream string, b []byte)
	buf    []byte
}

// Write keeps p and hands line every whole line, or part of setupLineSize bytes, the
// buffer then contains.
func (w *setupLines) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		cut := bytes.IndexByte(w.buf, '\n') + 1
		if cut == 0 || cut > setupLineSize {
			if len(w.buf) < setupLineSize {
				return len(p), nil
			}
			cut = setupLineSize
		}
		w.line(w.stream, slices.Clone(w.buf[:cut]))
		w.buf = w.buf[cut:]
	}
}

// flush hands line the last line, which has no line break, when there is one.
func (w *setupLines) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 {
		w.line(w.stream, w.buf)
		w.buf = nil
	}
}

// setupSender sends a setup command's records after its first, in order: what it was
// handed while it sent the ones before goes over the next connection, one connection
// at a time, since the session cuts off a connection that stays open longer than
// socket.Patience.
type setupSender struct {
	records chan descriptor.Record
	done    chan struct{}
	// err is the first failure to send, after which nothing more is sent.
	err error
}

// startSetupSender starts sending records to the socket at addr.
func startSetupSender(ctx context.Context, addr string) *setupSender {
	s := &setupSender{records: make(chan descriptor.Record, 1024), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		for rec := range s.records {
			batch := []descriptor.Record{rec}
		more:
			for len(batch) < cap(s.records) {
				select {
				case next, ok := <-s.records:
					if !ok {
						break more
					}
					batch = append(batch, next)
				default:
					break more
				}
			}
			if s.err == nil {
				s.err = socket.Send(ctx, addr, batch)
			}
		}
	}()
	return s
}

// send hands the sender one record.
func (s *setupSender) send(rec descriptor.Record) { s.records <- rec }

// close waits until every record handed to the sender is sent and returns the first
// failure.
func (s *setupSender) close() error {
	close(s.records)
	<-s.done
	return s.err
}
