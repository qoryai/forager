// Package tool starts the programs a run reaches through the proxy for more than a
// token in a header: a tool.
//
// A tool is a program of the machine's that serves hosts. The runner starts it for the
// run, outside the enclosure, with one argument the run's policy chose, and tells it
// where to listen: a Unix socket in a private directory of the runner's, named in the
// tool's environment as [EnvListen]. The proxy ends the session's TLS for the hosts the
// tool serves, decides the host and the path as for any host, and hands each request it
// lets through to the tool over that socket as plain HTTP/1.1. What the tool does with a
// request, and whom it calls, is the tool's: the runner knows no protocol, holds none of
// the tool's secrets and reads no body.
//
// A [Definition] is the machine's. A run's policy selects definitions by name and
// defines none, so whoever writes a policy chooses among the programs the machine's
// owner installed and never names one.
package tool

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/qoryai/runner/policy"
	"github.com/qoryai/runner/refusal"
)

// EnvListen names, in a tool's environment, the path of the Unix socket it listens on.
const EnvListen = "QORY_TOOL_LISTEN"

// EnvRunID names, in a tool's environment, the run it was started for.
const EnvRunID = "QORY_RUN_ID"

// socketDirPrefix begins the name of the private directory a tool's socket is in, which
// is made in the system's temporary directory when the tool starts.
const socketDirPrefix = "qory-tool-"

// SocketDirs is the pattern of the private directories the tools' sockets are in, the
// system's temporary directory with socketDirPrefix and a random part: a path that
// contains it contains every one of them, and nothing else contains one before it is
// made.
func SocketDirs() string { return filepath.Join(os.TempDir(), socketDirPrefix+"*") }

// listenWait is how long a tool has to listen after it was started; a variable so a
// test need not wait a minute.
var listenWait = time.Minute

// Timing of a tool.
const (
	// stopGrace is how long a tool has between SIGTERM and SIGKILL when the run ends.
	stopGrace = 5 * time.Second
	// poll is how often the runner looks whether a starting tool listens yet.
	poll = 25 * time.Millisecond
)

// Definition is one tool as the machine defines it.
type Definition struct {
	Name string
	// Command is the program and its arguments; ${argument} in an argument is replaced
	// by the run's argument.
	Command []string
	// Argument is a regular expression the run's argument must match whole. Empty
	// means the run passes none.
	Argument string
	// Serves are the hosts whose requests the proxy hands to the tool, in the grammar
	// of the policy's allow list. A host need not exist: a tool with no host of its own
	// serves a name the machine's owner chose.
	Serves []string
	// Placeholders are variables the enclosure gets with a value that is no credential.
	Placeholders []string
}

var (
	nameShape = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	hostShape = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	envShape  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Check refuses a definition that cannot be one, before any run selects it.
func (d Definition) Check() error {
	if !nameShape.MatchString(d.Name) {
		return fmt.Errorf("the tool name %q is not 1 to 64 of a-z, 0-9, underscore, dot and dash", d.Name)
	}
	if len(d.Command) == 0 || d.Command[0] == "" {
		return fmt.Errorf("tool %s: the command is empty", d.Name)
	}
	if strings.Contains(d.Command[0], "${argument}") {
		return fmt.Errorf("tool %s: the argument goes in the command's arguments, not in the program's name", d.Name)
	}
	if d.Argument != "" {
		if _, err := regexp.Compile(d.Argument); err != nil {
			return fmt.Errorf("tool %s: argument: %w", d.Name, err)
		}
	}
	if len(d.Serves) == 0 {
		return fmt.Errorf("tool %s serves no host; a tool is reached by the hosts it serves", d.Name)
	}
	for _, h := range d.Serves {
		if !hostShape.MatchString(h) {
			return fmt.Errorf("tool %s: %q is not a lower-case host name or a *. suffix", d.Name, h)
		}
	}
	for _, p := range d.Placeholders {
		if !envShape.MatchString(p) {
			return fmt.Errorf("tool %s: the placeholder %q is not a variable's name", d.Name, p)
		}
	}
	return nil
}

// check refuses a run's argument the definition does not provide for.
func (d Definition) check(argument string) error {
	if err := d.Check(); err != nil {
		return err
	}
	switch {
	case d.Argument == "" && argument != "":
		return fmt.Errorf("tool %s takes no argument and the policy gives %q", d.Name, argument)
	case d.Argument != "":
		if re := regexp.MustCompile(`^(?:` + d.Argument + `)$`); !re.MatchString(argument) {
			return fmt.Errorf("tool %s: the argument %q is not one the machine provides for", d.Name, argument)
		}
	}
	return nil
}

// Chosen is a tool a run's policy selects, with its argument: what is started.
type Chosen struct {
	Definition
	Argument string
}

// Choose resolves the tools a policy selects among the machine's definitions and
// refuses what cannot hold: a name the machine does not define, a tool selected twice,
// an argument the definition does not provide for, and a host two tools serve.
func Choose(defs []Definition, selected []policy.Selected) ([]Chosen, error) {
	var out []Chosen
	for _, sel := range selected {
		i := slices.IndexFunc(defs, func(d Definition) bool { return d.Name == sel.Name })
		if i < 0 {
			return nil, refusal.New(refusal.ToolUnknown, []string{sel.Name}, "the policy selects the tool %q, which this machine does not define", sel.Name)
		}
		def := defs[i]
		if slices.ContainsFunc(out, func(c Chosen) bool { return c.Name == def.Name }) {
			return nil, fmt.Errorf("the policy selects the tool %q twice", def.Name)
		}
		if err := def.check(sel.Argument); err != nil {
			return nil, err
		}
		for _, host := range def.Serves {
			for _, other := range out {
				if claims(other.Serves, host) {
					return nil, fmt.Errorf("the tools %s and %s both serve %s; a host has one", other.Name, def.Name, host)
				}
			}
		}
		out = append(out, Chosen{Definition: def, Argument: sel.Argument})
	}
	return out, nil
}

// Check refuses chosen tools a run cannot have beside what else it holds: a host a
// credential is for as well, claimed(host) naming that credential, and under enforce a
// host the run's allow list does not cover, since a tool the run never reaches is a
// mistake to hear of before the run, not during it.
func Check(chosen []Chosen, mode policy.Mode, allow []string, claimed func(host string) string) error {
	for _, c := range chosen {
		for _, host := range c.Serves {
			if name := claimed(host); name != "" {
				return fmt.Errorf("the tool %s and the credential %s both claim %s; a host has one", c.Name, name, host)
			}
			if mode == policy.Enforce && !slices.ContainsFunc(allow, func(entry string) bool { return policy.Covers(entry, host) }) {
				return fmt.Errorf("the tool %s serves %s, which the run's allow list does not cover", c.Name, host)
			}
		}
	}
	return nil
}

// claims reports whether one of hosts and host stand above the other, either way.
func claims(hosts []string, host string) bool {
	return slices.ContainsFunc(hosts, func(h string) bool { return policy.Covers(h, host) || policy.Covers(host, h) })
}

// Placeholders are the variables the chosen tools want set inside, each once.
func Placeholders(chosen []Chosen) []string {
	var out []string
	for _, c := range chosen {
		for _, p := range c.Placeholders {
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

// Running is a tool the runner started, listening.
type Running struct {
	Name string
	// Serves are the hosts it serves, as the machine defined them.
	Serves []string
	// Socket is the path of the Unix socket it listens on.
	Socket string

	dir    string
	cmd    *exec.Cmd
	exited chan struct{}
	err    error
	// stderr is the read end of the tool's standard error, and drained is closed once
	// it is read to its end.
	stderr  *os.File
	drained chan struct{}
	report  func(string)
	// ready says the tool listens, from when its lines are the runner's to report.
	mu    sync.Mutex
	ready bool
	// early are the lines written before the tool listened, reported once it does, or
	// the last of them given as the reason when it does not.
	early    []string
	stopping bool
}

// earlyLines is how many lines of a starting tool are kept.
const earlyLines = 100

// Set is the tools of one run.
type Set struct {
	Tools []*Running
}

// Close stops every tool: SIGTERM to its process group, SIGKILL after a grace, and
// removes its socket's directory.
func (s *Set) Close() {
	if s == nil {
		return
	}
	var wg sync.WaitGroup
	for _, t := range s.Tools {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t.stop()
		}()
	}
	wg.Wait()
}

// Start starts every chosen tool with env, the runner's own environment, and waits
// until each listens. A tool that exits first, or does not listen within a minute, is
// no run, and the last line it wrote to standard error is the reason given. After
// that, what a tool writes to standard error goes to report line by line, and a tool
// that exits while the run goes on is reported; it is not started again.
func Start(ctx context.Context, chosen []Chosen, runID string, env []string, report func(string)) (*Set, error) {
	set := &Set{}
	for _, c := range chosen {
		t, err := start(ctx, c, runID, env, report)
		if err != nil {
			set.Close()
			return nil, fmt.Errorf("tool %s: %w", c.Name, err)
		}
		set.Tools = append(set.Tools, t)
	}
	return set, nil
}

func start(ctx context.Context, c Chosen, runID string, env []string, report func(string)) (*Running, error) {
	dir, err := os.MkdirTemp("", socketDirPrefix)
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "sock")
	args := make([]string, len(c.Command)-1)
	for i, a := range c.Command[1:] {
		args[i] = strings.ReplaceAll(a, "${argument}", c.Argument)
	}
	cmd := exec.Command(c.Command[0], args...)
	cmd.Env = append(slices.Clone(env), EnvListen+"="+sock, EnvRunID+"="+runID)
	// A group of its own, so what the tool starts in turn is stopped with it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Standard output goes to the null device: a pipe the runner copied would make
	// waiting for the tool wait for whatever it started as well.
	cmd.Stdout = nil
	// A pipe of the runner's own, not the command's: waiting for the tool does not wait
	// for whatever it started that still holds its standard error.
	stderr, w, err := os.Pipe()
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	cmd.Stderr = w
	t := &Running{Name: c.Name, Serves: c.Serves, Socket: sock, dir: dir, cmd: cmd, exited: make(chan struct{}), drained: make(chan struct{}), stderr: stderr, report: report}
	err = cmd.Start()
	w.Close()
	if err != nil {
		stderr.Close()
		os.RemoveAll(dir)
		return nil, err
	}
	go func() {
		defer close(t.drained)
		t.lines(stderr)
	}()
	go func() {
		t.err = cmd.Wait()
		close(t.exited)
		t.mu.Lock()
		gone := t.ready && !t.stopping
		t.mu.Unlock()
		if gone {
			report(fmt.Sprintf("tool %s exited while the run goes on (%v); requests to it fail from now on", t.Name, t.err))
		}
	}()
	if err := t.listens(ctx); err != nil {
		t.stop()
		return nil, err
	}
	return t, nil
}

// lines reads what the tool writes to standard error: kept while it starts, reported
// once it listens.
func (t *Running) lines(r io.Reader) {
	s := bufio.NewScanner(r)
	s.Buffer(nil, 64*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		t.mu.Lock()
		ready := t.ready
		if !ready {
			if len(t.early) == earlyLines {
				t.early = t.early[1:]
			}
			t.early = append(t.early, line)
		}
		t.mu.Unlock()
		if ready {
			t.report("tool " + t.Name + ": " + line)
		}
	}
	// A line longer than the buffer ends the scan; the rest is read and dropped, so the
	// tool never blocks on a pipe nobody reads.
	io.Copy(io.Discard, r)
}

// listens waits until the tool accepts a connection on its socket.
func (t *Running) listens(ctx context.Context) error {
	deadline := time.NewTimer(listenWait)
	defer deadline.Stop()
	tick := time.NewTicker(poll)
	defer tick.Stop()
	for {
		if c, err := net.Dial("unix", t.Socket); err == nil {
			c.Close()
			t.mu.Lock()
			t.ready = true
			early := t.early
			t.early = nil
			t.mu.Unlock()
			for _, line := range early {
				t.report("tool " + t.Name + ": " + line)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.exited:
			// The last line it wrote is the reason; it may still be in the pipe.
			select {
			case <-t.drained:
			case <-time.After(time.Second):
			}
			return fmt.Errorf("%s exited before it listened: %v%s", t.cmd.Path, t.err, t.reason())
		case <-deadline.C:
			return fmt.Errorf("%s did not listen on %s within %s%s", t.cmd.Path, EnvListen, listenWait, t.reason())
		case <-tick.C:
		}
	}
}

// reason is the last line the tool wrote while it started, as a clause.
func (t *Running) reason() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.early) == 0 {
		return ""
	}
	return ": " + t.early[len(t.early)-1]
}

// stop ends the tool and removes its socket's directory.
func (t *Running) stop() {
	t.mu.Lock()
	t.stopping = true
	t.mu.Unlock()
	defer os.RemoveAll(t.dir)
	// What the tool started may hold its standard error after it is gone; the runner
	// stops reading it.
	defer t.stderr.Close()
	select {
	case <-t.exited:
		return
	default:
	}
	pid := t.cmd.Process.Pid
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		t.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-t.exited:
	case <-time.After(stopGrace):
		syscall.Kill(-pid, syscall.SIGKILL)
		t.cmd.Process.Kill()
		// A process that left the group may still hold the pipe; the run does not wait
		// for it longer than a grace.
		select {
		case <-t.exited:
		case <-time.After(stopGrace):
		}
	}
}
