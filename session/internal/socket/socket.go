// Package socket is the local socket a harness reports through.
//
// The session opens a Unix domain socket before the runtime starts and sets it in the
// session's environment as QORY_RUN_SOCKET. A client connects, writes records, one per
// line in the shape of contracts/forager/v1/record.schema.json, and closes; there is no
// answer. [Listen] opens the socket in a private directory of its own, because a socket
// path has a short limit on some systems and a run directory inside a deep checkout can
// exceed it. [Forward] is the client the session installs as a hook: it wraps what it
// reads as one record of the hooks source and writes it. [Send] writes records the
// caller made, such as a setup command's records of the setup source.
//
// The listener of a launch reads records of the hooks, the setup and the measure source,
// and hands them to a function that does nothing else with them: a record of the hooks
// source reaches a receiver only through a descriptor's rules, the session writes the
// setup steps from the records of the setup source, and puts the values of a record of
// the measure source on the session's dev.qory.session.exited. The listener of a
// session's After ([ListenAfter]) reads records of the after source only, from the
// first connection alone ([Listener.ServeFirst]): the session writes the after step from
// them.
//
// The listener refuses a record of the output source. Output records come only from
// the runtime's standard output, which the session reads on the host. Any process in
// the agent's container can write to the socket, so an output record from the socket
// would add runtime output, such as text or a tool result, that the runtime never
// printed.
package socket

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/session/internal/descriptor"
)

// Listener is an open socket.
type Listener struct {
	dir  string
	path string
	ln   *net.UnixListener
	done chan struct{}
	// served is true once Serve has started, so Close waits for its end.
	served atomic.Bool
	// grace is how long Close keeps accepting.
	grace time.Duration
	// sources are the sources of a record this listener reads.
	sources []string
	// mu guards first, the connection ServeFirst reads, which Close ends.
	mu    sync.Mutex
	first net.Conn
}

// dirPrefix begins the name of the private directory a run's socket is in.
const dirPrefix = "qory-run-"

// Dirs is the pattern of the private directories the runs' sockets are in, the
// system's temporary directory with dirPrefix and a random part.
func Dirs() string { return filepath.Join(os.TempDir(), dirPrefix+"*") }

// Listen creates a private directory under the system's temporary directory, mode
// 0700, and listens on a socket in it. Close removes both. grace is how long Close
// keeps accepting; zero or less means [Grace].
func Listen(grace time.Duration) (*Listener, error) {
	return listen(grace, launchSources)
}

// ListenAfter is [Listen] for a session's After: the listener reads records of the
// after source only, and a record of any other source is skipped as one that is not a
// record.
func ListenAfter(grace time.Duration) (*Listener, error) {
	return listen(grace, []string{descriptor.SourceAfter})
}

func listen(grace time.Duration, sources []string) (*Listener, error) {
	if grace <= 0 {
		grace = Grace
	}
	dir, err := os.MkdirTemp("", dirPrefix)
	if err != nil {
		return nil, accesskey.ShownError(err)
	}
	path := filepath.Join(dir, "sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		os.RemoveAll(dir)
		return nil, accesskey.ShownError(err)
	}
	return &Listener{dir: dir, path: path, ln: ln, done: make(chan struct{}), grace: grace, sources: sources}, nil
}

// Path is the socket's path, the value of [link.EnvRunSocket].
func (l *Listener) Path() string { return l.path }

// Serve accepts connections until the listener is closed and hands every record read
// to handle. Connections are read one at a time in the order accepted, so two hook
// calls made one after the other reach handle in that order; a client that connects and
// then stalls is cut off after [Patience] so it cannot hold the ones behind it. A line
// that is not a record, or a record of the output source, is passed to bad with the
// error and skipped; bad may be nil. When handle returns an error, the record is not
// recorded, and the error goes to bad as a bad line does. One connection passes at most
// [MaxBadLines] errors to bad, then skips the rest without a call and passes one error
// at its end with the count skipped. Serve returns when the listener is closed.
func (l *Listener) Serve(handle func(descriptor.Record) error, bad func(error)) {
	l.served.Store(true)
	defer close(l.done)
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return
		}
		conn.SetReadDeadline(time.Now().Add(Patience))
		read(conn, l.sources, handle, bad)
		conn.Close()
	}
}

// ServeFirst reads the first connection accepted and no other: it hands every record of
// that connection to handle until the client closes it, or until wait has passed since
// the accept, and returns. A later connection is closed unread. The client holds its
// connection from before it starts any program that another process of its container
// could use to connect first. handle and bad are as in Serve: an error from handle on the
// first connection counts against [MaxBadLines] as it does for any one connection.
func (l *Listener) ServeFirst(handle func(descriptor.Record) error, bad func(error), wait time.Duration) {
	l.served.Store(true)
	defer close(l.done)
	conn, err := l.ln.Accept()
	if err != nil {
		return
	}
	l.mu.Lock()
	l.first = conn
	l.mu.Unlock()
	go func() {
		for {
			c, err := l.ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	conn.SetReadDeadline(time.Now().Add(wait))
	read(conn, l.sources, handle, bad)
	conn.Close()
}

// Patience is how long one connection may take to write its records and close.
const Patience = 5 * time.Second

// launchSources are the sources of a record a launch's listener reads. The output source is not
// among them: output records come only from the runtime's standard output.
var launchSources = []string{descriptor.SourceHooks, descriptor.SourceSetup, descriptor.SourceMeasure, descriptor.SourceLaunch}

// errOutput is the error of a record of the output source read on the socket.
var errOutput = errors.New("refused a record of the output source: output records come only from the runtime's standard output")

// MaxBadLines is how many lines of one connection that are not records, are records of
// the output source, or are records that handle returns an error for, [Listener.Serve]
// passes to bad. Each one becomes a report to the control plane, and any process in the
// agent's container can write millions of them within [Patience]. 10 shows a client's
// first mistakes, which say what is wrong, and the lines after them are only counted.
const MaxBadLines = 10

// read decodes one connection's lines until end of file. A record of the output source
// is passed to bad as errOutput, and every other line that is not a record of
// [sources] as "not a record". An error from handle counts as a bad line and is passed
// to bad as it is. After [MaxBadLines] such lines it skips the rest without calling
// bad and, at the end of the connection, passes one error with the count skipped. A
// scanner error at the end is passed to bad too, apart from that count.
func read(r io.Reader, sources []string, handle func(descriptor.Record) error, bad func(error)) {
	s := bufio.NewScanner(r)
	s.Buffer(nil, 16<<20)
	var badLines, skipped int
	// report passes err to bad, or counts it as skipped after MaxBadLines.
	report := func(err error) {
		if bad == nil {
			return
		}
		if badLines >= MaxBadLines {
			skipped++
			return
		}
		badLines++
		bad(err)
	}
	for s.Scan() {
		line := s.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec descriptor.Record
		err := json.Unmarshal(line, &rec)
		if err == nil && rec.Source == descriptor.SourceOutput {
			report(errOutput)
			continue
		}
		if err != nil || !slices.Contains(sources, rec.Source) || rec.Record == nil {
			if err == nil {
				err = fmt.Errorf("not a record: %.80s", accesskey.ShownValue(string(line), false))
			}
			report(accesskey.ShownError(err))
			continue
		}
		if err := handle(rec); err != nil {
			report(err)
		}
	}
	if skipped > 0 {
		noun, verb := "lines", "were"
		if skipped == 1 {
			noun, verb = "line", "was"
		}
		bad(fmt.Errorf("skipped %d more %s on one connection that %s not recorded", skipped, noun, verb))
	}
	if err := s.Err(); err != nil && bad != nil {
		bad(err)
	}
}

// Grace is how long Close keeps accepting by default, so a client that connected just
// before the runtime exited, a hook on the runtime's last event say, is still read.
const Grace = 200 * time.Millisecond

// Close drains the socket, then removes it and its directory: it keeps accepting for
// the grace Listen was given, waits for Serve to return, and closes. Records read
// during the drain still reach handle, which is why a caller closes the socket before
// it writes the run's last event. Close returns after Serve's last call of handle: a
// connection still read after the drain's wait ends at its read deadline, [Patience]
// after it was accepted.
func (l *Listener) Close() error {
	l.ln.SetDeadline(time.Now().Add(l.grace))
	wait := l.grace + Patience
	l.mu.Lock()
	if l.first != nil {
		// The first connection of ServeFirst is read until its client closes it or the
		// wait it was given ends: Close gives what the socket still holds the grace, no more.
		wait = l.grace
	}
	l.mu.Unlock()
	if wait < l.grace {
		// A grace near the largest duration waits as long as a duration can.
		wait = math.MaxInt64
	}
	select {
	case <-l.done:
	case <-time.After(wait):
	}
	err := l.ln.Close()
	l.mu.Lock()
	if l.first != nil {
		l.first.Close()
	}
	l.mu.Unlock()
	if l.served.Load() {
		<-l.done
	}
	if rmErr := os.RemoveAll(l.dir); err == nil {
		err = rmErr
	}
	return err
}

// network reads the value of [link.EnvRunSocket]. It is an address, not a path: a path, or unix: and a
// path, is the local socket; another scheme is a transport, and a forwarder that does
// not have it says so instead of opening a file of that name.
func network(addr string) (string, string, error) {
	if path, ok := strings.CutPrefix(addr, "unix:"); ok {
		return "unix", path, nil
	}
	if scheme, _, ok := strings.Cut(addr, ":"); ok && !strings.ContainsAny(scheme, "/.") {
		return "", "", fmt.Errorf("%s names the transport %s, which this forwarder does not have", link.EnvRunSocket, accesskey.ShownValue(scheme, true))
	}
	return "unix", addr, nil
}

// Forward reads one JSON object from r, wraps it as a record of the hooks source and
// writes it to the socket at addr, the value of [link.EnvRunSocket], as one line. It is what a hook command does: the
// runtime writes the hook's input on the command's standard input, the command forwards
// it and exits 0 with no output, which the runtime reads as no decision. An input that
// is not a JSON object is an error and nothing is sent.
func Forward(ctx context.Context, addr string, r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err != nil {
		return fmt.Errorf("hook input is not a JSON object: %w", accesskey.ShownError(err))
	}
	if obj == nil {
		return errors.New("hook input is not a JSON object")
	}
	line, err := json.Marshal(descriptor.Record{Source: descriptor.SourceHooks, Record: obj})
	if err != nil {
		return err
	}
	netw, path, err := network(addr)
	if err != nil {
		return err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, netw, path)
	if err != nil {
		// The dial's and the write's errors quote the socket's path.
		return accesskey.ShownError(err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	_, err = conn.Write(append(line, '\n'))
	return accesskey.ShownError(err)
}

// Send writes recs to the socket at addr, the value of [link.EnvRunSocket], one line
// each, over one connection, which it closes. The dial and the write end with ctx, and
// within [Patience] at most, since the session reads one connection at a time and cuts
// off one that takes longer.
func Send(ctx context.Context, addr string, recs []descriptor.Record) error {
	var b []byte
	for _, rec := range recs {
		line, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		b = append(append(b, line...), '\n')
	}
	netw, path, err := network(addr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, Patience)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, netw, path)
	if err != nil {
		return accesskey.ShownError(err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	_, err = conn.Write(b)
	return accesskey.ShownError(err)
}

// Conn is a connection to the socket at an address that stays open for many sends: a
// client that [Listener.ServeFirst] reads.
type Conn struct {
	conn net.Conn
}

// Dial connects to the socket at addr, the value of [link.EnvRunSocket], within
// [Patience] or ctx. The descriptor is close-on-exec, so no program the process starts
// has it.
func Dial(ctx context.Context, addr string) (*Conn, error) {
	netw, path, err := network(addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, Patience)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, netw, path)
	if err != nil {
		return nil, accesskey.ShownError(err)
	}
	return &Conn{conn: conn}, nil
}

// Send writes recs, one line each, to the connection within [Patience].
func (c *Conn) Send(recs []descriptor.Record) error {
	var b []byte
	for _, rec := range recs {
		line, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		b = append(append(b, line...), '\n')
	}
	c.conn.SetWriteDeadline(time.Now().Add(Patience))
	_, err := c.conn.Write(b)
	return accesskey.ShownError(err)
}

// Close closes the connection.
func (c *Conn) Close() error { return c.conn.Close() }
