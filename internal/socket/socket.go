// Package socket is the local socket a harness reports through.
//
// The runner opens a Unix domain socket before the runtime starts and names it in the
// session's environment as QORY_RUN_SOCKET. A client connects, writes records, one per
// line in the shape of contracts/runner/v1/record.schema.json, and closes; there is no
// answer. [Listen] opens the socket in a private directory of its own, because a socket
// path has a short limit on some systems and a run directory inside a deep checkout can
// exceed it. [Forward] is the client the runner installs as a hook: it wraps what it
// reads as one record of the hooks source and writes it.
//
// Nothing on the socket reaches a receiver except through a descriptor's rules; the
// listener hands records to a function and does nothing else with them.
package socket

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/qoryai/runner/internal/descriptor"
)

// Env is the variable that names the socket in the session's environment.
const Env = "QORY_RUN_SOCKET"

// Listener is an open socket.
type Listener struct {
	dir  string
	path string
	ln   *net.UnixListener
	done chan struct{}
}

// dirPrefix begins the name of the private directory a run's socket is in.
const dirPrefix = "qory-run-"

// Dirs is the pattern of the private directories the runs' sockets are in, the
// system's temporary directory with dirPrefix and a random part.
func Dirs() string { return filepath.Join(os.TempDir(), dirPrefix+"*") }

// Listen creates a private directory under the system's temporary directory, mode
// 0700, and listens on a socket in it. Close removes both.
func Listen() (*Listener, error) {
	dir, err := os.MkdirTemp("", dirPrefix)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	return &Listener{dir: dir, path: path, ln: ln, done: make(chan struct{})}, nil
}

// Path is the socket's path, the value of [Env].
func (l *Listener) Path() string { return l.path }

// Serve accepts connections until the listener is closed and hands every record read
// to handle. Connections are read one at a time in the order accepted, so two hook
// calls made one after the other reach handle in that order; a client that connects and
// then stalls is cut off after [Patience] so it cannot hold the ones behind it. A line
// that is not a record is passed to bad with the error and skipped; bad may be nil.
// Serve returns when the listener is closed.
func (l *Listener) Serve(handle func(descriptor.Record), bad func(error)) {
	defer close(l.done)
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return
		}
		conn.SetReadDeadline(time.Now().Add(Patience))
		read(conn, handle, bad)
		conn.Close()
	}
}

// Patience is how long one connection may take to write its records and close.
const Patience = 5 * time.Second

// read decodes one connection's lines until end of file.
func read(r io.Reader, handle func(descriptor.Record), bad func(error)) {
	s := bufio.NewScanner(r)
	s.Buffer(nil, 16<<20)
	for s.Scan() {
		line := s.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec descriptor.Record
		if err := json.Unmarshal(line, &rec); err != nil || (rec.Source != descriptor.SourceHooks && rec.Source != descriptor.SourceOutput) || rec.Record == nil {
			if bad != nil {
				if err == nil {
					err = fmt.Errorf("not a record: %.80s", line)
				}
				bad(err)
			}
			continue
		}
		handle(rec)
	}
	if err := s.Err(); err != nil && bad != nil {
		bad(err)
	}
}

// Grace is how long Close keeps accepting, so a client that connected just before the
// runtime exited, a hook on the runtime's last event say, is still read.
const Grace = 200 * time.Millisecond

// Close drains the socket, then removes it and its directory: it keeps accepting for
// Grace, waits for Serve to return, and closes. Records read during the drain still
// reach handle, which is why a caller closes the socket before it writes the run's
// last event.
func (l *Listener) Close() error {
	l.ln.SetDeadline(time.Now().Add(Grace))
	select {
	case <-l.done:
	case <-time.After(Grace + Patience):
	}
	err := l.ln.Close()
	if rmErr := os.RemoveAll(l.dir); err == nil {
		err = rmErr
	}
	return err
}

// network reads the value of [Env]. It is an address, not a path: a path, or unix: and a
// path, is the local socket; another scheme is a transport, and a forwarder that does
// not have it says so instead of opening a file of that name.
func network(addr string) (string, string, error) {
	if path, ok := strings.CutPrefix(addr, "unix:"); ok {
		return "unix", path, nil
	}
	if scheme, _, ok := strings.Cut(addr, ":"); ok && !strings.ContainsAny(scheme, "/.") {
		return "", "", fmt.Errorf("%s names the transport %q, which this forwarder does not have", Env, scheme)
	}
	return "unix", addr, nil
}

// Forward reads one JSON object from r, wraps it as a record of the hooks source and
// writes it to the socket at addr, the value of [Env], as one line. It is what a hook command does: the
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
		return fmt.Errorf("hook input is not a JSON object: %w", err)
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
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	_, err = conn.Write(append(line, '\n'))
	return err
}
