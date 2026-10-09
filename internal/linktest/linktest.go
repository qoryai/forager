// Package linktest is a gateway's local link for tests: a Unix socket in a private
// temporary directory that reads the link's preamble on every connection, closes one
// that opens otherwise unanswered, and serves HTTP/1.1 on the rest, as the gateway
// does.
package linktest

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/link"
)

// Gateway is a fake gateway's local link.
type Gateway struct {
	// Socket is the link's socket and Secret the link secret it reads.
	Socket, Secret string
	// Accepted counts the connections that opened with the preamble, Rejected those
	// closed unanswered.
	Accepted, Rejected atomic.Int32
}

// Local is the link as a session receives it.
func (g *Gateway) Local() link.Local { return link.Local{Socket: g.Socket, Secret: g.Secret} }

// SocketPath returns the path of a socket in a fresh private directory short enough
// for a Unix socket's address on every system, removed when the test ends.
func SocketPath(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", link.LinkDirPrefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, link.LinkDirMode); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, link.LinkSocketName)
}

// Start serves h on a fresh local link with the secret, until the test ends.
func Start(t testing.TB, secret string, h http.Handler) *Gateway {
	t.Helper()
	g := &Gateway{Socket: SocketPath(t), Secret: secret}
	ln, err := net.Listen("unix", g.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(g.Socket, link.LinkSocketMode); err != nil {
		t.Fatal(err)
	}
	pl := &listener{Listener: ln, g: g, conns: make(chan net.Conn), done: make(chan struct{})}
	go pl.accept()
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(pl)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return g
}

// listener hands the server the connections that opened with the preamble.
type listener struct {
	net.Listener
	g     *Gateway
	conns chan net.Conn
	done  chan struct{}
}

func (l *listener) accept() {
	defer close(l.done)
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return
		}
		go l.check(c)
	}
}

// check reads the preamble within [link.PreambleWait] and hands the connection on, or
// closes it unanswered.
func (l *listener) check(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(link.PreambleWait))
	r := bufio.NewReader(c)
	ok, err := link.ReadLinkPreamble(r, l.g.Secret)
	if !ok || err != nil {
		l.g.Rejected.Add(1)
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	l.g.Accepted.Add(1)
	select {
	case l.conns <- &conn{Conn: c, r: r}:
	case <-l.done:
		c.Close()
	}
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// conn reads through the reader the preamble was read with, which may hold the first
// bytes of HTTP.
type conn struct {
	net.Conn
	r *bufio.Reader
}

func (c *conn) Read(b []byte) (int, error) { return c.r.Read(b) }
