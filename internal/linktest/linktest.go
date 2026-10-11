// Package linktest is a gateway's link for tests: a local link, a Unix socket in a
// private temporary directory that serves HTTP/1.1 on every connection, as the gateway
// does; and a fake separate gateway over TLS 1.3 that binds every connection to a key a
// run key names and signs its answers, [StartRemoteFake].
package linktest

import (
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
	// Socket is the link's socket.
	Socket string
	// Accepted counts the connections the link served.
	Accepted atomic.Int32
}

// Local is the link as a session receives it.
func (g *Gateway) Local() link.Local { return link.Local{Socket: g.Socket} }

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

// Start serves h on a fresh local link, until the test ends.
func Start(t testing.TB, h http.Handler) *Gateway {
	t.Helper()
	g := &Gateway{Socket: SocketPath(t)}
	ln, err := net.Listen("unix", g.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(g.Socket, link.LinkSocketMode); err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(&counting{Listener: ln, g: g})
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return g
}

// counting counts the connections it hands the server.
type counting struct {
	net.Listener
	g *Gateway
}

// Accept is the next connection, counted.
func (l *counting) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.g.Accepted.Add(1)
	}
	return c, err
}
