package gateway

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/routine"
)

// panicFirst is a listener whose first Accept panics, with a value that contains a fake
// key, and whose later ones accept from the listener it wraps.
type panicFirst struct {
	net.Listener
	once sync.Once
}

func (l *panicFirst) Accept() (net.Conn, error) {
	l.once.Do(func() { panic("Authorization: Bearer fake-key-0001") })
	return l.Listener.Accept()
}

// TestTheLinkListenerAcceptsAfterAPanic pins that a panic while the link's listener
// accepts a connection is reported without its value, and that the listener accepts
// the next session's connection.
func TestTheLinkListenerAcceptsAfterAPanic(t *testing.T) {
	// A short directory: a socket's path has a bound of about 100 bytes.
	dir, err := os.MkdirTemp("", "link")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	reports := make(chan string, 4)
	l := newLinkListener(&panicFirst{Listener: ln}, os.Getuid(), func(line string) { reports <- line })
	defer l.Close()
	select {
	case got := <-reports:
		if first, _, _ := strings.Cut(got, "\n"); first != routine.Panicked || strings.Contains(got, "fake-key-0001") {
			t.Errorf("the report of the accept's panic: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the accept's panic was not reported")
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if a, err := l.Accept(); err == nil {
			accepted <- a
		}
	}()
	select {
	case a := <-accepted:
		a.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("the link's listener accepted no connection after the panic")
	}
}
