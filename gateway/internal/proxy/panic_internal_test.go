package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/routine"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// panicking is an upstream connection whose Write panics with a value that contains a
// fake key, and whose Read waits for Close.
type panicking struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *panicking) Write([]byte) (int, error) { panic("Authorization: Bearer fake-key-0001") }

func (c *panicking) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *panicking) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// TestAPanicInOneRunLeavesTheOthersServed pins that a panic in a goroutine of one run's
// tunnel closes that tunnel and is reported under the run's id with the stack and
// without the panic's value, and that the shared listener serves another run after it.
func TestAPanicInOneRunLeavesTheOthersServed(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "origin") }))
	defer origin.Close()
	l, err := NewListener("", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	reports := make(chan string, 4)
	runs := map[string]*Proxy{}
	secrets := map[string]string{}
	for _, name := range []string{"run-a", "run-b"} {
		p, err := New(policy.Observe, nil, nil, func(Decision) {})
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		p.ReportPanics(routine.ForRun(func(line string) { reports <- line }, name))
		secret, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Register(secret, p); err != nil {
			t.Fatal(err)
		}
		runs[name], secrets[name] = p, secret
	}
	runs["run-a"].dial = func(context.Context, string, string) (net.Conn, error) {
		return &panicking{closed: make(chan struct{})}, nil
	}

	// Run A's tunnel: the first byte sent through it panics the copy to the host.
	c, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "%s %s\nCONNECT a.example:443 HTTP/1.1\r\nHost: a.example:443\r\n\r\n", link.RelayPreamble, secrets["run-a"])
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT through run A: %v %v", resp, err)
	}
	io.WriteString(c, "hello")
	if _, err := io.ReadAll(br); err != nil {
		t.Errorf("run A's tunnel did not close after the panic: %v", err)
	}
	select {
	case got := <-reports:
		first, _, _ := strings.Cut(got, "\n")
		if want := "run run-a: " + routine.Panicked; first != want {
			t.Errorf("the report's first line is %q, want %q", first, want)
		}
		if strings.Contains(got, "fake-key-0001") {
			t.Errorf("the report contains the panic's value: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the panic was not reported")
	}

	// Run B is served after it.
	b, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(b, "%s %s\nGET %s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", link.RelayPreamble, secrets["run-b"], origin.URL, origin.Listener.Addr())
	resp, err = http.ReadResponse(bufio.NewReader(b), nil)
	if err != nil {
		t.Fatalf("run B after run A's panic: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "origin" {
		t.Errorf("run B after run A's panic: %d %q", resp.StatusCode, body)
	}
}
