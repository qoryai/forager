package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

// lockedBuffer is a buffer the standard logger writes to from many goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// TestAHandlersPanicIsReportedWithoutItsValue pins that a panic in the proxy's handler,
// for a plain request, and in the handler of a terminated connection, closes the
// connection and is reported with the stack, while neither the report nor net/http's
// log contains the panic's value; and that the proxy serves the next request.
func TestAHandlersPanicIsReportedWithoutItsValue(t *testing.T) {
	logged := &lockedBuffer{}
	log.SetOutput(logged)
	defer log.SetOutput(os.Stderr)
	var armed atomic.Bool
	armed.Store(true)
	p, err := Listen("", policy.Observe, nil, nil, func(Decision) {
		if armed.Load() {
			panic("Authorization: Bearer fake-key-0001")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	reports := make(chan string, 4)
	p.ReportPanics(routine.ForRun(func(line string) { reports <- line }, "run-a"))
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("no host in this test")}
	}
	paths := map[string][]string{"key.example": {"/*"}}
	ca, err := NewCA("test", p.Terminating(nil, paths, nil))
	if err != nil {
		t.Fatal(err)
	}
	p.Terminate(ca, nil, paths, nil)

	// A plain request: the proxy's handler panics as it records the failed dial.
	c, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(c, "GET http://plain.example/ HTTP/1.1\r\nHost: plain.example\r\n\r\n")
	if b, err := io.ReadAll(c); err != nil || len(b) != 0 {
		t.Errorf("after the plain handler's panic the connection answered %q (%v), want it closed", b, err)
	}
	// A terminated connection: its handler panics as it records the failed dial.
	tc, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(tc, "CONNECT key.example:443 HTTP/1.1\r\nHost: key.example:443\r\n\r\n")
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT key.example: %v %v", resp, err)
	}
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	inner := tls.Client(&bufferedConn{Conn: tc, r: br}, &tls.Config{RootCAs: trusted, ServerName: "key.example"})
	io.WriteString(inner, "GET /x HTTP/1.1\r\nHost: key.example\r\n\r\n")
	if b, err := io.ReadAll(inner); len(b) != 0 {
		t.Errorf("after the terminated handler's panic the connection answered %q (%v), want it closed", b, err)
	}

	for range 2 {
		select {
		case got := <-reports:
			first, stack, _ := strings.Cut(got, "\n")
			if want := "run run-a: " + routine.Panicked; first != want {
				t.Errorf("the report's first line is %q, want %q", first, want)
			}
			if !strings.Contains(stack, "proxy.(*Proxy).ServeHTTP") && !strings.Contains(stack, "proxy.(*terminator)") {
				t.Errorf("the report has no stack of the proxy's handler: %q", stack)
			}
			if strings.Contains(got, "fake-key-0001") {
				t.Errorf("the report contains the panic's value: %q", got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a handler's panic was not reported")
		}
	}
	if strings.Contains(logged.String(), "fake-key-0001") || strings.Contains(logged.String(), "panic") {
		t.Errorf("net/http logged the panic: %q", logged.String())
	}

	// The proxy serves the next request.
	armed.Store(false)
	if status := ask(t, p, "GET http://plain.example/"); status != http.StatusBadGateway {
		t.Errorf("the next request after the panics: %d, want 502", status)
	}
}

// bufferedConn is a connection whose first bytes were read into r.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

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

// TestTheSharedListenerAcceptsAfterAPanic pins that a panic while the shared listener
// accepts a connection is reported without its value, and that the listener accepts
// and serves the next connection.
func TestTheSharedListenerAcceptsAfterAPanic(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "origin") }))
	defer origin.Close()
	ln, err := net.Listen("tcp", link.Loopback)
	if err != nil {
		t.Fatal(err)
	}
	reports := make(chan string, 4)
	l := &Listener{ln: &panicFirst{Listener: ln}, runs: map[[32]byte]*registered{}, pending: map[net.Conn]struct{}{}}
	l.wait.Store(int64(preambleWait))
	l.ReportPanics(func(line string) { reports <- line })
	l.wg.Add(1)
	go l.accept()
	defer l.Close()
	p, err := New(policy.Observe, nil, nil, func(Decision) {})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Register(secret, p); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-reports:
		if first, _, _ := strings.Cut(got, "\n"); first != routine.Panicked || strings.Contains(got, "fake-key-0001") {
			t.Errorf("the report of the accept's panic: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the accept's panic was not reported")
	}
	c, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "%s %s\nGET %s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", link.RelayPreamble, secret, origin.URL, origin.Listener.Addr())
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("a connection after the accept's panic: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "origin" {
		t.Errorf("a connection after the accept's panic: %d %q", resp.StatusCode, body)
	}
}
