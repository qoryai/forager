package session

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/link"
)

// upstream is a stand-in for the gateway's proxy: it keeps what each connection the
// forwarder opened sent it, until that connection's end.
type upstream struct {
	ln net.Listener

	mu       sync.Mutex
	received []string
	opened   int
}

func startUpstream(t *testing.T) *upstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &upstream{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u.mu.Lock()
			u.opened++
			u.mu.Unlock()
			go func() {
				defer c.Close()
				b, _ := io.ReadAll(c)
				u.mu.Lock()
				u.received = append(u.received, string(b))
				u.mu.Unlock()
			}()
		}
	}()
	return u
}

func (u *upstream) seen() (opened int, received []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.opened, append([]string(nil), u.received...)
}

// TestTheForwarderTakesOnlyTheRelaysHop pins the hop secret of a forwarder behind a wall
// and a separate gateway: a connection that opens with no relay preamble, with another
// hop, or with a prefix of the hop is closed, and nothing of it reaches the gateway's
// proxy, not even a connection; one that opens with the hop goes to the proxy, which
// receives the relay's preamble with the run's proxy secret in its place, then what the
// relay sent after the hop.
func TestTheForwarderTakesOnlyTheRelaysHop(t *testing.T) {
	const (
		hop    = "hop-secret-0123456789abcdefghijklmnopqrstuv"
		secret = "proxy-secret-0123456789abcdefghijklmnopqrst"
		other  = "hop-secret-0123456789abcdefghijklmnopqrstuw"
	)
	up := startUpstream(t)
	var d net.Dialer
	f, err := listenForwarding("127.0.0.1:0", forwarding{
		dial:   func(ctx context.Context) (net.Conn, error) { return d.DialContext(ctx, "tcp", up.ln.Addr().String()) },
		secret: secret,
		hop:    hop,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// send writes what to the forwarder, ends its writing half, and reports whether
	// the forwarder closed the connection, at the end or with a reset, within 5 seconds,
	// with what it answered.
	send := func(t *testing.T, what string) (closed bool, answer string) {
		t.Helper()
		c, err := net.Dial("tcp", f.Addr())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := io.WriteString(c, what); err != nil {
			return true, ""
		}
		c.(*net.TCPConn).CloseWrite()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, err := io.ReadAll(c)
		// A close with unread bytes may come as a reset; only the deadline is no close.
		var ne net.Error
		return err == nil || !(errors.As(err, &ne) && ne.Timeout()), string(b)
	}

	for name, what := range map[string]string{
		"no preamble":         "CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\n\r\n",
		"another hop":         link.RelayLine(other) + "CONNECT api.example:443 HTTP/1.1\r\n\r\n",
		"a prefix of the hop": link.RelayLine(hop[:len(hop)-1]),
	} {
		t.Run(name, func(t *testing.T) {
			if closed, answer := send(t, what); !closed || answer != "" {
				t.Errorf("the forwarder answered %q, closed %v", answer, closed)
			}
		})
	}
	// The forwarder dials only after the hop: give a stray dial the time to land.
	time.Sleep(200 * time.Millisecond)
	if opened, received := up.seen(); opened != 0 || len(received) != 0 {
		t.Fatalf("the proxy got %d connections, %q, before any hop", opened, received)
	}

	if closed, _ := send(t, link.RelayLine(hop)+"CONNECT api.example:443 HTTP/1.1\r\n\r\n"); !closed {
		t.Error("the forwarder kept the relay's connection open after its end")
	}
	want := link.RelayLine(secret) + "CONNECT api.example:443 HTTP/1.1\r\n\r\n"
	deadline := time.Now().Add(5 * time.Second)
	for {
		opened, received := up.seen()
		if len(received) == 1 {
			if opened != 1 || received[0] != want {
				t.Errorf("the proxy got %d connections, %q; want one, %q", opened, received, want)
			}
			if strings.Contains(received[0], hop) {
				t.Error("the hop reached the proxy")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the proxy got %d connections, %q", opened, received)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestTheUnwalledForwarderTakesOnlyItsPassword pins the password of an unwalled agent's
// proxy URL behind a separate gateway: a connection whose first request carries no
// Proxy-Authorization, another password, a prefix of the password, or two of them is
// closed, and nothing of it reaches the gateway's proxy, not even a connection; one
// that carries the password goes to the proxy without that header, and the proxy URL
// carries the password and no other secret.
func TestTheUnwalledForwarderTakesOnlyItsPassword(t *testing.T) {
	const password = "forwarder-password-0123456789abcdefghijklmn"
	login := func(user, pw string) string {
		return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pw)) + "\r\n"
	}
	up := startUpstream(t)
	var d net.Dialer
	f, err := listenForwarding("127.0.0.1:0", forwarding{
		dial:     func(ctx context.Context) (net.Conn, error) { return d.DialContext(ctx, "tcp", up.ln.Addr().String()) },
		password: password,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if env := f.Env(); !slices.Contains(env, "HTTP_PROXY=http://qory:"+password+"@"+f.Addr()) {
		t.Errorf("the proxy URL %q", env)
	}
	send := func(t *testing.T, what string) (closed bool, answer string) {
		t.Helper()
		c, err := net.Dial("tcp", f.Addr())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := io.WriteString(c, what); err != nil {
			return true, ""
		}
		c.(*net.TCPConn).CloseWrite()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, err := io.ReadAll(c)
		var ne net.Error
		return err == nil || !(errors.As(err, &ne) && ne.Timeout()), string(b)
	}
	const connect = "CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\n"
	for name, what := range map[string]string{
		"no password":              connect + "\r\n",
		"another password":         connect + login("qory", password[:len(password)-1]+"x") + "\r\n",
		"a prefix of the password": connect + login("qory", password[:len(password)-1]) + "\r\n",
		"the password twice":       connect + login("qory", password) + login("qory", password) + "\r\n",
		"another scheme":           connect + "Proxy-Authorization: Bearer " + password + "\r\n\r\n",
		"no end of the head":       connect + login("qory", password),
	} {
		t.Run(name, func(t *testing.T) {
			if closed, answer := send(t, what); !closed || answer != "" {
				t.Errorf("the forwarder answered %q, closed %v", answer, closed)
			}
		})
	}
	time.Sleep(200 * time.Millisecond)
	if opened, received := up.seen(); opened != 0 || len(received) != 0 {
		t.Fatalf("the proxy got %d connections, %q, without the password", opened, received)
	}
	if closed, _ := send(t, connect+login("anyone", password)+"\r\nafter"); !closed {
		t.Error("the forwarder kept the agent's connection open after its end")
	}
	want := connect + "\r\nafter"
	deadline := time.Now().Add(5 * time.Second)
	for {
		opened, received := up.seen()
		if len(received) == 1 {
			if opened != 1 || received[0] != want {
				t.Errorf("the proxy got %d connections, %q; want one, %q", opened, received, want)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the proxy got %d connections, %q", opened, received)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
