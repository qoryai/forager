package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os/exec"
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
// Proxy-Authorization, another password, a prefix of the password, or two of them, or
// whose head has a line too long, too many lines, too many bytes in all, even in short
// lines, or does not end in time, is closed, and nothing of it reaches the gateway's
// proxy, not even a connection; one that carries the password goes to the proxy
// without that header and with Connection: close, and the proxy URL carries the
// password and no other secret.
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
		headWait: 300 * time.Millisecond,
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
	// The head's bounds: a line longer than the forwarder reads, more lines than it
	// reads, more bytes in all than it reads, in short lines, and a head that does not
	// end in time, each with the password.
	slow, err := net.Dial("tcp", f.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	io.WriteString(slow, connect+login("qory", password))
	slow.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(slow); err != nil {
		t.Errorf("a slow head was not closed: %v", err)
	}
	for name, what := range map[string]string{
		"no password":              connect + "\r\n",
		"another password":         connect + login("qory", password[:len(password)-1]+"x") + "\r\n",
		"a prefix of the password": connect + login("qory", password[:len(password)-1]) + "\r\n",
		"the password twice":       connect + login("qory", password) + login("qory", password) + "\r\n",
		"another scheme":           connect + "Proxy-Authorization: Bearer " + password + "\r\n\r\n",
		"no end of the head":       connect + login("qory", password),
		"a line too long":          connect + login("qory", password) + "X-Long: " + strings.Repeat("a", maxProxyLine) + "\r\n\r\n",
		"too many lines":           connect + login("qory", password) + strings.Repeat("X-Line: a\r\n", maxProxyLines) + "\r\n",
		"a head too large":         connect + login("qory", password) + strings.Repeat("X-Line: "+strings.Repeat("a", 200)+"\r\n", maxProxyHead/200) + "\r\n",
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
	want := connect + "Connection: close\r\n\r\nafter"
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

// TestTheOneMachineForwarderTakesOnlyItsPassword pins the password of an unwalled
// agent's proxy URL on one machine, where the forwarder opens every connection to the
// gateway's proxy with the run's proxy secret: a connection whose first request carries
// no Proxy-Authorization, another password or the proxy secret in its place, or that
// opens with the relay's preamble and the proxy secret, is closed, and nothing of it
// reaches the gateway's proxy, not even a connection; one that carries the password
// goes to the proxy after the relay's preamble with the proxy secret, without that
// header and with Connection: close, and the proxy URL carries the password and not the
// proxy secret.
func TestTheOneMachineForwarderTakesOnlyItsPassword(t *testing.T) {
	const (
		password = "forwarder-password-0123456789abcdefghijklmn"
		secret   = "proxy-secret-0123456789abcdefghijklmnopqrst"
	)
	login := func(pw string) string {
		return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("qory:"+pw)) + "\r\n"
	}
	up := startUpstream(t)
	f, err := listenForwarder("127.0.0.1:0", up.ln.Addr().String(), secret, password)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if env := f.Env(); !slices.Contains(env, "HTTP_PROXY=http://qory:"+password+"@"+f.Addr()) || strings.Contains(strings.Join(env, "\n"), secret) {
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
		"no password":      connect + "\r\n",
		"another password": connect + login(password[:len(password)-1]+"x") + "\r\n",
		"the proxy secret": connect + login(secret) + "\r\n",
		"the proxy's own":  link.RelayLine(secret) + connect + "\r\n",
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
	if closed, _ := send(t, connect+login(password)+"\r\nafter"); !closed {
		t.Error("the forwarder kept the agent's connection open after its end")
	}
	want := link.RelayLine(secret) + connect + "Connection: close\r\n\r\nafter"
	deadline := time.Now().Add(5 * time.Second)
	for {
		opened, received := up.seen()
		if len(received) == 1 {
			if opened != 1 || received[0] != want {
				t.Errorf("the proxy got %d connections, %q; want one, %q", opened, received, want)
			}
			if strings.Contains(received[0], password) {
				t.Error("the password reached the proxy")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the proxy got %d connections, %q", opened, received)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// proxyStandIn is a stand-in for the gateway's proxy that speaks HTTP, a server of
// net/http: it checks the relay's preamble with secret when it is set, keeps every byte
// each connection sent it, and answers each request with "ok <its body's length>",
// recording its method, URL and body.
type proxyStandIn struct {
	ln     net.Listener
	secret string

	mu       sync.Mutex
	raw      []*bytes.Buffer
	requests []string
}

// startProxyStandIn starts a stand-in that answers with h, when it is set, recording
// each request's method and URL alone.
func startProxyStandIn(t *testing.T, secret string, h http.Handler) *proxyStandIn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxyStandIn{ln: ln, secret: secret}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h != nil {
			p.mu.Lock()
			p.requests = append(p.requests, r.Method+" "+r.URL.String())
			p.mu.Unlock()
			h.ServeHTTP(w, r)
			return
		}
		b, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.requests = append(p.requests, r.Method+" "+r.URL.String()+" "+string(b))
		p.mu.Unlock()
		fmt.Fprintf(w, "ok %d", len(b))
	})}
	go srv.Serve(p)
	t.Cleanup(func() { srv.Close() })
	return p
}

// Accept hands the server each connection, after the relay's preamble, keeping what it
// sends.
func (p *proxyStandIn) Accept() (net.Conn, error) {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return nil, err
		}
		raw := &bytes.Buffer{}
		p.mu.Lock()
		p.raw = append(p.raw, raw)
		p.mu.Unlock()
		r := bufio.NewReader(io.TeeReader(c, lockedWriter{&p.mu, raw}))
		if p.secret != "" {
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if line, err := r.ReadString('\n'); err != nil || line != link.RelayLine(p.secret) {
				c.Close()
				continue
			}
			c.SetReadDeadline(time.Time{})
		}
		return &readConn{Conn: c, r: r}, nil
	}
}

func (p *proxyStandIn) Close() error   { return p.ln.Close() }
func (p *proxyStandIn) Addr() net.Addr { return p.ln.Addr() }

// seen is what the stand-in received: every byte of every connection, and each request.
func (p *proxyStandIn) seen() (raw []string, requests []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, b := range p.raw {
		raw = append(raw, b.String())
	}
	return raw, append([]string(nil), p.requests...)
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

type readConn struct {
	net.Conn
	r io.Reader
}

func (c *readConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// TestTheUnwalledForwarderTakesOnePlainRequestAConnection pins that the password of an
// unwalled agent's proxy URL never reaches the gateway's proxy, on one machine, with the
// run's proxy secret, and behind a separate gateway, without it: a client that sends
// the password in every request of a kept-alive connection, as Go's and curl's do, gets
// each answer, its bodies with a length or in chunks passed on whole, while each plain
// request reaches the proxy on a connection of its own and no byte the proxy receives
// holds the password or its Proxy-Authorization; and a request pipelined after the first
// on one connection never reaches the proxy.
func TestTheUnwalledForwarderTakesOnePlainRequestAConnection(t *testing.T) {
	const (
		password = "forwarder-password-0123456789abcdefghijklmn"
		secret   = "proxy-secret-0123456789abcdefghijklmnopqrst"
	)
	credential := base64.StdEncoding.EncodeToString([]byte("qory:" + password))
	for name, secret := range map[string]string{"on one machine": secret, "behind a separate gateway": ""} {
		t.Run(name, func(t *testing.T) {
			up := startProxyStandIn(t, secret, nil)
			var d net.Dialer
			f, err := listenForwarding("127.0.0.1:0", forwarding{
				dial:     func(ctx context.Context) (net.Conn, error) { return d.DialContext(ctx, "tcp", up.Addr().String()) },
				secret:   secret,
				password: password,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			proxyURL, err := url.Parse("http://" + proxyUser + ":" + password + "@" + f.Addr())
			if err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}
			defer client.CloseIdleConnections()
			large := strings.Repeat("x", 64<<10)
			// chunked has no length, so the client sends it in chunks.
			chunked := struct{ io.Reader }{strings.NewReader("chunked body")}
			for _, r := range []struct {
				method, path string
				body         io.Reader
				want         string
			}{
				{"GET", "/a", nil, "ok 0"},
				{"GET", "/b", nil, "ok 0"},
				{"POST", "/length", strings.NewReader(large), fmt.Sprintf("ok %d", len(large))},
				{"POST", "/chunked", chunked, "ok 12"},
				{"GET", "/c", nil, "ok 0"},
			} {
				req, err := http.NewRequest(r.method, "http://api.example"+r.path, r.body)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("%s %s: %v", r.method, r.path, err)
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 || string(b) != r.want {
					t.Errorf("%s %s: %d %q, want %q", r.method, r.path, resp.StatusCode, b, r.want)
				}
			}
			if _, err := exec.LookPath("curl"); err == nil {
				if out, err := exec.Command("curl", "-sS", "-x", proxyURL.String(), "http://api.example/curl-1", "http://api.example/curl-2").CombinedOutput(); err != nil || string(out) != "ok 0ok 0" {
					t.Errorf("curl: %q %v", out, err)
				}
			}

			// A request pipelined after the first: the answer to the first, and nothing of
			// the second at the proxy.
			c, err := net.Dial("tcp", f.Addr())
			if err != nil {
				t.Fatal(err)
			}
			login := "Proxy-Authorization: Basic " + credential + "\r\n"
			io.WriteString(c, "GET http://api.example/first HTTP/1.1\r\nHost: api.example\r\n"+login+"\r\n"+
				"GET http://api.example/pipelined HTTP/1.1\r\nHost: api.example\r\n"+login+"\r\n")
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			answer, err := io.ReadAll(c)
			c.Close()
			if err != nil || !strings.HasPrefix(string(answer), "HTTP/1.1 200 OK\r\n") || strings.Count(string(answer), "HTTP/1.1") != 1 {
				t.Errorf("the pipelined connection got %q, %v", answer, err)
			}

			raw, requests := up.seen()
			want := []string{"GET http://api.example/a ", "GET http://api.example/b ", "POST http://api.example/length " + large,
				"POST http://api.example/chunked chunked body", "GET http://api.example/c "}
			if _, err := exec.LookPath("curl"); err == nil {
				want = append(want, "GET http://api.example/curl-1 ", "GET http://api.example/curl-2 ")
			}
			want = append(want, "GET http://api.example/first ")
			if !slices.Equal(requests, want) {
				t.Errorf("the proxy got %.200q, want %.200q", requests, want)
			}
			if len(raw) != len(want) {
				t.Errorf("the proxy got %d connections for %d requests", len(raw), len(want))
			}
			for _, b := range raw {
				if strings.Contains(b, password) || strings.Contains(b, credential) || strings.Contains(strings.ToLower(b), "proxy-authorization") {
					t.Errorf("the proxy received the password: %.300q", b)
				}
				if strings.Contains(b, "pipelined") {
					t.Errorf("the pipelined request reached the proxy: %.300q", b)
				}
			}
		})
	}
}

// unwalledForwarder is a forwarder of an unwalled agent to target, with the run's proxy
// secret on one machine or without it behind a separate gateway, and the agent's
// Proxy-Authorization with its password.
func unwalledForwarder(t *testing.T, target, secret string) (f *forwarder, login string) {
	t.Helper()
	const password = "forwarder-password-0123456789abcdefghijklmn"
	var d net.Dialer
	f, err := listenForwarding("127.0.0.1:0", forwarding{
		dial:     func(ctx context.Context) (net.Conn, error) { return d.DialContext(ctx, "tcp", target) },
		secret:   secret,
		password: password,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f, "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(proxyUser+":"+password)) + "\r\n"
}

// unwalledWays are the two unwalled forwarders by name: the run's proxy secret of each.
var unwalledWays = map[string]string{"on one machine": "proxy-secret-0123456789abcdefghijklmnopqrst", "behind a separate gateway": ""}

// TestTheUnwalledForwarderPassesAnUpgrade pins a plain request that asks for an upgrade,
// a ws:// one, through an unwalled forwarder to a proxy that passes it on as a reverse
// proxy of net/http does: a 101 makes the connection a tunnel, with bytes both ways, and
// any other answer ends the connection with it; neither carries the password to the
// proxy.
func TestTheUnwalledForwarderPassesAnUpgrade(t *testing.T) {
	tool := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" || r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "no upgrade", http.StatusBadRequest)
			return
		}
		c, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		io.Copy(c, rw.Reader)
	}))
	defer tool.Close()
	toolURL, _ := url.Parse(tool.URL)
	reverse := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(toolURL) }}
	for name, secret := range unwalledWays {
		t.Run(name, func(t *testing.T) {
			up := startProxyStandIn(t, secret, reverse)
			f, login := unwalledForwarder(t, up.Addr().String(), secret)

			c, err := net.Dial("tcp", f.Addr())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			io.WriteString(c, "GET http://tool.example/ws HTTP/1.1\r\nHost: tool.example\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n"+login+"\r\n")
			r := bufio.NewReader(c)
			resp, err := http.ReadResponse(r, nil)
			if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("the upgrade got %v, %v", resp, err)
			}
			for _, b := range []string{"ping\n", "pong\n"} {
				io.WriteString(c, b)
				if got, err := r.ReadString('\n'); got != b {
					t.Errorf("the tunnel echoed %q, %v; want %q", got, err, b)
				}
			}
			c.Close()

			refused, err := net.Dial("tcp", f.Addr())
			if err != nil {
				t.Fatal(err)
			}
			defer refused.Close()
			io.WriteString(refused, "GET http://tool.example/other HTTP/1.1\r\nHost: tool.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+login+"\r\n")
			refused.SetReadDeadline(time.Now().Add(5 * time.Second))
			b, err := io.ReadAll(refused)
			if err != nil || !strings.HasPrefix(string(b), "HTTP/1.1 400 ") || !strings.HasSuffix(string(b), "no upgrade\n") {
				t.Errorf("an upgrade the tool refused got %q, %v; want its answer and the end", b, err)
			}

			raw, requests := up.seen()
			if want := []string{"GET http://tool.example/ws", "GET http://tool.example/other"}; !slices.Equal(requests, want) {
				t.Errorf("the proxy got %q, want %q", requests, want)
			}
			for _, b := range raw {
				if strings.Contains(strings.ToLower(b), "proxy-authorization") || strings.Contains(b, "forwarder-password") {
					t.Errorf("the proxy received the password: %q", b)
				}
			}
		})
	}
}

// heldUpgrade is a stand-in for the gateway's proxy that reads one request's head, after
// the relay's preamble when there is one, and holds its reply: it reports on head when
// the head has come, and on ended when the forwarder has closed the connection, before
// or after the reply. With answer, it writes a 101 once wait has passed, then echoes.
func heldUpgrade(t *testing.T, wait time.Duration, answer bool) (addr string, head, ended <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	h, e := make(chan struct{}), make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		close(h)
		read := make(chan struct{})
		go func() {
			io.Copy(io.Discard, r)
			close(e)
			close(read)
		}()
		if answer {
			time.Sleep(wait)
			io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		}
		select {
		case <-read:
		case <-time.After(10 * time.Second):
		}
	}()
	return ln.Addr().String(), h, e
}

// TestTheUnwalledForwarderRefusesBytesBeforeTheUpgrade pins a plain request that asks
// for an upgrade, whose agent sends a byte before the proxy's reply: the forwarder
// closes the proxy's connection and the agent's, which gets no 101 and no tunnel, and
// an agent that sends a byte and leaves has the proxy's connection closed at once,
// rather than when the reply comes.
func TestTheUnwalledForwarderRefusesBytesBeforeTheUpgrade(t *testing.T) {
	const upgrade = "GET http://tool.example/ws HTTP/1.1\r\nHost: tool.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
	for name, secret := range unwalledWays {
		t.Run(name, func(t *testing.T) {
			t.Run("an early byte", func(t *testing.T) {
				addr, _, ended := heldUpgrade(t, 300*time.Millisecond, true)
				f, login := unwalledForwarder(t, addr, secret)
				c, err := net.Dial("tcp", f.Addr())
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				io.WriteString(c, upgrade+login+"\r\nearly")
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				b, err := io.ReadAll(c)
				var ne net.Error
				if len(b) != 0 || errors.As(err, &ne) && ne.Timeout() {
					t.Errorf("an agent that sent a byte before the reply got %q, %v; want the end and nothing", b, err)
				}
				select {
				case <-ended:
				case <-time.After(2 * time.Second):
					t.Error("the proxy's connection outlived the agent's")
				}
			})
			t.Run("a byte and the end", func(t *testing.T) {
				addr, head, ended := heldUpgrade(t, 0, false)
				f, login := unwalledForwarder(t, addr, secret)
				c, err := net.Dial("tcp", f.Addr())
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				io.WriteString(c, upgrade+login+"\r\n")
				select {
				case <-head:
				case <-time.After(5 * time.Second):
					t.Fatal("the request did not reach the proxy")
				}
				time.Sleep(100 * time.Millisecond)
				io.WriteString(c, "x")
				time.Sleep(100 * time.Millisecond)
				c.Close()
				select {
				case <-ended:
				case <-time.After(2 * time.Second):
					t.Error("the proxy's connection outlived the agent's")
				}
			})
		})
	}
}

// TestTheUnwalledForwarderLetsGoOfAnAgentThatLeft pins a plain request whose answer
// never comes: once the agent closes its connection, the forwarder closes the proxy's
// soon after, rather than at the run's end.
func TestTheUnwalledForwarderLetsGoOfAnAgentThatLeft(t *testing.T) {
	for name, secret := range unwalledWays {
		t.Run(name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			accepted, closed := make(chan struct{}), make(chan struct{})
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				close(accepted)
				// The proxy reads, and answers nothing, until the forwarder closes.
				io.Copy(io.Discard, c)
				close(closed)
			}()
			f, login := unwalledForwarder(t, ln.Addr().String(), secret)
			c, err := net.Dial("tcp", f.Addr())
			if err != nil {
				t.Fatal(err)
			}
			io.WriteString(c, "GET http://api.example/slow HTTP/1.1\r\nHost: api.example\r\n"+login+"\r\n")
			select {
			case <-accepted:
			case <-time.After(5 * time.Second):
				t.Fatal("the request did not reach the proxy")
			}
			time.Sleep(100 * time.Millisecond)
			c.Close()
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Error("the proxy's connection outlived the agent's")
			}
		})
	}
}

// TestTheUnwalledForwarderEndsARefusedTunnel pins a CONNECT the proxy refuses, with
// Connection: close and the end of its side: nothing the agent sends after it, a request
// with the password say, reaches the proxy.
func TestTheUnwalledForwarderEndsARefusedTunnel(t *testing.T) {
	for name, secret := range unwalledWays {
		t.Run(name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			after := make(chan string, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						after <- "the head did not end: " + err.Error()
						return
					}
					if line == "\r\n" {
						break
					}
				}
				io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
				c.(*net.TCPConn).CloseWrite()
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				b, _ := io.ReadAll(r)
				after <- string(b)
			}()
			f, login := unwalledForwarder(t, ln.Addr().String(), secret)
			c, err := net.Dial("tcp", f.Addr())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			io.WriteString(c, "CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\n"+login+"\r\n")
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if b, err := io.ReadAll(c); err != nil || !strings.HasPrefix(string(b), "HTTP/1.1 403 ") {
				t.Fatalf("the refused CONNECT got %q, %v", b, err)
			}
			// An agent that minds neither the Connection: close nor the end.
			io.WriteString(c, "GET http://api.example/second HTTP/1.1\r\nHost: api.example\r\n"+login+"\r\n")
			if b := <-after; b != "" {
				t.Errorf("the proxy got %q after its refusal", b)
			}
		})
	}
}
