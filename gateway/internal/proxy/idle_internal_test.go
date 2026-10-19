package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/policy"
)

// connStates are the connections an origin holds open, by the state each was in last.
type connStates struct {
	mu    sync.Mutex
	conns map[net.Conn]http.ConnState
}

func (c *connStates) track(conn net.Conn, s http.ConnState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conns == nil {
		c.conns = map[net.Conn]http.ConnState{}
	}
	if s == http.StateClosed || s == http.StateHijacked {
		delete(c.conns, conn)
		return
	}
	c.conns[conn] = s
}

// idle is how many connections are open and idle.
func (c *connStates) idle() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, s := range c.conns {
		if s == http.StateIdle {
			n++
		}
	}
	return n
}

// open is how many connections are open.
func (c *connStates) open() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.conns)
}

// within waits up to five seconds for ok.
func within(ok func() bool) bool {
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}

// TestTheRunsEndClosesItsIdleUpstreamConnections pins that the connection to a host
// the proxy terminates, which carried the run's credential, stays pooled while the run
// goes on and closes when the proxy closes, at the run's end; that a plain request's
// connection closes once the request ends; and that every upstream transport closes a
// connection idle for idleTimeout.
func TestTheRunsEndClosesItsIdleUpstreamConnections(t *testing.T) {
	up, err := NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "origin") })
	secureConns, plainConns := &connStates{}, &connStates{}
	secure := httptest.NewUnstartedServer(handler)
	secure.Config.ErrorLog = log.New(io.Discard, "", 0)
	secure.Config.ConnState = secureConns.track
	secure.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return up.leaf(hello.ServerName) }}
	secure.StartTLS()
	defer secure.Close()
	plain := httptest.NewUnstartedServer(handler)
	plain.Config.ConnState = plainConns.track
	plain.Start()
	defer plain.Close()

	p, err := Listen("", policy.Observe, nil, nil, (&decisions{}).observe)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			p.Close()
		}
	}()
	p.dial = (&dials{plain: plain.Listener.Addr().String(), secure: secure.Listener.Addr().String()}).dial
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(up.PEM())
	p.TrustUpstream(roots)
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	p.Terminate(ca, []Credential{{Name: "key", Hosts: []string{"key.example"}, Scheme: "bearer", Token: func() string { return "fake-key-0001" }}}, nil, nil)

	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	proxyURL, _ := url.Parse(p.URL())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	for _, target := range []string{"https://key.example/v1", "http://plain.example/v1"} {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", target, resp.StatusCode)
		}
	}
	if !within(func() bool { return plainConns.open() == 0 }) {
		t.Errorf("a plain request's upstream connection is open after the request: %d", plainConns.open())
	}
	if !within(func() bool { return secureConns.idle() == 1 }) {
		t.Fatalf("while the run goes on, %d idle connections to the terminated host, want 1", secureConns.idle())
	}
	closed = true
	p.Close()
	if !within(func() bool { return secureConns.open() == 0 }) {
		t.Errorf("after the run's end, %d connections to the terminated host are open", secureConns.open())
	}

	for name, rt := range map[string]http.RoundTripper{"upstream": p.upstream().(*unmark).rt, "plain": p.transport()} {
		if got := rt.(*http.Transport).IdleConnTimeout; got != idleTimeout {
			t.Errorf("the %s transport's IdleConnTimeout is %s, want %s", name, got, idleTimeout)
		}
	}
}
