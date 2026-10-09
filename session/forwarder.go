package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/qoryai/forager/link"
)

// dialWait is how long the forwarder has to reach the gateway's proxy for one
// connection.
const dialWait = 10 * time.Second

// forwarder is the run's own listener on this machine: every connection it accepts it
// copies, byte for byte, to the gateway's proxy. Without a wall it opens each with the
// relay's preamble and the run's proxy secret first; behind a wall the wall's relay
// writes the preamble itself, and the forwarder passes on what arrives as it is.
//
// Behind a separate gateway it reaches the gateway's one address over TLS, with the
// link's trust: behind a wall, every connection must first open with the relay's
// preamble and the hop secret the session gave the wall's relay, which the forwarder
// replaces with the run's proxy secret inside TLS; without a wall, the agent's proxy URL
// carries the proxy secret as its password, which reaches the gateway inside TLS.
//
// The secrets are held in memory alone: never in a file or a report, and in an
// environment only as an unwalled agent's proxy URL behind a separate gateway.
type forwarder struct {
	ln  net.Listener
	way forwarding

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// forwarding is where a forwarder sends what it accepts, and with which secrets.
type forwarding struct {
	// dial opens one connection to the gateway's proxy.
	dial func(context.Context) (net.Conn, error)
	// secret, when set, is written in the relay's preamble at the start of every
	// connection to the proxy.
	secret string
	// hop, when set, is the secret every accepted connection must open with, in the
	// relay's preamble, before anything reaches the proxy; the preamble is not passed
	// on.
	hop string
	// password, when set, is the password of the proxy URL [forwarder.Env] gives.
	password string
}

// listenForwarder listens on addr, host:port, and forwards to target, the gateway's
// proxy address on this machine. A non-empty secret is written in the relay's preamble
// at the start of every connection.
func listenForwarder(addr, target, secret string) (*forwarder, error) {
	var d net.Dialer
	return listenForwarding(addr, forwarding{
		dial:   func(ctx context.Context) (net.Conn, error) { return d.DialContext(ctx, "tcp", target) },
		secret: secret,
	})
}

// listenForwarding listens on addr, host:port, and forwards each connection the way
// says.
func listenForwarding(addr string, way forwarding) (*forwarder, error) {
	for _, s := range []string{way.secret, way.hop, way.password} {
		if s == "" {
			continue
		}
		if err := link.CheckSecret(s); err != nil {
			return nil, fmt.Errorf("the gateway's proxy secret: %w", err)
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	f := &forwarder{ln: ln, way: way, conns: map[net.Conn]struct{}{}}
	f.wg.Add(1)
	go f.accept()
	return f, nil
}

// Addr is the address the forwarder listens on, host:port with the port it got.
func (f *forwarder) Addr() string { return f.ln.Addr().String() }

// Env is the variables that point a program at the forwarder: its address, and the
// password of the proxy URL when it has one.
func (f *forwarder) Env() []string {
	u := url.URL{Scheme: "http", Host: f.Addr()}
	if f.way.password != "" {
		// The user name is ignored; the password is the run's proxy secret.
		u.User = url.UserPassword(proxyUser, f.way.password)
	}
	return link.ProxyEnv(u.String())
}

// proxyUser is the user name of an unwalled agent's proxy URL behind a separate
// gateway, which the gateway ignores.
const proxyUser = "qory"

// newHopSecret makes the secret the wall's relay opens every connection to the
// forwarder with behind a separate gateway: 32 bytes from crypto/rand, base64url
// without padding. It is good for this run's forwarder alone, so the run's proxy
// secret is in no file of the wall's.
func newHopSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func (f *forwarder) accept() {
	defer f.wg.Done()
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		if !f.track(c) {
			c.Close()
			return
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer f.untrack(c)
			f.serve(c)
		}()
	}
}

// track lists a connection, so Close ends it; false once the forwarder is closed.
func (f *forwarder) track(c net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.conns[c] = struct{}{}
	return true
}

func (f *forwarder) untrack(c net.Conn) {
	f.mu.Lock()
	delete(f.conns, c)
	f.mu.Unlock()
	c.Close()
}

// serve copies one connection to the proxy and back, each direction until its end,
// which it passes on as a half close.
func (f *forwarder) serve(c net.Conn) {
	if f.way.hop != "" {
		// Nothing reaches the proxy from a connection that is not the run's relay.
		c.SetReadDeadline(time.Now().Add(link.PreambleWait))
		if ok, err := link.ReadRelayPreamble(c, f.way.hop); !ok || err != nil {
			return
		}
		c.SetReadDeadline(time.Time{})
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialWait)
	up, err := f.way.dial(ctx)
	cancel()
	if err != nil {
		return
	}
	if !f.track(up) {
		up.Close()
		return
	}
	defer f.untrack(up)
	if f.way.secret != "" {
		up.SetWriteDeadline(time.Now().Add(link.PreambleWait))
		if _, err := io.WriteString(up, link.Preamble(link.RelayPreamble, f.way.secret)); err != nil {
			return
		}
		up.SetWriteDeadline(time.Time{})
	}
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go pipe(up, c)
	go pipe(c, up)
	<-done
	<-done
}

// Close stops listening and ends every connection; it waits for them.
func (f *forwarder) Close() error {
	f.mu.Lock()
	f.closed = true
	for c := range f.conns {
		c.Close()
	}
	f.mu.Unlock()
	err := f.ln.Close()
	f.wg.Wait()
	return err
}
