package session

import (
	"context"
	"fmt"
	"io"
	"net"
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
// writes the preamble itself, and the forwarder passes on what arrives as it is. The
// secret is held in memory alone: never in an environment, a file or a report.
type forwarder struct {
	ln       net.Listener
	target   string
	preamble string

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// listenForwarder listens on addr, host:port, and forwards to target, the gateway's
// proxy address. A non-empty secret is written in the relay's preamble at the start of
// every connection.
func listenForwarder(addr, target, secret string) (*forwarder, error) {
	if secret != "" {
		if err := link.CheckSecret(secret); err != nil {
			return nil, fmt.Errorf("the gateway's proxy secret: %w", err)
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	f := &forwarder{ln: ln, target: target, conns: map[net.Conn]struct{}{}}
	if secret != "" {
		f.preamble = link.Preamble(link.RelayPreamble, secret)
	}
	f.wg.Add(1)
	go f.accept()
	return f, nil
}

// Addr is the address the forwarder listens on, host:port with the port it got.
func (f *forwarder) Addr() string { return f.ln.Addr().String() }

// Env is the variables that point a program at the forwarder.
func (f *forwarder) Env() []string { return link.ProxyEnv("http://" + f.Addr()) }

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
	ctx, cancel := context.WithTimeout(context.Background(), dialWait)
	var d net.Dialer
	up, err := d.DialContext(ctx, "tcp", f.target)
	cancel()
	if err != nil {
		return
	}
	if !f.track(up) {
		up.Close()
		return
	}
	defer f.untrack(up)
	if f.preamble != "" {
		up.SetWriteDeadline(time.Now().Add(link.PreambleWait))
		if _, err := io.WriteString(up, f.preamble); err != nil {
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
