package proxy

import (
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/qoryai/forager/link"
)

// preambleWait is how long a connection has to send its preamble.
const preambleWait = 10 * time.Second

// errNoToken ends a connection that did not open with the run's token.
var errNoToken = errors.New("the connection did not open with the run's token")

// Require makes the proxy serve only connections that open with the preamble and this
// secret. The session calls it once, before the wall starts the relay.
func (p *Proxy) Require(token string, refused func()) {
	p.refused = refused
	p.token.Store(&token)
}

// gate is the proxy's listener: it hands every connection on as one that checks the
// preamble on its first read, in the connection's own goroutine, so a peer that sends
// nothing holds up no one else.
type gate struct {
	net.Listener
	p *Proxy
}

// Accept hands on the next connection, gated when a token is required.
func (g *gate) Accept() (net.Conn, error) {
	c, err := g.Listener.Accept()
	if err != nil {
		return nil, err
	}
	token := g.p.token.Load()
	if token == nil {
		return c, nil
	}
	return &gated{Conn: c, want: link.RelayPreamble + " " + *token + "\n", refused: g.p.refused}, nil
}

// gated is a connection that must open with the preamble.
type gated struct {
	net.Conn
	want    string
	refused func()
	once    sync.Once
	err     error
}

// Read checks the preamble before the first byte it hands on.
func (c *gated) Read(b []byte) (int, error) {
	c.once.Do(func() {
		got := make([]byte, len(c.want))
		c.SetReadDeadline(time.Now().Add(preambleWait))
		_, err := io.ReadFull(c.Conn, got)
		c.SetReadDeadline(time.Time{})
		if err != nil || subtle.ConstantTimeCompare(got, []byte(c.want)) != 1 {
			c.err = errNoToken
			c.Conn.Close()
			if c.refused != nil {
				c.refused()
			}
		}
	})
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(b)
}
