package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// linkListener hands the link's HTTP server the connections that opened with the link's
// preamble: those to the socket whose peer is this process's user, and those made in
// memory by a session in this process, [linkListener.dial]. Any other is closed
// unanswered, and nothing is logged of it.
type linkListener struct {
	ln     net.Listener
	secret string
	uid    int
	conns  chan net.Conn
	done   chan struct{}
	once   sync.Once

	mu      sync.Mutex
	pending map[net.Conn]struct{}
	wg      sync.WaitGroup
}

// newLinkListener serves the connections of uid's processes on ln, and those made in
// memory; a nil ln is no socket, and the connections made in memory alone.
func newLinkListener(ln net.Listener, secret string, uid int) *linkListener {
	l := &linkListener{ln: ln, secret: secret, uid: uid, conns: make(chan net.Conn), done: make(chan struct{}), pending: map[net.Conn]struct{}{}}
	if ln != nil {
		l.wg.Add(1)
		go l.accept()
	}
	return l
}

// accept checks every connection in its own goroutine, so a peer that sends nothing
// holds up no one else.
func (l *linkListener) accept() {
	defer l.wg.Done()
	var backoff time.Duration
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		l.mu.Lock()
		select {
		case <-l.done:
			l.mu.Unlock()
			c.Close()
			return
		default:
		}
		l.pending[c] = struct{}{}
		l.wg.Add(1)
		l.mu.Unlock()
		go l.check(c, false)
	}
}

// dial opens a connection to the link in this process's memory, one end of a
// [net.Pipe]: the session's client writes the preamble on it and speaks HTTP/1.1, as
// over the socket, and the other end is checked and served as a socket's connection is,
// its peer this process. It is the in-memory way of [link.Local.InMemory].
func (l *linkListener) dial(context.Context) (net.Conn, error) {
	client, served := net.Pipe()
	l.mu.Lock()
	select {
	case <-l.done:
		l.mu.Unlock()
		client.Close()
		served.Close()
		return nil, net.ErrClosed
	default:
	}
	l.pending[served] = struct{}{}
	l.wg.Add(1)
	l.mu.Unlock()
	go l.check(served, true)
	return client, nil
}

// check hands c on when its peer is this user, or this process for one made in memory,
// and it opens with the preamble within [link.PreambleWait], and closes it otherwise.
func (l *linkListener) check(c net.Conn, inMemory bool) {
	defer l.wg.Done()
	ok, r := l.opens(c, inMemory)
	l.mu.Lock()
	delete(l.pending, c)
	l.mu.Unlock()
	if !ok {
		c.Close()
		return
	}
	select {
	case l.conns <- &linkConn{Conn: c, r: r}:
	case <-l.done:
		c.Close()
	}
}

// opens reports whether c is a session's: its peer this process's user, by the uid the
// kernel recorded, or this process itself for a connection made in memory; and its
// first bytes the preamble with the link secret.
func (l *linkListener) opens(c net.Conn, inMemory bool) (bool, *bufio.Reader) {
	if !inMemory {
		uc, ok := c.(*net.UnixConn)
		if !ok {
			return false, nil
		}
		if uid, err := peerUID(uc); err != nil || uid != l.uid {
			return false, nil
		}
	}
	c.SetReadDeadline(time.Now().Add(link.PreambleWait))
	defer c.SetReadDeadline(time.Time{})
	r := bufio.NewReader(c)
	if ok, err := link.ReadLinkPreamble(r, l.secret); !ok || err != nil {
		return false, nil
	}
	return true, r
}

// Accept is the next session's connection.
func (l *linkListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops the listener and closes every connection still being checked.
func (l *linkListener) Close() error {
	var err error
	l.once.Do(func() {
		l.mu.Lock()
		close(l.done)
		for c := range l.pending {
			c.Close()
		}
		l.mu.Unlock()
		if l.ln != nil {
			err = l.ln.Close()
		}
		l.wg.Wait()
	})
	return err
}

// Addr is the link's socket, or the in-memory link's when there is none.
func (l *linkListener) Addr() net.Addr {
	if l.ln == nil {
		return memoryAddr{}
	}
	return l.ln.Addr()
}

// memoryAddr is the address of the link served in memory alone.
type memoryAddr struct{}

// Network is "memory".
func (memoryAddr) Network() string { return "memory" }

// String names the link in memory.
func (memoryAddr) String() string { return "the gateway's local link in memory" }

// linkConn reads through the reader the preamble was read with, which may hold the
// first bytes of HTTP.
type linkConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *linkConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// quietLog is the link server's error log: nothing, since what a peer sends is no
// reason to write anything.
func quietLog() *log.Logger { return log.New(io.Discard, "", 0) }

// maxBatch is the most of a batch's body the gateway reads: twice the mebibyte a batch
// is cut at.
const maxBatch = 2 << 20

// handler routes the link's requests.
func (g *Gateway) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get(server.HeaderContractVersion); v != "" && v != strconv.Itoa(server.Revision) {
			refuse(w, http.StatusBadRequest, "unsupported_contract_version", nil, accesskey.FromGateway, gatewayText("unsupported_contract_version"))
			return
		}
		switch {
		case r.URL.Path == server.WellKnown && r.Method == http.MethodGet:
			g.discover(w)
		case r.URL.Path == runPath && r.Method == http.MethodPost:
			g.openRun(w, r)
		case strings.HasPrefix(r.URL.Path, runPath+"/") && r.Method == http.MethodGet:
			g.reload(w, strings.TrimPrefix(r.URL.Path, runPath+"/"))
		case r.URL.Path == eventsPath && r.Method == http.MethodPost:
			g.batch(w, r)
		case r.URL.Path == server.WellKnown || r.URL.Path == runPath || r.URL.Path == eventsPath || strings.HasPrefix(r.URL.Path, runPath+"/"):
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// discover answers the link's discovery.
func (g *Gateway) discover(w http.ResponseWriter) {
	w.Header().Set("Content-Type", server.LinkContentType)
	w.Header().Set(server.HeaderConfiguration, g.discoveryDigest)
	w.WriteHeader(http.StatusOK)
	w.Write(g.discovery)
}

// linkRefusal is the body of a refusal on the link, link-refusal.schema.json: the code,
// the names it concerns, the text the user reads of it, and who refused.
type linkRefusal struct {
	Error   string   `json:"error"`
	Names   []string `json:"names,omitempty"`
	Message string   `json:"message,omitempty"`
	From    string   `json:"from"`
}

// refuse answers a coded refusal: the code, its names, who refused, and text, the
// error's text the session returns, as the message holds it.
func refuse(w http.ResponseWriter, status int, code string, names []string, from, text string) {
	b, _ := json.Marshal(linkRefusal{Error: code, Names: names, Message: message(text), From: from})
	w.Header().Set("Content-Type", server.LinkContentType)
	w.WriteHeader(status)
	w.Write(b)
}

// gatewayText is the text of a refusal the gateway decides with a code of its own,
// which no session decided before: the code alone.
func gatewayText(code string) string { return "the gateway refused the run: " + code }

// invalid answers 400 invalid_request, the gateway's.
func invalid(w http.ResponseWriter) {
	refuse(w, http.StatusBadRequest, server.CodeInvalidRequest, nil, accesskey.FromGateway, gatewayText(server.CodeInvalidRequest))
}

// gone answers the 410 of a run that ended at the gateway: its code, and who ended it.
// The server's close of a run that has not started reads as today's session's error
// then; of one that has, the same without "before it started".
func gone(w http.ResponseWriter, code, from string, started bool) {
	text := gatewayText(code)
	if from == accesskey.FromApiary {
		detail := "the server closed the run before it started"
		if started {
			detail = "the server closed the run"
		}
		text = (&accesskey.Refusal{Code: code, Status: http.StatusGone, Detail: detail}).Error()
	}
	refuse(w, http.StatusGone, code, nil, from, text)
}

// readBody reads at most max bytes of a request's body; a longer one is no body.
func readBody(r *http.Request, max int) ([]byte, bool) {
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(max)+1))
	if err != nil || len(b) > max {
		return nil, false
	}
	return b, true
}
