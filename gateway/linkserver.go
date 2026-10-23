package gateway

import (
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

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/routine"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// linkListener hands the link's HTTP server the connections of a session: those to
// the socket whose peer is this process's user, and those made in memory by a session
// in this process, [linkListener.dial]. Any other is closed unanswered before anything
// is read of it, and nothing is logged of it.
type linkListener struct {
	ln  net.Listener
	uid int
	// report gets a panic of the listener's goroutines ([routine.Go]).
	report func(string)
	conns  chan net.Conn
	done   chan struct{}
	once   sync.Once

	mu      sync.Mutex
	pending map[net.Conn]struct{}
	wg      sync.WaitGroup
}

// newLinkListener serves the connections of uid's processes on ln, and those made in
// memory; a nil ln is no socket, and the connections made in memory alone. report gets
// a panic of the listener's goroutines.
func newLinkListener(ln net.Listener, uid int, report func(string)) *linkListener {
	l := &linkListener{ln: ln, uid: uid, report: report, conns: make(chan net.Conn), done: make(chan struct{}), pending: map[net.Conn]struct{}{}}
	if ln != nil {
		l.wg.Add(1)
		routine.Go(report, l.accept)
	}
	return l
}

// accept checks every connection in its own goroutine, so a peer that is slow to be
// checked holds up no one else.
func (l *linkListener) accept() {
	defer l.wg.Done()
	routine.Accept(l.report, l.take)
}

// take accepts one connection into *c and checks it in its own goroutine, for
// [routine.Accept].
func (l *linkListener) take(c *net.Conn) (more, failed bool) {
	conn, err := l.ln.Accept()
	if err != nil {
		return !errors.Is(err, net.ErrClosed), true
	}
	*c = conn
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.done:
		conn.Close()
		return false, false
	default:
	}
	l.pending[conn] = struct{}{}
	l.wg.Add(1)
	routine.Go(l.report, func() { l.check(conn, false) }, conn)
	return true, false
}

// dial opens a connection to the link in this process's memory, one end of a
// [net.Pipe]: the session's client speaks HTTP/1.1 on it, as over the socket, and the
// other end is served as a socket's connection is, its peer this process. It is the
// in-memory way of [link.Local.InMemory].
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
	routine.Go(l.report, func() { l.check(served, true) }, served)
	return client, nil
}

// check hands c on when its peer is this user, or this process for one made in memory,
// and closes it otherwise.
func (l *linkListener) check(c net.Conn, inMemory bool) {
	defer l.wg.Done()
	forgotten := false
	defer func() {
		// After a panic in opens.
		if !forgotten {
			l.forget(c)
		}
	}()
	ok := l.opens(c, inMemory)
	l.forget(c)
	forgotten = true
	if !ok {
		c.Close()
		return
	}
	select {
	case l.conns <- c:
	case <-l.done:
		c.Close()
	}
}

// forget takes c off the connections being checked.
func (l *linkListener) forget(c net.Conn) {
	l.mu.Lock()
	delete(l.pending, c)
	l.mu.Unlock()
}

// opens reports whether c is a session's: its peer this process's user, by the uid the
// kernel recorded, or this process itself for a connection made in memory.
func (l *linkListener) opens(c net.Conn, inMemory bool) bool {
	if inMemory {
		return true
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return false
	}
	uid, err := peerUID(uc)
	return err == nil && uid == l.uid
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

// quietLog is the link server's error log: nothing, since what a peer sends is no
// reason to write anything.
func quietLog() *log.Logger { return log.New(io.Discard, "", 0) }

// maxBatch is the most of a batch's body the gateway reads: twice the mebibyte a batch
// is cut at.
const maxBatch = 2 << 20

// handler routes the requests of the contract that reach the gateway by s: its local
// link, on the paths of its discovery there, or its one address, on the paths under
// [link.RemotePathPrefix].
func (g *Gateway) handler(s *side) http.Handler {
	discovery, runs, events := server.WellKnown, runPath, eventsPath
	if s.remote {
		discovery, runs, events = link.RemoteDiscoveryPath, remoteRunPath, remoteEventsPath
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get(server.HeaderContractVersion); v != "" && v != strconv.Itoa(server.Revision) {
			refuse(w, http.StatusBadRequest, "unsupported_contract_version", nil, accesskey.FromGateway, gatewayText("unsupported_contract_version"))
			return
		}
		switch {
		case r.URL.Path == discovery && r.Method == http.MethodGet:
			g.discover(s, w, r)
		case r.URL.Path == runs && r.Method == http.MethodPost:
			g.openRun(s, w, r)
		case r.Method == http.MethodPost && isJoin(r.URL.Path, runs):
			id, _ := joinRun(r.URL.Path, runs)
			g.joinSession(s, w, r, id)
		case strings.HasPrefix(r.URL.Path, runs+"/") && r.Method == http.MethodGet:
			g.reload(s, w, r, strings.TrimPrefix(r.URL.Path, runs+"/"))
		case r.URL.Path == events && r.Method == http.MethodPost:
			g.batch(s, w, r)
		case r.URL.Path == discovery || r.URL.Path == runs || r.URL.Path == events || strings.HasPrefix(r.URL.Path, runs+"/"):
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// discover answers the link's discovery: 400 invalid_request on the one address to a
// request whose Host names no origin a discovery can list.
func (g *Gateway) discover(s *side, w http.ResponseWriter, r *http.Request) {
	body, digest, ok := g.discoveryOf(s, r)
	if !ok {
		invalid(w)
		return
	}
	w.Header().Set("Content-Type", server.LinkContentType)
	w.Header().Set(server.HeaderConfiguration, digest)
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// linkRefusal is the body of a refusal on the link, link-refusal.schema.json: the code,
// the names it concerns, the text the user reads of it, and who refused; and of a 410
// that ends a run, the state and the reason of the gateway's dev.qory.run.exited of it.
type linkRefusal struct {
	Error   string   `json:"error"`
	Names   []string `json:"names,omitempty"`
	Message string   `json:"message,omitempty"`
	From    string   `json:"from"`
	State   string   `json:"state,omitempty"`
	Reason  string   `json:"reason,omitempty"`
}

// refuse answers a coded refusal: the code, its names, who refused, and text, the
// error's text the session returns, as the message holds it.
func refuse(w http.ResponseWriter, status int, code string, names []string, from, text string) {
	answerRefusal(w, status, linkRefusal{Error: code, Names: names, Message: message(text), From: from})
}

// answerRefusal answers the refusal ref with status.
func answerRefusal(w http.ResponseWriter, status int, ref linkRefusal) {
	b, _ := json.Marshal(ref)
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

// gone answers the 410 of a run that ended at the gateway: its code, and who ended it,
// always the gateway, since a server's 410 ends no run; and of an end that ended the run,
// the state and the reason of the gateway's dev.qory.run.exited of it, which its message
// says.
func gone(w http.ResponseWriter, end runEnd) {
	text := "the run has ended"
	if end.state != "" {
		text += ": " + endWords(end)
	}
	answerRefusal(w, http.StatusGone, linkRefusal{Error: end.code, Message: message(text), From: end.from, State: end.state, Reason: end.reason})
}

// readBody reads at most max bytes of a request's body; a longer one is no body.
func readBody(r *http.Request, max int) ([]byte, bool) {
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(max)+1))
	if err != nil || len(b) > max {
		return nil, false
	}
	return b, true
}
