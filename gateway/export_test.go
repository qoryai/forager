package gateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/server"
)

// BoundLine is the line the gateway answers the binding with under key, on a connection
// whose exporter value is ekm.
func BoundLine(key *accesskey.Key, ekm []byte) string { return boundLine(key, ekm) }

// SignedAnswer is what the one address writes, signed under key, on a connection whose
// exporter value is ekm, when handler answers req, whose body is body.
func SignedAnswer(key *accesskey.Key, ekm []byte, req *http.Request, body []byte, handler http.HandlerFunc) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req.Body = io.NopCloser(bytes.NewReader(body))
	cb := newCapturedBody(req, ekm)
	req.Body = cb
	sw := &signedWriter{w: rec, key: key, req: req, body: cb, header: http.Header{}}
	handler(sw, req)
	sw.Flush()
	return rec
}

// RegistrationAt is the bytes g sends for the registration reg at now: those it kept
// for the run id, or new ones.
func RegistrationAt(g *Gateway, reg server.Registration, now time.Time) ([]byte, error) {
	return g.registrationAt(reg, now)
}

// SetQuiet makes a run whose session sends nothing for d end, in place of three
// heartbeat intervals.
func SetQuiet(c *Config, d time.Duration) { c.quiet = d }

// SetLinkUID makes the link serve the user uid in place of this process's.
func SetLinkUID(c *Config, uid int) { c.uid = &uid }

// RefuseOpen answers a run that did not open with err.
func RefuseOpen(w http.ResponseWriter, err error) { refuseOpen(w, err) }

// MessageOf is err's text as a refusal's message holds it.
func MessageOf(err error) string { return message(err.Error()) }

// SetCloseWait bounds each run's flush when it closes by d.
func SetCloseWait(c *Config, d time.Duration) { c.closeWait = d }

// SetRelayWait makes wait how long the relay waits for the server.
func SetRelayWait(c *Config, wait time.Duration) { c.relayWait = wait }

// SetRelayInFlight makes n the most requests the relay has with the server at once.
func SetRelayInFlight(c *Config, n int) { c.relayInFlight = n }

// SetNow makes now the clock the one address judges a run key's attach window by.
func SetNow(c *Config, now func() time.Time) { c.now = now }

// Bearer is the bearer value of a request's Authorization values.
func Bearer(values []string) (string, bool) { return bearer(values) }

// PrintedCopy is a copy of the Gateway, *g, printed with format: its fields, since its
// print methods are on the pointer.
func PrintedCopy(g *Gateway, format string) string {
	return fmt.Sprintf(format, reflect.ValueOf(g).Elem())
}

// Held counts what g holds of its runs: the runs, and what the ended ones it let go of
// left, each for KeepEnded.
func Held(g *Gateway) (runs, spent int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.runs), len(g.spent)
}

// Tokens are the tokens of the credentials g's run of runID holds now, which its proxy
// sets, by the credential's name.
func Tokens(g *Gateway, runID string) map[string]string {
	g.mu.Lock()
	lr := g.runs[runID]
	g.mu.Unlock()
	out := map[string]string{}
	for _, u := range lr.r.Uses() {
		out[u.Name] = u.Token()
	}
	return out
}

// SetOpened sets what is called once a run on the one address opened.
func SetOpened(c *Config, f func()) { c.opened = f }

// WaitOpens waits for the run requests the gateway is answering to be answered.
func WaitOpens(g *Gateway) { g.opens.Wait() }

// SetMarked sets what is called once the record of a run on the one address is marked
// answered, with the context of its run request.
func SetMarked(c *Config, f func(context.Context)) { c.marked = f }

// SetOpenTries sets the waits between the tries of the run's registration with Qory
// Apiary as a run opens, and how long after the run request a try may start again, in place of openWaits and openWindow.
func SetOpenTries(c *Config, waits []time.Duration, window time.Duration) {
	c.openWaits, c.openWindow = waits, window
}

// OpenTries are the gateway's own waits between the tries of Qory Apiary as a run
// opens, and its window.
func OpenTries() ([]time.Duration, time.Duration) { return openWaits, openWindow }

// EndWords is how a line says a run ended with the state and the reason.
func EndWords(state, reason string) string {
	return endWords(runEnd{state: state, reason: reason})
}

// KeepEnded is how long a gateway keeps what an ended run on its one address left.
const KeepEnded = keepEnded

// The relay's limits.
const (
	RelayBurst     = relayBurst
	RelayEnrolment = relayEnrolment
	RelayRegister  = relayRegister
	RelayOutcome   = relayOutcome
	RelayMaxAnswer = relayMaxAnswer
)

// ServiceServers are the servers of g's one address: the link's and the relay's.
func ServiceServers(g *Gateway) (edge, relay *http.Server) { return g.svc.edge, g.svc.relay.http }

// HoldEnded marks g's run of runID ended, as its end does before anything of the run is
// let go of, and returns what marks it live again.
func HoldEnded(g *Gateway, runID string) (undo func()) {
	g.mu.Lock()
	lr := g.runs[runID]
	g.mu.Unlock()
	lr.mu.Lock()
	lr.ended = true
	lr.mu.Unlock()
	return func() {
		lr.mu.Lock()
		lr.ended = false
		lr.mu.Unlock()
	}
}

// The one address's bounds.
const (
	MaxSourceConns = maxSourceConns
	MaxBlockConns  = maxBlockConns
	RefusedBody    = refusedBody
	MaxBound       = maxBound
	RefusedWait    = refusedWait
	EdgeReadWait   = edgeReadWait
	EdgeMaxHeader  = edgeMaxHeader
	RelayReadWait  = relayReadWait
	RelayWriteWait = relayWriteWait
	RelayMaxHeader = relayMaxHeader
)

// PendingConns counts the connections g's one address holds whose run key it has not
// admitted.
func PendingConns(g *Gateway) int {
	g.svc.conns.mu.Lock()
	defer g.svc.conns.mu.Unlock()
	return g.svc.conns.total
}

// WaitingConns counts the connections g's one address holds whose run key it has not
// admitted and no run key has vouched for: those it may close for a newer one.
func WaitingConns(g *Gateway) int {
	g.svc.conns.mu.Lock()
	defer g.svc.conns.mu.Unlock()
	return g.svc.conns.waiting.Len()
}
