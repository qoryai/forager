package gateway

import (
	"bytes"
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
	cb := &capturedBody{r: io.NopCloser(bytes.NewReader(body)), post: req.Method == http.MethodPost}
	req.Body = cb
	sw := &signedWriter{w: rec, key: key, ekm: ekm, req: req, body: cb, header: http.Header{}}
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

// SetOpened sets what is called once a run on the one address opened.
func SetOpened(c *Config, f func()) { c.opened = f }

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
