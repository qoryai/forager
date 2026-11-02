package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/server"
)

// ChannelRunAPI is the channel of a decision of the run API's route, [Decision.Channel].
const ChannelRunAPI = "run_api"

// RunAPIRule is the rule of every decision of the run API's route, and of a denial of
// the host link.RunAPIHost that the policy would otherwise allow: not an allow or deny
// entry, the proxy's route, in either mode.
const RunAPIRule = "wall:run-api"

// The limits of the run API's route. The two sizes are Qory Apiary's: bodies are read
// whole, because Ed25519 signs the whole message.
const (
	maxRunAPIArtifacts int64 = 32 << 20
	maxRunAPIVerdict   int64 = 64 << 10
	// RunAPIRate is the most requests one run sends through the route in a second.
	RunAPIRate = 10
	// RunAPIInFlight is the most requests one run has in flight through the route.
	RunAPIInFlight = 4
	// RunAPIPostsInFlight is the most POSTs one gateway has in flight through the route.
	RunAPIPostsInFlight = 8
	runAPIPostWait      = 60 * time.Second
	runAPIFileWait      = 10 * time.Minute
)

// maxRunAPIShown is the most bytes of a request's method or path a decision contains.
const maxRunAPIShown = 2048

// runAPIHeaders are the headers of Qory Apiary's answer the route passes, beside
// Content-Length.
var runAPIHeaders = []string{"Content-Type", "Content-Disposition", "X-Content-Type-Options", "Content-Security-Policy", "Retry-After"}

// RunAPIPosts counts the POSTs in flight through the route of every run of one gateway.
type RunAPIPosts struct{ n atomic.Int32 }

// enter counts one more POST, and returns false, counting nothing, at
// [RunAPIPostsInFlight].
func (c *RunAPIPosts) enter() bool {
	if c.n.Add(1) > RunAPIPostsInFlight {
		c.n.Add(-1)
		return false
	}
	return true
}

// leave counts one POST fewer.
func (c *RunAPIPosts) leave() { c.n.Add(-1) }

// RunAPI is the route of one run's proxy to Qory Apiary's run API: the run's id, how a
// request is sent, signed, and the gateway's count of POSTs. The gateway makes one for
// a run with a control plane ([Proxy.SetRunAPI]); a stack proxy has none.
type RunAPI struct {
	RunID string
	// Send signs one request and sends it, as [server.Client.RunAPI] does. path is
	// escaped and starts after the run's id.
	Send func(ctx context.Context, method, path string, body []byte, file bool) (*server.RunAPIAnswer, error)
	// Posts counts the gateway's POSTs in flight.
	Posts *RunAPIPosts

	// postWait and fileWait, when set, replace the 60 seconds and the 10 minutes; now,
	// when set, is the clock of the rate limit. Tests set them.
	postWait, fileWait time.Duration
	now                func() time.Time

	mu       sync.Mutex
	inFlight int
	tokens   float64
	at       time.Time
}

// SetRunAPI gives p the route a. The gateway calls it once, after [New] and before the
// run's first connection. A proxy without a route treats the host link.RunAPIHost as
// any other host, but for a CONNECT ([Proxy.decide]).
func (p *Proxy) SetRunAPI(a *RunAPI) {
	a.tokens = RunAPIRate
	if a.now == nil {
		a.now = time.Now
	}
	a.at = a.now()
	p.runAPI.Store(a)
}

// forRunAPI reports whether r, a request other than a CONNECT, names the host of the
// run API. A host is read as sent, as a decision reads it: one percent-encoded has no
// form, and is decided as any other.
func forRunAPI(r *http.Request) bool {
	if r.URL.Host == "" || r.URL.Scheme == "" {
		return false
	}
	host, ok := policy.Host(sent(authorityOf(r.RequestURI)))
	return ok && host == link.RunAPIHost
}

// runAPITarget is one request inside the five shapes.
type runAPITarget struct {
	// path is the path after the run's id, each segment decoded and escaped again.
	path string
	// post is true for a POST, and limit is its largest body.
	post  bool
	limit int64
	// file is true for a request for a file of an artifact's version.
	file bool
}

// segmentClean reports whether a decoded segment of a path may reach Qory Apiary: not
// empty, not a dot segment, valid UTF-8 with no slash, no backslash and no control
// character.
func segmentClean(s string) bool {
	if s == "" || s == "." || s == ".." || !utf8.ValidString(s) {
		return false
	}
	return !strings.ContainsFunc(s, func(c rune) bool { return c == '/' || c == '\\' || unicode.IsControl(c) })
}

// target reads r as one of the five shapes of the route, and reports whether it is one:
// GET work-item, GET artifacts, GET artifacts/<version_id>/files/<filename>, POST
// artifacts and POST verdict, under /v1/runs/ and the run's id. A request outside them
// reaches nothing: a query, a fragment, user information, a scheme other than http, a
// port other than 80, a segment that fails [segmentClean], another run's id, another
// method, and HTTP/1.0, which has no way to end a file's stream with a read error.
func (a *RunAPI) target(r *http.Request) (runAPITarget, bool) {
	if port := r.URL.Port(); r.URL.Scheme != "http" || r.URL.User != nil || (port != "" && port != "80") || !r.ProtoAtLeast(1, 1) {
		return runAPITarget{}, false
	}
	_, rest, _ := strings.Cut(r.RequestURI, "://")
	_, raw, found := strings.Cut(rest, "/")
	if !found || strings.ContainsAny(raw, "?#") {
		return runAPITarget{}, false
	}
	var parts []string
	for _, escaped := range strings.Split(raw, "/") {
		part, err := url.PathUnescape(escaped)
		if err != nil || !segmentClean(part) {
			return runAPITarget{}, false
		}
		parts = append(parts, part)
	}
	if len(parts) < 4 || parts[0] != "v1" || parts[1] != "runs" || parts[2] != a.RunID {
		return runAPITarget{}, false
	}
	parts = parts[3:]
	get, post := r.Method == http.MethodGet, r.Method == http.MethodPost
	switch {
	case len(parts) == 1 && parts[0] == "work-item" && get:
		return runAPITarget{path: "/work-item"}, true
	case len(parts) == 1 && parts[0] == "artifacts" && get:
		return runAPITarget{path: "/artifacts"}, true
	case len(parts) == 1 && parts[0] == "artifacts" && post:
		return runAPITarget{path: "/artifacts", post: true, limit: maxRunAPIArtifacts}, true
	case len(parts) == 1 && parts[0] == "verdict" && post:
		return runAPITarget{path: "/verdict", post: true, limit: maxRunAPIVerdict}, true
	case len(parts) == 4 && parts[0] == "artifacts" && parts[2] == "files" && get:
		return runAPITarget{path: "/artifacts/" + url.PathEscape(parts[1]) + "/files/" + url.PathEscape(parts[3]), file: true}, true
	}
	return runAPITarget{}, false
}

// admit takes one token of the route's bucket, which holds [RunAPIRate] tokens at most
// and gains that many a second, and reports whether it held one.
func (a *RunAPI) admit() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if d := now.Sub(a.at); d > 0 {
		a.tokens = min(a.tokens+d.Seconds()*RunAPIRate, RunAPIRate)
		a.at = now
	}
	if a.tokens < 1 {
		return false
	}
	a.tokens--
	return true
}

// enter counts one more request in flight, and returns false, counting nothing, at
// [RunAPIInFlight].
func (a *RunAPI) enter() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.inFlight >= RunAPIInFlight {
		return false
	}
	a.inFlight++
	return true
}

// leave counts one request fewer in flight.
func (a *RunAPI) leave() {
	a.mu.Lock()
	a.inFlight--
	a.mu.Unlock()
}

// wait is how long t's request has, from the first byte of its body read.
func (a *RunAPI) wait(t runAPITarget) time.Duration {
	switch {
	case t.file && a.fileWait != 0:
		return a.fileWait
	case t.file:
		return runAPIFileWait
	case a.postWait != 0:
		return a.postWait
	}
	return runAPIPostWait
}

// runAPIError writes one of the route's answers: JSON, its message starting with the fix.
func runAPIError(w http.ResponseWriter, status int, code, message string) {
	b, _ := json.Marshal(struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}{code, message})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(status)
	w.Write(b)
}

// The route's texts. Each starts with the fix, and none contains what a request sent.
const (
	runAPINotFound    = "Send the request over HTTP/1.1 to one of the five run API paths under QORY_RUN_API, with no query: this request is outside them."
	runAPIBucket      = "Retry in 1 second: the run's requests came faster than gateway.run_limits.requests_per_second allows."
	runAPIConnections = "Retry once one of this run's connections closes: the run has as many open as gateway.run_limits.connections allows."
	runAPIUnverified  = "Check the gateway's pin, apiary_public_key, against the keys of Qory Apiary: the answer to this request failed verification under it, and the gateway dropped the answer."
	runAPIUnavailable = "Retry the request: the gateway did not reach Qory Apiary, or the request timed out."
)

// tooLarge is the text of a body over limit.
func tooLarge(limit int64) string {
	return fmt.Sprintf("Shrink the body to at most %d bytes: the run API takes no more on this path.", limit)
}

// shownRunAPI is s as a decision contains it, at most [maxRunAPIShown] bytes.
func shownRunAPI(s string) string { return s[:min(len(s), maxRunAPIShown)] }

// serveRunAPI serves one request of the route: it takes a token of the run's bucket,
// reads the five shapes ([RunAPI.target]), checks the limits, and sends the request
// built from the parsed parts, so no header of the caller's crosses. A request that
// fails a check gets a JSON error, and nothing is signed or sent. The answer passes once
// it verifies, with its status, its body and the headers [runAPIHeaders] lists. Every
// request writes one decision, with no body and no header value in it; a 429 of the
// run's bucket, which spends no token, is recorded as [limiter.recordable] allows.
func (p *Proxy) serveRunAPI(w http.ResponseWriter, r *http.Request, a *RunAPI) {
	shown, ok := policy.CleanPath(r.URL.EscapedPath())
	if !ok {
		shown = r.URL.EscapedPath()
	}
	d := Decision{Host: link.RunAPIHost, Port: 80, Method: "HTTP", Mode: p.rules.Load().mode, Rule: RunAPIRule, Outcome: Refused, Channel: ChannelRunAPI,
		RequestMethod: shownRunAPI(r.Method), Path: shownRunAPI(shown), RequestID: newRequestID()}
	refuse := func(status int, code, message string) {
		d.Status = status
		p.observe(d)
		runAPIError(w, status, code, message)
	}
	if err := p.take(r.Context()); err != nil {
		if p.limits.Load().recordable(RunAPIRule) {
			d.Status = http.StatusTooManyRequests
			p.observe(d)
		}
		runAPIError(w, http.StatusTooManyRequests, "rate_limited", runAPIBucket)
		return
	}
	t, ok := a.target(r)
	if !ok {
		refuse(http.StatusNotFound, "not_found", runAPINotFound)
		return
	}
	if t.post && r.ContentLength > t.limit {
		refuse(http.StatusRequestEntityTooLarge, "payload_too_large", tooLarge(t.limit))
		return
	}
	if !a.admit() {
		refuse(http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("Retry in 1 second: the run sent more than %d run API requests in a second.", RunAPIRate))
		return
	}
	if !p.hold() {
		refuse(http.StatusTooManyRequests, "rate_limited", runAPIConnections)
		return
	}
	defer p.release()
	if !a.enter() {
		refuse(http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("Retry in 1 second: the run has %d run API requests in flight, the most it may have.", RunAPIInFlight))
		return
	}
	defer a.leave()
	if t.post {
		if !a.Posts.enter() {
			refuse(http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("Retry in 1 second: the gateway has %d run API POST requests in flight, the most it takes.", RunAPIPostsInFlight))
			return
		}
		defer a.Posts.leave()
	}
	wait := a.wait(t)
	deadline := time.Now().Add(wait)
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	defer context.AfterFunc(p.stopped, cancel)()
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(deadline)
	defer rc.SetWriteDeadline(time.Time{})
	var body []byte
	if t.post {
		rc.SetReadDeadline(deadline)
		var err error
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, t.limit))
		var over *http.MaxBytesError
		switch {
		case errors.As(err, &over):
			refuse(http.StatusRequestEntityTooLarge, "payload_too_large", tooLarge(t.limit))
			return
		case err != nil:
			// The connection cannot serve another request: part of the body is unread.
			w.Header().Set("Connection", "close")
			refuse(http.StatusServiceUnavailable, "unavailable", runAPIUnavailable)
			return
		}
		rc.SetReadDeadline(time.Time{})
	}
	ans, err := a.Send(ctx, r.Method, t.path, body, t.file)
	d.Allowed = true
	switch {
	case errors.Is(err, server.ErrRunAPIUnverified):
		d.Outcome, d.Status = Connected, http.StatusBadGateway
		p.observe(d)
		runAPIError(w, http.StatusBadGateway, "answer_unverified", runAPIUnverified)
		return
	case err != nil:
		d = failed(d, err)
		d.Status = http.StatusServiceUnavailable
		p.observe(d)
		runAPIError(w, http.StatusServiceUnavailable, "unavailable", runAPIUnavailable)
		return
	}
	d.Outcome, d.Status = Connected, ans.Status
	for _, name := range runAPIHeaders {
		for _, v := range ans.Header.Values(name) {
			w.Header().Add(name, v)
		}
	}
	if ans.File != nil {
		defer ans.File.Close()
		p.streamRunAPI(w, rc, d, ans.File)
		return
	}
	p.observe(d)
	w.Header().Set("Content-Length", strconv.Itoa(len(ans.Body)))
	w.WriteHeader(ans.Status)
	w.Write(ans.Body)
}

// streamRunAPI passes a file to the caller as it reads it, chunked: the status and the
// headers go first, with no Content-Length, so the caller's read ends in the chunk after
// the last one, and the digest can stop it. When file ends in anything other than
// [io.EOF], or the caller goes, the handler aborts before that last chunk, and the
// caller gets a read error, never a clean end of body. A file that fails its digest is
// recorded with status 502, and one whose stream failed with 503.
func (p *Proxy) streamRunAPI(w http.ResponseWriter, rc *http.ResponseController, d Decision, file io.Reader) {
	w.WriteHeader(d.Status)
	rc.Flush()
	if _, err := io.Copy(w, file); err != nil {
		switch {
		case errors.Is(err, server.ErrRunAPIUnverified):
			d.Status = http.StatusBadGateway
		default:
			d.Status = http.StatusServiceUnavailable
		}
		p.observe(d)
		panic(http.ErrAbortHandler)
	}
	p.observe(d)
}
