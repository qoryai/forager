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
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/qoryai/forager/accesskey"
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
	// RunAPIPostsPerRun is the most POSTs one run has in flight through the route, among
	// its [RunAPIInFlight].
	RunAPIPostsPerRun = 1
	// RunAPIArtifactSends is the most POST artifacts one gateway sends to Qory Apiary at
	// once: from the body read whole to the answer read.
	RunAPIArtifactSends = 8
	// RunAPIGatewayRate is the most requests of the route one gateway signs in a second,
	// beyond a burst of as many. Qory Apiary's bucket for one key refills 50 a second, so
	// a run's start on the same key keeps its tokens.
	RunAPIGatewayRate = 20
	// runAPIQueueWait is how long a request waits for a send slot, and for a token of the
	// gateway's bucket.
	runAPIQueueWait = 5 * time.Second
	runAPIPostWait  = 60 * time.Second
	runAPIFileWait  = 10 * time.Minute
)

// maxRunAPIShown is the most bytes of a request's method a decision contains. A
// decision's path is one of the five shapes, under [maxRunAPITarget].
const maxRunAPIShown = 2048

// maxRunAPITarget is the longest request target the route takes, as sent.
const maxRunAPITarget = 4 << 10

// runAPIOutside is the path of the decision of a request outside the five shapes, whose
// path is the caller's choice.
const runAPIOutside = "outside"

// runAPIHeaders are the headers of Qory Apiary's answer the route passes, beside
// Content-Length.
var runAPIHeaders = []string{"Content-Type", "Content-Disposition", "X-Content-Type-Options", "Content-Security-Policy", "Retry-After"}

// errRunAPIBusy is the error of a request that waited [runAPIQueueWait] for a send slot
// or a token of the gateway's bucket and got none.
var errRunAPIBusy = errors.New("the gateway's run API limits refused the request")

// RunAPILimits are the limits of the route that one gateway shares across its runs: the
// send slots of POST artifacts and the bucket of signed requests. The zero value is
// ready to use.
type RunAPILimits struct {
	// now, sleep and queueWait, when set, replace the clock, the timer and the 5 seconds
	// a request waits. Tests set them.
	now       func() time.Time
	sleep     func(ctx context.Context, d time.Duration) bool
	queueWait time.Duration

	once  sync.Once
	slots chan struct{}

	mu sync.Mutex
	// tokens is below zero while requests wait: each waiting request took one ahead, so
	// requests get their tokens in the order they came.
	tokens float64
	at     time.Time
}

// start sets what the zero value leaves unset.
func (l *RunAPILimits) start() {
	l.once.Do(func() {
		l.slots = make(chan struct{}, RunAPIArtifactSends)
		l.tokens = RunAPIGatewayRate
		if l.now == nil {
			l.now = time.Now
		}
		if l.sleep == nil {
			l.sleep = sleep
		}
		if l.queueWait == 0 {
			l.queueWait = runAPIQueueWait
		}
		l.at = l.now()
	})
}

// enter takes one send slot, and waits for one up to the queue wait. Requests get slots
// in the order they came. It returns [errRunAPIBusy] after the wait, or ctx's error; a
// nil error is followed by one leave.
func (l *RunAPILimits) enter(ctx context.Context) error {
	l.start()
	select {
	case l.slots <- struct{}{}:
		return nil
	default:
	}
	t := time.NewTimer(l.queueWait)
	defer t.Stop()
	select {
	case l.slots <- struct{}{}:
		return nil
	case <-t.C:
		return errRunAPIBusy
	case <-ctx.Done():
		return ctx.Err()
	}
}

// leave gives one send slot back.
func (l *RunAPILimits) leave() { <-l.slots }

// take takes one token of the gateway's bucket, which holds [RunAPIGatewayRate] tokens at
// most and gains that many a second, and waits for its token up to the queue wait. It
// returns [errRunAPIBusy] when the wait would be longer, at once, or ctx's error.
func (l *RunAPILimits) take(ctx context.Context) error {
	l.start()
	l.mu.Lock()
	now := l.now()
	if d := now.Sub(l.at); d > 0 {
		l.tokens = min(l.tokens+d.Seconds()*RunAPIGatewayRate, RunAPIGatewayRate)
		l.at = now
	}
	wait := time.Duration((1 - l.tokens) / RunAPIGatewayRate * float64(time.Second))
	if l.tokens >= 1 {
		wait = 0
	}
	if wait > l.queueWait {
		l.mu.Unlock()
		return errRunAPIBusy
	}
	l.tokens--
	l.mu.Unlock()
	if wait > 0 && !l.sleep(ctx, wait) {
		l.mu.Lock()
		l.tokens = min(l.tokens+1, RunAPIGatewayRate)
		l.mu.Unlock()
		return ctx.Err()
	}
	return nil
}

// RunAPI is the route of one run's proxy to Qory Apiary's run API: the run's id, how a
// request is sent, signed, and the gateway's limits. The gateway makes one for a run
// with a control plane ([Proxy.SetRunAPI]); a stack proxy has none.
type RunAPI struct {
	RunID string
	// Send signs one request and sends it, as [server.Client.RunAPI] does. path is
	// escaped and starts after the run's id.
	Send func(ctx context.Context, method, path string, body []byte, file bool) (*server.RunAPIAnswer, error)
	// Limits are the limits the run shares with the gateway's other runs.
	Limits *RunAPILimits

	// postWait and fileWait, when set, replace the 60 seconds and the 10 minutes; now,
	// when set, is the clock of the rate limit. Tests set them.
	postWait, fileWait time.Duration
	now                func() time.Time

	mu       sync.Mutex
	inFlight int
	posting  bool
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
	// path is the path after the run's id, each segment decoded and escaped again, and
	// shown the same with a segment that contains a secret in [accesskey.ShownValue]'s
	// form, read from the decoded segment: what a decision contains.
	path, shown string
	// post is true for a POST, and limit is its largest body.
	post  bool
	limit int64
	// slot is true for a request that takes a send slot: POST artifacts.
	slot bool
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

// shownSegment is the decoded segment s as a decision contains it.
func shownSegment(s string) string {
	if accesskey.ContainsSecret(s) {
		return accesskey.ShownValue(s, false)
	}
	return url.PathEscape(s)
}

// target reads r as one of the five shapes of the route, and reports whether it is one:
// GET work-item, GET artifacts, GET artifacts/<version_id>/files/<filename>, POST
// artifacts and POST verdict, under /v1/runs/ and the run's id. A request outside them
// reaches nothing: a target over [maxRunAPITarget], a query, a fragment, user
// information, a scheme other than http, a port other than 80, a segment that fails
// [segmentClean], another run's id, another method, and an HTTP/1.0 request that reaches
// the proxy, which has no way to end a file's stream with a read error. A forwarder
// without a wall sends every plain request as HTTP/1.1, so only a walled program's
// HTTP/1.0 reaches the proxy as it is.
func (a *RunAPI) target(r *http.Request) (runAPITarget, bool) {
	port := r.URL.Port()
	if len(r.RequestURI) > maxRunAPITarget || r.URL.Scheme != "http" || r.URL.User != nil || (port != "" && port != "80") ||
		r.URL.RawQuery != "" || r.URL.ForceQuery || !r.ProtoAtLeast(1, 1) {
		return runAPITarget{}, false
	}
	_, rest, _ := strings.Cut(r.RequestURI, "://")
	// The path starts at the authority's end. A query or a fragment there may contain
	// anything, a whole path of the five shapes among it.
	end := strings.IndexAny(rest, "/?#")
	if end < 0 || rest[end] != '/' {
		return runAPITarget{}, false
	}
	raw := rest[end+1:]
	if strings.ContainsAny(raw, "?#") {
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
		return runAPITarget{path: "/work-item", shown: "/work-item"}, true
	case len(parts) == 1 && parts[0] == "artifacts" && get:
		return runAPITarget{path: "/artifacts", shown: "/artifacts"}, true
	case len(parts) == 1 && parts[0] == "artifacts" && post:
		return runAPITarget{path: "/artifacts", shown: "/artifacts", post: true, limit: maxRunAPIArtifacts, slot: true}, true
	case len(parts) == 1 && parts[0] == "verdict" && post:
		return runAPITarget{path: "/verdict", shown: "/verdict", post: true, limit: maxRunAPIVerdict}, true
	case len(parts) == 4 && parts[0] == "artifacts" && parts[2] == "files" && get:
		return runAPITarget{path: "/artifacts/" + url.PathEscape(parts[1]) + "/files/" + url.PathEscape(parts[3]),
			shown: "/artifacts/" + shownSegment(parts[1]) + "/files/" + shownSegment(parts[3]), file: true}, true
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

// enterPost takes the run's one POST slot, and returns false when another POST of the
// run holds it. The slot counts among the run's [RunAPIInFlight], so a stalled body
// holds this run's slot and no slot of the gateway.
func (a *RunAPI) enterPost() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.posting {
		return false
	}
	a.posting = true
	return true
}

// leavePost gives the run's POST slot back.
func (a *RunAPI) leavePost() {
	a.mu.Lock()
	a.posting = false
	a.mu.Unlock()
}

// send signs and sends one request, once the gateway's limits allow it: POST artifacts
// holds a send slot until its answer is read, which [RunAPI.Send] does for a POST, and
// every request takes a token of the gateway's bucket. sent is false when nothing was
// signed: err is [errRunAPIBusy] when a limit had no room, or ctx's error.
func (a *RunAPI) send(ctx context.Context, method string, t runAPITarget, body []byte) (ans *server.RunAPIAnswer, sent bool, err error) {
	if t.slot {
		if err := a.Limits.enter(ctx); err != nil {
			return nil, false, err
		}
		defer a.Limits.leave()
	}
	if err := a.Limits.take(ctx); err != nil {
		return nil, false, err
	}
	ans, err = a.Send(ctx, method, t.path, body, t.file)
	return ans, true, err
}

// wait is how long t's request has from the moment the route admits it: the read of a
// POST's body, any wait for a slot or a token, and the send all count.
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
	runAPITooLarge    = "Check the size of the work item's data in Qory Apiary: the answer is over the bound the gateway reads, 16 MiB for a 200 and 64 KiB for any other status, and the gateway dropped the answer."
	runAPIUnavailable = "Retry the request: the gateway did not reach Qory Apiary, or the request timed out."
)

// The texts of a 403 to the host: on a proxy with the route, which a CONNECT reaches, and
// on a proxy with none.
const (
	runAPIDenied  = "qory: send run API requests as plain http:// requests to QORY_RUN_API through the run's proxy: a CONNECT to this host opens no tunnel.\n"
	runAPINoRoute = "qory: use QORY_RUN_API in a run with a control plane: this proxy has no route to the run API.\n"
)

// tooLarge is the text of a body over limit.
func tooLarge(limit int64) string {
	return fmt.Sprintf("Shrink the body to at most %d bytes: the run API takes no more on this path.", limit)
}

// runAPIBusy is the text of a request that found the gateway's limits full.
func runAPIBusy() string {
	return fmt.Sprintf("Retry in 1 second: the gateway signs at most %d run API requests a second and sends %d artifacts at once.", RunAPIGatewayRate, RunAPIArtifactSends)
}

// shownMethod is a method as a decision contains it, at most [maxRunAPIShown] bytes.
func shownMethod(s string) string { return s[:min(len(s), maxRunAPIShown)] }

// serveRunAPI serves one request of the route: it reads the five shapes
// ([RunAPI.target]), takes a token of the run's bucket, checks the limits, and sends the
// request built from the parsed parts, so no header of the caller's crosses. A request
// that fails a check gets a JSON error, and nothing is signed or sent. The answer passes
// once it verifies, with its status, its body and the headers [runAPIHeaders] lists.
// Every request writes one decision, with no body and no header value in it: a request
// inside the shapes with its canonical path, and one outside them with
// [runAPIOutside]. A 429 of the run's bucket, which spends no token, is recorded as
// [limiter.recordable] allows.
func (p *Proxy) serveRunAPI(w http.ResponseWriter, r *http.Request, a *RunAPI) {
	t, inside := a.target(r)
	d := Decision{Host: link.RunAPIHost, Port: 80, Method: "HTTP", Mode: p.rules.Load().mode, Rule: RunAPIRule, Outcome: Refused, Channel: ChannelRunAPI,
		RequestMethod: shownMethod(r.Method), Path: runAPIOutside, RequestID: newRequestID()}
	if inside {
		d.Path = "/v1/runs/" + a.RunID + t.shown
	}
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
	if !inside {
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
		if !a.enterPost() {
			refuse(http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("Retry in 1 second: the run has %d run API POST request in flight, the most it may have.", RunAPIPostsPerRun))
			return
		}
		defer a.leavePost()
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
	ans, sent, err := a.send(ctx, r.Method, t, body)
	if !sent {
		if errors.Is(err, errRunAPIBusy) {
			refuse(http.StatusTooManyRequests, "rate_limited", runAPIBusy())
			return
		}
		refuse(http.StatusServiceUnavailable, "unavailable", runAPIUnavailable)
		return
	}
	d.Allowed = true
	switch {
	case errors.Is(err, server.ErrRunAPIUnverified):
		d.Outcome, d.Status = Connected, http.StatusBadGateway
		p.observe(d)
		runAPIError(w, http.StatusBadGateway, "answer_unverified", runAPIUnverified)
		return
	case errors.Is(err, server.ErrRunAPITooLarge):
		d.Outcome, d.Status = Connected, http.StatusBadGateway
		p.observe(d)
		runAPIError(w, http.StatusBadGateway, "answer_too_large", runAPITooLarge)
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
