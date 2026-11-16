package session

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// The limits of the route to [link.QoryHost], OpenSpec.QoryRoute.
const (
	// qoryHostRate is the most requests one run sends through the route in a second,
	// beyond a burst of as many.
	qoryHostRate = 10
	// qoryHostInFlight is the most requests one run has in flight through the route.
	qoryHostInFlight = 4
	// qoryHostWait is how long a request has from its head's read to the handler's
	// return: the body's read and the handler's call.
	qoryHostWait = 30 * time.Second
	// maxQoryHostPath is the most bytes of a request's path its record has.
	maxQoryHostPath = 1 << 10
	// qoryHostRecordEvery is the interval in which at most one refusal of each status,
	// 400, 429 and 503, is recorded.
	qoryHostRecordEvery = time.Second
	// qoryHostAgentWait is how long the enclosure has to report the addresses of the
	// agent's container, wall.AgentAddresser.
	qoryHostAgentWait = 10 * time.Second
)

// The codes of the forwarder's answers on the route.
const (
	qoryHostBadRequest  = "bad_request"
	qoryHostNoSession   = "session_not_running"
	qoryHostRateLimited = "rate_limited"
	qoryHostTooLarge    = "payload_too_large"
	qoryHostTimeout     = "timeout"
	qoryHostBadAnswer   = "bad_answer"
)

// The forwarder's texts on the route. Each starts with the fix.
var (
	qoryHostBadTarget = "Send the request over HTTP/1.1 to " + link.QoryHostURL + "/ as " + link.EnvQoryHost + " has it: the run's proxy reads no other form of a request to that host."
	qoryHostBadHost   = "Send one Host header, " + link.QoryHost + ", with the request: the run's proxy reads no other Host for a request to " + link.EnvQoryHost + "."
	qoryHostBadHeader = "Send each header of the request on one line that ends in CRLF, with a valid name and no control characters: the run's proxy reads no folded line and no bare CR or LF."
	qoryHostBadLength = "Send the body with at most one Content-Length header and no Transfer-Encoding: the run's proxy reads a request to " + link.EnvQoryHost + " whole before it passes the request on."
	qoryHostBadBody   = "Send the whole body within 30 seconds: the run's proxy reads it whole before it passes the request on."
	qoryHostNoRun     = "Send requests to " + link.EnvQoryHost + " while a session of the run runs: no session runs, so the request reached no handler."
	qoryHostRateText  = fmt.Sprintf("Retry in 1 second: the run sent more than %d requests to %s in a second.", qoryHostRate, link.EnvQoryHost)
	qoryHostFlight    = fmt.Sprintf("Retry in 1 second: the run has %d requests to %s in flight, the most it may have.", qoryHostInFlight, link.EnvQoryHost)
	qoryHostLarge     = fmt.Sprintf("Shrink the body to at most %d bytes: the run's proxy takes no more on %s.", link.MaxQoryHostBody, link.EnvQoryHost)
	qoryHostSlow      = "Send the request again later: the handler did not return within 30 seconds."
	qoryHostBig       = fmt.Sprintf("Report this to whoever runs qory: the handler's answer has more than %d bytes, which the run's proxy does not pass on.", link.MaxQoryHostBody)
	qoryHostBadStatus = "Report this to whoever runs qory: the handler answered with a status outside 200 to 599, or 407, which the run's proxy does not pass on."
	qoryHostPanicked  = "Report this to whoever runs qory: the handler failed before it answered."
)

// qoryRoute is a run's route to OpenSpec.QoryRoute, which the run's forwarders share:
// the run's wall forwarder, and the forwarder of each unwalled session. It holds the
// session that runs, the passwords of the walled sessions' proxy URLs, the run's
// limits, and how a request is recorded.
type qoryRoute struct {
	handler http.Handler
	// record writes a decision of the route, a dev.qory.run.egress, which it completes
	// with the policy's mode.
	record func(data map[string]any)
	// report gets a line for a handler that panicked.
	report func(string)
	// done ends when the run closes.
	done context.Context
	// wait and now, when set, replace [qoryHostWait] and the clock of the rate limit.
	// Tests set them.
	wait time.Duration
	now  func() time.Time

	mu sync.Mutex
	// session is the number of the session whose launch runs, 0 for none, and ctx ends
	// when that session ends.
	session int
	ctx     context.Context
	// passwords are the passwords of the proxy URLs of the run's walled sessions with a
	// route, by session number: behind a wall the forwarder serves a request only with
	// one of them.
	passwords map[int]string
	// agent, behind a wall, returns the addresses of the agent's container of the
	// session that runs, wall.AgentAddresser; addrs are what it returned for that
	// session, by session number, until the session ends. Behind a wall the forwarder
	// serves a request of the session that runs only from one of them, so a program
	// outside the agent's container that holds the password, such as one in the setup
	// container, never reaches the handler. lookup lets one call of agent run at a time.
	agent  func(context.Context) ([]netip.Addr, error)
	addrs  map[int][]netip.Addr
	lookup sync.Mutex
	// inFlight counts the handler's calls that have not returned.
	inFlight int
	tokens   float64
	at       time.Time
	// recorded is when a refusal of each status, 400, 429 and 503, was last recorded.
	recorded map[int]time.Time
}

// newQoryRoute is the route to handler of a run that closes with done.
func newQoryRoute(handler http.Handler, done context.Context, record func(map[string]any), report func(string)) *qoryRoute {
	return &qoryRoute{handler: handler, done: done, record: record, report: report}
}

// open opens the route to session n, whose launch starts, and returns what closes it
// again, before the session's end is written. password, behind a wall, is the password
// of the session's proxy URL, which a request to the route must carry; without a wall it
// is empty, since the session's forwarder serves that session alone. A nil route opens
// nothing.
func (q *qoryRoute) open(n int, password string) (closeRoute func()) {
	if q == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(q.done)
	q.mu.Lock()
	q.session, q.ctx = n, ctx
	if password != "" {
		if q.passwords == nil {
			q.passwords = map[int]string{}
		}
		q.passwords[n] = password
	}
	q.mu.Unlock()
	return sync.OnceFunc(func() {
		q.mu.Lock()
		if q.session == n {
			q.session, q.ctx = 0, nil
		}
		delete(q.addrs, n)
		q.mu.Unlock()
		cancel()
	})
}

// current is the session whose launch runs, 0 for none, with the context that ends
// with it.
func (q *qoryRoute) current() (int, context.Context) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.session, q.ctx
}

// sessionOf is the walled session whose proxy URL's password logins, the values of a
// request's Proxy-Authorization headers, carry: exactly one, Basic, compared in
// constant time with each session's. For the session that runs, peer, the address the
// relay wrote for the connection, must also be an address of that session's agent's
// container ([qoryRoute.fromAgent]). It is 0 for none, so the request goes to the
// gateway's proxy, which denies the route's host, as in a run with no route. A
// password of a session that has ended passes without the address, since
// [qoryRoute.serve] answers 503 to it and calls no handler.
func (q *qoryRoute) sessionOf(ctx context.Context, logins []string, peer netip.Addr) int {
	if len(logins) != 1 {
		return 0
	}
	q.mu.Lock()
	found := 0
	for n, password := range q.passwords {
		if proxyLogin(logins[0], password) {
			found = n
		}
	}
	current := q.session
	q.mu.Unlock()
	if found == 0 || found != current {
		return found
	}
	if !q.fromAgent(ctx, found, peer) {
		return 0
	}
	return found
}

// fromAgent reports whether peer is an address of the agent's container of session n,
// which [qoryRoute.agent] returns: once per session, kept until the session ends. A
// route with no agent, an invalid peer and a failed call are false, and a failed call
// is made again for the next request.
func (q *qoryRoute) fromAgent(ctx context.Context, n int, peer netip.Addr) bool {
	if q.agent == nil || !peer.IsValid() {
		return false
	}
	q.lookup.Lock()
	defer q.lookup.Unlock()
	q.mu.Lock()
	addrs, ok := q.addrs[n]
	q.mu.Unlock()
	if !ok {
		ctx, cancel := context.WithTimeout(ctx, qoryHostAgentWait)
		got, err := q.agent(ctx)
		cancel()
		if err != nil {
			return false
		}
		q.mu.Lock()
		if q.session == n {
			if q.addrs == nil {
				q.addrs = map[int][]netip.Addr{}
			}
			q.addrs[n] = got
		}
		q.mu.Unlock()
		addrs = got
	}
	return slices.Contains(addrs, peer.Unmap())
}

// clock is the time the rate limit and the records' limit read.
func (q *qoryRoute) clock() time.Time {
	if q.now != nil {
		return q.now()
	}
	return time.Now()
}

// recordRefusal reports whether a refusal of status is recorded: every refusal but one
// of 400, 429 or 503 that follows another of the same status within
// [qoryHostRecordEvery], so a program at a limit adds at most one event a second per
// status to the record, as the gateway's proxy does for its limits.
func (q *qoryRoute) recordRefusal(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusTooManyRequests, http.StatusServiceUnavailable:
	default:
		return true
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.clock()
	if last, ok := q.recorded[status]; ok && now.Sub(last) < qoryHostRecordEvery && !now.Before(last) {
		return false
	}
	if q.recorded == nil {
		q.recorded = map[int]time.Time{}
	}
	q.recorded[status] = now
	return true
}

// admit takes one of the run's tokens, which number [qoryHostRate] at most and gain
// that many a second, and reports whether it held one.
func (q *qoryRoute) admit() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.clock()
	if q.at.IsZero() {
		q.tokens, q.at = qoryHostRate, now
	}
	if d := now.Sub(q.at); d > 0 {
		q.tokens = min(q.tokens+d.Seconds()*qoryHostRate, qoryHostRate)
		q.at = now
	}
	if q.tokens < 1 {
		return false
	}
	q.tokens--
	return true
}

// enter counts one more call of the handler in flight, and returns false, counting
// nothing, at [qoryHostInFlight].
func (q *qoryRoute) enter() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.inFlight >= qoryHostInFlight {
		return false
	}
	q.inFlight++
	return true
}

// leave counts one call of the handler fewer in flight, once it returned.
func (q *qoryRoute) leave() {
	q.mu.Lock()
	q.inFlight--
	q.mu.Unlock()
}

// waitFor is how long a request has from its head's read to the handler's return.
func (q *qoryRoute) waitFor() time.Duration {
	if q.wait == 0 {
		return qoryHostWait
	}
	return q.wait
}

// forQoryHost reports whether head, the head of a plain request that
// [checkRequestLine] accepts, names the route's host in any reading: the target's
// authority as sent, the host net/http decodes from it, or a Host header. Each such
// request goes to [qoryRoute.serve], which reads it as net/http does or answers 400, so
// no reading of the host sends a request for it to the gateway's proxy, which would
// deny it.
func forQoryHost(head []byte) bool {
	line, _, _ := bytes.Cut(head, []byte("\n"))
	_, rest, _ := strings.Cut(string(bytes.TrimSuffix(line, []byte("\r"))), " ")
	target, _, _ := strings.Cut(rest, " ")
	hosts := []string{authorityHost(targetAuthority(target))}
	if u, err := url.ParseRequestURI(target); err == nil {
		hosts = append(hosts, u.Hostname())
	}
	for _, l := range bytes.Split(head, []byte("\n"))[1:] {
		if name, value, ok := bytes.Cut(l, []byte(":")); ok && strings.EqualFold(string(bytes.TrimSpace(name)), "Host") {
			hosts = append(hosts, authorityHost(string(bytes.TrimSpace(value))))
		}
	}
	for _, h := range hosts {
		if got, ok := policy.Host(h); ok && got == link.QoryHost {
			return true
		}
	}
	return false
}

// qoryHostPrefix is the start of every target the route reads.
const qoryHostPrefix = link.QoryHostURL + "/"

// qoryHostRequest is a request to the route, read from its head.
type qoryHostRequest struct {
	req *http.Request
	// length is the body's length.
	length int64
	// expect is true for a request that waits for a 100 Continue before its body.
	expect bool
}

// readQoryHostRequest reads head, the head of a request that [forQoryHost] accepts, so
// that one reading of it holds: a target that starts with http://host.qory.invalid/,
// HTTP/1.1, each line ending in CRLF with no other CR or LF, no folded line, header
// names that are tokens and values without control characters, one Host header that
// is the route's host, and at most one Content-Length, a decimal number, with no
// Transfer-Encoding. Its error is the text of the forwarder's 400.
func readQoryHostRequest(head []byte) (qoryHostRequest, error) {
	lines := bytes.SplitAfter(head, []byte("\n"))
	lines = lines[:len(lines)-1]
	for _, l := range lines {
		if !bytes.HasSuffix(l, []byte("\r\n")) || bytes.Count(l, []byte("\r")) != 1 {
			return qoryHostRequest{}, errors.New(qoryHostBadHeader)
		}
	}
	method, rest, _ := strings.Cut(string(bytes.TrimSuffix(lines[0], []byte("\r\n"))), " ")
	target, version, _ := strings.Cut(rest, " ")
	if !validToken([]byte(method)) || version != "HTTP/1.1" || !strings.HasPrefix(target, qoryHostPrefix) {
		return qoryHostRequest{}, errors.New(qoryHostBadTarget)
	}
	var hosts, lengths []string
	p := qoryHostRequest{}
	for _, l := range lines[1 : len(lines)-1] {
		l = bytes.TrimSuffix(l, []byte("\r\n"))
		name, value, found := bytes.Cut(l, []byte(":"))
		if !found || !validToken(name) || !validValue(value) {
			return qoryHostRequest{}, errors.New(qoryHostBadHeader)
		}
		v := strings.Trim(string(value), " \t")
		switch {
		case strings.EqualFold(string(name), "Host"):
			hosts = append(hosts, v)
		case strings.EqualFold(string(name), "Content-Length"):
			lengths = append(lengths, v)
		case strings.EqualFold(string(name), "Transfer-Encoding"):
			return qoryHostRequest{}, errors.New(qoryHostBadLength)
		case strings.EqualFold(string(name), "Expect"):
			p.expect = strings.EqualFold(v, "100-continue")
		}
	}
	if len(hosts) != 1 || !strings.EqualFold(hosts[0], link.QoryHost) {
		return qoryHostRequest{}, errors.New(qoryHostBadHost)
	}
	if len(lengths) > 1 {
		return qoryHostRequest{}, errors.New(qoryHostBadLength)
	}
	if len(lengths) == 1 {
		n, err := strconv.ParseUint(lengths[0], 10, 63)
		if err != nil || strings.TrimLeft(lengths[0], "0123456789") != "" {
			return qoryHostRequest{}, errors.New(qoryHostBadLength)
		}
		p.length = int64(n)
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(head)))
	if err != nil {
		return qoryHostRequest{}, errors.New(qoryHostBadHeader)
	}
	if !strings.EqualFold(req.Host, link.QoryHost) || req.URL.Host != link.QoryHost {
		return qoryHostRequest{}, errors.New(qoryHostBadHost)
	}
	if req.ContentLength != p.length || len(req.TransferEncoding) != 0 {
		return qoryHostRequest{}, errors.New(qoryHostBadLength)
	}
	p.req = req
	return p, nil
}

// qoryHostAnswer is the handler's answer, kept until the handler returns: at most
// [link.MaxQoryHostBody] bytes of its body.
type qoryHostAnswer struct {
	header http.Header
	status int
	body   bytes.Buffer
	over   bool
}

// errQoryHostAnswer is the error of a write past [link.MaxQoryHostBody].
var errQoryHostAnswer = errors.New("the answer is over the route's limit")

// Header returns the answer's header, of which the program gets Content-Type alone.
func (a *qoryHostAnswer) Header() http.Header { return a.header }

// WriteHeader keeps the first status the handler writes, but a 1xx other than 101,
// which net/http sends ahead of the answer and the forwarder drops.
func (a *qoryHostAnswer) WriteHeader(status int) {
	if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
		return
	}
	if a.status == 0 {
		a.status = status
	}
}

// Write keeps b in the body, or returns errQoryHostAnswer and marks the answer over
// the limit when the body would pass [link.MaxQoryHostBody].
func (a *qoryHostAnswer) Write(b []byte) (int, error) {
	a.WriteHeader(http.StatusOK)
	if a.over || int64(a.body.Len()+len(b)) > link.MaxQoryHostBody {
		a.over = true
		return 0, errQoryHostAnswer
	}
	return a.body.Write(b)
}

// serve answers one request to the route whose head is head and whose body follows in
// from, on the program's connection c, and records it. n is the session the request
// comes from: the session of an unwalled forwarder, or the walled session whose proxy
// password the request carried. Only while n runs does the handler get it. The
// connection carries this one request.
func (q *qoryRoute) serve(c net.Conn, head []byte, from *bufio.Reader, n int) {
	start := time.Now()
	d := map[string]any{
		"host": link.QoryHost, "port": 80, "method": "HTTP",
		"request_method": "outside", "path": "outside", "request_id": newQoryRequestID(),
		"channel": link.QoryHostChannel, "rule": link.QoryHostRule,
		"decision": "denied", "outcome": "refused",
	}
	// noBody is true for a HEAD, whose answer has no body.
	noBody := false
	refuse := func(status int, code, text string, unread int64) {
		d["status"] = status
		if q.recordRefusal(status) {
			q.record(d)
		}
		writeQoryHostError(c, from, unread, status, code, text, noBody)
	}
	p, err := readQoryHostRequest(head)
	if err != nil {
		refuse(http.StatusBadRequest, qoryHostBadRequest, err.Error(), -1)
		return
	}
	noBody = p.req.Method == http.MethodHead
	d["request_method"], d["path"] = shownQoryMethod(p.req.Method), shownQoryPath(p.req.URL)
	current, sessionCtx := q.current()
	if current == 0 || current != n {
		refuse(http.StatusServiceUnavailable, qoryHostNoSession, qoryHostNoRun, p.length)
		return
	}
	if !q.admit() {
		refuse(http.StatusTooManyRequests, qoryHostRateLimited, qoryHostRateText, p.length)
		return
	}
	if p.length > link.MaxQoryHostBody {
		refuse(http.StatusRequestEntityTooLarge, qoryHostTooLarge, qoryHostLarge, p.length)
		return
	}
	deadline := start.Add(q.waitFor())
	if p.expect {
		c.SetWriteDeadline(time.Now().Add(link.PreambleWait))
		if _, err := io.WriteString(c, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			return
		}
		c.SetWriteDeadline(time.Time{})
	}
	c.SetReadDeadline(deadline)
	// The buffer grows as the body arrives, so a Content-Length alone costs nothing.
	buf := bytes.NewBuffer(make([]byte, 0, min(p.length, 64<<10)))
	if _, err := io.CopyN(buf, from, p.length); err != nil {
		c.SetReadDeadline(time.Time{})
		refuse(http.StatusBadRequest, qoryHostBadRequest, qoryHostBadBody, 0)
		return
	}
	c.SetReadDeadline(time.Time{})
	// A session that ended while the body arrived gets no call, whatever runs now.
	if sessionCtx.Err() != nil {
		refuse(http.StatusServiceUnavailable, qoryHostNoSession, qoryHostNoRun, 0)
		return
	}
	// The slot is the handler's: it is taken once the body is read, and freed when the
	// handler returns, also after the forwarder stopped waiting for it.
	if !q.enter() {
		refuse(http.StatusTooManyRequests, qoryHostRateLimited, qoryHostFlight, 0)
		return
	}
	ctx, cancel := context.WithDeadline(sessionCtx, deadline)
	defer cancel()
	ans, called, err := q.call(ctx, p.req, buf.Bytes(), n)
	if called {
		d["decision"] = "allowed"
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded) && sessionCtx.Err() == nil:
		refuse(http.StatusGatewayTimeout, qoryHostTimeout, qoryHostSlow, maxProxyHead)
		return
	case err != nil && ctx.Err() != nil:
		refuse(http.StatusServiceUnavailable, qoryHostNoSession, qoryHostNoRun, maxProxyHead)
		return
	}
	d["outcome"] = "connected"
	switch {
	case err != nil:
		refuse(http.StatusBadGateway, qoryHostBadAnswer, qoryHostPanicked, maxProxyHead)
		return
	case ans.over:
		refuse(http.StatusBadGateway, qoryHostBadAnswer, qoryHostBig, maxProxyHead)
		return
	}
	status := cmpStatus(ans.status)
	if status < 200 || status > 599 || status == http.StatusProxyAuthRequired {
		refuse(http.StatusBadGateway, qoryHostBadAnswer, qoryHostBadStatus, maxProxyHead)
		return
	}
	d["status"] = status
	q.record(d)
	writeQoryHostReply(c, from, maxProxyHead, status, ans.header.Get("Content-Type"), ans.body.Bytes(), noBody)
}

// cmpStatus is the status of an answer whose handler wrote nothing: 200, as net/http
// answers.
func cmpStatus(status int) int {
	if status == 0 {
		return http.StatusOK
	}
	return status
}

// errQoryHostPanic is the error of a handler that panicked.
var errQoryHostPanic = errors.New("the handler panicked")

// call calls the handler with the request read from req, the body and the session's
// number, under ctx, and returns its answer once it returns, or ctx's error once ctx
// ends first: the forwarder does not wait for a handler that outlasts it. It takes over
// the slot [qoryRoute.enter] took, and frees it when the handler returns, or at once when
// ctx ended before the call, which then does not start and called is false. A panic is a
// Report line and [errQoryHostPanic].
func (q *qoryRoute) call(ctx context.Context, read *http.Request, body []byte, n int) (ans *qoryHostAnswer, called bool, err error) {
	if err := ctx.Err(); err != nil {
		q.leave()
		return nil, false, err
	}
	u := &url.URL{Scheme: "http", Host: link.QoryHost, Path: read.URL.Path, RawPath: read.URL.RawPath, RawQuery: read.URL.RawQuery}
	header := http.Header{}
	if ct := read.Header.Values("Content-Type"); len(ct) > 0 {
		header["Content-Type"] = ct
	}
	header.Set(link.QorySessionHeader, strconv.Itoa(n))
	var rc io.ReadCloser = http.NoBody
	if len(body) > 0 {
		rc = io.NopCloser(bytes.NewReader(body))
	}
	req := (&http.Request{
		Method: read.Method, URL: u, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: header, Body: rc, ContentLength: int64(len(body)), Host: link.QoryHost,
		RequestURI: u.RequestURI(),
	}).WithContext(ctx)
	// The handler writes to answer, a variable of this call alone: the goroutine may
	// outlast the call, whose results it must not touch.
	answer := &qoryHostAnswer{header: http.Header{}}
	done := make(chan error, 1)
	go func() {
		defer q.leave()
		defer func() {
			if v := recover(); v != nil {
				if q.report != nil && v != http.ErrAbortHandler {
					q.report(fmt.Sprintf("the handler of %s panicked: %v", link.QoryHost, v))
				}
				done <- errQoryHostPanic
			}
		}()
		q.handler.ServeHTTP(answer, req)
		done <- nil
	}()
	select {
	case err := <-done:
		if err == nil && ctx.Err() != nil {
			// A handler that returned after its context ended outlasted it.
			return nil, true, ctx.Err()
		}
		return answer, true, err
	case <-ctx.Done():
		return nil, true, ctx.Err()
	}
}

// newQoryRequestID is a request's id in its record: 16 random bytes in lower-case hex.
func newQoryRequestID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// shownQoryMethod is a request's method as its record has it: a standard one as sent,
// and outside for any other, which the caller chose.
func shownQoryMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodTrace:
		return m
	}
	return "outside"
}

// shownQoryPath is a request's path as its record has it: without the query, each
// segment decoded and escaped again, a segment that decodes to a secret as its phrase,
// cut at [maxQoryHostPath] bytes.
func shownQoryPath(u *url.URL) string {
	var b strings.Builder
	for _, escaped := range strings.Split(strings.TrimPrefix(u.EscapedPath(), "/"), "/") {
		part, err := url.PathUnescape(escaped)
		if err != nil {
			part = escaped
		}
		b.WriteString("/")
		if accesskey.ContainsSecret(part) {
			b.WriteString(accesskey.ShownValue(part, false))
		} else {
			b.WriteString(url.PathEscape(part))
		}
		if b.Len() > maxQoryHostPath {
			break
		}
	}
	s := b.String()
	if len(s) > maxQoryHostPath {
		s = s[:maxQoryHostPath]
	}
	return s
}

// writeQoryHostError writes the program the forwarder's answer of status, with a JSON
// body of code and text, as [writeQoryHostReply] does.
func writeQoryHostError(c net.Conn, from io.Reader, unread int64, status int, code, text string, noBody bool) {
	b, _ := json.Marshal(struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}{code, text})
	writeQoryHostReply(c, from, unread, status, "application/json", b, noBody)
}

// writeQoryHostReply writes the program an answer of status, with Content-Type when it
// is set, the body b and Connection: close. The answer to a HEAD, noBody, and a 204 or
// 304 have no body; a 204 and a 304 have no Content-Length either, and a HEAD's is b's
// length. It then ends the connection's writing half and reads and drops what the
// program still sends, up to unread bytes, or [maxQoryHostDrain] when unread is below
// zero or over it, for at most [runAPIDrainWait] in all, so the close that follows does
// not reset the connection before the program reads the answer.
func writeQoryHostReply(c net.Conn, from io.Reader, unread int64, status int, contentType string, b []byte, noBody bool) {
	var head strings.Builder
	text := http.StatusText(status)
	if text == "" {
		text = "status code " + strconv.Itoa(status)
	}
	fmt.Fprintf(&head, "HTTP/1.1 %d %s\r\nConnection: close\r\n", status, text)
	bodyless := status == http.StatusNoContent || status == http.StatusNotModified
	if !bodyless {
		fmt.Fprintf(&head, "Content-Length: %d\r\n", len(b))
	}
	if contentType != "" && validValue([]byte(contentType)) {
		fmt.Fprintf(&head, "Content-Type: %s\r\n", contentType)
	}
	head.WriteString("\r\n")
	if noBody || bodyless {
		b = nil
	}
	c.SetWriteDeadline(time.Now().Add(link.PreambleWait))
	if _, err := io.WriteString(c, head.String()); err != nil {
		return
	}
	if _, err := c.Write(b); err != nil {
		return
	}
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	if unread < 0 || unread > maxQoryHostDrain {
		unread = maxQoryHostDrain
	}
	c.SetReadDeadline(time.Now().Add(runAPIDrainWait))
	io.Copy(io.Discard, io.LimitReader(from, unread))
}

// maxQoryHostDrain is the most bytes the forwarder reads and drops after an answer it
// writes on the route: the largest body the route takes, and a head.
const maxQoryHostDrain = link.MaxQoryHostBody + maxProxyHead
