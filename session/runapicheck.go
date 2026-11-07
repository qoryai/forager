package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// RunAPIRequest is one POST to the run API that a program behind the wall sent, as
// [Run.SetRunAPICheck] gets it.
type RunAPIRequest struct {
	// Path is the path after /v1/runs/<run id>, each segment decoded and escaped again,
	// as the gateway's route reads it: /artifacts for a push of artifacts, /verdict for
	// a verdict.
	Path string
	// Header is the request's header as the program sent it, without the hop-by-hop
	// headers, the headers its Connection lists and every Proxy- header.
	Header http.Header
	// Body is the whole body. The forwarder keeps a copy of it, so a change to Body
	// changes nothing that the gateway gets.
	Body []byte
}

// RunAPIRefusal is the reply that [Run.SetRunAPICheck] returns for a POST that does
// not go on. The forwarder writes it to the program with Status, 400 to 499, and a JSON
// body in the shape of the gateway's run API errors:
// {"error":Code,"message":Message,"findings":Findings}, without "findings" when
// Findings is empty. Message may contain line feeds.
type RunAPIRefusal struct {
	Status   int
	Code     string
	Message  string
	Findings []string
}

// SetRunAPICheck sets check, which checks each POST to the run API that a program behind
// the wall sends, the agent's or a setup command's, before anything of it reaches the
// gateway: a POST to run-api.qory.invalid under /v1/runs/<run id>/, such as a push of
// artifacts. Call it after [Open], when the caller knows whether the run has checks, and
// before [Run.Setup] and the first [Run.Join]. Without the call, the run's forwarder
// passes every connection through the wall as it arrives, byte for byte.
//
// The run's forwarder reads the POST whole, as the gateway's route does, then calls
// check. When it returns nil, nil, the forwarder sends the POST on, the bytes check got
// with Connection: close added to the head, and the gateway's route checks it as any
// other. A [RunAPIRefusal] goes to the program instead, with its Status, and nothing
// reaches the gateway. An error, a panic, which is a Report line, a refusal with no
// Code, a Status of 407 or outside 400 to 499, or a call that outlasts its context gets
// a 503, {"error":"push_check_unavailable",...}, and nothing reaches the gateway either.
// The context ends after 90 seconds or when the run closes. Return when ctx ends: the
// forwarder reads and checks one POST of the run at a time and takes the next one once
// the context ends, so a check that ignores ctx may still run beside the next POST's
// check. A POST that waits 90 seconds for its turn gets the 503 too.
//
// With the check set, the forwarder passes one request per connection through the
// wall, with no plain-HTTP keep-alive or pipelining: a CONNECT and its tunnel, or one
// plain request and its reply, after which the connection closes and a client opens
// another. A request's head must arrive within 10 seconds and have at most 16 KiB, 100
// lines and 8 KiB a line; a larger one gets a 431, and one net/http does not read gets a
// 400. The forwarder sends a plain request that it does not check as HTTP/1.1, an
// HTTP/1.0 one among them. A POST to the run API host must reach the forwarder as
// net/http would read it, with no doubt about its host or the end of its body: HTTP/1.1
// to http://run-api.qory.invalid/, one Host header with that host, every line ending in
// CRLF, no folded line, and a body of at most one Content-Length with no
// Transfer-Encoding; any other gets a 400. A body over the path's limit, 64 KiB for
// /verdict and 32 MiB otherwise, gets the gateway's 413 before the body is read. A POST
// with Expect: 100-continue gets the forwarder's 100 Continue, then, once its body goes
// on, the route's. GETs, other methods and other hosts pass unchecked.
//
// SetRunAPICheck may be called from any goroutine, beside Setup, Join and Close too:
// each of them that begins first makes the call fail, and a Close waits for a call that
// runs. It returns an error, and changes nothing, when check is nil; the run has no wall
// or no control plane; the run is closed or closing; the check is set already;
// [Run.Setup] passed its checks; a [Run.Join] passed its checks; or a connection
// reached the run's forwarder with the relay's preamble, and so passed on unread. A
// connection that shows that preamble during the call shows it either before the check
// is set, and the call returns that error, or after it, and every request on it is
// checked. A connection without the preamble is closed, and changes nothing.
//
// Close the run when SetRunAPICheck returns an error for a run that needs the check: the
// run would otherwise carry its programs' POSTs to the run API unchecked.
func (r *Run) SetRunAPICheck(check func(ctx context.Context, req RunAPIRequest) (*RunAPIRefusal, error)) error {
	if check == nil {
		return errors.New("Give SetRunAPICheck a check: a nil check checks nothing.")
	}
	if r.open.Wall == nil {
		return errors.New("Open the run with a wall to check its run API: the check runs in the run's forwarder behind the wall.")
	}
	if r.answer.RunAPI == "" {
		return errors.New("Open the run at a gateway with a control plane to check its run API: the run has no run API.")
	}
	r.checkMu.Lock()
	defer r.checkMu.Unlock()
	switch {
	case r.checkShut != nil:
		return r.checkShut
	case r.closing.Err() != nil:
		return errors.New("Open another run to check its run API: the run is closing.")
	}
	// Close writes r.wallFwd only after it set r.checkShut under r.checkMu.
	return r.wallFwd.setCheck(&runAPICheck{check: check, runID: r.id, done: r.closing, report: r.open.Report})
}

// The errors of [Run.SetRunAPICheck] once Setup, Join or Close began.
var (
	errCheckAfterSetup = errors.New("Call SetRunAPICheck before Setup: the setup started.")
	errCheckAfterJoin  = errors.New("Call SetRunAPICheck before the first Join: a session joined the run.")
	errCheckClosedRun  = errors.New("Open another run to check its run API: the run is closed.")
)

// shutCheck makes every later [Run.SetRunAPICheck] return err, once a call that runs
// returned. Without replace, an err set earlier stays.
func (r *Run) shutCheck(err error, replace bool) {
	r.checkMu.Lock()
	defer r.checkMu.Unlock()
	if replace || r.checkShut == nil {
		r.checkShut = err
	}
}

// The waits of a check of [Run.SetRunAPICheck].
const (
	// runAPICheckWait is how long one call of the check has.
	runAPICheckWait = 90 * time.Second
	// runAPIBodyWait is how long a program has to send a checked POST's body: the time
	// the gateway's route allows a POST to arrive and reach Qory Apiary, so a body that
	// takes longer would fail at the gateway too.
	runAPIBodyWait = 60 * time.Second
	// runAPIDrainWait is how long, in all, the forwarder reads and drops what a program
	// still sends after a reply that the forwarder writes, before it closes the
	// connection, so the close does not reset the connection before the program reads the
	// reply.
	runAPIDrainWait = 5 * time.Second
)

// runAPICheck is a walled run's check of every POST to its run API, which the forwarder
// calls before anything of the POST reaches the gateway's proxy.
type runAPICheck struct {
	check func(ctx context.Context, req RunAPIRequest) (*RunAPIRefusal, error)
	// runID is the run's id: a POST under /v1/runs/<runID>/ is checked.
	runID string
	// done ends when the run closes, and ends a check in flight with it.
	done context.Context
	// report gets a line for a check that panicked.
	report func(string)
	// wait and bodyWait, when set, replace [runAPICheckWait] and [runAPIBodyWait].
	// Tests set them.
	wait, bodyWait time.Duration

	// slot is taken from a checked POST's body read to the check's return, so one body at
	// a time is in memory before its check, as the gateway's route has one POST of a run
	// in flight.
	slotOnce sync.Once
	slot     chan struct{}
}

// take waits for the run's one slot until ctx ends, and reports whether it got it; a
// true is followed by one call of leave.
func (k *runAPICheck) take(ctx context.Context) bool {
	k.slotOnce.Do(func() { k.slot = make(chan struct{}, 1) })
	select {
	case k.slot <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// leave gives the slot back.
func (k *runAPICheck) leave() { <-k.slot }

// The forwarder's texts for a POST to the run API's host. Each starts with the fix.
const (
	runAPICheckUnavailable = "Run the push again: the check before the push did not finish."
	runAPIBadTarget        = "Send the POST over HTTP/1.1 to http://" + link.RunAPIHost + "/ as QORY_RUN_API has it: the run's proxy checks each POST to that host before it sends the POST on, and reads no other form of the target."
	runAPIBadHost          = "Send one Host header, " + link.RunAPIHost + ", with the POST: the run's proxy reads no other Host for a POST to the run API."
	runAPIBadHeader        = "Send each header of the POST on one line that ends in CRLF, with a valid name and no control characters: the run's proxy reads no folded line and no bare CR or LF."
	runAPIBadLength        = "Send the body with one Content-Length header and no Transfer-Encoding: the run's proxy reads a POST to the run API whole before it checks the POST."
)

// runAPIPost is a POST to the run API's host, read from its head.
type runAPIPost struct {
	// path is the path after the run's id, as [RunAPIRequest.Path] has it, and empty for
	// a POST outside the run's path, which is not checked.
	path string
	// length is the body's length, and limit the largest the forwarder reads.
	length, limit int64
	// header is what [RunAPIRequest.Header] gets.
	header http.Header
	// expect is true for a POST that waits for a 100 Continue before its body.
	expect bool
}

// errRunAPIPanic is the error of a check that panicked.
var errRunAPIPanic = errors.New("the check panicked")

// forRunAPIPost reports whether head, a plain request's head that [checkRequestLine]
// accepts, is a POST, in any case, whose host is the run API's in any reading: the
// target's authority as sent, the host net/http decodes from it, which a forwarder that
// writes the request again sends on, or a Host header. Each such POST goes to
// [readRunAPIPost], which reads it as the gateway does or returns the text of a 400, so
// no reading of the host lets a POST to the run API pass unchecked.
func forRunAPIPost(head []byte) bool {
	line, _, _ := bytes.Cut(head, []byte("\n"))
	method, rest, _ := strings.Cut(string(bytes.TrimSuffix(line, []byte("\r"))), " ")
	target, _, _ := strings.Cut(rest, " ")
	if !strings.EqualFold(method, http.MethodPost) {
		return false
	}
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
		if got, ok := policy.Host(h); ok && got == link.RunAPIHost {
			return true
		}
	}
	return false
}

// targetAuthority is the authority of an absolute-form target as sent, as the gateway's
// proxy reads it.
func targetAuthority(target string) string {
	if _, rest, ok := strings.Cut(target, "://"); ok {
		target = rest
	}
	if i := strings.IndexAny(target, "/?#"); i >= 0 {
		target = target[:i]
	}
	return target
}

// authorityHost is the host of an authority as sent: without user information, port and
// brackets, and not decoded, as the gateway's proxy reads it.
func authorityHost(authority string) string {
	authority = authority[strings.LastIndex(authority, "@")+1:]
	if host, _, err := net.SplitHostPort(authority); err == nil {
		return host
	}
	return strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]")
}

// runAPIPrefix is the start of every target the forwarder reads as a POST to the run
// API.
const runAPIPrefix = "http://" + link.RunAPIHost + "/"

// readRunAPIPost reads head, the head of a POST that [forRunAPIPost] accepts, so that the
// forwarder and the gateway's proxy, a server of net/http, agree on every part of it: the
// method POST, a target that starts with http://run-api.qory.invalid/, HTTP/1.1, each
// line ending in CRLF with no other CR or LF, no folded line, header names that are
// tokens and values without control characters, one Host header that is the run API's
// host, and at most one Content-Length, a decimal number, with no Transfer-Encoding. Its
// error is the text of the forwarder's 400.
func readRunAPIPost(head []byte, runID string) (runAPIPost, error) {
	// The head ends in its empty line, after which SplitAfter gives one empty piece.
	lines := bytes.SplitAfter(head, []byte("\n"))
	lines = lines[:len(lines)-1]
	for _, l := range lines {
		if !bytes.HasSuffix(l, []byte("\r\n")) || bytes.Count(l, []byte("\r")) != 1 {
			return runAPIPost{}, errors.New(runAPIBadHeader)
		}
	}
	method, rest, _ := strings.Cut(string(bytes.TrimSuffix(lines[0], []byte("\r\n"))), " ")
	target, version, _ := strings.Cut(rest, " ")
	if method != http.MethodPost || version != "HTTP/1.1" || !strings.HasPrefix(target, runAPIPrefix) {
		return runAPIPost{}, errors.New(runAPIBadTarget)
	}
	var hosts, lengths []string
	p := runAPIPost{}
	for _, l := range lines[1 : len(lines)-1] {
		l = bytes.TrimSuffix(l, []byte("\r\n"))
		name, value, found := bytes.Cut(l, []byte(":"))
		if !found || !validToken(name) || !validValue(value) {
			return runAPIPost{}, errors.New(runAPIBadHeader)
		}
		v := strings.Trim(string(value), " \t")
		switch {
		case strings.EqualFold(string(name), "Host"):
			hosts = append(hosts, v)
		case strings.EqualFold(string(name), "Content-Length"):
			lengths = append(lengths, v)
		case strings.EqualFold(string(name), "Transfer-Encoding"):
			return runAPIPost{}, errors.New(runAPIBadLength)
		case strings.EqualFold(string(name), "Expect"):
			p.expect = strings.EqualFold(v, "100-continue")
		}
	}
	if len(hosts) != 1 || !strings.EqualFold(hosts[0], link.RunAPIHost) {
		return runAPIPost{}, errors.New(runAPIBadHost)
	}
	if len(lengths) > 1 {
		return runAPIPost{}, errors.New(runAPIBadLength)
	}
	if len(lengths) == 1 {
		n, err := strconv.ParseUint(lengths[0], 10, 63)
		if err != nil || strings.TrimLeft(lengths[0], "0123456789") != "" {
			return runAPIPost{}, errors.New(runAPIBadLength)
		}
		p.length = int64(n)
	}
	// net/http reads the head as the gateway's proxy does: where it reads another length
	// or host, the POST does not go on.
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(head)))
	if err != nil {
		return runAPIPost{}, errors.New(runAPIBadHeader)
	}
	if req.Host != link.RunAPIHost || req.URL.Host != link.RunAPIHost {
		return runAPIPost{}, errors.New(runAPIBadHost)
	}
	if req.ContentLength != p.length || len(req.TransferEncoding) != 0 {
		return runAPIPost{}, errors.New(runAPIBadLength)
	}
	p.header = withoutHopHeaders(req.Header)
	p.path = runAPIPath(target[len(runAPIPrefix)-1:], runID)
	p.limit = link.MaxRunAPIArtifacts
	if p.path == "/verdict" {
		p.limit = link.MaxRunAPIVerdict
	}
	return p, nil
}

// validToken reports whether b is a header name: one or more token characters.
func validToken(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

// validValue reports whether b is a header value without a control character other than
// a tab.
func validValue(b []byte) bool {
	for _, c := range b {
		if c < ' ' && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}

// runAPIHopHeaders are the hop-by-hop headers, as the gateway's proxy lists them.
var runAPIHopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// withoutHopHeaders is h without the hop-by-hop headers, the headers its Connection lists
// and every Proxy- header.
func withoutHopHeaders(h http.Header) http.Header {
	out := h.Clone()
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			out.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range runAPIHopHeaders {
		out.Del(name)
	}
	for name := range out {
		if strings.HasPrefix(name, "Proxy-") {
			delete(out, name)
		}
	}
	return out
}

// runAPIPath is the path after the run's id of raw, a target's path, query and fragment
// as sent, each segment decoded and escaped again as the gateway's route reads it, or
// empty when raw is outside /v1/runs/<runID>/. Every POST the route accepts is inside: it
// accepts no query, no fragment and no segment that fails to decode.
func runAPIPath(raw, runID string) string {
	raw, _, _ = strings.Cut(raw, "?")
	raw, _, _ = strings.Cut(raw, "#")
	var parts []string
	for _, escaped := range strings.Split(strings.TrimPrefix(raw, "/"), "/") {
		part, err := url.PathUnescape(escaped)
		if err != nil {
			return ""
		}
		parts = append(parts, part)
	}
	if len(parts) < 4 || parts[0] != "v1" || parts[1] != "runs" || parts[2] != runID {
		return ""
	}
	var path strings.Builder
	for _, part := range parts[3:] {
		path.WriteString("/" + url.PathEscape(part))
	}
	return path.String()
}

// pass reads the POST to the run API whose head is head and whose body follows in from,
// checks it when it is under the run's path, and returns what the forwarder sends on:
// head with Connection: close before its empty line, then the body, the bytes the
// check got. It returns nil when the POST does not go on: the forwarder has then written
// the program a reply and read what it sent after it, or the connection failed.
func (k *runAPICheck) pass(ctx context.Context, c net.Conn, head []byte, from *bufio.Reader) []byte {
	p, err := readRunAPIPost(head, k.runID)
	if err != nil {
		replyRunAPI(c, from, -1, http.StatusBadRequest, &RunAPIRefusal{Code: "bad_request", Message: err.Error()})
		return nil
	}
	if p.length > p.limit {
		replyRunAPI(c, from, p.length, http.StatusRequestEntityTooLarge, &RunAPIRefusal{Code: "payload_too_large", Message: link.RunAPITooLarge(p.limit)})
		return nil
	}
	wait := k.bodyWait
	if wait == 0 {
		wait = runAPIBodyWait
	}
	// A POST that waits longer than a check has for the slot gets the 503 of a check that
	// did not finish.
	slotCtx, cancel := context.WithTimeout(ctx, k.checkWait())
	got := k.take(slotCtx)
	cancel()
	if !got {
		replyRunAPI(c, from, p.length, http.StatusServiceUnavailable, &RunAPIRefusal{Code: "push_check_unavailable", Message: runAPICheckUnavailable})
		return nil
	}
	out, err := k.readBody(c, head, from, p, wait)
	if err != nil || p.path == "" {
		k.leave()
		return out
	}
	body := out[len(out)-int(p.length):]
	refusal, err := k.call(ctx, RunAPIRequest{Path: p.path, Header: p.header, Body: bytes.Clone(body)})
	// The slot goes back before the reply and its drain, so a program that keeps sending
	// after a refusal holds back no other POST's check.
	k.leave()
	if err == nil && refusal != nil {
		err = checkRefusal(refusal)
	}
	switch {
	case err != nil:
		replyRunAPI(c, from, maxProxyHead, http.StatusServiceUnavailable, &RunAPIRefusal{Code: "push_check_unavailable", Message: runAPICheckUnavailable})
		return nil
	case refusal != nil:
		replyRunAPI(c, from, maxProxyHead, refusal.Status, refusal)
		return nil
	}
	return out
}

// readBody writes the program a 100 Continue when the POST p expects one, then reads its
// body from from, within wait, and returns head with Connection: close before its empty
// line, then the body, or the error of a failed write or read.
func (k *runAPICheck) readBody(c net.Conn, head []byte, from *bufio.Reader, p runAPIPost, wait time.Duration) ([]byte, error) {
	if p.expect {
		c.SetWriteDeadline(time.Now().Add(link.PreambleWait))
		if _, err := io.WriteString(c, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			return nil, err
		}
		c.SetWriteDeadline(time.Time{})
	}
	out := bytes.NewBuffer(closingHead(head))
	c.SetReadDeadline(time.Now().Add(wait))
	// The buffer grows as the body arrives, so a Content-Length alone costs nothing.
	if _, err := io.CopyN(out, from, p.length); err != nil {
		return nil, err
	}
	c.SetReadDeadline(time.Time{})
	return out.Bytes(), nil
}

// checkRefusal returns an error for a refusal the forwarder does not pass on: one with
// no Code, a Status outside 400 to 499, or 407, which a client reads as the proxy's
// demand for credentials.
func checkRefusal(r *RunAPIRefusal) error {
	switch {
	case r.Code == "":
		return errors.New("the check returned a refusal with no code")
	case r.Status < 400 || r.Status > 499 || r.Status == http.StatusProxyAuthRequired:
		return fmt.Errorf("the check returned status %d, outside 400 to 499 or 407", r.Status)
	}
	return nil
}

// call calls the check with req, under a context that ends after [runAPICheckWait], when
// the run closes or when ctx ends. A panic of the check is a Report line and an error.
// A check that outlasts its context is an error too: the forwarder does not wait for its
// return.
func (k *runAPICheck) call(ctx context.Context, req RunAPIRequest) (*RunAPIRefusal, error) {
	ctx, cancel := context.WithTimeout(ctx, k.checkWait())
	defer cancel()
	if k.done != nil {
		defer context.AfterFunc(k.done, cancel)()
	}
	type result struct {
		refusal *RunAPIRefusal
		err     error
	}
	got := make(chan result, 1)
	go func() {
		defer func() {
			if v := recover(); v != nil {
				if k.report != nil {
					k.report(fmt.Sprintf("the check of a run API POST panicked: %v", v))
				}
				got <- result{err: errRunAPIPanic}
			}
		}()
		refusal, err := k.check(ctx, req)
		got <- result{refusal, err}
	}()
	select {
	case r := <-got:
		if r.err == nil && ctx.Err() != nil {
			// A check that let the POST pass after its context ended fails as one that
			// outlasted it.
			return nil, ctx.Err()
		}
		return r.refusal, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// checkWait is how long one call of the check has.
func (k *runAPICheck) checkWait() time.Duration {
	if k.wait == 0 {
		return runAPICheckWait
	}
	return k.wait
}

// replyRunAPI writes the program a reply of status with refusal's code, message and
// findings, in the gateway's JSON shape, and Connection: close. It then ends the
// connection's writing half and reads and drops what the program still sends, up to
// unread bytes, or [maxRunAPIDrain] when unread is below zero or over it, for at most
// [runAPIDrainWait] in all, so the close that follows does not reset the connection
// before the program reads the reply.
func replyRunAPI(c net.Conn, from io.Reader, unread int64, status int, refusal *RunAPIRefusal) {
	b, _ := json.Marshal(struct {
		Error    string   `json:"error"`
		Message  string   `json:"message"`
		Findings []string `json:"findings,omitempty"`
	}{refusal.Code, refusal.Message, refusal.Findings})
	text := http.StatusText(status)
	if text == "" {
		text = "status code " + strconv.Itoa(status)
	}
	c.SetWriteDeadline(time.Now().Add(link.PreambleWait))
	if _, err := fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n%s",
		status, text, len(b), b); err != nil {
		return
	}
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	if unread < 0 || unread > maxRunAPIDrain {
		unread = maxRunAPIDrain
	}
	c.SetReadDeadline(time.Now().Add(runAPIDrainWait))
	io.Copy(io.Discard, io.LimitReader(from, unread))
}

// maxRunAPIDrain is the most bytes the forwarder reads and drops after a reply that the
// forwarder writes: the largest body the run API takes, and a head.
const maxRunAPIDrain = link.MaxRunAPIArtifacts + maxProxyHead
