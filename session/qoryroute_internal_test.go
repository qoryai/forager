package session

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/link"
)

// The tests of this file pin the route to link.QoryHost in a forwarder, walled and
// unwalled: what the handler gets, what the program gets, each limit, and what reaches
// the gateway's proxy.

// routeCall is one request the handler got.
type routeCall struct {
	method, path, query string
	header              http.Header
	body                string
}

// routeHandler records what it gets and answers with answer, or with 200 and "ok".
type routeHandler struct {
	mu     sync.Mutex
	calls  []routeCall
	answer func(w http.ResponseWriter, r *http.Request)
}

func (h *routeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.calls = append(h.calls, routeCall{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(b)})
	answer := h.answer
	h.mu.Unlock()
	if answer != nil {
		answer(w, r)
		return
	}
	io.WriteString(w, "ok")
}

func (h *routeHandler) got() []routeCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.calls)
}

// routeRecords collects the route's records.
type routeRecords struct {
	mu   sync.Mutex
	recs []map[string]any
}

func (r *routeRecords) record(d map[string]any) {
	r.mu.Lock()
	r.recs = append(r.recs, d)
	r.mu.Unlock()
}

func (r *routeRecords) got() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.recs)
}

// routeProxy is a listener in place of the gateway's proxy: it records the first line
// it reads after the relay's preamble of every connection, and answers 403.
type routeProxy struct {
	ln   net.Listener
	mu   sync.Mutex
	got  []string
	done chan struct{}
}

func startRouteProxy(t *testing.T) *routeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &routeProxy{ln: ln, done: make(chan struct{})}
	go func() {
		defer close(p.done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				head, _, err := readHead(c, nil)
				if err != nil {
					return
				}
				lines := strings.Split(string(head), "\n")
				first := lines[0]
				if strings.HasPrefix(first, link.RelayPreamble) && len(lines) > 1 {
					first = lines[1]
				}
				p.mu.Lock()
				p.got = append(p.got, strings.TrimSpace(first))
				p.mu.Unlock()
				io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied")
			}()
		}
	}()
	t.Cleanup(func() { ln.Close(); <-p.done })
	return p
}

func (p *routeProxy) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.got)
}

// routePassword is the proxy password of walled session 1 in the tests of the route,
// and routePassword2 that of session 2.
const (
	routePassword  = "session-1-password-0123456789abcdefghijkl"
	routePassword2 = "session-2-password-0123456789abcdefghijkl"
)

// loginOf is the Proxy-Authorization header line of a proxy URL with password.
func loginOf(password string) string {
	return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(link.ProxyUser+":"+password))
}

// withLogin is what with the header line login after its request line.
func withLogin(what, login string) string {
	line, rest, _ := strings.Cut(what, "\n")
	return line + "\n" + login + "\r\n" + rest
}

// routeFor is a route to h whose walled session 1 runs, with routePassword, and its
// records.
func routeFor(t *testing.T, h http.Handler) (*qoryRoute, *routeRecords, func()) {
	t.Helper()
	recs := &routeRecords{}
	q := newQoryRoute(h, context.Background(), recs.record, func(l string) { t.Log("report:", l) })
	return q, recs, q.open(1, routePassword)
}

// walledRoute starts a walled forwarder behind a separate gateway, with the hop, to the
// fake proxy p, with the route q.
func walledRoute(t *testing.T, p *routeProxy, q *qoryRoute) *forwarder {
	t.Helper()
	f, err := listenForwarding("127.0.0.1:0", forwarding{dial: dialTCP(p.ln.Addr().String()), secret: checkSecret, hop: checkHop, route: q})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// toRoute is a request of walled session 1 to the route's host, with routePassword,
// method, path, the header lines and body.
func toRoute(method, path, body string, header ...string) string {
	h := method + " " + link.QoryHostURL + path + " HTTP/1.1\r\nHost: " + link.QoryHost + "\r\n" + loginOf(routePassword) + "\r\n"
	for _, l := range header {
		h += l + "\r\n"
	}
	return h + fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)) + body
}

// TestARequestReachesTheHandlerAndReturnsItsAnswer pins a request to the route through
// a walled forwarder: the handler gets the method, the path, the query, Content-Type,
// the body and Qory-Session, and no other header; the program gets the handler's
// status, Content-Type and body; nothing reaches the proxy; and the record has one
// allowed decision of the route.
func TestARequestReachesTheHandlerAndReturnsItsAnswer(t *testing.T) {
	h := &routeHandler{answer: func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Other", "dropped")
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, "queued")
	}}
	q, recs, _ := routeFor(t, h)
	p := startRouteProxy(t)
	f := walledRoute(t, p, q)
	out := relaySend(t, f, toRoute("POST", "/push?branch=main", `{"ref":"main"}`,
		"Content-Type: application/json", "Cookie: a=b", "Authorization: Bearer forged",
		"Qory-Session: 9", "X-Custom: 1"))
	resp, body := replyOf(t, out)
	if resp.StatusCode != http.StatusAccepted || body != "queued" || resp.Header.Get("Content-Type") != "text/plain" || resp.Header.Get("X-Other") != "" {
		t.Errorf("the program got %q", out)
	}
	calls := h.got()
	if len(calls) != 1 {
		t.Fatalf("the handler got %d calls", len(calls))
	}
	c := calls[0]
	want := http.Header{"Content-Type": {"application/json"}, link.QorySessionHeader: {"1"}}
	if c.method != "POST" || c.path != "/push" || c.query != "branch=main" || c.body != `{"ref":"main"}` || fmt.Sprint(c.header) != fmt.Sprint(want) {
		t.Errorf("the handler got %+v", c)
	}
	if got := p.requests(); len(got) != 0 {
		t.Errorf("the proxy got %q", got)
	}
	rs := recs.got()
	if len(rs) != 1 {
		t.Fatalf("the records %v", rs)
	}
	r := rs[0]
	if r["host"] != link.QoryHost || r["port"] != 80 || r["method"] != "HTTP" || r["channel"] != link.QoryHostChannel || r["rule"] != link.QoryHostRule ||
		r["decision"] != "allowed" || r["outcome"] != "connected" || r["status"] != http.StatusAccepted || r["request_method"] != "POST" || r["path"] != "/push" {
		t.Errorf("the record %v", r)
	}
}

// TestAnotherHostIsNotRouted pins that only the route's host reaches the handler: a
// plain request to another host, a CONNECT to the route's host and a request to a host
// that merely ends like it go to the proxy, and the handler gets none of them.
func TestAnotherHostIsNotRouted(t *testing.T) {
	h := &routeHandler{}
	q, recs, _ := routeFor(t, h)
	p := startRouteProxy(t)
	f := walledRoute(t, p, q)
	for _, what := range []string{
		"GET http://other.example/push HTTP/1.1\r\nHost: other.example\r\n\r\n",
		"CONNECT " + link.QoryHost + ":443 HTTP/1.1\r\nHost: " + link.QoryHost + ":443\r\n\r\n",
		"GET http://x" + link.QoryHost + "/push HTTP/1.1\r\nHost: x" + link.QoryHost + "\r\n\r\n",
	} {
		if resp, _ := replyOf(t, relaySend(t, f, what)); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%q got %d, want the proxy's 403", what, resp.StatusCode)
		}
	}
	if got := h.got(); len(got) != 0 {
		t.Errorf("the handler got %+v", got)
	}
	if got := recs.got(); len(got) != 0 {
		t.Errorf("the route recorded %v", got)
	}
	want := []string{"GET http://other.example/push HTTP/1.1", "CONNECT " + link.QoryHost + ":443 HTTP/1.1", "GET http://x" + link.QoryHost + "/push HTTP/1.1"}
	got := p.requests()
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("the proxy got %q, want %q", got, want)
	}
}

// TestTheUnwalledForwarderServesTheRouteForItsSessionAlone pins the route through an
// unwalled session's forwarder, with the password: the handler gets the request without
// the Proxy-Authorization; once another session runs, that forwarder's request gets 503
// and reaches no handler.
func TestTheUnwalledForwarderServesTheRouteForItsSessionAlone(t *testing.T) {
	h := &routeHandler{}
	q, _, closeRoute := routeFor(t, h)
	p := startRouteProxy(t)
	const password = "agent-password-0123456789abcdefghijklmnop"
	f, err := listenForwarding("127.0.0.1:0", forwarding{dial: dialTCP(p.ln.Addr().String()), secret: checkSecret, password: password, route: q, session: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	login := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("qory:"+password))
	send := func() *http.Response {
		c, err := net.Dial("tcp", f.Addr())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		go io.WriteString(c, withLogin("GET "+link.QoryHostURL+"/tests HTTP/1.1\r\nHost: "+link.QoryHost+"\r\n\r\n", login))
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(c)
		resp, _ := replyOf(t, string(b))
		return resp
	}
	if resp := send(); resp.StatusCode != http.StatusOK {
		t.Errorf("session 1's request got %d", resp.StatusCode)
	}
	if calls := h.got(); len(calls) != 1 || calls[0].header.Get("Proxy-Authorization") != "" || calls[0].header.Get(link.QorySessionHeader) != "1" {
		t.Errorf("the handler got %+v", calls)
	}
	closeRoute()
	q.open(2, "")
	if resp := send(); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("session 1's forwarder while session 2 runs got %d, want 503", resp.StatusCode)
	}
	if len(h.got()) != 1 {
		t.Errorf("the handler got %d calls", len(h.got()))
	}
	if got := p.requests(); len(got) != 0 {
		t.Errorf("the proxy got %q", got)
	}
}

// errorOf is the code of the forwarder's JSON answer in out, and its status.
func errorOf(t *testing.T, out string) (int, string) {
	t.Helper()
	resp, body := replyOf(t, out)
	var code string
	if i := strings.Index(body, `"error":"`); i >= 0 {
		code, _, _ = strings.Cut(body[i+len(`"error":"`):], `"`)
	}
	return resp.StatusCode, code
}

// TestNoSessionGets503AndNoHandlerCall pins the gate behind a wall: before any
// session a request has no session's password and goes to the proxy; during session 1
// the handler answers session 1's request; after it, and while session 2 runs, session
// 1's request gets 503 session_not_running and reaches no handler, so a container of an
// earlier session left running does not share the route; session 2's request reaches
// the handler as session 2. The record has a denied decision with status 503.
func TestNoSessionGets503AndNoHandlerCall(t *testing.T) {
	h := &routeHandler{}
	recs := &routeRecords{}
	q := newQoryRoute(h, context.Background(), recs.record, nil)
	p := startRouteProxy(t)
	f := walledRoute(t, p, q)
	ask := func(password string) (int, string) {
		return errorOf(t, relaySend(t, f, withLogin("GET "+link.QoryHostURL+"/tests HTTP/1.1\r\nHost: "+link.QoryHost+"\r\n\r\n", loginOf(password))))
	}
	if status, _ := ask(routePassword); status != http.StatusForbidden || len(p.requests()) != 1 {
		t.Errorf("before the first session: %d, the proxy got %q", status, p.requests())
	}
	closeRoute := q.open(1, routePassword)
	if status, _ := ask(routePassword); status != http.StatusOK {
		t.Errorf("during session 1: %d", status)
	}
	closeRoute()
	if status, code := ask(routePassword); status != http.StatusServiceUnavailable || code != "session_not_running" {
		t.Errorf("after session 1: %d %s", status, code)
	}
	q.open(2, routePassword2)
	q.now = func() time.Time { return time.Now().Add(2 * time.Second) }
	if status, code := ask(routePassword); status != http.StatusServiceUnavailable || code != "session_not_running" {
		t.Errorf("session 1's request while session 2 runs: %d %s", status, code)
	}
	if status, _ := ask(routePassword2); status != http.StatusOK {
		t.Errorf("session 2's request: %d", status)
	}
	calls := h.got()
	if len(calls) != 2 || calls[0].header.Get(link.QorySessionHeader) != "1" || calls[1].header.Get(link.QorySessionHeader) != "2" {
		t.Errorf("the handler got %+v", calls)
	}
	rs := recs.got()
	if len(rs) != 4 || rs[1]["status"] != 503 || rs[1]["decision"] != "denied" || rs[1]["outcome"] != "refused" || rs[2]["status"] != 503 {
		t.Errorf("the records %v", rs)
	}
}

// TestARequestWithoutASessionsPasswordGoesToTheProxy pins the walled forwarder's
// gate on the route: a request to the route's host with no Proxy-Authorization, as the
// setup container sends it, with another password, or with two, goes to the proxy,
// which denies the host, while a session runs; the handler gets none of them and the
// route records none.
func TestARequestWithoutASessionsPasswordGoesToTheProxy(t *testing.T) {
	h := &routeHandler{}
	q, recs, _ := routeFor(t, h)
	p := startRouteProxy(t)
	f := walledRoute(t, p, q)
	plain := "GET " + link.QoryHostURL + "/tests HTTP/1.1\r\nHost: " + link.QoryHost + "\r\n\r\n"
	for name, what := range map[string]string{
		"no password":      plain,
		"another password": withLogin(plain, loginOf("another-password-0123456789abcdefghij")),
		"two passwords":    withLogin(withLogin(plain, loginOf(routePassword)), loginOf(routePassword)),
	} {
		if resp, _ := replyOf(t, relaySend(t, f, what)); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d, want the proxy's 403", name, resp.StatusCode)
		}
	}
	if got := h.got(); len(got) != 0 {
		t.Errorf("the handler got %+v", got)
	}
	if got := recs.got(); len(got) != 0 {
		t.Errorf("the route recorded %v", got)
	}
	if got := p.requests(); len(got) != 3 {
		t.Errorf("the proxy got %q", got)
	}
}

// TestEachLimitOfTheRoute pins the forwarder's answers for each limit: a form it does
// not read (400), a body over 1 MiB (413), the fifth request in flight and the
// eleventh in a second (429), a handler that does not return within the wait (504), a
// session that ends during the call (503), and an answer over 1 MiB, a status outside
// the range and a handler that panics (502).
func TestEachLimitOfTheRoute(t *testing.T) {
	p := startRouteProxy(t)
	t.Run("a form the forwarder does not read", func(t *testing.T) {
		h := &routeHandler{}
		q, _, _ := routeFor(t, h)
		f := walledRoute(t, p, q)
		for _, what := range []string{
			"GET " + link.QoryHostURL + "/x HTTP/1.0\r\nHost: " + link.QoryHost + "\r\n\r\n",
			"GET " + link.QoryHostURL + "/x HTTP/1.1\r\nHost: " + link.QoryHost + "\r\nHost: " + link.QoryHost + "\r\n\r\n",
			"GET http://other.example/x HTTP/1.1\r\nHost: " + link.QoryHost + "\r\n\r\n",
			"POST " + link.QoryHostURL + "/x HTTP/1.1\r\nHost: " + link.QoryHost + "\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
			"POST " + link.QoryHostURL + "/x HTTP/1.1\r\nHost: " + link.QoryHost + "\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na",
			"GET " + link.QoryHostURL + "/x HTTP/1.1\nHost: " + link.QoryHost + "\n\n",
			"GET http://HOST.QORY.INVALID/x HTTP/1.1\r\nHost: HOST.QORY.INVALID\r\n\r\n",
			"GET http://" + link.QoryHost + "./x HTTP/1.1\r\nHost: " + link.QoryHost + ".\r\n\r\n",
		} {
			what = withLogin(what, loginOf(routePassword))
			if status, code := errorOf(t, relaySend(t, f, what)); status != http.StatusBadRequest || code != "bad_request" {
				t.Errorf("%q: %d %s", what, status, code)
			}
		}
		if len(h.got()) != 0 || len(p.requests()) != 0 {
			t.Errorf("the handler got %d calls, the proxy %q", len(h.got()), p.requests())
		}
	})
	t.Run("a body over 1 MiB", func(t *testing.T) {
		h := &routeHandler{}
		q, _, _ := routeFor(t, h)
		f := walledRoute(t, p, q)
		what := fmt.Sprintf("POST %s/x HTTP/1.1\r\nHost: %s\r\n%s\r\nContent-Length: %d\r\n\r\n", link.QoryHostURL, link.QoryHost, loginOf(routePassword), link.MaxQoryHostBody+1)
		if status, code := errorOf(t, relaySend(t, f, what)); status != http.StatusRequestEntityTooLarge || code != "payload_too_large" {
			t.Errorf("%d %s", status, code)
		}
		full := toRoute("POST", "/x", strings.Repeat("a", int(link.MaxQoryHostBody)))
		if status, _ := errorOf(t, relaySend(t, f, full)); status != http.StatusOK {
			t.Errorf("a body of 1 MiB: %d", status)
		}
		if got := h.got(); len(got) != 1 {
			t.Errorf("the handler got %d calls", len(got))
		}
	})
	t.Run("the fifth request in flight", func(t *testing.T) {
		release := make(chan struct{})
		var entered sync.WaitGroup
		entered.Add(qoryHostInFlight)
		h := &routeHandler{answer: func(w http.ResponseWriter, _ *http.Request) { entered.Done(); <-release }}
		q, _, _ := routeFor(t, h)
		f := walledRoute(t, p, q)
		outs := make(chan string, qoryHostInFlight)
		for range qoryHostInFlight {
			go func() { outs <- relaySend(t, f, toRoute("GET", "/slow", "")) }()
		}
		entered.Wait()
		if status, code := errorOf(t, relaySend(t, f, toRoute("GET", "/fifth", ""))); status != http.StatusTooManyRequests || code != "rate_limited" {
			t.Errorf("the fifth: %d %s", status, code)
		}
		close(release)
		for range qoryHostInFlight {
			if status, _ := errorOf(t, <-outs); status != http.StatusOK {
				t.Errorf("one of the four: %d", status)
			}
		}
	})
	t.Run("the eleventh request in a second", func(t *testing.T) {
		h := &routeHandler{}
		q, _, _ := routeFor(t, h)
		at := time.Unix(1_800_000_000, 0)
		q.now = func() time.Time { return at }
		f := walledRoute(t, p, q)
		for i := range qoryHostRate {
			if status, _ := errorOf(t, relaySend(t, f, toRoute("GET", "/x", ""))); status != http.StatusOK {
				t.Fatalf("request %d: %d", i+1, status)
			}
		}
		if status, code := errorOf(t, relaySend(t, f, toRoute("GET", "/x", ""))); status != http.StatusTooManyRequests || code != "rate_limited" {
			t.Errorf("the eleventh: %d %s", status, code)
		}
		at = at.Add(time.Second)
		if status, _ := errorOf(t, relaySend(t, f, toRoute("GET", "/x", ""))); status != http.StatusOK {
			t.Errorf("a second later: %d", status)
		}
	})
	t.Run("no answer in time", func(t *testing.T) {
		h := &routeHandler{answer: func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }}
		q, recs, _ := routeFor(t, h)
		q.wait = 200 * time.Millisecond
		f := walledRoute(t, p, q)
		if status, code := errorOf(t, relaySend(t, f, toRoute("GET", "/x", ""))); status != http.StatusGatewayTimeout || code != "timeout" {
			t.Errorf("%d %s", status, code)
		}
		if rs := recs.got(); len(rs) != 1 || rs[0]["decision"] != "allowed" || rs[0]["outcome"] != "refused" || rs[0]["status"] != 504 {
			t.Errorf("the records %v", rs)
		}
	})
	t.Run("the session ends during the call", func(t *testing.T) {
		called := make(chan struct{})
		h := &routeHandler{answer: func(w http.ResponseWriter, r *http.Request) { close(called); <-r.Context().Done() }}
		q, _, closeRoute := routeFor(t, h)
		f := walledRoute(t, p, q)
		go func() { <-called; closeRoute() }()
		if status, code := errorOf(t, relaySend(t, f, toRoute("GET", "/x", ""))); status != http.StatusServiceUnavailable || code != "session_not_running" {
			t.Errorf("%d %s", status, code)
		}
	})
	for _, c := range []struct {
		name   string
		answer func(w http.ResponseWriter, r *http.Request)
	}{
		{"an answer over 1 MiB", func(w http.ResponseWriter, _ *http.Request) {
			w.Write(make([]byte, link.MaxQoryHostBody))
			w.Write([]byte("x"))
		}},
		{"a status of 407", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusProxyAuthRequired) }},
		{"a status of 101", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusSwitchingProtocols) }},
		{"a handler that panics", func(http.ResponseWriter, *http.Request) { panic("a fault of the test's") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			q, _, _ := routeFor(t, &routeHandler{answer: c.answer})
			f := walledRoute(t, p, q)
			if status, code := errorOf(t, relaySend(t, f, toRoute("GET", "/x", ""))); status != http.StatusBadGateway || code != "bad_answer" {
				t.Errorf("%d %s", status, code)
			}
		})
	}
}

// TestARecordedPathHasNoSecret pins a request's path in its record: decoded and escaped
// again, a segment with a secret as its phrase, without the query, cut at 1 KiB.
func TestARecordedPathHasNoSecret(t *testing.T) {
	q, recs, _ := routeFor(t, &routeHandler{})
	f := walledRoute(t, startRouteProxy(t), q)
	relaySend(t, f, toRoute("GET", "/keys/qak_secretvalue/a%20b?token=qak_other", ""))
	relaySend(t, f, toRoute("GET", "/"+strings.Repeat("a", 2000), ""))
	rs := recs.got()
	if len(rs) != 2 {
		t.Fatalf("the records %v", rs)
	}
	if p := rs[0]["path"].(string); strings.Contains(p, "qak_") || !strings.HasPrefix(p, "/keys/") || !strings.HasSuffix(p, "/a%20b") || strings.Contains(p, "token") {
		t.Errorf("the path %q", p)
	}
	if p := rs[1]["path"].(string); len(p) != maxQoryHostPath {
		t.Errorf("the long path has %d bytes", len(p))
	}
}

// relayConn opens a connection to the walled forwarder f as the wall's relay does, with
// the hop's preamble written.
func relayConn(t *testing.T, f *forwarder) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", f.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	io.WriteString(c, link.RelayLine(checkHop))
	return c
}

// readAllOf reads c until it closes, or 5 seconds pass.
func readAllOf(c net.Conn) string {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c)
	return string(b)
}

// waitIdle waits until the route has no call of the handler in flight.
func waitIdle(t *testing.T, q *qoryRoute) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		q.mu.Lock()
		n := q.inFlight
		q.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(end) {
			t.Fatalf("%d calls are still in flight", n)
		}
	}
}

// TestTheSlotsCountTheHandlersCallsAlone pins the four slots of the route: four
// requests whose bodies have not arrived hold none, so a fifth reaches the handler; and
// a handler that ignores its context holds its slot until it returns, after the
// program got its 504, so the next request gets 429 until the four return.
func TestTheSlotsCountTheHandlersCallsAlone(t *testing.T) {
	p := startRouteProxy(t)
	t.Run("a body on its way holds no slot", func(t *testing.T) {
		h := &routeHandler{}
		q, _, _ := routeFor(t, h)
		q.wait = time.Second
		f := walledRoute(t, p, q)
		var waiting []net.Conn
		for range qoryHostInFlight {
			c := relayConn(t, f)
			io.WriteString(c, strings.TrimSuffix(toRoute("POST", "/slow", "12345"), "12345"))
			waiting = append(waiting, c)
		}
		time.Sleep(100 * time.Millisecond)
		if status, _ := errorOf(t, relaySend(t, f, toRoute("GET", "/fifth", ""))); status != http.StatusOK {
			t.Errorf("the fifth, while four bodies are on their way: %d", status)
		}
		for _, c := range waiting {
			c.Close()
		}
	})
	t.Run("a handler that ignores its context", func(t *testing.T) {
		release := make(chan struct{})
		h := &routeHandler{answer: func(http.ResponseWriter, *http.Request) { <-release }}
		q, _, _ := routeFor(t, h)
		q.wait = 100 * time.Millisecond
		f := walledRoute(t, p, q)
		for i := range qoryHostInFlight {
			if status, code := errorOf(t, relaySend(t, f, toRoute("GET", "/x", ""))); status != http.StatusGatewayTimeout || code != "timeout" {
				t.Fatalf("request %d: %d %s", i+1, status, code)
			}
		}
		if status, code := errorOf(t, relaySend(t, f, toRoute("GET", "/x", ""))); status != http.StatusTooManyRequests || code != "rate_limited" {
			t.Errorf("while four handlers run on: %d %s", status, code)
		}
		if got := len(h.got()); got != qoryHostInFlight {
			t.Errorf("the handler got %d calls", got)
		}
		close(release)
		waitIdle(t, q)
		h.mu.Lock()
		h.answer = nil
		h.mu.Unlock()
		if status, _ := errorOf(t, relaySend(t, f, toRoute("GET", "/x", ""))); status != http.StatusOK {
			t.Errorf("once they returned: %d", status)
		}
	})
}

// TestTheRouteRecordsOneRefusalASecondPerStatus pins the records of refusals: of three
// 400s, three 503s and three 429s in one second, one each is recorded, every allowed
// request is, and a 400 a second later is again.
func TestTheRouteRecordsOneRefusalASecondPerStatus(t *testing.T) {
	recs := &routeRecords{}
	q := newQoryRoute(&routeHandler{}, context.Background(), recs.record, nil)
	at := time.Unix(1_800_000_000, 0)
	q.now = func() time.Time { return at }
	f := walledRoute(t, startRouteProxy(t), q)
	closeRoute := q.open(1, routePassword)
	bad := withLogin("GET "+link.QoryHostURL+"/x HTTP/1.0\r\nHost: "+link.QoryHost+"\r\n\r\n", loginOf(routePassword))
	for range 3 {
		relaySend(t, f, bad)
	}
	closeRoute()
	for range 3 {
		relaySend(t, f, toRoute("GET", "/x", ""))
	}
	q.open(2, routePassword2)
	for range qoryHostRate + 3 {
		relaySend(t, f, withLogin("GET "+link.QoryHostURL+"/x HTTP/1.1\r\nHost: "+link.QoryHost+"\r\n\r\n", loginOf(routePassword2)))
	}
	at = at.Add(time.Second)
	relaySend(t, f, bad)
	count := map[any]int{}
	for _, r := range recs.got() {
		count[r["status"]]++
	}
	if want := map[any]int{400: 2, 503: 1, 429: 1, 200: qoryHostRate}; fmt.Sprint(count) != fmt.Sprint(want) {
		t.Errorf("the records by status %v, want %v", count, want)
	}
}

// TestASessionThatEndsDuringTheBodyGetsNoCall pins a session that ends while its
// request's body arrives: the program gets 503 session_not_running and the handler no
// call.
func TestASessionThatEndsDuringTheBodyGetsNoCall(t *testing.T) {
	h := &routeHandler{}
	q, recs, closeRoute := routeFor(t, h)
	f := walledRoute(t, startRouteProxy(t), q)
	c := relayConn(t, f)
	io.WriteString(c, strings.TrimSuffix(toRoute("POST", "/x", "abcd"), "cd"))
	time.Sleep(100 * time.Millisecond)
	closeRoute()
	io.WriteString(c, "cd")
	if status, code := errorOf(t, readAllOf(c)); status != http.StatusServiceUnavailable || code != "session_not_running" {
		t.Errorf("%d %s", status, code)
	}
	if got := h.got(); len(got) != 0 {
		t.Errorf("the handler got %+v", got)
	}
	if rs := recs.got(); len(rs) != 1 || rs[0]["decision"] != "denied" || rs[0]["status"] != 503 {
		t.Errorf("the records %v", rs)
	}
}

// TestABodyThatStallsGets400 pins the body's wait: a body that does not arrive whole
// within the route's wait gets 400 bad_request, and the handler no call.
func TestABodyThatStallsGets400(t *testing.T) {
	h := &routeHandler{}
	q, _, _ := routeFor(t, h)
	q.wait = 200 * time.Millisecond
	f := walledRoute(t, startRouteProxy(t), q)
	c := relayConn(t, f)
	io.WriteString(c, strings.TrimSuffix(toRoute("POST", "/x", "abcdefghij"), "cdefghij"))
	if status, code := errorOf(t, readAllOf(c)); status != http.StatusBadRequest || code != "bad_request" {
		t.Errorf("%d %s", status, code)
	}
	if got := h.got(); len(got) != 0 {
		t.Errorf("the handler got %+v", got)
	}
}

// TestARequestThatExpectsAContinueGetsOne pins Expect: 100-continue: the forwarder
// writes 100 Continue before the body, and the handler gets the body.
func TestARequestThatExpectsAContinueGetsOne(t *testing.T) {
	h := &routeHandler{}
	q, _, _ := routeFor(t, h)
	f := walledRoute(t, startRouteProxy(t), q)
	c := relayConn(t, f)
	io.WriteString(c, strings.TrimSuffix(toRoute("POST", "/x", "body", "Expect: 100-continue"), "body"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	const cont = "HTTP/1.1 100 Continue\r\n\r\n"
	b := make([]byte, len(cont))
	if _, err := io.ReadFull(c, b); err != nil || string(b) != cont {
		t.Fatalf("before the body: %q %v", b, err)
	}
	io.WriteString(c, "body")
	if resp, body := replyOf(t, readAllOf(c)); resp.StatusCode != http.StatusOK || body != "ok" {
		t.Errorf("%d %q", resp.StatusCode, body)
	}
	if got := h.got(); len(got) != 1 || got[0].body != "body" {
		t.Errorf("the handler got %+v", got)
	}
}

// TestARunClosedDuringTheCallGets503 pins a run that closes from outside while the
// handler runs: its context ends and the program gets 503 session_not_running.
func TestARunClosedDuringTheCallGets503(t *testing.T) {
	called := make(chan struct{})
	h := &routeHandler{answer: func(_ http.ResponseWriter, r *http.Request) { close(called); <-r.Context().Done() }}
	runCtx, closeRun := context.WithCancel(context.Background())
	defer closeRun()
	q := newQoryRoute(h, runCtx, (&routeRecords{}).record, nil)
	q.open(1, routePassword)
	f := walledRoute(t, startRouteProxy(t), q)
	go func() { <-called; closeRun() }()
	if status, code := errorOf(t, relaySend(t, f, toRoute("GET", "/x", ""))); status != http.StatusServiceUnavailable || code != "session_not_running" {
		t.Errorf("%d %s", status, code)
	}
}

// TestAProgramThatGoesAwayDuringTheCallFreesItsSlot pins a program that closes its
// connection while the handler runs: the handler's call runs to its end, the record
// has its decision, the slot is free once the handler returns, and the next request
// reaches the handler.
func TestAProgramThatGoesAwayDuringTheCallFreesItsSlot(t *testing.T) {
	called, release := make(chan struct{}), make(chan struct{})
	h := &routeHandler{answer: func(w http.ResponseWriter, _ *http.Request) {
		close(called)
		<-release
		io.WriteString(w, "late")
	}}
	q, recs, _ := routeFor(t, h)
	f := walledRoute(t, startRouteProxy(t), q)
	c := relayConn(t, f)
	io.WriteString(c, toRoute("GET", "/x", ""))
	<-called
	c.Close()
	close(release)
	waitIdle(t, q)
	h.mu.Lock()
	h.answer = nil
	h.mu.Unlock()
	if status, _ := errorOf(t, relaySend(t, f, toRoute("GET", "/y", ""))); status != http.StatusOK {
		t.Errorf("the next request: %d", status)
	}
	if rs := recs.got(); len(rs) != 2 || rs[0]["decision"] != "allowed" || rs[0]["status"] != 200 {
		t.Errorf("the records %v", rs)
	}
}

// TestTheAnswerHasNoBodyWhereHTTPHasNone pins the answers HTTP gives no body: a HEAD's,
// with the Content-Length of the handler's body, a 204, with no Content-Length, and a
// 304; and a 103 before the answer, which the program does not get.
func TestTheAnswerHasNoBodyWhereHTTPHasNone(t *testing.T) {
	p := startRouteProxy(t)
	for _, c := range []struct {
		name, method string
		answer       func(w http.ResponseWriter, r *http.Request)
		head, body   string
	}{
		{"a HEAD", "HEAD", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "hello") }, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 5\r\n\r\n", ""},
		{"a 204", "GET", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n", ""},
		{"a 304", "GET", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotModified)
			io.WriteString(w, "x")
		}, "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n", ""},
		{"a 103 first", "GET", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusEarlyHints)
			io.WriteString(w, "ok")
		}, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\n", "ok"},
	} {
		t.Run(c.name, func(t *testing.T) {
			q, _, _ := routeFor(t, &routeHandler{answer: c.answer})
			f := walledRoute(t, p, q)
			if out := relaySend(t, f, toRoute(c.method, "/x", "")); out != c.head+c.body {
				t.Errorf("the program got %q, want %q", out, c.head+c.body)
			}
		})
	}
}

// TestAWalledForwarderWithARouteStillCarriesOtherRequests pins what a route leaves to the
// proxy behind a wall: a CONNECT and the data of its tunnel both ways, two requests to
// another host from a client that keeps its connections alive, and a request to the run
// API, with and without the run's check, which still checks its POSTs beside the route.
// None of them carries the session's password to the proxy.
func TestAWalledForwarderWithARouteStillCarriesOtherRequests(t *testing.T) {
	agent := func(f *forwarder) *http.Client {
		proxy := &url.URL{Scheme: "http", User: url.UserPassword(link.ProxyUser, routePassword), Host: f.Addr()}
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy),
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err == nil {
					_, err = io.WriteString(c, link.RelayLine(checkHop))
				}
				return c, err
			},
		}}
	}
	t.Run("a CONNECT and its data", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		got := make(chan string, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			head, rest, err := readHead(c, nil)
			if err != nil {
				return
			}
			got <- string(head)
			io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
			b := make([]byte, len("ping"))
			io.ReadFull(rest, b)
			io.WriteString(c, "pong:"+string(b))
		}()
		q, _, _ := routeFor(t, &routeHandler{})
		f, err := listenForwarding("127.0.0.1:0", forwarding{dial: dialTCP(ln.Addr().String()), hop: checkHop, route: q})
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		c := relayConn(t, f)
		io.WriteString(c, withLogin("CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\n\r\n", loginOf(routePassword))+"ping")
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(c)
		resp, err := http.ReadResponse(r, &http.Request{Method: http.MethodConnect})
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("the CONNECT: %v %v", resp, err)
		}
		if b, _ := io.ReadAll(r); string(b) != "pong:ping" {
			t.Errorf("the tunnel returned %q", b)
		}
		if head := <-got; head != "CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\nConnection: close\r\n\r\n" {
			t.Errorf("the proxy got %q", head)
		}
	})
	for _, checked := range []bool{false, true} {
		t.Run(fmt.Sprint("with the check ", checked), func(t *testing.T) {
			h := &routeHandler{}
			q, _, _ := routeFor(t, h)
			p := startProxyStandIn(t, checkSecret, nil)
			way := forwarding{dial: dialTCP(p.Addr().String()), secret: checkSecret, hop: checkHop, route: q}
			k := &checkCalls{}
			if checked {
				way.check = &runAPICheck{check: k.check, runID: checkRunID}
			}
			f, err := listenForwarding("127.0.0.1:0", way)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			c := agent(f)
			for _, target := range []string{"http://other.example/a", "http://other.example/b"} {
				resp, err := c.Get(target)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK || string(b) != "ok 0" {
					t.Errorf("%s: %d %q", target, resp.StatusCode, b)
				}
			}
			resp, err := c.Post(checkTarget("/artifacts"), "application/json", strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("the POST to the run API: %d", resp.StatusCode)
			}
			resp, err = c.Get(link.QoryHostURL + "/tests")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || len(h.got()) != 1 {
				t.Errorf("the route: %d, the handler got %d calls", resp.StatusCode, len(h.got()))
			}
			if calls := k.got(); checked && (len(calls) != 1 || calls[0].Path != "/artifacts") || !checked && len(calls) != 0 {
				t.Errorf("the check got %v", calls)
			}
			raw, requests := p.seen()
			if want := []string{"GET http://other.example/a ", "GET http://other.example/b ", "POST " + checkTarget("/artifacts") + " {}"}; !slices.Equal(requests, want) {
				t.Errorf("the proxy got %q\nwant %q", requests, want)
			}
			for _, b := range raw {
				if strings.Contains(b, "Proxy-Authorization") || strings.Contains(b, routePassword) {
					t.Errorf("the proxy got the session's password: %q", b)
				}
			}
		})
	}
}
