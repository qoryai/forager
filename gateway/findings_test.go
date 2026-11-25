package gateway_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// The tests of this file pin what the host calls GET findings and POST findings have and
// the other host calls do not: one path with two methods, a body and an answer past 1 MiB
// in the gateway's memory budget, and an answer's signature over a body past 2 MiB.

// memoryBudget is the gateway's memory budget, and freeBytes the part of each body and
// answer that it does not count.
const (
	memoryBudget = 512 << 20
	freeBytes    = 1 << 20
)

// hasRoom reports whether g's memory budget has room for n bytes.
func hasRoom(g *gateway.Gateway, n int) bool { return gateway.UsedRunAPI(g)+int64(n) <= memoryBudget }

// fill takes all of g's memory budget but left bytes until the returned func is called.
func fill(t *testing.T, g *gateway.Gateway, left int) func() {
	t.Helper()
	release, ok := gateway.ChargeRunAPI(g, memoryBudget-left)
	if !ok {
		t.Fatalf("the memory budget has no room for %d bytes", memoryBudget-left)
	}
	return release
}

// isFree fails the test unless g's whole memory budget, and no more than it, is free
// within a few seconds.
func isFree(t *testing.T, what string, g *gateway.Gateway) {
	t.Helper()
	freeWithin(t, what, g, 10*time.Second)
}

// freeWithin is isFree within d.
func freeWithin(t *testing.T, what string, g *gateway.Gateway, d time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(d); gateway.UsedRunAPI(g) != 0; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d bytes of the memory budget taken after %s", what, gateway.UsedRunAPI(g), d)
		}
	}
}

// sendRaw sends a request of method to path on the local link of h, with body, and
// returns the answer's status and body.
func sendRaw(t *testing.T, h *harness, method, path string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, server.LocalOrigin+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := raw(t, h.g.LocalLink()).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("%s %s: %v", method, path, err)
	}
	return resp.StatusCode, got
}

// TestAHostCallHasItsMethod pins the method of each host call, on the local link and on
// the one address: a GET of findings is sent as a GET, with no body and no Content-Type
// though the caller sent one, and a POST as a POST; a GET of next-session and of
// pushed-commits is no host call, but a reload of no run; and any other method of
// findings gets the 405 it gets of next-session. The control plane gets the GET and the
// POST of findings alone.
func TestAHostCallHasItsMethod(t *testing.T) {
	others := []string{http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead}
	sentOf := func(t *testing.T, f *fakeRunAPI, runID string) {
		t.Helper()
		seen := f.requests()
		if len(seen) != 2 || seen[0].method != http.MethodGet || len(seen[0].body) != 0 || seen[0].header.Get("Content-Type") != "" ||
			seen[1].method != http.MethodPost || string(seen[1].body) != `{"a":1}` {
			t.Errorf("the control plane got %+v", seen)
		}
		for _, s := range seen {
			if s.target != "/v1/runs/"+runID+"/findings" {
				t.Errorf("the control plane got %s", s.target)
			}
		}
	}
	t.Run("the local link", func(t *testing.T) {
		o := openRunAPIRun(t)
		serveHostCalls(o.f)
		o.f.reset()
		base := "/v1/run-configuration/" + o.a.RunID
		for method, body := range map[string][]byte{http.MethodGet: nil, http.MethodPost: []byte(`{"a":1}`)} {
			if status, _ := sendRaw(t, o.h, method, base+"/findings", body); status != http.StatusOK {
				t.Errorf("%s findings: %d", method, status)
			}
		}
		for _, path := range []string{"/next-session", "/pushed-commits"} {
			if status, _ := sendRaw(t, o.h, http.MethodGet, base+path, nil); status != http.StatusBadRequest {
				t.Errorf("GET %s: %d", path, status)
			}
		}
		for _, method := range others {
			for _, path := range []string{"/next-session", "/findings"} {
				if status, _ := sendRaw(t, o.h, method, base+path, []byte(`{}`)); status != http.StatusMethodNotAllowed {
					t.Errorf("%s %s: %d", method, path, status)
				}
			}
		}
		sentOf(t, o.f, o.a.RunID)
	})
	t.Run("the one address", func(t *testing.T) {
		c := gatewayControl(t)
		f := runAPIOf(c)
		f.passAttach.Store(true)
		serveHostCalls(f)
		r := startRemote(t, c, gateway.Config{})
		e := r.open(t, runKeyFor(t, event.NewRunID(), nil), server.LinkRunRequest{})
		f.reset()
		base := "/qory-link/run-configuration/" + e.a.RunID
		if got := r.do(t, e.key, http.MethodGet, base+"/findings", nil, http.Header{"Content-Type": {"application/json"}}); got.status != http.StatusOK {
			t.Errorf("GET findings: %d %s", got.status, got.body)
		}
		if got := r.do(t, e.key, http.MethodPost, base+"/findings", []byte(`{"a":1}`)); got.status != http.StatusOK {
			t.Errorf("POST findings: %d %s", got.status, got.body)
		}
		for _, path := range []string{"/next-session", "/pushed-commits"} {
			if got := r.do(t, e.key, http.MethodGet, base+path, nil); got.status != http.StatusBadRequest {
				t.Errorf("GET %s: %d %s", path, got.status, got.body)
			}
		}
		for _, method := range others {
			for _, path := range []string{"/next-session", "/findings"} {
				if got := r.do(t, e.key, method, base+path, nil); got.status != http.StatusMethodNotAllowed {
					t.Errorf("%s %s: %d %s", method, path, got.status, got.body)
				}
			}
		}
		sentOf(t, f, e.a.RunID)
	})
}

// TestAFindingsAnswerHasItsLimit pins the largest answers of the findings calls on the
// local link and on the one address: 16 MiB of a GET's 200 and 64 KiB of a POST's pass
// byte for byte, and one byte more is 502 control_plane_unavailable.
func TestAFindingsAnswerHasItsLimit(t *testing.T) {
	c := gatewayControl(t)
	f := runAPIOf(c)
	f.passAttach.Store(true)
	r := startRemote(t, c, gateway.Config{})
	e := r.open(t, runKeyFor(t, event.NewRunID(), nil), server.LinkRunRequest{})
	o := openRunAPIRun(t)
	for _, l := range []struct {
		method string
		most   int
	}{{http.MethodGet, 16 << 20}, {http.MethodPost, 64 << 10}} {
		for _, over := range []int{0, 1} {
			doc := bytes.Repeat([]byte("f"), l.most+over)
			what := fmt.Sprintf("%s findings: an answer of %d bytes", l.method, len(doc))
			for _, fake := range []*fakeRunAPI{f, o.f} {
				fake.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) { fake.sign(w, r, http.StatusOK, doc) })
			}
			var body []byte
			if l.method == http.MethodPost {
				body = []byte(`{}`)
			}
			got, err := hostCall(o.h, o.a.RunID, l.method+" /findings", body)
			signed := r.do(t, e.key, l.method, "/qory-link/run-configuration/"+e.a.RunID+"/findings", body)
			if over == 0 {
				if err != nil || !bytes.Equal(got, doc) {
					t.Errorf("%s: %d bytes, %v", what, len(got), err)
				}
				if signed.status != http.StatusOK || !bytes.Equal(signed.body, doc) {
					t.Errorf("%s on the one address: %d, %d bytes", what, signed.status, len(signed.body))
				}
				continue
			}
			refusalWith(t, what, err, http.StatusBadGateway, "control_plane_unavailable", accesskey.FromGateway)
			if signed.status != http.StatusBadGateway || signed.refusal()["error"] != "control_plane_unavailable" {
				t.Errorf("%s on the one address: %d, %d bytes", what, signed.status, len(signed.body))
			}
		}
	}
	isFree(t, "after the answers on the local link", o.h.g)
	isFree(t, "after the answers on the one address", r.g)
}

// sendBound sends a POST of body to path on a fresh bound connection with the run key,
// and returns whether the signature of its answer covers covered, and the status.
func sendBound(t *testing.T, r *remote, key, path string, body, covered []byte) (bool, int) {
	t.Helper()
	b, err := r.bind(t, gatewayKeys())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	contentType := server.LinkContentType
	if path == "/qory-link/events" {
		contentType = server.ContentType
	}
	fmt.Fprintf(b.c, "POST %s HTTP/1.1\r\nHost: gateway.example:8443\r\nAuthorization: Bearer %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n", path, key, contentType, len(body))
	go b.c.Write(body)
	resp, err := http.ReadResponse(b.r, nil)
	if err != nil {
		t.Fatalf("POST %s of %d bytes: %v", path, len(body), err)
	}
	got, _ := io.ReadAll(resp.Body)
	a := accesskey.Answer{Link: true, Status: resp.StatusCode, RequestSignature: link.AnswerRequest(b.ekm, http.MethodPost, path, covered), Body: got,
		Configuration: resp.Header.Get(server.HeaderConfiguration), RunConfiguration: resp.Header.Get(server.HeaderRunConfiguration)}
	return verifyAnswer(gatewayKeys(), a, resp.Header.Get(server.HeaderSignature)), resp.StatusCode
}

// TestTheSignatureCoversAPostFindingsBodyAlone pins the most of a body that a signed
// answer covers: 8 MiB and one byte of a POST findings body, and 2 MiB and one byte of
// every other, a GET's path with a POST's method among them. At each bound the answer's
// signature covers the whole body, one byte past it the first of the body alone, as on
// the answers before the findings calls.
func TestTheSignatureCoversAPostFindingsBodyAlone(t *testing.T) {
	const findingsBound = 8<<20 + 1
	if gateway.MaxBound != 2<<20+1 {
		t.Fatalf("the bound is %d bytes", gateway.MaxBound)
	}
	r := startRemote(t, nil, gateway.Config{})
	runID, key := endedRun(t, r)
	base := "/qory-link/run-configuration/" + runID
	for path, bound := range map[string]int{
		"/qory-link/events": gateway.MaxBound, base + "/next-session": gateway.MaxBound, base + "/pushed-commits": gateway.MaxBound,
		base + "/sessions": gateway.MaxBound, base + "/findings": findingsBound, base + "/%66indings": findingsBound,
	} {
		body := bytes.Repeat([]byte("x"), bound+1)
		for _, size := range []int{bound - 1, bound} {
			if ok, status := sendBound(t, r, key, path, body[:size], body[:size]); !ok || status != http.StatusGone {
				t.Errorf("%s: a body of %d bytes: covered whole %v, %d", path, size, ok, status)
			}
		}
		if ok, status := sendBound(t, r, key, path, body, body[:bound]); !ok || status != http.StatusGone {
			t.Errorf("%s: a body past the bound: the first %d bytes covered %v, %d", path, bound, ok, status)
		}
	}
}

// TestAPostFindingsBodyVerifiesWhole pins a POST findings of exactly 8 MiB on the one
// address, whose 200 has a signature over the whole body, and one byte more, whose signed
// 413 has one too; an answer to a body that differs in one byte, past 2 MiB or at its end,
// fails verification, as for a body altered on its way.
func TestAPostFindingsBodyVerifiesWhole(t *testing.T) {
	c := gatewayControl(t)
	f := runAPIOf(c)
	f.passAttach.Store(true)
	serveHostCalls(f)
	r := startRemote(t, c, gateway.Config{})
	e := r.open(t, runKeyFor(t, event.NewRunID(), nil), server.LinkRunRequest{})
	f.reset()
	path := "/qory-link/run-configuration/" + e.a.RunID + "/findings"
	body := bytes.Repeat([]byte("a"), 8<<20)
	if got := r.do(t, e.key, http.MethodPost, path, body); got.status != http.StatusOK {
		t.Errorf("8 MiB: %d %s", got.status, got.body)
	}
	if got := r.do(t, e.key, http.MethodPost, path, append(bytes.Clone(body), 'a')); got.status != http.StatusRequestEntityTooLarge || got.refusal()["error"] != "payload_too_large" {
		t.Errorf("8 MiB and a byte: %d %s", got.status, got.body)
	}
	for _, at := range []int{3 << 20, len(body) - 1} {
		sent := bytes.Clone(body)
		sent[at] = 'b'
		if ok, status := sendBound(t, r, e.key, path, sent, body); ok || status != http.StatusOK {
			t.Errorf("a body altered at byte %d: verifies %v, %d", at, ok, status)
		}
	}
	if seen := f.requests(); len(seen) != 3 || !bytes.Equal(seen[0].body, body) {
		t.Errorf("the control plane got %d requests", len(seen))
	}
	isFree(t, "after the bodies", r.g)
}

// budgetAt is the two ways to a gateway's findings calls that the budget's tests take, the
// local link and the one address, with two runs of the gateway.
type budgetAt struct {
	t      *testing.T
	g      *gateway.Gateway
	f      *fakeRunAPI
	remote bool
	// runs are the ids of the two runs, send sends a request of run with body to the path
	// under its id and returns its answer, and sendTo, of the one address alone, sends one
	// with run's key to any path.
	runs         [2]string
	send, sendTo func(run int, method, path string, body []byte) answer
	// dial opens a connection for a request, and lineTo is the request line of a method
	// and a run id's findings on it, with the headers every request of the first run has.
	dial   func() net.Conn
	lineTo func(method, runID string) string
	// end ends run at the gateway, and holdReports keeps each line the gateway reports
	// from its end until the returned func is called.
	end         func(run int)
	holdReports func() (unhold func())
}

// head is the request line of the first run's findings call of method, with the headers
// every request has.
func (at *budgetAt) head(method string) string { return at.lineTo(method, at.runs[0]) }

// call sends the first run's findings call of method and returns its status and the
// refusal's code, message and from.
func (at *budgetAt) call(method string, body []byte) (status int, code, message, from string) {
	return at.refusalOf(at.send(0, method, "/findings", body))
}

// refusalOf is got's status and its refusal's code, message and from.
func (at *budgetAt) refusalOf(got answer) (status int, code, message, from string) {
	if got.status == http.StatusOK {
		return got.status, "", "", ""
	}
	validDocument(at.t, "link-refusal.schema.json", got.body)
	ref := got.refusal()
	if ref["retry_after"] != nil {
		at.t.Errorf("retry_after %v", ref["retry_after"])
	}
	code, _ = ref["error"].(string)
	message, _ = ref["message"].(string)
	from, _ = ref["from"].(string)
	return got.status, code, message, from
}

// stall opens a connection, sends the first run's POST findings with a Content-Length of
// size and sent bytes of the body, and returns the connection. The gateway reads them all
// but what the connection buffers, so a caller that writes before it reads gets its
// answer.
func (at *budgetAt) stall(size, sent int) net.Conn {
	conn := at.dial()
	at.write(conn, at.head(http.MethodPost), size, sent)
	return conn
}

// write writes head, a Content-Length of size and sent bytes of the body to conn, and
// fails the test unless all are written within 20 seconds.
func (at *budgetAt) write(conn net.Conn, head string, size, sent int) {
	at.t.Helper()
	conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
	fmt.Fprintf(conn, "%sContent-Length: %d\r\n\r\n", head, size)
	if _, err := conn.Write(make([]byte, sent)); err != nil {
		at.t.Errorf("the write of a body: %v", err)
	}
}

// statusOn is the status of the answer on conn, read within 20 seconds.
func statusOn(t *testing.T, conn net.Conn) int {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Errorf("no answer: %v", err)
		return 0
	}
	return resp.StatusCode
}

// budgetWays runs try on the local link and on the one address.
func budgetWays(t *testing.T, cfg func(*gateway.Config), try func(t *testing.T, at *budgetAt)) {
	t.Run("the local link", func(t *testing.T) {
		c := newControl(t)
		f := runAPIOf(c)
		conf := gateway.Config{Server: c.server()}
		cfg(&conf)
		h := start(t, conf)
		at := &budgetAt{t: t, g: h.g, f: f}
		for i := range at.runs {
			at.runs[i] = startRunAPIRun(t, h, f).a.RunID
		}
		serveHostCalls(f)
		f.reset()
		at.send = func(run int, method, path string, body []byte) answer {
			status, got := sendRaw(t, h, method, "/v1/run-configuration/"+at.runs[run]+path, body)
			return answer{status: status, body: got}
		}
		at.dial = func() net.Conn {
			conn, err := net.Dial("unix", h.g.LocalLink().Socket)
			if err != nil {
				t.Fatal(err)
			}
			return conn
		}
		at.lineTo = func(method, runID string) string {
			return line(method, "/v1/run-configuration/"+runID+"/findings") + "Host: localhost\r\nContent-Type: application/json\r\n"
		}
		at.end = func(run int) { h.post(exited(at.runs[run])) }
		at.holdReports = func() func() {
			h.mu.Lock()
			return h.mu.Unlock
		}
		try(t, at)
	})
	t.Run("the one address", func(t *testing.T) {
		c := gatewayControl(t)
		f := runAPIOf(c)
		f.passAttach.Store(true)
		serveHostCalls(f)
		var conf gateway.Config
		cfg(&conf)
		r := startRemote(t, c, conf)
		at := &budgetAt{t: t, g: r.g, f: f, remote: true}
		var keys [2]string
		for i := range at.runs {
			e := r.open(t, runKeyFor(t, event.NewRunID(), nil), server.LinkRunRequest{})
			at.runs[i], keys[i] = e.a.RunID, e.key
		}
		f.reset()
		at.sendTo = func(run int, method, path string, body []byte) answer {
			return r.do(t, keys[run], method, path, body)
		}
		at.send = func(run int, method, path string, body []byte) answer {
			return at.sendTo(run, method, "/qory-link/run-configuration/"+at.runs[run]+path, body)
		}
		at.dial = func() net.Conn {
			b, err := r.bind(t, gatewayKeys())
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		at.lineTo = func(method, runID string) string {
			return line(method, "/qory-link/run-configuration/"+runID+"/findings") + "Host: gateway.example:8443\r\nAuthorization: Bearer " + keys[0] + "\r\nContent-Type: application/json\r\n"
		}
		at.end = func(run int) {
			body, _ := json.Marshal([]map[string]any{exited(at.runs[run])})
			if got := at.sendTo(run, http.MethodPost, "/qory-link/events", body); got.status != http.StatusAccepted {
				t.Fatalf("the run's end: %d %s", got.status, got.body)
			}
		}
		at.holdReports = func() func() {
			r.mu.Lock()
			return r.mu.Unlock
		}
		try(t, at)
	})
}

// TestAFullBudgetRefusesAFindingsCall pins the gateway's 512 MiB for the findings calls:
// while it is full, a POST of 1 MiB and an answer of 1 MiB pass; a longer POST, up to the
// limit, is 429 rate_limited from the gateway, with nothing sent, and a longer
// answer is 429, with the answer dropped; and each passes once the budget has room, which
// is free again after every call.
func TestAFullBudgetRefusesAFindingsCall(t *testing.T) {
	budgetWays(t, func(*gateway.Config) {}, func(t *testing.T, at *budgetAt) {
		answerOf := func(n int) {
			at.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) {
				at.f.sign(w, r, http.StatusOK, bytes.Repeat([]byte(" "), n))
			})
		}
		answerOf(2)
		release := fill(t, at.g, 0)
		if status, code, _, _ := at.call(http.MethodPost, make([]byte, freeBytes)); status != http.StatusOK {
			t.Errorf("a POST of 1 MiB: %d %s", status, code)
		}
		sent := len(at.f.requests())
		for _, n := range []int{freeBytes + 1, 8 << 20} {
			status, code, message, from := at.call(http.MethodPost, make([]byte, n))
			if status != http.StatusTooManyRequests || code != "rate_limited" || from != "gateway" || !strings.HasPrefix(message, "Retry in 1 second: ") || !strings.HasSuffix(message, "and this body would pass that.") {
				t.Errorf("a POST of %d bytes: %d %s from %s: %s", n, status, code, from, message)
			}
		}
		if n := len(at.f.requests()); n != sent {
			t.Errorf("the control plane got %d POSTs past the budget", n-sent)
		}
		answerOf(freeBytes)
		if status, code, _, _ := at.call(http.MethodGet, nil); status != http.StatusOK {
			t.Errorf("an answer of 1 MiB: %d %s", status, code)
		}
		answerOf(freeBytes + 1)
		status, code, message, from := at.call(http.MethodGet, nil)
		if status != http.StatusTooManyRequests || code != "rate_limited" || from != "gateway" || !strings.HasPrefix(message, "Retry in 1 second: ") || !strings.HasSuffix(message, "The gateway dropped the answer.") {
			t.Errorf("an answer past the budget: %d %s from %s: %s", status, code, from, message)
		}
		if hasRoom(at.g, 1) {
			t.Error("a call gave back bytes it did not take")
		}

		release()
		isFree(t, "after the calls", at.g)
		if status, code, _, _ := at.call(http.MethodGet, nil); status != http.StatusOK {
			t.Errorf("an answer once the budget has room: %d %s", status, code)
		}
		answerOf(2)
		if status, code, _, _ := at.call(http.MethodPost, make([]byte, 8<<20)); status != http.StatusOK {
			t.Errorf("a POST once the budget has room: %d %s", status, code)
		}
		isFree(t, "after the retries", at.g)
	})
}

// TestAFindingsBodyCountsBeforeItIsSigned pins the order on a POST findings: the body is
// bounded and counted as it arrives, and only then signed and sent. A body over the
// budget's room ends the count with nothing sent while its last bytes are still to come;
// a body that arrives counts past its first 1 MiB; at the control plane the count is
// whole; and it is free after the answer and after a caller that hangs up, while its body
// arrives and while the control plane has the request.
func TestAFindingsBodyCountsBeforeItIsSigned(t *testing.T) {
	budgetWays(t, func(*gateway.Config) {}, func(t *testing.T, at *budgetAt) {
		const size = 3 << 20
		counted := make(chan bool, 1)
		at.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) {
			// The count is the body's 2 MiB past the first, no more and no less.
			counted <- hasRoom(at.g, memoryBudget-(size-freeBytes)) && !hasRoom(at.g, memoryBudget-(size-freeBytes)+1)
			at.f.sign(w, r, http.StatusOK, []byte(`{}`))
		})
		if status, code, _, _ := at.call(http.MethodPost, make([]byte, size)); status != http.StatusOK || !<-counted {
			t.Errorf("the body's count at the control plane: %d %s", status, code)
		}
		isFree(t, "after the answer", at.g)

		// A body that stalls.
		at.f.reset()
		conn := at.dial()
		defer conn.Close()
		fmt.Fprintf(conn, "%sContent-Length: %d\r\n\r\n", at.head(http.MethodPost), size)
		if !hasRoom(at.g, memoryBudget) {
			t.Error("a head with a Content-Length counts")
		}
		conn.Write(make([]byte, 2<<20))
		eventually(t, "the arrived bytes counted", func() bool { return !hasRoom(at.g, memoryBudget-freeBytes+1) && hasRoom(at.g, memoryBudget-freeBytes) })
		conn.Close()
		isFree(t, "after a caller that hung up in its body", at.g)

		// A body that stalls past the budget's room: the count ended before the last byte.
		release := fill(t, at.g, freeBytes/2)
		conn = at.dial()
		defer conn.Close()
		fmt.Fprintf(conn, "%sContent-Length: %d\r\n\r\n", at.head(http.MethodPost), size)
		conn.Write(make([]byte, size-1))
		eventually(t, "the bytes of a body past the room given back", func() bool { return hasRoom(at.g, freeBytes/2) })
		conn.Write(make([]byte, 1))
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil || resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("a body past the budget's room: %v %v", resp, err)
		}
		conn.Close()

		// A caller that writes its whole body before it reads gets the 429 too.
		conn = at.dial()
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(20 * time.Second))
		fmt.Fprintf(conn, "%sContent-Length: %d\r\n\r\n", at.head(http.MethodPost), server.MaxPostFindingsRequest)
		if _, err := conn.Write(make([]byte, server.MaxPostFindingsRequest)); err != nil {
			t.Errorf("the write of a body past the budget's room: %v", err)
		}
		resp, err = http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil || resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("a whole body past the budget's room: %v %v", resp, err)
		}
		conn.Close()
		release()
		if seen := at.f.requests(); len(seen) != 0 {
			t.Errorf("the control plane got %d requests", len(seen))
		}
		isFree(t, "after a body past the room", at.g)

		// A caller that hangs up while the control plane has the request.
		arrived, ended := holdHostCalls(at.f)
		conn = at.dial()
		fmt.Fprintf(conn, "%sContent-Length: %d\r\n\r\n", at.head(http.MethodPost), size)
		conn.Write(make([]byte, size))
		within(t, "the request at the control plane", arrived, 10*time.Second)
		if hasRoom(at.g, memoryBudget) {
			t.Error("a body at the control plane does not count")
		}
		conn.Close()
		within(t, "the control plane's request cancelled", ended, 5*time.Second)
		isFree(t, "after a caller that hung up", at.g)
	})
}

// TestAFindingsBodyIsBounded pins the limit of a POST findings body, 8 MiB. A
// Content-Length one byte over it is 413 before the gateway reads the body: on the local
// link while the caller holds the body back, and on the one address, which reads the body
// to sign the answer, while the memory budget is full. A Content-Length at the limit
// passes the head: with the budget full its body is read and 429, and with room it is
// sent. A chunked body one byte over the limit is 413 once read, and a body over the limit
// of another run's id gets the refusal of the run id. Nothing else is sent, and nothing
// counts after the answers.
func TestAFindingsBodyIsBounded(t *testing.T) {
	const limit = server.MaxPostFindingsRequest
	budgetWays(t, func(*gateway.Config) {}, func(t *testing.T, at *budgetAt) {
		// send writes head, a Content-Length of size and sent bytes of the body, and
		// returns the answer's status.
		send := func(head string, size, sent int) int {
			conn := at.dial()
			defer conn.Close()
			at.write(conn, head, size, sent)
			return statusOn(t, conn)
		}
		release := fill(t, at.g, 0)
		over := limit + 1
		if !at.remote {
			// The gateway closes the connection after the 413 with the body unread: a caller
			// that still writes 8 MiB gets an error.
			over = 0
		}
		if status := send(at.head(http.MethodPost), limit+1, over); status != http.StatusRequestEntityTooLarge {
			t.Errorf("a Content-Length over the limit with the budget full: %d", status)
		}
		if status := send(at.head(http.MethodPost), limit, limit); status != http.StatusTooManyRequests {
			t.Errorf("a Content-Length at the limit with the budget full: %d", status)
		}
		release()

		conn := at.dial()
		defer conn.Close()
		conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
		fmt.Fprintf(conn, "%sTransfer-Encoding: chunked\r\n\r\n%x\r\n", at.head(http.MethodPost), limit+1)
		conn.Write(make([]byte, limit+1))
		io.WriteString(conn, "\r\n0\r\n\r\n")
		if status := statusOn(t, conn); status != http.StatusRequestEntityTooLarge {
			t.Errorf("a chunked body over the limit: %d", status)
		}

		unknown := event.NewRunID()
		if at.remote {
			unknown = at.runs[1]
		}
		if status := send(at.lineTo(http.MethodPost, unknown), limit+1, limit+1); status != http.StatusBadRequest {
			t.Errorf("a body over the limit of another run id: %d", status)
		}
		if seen := at.f.requests(); len(seen) != 0 {
			t.Errorf("the control plane got %d requests", len(seen))
		}
		isFree(t, "after the refusals", at.g)
		if status := send(at.head(http.MethodPost), limit, limit); status != http.StatusOK {
			t.Errorf("a body at the limit: %d", status)
		}
		if seen := at.f.requests(); len(seen) != 1 || len(seen[0].body) != limit {
			t.Errorf("the control plane got %d requests", len(seen))
		}
		isFree(t, "after the answer", at.g)
	})
}

// TestAFindingsAnswerCountsUntilItIsWritten pins the count of a GET findings answer: it
// counts while the caller has not read it, on the one address too, where the gateway
// signs it whole before it writes it, and is free once the caller hangs up, and once the
// time of a host call passed for a caller that stops reading.
func TestAFindingsAnswerCountsUntilItIsWritten(t *testing.T) {
	const size = 16 << 20
	const wait = 10 * time.Second
	budgetWays(t, func(c *gateway.Config) { gateway.SetHostCallTime(c, wait) }, func(t *testing.T, at *budgetAt) {
		at.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) {
			at.f.sign(w, r, http.StatusOK, make([]byte, size))
		})
		for _, hangUp := range []bool{true, false} {
			conn := at.dial()
			defer conn.Close()
			io.WriteString(conn, at.head(http.MethodGet)+"\r\n")
			eventually(t, "the answer counted", func() bool { return !hasRoom(at.g, memoryBudget-(size-freeBytes)+1) })
			if hangUp {
				conn.Close()
			}
			freeWithin(t, fmt.Sprintf("after the caller's end, hang up %v", hangUp), at.g, 3*wait)
		}
	})
}

// TestAFindingsGETWithABodyIsRefused pins the refusal of a GET findings with a body, by
// its Content-Length and chunked: 400 invalid_request from the gateway while the caller
// holds the body back, with nothing sent and nothing counted; on the local link the
// connection closes after the 400. The refused GET takes no place of the run, so the
// run's next GET findings, with no body, passes while the first caller keeps its
// connection open.
func TestAFindingsGETWithABodyIsRefused(t *testing.T) {
	budgetWays(t, func(*gateway.Config) {}, func(t *testing.T, at *budgetAt) {
		const want = "Send the GET findings request with no body: the gateway sent nothing."
		for _, head := range []string{"Content-Length: 1\r\n", "Transfer-Encoding: chunked\r\n"} {
			conn := at.dial()
			defer conn.Close()
			io.WriteString(conn, at.head(http.MethodGet)+head+"\r\n")
			conn.SetReadDeadline(time.Now().Add(20 * time.Second))
			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Errorf("a GET with %q: no answer: %v", head, err)
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			if status, code, message, from := at.refusalOf(answer{status: resp.StatusCode, body: body}); status != http.StatusBadRequest || code != "invalid_request" || from != "gateway" || message != want {
				t.Errorf("a GET with %q: %d %s from %s: %q", head, status, code, from, message)
			}
			if !at.remote {
				// net/http reads up to 256 KiB of a body left unread after the handler. Behind
				// a separate gateway, that read has the 10 seconds the gateway gives the body
				// of a refused request, so the check runs on the local link alone.
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, err = io.Copy(io.Discard, br)
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					t.Errorf("a GET with %q: the connection is open 2 seconds after the 400", head)
				}
			}
			if status, code, _, _ := at.call(http.MethodGet, nil); status != http.StatusOK {
				t.Errorf("a GET with no body after one with %q: %d %s", head, status, code)
			}
		}
		if seen := at.f.requests(); len(seen) != 2 {
			t.Errorf("the control plane got %d requests", len(seen))
		}
		isFree(t, "after the GETs", at.g)
	})
}

// TestAFindingsHeadIsCheckedBeforeThePlace pins that the head of a findings call is
// checked before the run's place: while the run has a GET findings in flight, a GET with
// a body is 400 invalid_request, and while it has a POST findings in flight, a POST whose
// Content-Length is over the limit is 413 payload_too_large, neither 429. Nothing of
// either is sent.
func TestAFindingsHeadIsCheckedBeforeThePlace(t *testing.T) {
	const limit = server.MaxPostFindingsRequest
	budgetWays(t, func(*gateway.Config) {}, func(t *testing.T, at *budgetAt) {
		arrived, let := make(chan struct{}, 2), make(chan struct{})
		at.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) {
			arrived <- struct{}{}
			select {
			case <-let:
			case <-r.Context().Done():
			}
			at.f.sign(w, r, http.StatusOK, []byte(`{}`))
		})
		done := make(chan int, 2)
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			var body []byte
			if method == http.MethodPost {
				body = []byte(`{}`)
			}
			go func() { done <- at.send(0, method, "/findings", body).status }()
			within(t, method+" findings at the control plane", arrived, 10*time.Second)
		}

		conn := at.dial()
		defer conn.Close()
		io.WriteString(conn, at.head(http.MethodGet)+"Content-Length: 1\r\n\r\n")
		if status := statusOn(t, conn); status != http.StatusBadRequest {
			t.Errorf("a GET with a body beside a GET in flight: %d", status)
		}
		over := limit + 1
		if !at.remote {
			// On the local link the gateway reads none of the body before the 413: a caller
			// that still writes 8 MiB gets an error.
			over = 0
		}
		large := at.dial()
		defer large.Close()
		at.write(large, at.head(http.MethodPost), limit+1, over)
		if status := statusOn(t, large); status != http.StatusRequestEntityTooLarge {
			t.Errorf("a Content-Length over the limit beside a POST in flight: %d", status)
		}
		if n := len(at.f.requests()); n != 2 {
			t.Errorf("the control plane got %d requests", n)
		}
		close(let)
		for range 2 {
			if status := <-done; status != http.StatusOK {
				t.Errorf("a request in flight: %d", status)
			}
		}
		isFree(t, "at the end", at.g)
	})
}

// TestAFindingsBodyCountsUntilTheCallEnds pins that a POST findings body is free once the
// call to the control plane ends: while the gateway writes the line of a failed call to its
// log, and while the caller does not read the answer; and that the run's next POST passes
// once the time of a host call passed.
func TestAFindingsBodyCountsUntilTheCallEnds(t *testing.T) {
	const wait = 6 * time.Second
	budgetWays(t, func(c *gateway.Config) { gateway.SetHostCallTime(c, wait) }, func(t *testing.T, at *budgetAt) {
		at.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) {
			at.f.sign(w, r, http.StatusGone, []byte(`{"error":"run_closed"}`))
		})
		unhold := sync.OnceFunc(at.holdReports())
		defer unhold()
		failed := make(chan int, 1)
		go func() { failed <- at.send(0, http.MethodPost, "/findings", make([]byte, 3<<20)).status }()
		eventually(t, "the POST at the control plane", func() bool { return len(at.f.requests()) == 1 })
		freeWithin(t, "while the gateway reports the failed call", at.g, wait/2)
		unhold()
		if status := <-failed; status != http.StatusBadGateway {
			t.Errorf("a POST whose call failed: %d", status)
		}

		sent := make(chan struct{}, 1)
		at.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) {
			at.f.sign(w, r, http.StatusOK, bytes.Repeat([]byte(" "), 64<<10))
			sent <- struct{}{}
		})
		conn := at.stall(3<<20, 3<<20)
		defer conn.Close()
		within(t, "the answer", sent, 10*time.Second)
		freeWithin(t, "with the answer unread", at.g, wait/2)
		eventually(t, "the next POST", func() bool {
			status, _, _, _ := at.call(http.MethodPost, []byte(`{}`))
			return status == http.StatusOK
		})
	})
}

// TestARunHasOneFindingsCallOfAMethodInFlight pins the one POST findings and the one GET
// findings of a run in flight: from before its body is read, a second one is 429
// rate_limited from the gateway, with nothing sent and nothing counted, its body over
// 1 MiB among them; one POST beside one GET, another run's, and two next-session requests
// pass; and the next one passes after an answer, a refusal, a failed call, a body cut off,
// and a caller that hangs up while the control plane has the request, which ends the
// request's handler in a panic.
func TestARunHasOneFindingsCallOfAMethodInFlight(t *testing.T) {
	budgetWays(t, func(*gateway.Config) {}, func(t *testing.T, at *budgetAt) {
		arrived, let := make(chan struct{}, 16), make(chan struct{})
		at.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) {
			arrived <- struct{}{}
			select {
			case <-let:
			case <-r.Context().Done():
			}
			at.f.sign(w, r, http.StatusOK, []byte(`{}`))
		})
		refused := func(what, method string, body []byte) {
			t.Helper()
			status, code, message, from := at.call(method, body)
			want := "Retry once the run's other " + method + " findings request ends: a run has at most one in flight.\nThe gateway sent nothing."
			if status != http.StatusTooManyRequests || code != "rate_limited" || from != "gateway" || message != want {
				t.Errorf("%s: %d %s from %s: %q", what, status, code, from, message)
			}
		}
		done := make(chan int, 16)
		hold := func(run int, method, path string, body []byte) {
			t.Helper()
			go func() { done <- at.send(run, method, path, body).status }()
			within(t, fmt.Sprintf("run %d: %s %s at the control plane", run, method, path), arrived, 10*time.Second)
		}
		hold(0, http.MethodPost, "/findings", make([]byte, 3<<20))
		refused("a second POST", http.MethodPost, []byte(`{}`))
		refused("a second POST of 8 MiB", http.MethodPost, make([]byte, 8<<20))
		whole := at.stall(8<<20, 8<<20)
		defer whole.Close()
		if status := statusOn(t, whole); status != http.StatusTooManyRequests {
			t.Errorf("a second POST whose caller writes its body first: %d", status)
		}
		if used := gateway.UsedRunAPI(at.g); used != 2<<20 {
			t.Errorf("%d bytes count beside a second POST", used)
		}
		hold(0, http.MethodGet, "/findings", nil)
		refused("a second GET", http.MethodGet, nil)
		hold(1, http.MethodPost, "/findings", []byte(`{}`))
		hold(1, http.MethodGet, "/findings", nil)
		hold(0, http.MethodPost, "/next-session", []byte(`{}`))
		hold(0, http.MethodPost, "/next-session", []byte(`{}`))
		if n := len(at.f.requests()); n != 6 {
			t.Errorf("the control plane got %d requests", n)
		}
		close(let)
		for range 6 {
			if status := <-done; status != http.StatusOK {
				t.Errorf("a request in flight: %d", status)
			}
		}

		passes := func(what string) {
			t.Helper()
			serveHostCalls(at.f)
			for _, method := range []string{http.MethodPost, http.MethodGet} {
				if status, code, _, _ := at.call(method, nil); status != http.StatusOK {
					t.Errorf("%s: %s findings: %d %s", what, method, status, code)
				}
			}
		}
		passes("after an answer")
		at.call(http.MethodPost, make([]byte, 8<<20+1))
		passes("after a 413")
		release := fill(t, at.g, 0)
		at.call(http.MethodPost, make([]byte, 2<<20))
		release()
		passes("after a 429 of the budget")
		at.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) { w.WriteHeader(http.StatusInternalServerError) })
		for _, method := range []string{http.MethodPost, http.MethodGet} {
			if status, _, _, _ := at.call(method, nil); status != http.StatusBadGateway {
				t.Errorf("a failed %s: %d", method, status)
			}
		}
		passes("after a failed call")

		// frees is passes once the caller that hung up has let go.
		frees := func(what, method string) {
			t.Helper()
			serveHostCalls(at.f)
			eventually(t, what, func() bool {
				status, _, _, _ := at.call(method, nil)
				return status == http.StatusOK
			})
		}
		conn := at.stall(3<<20, 2<<20)
		eventually(t, "a part of a body counted", func() bool { return gateway.UsedRunAPI(at.g) > 0 })
		refused("a second POST while the first's body arrives", http.MethodPost, []byte(`{}`))
		conn.Close()
		frees("a POST after a body cut off", http.MethodPost)
		for _, method := range []string{http.MethodPost, http.MethodGet} {
			arrived, ended := holdHostCalls(at.f)
			conn := at.dial()
			head := at.head(method)
			if method == http.MethodPost {
				head += "Content-Length: 0\r\n"
			}
			io.WriteString(conn, head+"\r\n")
			within(t, "the request at the control plane", arrived, 10*time.Second)
			refused("a second "+method+" before the hang up", method, nil)
			conn.Close()
			within(t, "the control plane's request cancelled", ended, 10*time.Second)
			frees("a "+method+" after a hang up", method)
		}
		isFree(t, "at the end", at.g)
	})
}

// TestAFindingsRunIDIsCheckedBeforeItsBody pins that the body of a POST findings of no run
// here, on the local link, and of another run than the run key's, on the one address,
// counts nothing and takes no run's place, and that its refusal is the one of every other
// request of the run id, also while that run has a POST in flight.
func TestAFindingsRunIDIsCheckedBeforeItsBody(t *testing.T) {
	budgetWays(t, func(*gateway.Config) {}, func(t *testing.T, at *budgetAt) {
		want := "invalid_request"
		unknown := event.NewRunID()
		if at.remote {
			want, unknown = "run_key_invalid", at.runs[1]
		}
		conn := at.dial()
		defer conn.Close()
		at.write(conn, at.lineTo(http.MethodPost, unknown), 8<<20, 8<<20-1)
		if used := gateway.UsedRunAPI(at.g); used != 0 {
			t.Errorf("%d bytes of a body of no run count", used)
		}
		for run := range at.runs {
			if got := at.send(run, http.MethodPost, "/findings", []byte(`{}`)); got.status != http.StatusOK {
				t.Errorf("run %d beside it: %d %s", run, got.status, got.body)
			}
		}
		conn.Write(make([]byte, 1))
		conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		if status, code, _, from := at.refusalOf(answer{status: resp.StatusCode, body: body}); status != http.StatusBadRequest || code != want || from != "gateway" {
			t.Errorf("%d %s from %s", status, code, from)
		}
		if n := len(at.f.requests()); n != 2 {
			t.Errorf("the control plane got %d requests", n)
		}
		if !at.remote {
			return
		}
		arrived, _ := holdHostCalls(at.f)
		held := at.dial()
		defer held.Close()
		io.WriteString(held, at.head(http.MethodPost)+"Content-Length: 0\r\n\r\n")
		within(t, "a POST at the control plane", arrived, 10*time.Second)
		path := "/qory-link/run-configuration/" + at.runs[0] + "/findings"
		if status, code, _, _ := at.refusalOf(at.sendTo(1, http.MethodPost, path, []byte(`{}`))); status != http.StatusBadRequest || code != want {
			t.Errorf("another run's key while the run has a POST in flight: %d %s", status, code)
		}
	})
}

// TestAFindingsBodyOnTheLocalLinkHasItsTime pins the time of a POST findings body on the
// local link, the time of a host call: a body that stalls, one past the budget's room, one
// of a run with a POST in flight and one of no run get their answer once it passed, with
// nothing counted after it; a body that ends in time leaves the call its whole time; and
// a POST with no body whose call passes the time of a host call gets the gateway's 502.
func TestAFindingsBodyOnTheLocalLinkHasItsTime(t *testing.T) {
	const wait = 4 * time.Second
	budgetWays(t, func(c *gateway.Config) { gateway.SetHostCallTime(c, wait) }, func(t *testing.T, at *budgetAt) {
		if at.remote {
			return // Its server has a time for every body, EdgeReadWait.
		}
		conn := at.stall(8<<20, 8<<20-1)
		defer conn.Close()
		eventually(t, "the body counted", func() bool { return gateway.UsedRunAPI(at.g) == 7<<20-1 })
		second := at.stall(8<<20, 8<<20-1)
		defer second.Close()
		if status := statusOn(t, second); status != http.StatusTooManyRequests {
			t.Errorf("a second body that stalls: %d", status)
		}
		if status := statusOn(t, conn); status != http.StatusBadRequest {
			t.Errorf("a body that stalls: %d", status)
		}
		isFree(t, "after a body that stalled", at.g)

		unknown := at.dial()
		defer unknown.Close()
		fmt.Fprintf(unknown, "%sContent-Length: %d\r\n\r\n", at.lineTo(http.MethodPost, event.NewRunID()), 8<<20)
		if status := statusOn(t, unknown); status != http.StatusBadRequest {
			t.Errorf("a body of no run that stalls: %d", status)
		}
		release := fill(t, at.g, 0)
		past := at.stall(8<<20, 8<<20-1)
		defer past.Close()
		if status := statusOn(t, past); status != http.StatusTooManyRequests {
			t.Errorf("a body past the budget that stalls: %d", status)
		}
		release()
		isFree(t, "after a body past the budget", at.g)

		at.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) {
			time.Sleep(wait * 5 / 8)
			at.f.sign(w, r, http.StatusOK, []byte(`{}`))
		})
		slow := at.stall(2, 1)
		defer slow.Close()
		time.Sleep(wait * 5 / 8)
		slow.Write([]byte("x"))
		if status := statusOn(t, slow); status != http.StatusOK {
			t.Errorf("a call past the time of its body: %d", status)
		}

		// A read deadline on a POST of 0 bytes would end the request with no answer. The
		// deadline and the call's timer both end after wait, so this check fails for such
		// a deadline only when the deadline ends before the timer.
		arrived, _ := holdHostCalls(at.f)
		empty := at.dial()
		defer empty.Close()
		io.WriteString(empty, at.head(http.MethodPost)+"Content-Length: 0\r\n\r\n")
		within(t, "a POST with no body at the control plane", arrived, 10*time.Second)
		if status := statusOn(t, empty); status != http.StatusBadGateway {
			t.Errorf("a POST with no body past the time of a host call: %d", status)
		}
	})
}

// TestAFindingsBodyOfARunThatEndedCountsNothing pins that the gateway answers a POST
// findings of a run that ended at the gateway with the run's 410 before it reads the
// body: the body counts nothing, and nothing is sent.
func TestAFindingsBodyOfARunThatEndedCountsNothing(t *testing.T) {
	budgetWays(t, func(*gateway.Config) {}, func(t *testing.T, at *budgetAt) {
		at.end(0)
		eventually(t, "the run's end", func() bool { return at.send(0, http.MethodGet, "/findings", nil).status == http.StatusGone })
		at.f.reset()
		conn := at.dial()
		defer conn.Close()
		at.write(conn, at.head(http.MethodPost), 8<<20, 8<<20-1)
		// The write can end before the gateway reads a byte: Linux's loopback buffers can
		// take the whole body. The check therefore goes on for 500 ms.
		for end := time.Now().Add(500 * time.Millisecond); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
			if used := gateway.UsedRunAPI(at.g); used != 0 {
				t.Errorf("%d bytes of a body of a run that ended count", used)
				break
			}
		}
		conn.Write(make([]byte, 1))
		if status := statusOn(t, conn); status != http.StatusGone {
			t.Errorf("a POST findings of a run that ended: %d", status)
		}
		if n := len(at.f.requests()); n != 0 {
			t.Errorf("the control plane got %d requests", n)
		}
	})
}

// TestNoContainerAddsToTheFindingsBudget pins that a program in a container, which
// reaches no host call, takes nothing of the budget with a POST to the findings path of
// the run API's route: the route's 404 comes with nothing counted and nothing sent.
func TestNoContainerAddsToTheFindingsBudget(t *testing.T) {
	o := openRunAPIRun(t)
	serveHostCalls(o.f)
	o.f.reset()
	release := fill(t, o.h.g, 0)
	defer release()
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		resp, b, _ := o.send(line(method, o.url("/findings"))+"Content-Type: application/json\r\nContent-Length: 2\r\n", []byte("{}"))
		routeError(t, method+" findings through the run API route", resp, b, http.StatusNotFound, "not_found")
	}
	if got := o.f.requests(); len(got) != 0 {
		t.Errorf("the control plane got %+v", got)
	}
}

// TestAFindingsCallEndsWithItsRun pins the findings calls of a run that ends at the
// gateway while the control plane has the request: the caller gets the run's 410, and the
// budget is free.
func TestAFindingsCallEndsWithItsRun(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		o := openRunAPIRun(t)
		arrived, _ := holdHostCalls(o.f)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := hostCallOn(ctx, o.h, o.a.RunID, method+" /findings", make([]byte, 2<<20))
			done <- err
		}()
		within(t, "the request at the control plane", arrived, 10*time.Second)
		o.h.post(exited(o.a.RunID))
		err := <-done
		if end, ok := server.Ended(err); !ok || end.From != accesskey.FromGateway {
			t.Errorf("%s findings of a run that ended meanwhile: %v (%+v)", method, err, end)
		}
		isFree(t, method+" findings", o.h.g)
	}
}
