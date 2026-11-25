package gateway_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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
func hasRoom(g *gateway.Gateway, n int) bool {
	release, ok := gateway.ChargeRunAPI(g, n)
	if ok {
		release()
	}
	return ok
}

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
	eventually(t, what+": the whole memory budget free", func() bool { return hasRoom(g, memoryBudget) && !hasRoom(g, memoryBudget+1) })
}

// sendRaw sends a request of method to path on the local link of h, with body, and
// returns the status.
func sendRaw(t *testing.T, h *harness, method, path string, body []byte) int {
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
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestAHostCallHasItsMethod pins the method of each host call, on the local link and on
// the one address: a GET of findings is sent as a GET, with no body and no Content-Type
// though the caller sent both, and a POST as a POST; a GET of next-session and of
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
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			if status := sendRaw(t, o.h, method, base+"/findings", []byte(`{"a":1}`)); status != http.StatusOK {
				t.Errorf("%s findings: %d", method, status)
			}
		}
		for _, path := range []string{"/next-session", "/pushed-commits"} {
			if status := sendRaw(t, o.h, http.MethodGet, base+path, nil); status != http.StatusBadRequest {
				t.Errorf("GET %s: %d", path, status)
			}
		}
		for _, method := range others {
			for _, path := range []string{"/next-session", "/findings"} {
				if status := sendRaw(t, o.h, method, base+path, []byte(`{}`)); status != http.StatusMethodNotAllowed {
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
		// The signature of a GET's answer covers no body, though the GET has one.
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			if got := r.do(t, e.key, method, base+"/findings", []byte(`{"a":1}`)); got.status != http.StatusOK {
				t.Errorf("%s findings: %d %s", method, got.status, got.body)
			}
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
			got, err := hostCall(o.h, o.a.RunID, l.method+" /findings", []byte(`{}`))
			signed := r.do(t, e.key, l.method, "/qory-link/run-configuration/"+e.a.RunID+"/findings", []byte(`{}`))
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

// budgetAt is the two ways to a gateway's findings calls that the budget's tests take:
// call sends one and returns its status and the refusal's code, message and from.
type budgetAt struct {
	g    *gateway.Gateway
	f    *fakeRunAPI
	call func(method string, body []byte) (status int, code, message, from string)
	// dial opens a connection for a request, and head is the request line of a method on
	// it, with the headers every request has.
	dial func() net.Conn
	head func(method string) string
}

// budgetWays runs try on the local link and on the one address.
func budgetWays(t *testing.T, cfg func(*gateway.Config), try func(t *testing.T, at *budgetAt)) {
	t.Run("the local link", func(t *testing.T) {
		c := newControl(t)
		f := runAPIOf(c)
		conf := gateway.Config{Server: c.server()}
		cfg(&conf)
		o := startRunAPIRun(t, start(t, conf), f)
		serveHostCalls(f)
		f.reset()
		try(t, &budgetAt{g: o.h.g, f: f, call: func(method string, body []byte) (int, string, string, string) {
			_, err := hostCall(o.h, o.a.RunID, method+" /findings", body)
			var ref *accesskey.Refusal
			switch {
			case err == nil:
				return http.StatusOK, "", "", ""
			case errors.As(err, &ref):
				if ref.RetryAfter != 0 {
					t.Errorf("RetryAfter %v", ref.RetryAfter)
				}
				return ref.Status, ref.Code, ref.Text, ref.From
			}
			t.Errorf("%s findings: %v", method, err)
			return 0, "", "", ""
		}, dial: func() net.Conn {
			conn, err := net.Dial("unix", o.h.g.LocalLink().Socket)
			if err != nil {
				t.Fatal(err)
			}
			return conn
		}, head: func(method string) string {
			return line(method, "/v1/run-configuration/"+o.a.RunID+"/findings") + "Host: localhost\r\nContent-Type: application/json\r\n"
		}})
	})
	t.Run("the one address", func(t *testing.T) {
		c := gatewayControl(t)
		f := runAPIOf(c)
		f.passAttach.Store(true)
		serveHostCalls(f)
		var conf gateway.Config
		cfg(&conf)
		r := startRemote(t, c, conf)
		e := r.open(t, runKeyFor(t, event.NewRunID(), nil), server.LinkRunRequest{})
		f.reset()
		path := "/qory-link/run-configuration/" + e.a.RunID + "/findings"
		try(t, &budgetAt{g: r.g, f: f, call: func(method string, body []byte) (int, string, string, string) {
			got := r.do(t, e.key, method, path, body)
			if got.status == http.StatusOK {
				return got.status, "", "", ""
			}
			ref := got.refusal()
			code, _ := ref["error"].(string)
			message, _ := ref["message"].(string)
			from, _ := ref["from"].(string)
			validDocument(t, "link-refusal.schema.json", got.body)
			return got.status, code, message, from
		}, dial: func() net.Conn {
			b, err := r.bind(t, gatewayKeys())
			if err != nil {
				t.Fatal(err)
			}
			return b
		}, head: func(method string) string {
			return line(method, path) + "Host: gateway.example:8443\r\nAuthorization: Bearer " + e.key + "\r\nContent-Type: application/json\r\n"
		}})
	})
}

// TestAFullBudgetRefusesAFindingsCall pins the gateway's 512 MiB for the findings calls:
// while it is full, a POST of 1 MiB and an answer of 1 MiB pass; a longer POST, up to one
// past the limit, is 429 rate_limited from the gateway, with nothing sent, and a longer
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
		for _, n := range []int{freeBytes + 1, 8 << 20, 8<<20 + 1} {
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

// TestAFindingsBodyIsBounded pins that the gateway reads at most one byte over the limit
// of a POST findings: a body with a longer Content-Length is 413 while its caller still
// holds the rest back, nothing is sent, and its count ends with the answer.
func TestAFindingsBodyIsBounded(t *testing.T) {
	budgetWays(t, func(*gateway.Config) {}, func(t *testing.T, at *budgetAt) {
		conn := at.dial()
		defer conn.Close()
		fmt.Fprintf(conn, "%sContent-Length: %d\r\n\r\n", at.head(http.MethodPost), 64<<20)
		conn.Write(make([]byte, server.MaxPostFindingsRequest+1))
		conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil || resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("a body held back past the limit: %v %v", resp, err)
		}
		if seen := at.f.requests(); len(seen) != 0 {
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
	budgetWays(t, func(c *gateway.Config) { gateway.SetHostCallTime(c, 3*time.Second) }, func(t *testing.T, at *budgetAt) {
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
			isFree(t, fmt.Sprintf("after the caller's end, hang up %v", hangUp), at.g)
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
