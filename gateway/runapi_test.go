package gateway_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// The tests of this file pin the route from a run to Qory Apiary's run API, at a real
// gateway in front of a fake run API, with raw requests where a target has to reach the
// proxy exactly as written.

const runAPIOrigin = "http://" + link.RunAPIHost

// runAPIRequest is one request that reached the fake run API.
type runAPIRequest struct {
	method, target string
	header         http.Header
	body           []byte
}

// fakeRunAPI is the run API of a control: it keeps every request that reaches the
// control other than the gateway's registration, deliveries and discovery, and signs
// the answer of answer, by default a work item.
type fakeRunAPI struct {
	c *control
	// passAttach leaves an attach to the control, for a separate gateway's run.
	passAttach atomic.Bool

	mu     sync.Mutex
	seen   []runAPIRequest
	answer func(w http.ResponseWriter, r *http.Request, body []byte)
}

// runAPIOf serves a fake run API at c.
func runAPIOf(c *control) *fakeRunAPI {
	f := &fakeRunAPI{c: c}
	hook := func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/events" || r.URL.Path == runsPath || strings.HasPrefix(r.URL.Path, "/.well-known/") ||
			strings.HasSuffix(r.URL.Path, "/attach") && f.passAttach.Load() {
			return false
		}
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.seen = append(f.seen, runAPIRequest{r.Method, r.RequestURI, r.Header.Clone(), body})
		answer := f.answer
		f.mu.Unlock()
		if answer == nil {
			f.sign(w, r, http.StatusOK, []byte(`{"work_item":{"title":"Fix the failing build"}}`))
			return true
		}
		answer(w, r, body)
		return true
	}
	c.intercept.Store(&hook)
	return f
}

// answers sets what the fake run API answers.
func (f *fakeRunAPI) answers(a func(w http.ResponseWriter, r *http.Request, body []byte)) {
	f.mu.Lock()
	f.answer = a
	f.mu.Unlock()
}

// sign answers r with the status and the body, signed.
func (f *fakeRunAPI) sign(w http.ResponseWriter, r *http.Request, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(server.HeaderSignature, f.c.signer.SignAnswer(accesskey.Answer{Status: status, RequestSignature: r.Header.Get(server.HeaderSignature), Body: body}))
	w.WriteHeader(status)
	w.Write(body)
}

// reset forgets the requests the fake run API got.
func (f *fakeRunAPI) reset() {
	f.mu.Lock()
	f.seen = nil
	f.mu.Unlock()
}

// requests are the requests the fake run API got.
func (f *fakeRunAPI) requests() []runAPIRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.seen)
}

// runAPIRun is a gateway with a fake run API and one run opened on it.
type runAPIRun struct {
	t *testing.T
	h *harness
	f *fakeRunAPI
	a *server.LinkRunAnswer
}

func openRunAPIRun(t *testing.T) *runAPIRun {
	t.Helper()
	c := newControl(t)
	f := runAPIOf(c)
	return startRunAPIRun(t, start(t, gateway.Config{Server: c.server()}), f)
}

// startRunAPIRun opens a run on h and starts it, so its record is written.
func startRunAPIRun(t *testing.T, h *harness, f *fakeRunAPI) *runAPIRun {
	t.Helper()
	a := h.open(server.LinkRunRequest{})
	h.post(started(a.RunID, nil), applied(a.RunID, a.Applied))
	return &runAPIRun{t: t, h: h, f: f, a: a}
}

// send writes one request on a fresh connection to the run's proxy, opened as the wall's
// relay opens it, and reads the answer. head is the request line, with its CRLF, and any
// headers; send adds Host, Connection: close and the end of the header. err is the
// error of the body's read.
func (o *runAPIRun) send(head string, body []byte) (*http.Response, []byte, error) {
	o.t.Helper()
	c, err := net.Dial("tcp", o.h.g.Addr())
	if err != nil {
		o.t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, link.RelayLine(o.a.ProxySecret)+head+"Host: "+link.RunAPIHost+"\r\nConnection: close\r\n\r\n"); err != nil {
		o.t.Fatal(err)
	}
	if _, err := c.Write(body); err != nil {
		o.t.Fatal(err)
	}
	method, _, _ := strings.Cut(head, " ")
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
	if err != nil {
		o.t.Fatalf("%q: %v", head, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp, b, err
}

// line is a request line for the target.
func line(method, target string) string { return method + " " + target + " HTTP/1.1\r\n" }

// url is a target under the run's base URL.
func (o *runAPIRun) url(path string) string { return o.a.RunAPI + path }

// routeError fails the test unless the answer is the route's JSON error with the
// status and the code, and a message that starts with a fix.
func routeError(t *testing.T, what string, resp *http.Response, b []byte, status int, code string) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil || resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("%s: not the route's JSON: %v %s", what, err, b)
		return
	}
	if resp.StatusCode != status || doc["error"] != code || len(doc) != 2 {
		t.Errorf("%s: %d %s, want %d %s", what, resp.StatusCode, b, status, code)
	}
	message, _ := doc["message"].(string)
	if !startsWithAFix.MatchString(message) {
		t.Errorf("%s: the message does not start with a fix: %s", what, message)
	}
}

// startsWithAFix matches a text that opens with the imperative of what to do.
var startsWithAFix = regexp.MustCompile(`^(Send|Retry|Shrink|Check) `)

// egressOf are the dev.qory.run.egress of the run with channel run_api.
func (o *runAPIRun) egressOf() []map[string]any {
	o.t.Helper()
	var out []map[string]any
	for _, l := range o.h.record(o.a.RunID) {
		if l.Type == event.RunEgress && l.Data["channel"] == "run_api" {
			out = append(out, l.Data)
		}
	}
	return out
}

// egress waits for n dev.qory.run.egress with channel run_api and returns them, or
// more, if more were written.
func (o *runAPIRun) egress(n int) []map[string]any {
	o.t.Helper()
	eventually(o.t, "the record's events", func() bool { return len(o.egressOf()) >= n })
	return o.egressOf()
}

// TestTheRunAnswerNamesTheRunAPI pins the run answer's run_api: the run's base URL, with
// a control plane.
func TestTheRunAnswerNamesTheRunAPI(t *testing.T) {
	o := openRunAPIRun(t)
	if want := "http://run-api.qory.invalid/v1/runs/" + o.a.RunID; o.a.RunAPI != want {
		t.Errorf("run_api %q, want %q", o.a.RunAPI, want)
	}
}

// TestARunWithNoControlPlaneHasNoRoute pins a gateway with no server: the run answer
// has no run_api, and a request to the host gets the proxy's ordinary denial, with no
// channel in its record.
func TestARunWithNoControlPlaneHasNoRoute(t *testing.T) {
	h := start(t, gateway.Config{})
	o := startRunAPIRun(t, h, nil)
	a := o.a
	if a.RunAPI != "" {
		t.Errorf("run_api %q", a.RunAPI)
	}
	resp, b, _ := o.send(line(http.MethodGet, runAPIOrigin+"/v1/runs/"+a.RunID+"/work-item"), nil)
	if resp.StatusCode != http.StatusForbidden || strings.HasPrefix(string(b), "{") {
		t.Errorf("%d %s", resp.StatusCode, b)
	}
	if got := o.egressOf(); len(got) != 0 {
		t.Errorf("run_api events %v", got)
	}
}

// TestOnlyTheFiveShapesReachTheRunAPI pins point by point what the route keeps from Qory
// Apiary: each target and method outside the five shapes is a 404, written to the record
// once, and no request reaches the fake run API, while the five shapes do.
func TestOnlyTheFiveShapesReachTheRunAPI(t *testing.T) {
	o := openRunAPIRun(t)
	another := event.NewRunID()
	base := o.a.RunAPI
	for _, c := range []struct{ what, method, target string }{
		{"the run", http.MethodGet, base},
		{"the run with a slash", http.MethodGet, base + "/"},
		{"the attach", http.MethodPost, base + "/attach"},
		{"the outcome", http.MethodPost, base + "/outcome"},
		{"the reload", http.MethodGet, base + "/reload"},
		{"the reload by POST", http.MethodPost, base + "/reload"},
		{"the diagnostics", http.MethodGet, base + "/diagnostics"},
		{"the sessions", http.MethodPost, base + "/sessions"},
		{"another run's work item", http.MethodGet, runAPIOrigin + "/v1/runs/" + another + "/work-item"},
		{"another run's verdict", http.MethodPost, runAPIOrigin + "/v1/runs/" + another + "/verdict"},
		{"another run's id in capitals", http.MethodGet, runAPIOrigin + "/v1/runs/" + strings.ToUpper(o.a.RunID) + "/work-item"},
		{"no run", http.MethodGet, runAPIOrigin + "/v1/runs"},
		{"the events", http.MethodPost, runAPIOrigin + "/v1/events"},
		{"the root", http.MethodGet, runAPIOrigin + "/"},
		{"a query", http.MethodGet, base + "/work-item?x=1"},
		{"an empty query", http.MethodGet, base + "/work-item?"},
		{"a fragment", http.MethodGet, base + "/work-item#x"},
		{"a dot dot", http.MethodGet, base + "/artifacts/../work-item"},
		{"a dot dot out of the run", http.MethodGet, base + "/../" + another + "/work-item"},
		{"a dot", http.MethodGet, base + "/./work-item"},
		{"an escaped dot dot", http.MethodGet, base + "/artifacts/%2e%2e/work-item"},
		{"a dot dot as the version", http.MethodGet, base + "/artifacts/../files/f"},
		{"a dot dot as the file", http.MethodGet, base + "/artifacts/v/files/.."},
		{"an escaped slash", http.MethodGet, base + "/artifacts%2Fv%2Ffiles%2Ff"},
		{"an escaped slash in the version", http.MethodGet, base + "/artifacts/a%2Fb/files/f"},
		{"an escaped slash in the file", http.MethodGet, base + "/artifacts/v/files/a%2Fb"},
		{"an escaped backslash", http.MethodGet, base + "/artifacts/v/files/a%5Cb"},
		{"a backslash", http.MethodGet, base + `/artifacts/v/files/a\b`},
		{"an escaped NUL", http.MethodGet, base + "/artifacts/v/files/a%00b"},
		{"an escaped new line", http.MethodGet, base + "/artifacts/v/files/a%0Ab"},
		{"bytes that are not UTF-8", http.MethodGet, base + "/artifacts/v/files/%ff"},
		{"an empty segment", http.MethodGet, base + "//work-item"},
		{"an empty last segment", http.MethodGet, base + "/work-item/"},
		{"an empty file", http.MethodGet, base + "/artifacts/v/files/"},
		{"an empty version", http.MethodGet, base + "/artifacts//files/f"},
		{"a file with no name", http.MethodGet, base + "/artifacts/v/files"},
		{"more after the file", http.MethodGet, base + "/artifacts/v/files/f/g"},
		{"another word for files", http.MethodGet, base + "/artifacts/v/blobs/f"},
		{"PUT", http.MethodPut, base + "/artifacts"},
		{"PATCH", http.MethodPatch, base + "/artifacts"},
		{"DELETE", http.MethodDelete, base + "/artifacts"},
		{"HEAD", http.MethodHead, base + "/work-item"},
		{"OPTIONS", http.MethodOptions, base + "/work-item"},
		{"POST to the work item", http.MethodPost, base + "/work-item"},
		{"GET of the verdict", http.MethodGet, base + "/verdict"},
		{"POST to a file", http.MethodPost, base + "/artifacts/v/files/f"},
		{"another port", http.MethodGet, "http://" + link.RunAPIHost + ":8080" + strings.TrimPrefix(base, runAPIOrigin) + "/work-item"},
		{"user information", http.MethodGet, "http://user@" + link.RunAPIHost + strings.TrimPrefix(base, runAPIOrigin) + "/work-item"},
		{"another scheme", http.MethodGet, "https://" + link.RunAPIHost + strings.TrimPrefix(base, runAPIOrigin) + "/work-item"},
	} {
		resp, b, _ := o.send(line(c.method, c.target), nil)
		if c.method == http.MethodHead {
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s: %d", c.what, resp.StatusCode)
			}
		} else {
			routeError(t, c.what, resp, b, http.StatusNotFound, "not_found")
		}
		if got := o.f.requests(); len(got) != 0 {
			t.Fatalf("%s reached the run API: %+v", c.what, got)
		}
	}
	resp, b, _ := o.send(o.requestLine10(), nil)
	routeError(t, "HTTP/1.0", resp, b, http.StatusNotFound, "not_found")
	// net/http takes no target with a broken escape: the proxy's server returns its 400.
	if resp, _, _ := o.send(line(http.MethodGet, base+"/artifacts/v/files/a%zz"), nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a broken escape: %d", resp.StatusCode)
	}
	if got := o.f.requests(); len(got) != 0 {
		t.Fatalf("a request reached the run API: %+v", got)
	}

	for _, c := range []struct {
		method, path, want string
	}{
		{http.MethodGet, "/work-item", "/work-item"},
		{http.MethodGet, "/artifacts", "/artifacts"},
		{http.MethodGet, "/artifacts/v1/files/report.md", "/artifacts/v1/files/report.md"},
		{http.MethodGet, "/artifacts/v%201/files/a%23b", "/artifacts/v%201/files/a%23b"},
		{http.MethodPost, "/artifacts", "/artifacts"},
		{http.MethodPost, "/verdict", "/verdict"},
	} {
		o.f.reset()
		resp, b, err := o.send(line(c.method, o.url(c.path)), nil)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Errorf("%s %s: %d %s %v", c.method, c.path, resp.StatusCode, b, err)
		}
		got := o.f.requests()
		if len(got) != 1 || got[0].method != c.method || got[0].target != "/v1/runs/"+o.a.RunID+c.want {
			t.Errorf("%s %s reached the run API as %+v", c.method, c.path, got)
		}
	}
}

// requestLine10 is the request line of a work item over HTTP/1.0.
func (o *runAPIRun) requestLine10() string {
	return http.MethodGet + " " + o.url("/work-item") + " HTTP/1.0\r\n"
}

// TestNoHeaderOfTheCallerCrosses pins what the run API gets: a GET has none of the
// caller's headers, and the request's signature verifies under the gateway's access key
// over the exact target. A signed answer's headers reach the caller from a short list.
func TestNoHeaderOfTheCallerCrosses(t *testing.T) {
	o := openRunAPIRun(t)
	o.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.Header().Set("Set-Cookie", "session=fake")
		w.Header().Set("X-Internal", "fake")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		o.f.sign(w, r, http.StatusOK, []byte(`{"version":1}`))
	})
	caller := map[string]string{
		"Authorization":       "Bearer fake-caller-bearer",
		"Proxy-Authorization": "Basic fake-caller-basic",
		"Cookie":              "fake-caller-cookie=1",
		"X-Qory-Signature":    "fake-caller-signature",
		"X-Qory-Key-Id":       "ak_fakecallerkey",
		"X-Qory-Instance-Id":  "i_fakecaller",
		"X-Qory-Timestamp":    "1000",
		"X-Qory-Other":        "fake-caller-other",
		"X-Forwarded-For":     "203.0.113.1",
		"Content-Type":        "text/fake",
		"User-Agent":          "fake-caller-agent",
	}
	head := line(http.MethodPost, o.url("/verdict"))
	body := []byte(`{"verdict":"pass"}`)
	for name, value := range caller {
		head += name + ": " + value + "\r\n"
	}
	head += "Content-Length: " + strconv.Itoa(len(body)) + "\r\n"
	resp, _, err := o.send(head, body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("%d %v", resp.StatusCode, err)
	}
	if resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("X-Internal") != "" || resp.Header.Get(server.HeaderSignature) != "" {
		t.Errorf("headers of the answer passed: %v", resp.Header)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("the headers of the answer %v", resp.Header)
	}
	got := o.f.requests()
	if len(got) != 1 {
		t.Fatalf("%d requests", len(got))
	}
	r := got[0]
	for name, value := range r.header {
		for _, v := range value {
			if strings.Contains(v, "fake-caller") || strings.Contains(v, "fakecaller") || v == "203.0.113.1" {
				t.Errorf("the run API got %s: %s", name, v)
			}
		}
	}
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-Forwarded-For", "X-Qory-Other"} {
		if v, ok := r.header[http.CanonicalHeaderKey(name)]; ok {
			t.Errorf("the run API got %s: %v", name, v)
		}
	}
	if r.header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type %q", r.header.Get("Content-Type"))
	}
	if !bytes.Equal(r.body, body) {
		t.Errorf("body %s", r.body)
	}
	if !testAccessKey.PublicKey().VerifyRequest(accesskey.Request{AccessKeyID: r.header.Get(server.HeaderAccessKeyID), InstanceID: r.header.Get(server.HeaderInstanceID),
		Method: r.method, Target: r.target, Body: r.body}, r.header.Get(server.HeaderSignature)) {
		t.Error("the request's signature does not verify under the gateway's access key")
	}
}

// TestAnAnswerThatFailsVerificationIsDropped pins answer_unverified: an answer with a
// bad signature, or none, is a 502, and no byte of it reaches the caller.
func TestAnAnswerThatFailsVerificationIsDropped(t *testing.T) {
	o := openRunAPIRun(t)
	const secret = "fake-answer-of-a-stranger"
	body := []byte(`{"secret":"` + secret + `"}`)
	for what, answer := range map[string]func(w http.ResponseWriter, r *http.Request, _ []byte){
		"a bad signature": func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			w.Header().Set(server.HeaderSignature, "AAAA")
			w.Write(body)
		},
		"another key": func(w http.ResponseWriter, r *http.Request, _ []byte) {
			w.Header().Set(server.HeaderSignature, mustGenerate().SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: r.Header.Get(server.HeaderSignature), Body: body}))
			w.Write(body)
		},
		"no signature": func(w http.ResponseWriter, _ *http.Request, _ []byte) { w.Write(body) },
		"an unsigned 401": func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(body)
		},
		"an unsigned 404": func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			w.WriteHeader(http.StatusNotFound)
			w.Write(body)
		},
	} {
		o.f.answers(answer)
		resp, b, _ := o.send(line(http.MethodGet, o.url("/work-item")), nil)
		routeError(t, what, resp, b, http.StatusBadGateway, "answer_unverified")
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("%s: the body reached the caller: %s", what, b)
		}
	}
	o.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		o.f.sign(w, r, http.StatusConflict, []byte(`{"error":"verdict_set"}`))
	})
	if resp, b, _ := o.send(line(http.MethodPost, o.url("/verdict")), nil); resp.StatusCode != http.StatusConflict || string(b) != `{"error":"verdict_set"}` {
		t.Errorf("a signed refusal: %d %s", resp.StatusCode, b)
	}
}

// fileAnswer answers with content under the signature of digest, sent with a
// Content-Length as Qory Apiary sends a file.
func (f *fakeRunAPI) fileAnswer(content []byte, digest string) func(w http.ResponseWriter, r *http.Request, _ []byte) {
	return func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="report.md"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		w.Header().Set(server.HeaderSignature, f.c.signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: r.Header.Get(server.HeaderSignature), Digest: digest}))
		w.Write(content)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestAFileStreamsChunkedAndEndsInItsDigest pins a file: chunked, with no
// Content-Length, it ends cleanly when its bytes match the signed digest, and in a read
// error, never a clean end of body, when they do not. The record has the status the
// caller got, or 502 for a stream that failed.
func TestAFileStreamsChunkedAndEndsInItsDigest(t *testing.T) {
	o := openRunAPIRun(t)
	content := bytes.Repeat([]byte("artifact "), 1<<16)
	o.f.answers(o.f.fileAnswer(content, sha256Hex(content)))
	resp, b, err := o.send(line(http.MethodGet, o.url("/artifacts/v1/files/report.md")), nil)
	if err != nil || resp.StatusCode != http.StatusOK || !bytes.Equal(b, content) {
		t.Fatalf("%d, %d bytes, %v", resp.StatusCode, len(b), err)
	}
	if !slices.Equal(resp.TransferEncoding, []string{"chunked"}) || resp.ContentLength != -1 {
		t.Errorf("transfer encoding %v, content length %d", resp.TransferEncoding, resp.ContentLength)
	}
	if resp.Header.Get("Content-Type") != "application/octet-stream" || resp.Header.Get("Content-Disposition") == "" {
		t.Errorf("the headers %v", resp.Header)
	}
	o.f.answers(o.f.fileAnswer(content, sha256Hex([]byte("other bytes"))))
	resp, b, err = o.send(line(http.MethodGet, o.url("/artifacts/v1/files/report.md")), nil)
	if resp.StatusCode != http.StatusOK || err == nil {
		t.Fatalf("%d, %d bytes, %v", resp.StatusCode, len(b), err)
	}
	var got []string
	for _, e := range o.egress(2) {
		got = append(got, strconv.Itoa(int(e["status"].(float64))))
	}
	if want := []string{"200", "502"}; !slices.Equal(got, want) {
		t.Errorf("the statuses recorded %v, want %v", got, want)
	}
}

// TestASmallFileThatFailsItsDigestIsAReadError pins the same for a body shorter than
// any buffer: the abort still comes before the last chunk.
func TestASmallFileThatFailsItsDigestIsAReadError(t *testing.T) {
	o := openRunAPIRun(t)
	o.f.answers(o.f.fileAnswer([]byte("x"), sha256Hex([]byte("y"))))
	resp, b, err := o.send(line(http.MethodGet, o.url("/artifacts/v1/files/f")), nil)
	if resp.StatusCode != http.StatusOK || err == nil {
		t.Fatalf("%d, %q, %v", resp.StatusCode, b, err)
	}
	o.f.answers(o.f.fileAnswer(nil, sha256Hex(nil)))
	if resp, b, err := o.send(line(http.MethodGet, o.url("/artifacts/v1/files/f")), nil); resp.StatusCode != http.StatusOK || err != nil || len(b) != 0 {
		t.Errorf("an empty file: %d, %q, %v", resp.StatusCode, b, err)
	}
}

// TestAFileThatAStreamCutsIsAReadError pins a stream that ends short of its
// Content-Length at Qory Apiary: a read error at the caller, recorded with status 503.
func TestAFileThatAStreamCutsIsAReadError(t *testing.T) {
	o := openRunAPIRun(t)
	o.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.Header().Set("Content-Length", "1000")
		w.Header().Set(server.HeaderSignature, o.f.c.signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: r.Header.Get(server.HeaderSignature), Digest: sha256Hex([]byte("x"))}))
		io.WriteString(w, "x")
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	})
	resp, b, err := o.send(line(http.MethodGet, o.url("/artifacts/v1/files/f")), nil)
	if resp.StatusCode != http.StatusOK || err == nil {
		t.Fatalf("%d, %q, %v", resp.StatusCode, b, err)
	}
	if got := o.egress(1); len(got) != 1 || got[0]["status"] != float64(503) {
		t.Errorf("%v", got)
	}
}

// TestTheBodyLimits pins the two sizes: a body at the limit is sent, and one byte more
// is a 413 with nothing sent, by its Content-Length and chunked alike.
func TestTheBodyLimits(t *testing.T) {
	o := openRunAPIRun(t)
	chunked := func(n int) []byte {
		var b bytes.Buffer
		b.WriteString(strconv.FormatInt(int64(n), 16) + "\r\n")
		b.Write(make([]byte, n))
		b.WriteString("\r\n0\r\n\r\n")
		return b.Bytes()
	}
	for _, c := range []struct {
		path  string
		limit int
	}{{"/verdict", 64 << 10}, {"/artifacts", 32 << 20}} {
		head := line(http.MethodPost, o.url(c.path))
		resp, b, _ := o.send(head+"Content-Length: "+strconv.Itoa(c.limit+1)+"\r\n", nil)
		routeError(t, c.path+" by its Content-Length", resp, b, http.StatusRequestEntityTooLarge, "payload_too_large")
		resp, b, _ = o.send(head+"Transfer-Encoding: chunked\r\n", chunked(c.limit+1))
		routeError(t, c.path+" chunked", resp, b, http.StatusRequestEntityTooLarge, "payload_too_large")
		if got := o.f.requests(); len(got) != 0 {
			t.Fatalf("%s: %d requests reached the run API", c.path, len(got))
		}
		resp, _, err := o.send(head+"Content-Length: "+strconv.Itoa(c.limit)+"\r\n", make([]byte, c.limit))
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Errorf("%s at its limit: %d %v", c.path, resp.StatusCode, err)
		}
		got := o.f.requests()
		if len(got) != 1 || len(got[0].body) != c.limit {
			t.Errorf("%s at its limit reached the run API %d times", c.path, len(got))
		}
		o.f.reset()
	}
}

// TestAPostGoesOutOnce pins that the gateway sends a failed POST no second time, also on
// a connection it used before.
func TestAPostGoesOutOnce(t *testing.T) {
	o := openRunAPIRun(t)
	o.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.Method == http.MethodGet {
			o.f.sign(w, r, http.StatusOK, []byte(`{}`))
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	})
	if resp, _, _ := o.send(line(http.MethodGet, o.url("/work-item")), nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("the GET: %d", resp.StatusCode)
	}
	resp, b, _ := o.send(line(http.MethodPost, o.url("/verdict"))+"Content-Length: 2\r\n", []byte("{}"))
	routeError(t, "the POST", resp, b, http.StatusServiceUnavailable, "unavailable")
	if got := o.f.requests(); len(got) != 2 {
		t.Errorf("%d requests reached the run API, want the GET and one POST", len(got))
	}
}

// TestARunAPIOutOfReachIsA503 pins unavailable: Qory Apiary out of reach.
func TestARunAPIOutOfReachIsA503(t *testing.T) {
	o := openRunAPIRun(t)
	o.f.c.srv.CloseClientConnections()
	o.f.c.srv.Listener.Close()
	resp, b, _ := o.send(line(http.MethodGet, o.url("/work-item")), nil)
	routeError(t, "the GET", resp, b, http.StatusServiceUnavailable, "unavailable")
	if d := o.egress(1)[0]; d["status"] != float64(503) || d["decision"] != "allowed" {
		t.Errorf("%v", d)
	}
}

// TestAConnectToTheRunAPIHostIsDenied pins that no tunnel opens to the host, in observe
// mode, with the host in the allow list, and in enforce mode, and that a stack proxy has
// no route: a request through it gets the proxy's ordinary denial.
func TestAConnectToTheRunAPIHostIsDenied(t *testing.T) {
	for what, policy := range map[string]string{
		"observe":          `{"version":1,"egress":{"mode":"observe"}}`,
		"an allow":         `{"version":1,"egress":{"mode":"enforce","allow":["` + link.RunAPIHost + `"]}}`,
		"a wildcard allow": `{"version":1,"egress":{"mode":"enforce","allow":["*.qory.invalid"]}}`,
		"enforce":          `{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`,
	} {
		t.Run(what, func(t *testing.T) {
			c := newControl(t)
			c.serve(policy, 'a')
			f := runAPIOf(c)
			h := start(t, gateway.Config{Server: c.server()})
			o := startRunAPIRun(t, h, f)
			for _, target := range []string{link.RunAPIHost + ":80", link.RunAPIHost + ":443", strings.ToUpper(link.RunAPIHost) + ":443"} {
				resp, b, _ := o.send(line(http.MethodConnect, target), nil)
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("CONNECT %s: %d %s", target, resp.StatusCode, b)
				}
			}
			if got := f.requests(); len(got) != 0 {
				t.Errorf("%d requests reached the run API", len(got))
			}
			eventually(t, "the denials in the record", func() bool {
				n := 0
				for _, l := range h.record(o.a.RunID) {
					if l.Type == event.RunEgress && l.Data["decision"] == "denied" {
						n++
					}
				}
				return n == 3
			})
		})
	}
}

// TestTheStackProxyHasNoRunAPIRoute pins the stack proxy: a request to the host through
// it gets the proxy's ordinary denial, and no request reaches the run API.
func TestTheStackProxyHasNoRunAPIRoute(t *testing.T) {
	c := newControl(t)
	c.serveDocument(harnessGatewayDoc(false), 'a')
	c.mu.Lock()
	c.secrets = map[string]string{"harness-1": "fake-harness-value"}
	c.mu.Unlock()
	f := runAPIOf(c)
	f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) { f.sign(w, r, http.StatusOK, []byte(`{}`)) })
	hook := *c.intercept.Load()
	passSecrets := func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == secretsPath {
			return false
		}
		return hook(w, r)
	}
	c.intercept.Store(&passSecrets)
	h := start(t, gateway.Config{Server: c.server()})
	a := h.open(server.LinkRunRequest{})
	if a.StackProxySecret == "" {
		t.Fatal("the run has no stack proxy")
	}
	o := &runAPIRun{t: t, h: h, f: f, a: &server.LinkRunAnswer{RunID: a.RunID, RunAPI: a.RunAPI, ProxySecret: a.StackProxySecret}}
	resp, b, _ := o.send(line(http.MethodGet, a.RunAPI+"/work-item"), nil)
	if resp.StatusCode != http.StatusForbidden || strings.HasPrefix(string(b), "{") {
		t.Errorf("the GET: %d %s", resp.StatusCode, b)
	}
	if resp, b, _ = o.send(line(http.MethodConnect, link.RunAPIHost+":443"), nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("the CONNECT: %d %s", resp.StatusCode, b)
	}
	if got := f.requests(); len(got) != 0 {
		t.Errorf("%d requests reached the run API", len(got))
	}
}

// TestEachRequestIsOneEvent pins the record: one dev.qory.run.egress for each request,
// valid under its schema, with the method HTTP, the channel, the request's method and
// path, the status and the rule, and no body and no header value.
func TestEachRequestIsOneEvent(t *testing.T) {
	o := openRunAPIRun(t)
	body := []byte(`{"verdict":"fake-verdict-body"}`)
	o.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		o.f.sign(w, r, http.StatusOK, []byte(`{"secret":"fake-answer-secret"}`))
	})
	head := line(http.MethodPost, o.url("/verdict")) + "Authorization: Bearer fake-header-value\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n"
	if resp, _, _ := o.send(head, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("%d", resp.StatusCode)
	}
	o.send(line(http.MethodGet, o.url("/work-item")), nil)
	o.send(line(http.MethodGet, o.url("/reload")), nil)
	o.send(line(http.MethodPost, o.url("/verdict"))+"Content-Length: 70000\r\n", nil)
	got := o.egress(4)
	if len(got) != 4 {
		t.Fatalf("%d events: %v", len(got), got)
	}
	path := "/v1/runs/" + o.a.RunID
	for i, want := range []struct {
		method, path, decision string
		status                 float64
	}{
		{http.MethodPost, path + "/verdict", "allowed", 200},
		{http.MethodGet, path + "/work-item", "allowed", 200},
		{http.MethodGet, path + "/reload", "denied", 404},
		{http.MethodPost, path + "/verdict", "denied", 413},
	} {
		d := got[i]
		if d["host"] != link.RunAPIHost || d["method"] != "HTTP" || d["channel"] != "run_api" || d["rule"] != "wall:run-api" ||
			d["request_method"] != want.method || d["path"] != want.path || d["status"] != want.status || d["decision"] != want.decision {
			t.Errorf("event %d: %v, want %+v", i, d, want)
		}
		if _, ok := d["path_rule"]; ok {
			t.Errorf("event %d has a path rule: %v", i, d)
		}
	}
	rec := o.h.record(o.a.RunID)
	validEvents(t, rec)
	b, _ := json.Marshal(rec)
	for _, value := range []string{"fake-verdict-body", "fake-header-value", "fake-answer-secret"} {
		if bytes.Contains(b, []byte(value)) {
			t.Errorf("the record holds %s", value)
		}
	}
}

// TestNoSignatureOrKeyReachesARecordOrAReport pins point by point that the signature,
// the key and the answer's secret material stay out of what the gateway writes, on a
// passed answer and on each failure.
func TestNoSignatureOrKeyReachesARecordOrAReport(t *testing.T) {
	o := openRunAPIRun(t)
	const secret = "fake-secret-material"
	body := []byte(`{"secret":"` + secret + `"}`)
	var signature []string
	var mu sync.Mutex
	o.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		sig := o.f.c.signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: r.Header.Get(server.HeaderSignature), Body: body})
		mu.Lock()
		signature = append(signature, r.Header.Get(server.HeaderSignature), sig)
		mu.Unlock()
		w.Header().Set(server.HeaderSignature, sig)
		if strings.HasSuffix(r.URL.Path, "/artifacts") {
			w.Header().Set(server.HeaderSignature, "bad")
		}
		w.Write(body)
	})
	if resp, _, _ := o.send(line(http.MethodGet, o.url("/work-item")), nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("%d", resp.StatusCode)
	}
	if resp, _, _ := o.send(line(http.MethodGet, o.url("/artifacts")), nil); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("%d", resp.StatusCode)
	}
	if len(signature) != 4 {
		t.Fatalf("%d signatures", len(signature))
	}
	o.egress(2)
	rec, _ := json.Marshal(o.h.record(o.a.RunID))
	o.h.mu.Lock()
	defer o.h.mu.Unlock()
	written := string(rec) + strings.Join(o.h.reports, "\n")
	for _, value := range append(signature, secret, testAccessKey.String(), o.a.ProxySecret) {
		if strings.Contains(written, value) {
			t.Errorf("the record or a report holds %s", value)
		}
	}
}

// TestTheRouteBehindASeparateGateway pins the route on a separate gateway's one address:
// the run answer, valid under its schema, has run_api, a request reaches the run API,
// and a request outside the five shapes is a 404.
func TestTheRouteBehindASeparateGateway(t *testing.T) {
	c := gatewayControl(t)
	f := runAPIOf(c)
	f.passAttach.Store(true)
	r := startRemote(t, c, gateway.Config{Version: "test"})
	runID := event.NewRunID()
	key := runKeyFor(t, runID, nil)
	a := r.tryOpen(t, key, server.LinkRunRequest{})
	if a.status != http.StatusOK {
		t.Fatalf("the run request: %d %s", a.status, a.body)
	}
	validDocument(t, "link-run-answer.schema.json", a.body)
	var ans server.LinkRunAnswer
	json.Unmarshal(a.body, &ans)
	if ans.RunAPI != link.RunAPIURL(runID) {
		t.Fatalf("run_api %q", ans.RunAPI)
	}
	client := r.relay(t, key)
	resp, err := client.Get(ans.RunAPI + "/work-item")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(b, []byte("work_item")) {
		t.Errorf("%d %s", resp.StatusCode, b)
	}
	resp, err = client.Get(ans.RunAPI + "/diagnostics")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	routeError(t, "the diagnostics", resp, b, http.StatusNotFound, "not_found")
	if got := f.requests(); len(got) != 1 || got[0].target != "/v1/runs/"+runID+"/work-item" {
		t.Errorf("the run API got %+v", got)
	}
}
