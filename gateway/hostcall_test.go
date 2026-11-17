package gateway_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// The tests of this file pin the link's two host calls, next-session and
// pushed-commits: the gateway forwards each body unread to the control plane, signed
// with its access key, and returns the answer unread; and no container reaches either.

// hostCallPaths are the paths of the two host calls under a run.
var hostCallPaths = []string{"/next-session", "/pushed-commits"}

// notJSON is a body no schema takes: the gateway reads none, so it arrives as sent.
var notJSON = []byte("not json \x00\xff {\"session\":1}")

// hostCall sends the host call path of the run on the local link of the harness, with
// body, and returns the answer's body and the error.
func hostCall(h *harness, runID, path string, body []byte) ([]byte, error) {
	l := h.linkOf(runID)
	runURL := server.LocalOrigin + "/v1/run-configuration"
	if path == "/next-session" {
		return l.NextSession(context.Background(), runURL, runID, body)
	}
	return l.PushedCommits(context.Background(), runURL, runID, body)
}

// noContentTo answers r with a signed 204 and no body, as Qory Apiary answers a
// pushed-commits request.
func (f *fakeRunAPI) noContentTo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(server.HeaderSignature, f.c.signer.SignAnswer(accesskey.Answer{Status: http.StatusNoContent, RequestSignature: r.Header.Get(server.HeaderSignature)}))
	w.WriteHeader(http.StatusNoContent)
}

// hostCallAnswers makes f answer a next-session request with a signed 200 that echoes
// its body back, and a pushed-commits request with a signed 204.
func hostCallAnswers(f *fakeRunAPI) {
	f.answers(func(w http.ResponseWriter, r *http.Request, body []byte) {
		if strings.HasSuffix(r.URL.Path, "/pushed-commits") {
			f.noContentTo(w, r)
			return
		}
		f.sign(w, r, http.StatusOK, append([]byte(`{"next":"end","echo":`), append(slices.Clone(body), '}')...))
	})
}

// refusalWith fails the test unless err is a refusal with the status, the code and
// from.
func refusalWith(t *testing.T, what string, err error, status int, code, from string) *accesskey.Refusal {
	t.Helper()
	var ref *accesskey.Refusal
	if !errors.As(err, &ref) || ref.Status != status || ref.Code != code || ref.From != from {
		t.Errorf("%s: %v (%+v), want %d %s from %s", what, err, ref, status, code, from)
		return nil
	}
	return ref
}

// TestAHostCallForwardsItsBodyUnread pins both host calls on the local link: the
// control plane gets a signed POST of <run.url>/<run_id> and the call's path with the
// body byte for byte and Content-Type: application/json, and the caller gets the
// answer byte for byte, a 204's empty body among them; a body of exactly the limit
// passes; and a call while a session is joined passes too.
func TestAHostCallForwardsItsBodyUnread(t *testing.T) {
	o := openRunAPIRun(t)
	hostCallAnswers(o.f)
	for _, path := range hostCallPaths {
		o.f.reset()
		got, err := hostCall(o.h, o.a.RunID, path, notJSON)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if path == "/next-session" && string(got) != `{"next":"end","echo":`+string(notJSON)+`}` {
			t.Errorf("%s: the answer %q", path, got)
		}
		if path == "/pushed-commits" && len(got) != 0 {
			t.Errorf("%s: the answer of a 204 %q", path, got)
		}
		seen := o.f.requests()
		if len(seen) != 1 {
			t.Fatalf("%s: the control plane got %d requests", path, len(seen))
		}
		s := seen[0]
		if s.method != http.MethodPost || s.target != "/v1/runs/"+o.a.RunID+path || !bytes.Equal(s.body, notJSON) ||
			s.header.Get("Content-Type") != "application/json" || s.header.Get(server.HeaderSignature) == "" {
			t.Errorf("%s: the control plane got %s %s %q %v", path, s.method, s.target, s.body, s.header)
		}
	}

	o.f.reset()
	for path, limit := range map[string]int{"/next-session": server.MaxNextSessionRequest, "/pushed-commits": server.MaxPushedCommitsRequest} {
		if _, err := hostCall(o.h, o.a.RunID, path, bytes.Repeat([]byte("a"), limit)); err != nil {
			t.Errorf("%s: a body of the limit: %v", path, err)
		}
	}
	if n := len(o.f.requests()); n != 2 {
		t.Errorf("the control plane got %d bodies of the limit, want 2", n)
	}

	o.h.joined(o.a.RunID)
	for _, path := range hostCallPaths {
		if _, err := hostCall(o.h, o.a.RunID, path, []byte(`{}`)); err != nil {
			t.Errorf("%s during a join: %v", path, err)
		}
	}
}

// TestAHostCallPassesOnTheControlPlanesRefusal pins the answers of the control plane
// that are no 2xx: a signed coded refusal passes with its status, code, names and
// message, from apiary, a 503 among them; an unsigned answer, a signed 410, a signed
// answer with no code, a 200 that is no JSON and a 200 over the answer's limit are
// 502 control_plane_unavailable from the gateway, with one line in its log.
func TestAHostCallPassesOnTheControlPlanesRefusal(t *testing.T) {
	o := openRunAPIRun(t)
	answer := func(a func(w http.ResponseWriter, r *http.Request)) {
		o.f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) { a(w, r) })
	}
	for _, path := range hostCallPaths {
		answer(func(w http.ResponseWriter, r *http.Request) {
			o.f.sign(w, r, http.StatusConflict, []byte(`{"error":"run_ended","names":["repositories[0].commit",""],"message":"Start a new run to record pushed commits."}`))
		})
		_, err := hostCall(o.h, o.a.RunID, path, []byte(`{}`))
		if ref := refusalWith(t, path+": a signed 409", err, http.StatusConflict, "run_ended", accesskey.FromApiary); ref != nil {
			if !slices.Equal(ref.Names, []string{"repositories[0].commit"}) || err.Error() != "Start a new run to record pushed commits." {
				t.Errorf("%s: a signed 409: names %q, text %q", path, ref.Names, err)
			}
		}
		answer(func(w http.ResponseWriter, r *http.Request) {
			o.f.sign(w, r, http.StatusServiceUnavailable, []byte(`{"error":"unavailable","message":"Try again."}`))
		})
		_, err = hostCall(o.h, o.a.RunID, path, []byte(`{}`))
		refusalWith(t, path+": a signed 503", err, http.StatusServiceUnavailable, "unavailable", accesskey.FromApiary)
		if _, ok := server.Ended(err); ok {
			t.Errorf("%s: a signed 503 ends the run", path)
		}
	}
	// A refusal whose names and message contain a run key reaches the caller with a
	// phrase in each place, in a body link-refusal.schema.json takes.
	key := runKeyFor(t, o.a.RunID, nil)
	answer(func(w http.ResponseWriter, r *http.Request) {
		o.f.sign(w, r, http.StatusBadRequest, []byte(`{"error":"invalid_request","names":["repositories[0].`+key+`","repositories[1].path"],"message":"Send a commit id: `+key+` is none."}`))
	})
	status, body := rawPost(t, raw(t, o.h.g.LocalLink()), "/v1/run-configuration/"+o.a.RunID+"/pushed-commits", "application/json", "{}")
	validDocument(t, "link-refusal.schema.json", []byte(body))
	if status != http.StatusBadRequest || strings.Contains(body, "qrk_") || !strings.Contains(body, `"names":["(a name that contains a run key)","repositories[1].path"]`) ||
		!strings.Contains(body, `"message":"(a value that contains a run key)"`) || !strings.Contains(body, `"from":"apiary"`) {
		t.Errorf("a refusal with a run key: %d %s", status, body)
	}

	unavailable := map[string]func(w http.ResponseWriter, r *http.Request){
		"an unsigned 409": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusConflict)
			io.WriteString(w, `{"error":"run_ended"}`)
		},
		"a signed 410": func(w http.ResponseWriter, r *http.Request) {
			o.f.sign(w, r, http.StatusGone, []byte(`{"error":"run_closed"}`))
		},
		"a signed 500 with no code": func(w http.ResponseWriter, r *http.Request) {
			o.f.sign(w, r, http.StatusInternalServerError, []byte(`oops`))
		},
		"a 200 that is no JSON": func(w http.ResponseWriter, r *http.Request) {
			body := []byte("next: end")
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set(server.HeaderSignature, o.f.c.signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: r.Header.Get(server.HeaderSignature), Body: body}))
			w.Write(body)
		},
		"a 200 over the limit": func(w http.ResponseWriter, r *http.Request) {
			o.f.sign(w, r, http.StatusOK, bytes.Repeat([]byte(" "), server.MaxNextSessionAnswer+1))
		},
	}
	for what, a := range unavailable {
		answer(a)
		_, err := hostCall(o.h, o.a.RunID, "/next-session", []byte(`{}`))
		refusalWith(t, what, err, http.StatusBadGateway, "control_plane_unavailable", accesskey.FromGateway)
		if _, ok := server.Ended(err); ok {
			t.Errorf("%s ends the run", what)
		}
	}
	if n := len(o.h.reportsWith("the next-session request got no valid answer")); n != len(unavailable) {
		t.Errorf("%d lines in the gateway's log, want %d", n, len(unavailable))
	}
}

// TestTheGatewaysRefusalsOfAHostCall pins the refusals the gateway decides, with
// nothing sent to the control plane: a body over the limit is 413 payload_too_large, a
// Content-Type other than application/json 400 invalid_request, a run id of no run
// here 400 invalid_request, a run that ended 410, and a run with no control plane 404
// not_found.
func TestTheGatewaysRefusalsOfAHostCall(t *testing.T) {
	o := openRunAPIRun(t)
	hostCallAnswers(o.f)
	for path, limit := range map[string]int{"/next-session": server.MaxNextSessionRequest, "/pushed-commits": server.MaxPushedCommitsRequest} {
		_, err := hostCall(o.h, o.a.RunID, path, bytes.Repeat([]byte("a"), limit+1))
		if ref := refusalWith(t, path+": over the limit", err, http.StatusRequestEntityTooLarge, "payload_too_large", accesskey.FromGateway); ref != nil && !startsWithAFix.MatchString(err.Error()) {
			t.Errorf("%s: the text %q starts with no fix", path, err)
		}
		status, body := rawPost(t, raw(t, o.h.g.LocalLink()), "/v1/run-configuration/"+o.a.RunID+path, "text/plain", "{}")
		if status != http.StatusBadRequest || !strings.Contains(body, `"error":"invalid_request"`) || !strings.Contains(body, `"from":"gateway"`) {
			t.Errorf("%s: text/plain: %d %s", path, status, body)
		}
		_, err = hostCall(o.h, event.NewRunID(), path, []byte(`{}`))
		refusalWith(t, path+": a run id of no run", err, http.StatusBadRequest, server.CodeInvalidRequest, accesskey.FromGateway)
	}
	if got := o.f.requests(); len(got) != 0 {
		t.Errorf("the control plane got %+v", got)
	}

	o.h.post(exited(o.a.RunID))
	for _, path := range hostCallPaths {
		_, err := hostCall(o.h, o.a.RunID, path, []byte(`{}`))
		if _, ok := server.Ended(err); !ok {
			t.Errorf("%s of a run that ended: %v", path, err)
		}
	}
	if got := o.f.requests(); len(got) != 0 {
		t.Errorf("the control plane got %+v", got)
	}

	h := start(t, gateway.Config{})
	a := h.open(server.LinkRunRequest{})
	for _, path := range hostCallPaths {
		_, err := hostCall(h, a.RunID, path, []byte(`{}`))
		refusalWith(t, path+": no control plane", err, http.StatusNotFound, "not_found", accesskey.FromGateway)
	}
}

// TestAHostCallBehindASeparateGateway pins both host calls on the one address: under
// /qory-link/run-configuration/<run_id>/ with the run key, the body forwarded unread,
// the answer signed whole, a 204 with no body among them; a refusal of the control
// plane's passes from apiary; another run's key is 400 run_key_invalid; and a body over
// the limit 413; the control plane gets nothing for either refusal of the gateway.
func TestAHostCallBehindASeparateGateway(t *testing.T) {
	c := gatewayControl(t)
	f := runAPIOf(c)
	f.passAttach.Store(true)
	hostCallAnswers(f)
	r := startRemote(t, c, gateway.Config{})
	e := r.open(t, runKeyFor(t, event.NewRunID(), nil), server.LinkRunRequest{})
	f.reset()
	base := "/qory-link/run-configuration/" + e.a.RunID
	if got := r.do(t, e.key, http.MethodPost, base+"/next-session", notJSON); got.status != http.StatusOK || string(got.body) != `{"next":"end","echo":`+string(notJSON)+`}` {
		t.Errorf("next-session: %d %q", got.status, got.body)
	}
	if got := r.do(t, e.key, http.MethodPost, base+"/pushed-commits", notJSON); got.status != http.StatusNoContent || len(got.body) != 0 {
		t.Errorf("pushed-commits: %d %q", got.status, got.body)
	}
	seen := f.requests()
	if len(seen) != 2 || !bytes.Equal(seen[0].body, notJSON) || !bytes.Equal(seen[1].body, notJSON) ||
		seen[0].target != "/v1/runs/"+e.a.RunID+"/next-session" || seen[1].target != "/v1/runs/"+e.a.RunID+"/pushed-commits" {
		t.Errorf("the control plane got %+v", seen)
	}

	f.answers(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		f.sign(w, r, http.StatusConflict, []byte(`{"error":"not_writable","message":"Record pushed commits only from a run with write access."}`))
	})
	if got := r.do(t, e.key, http.MethodPost, base+"/pushed-commits", []byte(`{}`)); got.status != http.StatusConflict || got.refusal()["error"] != "not_writable" || got.refusal()["from"] != "apiary" {
		t.Errorf("a signed 409: %d %s", got.status, got.body)
	}
	// An unsigned answer is a 502 with one line in the gateway's log, which the
	// cleanup of startRemote checks for the run key.
	f.answers(func(w http.ResponseWriter, _ *http.Request, _ []byte) { w.WriteHeader(http.StatusConflict) })
	if got := r.do(t, e.key, http.MethodPost, base+"/next-session", []byte(`{}`)); got.status != http.StatusBadGateway || got.refusal()["error"] != "control_plane_unavailable" {
		t.Errorf("an unsigned 409: %d %s", got.status, got.body)
	}
	if !r.reported("the next-session request got no valid answer") {
		t.Error("no line in the gateway's log for the unsigned 409")
	}

	f.reset()
	other := runKeyFor(t, event.NewRunID(), nil)
	r.mu.Lock()
	r.keys = append(r.keys, other)
	r.mu.Unlock()
	for _, path := range hostCallPaths {
		if got := r.do(t, other, http.MethodPost, base+path, []byte(`{}`)); got.status != http.StatusBadRequest || got.refusal()["error"] != "run_key_invalid" {
			t.Errorf("%s with another run's key: %d %s", path, got.status, got.body)
		}
		if got := r.do(t, e.key, http.MethodPost, base+path, bytes.Repeat([]byte("a"), server.MaxPushedCommitsRequest+1)); got.status != http.StatusRequestEntityTooLarge || got.refusal()["error"] != "payload_too_large" {
			t.Errorf("%s over the limit: %d %s", path, got.status, got.body)
		}
	}
	if got := f.requests(); len(got) != 0 {
		t.Errorf("the control plane got %+v", got)
	}
}

// enforceNothing is a node policy that allows no host: the proxy refuses every host
// but the run API's.
var enforceNothing = &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{}}}

// TestNoContainerReachesAHostCall pins that a program in a container, whose one way out
// is the run's proxy through the wall's relay, reaches neither host call on one
// machine: the run API route answers 404 for both paths; the proxy answers 400 to a
// request with no host and 403 to the link's paths at localhost, which the policy does
// not allow; and a connection to the proxy's address with no relay preamble is closed
// unanswered. The control plane gets nothing.
func TestNoContainerReachesAHostCall(t *testing.T) {
	c := newControl(t)
	f := runAPIOf(c)
	o := startRunAPIRun(t, start(t, gateway.Config{Server: c.server(), Policy: enforceNothing}), f)
	hostCallAnswers(o.f)
	o.f.reset()
	body := []byte(`{"session":1,"state":"succeeded","reason":null}`)
	head := "Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n"
	for _, path := range hostCallPaths {
		resp, b, _ := o.send(line(http.MethodPost, o.url(path))+head, body)
		routeError(t, path+" through the run API route", resp, b, http.StatusNotFound, "not_found")

		target := "/v1/run-configuration/" + o.a.RunID + path
		if resp, b, _ = o.send(line(http.MethodPost, target)+head, body); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s with no host through the proxy: %d %s", path, resp.StatusCode, b)
		}
		if resp, b, _ = o.send(line(http.MethodPost, server.LocalOrigin+target)+head, body); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s at localhost through the proxy: %d %s", path, resp.StatusCode, b)
		}

		conn, err := net.Dial("tcp", o.h.g.Addr())
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(conn, line(http.MethodPost, target)+"Host: localhost\r\n"+head+"\r\n"+string(body))
		if resp, err := http.ReadResponse(bufio.NewReader(conn), nil); err == nil {
			t.Errorf("%s to the proxy's address with no preamble: %d", path, resp.StatusCode)
		}
		conn.Close()
	}
	if got := o.f.requests(); len(got) != 0 {
		t.Errorf("the control plane got %+v", got)
	}
}

// TestNoContainerReachesAHostCallBehindASeparateGateway pins the same behind a
// separate gateway. The run's proxy connections arrive on the one address with the
// relay's preamble and the run key, as the session's forwarder opens them for a
// container, and never reach the link: the run API route answers 404 for both paths, a
// request with no host 400, and the link's paths at the one address 403. A link
// request needs the run key as its bearer, which no container has: a bound request
// without it is 400 run_key_invalid (TestEveryRequestCarriesAnAcceptedRunKey), and an
// unbound one an unsigned 404. The control plane gets nothing.
func TestNoContainerReachesAHostCallBehindASeparateGateway(t *testing.T) {
	c := gatewayControl(t)
	f := runAPIOf(c)
	f.passAttach.Store(true)
	hostCallAnswers(f)
	r := startRemote(t, c, gateway.Config{Policy: enforceNothing})
	e := r.open(t, runKeyFor(t, event.NewRunID(), nil), server.LinkRunRequest{})
	f.reset()
	client := r.relay(t, e.key)
	for _, path := range hostCallPaths {
		resp, err := client.Post(link.RunAPIURL(e.a.RunID)+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		routeError(t, path+" through the run API route", resp, b, http.StatusNotFound, "not_found")

		linkPath := "/qory-link/run-configuration/" + e.a.RunID + path
		for _, u := range []string{"http://gateway.example:8443" + linkPath, "http://" + r.g.Addr() + linkPath} {
			resp, err := client.Post(u, "application/json", strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s through the proxy: %d %s", u, resp.StatusCode, b)
			}
		}

		bc, err := r.bind(t, gatewayKeys())
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(bc, link.RelayLine(e.key)+line(http.MethodPost, linkPath)+"Host: gateway.example:8443\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
		resp, err = http.ReadResponse(bufio.NewReader(bc), nil)
		if err != nil || resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s with no host through the proxy: %v %v", path, resp, err)
		}
		bc.Close()

		tc := r.dialTLS(t)
		req, _ := http.NewRequest(http.MethodPost, "https://gateway.example:8443"+linkPath, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+e.key)
		req.Header.Set("Content-Type", "application/json")
		req.Write(tc)
		resp, err = http.ReadResponse(bufio.NewReader(tc), req)
		tc.Close()
		if err != nil || resp.StatusCode != http.StatusNotFound || resp.Header.Get(server.HeaderSignature) != "" {
			t.Errorf("%s unbound: %v %v", path, resp, err)
		}
	}
	if got := f.requests(); len(got) != 0 {
		t.Errorf("the control plane got %+v", got)
	}
}
