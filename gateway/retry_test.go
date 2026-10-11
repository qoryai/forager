package gateway_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/server"
)

// apiaryReply is one answer of Qory Apiary's a test scripts: its status and body, with
// its Content-Type, signed under the test's signing key or not, and with the digest of
// a run configuration when it carries one; drop closes the connection unanswered.
type apiaryReply struct {
	status      int
	body        string
	contentType string
	signed      bool
	digest      string
	drop        bool
}

// coded is a signed coded refusal.
func coded(status int, code string) apiaryReply {
	return apiaryReply{status: status, body: `{"error":"` + code + `"}`, contentType: "application/json", signed: true}
}

// unsignedReply is an answer without a signature.
func unsignedReply(status int, contentType, body string) apiaryReply {
	return apiaryReply{status: status, body: body, contentType: contentType}
}

// dropped is a connection closed unanswered.
var dropped = apiaryReply{drop: true}

// write answers r with the reply.
func (a apiaryReply) write(w http.ResponseWriter, r *http.Request) {
	if a.drop {
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			conn.Close()
		}
		return
	}
	if a.contentType != "" {
		w.Header().Set("Content-Type", a.contentType)
	}
	if a.digest != "" {
		w.Header().Set(server.HeaderRunConfiguration, a.digest)
	}
	if a.signed {
		w.Header().Set(server.HeaderSignature, testSigner.SignAnswer(accesskey.Answer{Status: a.status, RequestSignature: r.Header.Get(server.HeaderSignature), Body: []byte(a.body), RunConfiguration: a.digest}))
	}
	w.WriteHeader(a.status)
	io.WriteString(w, a.body)
}

// scripted answers the control's requests of a path with the replies a test gave, in
// order, and once they run out leaves each to the control; it keeps every request it
// saw, by path.
type scripted struct {
	mu      sync.Mutex
	replies map[string][]apiaryReply
	seen    map[string][]seenRequest
}

// seenRequest is a request the control had: when, its delivery id and its body.
type seenRequest struct {
	at       time.Time
	delivery string
	body     []byte
}

func script(c *control) *scripted {
	s := &scripted{replies: map[string][]apiaryReply{}, seen: map[string][]seenRequest{}}
	f := func(w http.ResponseWriter, r *http.Request) bool {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		s.mu.Lock()
		s.seen[r.URL.Path] = append(s.seen[r.URL.Path], seenRequest{time.Now(), r.Header.Get(server.HeaderDelivery), body})
		q := s.replies[r.URL.Path]
		if len(q) == 0 {
			s.mu.Unlock()
			return false
		}
		s.replies[r.URL.Path] = q[1:]
		s.mu.Unlock()
		q[0].write(w, r)
		return true
	}
	c.intercept.Store(&f)
	return s
}

// then answers the next requests of path with the replies.
func (s *scripted) then(path string, replies ...apiaryReply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replies[path] = append(s.replies[path], replies...)
}

// requests are the requests of path the control had.
func (s *scripted) requests(path string) []seenRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.seen[path])
}

// The paths of the control.
const (
	eventsPath = "/v1/events"
	runPath    = runsPath
)

// notFoundPage is Qory Apiary's page for a path it does not know, unsigned.
var notFoundPage = unsignedReply(404, "text/html; charset=utf-8", "<!DOCTYPE html>\n<html><head><title>Not Found</title></head><body><h1>Not Found</h1></body></html>\n")

// gonePage is a page of a 410, unsigned, as a proxy in front of Qory Apiary may answer.
var gonePage = unsignedReply(410, "text/html; charset=utf-8", "<!DOCTYPE html>\n<html><head><title>Gone</title></head><body><h1>Gone</h1></body></html>\n")

// gaps are the times between the requests.
func gaps(seen []seenRequest) []time.Duration {
	var out []time.Duration
	for i := 1; i < len(seen); i++ {
		out = append(out, seen[i].at.Sub(seen[i-1].at))
	}
	return out
}

// TestTheTriesOfQoryApiaryAsARunOpens pins the tries of the run's registration as a
// run opens: the gateway's own waits, 1 second and then 2 seconds, in a window of 6
// seconds; a signed 503 or 429 rate_limited, an unsigned 5xx and no answer are asked
// again, every try with the same bytes, its time included, and an answer on a later try
// opens the run, whose record holds one run.registered, its first line; a refusal with
// any other code, an unsigned answer other than a 5xx, a signed answer without a code
// and a 410, signed or not, with a code or none, are asked once, the 410 a failure
// without a code; and the last try's refusal is the session's, as before the tries.
func TestTheTriesOfQoryApiaryAsARunOpens(t *testing.T) {
	if waits, window := gateway.OpenTries(); !slices.Equal(waits, []time.Duration{time.Second, 2 * time.Second}) || window != 6*time.Second {
		t.Fatalf("the waits %v and the window %v; want [1s 2s] and 6s", waits, window)
	}
	waits := []time.Duration{50 * time.Millisecond, 100 * time.Millisecond}
	for _, c := range []struct {
		name    string
		path    string
		replies []apiaryReply
		tries   int
		code    string // the refusal's, empty when the run opens
		status  int
		from    string
		uncoded string // the end of a failure without a code's text
	}{
		{"a registration's 503, then its 200", runPath, []apiaryReply{coded(503, "unavailable")}, 2, "", 0, "", ""},
		{"a registration's unsigned 502, no answer, then its 200", runPath, []apiaryReply{unsignedReply(502, "text/plain", "bad gateway"), dropped}, 3, "", 0, "", ""},
		{"a registration's 429 rate_limited, then its 200", runPath, []apiaryReply{coded(429, "rate_limited")}, 2, "", 0, "", ""},
		{"a registration's 429 rate_limited twice, then its 200", runPath, []apiaryReply{coded(429, "rate_limited"), coded(429, "rate_limited")}, 3, "", 0, "", ""},
		{"a registration's 429 rate_limited three times", runPath, []apiaryReply{coded(429, "rate_limited"), coded(429, "rate_limited"), coded(429, "rate_limited")}, 3, "rate_limited", 429, "apiary", ""},
		{"a registration's 503 three times", runPath, []apiaryReply{coded(503, "unavailable"), coded(503, "unavailable"), coded(503, "unavailable")}, 3, "unavailable", 503, "apiary", ""},
		{"a registration's unsigned 401", runPath, []apiaryReply{unsignedReply(401, "application/json", `{"error":"unauthorized"}`)}, 1, "unauthorized", 401, "apiary", ""},
		{"a registration's 409 instance_limit", runPath, []apiaryReply{coded(409, "instance_limit")}, 1, "instance_limit", 409, "apiary", ""},
		{"a registration's 409 run_id_used", runPath, []apiaryReply{coded(409, "run_id_used")}, 1, "run_id_used", 409, "apiary", ""},
		{"a registration's 409 of the server's own", runPath, []apiaryReply{coded(409, "node_paused")}, 1, "node_paused", 409, "apiary", ""},
		{"a registration's 400 invalid_request", runPath, []apiaryReply{coded(400, "invalid_request")}, 1, "invalid_request", 400, "apiary", ""},
		{"a registration's unsigned 429", runPath, []apiaryReply{unsignedReply(429, "application/json", `{"error":"rate_limited"}`)}, 1, "answer_unsigned", 429, "gateway", ""},
		{"a registration's 404 not_found", runPath, []apiaryReply{coded(404, "not_found")}, 1, "not_found", 404, "apiary", ""},
		{"a registration's signed 404 without a code", runPath, []apiaryReply{{status: 404, signed: true}}, 1, "", 0, "", ": status 404: the server did not accept the run"},
		{"a registration's unsigned 404 page", runPath, []apiaryReply{notFoundPage}, 1, "answer_unsigned", 404, "gateway", ""},
		{"a registration's signed 410 run_closed", runPath, []apiaryReply{coded(410, "run_closed")}, 1, "", 0, "", runPath + ": status 410: the server did not accept the run"},
		{"a registration's signed 410 without a code", runPath, []apiaryReply{{status: 410, signed: true}}, 1, "", 0, "", runPath + ": status 410: the server did not accept the run"},
		{"a registration's unsigned 410 without a body", runPath, []apiaryReply{unsignedReply(410, "", "")}, 1, "", 0, "", runPath + ": status 410"},
		{"a registration's unsigned 410 page", runPath, []apiaryReply{gonePage}, 1, "", 0, "", runPath + ": status 410"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctl := newControl(t)
			ctl.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`, 'a')
			cfg := gateway.Config{Server: ctl.server()}
			gateway.SetOpenTries(&cfg, waits, 5*time.Second)
			h := start(t, cfg)
			s := script(ctl)
			s.then(c.path, c.replies...)
			req := server.LinkRunRequest{RunID: event.NewRunID()}
			a, err := h.tryOpen(req)
			seen := s.requests(c.path)
			if len(seen) != c.tries {
				t.Errorf("asked %d times; want %d", len(seen), c.tries)
			}
			for i, g := range gaps(seen) {
				if g < waits[i] {
					t.Errorf("try %d came %v after the one before; want at least %v", i+2, g, waits[i])
				}
			}
			for _, r := range seen {
				if !bytes.Equal(r.body, seen[0].body) || len(r.body) == 0 {
					t.Errorf("the tries carry other bytes:\n%s\n%s", seen[0].body, r.body)
				}
			}
			switch {
			case c.code == "" && c.uncoded == "":
				if err != nil {
					t.Fatalf("the run did not open: %v", err)
				}
				h.post(heartbeat(a.RunID))
				h.close()
				registered := 0
				rec := h.record(a.RunID)
				for _, l := range rec {
					if l.Type == event.RunRegistered {
						registered++
					}
				}
				if registered != 1 || rec[0].Type != event.RunRegistered || rec[0].Sequence != "0000000001" {
					t.Errorf("the record %v", types(rec))
				}
			case c.uncoded != "":
				var ref *accesskey.Refusal
				var failed *server.StatusError
				if errors.As(err, &ref) || !errors.As(err, &failed) || failed.Status != http.StatusInternalServerError || !strings.HasSuffix(failed.Message, c.uncoded) {
					t.Errorf("a failure without a code: %v", err)
				}
			default:
				var ref *accesskey.Refusal
				if !errors.As(err, &ref) || ref.Code != c.code || ref.Status != c.status || ref.From != c.from {
					t.Fatalf("the refusal %#v; want %s, %d from %s", err, c.code, c.status, c.from)
				}
				if c.code == "rate_limited" && err.Error() != "register "+ctl.srv.URL+runPath+": rate_limited (status 429)" {
					t.Errorf("the session's text %q", err)
				}
			}
		})
	}
}

// TestTheTriesStopWhenTheSessionGoes pins that a session's run request that ends
// while the gateway waits between its tries of Qory Apiary ends them: the run does not
// open, Qory Apiary is asked nothing more, and the run id is free again at once, so the
// session's next request of it opens.
func TestTheTriesStopWhenTheSessionGoes(t *testing.T) {
	ctl := newControl(t)
	cfg := gateway.Config{Server: ctl.server()}
	gateway.SetOpenTries(&cfg, []time.Duration{2 * time.Second, 2 * time.Second}, 10*time.Second)
	h := start(t, cfg)
	s := script(ctl)
	s.then(runPath, coded(503, "unavailable"))
	req := server.LinkRunRequest{RunID: event.NewRunID()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := h.link.OpenRun(ctx, server.LocalOrigin+"/v1/run-configuration", req)
		done <- err
	}()
	eventually(t, "the first try", func() bool { return len(s.requests(runPath)) == 1 })
	time.Sleep(100 * time.Millisecond)
	cancel()
	if err := <-done; err == nil {
		t.Fatal("the run opened")
	}
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	a, err := h.tryOpen(req)
	if err != nil {
		t.Fatalf("the next request of the run id: %v", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("the next request took %v: the tries went on", took)
	}
	if n := len(s.requests(runPath)); n != 2 {
		t.Errorf("Qory Apiary was asked %d times; want the first request's try and the next request's", n)
	}
	h.post(heartbeat(a.RunID))
}

// TestTheWindowOfTheTries pins the window of the tries of Qory Apiary as a run opens: a
// try starts again only within the window of the run request's arrival.
func TestTheWindowOfTheTries(t *testing.T) {
	waits := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond}
	for _, c := range []struct {
		window time.Duration
		tries  int
	}{{450 * time.Millisecond, 3}, {250 * time.Millisecond, 2}} {
		ctl := newControl(t)
		cfg := gateway.Config{Server: ctl.server()}
		gateway.SetOpenTries(&cfg, waits, c.window)
		h := start(t, cfg)
		s := script(ctl)
		s.then(runPath, coded(503, "unavailable"), coded(503, "unavailable"), coded(503, "unavailable"))
		if _, err := h.tryOpen(server.LinkRunRequest{}); err == nil {
			t.Fatal("the run opened")
		}
		if n := len(s.requests(runPath)); n != c.tries {
			t.Errorf("a window of %v: asked %d times; want %d", c.window, n, c.tries)
		}
	}
}

// TestARegistrationIsKeptForARetryOfItsRunID pins the bytes a retry of a run id sends:
// within half the server's window of the time the first registration holds, by the
// wall clock, the same registration but for its time sends the same bytes; other labels
// or another about build new bytes; and past that half window, or before the time it
// holds, a clock set back, the registration is built anew, its own time in it.
func TestARegistrationIsKeptForARetryOfItsRunID(t *testing.T) {
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	reg := func(at time.Time, labels map[string]string, about *server.About) server.Registration {
		return server.Registration{Version: 1, RunID: event.NewRunID(), Labels: labels, About: about, ForagerVersion: "test",
			ContractVersion: server.Revision, IntervalSeconds: 30, Events: []string{"*"}, Time: server.RegistrationTime(at)}
	}
	labels := map[string]string{"repository": "acme/shop"}
	for name, tc := range map[string]struct {
		after  time.Duration
		labels map[string]string
		about  *server.About
		same   bool
	}{
		"the same, at once":             {time.Second, labels, nil, true},
		"the same, within half":         {server.Window/2 - time.Second, labels, nil, true},
		"the same, past half":           {server.Window/2 + time.Second, labels, nil, false},
		"the same, with the clock back": {-time.Second, labels, nil, false},
		"other labels":                  {time.Second, map[string]string{"repository": "acme/other"}, nil, false},
		"another about":                 {time.Second, labels, &server.About{Title: "Fix the build"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			g := &gateway.Gateway{}
			first := reg(t0, labels, nil)
			b1, err := gateway.RegistrationAt(g, first, t0)
			if err != nil {
				t.Fatal(err)
			}
			at := t0.Add(tc.after)
			retry := reg(at, tc.labels, tc.about)
			retry.RunID = first.RunID
			b2, err := gateway.RegistrationAt(g, retry, at)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := retry.Body()
			if tc.same {
				want = b1
			}
			if !bytes.Equal(b2, want) {
				t.Errorf("sent %s, want %s", b2, want)
			}
		})
	}
}
