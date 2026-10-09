package gateway_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/runcredential"
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

// seenRequest is a request the control had: when, and its delivery id.
type seenRequest struct {
	at       time.Time
	delivery string
}

func script(c *control) *scripted {
	s := &scripted{replies: map[string][]apiaryReply{}, seen: map[string][]seenRequest{}}
	f := func(w http.ResponseWriter, r *http.Request) bool {
		s.mu.Lock()
		s.seen[r.URL.Path] = append(s.seen[r.URL.Path], seenRequest{time.Now(), r.Header.Get(server.HeaderDelivery)})
		q := s.replies[r.URL.Path]
		if len(q) == 0 {
			s.mu.Unlock()
			return false
		}
		s.replies[r.URL.Path] = q[1:]
		s.mu.Unlock()
		io.ReadAll(r.Body)
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
	runPath    = "/v1/run-configuration"
)

// notFoundPage is Qory Apiary's page for a path it does not know, unsigned.
var notFoundPage = unsignedReply(404, "text/html; charset=utf-8", "<!DOCTYPE html>\n<html><head><title>Not Found</title></head><body><h1>Not Found</h1></body></html>\n")

// gaps are the times between the requests.
func gaps(seen []seenRequest) []time.Duration {
	var out []time.Duration
	for i := 1; i < len(seen); i++ {
		out = append(out, seen[i].at.Sub(seen[i-1].at))
	}
	return out
}

// TestTheTriesOfQoryApiaryAsARunOpens pins the tries of the ping and the run
// configuration as a run opens: the gateway's own waits, 1 second and then 2 seconds,
// in a window of 6 seconds; a signed 503 or 429 rate_limited, an unsigned 5xx and no
// answer are asked again, the ping with its delivery id and recorded once, and an
// answer on a later try opens the run; a refusal with any other code, an unsigned
// answer other than a 5xx and a signed answer without a code are asked once; and the
// last try's refusal is the session's, as before the tries.
func TestTheTriesOfQoryApiaryAsARunOpens(t *testing.T) {
	if waits, window := gateway.OpenTries(); !slices.Equal(waits, []time.Duration{time.Second, 2 * time.Second}) || window != 6*time.Second {
		t.Fatalf("the waits %v and the window %v; want [1s 2s] and 6s", waits, window)
	}
	waits := []time.Duration{50 * time.Millisecond, 100 * time.Millisecond}
	for _, c := range []struct {
		name         string
		path         string
		replies      []apiaryReply
		tries        int
		code         string // the refusal's, empty when the run opens
		status       int
		from         string
		uncodedTries bool // a failure without a code
	}{
		{"a ping's 503, then its 202", eventsPath, []apiaryReply{coded(503, "unavailable")}, 2, "", 0, "", false},
		{"a ping's unsigned 502, no answer, then its 202", eventsPath, []apiaryReply{unsignedReply(502, "text/plain", "bad gateway"), dropped}, 3, "", 0, "", false},
		{"a ping's 429 rate_limited, then its 202", eventsPath, []apiaryReply{coded(429, "rate_limited")}, 2, "", 0, "", false},
		{"a run configuration's 503, then its 200", runPath, []apiaryReply{coded(503, "unavailable")}, 2, "", 0, "", false},
		{"a run configuration's 429 rate_limited twice, then its 200", runPath, []apiaryReply{coded(429, "rate_limited"), coded(429, "rate_limited")}, 3, "", 0, "", false},
		{"a ping's 429 rate_limited three times", eventsPath, []apiaryReply{coded(429, "rate_limited"), coded(429, "rate_limited"), coded(429, "rate_limited")}, 3, "rate_limited", 429, "apiary", false},
		{"a run configuration's 503 three times", runPath, []apiaryReply{coded(503, "unavailable"), coded(503, "unavailable"), coded(503, "unavailable")}, 3, "unavailable", 503, "apiary", false},
		{"a ping's unsigned 401", eventsPath, []apiaryReply{unsignedReply(401, "application/json", `{"error":"unauthorized"}`)}, 1, "unauthorized", 401, "apiary", false},
		{"a ping's 409 instance_limit", eventsPath, []apiaryReply{coded(409, "instance_limit")}, 1, "instance_limit", 409, "apiary", false},
		{"a ping's 400 invalid_request", eventsPath, []apiaryReply{coded(400, "invalid_request")}, 1, "invalid_request", 400, "apiary", false},
		{"a ping's unsigned 429", eventsPath, []apiaryReply{unsignedReply(429, "application/json", `{"error":"rate_limited"}`)}, 1, "answer_unsigned", 429, "gateway", false},
		{"a run configuration's 404 not_found", runPath, []apiaryReply{coded(404, "not_found")}, 1, "not_found", 404, "apiary", false},
		{"a run configuration's signed 404 without a code", runPath, []apiaryReply{{status: 404, signed: true}}, 1, "", 0, "", true},
		{"a run configuration's unsigned 404 page", runPath, []apiaryReply{notFoundPage}, 1, "answer_unsigned", 404, "gateway", false},
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
			if c.path == eventsPath {
				for _, r := range seen {
					if r.delivery != seen[0].delivery {
						t.Errorf("the ping's tries carry the delivery ids %v", seen)
					}
				}
			}
			switch {
			case c.code == "" && !c.uncodedTries:
				if err != nil {
					t.Fatalf("the run did not open: %v", err)
				}
				h.post(heartbeat(a.RunID))
				h.close()
				pings := 0
				for _, l := range h.record(a.RunID) {
					if l.Type == event.Ping {
						pings++
					}
				}
				if pings != 1 {
					t.Errorf("the record holds %d pings", pings)
				}
			case c.uncodedTries:
				var ref *accesskey.Refusal
				var failed *server.StatusError
				if errors.As(err, &ref) || !errors.As(err, &failed) || failed.Status != http.StatusInternalServerError || !strings.HasSuffix(failed.Message, ": status 404") {
					t.Errorf("a signed answer without a code: %v", err)
				}
			default:
				var ref *accesskey.Refusal
				if !errors.As(err, &ref) || ref.Code != c.code || ref.Status != c.status || ref.From != c.from {
					t.Fatalf("the refusal %#v; want %s, %d from %s", err, c.code, c.status, c.from)
				}
				if c.code == "rate_limited" && err.Error() != "ping "+ctl.srv.URL+"/v1/events: rate_limited (status 429)" {
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
	s.then(eventsPath, coded(503, "unavailable"))
	req := server.LinkRunRequest{RunID: event.NewRunID()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := h.link.OpenRun(ctx, server.LocalOrigin+"/v1/run-configuration", req)
		done <- err
	}()
	eventually(t, "the first try", func() bool { return len(s.requests(eventsPath)) == 1 })
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
	if n := len(s.requests(eventsPath)); n != 2 {
		t.Errorf("Qory Apiary was asked %d times; want the first request's try and the next request's", n)
	}
	h.post(heartbeat(a.RunID))
}

// TestTheWindowOfTheTries pins the window of the tries of Qory Apiary as a run opens: a
// try starts again only within the window of the run request's arrival, the time the
// issuer was asked included.
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
		s.then(eventsPath, coded(503, "unavailable"), coded(503, "unavailable"), coded(503, "unavailable"))
		if _, err := h.tryOpen(server.LinkRunRequest{}); err == nil {
			t.Fatal("the run opened")
		}
		if n := len(s.requests(eventsPath)); n != c.tries {
			t.Errorf("a window of %v: asked %d times; want %d", c.window, n, c.tries)
		}
	}
	// An issuer that takes most of the window leaves no time for a second try.
	ctl := newControl(t)
	cfg := gateway.Config{Server: ctl.server()}
	gateway.SetOpenTries(&cfg, waits, 400*time.Millisecond)
	cfg.RunCredentials = realIssuers(t, true)
	gateway.SetIntrospection(&cfg, func(string, string) (bool, error) {
		time.Sleep(350 * time.Millisecond)
		return true, nil
	}, time.Hour)
	s := startVerifying(t, cfg, nil, 0)
	sc := script(ctl)
	sc.then(eventsPath, coded(503, "unavailable"), coded(503, "unavailable"), coded(503, "unavailable"))
	cred := credentialFor("rk-0001")
	s.secrets = append(s.secrets, cred)
	if status, b := s.tryOpenWith(t, cred, server.LinkRunRequest{}); status != http.StatusServiceUnavailable || refusalOf(b)["error"] != "unavailable" {
		t.Errorf("the open: %d %s", status, b)
	}
	if n := len(sc.requests(eventsPath)); n != 1 {
		t.Errorf("asked %d times after the issuer took the window; want once", n)
	}
}

// answerInvalid is the issuer's answer that is no valid one, as runcredential's client
// gives it.
type answerInvalid string

func (e answerInvalid) Error() string { return string(e) }
func (answerInvalid) Unwrap() error   { return runcredential.ErrAnswerInvalid }

// issuerAnswers is the introspection endpoint of a test: it answers what it is set to.
type issuerAnswers struct{ v atomic.Pointer[issuerAnswer] }

type issuerAnswer struct {
	active bool
	err    error
}

func (a *issuerAnswers) set(active bool, err error) { a.v.Store(&issuerAnswer{active, err}) }

func (a *issuerAnswers) answer(string, string) (bool, error) {
	got := a.v.Load()
	return got.active, got.err
}

// noHold fails the test when the gateway's directory holds a refused run key.
func noHold(t *testing.T, dir string) {
	t.Helper()
	if b, err := os.ReadFile(filepath.Join(dir, runcredential.EndedFile)); err == nil && strings.Contains(string(b), "rk-") {
		t.Errorf("the gateway holds a run key: %s", b)
	}
}

// loginHead is a client's CONNECT to host with the run credential as its proxy login.
func loginHead(host, credential string) string {
	return "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("anyone:"+credential)) + "\r\n\r\n"
}

// connectWith sends the login and returns the answer's status, Content-Type and body;
// the connection stays open, the caller's to close, when it is 200.
func connectWith(t *testing.T, s *service, head string) (int, string, string, net.Conn) {
	t.Helper()
	resp, conn, _ := s.proxyRequest(t, head)
	if resp.StatusCode == http.StatusOK {
		return resp.StatusCode, "", "", conn
	}
	b, _ := io.ReadAll(resp.Body)
	conn.Close()
	if resp.ContentLength != int64(len(b)) {
		t.Errorf("Content-Length %d for %d bytes", resp.ContentLength, len(b))
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), string(b), nil
}

// The texts a session and a client read when the issuer's introspection endpoint gave
// no answer, or none that is valid, and when the gateway could not open a client's run.
const (
	unreachableText = "the gateway could not open the run: the issuer's introspection endpoint could not be reached; try again"
	invalidText     = "the gateway could not open the run: the issuer's introspection endpoint gave no valid answer"
	tryAgainText    = "the gateway could not open the run; try again"
	plainText       = "text/plain; charset=utf-8"
)

// TestAnIssuerWithNoAnswerAtOpen pins a run whose issuer's introspection endpoint gives
// no answer, or none that is valid, when it would open: the session's run request gets
// the 503 issuer_unreachable or the 502 issuer_answer_invalid with its message, the
// client's login the 503 that says to try again or the 403 that says the answer was not
// valid, with a report line; no run opens, nothing is recorded, no run key is held, and
// the same run credential opens a run once the issuer answers.
func TestAnIssuerWithNoAnswerAtOpen(t *testing.T) {
	o := origin(t)
	host := strings.TrimPrefix(o.URL, "http://")
	issuer := &issuerAnswers{}
	issuer.set(true, nil)
	cfg := gateway.Config{Policy: enforce127, RunCredentials: realIssuers(t, true)}
	gateway.SetIntrospection(&cfg, issuer.answer, time.Hour)
	s := startVerifying(t, cfg, nil, 0)
	cred := credentialFor("rk-0001")
	s.secrets = append(s.secrets, cred)
	for _, c := range []struct {
		name          string
		err           error
		status        int
		code, message string
		client        int
		clientText    string
		report        string
	}{
		{"unreachable", runcredential.ErrIssuerUnreachable, http.StatusServiceUnavailable, "issuer_unreachable", unreachableText,
			http.StatusServiceUnavailable, tryAgainText, "a run of a client with no session did not open: the issuer's introspection endpoint could not be reached"},
		{"no valid answer", answerInvalid("the introspection endpoint answered status 401"), http.StatusBadGateway, "issuer_answer_invalid", invalidText,
			http.StatusForbidden, invalidText, "a run of a client with no session did not open: the introspection endpoint answered status 401"},
	} {
		issuer.set(false, c.err)
		status, b := s.tryOpenWith(t, cred, server.LinkRunRequest{})
		r := refusalOf(b)
		if status != c.status || r["error"] != c.code || r["from"] != "gateway" || r["message"] != c.message || len(r) != 3 {
			t.Errorf("%s: the session's run request: %d %s", c.name, status, b)
		}
		code, contentType, text, _ := connectWith(t, s, loginHead(host, cred))
		if code != c.client || contentType != plainText || text != c.clientText {
			t.Errorf("%s: the client's login: %d %q %q", c.name, code, contentType, text)
		}
		if got := s.reportsWith(c.report); len(got) != 1 || got[0] != c.report {
			t.Errorf("%s: reports %q", c.name, got)
		}
	}
	if got := runsIn(t, s.dir); len(got) != 0 {
		t.Errorf("runs %v", got)
	}
	noHold(t, s.dir)
	issuer.set(true, nil)
	if status, b := s.tryOpenWith(t, cred, server.LinkRunRequest{}); status != http.StatusOK {
		t.Errorf("once the issuer answers: %d %s", status, b)
	}
	if code, _, text, conn := connectWith(t, s, loginHead(host, cred)); code != http.StatusOK {
		t.Errorf("the client once the issuer answers: %d %q", code, text)
	} else {
		conn.Close()
	}
}

// TestALiveRunWhoseIssuerGivesNoAnswer pins a session's live run whose issuer's
// introspection endpoint no longer answers, or answers no valid answer: the run ends,
// issuer_unreachable or issuer_answer_invalid, its record's run.exited with that reason,
// failed and -1, and a report line; the request and every later one get the 410 with
// its code from the gateway; no run key is held, and the same run credential opens a
// new run once the issuer answers.
func TestALiveRunWhoseIssuerGivesNoAnswer(t *testing.T) {
	for _, c := range []struct {
		err    error
		code   string
		report string
	}{
		{runcredential.ErrIssuerUnreachable, "issuer_unreachable", "the issuer's introspection endpoint could not be reached; the run ends, issuer_unreachable"},
		{answerInvalid("the introspection endpoint answered status 401"), "issuer_answer_invalid", "the introspection endpoint answered status 401; the run ends, issuer_answer_invalid"},
	} {
		t.Run(c.code, func(t *testing.T) {
			issuer := &issuerAnswers{}
			issuer.set(true, nil)
			cfg := gateway.Config{RunCredentials: realIssuers(t, true)}
			gateway.SetIntrospection(&cfg, issuer.answer, time.Hour)
			s := startVerifying(t, cfg, nil, 0)
			cred := credentialFor("rk-0001")
			r := s.openSession(t, cred, server.LinkRunRequest{})
			issuer.set(false, c.err)
			status, b := r.post(t, cred, heartbeat(r.a.RunID))
			gone(t, "the batch", status, b, c.code)
			if msg := refusalOf(b)["message"]; msg != "the gateway refused the run: "+c.code {
				t.Errorf("the 410's message %q", msg)
			}
			status, b = r.reload(t, cred, r.a.RunID)
			gone(t, "a later reload", status, b, c.code)
			if got := s.reportsWith("the run ends, " + c.code); len(got) != 1 || got[0] != "run "+r.a.RunID+": "+c.report {
				t.Errorf("reports %q", got)
			}
			noHold(t, s.dir)
			issuer.set(true, nil)
			if status, b := s.tryOpenWith(t, cred, server.LinkRunRequest{}); status != http.StatusOK {
				t.Errorf("once the issuer answers: %d %s", status, b)
			}
			s.close()
			rec := s.record(r.a.RunID)
			last := rec[len(rec)-1]
			if last.Type != event.RunExited || last.Data["reason"] != c.code || last.Data["state"] != "failed" || last.Data["exit_code"] != float64(-1) {
				t.Errorf("the record ends %+v", last)
			}
			validEvents(t, rec)
			noHold(t, s.dir)
		})
	}
}

// TestAClientsRunWhoseIssuerGivesNoAnswer pins a client's live run whose issuer's
// introspection endpoint no longer answers, or answers no valid answer: a later
// connection of its run key ends the run, issuer_unreachable or issuer_answer_invalid,
// and gets the 503 that says to try again or the 403 that says the answer was not
// valid; asked again while the run has a connection, the run ends the same way; its
// record's run.exited has that reason and neither state nor exit_code; no run key is
// held, and the next connection opens a new run once the issuer answers.
func TestAClientsRunWhoseIssuerGivesNoAnswer(t *testing.T) {
	o := origin(t)
	host := strings.TrimPrefix(o.URL, "http://")
	for _, c := range []struct {
		err          error
		code         string
		status       int
		text, report string
	}{
		{runcredential.ErrIssuerUnreachable, "issuer_unreachable", http.StatusServiceUnavailable, tryAgainText,
			"the issuer's introspection endpoint could not be reached; the run ends, issuer_unreachable"},
		{answerInvalid("the introspection endpoint answered status 400"), "issuer_answer_invalid", http.StatusForbidden, invalidText,
			"the introspection endpoint answered status 400; the run ends, issuer_answer_invalid"},
	} {
		for _, how := range []string{"a later connection", "the periodic ask"} {
			t.Run(c.code+", "+how, func(t *testing.T) {
				issuer := &issuerAnswers{}
				issuer.set(true, nil)
				cfg := gateway.Config{Policy: enforce127, RunCredentials: realIssuers(t, true)}
				cache := time.Hour
				if how == "the periodic ask" {
					cache = 100 * time.Millisecond
				}
				gateway.SetIntrospection(&cfg, issuer.answer, cache)
				s := startVerifying(t, cfg, nil, 0)
				cred := credentialFor("rk-0001")
				s.secrets = append(s.secrets, cred)
				code, _, text, conn := connectWith(t, s, loginHead(host, cred))
				if code != http.StatusOK {
					t.Fatalf("the first connection: %d %q", code, text)
				}
				ids := runsIn(t, s.dir)
				if len(ids) != 1 {
					t.Fatalf("runs %v", ids)
				}
				issuer.set(false, c.err)
				if how == "a later connection" {
					conn.Close()
					code, contentType, text, _ := connectWith(t, s, loginHead(host, cred))
					if code != c.status || contentType != plainText || text != c.text {
						t.Errorf("the later connection: %d %q %q", code, contentType, text)
					}
				} else {
					defer conn.Close()
				}
				eventually(t, "the run's end", func() bool {
					rec := s.record(ids[0])
					return rec[len(rec)-1].Type == event.RunExited
				})
				if got := s.reportsWith("the run ends, " + c.code); len(got) != 1 || got[0] != "run "+ids[0]+": "+c.report {
					t.Errorf("reports %q", got)
				}
				noHold(t, s.dir)
				issuer.set(true, nil)
				code, _, text, next := connectWith(t, s, loginHead(host, cred))
				if code != http.StatusOK {
					t.Fatalf("once the issuer answers: %d %q", code, text)
				}
				next.Close()
				if got := runsIn(t, s.dir); len(got) != 2 {
					t.Errorf("runs %v; want a new one", got)
				}
				s.close()
				rec := s.record(ids[0])
				end := rec[len(rec)-1].Data
				if end["reason"] != c.code || end["state"] != nil || end["exit_code"] != nil {
					t.Errorf("run.exited %v", end)
				}
				validEvents(t, rec)
				noHold(t, s.dir)
			})
		}
	}
}

// TestAClientsRunThatQoryApiaryRefuses pins what a client with no session reads of a
// run Qory Apiary or the gateway refuses as it opens: a 403 that says who refused it
// and the code, Qory Apiary for a code of its answer, answer_unsigned among them, and
// the gateway for a code it decides of the run configuration; a 403 with the status of
// a signed answer without a code; and, once the tries are spent, the 503 that says to
// try again for a 503 or 429 rate_limited and for an unsigned 5xx. The record holds
// the ping and the run.refused with its code, and its status for a code from Qory
// Apiary; a refusal without a code is in the report line alone. A 404 is asked once,
// and the configuration document is not fetched again.
func TestAClientsRunThatQoryApiaryRefuses(t *testing.T) {
	o := origin(t)
	host := strings.TrimPrefix(o.URL, "http://")
	const allow = `{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`
	for _, c := range []struct {
		name    string
		path    string
		replies []apiaryReply
		policy  string // the run configuration served, when not allow
		status  int
		text    string
		refused map[string]any // the record's run.refused, nil for none
		tries   int
		report  string // a part of the report line
	}{
		{"the ping's 400 bad_request", eventsPath, []apiaryReply{coded(400, "bad_request")}, "", 403,
			"the gateway could not open the run: Qory Apiary refused it, bad_request", map[string]any{"code": "bad_request", "status": 400.0}, 1, "bad_request (status 400)"},
		{"the ping's 400 unsupported_contract_version", eventsPath, []apiaryReply{coded(400, "unsupported_contract_version")}, "", 403,
			"the gateway could not open the run: Qory Apiary refused it, unsupported_contract_version", map[string]any{"code": "unsupported_contract_version", "status": 400.0}, 1, "unsupported_contract_version (status 400)"},
		{"the ping's 400 invalid_request", eventsPath, []apiaryReply{coded(400, "invalid_request")}, "", 403,
			"the gateway could not open the run: Qory Apiary refused it, invalid_request", map[string]any{"code": "invalid_request", "status": 400.0}, 1, "invalid_request (status 400)"},
		{"the ping's 409 instance_limit", eventsPath, []apiaryReply{coded(409, "instance_limit")}, "", 403,
			"the gateway could not open the run: Qory Apiary refused it, instance_limit", map[string]any{"code": "instance_limit", "status": 409.0}, 1, "instance_limit (status 409)"},
		{"the ping's unsigned 401", eventsPath, []apiaryReply{unsignedReply(401, "application/json", `{"error":"unauthorized"}`)}, "", 403,
			"the gateway could not open the run: Qory Apiary refused it, unauthorized", map[string]any{"code": "unauthorized", "status": 401.0}, 1, "unauthorized (status 401)"},
		{"the ping's unsigned 413", eventsPath, []apiaryReply{unsignedReply(413, "", "")}, "", 403,
			"the gateway could not open the run: Qory Apiary refused it, answer_unsigned", map[string]any{"code": "answer_unsigned"}, 1, "answer_unsigned (status 413)"},
		{"a run configuration the schema refuses", runPath, nil, `{"version":"one"}`, 403,
			"the gateway could not open the run: the gateway refused it, run_configuration_invalid", map[string]any{"code": "run_configuration_invalid"}, 1, "run_configuration_invalid"},
		{"a run configuration's unknown tool", runPath, nil, `{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]},"tools":[{"name":"example-tool"}]}`, 403,
			"the gateway could not open the run: the gateway refused it, tool_unknown", map[string]any{"code": "tool_unknown", "names": []any{"example-tool"}}, 1, "tool_unknown"},
		{"a run configuration's unknown image", runPath, nil, `{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]},"image":"example-image"}`, 403,
			"the gateway could not open the run: the gateway refused it, image_unknown", map[string]any{"code": "image_unknown", "names": []any{"example-image"}}, 1, "image_unknown"},
		{"a run configuration's 404 not_found", runPath, []apiaryReply{coded(404, "not_found")}, "", 403,
			"the gateway could not open the run: Qory Apiary refused it, not_found", map[string]any{"code": "not_found", "status": 404.0}, 1, "not_found (status 404)"},
		{"a run configuration's unsigned 404 page", runPath, []apiaryReply{notFoundPage}, "", 403,
			"the gateway could not open the run: Qory Apiary refused it, answer_unsigned", map[string]any{"code": "answer_unsigned"}, 1, "answer_unsigned (status 404)"},
		{"a run configuration's code the contract does not list", runPath, []apiaryReply{coded(404, "example_server_code")}, "", 403,
			"the gateway could not open the run: Qory Apiary refused it, example_server_code", map[string]any{"code": "example_server_code", "status": 404.0}, 1, "example_server_code (status 404)"},
		{"a run configuration's signed 404 without a code", runPath, []apiaryReply{{status: 404, signed: true}}, "", 403,
			"the gateway could not open the run: Qory Apiary refused it, status 404", nil, 1, ": status 404"},
		{"a run configuration's signed 200 without its digest", runPath, []apiaryReply{{status: 200, body: allow, contentType: "application/json", signed: true}}, "", 403,
			"the gateway could not open the run: Qory Apiary refused it, status 200", nil, 1, "the answer contains no X-Qory-Run-Configuration header"},
		{"the ping's 503 unavailable three times", eventsPath, []apiaryReply{coded(503, "unavailable"), coded(503, "unavailable"), coded(503, "unavailable")}, "", 503,
			tryAgainText, map[string]any{"code": "unavailable", "status": 503.0}, 3, "unavailable (status 503)"},
		{"the ping's unsigned 502 three times", eventsPath, []apiaryReply{unsignedReply(502, "", ""), unsignedReply(502, "", ""), unsignedReply(502, "", "")}, "", 503,
			tryAgainText, map[string]any{"code": "answer_unsigned"}, 3, "answer_unsigned (status 502)"},
		{"a run configuration's signed 500 without a code three times", runPath, []apiaryReply{{status: 500, signed: true}, {status: 500, signed: true}, {status: 500, signed: true}}, "", 503,
			tryAgainText, nil, 3, ": status 500"},
		{"a run configuration's 429 rate_limited three times", runPath, []apiaryReply{coded(429, "rate_limited"), coded(429, "rate_limited"), coded(429, "rate_limited")}, "", 503,
			tryAgainText, map[string]any{"code": "rate_limited", "status": 429.0}, 3, "rate_limited (status 429)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctl := newControl(t)
			policy := allow
			if c.policy != "" {
				policy = c.policy
			}
			ctl.serve(policy, 'a')
			cfg := gateway.Config{Server: ctl.server()}
			gateway.SetOpenTries(&cfg, []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}, 5*time.Second)
			s := startVerifying(t, cfg, nil, 0)
			sc := script(ctl)
			sc.then(c.path, c.replies...)
			cred := credentialFor("rk-0001")
			s.secrets = append(s.secrets, cred)
			code, contentType, text, conn := connectWith(t, s, loginHead(host, cred))
			if conn != nil {
				conn.Close()
			}
			if code != c.status || contentType != plainText || text != c.text {
				t.Errorf("the client read %d %q %q; want %d %q", code, contentType, text, c.status, c.text)
			}
			if n := len(sc.requests(c.path)); (c.path == runPath || c.tries > 1) && n != c.tries {
				t.Errorf("asked %d times; want %d", n, c.tries)
			}
			if n := len(sc.requests(server.WellKnown)); n != 0 {
				t.Errorf("the configuration document was fetched %d times as the run opened", n)
			}
			if got := s.reportsWith("a run of a client with no session did not open: "); len(got) != 1 || !strings.Contains(got[0], c.report) {
				t.Errorf("reports %q", got)
			}
			ids := runsIn(t, s.dir)
			if len(ids) != 1 {
				t.Fatalf("runs %v", ids)
			}
			rec := s.record(ids[0])
			want := []string{event.Ping}
			if c.refused != nil {
				want = append(want, event.RunRefused)
			}
			if got := types(rec); !slices.Equal(got, want) {
				t.Errorf("record %v; want %v", got, want)
			} else if c.refused != nil && !equalData(rec[1].Data, c.refused) {
				t.Errorf("run.refused %v; want %v", rec[1].Data, c.refused)
			}
			validEvents(t, rec)
		})
	}
}

// equalData compares an event's data as JSON decodes it.
func equalData(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range b {
		if list, ok := v.([]any); ok {
			got, _ := a[k].([]any)
			if !slices.Equal(got, list) {
				return false
			}
			continue
		}
		if a[k] != v {
			return false
		}
	}
	return true
}
