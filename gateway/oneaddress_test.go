package gateway_test

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// The runs of these tests open on the gateway's one address, each request's bearer
// value decided by the tests' verifier, the seam of service_test.go: the gateway itself
// has no verifier of its own yet.

// exampleLabels are the labels of the example runs.
func exampleLabels() map[string]string {
	return map[string]string{"forge": "example-forge", "repository": "example-namespace/project"}
}

// tryOpenWith sends a run request on the one address with the bearer value, and
// returns the status and the answer's body.
func (s *service) tryOpenWith(t *testing.T, value string, req server.LinkRunRequest) (int, []byte) {
	t.Helper()
	req.Version = 1
	if req.RunID == "" {
		req.RunID = event.NewRunID()
	}
	body, _ := json.Marshal(req)
	resp, b := do(t, s.client(value), http.MethodPost, s.url("/v1/run-configuration"), server.LinkContentType, string(body))
	return resp.StatusCode, b
}

// refusalOf decodes a refusal's body.
func refusalOf(b []byte) map[string]any {
	var r map[string]any
	json.Unmarshal(b, &r)
	return r
}

// sessionRun is a session's run on the one address, opened with its bearer value.
type sessionRun struct {
	s     *service
	value string
	a     *server.LinkRunAnswer
}

// openSession opens a session's run with the bearer value and starts it: its
// run.started, with the run's labels and an about, and its policy_applied.
func (s *service) openSession(t *testing.T, value string, req server.LinkRunRequest) *sessionRun {
	t.Helper()
	if req.Labels == nil {
		req.Labels = exampleLabels()
	}
	a, _ := s.openWith(t, value, req)
	r := &sessionRun{s: s, value: value, a: a}
	st := started(a.RunID, a.Labels)
	st["data"].(map[string]any)["about"] = map[string]any{"title": "Fix the failing build", "details": map[string]any{"requester": "example-requester"}}
	s.postWith(t, value, st, applied(a.RunID, a.Applied))
	return r
}

// post posts one batch of the run's events with the bearer value given, and returns
// the status and the body.
func (r *sessionRun) post(t *testing.T, value string, evs ...map[string]any) (int, []byte) {
	t.Helper()
	body, _ := json.Marshal(evs)
	resp, b := do(t, r.s.client(value), http.MethodPost, r.s.url("/v1/events"), server.ContentType, string(body))
	return resp.StatusCode, b
}

// reload asks for the run's configuration with the bearer value given.
func (r *sessionRun) reload(t *testing.T, value, runID string) (int, []byte) {
	t.Helper()
	resp, b := do(t, r.s.client(value), http.MethodGet, r.s.url("/v1/run-configuration/"+runID), "", "")
	return resp.StatusCode, b
}

// gone checks a 410 of the gateway's with the code.
func gone(t *testing.T, what string, status int, b []byte, code string) {
	t.Helper()
	r := refusalOf(b)
	if status != http.StatusGone || r["error"] != code || r["from"] != "gateway" {
		t.Errorf("%s: %d %s", what, status, b)
	}
}

// noSecretIn fails the test when a file of dir, or any below it, holds one of the
// secrets.
func noSecretIn(t *testing.T, dir string, secrets ...string) {
	t.Helper()
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(path)
		for _, s := range secrets {
			if s != "" && bytes.Contains(b, []byte(s)) {
				t.Errorf("%s holds a secret", path)
			}
		}
		return nil
	})
}

// validEvents fails the test unless every event of the record is valid under its
// type's schema.
func validEvents(t *testing.T, rec []recorded) {
	t.Helper()
	for _, l := range rec {
		name := "events/" + strings.TrimPrefix(l.Type, "dev.qory.") + ".schema.json"
		schema, err := contracts.Compile(name)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(l.Data)
		doc, _ := contracts.Decode("data.json", b)
		if err := schema.Validate(doc); err != nil {
			t.Errorf("%s %s: %v", l.Type, b, err)
		}
	}
}

// runsIn are the run ids of the gateway's records.
func runsIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, _ := os.ReadDir(filepath.Join(dir, "runs"))
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// sameMap reports whether two maps of labels are equal.
func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// relayTunnel is a CONNECT tunnel to host through a session's run's relay on the one
// address, the run's proxy secret its preamble.
func (s *service) relayTunnel(t *testing.T, secret, host string) net.Conn {
	t.Helper()
	c := s.dial(t)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(c, link.Preamble(link.RelayPreamble, secret)+"CONNECT "+host+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, nil)
	if err != nil || resp.StatusCode != http.StatusOK || r.Buffered() > 0 {
		c.Close()
		t.Fatalf("the relay's CONNECT: %v %v", resp, err)
	}
	return c
}

// tunnelOpen reports whether a tunnel to the origin at host still relays: a request
// sent through it is answered. A tunnel the gateway closed answers nothing; one that
// only times out would be open, and is reported so.
func tunnelOpen(c net.Conn, host string) bool {
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"); err != nil {
		return false
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		var ne net.Error
		return errors.As(err, &ne) && ne.Timeout()
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return true
}

// TestASessionsRunOverTheOneAddress pins a session's run on the one address end to
// end: the run's labels are the run request's; the server is asked for the run
// configuration by them; the run answer is valid under its schema; a batch and a
// reload with the bearer value are answered; and neither the record, the server, nor a
// report holds the bearer value.
func TestASessionsRunOverTheOneAddress(t *testing.T) {
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`, 'a')
	s := startService(t, gateway.Config{Server: c.server()}, false)
	r := s.openSession(t, goodBearer, server.LinkRunRequest{})
	if !sameMap(r.a.Labels, exampleLabels()) {
		t.Errorf("the answer's labels %v", r.a.Labels)
	}
	schema, err := contracts.Compile("link-run-answer.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := json.Marshal(r.a)
	if doc, _ := contracts.Decode("answer.json", answer); schema.Validate(doc) != nil {
		t.Errorf("the run answer %s: %v", answer, schema.Validate(doc))
	}
	c.mu.Lock()
	asked := c.labels
	c.mu.Unlock()
	if !sameMap(asked, exampleLabels()) {
		t.Errorf("the server was asked by %v", asked)
	}
	if status, b := r.reload(t, goodBearer, r.a.RunID); status != http.StatusOK {
		t.Errorf("the reload: %d %s", status, b)
	}
	if status, b := r.post(t, goodBearer, exited(r.a.RunID)); status != http.StatusAccepted {
		t.Errorf("the run.exited: %d %s", status, b)
	}
	s.close()
	rec := s.record(r.a.RunID)
	if got := types(rec); !slices.Equal(got, []string{event.RunRegistered, event.RunStarted, event.PolicyApplied, event.RunExited}) {
		t.Errorf("record %v", got)
	}
	validEvents(t, rec)
	noSecretIn(t, s.dir, goodBearer)
	if b, _ := os.ReadFile(c.received); bytes.Contains(b, []byte(goodBearer)) || !bytes.Contains(b, []byte(`"repository":"example-namespace/project"`)) {
		t.Error("what the server received holds the bearer value, or not the run's labels")
	}
}

// TestEveryRequestOfARunCarriesItsBearerValue pins the bearer value of a run's later
// requests: a reload or a batch with a value of another key, one with no run or one
// with a run of its own, is 401, so no run id can be probed, and neither run ends; a
// later value of the run's key carries the run once the first is no longer accepted,
// its proxy secret still served.
func TestEveryRequestOfARunCarriesItsBearerValue(t *testing.T) {
	o := origin(t)
	s := startService(t, gateway.Config{Policy: enforce127}, false)
	first := "first.bearer-value.0001"
	s.v.allow(first, "rk-0001", time.Now().Add(1500*time.Millisecond))
	s.secrets = append(s.secrets, first)
	r := s.openSession(t, first, server.LinkRunRequest{})
	b := s.openSession(t, otherBearer, server.LinkRunRequest{})
	stranger := "stranger.bearer-value.0009"
	s.v.allow(stranger, "rk-0009", time.Now().Add(time.Hour))
	s.secrets = append(s.secrets, stranger)
	for name, c := range map[string]string{"a key with no run": stranger, "another run's key": otherBearer} {
		if status, body := r.reload(t, c, r.a.RunID); status != http.StatusUnauthorized {
			t.Errorf("a reload, %s: %d %s", name, status, body)
		}
	}
	if status, body := r.post(t, stranger, heartbeat(r.a.RunID)); status != http.StatusUnauthorized {
		t.Errorf("a batch, a key with no run: %d %s", status, body)
	}
	if status, body := r.post(t, otherBearer, heartbeat(r.a.RunID)); status != http.StatusUnauthorized {
		t.Errorf("a batch of another key's run: %d %s", status, body)
	}
	if status, body := b.reload(t, otherBearer, b.a.RunID); status != http.StatusOK {
		t.Errorf("the run whose bearer value was presented: %d %s", status, body)
	}
	// A later value of the run's key carries the run past the first's expiry.
	later := "later.bearer-value.0001"
	s.v.allow(later, "rk-0001", time.Now().Add(time.Hour))
	s.secrets = append(s.secrets, later)
	if status, body := r.post(t, later, heartbeat(r.a.RunID)); status != http.StatusAccepted {
		t.Fatalf("a batch with a later value: %d %s", status, body)
	}
	time.Sleep(2 * time.Second)
	if status, body := r.reload(t, first, r.a.RunID); status != http.StatusUnauthorized {
		t.Errorf("the first value past its expiry: %d %s", status, body)
	}
	if status, body := r.reload(t, later, r.a.RunID); status != http.StatusOK {
		t.Errorf("the later value: %d %s", status, body)
	}
	if code, _, err := get(s.relayOver(r.a.ProxySecret), o.URL); err != nil || code != http.StatusOK {
		t.Errorf("the relay: %d %v", code, err)
	}
	host := strings.TrimPrefix(o.URL, "http://")
	tunnel := s.relayTunnel(t, r.a.ProxySecret, host)
	defer tunnel.Close()
	if !tunnelOpen(tunnel, host) {
		t.Fatal("the relay's tunnel does not relay")
	}
	if status, body := r.post(t, later, exited(r.a.RunID)); status != http.StatusAccepted {
		t.Errorf("the run.exited: %d %s", status, body)
	}
	s.close()
	rec := s.record(r.a.RunID)
	if last := rec[len(rec)-1]; last.Type != event.RunExited || last.Data["state"] != "succeeded" {
		t.Errorf("the record ends %+v", last)
	}
	validEvents(t, rec)
	noSecretIn(t, s.dir, first, later, otherBearer, stranger)
}

// TestANarrowingOnTheOneAddress pins a session's narrowing behind a separate gateway:
// accepted, it narrows the node's policy, so a host the narrowing's allow does not
// cover is denied to the run's relay; the answer's policy is the narrowed one, with
// its own digest.
func TestANarrowingOnTheOneAddress(t *testing.T) {
	o := origin(t)
	s := startService(t, gateway.Config{Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"127.0.0.1", "api.example"}}}}, false)
	r := s.openSession(t, goodBearer, server.LinkRunRequest{Narrowing: &server.LinkNarrowing{Egress: server.LinkNarrowingEgress{Allow: []string{"api.example"}, Deny: []string{"tracker.example"}}}})
	var p struct {
		Egress struct {
			Mode        string
			Allow, Deny []string
		}
	}
	json.Unmarshal(r.a.Policy, &p)
	if p.Egress.Mode != "enforce" || !slices.Equal(p.Egress.Allow, []string{"api.example"}) || !slices.Equal(p.Egress.Deny, []string{"tracker.example"}) || r.a.Digest == "" {
		t.Errorf("the policy %s %s", r.a.Policy, r.a.Digest)
	}
	if status, _, err := get(s.relayOver(r.a.ProxySecret), o.URL); err != nil || status != http.StatusForbidden {
		t.Errorf("a host the narrowing removed: %d %v", status, err)
	}
	// The local link takes none.
	if _, err := s.tryOpen(server.LinkRunRequest{Narrowing: &server.LinkNarrowing{Egress: server.LinkNarrowingEgress{Deny: []string{"tracker.example"}}}}); err == nil {
		t.Error("the local link took a narrowing")
	}
}

// TestANarrowingOpensNoneOfTheMachinesAddresses pins the guard of a session's run on
// the one address under its narrowing: a narrowing's allow that names the gateway's
// own address opens it under no policy and under an observe policy, at the start and
// after a reload alike; only a policy that enforces and names the host itself does.
func TestANarrowingOpensNoneOfTheMachinesAddresses(t *testing.T) {
	o := origin(t)
	narrowing := &server.LinkNarrowing{Egress: server.LinkNarrowingEgress{Allow: []string{"127.0.0.1"}}}
	denied := func(what string, s *service, r *sessionRun) {
		t.Helper()
		if status, _, err := get(s.relayOver(r.a.ProxySecret), o.URL); err != nil || status != http.StatusForbidden {
			t.Errorf("%s: the gateway's own address answered %d %v", what, status, err)
		}
	}
	for name, pol := range map[string]*gateway.Policy{
		"no policy": nil,
		"observe":   {Version: 1, Egress: gateway.PolicyEgress{Mode: "observe"}},
	} {
		s := startService(t, gateway.Config{Policy: pol}, false)
		denied(name, s, s.openSession(t, goodBearer, server.LinkRunRequest{Narrowing: narrowing}))
	}
	// A reload to another observe policy opens nothing either.
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"observe"}}`, 'a')
	s := startService(t, gateway.Config{Server: c.server()}, false)
	r := s.openSession(t, goodBearer, server.LinkRunRequest{Narrowing: narrowing})
	denied("at the start", s, r)
	c.serve(`{"version":1,"egress":{"mode":"observe","deny":["tracker.example"]}}`, 'b')
	eventually(t, "the reload", func() bool {
		r.post(t, goodBearer, heartbeat(r.a.RunID))
		_, b := r.reload(t, goodBearer, r.a.RunID)
		return bytes.Contains(b, []byte("tracker.example"))
	})
	denied("after the reload", s, r)
	// A policy that enforces and names the host itself opens it.
	named := startService(t, gateway.Config{Policy: enforce127}, false)
	nr := named.openSession(t, goodBearer, server.LinkRunRequest{Narrowing: narrowing})
	if status, _, err := get(named.relayOver(nr.a.ProxySecret), o.URL); err != nil || status != http.StatusOK {
		t.Errorf("a host the policy names itself: %d %v", status, err)
	}
}

// TestNoLinkSocketWithTheOneAddress pins Config.NoLinkSocket beside Listen: the
// gateway serves the one address over TLS, a session's run going as without it, and
// makes no link directory and no socket; its local link is in memory alone.
func TestNoLinkSocketWithTheOneAddress(t *testing.T) {
	tmp, err := os.MkdirTemp("/tmp", "qt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	t.Setenv("TMPDIR", tmp)
	s := startService(t, gateway.Config{NoLinkSocket: true}, false)
	if l := s.g.LocalLink(); l.Socket != "" || !l.IsInMemory() {
		t.Errorf("local %+v", l)
	}
	r := s.openSession(t, goodBearer, server.LinkRunRequest{})
	if status, b := r.reload(t, goodBearer, r.a.RunID); status != http.StatusOK {
		t.Errorf("the reload: %d %s", status, b)
	}
	if status, b := r.post(t, goodBearer, exited(r.a.RunID)); status != http.StatusAccepted {
		t.Errorf("the run.exited: %d %s", status, b)
	}
	if m, _ := filepath.Glob(filepath.Join(tmp, link.LinkDirPrefix+"*")); len(m) != 0 {
		t.Errorf("link directories %v", m)
	}
	s.close()
	if got := types(s.record(r.a.RunID)); !slices.Equal(got, []string{event.RunStarted, event.PolicyApplied, event.RunExited}) {
		t.Errorf("record %v", got)
	}
}

// TestAGatewayLetsGoOfEndedRuns pins the bound on what a gateway holds of the runs of
// its one address: once a run has ended and its record is flushed, the gateway holds
// only what a later request of the run is answered with, the 410, a run id not the
// key's still 401; and once its bearer value has expired, the next run to end takes
// what it left with it.
func TestAGatewayLetsGoOfEndedRuns(t *testing.T) {
	s := startService(t, gateway.Config{Policy: enforce127}, false)
	exp := time.Now().Add(3 * time.Second)
	var ended []*sessionRun
	for _, k := range []string{"rk-0001", "rk-0002", "rk-0003"} {
		value := "ending.bearer-value." + k
		s.v.allow(value, k, exp)
		s.secrets = append(s.secrets, value)
		r := s.openSession(t, value, server.LinkRunRequest{})
		if status, b := r.post(t, value, exited(r.a.RunID)); status != http.StatusAccepted {
			t.Fatalf("the run.exited: %d %s", status, b)
		}
		ended = append(ended, r)
	}
	eventually(t, "the runs let go of", func() bool {
		runs, spent := gateway.Held(s.g)
		return runs == 0 && spent == 3
	})
	r := ended[0]
	if status, b := r.reload(t, r.value, r.a.RunID); status != http.StatusGone {
		t.Errorf("a reload of a run let go of: %d %s", status, b)
	}
	if status, b := r.reload(t, r.value, ended[1].a.RunID); status != http.StatusUnauthorized {
		t.Errorf("a reload of another run id: %d %s", status, b)
	}
	if status, b := r.post(t, r.value, heartbeat(r.a.RunID)); status != http.StatusGone {
		t.Errorf("a batch of a run let go of: %d %s", status, b)
	}
	// Past their expiry, the next run to end takes what they left with it.
	time.Sleep(time.Until(exp) + 100*time.Millisecond)
	last := s.openSession(t, goodBearer, server.LinkRunRequest{})
	last.post(t, goodBearer, exited(last.a.RunID))
	eventually(t, "what the earlier runs left let go of", func() bool {
		runs, spent := gateway.Held(s.g)
		return runs == 0 && spent == 1
	})
	// Of the run secrets, only the last run's is known still.
	if n := gateway.SecretsIndexed(s.g); n != 1 {
		t.Errorf("%d run secrets known, want the last run's alone", n)
	}
}

// TestARefusedProxyRequestIsAnsweredInFull pins the 407 of a client that sends a body
// before it reads: the gateway answers, closes its writing side and reads what the
// client still sends before it closes, so the client reads the whole answer, never a
// reset in its place.
func TestARefusedProxyRequestIsAnsweredInFull(t *testing.T) {
	s := startService(t, gateway.Config{}, false)
	body := strings.Repeat("x", 32<<10)
	for i := range 20 {
		c := s.dial(t)
		c.SetDeadline(time.Now().Add(5 * time.Second))
		head := "POST http://api.example/upload HTTP/1.1\r\nHost: api.example\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(":not-a-proxy-secret")) + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
		if _, err := io.WriteString(c, head+body); err != nil {
			t.Fatalf("%d: sending: %v", i, err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("%d: reading the answer: %v", i, err)
		}
		b, err := io.ReadAll(resp.Body)
		c.Close()
		if err != nil || resp.StatusCode != http.StatusProxyAuthRequired || string(b) != "a live run's proxy secret is required as the proxy password" {
			t.Fatalf("%d: %d %q %v", i, resp.StatusCode, b, err)
		}
	}
}

// TestARunKeyIsNotUnique pins the gateway tracking keys without requiring them to be
// unique: two sessions with one key open two runs at once, each of its own run id and
// proxy secret; a run of a key whose run ended, whose run was refused, or whose run
// Qory Apiary closed with its 410 opens as any other; and a run id another run has is
// still run_id_used.
func TestARunKeyIsNotUnique(t *testing.T) {
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, 'a')
	s := startService(t, gateway.Config{Server: c.server()}, false)
	a := s.openSession(t, goodBearer, server.LinkRunRequest{})
	b := s.openSession(t, goodBearer, server.LinkRunRequest{})
	if a.a.RunID == b.a.RunID || a.a.ProxySecret == b.a.ProxySecret {
		t.Errorf("two runs of one key: %s %s", a.a.RunID, b.a.RunID)
	}
	for _, r := range []*sessionRun{a, b} {
		if status, body := r.reload(t, goodBearer, r.a.RunID); status != http.StatusOK {
			t.Errorf("a reload of %s: %d %s", r.a.RunID, status, body)
		}
	}
	if status, body := s.tryOpenWith(t, goodBearer, server.LinkRunRequest{RunID: a.a.RunID}); status != http.StatusConflict || refusalOf(body)["error"] != "run_id_used" {
		t.Errorf("a run id in use: %d %s", status, body)
	}
	// After a run ended.
	if status, body := a.post(t, goodBearer, exited(a.a.RunID)); status != http.StatusAccepted {
		t.Fatalf("the run.exited: %d %s", status, body)
	}
	after := s.openSession(t, goodBearer, server.LinkRunRequest{})
	// After a refused run.
	c.serve(`{"version":1,"egress":{"mode":"bogus"}}`, 'b')
	if status, body := s.tryOpenWith(t, goodBearer, server.LinkRunRequest{}); status != http.StatusForbidden || refusalOf(body)["error"] != "run_configuration_invalid" {
		t.Errorf("a run the server's configuration refuses: %d %s", status, body)
	}
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, 'c')
	s.openSession(t, goodBearer, server.LinkRunRequest{})
	// After Qory Apiary's 410: the run goes on, and the key opens a new run.
	c.closed.Store(true)
	after.post(t, goodBearer, heartbeat(after.a.RunID))
	eventually(t, "Qory Apiary's 410", func() bool {
		b, _ := os.ReadFile(filepath.Join(s.dir, "runs", after.a.RunID, "delivered.log"))
		return bytes.Contains(b, []byte("stopped"))
	})
	c.closed.Store(false)
	if status, body := after.post(t, goodBearer, heartbeat(after.a.RunID)); status != http.StatusAccepted {
		t.Errorf("a batch after Qory Apiary's 410: %d %s", status, body)
	}
	if status, body := after.reload(t, goodBearer, after.a.RunID); status != http.StatusOK {
		t.Errorf("a reload after Qory Apiary's 410: %d %s", status, body)
	}
	s.openSession(t, goodBearer, server.LinkRunRequest{})
}

// TestARunWhoseSessionGaveUpDoesNotOpen pins a run request whose session gives up
// waiting for its answer, while Qory Apiary is slow on the registration, or as the run
// opens: no run opens, Qory Apiary's events hold nothing of it, and a retry of the same
// run id opens the run, its registration the same bytes, which Qory Apiary, which took
// the first when the run was slow to open, answers alike.
func TestARunWhoseSessionGaveUpDoesNotOpen(t *testing.T) {
	for _, slowAt := range []string{"registration", "open"} {
		c := newControl(t)
		c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, 'a')
		cfg := gateway.Config{Server: c.server()}
		var slowOpen atomic.Bool
		gateway.SetOpened(&cfg, func() {
			if slowOpen.Load() {
				time.Sleep(time.Second)
			}
		})
		s := startService(t, cfg, false)
		runID := event.NewRunID()
		var want []string
		switch slowAt {
		case "registration":
			c.slowFetch.Store(int64(5 * time.Second))
		case "open":
			slowOpen.Store(true)
		}
		impatient := s.client(goodBearer)
		impatient.Timeout = 300 * time.Millisecond
		body, _ := json.Marshal(server.LinkRunRequest{Version: 1, RunID: runID, Labels: exampleLabels()})
		if resp, err := impatient.Post(s.url("/v1/run-configuration"), server.LinkContentType, bytes.NewReader(body)); err == nil {
			resp.Body.Close()
			t.Fatalf("slow at the %s: answered %d", slowAt, resp.StatusCode)
		}
		eventually(t, "the run's record removed", func() bool {
			_, err := os.Stat(filepath.Join(s.dir, "runs", runID))
			return errors.Is(err, fs.ErrNotExist)
		})
		if runs, spent := gateway.Held(s.g); runs != 0 || spent != 0 {
			t.Errorf("slow at the %s: runs %d, spent %d", slowAt, runs, spent)
		}
		var got []string
		for _, l := range c.lines(t) {
			if l.Subject == runID {
				got = append(got, l.Type)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("slow at the %s: Qory Apiary's events of the run %v", slowAt, got)
		}
		c.slowEvents.Store(0)
		c.slowFetch.Store(0)
		slowOpen.Store(false)
		r := s.openSession(t, goodBearer, server.LinkRunRequest{RunID: runID})
		if r.a == nil || r.a.RunID != runID {
			t.Fatalf("slow at the %s: the retry %+v", slowAt, r.a)
		}
		c.mu.Lock()
		regs := slices.Clone(c.registrations)
		c.mu.Unlock()
		// Slow at the registration, Qory Apiary took none of the first.
		if n := map[string]int{"registration": 1, "open": 2}[slowAt]; len(regs) != n || !bytes.Equal(regs[0], regs[n-1]) {
			t.Errorf("slow at the %s: the registrations %q", slowAt, regs)
		}
		if status, b := r.reload(t, goodBearer, runID); status != http.StatusOK {
			t.Errorf("slow at the %s: a reload of the retry: %d %s", slowAt, status, b)
		}
		r.post(t, goodBearer, exited(runID))
		s.close()
	}
}
