package gateway_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/server"
)

// runIDHeaders are the ways a batch can name no run of its own in X-Qory-Run-Id: none,
// an empty one, the run id of no run, and the run's own twice.
func runIDHeaders(own string) map[string][]string {
	return map[string][]string{
		"no run id":          nil,
		"an empty run id":    {""},
		"a run id of no run": {event.NewRunID()},
		"the run id twice":   {own, own},
	}
}

// localRequest sends a reload or a batch on the local link with the X-Qory-Run-Id
// values given, none for nil, and returns the status and the refusal.
func localRequest(t *testing.T, h *harness, method, path, body string, runID []string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, server.LocalOrigin+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", server.ContentType)
	}
	if runID != nil {
		req.Header[server.HeaderRunID] = runID
	}
	resp, err := raw(t, h.g.LocalLink()).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, refusalOf(b)
}

// TestTheLocalLinkFindsABatchsRunByItsRunID pins D-15 on the local link: a batch that
// names no run in X-Qory-Run-Id, an empty one, one of no run or the run's own twice is
// a 400 invalid_request that ends no run; a reload names its run by its path alone, and
// one of no run id is the same 400; the run goes on, and a batch that names it reaches
// it.
func TestTheLocalLinkFindsABatchsRunByItsRunID(t *testing.T) {
	h := start(t, gateway.Config{})
	a := h.open(server.LinkRunRequest{})
	other := h.open(server.LinkRunRequest{})
	if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	beat := string(mustJSON(t, []map[string]any{heartbeat(a.RunID)}))
	for name, runID := range runIDHeaders(a.RunID) {
		if status, r := localRequest(t, h, http.MethodPost, "/v1/events", beat, runID); status != http.StatusBadRequest || r["error"] != "invalid_request" {
			t.Errorf("a batch with %s: %d %v", name, status, r)
		}
	}
	if status, r := localRequest(t, h, http.MethodGet, "/v1/run-configuration/", "", []string{a.RunID}); status != http.StatusBadRequest || r["error"] != "invalid_request" {
		t.Errorf("a reload of no run id: %d %v", status, r)
	}
	for _, runID := range [][]string{nil, {other.RunID}} {
		if status, _ := localRequest(t, h, http.MethodGet, "/v1/run-configuration/"+a.RunID, "", runID); status != http.StatusOK {
			t.Errorf("a reload by its path, X-Qory-Run-Id %q: %d", runID, status)
		}
	}
	if status, r := localRequest(t, h, http.MethodPost, "/v1/events", beat, []string{a.RunID}); status != http.StatusAccepted {
		t.Errorf("a batch that names its run: %d %v", status, r)
	}
	if d := h.post(heartbeat(a.RunID)); !d.Accepted() {
		t.Errorf("the run after the refusals: %+v", d)
	}
	if d := h.post(heartbeat(other.RunID)); !d.Accepted() {
		t.Errorf("the other run after the refusals: %+v", d)
	}
	if len(h.reportsWith("refused a batch")) != 0 {
		t.Errorf("a refusal ended a run: %q", h.reportsWith("refused a batch"))
	}
}

// mustJSON is v as JSON.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// remoteRequest sends a reload or a batch on the one address with the bearer value,
// none when empty, and the X-Qory-Run-Id values given, none for nil, and returns the
// status, the WWW-Authenticate and the body.
func remoteRequest(t *testing.T, s *service, value, method, path, body string, runID []string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(method, s.url(path), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", server.ContentType)
	}
	req.Header[server.HeaderRunID] = runID
	if runID == nil {
		// Set, so the client adds none of its own.
		req.Header[server.HeaderRunID] = []string{}
	}
	resp, err := s.client(value).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate"), string(b)
}

// TestTheOneAddressTakesARequestOfARunOfItsKeyAlone pins the one address: a batch that
// names no run of the identity's key in X-Qory-Run-Id, an empty one, one of no run or
// the run's own twice, a reload or a batch of the run with another run key's bearer
// value or none, and a reload of no run id get the same 401 unauthorized, body and
// header alike, so no run can be probed; no run is ended, and each goes on.
func TestTheOneAddressTakesARequestOfARunOfItsKeyAlone(t *testing.T) {
	s := startService(t, gateway.Config{}, false)
	cred, otherKey := goodBearer, otherBearer
	a := s.openSession(t, cred, server.LinkRunRequest{})
	sibling := s.openSession(t, cred, server.LinkRunRequest{})
	s.openSession(t, otherKey, server.LinkRunRequest{})
	beat := string(mustJSON(t, []map[string]any{heartbeat(a.a.RunID)}))
	var first string
	check := func(what string, status int, auth, body string) {
		t.Helper()
		got := fmt.Sprintf("%d %s %s", status, auth, body)
		if first == "" {
			first = got
		}
		if status != http.StatusUnauthorized || refusalOf([]byte(body))["error"] != "unauthorized" || got != first {
			t.Errorf("%s: %s, want %s", what, got, first)
		}
	}
	for name, runID := range runIDHeaders(a.a.RunID) {
		status, auth, body := remoteRequest(t, s, cred, http.MethodPost, "/v1/events", beat, runID)
		check("a batch with "+name, status, auth, body)
	}
	for name, value := range map[string]string{"another key's bearer value": otherKey, "no bearer value": ""} {
		status, auth, body := remoteRequest(t, s, value, http.MethodGet, "/v1/run-configuration/"+a.a.RunID, "", nil)
		check("a reload with "+name, status, auth, body)
		status, auth, body = remoteRequest(t, s, value, http.MethodPost, "/v1/events", beat, []string{a.a.RunID})
		check("a batch with "+name, status, auth, body)
	}
	status, auth, body := remoteRequest(t, s, cred, http.MethodGet, "/v1/run-configuration/", "", nil)
	check("a reload of no run id", status, auth, body)
	for _, r := range []*sessionRun{a, sibling} {
		if status, body := r.reload(t, cred, r.a.RunID); status != http.StatusOK {
			t.Errorf("run %s after the refusals: %d %s", r.a.RunID, status, body)
		}
		if status, body := r.post(t, cred, heartbeat(r.a.RunID)); status != http.StatusAccepted {
			t.Errorf("a batch of run %s after the refusals: %d %s", r.a.RunID, status, body)
		}
	}
	if len(s.reportsWith("refused a batch")) != 0 {
		t.Errorf("a refusal ended a run: %q", s.reportsWith("refused a batch"))
	}
}

// TestABatchTheLinkRefusesEndsTheRunItNames pins D4 and the bad batches on both links:
// a batch the link refuses ends the run its X-Qory-Run-Id names, batch_refused, with
// the gateway's line, whatever run its events name: another run's events, whose
// subject is not the run's, a batch over the size limit, one that does not decode and
// an empty one among them. The run its events name goes on. A batch whose body never
// arrives whole ends no run.
func TestABatchTheLinkRefusesEndsTheRunItNames(t *testing.T) {
	h := start(t, gateway.Config{})
	s := startService(t, gateway.Config{}, false)
	cred := goodBearer
	// Each batch, by the why the gateway reports, given the run its events name.
	batches := []struct {
		name, why string
		body      func(other string) string
	}{
		{"another run's events", "an event of another run", func(other string) string {
			return string(mustJSON(t, []map[string]any{heartbeat(other)}))
		}},
		{"over the size limit", "a batch over the size limit", func(string) string { return "[" + strings.Repeat(" ", 2<<20) + "]" }},
		{"not decoding", "one link-batch.schema.json refuses", func(string) string { return "not a batch" }},
		{"empty", "one link-batch.schema.json refuses", func(string) string { return "[]" }},
	}
	for _, c := range batches {
		t.Run("local "+c.name, func(t *testing.T) {
			a, b := h.open(server.LinkRunRequest{}), h.open(server.LinkRunRequest{})
			if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
				t.Fatalf("the first batch: %+v", d)
			}
			if status, r := localRequest(t, h, http.MethodPost, "/v1/events", c.body(b.RunID), []string{a.RunID}); status != http.StatusBadRequest || r["error"] != "invalid_request" {
				t.Errorf("the batch: %d %v", status, r)
			}
			line := fmt.Sprintf("run %s: the gateway refused a batch of its session's, %s; the run ends: failed", a.RunID, c.why)
			if !h.reported(line) {
				t.Errorf("no line %q in %q", line, h.reportsWith(a.RunID))
			}
			if d := h.post(heartbeat(a.RunID)); d.Status != http.StatusGone || d.Code != "batch_refused" {
				t.Errorf("the run after its refused batch: %+v", d)
			}
			if d := h.post(heartbeat(b.RunID)); !d.Accepted() {
				t.Errorf("the other run: %+v", d)
			}
		})
		t.Run("one address "+c.name, func(t *testing.T) {
			a := s.openSession(t, cred, server.LinkRunRequest{})
			b := s.openSession(t, cred, server.LinkRunRequest{})
			if status, _, got := remoteRequest(t, s, cred, http.MethodPost, "/v1/events", c.body(b.a.RunID), []string{a.a.RunID}); status != http.StatusBadRequest || refusalOf([]byte(got))["error"] != "invalid_request" {
				t.Errorf("the batch: %d %s", status, got)
			}
			line := fmt.Sprintf("run %s: the gateway refused a batch of its session's, %s; the run ends: failed", a.a.RunID, c.why)
			if !s.reported(line) {
				t.Errorf("no line %q in %q", line, s.reportsWith(a.a.RunID))
			}
			status, body := a.reload(t, cred, a.a.RunID)
			gone(t, "the run after its refused batch", status, body, "batch_refused")
			if status, body := b.post(t, cred, heartbeat(b.a.RunID)); status != http.StatusAccepted {
				t.Errorf("the other run: %d %s", status, body)
			}
		})
	}
	t.Run("a body cut short", func(t *testing.T) {
		a := h.open(server.LinkRunRequest{})
		c, err := net.Dial("unix", h.g.LocalLink().Socket)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(c, "POST /v1/events HTTP/1.1\r\nHost: localhost\r\nContent-Type: "+server.ContentType+"\r\n"+server.HeaderRunID+": "+a.RunID+"\r\nContent-Length: 1000\r\n\r\n[{")
		c.(*net.UnixConn).CloseWrite()
		io.ReadAll(c)
		c.Close()
		if d := h.post(heartbeat(a.RunID)); !d.Accepted() {
			t.Errorf("the run after a body cut short: %+v", d)
		}
		if len(h.reportsWith(a.RunID)) != 0 {
			t.Errorf("reported %q", h.reportsWith(a.RunID))
		}
	})
}

// answered is a request's status and body.
type answered struct {
	status int
	body   []byte
}

// ofRun sends a reload of the run by its path and a batch of it on the one address
// with the bearer value, the batch with the X-Qory-Run-Id values given, none for nil,
// and returns each one's status and body, by name.
func ofRun(t *testing.T, s *service, value, runID string, ids []string) map[string]answered {
	t.Helper()
	out := map[string]answered{}
	beat := string(mustJSON(t, []map[string]any{heartbeat(runID)}))
	status, _, body := remoteRequest(t, s, value, http.MethodGet, "/v1/run-configuration/"+runID, "", nil)
	out["a reload"] = answered{status, []byte(body)}
	status, _, body = remoteRequest(t, s, value, http.MethodPost, "/v1/events", beat, ids)
	out["a batch"] = answered{status, []byte(body)}
	return out
}

// refusedAll checks that each of a reload and a batch got the 401 unauthorized.
func refusedAll(t *testing.T, what string, got map[string]answered) {
	t.Helper()
	for name, g := range got {
		if g.status != http.StatusUnauthorized || refusalOf(g.body)["error"] != "unauthorized" {
			t.Errorf("%s, %s: %d %s", what, name, g.status, g.body)
		}
	}
}

// TestASpentRunIsFoundUntilItLapses pins a run that ended and was let go of: with a
// bearer value of its key, a reload by its path and a batch that names it get its 410
// until the identity it was opened with expires, and the 401 after; with a value of
// another key, the 401 throughout.
func TestASpentRunIsFoundUntilItLapses(t *testing.T) {
	s := startService(t, gateway.Config{Policy: enforce127}, false)
	exp := time.Now().Add(4 * time.Second)
	short := "short.bearer-value.0001"
	s.v.allow(short, "rk-0001", exp)
	s.secrets = append(s.secrets, short)
	r := s.openSession(t, short, server.LinkRunRequest{})
	if status, b := r.post(t, short, exited(r.a.RunID)); status != http.StatusAccepted {
		t.Fatalf("the run.exited: %d %s", status, b)
	}
	eventually(t, "the run let go of", func() bool {
		runs, spent := gateway.Held(s.g)
		return runs == 0 && spent == 1
	})
	for name, g := range ofRun(t, s, goodBearer, r.a.RunID, []string{r.a.RunID}) {
		if g.status != http.StatusGone || refusalOf(g.body)["from"] != "gateway" {
			t.Errorf("%s of the spent run: %d %s", name, g.status, g.body)
		}
	}
	refusedAll(t, "the spent run with a value of another key", ofRun(t, s, otherBearer, r.a.RunID, []string{r.a.RunID}))
	if time.Now().After(exp) {
		t.Fatal("the spent run lapsed before it was asked of")
	}
	time.Sleep(time.Until(exp) + 100*time.Millisecond)
	refusedAll(t, "the lapsed run", ofRun(t, s, goodBearer, r.a.RunID, []string{r.a.RunID}))
}

// TestARestartedGatewayKnowsNoRunOfBefore pins a restart on the same directory: a
// reload or a batch of a run from before, with its bearer value, gets the 401, and a
// new run opens.
func TestARestartedGatewayKnowsNoRunOfBefore(t *testing.T) {
	dir := t.TempDir()
	cred := goodBearer
	before := startService(t, gateway.Config{Dir: dir}, false)
	r := before.openSession(t, cred, server.LinkRunRequest{})
	before.close()
	s := startService(t, gateway.Config{Dir: dir}, false)
	s.secrets = append(s.secrets, cred, r.a.ProxySecret)
	refusedAll(t, "a run from before", ofRun(t, s, cred, r.a.RunID, []string{r.a.RunID}))
	s.openSession(t, cred, server.LinkRunRequest{})
}
