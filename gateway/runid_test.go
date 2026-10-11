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

// TestABatchTheLinkRefusesEndsTheRunItNames pins D4 and the bad batches on the local link:
// a batch the link refuses ends the run its X-Qory-Run-Id names, batch_refused, with
// the gateway's line, whatever run its events name: another run's events, whose
// subject is not the run's, a batch over the size limit, one that does not decode and
// an empty one among them. The run its events name goes on. A batch whose body never
// arrives whole ends no run.
func TestABatchTheLinkRefusesEndsTheRunItNames(t *testing.T) {
	h := start(t, gateway.Config{})
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
