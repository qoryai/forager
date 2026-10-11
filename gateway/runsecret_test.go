package gateway_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// runSecretShape is a run secret's form, link-run-answer.schema.json's run_secret.
var runSecretShape = regexp.MustCompile(`^[A-Za-z0-9_-]{22,256}$`)

// anotherSecret is a run secret of the right form that no run has.
const anotherSecret = "no-runs-secret-0123456789abcdefghijklmnopq"

// secretHeaders are the ways a request can carry a run secret that is not its run's:
// none, an empty one, one of the right form no run has, and the run's own twice.
func secretHeaders(own string) map[string][]string {
	return map[string][]string{
		"no run secret":          nil,
		"an empty run secret":    {""},
		"a run secret of no run": {anotherSecret},
		"the run secret twice":   {own, own},
	}
}

// TestTheRunAnswerGivesARunSecret pins the run answer's run_secret on the local link:
// of the schema's form, 43 characters from 32 random bytes, other than the run's proxy
// secret and other than every other run's; the reload answer, whose schema refuses the
// member, never holds it.
func TestTheRunAnswerGivesARunSecret(t *testing.T) {
	h := start(t, gateway.Config{})
	a, b := h.open(server.LinkRunRequest{}), h.open(server.LinkRunRequest{})
	seen := map[string]bool{}
	for _, ans := range []*server.LinkRunAnswer{a, b} {
		if !runSecretShape.MatchString(ans.RunSecret) || len(ans.RunSecret) != 43 || ans.RunSecret == ans.ProxySecret || seen[ans.RunSecret] {
			t.Errorf("run %s: a run secret of %d characters, its proxy secret's or another run's", ans.RunID, len(ans.RunSecret))
		}
		seen[ans.RunSecret] = true
	}
	req, _ := http.NewRequest(http.MethodGet, server.LocalOrigin+"/v1/run-configuration/"+a.RunID, nil)
	req.Header.Set(server.HeaderRunSecret, a.RunSecret)
	resp, err := raw(t, h.g.LocalLink()).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || bytes.Contains(body, []byte("run_secret")) || bytes.Contains(body, []byte(a.RunSecret)) {
		t.Errorf("the reload: %d", resp.StatusCode)
	}
}

// localRequest sends a reload or a batch of the run on the local link with the run
// secret header given, none for nil, and returns the status and the body.
func localRequest(t *testing.T, h *harness, method, path, body string, secret []string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, server.LocalOrigin+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", server.ContentType)
	}
	if secret != nil {
		req.Header[server.HeaderRunSecret] = secret
	}
	resp, err := raw(t, h.g.LocalLink()).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, refusalOf(b)
}

// TestTheLocalLinkTakesARequestOfARunWithItsRunSecretAlone pins the run secret on the
// local link: a reload or a batch without the run's secret, with an empty one, one of
// no run, the run's own twice, or for a reload another run's, or the run's own with no
// run id in the path, is a 400 invalid_request that ends no run; the run goes on, and its own secret reaches it.
func TestTheLocalLinkTakesARequestOfARunWithItsRunSecretAlone(t *testing.T) {
	h := start(t, gateway.Config{})
	a := h.open(server.LinkRunRequest{})
	other := h.open(server.LinkRunRequest{})
	if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	beat := string(mustJSON(t, []map[string]any{heartbeat(a.RunID)}))
	cases := secretHeaders(a.RunSecret)
	for name, secret := range cases {
		if status, r := localRequest(t, h, http.MethodGet, "/v1/run-configuration/"+a.RunID, "", secret); status != http.StatusBadRequest || r["error"] != "invalid_request" {
			t.Errorf("a reload with %s: %d %v", name, status, r)
		}
		if status, r := localRequest(t, h, http.MethodPost, "/v1/events", beat, secret); status != http.StatusBadRequest || r["error"] != "invalid_request" {
			t.Errorf("a batch with %s: %d %v", name, status, r)
		}
	}
	if status, r := localRequest(t, h, http.MethodGet, "/v1/run-configuration/"+a.RunID, "", []string{other.RunSecret}); status != http.StatusBadRequest || r["error"] != "invalid_request" {
		t.Errorf("a reload with another run's secret: %d %v", status, r)
	}
	if status, r := localRequest(t, h, http.MethodGet, "/v1/run-configuration/", "", []string{a.RunSecret}); status != http.StatusBadRequest || r["error"] != "invalid_request" {
		t.Errorf("a reload of no run id with the run's secret: %d %v", status, r)
	}
	if status, _ := localRequest(t, h, http.MethodGet, "/v1/run-configuration/"+a.RunID, "", []string{a.RunSecret}); status != http.StatusOK {
		t.Errorf("a reload with the run's secret: %d", status)
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

// TestABatchTheLinkRefusesEndsTheRunOfItsSecret pins D4 and the bad batches on the local
// link: a batch the link refuses ends the run whose secret it carries, batch_refused,
// with the gateway's line, whatever run its events name: another run's events, a batch
// over the size limit, one that does not decode and an empty one among them. The run
// its events name goes on. A batch whose body never arrives whole ends no run.
func TestABatchTheLinkRefusesEndsTheRunOfItsSecret(t *testing.T) {
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
			if status, r := localRequest(t, h, http.MethodPost, "/v1/events", c.body(b.RunID), []string{a.RunSecret}); status != http.StatusBadRequest || r["error"] != "invalid_request" {
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
		l := h.g.LocalLink()
		c, err := net.Dial("unix", l.Socket)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		link.WriteLinkPreamble(c, l.Secret)
		io.WriteString(c, "POST /v1/events HTTP/1.1\r\nHost: localhost\r\nContent-Type: "+server.ContentType+"\r\n"+server.HeaderRunSecret+": "+a.RunSecret+"\r\nContent-Length: 1000\r\n\r\n[{")
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
