package gateway_test

import (
	"bytes"
	"context"
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

// TestTheRunAnswerGivesARunSecret pins the run answer's run_secret on both links: of
// the schema's form, 43 characters from 32 random bytes, other than the run's proxy
// secret and other than every other run's; the reload answer, whose schema refuses the
// member, never holds it.
func TestTheRunAnswerGivesARunSecret(t *testing.T) {
	h := start(t, gateway.Config{})
	s := startVerifying(t, gateway.Config{}, nil, 0)
	cred := credentialFor("rk-0001")
	a, b := h.open(server.LinkRunRequest{}), h.open(server.LinkRunRequest{})
	c, _ := s.openWith(t, cred, server.LinkRunRequest{})
	d, _ := s.openWith(t, cred, server.LinkRunRequest{})
	seen := map[string]bool{}
	for _, ans := range []*server.LinkRunAnswer{a, b, c, d} {
		if !runSecretShape.MatchString(ans.RunSecret) || len(ans.RunSecret) != 43 || ans.RunSecret == ans.ProxySecret || seen[ans.RunSecret] {
			t.Errorf("run %s: a run secret of %d characters, its proxy secret's or another run's", ans.RunID, len(ans.RunSecret))
		}
		seen[ans.RunSecret] = true
	}
	if _, err := h.linkOf(a.RunID).Reload(context.Background(), server.LocalOrigin+"/v1/run-configuration", a.RunID); err != nil {
		t.Errorf("the reload on the local link: %v", err)
	}
	r := &sessionRun{s: s, credential: cred, a: c}
	if status, body := r.reload(t, cred, c.RunID); status != http.StatusOK || bytes.Contains(body, []byte("run_secret")) || bytes.Contains(body, []byte(c.RunSecret)) {
		t.Errorf("the reload on the one address: %d", status)
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
// no run, the run's own twice, or for a reload another run's, is a 400
// invalid_request that ends no run; the run goes on, and its own secret reaches it.
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

// remoteRequest sends a reload or a batch on the one address with the run credential,
// none when empty, and the run secret header given, none for nil, and returns the
// status, the WWW-Authenticate and the body.
func remoteRequest(t *testing.T, s *service, credential, method, path, body string, secret []string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(method, s.url(path), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", server.ContentType)
	}
	req.Header[server.HeaderRunSecret] = secret
	if secret == nil {
		// Set, so the client adds none of its own.
		req.Header[server.HeaderRunSecret] = []string{}
	}
	resp, err := s.client(credential).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate"), string(b)
}

// TestTheOneAddressTakesARequestOfARunWithItsRunSecretAlone pins the run secret on the
// one address, follow-up 10: a reload or a batch without the run's secret, with an
// empty one, one of no run, the run's own twice, or the run's own with another run
// key's run credential or none, and a reload with a sibling run's of the same run key,
// gets the same 401
// run_credential_refused, body and header alike, so no run can be probed; neither the
// run nor its sibling is ended, and each goes on with its own secret.
func TestTheOneAddressTakesARequestOfARunWithItsRunSecretAlone(t *testing.T) {
	s := startVerifying(t, gateway.Config{}, nil, 0)
	cred, otherKey := credentialFor("rk-0001"), credentialFor("rk-0002")
	a := s.openSession(t, cred, server.LinkRunRequest{})
	sibling := s.openSession(t, cred, server.LinkRunRequest{})
	s.openSession(t, otherKey, server.LinkRunRequest{})
	beat := string(mustJSON(t, []map[string]any{heartbeat(a.a.RunID)}))
	type try struct {
		credential string
		secret     []string
	}
	cases := map[string]try{
		"another run key's run credential":     {otherKey, []string{a.a.RunSecret}},
		"no run credential and the run secret": {"", []string{a.a.RunSecret}},
	}
	for name, secret := range secretHeaders(a.a.RunSecret) {
		cases[name] = try{cred, secret}
	}
	var first string
	for name, c := range cases {
		for _, req := range []struct{ method, path, body string }{
			{http.MethodGet, "/v1/run-configuration/" + a.a.RunID, ""},
			{http.MethodPost, "/v1/events", beat},
		} {
			status, auth, body := remoteRequest(t, s, c.credential, req.method, req.path, req.body, c.secret)
			got := fmt.Sprintf("%d %s %s", status, auth, body)
			if first == "" {
				first = got
			}
			if status != http.StatusUnauthorized || refusalOf([]byte(body))["error"] != "run_credential_refused" || got != first {
				t.Errorf("%s %s with %s: %s, want %s", req.method, req.path, name, got, first)
			}
		}
	}
	// A reload of the run's path with its sibling's secret, of the same run key, is
	// refused the same; a batch with the sibling's secret is the sibling's,
	// TestABatchTheLinkRefusesEndsTheRunOfItsSecret.
	if status, auth, body := remoteRequest(t, s, cred, http.MethodGet, "/v1/run-configuration/"+a.a.RunID, "", []string{sibling.a.RunSecret}); fmt.Sprintf("%d %s %s", status, auth, body) != first {
		t.Errorf("a reload with a sibling run's secret: %d %s", status, body)
	}
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

// TestABatchTheLinkRefusesEndsTheRunOfItsSecret pins D4 and the bad batches on both
// links: a batch the link refuses ends the run whose secret it carries, batch_refused,
// with the gateway's line, whatever run its events name: another run's events, a batch
// over the size limit, one that does not decode and an empty one among them. The run
// its events name goes on. A batch whose body never arrives whole ends no run.
func TestABatchTheLinkRefusesEndsTheRunOfItsSecret(t *testing.T) {
	h := start(t, gateway.Config{})
	s := startVerifying(t, gateway.Config{}, nil, 0)
	cred := credentialFor("rk-0001")
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
			line := fmt.Sprintf("run %s: the gateway refused a batch of its session's, %s; the run ends, session_lost", a.RunID, c.why)
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
			if status, _, got := remoteRequest(t, s, cred, http.MethodPost, "/v1/events", c.body(b.a.RunID), []string{a.a.RunSecret}); status != http.StatusBadRequest || refusalOf([]byte(got))["error"] != "invalid_request" {
				t.Errorf("the batch: %d %s", status, got)
			}
			line := fmt.Sprintf("run %s: the gateway refused a batch of its session's, %s; the run ends, session_lost", a.a.RunID, c.why)
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
