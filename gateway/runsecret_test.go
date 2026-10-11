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
	s := startService(t, gateway.Config{}, false)
	cred := goodBearer
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
	r := &sessionRun{s: s, value: cred, a: c}
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

// remoteRequest sends a reload or a batch on the one address with the bearer value,
// none when empty, and the run secret header given, none for nil, and returns the
// status, the WWW-Authenticate and the body.
func remoteRequest(t *testing.T, s *service, value, method, path, body string, secret []string) (int, string, string) {
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
	resp, err := s.client(value).Do(req)
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
// key's bearer value or none, and a reload with a sibling run's of the same key, or
// with the run's own and no run id in the path, gets the same 401 unauthorized, body
// and header alike, so no run can be probed; neither the
// run nor its sibling is ended, and each goes on with its own secret.
func TestTheOneAddressTakesARequestOfARunWithItsRunSecretAlone(t *testing.T) {
	s := startService(t, gateway.Config{}, false)
	cred, otherKey := goodBearer, otherBearer
	a := s.openSession(t, cred, server.LinkRunRequest{})
	sibling := s.openSession(t, cred, server.LinkRunRequest{})
	s.openSession(t, otherKey, server.LinkRunRequest{})
	beat := string(mustJSON(t, []map[string]any{heartbeat(a.a.RunID)}))
	type try struct {
		value  string
		secret []string
	}
	cases := map[string]try{
		"another key's bearer value":         {otherKey, []string{a.a.RunSecret}},
		"no bearer value and the run secret": {"", []string{a.a.RunSecret}},
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
			status, auth, body := remoteRequest(t, s, c.value, req.method, req.path, req.body, c.secret)
			got := fmt.Sprintf("%d %s %s", status, auth, body)
			if first == "" {
				first = got
			}
			if status != http.StatusUnauthorized || refusalOf([]byte(body))["error"] != "unauthorized" || got != first {
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
	if status, auth, body := remoteRequest(t, s, cred, http.MethodGet, "/v1/run-configuration/", "", []string{a.a.RunSecret}); fmt.Sprintf("%d %s %s", status, auth, body) != first {
		t.Errorf("a reload of no run id with the run's secret: %d %s", status, body)
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
		t.Run("one address "+c.name, func(t *testing.T) {
			a := s.openSession(t, cred, server.LinkRunRequest{})
			b := s.openSession(t, cred, server.LinkRunRequest{})
			if status, _, got := remoteRequest(t, s, cred, http.MethodPost, "/v1/events", c.body(b.a.RunID), []string{a.a.RunSecret}); status != http.StatusBadRequest || refusalOf([]byte(got))["error"] != "invalid_request" {
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

// answered is a request's status and body.
type answered struct {
	status int
	body   []byte
}

// ofRun sends a reload and a batch of the run on the one address with the bearer value
// and the run secret header given, none for nil, and returns each one's
// status and body, by name.
func ofRun(t *testing.T, s *service, value, runID string, secret []string) map[string]answered {
	t.Helper()
	out := map[string]answered{}
	beat := string(mustJSON(t, []map[string]any{heartbeat(runID)}))
	status, _, body := remoteRequest(t, s, value, http.MethodGet, "/v1/run-configuration/"+runID, "", secret)
	out["a reload"] = answered{status, []byte(body)}
	status, _, body = remoteRequest(t, s, value, http.MethodPost, "/v1/events", beat, secret)
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

// TestASpentRunIsFoundByItsRunSecretUntilItLapses pins a run that ended and was let go
// of: with its run secret and a bearer value of its key, a reload and a batch get its
// 410 until the identity it was opened with expires, and the 401 after; with a wrong
// secret, or a value of another key, the 401 throughout. Once it lapses, the gateway
// knows its secret no more.
func TestASpentRunIsFoundByItsRunSecretUntilItLapses(t *testing.T) {
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
	if n := gateway.SecretsIndexed(s.g); n != 1 {
		t.Errorf("the spent run: %d run secrets known, want 1", n)
	}
	for name, g := range ofRun(t, s, goodBearer, r.a.RunID, []string{r.a.RunSecret}) {
		if g.status != http.StatusGone || refusalOf(g.body)["from"] != "gateway" {
			t.Errorf("%s of the spent run with its secret: %d %s", name, g.status, g.body)
		}
	}
	refusedAll(t, "the spent run with a value of another key", ofRun(t, s, otherBearer, r.a.RunID, []string{r.a.RunSecret}))
	if time.Now().After(exp) {
		t.Fatal("the spent run lapsed before it was asked of")
	}
	for name, secret := range map[string][]string{"no run secret": nil, "a run secret of no run": {anotherSecret}} {
		refusedAll(t, "the spent run with "+name, ofRun(t, s, goodBearer, r.a.RunID, secret))
	}
	time.Sleep(time.Until(exp) + 100*time.Millisecond)
	refusedAll(t, "the lapsed run with its secret", ofRun(t, s, goodBearer, r.a.RunID, []string{r.a.RunSecret}))
	if n := gateway.SecretsIndexed(s.g); n != 0 {
		t.Errorf("the lapsed run: %d run secrets known, want 0", n)
	}
}

// TestARestartedGatewayKnowsNoRunSecretOfBefore pins a restart on the same directory:
// the gateway keeps no run secret, so a reload or a batch of a run from before, with
// its bearer value and its run secret, gets the 401, and a new run opens.
func TestARestartedGatewayKnowsNoRunSecretOfBefore(t *testing.T) {
	dir := t.TempDir()
	cred := goodBearer
	before := startService(t, gateway.Config{Dir: dir}, false)
	r := before.openSession(t, cred, server.LinkRunRequest{})
	before.close()
	s := startService(t, gateway.Config{Dir: dir}, false)
	s.secrets = append(s.secrets, cred, r.a.RunSecret, r.a.ProxySecret)
	refusedAll(t, "a run from before with its secret", ofRun(t, s, cred, r.a.RunID, []string{r.a.RunSecret}))
	if n := gateway.SecretsIndexed(s.g); n != 0 {
		t.Errorf("after the restart: %d run secrets known", n)
	}
	s.openSession(t, cred, server.LinkRunRequest{})
}
