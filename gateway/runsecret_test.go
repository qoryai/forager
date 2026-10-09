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
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/runcredential"
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
// or with the run's own and no run id in the path, gets the same 401
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

// answered is a request's status and body.
type answered struct {
	status int
	body   []byte
}

// ofRun sends a reload and a batch of the run on the one address with the run
// credential and the run secret header given, none for nil, and returns each one's
// status and body, by name.
func ofRun(t *testing.T, s *service, credential, runID string, secret []string) map[string]answered {
	t.Helper()
	out := map[string]answered{}
	beat := string(mustJSON(t, []map[string]any{heartbeat(runID)}))
	status, _, body := remoteRequest(t, s, credential, http.MethodGet, "/v1/run-configuration/"+runID, "", secret)
	out["a reload"] = answered{status, []byte(body)}
	status, _, body = remoteRequest(t, s, credential, http.MethodPost, "/v1/events", beat, secret)
	out["a batch"] = answered{status, []byte(body)}
	return out
}

// refusedAll checks that each of a reload and a batch got the 401
// run_credential_refused.
func refusedAll(t *testing.T, what string, got map[string]answered) {
	t.Helper()
	for name, g := range got {
		if g.status != http.StatusUnauthorized || refusalOf(g.body)["error"] != "run_credential_refused" {
			t.Errorf("%s, %s: %d %s", what, name, g.status, g.body)
		}
	}
}

// TestAnExpiredRunCredentialFindsItsEndedRunByItsRunSecret pins a run credential whose
// exp has passed, under an issuer with no leeway, against the run secret: with the
// secret of its run that has ended, a reload and a batch get that end's 410,
// credential_expired; with no secret, one of no run, or a live run's of its run key,
// and of the live run with its own, they get the 401.
func TestAnExpiredRunCredentialFindsItsEndedRunByItsRunSecret(t *testing.T) {
	issuers := realIssuers(t, false)
	none := runcredential.Duration(0)
	issuers[0].Leeway = &none
	s := startVerifying(t, gateway.Config{RunCredentials: issuers, Policy: enforce127}, nil, 0)
	short := mint(issuerKey(), "rk-0001", time.Now().Add(1500*time.Millisecond), nil)
	ended := s.openSession(t, short, server.LinkRunRequest{})
	laterExp := time.Now().Add(1500 * time.Millisecond)
	later := mint(issuerKey(), "rk-0001", laterExp, nil)
	live := s.openSession(t, later, server.LinkRunRequest{})
	long := mint(issuerKey(), "rk-0001", time.Now().Add(time.Hour), nil)
	s.secrets = append(s.secrets, long)
	if status, body := live.post(t, long, heartbeat(live.a.RunID)); status != http.StatusAccepted {
		t.Fatalf("a refreshed run credential of the live run: %d %s", status, body)
	}
	eventually(t, "credential_expired", func() bool {
		rec := s.record(ended.a.RunID)
		return rec[len(rec)-1].Type == event.RunExited
	})
	time.Sleep(time.Until(laterExp.Add(time.Second)))
	for name, g := range ofRun(t, s, short, ended.a.RunID, []string{ended.a.RunSecret}) {
		gone(t, name+" with the run's secret", g.status, g.body, "credential_expired")
	}
	for name, secret := range map[string][]string{
		"no run secret":          nil,
		"a run secret of no run": {anotherSecret},
		"the live run's secret":  {live.a.RunSecret},
	} {
		refusedAll(t, "the ended run with "+name, ofRun(t, s, short, ended.a.RunID, secret))
	}
	refusedAll(t, "the live run with its own secret", ofRun(t, s, later, live.a.RunID, []string{live.a.RunSecret}))
	if status, body := live.reload(t, long, live.a.RunID); status != http.StatusOK {
		t.Errorf("the live run after: %d %s", status, body)
	}
}

// TestASpentRunIsFoundByItsRunSecretUntilItLapses pins a run that ended and was let go
// of: with its run secret and a run credential of its run key, a reload and a batch get
// its 410 until what it left lapses, and the 401 after; with a wrong secret, the 401
// throughout. Once it lapses, the gateway knows its secret no more.
func TestASpentRunIsFoundByItsRunSecretUntilItLapses(t *testing.T) {
	cfg := gateway.Config{Policy: enforce127}
	gateway.SetKeepSpent(&cfg, time.Millisecond)
	s := startVerifying(t, cfg, nil, 0)
	exp := time.Unix(time.Now().Add(4*time.Second).Unix(), 0)
	short := mint(issuerKey(), "rk-0001", exp, nil)
	r := s.openSession(t, short, server.LinkRunRequest{})
	if status, b := r.post(t, short, exited(r.a.RunID)); status != http.StatusAccepted {
		t.Fatalf("the run.exited: %d %s", status, b)
	}
	eventually(t, "the run let go of", func() bool {
		runs, _, spent, _ := gateway.Held(s.g)
		return runs == 0 && spent == 1
	})
	if n := gateway.SecretsIndexed(s.g); n != 1 {
		t.Errorf("the spent run: %d run secrets known, want 1", n)
	}
	long := credentialFor("rk-0001")
	s.secrets = append(s.secrets, long)
	for name, g := range ofRun(t, s, long, r.a.RunID, []string{r.a.RunSecret}) {
		if g.status != http.StatusGone || refusalOf(g.body)["from"] != "gateway" {
			t.Errorf("%s of the spent run with its secret: %d %s", name, g.status, g.body)
		}
	}
	if time.Now().After(exp) {
		t.Fatal("the spent run lapsed before it was asked of")
	}
	for name, secret := range map[string][]string{"no run secret": nil, "a run secret of no run": {anotherSecret}} {
		refusedAll(t, "the spent run with "+name, ofRun(t, s, long, r.a.RunID, secret))
	}
	time.Sleep(time.Until(exp) + 100*time.Millisecond)
	refusedAll(t, "the lapsed run with its secret", ofRun(t, s, long, r.a.RunID, []string{r.a.RunSecret}))
	if n := gateway.SecretsIndexed(s.g); n != 0 {
		t.Errorf("the lapsed run: %d run secrets known, want 0", n)
	}
}

// TestAHeldRunKeysRunIsRefusedWithItsRunSecret pins the run secret against the hold
// after the issuer's end of a run of the run key: a reload or a batch of a live run of
// the key with a wrong secret gets the 401, and its run credential, presented, holds
// the key to its exp; with the run's own secret, the run ends, run_ended_at_issuer,
// and the request gets its 410.
func TestAHeldRunKeysRunIsRefusedWithItsRunSecret(t *testing.T) {
	in := &introspection{}
	var ahead atomic.Int64
	cfg := gateway.Config{Policy: enforce127}
	gateway.SetClock(&cfg, func() time.Time { return time.Now().Add(time.Duration(ahead.Load())) })
	s := startVerifying(t, cfg, in, 0)
	now := time.Now()
	first := mint(issuerKey(), "rk-0001", now.Add(time.Hour), nil)
	later := mint(issuerKey(), "rk-0001", now.Add(3*time.Hour), nil)
	probe := mint(issuerKey(), "rk-0001", now.Add(2*time.Hour+30*time.Minute), nil)
	s.secrets = append(s.secrets, first, later, probe)
	ended := s.openSession(t, first, server.LinkRunRequest{})
	held := s.openSession(t, first, server.LinkRunRequest{})
	in.end(first)
	status, body := ended.reload(t, first, ended.a.RunID)
	gone(t, "the issuer's end", status, body, "run_ended_at_issuer")
	for name, secret := range secretHeaders(held.a.RunSecret) {
		refusedAll(t, "the held run key's live run with "+name, ofRun(t, s, later, held.a.RunID, secret))
	}
	// Past first's exp and its leeway, later's exp, presented with the wrong secrets,
	// still holds the run key; the probe's own exp is earlier, so it extends nothing.
	ahead.Store(int64(2*time.Hour + 10*time.Minute))
	if status, body := s.tryOpenWith(t, probe, server.LinkRunRequest{}); status != http.StatusUnauthorized {
		t.Errorf("a run request of the held run key: %d %s", status, body)
	}
	for name, g := range ofRun(t, s, later, held.a.RunID, []string{held.a.RunSecret}) {
		gone(t, name+" of the live run with its secret", g.status, g.body, "run_ended_at_issuer")
	}
	ahead.Store(int64(3*time.Hour + 10*time.Minute))
	if status, body := s.tryOpenWith(t, probe, server.LinkRunRequest{}); status != http.StatusOK {
		t.Errorf("past the latest exp held: %d %s", status, body)
	}
}

// TestARestartedGatewayKnowsNoRunSecretOfBefore pins a restart on the same directory:
// the gateway keeps no run secret, so a reload or a batch of a run from before, with
// its run credential and its run secret, gets the 401, and a new run opens.
func TestARestartedGatewayKnowsNoRunSecretOfBefore(t *testing.T) {
	dir := t.TempDir()
	cred := credentialFor("rk-0001")
	before := startVerifying(t, gateway.Config{Dir: dir}, nil, 0)
	r := before.openSession(t, cred, server.LinkRunRequest{})
	before.close()
	s := startVerifying(t, gateway.Config{Dir: dir}, nil, 0)
	s.secrets = append(s.secrets, cred, r.a.RunSecret, r.a.ProxySecret)
	refusedAll(t, "a run from before with its secret", ofRun(t, s, cred, r.a.RunID, []string{r.a.RunSecret}))
	if n := gateway.SecretsIndexed(s.g); n != 0 {
		t.Errorf("after the restart: %d run secrets known", n)
	}
	s.openSession(t, cred, server.LinkRunRequest{})
}
