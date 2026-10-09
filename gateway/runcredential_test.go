package gateway_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/runcredential"
	"github.com/qoryai/forager/server"
)

// The run credentials of these tests are signed with an Ed25519 key made for this run
// of the tests, which the issuer pins: no published fixture key, so the gateway's
// verifier accepts it as it accepts an issuer's own.
var issuerKey = sync.OnceValue(func() ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
})

// otherKey signs run credentials no issuer pins.
var otherKey = sync.OnceValue(func() ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
})

// The neutral example issuer of these tests.
const (
	exampleIssuer   = "https://issuer.example"
	exampleAudience = "qory-gateway"
)

// exampleLabels are the labels the example issuer's mapping makes of a run key.
func exampleLabels(runKey string) map[string]string {
	return map[string]string{"forge": "example-forge", "repository": "example-namespace/project", "run_key": runKey}
}

// realIssuers are the example issuer, its key's file written into a directory of the
// test's, as the operator's forager.yaml names it: the scope by namespace, the labels
// from namespace and project, the detail requester; with introspection when asked.
func realIssuers(t *testing.T, introspection bool) runcredential.Issuers {
	t.Helper()
	dir := t.TempDir()
	der, err := x509.MarshalPKIXPublicKey(issuerKey().Public())
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "issuer-k1.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	i := runcredential.Issuer{
		Issuer: exampleIssuer, Audience: exampleAudience, Algorithms: []string{runcredential.EdDSA},
		Keys:  []runcredential.Key{{KID: "k1", Alg: runcredential.EdDSA, PublicKeyFile: keyFile}},
		Allow: &runcredential.Allow{Claim: "namespace", Values: []string{"example-namespace"}},
		LabelMapping: runcredential.LabelMapping{
			Forge:      runcredential.Source{Value: "example-forge"},
			Repository: runcredential.Source{Claims: []string{"namespace", "project"}, Join: "/"},
			RunKey:     runcredential.Claim{Claim: "sub"},
		},
		DetailMapping: map[string]runcredential.Claim{"requester": {Claim: "requester"}},
	}
	if introspection {
		secret := filepath.Join(dir, "introspection-secret")
		if err := os.WriteFile(secret, []byte("example-client-secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		i.Introspection = &runcredential.Introspection{URL: exampleIssuer + "/introspect", ClientID: "example-gateway", ClientSecretFile: secret}
	}
	return runcredential.Issuers{i}
}

// mint is a run credential of the example issuer for the run key, expiring at exp,
// signed by key, with changes made to its claims: a nil value removes a claim.
func mint(key ed25519.PrivateKey, runKey string, exp time.Time, changes map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": "k1", "typ": "JWT"})
	claims := map[string]any{
		"iss": exampleIssuer, "aud": exampleAudience, "sub": runKey, "iat": time.Now().Unix() - 1, "exp": exp.Unix(),
		"namespace": "example-namespace", "project": "project", "requester": "example-requester",
	}
	for k, v := range changes {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(input)))
}

// credentialFor is a good run credential of the run key, for an hour.
func credentialFor(runKey string) string {
	return mint(issuerKey(), runKey, time.Now().Add(time.Hour), nil)
}

// introspection is the issuer's introspection endpoint of a test: a run credential is
// active until the test says otherwise, and every one asked about is counted.
type introspection struct {
	mu       sync.Mutex
	inactive map[string]bool
	asked    map[string]int
}

func (in *introspection) active(_, credential string) bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.asked[credential]++
	return !in.inactive[credential]
}

func (in *introspection) end(credential string) {
	in.mu.Lock()
	in.inactive[credential] = true
	in.mu.Unlock()
}

func (in *introspection) count(credential string) int {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.asked[credential]
}

// startVerifying starts a gateway on 127.0.0.1 over TLS whose run credentials the
// gateway verifies itself, under the example issuer: no seam of the tests decides
// them. With in, the issuer has introspection, answered by in, every answer kept for
// cache.
func startVerifying(t *testing.T, cfg gateway.Config, in *introspection, cache time.Duration) *service {
	t.Helper()
	s := &service{}
	cfg.Listen = "127.0.0.1:0"
	cfg.RunCredentials = realIssuers(t, in != nil)
	if in != nil {
		in.inactive, in.asked = map[string]bool{}, map[string]int{}
		gateway.SetIntrospector(&cfg, in.active, cache)
	}
	certFile, keyFile, pool := testCertificate(t, t.TempDir())
	cfg.TLS = &gateway.TLS{CertFile: certFile, KeyFile: keyFile}
	s.pool = pool
	s.harness = start(t, cfg)
	return s
}

// tryOpenWith sends a run request on the one address with the run credential, and
// returns the status and the answer's body.
func (s *service) tryOpenWith(t *testing.T, credential string, req server.LinkRunRequest) (int, []byte) {
	t.Helper()
	req.Version = 1
	if req.RunID == "" {
		req.RunID = event.NewRunID()
	}
	body, _ := json.Marshal(req)
	resp, b := do(t, s.client(credential), http.MethodPost, s.url("/v1/run-configuration"), server.LinkContentType, string(body))
	return resp.StatusCode, b
}

// refusal decodes a refusal's body.
func refusalOf(b []byte) map[string]any {
	var r map[string]any
	json.Unmarshal(b, &r)
	return r
}

// session is a session's run on the one address, opened with its run credential.
type sessionRun struct {
	s          *service
	credential string
	a          *server.LinkRunAnswer
}

// openSession opens a session's run of the run key and starts it: its run.started,
// with the run credential's labels and details, and its policy_applied.
func (s *service) openSession(t *testing.T, credential string, req server.LinkRunRequest) *sessionRun {
	t.Helper()
	s.mu.Lock()
	s.secrets = append(s.secrets, credential)
	s.mu.Unlock()
	a, _ := s.openWith(t, credential, req)
	r := &sessionRun{s: s, credential: credential, a: a}
	st := started(a.RunID, a.Labels)
	st["data"].(map[string]any)["about"] = map[string]any{"title": "Fix the failing build", "details": map[string]any{"requester": "example-requester"}}
	s.postWith(t, credential, st, applied(a.RunID, a.Applied))
	return r
}

// post posts one batch of the run's events with the run credential given, and
// returns the status and the body.
func (r *sessionRun) post(t *testing.T, credential string, evs ...map[string]any) (int, []byte) {
	t.Helper()
	body, _ := json.Marshal(evs)
	resp, b := do(t, r.s.client(credential), http.MethodPost, r.s.url("/v1/events"), server.ContentType, string(body))
	return resp.StatusCode, b
}

// reload asks for the run's configuration with the run credential given.
func (r *sessionRun) reload(t *testing.T, credential, runID string) (int, []byte) {
	t.Helper()
	resp, b := do(t, r.s.client(credential), http.MethodGet, r.s.url("/v1/run-configuration/"+runID), "", "")
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
		if l.Type == event.Ping {
			name = "events/ping.schema.json"
		}
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

// TestASessionsRunOnARunCredential pins a session's run on the one address end to end,
// its run credential verified by the gateway: the run's labels and details are the
// run credential's, whatever the session leaves out; the server is asked for the run
// configuration by them; a batch and a reload with the run credential are answered;
// and neither the record, the server, nor a report holds the run credential.
func TestASessionsRunOnARunCredential(t *testing.T) {
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`, 'a')
	s := startVerifying(t, gateway.Config{Server: c.server()}, nil, 0)
	cred := credentialFor("rk-0001")
	r := s.openSession(t, cred, server.LinkRunRequest{})
	if !sameMap(r.a.Labels, exampleLabels("rk-0001")) || string(r.a.Details) != `{"requester":"example-requester"}` {
		t.Errorf("the answer's labels %v and details %s", r.a.Labels, r.a.Details)
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
	if !sameMap(asked, exampleLabels("rk-0001")) {
		t.Errorf("the server was asked by %v", asked)
	}
	if status, b := r.reload(t, cred, r.a.RunID); status != http.StatusOK {
		t.Errorf("the reload: %d %s", status, b)
	}
	if status, b := r.post(t, cred, exited(r.a.RunID)); status != http.StatusAccepted {
		t.Errorf("the run.exited: %d %s", status, b)
	}
	// A run.started whose about.details differ from the run credential's is refused,
	// and its run ends.
	other := credentialFor("rk-0002")
	s.secrets = append(s.secrets, other)
	b, _ := s.openWith(t, other, server.LinkRunRequest{})
	if status, body := (&sessionRun{s: s}).post(t, other, started(b.RunID, b.Labels)); status != http.StatusBadRequest {
		t.Errorf("a run.started without the run credential's details: %d %s", status, body)
	}
	s.close()
	rec := s.record(r.a.RunID)
	if got := types(rec); !slices.Equal(got, []string{event.Ping, event.RunStarted, event.PolicyApplied, event.RunExited}) {
		t.Errorf("record %v", got)
	}
	validEvents(t, rec)
	noSecretIn(t, s.dir, cred)
	if b, _ := os.ReadFile(c.received); bytes.Contains(b, []byte(cred)) || !bytes.Contains(b, []byte(`"run_key":"rk-0001"`)) {
		t.Error("what the server received holds the run credential, or not the run's labels")
	}
}

// maps reports whether two maps of labels are equal.
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

// TestARunRequestDifferentFromItsRunCredential pins the run credential deciding the
// run: a forge or repository of the session's that differs is
// target_differs_from_credential, another label or detail the mapping sets is
// differs_from_credential, each named with the run credential's value; a label the
// mapping does not set is ignored; a refused run opens nothing, so its run key opens
// a run afterwards; and a run credential the verifier refuses is 401.
func TestARunRequestDifferentFromItsRunCredential(t *testing.T) {
	s := startVerifying(t, gateway.Config{}, nil, 0)
	cred := credentialFor("rk-0001")
	s.secrets = append(s.secrets, cred)
	for name, c := range map[string]struct {
		req   server.LinkRunRequest
		code  string
		names []string
	}{
		"another repository": {server.LinkRunRequest{Labels: map[string]string{"repository": "other/project"}}, "target_differs_from_credential", []string{"labels.repository=example-namespace/project"}},
		"another forge":      {server.LinkRunRequest{Labels: map[string]string{"forge": "other-forge", "run_key": "rk-0009"}}, "target_differs_from_credential", []string{"labels.forge=example-forge"}},
		"another run key":    {server.LinkRunRequest{Labels: map[string]string{"run_key": "rk-0009"}}, "differs_from_credential", []string{"labels.run_key=rk-0001"}},
		"another requester":  {server.LinkRunRequest{About: &server.About{Details: json.RawMessage(`{"requester":"someone-else"}`)}}, "differs_from_credential", []string{"about.details.requester=example-requester"}},
	} {
		status, b := s.tryOpenWith(t, cred, c.req)
		r := refusalOf(b)
		names, _ := json.Marshal(r["names"])
		want, _ := json.Marshal(c.names)
		if status != http.StatusForbidden || r["error"] != c.code || r["from"] != "gateway" || string(names) != string(want) {
			t.Errorf("%s: %d %s", name, status, b)
		}
	}
	// A label the mapping does not set is the session's to send, and ignored.
	a, _ := s.openWith(t, cred, server.LinkRunRequest{Labels: map[string]string{"forge": "example-forge", "queue": "nightly"}})
	if !sameMap(a.Labels, exampleLabels("rk-0001")) {
		t.Errorf("labels %v", a.Labels)
	}
	for name, bad := range map[string]string{
		"another issuer's key": mint(otherKey(), "rk-0002", time.Now().Add(time.Hour), nil),
		"expired":              mint(issuerKey(), "rk-0002", time.Now().Add(-time.Hour), nil),
		"another audience":     mint(issuerKey(), "rk-0002", time.Now().Add(time.Hour), map[string]any{"aud": "another-service"}),
		"out of scope":         mint(issuerKey(), "rk-0002", time.Now().Add(time.Hour), map[string]any{"namespace": "other-namespace"}),
		"no run key":           mint(issuerKey(), "rk-0002", time.Now().Add(time.Hour), map[string]any{"sub": nil}),
	} {
		s.secrets = append(s.secrets, bad)
		status, b := s.tryOpenWith(t, bad, server.LinkRunRequest{})
		if r := refusalOf(b); status != http.StatusUnauthorized || r["error"] != "run_credential_refused" || r["names"] != nil {
			t.Errorf("%s: %d %s", name, status, b)
		}
	}
}

// TestARunKeyOpensOneRun pins a run key's one run at a gateway: a second run request
// of a live run's run key is 401, and so is one after its run ended, and after the
// gateway restarts on the same directory; a run_id another run has is 409 for a fresh
// run key; and a fresh run key opens its run after each.
func TestARunKeyOpensOneRun(t *testing.T) {
	dir := t.TempDir()
	s := startVerifying(t, gateway.Config{Dir: dir}, nil, 0)
	cred := credentialFor("rk-0001")
	r := s.openSession(t, cred, server.LinkRunRequest{})
	refused := func(what string, s *service, credential string, req server.LinkRunRequest) {
		t.Helper()
		status, b := s.tryOpenWith(t, credential, req)
		if r := refusalOf(b); status != http.StatusUnauthorized || r["error"] != "run_credential_refused" {
			t.Errorf("%s: %d %s", what, status, b)
		}
	}
	refused("the live run's run key", s, cred, server.LinkRunRequest{})
	// The same run_id and the same run credential, as a retry after a lost answer: the
	// run key has a run.
	refused("a retry", s, cred, server.LinkRunRequest{RunID: r.a.RunID})
	// A refreshed run credential of the same run key opens nothing either.
	refused("a refreshed run credential", s, mint(issuerKey(), "rk-0001", time.Now().Add(2*time.Hour), nil), server.LinkRunRequest{})
	other := credentialFor("rk-0002")
	s.secrets = append(s.secrets, other)
	if status, b := s.tryOpenWith(t, other, server.LinkRunRequest{RunID: r.a.RunID}); status != http.StatusConflict || refusalOf(b)["error"] != "run_id_used" {
		t.Errorf("a run_id in use: %d %s", status, b)
	}
	if status, b := r.post(t, cred, exited(r.a.RunID)); status != http.StatusAccepted {
		t.Fatalf("the run.exited: %d %s", status, b)
	}
	eventually(t, "the run's end", func() bool {
		status, _ := r.reload(t, cred, r.a.RunID)
		return status == http.StatusGone
	})
	refused("the ended run's run key", s, cred, server.LinkRunRequest{})
	s.openSession(t, other, server.LinkRunRequest{})
	s.close()
	if b, err := os.ReadFile(filepath.Join(dir, runcredential.EndedFile)); err != nil || !bytes.Contains(b, []byte(`"rk-0001"`)) || !bytes.Contains(b, []byte(`"rk-0002"`)) || bytes.Contains(b, []byte(cred)) {
		t.Errorf("the ended run keys: %s %v", b, err)
	}
	// A restart on the same directory reopens neither: both ended, the one at its
	// session's end, the other at the gateway's.
	again := startVerifying(t, gateway.Config{Dir: dir}, nil, 0)
	refused("after a restart", again, cred, server.LinkRunRequest{})
	refused("the other after a restart", again, other, server.LinkRunRequest{})
	// A batch or a reload of a run key with no run here is 401: no run is reached but
	// the run credential's.
	if status, b := (&sessionRun{s: again}).post(t, cred, heartbeat(r.a.RunID)); status != http.StatusUnauthorized {
		t.Errorf("a batch after a restart: %d %s", status, b)
	}
	again.openSession(t, credentialFor("rk-0003"), server.LinkRunRequest{})
}

// TestEveryRequestOfARunCarriesItsRunCredential pins the run credential of a run's
// later requests: a reload or a batch with the run credential of another run key, one
// with no run or one with a run of its own, is 401, so no run id can be probed; a
// refreshed run credential of the run key, with a later exp, carries the run past the
// first one's exp; and once the latest exp passes with no fresher one the run ends,
// credential_expired, its run.exited the gateway's, its proxy secret refused, and every
// later request the 410 from the gateway.
func TestEveryRequestOfARunCarriesItsRunCredential(t *testing.T) {
	o := origin(t)
	s := startVerifying(t, gateway.Config{Policy: enforce127}, nil, 0)
	first := mint(issuerKey(), "rk-0001", time.Now().Add(1500*time.Millisecond), nil)
	r := s.openSession(t, first, server.LinkRunRequest{})
	other := credentialFor("rk-0002")
	b := s.openSession(t, other, server.LinkRunRequest{})
	stranger := credentialFor("rk-0009")
	s.secrets = append(s.secrets, stranger)
	for name, c := range map[string]string{"a run key with no run": stranger, "another run's run key": other} {
		if status, body := r.reload(t, c, r.a.RunID); status != http.StatusUnauthorized {
			t.Errorf("a reload, %s: %d %s", name, status, body)
		}
	}
	if status, body := r.post(t, stranger, heartbeat(r.a.RunID)); status != http.StatusUnauthorized {
		t.Errorf("a batch, a run key with no run: %d %s", status, body)
	}
	// A batch of r's events with b's run credential is b's batch with another run's
	// events: refused, and b ends.
	if status, body := r.post(t, other, heartbeat(r.a.RunID)); status != http.StatusBadRequest {
		t.Errorf("a batch of another run's events: %d %s", status, body)
	}
	status, body := b.reload(t, other, b.a.RunID)
	gone(t, "the run whose batch was refused", status, body, "run_closed")
	// A refreshed run credential carries the run past the first's exp.
	refreshed := mint(issuerKey(), "rk-0001", time.Now().Add(3500*time.Millisecond), nil)
	s.secrets = append(s.secrets, refreshed)
	if status, body := r.post(t, refreshed, heartbeat(r.a.RunID)); status != http.StatusAccepted {
		t.Fatalf("a batch with a refreshed run credential: %d %s", status, body)
	}
	time.Sleep(2 * time.Second)
	if status, body := r.reload(t, first, r.a.RunID); status != http.StatusOK {
		t.Errorf("past the first exp: %d %s", status, body)
	}
	if code, _, err := get(s.relayOver(r.a.ProxySecret), o.URL); err != nil || code != http.StatusOK {
		t.Errorf("the relay before the end: %d %v", code, err)
	}
	eventually(t, "credential_expired", func() bool {
		status, _ := r.reload(t, refreshed, r.a.RunID)
		return status == http.StatusGone
	})
	status, body = r.post(t, refreshed, heartbeat(r.a.RunID))
	gone(t, "a batch after the end", status, body, "credential_expired")
	status, body = r.reload(t, refreshed, r.a.RunID)
	gone(t, "a reload after the end", status, body, "credential_expired")
	if _, _, err := get(s.relayOver(r.a.ProxySecret), o.URL); err == nil {
		t.Error("the proxy secret of an ended run was served")
	}
	s.close()
	rec := s.record(r.a.RunID)
	last := rec[len(rec)-1]
	if last.Type != event.RunExited || last.Data["reason"] != "credential_expired" || last.Data["state"] != "failed" || last.Data["exit_code"] != float64(-1) {
		t.Errorf("the record ends %+v", last)
	}
	validEvents(t, rec)
	noSecretIn(t, s.dir, first, refreshed, other, stranger)
}

// TestIntrospectionEndsARun pins the issuer's introspection: asked before a run opens,
// a run credential it holds inactive opens none, 401; asked again on a run's requests,
// once it holds the run credential inactive the run ends, run_ended_at_issuer, which
// the request and every later one get as the 410.
func TestIntrospectionEndsARun(t *testing.T) {
	in := &introspection{}
	s := startVerifying(t, gateway.Config{}, in, time.Hour)
	inactive := credentialFor("rk-0002")
	s.secrets = append(s.secrets, inactive)
	in.end(inactive)
	if status, b := s.tryOpenWith(t, inactive, server.LinkRunRequest{}); status != http.StatusUnauthorized {
		t.Errorf("an inactive run credential: %d %s", status, b)
	}
	cred := credentialFor("rk-0001")
	r := s.openSession(t, cred, server.LinkRunRequest{})
	if in.count(cred) == 0 {
		t.Error("the issuer was not asked before the run opened")
	}
	in.end(cred)
	status, b := r.post(t, cred, heartbeat(r.a.RunID))
	gone(t, "the batch", status, b, "run_ended_at_issuer")
	status, b = r.reload(t, cred, r.a.RunID)
	gone(t, "a later reload", status, b, "run_ended_at_issuer")
	s.close()
	rec := s.record(r.a.RunID)
	if last := rec[len(rec)-1]; last.Type != event.RunExited || last.Data["reason"] != "run_ended_at_issuer" {
		t.Errorf("the record ends %+v", last)
	}
	validEvents(t, rec)
}

// TestANarrowingOnTheOneAddress pins a session's narrowing behind a separate gateway:
// accepted, it narrows the node's policy, so a host the narrowing's allow does not
// cover is denied to the run's relay; the answer's policy is the narrowed one, with
// its own digest.
func TestANarrowingOnTheOneAddress(t *testing.T) {
	o := origin(t)
	s := startVerifying(t, gateway.Config{Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"127.0.0.1", "api.example"}}}}, nil, 0)
	cred := credentialFor("rk-0001")
	r := s.openSession(t, cred, server.LinkRunRequest{Narrowing: &server.LinkNarrowing{Egress: server.LinkNarrowingEgress{Allow: []string{"api.example"}, Deny: []string{"tracker.example"}}}})
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

// client is a client with no session: its proxy is the gateway's one address over TLS,
// its login the run credential; it trusts the gateway's own authority for what the
// proxy reads inside HTTPS.
func (s *service) clientWith(credential string) *http.Client {
	tlsConfig := s.tlsConfig()
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "https", User: url.UserPassword("anyone", credential), Host: s.g.Addr()}),
		TLSClientConfig: tlsConfig, DisableKeepAlives: true,
	}}
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

// TestARunWithNoSession pins the run of a client with no session: without a login or
// with a run credential the gateway refuses, 407 with Proxy-Authenticate; the first
// connection with a good one opens the run, with the ping, run.started opened by the
// gateway with the run credential's labels and details, the gateway's own
// policy_applied, and the connection's egress; a second connection, with a refreshed
// run credential of the same run key, joins the run; the gateway's own heartbeats
// while it lives; the run ends quiet after the quiet time with no connection, its
// run.exited with quiet_seconds and neither state nor exit_code; and its run key's run
// credentials are 407 from then on. Nothing secret reaches the record, the server or a
// report.
func TestARunWithNoSession(t *testing.T) {
	o := origin(t)
	c := newControl(t)
	s := startVerifying(t, gateway.Config{Server: c.server(), Policy: enforce127, Heartbeat: time.Second, Runs: gateway.RunsConfig{Quiet: 2 * time.Second}}, nil, 0)
	cred := credentialFor("rk-0001")
	bad := mint(otherKey(), "rk-0001", time.Now().Add(time.Hour), nil)
	s.secrets = append(s.secrets, cred, bad)
	host := strings.TrimPrefix(o.URL, "http://")
	for name, head := range map[string]string{
		"no login":          "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"a refused login":   "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("anyone:"+bad)) + "\r\n\r\n",
		"a Bearer login":    "GET " + o.URL + "/ HTTP/1.1\r\nHost: " + host + "\r\nProxy-Authorization: Bearer " + cred + "\r\n\r\n",
		"no password":       "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(cred)) + "\r\n\r\n",
		"an empty password": "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("anyone:")) + "\r\n\r\n",
	} {
		resp, conn, _ := s.proxyRequest(t, head)
		conn.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired || resp.Header.Get("Proxy-Authenticate") != `Basic realm="qory"` {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	if got := runsIn(t, s.dir); len(got) != 0 {
		t.Fatalf("a refused login opened %v", got)
	}
	if status, body, err := get(s.clientWith(cred), o.URL); err != nil || status != http.StatusOK || body != "ok" {
		t.Fatalf("the first connection: %d %q %v", status, body, err)
	}
	refreshed := mint(issuerKey(), "rk-0001", time.Now().Add(2*time.Hour), nil)
	s.secrets = append(s.secrets, refreshed)
	if status, _, err := get(s.clientWith(refreshed), "http://denied.example/"); err != nil || status != http.StatusForbidden {
		t.Errorf("the second connection: %d %v", status, err)
	}
	ids := runsIn(t, s.dir)
	if len(ids) != 1 {
		t.Fatalf("runs %v", ids)
	}
	runID := ids[0]
	eventually(t, "the quiet end", func() bool {
		rec := s.record(runID)
		return rec[len(rec)-1].Type == event.RunExited
	})
	resp, conn, _ := s.proxyRequest(t, "CONNECT "+host+" HTTP/1.1\r\nHost: "+host+"\r\nProxy-Authorization: Basic "+base64.StdEncoding.EncodeToString([]byte("anyone:"+refreshed))+"\r\n\r\n")
	conn.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("after the end: %d", resp.StatusCode)
	}
	if got := runsIn(t, s.dir); len(got) != 1 {
		t.Errorf("after the end, runs %v", got)
	}
	s.close()
	rec := s.record(runID)
	got := types(rec)
	if len(got) < 6 || !slices.Equal(got[:5], []string{event.Ping, event.RunStarted, event.PolicyApplied, event.RunEgress, event.RunEgress}) || !slices.Contains(got, event.RunHeartbeat) || got[len(got)-1] != event.RunExited {
		t.Errorf("record %v", got)
	}
	st := rec[1].Data
	about, _ := st["about"].(map[string]any)
	if st["opened_by"] != "gateway" || !sameMap(stringMap(st["labels"]), exampleLabels("rk-0001")) || !sameMap(stringMap(about["details"]), map[string]string{"requester": "example-requester"}) || st["runtime"] != nil || st["host"] != nil {
		t.Errorf("run.started %v", st)
	}
	if rec[2].Data["source"] != "config" || rec[2].Data["variables"] != nil {
		t.Errorf("policy_applied %v", rec[2].Data)
	}
	if rec[3].Data["host"] != "127.0.0.1" || rec[3].Data["decision"] != "allowed" || rec[4].Data["host"] != "denied.example" || rec[4].Data["decision"] != "denied" {
		t.Errorf("egress %v %v", rec[3].Data, rec[4].Data)
	}
	end := rec[len(rec)-1].Data
	if end["reason"] != "quiet" || end["quiet_seconds"] != float64(2) || end["state"] != nil || end["exit_code"] != nil {
		t.Errorf("run.exited %v", end)
	}
	validEvents(t, rec)
	noSecretIn(t, s.dir, cred, refreshed)
	if b, _ := os.ReadFile(c.received); bytes.Contains(b, []byte(cred)) || bytes.Contains(b, []byte(refreshed)) || !bytes.Contains(b, []byte(`"opened_by":"gateway"`)) {
		t.Error("what the server received holds a run credential, or not the run")
	}
}

// stringMap is a map of strings as JSON decodes it.
func stringMap(v any) map[string]string {
	m, _ := v.(map[string]any)
	out := map[string]string{}
	for k, x := range m {
		out[k], _ = x.(string)
	}
	return out
}

// TestARunWithNoSessionEnds pins the other ends of a run with no session: its run
// credential's exp with no fresher one, credential_expired, even while a connection
// is open; and the issuer that no longer holds it active, run_ended_at_issuer, asked
// again while the run has connections. Each run.exited has neither state nor
// exit_code, and the run key's run credentials are 407 after it.
func TestARunWithNoSessionEnds(t *testing.T) {
	o := origin(t)
	in := &introspection{}
	s := startVerifying(t, gateway.Config{Policy: enforce127}, in, 200*time.Millisecond)
	host := strings.TrimPrefix(o.URL, "http://")
	login := func(credential string) string {
		return "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(":"+credential)) + "\r\n\r\n"
	}
	expiring := mint(issuerKey(), "rk-0001", time.Now().Add(1500*time.Millisecond), nil)
	ending := credentialFor("rk-0002")
	s.secrets = append(s.secrets, expiring, ending)
	// The issuer holds an inactive run credential's run unopened.
	inactive := credentialFor("rk-0003")
	s.secrets = append(s.secrets, inactive)
	in.end(inactive)
	resp, conn, _ := s.proxyRequest(t, login(inactive))
	conn.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("an inactive run credential: %d", resp.StatusCode)
	}
	// A tunnel open across the exp.
	resp, tunnel, _ := s.proxyRequest(t, login(expiring))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the tunnel: %d", resp.StatusCode)
	}
	defer tunnel.Close()
	tunnel.SetDeadline(time.Now().Add(10 * time.Second))
	if status, _, err := get(s.clientWith(ending), o.URL); err != nil || status != http.StatusOK {
		t.Fatalf("the other run: %d %v", status, err)
	}
	// Held open, so the issuer is asked again while it is.
	resp, held, _ := s.proxyRequest(t, login(ending))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the other run's tunnel: %d", resp.StatusCode)
	}
	defer held.Close()
	in.end(ending)
	var expired, ended string
	eventually(t, "both ends", func() bool {
		for _, id := range runsIn(t, s.dir) {
			rec := s.record(id)
			if last := rec[len(rec)-1]; last.Type == event.RunExited {
				switch last.Data["reason"] {
				case "credential_expired":
					expired = id
				case "run_ended_at_issuer":
					ended = id
				}
			}
		}
		return expired != "" && ended != ""
	})
	for name, credential := range map[string]string{"credential_expired": mint(issuerKey(), "rk-0001", time.Now().Add(time.Hour), nil), "run_ended_at_issuer": ending} {
		s.secrets = append(s.secrets, credential)
		resp, conn, _ := s.proxyRequest(t, login(credential))
		conn.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("after %s: %d", name, resp.StatusCode)
		}
	}
	s.close()
	for _, id := range []string{expired, ended} {
		rec := s.record(id)
		if end := rec[len(rec)-1].Data; end["state"] != nil || end["exit_code"] != nil {
			t.Errorf("run.exited %v", end)
		}
		validEvents(t, rec)
	}
	if got := len(runsIn(t, s.dir)); got != 2 {
		t.Errorf("%d runs", got)
	}
	noSecretIn(t, s.dir, expiring, ending, inactive)
}

// TestARunWithNoSessionReadsInsideHTTPSWithTheGatewaysAuthority pins the proxy of a run
// with no session for a host its policy holds path rules for: it ends the client's TLS
// with a certificate of the gateway's own authority, which the operator installs on
// the clients' machines.
func TestARunWithNoSessionReadsInsideHTTPSWithTheGatewaysAuthority(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer upstream.Close()
	host := strings.TrimPrefix(upstream.URL, "https://")
	s := startVerifying(t, gateway.Config{Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"127.0.0.1"}, Paths: map[string][]string{"127.0.0.1": {"/allowed"}}}}}, nil, 0)
	cred := credentialFor("rk-0001")
	s.secrets = append(s.secrets, cred)
	resp, conn, r := s.proxyRequest(t, "CONNECT "+host+" HTTP/1.1\r\nHost: "+host+"\r\nProxy-Authorization: Basic "+base64.StdEncoding.EncodeToString([]byte(":"+cred))+"\r\n\r\n")
	defer conn.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %d", resp.StatusCode)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(gateway.Authority(s.g)) {
		t.Fatal("no authority")
	}
	inner := tls.Client(&bufferedConn{Conn: conn, r: r}, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	inner.SetDeadline(time.Now().Add(5 * time.Second))
	if err := inner.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("the handshake under the gateway's authority: %v", err)
	}
	io.WriteString(inner, "GET /denied HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
	if b, _ := io.ReadAll(inner); !bytes.HasPrefix(b, []byte("HTTP/1.1 403")) {
		t.Errorf("a path the rules deny: %q", b)
	}
}

// bufferedConn reads through what a reader has buffered of a connection.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }
