package gateway_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/qoryai/forager/link"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	held     map[string]*heldAsk
}

// heldAsk is an ask of the issuer held open: asked is closed once it is asked, and the
// ask answers once release is closed.
type heldAsk struct {
	asked, release chan struct{}
	once           sync.Once
}

func (in *introspection) active(_, credential string) bool {
	in.mu.Lock()
	in.asked[credential]++
	h := in.held[credential]
	in.mu.Unlock()
	if h != nil {
		h.once.Do(func() { close(h.asked) })
		<-h.release
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	return !in.inactive[credential]
}

// hold holds every ask of the issuer for the credential open until the release is
// closed.
func (in *introspection) hold(credential string) *heldAsk {
	h := &heldAsk{asked: make(chan struct{}), release: make(chan struct{})}
	in.mu.Lock()
	if in.held == nil {
		in.held = map[string]*heldAsk{}
	}
	in.held[credential] = h
	in.mu.Unlock()
	return h
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
	if cfg.RunCredentials == nil {
		cfg.RunCredentials = realIssuers(t, in != nil)
	}
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
	st := issuerStarted(a.RunID, a.Labels)
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
	if status, body := (&sessionRun{s: s}).post(t, other, issuerStarted(b.RunID, b.Labels)); status != http.StatusBadRequest {
		t.Errorf("a run.started without the run credential's details: %d %s", status, body)
	}
	s.close()
	rec := s.record(r.a.RunID)
	if got := types(rec); !slices.Equal(got, []string{event.RunRegistered, event.RunStarted, event.PolicyApplied, event.RunExited}) {
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
// mapping does not set is ignored; a refused run opens nothing, and a later run
// request opens a run as any other; and a run credential the verifier refuses is 401.
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
	// A batch of r's events with b's run credential reaches no run: 401, and neither
	// run ends.
	if status, body := r.post(t, other, heartbeat(r.a.RunID)); status != http.StatusUnauthorized {
		t.Errorf("a batch of another run key's run: %d %s", status, body)
	}
	if status, body := b.reload(t, other, b.a.RunID); status != http.StatusOK {
		t.Errorf("the run whose run credential was presented: %d %s", status, body)
	}
	var status int
	var body []byte
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
	host := strings.TrimPrefix(o.URL, "http://")
	tunnel := s.relayTunnel(t, r.a.ProxySecret, host)
	defer tunnel.Close()
	if !tunnelOpen(tunnel, host) {
		t.Fatal("the relay's tunnel does not relay")
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
	if tunnelOpen(tunnel, host) {
		t.Error("the relay's tunnel relays after credential_expired")
	}
	s.close()
	rec := s.record(r.a.RunID)
	last := rec[len(rec)-1]
	if last.Type != event.RunExited || last.Data["reason"] != "credential_expired" || last.Data["state"] != "cancelled" || last.Data["exit_code"] != float64(-1) {
		t.Errorf("the record ends %+v", last)
	}
	validEvents(t, rec)
	noSecretIn(t, s.dir, first, refreshed, other, stranger)
}

// TestIntrospectionEndsARun pins the issuer's introspection: asked before a run opens,
// a run credential it holds inactive opens none, 401; asked again on a run's requests,
// once it holds the run credential inactive the run ends, cancelled and stopped, which
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
	gone(t, "the batch", status, b, "stopped")
	status, b = r.reload(t, cred, r.a.RunID)
	gone(t, "a later reload", status, b, "stopped")
	s.close()
	rec := s.record(r.a.RunID)
	if last := rec[len(rec)-1]; last.Type != event.RunExited || last.Data["reason"] != "stopped" || last.Data["state"] != "cancelled" || last.Data["exit_code"] != float64(-1) {
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
// connection with a good one opens the run, with its registration, run.started
// opened by the gateway with the run credential's labels and details, the gateway's
// own policy_applied, and the connection's egress; a second connection, with a refreshed
// run credential of the same run key, joins the run; the gateway's own heartbeats
// while it lives; the run ends quiet after the quiet time with no connection, its
// run.exited with quiet_seconds, the state cancelled and no exit_code; and the next
// connection of its run key opens a new run, of a new run id and the same run_key
// label, with its own run.started. Nothing secret reaches the record, the server or a
// report.
func TestARunWithNoSession(t *testing.T) {
	o := origin(t)
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, 'a')
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
		b, _ := io.ReadAll(resp.Body)
		conn.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired || resp.Header.Get("Proxy-Authenticate") != `Basic realm="qory"` || string(b) != "a valid run credential is required as the proxy password" {
			t.Errorf("%s: %d %q", name, resp.StatusCode, b)
		}
	}
	if got := runsIn(t, s.dir); len(got) != 0 {
		t.Fatalf("a refused login opened %v", got)
	}
	if status, body, err := get(s.clientWith(cred), o.URL); err != nil || status != http.StatusOK || body != "ok" {
		t.Fatalf("the first connection: %d %q %v", status, body, err)
	}
	c.mu.Lock()
	asked := c.labels
	c.mu.Unlock()
	if !sameMap(asked, exampleLabels("rk-0001")) {
		t.Errorf("the server was asked for the run configuration by %v", asked)
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
	if status, _, err := get(s.clientWith(refreshed), o.URL); err != nil || status != http.StatusOK {
		t.Errorf("after the end: %d %v", status, err)
	}
	after := runsIn(t, s.dir)
	if len(after) != 2 {
		t.Fatalf("after the end, runs %v", after)
	}
	next := after[0]
	if next == runID {
		next = after[1]
	}
	s.close()
	if again := s.record(next); len(again) < 2 || again[1].Type != event.RunStarted || !sameMap(stringMap(again[1].Data["labels"]), exampleLabels("rk-0001")) {
		t.Errorf("the new run's record %v", types(again))
	}
	rec := s.record(runID)
	got := types(rec)
	if len(got) < 6 || !slices.Equal(got[:5], []string{event.RunRegistered, event.RunStarted, event.PolicyApplied, event.RunEgress, event.RunEgress}) || !slices.Contains(got, event.RunHeartbeat) || got[len(got)-1] != event.RunExited {
		t.Errorf("record %v", got)
	}
	st := rec[1].Data
	about, _ := st["about"].(map[string]any)
	if st["opened_by"] != "gateway" || st["credential"] != "starter" || !sameMap(stringMap(st["labels"]), exampleLabels("rk-0001")) || !sameMap(stringMap(about["details"]), map[string]string{"requester": "example-requester"}) || st["runtime"] != nil || st["host"] != nil {
		t.Errorf("run.started %v", st)
	}
	if rec[2].Data["source"] != "fetched" || rec[2].Data["variables"] != nil {
		t.Errorf("policy_applied %v", rec[2].Data)
	}
	if rec[3].Data["host"] != "127.0.0.1" || rec[3].Data["decision"] != "allowed" || rec[4].Data["host"] != "denied.example" || rec[4].Data["decision"] != "denied" {
		t.Errorf("egress %v %v", rec[3].Data, rec[4].Data)
	}
	end := rec[len(rec)-1].Data
	if end["reason"] != "quiet" || end["quiet_seconds"] != float64(2) || end["state"] != "cancelled" || end["exit_code"] != nil {
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
// is open; and the issuer that no longer holds it active, stopped, asked
// again while the run has connections. Each run.exited has the state cancelled and
// no exit_code. After credential_expired, a fresh run credential of the run key opens a
// new run; after the issuer's end, the gateway refuses the run key, 407, even for a
// run credential the issuer holds active.
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
	if !tunnelOpen(tunnel, host) {
		t.Fatal("the tunnel does not relay")
	}
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
				case "stopped":
					ended = id
				}
			}
		}
		return expired != "" && ended != ""
	})
	// Neither tunnel outlives its run.
	if tunnelOpen(tunnel, host) {
		t.Error("the tunnel relays after credential_expired")
	}
	if tunnelOpen(held, host) {
		t.Error("the tunnel relays after stopped")
	}
	for name, c := range map[string]struct {
		credential string
		want       int
	}{
		"credential_expired": {mint(issuerKey(), "rk-0001", time.Now().Add(time.Hour), nil), http.StatusOK},
		"stopped":            {mint(issuerKey(), "rk-0002", time.Now().Add(2*time.Hour), nil), http.StatusProxyAuthRequired},
	} {
		s.secrets = append(s.secrets, c.credential)
		resp, conn, _ := s.proxyRequest(t, login(c.credential))
		conn.Close()
		if resp.StatusCode != c.want {
			t.Errorf("after %s: %d", name, resp.StatusCode)
		}
	}
	s.close()
	for _, id := range []string{expired, ended} {
		rec := s.record(id)
		if end := rec[len(rec)-1].Data; end["state"] != "cancelled" || end["exit_code"] != nil {
			t.Errorf("run.exited %v", end)
		}
		validEvents(t, rec)
	}
	if got := len(runsIn(t, s.dir)); got != 3 {
		t.Errorf("%d runs", got)
	}
	noSecretIn(t, s.dir, expiring, ending, inactive)
}

// TestARunWithNoSessionOutlivesAServersStop pins a run with no session whose server
// answers a signed 410, run_closed among them: the run goes on. Its next connection
// joins the same run, its gateway heartbeats are recorded and sent no more, and its
// record holds no run.exited.
func TestARunWithNoSessionOutlivesAServersStop(t *testing.T) {
	o := origin(t)
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, 'a')
	s := startVerifying(t, gateway.Config{Server: c.server(), Policy: enforce127, Heartbeat: time.Second}, nil, 0)
	cred := credentialFor("rk-0001")
	s.secrets = append(s.secrets, cred)
	if status, _, err := get(s.clientWith(cred), o.URL); err != nil || status != http.StatusOK {
		t.Fatalf("the first connection: %d %v", status, err)
	}
	ids := runsIn(t, s.dir)
	if len(ids) != 1 {
		t.Fatalf("runs %v", ids)
	}
	runID := ids[0]
	c.closed.Store(true)
	eventually(t, "the server's 410", func() bool {
		b, _ := os.ReadFile(filepath.Join(s.dir, "runs", runID, "delivered.log"))
		return bytes.Contains(b, []byte("stopped"))
	})
	sent := c.deliveries.Load()
	before := len(s.record(runID))
	eventually(t, "a heartbeat after the server's 410", func() bool {
		rec := s.record(runID)
		return len(rec) > before && rec[len(rec)-1].Type == event.RunHeartbeat
	})
	if status, _, err := get(s.clientWith(cred), o.URL); err != nil || status != http.StatusOK {
		t.Errorf("a connection after the server's 410: %d %v", status, err)
	}
	if got := runsIn(t, s.dir); len(got) != 1 {
		t.Errorf("after the server's 410, runs %v", got)
	}
	if got := types(s.record(runID)); slices.Contains(got, event.RunExited) {
		t.Errorf("the run ended at the server's 410: %v", got)
	}
	if n := c.deliveries.Load() - sent; n != 0 {
		t.Errorf("%d requests reached the server after its 410", n)
	}
	s.close()
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

// TestARunWithNoSessionReloads pins a reload of a run with no session: the server's
// new run configuration, which its answers to the gateway's own heartbeats announce,
// is put in force, the gateway writes its policy_applied itself, and a connection
// decided under the new policy is recorded after it.
func TestARunWithNoSessionReloads(t *testing.T) {
	o := origin(t)
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, 'a')
	s := startVerifying(t, gateway.Config{Server: c.server(), Heartbeat: time.Second}, nil, 0)
	cred := credentialFor("rk-0001")
	s.secrets = append(s.secrets, cred)
	// Kept open, so the run is not quiet while the reload comes.
	host := strings.TrimPrefix(o.URL, "http://")
	resp, held, _ := s.proxyRequest(t, "CONNECT "+host+" HTTP/1.1\r\nHost: "+host+"\r\nProxy-Authorization: Basic "+base64.StdEncoding.EncodeToString([]byte(":"+cred))+"\r\n\r\n")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %d", resp.StatusCode)
	}
	defer held.Close()
	runID := runsIn(t, s.dir)[0]
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`, 'b')
	eventually(t, "the reload", func() bool {
		n := 0
		for _, l := range s.record(runID) {
			if l.Type == event.PolicyApplied {
				n++
			}
		}
		return n == 2
	})
	if status, _, err := get(s.clientWith(cred), o.URL); err != nil || status != http.StatusForbidden {
		t.Errorf("under the new policy: %d %v", status, err)
	}
	s.close()
	rec := s.record(runID)
	second := -1
	for i, l := range rec {
		if l.Type == event.PolicyApplied && l.Data["run_configuration"] == "sha256="+strings.Repeat("b", 64) {
			second = i
		}
	}
	if second < 0 {
		t.Fatalf("record %v", types(rec))
	}
	for i, l := range rec {
		if l.Type == event.RunEgress && l.Data["decision"] == "denied" && i < second {
			t.Errorf("a connection under the new policy at %d, before its policy_applied at %d", i, second)
		}
	}
	if !slices.ContainsFunc(rec[second:], func(l recorded) bool { return l.Type == event.RunEgress && l.Data["decision"] == "denied" }) {
		t.Errorf("no denied egress after the new policy_applied: %v", types(rec))
	}
	validEvents(t, rec)
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
		s := startVerifying(t, gateway.Config{Policy: pol}, nil, 0)
		denied(name, s, s.openSession(t, credentialFor("rk-0001"), server.LinkRunRequest{Narrowing: narrowing}))
	}
	// A reload to another observe policy opens nothing either.
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"observe"}}`, 'a')
	s := startVerifying(t, gateway.Config{Server: c.server()}, nil, 0)
	cred := credentialFor("rk-0001")
	r := s.openSession(t, cred, server.LinkRunRequest{Narrowing: narrowing})
	denied("at the start", s, r)
	c.serve(`{"version":1,"egress":{"mode":"observe","deny":["tracker.example"]}}`, 'b')
	eventually(t, "the reload", func() bool {
		r.post(t, cred, heartbeat(r.a.RunID))
		_, b := r.reload(t, cred, r.a.RunID)
		return bytes.Contains(b, []byte("tracker.example"))
	})
	denied("after the reload", s, r)
	// A policy that enforces and names the host itself opens it.
	named := startVerifying(t, gateway.Config{Policy: enforce127}, nil, 0)
	nr := named.openSession(t, credentialFor("rk-0001"), server.LinkRunRequest{Narrowing: narrowing})
	if status, _, err := get(named.relayOver(nr.a.ProxySecret), o.URL); err != nil || status != http.StatusOK {
		t.Errorf("a host the policy names itself: %d %v", status, err)
	}
}

// TestARunWithNoSessionThatDoesNotOpen pins a run with no session the gateway cannot
// open. Refused with a code after its registration, its record holds run.registered
// and then dev.qory.run.refused with that code, which the server receives alone, and the connection gets the 403 that
// says who refused it and the code; failing without a code, after its tries, the
// connection gets the 503 that says to try again. Either way the next connection of
// the run key opens a run.
func TestARunWithNoSessionThatDoesNotOpen(t *testing.T) {
	o := origin(t)
	host := strings.TrimPrefix(o.URL, "http://")
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]},"image":"example-image"}`, 'a')
	cfg := gateway.Config{Server: c.server()}
	gateway.SetOpenTries(&cfg, []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}, time.Second)
	s := startVerifying(t, cfg, nil, 0)
	cred := credentialFor("rk-0001")
	s.secrets = append(s.secrets, cred)
	login := "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(":"+cred)) + "\r\n\r\n"
	connect := func() (*http.Response, []byte) {
		t.Helper()
		resp, conn, _ := s.proxyRequest(t, login)
		defer conn.Close()
		if resp.StatusCode == http.StatusOK {
			return resp, nil
		}
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	if resp, b := connect(); resp.StatusCode != http.StatusForbidden || string(b) != "the gateway could not open the run: the gateway refused it, image_unknown" {
		t.Errorf("a refusal with a code: %d %q", resp.StatusCode, b)
	}
	ids := runsIn(t, s.dir)
	if len(ids) != 1 {
		t.Fatalf("runs %v", ids)
	}
	rec := s.record(ids[0])
	if got := types(rec); !slices.Equal(got, []string{event.RunRegistered, event.RunRefused}) || rec[1].Data["code"] != "image_unknown" {
		t.Errorf("record %v %v", got, rec[len(rec)-1].Data)
	}
	validEvents(t, rec)
	eventually(t, "the server's run.refused", func() bool {
		var got []string
		for _, l := range c.lines(t) {
			if l.Subject == ids[0] {
				got = append(got, l.Type)
			}
		}
		return slices.Equal(got, []string{event.RunRefused})
	})
	// Without a code: the server closes the connection unanswered.
	script(c).then(runPath, dropped, dropped, dropped)
	resp, b := connect()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" || resp.ContentLength != int64(len(b)) || string(b) != "the gateway could not open the run; try again" {
		t.Errorf("a failure without a code: %d %v %q", resp.StatusCode, resp.Header, b)
	}
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, 'b')
	if resp, _ := connect(); resp.StatusCode != http.StatusOK {
		t.Errorf("the next connection: %d", resp.StatusCode)
	}
	if got := runsIn(t, s.dir); len(got) != 3 {
		t.Errorf("runs %v", got)
	}
	s.close()
	noSecretIn(t, s.dir, cred)
}

// TestARunWithNoSessionThatAServers410DoesNotOpen pins a run with no session whose
// server answers its registration with a signed 410 run_closed: no run, as for a
// failure without a code. The connection gets the 503 that says to try again, its
// record holds nothing, and the server receives nothing.
func TestARunWithNoSessionThatAServers410DoesNotOpen(t *testing.T) {
	o := origin(t)
	host := strings.TrimPrefix(o.URL, "http://")
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, 'a')
	c.goneOnFetch.Store(true)
	s := startVerifying(t, gateway.Config{Server: c.server()}, nil, 0)
	cred := credentialFor("rk-0001")
	s.secrets = append(s.secrets, cred)
	login := "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(":"+cred)) + "\r\n\r\n"
	resp, conn, _ := s.proxyRequest(t, login)
	b, _ := io.ReadAll(resp.Body)
	conn.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || string(b) != "the gateway could not open the run; try again" {
		t.Errorf("a 410 to the run configuration: %d %q", resp.StatusCode, b)
	}
	ids := runsIn(t, s.dir)
	if len(ids) != 1 {
		t.Fatalf("runs %v", ids)
	}
	if got := types(s.record(ids[0])); len(got) != 0 {
		t.Errorf("record %v", got)
	}
	s.close()
	if got := c.lines(t); len(got) != 0 {
		t.Errorf("the server was sent %v", types(got))
	}
}

// TestNoLinkSocketWithTheOneAddress pins Config.NoLinkSocket beside Listen: the
// gateway serves the one address over TLS, a session's run on its run credential going
// as without it, and makes no link directory and no socket; its local link is in
// memory alone.
func TestNoLinkSocketWithTheOneAddress(t *testing.T) {
	tmp, err := os.MkdirTemp("/tmp", "qt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	t.Setenv("TMPDIR", tmp)
	s := startVerifying(t, gateway.Config{NoLinkSocket: true}, nil, 0)
	if l := s.g.LocalLink(); l.Socket != "" || !l.IsInMemory() {
		t.Errorf("local %+v", l)
	}
	cred := credentialFor("rk-0001")
	r := s.openSession(t, cred, server.LinkRunRequest{})
	if status, b := r.reload(t, cred, r.a.RunID); status != http.StatusOK {
		t.Errorf("the reload: %d %s", status, b)
	}
	if status, b := r.post(t, cred, exited(r.a.RunID)); status != http.StatusAccepted {
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
// run key's still 401; a client's run likewise; and once a run credential of an ended
// run can no longer be accepted, nothing of it is held at all.
func TestAGatewayLetsGoOfEndedRuns(t *testing.T) {
	o := origin(t)
	host := strings.TrimPrefix(o.URL, "http://")
	cfg := gateway.Config{Policy: enforce127, Runs: gateway.RunsConfig{Quiet: time.Second}}
	gateway.SetKeepSpent(&cfg, time.Millisecond)
	s := startVerifying(t, cfg, nil, 0)
	exp := time.Unix(time.Now().Add(3*time.Second).Unix(), 0)
	var ended []*sessionRun
	for _, k := range []string{"rk-0001", "rk-0002", "rk-0003"} {
		r := s.openSession(t, mint(issuerKey(), k, exp, nil), server.LinkRunRequest{})
		if status, b := r.post(t, r.credential, exited(r.a.RunID)); status != http.StatusAccepted {
			t.Fatalf("the run.exited: %d %s", status, b)
		}
		ended = append(ended, r)
	}
	client := mint(issuerKey(), "rk-0004", exp, nil)
	s.secrets = append(s.secrets, client)
	login := "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(":"+client)) + "\r\n\r\n"
	resp, conn, _ := s.proxyRequest(t, login)
	conn.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the client's run: %d", resp.StatusCode)
	}
	eventually(t, "the runs let go of", func() bool {
		runs, keys, spent, _ := gateway.Held(s.g)
		return runs == 0 && keys == 0 && spent == 4
	})
	r := ended[0]
	if status, b := r.reload(t, r.credential, r.a.RunID); status != http.StatusGone {
		t.Errorf("a reload of a run let go of: %d %s", status, b)
	}
	if status, b := r.reload(t, r.credential, ended[1].a.RunID); status != http.StatusUnauthorized {
		t.Errorf("a reload of another run id: %d %s", status, b)
	}
	if status, b := r.post(t, r.credential, heartbeat(r.a.RunID)); status != http.StatusGone {
		t.Errorf("a batch of a run let go of: %d %s", status, b)
	}
	// Past their exp, the next run to end takes what they left with it.
	time.Sleep(time.Until(exp) + 100*time.Millisecond)
	last := s.openSession(t, credentialFor("rk-0005"), server.LinkRunRequest{})
	last.post(t, last.credential, exited(last.a.RunID))
	eventually(t, "what the earlier runs left let go of", func() bool {
		runs, keys, spent, kept := gateway.Held(s.g)
		return runs == 0 && keys == 0 && spent == 1 && kept == 0
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
	s := startVerifying(t, gateway.Config{}, nil, 0)
	body := strings.Repeat("x", 32<<10)
	for i := range 20 {
		c := s.dial(t)
		c.SetDeadline(time.Now().Add(5 * time.Second))
		head := "POST http://api.example/upload HTTP/1.1\r\nHost: api.example\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(":not-a-run-credential")) + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
		if _, err := io.WriteString(c, head+body); err != nil {
			t.Fatalf("%d: sending: %v", i, err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("%d: reading the answer: %v", i, err)
		}
		b, err := io.ReadAll(resp.Body)
		c.Close()
		if err != nil || resp.StatusCode != http.StatusProxyAuthRequired || string(b) != "a valid run credential is required as the proxy password" {
			t.Fatalf("%d: %d %q %v", i, resp.StatusCode, b, err)
		}
	}
}

// TestARunKeyIsNotUnique pins the gateway tracking run keys without requiring them to
// be unique: two sessions with one run key open two runs at once, each of its own run
// id and proxy secret and the same run_key label; a run of a run key whose run ended,
// whose run was refused, or whose run Qory Apiary closed with its 410 opens as any
// other; and a run id another run has is still run_id_used.
func TestARunKeyIsNotUnique(t *testing.T) {
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, 'a')
	s := startVerifying(t, gateway.Config{Server: c.server()}, nil, 0)
	cred := credentialFor("rk-0001")
	a := s.openSession(t, cred, server.LinkRunRequest{})
	b := s.openSession(t, cred, server.LinkRunRequest{})
	if a.a.RunID == b.a.RunID || a.a.ProxySecret == b.a.ProxySecret || a.a.Labels["run_key"] != "rk-0001" || b.a.Labels["run_key"] != "rk-0001" {
		t.Errorf("two runs of one run key: %s %s %v %v", a.a.RunID, b.a.RunID, a.a.Labels, b.a.Labels)
	}
	for _, r := range []*sessionRun{a, b} {
		if status, body := r.reload(t, cred, r.a.RunID); status != http.StatusOK {
			t.Errorf("a reload of %s: %d %s", r.a.RunID, status, body)
		}
	}
	if status, body := s.tryOpenWith(t, cred, server.LinkRunRequest{RunID: a.a.RunID}); status != http.StatusConflict || refusalOf(body)["error"] != "run_id_used" {
		t.Errorf("a run id in use: %d %s", status, body)
	}
	// After a run ended.
	if status, body := a.post(t, cred, exited(a.a.RunID)); status != http.StatusAccepted {
		t.Fatalf("the run.exited: %d %s", status, body)
	}
	after := s.openSession(t, cred, server.LinkRunRequest{})
	// After a refused run.
	if status, body := s.tryOpenWith(t, cred, server.LinkRunRequest{Labels: map[string]string{"repository": "other/project"}}); status != http.StatusForbidden {
		t.Errorf("a refused run: %d %s", status, body)
	}
	c.serve(`{"version":1,"egress":{"mode":"bogus"}}`, 'b')
	if status, body := s.tryOpenWith(t, cred, server.LinkRunRequest{}); status != http.StatusForbidden || refusalOf(body)["error"] != "run_configuration_invalid" {
		t.Errorf("a run the server's configuration refuses: %d %s", status, body)
	}
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, 'c')
	s.openSession(t, cred, server.LinkRunRequest{})
	// After Qory Apiary's 410: the run goes on, and the run key opens a new run.
	c.closed.Store(true)
	after.post(t, cred, heartbeat(after.a.RunID))
	eventually(t, "Qory Apiary's 410", func() bool {
		b, _ := os.ReadFile(filepath.Join(s.dir, "runs", after.a.RunID, "delivered.log"))
		return bytes.Contains(b, []byte("stopped"))
	})
	c.closed.Store(false)
	if status, body := after.post(t, cred, heartbeat(after.a.RunID)); status != http.StatusAccepted {
		t.Errorf("a batch after Qory Apiary's 410: %d %s", status, body)
	}
	if status, body := after.reload(t, cred, after.a.RunID); status != http.StatusOK {
		t.Errorf("a reload after Qory Apiary's 410: %d %s", status, body)
	}
	s.openSession(t, cred, server.LinkRunRequest{})
}

// TestTheIssuersEndRefusesTheRunKey pins the one end after which the gateway refuses a
// run key: after the issuer's end, stopped, a session's run request of the
// run key is 401 and a client's connection 407, even with a run credential the issuer
// holds active, and so after a restart on the same directory. A run credential of the
// run key presented then is refused and extends the refusal to its own exp; the
// refusal lapses after the latest exp presented, and then the run key opens a new run.
func TestTheIssuersEndRefusesTheRunKey(t *testing.T) {
	o := origin(t)
	host := strings.TrimPrefix(o.URL, "http://")
	dir := t.TempDir()
	var ahead atomic.Int64
	clock := func() time.Time { return time.Now().Add(time.Duration(ahead.Load())) }
	in := &introspection{}
	start := func() *service {
		cfg := gateway.Config{Dir: dir, Policy: enforce127}
		gateway.SetClock(&cfg, clock)
		return startVerifying(t, cfg, in, time.Hour)
	}
	s := start()
	first := credentialFor("rk-0001")
	r := s.openSession(t, first, server.LinkRunRequest{})
	in.end(first)
	status, body := r.reload(t, first, r.a.RunID)
	gone(t, "the issuer's end", status, body, "stopped")
	login := func(credential string) string {
		return "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(":"+credential)) + "\r\n\r\n"
	}
	refused := func(what string, s *service, credential string) {
		t.Helper()
		if status, body := s.tryOpenWith(t, credential, server.LinkRunRequest{}); status != http.StatusUnauthorized {
			t.Errorf("%s, a session: %d %s", what, status, body)
		}
		resp, conn, _ := s.proxyRequest(t, login(credential))
		conn.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("%s, a client: %d", what, resp.StatusCode)
		}
	}
	// A run credential the issuer holds active, of a later exp: refused, and the
	// refusal extended to its exp.
	later := mint(issuerKey(), "rk-0001", time.Now().Add(2*time.Hour), nil)
	s.secrets = append(s.secrets, later)
	refused("an active run credential", s, later)
	s.close()
	again := start()
	again.secrets = append(again.secrets, first, later)
	refused("after a restart", again, later)
	// Past the first exp and its leeway, the later one still holds it.
	ahead.Store(int64(time.Hour + 10*time.Minute))
	refused("past the first exp", again, later)
	// Past the latest exp presented, the run key opens a new run.
	ahead.Store(int64(2*time.Hour + 10*time.Minute))
	again.openSession(t, later, server.LinkRunRequest{})
	if status, _, err := get(again.clientWith(later), o.URL); err != nil || status != http.StatusOK {
		t.Errorf("a client past the latest exp: %d %v", status, err)
	}
}

// TestAClientsRunOfARunKey pins the client's run of a run key: at most one is open, so
// concurrent first connections open one run and join it; and a client never joins a
// session's run, which only its proxy secret reaches: a client of a run key whose
// sessions' runs are open opens its own run beside them.
func TestAClientsRunOfARunKey(t *testing.T) {
	o := origin(t)
	s := startVerifying(t, gateway.Config{Policy: enforce127}, nil, 0)
	cred := credentialFor("rk-0001")
	session := s.openSession(t, cred, server.LinkRunRequest{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if status, _, err := get(s.clientWith(cred), o.URL); err != nil || status != http.StatusOK {
				t.Errorf("a first connection: %d %v", status, err)
			}
		}()
	}
	wg.Wait()
	runs := runsIn(t, s.dir)
	if len(runs) != 2 {
		t.Fatalf("runs %v", runs)
	}
	client := runs[0]
	if client == session.a.RunID {
		client = runs[1]
	}
	if status, body := session.reload(t, cred, session.a.RunID); status != http.StatusOK {
		t.Errorf("the session's run: %d %s", status, body)
	}
	s.close()
	n := 0
	for _, l := range s.record(client) {
		switch l.Type {
		case event.RunStarted:
			if l.Data["opened_by"] != "gateway" {
				t.Errorf("the client's run.started %v", l.Data)
			}
		case event.RunEgress:
			n++
		}
	}
	if n != 8 {
		t.Errorf("%d connections in the client's run", n)
	}
	for _, l := range s.record(session.a.RunID) {
		if l.Type == event.RunEgress {
			t.Error("a client's connection in the session's run")
		}
	}
}

// TestTheIssuersEndRefusesTheRunKeyInFlight pins the issuer's end against what is in
// flight for its run key: a session's run request and a client's first connection
// whose run credential the issuer is still being asked about when it ends another run
// of the run key are refused, 401 and 407, and open no run; and a later connection of
// a client's run that was open before the end is refused, 407, as it would join.
func TestTheIssuersEndRefusesTheRunKeyInFlight(t *testing.T) {
	o := origin(t)
	in := &introspection{}
	s := startVerifying(t, gateway.Config{Policy: enforce127}, in, 0)
	endOf := func(k string) (string, *sessionRun) {
		t.Helper()
		first := mint(issuerKey(), k, time.Now().Add(time.Hour), nil)
		return first, s.openSession(t, first, server.LinkRunRequest{})
	}
	issuerEnds := func(first string, r *sessionRun) {
		t.Helper()
		in.end(first)
		status, body := r.reload(t, first, r.a.RunID)
		gone(t, "the issuer's end", status, body, "stopped")
	}

	// A session's run request.
	first, r := endOf("rk-0001")
	second := mint(issuerKey(), "rk-0001", time.Now().Add(2*time.Hour), nil)
	s.secrets = append(s.secrets, second)
	h := in.hold(second)
	session := make(chan int, 1)
	go func() {
		status, _ := s.tryOpenWith(t, second, server.LinkRunRequest{})
		session <- status
	}()
	<-h.asked
	issuerEnds(first, r)
	close(h.release)
	if status := <-session; status != http.StatusUnauthorized {
		t.Errorf("a session's run request in flight: %d", status)
	}

	// A client's first connection.
	first, r = endOf("rk-0002")
	second = mint(issuerKey(), "rk-0002", time.Now().Add(2*time.Hour), nil)
	s.secrets = append(s.secrets, second)
	h = in.hold(second)
	client := make(chan int, 1)
	go func() {
		status, _, _ := get(s.clientWith(second), o.URL)
		client <- status
	}()
	<-h.asked
	issuerEnds(first, r)
	close(h.release)
	if status := <-client; status != http.StatusProxyAuthRequired {
		t.Errorf("a client's connection in flight: %d", status)
	}

	// A client's run open before the end: its next connection would join.
	joined := mint(issuerKey(), "rk-0003", time.Now().Add(2*time.Hour), nil)
	s.secrets = append(s.secrets, joined)
	if status, _, err := get(s.clientWith(joined), o.URL); err != nil || status != http.StatusOK {
		t.Fatalf("the client's run: %d %v", status, err)
	}
	first, r = endOf("rk-0003")
	issuerEnds(first, r)
	if status, _, err := get(s.clientWith(joined), o.URL); err != nil || status != http.StatusProxyAuthRequired {
		t.Errorf("a connection joining after the end: %d %v", status, err)
	}

	// Three sessions' runs and one client's: nothing opened in flight.
	if got := runsIn(t, s.dir); len(got) != 4 {
		t.Errorf("runs %v", got)
	}
}

// TestTheIssuersEndRefusesTheRunKeysLiveRuns pins the issuer's end against the run
// key's other runs that are live: a reload or a batch of a session's run of it gets the
// run's 410, stopped, though the issuer holds that run's own run credential
// active, and the run ends; a client's run of it refuses its next connection, 407, and
// ends too.
func TestTheIssuersEndRefusesTheRunKeysLiveRuns(t *testing.T) {
	o := origin(t)
	in := &introspection{}
	s := startVerifying(t, gateway.Config{Policy: enforce127}, in, 0)
	first := mint(issuerKey(), "rk-0001", time.Now().Add(time.Hour), nil)
	second := mint(issuerKey(), "rk-0001", time.Now().Add(2*time.Hour), nil)
	s.secrets = append(s.secrets, first, second)
	a := s.openSession(t, first, server.LinkRunRequest{})
	b := s.openSession(t, second, server.LinkRunRequest{})
	reloaded := s.openSession(t, second, server.LinkRunRequest{})
	if status, _, err := get(s.clientWith(second), o.URL); err != nil || status != http.StatusOK {
		t.Fatalf("the client's run: %d %v", status, err)
	}
	var client string
	for _, id := range runsIn(t, s.dir) {
		if id != a.a.RunID && id != b.a.RunID && id != reloaded.a.RunID {
			client = id
		}
	}
	in.end(first)
	status, body := a.reload(t, first, a.a.RunID)
	gone(t, "the issuer's end", status, body, "stopped")

	status, body = b.post(t, second, heartbeat(b.a.RunID))
	gone(t, "a batch of another run of the run key", status, body, "stopped")
	status, body = reloaded.reload(t, second, reloaded.a.RunID)
	gone(t, "a reload of another run of the run key", status, body, "stopped")
	status, body = b.reload(t, second, b.a.RunID)
	gone(t, "a later reload", status, body, "stopped")
	if status, _, err := get(s.clientWith(second), o.URL); err != nil || status != http.StatusProxyAuthRequired {
		t.Errorf("a client's connection after the end: %d %v", status, err)
	}
	s.close()
	for _, id := range []string{b.a.RunID, reloaded.a.RunID, client} {
		rec := s.record(id)
		if last := rec[len(rec)-1]; last.Type != event.RunExited || last.Data["reason"] != "stopped" || last.Data["state"] != "cancelled" {
			t.Errorf("run %s: the record ends %+v", id, last)
		}
	}
}

// TestCloseWaitsForARunEndedAsItOpened pins a run that opened while the issuer ended
// another run of its run key: it ends at once, and Close waits for its record as for
// every run, what it left undelivered in the Delivery.
func TestCloseWaitsForARunEndedAsItOpened(t *testing.T) {
	o := origin(t)
	for _, client := range []bool{false, true} {
		c := newControl(t)
		in := &introspection{}
		cfg := gateway.Config{Server: c.server(), Policy: enforce127}
		gateway.SetCloseWait(&cfg, 2*time.Second)
		var armed atomic.Bool
		var s *service
		var first string
		var a *sessionRun
		gateway.SetOpened(&cfg, func() {
			if !armed.CompareAndSwap(true, false) {
				return
			}
			// The issuer ends the other run as this one opens; once that run is let go
			// of, the server takes nothing more.
			in.end(first)
			status, body := a.reload(t, first, a.a.RunID)
			gone(t, "the issuer's end", status, body, "stopped")
			eventually(t, "the ended run let go of", func() bool {
				runs, _, _, _ := gateway.Held(s.g)
				return runs == 0
			})
			c.refuse.Store(http.StatusServiceUnavailable)
		})
		s = startVerifying(t, cfg, in, 0)
		first = mint(issuerKey(), "rk-0001", time.Now().Add(time.Hour), nil)
		second := mint(issuerKey(), "rk-0001", time.Now().Add(2*time.Hour), nil)
		s.secrets = append(s.secrets, first, second)
		a = s.openSession(t, first, server.LinkRunRequest{})
		armed.Store(true)
		if client {
			if status, _, err := get(s.clientWith(second), o.URL); err != nil || status != http.StatusProxyAuthRequired {
				t.Errorf("a client's connection: %d %v", status, err)
			}
		} else if status, body := s.tryOpenWith(t, second, server.LinkRunRequest{}); status != http.StatusUnauthorized {
			t.Errorf("a session's run request: %d %s", status, body)
		}
		if armed.Load() {
			t.Fatal("no run opened")
		}
		runs := runsIn(t, s.dir)
		if len(runs) != 2 {
			t.Fatalf("runs %v", runs)
		}
		ended := runs[0]
		if ended == a.a.RunID {
			ended = runs[1]
		}
		d := s.close()
		rec := s.record(ended)
		if client {
			// The client's run started: its record ends with its exit, undelivered.
			if last := rec[len(rec)-1]; last.Type != event.RunExited || last.Data["reason"] != "stopped" {
				t.Errorf("the client's run: the record ends %+v", last)
			}
			if d.Undelivered == 0 {
				t.Errorf("delivery %+v", d)
			}
		} else if got := types(rec); !slices.Equal(got, []string{event.RunRegistered}) {
			// A session's run: its run.registered, the registration the server accepted
			// as it opened, and nothing after.
			t.Errorf("the session's run: the record %v", got)
		}
	}
}

// blockHold makes every write of the refused run keys in dir fail, for any user, root
// among them, who writes a directory of mode 0500 all the same: the file is written
// beside itself and renamed over, and a directory that is not empty stands at its path,
// so the rename fails. The file as last written, when there is one, is set aside. The
// function returned puts it back, and writes succeed again; it runs at the test's end
// too.
func blockHold(t *testing.T, dir string) (unblock func()) {
	t.Helper()
	path := filepath.Join(dir, runcredential.EndedFile)
	aside := filepath.Join(t.TempDir(), runcredential.EndedFile)
	written := true
	if err := os.Rename(path, aside); errors.Is(err, fs.ErrNotExist) {
		written = false
	} else if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "blocked"), 0o700); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	unblock = func() {
		once.Do(func() {
			if err := os.RemoveAll(path); err != nil {
				t.Error(err)
			}
			if written {
				if err := os.Rename(aside, path); err != nil {
					t.Error(err)
				}
			}
		})
	}
	t.Cleanup(unblock)
	return unblock
}

// TestARunWhoseHoldIsNotWrittenIsLetGoOf pins the issuer's end when the refused run
// keys cannot be written: the failure is reported, the run key is refused all the same,
// and the run that ended is let go of once its record is flushed.
func TestARunWhoseHoldIsNotWrittenIsLetGoOf(t *testing.T) {
	in := &introspection{}
	cfg := gateway.Config{Policy: enforce127}
	gateway.SetKeepSpent(&cfg, time.Millisecond)
	s := startVerifying(t, cfg, in, 0)
	first := credentialFor("rk-0001")
	r := s.openSession(t, first, server.LinkRunRequest{})
	// The refused run keys cannot be written.
	blockHold(t, s.dir)
	in.end(first)
	status, body := r.reload(t, first, r.a.RunID)
	gone(t, "the issuer's end", status, body, "stopped")
	if !s.reported("keeping the run key of an ended run, for the run credentials of") {
		t.Error("the failed write was not reported")
	}
	eventually(t, "the run let go of", func() bool {
		runs, _, spent, _ := gateway.Held(s.g)
		return runs == 0 && spent == 1
	})
	later := mint(issuerKey(), "rk-0001", time.Now().Add(2*time.Hour), nil)
	s.secrets = append(s.secrets, later)
	if status, body := s.tryOpenWith(t, later, server.LinkRunRequest{}); status != http.StatusUnauthorized {
		t.Errorf("a run request of the run key: %d %s", status, body)
	}
}

// TestTheHoldRunsToTheLatestExpHeld pins the hold's length: after the issuer's end of
// a run of a run key, the gateway refuses the run key until the latest exp of the run
// credentials of the key it still holds, a live run's later exp among them, not the
// ended run's own.
func TestTheHoldRunsToTheLatestExpHeld(t *testing.T) {
	in := &introspection{}
	var ahead atomic.Int64
	cfg := gateway.Config{Policy: enforce127}
	gateway.SetClock(&cfg, func() time.Time { return time.Now().Add(time.Duration(ahead.Load())) })
	s := startVerifying(t, cfg, in, 0)
	now := time.Now()
	first := mint(issuerKey(), "rk-0001", now.Add(time.Hour), nil)
	second := mint(issuerKey(), "rk-0001", now.Add(2*time.Hour), nil)
	probe := mint(issuerKey(), "rk-0001", now.Add(time.Hour+time.Minute), nil)
	s.secrets = append(s.secrets, first, second, probe)
	ended := s.openSession(t, first, server.LinkRunRequest{})
	s.openSession(t, second, server.LinkRunRequest{})
	in.end(first)
	status, body := ended.reload(t, first, ended.a.RunID)
	gone(t, "the issuer's end", status, body, "stopped")
	// Past the ended run's exp and its leeway, the live run's later exp holds the run
	// key; the probe's own exp is earlier, so it extends nothing.
	ahead.Store(int64(time.Hour + 10*time.Minute))
	if status, body := s.tryOpenWith(t, probe, server.LinkRunRequest{}); status != http.StatusUnauthorized {
		t.Errorf("past the ended run's exp: %d %s", status, body)
	}
	// Past the later exp and its leeway, the run key opens a new run.
	ahead.Store(int64(2*time.Hour + 10*time.Minute))
	if status, body := s.tryOpenWith(t, probe, server.LinkRunRequest{}); status != http.StatusOK {
		t.Errorf("past the latest exp held: %d %s", status, body)
	}
}

// TestAHoldThatFailsToWrite pins a write of the refused run keys that fails: the
// failure is reported once, the run key is refused all the same, and the write is tried
// again until it succeeds, on each refused request of the run key, every keepRetry, and
// once more at Close; a write that recovers is reported, and so is a Close that still
// cannot write them, with how many run keys a restart would not refuse.
func TestAHoldThatFailsToWrite(t *testing.T) {
	kept := func(dir string) bool {
		b, err := os.ReadFile(filepath.Join(dir, runcredential.EndedFile))
		return err == nil && strings.Contains(string(b), `"rk-0001"`)
	}
	// failing starts a gateway whose refused run keys cannot be written once a run of
	// rk-0001 is open, and ends that run at the issuer; unblock lets them be written.
	unblock := map[*service]func(){}
	failing := func(retry time.Duration) *service {
		t.Helper()
		in := &introspection{}
		cfg := gateway.Config{Policy: enforce127}
		gateway.SetKeepRetry(&cfg, retry)
		s := startVerifying(t, cfg, in, 0)
		first := credentialFor("rk-0001")
		r := s.openSession(t, first, server.LinkRunRequest{})
		unblock[s] = blockHold(t, s.dir)
		in.end(first)
		status, body := r.reload(t, first, r.a.RunID)
		gone(t, "the issuer's end", status, body, "stopped")
		return s
	}
	refused := func(s *service) {
		t.Helper()
		later := mint(issuerKey(), "rk-0001", time.Now().Add(2*time.Hour), nil)
		s.secrets = append(s.secrets, later)
		if status, body := s.tryOpenWith(t, later, server.LinkRunRequest{}); status != http.StatusUnauthorized {
			t.Errorf("a run request of the run key: %d %s", status, body)
		}
	}
	const line = "keeping the run key of an ended run, for the run credentials of"
	recovered := func(s *service) {
		t.Helper()
		want := "the run keys of ended runs are written to " + filepath.Join(s.dir, runcredential.EndedFile) + " again"
		if got := s.reportsWith("are written to"); len(got) != 1 || got[0] != want {
			t.Errorf("the recovery reported %q, want %q", got, want)
		}
	}

	// Each refused request of the run key tries again.
	s := failing(time.Hour)
	refused(s)
	refused(s)
	if n := len(s.reportsWith(line)); n != 1 {
		t.Errorf("the failure reported %d times", n)
	}
	if kept(s.dir) {
		t.Fatal("kept while the refused run keys cannot be written")
	}
	unblock[s]()
	if s.reported("are written to") {
		t.Error("a recovery reported while the write fails")
	}
	refused(s)
	if !kept(s.dir) {
		t.Error("a refused request did not write the run key")
	}
	recovered(s)

	// Every keepRetry, with no request.
	s = failing(20 * time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	if n := len(s.reportsWith(line)); n != 1 {
		t.Errorf("the failure reported %d times as it was retried", n)
	}
	refused(s)
	unblock[s]()
	eventually(t, "the run key written again", func() bool { return kept(s.dir) })
	eventually(t, "the recovery reported", func() bool { return s.reported("are written to") })
	recovered(s)

	// Once more at Close.
	s = failing(time.Hour)
	unblock[s]()
	if kept(s.dir) {
		t.Fatal("kept before Close")
	}
	s.close()
	if !kept(s.dir) {
		t.Error("Close did not write the run key")
	}
	recovered(s)
	if s.reported("closing with") {
		t.Error("a Close that wrote the run keys reported them not written")
	}

	// A Close that still cannot write them.
	s = failing(time.Hour)
	s.close()
	want := "closing with 1 run keys of ended runs not written to " + filepath.Join(s.dir, runcredential.EndedFile) + ": a restart would not refuse them"
	if got := s.reportsWith("closing with"); len(got) != 1 || got[0] != want {
		t.Errorf("Close reported %q, want %q", got, want)
	}
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
		s := startVerifying(t, cfg, nil, 0)
		cred := credentialFor("rk-0001")
		s.secrets = append(s.secrets, cred)
		runID := event.NewRunID()
		var want []string
		switch slowAt {
		case "registration":
			c.slowFetch.Store(int64(5 * time.Second))
		case "open":
			slowOpen.Store(true)
		}
		impatient := s.client(cred)
		impatient.Timeout = 300 * time.Millisecond
		body, _ := json.Marshal(server.LinkRunRequest{Version: 1, RunID: runID})
		if resp, err := impatient.Post(s.url("/v1/run-configuration"), server.LinkContentType, bytes.NewReader(body)); err == nil {
			resp.Body.Close()
			t.Fatalf("slow at the %s: answered %d", slowAt, resp.StatusCode)
		}
		eventually(t, "the run's record removed", func() bool {
			_, err := os.Stat(filepath.Join(s.dir, "runs", runID))
			return errors.Is(err, fs.ErrNotExist)
		})
		if runs, _, spent, _ := gateway.Held(s.g); runs != 0 || spent != 0 {
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
		r := s.openSession(t, cred, server.LinkRunRequest{RunID: runID})
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
		if status, b := r.reload(t, cred, runID); status != http.StatusOK {
			t.Errorf("slow at the %s: a reload of the retry: %d %s", slowAt, status, b)
		}
		r.post(t, cred, exited(runID))
		s.close()
	}
}

// TestAStateDirectoryThatCannotBeWritten pins Start against a state directory it
// cannot create a file in, though it holds the gateway's authority already: no gateway,
// since it could never keep a run key the issuer ended.
func TestAStateDirectoryThatCannotBeWritten(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a directory of mode 0500")
	}
	dir := t.TempDir()
	certFile, keyFile, _ := testCertificate(t, t.TempDir())
	cfg := gateway.Config{Dir: dir, Listen: "127.0.0.1:0", RunCredentials: realIssuers(t, false), TLS: &gateway.TLS{CertFile: certFile, KeyFile: keyFile}}
	g, err := gateway.Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "authority", "ca.pem")); err != nil {
		t.Fatalf("the authority: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	g, err = gateway.Start(context.Background(), cfg)
	if err == nil {
		g.Close(context.Background())
		t.Fatal("a gateway started on a directory it cannot write")
	}
	if want := "the ended run keys: " + dir + " cannot be written: "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("Start: %v, want %q and the OS error", err, want)
	}
}

// TestCloseCountsTheRunKeysARestartWouldNotRefuse pins the count of Close's report
// when the refused run keys still cannot be written: a run key the file never held
// counts; one the file holds, whose later extension alone failed to write, a restart
// still refuses, and does not count. With only such a run key, Close reports nothing.
func TestCloseCountsTheRunKeysARestartWouldNotRefuse(t *testing.T) {
	for _, neverWritten := range []bool{true, false} {
		in := &introspection{}
		cfg := gateway.Config{Policy: enforce127}
		gateway.SetKeepRetry(&cfg, time.Hour)
		s := startVerifying(t, cfg, in, 0)
		end := func(k string) {
			t.Helper()
			first := mint(issuerKey(), k, time.Now().Add(time.Hour), nil)
			r := s.openSession(t, first, server.LinkRunRequest{})
			in.end(first)
			status, body := r.reload(t, first, r.a.RunID)
			gone(t, "the issuer's end", status, body, "stopped")
		}
		// Written once, while the refused run keys can be written.
		end("rk-0002")
		var never string
		var neverRun *sessionRun
		if neverWritten {
			never = mint(issuerKey(), "rk-0001", time.Now().Add(time.Hour), nil)
			s.secrets = append(s.secrets, never)
			neverRun = s.openSession(t, never, server.LinkRunRequest{})
		}
		blockHold(t, s.dir)
		// Its extension to a later exp fails to write.
		later := mint(issuerKey(), "rk-0002", time.Now().Add(2*time.Hour), nil)
		s.secrets = append(s.secrets, later)
		if status, body := s.tryOpenWith(t, later, server.LinkRunRequest{}); status != http.StatusUnauthorized {
			t.Errorf("a run request of the run key written once: %d %s", status, body)
		}
		if neverWritten {
			// The issuer ends a run of a run key the file never holds.
			in.end(never)
			status, body := neverRun.reload(t, never, neverRun.a.RunID)
			gone(t, "the issuer's end of the run key never written", status, body, "stopped")
		}
		if !s.reported("keeping the run key of an ended run, for the run credentials of") {
			t.Fatal("no write failed")
		}
		s.close()
		got := s.reportsWith("closing with")
		if !neverWritten {
			if len(got) != 0 {
				t.Errorf("Close reported %q with only an extension unwritten", got)
			}
			continue
		}
		want := "closing with 1 run keys of ended runs not written to " + filepath.Join(s.dir, runcredential.EndedFile) + ": a restart would not refuse them"
		if len(got) != 1 || got[0] != want {
			t.Errorf("Close reported %q, want %q", got, want)
		}
	}
}

// TestARequestThatGoesWhileTheIssuerIsAsked pins that only the issuer's answer ends a
// run stopped: a request that goes while the issuer is still being asked
// gets no answer, and the run goes on, its later requests answered as before.
func TestARequestThatGoesWhileTheIssuerIsAsked(t *testing.T) {
	in := &introspection{}
	s := startVerifying(t, gateway.Config{Policy: enforce127}, in, 0)
	cred := credentialFor("rk-0001")
	r := s.openSession(t, cred, server.LinkRunRequest{})
	h := in.hold(cred)
	impatient := s.client(cred)
	impatient.Timeout = 200 * time.Millisecond
	if resp, err := impatient.Get(s.url("/v1/run-configuration/" + r.a.RunID)); err == nil {
		resp.Body.Close()
		t.Fatalf("the request that went: %d", resp.StatusCode)
	}
	<-h.asked
	close(h.release)
	if status, body := r.reload(t, cred, r.a.RunID); status != http.StatusOK {
		t.Errorf("after the request that went: %d %s", status, body)
	}
	s.close()
	for _, l := range s.record(r.a.RunID) {
		if l.Type == event.RunExited {
			t.Errorf("the run ended: %v", l.Data)
		}
	}
}

// TestAnExpiredRunCredentialLearnsItsRunsEnd pins a run credential whose exp has
// passed, under an issuer with no leeway: a reload or a batch of its run that has ended
// gets the 410 of that end, credential_expired; of a run that is live, or of another
// run key's, or with any other request, the discovery and a run request among them, it
// is 401 run_credential_refused, and nothing is served.
func TestAnExpiredRunCredentialLearnsItsRunsEnd(t *testing.T) {
	issuers := realIssuers(t, false)
	none := runcredential.Duration(0)
	issuers[0].Leeway = &none
	s := startVerifying(t, gateway.Config{RunCredentials: issuers, Policy: enforce127}, nil, 0)
	short := mint(issuerKey(), "rk-0001", time.Now().Add(1500*time.Millisecond), nil)
	r := s.openSession(t, short, server.LinkRunRequest{})
	long := mint(issuerKey(), "rk-0002", time.Now().Add(time.Hour), nil)
	other := s.openSession(t, long, server.LinkRunRequest{})
	laterExp := time.Now().Add(1500 * time.Millisecond)
	later := mint(issuerKey(), "rk-0001", laterExp, nil)
	live := s.openSession(t, later, server.LinkRunRequest{})
	if status, body := live.post(t, mint(issuerKey(), "rk-0001", time.Now().Add(time.Hour), nil), heartbeat(live.a.RunID)); status != http.StatusAccepted {
		t.Fatalf("a refreshed run credential of the live run: %d %s", status, body)
	}
	eventually(t, "credential_expired", func() bool {
		rec := s.record(r.a.RunID)
		return rec[len(rec)-1].Type == event.RunExited
	})
	time.Sleep(time.Until(laterExp.Add(time.Second)))
	status, body := r.reload(t, short, r.a.RunID)
	gone(t, "a reload", status, body, "credential_expired")
	status, body = r.post(t, short, heartbeat(r.a.RunID))
	gone(t, "a batch", status, body, "credential_expired")
	for name, req := range map[string]func() (int, []byte){
		"a reload of the live run":      func() (int, []byte) { return live.reload(t, later, live.a.RunID) },
		"a batch of the live run":       func() (int, []byte) { return live.post(t, later, heartbeat(live.a.RunID)) },
		"a reload of another run key's": func() (int, []byte) { return other.reload(t, short, other.a.RunID) },
		"a run request":                 func() (int, []byte) { return s.tryOpenWith(t, short, server.LinkRunRequest{}) },
		"the discovery": func() (int, []byte) {
			resp, b := do(t, s.client(short), http.MethodGet, s.url(server.WellKnown), "", "")
			return resp.StatusCode, b
		},
	} {
		if status, body := req(); status != http.StatusUnauthorized || refusalOf(body)["error"] != "run_credential_refused" {
			t.Errorf("%s: %d %s", name, status, body)
		}
	}
}

// TestARefreshedRunCredentialIsOfTheRunsTarget pins a refreshed run credential of a
// run's run key whose labels or about.details differ from the run's: a reload or a
// batch with it is 403, target_differs_from_credential for the repository and
// differs_from_credential for a detail, each named with the run credential's value, a
// detail it leaves out among them, and the run goes on; a client's connection with it
// is 407.
func TestARefreshedRunCredentialIsOfTheRunsTarget(t *testing.T) {
	o := origin(t)
	s := startVerifying(t, gateway.Config{Policy: enforce127}, nil, 0)
	cred := credentialFor("rk-0001")
	r := s.openSession(t, cred, server.LinkRunRequest{})
	exp := time.Now().Add(2 * time.Hour)
	for _, c := range []struct {
		name, code, names string
		changes           map[string]any
	}{
		{"another repository", "target_differs_from_credential", "[labels.repository=example-namespace/other]", map[string]any{"project": "other"}},
		{"another requester", "differs_from_credential", "[about.details.requester=someone-else]", map[string]any{"requester": "someone-else"}},
		{"no requester", "differs_from_credential", "[about.details.requester=]", map[string]any{"requester": nil}},
	} {
		refreshed := mint(issuerKey(), "rk-0001", exp, c.changes)
		s.secrets = append(s.secrets, refreshed)
		for what, send := range map[string]func() (int, []byte){
			"a reload": func() (int, []byte) { return r.reload(t, refreshed, r.a.RunID) },
			"a batch":  func() (int, []byte) { return r.post(t, refreshed, heartbeat(r.a.RunID)) },
		} {
			status, body := send()
			got := refusalOf(body)
			if status != http.StatusForbidden || got["error"] != c.code || fmt.Sprint(got["names"]) != c.names || got["from"] != "gateway" {
				t.Errorf("%s, %s: %d %s", c.name, what, status, body)
			}
		}
		if status, _, err := get(s.clientWith(credentialFor("rk-0002")), o.URL); err != nil || status != http.StatusOK {
			t.Fatalf("the client's run: %d %v", status, err)
		}
		other := mint(issuerKey(), "rk-0002", exp, c.changes)
		s.secrets = append(s.secrets, other)
		if status, _, err := get(s.clientWith(other), o.URL); err != nil || status != http.StatusProxyAuthRequired {
			t.Errorf("%s, a client's connection: %d %v", c.name, status, err)
		}
	}
	if status, body := r.reload(t, cred, r.a.RunID); status != http.StatusOK {
		t.Errorf("the run after: %d %s", status, body)
	}
}

// TestASessionOnTheOneAddressSaysItsCredentialIsAnIssuers pins the credential of a
// session's run.started on the one address: the run answer says issuer, and a
// run.started that says none is a refused batch, the run ending, batch_refused.
func TestASessionOnTheOneAddressSaysItsCredentialIsAnIssuers(t *testing.T) {
	s := startVerifying(t, gateway.Config{Policy: enforce127}, nil, 0)
	cred := credentialFor("rk-0001")
	s.secrets = append(s.secrets, cred)
	a, _ := s.openWith(t, cred, server.LinkRunRequest{})
	if a.Credential != "starter" {
		t.Errorf("the run answer's credential %q", a.Credential)
	}
	r := &sessionRun{s: s, credential: cred, a: a}
	if status, body := r.post(t, cred, started(a.RunID, a.Labels)); status != http.StatusBadRequest {
		t.Errorf("a run.started that says none: %d %s", status, body)
	}
	status, body := r.reload(t, cred, a.RunID)
	gone(t, "after the refused batch", status, body, "batch_refused")
}
