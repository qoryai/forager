package session_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	refusals "github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/runcredential"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// The runs of this file are a real session.Run behind a separate gateway: a real
// gateway, gateway.Start, serving its one address on loopback over TLS, which verifies
// real run credentials itself, signed with an issuer key the tests make and pin through
// gateway.Config.RunCredentials; and the session's RemoteGateway pointed at it.

// The neutral example issuer of these runs.
const (
	sepIssuer   = "https://issuer.example"
	sepAudience = "qory-gateway"
)

// sepIssuerKey signs the run credentials of these runs, made for this run of the tests,
// so no published fixture key is used; sepOtherKey signs ones no issuer pins.
var (
	sepIssuerKey = sync.OnceValue(newEd25519)
	sepOtherKey  = sync.OnceValue(newEd25519)
)

func newEd25519() ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

// sepIssuers is the example issuer, its key pinned in a PEM file of the test's: the
// scope by namespace, the labels from namespace and project, the detail requester.
func sepIssuers(t *testing.T) runcredential.Issuers {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(sepIssuerKey().Public())
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "issuer-k1.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return runcredential.Issuers{{
		Issuer: sepIssuer, Audience: sepAudience, Algorithms: []string{runcredential.EdDSA},
		Keys:  []runcredential.Key{{KID: "k1", Alg: runcredential.EdDSA, PublicKeyFile: keyFile}},
		Allow: &runcredential.Allow{Claim: "namespace", Values: []string{"example-namespace"}},
		LabelMapping: runcredential.LabelMapping{
			Forge:      runcredential.Source{Value: "example-forge"},
			Repository: runcredential.Source{Claims: []string{"namespace", "project"}, Join: "/"},
			RunKey:     runcredential.Claim{Claim: "sub"},
		},
		DetailMapping: map[string]runcredential.Claim{"requester": {Claim: "requester"}},
	}}
}

// mintCredential is a run credential of the example issuer for the run key, expiring
// at exp, signed by key: the target example-namespace/project, the requester
// example-requester.
func mintCredential(key ed25519.PrivateKey, runKey string, exp time.Time) string {
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": "k1", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{
		"iss": sepIssuer, "aud": sepAudience, "sub": runKey, "iat": time.Now().Unix() - 1, "exp": exp.Unix(),
		"namespace": "example-namespace", "project": "project", "requester": "example-requester",
	})
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(input)))
}

// credentialOf is a good run credential of the run key, for an hour.
func credentialOf(runKey string) string {
	return mintCredential(sepIssuerKey(), runKey, time.Now().Add(time.Hour))
}

// separate is a gateway serving its one address over TLS, and how a session trusts it.
type separate struct {
	g           *gateway.Gateway
	dir         string
	caFile, pin string
	pool        *x509.CertPool

	mu      sync.Mutex
	reports []string
}

// startSeparate starts a gateway on 127.0.0.1 over TLS, under an authority of the test's
// own, whose certificate names 127.0.0.1 alone, with the example issuer and a policy
// that allows api.example alone.
func startSeparate(t *testing.T, issuers ...func(*runcredential.Issuer)) *separate {
	t.Helper()
	certDir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "separate test authority"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "gateway.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"gateway.example"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	s := &separate{dir: t.TempDir(), caFile: filepath.Join(certDir, "ca.pem"), pin: base64.StdEncoding.EncodeToString(sum[:]), pool: x509.NewCertPool()}
	s.pool.AddCert(ca)
	certFile, keyFile := filepath.Join(certDir, "gateway.pem"), filepath.Join(certDir, "gateway-key.pem")
	for file, b := range map[string][]byte{
		s.caFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		certFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyFile:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		if err := os.WriteFile(file, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runCredentials := sepIssuers(t)
	for _, f := range issuers {
		f(&runCredentials[0])
	}
	g, err := gateway.Start(context.Background(), gateway.Config{
		Version: "test", Heartbeat: time.Second, Dir: s.dir,
		Listen: "127.0.0.1:0", TLS: &gateway.TLS{CertFile: certFile, KeyFile: keyFile}, RunCredentials: runCredentials,
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example"}}},
		Report: func(l string) {
			t.Log("the gateway reported:", l)
			s.mu.Lock()
			s.reports = append(s.reports, l)
			s.mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.g = g
	t.Cleanup(func() { s.close(t) })
	return s
}

// close ends the gateway, which numbers each run's last events.
func (s *separate) close(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := s.g.Close(ctx); err != nil {
		t.Errorf("the gateway's close: %v", err)
	}
}

// url is the gateway's URL, its one address.
func (s *separate) url() string { return "https://" + s.g.Addr() }

// remote is the session's RemoteGateway of the gateway, with the credential.
func (s *separate) remote(credential func(context.Context) (string, error)) session.RemoteGateway {
	return session.RemoteGateway{URL: s.url(), CAFile: s.caFile, CertificateSHA256: s.pin, Credential: credential}
}

// record is the gateway's record of a run, its events.jsonl in the gateway's directory.
func (s *separate) record(t *testing.T, runID string) []map[string]any {
	t.Helper()
	return record(t, &session.Result{Dir: filepath.Join(s.dir, "runs", runID)})
}

// runs are the runs the gateway holds a record of.
func (s *separate) runs() []string {
	entries, _ := os.ReadDir(filepath.Join(s.dir, "runs"))
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// noSecretInReports fails the test if a line the gateway reported holds a secret.
func (s *separate) noSecretInReports(t *testing.T, secrets ...string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.reports {
		for _, sec := range secrets {
			if sec != "" && strings.Contains(l, sec) {
				t.Errorf("a report of the gateway's holds a secret: %s", l)
			}
		}
	}
}

// fixedCredential is a run credential that does not change.
func fixedCredential(c string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return c, nil }
}

// credentialFile is a run credential's file, read again on every request, as qory reads
// session.gateway.run_credential_file.
func credentialFile(t *testing.T, credential string) (string, func(context.Context) (string, error)) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "run-credential")
	if err := os.WriteFile(file, []byte(credential), 0o600); err != nil {
		t.Fatal(err)
	}
	return file, func(context.Context) (string, error) {
		b, err := os.ReadFile(file)
		return strings.TrimSpace(string(b)), err
	}
}

// deniedURL is a host the gateway's policy does not allow: a request for it reaches
// the gateway's proxy and is denied there.
const deniedURL = "http://denied.invalid/a"

// sepRun is a run of the fake runtime behind the gateway: it writes its environment to
// envFile and asks for deniedURL through its proxy; what the session reported is in
// reports.
type sepRun struct {
	sp      session.Spec
	envFile string
	stderr  *syncBuffer

	mu      sync.Mutex
	reports []string
}

func newSepRun(t *testing.T, gw session.Gateway) *sepRun {
	t.Helper()
	r := &sepRun{envFile: filepath.Join(t.TempDir(), "env"), stderr: &syncBuffer{}}
	stdout := &syncBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("stdout:\n%s\nstderr:\n%s", stdout.String(), r.stderr.String())
		}
	})
	r.sp = session.Spec{
		Command: "/bin/sh", Args: []string{"-c", `env > "$0"; exec "$1"`, r.envFile, os.Args[0]},
		Env: []string{"FAKE_RUNTIME=1", "FAKE_EXIT=0", "FAKE_DENIED_URL=" + deniedURL, "PATH=" + os.Getenv("PATH")},
		Dir: t.TempDir(), RunsDir: filepath.Join(t.TempDir(), "runs"),
		Stdin: strings.NewReader(""), Stdout: stdout, Stderr: r.stderr,
		Gateway: gw, ForagerVersion: "test",
		Labels: map[string]string{"forge": "example-forge", "repository": "example-namespace/project"},
		About:  &session.About{Title: "Example title"},
		Report: func(l string) {
			t.Log("the session reported:", l)
			r.mu.Lock()
			r.reports = append(r.reports, l)
			r.mu.Unlock()
		},
	}
	return r
}

// env is the runtime's environment as it wrote it.
func (r *sepRun) env(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(r.envFile)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			out[k] = v
		}
	}
	return out
}

// noSecretIn fails the test if the session's record, the gateway's record of the run,
// or a line either reported holds one of the secrets.
func (r *sepRun) noSecretIn(t *testing.T, s *separate, runID string, secrets ...string) {
	t.Helper()
	for _, f := range []string{filepath.Join(r.sp.RunsDir, runID, "session.jsonl"), filepath.Join(s.dir, "runs", runID, "events.jsonl")} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, sec := range secrets {
			if sec != "" && bytes.Contains(b, []byte(sec)) {
				t.Errorf("%s holds a secret", f)
			}
		}
	}
	r.mu.Lock()
	for _, l := range r.reports {
		for _, sec := range secrets {
			if sec != "" && strings.Contains(l, sec) {
				t.Errorf("a report of the session's holds a secret: %s", l)
			}
		}
	}
	r.mu.Unlock()
	s.noSecretInReports(t, secrets...)
}

// denied counts the run.egress events of the gateway's record that deny host.
func denied(rec []map[string]any, host string) int {
	n := 0
	for _, e := range ofType(rec, "dev.qory.run.egress") {
		if data(e)["host"] == host && data(e)["decision"] == "denied" {
			n++
		}
	}
	return n
}

// TestASessionRunsThroughASeparateGateway is a run without a wall behind a separate
// gateway, end to end, on a real run credential: discovery, the run request and every
// batch carry it, read from its file; the run's labels and details are the
// credential's; the agent's request reaches the gateway's proxy over TLS through the
// session's forwarder, with the run's proxy secret as its proxy URL's password, and is
// denied there; the agent's environment holds no QORY_RUN_CREDENTIAL_SECRET, though the
// session's did; and neither the run credential nor the proxy secret is in a record or
// a report.
func TestASessionRunsThroughASeparateGateway(t *testing.T) {
	s := startSeparate(t)
	first := credentialOf("rk-0001")
	_, read := credentialFile(t, first)
	r := newSepRun(t, s.remote(read))
	// The variable qory may read the run credential from, left in the session's own
	// environment: the agent's has none of it.
	r.sp.Env = append(r.sp.Env, "QORY_RUN_CREDENTIAL_SECRET="+first)
	res, err := session.Run(context.Background(), r.sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || res.State != "succeeded" || res.Undelivered != 0 || res.RunClosed {
		t.Errorf("result %+v", res)
	}
	if !strings.Contains(r.stderr.String(), "get "+deniedURL+": 403") {
		t.Errorf("the agent's request: %s", r.stderr.String())
	}
	env := r.env(t)
	proxy, err := url.Parse(env["HTTP_PROXY"])
	if err != nil || proxy.User == nil {
		t.Fatalf("the agent's proxy URL: %v", err)
	}
	password, _ := proxy.User.Password()
	host, _, _ := net.SplitHostPort(proxy.Host)
	if proxy.Scheme != "http" || host != "127.0.0.1" || proxy.User.Username() != "qory" || link.CheckSecret(password) != nil || len(password) < 22 {
		t.Errorf("the agent's proxy URL is %s on %s, user %q, a password of %d characters", proxy.Scheme, proxy.Host, proxy.User.Username(), len(password))
	}
	if _, ok := env["QORY_RUN_CREDENTIAL_SECRET"]; ok {
		t.Error("the agent's environment holds QORY_RUN_CREDENTIAL_SECRET")
	}
	for k, v := range env {
		if strings.Contains(v, first) {
			t.Errorf("the agent's %s holds the run credential", k)
		}
	}
	own := events(t, res)
	started := ofType(own, "dev.qory.run.started")
	if len(started) != 1 || fmt.Sprint(data(started[0])["labels"]) != "map[forge:example-forge repository:example-namespace/project run_key:rk-0001]" {
		t.Errorf("run.started %v", started)
	}
	if about := data(started[0])["about"].(map[string]any); fmt.Sprint(about["details"]) != "map[requester:example-requester]" {
		t.Errorf("run.started about %v", about)
	}
	if c := data(started[0])["credential"]; c != "issuer" {
		t.Errorf("run.started credential %v; want issuer behind a separate gateway", c)
	}
	s.close(t)
	numbered := s.record(t, res.RunID)
	if got := types(numbered); len(got) < 3 || got[0] != "dev.qory.run.started" || got[len(got)-1] != "dev.qory.run.exited" {
		t.Fatalf("the gateway's record %v", got)
	}
	if denied(numbered, "denied.invalid") != 1 {
		t.Errorf("run.egress %v", ofType(numbered, "dev.qory.run.egress"))
	}
	if !slices.Equal(types(own), ofTypes(numbered, types(own))) {
		t.Errorf("the session recorded %v, the gateway numbered %v", types(own), types(numbered))
	}
	r.noSecretIn(t, s, res.RunID, first, password)
}

// TestTheRefreshedRunCredentialCarriesTheRun pins the refresh: a run whose first run
// credential expires while it runs goes on with the one its issuer refreshed in the
// file, which the session sends from then on; without a fresh one it would have ended
// at the first's exp.
func TestTheRefreshedRunCredentialCarriesTheRun(t *testing.T) {
	s := startSeparate(t)
	first := mintCredential(sepIssuerKey(), "rk-0001", time.Now().Add(2*time.Second))
	refreshed := credentialOf("rk-0001")
	file, read := credentialFile(t, first)
	r := newSepRun(t, s.remote(read))
	r.sp.Args = []string{"-c", "sleep 4"}
	r.sp.OnVariables = func(session.Applied) {
		if err := os.WriteFile(file, []byte(refreshed), 0o600); err != nil {
			t.Error(err)
		}
	}
	res, err := session.Run(context.Background(), r.sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.RunClosed || res.State != "succeeded" || res.ExitCode != 0 {
		t.Errorf("result %+v", res)
	}
}

// TestARunCredentialThatExpiresEndsTheRun pins credential_expired end to end: with no
// fresh run credential by its exp, the gateway ends the run, and the session, at its
// next request's 410, stops the runtime as at its time limit and records its own
// run.exited with credential_expired, the run closed by the gateway.
func TestARunCredentialThatExpiresEndsTheRun(t *testing.T) {
	s := startSeparate(t)
	cred := mintCredential(sepIssuerKey(), "rk-0001", time.Now().Add(2*time.Second))
	r := newSepRun(t, s.remote(fixedCredential(cred)))
	r.sp.Args = []string{"-c", "sleep 30"}
	start := time.Now()
	res, err := session.Run(context.Background(), r.sp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.RunClosed || res.ClosedBy != accesskey.FromGateway || res.ClosedReason != "credential_expired" || res.State != "failed" || time.Since(start) > 20*time.Second {
		t.Errorf("result %+v after %s", res, time.Since(start))
	}
	own := events(t, res)
	exited := ofType(own, "dev.qory.run.exited")
	if len(exited) != 1 || data(exited[0])["reason"] != "credential_expired" {
		t.Errorf("the session's run.exited %v", exited)
	}
	s.close(t)
	rec := s.record(t, res.RunID)
	if last := rec[len(rec)-1]; last["type"] != "dev.qory.run.exited" || data(last)["reason"] != "credential_expired" {
		t.Errorf("the gateway's record ends %v", last)
	}
	r.noSecretIn(t, s, res.RunID, cred)
}

// TestARunCredentialThatExpiresWithNoLeewayEndsTheRun pins credential_expired end to
// end under an issuer with no leeway, whose run credential the gateway no longer
// accepts from its exp on: the session's next request after the end still gets the
// 410 credential_expired, and the session stops as at any other end of the gateway's.
func TestARunCredentialThatExpiresWithNoLeewayEndsTheRun(t *testing.T) {
	none := runcredential.Duration(0)
	s := startSeparate(t, func(i *runcredential.Issuer) { i.Leeway = &none })
	cred := mintCredential(sepIssuerKey(), "rk-0001", time.Now().Add(2*time.Second))
	r := newSepRun(t, s.remote(fixedCredential(cred)))
	r.sp.Args = []string{"-c", "sleep 30"}
	start := time.Now()
	res, err := session.Run(context.Background(), r.sp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.RunClosed || res.ClosedBy != accesskey.FromGateway || res.ClosedReason != "credential_expired" || res.State != "failed" || time.Since(start) > 20*time.Second {
		t.Errorf("result %+v after %s", res, time.Since(start))
	}
	if exited := ofType(events(t, res), "dev.qory.run.exited"); len(exited) != 1 || data(exited[0])["reason"] != "credential_expired" {
		t.Errorf("the session's run.exited %v", exited)
	}
	r.noSecretIn(t, s, res.RunID, cred)
}

// TestASeparateGatewaysCloseCarriesItsCause pins the gateway's own end of a session's
// run on the one address, over TLS: a session it hears nothing from for three heartbeat
// intervals gets a 410 session_lost, and one whose batch it refused a 410
// batch_refused. The session stops the runtime, its result says the gateway closed the
// run with that code, and its record ends with run.exited of that reason, while the
// gateway's says session_lost for both.
func TestASeparateGatewaysCloseCarriesItsCause(t *testing.T) {
	for _, cause := range []string{"session_lost", "batch_refused"} {
		t.Run(cause, func(t *testing.T) {
			s := startSeparate(t)
			cred := credentialOf("rk-0001")
			// While shut, the session's requests wait for their run credential, and so
			// send nothing.
			var shut sync.RWMutex
			r := newSepRun(t, s.remote(func(context.Context) (string, error) {
				shut.RLock()
				defer shut.RUnlock()
				return cred, nil
			}))
			r.sp.Args = []string{"-c", "sleep 30"}
			r.sp.StopGrace = time.Second
			r.sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
			own := &session.Result{Dir: filepath.Join(r.sp.RunsDir, r.sp.RunID)}
			going := func() bool {
				_, err := os.Stat(filepath.Join(own.Dir, "session.jsonl"))
				return err == nil && len(ofType(events(t, own), "dev.qory.run.heartbeat")) > 0
			}
			ended := func() bool {
				_, err := os.Stat(filepath.Join(s.dir, "runs", r.sp.RunID, "events.jsonl"))
				return err == nil && len(ofType(s.record(t, r.sp.RunID), "dev.qory.run.exited")) > 0
			}
			go func() {
				waitFor(t, going)
				if cause == "session_lost" {
					shut.Lock()
					defer shut.Unlock()
					waitFor(t, ended)
					return
				}
				// A batch of the run's the gateway refuses: a ping, which the gateway
				// alone writes.
				body, _ := json.Marshal([]map[string]any{{
					"specversion": "1.0", "id": event.NewID(), "source": event.Source(r.sp.RunID), "type": event.Ping, "subject": r.sp.RunID,
					"time": time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00"), "dataschema": event.DataSchema(event.Ping),
					"data": map[string]any{"forager_version": "x", "events": []string{"*"}, "contract_version": 1, "interval_seconds": 30},
				}})
				req, _ := http.NewRequest(http.MethodPost, s.url()+"/v1/events", bytes.NewReader(body))
				req.Header.Set("Content-Type", server.ContentType)
				req.Header.Set("Authorization", link.BearerScheme+" "+cred)
				c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.pool, MinVersion: tls.VersionTLS13}}}
				resp, err := c.Do(req)
				if err != nil {
					t.Error(err)
					return
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusBadRequest {
					t.Errorf("the refused batch: %d", resp.StatusCode)
				}
			}()
			start := time.Now()
			res, err := session.Run(context.Background(), r.sp)
			if err != nil {
				t.Fatal(err)
			}
			if !res.RunClosed || res.ClosedBy != accesskey.FromGateway || res.ClosedReason != cause || res.State != "failed" || res.TimedOut || time.Since(start) > 20*time.Second {
				t.Errorf("result %+v after %s", res, time.Since(start))
			}
			if exited := ofType(events(t, res), "dev.qory.run.exited"); len(exited) != 1 || data(exited[0])["reason"] != cause {
				t.Errorf("the session's run.exited %v", exited)
			}
			s.close(t)
			rec := s.record(t, res.RunID)
			if last := rec[len(rec)-1]; last["type"] != "dev.qory.run.exited" || data(last)["reason"] != "session_lost" {
				t.Errorf("the gateway's record ends %v", last)
			}
			r.noSecretIn(t, s, res.RunID, cred)
		})
	}
}

// sepWall is a wall with a relay, for a run behind a separate gateway: the launch
// reaches the session's forwarder through a listener of the test's that opens every
// connection with the token the session gave the wall, as the wall's relay does. While
// it wraps the launch it checks that the token opens nothing at the gateway itself, and
// that the forwarder refuses a connection without it.
type sepWall struct {
	gateway string
	pool    *x509.CertPool

	mu     sync.Mutex
	got    wall.Launch
	probes []string
	ln     net.Listener
}

func (w *sepWall) Name() string                                                  { return "test" }
func (w *sepWall) Prepare(context.Context, wall.Request) (wall.Enclosure, error) { return w, nil }
func (w *sepWall) ProxyAddr() string                                             { return "127.0.0.1:0" }
func (w *sepWall) Close(context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ln != nil {
		w.ln.Close()
	}
	return nil
}

// probe is what a connection that opens with open and a proxy request gets back: the
// first line of an answer, or "closed" when it gets none.
func probe(c net.Conn, open string) string {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, open+"GET http://denied.invalid/b HTTP/1.1\r\nHost: denied.invalid\r\n\r\n")
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil && line == "" {
		return "closed"
	}
	return strings.TrimSpace(line)
}

func (w *sepWall) Wrap(_ context.Context, l wall.Launch) (wall.Launch, error) {
	relayed := link.Preamble(link.RelayPreamble, l.ProxyToken)
	// The token at the gateway itself, inside TLS, as a relay's secret.
	tc, err := tls.Dial("tcp", w.gateway, &tls.Config{RootCAs: w.pool, MinVersion: tls.VersionTLS13, ServerName: "127.0.0.1"})
	if err != nil {
		return wall.Launch{}, err
	}
	atGateway := probe(tc, relayed)
	// The forwarder without the token, and with it.
	var withoutToken, withToken string
	if c, err := net.Dial("tcp", l.Proxy); err == nil {
		withoutToken = probe(c, link.Preamble(link.RelayPreamble, strings.Repeat("x", 43)))
	}
	if c, err := net.Dial("tcp", l.Proxy); err == nil {
		withToken = probe(c, relayed)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return wall.Launch{}, err
	}
	w.mu.Lock()
	w.got, w.ln, w.probes = l, ln, []string{atGateway, withoutToken, withToken}
	w.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				up, err := net.Dial("tcp", l.Proxy)
				if err != nil {
					return
				}
				defer up.Close()
				io.WriteString(up, relayed)
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	env := append(slices.Clone(l.Env), link.ProxyEnv("http://"+ln.Addr().String())...)
	return wall.Launch{Command: l.Command, Args: l.Args, Env: env, Dir: l.Dir}, nil
}

// TestAWalledSessionRunsThroughASeparateGateway is a walled run behind a separate
// gateway: the wall's relay opens every connection to the session's forwarder with a
// token of the forwarder's own, which opens nothing at the gateway, and the forwarder,
// which refuses a connection without it, carries the connection to the gateway's one
// address over TLS with the run's proxy secret; the agent's request is decided there.
func TestAWalledSessionRunsThroughASeparateGateway(t *testing.T) {
	s := startSeparate(t)
	w := &sepWall{gateway: s.g.Addr(), pool: s.pool}
	cred := credentialOf("rk-0001")
	r := newSepRun(t, s.remote(fixedCredential(cred)))
	r.sp.Wall, r.sp.Image = w, "registry.example/agents/base:1"
	res, err := session.Run(context.Background(), r.sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || res.State != "succeeded" {
		t.Errorf("result %+v", res)
	}
	if !strings.Contains(r.stderr.String(), "get "+deniedURL+": 403") {
		t.Errorf("the agent's request: %s", r.stderr.String())
	}
	w.mu.Lock()
	got, probes := w.got, w.probes
	w.mu.Unlock()
	if probes[0] != "closed" || probes[1] != "closed" || !strings.HasPrefix(probes[2], "HTTP/1.1 403") {
		t.Errorf("the token at the gateway, the forwarder without it and with it: %q", probes)
	}
	if err := link.CheckSecret(got.ProxyToken); err != nil || len(got.ProxyToken) < 22 {
		t.Errorf("the relay's token: %v", err)
	}
	for _, kv := range got.Env {
		if strings.Contains(kv, got.ProxyToken) || strings.Contains(kv, cred) {
			t.Errorf("the enclosure's environment holds a secret: %s", strings.SplitN(kv, "=", 2)[0])
		}
	}
	s.close(t)
	if n := denied(s.record(t, res.RunID), "denied.invalid"); n != 2 {
		t.Errorf("%d requests decided at the gateway, want the probe's and the agent's", n)
	}
	r.noSecretIn(t, s, res.RunID, cred, got.ProxyToken)
}

// refusedRun runs r, which the gateway refuses, and returns the refusal: the gateway's,
// with its message as the error's text word for word, recorded as dev.qory.run.refused
// in the session's record alone when the run request was refused, the runtime never
// started.
func refusedRun(t *testing.T, r *sepRun) *session.Refusal {
	t.Helper()
	res, err := session.Run(context.Background(), r.sp)
	var ref *session.Refusal
	if !errors.As(err, &ref) || res != nil {
		t.Fatalf("a refused run: %v %+v", err, res)
	}
	if ref.From != accesskey.FromGateway || ref.Text == "" || err.Error() != ref.Text {
		t.Errorf("the refusal %#v, its text %q", ref, err.Error())
	}
	if _, err := os.Stat(r.envFile); err == nil {
		t.Error("the runtime started")
	}
	return ref
}

// refusedRecord is the session's dev.qory.run.refused of the one run of r.
func refusedRecord(t *testing.T, r *sepRun) map[string]any {
	t.Helper()
	entries, _ := os.ReadDir(r.sp.RunsDir)
	if len(entries) != 1 {
		t.Fatalf("run directories %v", entries)
	}
	got := events(t, &session.Result{Dir: filepath.Join(r.sp.RunsDir, entries[0].Name())})
	refused := ofType(got, "dev.qory.run.refused")
	if len(refused) != 1 || len(got) != 1 {
		t.Fatalf("the session's record %v", types(got))
	}
	return data(refused[0])
}

// TestASeparateGatewayRefusesARunDifferentFromItsCredential pins the checkout's match
// with the run credential end to end: a repository other than the credential's is
// target_differs_from_credential, a detail the mapping sets with another value
// differs_from_credential, each a 403 from the gateway naming the member and the
// credential's value; nothing opens at the gateway.
func TestASeparateGatewayRefusesARunDifferentFromItsCredential(t *testing.T) {
	s := startSeparate(t)
	cred := credentialOf("rk-0001")
	r := newSepRun(t, s.remote(fixedCredential(cred)))
	r.sp.Labels["repository"] = "example-namespace/other"
	ref := refusedRun(t, r)
	if ref.Code != refusals.TargetDiffersFromCredential || ref.Status != 403 || fmt.Sprint(ref.Names) != "[labels.repository=example-namespace/project]" {
		t.Errorf("another repository: %#v", ref)
	}
	if got := refusedRecord(t, r); got["code"] != "target_differs_from_credential" || fmt.Sprint(got["names"]) != "[labels.repository=example-namespace/project]" {
		t.Errorf("its record %v", got)
	}

	r = newSepRun(t, s.remote(fixedCredential(credentialOf("rk-0002"))))
	r.sp.About.Details = json.RawMessage(`{"requester":"someone-else"}`)
	ref = refusedRun(t, r)
	if ref.Code != refusals.DiffersFromCredential || ref.Status != 403 || fmt.Sprint(ref.Names) != "[about.details.requester=example-requester]" {
		t.Errorf("another requester: %#v", ref)
	}
	if got := refusedRecord(t, r); got["code"] != "differs_from_credential" {
		t.Errorf("its record %v", got)
	}
	if runs := s.runs(); len(runs) != 0 {
		t.Errorf("the gateway opened %v", runs)
	}
	s.noSecretInReports(t, cred)
}

// TestASeparateGatewaysCredentialRefusalsReachTheSession pins run_credential_refused
// end to end: a run credential no pinned key signed is the gateway's 401 with the text
// qory gives, word for word, and the run never starts. The gateway tracks run keys and
// does not require them to be unique: a session of a run key whose run ended opens a
// run of its own.
func TestASeparateGatewaysCredentialRefusalsReachTheSession(t *testing.T) {
	s := startSeparate(t)
	forged := mintCredential(sepOtherKey(), "rk-0001", time.Now().Add(time.Hour))
	ref := refusedRun(t, newSepRun(t, s.remote(fixedCredential(forged))))
	if ref.Code != refusals.RunCredentialRefused || ref.Status != 401 || ref.Text != runcredential.ErrRefused.Error() {
		t.Errorf("a credential no pinned key signed: %#v", ref)
	}

	cred := credentialOf("rk-0003")
	if _, err := session.Run(context.Background(), newSepRun(t, s.remote(fixedCredential(cred))).sp); err != nil {
		t.Fatal(err)
	}
	// The same run key again, a session with a new run id: a run of its own.
	if _, err := session.Run(context.Background(), newSepRun(t, s.remote(fixedCredential(cred))).sp); err != nil {
		t.Errorf("a run key whose run ended: %v", err)
	}
	if runs := s.runs(); len(runs) != 2 {
		t.Errorf("the gateway's runs %v", runs)
	}
	s.noSecretInReports(t, forged, cred)
}

// TestARunIDTheSeparateGatewayHoldsIsRefused pins run_id_used end to end: a run id the
// gateway already has a run of is its 409, for a run credential of another run key.
func TestARunIDTheSeparateGatewayHoldsIsRefused(t *testing.T) {
	s := startSeparate(t)
	r := newSepRun(t, s.remote(fixedCredential(credentialOf("rk-0001"))))
	r.sp.RunID = "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d"
	if _, err := session.Run(context.Background(), r.sp); err != nil {
		t.Fatal(err)
	}
	again := newSepRun(t, s.remote(fixedCredential(credentialOf("rk-0002"))))
	again.sp.RunID = r.sp.RunID
	if ref := refusedRun(t, again); ref.Code != refusals.RunIDUsed || ref.Status != 409 {
		t.Errorf("a run id the gateway holds: %#v", ref)
	}
}

// TestASessionTrustsTheSeparateGatewayItIsTold pins the trust behind a separate
// gateway at the session: without the gateway's authority, or with a pin of another
// key, the run does not start and the gateway opens nothing; without a run credential
// it is no run; and a RemoteGateway prints by its URL, never its run credential.
func TestASessionTrustsTheSeparateGatewayItIsTold(t *testing.T) {
	s := startSeparate(t)
	cred := credentialOf("rk-0001")
	sum := sha256.Sum256([]byte("another key"))
	for name, gw := range map[string]session.RemoteGateway{
		"the system's roots": {URL: s.url(), Credential: fixedCredential(cred)},
		"another pin":        {URL: s.url(), CAFile: s.caFile, CertificateSHA256: base64.StdEncoding.EncodeToString(sum[:]), Credential: fixedCredential(cred)},
		"no credential":      {URL: s.url(), CAFile: s.caFile},
	} {
		if _, err := session.Run(context.Background(), newSepRun(t, gw).sp); err == nil || strings.Contains(err.Error(), cred) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if runs := s.runs(); len(runs) != 0 {
		t.Errorf("the gateway opened %v", runs)
	}
	gw := s.remote(fixedCredential(cred))
	for _, out := range []string{fmt.Sprint(gw), fmt.Sprintf("%#v", gw), fmt.Sprintf("%+v", &gw), gw.String()} {
		if !strings.Contains(out, s.url()) || strings.Contains(out, cred) || strings.Contains(out, "0x") {
			t.Errorf("printed as %s", out)
		}
	}
	// A URL the session refuses prints by its origin alone, nothing after it or before
	// its host.
	for raw, want := range map[string]string{
		"https://user:pw-of-the-url@gateway.example:8443/path?q=query-of-the-url#fragment-of-the-url": "session.RemoteGateway{https://gateway.example:8443}",
		"gateway.example/path-of-the-url": "session.RemoteGateway{(not a URL)}",
		"":                                "session.RemoteGateway{(no URL)}",
	} {
		if got := (session.RemoteGateway{URL: raw}).String(); got != want {
			t.Errorf("%q prints as %s", raw, got)
		}
	}
}

// TestTheRemoteLinkNarrowsTheRunAtARealGateway pins a narrowing against a real
// separate gateway, through the session's client of its link, since a Spec carries
// none: the run answer's policy is the gateway's narrowed by it.
func TestTheRemoteLinkNarrowsTheRunAtARealGateway(t *testing.T) {
	s := startSeparate(t)
	cred := credentialOf("rk-0001")
	k, err := server.NewRemoteLink(s.url(), server.RemoteTLS{CAFile: s.caFile, CertificateSHA256: s.pin}, fixedCredential(cred), accesskey.UserAgent("test"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	d, err := k.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a, err := k.OpenRun(context.Background(), d.Run.URL, server.LinkRunRequest{
		RunID: "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9e", Labels: map[string]string{"forge": "example-forge", "repository": "example-namespace/project"},
		Narrowing: &server.LinkNarrowing{Egress: server.LinkNarrowingEgress{Deny: []string{"tracker.example"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Egress struct {
			Mode        string
			Allow, Deny []string
		}
	}
	if err := json.Unmarshal(a.Policy, &p); err != nil || p.Egress.Mode != "enforce" || !slices.Equal(p.Egress.Allow, []string{"api.example"}) || !slices.Equal(p.Egress.Deny, []string{"tracker.example"}) || a.Digest == "" {
		t.Errorf("the policy %s %s %v", a.Policy, a.Digest, err)
	}
	if fmt.Sprint(a.Labels) != "map[forge:example-forge repository:example-namespace/project run_key:rk-0001]" {
		t.Errorf("the run's labels %v", a.Labels)
	}
	s.noSecretInReports(t, cred, a.ProxySecret)
}
