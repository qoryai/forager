package gateway_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/runcredential"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// The runs of this file are a real session.Run behind a separate gateway: a real
// gateway, gateway.Start, serving its one address on loopback over TLS, with the
// tests' verifier of run credentials, and the session's RemoteGateway pointed at it.

// refreshedCredential is a second run credential of the run key goodCredential is for,
// as an issuer that refreshes it gives one.
const refreshedCredential = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJyay0wMDAxIn0.cmVmcmVzaGVk"

// separate is a gateway serving its one address over TLS, and how a session trusts it.
type separate struct {
	*harness
	caFile, pin string
	pool        *x509.CertPool
	v           *sepVerifier
}

// sepVerifier is the tests' verifier: it records every run credential it is handed, and
// accepts goodCredential and refreshedCredential until refuse is set.
type sepVerifier struct {
	mu     sync.Mutex
	seen   []string
	refuse bool
}

func (v *sepVerifier) authenticate(credential string) (gateway.RunIdentity, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.seen = append(v.seen, credential)
	if v.refuse || (credential != goodCredential && credential != refreshedCredential) {
		return gateway.RunIdentity{}, runcredential.ErrRefused
	}
	return gateway.RunIdentity{RunKey: "rk-0001", Labels: map[string]string{"forge": "example-forge", "repository": "example-namespace/project", "run_key": "rk-0001"}, Expires: time.Now().Add(time.Hour)}, nil
}

func (v *sepVerifier) handed() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return slices.Clone(v.seen)
}

func (v *sepVerifier) refuseFromNow() {
	v.mu.Lock()
	v.refuse = true
	v.mu.Unlock()
}

// startSeparate starts a gateway on 127.0.0.1 over TLS, under an authority of the test's
// own, whose certificate names 127.0.0.1, with the policy and the tests' verifier.
func startSeparate(t *testing.T) *separate {
	t.Helper()
	dir := t.TempDir()
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
	s := &separate{caFile: filepath.Join(dir, "ca.pem"), pin: base64.StdEncoding.EncodeToString(sum[:]), pool: x509.NewCertPool(), v: &sepVerifier{}}
	s.pool.AddCert(ca)
	certFile, keyFile := filepath.Join(dir, "gateway.pem"), filepath.Join(dir, "gateway-key.pem")
	for file, b := range map[string][]byte{
		s.caFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		certFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyFile:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		if err := os.WriteFile(file, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := gateway.Config{Version: "test", Heartbeat: time.Second, Listen: "127.0.0.1:0", RunCredentials: testIssuers,
		TLS:    &gateway.TLS{CertFile: certFile, KeyFile: keyFile},
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example"}}}}
	gateway.SetRunAuth(&cfg, s.v.authenticate)
	s.harness = start(t, cfg)
	s.keep(goodCredential, refreshedCredential, badCredential)
	return s
}

// keep adds secrets no report of the gateway's may hold.
func (s *separate) keep(secrets ...string) {
	s.mu.Lock()
	s.secrets = append(s.secrets, secrets...)
	s.mu.Unlock()
}

// url is the gateway's URL, its one address.
func (s *separate) url() string { return "https://" + s.g.Addr() }

// remote is the session's RemoteGateway of the gateway, with the credential.
func (s *separate) remote(credential func(context.Context) (string, error)) session.RemoteGateway {
	return session.RemoteGateway{URL: s.url(), CAFile: s.caFile, CertificateSHA256: s.pin, Credential: credential}
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

// The agent of these runs is this test binary, run again as TestSeparateAgent: it asks
// for agentURL through the proxy its environment names, and writes the status it got,
// and the user name and password of its proxy URL, to the files the environment names.
const (
	envAgent      = "SEPARATE_TEST_AGENT"
	envAgentURL   = "SEPARATE_TEST_AGENT_URL"
	envAgentOut   = "SEPARATE_TEST_AGENT_OUT"
	envAgentProxy = "SEPARATE_TEST_AGENT_PROXY"
	agentURL      = "http://denied.invalid/a"
)

// TestSeparateAgent is the agent of the runs of this file, when the environment says
// so; otherwise it does nothing.
func TestSeparateAgent(t *testing.T) {
	if os.Getenv(envAgent) == "" {
		return
	}
	code := 0
	defer func() { os.Exit(code) }()
	if u, err := url.Parse(os.Getenv("HTTP_PROXY")); err == nil && u.User != nil {
		password, _ := u.User.Password()
		os.WriteFile(os.Getenv(envAgentProxy), []byte(u.User.Username()+"\n"+password), 0o600)
	}
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true}}
	resp, err := c.Get(os.Getenv(envAgentURL))
	if err != nil {
		os.WriteFile(os.Getenv(envAgentOut), []byte("error: "+err.Error()), 0o600)
		code = 1
		return
	}
	resp.Body.Close()
	os.WriteFile(os.Getenv(envAgentOut), []byte(fmt.Sprint(resp.StatusCode)), 0o600)
}

// agentSpec is a run of the agent behind the gateway.
func agentSpec(t *testing.T, gw session.Gateway) (session.Spec, string, string) {
	t.Helper()
	dir := t.TempDir()
	out, proxyFile := filepath.Join(t.TempDir(), "agent-out"), filepath.Join(t.TempDir(), "agent-proxy")
	// What the session reports to its user, beside the agent's out, reportsOf.
	reports := reportsOf(out)
	if err := os.WriteFile(reports, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("stdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
		}
	})
	return session.Spec{
		Command: os.Args[0], Args: []string{"-test.run=^TestSeparateAgent$"},
		Env: []string{envAgent + "=1", envAgentURL + "=" + agentURL, envAgentOut + "=" + out, envAgentProxy + "=" + proxyFile},
		Dir: dir, RunsDir: filepath.Join(t.TempDir(), "runs"),
		Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
		Gateway: gw, ForagerVersion: "test",
		Labels: map[string]string{"forge": "example-forge", "repository": "example-namespace/project"},
		About:  &session.About{Title: "Example title"},
		Report: func(l string) {
			t.Log("the session reported:", l)
			reportsMu.Lock()
			defer reportsMu.Unlock()
			f, err := os.OpenFile(reports, os.O_APPEND|os.O_WRONLY, 0o600)
			if err == nil {
				fmt.Fprintln(f, l)
				f.Close()
			}
		},
	}, out, proxyFile
}

// reportsMu orders the writes of the sessions' reports.
var reportsMu sync.Mutex

// reportsOf is the file of the lines the session of the agent writing out reported.
func reportsOf(out string) string { return filepath.Join(filepath.Dir(out), "reports") }

// noSecretIn fails the test if a file of the run's holds one of the secrets.
func noSecretIn(t *testing.T, files []string, secrets ...string) {
	t.Helper()
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range secrets {
			if s != "" && bytes.Contains(b, []byte(s)) {
				t.Errorf("%s holds a secret", f)
			}
		}
	}
}

// TestASessionRunsThroughASeparateGateway is a run without a wall behind a separate
// gateway, end to end: discovery, the run request and every batch carry the run
// credential, read from its file before each request, so the refreshed one is sent
// once the issuer replaced it; the agent's request reaches the gateway's proxy over
// TLS through the session's forwarder, with the run's proxy secret as its proxy URL's
// password, and is decided there; the run's labels are the credential's; and neither
// the run credential nor the proxy secret is in a record or a report.
func TestASessionRunsThroughASeparateGateway(t *testing.T) {
	s := startSeparate(t)
	file, read := credentialFile(t, goodCredential)
	sp, out, proxyFile := agentSpec(t, s.remote(read))
	// Once the run is open, the issuer refreshes the run credential.
	sp.OnVariables = func(session.Applied) {
		if err := os.WriteFile(file, []byte(refreshedCredential+"\n"), 0o600); err != nil {
			t.Error(err)
		}
	}
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || res.State != "succeeded" || res.Undelivered != 0 {
		t.Errorf("result %+v", res)
	}
	if b, _ := os.ReadFile(out); string(b) != "403" {
		t.Errorf("the agent's request: %s", b)
	}
	proxy, _ := os.ReadFile(proxyFile)
	user, password, _ := strings.Cut(string(proxy), "\n")
	if user != "qory" || len(password) < 22 || password == goodCredential || password == refreshedCredential {
		t.Errorf("the agent's proxy URL has the user %q and a password of %d characters", user, len(password))
	}
	s.keep(password)
	// The gateway's stream has the run's events as the session posted them.
	s.close()
	numbered := s.record(res.RunID)
	if got := types(numbered); len(got) < 3 || got[0] != "dev.qory.run.started" || got[len(got)-1] != "dev.qory.run.exited" {
		t.Fatalf("the gateway's record %v", got)
	}
	if l := numbered[0].Data["labels"].(map[string]any); l["forge"] != "example-forge" || l["repository"] != "example-namespace/project" {
		t.Errorf("run.started labels %v", l)
	}
	var egress []recorded
	for _, e := range numbered {
		if e.Type == "dev.qory.run.egress" {
			egress = append(egress, e)
		}
	}
	if len(egress) != 1 || egress[0].Data["host"] != "denied.invalid" || egress[0].Data["decision"] != "denied" {
		t.Errorf("run.egress %v", egress)
	}
	// Every request carried the run credential: the first ones the file's first, the
	// batches after the refresh the refreshed one.
	seen := s.v.handed()
	if len(seen) < 3 || seen[0] != goodCredential || seen[1] != goodCredential || seen[len(seen)-1] != refreshedCredential {
		t.Errorf("the credentials the gateway was handed: %d, first %v, last %v", len(seen), seen[:min(2, len(seen))], seen[len(seen)-1:])
	}
	for _, c := range seen {
		if c != goodCredential && c != refreshedCredential {
			t.Errorf("a request carried another credential")
		}
	}
	noSecretIn(t, []string{filepath.Join(res.Dir, "session.jsonl"), filepath.Join(s.dir, "runs", res.RunID, "events.jsonl"), reportsOf(out)}, goodCredential, refreshedCredential, password)
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
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	s := startSeparate(t)
	w := &sepWall{gateway: s.g.Addr(), pool: s.pool}
	sp, out, _ := agentSpec(t, s.remote(func(context.Context) (string, error) { return goodCredential, nil }))
	sp.Wall, sp.Image = w, "registry.example/agents/base:1"
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || res.State != "succeeded" {
		t.Errorf("result %+v", res)
	}
	if b, _ := os.ReadFile(out); string(b) != "403" {
		t.Errorf("the agent's request: %s", b)
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
		if strings.Contains(kv, got.ProxyToken) || strings.Contains(kv, goodCredential) {
			t.Errorf("the enclosure's environment holds a secret: %s", strings.SplitN(kv, "=", 2)[0])
		}
	}
	s.close()
	var egress int
	for _, e := range s.record(res.RunID) {
		if e.Type == "dev.qory.run.egress" && e.Data["host"] == "denied.invalid" && e.Data["decision"] == "denied" {
			egress++
		}
	}
	if egress != 2 {
		t.Errorf("%d requests decided at the gateway, want the probe's and the agent's", egress)
	}
	noSecretIn(t, []string{filepath.Join(res.Dir, "session.jsonl"), filepath.Join(s.dir, "runs", res.RunID, "events.jsonl"), reportsOf(out)}, goodCredential, got.ProxyToken)
}

// TestASeparateGatewaysRefusalsReachTheSession pins the gateway's refusals as the
// session returns them: a run credential refused at discovery is the gateway's 401,
// before anything is recorded; one refused at the run request is the same refusal,
// recorded in the session's record alone as dev.qory.run.refused; and a run id the
// gateway already has is its run_id_used. Each is the gateway's, with its message as
// the error's text word for word, and nothing starts.
func TestASeparateGatewaysRefusalsReachTheSession(t *testing.T) {
	s := startSeparate(t)
	sp, out, _ := agentSpec(t, s.remote(func(context.Context) (string, error) { return badCredential, nil }))
	_, err := session.Run(context.Background(), sp)
	var r *accesskey.Refusal
	if !errors.As(err, &r) || r.Code != refusal.RunCredentialRefused || r.Status != 401 || r.From != accesskey.FromGateway || err.Error() != runcredential.ErrRefused.Error() {
		t.Errorf("a refused credential at discovery: %#v", err)
	}
	if entries, _ := os.ReadDir(sp.RunsDir); len(entries) != 0 {
		t.Errorf("a run directory was made: %v", entries)
	}

	// Accepted at discovery, refused at the run request.
	calls := 0
	sp, out, _ = agentSpec(t, s.remote(func(context.Context) (string, error) {
		calls++
		if calls == 2 {
			s.v.refuseFromNow()
		}
		return goodCredential, nil
	}))
	res, err := session.Run(context.Background(), sp)
	if !errors.As(err, &r) || r.Code != refusal.RunCredentialRefused || r.Status != 401 || r.From != accesskey.FromGateway || err.Error() != runcredential.ErrRefused.Error() || res != nil {
		t.Errorf("a refused credential at the run request: %#v", err)
	}
	entries, _ := os.ReadDir(sp.RunsDir)
	if len(entries) != 1 {
		t.Fatalf("run directories %v", entries)
	}
	own, _ := os.ReadFile(filepath.Join(sp.RunsDir, entries[0].Name(), "session.jsonl"))
	if !bytes.Contains(own, []byte(`"type":"dev.qory.run.refused"`)) || !bytes.Contains(own, []byte(`"code":"run_credential_refused"`)) {
		t.Errorf("the session's record: %s", own)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("the agent started")
	}

	// A run id the gateway already holds.
	s2 := startSeparate(t)
	sp, _, _ = agentSpec(t, s2.remote(func(context.Context) (string, error) { return goodCredential, nil }))
	sp.RunID = "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d"
	if _, err := session.Run(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	sp.RunsDir = filepath.Join(t.TempDir(), "runs")
	_, err = session.Run(context.Background(), sp)
	if !errors.As(err, &r) || r.Code != refusal.RunIDUsed || r.Status != 409 || r.From != accesskey.FromGateway || r.Text == "" || err.Error() != r.Text {
		t.Errorf("a run id the gateway holds: %#v", err)
	}
}

// TestASessionTrustsTheSeparateGatewayItIsTold pins the trust behind a separate
// gateway at the session: without the gateway's authority, or with a pin of another
// key, the run does not start and the gateway is handed no run credential.
func TestASessionTrustsTheSeparateGatewayItIsTold(t *testing.T) {
	s := startSeparate(t)
	cred := func(context.Context) (string, error) { return goodCredential, nil }
	sum := sha256.Sum256([]byte("another key"))
	for name, gw := range map[string]session.RemoteGateway{
		"the system's roots": {URL: s.url(), Credential: cred},
		"another pin":        {URL: s.url(), CAFile: s.caFile, CertificateSHA256: base64.StdEncoding.EncodeToString(sum[:]), Credential: cred},
		"no credential":      {URL: s.url(), CAFile: s.caFile},
	} {
		sp, _, _ := agentSpec(t, gw)
		if _, err := session.Run(context.Background(), sp); err == nil || strings.Contains(err.Error(), goodCredential) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := len(s.v.handed()); n != 0 {
		t.Errorf("the gateway was handed %d run credentials", n)
	}
	gw := s.remote(cred)
	for _, out := range []string{fmt.Sprint(gw), fmt.Sprintf("%#v", gw), fmt.Sprintf("%+v", &gw), gw.String()} {
		if !strings.Contains(out, s.url()) || strings.Contains(out, goodCredential) || strings.Contains(out, "0x") {
			t.Errorf("printed as %s", out)
		}
	}
}
