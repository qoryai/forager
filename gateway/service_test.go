package gateway_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
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
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/runcredential"
	"github.com/qoryai/forager/server"
)

// testIssuers are issuers of run credentials, neutral examples: Start checks only that
// there are some, and the tests' verifier decides every run credential.
var testIssuers = runcredential.Issuers{{Issuer: "https://issuer.example", Audience: "qory-gateway"}}

// The run credentials of the tests' verifier: good opens a run of rk-0001, other one
// of rk-0003, any other is refused.
const (
	goodCredential  = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJyay0wMDAxIn0.c2lnbmF0dXJl"
	badCredential   = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJyay0wMDAyIn0.c2lnbmF0dXJl"
	otherCredential = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJyay0wMDAzIn0.c2lnbmF0dXJl"
)

// testCertificate writes a certificate for 127.0.0.1, ::1 and localhost, and its key,
// into dir, signed by an authority of the test's own, which pool trusts.
func testCertificate(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test authority"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "gateway.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost", "gateway.example"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "gateway.pem"), filepath.Join(dir, "gateway-key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(ca)
	return certFile, keyFile, pool
}

// verifier is the tests' run credential verifier: it records every credential it is
// handed and accepts goodCredential alone.
type verifier struct {
	mu   sync.Mutex
	seen []string
}

func (v *verifier) authenticate(credential string) (gateway.RunIdentity, error) {
	v.mu.Lock()
	v.seen = append(v.seen, credential)
	v.mu.Unlock()
	runKey := map[string]string{goodCredential: "rk-0001", otherCredential: "rk-0003"}[credential]
	if runKey == "" {
		return gateway.RunIdentity{}, runcredential.ErrRefused
	}
	return gateway.RunIdentity{Issuer: "https://issuer.example", RunKey: runKey, Labels: map[string]string{"forge": "example-forge", "repository": "example-namespace/project", "run_key": runKey}, Expires: time.Now().Add(time.Hour)}, nil
}

func (v *verifier) handed() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return slices.Clone(v.seen)
}

// service is a gateway serving its one address, with the harness of its local link.
type service struct {
	*harness
	pool *x509.CertPool
	v    *verifier
}

// startService starts a gateway on 127.0.0.1, over TLS unless plain, with the tests'
// verifier; cfg's Policy and the like are kept.
func startService(t *testing.T, cfg gateway.Config, plain bool) *service {
	t.Helper()
	s := &service{v: &verifier{}}
	cfg.Listen = "127.0.0.1:0"
	cfg.RunCredentials = testIssuers
	if !plain {
		certFile, keyFile, pool := testCertificate(t, t.TempDir())
		cfg.TLS = &gateway.TLS{CertFile: certFile, KeyFile: keyFile}
		s.pool = pool
	}
	gateway.SetRunAuth(&cfg, s.v.authenticate)
	s.harness = start(t, cfg)
	s.secrets = append(s.secrets, goodCredential, badCredential, otherCredential)
	return s
}

// scheme is the origin's scheme of the one address.
func (s *service) scheme() string {
	if s.pool == nil {
		return "http"
	}
	return "https"
}

// tlsConfig is the client's TLS toward the one address.
func (s *service) tlsConfig() *tls.Config {
	return &tls.Config{RootCAs: s.pool, MinVersion: tls.VersionTLS13, ServerName: "127.0.0.1"}
}

// dial opens a connection to the one address, through TLS when it has it.
func (s *service) dial(t *testing.T) net.Conn {
	t.Helper()
	if s.pool == nil {
		c, err := net.Dial("tcp", s.g.Addr())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c, err := tls.Dial("tcp", s.g.Addr(), s.tlsConfig())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// bearerTransport sets a run credential on every request.
type bearerTransport struct {
	credential string
	next       http.RoundTripper
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.credential != "" {
		r.Header.Set("Authorization", "Bearer "+b.credential)
	}
	return b.next.RoundTrip(r)
}

// client is a session's client of the contract on the one address, a plain net/http
// client trusting the gateway's certificate, with the run credential on every request.
func (s *service) client(credential string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: bearerTransport{credential: credential, next: &http.Transport{TLSClientConfig: s.tlsConfig(), Proxy: nil}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// url is the URL of path on the one address.
func (s *service) url(path string) string { return s.scheme() + "://" + s.g.Addr() + path }

// do sends a request to the one address and returns the answer and its body.
func do(t *testing.T, c *http.Client, method, u, contentType, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, u, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

// openOver opens a run on the one address with the good run credential.
func (s *service) openOver(t *testing.T, req server.LinkRunRequest) (*server.LinkRunAnswer, http.Header) {
	t.Helper()
	return s.openWith(t, goodCredential, req)
}

// openWith opens a run on the one address with the run credential given.
func (s *service) openWith(t *testing.T, credential string, req server.LinkRunRequest) (*server.LinkRunAnswer, http.Header) {
	t.Helper()
	req.Version = 1
	if req.RunID == "" {
		req.RunID = event.NewRunID()
	}
	body, _ := json.Marshal(req)
	resp, b := do(t, s.client(credential), http.MethodPost, s.url("/v1/run-configuration"), server.LinkContentType, string(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the run request: %d %s", resp.StatusCode, b)
	}
	var a server.LinkRunAnswer
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.secrets = append(s.secrets, a.ProxySecret)
	s.mu.Unlock()
	return &a, resp.Header
}

// postOver posts one batch of a run's events on the one address, with the good run
// credential.
func (s *service) postOver(t *testing.T, evs ...map[string]any) int {
	t.Helper()
	return s.postWith(t, goodCredential, evs...)
}

// postWith posts one batch of a run's events on the one address, with the run
// credential given.
func (s *service) postWith(t *testing.T, credential string, evs ...map[string]any) int {
	t.Helper()
	body, _ := json.Marshal(evs)
	resp, b := do(t, s.client(credential), http.MethodPost, s.url("/v1/events"), server.ContentType, string(body))
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("a batch: %d %s", resp.StatusCode, b)
	}
	return resp.StatusCode
}

// relayOver is a client whose every connection goes to the one address, through TLS
// when it has it, opening with the relay's preamble and secret, as the wall's relay
// does between two machines.
func (s *service) relayOver(secret string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: s.g.Addr()}),
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var c net.Conn
			var err error
			if s.pool == nil {
				c, err = (&net.Dialer{}).DialContext(ctx, "tcp", s.g.Addr())
			} else {
				c, err = (&tls.Dialer{Config: s.tlsConfig()}).DialContext(ctx, "tcp", s.g.Addr())
			}
			if err != nil {
				return nil, err
			}
			if _, err := io.WriteString(c, link.Preamble(link.RelayPreamble, secret)); err != nil {
				c.Close()
				return nil, err
			}
			return c, nil
		},
		DisableKeepAlives: true,
	}}
}

// get fetches u through c, and returns the status and the body; err when it got none.
func get(c *http.Client, u string) (int, string, error) {
	resp, err := c.Get(u)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

// origin is a host the runs reach, on loopback: a policy that names 127.0.0.1 opens it
// to a guarded proxy.
func origin(t *testing.T) *httptest.Server {
	t.Helper()
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	t.Cleanup(o.Close)
	return o
}

// enforce127 is a policy that allows 127.0.0.1 alone.
var enforce127 = &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"127.0.0.1"}}}

// TestStartRefusesAnAddressItCannotServe pins Start's checks of the one address, each
// before anything starts.
func TestStartRefusesAnAddressItCannotServe(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := testCertificate(t, t.TempDir())
	_, otherKey, _ := testCertificate(t, t.TempDir())
	for name, cfg := range map[string]gateway.Config{
		"not host:port":                  {Dir: dir, Listen: "127.0.0.1", RunCredentials: testIssuers},
		"a port out of range":            {Dir: dir, Listen: "127.0.0.1:65536", RunCredentials: testIssuers},
		"a port that is no number":       {Dir: dir, Listen: "127.0.0.1:https", RunCredentials: testIssuers},
		"every address without TLS":      {Dir: dir, Listen: ":0", RunCredentials: testIssuers},
		"0.0.0.0 without TLS":            {Dir: dir, Listen: "0.0.0.0:0", RunCredentials: testIssuers},
		"another machine's without TLS":  {Dir: dir, Listen: "192.0.2.1:0", RunCredentials: testIssuers},
		"a name without TLS":             {Dir: dir, Listen: "gateway.example:8443", RunCredentials: testIssuers},
		"no run credentials":             {Dir: dir, Listen: "127.0.0.1:0"},
		"no run credentials, with TLS":   {Dir: dir, Listen: "127.0.0.1:0", TLS: &gateway.TLS{CertFile: certFile, KeyFile: keyFile}},
		"no directory":                   {RunDir: func(id string) string { return filepath.Join(dir, id) }, Listen: "127.0.0.1:0", RunCredentials: testIssuers},
		"a certificate file not there":   {Dir: dir, Listen: "127.0.0.1:0", RunCredentials: testIssuers, TLS: &gateway.TLS{CertFile: filepath.Join(dir, "none.pem"), KeyFile: keyFile}},
		"a key file not there":           {Dir: dir, Listen: "127.0.0.1:0", RunCredentials: testIssuers, TLS: &gateway.TLS{CertFile: certFile, KeyFile: filepath.Join(dir, "none.pem")}},
		"no files":                       {Dir: dir, Listen: "127.0.0.1:0", RunCredentials: testIssuers, TLS: &gateway.TLS{}},
		"a key of another certificate":   {Dir: dir, Listen: "127.0.0.1:0", RunCredentials: testIssuers, TLS: &gateway.TLS{CertFile: certFile, KeyFile: otherKey}},
		"a certificate without address":  {Dir: dir, TLS: &gateway.TLS{CertFile: certFile, KeyFile: keyFile}},
		"a quiet time that is negative":  {Dir: dir, Runs: gateway.RunsConfig{Quiet: -time.Second}},
		"the key in place of the cert":   {Dir: dir, Listen: "127.0.0.1:0", RunCredentials: testIssuers, TLS: &gateway.TLS{CertFile: keyFile, KeyFile: keyFile}},
		"the cert in place of the key":   {Dir: dir, Listen: "127.0.0.1:0", RunCredentials: testIssuers, TLS: &gateway.TLS{CertFile: certFile, KeyFile: certFile}},
		"loopback, TLS and no issuers":   {Dir: dir, Listen: "[::1]:0", TLS: &gateway.TLS{CertFile: certFile, KeyFile: keyFile}},
		"loopback by name and no issuer": {Dir: dir, Listen: "localhost:0"},
	} {
		g, err := gateway.Start(context.Background(), cfg)
		if err == nil {
			g.Close(context.Background())
			t.Errorf("%s: started", name)
			continue
		}
		if b, _ := os.ReadFile(keyFile); strings.Contains(err.Error(), string(b[30:60])) {
			t.Errorf("%s: the error holds the key: %v", name, err)
		}
	}
	// Nothing was made of the gateway's authority by a start that was refused.
	if _, err := os.Stat(gateway.AuthorityPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the authority after refused starts: %v", err)
	}
}

// TestTheOneAddressIsTLS13Only pins TLS on the one address: 1.3, with the operator's
// certificate; an earlier version is refused in the handshake.
func TestTheOneAddressIsTLS13Only(t *testing.T) {
	s := startService(t, gateway.Config{}, false)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10} {
		cfg := s.tlsConfig()
		cfg.MinVersion, cfg.MaxVersion = version, version
		if c, err := tls.Dial("tcp", s.g.Addr(), cfg); err == nil {
			c.Close()
			t.Errorf("TLS version %#x was served", version)
		}
	}
	c := s.dial(t)
	defer c.Close()
	if st := c.(*tls.Conn).ConnectionState(); st.Version != tls.VersionTLS13 || st.PeerCertificates[0].Subject.CommonName != "gateway.example" {
		t.Errorf("version %#x, certificate %s", st.Version, st.PeerCertificates[0].Subject)
	}
	// A client that trusts another authority does not reach it.
	if _, err := tls.Dial("tcp", s.g.Addr(), &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "127.0.0.1"}); err == nil {
		t.Error("an untrusted certificate was accepted")
	}
	// Plain HTTP on the TLS address is no request.
	p, err := net.Dial("tcp", s.g.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(p, "GET /.well-known/qory-configuration HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer "+goodCredential+"\r\n\r\n")
	if b, _ := io.ReadAll(p); bytes.Contains(b, []byte("HTTP/1.1 200")) {
		t.Errorf("plain HTTP was answered: %q", b)
	}
	if got := s.v.handed(); len(got) != 0 {
		t.Errorf("the verifier was handed %d credentials", len(got))
	}
}

// TestADiscoveryOnTheOneAddress pins the discovery of a separate gateway, over TLS and
// on a plain loopback listener: every URL on the origin the session reached, the proxy
// the same one address, each valid under link-discovery.schema.json; the local link is
// served beside it as before.
func TestADiscoveryOnTheOneAddress(t *testing.T) {
	schema, err := contracts.Compile("link-discovery.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []bool{false, true} {
		s := startService(t, gateway.Config{Heartbeat: 5 * time.Second}, plain)
		resp, b := do(t, s.client(goodCredential), http.MethodGet, s.url(server.WellKnown), "", "")
		if resp.StatusCode != http.StatusOK || resp.Header.Get(server.HeaderConfiguration) == "" {
			t.Fatalf("plain %v: %d %s", plain, resp.StatusCode, b)
		}
		doc, err := contracts.Decode("discovery.json", b)
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("plain %v: %v", plain, err)
		}
		var d server.LinkDiscovery
		json.Unmarshal(b, &d)
		origin := s.scheme() + "://" + s.g.Addr()
		if d.Events.URL != origin+"/v1/events" || d.Run.URL != origin+"/v1/run-configuration" || d.Proxy == nil || d.Proxy.Address != s.g.Addr() || d.Events.IntervalSeconds != 5 {
			t.Errorf("plain %v: discovery %s", plain, b)
		}
		if got := s.v.handed(); !slices.Equal(got, []string{goodCredential}) {
			t.Errorf("plain %v: the verifier was handed %d credentials", plain, len(got))
		}
		// The origin the session names, as its Host says.
		req, _ := http.NewRequest(http.MethodGet, s.url(server.WellKnown), nil)
		req.Host = "gateway.example"
		resp, err = s.client(goodCredential).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		json.Unmarshal(b, &d)
		port := "443"
		if plain {
			port = "80"
		}
		if d.Events.URL != s.scheme()+"://gateway.example/v1/events" || d.Proxy.Address != "gateway.example:"+port {
			t.Errorf("plain %v: by name %s", plain, b)
		}
		// The local link is as it was.
		ld, err := s.link.Discover(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if ld.Events.URL != "http://localhost/v1/events" || ld.Proxy.Address == s.g.Addr() || !strings.HasPrefix(ld.Proxy.Address, "127.0.0.1:") || s.g.LocalLink().Proxy != ld.Proxy.Address {
			t.Errorf("plain %v: the local link's discovery %+v", plain, ld)
		}
		if !strings.Contains(s.g.String(), "address "+s.g.Addr()) {
			t.Errorf("String %s", s.g)
		}
	}
}

// TestTheContractRefusesARequestWithoutARunCredential pins the 401 on the one address:
// every path, with no Authorization, another scheme, two of them, or a run credential
// the verifier refuses, is 401 run_credential_refused from the gateway, with
// WWW-Authenticate: Bearer and nothing of why; the verifier is handed only a Bearer
// credential in its syntax, and nothing reports one.
func TestTheContractRefusesARequestWithoutARunCredential(t *testing.T) {
	schema, err := contracts.Compile("link-refusal.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	s := startService(t, gateway.Config{}, false)
	runID := event.NewRunID()
	requests := []struct{ method, path, contentType, body string }{
		{http.MethodGet, server.WellKnown, "", ""},
		{http.MethodPost, "/v1/run-configuration", server.LinkContentType, openBody(runID)},
		{http.MethodGet, "/v1/run-configuration/" + runID, "", ""},
		{http.MethodPost, "/v1/events", server.ContentType, "[]"},
		{http.MethodGet, "/nowhere", "", ""},
	}
	authorizations := map[string][]string{
		"none":            nil,
		"another scheme":  {"Basic " + base64.StdEncoding.EncodeToString([]byte("x:"+goodCredential))},
		"two":             {"Bearer " + goodCredential, "Bearer " + goodCredential},
		"no credential":   {"Bearer "},
		"not its syntax":  {"Bearer " + goodCredential + " trailing"},
		"a refused one":   {"Bearer " + badCredential},
		"a refused, case": {"bEaReR " + badCredential},
	}
	plain := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: s.tlsConfig()}}
	for name, values := range authorizations {
		for _, rq := range requests {
			req, _ := http.NewRequest(rq.method, s.url(rq.path), strings.NewReader(rq.body))
			if rq.contentType != "" {
				req.Header.Set("Content-Type", rq.contentType)
			}
			for _, v := range values {
				req.Header.Add("Authorization", v)
			}
			resp, err := plain.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var r map[string]any
			json.Unmarshal(b, &r)
			doc, _ := contracts.Decode("refusal.json", b)
			if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != "Bearer" || r["error"] != "run_credential_refused" || r["from"] != "gateway" ||
				r["names"] != nil || r["message"] != "the gateway refused this run credential" || schema.Validate(doc) != nil {
				t.Errorf("%s, %s %s: %d %q %s", name, rq.method, rq.path, resp.StatusCode, resp.Header.Get("WWW-Authenticate"), b)
			}
			if bytes.Contains(b, []byte(goodCredential)) || bytes.Contains(b, []byte(badCredential)) {
				t.Errorf("%s: the answer holds the credential", name)
			}
		}
	}
	for _, c := range s.v.handed() {
		if c != badCredential {
			t.Errorf("the verifier was handed %d bytes other than the refused credential", len(c))
		}
	}
	if got := len(s.v.handed()); got != 2*len(requests) {
		t.Errorf("the verifier was handed %d credentials", got)
	}
	// Nothing opened: the run id is free.
	if _, err := s.tryOpen(server.LinkRunRequest{RunID: runID}); err != nil {
		t.Errorf("the refused run's id: %v", err)
	}
}

// TestARunOverTheOneAddress pins a session's run end to end over TLS, with the
// verifier's double: the run request, a batch and a reload, each answered with the
// digests of the one address; each run's relay over TLS, by its proxy secret, reaches
// that run's proxy and is decided by its policy, and the proxy secret as the password
// of the proxy URL reaches it too, as an unwalled agent's does.
func TestARunOverTheOneAddress(t *testing.T) {
	o := origin(t)
	s := startService(t, gateway.Config{Policy: enforce127}, false)
	_, discovered := do(t, s.client(goodCredential), http.MethodGet, s.url(server.WellKnown), "", "")
	var d server.LinkDiscovery
	json.Unmarshal(discovered, &d)
	a, header := s.openOver(t, server.LinkRunRequest{})
	b, _ := s.openWith(t, otherCredential, server.LinkRunRequest{})
	if a.ProxySecret == "" || a.ProxySecret == b.ProxySecret || header.Get(server.HeaderConfiguration) == "" || header.Get(server.HeaderRunConfiguration) == "" {
		t.Fatalf("answers %+v %+v %v", a, b, header)
	}
	s.postOver(t, started(a.RunID, a.Labels), applied(a.RunID, a.Applied))
	s.postWith(t, otherCredential, started(b.RunID, b.Labels), applied(b.RunID, b.Applied))
	resp, body := do(t, s.client(goodCredential), http.MethodGet, d.Run.URL+"/"+a.RunID, "", "")
	if resp.StatusCode != http.StatusOK || resp.Header.Get(server.HeaderRunConfiguration) != header.Get(server.HeaderRunConfiguration) {
		t.Errorf("the reload: %d %s", resp.StatusCode, body)
	}
	// A's relay reaches A's proxy, and B's B's.
	if status, got, err := get(s.relayOver(a.ProxySecret), o.URL); err != nil || status != http.StatusOK || got != "ok" {
		t.Errorf("A's relay: %d %q %v", status, got, err)
	}
	if status, _, err := get(s.relayOver(b.ProxySecret), "http://denied.example/"); err != nil || status != http.StatusForbidden {
		t.Errorf("B's relay: %d %v", status, err)
	}
	// Another secret is closed unanswered.
	if _, _, err := get(s.relayOver(strings.Repeat("x", len(a.ProxySecret))), o.URL); err == nil {
		t.Error("another secret was served")
	}
	// The proxy secret as the proxy URL's password, the user name ignored.
	unwalled := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "https", User: url.UserPassword("anyone", a.ProxySecret), Host: s.g.Addr()}),
		TLSClientConfig: s.tlsConfig(), DisableKeepAlives: true,
	}}
	if status, got, err := get(unwalled, o.URL); err != nil || status != http.StatusOK || got != "ok" {
		t.Errorf("by the proxy URL: %d %q %v", status, got, err)
	}
	s.close()
	if got := s.record(a.RunID); len(got) != 4 || got[2].Type != event.RunEgress || got[2].Data["host"] != "127.0.0.1" || got[2].Data["decision"] != "allowed" || got[3].Data["host"] != "127.0.0.1" {
		t.Errorf("A's record %v", got)
	}
	if got := s.record(b.RunID); len(got) != 3 || got[2].Type != event.RunEgress || got[2].Data["host"] != "denied.example" || got[2].Data["decision"] != "denied" {
		t.Errorf("B's record %v", got)
	}
}

// TestTheOneAddressAlwaysGuardsItsRuns pins the guard: a run opened on the one address
// does not reach this machine's own addresses unless its policy names the host, wall
// or none, while a run of the local link without a wall does, as before; and a local
// run's proxy, which is not guarded, is never reached from the one address.
func TestTheOneAddressAlwaysGuardsItsRuns(t *testing.T) {
	o := origin(t)
	s := startService(t, gateway.Config{Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "observe"}}}, false)
	remote, _ := s.openOver(t, server.LinkRunRequest{})
	status, body, err := get(s.relayOver(remote.ProxySecret), o.URL)
	if err != nil || status != http.StatusForbidden || !strings.Contains(body, "denied by the gateway") {
		t.Errorf("the one address's run: %d %q %v", status, body, err)
	}
	local := s.open(server.LinkRunRequest{})
	if status, got, err := get(relay(s.g.LocalLink().Proxy, local.ProxySecret), o.URL); err != nil || status != http.StatusOK || got != "ok" {
		t.Errorf("the local link's run: %d %q %v", status, got, err)
	}
	if _, _, err := get(s.relayOver(local.ProxySecret), o.URL); err == nil {
		t.Error("a local run's unguarded proxy was reached from the one address")
	}
	byPassword := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "https", User: url.UserPassword("", local.ProxySecret), Host: s.g.Addr()}),
		TLSClientConfig: s.tlsConfig(), DisableKeepAlives: true,
	}}
	if status, _, err := get(byPassword, o.URL); err != nil || status != http.StatusProxyAuthRequired {
		t.Errorf("a local run's secret as a password: %d %v", status, err)
	}
}

// proxyRequest writes a proxy request's head on a fresh connection to the one address
// and returns the answer, with the connection, which the caller closes.
func (s *service) proxyRequest(t *testing.T, head string) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	c := s.dial(t)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, head); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		c.Close()
		t.Fatalf("%q: %v", head, err)
	}
	return resp, c, r
}

// TestTheProxyLogin pins the proxy for a client with no session on the one address: a
// CONNECT or an absolute-form request without a login the seam accepts is 407 with
// Proxy-Authenticate: Basic realm="qory" and one line of text, the same for every
// failure; with one, it reaches the
// proxy the seam answers, which decides it by its policy.
func TestTheProxyLogin(t *testing.T) {
	o := origin(t)
	host := strings.TrimPrefix(o.URL, "http://")
	login := "Basic " + base64.StdEncoding.EncodeToString([]byte("anyone:"+goodCredential))
	var mu sync.Mutex
	var decisions []proxy.Decision
	px, err := proxy.New(policy.Enforce, []string{"127.0.0.1"}, nil, func(d proxy.Decision) {
		mu.Lock()
		decisions = append(decisions, d)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	px.Guard([]string{"127.0.0.1"})
	defer px.Close()
	unguarded, _ := proxy.New(policy.Observe, nil, nil, func(proxy.Decision) {})
	defer unguarded.Close()
	var handed []string
	var firsts []string
	cfg := gateway.Config{}
	gateway.SetProxyLogin(&cfg, func(authorization string, first *http.Request) (*proxy.Proxy, error) {
		mu.Lock()
		handed = append(handed, authorization)
		firsts = append(firsts, first.Method+" "+first.Host)
		mu.Unlock()
		switch authorization {
		case login:
			return px, nil
		case "Basic " + base64.StdEncoding.EncodeToString([]byte(":unguarded")):
			return unguarded, nil
		}
		return nil, runcredential.ErrRefused
	})
	s := startService(t, cfg, false)
	refused := map[string]string{
		"a CONNECT without a login":       "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"an absolute form without login":  "GET " + o.URL + "/ HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"a CONNECT with a refused login":  "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("anyone:"+badCredential)) + "\r\n\r\n",
		"a POST with a refused login":     "POST " + o.URL + "/ HTTP/1.1\r\nHost: " + host + "\r\nProxy-Authorization: Bearer " + badCredential + "\r\nContent-Length: 2\r\n\r\nhi",
		"two logins":                      "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\nProxy-Authorization: " + login + "\r\nProxy-Authorization: " + login + "\r\n\r\n",
		"a CONNECT to the contract's way": "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nAuthorization: Bearer " + goodCredential + "\r\n\r\n",
	}
	for name, head := range refused {
		resp, c, _ := s.proxyRequest(t, head)
		b, _ := io.ReadAll(resp.Body)
		c.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired || resp.Header.Get("Proxy-Authenticate") != `Basic realm="qory"` || resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" || resp.ContentLength != int64(len(b)) || string(b) != "a valid run credential is required as the proxy password" {
			t.Errorf("%s: %d %v %q", name, resp.StatusCode, resp.Header, b)
		}
	}
	mu.Lock()
	if want := []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("anyone:"+badCredential)), "Bearer " + badCredential}; !sameSet(handed, want) {
		t.Errorf("the login was handed %d values", len(handed))
	}
	handed = nil
	mu.Unlock()

	// With the login, CONNECT reaches the run's proxy and its tunnel the origin.
	resp, c, r := s.proxyRequest(t, "CONNECT "+host+" HTTP/1.1\r\nHost: "+host+"\r\nProxy-Authorization: "+login+"\r\n\r\n")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %d", resp.StatusCode)
	}
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
	if inner, err := http.ReadResponse(r, nil); err != nil || inner.StatusCode != http.StatusOK {
		t.Errorf("through the tunnel: %v %v", inner, err)
	} else if b, _ := io.ReadAll(inner.Body); string(b) != "ok" {
		t.Errorf("through the tunnel: %q", b)
	}
	c.Close()
	for name, head := range map[string]string{
		"a CONNECT the policy denies":        "CONNECT denied.example:443 HTTP/1.1\r\nHost: denied.example:443\r\nProxy-Authorization: " + login + "\r\n\r\n",
		"an absolute form the policy denies": "GET http://denied.example/ HTTP/1.1\r\nHost: denied.example\r\nProxy-Authorization: " + login + "\r\n\r\n",
	} {
		resp, c, _ := s.proxyRequest(t, head)
		c.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	resp, c, _ = s.proxyRequest(t, "GET "+o.URL+"/ HTTP/1.1\r\nHost: "+host+"\r\nProxy-Authorization: "+login+"\r\nConnection: close\r\n\r\n")
	if b, _ := io.ReadAll(resp.Body); resp.StatusCode != http.StatusOK || string(b) != "ok" {
		t.Errorf("an absolute form: %d %q", resp.StatusCode, b)
	}
	c.Close()
	// A proxy the gateway may not serve another machine with is refused.
	resp, c, _ = s.proxyRequest(t, "CONNECT "+host+" HTTP/1.1\r\nHost: "+host+"\r\nProxy-Authorization: Basic "+base64.StdEncoding.EncodeToString([]byte(":unguarded"))+"\r\n\r\n")
	c.Close()
	if resp.StatusCode != http.StatusInternalServerError || !s.reported("is not guarded") {
		t.Errorf("an unguarded proxy: %d", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(firsts, "CONNECT "+host) || !slices.Contains(firsts, "GET "+host) {
		t.Errorf("first requests %v", firsts)
	}
	var got []string
	for _, d := range decisions {
		got = append(got, d.Method+" "+d.Host+" "+d.Outcome)
	}
	if want := []string{"CONNECT 127.0.0.1 connected", "CONNECT denied.example refused", "HTTP denied.example refused", "HTTP 127.0.0.1 connected"}; !sameSet(got, want) {
		t.Errorf("decisions %v", got)
	}
	if got := s.v.handed(); len(got) != 0 {
		t.Errorf("the contract's verifier was handed %d credentials", len(got))
	}
}

// sameSet reports whether a and b hold the same strings, each as often, in any order.
func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// TestTheOneAddressRoutesByTheFirstBytes pins what is neither the relay, nor a proxy,
// nor the contract: a request line the contract's server refuses with 400, a relay of
// no live run's secret and a first line over the bound closed unanswered; on a plain
// loopback listener as over TLS.
func TestTheOneAddressRoutesByTheFirstBytes(t *testing.T) {
	for _, plain := range []bool{false, true} {
		s := startService(t, gateway.Config{}, plain)
		c := s.dial(t)
		c.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(c, "NOT A REQUEST LINE AT ALL\r\n\r\n")
		if b, _ := io.ReadAll(c); !bytes.HasPrefix(b, []byte("HTTP/1.1 400")) {
			t.Errorf("plain %v: a line that is no request: %q", plain, b)
		}
		c.Close()
		for name, open := range map[string]string{
			"a relay of no run":  link.Preamble(link.RelayPreamble, strings.Repeat("x", 43)) + "GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
			"a line over bound":  strings.Repeat("G", 9<<10),
			"a head over bound":  "CONNECT 127.0.0.1:1 HTTP/1.1\r\n" + strings.Repeat("X-Fill: "+strings.Repeat("y", 1000)+"\r\n", 70),
			"the local preamble": link.Preamble(link.LinkPreamble, s.g.LocalLink().Secret) + "GET /.well-known/qory-configuration HTTP/1.1\r\nHost: localhost\r\n\r\n",
		} {
			c := s.dial(t)
			c.SetDeadline(time.Now().Add(5 * time.Second))
			io.WriteString(c, open)
			b, _ := io.ReadAll(c)
			c.Close()
			if name == "the local preamble" {
				// The contract's server reads it as a request line it refuses: the
				// link's secret opens nothing on the one address.
				if bytes.Contains(b, []byte("200 OK")) {
					t.Errorf("plain %v: %s: %q", plain, name, b)
				}
				continue
			}
			if len(b) != 0 {
				t.Errorf("plain %v: %s: answered %q", plain, name, b)
			}
		}
	}
}

// TestTheGatewaysOwnAuthority pins the certificate authority of the clients with no
// session: made once in the gateway's directory, the directory mode 0700 and the file
// 0600, the same after a restart; refused when another user may read it; none
// without the one address.
func TestTheGatewaysOwnAuthority(t *testing.T) {
	dir := t.TempDir()
	cfg := gateway.Config{Dir: dir, Listen: "127.0.0.1:0", RunCredentials: realIssuers(t, false), Report: func(string) {}}
	g, err := gateway.Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	first := gateway.Authority(g)
	g.Close(context.Background())
	block, _ := pem.Decode(first)
	if block == nil {
		t.Fatalf("authority %q", first)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || cert.NotAfter.Before(time.Now().Add(5*365*24*time.Hour)) {
		t.Errorf("authority %v %v", cert, err)
	}
	path := gateway.AuthorityPath(dir)
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the file: %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the directory: %v %v", fi, err)
	}
	g, err = gateway.Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if again := gateway.Authority(g); !bytes.Equal(again, first) {
		t.Error("a restart made another authority")
	}
	g.Close(context.Background())
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if g, err := gateway.Start(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "open to other users") {
		if g != nil {
			g.Close(context.Background())
		}
		t.Errorf("an authority open to other users: %v", err)
	}
	os.Chmod(path, 0o600)
	if err := os.WriteFile(path, []byte("not an authority"), 0o600); err != nil {
		t.Fatal(err)
	}
	if g, err := gateway.Start(context.Background(), cfg); err == nil || strings.Contains(err.Error(), "not an authority") {
		if g != nil {
			g.Close(context.Background())
		}
		t.Errorf("a file that is no authority: %v", err)
	}
	// Without the one address the gateway keeps none.
	other := t.TempDir()
	g, err = gateway.Start(context.Background(), gateway.Config{Dir: other, Report: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close(context.Background())
	if gateway.Authority(g) != nil {
		t.Error("an authority without the one address")
	}
	if _, err := os.Stat(gateway.AuthorityPath(other)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the authority's file without the one address: %v", err)
	}
}

// TestTheLoginsSyntax pins how the one address reads a login: the password of Basic,
// the user name ignored; the credential of Bearer in RFC 6750's syntax, one header.
func TestTheLoginsSyntax(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for value, want := range map[string]string{
		"Basic " + b64("anyone:secret-value"):  "secret-value",
		"basic " + b64(":secret-value"):        "secret-value",
		"Basic " + b64("anyone:with:colons"):   "with:colons",
		"Basic  " + b64("anyone:spaced"):       "spaced",
		"Basic " + b64("no colon"):             "",
		"Bearer " + b64("anyone:secret-value"): "",
		"Basic not-base64!":                    "",
		"Basic":                                "",
	} {
		if got, _ := gateway.BasicPassword(value); got != want {
			t.Errorf("%q: %q", value, got)
		}
	}
	for _, ok := range [][]string{{"Bearer abc.def-_~+/=="}, {"bearer x"}, {"BEARER  x"}} {
		if _, got := gateway.Bearer(ok); !got {
			t.Errorf("%q refused", ok)
		}
	}
	for _, refused := range [][]string{nil, {""}, {"Bearer"}, {"Bearer "}, {"Bearer a b"}, {"Bearer a=b"}, {"Basic x"}, {"Bearer x", "Bearer x"}, {"Bearer x\t"}} {
		if _, got := gateway.Bearer(refused); got {
			t.Errorf("%q accepted", refused)
		}
	}
}
