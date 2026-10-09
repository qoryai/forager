package server_test

import (
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
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// The run credentials of the tests: no real ones, in the syntax of a Bearer token.
const (
	credential  = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJyay0wMDAxIn0.Y3JlZGVudGlhbC1vbmU"
	refreshed   = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJyay0wMDAxIn0.Y3JlZGVudGlhbC10d28"
	remoteRunID = runID
)

// authority is a certificate authority of a test's own, and the PEM file of its
// certificate.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	file string
}

func newAuthority(t *testing.T, name string) *authority {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	file := filepath.Join(t.TempDir(), name+".pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &authority{cert: cert, key: key, file: file}
}

// issue is a certificate the authority issues for gateway.example and 127.0.0.1, never
// localhost, and its pin.
func (a *authority) issue(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "gateway.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"gateway.example"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, base64.StdEncoding.EncodeToString(sum[:])
}

// remoteGateway is a fake separate gateway over TLS: it answers the contract on the
// origin the request names, as the gateway does, and records what each request
// carried.
type remoteGateway struct {
	srv  *httptest.Server
	ca   *authority
	pin  string
	hits atomic.Int32

	mu      sync.Mutex
	auths   []string
	secrets []string
	agents  []string
	bodies  [][]byte
	refusal func(w http.ResponseWriter, r *http.Request) bool
}

// startRemote starts a fake separate gateway whose TLS is cfg's, TLS 1.3 alone when nil.
func startRemote(t *testing.T, cfg *tls.Config) *remoteGateway {
	t.Helper()
	g := &remoteGateway{ca: newAuthority(t, "test-authority")}
	cert, pin := g.ca.issue(t)
	g.pin = pin
	g.srv = httptest.NewUnstartedServer(http.HandlerFunc(g.serve))
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	cfg.Certificates = []tls.Certificate{cert}
	g.srv.TLS = cfg
	g.srv.StartTLS()
	t.Cleanup(g.srv.Close)
	return g
}

// url is the fake gateway's URL, on 127.0.0.1, which its certificate names.
func (g *remoteGateway) url() string { return g.srv.URL }

func (g *remoteGateway) serve(w http.ResponseWriter, r *http.Request) {
	g.hits.Add(1)
	body, _ := io.ReadAll(r.Body)
	g.mu.Lock()
	g.auths = append(g.auths, strings.Join(r.Header.Values("Authorization"), "|"))
	g.secrets = append(g.secrets, strings.Join(r.Header.Values(server.HeaderRunSecret), "|"))
	g.agents = append(g.agents, r.Header.Get("User-Agent"))
	g.bodies = append(g.bodies, body)
	refuse := g.refusal
	g.mu.Unlock()
	if refuse != nil && refuse(w, r) {
		return
	}
	origin := "https://" + r.Host
	switch {
	case r.URL.Path == "/.well-known/qory-configuration":
		answer(w, 200, `{"version":1,"events":{"url":"`+origin+`/v1/events","types":["*"],"interval_seconds":30},"run":{"url":"`+origin+`/v1/run-configuration"},"proxy":{"address":"`+r.Host+`"}}`)
	case r.URL.Path == "/v1/run-configuration":
		answer(w, 200, runAnswer)
	case r.URL.Path == "/v1/run-configuration/"+remoteRunID:
		answer(w, 200, reloadAnswer)
	case r.URL.Path == "/v1/events":
		w.WriteHeader(202)
	default:
		w.WriteHeader(404)
	}
}

func (g *remoteGateway) seen() (auths, agents []string, bodies [][]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.auths...), append([]string(nil), g.agents...), append([][]byte(nil), g.bodies...)
}

// fixed is a run credential that does not change.
func fixed(c string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return c, nil }
}

func remoteLink(t *testing.T, url string, trust server.RemoteTLS, cred func(context.Context) (string, error)) *server.Link {
	t.Helper()
	k, err := server.NewRemoteLink(url, trust, cred, userAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	return k
}

// TestTheRemoteLinkSpeaksTheContractOverTLS pins one run's requests behind a separate
// gateway: discovery, the run request with its narrowing, the reload and a batch, each
// over TLS 1.3 with the run credential as Authorization: Bearer, asked for before each
// request so a refreshed one is sent from then on, and the reload and the batch with the
// run answer's run secret besides; no proxy of the environment is used.
func TestTheRemoteLinkSpeaksTheContractOverTLS(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	g := startRemote(t, nil)
	var current atomic.Value
	current.Store(credential)
	var asked atomic.Int32
	k := remoteLink(t, g.url(), server.RemoteTLS{CAFile: g.ca.file}, func(context.Context) (string, error) {
		asked.Add(1)
		return current.Load().(string), nil
	})
	ctx := context.Background()
	d, err := k.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d.Proxy == nil || d.Proxy.Address != strings.TrimPrefix(g.url(), "https://") || k.ProxyAddress() != d.Proxy.Address {
		t.Errorf("the proxy %+v, the link's one address %s", d.Proxy, k.ProxyAddress())
	}
	narrowing := &server.LinkNarrowing{Egress: server.LinkNarrowingEgress{Allow: []string{"api.example"}}}
	if _, err := k.OpenRun(ctx, d.Run.URL, server.LinkRunRequest{RunID: remoteRunID, Labels: map[string]string{"forge": "example-forge"}, Narrowing: narrowing}); err != nil {
		t.Fatal(err)
	}
	current.Store(refreshed)
	if _, err := k.Reload(ctx, d.Run.URL, remoteRunID); err != nil {
		t.Fatal(err)
	}
	if dl, err := k.Deliver(ctx, d.Events.URL, "d-1", []byte("[]"), ""); err != nil || dl.Status != 202 {
		t.Fatalf("the batch: %+v %v", dl, err)
	}
	auths, agents, bodies := g.seen()
	want := []string{"Bearer " + credential, "Bearer " + credential, "Bearer " + refreshed, "Bearer " + refreshed}
	if fmt.Sprint(auths) != fmt.Sprint(want) || asked.Load() != 4 {
		t.Errorf("Authorization %v, the credential asked for %d times", auths, asked.Load())
	}
	g.mu.Lock()
	secrets := slices.Clone(g.secrets)
	g.mu.Unlock()
	if want := []string{"", "", runSecret, runSecret}; fmt.Sprint(secrets) != fmt.Sprint(want) {
		t.Errorf("the run secrets carried %q, want the run answer's on the reload and the batch alone", secrets)
	}
	for _, a := range agents {
		if a != userAgent {
			t.Errorf("User-Agent %q", a)
		}
	}
	if !bytes.Contains(bodies[1], []byte(`"narrowing":{"egress":{"allow":["api.example"]}}`)) {
		t.Errorf("the run request %s", bodies[1])
	}
}

// TestTheRemoteLinkTakesAnHTTPSURLAlone pins what NewRemoteLink refuses before it
// sends anything: a URL that is not https, or that has user information, a path, a
// query or a fragment; no run credential; a CAFile that is missing or holds no
// certificate; and a pin that is not 32 bytes in standard base64 with padding.
func TestTheRemoteLinkTakesAnHTTPSURLAlone(t *testing.T) {
	ca := newAuthority(t, "refusals")
	notPEM := filepath.Join(t.TempDir(), "not.pem")
	os.WriteFile(notPEM, []byte("no certificate"), 0o600)
	ok := "https://gateway.example:8443"
	sum := sha256.Sum256([]byte("a key"))
	for name, c := range map[string]struct {
		url   string
		trust server.RemoteTLS
		cred  func(context.Context) (string, error)
	}{
		"http":               {"http://gateway.example:8443", server.RemoteTLS{}, fixed(credential)},
		"user information":   {"https://user:secret-of-the-url@gateway.example", server.RemoteTLS{}, fixed(credential)},
		"a path":             {"https://gateway.example/qory", server.RemoteTLS{}, fixed(credential)},
		"a query":            {"https://gateway.example/?a=1", server.RemoteTLS{}, fixed(credential)},
		"a fragment":         {"https://gateway.example/#a", server.RemoteTLS{}, fixed(credential)},
		"no host":            {"https:///", server.RemoteTLS{}, fixed(credential)},
		"no credential":      {ok, server.RemoteTLS{}, nil},
		"a missing CA file":  {ok, server.RemoteTLS{CAFile: filepath.Join(t.TempDir(), "none.pem")}, fixed(credential)},
		"a CA file not PEM":  {ok, server.RemoteTLS{CAFile: notPEM}, fixed(credential)},
		"a hex pin":          {ok, server.RemoteTLS{CAFile: ca.file, CertificateSHA256: fmt.Sprintf("%x", sum)}, fixed(credential)},
		"a pin unpadded":     {ok, server.RemoteTLS{CertificateSHA256: base64.RawStdEncoding.EncodeToString(sum[:])}, fixed(credential)},
		"a pin of base64url": {ok, server.RemoteTLS{CertificateSHA256: strings.NewReplacer("+", "-", "/", "_").Replace(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32)))}, fixed(credential)},
		"a short pin":        {ok, server.RemoteTLS{CertificateSHA256: base64.StdEncoding.EncodeToString(sum[:16])}, fixed(credential)},
	} {
		if _, err := server.NewRemoteLink(c.url, c.trust, c.cred, userAgent, nil); err == nil {
			t.Errorf("%s: a link", name)
		} else if strings.Contains(err.Error(), "secret-of-the-url") {
			t.Errorf("%s: the error quotes the URL: %v", name, err)
		}
	}
	if _, err := server.NewRemoteLink("https://gateway.example", server.RemoteTLS{CAFile: ca.file, CertificateSHA256: base64.StdEncoding.EncodeToString(sum[:])}, fixed(credential), userAgent, nil); err != nil {
		t.Errorf("a URL without a port: %v", err)
	}
}

// TestTheRemoteLinksCAFileReplacesTheSystemsRoots pins the trust in the gateway's
// chain: the system's roots without a CAFile, which know no test authority; with one,
// its authorities alone, so another authority's file trusts nothing of this gateway.
// A gateway that is not trusted is sent nothing.
func TestTheRemoteLinksCAFileReplacesTheSystemsRoots(t *testing.T) {
	g := startRemote(t, nil)
	other := newAuthority(t, "another-authority")
	for name, ca := range map[string]string{"the system's roots": "", "another authority": other.file} {
		k := remoteLink(t, g.url(), server.RemoteTLS{CAFile: ca}, fixed(credential))
		_, err := k.Discover(context.Background())
		if err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := g.hits.Load(); n != 0 {
		t.Errorf("an untrusted gateway was sent %d requests", n)
	}
	if _, err := remoteLink(t, g.url(), server.RemoteTLS{CAFile: g.ca.file}, fixed(credential)).Discover(context.Background()); err != nil {
		t.Errorf("the gateway's own authority: %v", err)
	}
}

// TestTheRemoteLinkChecksTheHostName pins that the chain is verified for the URL's host
// name: a certificate for gateway.example and 127.0.0.1 is no certificate of localhost.
func TestTheRemoteLinkChecksTheHostName(t *testing.T) {
	g := startRemote(t, nil)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(g.url(), "https://"))
	k := remoteLink(t, "https://localhost:"+port, server.RemoteTLS{CAFile: g.ca.file}, fixed(credential))
	if _, err := k.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "localhost") {
		t.Errorf("another host name: %v", err)
	}
	if g.hits.Load() != 0 {
		t.Error("a gateway of another name was sent a request")
	}
}

// TestTheRemoteLinkRefusesTLS12 pins TLS 1.3 alone: a gateway that offers no more than
// TLS 1.2 is sent nothing, its proxy as its contract.
func TestTheRemoteLinkRefusesTLS12(t *testing.T) {
	g := startRemote(t, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	k := remoteLink(t, g.url(), server.RemoteTLS{CAFile: g.ca.file}, fixed(credential))
	if _, err := k.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("TLS 1.2: %v", err)
	}
	if c, err := k.DialProxy(context.Background()); err == nil {
		c.Close()
		t.Error("the proxy over TLS 1.2 was dialled")
	}
	if g.hits.Load() != 0 {
		t.Error("a TLS 1.2 gateway was sent a request")
	}
}

// TestTheRemoteLinkChecksThePin pins the pin of the certificate's public key: the
// gateway's own key opens the link and its proxy; another key opens neither, its chain
// trusted all the same.
func TestTheRemoteLinkChecksThePin(t *testing.T) {
	g := startRemote(t, nil)
	k := remoteLink(t, g.url(), server.RemoteTLS{CAFile: g.ca.file, CertificateSHA256: g.pin}, fixed(credential))
	if _, err := k.Discover(context.Background()); err != nil {
		t.Errorf("the gateway's own key: %v", err)
	}
	c, err := k.DialProxy(context.Background())
	if err != nil {
		t.Fatalf("the proxy with the gateway's own key: %v", err)
	}
	if tc, ok := c.(*tls.Conn); !ok || tc.ConnectionState().Version != tls.VersionTLS13 {
		t.Errorf("the proxy's connection %T", c)
	}
	c.Close()
	hits := g.hits.Load()
	_, other := g.ca.issue(t)
	k = remoteLink(t, g.url(), server.RemoteTLS{CAFile: g.ca.file, CertificateSHA256: other}, fixed(credential))
	if _, err := k.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "pin") {
		t.Errorf("another key: %v", err)
	}
	if c, err := k.DialProxy(context.Background()); err == nil || !strings.Contains(err.Error(), "pin") {
		if c != nil {
			c.Close()
		}
		t.Errorf("the proxy with another key: %v", err)
	}
	if g.hits.Load() != hits {
		t.Error("a gateway whose key is not the pin's was sent a request")
	}
}

// TestTheRemoteLinkPassesTheGatewaysRefusalsOn pins the refusals of a separate gateway
// as the local link's: the code, the status, the names and who refused, and the
// refusal's message as its text, word for word; to a batch, in the Delivery's Refusal.
func TestTheRemoteLinkPassesTheGatewaysRefusalsOn(t *testing.T) {
	for _, c := range []struct {
		status int
		code   string
		names  []string
		text   string
	}{
		{401, "run_credential_refused", nil, "the gateway refused this run credential"},
		{403, "target_differs_from_credential", []string{"labels.repository=example-namespace/project"}, "this checkout is example-forge/other, and the run credential is for example-forge/example-namespace/project"},
		{403, "differs_from_credential", []string{"about.details.requester=requester"}, "about.details.requester differs from the run credential's"},
	} {
		g := startRemote(t, nil)
		g.refusal = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != "/v1/run-configuration" && r.URL.Path != "/v1/events" {
				return false
			}
			names := ""
			if c.names != nil {
				names = `,"names":["` + strings.Join(c.names, `","`) + `"]`
			}
			answer(w, c.status, `{"error":"`+c.code+`"`+names+`,"message":"`+c.text+`","from":"gateway"}`)
			return true
		}
		k := remoteLink(t, g.url(), server.RemoteTLS{CAFile: g.ca.file}, fixed(credential))
		_, err := k.OpenRun(context.Background(), g.url()+"/v1/run-configuration", server.LinkRunRequest{RunID: remoteRunID})
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != c.code || r.Status != c.status || r.From != accesskey.FromGateway || fmt.Sprint(r.Names) != fmt.Sprint(c.names) || err.Error() != c.text {
			t.Errorf("%s: %#v", c.code, err)
		}
		// A batch's answer carries the same refusal, which a resend stops on.
		dl, err := k.Deliver(context.Background(), g.url()+"/v1/events", "d", []byte("[]"), "")
		if r := dl.Refusal; err != nil || dl.Accepted() || dl.Stop() || dl.Code != c.code || r == nil || r.Code != c.code || r.Status != c.status || r.From != accesskey.FromGateway || fmt.Sprint(r.Names) != fmt.Sprint(c.names) || r.Error() != c.text {
			t.Errorf("%s: the batch's answer %+v %v", c.code, dl, err)
		}
	}
}

// TestARemoteDiscoveryOffTheGatewayIsRefused pins that a separate gateway's discovery
// lists URLs of its own origin alone, so the run credential goes to it alone, and its
// one address as the proxy; and that a request to a URL of another origin is never
// sent.
func TestARemoteDiscoveryOffTheGatewayIsRefused(t *testing.T) {
	for name, doc := range map[string]func(origin, host string) string{
		"events elsewhere": func(o, h string) string {
			return `{"version":1,"events":{"url":"https://elsewhere.example/v1/events","types":["*"],"interval_seconds":30},"run":{"url":"` + o + `/v1/run"},"proxy":{"address":"` + h + `"}}`
		},
		"run over http": func(o, h string) string {
			return `{"version":1,"events":{"url":"` + o + `/v1/events","types":["*"],"interval_seconds":30},"run":{"url":"http://` + h + `/v1/run"},"proxy":{"address":"` + h + `"}}`
		},
		"another proxy": func(o, h string) string {
			return `{"version":1,"events":{"url":"` + o + `/v1/events","types":["*"],"interval_seconds":30},"run":{"url":"` + o + `/v1/run"},"proxy":{"address":"proxy.example:3128"}}`
		},
		"another port": func(o, h string) string {
			return `{"version":1,"events":{"url":"` + o + `/v1/events","types":["*"],"interval_seconds":30},"run":{"url":"` + o + `/v1/run"},"proxy":{"address":"127.0.0.1:1"}}`
		},
	} {
		g := startRemote(t, nil)
		g.refusal = func(w http.ResponseWriter, r *http.Request) bool {
			answer(w, 200, doc("https://"+r.Host, r.Host))
			return true
		}
		k := remoteLink(t, g.url(), server.RemoteTLS{CAFile: g.ca.file}, fixed(credential))
		var de *server.DocumentError
		if _, err := k.Discover(context.Background()); !errors.As(err, &de) {
			t.Errorf("%s: %v", name, err)
		}
	}
	g := startRemote(t, nil)
	k := remoteLink(t, g.url(), server.RemoteTLS{CAFile: g.ca.file}, fixed(credential))
	for _, u := range []string{"https://elsewhere.example/v1/run", "http://" + strings.TrimPrefix(g.url(), "https://") + "/v1/run"} {
		if _, err := k.OpenRun(context.Background(), u, server.LinkRunRequest{RunID: remoteRunID}); err == nil {
			t.Errorf("a run request to %s was sent", u)
		}
		if _, err := k.Deliver(context.Background(), u, "d", []byte("[]"), ""); err == nil {
			t.Errorf("a batch to %s was sent", u)
		}
	}
	if g.hits.Load() != 0 {
		t.Error("a request off the gateway was sent")
	}
}

// TestTheRemoteLinkFollowsNoRedirect pins that a redirect is a status like any other:
// the run credential goes nowhere it points.
func TestTheRemoteLinkFollowsNoRedirect(t *testing.T) {
	g := startRemote(t, nil)
	var elsewhere atomic.Int32
	g.refusal = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/elsewhere" {
			elsewhere.Add(1)
			return false
		}
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
		return true
	}
	k := remoteLink(t, g.url(), server.RemoteTLS{CAFile: g.ca.file}, fixed(credential))
	if _, err := k.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "status 307") {
		t.Errorf("a redirect: %v", err)
	}
	if elsewhere.Load() != 0 {
		t.Error("the redirect was followed")
	}
}

// TestTheRemoteLinkNeverShowsTheCredential pins that a run credential is in no error,
// print or log of the link: a credential that fails, or is not a Bearer token, sends
// nothing, and the error says why without it.
func TestTheRemoteLinkNeverShowsTheCredential(t *testing.T) {
	g := startRemote(t, nil)
	for name, cred := range map[string]func(context.Context) (string, error){
		"a failure":       func(context.Context) (string, error) { return "", errors.New("the run credential file is gone") },
		"a line break":    fixed(credential + "\r\nX-Other: " + refreshed),
		"a space":         fixed(credential + " " + refreshed),
		"no credential":   fixed(""),
		"a quote":         fixed(`"` + credential + `"`),
		"a control":       fixed(credential + "\x00"),
		"a padded middle": fixed(credential[:10] + "=" + refreshed),
	} {
		k := remoteLink(t, g.url(), server.RemoteTLS{CAFile: g.ca.file}, cred)
		_, err := k.Discover(context.Background())
		if err == nil || strings.Contains(err.Error(), credential[20:]) || strings.Contains(err.Error(), refreshed[20:]) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if g.hits.Load() != 0 {
		t.Error("a request without a good run credential was sent")
	}
	k := remoteLink(t, g.url(), server.RemoteTLS{CAFile: g.ca.file, CertificateSHA256: g.pin}, fixed(credential))
	var b bytes.Buffer
	slog.New(slog.NewJSONHandler(&b, nil)).Info("link", "link", k)
	for _, out := range []string{fmt.Sprint(k), fmt.Sprintf("%+v", k), fmt.Sprintf("%#v", k), k.String(), b.String()} {
		if strings.Contains(out, credential) || !strings.Contains(out, g.url()) {
			t.Errorf("printed as %s", out)
		}
	}
}

// TestTheLocalLinkHasNoProxyOverTLS pins that DialProxy is a separate gateway's alone.
func TestTheLocalLinkHasNoProxyOverTLS(t *testing.T) {
	k, err := server.NewLocalLink(link.Local{Socket: "/nonexistent/qory-link-x/sock", Secret: linkSecret}, userAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.DialProxy(context.Background()); err == nil {
		t.Error("the local link dialled a proxy over TLS")
	}
	if k.ProxyAddress() != "" {
		t.Errorf("the local link's one address %q", k.ProxyAddress())
	}
}
