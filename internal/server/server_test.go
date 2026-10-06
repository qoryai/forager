package server_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/runner/contracts"
	"github.com/qoryai/runner/internal/server"
)

const (
	secret = "fixture-secret-not-a-real-one"
	key    = "ak_f1xt0re000000000"
)

// fixture is the bytes of a contract fixture.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(contracts.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestServerDocumentReads pins the fixtures reading and that a refused document is an
// error naming it.
func TestServerDocumentReads(t *testing.T) {
	for _, f := range []string{"fixtures/server/loopback.yaml", "fixtures/server/https.yaml"} {
		c, err := server.Read(f, fixture(t, f))
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if c.Version != 1 || c.URL == "" || c.AccessKey != key || len(c.Secret) < 16 {
			t.Errorf("%s read as %+v", f, c)
		}
	}
	for _, f := range []string{"fixtures/invalid/server-no-key.yaml", "fixtures/invalid/server-plain-http.yaml"} {
		_, err := server.Read(f, fixture(t, f))
		var se *server.Error
		if !errors.As(err, &se) || se.Name != f {
			t.Errorf("%s: %v", f, err)
		}
	}
}

// TestSignatureRoundTrips pins the header value and constant-time verification.
func TestSignatureRoundTrips(t *testing.T) {
	sig := server.Sign(secret, []byte("[]"))
	if len(sig) != len("sha256=")+64 || sig[:7] != "sha256=" {
		t.Errorf("signature %s", sig)
	}
	if !server.Verify(secret, []byte("[]"), sig) {
		t.Error("a valid signature was refused")
	}
	if server.Verify(secret, []byte("[{}]"), sig) || server.Verify("other", []byte("[]"), sig) || server.Verify(secret, []byte("[]"), "") {
		t.Error("an invalid signature was accepted")
	}
}

// TestSignedGETMatchesTheKnownAnswers pins the canonical string and the signature of a
// GET against the contract's published answers: the one under test-secret, and the
// signed fixtures under the fixture secret.
func TestSignedGETMatchesTheKnownAnswers(t *testing.T) {
	if got := server.Canonical("get", "/.well-known/qory-configuration?x=1", "1700000000"); got != "GET\n/.well-known/qory-configuration?x=1\n1700000000" {
		t.Errorf("canonical %q", got)
	}
	const want = "sha256=e8cc6260e2740e9282f2b45fa8bc590e3afe0e59eb53882b19cdb0f87a613c02"
	if got := server.SignGET("test-secret", "GET", "/.well-known/qory-configuration?x=1", "1700000000"); got != want {
		t.Errorf("SignGET = %s, want %s", got, want)
	}
	if !server.VerifyGET("test-secret", "GET", "/.well-known/qory-configuration?x=1", "1700000000", want) || server.VerifyGET("test-secret", "GET", "/.well-known/qory-configuration", "1700000000", want) {
		t.Error("VerifyGET disagrees with the known answer")
	}
	if got := server.Timestamp(time.Unix(1700000000, 999)); got != "1700000000" {
		t.Errorf("Timestamp = %s", got)
	}
	for _, name := range []string{"get-configuration-valid", "get-run-configuration-valid", "get-run-configuration-labels-valid"} {
		f := signedFixture(t, name)
		if !server.VerifyGET(secret, f.Method, f.Target, f.Headers[server.HeaderTimestamp], f.Headers[server.HeaderSignature]) {
			t.Errorf("%s: the fixture's signature is not what SignGET makes of its target", name)
		}
	}
	f := signedFixture(t, "batch-valid")
	if !server.Verify(secret, []byte(f.Body), f.Headers[server.HeaderSignature]) {
		t.Error("batch-valid: the fixture's signature is not what Sign makes of its body")
	}
}

// signed is one fixture under fixtures/signed.
type signed struct {
	Method  string            `json:"method"`
	Target  string            `json:"target"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Expect  int               `json:"expect"`
}

func signedFixture(t *testing.T, name string) signed {
	t.Helper()
	doc, err := contracts.Document("fixtures/signed/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	m := doc.(map[string]any)
	f := signed{Method: m["method"].(string), Target: m["target"].(string), Headers: map[string]string{}}
	for k, v := range m["headers"].(map[string]any) {
		f.Headers[http.CanonicalHeaderKey(k)] = v.(string)
	}
	if b, ok := m["body"].(string); ok {
		f.Body = b
	}
	n, _ := m["expect"].(interface{ Int64() (int64, error) }).Int64()
	f.Expect = int(n)
	return f
}

// verified is a server of the test's own that checks what every request carries and
// answers as told: the configuration document, the run configuration, and the events
// endpoint with digests on its answer.
type verified struct {
	t      *testing.T
	srv    *httptest.Server
	status int
	// seen is the last request's target and headers.
	seen   *http.Request
	body   []byte
	runDoc string
}

func newVerified(t *testing.T) *verified {
	t.Helper()
	v := &verified{t: t, status: 202, runDoc: `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}}`}
	v.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v.seen = r
		v.body, _ = io.ReadAll(r.Body)
		if r.Header.Get("User-Agent") != "qory-runner/test" || r.Header.Get(server.HeaderAccessKey) != key || r.Header.Get(server.HeaderContractVersion) != strconv.Itoa(server.Revision) {
			t.Errorf("%s %s: headers %v", r.Method, r.URL, r.Header)
		}
		if r.Method == http.MethodGet {
			ts := r.Header.Get(server.HeaderTimestamp)
			if n, err := strconv.ParseInt(ts, 10, 64); err != nil || time.Since(time.Unix(n, 0)).Abs() > time.Minute {
				t.Errorf("timestamp %q", ts)
			}
			if !server.VerifyGET(secret, r.Method, r.URL.RequestURI(), ts, r.Header.Get(server.HeaderSignature)) {
				t.Errorf("GET %s: the signature does not verify over the target as sent", r.URL.RequestURI())
			}
		}
		switch {
		case r.URL.Path == server.WellKnown:
			w.Header().Set(server.HeaderConfiguration, "sha256=c0")
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"version":1,"events":{"url":"`+v.srv.URL+`/v1/events","types":["*"]},"run":{"url":"`+v.srv.URL+`/v1/run-configuration"},"later":{"x":1}}`)
		case r.URL.Path == "/v1/run-configuration":
			w.Header().Set(server.HeaderRunConfiguration, "sha256="+strings.Repeat("0", 64))
			w.Header().Set("ETag", `"sha256=`+strings.Repeat("0", 64)+`"`)
			io.WriteString(w, v.runDoc)
		case r.URL.Path == "/v1/events" && r.Method == http.MethodPost:
			if r.Header.Get("Content-Type") != server.ContentType || r.Header.Get(server.HeaderDelivery) == "" || !server.Verify(secret, v.body, r.Header.Get(server.HeaderSignature)) {
				t.Errorf("POST headers %v", r.Header)
			}
			w.Header().Set(server.HeaderConfiguration, "sha256=c1")
			w.Header().Set(server.HeaderRunConfiguration, "sha256=r1")
			w.WriteHeader(v.status)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(v.srv.Close)
	return v
}

func (v *verified) client() *server.Client {
	return &server.Client{Config: &server.Config{Version: 1, URL: v.srv.URL, AccessKey: key, Secret: secret}, UserAgent: "qory-runner/test"}
}

// TestDiscoverReadsTheConfigurationAndItsDigest pins discovery: the well-known path,
// the document decoded with a section the runner does not know ignored, the digest
// from the header, and no run on a status that is not 200.
func TestDiscoverReadsTheConfigurationAndItsDigest(t *testing.T) {
	v := newVerified(t)
	c := v.client()
	conf, digest, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if digest != "sha256=c0" || conf.Events.URL != v.srv.URL+"/v1/events" || len(conf.Events.Types) != 1 || conf.Run == nil || conf.Run.URL != v.srv.URL+"/v1/run-configuration" {
		t.Errorf("discovered %+v, digest %s", conf, digest)
	}
	if !conf.Wants("dev.qory.run.log") || !conf.Wants("dev.qory.ping") {
		t.Error("the filter refused an event of a configuration with *")
	}
	conf.Events.Types = []string{"dev.qory.run.started"}
	if conf.Wants("dev.qory.run.log") || !conf.Wants("dev.qory.run.started") || !conf.Wants("dev.qory.ping") {
		t.Error("the filter of a listed configuration is wrong")
	}
	c.Config.URL = v.srv.URL + "/elsewhere"
	if _, _, err := c.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "status 404") || !strings.Contains(err.Error(), "/elsewhere"+server.WellKnown) {
		t.Errorf("discovery of a URL that does not answer: %v", err)
	}
	v.srv.Close()
	if _, _, err := c.Discover(context.Background()); err == nil {
		t.Error("discovery of a server that is down succeeded")
	}
}

// TestRunConfigurationSignsTheQueryItSends pins the run configuration fetch: every
// label of the run is one query parameter, sorted by key and encoded, an empty value
// included, added to the run URL's own query, and the target signed is the target
// sent; the document is decoded with its raw policy and the digest read.
func TestRunConfigurationSignsTheQueryItSends(t *testing.T) {
	v := newVerified(t)
	c := v.client()
	run := v.srv.URL + "/v1/run-configuration"
	rc, digest, err := c.RunConfiguration(context.Background(), run, map[string]string{"repository": "acme/shop", "issue": "77", "forge": "github.com"})
	if err != nil {
		t.Fatal(err)
	}
	if digest != "sha256="+strings.Repeat("0", 64) || rc.Version != 1 || !strings.Contains(string(rc.SecurityPolicy), `"api.example"`) {
		t.Errorf("run configuration %+v, digest %s", rc, digest)
	}
	// The targets of the signed fixtures, a run of three labels and a run of two, then
	// the edges.
	for _, tc := range []struct {
		run    string
		labels map[string]string
		want   string
	}{
		{run, map[string]string{"repository": "acme/shop", "issue": "77", "forge": "github.com"}, signedFixture(t, "get-run-configuration-labels-valid").Target},
		{run, map[string]string{"forge": "github.com", "repository": "acme/shop"}, signedFixture(t, "get-run-configuration-valid").Target},
		{run, map[string]string{"run_key": "queue/1 2", "note": "", "k.v-x_y": "\u00fc&="}, "/v1/run-configuration?k.v-x_y=%C3%BC%26%3D&note=&run_key=queue%2F1+2"},
		{run + "?tenant=a&issue=0", map[string]string{"issue": "77"}, "/v1/run-configuration?issue=77&tenant=a"},
		{run, map[string]string{}, "/v1/run-configuration"},
		{run, nil, "/v1/run-configuration"},
	} {
		if _, _, err := c.RunConfiguration(context.Background(), tc.run, tc.labels); err != nil {
			t.Fatal(err)
		}
		if got := v.seen.URL.RequestURI(); got != tc.want {
			t.Errorf("labels %v: target %s, want %s", tc.labels, got, tc.want)
		}
	}
	v.runDoc = `{"version":1}`
	if rc, _, err := c.RunConfiguration(context.Background(), run, nil); err != nil || rc.SecurityPolicy != nil || rc.Variables != nil {
		t.Errorf("a run configuration without a policy: %+v %v", rc, err)
	}
	if _, _, err := c.RunConfiguration(context.Background(), v.srv.URL+"/v1/missing", nil); err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Errorf("a run URL that does not answer: %v", err)
	}
}

// TestLabelsBoundTheQuery pins the bound the contract states: the longest labels a run
// may carry, sixteen keys of 64 bytes and values of 256 bytes that all need encoding,
// make a query of 13,343 bytes, and one more label or byte is refused.
func TestLabelsBoundTheQuery(t *testing.T) {
	v := newVerified(t)
	labels := map[string]string{}
	for i := range server.MaxLabels {
		labels[fmt.Sprintf("%02d", i)+strings.Repeat("k", 62)] = strings.Repeat("\u00e9", 128)
	}
	if err := server.CheckLabels(labels); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/run-configuration", labels); err != nil {
		t.Fatal(err)
	}
	if n := len(v.seen.URL.RawQuery); n != 13343 {
		t.Errorf("the longest query is %d bytes, the contract says 13343", n)
	}
	for name, change := range map[string]func(map[string]string){
		"a seventeenth label": func(l map[string]string) { l["x"] = "" },
		"a longer value":      func(l map[string]string) { l["00"+strings.Repeat("k", 62)] += "x" },
		"a longer key":        func(l map[string]string) { l[strings.Repeat("k", 65)] = ""; delete(l, "00"+strings.Repeat("k", 62)) },
		"an upper-case key":   func(l map[string]string) { l["Forge"] = ""; delete(l, "00"+strings.Repeat("k", 62)) },
		"a value not UTF-8":   func(l map[string]string) { l["00"+strings.Repeat("k", 62)] = "\xff" },
	} {
		l := maps.Clone(labels)
		change(l)
		if err := server.CheckLabels(l); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// TestDeliveryCarriesTheHeadersAndReadsTheDigests pins one POST: content type, user
// agent, key, revision, delivery id, a signature the server verifies, the run
// configuration digest when the run holds one, the answer's digests, and the ping's
// fail-closed rule.
func TestDeliveryCarriesTheHeadersAndReadsTheDigests(t *testing.T) {
	v := newVerified(t)
	c := v.client()
	events := v.srv.URL + "/v1/events"
	status, answer, err := c.Deliver(context.Background(), events, "d1", []byte("[]"), "sha256=r0")
	if err != nil || status != 202 || answer.Configuration != "sha256=c1" || answer.RunConfiguration != "sha256=r1" {
		t.Errorf("deliver: %d %+v %v", status, answer, err)
	}
	if v.seen.Header.Get(server.HeaderRunConfiguration) != "sha256=r0" || v.seen.Header.Get(server.HeaderTimestamp) != "" {
		t.Errorf("POST headers %v", v.seen.Header)
	}
	if err := c.Ping(context.Background(), events, "d2", []byte("[]")); err != nil {
		t.Error(err)
	}
	if _, ok := v.seen.Header[server.HeaderRunConfiguration]; ok {
		t.Error("the ping sent a run configuration digest with none held")
	}
	v.status = 500
	if err := c.Ping(context.Background(), events, "d3", []byte("[]")); !errors.Is(err, server.ErrNotAccepted) || !strings.Contains(err.Error(), events) {
		t.Errorf("ping on 500: %v", err)
	}
	v.srv.Close()
	if err := c.Ping(context.Background(), events, "d4", []byte("[]")); err == nil {
		t.Error("ping on a closed server succeeded")
	}
}

// TestARedirectIsNotFollowed pins that a 3xx is a status like any other: the host it
// points at sees no request, so no key, signature or timestamp reaches it, whether the
// client is the package's own or the caller's; discovery is then no run, and a
// delivery is not accepted.
func TestARedirectIsNotFollowed(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		w.Header().Set(server.HeaderConfiguration, "sha256=c0")
		io.WriteString(w, `{"version":1,"events":{"url":"https://elsewhere.example/v1/events","types":["*"]}}`)
	}))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer origin.Close()
	for name, hc := range map[string]*http.Client{"the package's client": nil, "the caller's client": {}} {
		c := &server.Client{Config: &server.Config{Version: 1, URL: origin.URL, AccessKey: key, Secret: secret}, UserAgent: "qory-runner/test", HTTP: hc}
		if _, _, err := c.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "status 302") {
			t.Errorf("%s: discovery through a redirect: %v", name, err)
		}
		if _, _, err := c.RunConfiguration(context.Background(), origin.URL+"/v1/run-configuration", nil); err == nil || !strings.Contains(err.Error(), "status 302") {
			t.Errorf("%s: a run configuration through a redirect: %v", name, err)
		}
		status, _, err := c.Deliver(context.Background(), origin.URL+"/v1/events", "d1", []byte("[]"), "")
		if err != nil || status != http.StatusFound || server.Accepted(status) {
			t.Errorf("%s: a delivery through a redirect: %d %v", name, status, err)
		}
		if err := c.Ping(context.Background(), origin.URL+"/v1/events", "d2", []byte("[]")); !errors.Is(err, server.ErrNotAccepted) {
			t.Errorf("%s: a ping through a redirect: %v", name, err)
		}
	}
	if n := elsewhere.Load(); n != 0 {
		t.Errorf("the host a redirect named saw %d requests", n)
	}
}
