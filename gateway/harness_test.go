package gateway_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/server"
)

// The tests of this file pin a run configuration's harness credentials: the stack
// proxy sets them for qory's fetch of the harness definition, and the run's proxy never
// does.

// harnessSecret is the fake value the control seals for harness-1.
const harnessSecret = "fake-harness-value-of-the-test"

// harnessOrigin is an HTTPS origin on localhost, under an authority of the test's, that
// records each request's path and Authorization, with the gateway that trusts it and
// serves doc, whose harness-1 the control seals as harnessSecret.
type harnessOrigin struct {
	h     *harness
	c     *control
	port  string
	roots *x509.CertPool
	mu    sync.Mutex
	got   []string
}

func newHarnessOrigin(t *testing.T, doc string) *harnessOrigin {
	t.Helper()
	certFile, keyFile, roots := testCertificate(t, t.TempDir())
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	o := &harnessOrigin{roots: roots}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.got = append(o.got, r.URL.Path+" "+r.Header.Get("Authorization"))
		o.mu.Unlock()
		io.WriteString(w, "harness")
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, o.port, _ = net.SplitHostPort(srv.Listener.Addr().String())
	o.c = newControl(t)
	o.c.serveDocument(doc, 'a')
	o.c.mu.Lock()
	o.c.secrets = map[string]string{"harness-1": harnessSecret}
	o.c.mu.Unlock()
	cfg := gateway.Config{Server: o.c.server()}
	gateway.SetUpstreamRoots(&cfg, roots)
	o.h = start(t, cfg)
	o.h.secrets = append(o.h.secrets, harnessSecret)
	return o
}

// client is an HTTP client through the gateway's proxy that the secret opens, which
// trusts the origin's authority and the run's.
func (o *harnessOrigin) client(t *testing.T, a *server.LinkRunAnswer, secret string) *http.Client {
	t.Helper()
	trusted := o.roots.Clone()
	if !trusted.AppendCertsFromPEM([]byte(a.CertificateAuthority)) {
		t.Fatal("the run answer has no certificate authority")
	}
	c := relay(o.h.g.Addr(), secret)
	c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: trusted}
	return c
}

// get sends a GET of path on the origin through c and returns the status.
func (o *harnessOrigin) get(t *testing.T, c *http.Client, path string) int {
	t.Helper()
	resp, err := c.Get("https://localhost:" + o.port + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// requests are what the origin got.
func (o *harnessOrigin) requests() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.got)
}

// harnessGatewayDoc is a run configuration whose policy allows localhost, whose
// stack_hosts list it, and whose harness credential, harness-1, is set as basic on
// localhost's harness repository; harness_hidden, when hidden.
func harnessGatewayDoc(hidden bool) string {
	d := `{"version":1,`
	if hidden {
		d += `"harness_hidden":true,`
	}
	return d + `"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["localhost"]}},"stack_hosts":["localhost"],` +
		`"credentials":[{"name":"harness-1","purpose":"harness","apply":[{"hosts":["localhost"],"scheme":"basic","username":"x-access-token","paths":["/example-org/harness.git/*"]}]}]}`
}

// withoutCredentials are the run answer's applied without credentials, as a join's
// dev.qory.run.policy_applied has them when the run's credentials are harness ones alone.
func withoutCredentials(t *testing.T, raw json.RawMessage) json.RawMessage {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "credentials")
	b, _ := json.Marshal(m)
	return b
}

// TestAHarnessCredentialReachesItsOriginThroughTheStackProxyAlone pins a harness
// credential on the local link: the run answer has no credential_hosts and no
// placeholders; the stack proxy sets the value on the credential's paths of an HTTPS
// origin and on no other path, which passes all the same; the run's proxy, which the
// session, the host proxy and the setup step go through, sets none; each decision of the
// stack proxy is a dev.qory.run.egress with channel stack, with its path and the
// credential, beside the gateway's report line, and the run's proxy's has no channel;
// the open's dev.qory.run.policy_applied lists harness-1 with purpose harness, and a
// join's, without it, is accepted; from the run's first join request on, the value is
// cleared.
func TestAHarnessCredentialReachesItsOriginThroughTheStackProxyAlone(t *testing.T) {
	o := newHarnessOrigin(t, harnessGatewayDoc(false))
	h := o.h
	a := h.open(server.LinkRunRequest{})
	if len(a.CredentialHosts) != 0 || len(a.Placeholders) != 0 {
		t.Errorf("the run answer's credential_hosts %+v, placeholders %v; want none", a.CredentialHosts, a.Placeholders)
	}
	if got := gateway.Tokens(h.g, a.RunID); len(got) != 0 {
		t.Errorf("the run's proxy sets %v; want nothing", got)
	}
	stack := o.client(t, a, a.StackProxySecret)
	for _, p := range []string{"/example-org/harness.git/info/refs", "/example-org/other.git/info/refs"} {
		if status := o.get(t, stack, p); status != http.StatusOK {
			t.Errorf("the stack proxy's GET %s: %d", p, status)
		}
	}
	if status := o.get(t, o.client(t, a, a.ProxySecret), "/example-org/harness.git/info/refs"); status != http.StatusOK {
		t.Errorf("the run's proxy's GET: %d", status)
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+harnessSecret))
	want := []string{"/example-org/harness.git/info/refs " + basic, "/example-org/other.git/info/refs ", "/example-org/harness.git/info/refs "}
	if got := o.requests(); !slices.Equal(got, want) {
		t.Errorf("the origin got\n%q\nwant\n%q", got, want)
	}
	if got := members(a.Applied)["credentials"]; !reflect.DeepEqual(got, []any{map[string]any{"name": "harness-1", "hosts": []any{"localhost"}, "scheme": "basic",
		"paths": []any{"/example-org/harness.git/*"}, "purpose": "harness"}}) {
		t.Errorf("the open's applied credentials %v", got)
	}
	if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
		t.Fatalf("the open's batch: %+v", d)
	}
	h.joined(a.RunID)
	if got := gateway.StackTokens(h.g, a.RunID); !reflect.DeepEqual(got, map[string]string{"harness-1": ""}) {
		t.Errorf("after the first join request, the stack proxy's values are %v; want harness-1's cleared", got)
	}
	if d := h.post(sessionStarted(a.RunID, 1), applied(a.RunID, withoutCredentials(t, a.Applied)), sessionExited(a.RunID, 1), exited(a.RunID)); !d.Accepted() {
		t.Fatalf("the join's batch: %+v", d)
	}
	h.close()
	var stackRecords, runRecords []map[string]any
	for _, l := range h.record(a.RunID) {
		if l.Type != event.RunEgress {
			continue
		}
		b, _ := json.Marshal(l.Data)
		validDocument(t, "events/run.egress.schema.json", b)
		if l.Data["channel"] == "stack" {
			stackRecords = append(stackRecords, l.Data)
		} else {
			runRecords = append(runRecords, l.Data)
		}
	}
	if len(stackRecords) != 2 || stackRecords[0]["credential"] != "harness-1" || stackRecords[0]["path"] != "/example-org/harness.git/info/refs" ||
		stackRecords[0]["method"] != "HTTPS" || stackRecords[0]["rule"] != "localhost" || stackRecords[1]["credential"] != nil || stackRecords[1]["path"] != "/example-org/other.git/info/refs" {
		t.Errorf("the stack proxy's records %v; want the two requests, the first with harness-1", stackRecords)
	}
	if len(runRecords) != 1 || runRecords[0]["method"] != "CONNECT" || runRecords[0]["credential"] != nil {
		t.Errorf("the run's proxy's records %v; want one tunnel with no credential and no channel", runRecords)
	}
	if got := h.reportsWith("stack fetch to localhost:" + o.port + " allowed by the run configuration's stack_hosts entry localhost"); len(got) != 2 {
		t.Errorf("the stack proxy's report lines %q; want one per request", got)
	}
}

// TestAHiddenHarnessShowsNoPath pins harness_hidden: the stack proxy's
// dev.qory.run.egress of a request has no path and no path_rule, and keeps its host,
// rule, credential and channel; the open's dev.qory.run.policy_applied lists harness-1
// by its name and purpose alone.
func TestAHiddenHarnessShowsNoPath(t *testing.T) {
	o := newHarnessOrigin(t, harnessGatewayDoc(true))
	h := o.h
	a := h.open(server.LinkRunRequest{})
	if status := o.get(t, o.client(t, a, a.StackProxySecret), "/example-org/harness.git/info/refs"); status != http.StatusOK {
		t.Errorf("the stack proxy's GET: %d", status)
	}
	if got := members(a.Applied)["credentials"]; !reflect.DeepEqual(got, []any{map[string]any{"name": "harness-1", "purpose": "harness"}}) {
		t.Errorf("the open's applied credentials %v; want harness-1's name and purpose alone", got)
	}
	if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied), exited(a.RunID)); !d.Accepted() {
		t.Fatalf("the batch: %+v", d)
	}
	h.close()
	n := 0
	for _, l := range h.record(a.RunID) {
		if l.Type != event.RunEgress {
			continue
		}
		n++
		b, _ := json.Marshal(l.Data)
		validDocument(t, "events/run.egress.schema.json", b)
		if _, ok := l.Data["path"]; ok || l.Data["path_rule"] != nil || l.Data["channel"] != "stack" || l.Data["credential"] != "harness-1" || l.Data["rule"] != "localhost" || l.Data["host"] != "localhost" {
			t.Errorf("the stack proxy's record %v; want no path and no path_rule", l.Data)
		}
		if strings.Contains(string(b), "example-org") {
			t.Errorf("the record shows the harness's path: %s", b)
		}
	}
	if n != 1 {
		t.Errorf("%d dev.qory.run.egress, want 1", n)
	}
}
