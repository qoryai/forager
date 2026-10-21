package gateway_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// TestAJoinSetsItsModelKey pins the model key the proxy sets for each session: a run
// with the model keys first, its start key, and second, both on the endpoint's host.
// Session 1 joins with none named and gets first; session 2 joins naming second, and
// while it runs the proxy sets second alone, so a request with first's placeholder gets
// no key; once session 2 exited the proxy sets first again.
func TestAJoinSetsItsModelKey(t *testing.T) {
	t.Setenv("GATEWAY_TEST_FIRST_KEY", "fake-first-value-0001")
	t.Setenv("GATEWAY_TEST_SECOND_KEY", "fake-second-value-0002")
	certFile, keyFile, roots := testCertificate(t, t.TempDir())
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []string
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Header.Get("X-Api-Key"))
		mu.Unlock()
		io.WriteString(w, "origin")
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	origin.StartTLS()
	defer origin.Close()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	endpoint := "https://localhost:" + port + "/v1"
	creds := []gateway.Credential{
		{Name: "first", Env: "GATEWAY_TEST_FIRST_KEY", Format: "anthropic-messages", Endpoint: endpoint, Scheme: "header", Header: "x-api-key"},
		{Name: "second", Env: "GATEWAY_TEST_SECOND_KEY", Format: "anthropic-messages", Endpoint: endpoint, Scheme: "header", Header: "x-api-key"},
	}
	c := newControl(t)
	c.serveDocument(`{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["localhost"]},"credentials":[{"name":"first"},{"name":"second"}]},"model_credential":"first"}`, 'a')
	// The node's policy lists localhost itself, which the guard of a walled run's proxy
	// reaches only then.
	node := &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost"}}}
	cfg := gateway.Config{Server: c.server(), Credentials: creds, Policy: node}
	gateway.SetUpstreamRoots(&cfg, roots)
	h := start(t, cfg)
	h.secrets = append(h.secrets, "fake-first-value-0001", "fake-second-value-0002")
	a := h.open(server.LinkRunRequest{Wall: true})
	runID := a.RunID
	if a.ModelCredential != "first" {
		t.Fatalf("the run's start key %q", a.ModelCredential)
	}
	if d := h.post(started(runID, nil), applied(runID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM([]byte(a.CertificateAuthority))
	agent := relay(h.g.Addr(), a.ProxySecret)
	agent.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: trusted}
	// send sends a request with the placeholder of the model key name and returns the
	// key the origin received.
	send := func(name string) string {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, endpoint+"/messages", nil)
		req.Header.Set("X-Api-Key", link.KeyPlaceholder(name))
		resp, err := agent.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		mu.Lock()
		defer mu.Unlock()
		return got[len(got)-1]
	}

	one, err := h.join(runID)
	if err != nil || one.Session != 1 || one.ModelCredential != "first" {
		t.Fatalf("join 1: %+v, %v", one, err)
	}
	h.post(sessionStarted(runID, 1))
	if v := send("first"); v != "fake-first-value-0001" {
		t.Errorf("session 1, first's placeholder: %q", v)
	}
	h.post(sessionExited(runID, 1))

	two, err := h.linkOf(runID).Join(t.Context(), server.LocalOrigin+"/v1/run-configuration", runID, server.LinkJoinRequest{Passes: []string{}, ModelCredential: "second"})
	if err != nil || two.Session != 2 || two.ModelCredential != "second" {
		t.Fatalf("join 2: %+v, %v", two, err)
	}
	h.post(sessionStarted(runID, 2))
	if v := send("second"); v != "fake-second-value-0002" {
		t.Errorf("session 2, second's placeholder: %q", v)
	}
	if v := send("first"); v != link.KeyPlaceholder("first") {
		t.Errorf("session 2, first's placeholder: %q, want no key set", v)
	}
	h.post(sessionExited(runID, 2))
	if v := send("first"); v != "fake-first-value-0001" {
		t.Errorf("after session 2, first's placeholder: %q", v)
	}
	if v := send("second"); v != link.KeyPlaceholder("second") {
		t.Errorf("after session 2, second's placeholder: %q, want no key set", v)
	}
	mu.Lock()
	n := len(got)
	mu.Unlock()
	if n != 5 {
		t.Errorf("the origin got %d requests", n)
	}
	if _, err := h.linkOf(runID).Join(t.Context(), server.LocalOrigin+"/v1/run-configuration", runID, server.LinkJoinRequest{ModelCredential: "third"}); err == nil {
		t.Error("a join naming no model key of the run was answered")
	}
	h.post(exited(runID))
}
