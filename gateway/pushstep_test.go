package gateway_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/server"
)

// pushValue is the fake value of the forge credential of the push step's run, which the
// gateway reads from pushSource.
const (
	pushValue  = "fake-forge-token-of-the-push-step-test"
	pushSource = "GATEWAY_TEST_PUSH_VALUE"
)

// pushStep is the batch of a push step, numbered step, that succeeded.
func pushStep(runID string, step int) []map[string]any {
	return []map[string]any{
		ev(runID, event.StepStarted, map[string]any{"step": step, "name": "push work to git.example/example-org/app", "kind": event.StepPush}),
		ev(runID, event.StepExited, map[string]any{"step": step, "state": event.StateSucceeded, "exit_code": 0, "duration_ms": 5}),
	}
}

// TestAPushStepAfterTheSessionExitedIsAccepted pins a batch of a push step after
// dev.qory.session.exited: the link accepts it, and the run's record has the step
// between the session's exit and dev.qory.run.exited.
func TestAPushStepAfterTheSessionExitedIsAccepted(t *testing.T) {
	h := start(t, gateway.Config{})
	a := h.open(server.LinkRunRequest{})
	runID := a.RunID
	if d := h.post(started(runID, nil), applied(runID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	if n := h.joined(runID); n != 1 {
		t.Fatalf("the join is session %d", n)
	}
	if d := h.post(sessionStarted(runID, 1), sessionExited(runID, 1)); !d.Accepted() {
		t.Fatalf("the session's batch: %+v", d)
	}
	if d := h.post(append(pushStep(runID, 1), exited(runID))...); !d.Accepted() {
		t.Fatalf("the push step's batch: %+v", d)
	}
	want := []string{event.RunStarted, event.PolicyApplied, event.SessionStarted, event.SessionExited, event.StepStarted, event.StepExited, event.RunExited}
	if got := types(h.record(runID)); !slices.Equal(got, want) {
		t.Errorf("record %v, want %v", got, want)
	}
}

// removalStep is the batch of the wall step of (*session.Run).RemoveSetup, numbered step:
// succeeded, or failed with its line.
func removalStep(runID string, step int, failed bool) []map[string]any {
	evs := []map[string]any{ev(runID, event.StepStarted, map[string]any{"step": step, "name": "remove the setup container", "kind": event.StepWall})}
	state := event.StateSucceeded
	if failed {
		state = event.StateFailed
		line := base64.StdEncoding.EncodeToString([]byte("Close the run: the setup container may still run, so no session can join: told to fail\n"))
		evs = append(evs, ev(runID, event.RunLog, map[string]any{"stream": "stderr", "bytes": line, "step": step}))
	}
	return append(evs, ev(runID, event.StepExited, map[string]any{"step": step, "state": state, "exit_code": -1, "duration_ms": 5}))
}

// TestARemovalStepAfterTheSessionExitedIsAccepted pins a batch of the setup container's
// removal after dev.qory.session.exited, outside every session: the link's schema and
// its checks accept the wall step, and the run does not end batch_refused. After a
// removal that succeeds the push step follows; one that fails has its line and no push.
func TestARemovalStepAfterTheSessionExitedIsAccepted(t *testing.T) {
	for what, c := range map[string]struct {
		batch func(runID string) []map[string]any
		want  []string
	}{
		"a removal, then a push": {
			func(runID string) []map[string]any {
				return slices.Concat(removalStep(runID, 1, false), pushStep(runID, 2))
			},
			[]string{event.StepStarted, event.StepExited, event.StepStarted, event.StepExited},
		},
		"a removal that fails": {
			func(runID string) []map[string]any { return removalStep(runID, 1, true) },
			[]string{event.StepStarted, event.RunLog, event.StepExited},
		},
	} {
		t.Run(what, func(t *testing.T) {
			h := start(t, gateway.Config{})
			a := h.open(server.LinkRunRequest{})
			runID := a.RunID
			if d := h.post(started(runID, nil), applied(runID, a.Applied)); !d.Accepted() {
				t.Fatalf("the first batch: %+v", d)
			}
			if n := h.joined(runID); n != 1 {
				t.Fatalf("the join is session %d", n)
			}
			if d := h.post(sessionStarted(runID, 1), sessionExited(runID, 1)); !d.Accepted() {
				t.Fatalf("the session's batch: %+v", d)
			}
			if d := h.post(append(c.batch(runID), exited(runID))...); !d.Accepted() {
				t.Fatalf("the removal's batch: %+v", d)
			}
			want := slices.Concat([]string{event.RunStarted, event.PolicyApplied, event.SessionStarted, event.SessionExited}, c.want, []string{event.RunExited})
			if got := types(h.record(runID)); !slices.Equal(got, want) {
				t.Errorf("record %v, want %v", got, want)
			}
		})
	}
}

// TestTheProxySetsACredentialAfterTheSessionExited pins the run's proxy after a run's
// last session, on a connection the run's proxy secret opens, as the host proxy's are:
// a request with no credential, as git sends, reaches the HTTPS origin with the token in
// Authorization, once, and its dev.qory.run.egress comes after the session's exit, with
// the credential, and before dev.qory.run.exited. The session's side, a host proxy
// after Join returned, is session's TestTheHostProxyStartsAfterAJoinReturned; e2e's
// TestTheGatewaySetsTheCredentialOnAHostProxyRequest runs both.
func TestTheProxySetsACredentialAfterTheSessionExited(t *testing.T) {
	t.Setenv(pushSource, pushValue)
	certFile, keyFile, roots := testCertificate(t, t.TempDir())
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []string
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		io.WriteString(w, "origin")
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())

	cfg := gateway.Config{
		Credentials: []gateway.Credential{{Name: "forge", Env: pushSource, Hosts: []string{"localhost"}, Scheme: "basic", Username: "x-access-token"}},
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost"}},
			Credentials: []gateway.PolicyCredential{{Name: "forge"}}}}
	gateway.SetUpstreamRoots(&cfg, roots)
	h := start(t, cfg)
	h.secrets = append(h.secrets, pushValue)
	a := h.open(server.LinkRunRequest{})
	runID := a.RunID
	if d := h.post(started(runID, nil), applied(runID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	if n := h.joined(runID); n != 1 {
		t.Fatalf("the join is session %d", n)
	}
	if d := h.post(sessionStarted(runID, 1), sessionExited(runID, 1)); !d.Accepted() {
		t.Fatalf("the session's batch: %+v", d)
	}

	trusted := x509.NewCertPool()
	if !trusted.AppendCertsFromPEM([]byte(a.CertificateAuthority)) {
		t.Fatal("the run answer has no certificate authority")
	}
	client := relay(h.g.Addr(), a.ProxySecret)
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: trusted}
	resp, err := client.Post("https://localhost:"+port+"/example-org/app.git/git-receive-pack", "application/x-git-receive-pack-request", nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("the request through the run's proxy got %d, want 200", resp.StatusCode)
	}
	if d := h.post(append(pushStep(runID, 1), exited(runID))...); !d.Accepted() {
		t.Fatalf("the push step's batch: %+v", d)
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+pushValue))
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"POST /example-org/app.git/git-receive-pack " + basic}; !slices.Equal(got, want) {
		t.Errorf("the origin got %q; want %q", got, want)
	}
	var order []string
	for _, l := range h.record(runID) {
		switch l.Type {
		case event.SessionExited, event.RunExited:
			order = append(order, l.Type)
		case event.RunEgress:
			if l.Data["method"] == "HTTPS" {
				order = append(order, fmt.Sprint(l.Type, " ", l.Data["path"], " ", l.Data["credential"]))
			}
		}
	}
	want := []string{event.SessionExited, event.RunEgress + " /example-org/app.git/git-receive-pack forge", event.RunExited}
	if !slices.Equal(order, want) {
		t.Errorf("the record's order %q; want %q", order, want)
	}
}
