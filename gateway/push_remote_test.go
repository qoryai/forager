package gateway_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// remotePush is a separate gateway whose control serves doc, a [pushRunDoc], with its
// credentials sealed, and an HTTPS origin on localhost, under an authority of the
// test's, that records each request's method, path and Authorization.
type remotePush struct {
	r     *remote
	cfg   gateway.Config
	port  string
	roots *x509.CertPool
	mu    sync.Mutex
	got   []string
}

func newRemotePush(t *testing.T, doc string) *remotePush {
	t.Helper()
	certFile, keyFile, roots := testCertificate(t, t.TempDir())
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	p := &remotePush{roots: roots}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		p.mu.Lock()
		p.got = append(p.got, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		p.mu.Unlock()
		io.WriteString(w, "origin")
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, p.port, _ = net.SplitHostPort(srv.Listener.Addr().String())
	c := gatewayControl(t)
	c.serveDocument(doc, 'a')
	c.mu.Lock()
	c.secrets = map[string]string{"work-1": workSecret, "push-1": pushSecretWord}
	c.mu.Unlock()
	// The node's policy names localhost, so the guarded proxies reach the origin on this
	// machine.
	p.cfg = gateway.Config{Dir: t.TempDir(), Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost"}}}}
	gateway.SetUpstreamRoots(&p.cfg, roots)
	p.r = startRemote(t, c, p.cfg)
	return p
}

// client is an HTTP client of the one address whose every connection opens with line,
// trusting the origin's authority and the run's.
func (p *remotePush) client(t *testing.T, e *edgeRun, line string) *http.Client {
	t.Helper()
	trusted := p.roots.Clone()
	if !trusted.AppendCertsFromPEM([]byte(e.a.CertificateAuthority)) {
		t.Fatal("the run answer has no certificate authority")
	}
	c := p.r.through(line)
	c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: trusted}
	return c
}

// requests are what the origin got, and forgets them.
func (p *remotePush) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	got := p.got
	p.got = nil
	return got
}

// TestThePushProxyBehindASeparateGateway pins the push proxy on the one address, in a
// write run and in a write-no-push run. The run answer has no push_proxy_secret. What
// the sessions, the setup step and After send through the run's proxy, QORY-RELAY and
// the run key, gets the read work credential alone: the push gets the branch guard's
// 403, and the REST write and the GraphQL mutation reach the origin with work-1's value.
// In the write run, QORY-PUSH and the run key open the push proxy, which pushes the work
// item's branch with push-1's value; QORY-PUSH with another run's key, or with no run
// key, is closed unanswered. In the write-no-push run, QORY-PUSH with the run's key is
// closed unanswered too, the run has no push value, its secrets request is for work-1
// alone, and its open's dev.qory.run.policy_applied lists no credential with purpose
// push. A second push through the run's proxy after the session exited, when After and
// qory's push step run, gets the same 403, and the record has each push through the
// run's proxy as a dev.qory.run.egress denied by wall:push-ref, with no channel push.
func TestThePushProxyBehindASeparateGateway(t *testing.T) {
	work := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+workSecret))
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+pushSecretWord))
	for _, c := range []struct {
		name string
		push bool
	}{{"write", true}, {"write-no-push", false}} {
		t.Run(c.name, func(t *testing.T) {
			p := newRemotePush(t, pushRunDoc(c.push))
			runID := event.NewRunID()
			key := runKeyFor(t, runID, nil)
			e := p.r.open(t, key, server.LinkRunRequest{Wall: true})
			if e.a.PushProxySecret != "" || e.a.ProxySecret != "" {
				t.Errorf("the run answer has a secret behind a separate gateway")
			}
			wantPush := map[string]string{}
			if c.push {
				wantPush["push-1"] = pushSecretWord
			}
			if tokens, proxied := gateway.PushTokens(p.r.g, runID); proxied != c.push || !reflect.DeepEqual(tokens, wantPush) {
				t.Errorf("the run has a push proxy: %v with %v, want %v with %v", proxied, tokens, c.push, wantPush)
			}
			if got := gateway.Tokens(p.r.g, runID); !reflect.DeepEqual(got, map[string]string{"work-1": workSecret}) {
				t.Errorf("the run's proxy sets %v; want work-1 alone", got)
			}
			pushSplit(t, p.r.c, e.a.Applied, c.push)
			relayed := p.client(t, e, link.RelayLine(key))
			pushed := sessionWrites(t, relayed, p.port)
			if pushed.status != http.StatusForbidden || !strings.HasPrefix(pushed.body, pushRefused) {
				t.Errorf("the push through the run's proxy got %+v; want the branch guard's 403", pushed)
			}
			want := []string{"PATCH /repos/example-org/app/git/refs/heads/main " + work, "POST /graphql " + work}
			if got := p.requests(); !slices.Equal(got, want) {
				t.Errorf("the origin got\n%q\nwant\n%q", got, want)
			}
			push := p.client(t, e, link.PushLine(key))
			got, err := push.Post("https://localhost:"+p.port+"/example-org/app.git/git-receive-pack", "application/x-git-receive-pack-request", strings.NewReader(receivePack(pushWorkItem)))
			switch {
			case c.push && err != nil:
				t.Fatalf("the push through QORY-PUSH: %v", err)
			case c.push:
				got.Body.Close()
				if want := []string{"POST /example-org/app.git/git-receive-pack " + basic}; got.StatusCode != http.StatusOK || !slices.Equal(p.requests(), want) {
					t.Errorf("the push through QORY-PUSH got %d; want 200 with push-1's value at the origin", got.StatusCode)
				}
			case err == nil:
				got.Body.Close()
				t.Errorf("QORY-PUSH of a run with no push credential was answered: %d", got.StatusCode)
			}
			other := runKeyFor(t, event.NewRunID(), nil)
			for what, line := range map[string]string{"another run's key": link.PushLine(other), "no run key": link.PushPreamble + " qrk_not.a-run-key\n"} {
				if _, err := p.client(t, e, line).Get("https://localhost:" + p.port + "/repos/example-org/app/pulls/12"); err == nil {
					t.Errorf("QORY-PUSH with %s was answered", what)
				}
			}
			if len(p.requests()) != 0 {
				t.Error("the origin got a request through a closed QORY-PUSH")
			}
			j := p.r.do(t, key, http.MethodPost, "/qory-link/run-configuration/"+runID+"/sessions", []byte(`{"version":1,"passes":[],"model_key":true}`))
			if j.status != http.StatusOK {
				t.Fatalf("the join: %d %s", j.status, j.body)
			}
			if got := e.post(t, sessionStarted(runID, 1), sessionExited(runID, 1)); got.status != http.StatusAccepted {
				t.Fatalf("the session's batch: %d %s", got.status, got.body)
			}
			if got := send(t, relayed, p.port, http.MethodPost, "/example-org/app.git/git-receive-pack", "application/x-git-receive-pack-request", receivePack(pushWorkItem)); got.status != http.StatusForbidden || !strings.HasPrefix(got.body, pushRefused) {
				t.Errorf("the push through the run's proxy after the session got %+v; want the branch guard's 403", got)
			}
			if got := p.requests(); len(got) != 0 {
				t.Errorf("the origin got %q after the session", got)
			}
			if got := e.post(t, exited(runID)); got.status != http.StatusAccepted {
				t.Fatalf("the last batch: %d %s", got.status, got.body)
			}
			want = []string{"<nil> denied wall:push-ref", "<nil> denied wall:push-ref"}
			if c.push {
				want = []string{"<nil> denied wall:push-ref", "push allowed /example-org/app.git/*", "<nil> denied wall:push-ref"}
			}
			eventually(t, "the record's pushes", func() bool { return len(receivePacks(p.r.record(runID))) >= len(want) })
			if got := receivePacks(p.r.record(runID)); !slices.Equal(got, want) {
				t.Errorf("the record's pushes %q, want %q", got, want)
			}
		})
	}
}

// TestAReopenedRunKeepsItsPushProxy pins the push proxy across a restart of a separate
// gateway, with a session joined and ended before it: the reopened run's push proxy
// pushes the work item's branch with push-1's value through QORY-PUSH, and its stack
// proxy stays closed.
func TestAReopenedRunKeepsItsPushProxy(t *testing.T) {
	p := newRemotePush(t, pushRunDoc(true))
	runID := event.NewRunID()
	key := runKeyFor(t, runID, nil)
	e := p.r.open(t, key, server.LinkRunRequest{Wall: true})
	j := p.r.do(t, key, http.MethodPost, "/qory-link/run-configuration/"+runID+"/sessions", []byte(`{"version":1,"passes":[],"model_key":true}`))
	if j.status != http.StatusOK {
		t.Fatalf("the join: %d %s", j.status, j.body)
	}
	if got := e.post(t, sessionStarted(runID, 1), sessionExited(runID, 1)); got.status != http.StatusAccepted {
		t.Fatalf("the session's batch: %d %s", got.status, got.body)
	}
	after := p.r.restart(t, p.cfg)
	p.r, e.r = after, after
	// The first request on the one address reopens the run.
	if got := e.post(t, heartbeat(runID)); got.status != http.StatusAccepted {
		t.Fatalf("the first batch after the restart: %d %s", got.status, got.body)
	}
	resp, err := p.client(t, e, link.PushLine(key)).Post("https://localhost:"+p.port+"/example-org/app.git/git-receive-pack", "application/x-git-receive-pack-request", strings.NewReader(receivePack(pushWorkItem)))
	if err != nil {
		t.Fatalf("the push through QORY-PUSH after the restart: %v", err)
	}
	resp.Body.Close()
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+pushSecretWord))
	if want := []string{"POST /example-org/app.git/git-receive-pack " + basic}; resp.StatusCode != http.StatusOK || !slices.Equal(p.requests(), want) {
		t.Errorf("the push after the restart got %d; want 200 with push-1's value at the origin", resp.StatusCode)
	}
	if _, err := p.client(t, e, link.StackLine(key)).Get("http://other.example.net/"); err == nil {
		t.Error("the stack proxy answered after the restart of a run with a session")
	}
	if got := e.post(t, exited(runID)); got.status != http.StatusAccepted {
		t.Fatalf("the last batch: %d %s", got.status, got.body)
	}
}
