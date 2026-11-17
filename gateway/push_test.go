package gateway_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/server"
)

// The tests of this file pin a run configuration's push credentials: the push proxy
// sets them for qory's push and the calls of its submit step, and the run's proxy, which
// the sessions, the setup step, After, the image step and the host proxy go through,
// never does.

// The fake values the control seals for the work credential and the push credential.
const (
	workSecret     = "fake-read-token-of-the-push-test"
	pushSecretWord = "fake-write-token-of-the-push-test"
)

// pushWorkItem is the branch push-1's branch guard lets a push change.
const pushWorkItem = "refs/heads/qory/wi_01"

// pushRunDoc is the run configuration of a write run, with a read work credential,
// work-1, on the repository's git paths, its REST paths and /graphql of localhost, and
// a push credential, push-1, on the same git paths with the branch guard's ref, and on
// the pull request paths. Without push, it is the run configuration of a write-no-push
// run: the read work credential alone.
func pushRunDoc(push bool) string {
	d := `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["localhost"]}},"credentials":[` +
		`{"name":"work-1","apply":[{"hosts":["localhost"],"scheme":"basic","username":"x-access-token","paths":["/example-org/app.git/*","/repos/example-org/app","/repos/example-org/app/*","/graphql"]}]}`
	if push {
		d += `,{"name":"push-1","purpose":"push","apply":[{"hosts":["localhost"],"scheme":"basic","username":"x-access-token","paths":["/example-org/app.git/*"],"push_ref":"` + pushWorkItem + `"},` +
			`{"hosts":["localhost"],"scheme":"bearer","paths":["/repos/example-org/app/pulls","/repos/example-org/app/pulls/{}"]}]}`
	}
	return d + `]}`
}

// pushOrigin is an HTTPS origin on localhost, under an authority of the test's, that
// records each request's method, path and Authorization, with a gateway on the local
// link that trusts it and serves doc, whose credentials the control seals.
type pushOrigin struct {
	h     *harness
	c     *control
	port  string
	roots *x509.CertPool
	mu    sync.Mutex
	got   []string
}

func newPushOrigin(t *testing.T, doc string) *pushOrigin { return newPushOriginUnder(t, doc, nil) }

// newPushOriginUnder is newPushOrigin with node as the node's policy, none when nil.
func newPushOriginUnder(t *testing.T, doc string, node *gateway.Policy) *pushOrigin {
	t.Helper()
	certFile, keyFile, roots := testCertificate(t, t.TempDir())
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	o := &pushOrigin{roots: roots}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		o.mu.Lock()
		o.got = append(o.got, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		o.mu.Unlock()
		io.WriteString(w, "origin")
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, o.port, _ = net.SplitHostPort(srv.Listener.Addr().String())
	c := newControl(t)
	c.serveDocument(doc, 'a')
	c.mu.Lock()
	c.secrets = map[string]string{"work-1": workSecret, "push-1": pushSecretWord}
	c.mu.Unlock()
	cfg := gateway.Config{Server: c.server(), Policy: node}
	gateway.SetUpstreamRoots(&cfg, roots)
	o.h, o.c = start(t, cfg), c
	o.h.secrets = append(o.h.secrets, workSecret, pushSecretWord)
	return o
}

// client is an HTTP client through the gateway's proxy address that the secret opens,
// which trusts the origin's authority and the run's.
func (o *pushOrigin) client(t *testing.T, a *server.LinkRunAnswer, secret string) *http.Client {
	t.Helper()
	trusted := o.roots.Clone()
	if !trusted.AppendCertsFromPEM([]byte(a.CertificateAuthority)) {
		t.Fatal("the run answer has no certificate authority")
	}
	c := relay(o.h.g.Addr(), secret)
	c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: trusted}
	return c
}

// requests are what the origin got, and forgets them.
func (o *pushOrigin) requests() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	got := o.got
	o.got = nil
	return got
}

// sent is one request through a proxy and what it got: the status and the body.
type sent struct {
	status int
	body   string
}

// send sends method on path of the origin through c, with body, and returns what it got.
func send(t *testing.T, c *http.Client, port, method, path, contentType, body string) sent {
	t.Helper()
	req, err := http.NewRequest(method, "https://localhost:"+port+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return sent{resp.StatusCode, string(b)}
}

// receivePack is the body of a git push of one ref, as git sends it: the ref command
// with its capabilities, the flush and the pack.
func receivePack(ref string) string {
	line := strings.Repeat("1", 40) + " " + strings.Repeat("2", 40) + " " + ref + "\x00report-status side-band-64k agent=git/2.47.0"
	return fmt.Sprintf("%04x%s0000PACK the pack's bytes", len(line)+4, line)
}

// sessionWrites sends through c, the run's proxy, what an agent would send to change the
// target: a push of the work item's branch, a REST write of a ref under
// /repos/example-org/app/ and a GraphQL mutation. It returns the push's answer.
func sessionWrites(t *testing.T, c *http.Client, port string) sent {
	t.Helper()
	push := send(t, c, port, http.MethodPost, "/example-org/app.git/git-receive-pack", "application/x-git-receive-pack-request", receivePack(pushWorkItem))
	if got := send(t, c, port, http.MethodPatch, "/repos/example-org/app/git/refs/heads/main", "application/json", `{"sha":"2222"}`); got.status != http.StatusOK {
		t.Errorf("the REST write through the run's proxy: %+v", got)
	}
	if got := send(t, c, port, http.MethodPost, "/graphql", "application/json", `{"query":"mutation { createCommitOnBranch }"}`); got.status != http.StatusOK {
		t.Errorf("the GraphQL mutation through the run's proxy: %+v", got)
	}
	return push
}

// pushRefused is the first line of the branch guard's 403 for a push through a
// credential with no push_ref.
const pushRefused = "qory: push through qory's push step, with a credential that allows a push.\n"

// pushSplit checks the credentials of a run of [pushRunDoc]. Without push, it pins the
// document of a write-no-push run: applied, the members of the open's
// dev.qory.run.policy_applied, lists work-1 alone with no purpose, and each secrets
// request c got is for work-1 alone. With push, applied lists work-1, then push-1's two
// items with purpose push, and each secrets request is for work-1 and push-1. Behind a
// separate gateway no other test checks a write run's applied, which a session reads
// to start its push proxy.
func pushSplit(t *testing.T, c *control, applied json.RawMessage, push bool) {
	t.Helper()
	wantApplied, wantAsked := []string{"work-1 <nil>"}, []string{"work-1"}
	if push {
		wantApplied, wantAsked = append(wantApplied, "push-1 push", "push-1 push"), append(wantAsked, "push-1")
	}
	listed, _ := members(applied)["credentials"].([]any)
	var got []string
	for _, e := range listed {
		m, _ := e.(map[string]any)
		got = append(got, fmt.Sprint(m["name"], " ", m["purpose"]))
	}
	if !slices.Equal(got, wantApplied) {
		t.Errorf("the open's applied credentials %q, want %q", got, wantApplied)
	}
	asked := c.requests(t)
	if len(asked) == 0 {
		t.Error("the control got no secrets request")
	}
	for _, r := range asked {
		if !slices.Equal(r.Credentials, wantAsked) {
			t.Errorf("a secrets request for %q, want %q", r.Credentials, wantAsked)
		}
	}
}

// receivePacks returns the channel, decision and path rule of each git push's
// dev.qory.run.egress among records.
func receivePacks(records []recorded) []string {
	var out []string
	for _, l := range records {
		if l.Type == event.RunEgress && strings.HasSuffix(fmt.Sprint(l.Data["path"]), "/git-receive-pack") {
			out = append(out, fmt.Sprint(l.Data["channel"], " ", l.Data["decision"], " ", l.Data["path_rule"]))
		}
	}
	return out
}

// TestASessionsRequestsGetOnlyTheWorkCredential pins the card's split, in a write run
// and in a write-no-push run, on the local link: what the sessions, the setup step,
// After, the image step and the host proxy send through the run's proxy, the run
// answer's proxy_secret, gets the read work credential alone, never push-1's value. A
// push of the work item's branch through it gets the branch guard's 403, wall:push-ref,
// since work-1 has no push_ref, and reaches nothing; the REST write and the GraphQL
// mutation reach the origin with work-1's value. A write run's answer has a
// push_proxy_secret apart from proxy_secret; a write-no-push run's has none, and the run
// has no push proxy and no push value: its secrets request is for work-1 alone, and its
// open's dev.qory.run.policy_applied lists no credential with purpose push. A second push
// through the run's proxy after the session exited gets the same 403. The record has
// each push as a dev.qory.run.egress denied by wall:push-ref, with no channel push.
func TestASessionsRequestsGetOnlyTheWorkCredential(t *testing.T) {
	work := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+workSecret))
	for _, c := range []struct {
		name string
		push bool
	}{{"write", true}, {"write-no-push", false}} {
		t.Run(c.name, func(t *testing.T) {
			o := newPushOrigin(t, pushRunDoc(c.push))
			a := o.h.open(server.LinkRunRequest{})
			tokens, proxied := gateway.PushTokens(o.h.g, a.RunID)
			switch {
			case c.push && (a.PushProxySecret == "" || a.PushProxySecret == a.ProxySecret || a.PushProxySecret == a.StackProxySecret || !proxied ||
				!reflect.DeepEqual(tokens, map[string]string{"push-1": pushSecretWord})):
				t.Errorf("the write run's push_proxy_secret %q, push proxy %v with %v", a.PushProxySecret, proxied, tokens)
			case !c.push && (a.PushProxySecret != "" || proxied || len(tokens) != 0):
				t.Errorf("the write-no-push run's push_proxy_secret %q, push proxy %v with %v; want none", a.PushProxySecret, proxied, tokens)
			}
			if got := gateway.Tokens(o.h.g, a.RunID); !reflect.DeepEqual(got, map[string]string{"work-1": workSecret}) {
				t.Errorf("the run's proxy sets %v; want work-1 alone", got)
			}
			pushSplit(t, o.c, a.Applied, c.push)
			proxy := o.client(t, a, a.ProxySecret)
			push := sessionWrites(t, proxy, o.port)
			if push.status != http.StatusForbidden || !strings.HasPrefix(push.body, pushRefused) {
				t.Errorf("the push through the run's proxy got %+v; want the branch guard's 403", push)
			}
			want := []string{"PATCH /repos/example-org/app/git/refs/heads/main " + work, "POST /graphql " + work}
			if got := o.requests(); !slices.Equal(got, want) {
				t.Errorf("the origin got\n%q\nwant\n%q", got, want)
			}
			if d := o.h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
				t.Fatalf("the open's batch: %+v", d)
			}
			o.h.joined(a.RunID)
			if d := o.h.post(sessionStarted(a.RunID, 1), applied(a.RunID, a.Applied), sessionExited(a.RunID, 1)); !d.Accepted() {
				t.Fatalf("the join's batch: %+v", d)
			}
			if got := send(t, proxy, o.port, http.MethodPost, "/example-org/app.git/git-receive-pack", "application/x-git-receive-pack-request", receivePack(pushWorkItem)); got.status != http.StatusForbidden || !strings.HasPrefix(got.body, pushRefused) {
				t.Errorf("the push through the run's proxy after the session got %+v; want the branch guard's 403", got)
			}
			if got := o.requests(); len(got) != 0 {
				t.Errorf("the origin got %q after the session", got)
			}
			if d := o.h.post(exited(a.RunID)); !d.Accepted() {
				t.Fatalf("the last batch: %+v", d)
			}
			o.h.close()
			if got, want := receivePacks(o.h.record(a.RunID)), []string{"<nil> denied wall:push-ref", "<nil> denied wall:push-ref"}; !slices.Equal(got, want) {
				t.Errorf("the record's pushes %q, want %q", got, want)
			}
		})
	}
}

// TestThePushProxySetsThePushCredentialAlone pins the push proxy on the local link: a
// push of the work item's branch through the push_proxy_secret reaches the origin with
// push-1's value, and a push of another branch gets the branch guard's 403; a pull
// request call gets push-1's bearer value; a merge, a REST write of a ref, a GraphQL
// mutation and a path of the repository outside push-1's items get the push proxy's 403
// and reach nothing; another host gets the push proxy's 403. Each decision is a
// dev.qory.run.egress with channel push; the open's dev.qory.run.policy_applied lists
// push-1's items with purpose push, and a join's lists them too. After the run's end
// the push proxy secret opens nothing.
func TestThePushProxySetsThePushCredentialAlone(t *testing.T) {
	o := newPushOrigin(t, pushRunDoc(true))
	h := o.h
	a := h.open(server.LinkRunRequest{})
	if len(a.CredentialHosts) != 1 || a.CredentialHosts[0].Name != "work-1" {
		t.Errorf("the run answer's credential_hosts %+v; want work-1 alone", a.CredentialHosts)
	}
	push := o.client(t, a, a.PushProxySecret)
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+pushSecretWord))
	if got := send(t, push, o.port, http.MethodPost, "/example-org/app.git/git-receive-pack", "application/x-git-receive-pack-request", receivePack(pushWorkItem)); got.status != http.StatusOK {
		t.Errorf("the push of the work item's branch: %+v", got)
	}
	if got := send(t, push, o.port, http.MethodPost, "/example-org/app.git/git-receive-pack", "application/x-git-receive-pack-request", receivePack("refs/heads/main")); got.status != http.StatusForbidden || !strings.HasPrefix(got.body, "qory: push only "+pushWorkItem+".\n") {
		t.Errorf("the push of another branch: %+v", got)
	}
	if got := send(t, push, o.port, http.MethodGet, "/repos/example-org/app/pulls/12", "", ""); got.status != http.StatusOK {
		t.Errorf("the pull request call: %+v", got)
	}
	refusedPaths := []struct{ method, path string }{
		{http.MethodPut, "/repos/example-org/app/pulls/12/merge"},
		{http.MethodPatch, "/repos/example-org/app/git/refs/heads/main"},
		{http.MethodPost, "/graphql"},
		{http.MethodGet, "/example-org/other.git/info/refs"},
	}
	for _, p := range refusedPaths {
		got := send(t, push, o.port, p.method, p.path, "application/json", "{}")
		want := "qory: send only the push and its pull request calls through the push proxy.\n" +
			"qory: " + p.method + " localhost" + p.path + " denied by the gateway: no push credential of the run covers this path\n"
		if got.status != http.StatusForbidden || got.body != want {
			t.Errorf("%s %s through the push proxy got %d %q; want 403 %q", p.method, p.path, got.status, got.body, want)
		}
	}
	resp, err := push.Get("http://other.example.net/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	const unlisted = "qory: send only the push and its pull request calls through the push proxy.\n" +
		"qory: egress to other.example.net:80 denied by the gateway: no push credential of the run is for this host\n"
	if resp.StatusCode != http.StatusForbidden || string(b) != unlisted {
		t.Errorf("another host through the push proxy got %d %q", resp.StatusCode, b)
	}
	bearer := "Bearer " + pushSecretWord
	want := []string{"POST /example-org/app.git/git-receive-pack " + basic, "GET /repos/example-org/app/pulls/12 " + bearer}
	if got := o.requests(); !slices.Equal(got, want) {
		t.Errorf("the origin got\n%q\nwant\n%q", got, want)
	}
	pushEntries := []any{
		map[string]any{"name": "push-1", "hosts": []any{"localhost"}, "scheme": "basic", "paths": []any{"/example-org/app.git/*"}, "purpose": "push"},
		map[string]any{"name": "push-1", "hosts": []any{"localhost"}, "scheme": "bearer", "paths": []any{"/repos/example-org/app/pulls", "/repos/example-org/app/pulls/{}"}, "purpose": "push"},
	}
	listed, _ := members(a.Applied)["credentials"].([]any)
	if len(listed) != 3 || !reflect.DeepEqual(listed[1:], pushEntries) || listed[0].(map[string]any)["purpose"] != nil {
		t.Errorf("the open's applied credentials %v; want work-1, then push-1's items with purpose push", listed)
	}
	if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
		t.Fatalf("the open's batch: %+v", d)
	}
	h.joined(a.RunID)
	if d := h.post(sessionStarted(a.RunID, 1), applied(a.RunID, a.Applied), sessionExited(a.RunID, 1)); !d.Accepted() {
		t.Fatalf("the join's batch: %+v", d)
	}
	// The push proxy stays open after the session: qory pushes after each one.
	if got := send(t, push, o.port, http.MethodGet, "/repos/example-org/app/pulls/12", "", ""); got.status != http.StatusOK {
		t.Errorf("the pull request call after the session: %+v", got)
	}
	if d := h.post(exited(a.RunID)); !d.Accepted() {
		t.Fatalf("the last batch: %+v", d)
	}
	// The run's end closes the push proxy while the gateway runs on.
	eventually(t, "the push proxy secret opens nothing after the run's end", func() bool {
		_, err := push.Get("https://localhost:" + o.port + "/repos/example-org/app/pulls/12")
		return err != nil
	})
	h.close()
	var pushed, writes []string
	for _, l := range h.record(a.RunID) {
		if l.Type == event.RunTargetWrite {
			writes = append(writes, fmt.Sprint(l.Data["system"], " ", l.Data["path"], " ", l.Data["state"]))
			continue
		}
		if l.Type != event.RunEgress {
			continue
		}
		raw, _ := json.Marshal(l.Data)
		validDocument(t, "events/run.egress.schema.json", raw)
		if l.Data["channel"] != "push" {
			t.Errorf("a dev.qory.run.egress of another channel: %v", l.Data)
			continue
		}
		pushed = append(pushed, fmt.Sprint(l.Data["request_method"], " ", l.Data["path"], " ", l.Data["decision"], " ", l.Data["credential"], " ", l.Data["path_rule"], " ", l.Data["rule"]))
	}
	wantRecords := []string{
		"POST /example-org/app.git/git-receive-pack allowed push-1 /example-org/app.git/* localhost",
		"POST /example-org/app.git/git-receive-pack denied push-1 wall:push-ref localhost",
		"GET /repos/example-org/app/pulls/12 allowed push-1 /repos/example-org/app/pulls/{} localhost",
		"PUT /repos/example-org/app/pulls/12/merge denied <nil>  localhost",
		"PATCH /repos/example-org/app/git/refs/heads/main denied <nil>  localhost",
		"POST /graphql denied <nil>  localhost",
		"GET /example-org/other.git/info/refs denied <nil>  localhost",
		"<nil> <nil> denied <nil> <nil> ",
		"GET /repos/example-org/app/pulls/12 allowed push-1 /repos/example-org/app/pulls/{} localhost",
	}
	// The push of the work item's branch through the push proxy is a target write: one
	// record when it begins, and one when it ends, cut since the stand-in host returns
	// no report-status. The push the branch guard stopped is none.
	if wantWrites := []string{"localhost example-org/app started", "localhost example-org/app cut"}; !slices.Equal(writes, wantWrites) {
		t.Errorf("the target writes %q, want %q", writes, wantWrites)
	}
	if !slices.Equal(pushed, wantRecords) {
		t.Errorf("the push proxy's records\n%q\nwant\n%q", pushed, wantRecords)
	}
}

// TestThePushAndWorkValuesAreRenewed pins the card's renewal: a run's work-1 and push-1
// values expire an hour after the start; 5 minutes before, the gateway requests both
// from the reference receiver in one request, and from then on the run's proxy sets
// work-1's second value and the push proxy push-1's second value. The run's proxy
// returns a 403 for push-1's path and sends nothing. In a write-no-push run, with
// work-1 alone, the renewal requests work-1 alone, and the run has no push proxy
// before or after it.
func TestThePushAndWorkValuesAreRenewed(t *testing.T) {
	for _, c := range []struct {
		name string
		push bool
	}{{"write", true}, {"write-no-push", false}} {
		t.Run(c.name, func(t *testing.T) { renewsPush(t, c.push) })
	}
}

// renewsPush is TestThePushAndWorkValuesAreRenewed for a write run, with push, or a
// write-no-push run.
func renewsPush(t *testing.T, push bool) {
	certFile, keyFile, roots := testCertificate(t, t.TempDir())
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	got := map[string]string{}
	o := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got[r.URL.Path] = r.Header.Get("X-Api-Key")
		mu.Unlock()
	}))
	o.Config.ErrorLog = log.New(io.Discard, "", 0)
	o.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	o.StartTLS()
	t.Cleanup(o.Close)
	_, port, _ := net.SplitHostPort(o.Listener.Addr().String())

	clock := &stepClock{now: time.Now().UTC().Truncate(time.Second)}
	begun := clock.Now()
	ref := newReference(t, "localhost")
	doc := `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["localhost"]}},"credentials":[` +
		`{"name":"work-1","apply":[{"hosts":["localhost"],"scheme":"header","header":"x-api-key","paths":["/work/*"]}]}`
	if push {
		doc += `,{"name":"push-1","purpose":"push","apply":[{"hosts":["localhost"],"scheme":"header","header":"x-api-key","paths":["/push/*"]}]}`
	}
	ref.doc = []byte(doc + `]}`)
	ref.h.Secrets = func(_ receiver.Run, names []string) ([]receiver.Value, *receiver.Refusal) {
		ref.mu.Lock()
		n := len(ref.asked)
		ref.asked = append(ref.asked, names)
		ref.mu.Unlock()
		var out []receiver.Value
		for _, name := range names {
			v := receiver.NewValue([]byte(fmt.Sprintf("%s-value-%d-of-the-renewal-test", name, n+1)))
			v.ExpiresAt = begun.Add(time.Duration(n+1) * time.Hour)
			out = append(out, v)
		}
		return out, nil
	}
	asked := func() [][]string {
		ref.mu.Lock()
		defer ref.mu.Unlock()
		return slices.Clone(ref.asked)
	}
	cfg := gateway.Config{Server: ref.server(testKey), Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost"}}}}
	gateway.SetUpstreamRoots(&cfg, roots)
	gateway.SetRenewClock(&cfg, clock)
	h := start(t, cfg)
	for _, name := range []string{"work-1", "push-1"} {
		for i := 1; i <= 2; i++ {
			h.secrets = append(h.secrets, fmt.Sprintf("%s-value-%d-of-the-renewal-test", name, i))
		}
	}
	a := h.open(server.LinkRunRequest{})
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM([]byte(a.CertificateAuthority))
	through := func(secret, path string) string {
		t.Helper()
		c := relay(h.g.Addr(), secret)
		c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: trusted}
		mu.Lock()
		delete(got, path)
		mu.Unlock()
		resp, err := c.Get("https://localhost:" + port + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		mu.Lock()
		defer mu.Unlock()
		v, ok := got[path]
		if !ok {
			return fmt.Sprintf("(no request: %d)", resp.StatusCode)
		}
		return v
	}
	noPushProxy := func(when string) {
		t.Helper()
		if tokens, proxied := gateway.PushTokens(h.g, a.RunID); a.PushProxySecret != "" || proxied || len(tokens) != 0 {
			t.Errorf("%s the write-no-push run's push_proxy_secret %q, push proxy %v with %v; want none", when, a.PushProxySecret, proxied, tokens)
		}
	}
	if push {
		if p := through(a.PushProxySecret, "/push/x"); p != "push-1-value-1-of-the-renewal-test" {
			t.Fatalf("before the renewal the push proxy reached the origin with %q", p)
		}
	} else {
		noPushProxy("before the renewal")
	}
	if w := through(a.ProxySecret, "/work/x"); w != "work-1-value-1-of-the-renewal-test" {
		t.Fatalf("before the renewal the run's proxy reached the origin with %q", w)
	}
	// The run's proxy has no credential for push-1's path, so no path rule covers it.
	if got := through(a.ProxySecret, "/push/x"); got != "(no request: 403)" {
		t.Errorf("the run's proxy on push-1's path: %q", got)
	}
	want := []string{"work-1"}
	if push {
		want = append(want, "push-1")
	}
	clock.advance(time.Hour - 5*time.Minute)
	eventually(t, "the renewal before expires_at", func() bool { return len(asked()) == 2 })
	if a := asked(); !slices.Equal(a[1], want) {
		t.Errorf("the renewal's secrets request was for %v; want %v", a[1], want)
	}
	eventually(t, "the second values at the origin", func() bool {
		return through(a.ProxySecret, "/work/x") == "work-1-value-2-of-the-renewal-test" && (!push || through(a.PushProxySecret, "/push/x") == "push-1-value-2-of-the-renewal-test")
	})
	if !push {
		noPushProxy("after the renewal")
	}
	h.post(started(a.RunID, nil), applied(a.RunID, a.Applied), exited(a.RunID))
	h.close()
}

// TestAWalledRunsPushProxyIsGuarded pins the guard on the push proxy of a walled run, as
// on the run's proxy: a push credential's host that resolves to the gateway's machine,
// localhost, which neither the node's policy nor the run's lists by name, gets the
// guard's 403 and reaches nothing.
func TestAWalledRunsPushProxyIsGuarded(t *testing.T) {
	o := newPushOrigin(t, pushRunDoc(true))
	a := o.h.open(server.LinkRunRequest{Wall: true})
	// The guard ends the CONNECT with a 403, which the client returns as its error.
	resp, err := o.client(t, a, a.PushProxySecret).Get("https://localhost:" + o.port + "/repos/example-org/app/pulls/12")
	if err == nil {
		resp.Body.Close()
		t.Errorf("the push proxy of a walled run got %d; want the guard's 403", resp.StatusCode)
	} else if !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("the push proxy of a walled run: %v; want the guard's 403", err)
	}
	if got := o.requests(); len(got) != 0 {
		t.Errorf("the origin got %q", got)
	}
	o.h.post(started(a.RunID, nil), applied(a.RunID, a.Applied), exited(a.RunID))
	o.h.close()
}

// TestAReloadSetsThePushProxysGuard pins the guard of a walled run's push proxy across a
// reload, as the run's proxy's: under a run policy that lists no host by name, the
// guard stops the push proxy's requests to localhost; once a reload lists localhost by
// name, as the node's policy does, the push proxy reaches it with push-1's value.
func TestAReloadSetsThePushProxysGuard(t *testing.T) {
	doc := func(allow string) string {
		return strings.Replace(pushRunDoc(true), `"mode":"enforce","allow":["localhost"]`, `"mode":"observe","allow":[`+allow+`]`, 1)
	}
	o := newPushOriginUnder(t, doc(""), &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "observe", Allow: []string{"localhost"}}})
	h := o.h
	a := h.open(server.LinkRunRequest{Wall: true})
	h.mu.Lock()
	first := h.digests[len(h.digests)-1].RunConfiguration
	h.mu.Unlock()
	h.post(started(a.RunID, nil), applied(a.RunID, a.Applied))
	pull := func() error {
		resp, err := o.client(t, a, a.PushProxySecret).Get("https://localhost:" + o.port + "/repos/example-org/app/pulls/12")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("status %d", resp.StatusCode)
			}
		}
		return err
	}
	if err := pull(); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("the push proxy before the reload: %v; want the guard's 403", err)
	}
	o.c.serveDocument(doc(`"localhost"`), 'b')
	h.post(logged(a.RunID))
	eventually(t, "the reload", func() bool {
		d := h.post(heartbeat(a.RunID))
		return d.Accepted() && d.Digests.RunConfiguration != first
	})
	if err := pull(); err != nil {
		t.Errorf("the push proxy after the reload: %v", err)
	}
	if got := o.requests(); !slices.Equal(got, []string{"GET /repos/example-org/app/pulls/12 Bearer " + pushSecretWord}) {
		t.Errorf("the origin got %q", got)
	}
	h.post(exited(a.RunID))
	h.close()
}

// TestAReloadAddsNoPushCredential pins a reload of a write-no-push run whose document
// adds push-1 with purpose push: the reload fails as a change of credentials, the
// gateway reports it, and the policy in force stays. The run has no push proxy after
// it, its proxy sets work-1 alone, and its one secrets request is for work-1.
func TestAReloadAddsNoPushCredential(t *testing.T) {
	o := newPushOrigin(t, pushRunDoc(false))
	h := o.h
	a := h.open(server.LinkRunRequest{})
	h.mu.Lock()
	first := h.digests[len(h.digests)-1].RunConfiguration
	h.mu.Unlock()
	if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
		t.Fatalf("the open's batch: %+v", d)
	}
	o.c.serveDocument(pushRunDoc(true), 'b')
	h.post(logged(a.RunID))
	const line = "start a new run to use other credentials; a run's credentials from the control plane are fixed when it starts, and this run configuration has other credentials than the run started with; the policy in force stays"
	eventually(t, "the failed reload's report", func() bool {
		h.post(heartbeat(a.RunID))
		return h.reported(line)
	})
	if d := h.post(heartbeat(a.RunID)); !d.Accepted() || d.Digests.RunConfiguration != first {
		t.Errorf("the batch after the failed reload: %+v; want the run configuration %s in force", d, first)
	}
	if tokens, proxied := gateway.PushTokens(h.g, a.RunID); proxied || len(tokens) != 0 {
		t.Errorf("after the failed reload the run has a push proxy: %v with %v", proxied, tokens)
	}
	if got := gateway.Tokens(h.g, a.RunID); !reflect.DeepEqual(got, map[string]string{"work-1": workSecret}) {
		t.Errorf("after the failed reload the run's proxy sets %v; want work-1 alone", got)
	}
	if reqs := o.c.requests(t); len(reqs) != 1 || !slices.Equal(reqs[0].Credentials, []string{"work-1"}) {
		t.Errorf("the secrets requests %+v; want one for work-1", reqs)
	}
	h.post(exited(a.RunID))
	h.close()
}
