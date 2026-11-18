package gateway_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// mixedValues are the fake values of the model keys of mixedRun, by name: the
// machine's key machine, and the server's keys a-1 and a-2 of group a and b-1 and b-2
// of group b.
var mixedValues = map[string]string{"machine": "fake-machine-value-0001", "a-1": "fake-a-value-0001", "a-2": "fake-a-value-0002", "b-1": "fake-b-value-0001", "b-2": "fake-b-value-0002"}

// mixedRun is a walled run whose start key is the machine's model key machine, and whose
// run configuration has two key groups of the server's, a with a-1 and a-2 and b with
// b-1 and b-2, all of the format anthropic-messages on one fake provider. The machine's
// key reaches the provider at 127.0.0.1 and the server's keys at localhost: a
// credential from the server replaces a machine's credential of its host. The provider
// returns a limit refusal for each key in limited, and a 401 for each key in
// unauthorized. A request with the key held waits at the provider until release is
// closed, then gets the answer of that moment.
type mixedRun struct {
	h     *harness
	runID string
	url   string
	// machineURL is the endpoint of the machine's key.
	machineURL string
	agent      *http.Client
	// hosts are the run answer's credential_hosts, from which a session computes its
	// key's placeholder (link.GroupPlaceholder).
	hosts []server.LinkCredentialHosts

	mu           sync.Mutex
	limited      map[string]bool
	unauthorized map[string]bool
	calls        []string
	reports      []string
	held         string
	release      chan struct{}
}

func startMixedRun(t *testing.T) *mixedRun {
	t.Helper()
	return startKeyGroupsRun(t, true, "machine")
}

// startKeyGroupsRun opens the run of mixedRun with the start key startKey; with machine
// false, the run has no key of the machine's.
func startKeyGroupsRun(t *testing.T, machine bool, startKey string) *mixedRun {
	t.Helper()
	m := &mixedRun{limited: map[string]bool{}, unauthorized: map[string]bool{}}
	t.Setenv("GATEWAY_TEST_MACHINE_KEY", mixedValues["machine"])
	certFile, keyFile, roots := testCertificate(t, t.TempDir())
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		key := r.Header.Get("X-Api-Key")
		for name, v := range mixedValues {
			if key == v {
				key = name
			}
		}
		m.mu.Lock()
		m.calls = append(m.calls, key)
		held, release := key != "" && key == m.held, m.release
		m.mu.Unlock()
		if held {
			<-release
		}
		m.mu.Lock()
		limited, rejected := m.limited[key], m.unauthorized[key]
		m.mu.Unlock()
		if rejected {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"type":"error","error":{"type":"authentication_error"}}`)
			return
		}
		if limited {
			w.Header().Set("Anthropic-Ratelimit-Unified-5h-Status", "rejected")
			w.Header().Set("Anthropic-Ratelimit-Unified-5h-Reset", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"type":"error","error":{"type":"rate_limit_error"}}`)
			return
		}
		io.WriteString(w, `{"type":"message"}`)
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	m.url = "https://localhost:" + port + "/v1"
	m.machineURL = "https://127.0.0.1:" + port + "/v1"
	entry := func(name, group string) string {
		return `{"name":"` + name + `","group":"` + group + `","format":"anthropic-messages","endpoint":"` + m.url + `","auth":{"scheme":"header","header":"x-api-key"},"pause_for_s":3600}`
	}
	c := newControl(t)
	policy := `{"version":1,"egress":{"mode":"enforce","allow":["localhost","127.0.0.1"]},"credentials":[{"name":"machine"}]}`
	if !machine {
		policy = `{"version":1,"egress":{"mode":"enforce","allow":["localhost"]}}`
	}
	c.serveDocument(`{"version":1,"security_policy":`+policy+`,"model_credential":"`+startKey+`","credentials":[`+
		entry("a-1", "a")+`,`+entry("b-1", "b")+`,`+entry("a-2", "a")+`,`+entry("b-2", "b")+`]}`, 'a')
	c.mu.Lock()
	c.secrets = map[string]string{"a-1": mixedValues["a-1"], "a-2": mixedValues["a-2"], "b-1": mixedValues["b-1"], "b-2": mixedValues["b-2"]}
	c.mu.Unlock()
	intercept := func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasSuffix(r.URL.Path, "/model-keys") {
			return false
		}
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.reports = append(m.reports, string(body))
		m.mu.Unlock()
		out := `{"version":1,"keys":[]}`
		w.Header().Set(server.HeaderSignature, c.signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: r.Header.Get(server.HeaderSignature), Body: []byte(out)}))
		io.WriteString(w, out)
		return true
	}
	c.intercept.Store(&intercept)
	var creds []gateway.Credential
	if machine {
		creds = []gateway.Credential{{Name: "machine", Env: "GATEWAY_TEST_MACHINE_KEY", Format: "anthropic-messages", Endpoint: m.machineURL, Scheme: "header", Header: "x-api-key"}}
	}
	node := &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost", "127.0.0.1"}}}
	cfg := gateway.Config{Server: c.server(), Credentials: creds, Policy: node}
	gateway.SetUpstreamRoots(&cfg, roots)
	m.h = start(t, cfg)
	for _, v := range mixedValues {
		m.h.secrets = append(m.h.secrets, v)
	}
	a := m.h.open(server.LinkRunRequest{Wall: true})
	m.runID, m.hosts = a.RunID, a.CredentialHosts
	if a.ModelCredential != startKey {
		t.Fatalf("the run's start key %q; want %s", a.ModelCredential, startKey)
	}
	for _, c := range a.CredentialHosts {
		if c.Name == "machine" && c.Group != "" {
			t.Errorf("the machine's key has the group %q in the run answer", c.Group)
		}
	}
	if d := m.h.post(started(m.runID, nil), applied(m.runID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM([]byte(a.CertificateAuthority))
	m.agent = relay(m.h.g.Addr(), a.ProxySecret)
	m.agent.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: trusted}
	return m
}

// send sends a model request with the placeholder of key name and returns its status
// and the keys the provider got for it, a placeholder where it got no key.
func (m *mixedRun) send(t *testing.T, name string) (int, string) {
	t.Helper()
	return m.sendTo(t, name, "/messages")
}

// sendTo is send to the path path of the endpoint. The endpoints end in /v1, so the
// path of the Messages API, whose 401 takes a key out, is /v1/messages there
// ([modelkey.StreamPath]).
func (m *mixedRun) sendTo(t *testing.T, name, path string) (int, string) {
	t.Helper()
	url := m.url
	if name == "machine" {
		url = m.machineURL
	}
	return m.request(t, url+path, link.KeyPlaceholder(name))
}

// placeholder is the placeholder a session that joined with the model key name sets,
// as the session computes it from the run answer's credential_hosts.
func (m *mixedRun) placeholder(name string) string {
	var keys []link.GroupKey
	for _, c := range m.hosts {
		if c.Format != "" {
			keys = append(keys, link.GroupKey{Name: c.Name, Group: c.Group})
		}
	}
	return link.GroupPlaceholder(keys, name)
}

// sendWith sends a model request with the placeholder value to the server's endpoint,
// as send does.
func (m *mixedRun) sendWith(t *testing.T, value string) (int, string) {
	t.Helper()
	return m.request(t, m.url+"/messages", value)
}

// request posts a model request to url with value in x-api-key, as send does.
func (m *mixedRun) request(t *testing.T, url, value string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(`{"model":"m"}`))
	req.Header.Set("X-Api-Key", value)
	resp, err := m.agent.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	m.mu.Lock()
	defer m.mu.Unlock()
	calls := strings.Join(m.calls, ",")
	m.calls = nil
	return resp.StatusCode, calls
}

// batch posts a heartbeat on the run's link as the session does and returns the
// answer's status and body.
func (m *mixedRun) batch(t *testing.T) (int, string) {
	t.Helper()
	b, _ := json.Marshal([]map[string]any{heartbeat(m.runID)})
	return rawPostWith(t, raw(t, m.h.g.LocalLink()), "/v1/events", server.ContentType, string(b),
		http.Header{server.HeaderRunID: {m.runID}, server.HeaderDelivery: {event.NewID()}})
}

// limit makes the provider refuse each key named at its limit.
func (m *mixedRun) limit(names ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range names {
		m.limited[n] = true
	}
}

// join joins a session with the model key name in its request, none for "", and returns the key of
// the answer.
func (m *mixedRun) join(t *testing.T, name string) string {
	t.Helper()
	a, err := m.h.linkOf(m.runID).Join(t.Context(), server.LocalOrigin+"/v1/run-configuration", m.runID, server.LinkJoinRequest{Passes: []string{}, ModelKey: true, ModelCredential: name})
	if err != nil {
		t.Fatalf("the join naming %q: %v", name, err)
	}
	return a.ModelCredential
}

// TestAMachineKeyIsInNoKeyGroup pins a run whose start key is the machine's model key,
// beside two key groups of the server's, a and b. Session 1 joins with no key in its
// request and gets the machine's key alone: a request with the placeholder of group a
// gets no key. Session 2 joins with a-2, of group a, which no session used: it gets
// a-2, a limit refusal of a-2 goes again with a-1, and the machine's key and group b get
// no key. Session 3 joins with no key in its request and gets the machine's key again,
// with no rotation and no stop after group a's refusal. The model keys reports list the
// keys of both groups and never the machine's.
func TestAMachineKeyIsInNoKeyGroup(t *testing.T) {
	m := startMixedRun(t)
	if key := m.join(t, ""); key != "machine" {
		t.Fatalf("join 1: %q; want machine", key)
	}
	m.h.post(sessionStarted(m.runID, 1))
	if status, calls := m.send(t, "machine"); status != http.StatusOK || calls != "machine" {
		t.Errorf("session 1, machine's placeholder: %d %q; want machine", status, calls)
	}
	if status, calls := m.send(t, "a-1"); status != http.StatusOK || calls != link.KeyPlaceholder("a-1") {
		t.Errorf("session 1, group a's placeholder: %d %q; want no key", status, calls)
	}
	m.h.post(sessionExited(m.runID, 1))

	if key := m.join(t, "a-2"); key != "a-2" {
		t.Fatalf("join 2 naming a-2: %q; want a-2", key)
	}
	m.h.post(sessionStarted(m.runID, 2))
	m.mu.Lock()
	m.limited["a-2"] = true
	m.mu.Unlock()
	if status, calls := m.send(t, "a-1"); status != http.StatusOK || calls != "a-2,a-1" {
		t.Errorf("session 2, group a's placeholder: %d %q; want a-2 refused, then a-1", status, calls)
	}
	if status, calls := m.send(t, "machine"); status != http.StatusOK || calls != link.KeyPlaceholder("machine") {
		t.Errorf("session 2, machine's placeholder: %d %q; want no key", status, calls)
	}
	if status, calls := m.send(t, "b-1"); status != http.StatusOK || calls != link.KeyPlaceholder("b-1") {
		t.Errorf("session 2, group b's placeholder: %d %q; want no key", status, calls)
	}
	if status, body := m.batch(t); status != http.StatusAccepted || body != "" {
		t.Errorf("a batch of session 2: %d %q; want 202 with no stop", status, body)
	}
	m.h.post(sessionExited(m.runID, 2))

	if key := m.join(t, ""); key != "machine" {
		t.Fatalf("join 3: %q; want machine", key)
	}
	m.h.post(sessionStarted(m.runID, 3))
	if status, calls := m.send(t, "machine"); status != http.StatusOK || calls != "machine" {
		t.Errorf("session 3, machine's placeholder: %d %q; want machine", status, calls)
	}
	if status, calls := m.send(t, "a-1"); status != http.StatusOK || calls != link.KeyPlaceholder("a-1") {
		t.Errorf("session 3, group a's placeholder: %d %q; want no key", status, calls)
	}
	eventually(t, "a report with a-2's cooldown", func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, r := range m.reports {
			if strings.Contains(r, `"credential":"a-2","window":"five_hour","status":"rejected"`) {
				return true
			}
		}
		return false
	})
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.reports {
		if strings.Contains(r, `"machine"`) {
			t.Errorf("a report lists the machine's key: %s", r)
		}
	}
}

// TestALaterSessionGetsItsGroupsKey pins a run of two key groups of the server's, a with
// the start key a-1 and b. Session 1 joins with no key in its request and gets a-1; a
// limit refusal of a-1 goes again with a-2, and a request with group b's placeholder
// gets no key. Session 2 joins with b-2, of group b, which no session used, and gets
// b-2: the proxy sets it on a request with b-1's placeholder, the placeholder of group
// b's first key, and sets no key of group a. With every key of group b at its limit, the
// refusal reaches the session, the next request gets the gateway's 429, and the next
// batch's answer has stop, model_key_limit; group a takes no part. Session 3 joins with
// no key in its request and gets a-2, group a's active key, with no stop in its batches.
func TestALaterSessionGetsItsGroupsKey(t *testing.T) {
	m := startKeyGroupsRun(t, false, "a-1")
	if key := m.join(t, ""); key != "a-1" {
		t.Fatalf("join 1: %q; want a-1", key)
	}
	m.h.post(sessionStarted(m.runID, 1))
	m.limit("a-1")
	if status, calls := m.send(t, "a-1"); status != http.StatusOK || calls != "a-1,a-2" {
		t.Errorf("session 1, group a's placeholder: %d %q; want a-1 refused, then a-2", status, calls)
	}
	if status, calls := m.send(t, "b-1"); status != http.StatusOK || calls != link.KeyPlaceholder("b-1") {
		t.Errorf("session 1, group b's placeholder: %d %q; want no key", status, calls)
	}
	m.h.post(sessionExited(m.runID, 1))

	if key := m.join(t, "b-2"); key != "b-2" {
		t.Fatalf("join 2 naming b-2: %q; want b-2", key)
	}
	m.h.post(sessionStarted(m.runID, 2))
	if status, calls := m.send(t, "b-1"); status != http.StatusOK || calls != "b-2" {
		t.Errorf("session 2, group b's placeholder: %d %q; want b-2", status, calls)
	}
	if status, calls := m.send(t, "a-1"); status != http.StatusOK || calls != link.KeyPlaceholder("a-1") {
		t.Errorf("session 2, group a's placeholder: %d %q; want no key", status, calls)
	}
	m.limit("b-1", "b-2")
	if status, calls := m.send(t, "b-1"); status != http.StatusTooManyRequests || calls != "b-2,b-1" {
		t.Errorf("session 2 with group b at its limit: %d %q; want the refusal after b-2 and b-1", status, calls)
	}
	if status, calls := m.send(t, "b-1"); status != http.StatusTooManyRequests || calls != "" {
		t.Errorf("session 2 after the stop: %d %q; want the gateway's 429 and no call", status, calls)
	}
	if status, body := m.batch(t); status != http.StatusAccepted || body != `{"stop":{"reason":"model_key_limit"}}` {
		t.Errorf("a batch of session 2: %d %q; want stop, model_key_limit", status, body)
	}
	m.h.post(ev(m.runID, event.SessionExited, map[string]any{"session": 2, "state": "paused", "exit_code": -1, "signal": "SIGTERM", "reason": "model_key_limit", "duration_ms": 5}))

	if key := m.join(t, ""); key != "a-2" {
		t.Fatalf("join 3: %q; want a-2, group a's active key", key)
	}
	m.h.post(sessionStarted(m.runID, 3))
	if status, calls := m.send(t, "a-1"); status != http.StatusOK || calls != "a-2" {
		t.Errorf("session 3, group a's placeholder: %d %q; want a-2", status, calls)
	}
	if status, body := m.batch(t); status != http.StatusAccepted || body != "" {
		t.Errorf("a batch of session 3: %d %q; want 202 with no stop", status, body)
	}
}

// TestAGroupWithEveryKeyOutStopsItsSessionAlone pins a 401 for every key of group b, of
// a run whose start key is a-1, of group a. Session 1 joins with b-2: the proxy sets
// b-2, then b-1, and the provider returns a 401 for each, whose values have no
// expires_at, so both are out for the run. The 401 reaches the session, and the answer
// to the next batch has stop, model_key_unauthorized. Session 2 then joins with no key in
// its request and gets a-1, of group a, with no stop in its batches.
func TestAGroupWithEveryKeyOutStopsItsSessionAlone(t *testing.T) {
	m := startKeyGroupsRun(t, false, "a-1")
	m.mu.Lock()
	m.unauthorized["b-1"], m.unauthorized["b-2"] = true, true
	m.mu.Unlock()
	if key := m.join(t, "b-2"); key != "b-2" {
		t.Fatalf("join 1 naming b-2: %q; want b-2", key)
	}
	m.h.post(sessionStarted(m.runID, 1))
	if status, calls := m.sendTo(t, "b-1", "/v1/messages"); status != http.StatusUnauthorized || calls != "b-2,b-1" {
		t.Errorf("session 1, group b's placeholder: %d %q; want the 401 after b-2 and b-1", status, calls)
	}
	if status, body := m.batch(t); status != http.StatusAccepted || body != `{"stop":{"reason":"model_key_unauthorized"}}` {
		t.Errorf("a batch of session 1: %d %q; want stop, model_key_unauthorized", status, body)
	}
	m.h.post(ev(m.runID, event.SessionExited, map[string]any{"session": 1, "state": "failed", "exit_code": 1, "reason": "model_key_unauthorized", "duration_ms": 5}))

	if key := m.join(t, ""); key != "a-1" {
		t.Fatalf("join 2: %q; want a-1, group a's active key", key)
	}
	m.h.post(sessionStarted(m.runID, 2))
	if status, calls := m.send(t, "a-1"); status != http.StatusOK || calls != "a-1" {
		t.Errorf("session 2, group a's placeholder: %d %q; want a-1", status, calls)
	}
	if status, body := m.batch(t); status != http.StatusAccepted || body != "" {
		t.Errorf("a batch of session 2: %d %q; want 202 with no stop", status, body)
	}
}

// TestALateRefusalLeavesASessionOnTheMachinesKeyAlone pins a limit refusal of group a
// that reaches the proxy after a session on the machine's model key joined. The run's
// start key is a-1, of group a, beside the machine's key. Session 1 joins with no key
// in its request and gets a-1, and its request waits at the provider. Session 1 ends,
// and session 2 joins with the machine's key. Only then does the provider refuse a-1
// and a-2 at their limit, so the proxy passes the refusal for group a. Session 2's
// batches have no stop: its key is in no group.
func TestALateRefusalLeavesASessionOnTheMachinesKeyAlone(t *testing.T) {
	m := startKeyGroupsRun(t, true, "a-1")
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	// The provider's server closes only once the request it holds ends.
	t.Cleanup(free)
	m.mu.Lock()
	m.held, m.release = "a-1", release
	m.mu.Unlock()
	if key := m.join(t, ""); key != "a-1" {
		t.Fatalf("join 1: %q; want a-1", key)
	}
	m.h.post(sessionStarted(m.runID, 1))
	req, _ := http.NewRequest(http.MethodPost, m.url+"/messages", strings.NewReader(`{"model":"m"}`))
	req.Header.Set("X-Api-Key", link.KeyPlaceholder("a-1"))
	answered := make(chan int, 1)
	go func() {
		resp, err := m.agent.Do(req)
		if err != nil {
			answered <- 0
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		answered <- resp.StatusCode
	}()
	eventually(t, "session 1's request at the provider", func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return slices.Contains(m.calls, "a-1")
	})
	m.h.post(sessionExited(m.runID, 1))
	if key := m.join(t, "machine"); key != "machine" {
		t.Fatalf("join 2 naming machine: %q; want machine", key)
	}
	m.h.post(sessionStarted(m.runID, 2))
	m.limit("a-1", "a-2")
	free()
	if status := <-answered; status != http.StatusTooManyRequests {
		t.Fatalf("session 1's request: %d; want the provider's 429", status)
	}
	m.mu.Lock()
	calls := strings.Join(m.calls, ",")
	m.calls = nil
	m.mu.Unlock()
	if calls != "a-1,a-2" {
		t.Errorf("the provider got %q; want a-1, then a-2", calls)
	}
	if status, body := m.batch(t); status != http.StatusAccepted || body != "" {
		t.Errorf("a batch of session 2: %d %q; want 202 with no stop", status, body)
	}
	if status, calls := m.send(t, "machine"); status != http.StatusOK || calls != "machine" {
		t.Errorf("session 2, machine's placeholder: %d %q; want machine", status, calls)
	}
}

// TestTheNextSessionGetsTheGroupsPlaceholder pins the placeholder of a key group across
// the sessions of one run of the group a, with a-1 and then a-2, for each start key.
// Session 1 joins with no key in its request and gets the start key. The placeholder
// computed from the run answer's credential_hosts is a-1's, the group's first key's, and
// a request with it reaches the provider with the start key, gets a limit refusal, and
// goes again with the other key. Session 2 joins with no key in its request and gets
// the other key, the group's active key: its placeholder is a-1's too, and a request
// with it reaches the provider with the active key alone.
func TestTheNextSessionGetsTheGroupsPlaceholder(t *testing.T) {
	for _, c := range []struct{ start, next string }{{"a-1", "a-2"}, {"a-2", "a-1"}} {
		t.Run("start key "+c.start, func(t *testing.T) {
			m := startKeyGroupsRun(t, false, c.start)
			want := link.KeyPlaceholder("a-1")
			key := m.join(t, "")
			if p := m.placeholder(key); key != c.start || p != want {
				t.Fatalf("join 1: %q with the placeholder %q; want %s with %q", key, p, c.start, want)
			}
			m.h.post(sessionStarted(m.runID, 1))
			m.limit(c.start)
			if status, calls := m.sendWith(t, m.placeholder(key)); status != http.StatusOK || calls != c.start+","+c.next {
				t.Errorf("session 1: %d %q; want %s refused, then %s", status, calls, c.start, c.next)
			}
			m.h.post(sessionExited(m.runID, 1))

			key = m.join(t, "")
			if p := m.placeholder(key); key != c.next || p != want {
				t.Fatalf("join 2: %q with the placeholder %q; want %s, the group's active key, with %q", key, p, c.next, want)
			}
			m.h.post(sessionStarted(m.runID, 2))
			if status, calls := m.sendWith(t, m.placeholder(key)); status != http.StatusOK || calls != c.next {
				t.Errorf("session 2: %d %q; want %s", status, calls, c.next)
			}
		})
	}
}

// TestASessionOnAnotherGroupGetsThatGroupsPlaceholder pins two key groups whose keys
// alternate in the run configuration: a with the start key a-1 and a-2, and b with b-1
// and b-2. Session 1 joins with no key in its request and gets a-1, whose placeholder,
// computed from the run answer's credential_hosts, is a-1's; a request with it reaches
// the provider with a-1. Session 2 joins with b-2, of group b, which no session used:
// its placeholder is b-1's, the placeholder of group b's first key, and a request with
// it reaches the provider with b-2.
func TestASessionOnAnotherGroupGetsThatGroupsPlaceholder(t *testing.T) {
	m := startKeyGroupsRun(t, false, "a-1")
	key := m.join(t, "")
	if p := m.placeholder(key); key != "a-1" || p != link.KeyPlaceholder("a-1") {
		t.Fatalf("join 1: %q with the placeholder %q; want a-1 with a-1's", key, p)
	}
	m.h.post(sessionStarted(m.runID, 1))
	if status, calls := m.sendWith(t, m.placeholder(key)); status != http.StatusOK || calls != "a-1" {
		t.Errorf("session 1: %d %q; want a-1", status, calls)
	}
	m.h.post(sessionExited(m.runID, 1))

	key = m.join(t, "b-2")
	if p := m.placeholder(key); key != "b-2" || p != link.KeyPlaceholder("b-1") {
		t.Fatalf("join 2 naming b-2: %q with the placeholder %q; want b-2 with b-1's, group b's", key, p)
	}
	m.h.post(sessionStarted(m.runID, 2))
	if status, calls := m.sendWith(t, m.placeholder(key)); status != http.StatusOK || calls != "b-2" {
		t.Errorf("session 2: %d %q; want b-2", status, calls)
	}
}

// TestALaterJoinOnAGroupInCooldownStops pins a join on a key group whose keys are all in
// cooldown, in a run whose start key is a-1, of group a. Session 1 joins with b-2, and
// the provider refuses b-2 and b-1 at their limit: both keys of group b are in cooldown
// for an hour, and session 1 pauses with model_key_limit. Session 2 then joins with
// b-1: the gateway accepts the join with b-1, the group's active key, and a request
// with group b's placeholder gets the gateway's 429 with no call to the provider. The
// answer to session 2's next batch has stop, model_key_limit.
func TestALaterJoinOnAGroupInCooldownStops(t *testing.T) {
	m := startKeyGroupsRun(t, false, "a-1")
	if key := m.join(t, "b-2"); key != "b-2" {
		t.Fatalf("join 1 naming b-2: %q; want b-2", key)
	}
	m.h.post(sessionStarted(m.runID, 1))
	m.limit("b-1", "b-2")
	if status, calls := m.sendWith(t, m.placeholder("b-2")); status != http.StatusTooManyRequests || calls != "b-2,b-1" {
		t.Errorf("session 1: %d %q; want the refusal after b-2 and b-1", status, calls)
	}
	if status, body := m.batch(t); status != http.StatusAccepted || body != `{"stop":{"reason":"model_key_limit"}}` {
		t.Errorf("a batch of session 1: %d %q; want stop, model_key_limit", status, body)
	}
	m.h.post(ev(m.runID, event.SessionExited, map[string]any{"session": 1, "state": "paused", "exit_code": -1, "signal": "SIGTERM", "reason": "model_key_limit", "duration_ms": 5}))

	key := m.join(t, "b-1")
	if key != "b-1" {
		t.Fatalf("join 2 naming b-1: %q; want b-1, group b's active key", key)
	}
	m.h.post(sessionStarted(m.runID, 2))
	if status, calls := m.sendWith(t, m.placeholder(key)); status != http.StatusTooManyRequests || calls != "" {
		t.Errorf("session 2: %d %q; want the gateway's 429 and no call", status, calls)
	}
	if status, body := m.batch(t); status != http.StatusAccepted || body != `{"stop":{"reason":"model_key_limit"}}` {
		t.Errorf("a batch of session 2: %d %q; want stop, model_key_limit", status, body)
	}
}
