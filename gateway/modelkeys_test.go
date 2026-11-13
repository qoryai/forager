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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// groupValues are the fake values of the key group's three keys, by name.
var groupValues = map[string]string{"model": "fake-group-value-0001", "model-2": "fake-group-value-0002", "model-3": "fake-group-value-0003"}

// groupRun is a walled run whose run configuration has a key group of three keys, model,
// model-2 and model-3, on the endpoint's host of a fake provider, and a control that
// serves model keys reports.
type groupRun struct {
	h     *harness
	c     *control
	runID string
	// limited are the keys the provider returns a limit refusal for.
	mu      sync.Mutex
	limited map[string]bool
	// unauthorized are the keys the provider returns 401 for.
	unauthorized map[string]bool
	calls        []string
	// reports are the bodies of the model keys reports, and answer, when set, the
	// status and body of the control's answer to each; a signed 200 with no key by
	// default.
	reports [][]byte
	answer  func() (int, string)
	agent   *http.Client
	url     string
	// format is the API format of the keys.
	format string
}

// startGroupRun opens the run, with keys of the format anthropic-messages, and posts
// its first batch.
func startGroupRun(t *testing.T) *groupRun {
	t.Helper()
	return startGroupRunOf(t, "anthropic-messages")
}

// startGroupRunOf opens the run, with keys of the format, and posts its first batch. A
// key of anthropic-messages goes in the header x-api-key, and the provider's refusal is
// Anthropic's; a key of openai-responses goes as a bearer, and the refusal is a ChatGPT
// subscription's, its shape from the openai/codex source at 17a0e6f63f (to confirm
// with probe burst-429).
func startGroupRunOf(t *testing.T, format string) *groupRun {
	t.Helper()
	g := &groupRun{limited: map[string]bool{}, unauthorized: map[string]bool{}, format: format}
	certFile, keyFile, roots := testCertificate(t, t.TempDir())
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		key := ""
		for name, v := range groupValues {
			if r.Header.Get("X-Api-Key") == v || r.Header.Get("Authorization") == "Bearer "+v {
				key = name
			}
		}
		g.mu.Lock()
		g.calls = append(g.calls, key)
		limited, rejected := g.limited[key], g.unauthorized[key]
		g.mu.Unlock()
		if rejected {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"type":"error","error":{"type":"authentication_error"}}`)
			return
		}
		if limited && format == "openai-responses" {
			reset := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
			w.Header().Set("X-Codex-Primary-Used-Percent", "100")
			w.Header().Set("X-Codex-Primary-Window-Minutes", "300")
			w.Header().Set("X-Codex-Primary-Reset-At", reset)
			w.Header().Set("X-Codex-Rate-Limit-Reached-Type", "rate_limit_reached")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"error":{"type":"usage_limit_reached","resets_at":`+reset+`}}`)
			return
		}
		if limited {
			w.Header().Set("Anthropic-Ratelimit-Unified-5h-Status", "rejected")
			w.Header().Set("Anthropic-Ratelimit-Unified-5h-Reset", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"type":"error","error":{"type":"rate_limit_error"}}`)
			return
		}
		w.Header().Set("Anthropic-Ratelimit-Unified-5h-Status", "allowed")
		w.Header().Set("Anthropic-Ratelimit-Unified-5h-Utilization", "0.42")
		io.WriteString(w, `{"type":"message"}`)
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	g.url = "https://localhost:" + port + "/v1"
	auth := `{"scheme":"header","header":"x-api-key"}`
	if format == "openai-responses" {
		auth = `{"scheme":"bearer"}`
	}
	entry := func(name string) string {
		return `{"name":"` + name + `","format":"` + format + `","endpoint":"` + g.url + `","auth":` + auth + `,"pause_for_s":3600}`
	}
	doc := `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["localhost"]}},"model_credential":"model","credentials":[` +
		entry("model") + `,` + entry("model-2") + `,` + entry("model-3") + `]}`
	g.c = newControl(t)
	g.c.serveDocument(doc, 'a')
	g.c.mu.Lock()
	g.c.secrets = groupValues
	g.c.mu.Unlock()
	intercept := func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasSuffix(r.URL.Path, "/model-keys") {
			return false
		}
		body, _ := io.ReadAll(r.Body)
		g.mu.Lock()
		g.reports = append(g.reports, body)
		answer := g.answer
		g.mu.Unlock()
		status, out := http.StatusOK, `{"version":1,"keys":[]}`
		if answer != nil {
			status, out = answer()
		}
		w.Header().Set(server.HeaderSignature, g.c.signer.SignAnswer(accesskey.Answer{Status: status, RequestSignature: r.Header.Get(server.HeaderSignature), Body: []byte(out)}))
		w.WriteHeader(status)
		io.WriteString(w, out)
		return true
	}
	g.c.intercept.Store(&intercept)
	node := &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost"}}}
	cfg := gateway.Config{Server: g.c.server(), Policy: node}
	gateway.SetUpstreamRoots(&cfg, roots)
	g.h = start(t, cfg)
	for _, v := range groupValues {
		g.h.secrets = append(g.h.secrets, v)
	}
	a := g.h.open(server.LinkRunRequest{Wall: true})
	g.runID = a.RunID
	if a.ModelCredential != "model" {
		t.Fatalf("the run's start key %q", a.ModelCredential)
	}
	if d := g.h.post(started(g.runID, nil), applied(g.runID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM([]byte(a.CertificateAuthority))
	g.agent = relay(g.h.g.Addr(), a.ProxySecret)
	g.agent.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: trusted}
	return g
}

// send sends a model request with the start key's placeholder and returns its status
// and the keys the provider received since the last send.
func (g *groupRun) send(t *testing.T) (int, []string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, g.url+"/messages", strings.NewReader(`{"model":"m"}`))
	req.Header.Set("X-Api-Key", link.KeyPlaceholder("model"))
	if g.format == "openai-responses" {
		req, _ = http.NewRequest(http.MethodPost, g.url+"/responses", strings.NewReader(`{"model":"m"}`))
		req.Header.Set("Authorization", "Bearer "+link.KeyPlaceholder("model"))
	}
	resp, err := g.agent.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	g.mu.Lock()
	defer g.mu.Unlock()
	calls := g.calls
	g.calls = nil
	return resp.StatusCode, calls
}

// limit makes the provider refuse each key named at its limit.
func (g *groupRun) limit(names ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, n := range names {
		g.limited[n] = true
	}
}

// batch posts evs on the run's link as the session does and returns the answer's
// status and body.
func (g *groupRun) batch(t *testing.T, evs ...map[string]any) (int, string) {
	t.Helper()
	b, _ := json.Marshal(evs)
	return rawPostWith(t, raw(t, g.h.g.LocalLink()), "/v1/events", server.ContentType, string(b),
		http.Header{server.HeaderRunID: {g.runID}, server.HeaderDelivery: {event.NewID()}})
}

// TestAKeyGroupResendsReportsAndStops pins the gateway side of several model keys: the
// join gets the active key, a refused request goes again with the next key, the
// control gets reports the schema accepts, a join naming a key of the group gets the
// active key, and once no key is left the next batch's answer has stop, which ends with
// the session's dev.qory.session.exited; the run then closes cancelled with
// model_key_limit.
func TestAKeyGroupResendsReportsAndStops(t *testing.T) {
	g := startGroupRun(t)
	one, err := g.h.join(g.runID)
	if err != nil || one.ModelCredential != "model" {
		t.Fatalf("join 1: %+v, %v", one, err)
	}
	g.h.post(sessionStarted(g.runID, 1))
	g.limit("model")
	if status, calls := g.send(t); status != http.StatusOK || strings.Join(calls, ",") != "model,model-2" {
		t.Fatalf("the first request: %d, %v; want 200 after model and model-2", status, calls)
	}
	eventually(t, "a report with model's cooldown", func() bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		for _, r := range g.reports {
			if strings.Contains(string(r), `"credential":"model","window":"five_hour","status":"rejected"`) && strings.Contains(string(r), `"credential":"model-2"`) {
				return true
			}
		}
		return false
	})
	schema, err := contracts.Compile("model-keys-report.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	for _, r := range g.reports {
		doc, _ := contracts.Decode("r.json", r)
		if err := schema.Validate(doc); err != nil {
			t.Errorf("the report %s fails the schema: %v", r, err)
		}
	}
	g.mu.Unlock()
	if status, body := g.batch(t, heartbeat(g.runID)); status != http.StatusAccepted || body != "" {
		t.Errorf("a batch while a key is left: %d %q; want 202 with no body", status, body)
	}
	g.h.post(sessionExited(g.runID, 1))

	two, err := g.h.linkOf(g.runID).Join(t.Context(), server.LocalOrigin+"/v1/run-configuration", g.runID, server.LinkJoinRequest{Passes: []string{}, ModelKey: true, ModelCredential: "model-3"})
	if err != nil || two.ModelCredential != "model-2" {
		t.Fatalf("join 2 naming model-3: %+v, %v; want the active key, model-2", two, err)
	}
	g.h.post(sessionStarted(g.runID, 2))
	g.limit("model-2", "model-3")
	if status, calls := g.send(t); status != http.StatusTooManyRequests || strings.Join(calls, ",") != "model-2,model-3" {
		t.Fatalf("with no key left: %d, %v; want the refusal after model-2 and model-3", status, calls)
	}
	if status, calls := g.send(t); status != http.StatusTooManyRequests || len(calls) != 0 {
		t.Errorf("after the stop: %d, %v; want the gateway's 429 and no call", status, calls)
	}
	for range 2 {
		if status, body := g.batch(t, heartbeat(g.runID)); status != http.StatusAccepted || body != `{"stop":{"reason":"model_key_limit"}}` {
			t.Errorf("a batch after the stop: %d %q; want 202 with stop", status, body)
		}
	}
	paused := ev(g.runID, event.SessionExited, map[string]any{"session": 2, "state": "paused", "exit_code": -1, "signal": "SIGTERM", "reason": "model_key_limit", "duration_ms": 5})
	if status, body := g.batch(t, paused); status != http.StatusAccepted || body != "" {
		t.Errorf("the session's end: %d %q; want 202 with no stop", status, body)
	}
	if status, body := g.batch(t, exitedWith(g.runID, map[string]any{"state": "paused", "exit_code": -1, "signal": "SIGTERM", "reason": "model_key_limit"})); status != http.StatusAccepted {
		t.Errorf("the close: %d %q", status, body)
	}
	if lines := g.h.reportsWith("limit answer, status 429"); len(lines) != 3 {
		t.Errorf("the log of limit answers: %q; want 3 lines", lines)
	}
}

// TestAnOpenAIKeyGroupStopsAtTheFirstRefusal pins the gateway side of a 429 for an
// openai-responses group: the provider's first 429 reaches the session with no resend,
// the next request gets the gateway's 429 and reaches no provider, and the answer to
// the session's next batch has stop, model_key_limit, before any dev.qory.session.exited;
// the run then closes paused with model_key_limit.
func TestAnOpenAIKeyGroupStopsAtTheFirstRefusal(t *testing.T) {
	g := startGroupRunOf(t, "openai-responses")
	one, err := g.h.join(g.runID)
	if err != nil || one.ModelCredential != "model" {
		t.Fatalf("join 1: %+v, %v", one, err)
	}
	g.h.post(sessionStarted(g.runID, 1))
	if status, calls := g.send(t); status != http.StatusOK || strings.Join(calls, ",") != "model" {
		t.Fatalf("the first request: %d, %v; want 200 from model", status, calls)
	}
	if status, body := g.batch(t, heartbeat(g.runID)); status != http.StatusAccepted || body != "" {
		t.Errorf("a batch before the refusal: %d %q; want 202 with no body", status, body)
	}
	g.limit("model")
	if status, calls := g.send(t); status != http.StatusTooManyRequests || strings.Join(calls, ",") != "model" {
		t.Fatalf("the refused request: %d, %v; want the provider's 429 from model alone", status, calls)
	}
	if status, calls := g.send(t); status != http.StatusTooManyRequests || len(calls) != 0 {
		t.Errorf("after the refusal: %d, %v; want the gateway's 429 and no call", status, calls)
	}
	if status, body := g.batch(t, heartbeat(g.runID)); status != http.StatusAccepted || body != `{"stop":{"reason":"model_key_limit"}}` {
		t.Errorf("the next batch: %d %q; want 202 with stop", status, body)
	}
	paused := ev(g.runID, event.SessionExited, map[string]any{"session": 1, "state": "paused", "exit_code": -1, "signal": "SIGINT", "reason": "model_key_limit", "duration_ms": 5})
	if status, body := g.batch(t, paused); status != http.StatusAccepted || body != "" {
		t.Errorf("the session's end: %d %q; want 202 with no stop", status, body)
	}
	if status, body := g.batch(t, exitedWith(g.runID, map[string]any{"state": "paused", "exit_code": -1, "signal": "SIGINT", "reason": "model_key_limit"})); status != http.StatusAccepted {
		t.Errorf("the close: %d %q", status, body)
	}
	if lines := g.h.reportsWith("limit answer, status 429, error type usage_limit_reached"); len(lines) != 1 {
		t.Errorf("the log of limit answers: %q; want 1 line", lines)
	}
}

// TestAnOpenAIKeyCooledByAReportStopsTheSession pins an openai-responses group whose
// active key goes into cooldown from the answer to a model keys report, during a
// session: the proxy sets no other key, the next request gets the gateway's 429, the
// provider gets no request with model-2, and the next batch's answer has stop,
// model_key_limit.
func TestAnOpenAIKeyCooledByAReportStopsTheSession(t *testing.T) {
	g := startGroupRunOf(t, "openai-responses")
	later := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	g.mu.Lock()
	g.answer = func() (int, string) {
		return http.StatusOK, `{"version":1,"keys":[{"credential":"model","window":"five_hour","status":"rejected","cooldown_until":"` + later +
			`","source":"provider","observed_at":"` + time.Now().Add(time.Minute).UTC().Format(time.RFC3339) + `"}]}`
	}
	g.mu.Unlock()
	if one, err := g.h.join(g.runID); err != nil || one.ModelCredential != "model" {
		t.Fatalf("join 1: %+v, %v", one, err)
	}
	g.h.post(sessionStarted(g.runID, 1))
	eventually(t, "the gateway's 429 after the report's answer", func() bool {
		status, calls := g.send(t)
		for _, c := range calls {
			if c != "model" {
				t.Fatalf("the provider got a request with %q; want model alone", c)
			}
		}
		return status == http.StatusTooManyRequests && len(calls) == 0
	})
	if status, body := g.batch(t, heartbeat(g.runID)); status != http.StatusAccepted || body != `{"stop":{"reason":"model_key_limit"}}` {
		t.Errorf("the next batch: %d %q; want 202 with stop", status, body)
	}
}

// TestAReportAnsweredWithACooldownBarsTheKey pins the merge of a report's answer: a key
// that another run found at its limit, with a cooldown in the answer, is not set; and a
// 404 stops the reports and writes the one dev.qory.run.log line.
func TestAReportAnsweredWithACooldownBarsTheKey(t *testing.T) {
	g := startGroupRun(t)
	later := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	g.mu.Lock()
	g.answer = func() (int, string) {
		return http.StatusOK, `{"version":1,"keys":[{"credential":"model-2","window":"seven_day","status":"rejected","cooldown_until":"` + later +
			`","source":"provider","observed_at":"` + time.Now().Add(time.Minute).UTC().Format(time.RFC3339) + `"}]}`
	}
	g.mu.Unlock()
	g.h.joined(g.runID)
	g.h.post(sessionStarted(g.runID, 1))
	if status, calls := g.send(t); status != http.StatusOK || strings.Join(calls, ",") != "model" {
		t.Fatalf("the first request: %d, %v", status, calls)
	}
	eventually(t, "a report", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return len(g.reports) > 0 })
	g.limit("model")
	// The answer of the report arrives after the request, and the next request may come
	// first: the test waits for a moment the answer is in.
	time.Sleep(100 * time.Millisecond)
	if status, calls := g.send(t); status != http.StatusOK || strings.Join(calls, ",") != "model,model-3" {
		t.Errorf("after the answer: %d, %v; want model, then model-3, skipping model-2", status, calls)
	}
	g.mu.Lock()
	g.answer = func() (int, string) { return http.StatusNotFound, `{"error":"not_found"}` }
	g.mu.Unlock()
	g.limit("model-3")
	g.send(t)
	line := "Upgrade the control plane to share model key cooldowns between runs: "
	eventually(t, "the run.log line of a 404", func() bool {
		for _, r := range g.h.record(g.runID) {
			if r.Type == event.RunLog {
				b, _ := base64.StdEncoding.DecodeString(r.Data["bytes"].(string))
				if strings.HasPrefix(string(b), line) && strings.HasSuffix(string(b), " returned 404 for model-keys\n") {
					return true
				}
			}
		}
		return false
	})
	g.mu.Lock()
	n := len(g.reports)
	g.mu.Unlock()
	g.limit("model-2")
	g.send(t)
	time.Sleep(1500 * time.Millisecond)
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.reports) != n {
		t.Errorf("%d reports after the 404; want %d", len(g.reports), n)
	}
}

// TestARunExitedModelKeyLimitNeedsThePausedSession pins the close of a paused run: a
// dev.qory.run.exited paused with model_key_limit is taken after a last
// dev.qory.session.exited paused with that reason, and refused in a run with no join and
// after a last session.exited with another reason; it fails the schema with failed or
// cancelled, and paused with no reason fails it too. A session's
// dev.qory.session.exited cancelled with model_key_limit fails the schema as well.
func TestARunExitedModelKeyLimitNeedsThePausedSession(t *testing.T) {
	h := start(t, gateway.Config{})
	pausedExit := func(runID string, n int, reason string) map[string]any {
		data := map[string]any{"session": n, "state": "succeeded", "exit_code": 0, "duration_ms": 5}
		if reason != "" {
			data = map[string]any{"session": n, "state": "paused", "exit_code": 1, "reason": reason, "duration_ms": 5}
		}
		return ev(runID, event.SessionExited, data)
	}
	closed := map[string]any{"state": "paused", "exit_code": 1, "reason": "model_key_limit"}
	for _, c := range []struct {
		what     string
		sessions []string
		data     map[string]any
		why      string
	}{
		{"paused", []string{"model_key_limit"}, closed, ""},
		{"paused, then another session", []string{"model_key_limit", ""}, closed, "a run.exited model_key_limit after a last session.exited with another reason"},
		{"a session that ended well", []string{""}, closed, "a run.exited model_key_limit after a last session.exited with another reason"},
		{"no join", nil, closed, "a run.exited model_key_limit of a run with no join"},
		{"failed", []string{"model_key_limit"}, map[string]any{"state": "failed", "exit_code": 1, "reason": "model_key_limit"}, "one link-batch.schema.json refuses"},
		{"cancelled", []string{"model_key_limit"}, map[string]any{"state": "cancelled", "exit_code": 1, "reason": "model_key_limit"}, "one link-batch.schema.json refuses"},
		{"paused with no reason", []string{"model_key_limit"}, map[string]any{"state": "paused", "exit_code": 1}, "one link-batch.schema.json refuses"},
	} {
		a := h.open(server.LinkRunRequest{})
		if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
			t.Fatalf("%s: the first batch: %+v", c.what, d)
		}
		for _, reason := range c.sessions {
			n := h.joined(a.RunID)
			if d := h.post(sessionStarted(a.RunID, n), pausedExit(a.RunID, n, reason)); !d.Accepted() {
				t.Fatalf("%s: session %d: %+v", c.what, n, d)
			}
		}
		d := h.post(exitedWith(a.RunID, c.data))
		if c.why == "" {
			if !d.Accepted() {
				t.Errorf("%s: %+v", c.what, d)
			}
			continue
		}
		if d.Status != http.StatusBadRequest || d.End != "batch_refused" {
			t.Errorf("%s: %+v", c.what, d)
		}
		if line := "run " + a.RunID + ": the gateway refused a batch from the run's session, " + c.why + "; the run ends: failed"; !h.reported(line) {
			t.Errorf("%s: not reported: %s", c.what, line)
		}
	}
	a := h.open(server.LinkRunRequest{})
	if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	n := h.joined(a.RunID)
	cancelled := ev(a.RunID, event.SessionExited, map[string]any{"session": n, "state": "cancelled", "exit_code": 1, "reason": "model_key_limit", "duration_ms": 5})
	if d := h.post(sessionStarted(a.RunID, n), cancelled); d.Status != http.StatusBadRequest || d.End != "batch_refused" {
		t.Errorf("a session.exited cancelled with model_key_limit: %+v", d)
	}
}

// reject makes the provider return 401 for each key named.
func (g *groupRun) reject(names ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, n := range names {
		g.unauthorized[n] = true
	}
}

// TestAnAnthropicGroupEndsWhenEveryKeyGets401 pins the 401 of an anthropic-messages
// group, whose keys have no expires_at: model's 401 sends the request again with
// model-2, and the session gets its 200 with no stop; the reports list model in
// unauthorized, and the schema takes them. Once model-2 and model-3 get a 401 too, the
// session gets the last 401, the next batch's answer has stop, model_key_unauthorized,
// and the session and the run end failed with it.
func TestAnAnthropicGroupEndsWhenEveryKeyGets401(t *testing.T) {
	g := startGroupRun(t)
	if one, err := g.h.join(g.runID); err != nil || one.ModelCredential != "model" {
		t.Fatalf("join 1: %+v, %v", one, err)
	}
	g.h.post(sessionStarted(g.runID, 1))
	g.reject("model")
	if status, calls := g.send(t); status != http.StatusOK || strings.Join(calls, ",") != "model,model-2" {
		t.Fatalf("the first request: %d, %v; want 200 after model and model-2", status, calls)
	}
	if status, body := g.batch(t, heartbeat(g.runID)); status != http.StatusAccepted || body != "" {
		t.Errorf("a batch while keys are left: %d %q; want no stop", status, body)
	}
	eventually(t, "a report with model unauthorized", func() bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		for _, r := range g.reports {
			if strings.Contains(string(r), `"unauthorized":[{"credential":"model","at":"`) {
				return true
			}
		}
		return false
	})
	schema, err := contracts.Compile("model-keys-report.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	for _, r := range g.reports {
		doc, _ := contracts.Decode("r.json", r)
		if err := schema.Validate(doc); err != nil {
			t.Errorf("the report %s fails the schema: %v", r, err)
		}
	}
	g.mu.Unlock()
	g.reject("model-2", "model-3")
	if status, calls := g.send(t); status != http.StatusUnauthorized || strings.Join(calls, ",") != "model-2,model-3" {
		t.Fatalf("with no key left: %d, %v; want the 401 after model-2 and model-3", status, calls)
	}
	if status, calls := g.send(t); status != http.StatusTooManyRequests || len(calls) != 0 {
		t.Errorf("after the stop: %d, %v; want the gateway's 429 and no call", status, calls)
	}
	const stop = `{"stop":{"reason":"model_key_unauthorized"}}`
	for range 2 {
		if status, body := g.batch(t, heartbeat(g.runID)); status != http.StatusAccepted || body != stop {
			t.Errorf("a batch after the stop: %d %q; want %s", status, body, stop)
		}
	}
	failed := ev(g.runID, event.SessionExited, map[string]any{"session": 1, "state": "failed", "exit_code": -1, "signal": "SIGTERM", "reason": "model_key_unauthorized", "duration_ms": 5})
	if status, body := g.batch(t, failed); status != http.StatusAccepted || body != "" {
		t.Errorf("the session's end: %d %q", status, body)
	}
	if status, body := g.batch(t, exitedWith(g.runID, map[string]any{"state": "failed", "exit_code": -1, "signal": "SIGTERM", "reason": "model_key_unauthorized"})); status != http.StatusAccepted {
		t.Errorf("the close: %d %q", status, body)
	}
	if lines := g.h.reportsWith(`: the provider returned 401; the key has no expires_at and leaves the run's key group`); len(lines) != 3 {
		t.Errorf("the log of 401 answers: %q; want 3 lines", lines)
	}
}

// TestAnOpenAIGroupSwitchesAfterA401 pins the 401 of an openai-responses group: the
// session gets the provider's 401 with no resend, the next request gets the gateway's
// 429, the next batch's answer has stop, model_key_switch, and the session and the run
// end paused with it. The next session joins with model-2.
func TestAnOpenAIGroupSwitchesAfterA401(t *testing.T) {
	g := startGroupRunOf(t, "openai-responses")
	if one, err := g.h.join(g.runID); err != nil || one.ModelCredential != "model" {
		t.Fatalf("join 1: %+v, %v", one, err)
	}
	g.h.post(sessionStarted(g.runID, 1))
	g.reject("model")
	if status, calls := g.send(t); status != http.StatusUnauthorized || strings.Join(calls, ",") != "model" {
		t.Fatalf("the first request: %d, %v; want the provider's 401 from model alone", status, calls)
	}
	if status, calls := g.send(t); status != http.StatusTooManyRequests || len(calls) != 0 {
		t.Errorf("after the 401: %d, %v; want the gateway's 429 and no call", status, calls)
	}
	if status, body := g.batch(t, heartbeat(g.runID)); status != http.StatusAccepted || body != `{"stop":{"reason":"model_key_switch"}}` {
		t.Errorf("the next batch: %d %q; want 202 with stop", status, body)
	}
	paused := ev(g.runID, event.SessionExited, map[string]any{"session": 1, "state": "paused", "exit_code": 1, "reason": "model_key_switch", "duration_ms": 5})
	if status, body := g.batch(t, paused); status != http.StatusAccepted || body != "" {
		t.Errorf("the session's end: %d %q", status, body)
	}
	two, err := g.h.join(g.runID)
	if err != nil || two.ModelCredential != "model-2" {
		t.Fatalf("join 2: %+v, %v; want model-2", two, err)
	}
	g.h.post(sessionStarted(g.runID, 2))
	if status, calls := g.send(t); status != http.StatusOK || strings.Join(calls, ",") != "model-2" {
		t.Errorf("a request of session 2: %d, %v", status, calls)
	}
	g.h.post(ev(g.runID, event.SessionExited, map[string]any{"session": 2, "state": "paused", "exit_code": 1, "reason": "model_key_switch", "duration_ms": 5}))
	if status, body := g.batch(t, exitedWith(g.runID, map[string]any{"state": "paused", "exit_code": 1, "reason": "model_key_switch"})); status != http.StatusAccepted {
		t.Errorf("the close: %d %q", status, body)
	}
}

// TestARunExitedOfAKeyStopNeedsItsSession pins the close after a 401: a
// dev.qory.run.exited paused with model_key_switch, or failed with
// model_key_unauthorized, is taken after a last dev.qory.session.exited with the same
// reason, and refused after a last session.exited with another reason and in a run
// with no join; the schema refuses each with another state.
func TestARunExitedOfAKeyStopNeedsItsSession(t *testing.T) {
	h := start(t, gateway.Config{})
	ended := func(runID string, n int, state, reason string) map[string]any {
		data := map[string]any{"session": n, "state": "succeeded", "exit_code": 0, "duration_ms": 5}
		if reason != "" {
			data = map[string]any{"session": n, "state": state, "exit_code": 1, "reason": reason, "duration_ms": 5}
		}
		return ev(runID, event.SessionExited, data)
	}
	type session struct{ state, reason string }
	switched := session{"paused", "model_key_switch"}
	revoked := session{"failed", "model_key_unauthorized"}
	for _, c := range []struct {
		what     string
		sessions []session
		data     map[string]any
		why      string
	}{
		{"switch", []session{switched}, map[string]any{"state": "paused", "exit_code": 1, "reason": "model_key_switch"}, ""},
		{"unauthorized", []session{revoked}, map[string]any{"state": "failed", "exit_code": 1, "reason": "model_key_unauthorized"}, ""},
		{"switch after another session", []session{switched, {}}, map[string]any{"state": "paused", "exit_code": 1, "reason": "model_key_switch"},
			"a run.exited model_key_switch after a last session.exited with another reason"},
		{"unauthorized after a switch", []session{switched}, map[string]any{"state": "failed", "exit_code": 1, "reason": "model_key_unauthorized"},
			"a run.exited model_key_unauthorized after a last session.exited with another reason"},
		{"switch with no join", nil, map[string]any{"state": "paused", "exit_code": 1, "reason": "model_key_switch"}, "a run.exited model_key_switch of a run with no join"},
		{"unauthorized with no join", nil, map[string]any{"state": "failed", "exit_code": 1, "reason": "model_key_unauthorized"}, "a run.exited model_key_unauthorized of a run with no join"},
		{"unauthorized cancelled", []session{revoked}, map[string]any{"state": "cancelled", "exit_code": 1, "reason": "model_key_unauthorized"}, "one link-batch.schema.json refuses"},
		{"switch failed", []session{switched}, map[string]any{"state": "failed", "exit_code": 1, "reason": "model_key_switch"}, "one link-batch.schema.json refuses"},
	} {
		a := h.open(server.LinkRunRequest{})
		if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
			t.Fatalf("%s: the first batch: %+v", c.what, d)
		}
		for _, s := range c.sessions {
			n := h.joined(a.RunID)
			if d := h.post(sessionStarted(a.RunID, n), ended(a.RunID, n, s.state, s.reason)); !d.Accepted() {
				t.Fatalf("%s: session %d: %+v", c.what, n, d)
			}
		}
		d := h.post(exitedWith(a.RunID, c.data))
		if c.why == "" {
			if !d.Accepted() {
				t.Errorf("%s: %+v", c.what, d)
			}
			continue
		}
		if d.Status != http.StatusBadRequest || d.End != "batch_refused" {
			t.Errorf("%s: %+v", c.what, d)
		}
		if line := "run " + a.RunID + ": the gateway refused a batch from the run's session, " + c.why + "; the run ends: failed"; !h.reported(line) {
			t.Errorf("%s: not reported: %s", c.what, line)
		}
	}
}
