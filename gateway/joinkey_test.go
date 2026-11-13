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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// openaiRemote is a run on the one address whose key group has two keys of the format
// openai-responses, model and model-2, as bearers, on a fake provider that returns a
// ChatGPT subscription's 429 for model and a 200 for model-2. The 429's shape follows
// the openai/codex source at 17a0e6f63f (to confirm with probe burst-429).
type openaiRemote struct {
	r   *remote
	cfg gateway.Config
	e   *edgeRun
	key string
	url string
	ca  *x509.CertPool

	mu    sync.Mutex
	calls []string
}

// startOpenAIRemote opens the run on a separate gateway with a directory, so it can
// start again.
func startOpenAIRemote(t *testing.T) *openaiRemote {
	t.Helper()
	o := &openaiRemote{}
	values := map[string]string{"model": "fake-openai-value-0001", "model-2": "fake-openai-value-0002"}
	certFile, keyFile, roots := testCertificate(t, t.TempDir())
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		key := ""
		for name, v := range values {
			if r.Header.Get("Authorization") == "Bearer "+v {
				key = name
			}
		}
		o.mu.Lock()
		o.calls = append(o.calls, key)
		o.mu.Unlock()
		if key == "model" {
			w.Header().Set("X-Codex-Primary-Used-Percent", "100")
			w.Header().Set("X-Codex-Primary-Window-Minutes", "300")
			w.Header().Set("X-Codex-Primary-Reset-At", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"error":{"type":"usage_limit_reached"}}`)
			return
		}
		io.WriteString(w, `{"type":"response"}`)
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	o.url = "https://localhost:" + port + "/v1"
	entry := func(name string) string {
		return `{"name":"` + name + `","format":"openai-responses","endpoint":"` + o.url + `","auth":{"scheme":"bearer"},"pause_for_s":3600}`
	}
	c := gatewayControl(t)
	c.serveDocument(`{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["localhost"]}},"model_credential":"model","credentials":[`+entry("model")+`,`+entry("model-2")+`]}`, 'a')
	c.mu.Lock()
	c.secrets = values
	c.mu.Unlock()
	node := &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost"}}}
	o.cfg = gateway.Config{Dir: t.TempDir(), Policy: node}
	gateway.SetUpstreamRoots(&o.cfg, roots)
	o.r = startRemote(t, c, o.cfg)
	runID := event.NewRunID()
	o.key = runKeyFor(t, runID, nil)
	o.e = o.r.open(t, o.key, server.LinkRunRequest{Wall: true})
	o.ca = x509.NewCertPool()
	o.ca.AppendCertsFromPEM([]byte(o.e.a.CertificateAuthority))
	return o
}

// runID is the run's id.
func (o *openaiRemote) runID() string { return o.e.a.RunID }

// join sends a join with a model key and returns the status and the model key of the
// answer.
func (o *openaiRemote) join(t *testing.T) (int, string) {
	t.Helper()
	a := o.r.do(t, o.key, http.MethodPost, "/qory-link/run-configuration/"+o.runID()+"/sessions", []byte(`{"version":1,"passes":[],"model_key":true}`))
	var joined server.LinkJoinAnswer
	json.Unmarshal(a.body, &joined)
	return a.status, joined.ModelCredential
}

// send sends a Responses request with the start key's placeholder, and returns its
// status and the keys the provider got since the last send.
func (o *openaiRemote) send(t *testing.T) (int, []string) {
	t.Helper()
	agent := o.r.relay(t, o.key)
	agent.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: o.ca}
	req, _ := http.NewRequest(http.MethodPost, o.url+"/responses", strings.NewReader(`{"model":"m"}`))
	req.Header.Set("Authorization", "Bearer "+link.KeyPlaceholder("model"))
	resp, err := agent.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	o.mu.Lock()
	defer o.mu.Unlock()
	calls := o.calls
	o.calls = nil
	return resp.StatusCode, calls
}

// posted posts evs and fails the test on any status but 202.
func (o *openaiRemote) posted(t *testing.T, evs ...map[string]any) {
	t.Helper()
	if got := o.e.post(t, evs...); got.status != http.StatusAccepted {
		t.Fatalf("the batch: %d %s", got.status, got.body)
	}
}

// coolFirstKey joins session 1 on model, whose request gets the provider's 429: model
// is in cooldown and stays the active key.
func (o *openaiRemote) coolFirstKey(t *testing.T) {
	t.Helper()
	if status, key := o.join(t); status != http.StatusOK || key != "model" {
		t.Fatalf("join 1: %d %s; want 200 with model", status, key)
	}
	if status, calls := o.send(t); status != http.StatusTooManyRequests || strings.Join(calls, ",") != "model" {
		t.Fatalf("the first request: %d %v; want the provider's 429 for model", status, calls)
	}
}

// TestARestartKeepsTheSessionsKey pins a gateway restart while an openai-responses
// session that joined with model-2, after model cooled, is open: the reopened run sets
// model-2 for the session, and the provider never gets model again.
func TestARestartKeepsTheSessionsKey(t *testing.T) {
	o := startOpenAIRemote(t)
	o.coolFirstKey(t)
	o.posted(t, sessionStarted(o.runID(), 1))
	o.posted(t, sessionExited(o.runID(), 1))
	if status, key := o.join(t); status != http.StatusOK || key != "model-2" {
		t.Fatalf("join 2: %d %s; want 200 with model-2", status, key)
	}
	o.posted(t, sessionStarted(o.runID(), 2))
	o.r = o.r.restart(t, o.cfg)
	o.e.r = o.r
	o.posted(t, heartbeat(o.runID()))
	for range 2 {
		if status, calls := o.send(t); status != http.StatusOK || strings.Join(calls, ",") != "model-2" {
			t.Errorf("a request after the restart: %d %v; want 200 from model-2", status, calls)
		}
	}
}

// TestARefusedJoinKeepsTheActiveKey pins a join refused while session 1 is open: it
// does not move the active key of the openai-responses group, so once session 1 ends a
// request with the placeholder gets the gateway's 429 for model, still in cooldown, and
// the provider gets no request with model-2.
func TestARefusedJoinKeepsTheActiveKey(t *testing.T) {
	o := startOpenAIRemote(t)
	o.coolFirstKey(t)
	o.posted(t, sessionStarted(o.runID(), 1))
	if status, _ := o.join(t); status != http.StatusBadRequest {
		t.Fatalf("a join while session 1 is open: %d; want 400", status)
	}
	o.posted(t, sessionExited(o.runID(), 1))
	if status, calls := o.send(t); status != http.StatusTooManyRequests || len(calls) != 0 {
		t.Errorf("a request after session 1: %d %v; want the gateway's 429 and no call", status, calls)
	}
}

// TestAReplayedJoinKeepsItsKey pins a join sent again before its session.started: the
// answer has model, the key the join got, and the group's active key does not move, so
// once the session ends a request gets the gateway's 429 and the provider gets no
// request with model-2.
func TestAReplayedJoinKeepsItsKey(t *testing.T) {
	o := startOpenAIRemote(t)
	o.coolFirstKey(t)
	if status, key := o.join(t); status != http.StatusOK || key != "model" {
		t.Fatalf("the join sent again: %d %s; want 200 with model", status, key)
	}
	o.posted(t, sessionStarted(o.runID(), 1))
	o.posted(t, sessionExited(o.runID(), 1))
	if status, calls := o.send(t); status != http.StatusTooManyRequests || len(calls) != 0 {
		t.Errorf("a request after session 1: %d %v; want the gateway's 429 and no call", status, calls)
	}
}
