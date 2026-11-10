package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// keyHost is the model provider's host of the key group tests.
const keyHost = "api.model.example"

// fakeKeys are the fake values of the three keys of the group, by name.
var fakeKeys = map[string]string{"model": "sk-fake-key-one", "model-2": "sk-fake-key-two", "model-3": "sk-fake-key-three"}

// upstreamCall is one request the fake provider received: the key and the body.
type upstreamCall struct {
	key  string
	body string
}

// provider is a fake model provider that answers each request by the key it carries,
// with answers[key], and records each call.
type provider struct {
	mu      sync.Mutex
	calls   []upstreamCall
	answers map[string]func(w http.ResponseWriter)
}

func (p *provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	key := ""
	for name, v := range fakeKeys {
		if r.Header.Get("Authorization") == "Bearer "+v {
			key = name
		}
	}
	p.mu.Lock()
	p.calls = append(p.calls, upstreamCall{key, string(body)})
	answer := p.answers[key]
	p.mu.Unlock()
	if answer == nil {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"type":"message","key":"`+fakeKeys[key]+`"}`)
		return
	}
	answer(w)
}

// taken returns the calls since the last take.
func (p *provider) taken() []upstreamCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.calls
	p.calls = nil
	return out
}

// limited answers a subscription's cap: a 429 whose 5h window is rejected, reset in an
// hour.
func limited(w http.ResponseWriter) {
	w.Header().Set("Anthropic-Ratelimit-Unified-5h-Status", "rejected")
	w.Header().Set("Anthropic-Ratelimit-Unified-5h-Reset", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
	w.Header().Set("Anthropic-Ratelimit-Unified-Representative-Claim", "five_hour")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	io.WriteString(w, `{"type":"error","error":{"type":"rate_limit_error","message":"You've hit your limit"}}`)
}

// keyFixture is a proxy that terminates keyHost with the three keys of a group, each
// with the start key's placeholder, a client through it, and the fake provider.
type keyFixture struct {
	p      *Proxy
	g      *modelkey.Group
	up     *provider
	client *http.Client
	seen   *decisions
	mu     sync.Mutex
	logged []string
}

// newKeyFixture starts the fake provider and the proxy.
func newKeyFixture(t *testing.T) *keyFixture {
	t.Helper()
	upCA, err := NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	f := &keyFixture{up: &provider{answers: map[string]func(http.ResponseWriter){}}, seen: &decisions{}}
	origin := httptest.NewUnstartedServer(f.up)
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return upCA.leaf(hello.ServerName) }}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	f.p, err = Listen("", policy.Enforce, []string{keyHost}, nil, f.seen.observe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.p.Close() })
	f.p.dial = (&dials{secure: origin.Listener.Addr().String()}).dial
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(upCA.PEM())
	f.p.TrustUpstream(roots)
	placeholder := link.KeyPlaceholder("model")
	var creds []Credential
	var keys []modelkey.Key
	for _, name := range []string{"model", "model-2", "model-3"} {
		value := fakeKeys[name]
		creds = append(creds, Credential{Name: name, Hosts: []string{keyHost}, Scheme: "bearer", Placeholder: placeholder, Token: func() string { return value }})
		keys = append(keys, modelkey.Key{Name: name, PauseFor: time.Hour})
	}
	f.g = modelkey.New(keys, nil)
	f.p.SetKeyGroup(f.g, func(line string) { f.mu.Lock(); f.logged = append(f.logged, line); f.mu.Unlock() })
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	f.p.Terminate(ca, creds, nil, nil)
	f.p.SetModelKey("model")
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	proxyURL, _ := url.Parse(f.p.URL())
	f.client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}, Timeout: 10 * time.Second}
	return f
}

// post sends body to the provider through the proxy with the placeholder, and returns
// the status and the answer's body.
func (f *keyFixture) post(t *testing.T, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "https://"+keyHost+"/v1/messages", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+link.KeyPlaceholder("model"))
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// keysOf are the keys of calls, in order.
func keysOf(calls []upstreamCall) []string {
	var out []string
	for _, c := range calls {
		out = append(out, c.key)
	}
	return out
}

// TestALimitRefusalIsSentAgainWithTheNextKey pins steps 1 to 3: the refusal of the
// active key never reaches the session, the same body goes again with the next key,
// and the session gets that answer, with the value replaced by the start key's
// placeholder. The next request goes with the next key, the record has it, and the log
// of limit answers has names alone.
func TestALimitRefusalIsSentAgainWithTheNextKey(t *testing.T) {
	f := newKeyFixture(t)
	f.up.answers["model"] = limited
	status, body := f.post(t, `{"model":"m","messages":[1]}`)
	if status != http.StatusOK || strings.Contains(body, "sk-fake") || !strings.Contains(body, link.KeyPlaceholder("model")) {
		t.Fatalf("the session got %d %q; want the second key's 200, masked", status, body)
	}
	calls := f.up.taken()
	if got := keysOf(calls); strings.Join(got, ",") != "model,model-2" || calls[0].body != calls[1].body || calls[1].body != `{"model":"m","messages":[1]}` {
		t.Fatalf("the provider got %+v; want the same body with model, then model-2", calls)
	}
	if d := f.seen.at(-1); d.Credential != "model-2" || d.Status != http.StatusOK {
		t.Errorf("the record %+v; want model-2 and 200", d)
	}
	if f.g.Active() != "model-2" || f.g.Passed() {
		t.Errorf("active %s, passed %v; want model-2 and no stop", f.g.Active(), f.g.Passed())
	}
	f.post(t, "{}")
	if got := keysOf(f.up.taken()); strings.Join(got, ",") != "model-2" {
		t.Errorf("the next request went with %v; want model-2", got)
	}
	f.mu.Lock()
	logged := strings.Join(f.logged, "\n")
	f.mu.Unlock()
	if !strings.HasPrefix(logged, `model key "model": limit answer, status 429, error type rate_limit_error, headers anthropic-ratelimit-unified-5h-reset`) ||
		strings.Contains(logged, "rejected") || strings.Contains(logged, "five_hour") {
		t.Errorf("the log of limit answers: %q", logged)
	}
	if w := f.g.Windows(); len(w) == 0 || w[0].Credential != "model" || w[0].Status != modelkey.StatusRejected {
		t.Errorf("windows %+v; want model's five_hour rejected first", w)
	}
}

// TestNoKeyLeftPassesTheRefusalAndHoldsTheRest pins the end of the group: when every
// key refuses, the session gets the last refusal, the group holds the stop, and from
// then on a request with the placeholder gets the gateway's 429 and reaches no
// provider, until Resume.
func TestNoKeyLeftPassesTheRefusalAndHoldsTheRest(t *testing.T) {
	f := newKeyFixture(t)
	for name := range fakeKeys {
		f.up.answers[name] = limited
	}
	status, body := f.post(t, "{}")
	if status != http.StatusTooManyRequests || !strings.Contains(body, "rate_limit_error") {
		t.Fatalf("the session got %d %q; want the provider's refusal", status, body)
	}
	if got := keysOf(f.up.taken()); strings.Join(got, ",") != "model,model-2,model-3" {
		t.Errorf("the provider got %v; want each key once", got)
	}
	if !f.g.Passed() {
		t.Error("the group holds no stop")
	}
	status, body = f.post(t, "{}")
	if status != http.StatusTooManyRequests || !strings.HasPrefix(body, "qory: start the run again once a model key's cooldown ends") || len(f.up.taken()) != 0 {
		t.Errorf("after the stop: %d %q; want the gateway's 429 and no call", status, body)
	}
	if d := f.seen.at(-1); d.Outcome != Refused || d.Credential != "" || d.Status != 0 {
		t.Errorf("the record of the held request %+v", d)
	}
	f.g.Resume()
	delete(f.up.answers, "model-3")
	f.g.Merge([]modelkey.Window{{Credential: "model-3", Window: "key", Status: modelkey.StatusAllowed, Source: modelkey.SourceProvider, ObservedAt: time.Now().Add(time.Minute)}})
	if status, _ := f.post(t, "{}"); status != http.StatusOK {
		t.Errorf("after Resume and a cooldown that ended: %d", status)
	}
}

// TestABodyOverTheCopyLimitIsNotSentAgain pins a refused body over 8 MiB: no copy, so
// the refusal reaches the session, the key still goes into cooldown, the next key
// becomes active, and the group holds the stop.
func TestABodyOverTheCopyLimitIsNotSentAgain(t *testing.T) {
	f := newKeyFixture(t)
	f.up.answers["model"] = limited
	big := `{"pad":"` + strings.Repeat("a", modelkey.MaxCopy) + `"}`
	status, _ := f.post(t, big)
	if status != http.StatusTooManyRequests {
		t.Fatalf("the session got %d; want the refusal", status)
	}
	calls := f.up.taken()
	if len(calls) != 1 || len(calls[0].body) != len(big) {
		t.Fatalf("the provider got %d calls; want one with the whole body", len(calls))
	}
	if !f.g.Passed() || f.g.Active() != "model-2" {
		t.Errorf("passed %v, active %s; want the stop and model-2", f.g.Passed(), f.g.Active())
	}
}

// TestAnotherStatusIsNoLimitRefusal pins that a 5xx or an overloaded error goes to the
// session as it came, with no resend and no cooldown.
func TestAnotherStatusIsNoLimitRefusal(t *testing.T) {
	f := newKeyFixture(t)
	for _, status := range []int{http.StatusServiceUnavailable, 529} {
		f.up.answers["model"] = func(w http.ResponseWriter) {
			w.WriteHeader(status)
			io.WriteString(w, `{"type":"error","error":{"type":"overloaded_error"}}`)
		}
		got, _ := f.post(t, "{}")
		if got != status || len(f.up.taken()) != 1 || f.g.Active() != "model" || f.g.Passed() {
			t.Errorf("%d: the session got %d, active %s; want it passed on, model active", status, got, f.g.Active())
		}
	}
}

// TestAStreamErrorSwitchesTheKeyAndPassesTheBytes pins a streamed 200 that ends with
// an error event of the type rate_limit_error: the bytes reach the session as they
// came, the key goes into cooldown, and the next request goes with the next key.
func TestAStreamErrorSwitchesTheKeyAndPassesTheBytes(t *testing.T) {
	f := newKeyFixture(t)
	stream := "event: message_start\ndata: {\"type\":\"message_start\"}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"rate_limit_error\"}}\n\n" +
		"event: error\r\ndata: {\"type\":\"error\",\"error\":{\"type\":\"rate_limit_error\",\"message\":\"m\"}}\r\n\r\n"
	f.up.answers["model"] = func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		for _, part := range []string{stream[:30], stream[30:120], stream[120:]} {
			io.WriteString(w, part)
			w.(http.Flusher).Flush()
		}
	}
	status, body := f.post(t, `{"stream":true}`)
	if status != http.StatusOK || body != stream {
		t.Fatalf("the session got %d %q; want the stream as it came", status, body)
	}
	if f.g.Active() != "model-2" || f.g.Passed() {
		t.Errorf("active %s, passed %v; want model-2 and no stop", f.g.Active(), f.g.Passed())
	}
	f.post(t, `{"stream":false}`)
	if got := keysOf(f.up.taken()); strings.Join(got, ",") != "model,model-2" {
		t.Errorf("the provider got %v; want model, then model-2", got)
	}
}

// TestAStreamWithoutAnErrorKeepsTheKey pins that a content delta that contains the
// words of an error, outside an error event, changes no key.
func TestAStreamWithoutAnErrorKeepsTheKey(t *testing.T) {
	s := &streamWatch{ReadCloser: io.NopCloser(bytes.NewReader(nil))}
	for _, line := range []string{"event: content_block_delta", `data: {"delta":"\"rate_limit_error\""}`, ""} {
		s.read(line)
	}
	if s.errorEvent {
		t.Error("an event ended, and the next is read as an error event")
	}
}

// TestTheJoinsKeyOfTheGroupMeansTheActiveKey pins SetModelKey with a key of the group:
// the proxy sets the active key, never the named one; SetNoModelKey sets none.
func TestTheJoinsKeyOfTheGroupMeansTheActiveKey(t *testing.T) {
	f := newKeyFixture(t)
	f.up.answers["model"] = limited
	f.post(t, "{}")
	f.up.taken()
	f.p.SetModelKey("model-3")
	f.post(t, "{}")
	if got := keysOf(f.up.taken()); strings.Join(got, ",") != "model-2" {
		t.Errorf("a session that joined with model-3 got %v; want the active key, model-2", got)
	}
	f.p.SetNoModelKey()
	f.post(t, "{}")
	if got := keysOf(f.up.taken()); strings.Join(got, ",") != "" {
		t.Errorf("a session with no model key got %v; want none", got)
	}
}
