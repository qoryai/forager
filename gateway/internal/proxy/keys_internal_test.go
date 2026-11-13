package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
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

// provider is a fake model provider that serves each request by the key it contains,
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

// limited returns a subscription's cap: a 429 whose 5h window is rejected, reset in an
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

// newKeyFixture starts the fake provider and the proxy, with a group of the format
// anthropic-messages whose stream path is /v1/messages. Each of set changes every key
// of the group.
func newKeyFixture(t *testing.T, set ...func(*modelkey.Key)) *keyFixture {
	t.Helper()
	return newKeyFixtureOf(t, modelkey.FormatAnthropicMessages, "/v1/messages", set...)
}

// newKeyFixtureOf starts the fake provider and the proxy, with a group of the format
// whose stream path is stream. Each of set changes every key of the group.
func newKeyFixtureOf(t *testing.T, format, stream string, set ...func(*modelkey.Key)) *keyFixture {
	t.Helper()
	return newKeyFixtureWith(t, format, stream, nil, set...)
}

// newKeyFixtureWith is [newKeyFixtureOf] whose credential of each key has the Rejected
// that rejected returns for its name; nil, or a nil func, for none.
func newKeyFixtureWith(t *testing.T, format, stream string, rejected func(name string) func(), set ...func(*modelkey.Key)) *keyFixture {
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
		c := Credential{Name: name, Hosts: []string{keyHost}, Scheme: "bearer", Placeholder: placeholder, Token: func() string { return value }}
		if rejected != nil {
			c.Rejected = rejected(name)
		}
		creds = append(creds, c)
		k := modelkey.Key{Name: name, PauseFor: time.Hour}
		for _, f := range set {
			f(&k)
		}
		keys = append(keys, k)
	}
	f.g = modelkey.New(keys, "model", nil)
	f.g.SetFormat(format)
	f.p.SetKeyGroup(f.g, format, stream, func(line string) { f.mu.Lock(); f.logged = append(f.logged, line); f.mu.Unlock() })
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

// TestNoKeyLeftPassesTheRefusalAndHoldsTheRest pins the end of the group: when the
// provider returns a limit refusal for every key, the session gets the last refusal,
// the group is stopped, and from then on a request with the placeholder gets the
// gateway's 429 and reaches no provider, until Resume.
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
		t.Error("the group is not stopped")
	}
	status, body = f.post(t, "{}")
	if status != http.StatusTooManyRequests || !strings.HasPrefix(body, "qory: the gateway sends no more model requests in this session: every model key of the run's key group is at its provider's limit") || len(f.up.taken()) != 0 {
		t.Errorf("after the stop: %d %q; want the gateway's 429 and no call", status, body)
	}
	if d := f.seen.at(-1); d.Outcome != Refused || d.Credential != "" || d.Status != 0 {
		t.Errorf("the record of the held request %+v", d)
	}
	f.g.Resume()
	delete(f.up.answers, "model-3")
	f.g.Merge([]modelkey.Window{{Credential: "model-3", Window: "five_hour", Status: modelkey.StatusAllowed, Source: modelkey.SourceProvider, ObservedAt: time.Now().Add(time.Minute)}})
	if status, _ := f.post(t, "{}"); status != http.StatusOK {
		t.Errorf("after Resume and a cooldown that ended: %d", status)
	}
}

// TestABodyOverTheCopyLimitIsNotSentAgain pins a refused body over 8 MiB: no copy, so
// the refusal reaches the session, the key still goes into cooldown, the next key
// becomes active, and the group is stopped.
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
// words of an error, or a data line of an error outside an event named error, changes
// no key, and that an empty line ends the event.
func TestAStreamWithoutAnErrorKeepsTheKey(t *testing.T) {
	// No resend: a cooldown would panic on the nil key group.
	s := &streamWatch{ReadCloser: io.NopCloser(bytes.NewReader(nil)), format: modelkey.FormatAnthropicMessages}
	for _, line := range []string{
		"event: content_block_delta", `data: {"delta":"\"rate_limit_error\""}`, "",
		"event: content_block_delta", `data: {"type":"error","error":{"type":"rate_limit_error"}}`, "",
		`data: {"type":"error","error":{"type":"rate_limit_error"}}`, "",
	} {
		s.read(line)
	}
	if s.event != "" || len(s.data) != 0 {
		t.Errorf("after an empty line the event is %q with data %q; want none", s.event, s.data)
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

// postTo sends body with method to path on the provider through the proxy with the
// placeholder, and returns the status and the answer's body.
func (f *keyFixture) postTo(t *testing.T, method, path, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, "https://"+keyHost+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+link.KeyPlaceholder("model"))
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// streamError returns a stream that ends with an error event of the type
// rate_limit_error.
func streamError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\"}\n\n"+
		"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"rate_limit_error\"}}\n\n")
}

// TestOnlyTheMessagesPostIsReadForAStreamError pins the path rule of the stream: an
// error event of the type rate_limit_error cools the key only in the streamed 200 of a
// POST to the messages path, with any query; the same stream on another path or for
// another method changes no key, and so does a data line of the error in an event
// that is not named error.
func TestOnlyTheMessagesPostIsReadForAStreamError(t *testing.T) {
	f := newKeyFixture(t)
	f.up.answers["model"] = streamError
	for _, c := range []struct{ method, path string }{{http.MethodPost, "/v1/messages/count_tokens"}, {http.MethodPost, "/v1/other"}, {http.MethodGet, "/v1/messages"}} {
		f.postTo(t, c.method, c.path, "{}")
		if f.g.Active() != "model" {
			t.Fatalf("%s %s: active %s; want model", c.method, c.path, f.g.Active())
		}
	}
	f.up.answers["model"] = func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"error\",\"error\":{\"type\":\"rate_limit_error\"}}\n\n")
	}
	f.postTo(t, http.MethodPost, "/v1/messages", "{}")
	if f.g.Active() != "model" {
		t.Fatalf("an error's data in a content_block_delta event: active %s; want model", f.g.Active())
	}
	f.up.answers["model"] = streamError
	f.postTo(t, http.MethodPost, "/v1/messages?beta=true", "{}")
	if f.g.Active() != "model-2" {
		t.Errorf("POST /v1/messages?beta=true: active %s; want model-2", f.g.Active())
	}
}

// TestEveryKeyCoolingGetsTheProxys429 pins the state after a report's answer that puts
// every key in cooldown: the proxy sets no key, returns its 429 without a call to the
// provider, and the group is stopped.
func TestEveryKeyCoolingGetsTheProxys429(t *testing.T) {
	f := newKeyFixture(t)
	later := time.Now().Add(time.Hour)
	var entries []modelkey.Window
	for name := range fakeKeys {
		entries = append(entries, modelkey.Window{Credential: name, Window: "five_hour", Status: modelkey.StatusRejected, CooldownUntil: later, Source: modelkey.SourceProvider, ObservedAt: time.Now()})
	}
	f.g.Merge(entries)
	status, body := f.post(t, "{}")
	if status != http.StatusTooManyRequests || !strings.HasPrefix(body, "qory: the gateway sends no more model requests in this session: every model key of the run's key group is at its provider's limit") {
		t.Errorf("the session got %d %q; want the gateway's 429", status, body)
	}
	if calls := f.up.taken(); len(calls) != 0 {
		t.Errorf("the provider got %v; want no call", calls)
	}
	if !f.g.Passed() {
		t.Error("the group is not stopped")
	}
}

// TestKeysAtTheirUseUpToPercentGetTheProxys429 pins the pause at use_up_to_percent:
// each key's 200 has its five_hour window at 90, the key's percentage, so each next
// request goes with the next key; once every key is at its percentage, the proxy sets
// no key, returns its 429 without a call to the provider, and the group is stopped.
func TestKeysAtTheirUseUpToPercentGetTheProxys429(t *testing.T) {
	f := newKeyFixture(t, func(k *modelkey.Key) { k.UseUpToPercent, k.UseUpToWindows = 90, []string{"five_hour"} })
	reset := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	for name := range fakeKeys {
		f.up.answers[name] = func(w http.ResponseWriter) {
			w.Header().Set("Anthropic-Ratelimit-Unified-5h-Status", "allowed_warning")
			w.Header().Set("Anthropic-Ratelimit-Unified-5h-Utilization", "0.9")
			w.Header().Set("Anthropic-Ratelimit-Unified-5h-Reset", reset)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"type":"message"}`)
		}
	}
	for _, want := range []string{"model", "model-2", "model-3"} {
		if status, body := f.post(t, "{}"); status != http.StatusOK {
			t.Fatalf("the request for %s got %d %q; want the provider's 200", want, status, body)
		}
		if got := keysOf(f.up.taken()); strings.Join(got, ",") != want {
			t.Errorf("the provider got %v; want %s alone", got, want)
		}
	}
	status, body := f.post(t, "{}")
	if want := "qory: the gateway sends no more model requests in this session: every model key of the run's key group is at its provider's limit, at its Use up to percentage, or out of use after a 401 of its provider, or the gateway could not send a refused request again with the next key (a request over 8 MiB, a key whose credential does not cover the path, or an openai-responses request, whose session keeps one key).\n"; status != http.StatusTooManyRequests || body != want {
		t.Errorf("the session got %d %q; want the gateway's 429", status, body)
	}
	if calls := f.up.taken(); len(calls) != 0 {
		t.Errorf("the provider got %v; want no call", calls)
	}
	if !f.g.Passed() {
		t.Error("the group is not stopped")
	}
}

// TestAResendNeedsTheNextKeysPaths pins the host rules of a resend: when the next key's
// credential has paths that do not match the request, the refusal reaches the session,
// the group is stopped, and model-2 gets nothing.
func TestAResendNeedsTheNextKeysPaths(t *testing.T) {
	f := newKeyFixture(t)
	f.p.term.Load().creds[1].Paths = []string{"/v1/files"}
	f.up.answers["model"] = limited
	if status, _ := f.post(t, "{}"); status != http.StatusTooManyRequests {
		t.Errorf("the session got %d; want the refusal", status)
	}
	if got := keysOf(f.up.taken()); strings.Join(got, ",") != "model" {
		t.Errorf("the provider got %v; want model alone", got)
	}
	if !f.g.Passed() {
		t.Error("the group is not stopped")
	}
}

// TestConcurrentRequestsSwitchKeys sends requests at once while model and model-2
// refuse: every request gets model-3's answer, for the race detector.
func TestConcurrentRequestsSwitchKeys(t *testing.T) {
	f := newKeyFixture(t)
	f.up.answers["model"] = limited
	f.up.answers["model-2"] = limited
	var wg sync.WaitGroup
	statuses := make([]int, 12)
	for i := range statuses {
		wg.Go(func() { statuses[i], _ = f.post(t, `{"n":1}`) })
	}
	wg.Wait()
	for i, s := range statuses {
		if s != http.StatusOK {
			t.Errorf("request %d: %d; want 200", i, s)
		}
	}
	if f.g.Active() != "model-3" || f.g.Passed() {
		t.Errorf("active %s, passed %v; want model-3 and no stop", f.g.Active(), f.g.Passed())
	}
}

// answers is a round tripper that returns its answers in order, and keeps each request
// and the bytes of its body, which it reads to their end and closes, as a transport does.
type answers struct {
	got  []*http.Request
	read []string
	list []*http.Response
}

func (a *answers) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	a.got = append(a.got, r)
	a.read = append(a.read, string(b))
	resp := a.list[0]
	a.list = a.list[1:]
	return resp, nil
}

// TestTheCopyIsDroppedWhenTheStatusArrives pins the copy of the body: once the status
// of the answer the proxy passes on arrives, the resend has no copy and GetBody fails,
// and the request's body and that of the resend, each read whole and closed, have no
// bytes of it, so no copy is kept while a streamed answer lasts.
func TestTheCopyIsDroppedWhenTheStatusArrives(t *testing.T) {
	g := modelkey.New([]modelkey.Key{{Name: "model", PauseFor: time.Hour}, {Name: "model-2", PauseFor: time.Hour}}, "model", nil)
	one := &Credential{Name: "model", Hosts: []string{keyHost}, Scheme: "bearer", Token: func() string { return fakeKeys["model"] }}
	two := &Credential{Name: "model-2", Hosts: []string{keyHost}, Scheme: "bearer", Token: func() string { return fakeKeys["model-2"] }}
	k := &keyGroup{g: g, format: modelkey.FormatAnthropicMessages, messages: "/v1/messages", log: func(string) {}}
	r := httptest.NewRequest(http.MethodPost, "https://"+keyHost+"/v1/messages", strings.NewReader(`{"model":"m"}`))
	p := &Proxy{}
	ctx := p.withResend(r.Context(), r, k, one, []*Credential{one, two}, "/v1/messages", true)
	rs := resendOf(r.WithContext(ctx))
	refusal := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"type":"error","error":{"type":"rate_limit_error"}}`))}
	stream := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: {}\n\n"))}
	rt := &answers{list: []*http.Response{refusal, stream}}
	resp, err := rs.roundTrip(rt, r)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("roundTrip: %v, %v", resp, err)
	}
	if rs.body != nil || rs.copied {
		t.Errorf("the resend has %d bytes of copy; want none", len(rs.body))
	}
	for i, out := range rt.got {
		if rt.read[i] != `{"model":"m"}` {
			t.Errorf("request %d: the transport read %q; want the whole body", i, rt.read[i])
		}
		if c, ok := out.Body.(*copyReader); !ok || c.held() {
			t.Errorf("request %d: its body %T has bytes of the copy after its Close", i, out.Body)
		}
	}
	if again := rt.got[1]; again.GetBody == nil {
		t.Error("the resend has no GetBody")
	} else if _, err := again.GetBody(); !errors.Is(err, errDropped) {
		t.Errorf("GetBody after the status: %v; want errDropped", err)
	}
	if _, ok := resp.Body.(*streamWatch); !ok {
		t.Error("the stream is not read for an error event")
	}
}

// TestABodyStillBeingWrittenGoesWhole pins a body the transport still writes when the
// answer's status arrives: the upstream reads every byte as sent, over HTTP/1.1 and
// HTTP/2, for a body of 8 MiB and one over 8 MiB, after a 400 and after a 200. Over
// HTTP/2 the transport stops the body after a 400, so the upstream reads the first
// bytes as sent. Each reader of the copy ends with no bytes of it once the transport
// closes the body.
func TestABodyStillBeingWrittenGoesWhole(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, status := range []int{http.StatusBadRequest, http.StatusOK} {
			for _, size := range []int{modelkey.MaxCopy, modelkey.MaxCopy + 4<<20} {
				t.Run(fmt.Sprintf("h2=%v/%d/%d", h2, status, size), func(t *testing.T) {
					answerBeforeTheBody(t, h2, status, size)
				})
			}
		}
	}
}

// readFirst is how much of the body the upstream of [answerBeforeTheBody] reads before
// it sends the status.
const readFirst = 1 << 20

// answerBeforeTheBody sends a body of size bytes with a key of the group to an upstream
// that reads readFirst bytes of it, sends status, and reads the rest only after the
// round trip returned.
func answerBeforeTheBody(t *testing.T, h2 bool, status, size int) {
	sent := make([]byte, size)
	for i := 0; i+4 <= size; i += 4 {
		binary.BigEndian.PutUint32(sent[i:], uint32(i))
	}
	answered := make(chan struct{})
	got := make(chan []byte, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		_ = rc.EnableFullDuplex()
		// The upstream reads the first MiB, more than one frame, before it sends status.
		first := make([]byte, readFirst)
		n, _ := io.ReadFull(r.Body, first)
		first = first[:n]
		w.WriteHeader(status)
		_ = rc.Flush()
		select {
		case <-answered:
		case <-time.After(10 * time.Second):
		}
		// Over HTTP/2 the transport stops the body after a 400 and ends no stream.
		_ = rc.SetReadDeadline(time.Now().Add(3 * time.Second))
		rest, _ := io.ReadAll(r.Body)
		got <- append(first, rest...)
	}))
	srv.EnableHTTP2 = h2
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	rt := srv.Client().Transport
	one := &Credential{Name: "model", Hosts: []string{keyHost}, Scheme: "bearer", Token: func() string { return fakeKeys["model"] }}
	k := &keyGroup{g: modelkey.New([]modelkey.Key{{Name: "model", PauseFor: time.Hour}}, "model", nil), format: modelkey.FormatAnthropicMessages, messages: "/v1/messages", log: func(string) {}}
	r, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/messages", io.NopCloser(bytes.NewReader(sent)))
	if err != nil {
		t.Fatal(err)
	}
	r.ContentLength = int64(size)
	r = r.WithContext((&Proxy{}).withResend(r.Context(), r, k, one, []*Credential{one}, "/v1/messages", false))
	rs := resendOf(r)
	body, ok := r.Body.(*copyReader)
	if !ok {
		t.Fatalf("the request's body is a %T; want a *copyReader", r.Body)
	}
	resp, err := rs.roundTrip(rt, r)
	close(answered)
	if err != nil {
		t.Fatalf("roundTrip: %v", err)
	}
	if resp.StatusCode != status {
		t.Errorf("the status %d; want %d", resp.StatusCode, status)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	var b []byte
	select {
	case b = <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream read no body")
	}
	switch {
	case h2 && status >= 300:
		if len(b) < readFirst || !bytes.Equal(b, sent[:len(b)]) {
			t.Errorf("the upstream read %d bytes; want at least %d, the first bytes sent", len(b), readFirst)
		}
	case len(b) != size:
		t.Errorf("the upstream read %d bytes; want %d", len(b), size)
	case !bytes.Equal(b, sent):
		t.Error("the upstream read bytes that differ from the bytes sent")
	}
	for end := time.Now().Add(2 * time.Second); body.held() && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond)
	}
	if body.held() {
		t.Error("the request's body has the copy after the transport closed it")
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.body != nil {
		t.Errorf("the resend has %d bytes of copy; want none", len(rs.body))
	}
}

// TestAnEmptyReadOfTheCopyReadsNothing pins a read of the copy into an empty buffer: it
// returns 0 and no error while bytes of the copy are left, and the next read gets them.
func TestAnEmptyReadOfTheCopyReadsNothing(t *testing.T) {
	c := &copyReader{b: []byte("body")}
	if n, err := c.Read(nil); n != 0 || err != nil {
		t.Errorf("a read into an empty buffer: %d, %v; want 0, nil", n, err)
	}
	if b, err := io.ReadAll(c); string(b) != "body" || err != nil {
		t.Errorf("the next reads: %q, %v; want the copy", b, err)
	}
}
