package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// The two key groups of the tests of this file: claude of the format
// anthropic-messages on claudeHost, whose stream path is /anthropic/v1/messages, and
// codex of the format openai-responses on codexHost, whose stream path is
// /v1/responses. Each group has two keys, and each key a fake value.
const (
	claudeHost = "api.claude.example"
	codexHost  = "api.codex.example"
)

var groupValues = map[string]string{"claude": "sk-fake-claude-one", "claude-2": "sk-fake-claude-two", "codex": "sk-fake-codex-one", "codex-2": "sk-fake-codex-two"}

// groupsFixture is a proxy that terminates claudeHost and codexHost with the keys of
// two groups, each key with the placeholder of its group's first key, and a fake
// provider on both hosts that serves each request by its host, path and key.
type groupsFixture struct {
	p      *Proxy
	claude *modelkey.Group
	codex  *modelkey.Group
	client *http.Client

	mu      sync.Mutex
	calls   []string
	answers map[string]func(http.ResponseWriter)
}

func newGroupsFixture(t *testing.T) *groupsFixture {
	t.Helper()
	f := &groupsFixture{answers: map[string]func(http.ResponseWriter){}}
	upCA, err := NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		for name, v := range groupValues {
			if key == v {
				key = name
			}
		}
		call := r.Host + r.URL.Path + " " + key
		f.mu.Lock()
		f.calls = append(f.calls, call)
		answer := f.answers[key]
		f.mu.Unlock()
		if answer == nil {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"type":"message"}`)
			return
		}
		answer(w)
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return upCA.leaf(hello.ServerName) }}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	f.p, err = Listen("", policy.Enforce, []string{claudeHost, codexHost}, nil, (&decisions{}).observe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.p.Close() })
	f.p.dial = (&dials{secure: origin.Listener.Addr().String()}).dial
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(upCA.PEM())
	f.p.TrustUpstream(roots)
	var creds []Credential
	group := func(host, format string, names ...string) *modelkey.Group {
		var keys []modelkey.Key
		for _, name := range names {
			value := groupValues[name]
			creds = append(creds, Credential{Name: name, Hosts: []string{host}, Scheme: "bearer", Placeholder: link.KeyPlaceholder(names[0]), Token: func() string { return value }})
			keys = append(keys, modelkey.Key{Name: name, PauseFor: time.Hour})
		}
		g := modelkey.New(keys, "", nil)
		g.SetFormat(format)
		return g
	}
	f.claude = group(claudeHost, modelkey.FormatAnthropicMessages, "claude", "claude-2")
	f.codex = group(codexHost, modelkey.FormatOpenAIResponses, "codex", "codex-2")
	f.p.SetKeyGroups([]KeyGroup{
		{Group: f.claude, Format: modelkey.FormatAnthropicMessages, Stream: "/anthropic/v1/messages"},
		{Group: f.codex, Format: modelkey.FormatOpenAIResponses, Stream: "/v1/responses"},
	}, nil)
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	f.p.Terminate(ca, creds, nil, nil)
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	proxyURL, _ := url.Parse(f.p.URL())
	f.client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}, Timeout: 10 * time.Second}
	return f
}

// post sends a POST to host and path with the placeholder of the key first, and returns
// the status and the calls the provider got for it.
func (f *groupsFixture) post(t *testing.T, host, path, first string) (int, []string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "https://"+host+path, strings.NewReader(`{"model":"m"}`))
	req.Header.Set("Authorization", "Bearer "+link.KeyPlaceholder(first))
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	calls := f.calls
	f.calls = nil
	return resp.StatusCode, calls
}

// stream answers a 200 event stream whose one event is event and data.
func stream(event, data string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: "+event+"\ndata: "+data+"\n\n")
	}
}

// TestEachKeyGroupRotatesApart pins two key groups in one proxy: the proxy sets the
// active key of the group of the key the gateway set, on a request with that group's
// placeholder, and no key of the other group. A limit refusal in the claude group,
// anthropic-messages, is sent again with that group's next key and changes nothing of
// the codex group; a limit refusal in the codex group, openai-responses, reaches the
// session and stops that group alone, whose next request gets the proxy's 429. Each
// group reads the stream of its stream path: a rate_limit_error event on
// /anthropic/v1/messages moves the claude group to its next key, and the same event
// on the codex host is not read.
func TestEachKeyGroupRotatesApart(t *testing.T) {
	f := newGroupsFixture(t)
	f.answers["claude"] = limited
	f.p.SetModelKey("claude")
	if status, calls := f.post(t, claudeHost, "/anthropic/v1/messages", "claude"); status != http.StatusOK ||
		!slices.Equal(calls, []string{claudeHost + "/anthropic/v1/messages claude", claudeHost + "/anthropic/v1/messages claude-2"}) {
		t.Errorf("the claude request: %d %q; want claude refused, then claude-2", status, calls)
	}
	// The session's key is of the claude group: the codex host gets no key.
	if status, calls := f.post(t, codexHost, "/v1/responses", "codex"); status != http.StatusOK || !slices.Equal(calls, []string{codexHost + "/v1/responses " + link.KeyPlaceholder("codex")}) {
		t.Errorf("a codex request in a claude session: %d %q; want the placeholder alone", status, calls)
	}
	if f.codex.Active() != "codex" || f.codex.Passed() {
		t.Errorf("the codex group: active %s, passed %v; want codex, not passed", f.codex.Active(), f.codex.Passed())
	}

	f.p.SetModelKey("codex")
	f.answers["codex"] = func(w http.ResponseWriter) {
		w.Header().Set("X-Codex-Primary-Used-Percent", "100")
		w.Header().Set("X-Codex-Primary-Window-Minutes", "300")
		w.Header().Set("X-Codex-Primary-Reset-At", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"error":{"type":"usage_limit_reached"}}`)
	}
	if status, calls := f.post(t, codexHost, "/v1/responses", "codex"); status != http.StatusTooManyRequests || !slices.Equal(calls, []string{codexHost + "/v1/responses codex"}) {
		t.Errorf("the codex request: %d %q; want the provider's 429 for codex alone", status, calls)
	}
	if status, calls := f.post(t, codexHost, "/v1/responses", "codex"); status != http.StatusTooManyRequests || len(calls) != 0 {
		t.Errorf("the next codex request: %d %q; want the proxy's 429", status, calls)
	}
	if !f.codex.Passed() || f.claude.Passed() || f.claude.Active() != "claude-2" {
		t.Errorf("codex passed %v, claude passed %v and active %s; want codex alone passed, claude on claude-2", f.codex.Passed(), f.claude.Passed(), f.claude.Active())
	}

	f.p.SetModelKey("claude")
	f.answers["claude-2"] = stream("error", `{"type":"error","error":{"type":"rate_limit_error"}}`)
	if status, calls := f.post(t, claudeHost, "/anthropic/v1/messages", "claude"); status != http.StatusOK || !slices.Equal(calls, []string{claudeHost + "/anthropic/v1/messages claude-2"}) {
		t.Errorf("the claude stream: %d %q; want claude-2's stream", status, calls)
	}
	// Both claude keys are in cooldown now: the group has no usable key.
	if _, ok := f.claude.Pick(); ok {
		t.Errorf("the claude group has a usable key after its stream's rate_limit_error")
	}
	if f.codex.Active() != "codex" {
		t.Errorf("the codex group's active key %s; want codex", f.codex.Active())
	}
}

// TestAGroupsFirstKeyPlaceholderSetsItsActiveKey pins the placeholder of a key group:
// with the group's second key active, a request with the placeholder of the group's
// first key gets the second key, and a request with the placeholder of the second key's
// name gets none.
func TestAGroupsFirstKeyPlaceholderSetsItsActiveKey(t *testing.T) {
	f := newGroupsFixture(t)
	f.claude.SetActive("claude-2")
	f.p.SetModelKey("claude-2")
	if status, calls := f.post(t, claudeHost, "/anthropic/v1/messages", "claude"); status != http.StatusOK || !slices.Equal(calls, []string{claudeHost + "/anthropic/v1/messages claude-2"}) {
		t.Errorf("a request with the group's placeholder: %d %q; want claude-2", status, calls)
	}
	if status, calls := f.post(t, claudeHost, "/anthropic/v1/messages", "claude-2"); status != http.StatusOK || !slices.Equal(calls, []string{claudeHost + "/anthropic/v1/messages " + link.KeyPlaceholder("claude-2")}) {
		t.Errorf("a request with claude-2's name's placeholder: %d %q; want no key", status, calls)
	}
}
