package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// chatHost is the host of the subscription keys of the account header tests.
const chatHost = "chat.model.example"

// chatClaim is the account_claim of the subscription keys: a member name with slashes,
// written with ~1.
const chatClaim = "/https:~1~1auth.model.example~1auth/account_id"

// chatToken is a fake JWT whose payload has the account id id at chatClaim, or no
// account id when id is empty. No key signed it.
func chatToken(id string) string {
	enc := base64.RawURLEncoding.EncodeToString
	payload := `{"sub":"fake"}`
	if id != "" {
		payload = `{"https://auth.model.example/auth":{"account_id":"` + id + `"}}`
	}
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(payload)) + ".fake-signature"
}

// seenRequest is what the fake provider received of one request: its path, its
// Authorization, and every value of each spelling of the account header.
type seenRequest struct {
	path, auth string
	account    []string
}

// accountFixture is a proxy that terminates chatHost with subscription keys and a host
// credential, files, beside them, and a fake provider that records each request.
type accountFixture struct {
	p      *Proxy
	client *http.Client
	mu     sync.Mutex
	seen   []seenRequest
	// status, by the request's Authorization, is the provider's answer; 200 without one.
	status map[string]int
}

// subscriptionKey is a subscription key on chatHost's codex paths with the account
// header, whose value is value and whose placeholder is the start key's.
func subscriptionKey(name, value string) Credential {
	return Credential{Name: name, Hosts: []string{chatHost}, Scheme: "bearer", Paths: []string{"/backend-api/codex/*"},
		Placeholder: link.KeyPlaceholder("subscription"), Stored: true, Value: func() []byte { return []byte(value) },
		AccountHeader: "chatgpt-account-id", Account: func(v []byte) (string, error) { return credential.AccountClaim(v, chatClaim) }}
}

// newAccountFixture starts the provider and the proxy, under enforce, with the policy's
// path rules paths, the credentials creds, and the key group g when it is not nil.
func newAccountFixture(t *testing.T, paths map[string][]string, g *modelkey.Group, creds ...Credential) *accountFixture {
	t.Helper()
	up, err := NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	f := &accountFixture{status: map[string]int{}}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := seenRequest{path: r.URL.Path, auth: r.Header.Get("Authorization")}
		for name, values := range r.Header {
			if strings.EqualFold(strings.ReplaceAll(name, "_", "-"), "chatgpt-account-id") {
				s.account = append(s.account, values...)
			}
		}
		f.mu.Lock()
		f.seen = append(f.seen, s)
		status := f.status[s.auth]
		f.mu.Unlock()
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		io.WriteString(w, "{}")
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return up.leaf(hello.ServerName) }}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	f.p, err = Listen("", policy.Enforce, []string{chatHost}, nil, (&decisions{}).observe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.p.Close() })
	f.p.dial = (&dials{secure: origin.Listener.Addr().String()}).dial
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(up.PEM())
	f.p.TrustUpstream(roots)
	if g != nil {
		f.p.SetKeyGroup(g, "/backend-api/codex/responses", nil)
	}
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	f.p.Terminate(ca, creds, paths, nil)
	f.p.SetModelKey("subscription")
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	proxyURL, _ := url.Parse(f.p.URL())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}
	t.Cleanup(tr.CloseIdleConnections)
	f.client = &http.Client{Transport: tr, Timeout: 10 * time.Second}
	return f
}

// send sends method to path on chatHost with the start key's placeholder when keyed is
// true, and the account header the agent chose in two spellings, and returns the
// status and what the provider received of it, nothing when it received none.
func (f *accountFixture) send(t *testing.T, method, path string, keyed bool) (int, []seenRequest) {
	t.Helper()
	f.mu.Lock()
	f.seen = nil
	f.mu.Unlock()
	req, _ := http.NewRequest(method, "https://"+chatHost+path, nil)
	if keyed {
		req.Header.Set("Authorization", "Bearer "+link.KeyPlaceholder("subscription"))
	}
	req.Header.Set("Chatgpt-Account-Id", "acct-of-the-agent")
	req.Header["chatgpt_account_id"] = []string{"acct-of-the-agent-2"}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	return resp.StatusCode, f.seen
}

// TestAModelKeyIsSetOnItsPathsAlone pins a model key with paths beside a host
// credential with other paths of its host, the 521 probe's fix 2: the key goes on its
// paths with the account id of its value in the account header; the host credential
// on its paths with no account header; another path of the host is denied with 403,
// unless the run policy's path rules list it, and then it goes with neither the key nor
// an account header. The agent's account header never reaches the provider, in any
// spelling, also on a request without the placeholder.
func TestAModelKeyIsSetOnItsPathsAlone(t *testing.T) {
	token := chatToken("acct-fake-0001")
	placeholder := "Bearer " + link.KeyPlaceholder("subscription")
	files := Credential{Name: "files", Hosts: []string{chatHost}, Scheme: "bearer", Paths: []string{"/backend-api/files/*"}, Stored: true,
		Value: func() []byte { return []byte("files-fake-value") }}
	for name, paths := range map[string]map[string][]string{
		"no path rules": nil,
		"path rules":    {chatHost: {"/backend-api/codex/*", "/backend-api/files/*", "/backend-api/wham/*"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAccountFixture(t, paths, nil, subscriptionKey("subscription", token), files)
			status, seen := f.send(t, http.MethodPost, "/backend-api/codex/responses", true)
			if status != http.StatusOK || len(seen) != 1 || seen[0].auth != "Bearer "+token || strings.Join(seen[0].account, ",") != "acct-fake-0001" {
				t.Errorf("the key's path: %d, %+v", status, seen)
			}
			status, seen = f.send(t, http.MethodGet, "/backend-api/codex/models", false)
			if status != http.StatusOK || len(seen) != 1 || seen[0].auth != "" || len(seen[0].account) != 0 {
				t.Errorf("the key's path without the placeholder: %d, %+v", status, seen)
			}
			status, seen = f.send(t, http.MethodGet, "/backend-api/files/one", false)
			if status != http.StatusOK || len(seen) != 1 || seen[0].auth != "Bearer files-fake-value" || len(seen[0].account) != 0 {
				t.Errorf("the host credential's path: %d, %+v", status, seen)
			}
			status, seen = f.send(t, http.MethodGet, "/backend-api/wham/accounts/check", true)
			switch {
			case paths == nil && (status != http.StatusForbidden || len(seen) != 0):
				t.Errorf("another path with no path rules: %d, %+v; want 403", status, seen)
			case paths != nil && (status != http.StatusOK || len(seen) != 1 || seen[0].auth != placeholder || len(seen[0].account) != 0):
				t.Errorf("another path the path rules list: %d, %+v; want it with the placeholder alone", status, seen)
			}
			if status, seen := f.send(t, http.MethodGet, "/elsewhere", true); status != http.StatusForbidden || len(seen) != 0 {
				t.Errorf("a path nothing lists: %d, %+v; want 403", status, seen)
			}
		})
	}
}

// TestAKeyWithoutItsClaimIsNotSet pins the proxy's side of a value with no account
// claim, one that changed since the run loaded it: the proxy sets neither the key nor
// the account header, and the agent's account header is gone all the same.
func TestAKeyWithoutItsClaimIsNotSet(t *testing.T) {
	f := newAccountFixture(t, nil, nil, subscriptionKey("subscription", chatToken("")))
	status, seen := f.send(t, http.MethodPost, "/backend-api/codex/responses", true)
	if status != http.StatusOK || len(seen) != 1 || seen[0].auth != "Bearer "+link.KeyPlaceholder("subscription") || len(seen[0].account) != 0 {
		t.Errorf("%d, %+v; want the placeholder alone", status, seen)
	}
}

// TestAResendSetsTheNextKeysAccount pins the account header on a request sent again
// with the next key of the group after a limit refusal: the second request has the
// second key and the second key's account id, never the first's.
func TestAResendSetsTheNextKeysAccount(t *testing.T) {
	one, two := chatToken("acct-fake-0001"), chatToken("acct-fake-0002")
	g := modelkey.New([]modelkey.Key{{Name: "subscription", PauseFor: time.Hour}, {Name: "subscription-2", PauseFor: time.Hour}}, "subscription", nil)
	f := newAccountFixture(t, nil, g, subscriptionKey("subscription", one), subscriptionKey("subscription-2", two))
	f.status["Bearer "+one] = http.StatusTooManyRequests
	status, seen := f.send(t, http.MethodPost, "/backend-api/codex/responses", true)
	if status != http.StatusOK || len(seen) != 2 || seen[1].auth != "Bearer "+two || strings.Join(seen[1].account, ",") != "acct-fake-0002" {
		t.Errorf("%d, %+v; want the second key with its account id", status, seen)
	}
}
