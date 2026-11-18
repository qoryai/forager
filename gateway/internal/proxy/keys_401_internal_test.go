package proxy

import (
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/forager/gateway/internal/modelkey"
)

// unauthorizedAnswer is the provider's 401 to a key it no longer accepts.
func unauthorizedAnswer(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	io.WriteString(w, `{"error":{"type":"invalid_request_error","code":"invalid_api_key"}}`)
}

// renewals records the calls of each key's Rejected; the key named none has none.
type renewals struct {
	mu    sync.Mutex
	calls []string
	none  string
}

func (r *renewals) rejected(name string) func() {
	if name == r.none {
		return nil
	}
	return func() {
		r.mu.Lock()
		r.calls = append(r.calls, name)
		r.mu.Unlock()
	}
}

func (r *renewals) taken() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

// TestA401ByFormat pins the provider's 401 to the active key: the key goes out of use,
// with its renewal pending when its value renews, and out of the group when it does not.
// anthropic-messages sends the same body again with the next key, and the session gets
// that answer with no stop; openai-responses passes the 401 to the session with no
// resend, and the group stops with model_key_switch.
func TestA401ByFormat(t *testing.T) {
	cases := []struct {
		format, path string
		renews       bool
		status       int
		calls        string
		reason       string
		unauthorized modelkey.Unauthorized
	}{
		{modelkey.FormatAnthropicMessages, "/v1/messages", true, http.StatusOK, "model,model-2", "", modelkey.Unauthorized{Credential: "model"}},
		{modelkey.FormatAnthropicMessages, "/v1/messages", false, http.StatusOK, "model,model-2", "", modelkey.Unauthorized{Credential: "model", Out: true}},
		{modelkey.FormatOpenAIResponses, responsesPath, true, http.StatusUnauthorized, "model", "model_key_switch", modelkey.Unauthorized{Credential: "model"}},
		{modelkey.FormatOpenAIResponses, responsesPath, false, http.StatusUnauthorized, "model", "model_key_switch", modelkey.Unauthorized{Credential: "model", Out: true}},
	}
	for _, c := range cases {
		name := c.format + ", no expires_at"
		if c.renews {
			name = c.format + ", renews"
		}
		t.Run(name, func(t *testing.T) {
			r := &renewals{}
			if !c.renews {
				r.none = "model"
			}
			f := newKeyFixtureWith(t, c.format, c.path, r.rejected)
			f.up.answers["model"] = unauthorizedAnswer
			status, body := f.postTo(t, http.MethodPost, c.path, `{"model":"m"}`)
			if status != c.status || (status == http.StatusUnauthorized && !strings.Contains(body, "invalid_api_key")) {
				t.Errorf("the session got %d %q; want %d", status, body, c.status)
			}
			if got := strings.Join(keysOf(f.up.taken()), ","); got != c.calls {
				t.Errorf("the provider got %s; want %s", got, c.calls)
			}
			got := f.g.Unauthorized()
			if len(got) != 1 || got[0].Credential != c.unauthorized.Credential || got[0].Out != c.unauthorized.Out || got[0].At.IsZero() {
				t.Errorf("unauthorized %+v; want %+v with its time", got, c.unauthorized)
			}
			if want := []string{"model"}; c.renews != slices.Equal(r.taken(), want) {
				t.Errorf("the renewals asked for %v; renews %v", r.taken(), c.renews)
			}
			reason, ok := f.g.Stop()
			if reason != c.reason || ok != (c.reason != "") {
				t.Errorf("the stop %q, %v; want %q", reason, ok, c.reason)
			}
			f.mu.Lock()
			logged := strings.Join(f.logged, "\n")
			f.mu.Unlock()
			if !strings.Contains(logged, `model key "model": the provider returned 401`) || strings.Contains(logged, "sk-fake") {
				t.Errorf("the log: %q", logged)
			}
		})
	}
}

// TestEveryKey401PassesTheLast pins an anthropic-messages group whose keys all get a
// 401: each key is tried once, the session gets the last 401, the stop is
// model_key_unauthorized when no key renews, and model_key_limit while a key waits for
// its renewal; the next request gets the gateway's 429 and reaches no provider.
func TestEveryKey401PassesTheLast(t *testing.T) {
	for _, c := range []struct {
		what   string
		none   func(string) bool
		reason string
	}{
		{"no key renews", func(string) bool { return true }, "model_key_unauthorized"},
		{"model-2 renews", func(n string) bool { return n != "model-2" }, "model_key_limit"},
	} {
		t.Run(c.what, func(t *testing.T) {
			f := newKeyFixtureWith(t, modelkey.FormatAnthropicMessages, "/v1/messages", func(name string) func() {
				if c.none(name) {
					return nil
				}
				return func() {}
			})
			for name := range fakeKeys {
				f.up.answers[name] = unauthorizedAnswer
			}
			if status, _ := f.post(t, "{}"); status != http.StatusUnauthorized {
				t.Fatalf("the session got %d; want the provider's 401", status)
			}
			if got := strings.Join(keysOf(f.up.taken()), ","); got != "model,model-2,model-3" {
				t.Errorf("the provider got %s; want each key once", got)
			}
			if reason, ok := f.g.Stop(); !ok || reason != c.reason {
				t.Errorf("the stop %q, %v; want %q", reason, ok, c.reason)
			}
			if status, _ := f.post(t, "{}"); status != http.StatusTooManyRequests || len(f.up.taken()) != 0 {
				t.Errorf("after the stop: %d; want the gateway's 429 and no call", status)
			}
		})
	}
}

// TestA401OnAnotherPathKeepsTheKey pins the path of a 401 that rejects a key: a 401 to
// a request to another path than the model API's, of either format, reaches the
// session as it came, with no resend, the key stays in use and the group goes on with
// no stop, and a key whose value renews has it requested again as any credential has.
func TestA401OnAnotherPathKeepsTheKey(t *testing.T) {
	for _, c := range []struct{ format, path string }{
		{modelkey.FormatAnthropicMessages, "/v1/messages"},
		{modelkey.FormatOpenAIResponses, responsesPath},
	} {
		t.Run(c.format, func(t *testing.T) {
			r := &renewals{}
			f := newKeyFixtureWith(t, c.format, c.path, r.rejected)
			f.up.answers["model"] = unauthorizedAnswer
			if status, _ := f.postTo(t, http.MethodGet, "/v1/accounts/check", ""); status != http.StatusUnauthorized {
				t.Errorf("the session got %d; want the provider's 401", status)
			}
			if got := strings.Join(keysOf(f.up.taken()), ","); got != "model" {
				t.Errorf("the provider got %s; want model alone", got)
			}
			if got := f.g.Unauthorized(); got != nil || f.g.Active() != "model" {
				t.Errorf("unauthorized %+v, active %s; want none and model", got, f.g.Active())
			}
			if _, ok := f.g.Stop(); ok {
				t.Error("a stop after a 401 on another path")
			}
			if got := r.taken(); !slices.Equal(got, []string{"model"}) {
				t.Errorf("the renewals asked for %v; want model once", got)
			}
		})
	}
}

// TestA401OnAnotherPathAfterAResendRenewsTheLastKey pins the key whose value the proxy
// requests again after a 401 on another path than the model API's: a request that the
// proxy sent again with model-2 after model's 429 gets model-2's 401, and the proxy
// requests model-2's value again, not model's.
func TestA401OnAnotherPathAfterAResendRenewsTheLastKey(t *testing.T) {
	r := &renewals{}
	f := newKeyFixtureWith(t, modelkey.FormatAnthropicMessages, "/v1/messages", r.rejected)
	f.up.answers["model"] = limited
	f.up.answers["model-2"] = unauthorizedAnswer
	if status, _ := f.postTo(t, http.MethodGet, "/v1/accounts/check", ""); status != http.StatusUnauthorized {
		t.Errorf("the session got %d; want model-2's 401", status)
	}
	if got := strings.Join(keysOf(f.up.taken()), ","); got != "model,model-2" {
		t.Errorf("the provider got %s; want model, then model-2", got)
	}
	if got := r.taken(); !slices.Equal(got, []string{"model-2"}) {
		t.Errorf("the renewals requested %v; want model-2 once", got)
	}
	if got := f.g.Unauthorized(); got != nil {
		t.Errorf("unauthorized %+v; want none", got)
	}
}
