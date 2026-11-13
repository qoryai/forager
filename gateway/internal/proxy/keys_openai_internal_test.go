package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/link"
)

// The openai-responses answers of this file have fake values. Their shapes follow the
// openai/codex source at 17a0e6f63f (from source, to confirm with probe
// 1a/1c/8-api/burst-429), and the x-codex-* header names follow the probe's item 8.

// responsesPath is the stream path of the openai-responses group of these tests.
const responsesPath = "/v1/responses"

// codexLimited returns a ChatGPT subscription's 429 (from source): the five_hour window
// at 100 percent, reset in an hour, x-codex-rate-limit-reached-type, and the body of
// usage_limit_reached, with no Retry-After.
func codexLimited(w http.ResponseWriter) {
	reset := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	w.Header().Set("X-Codex-Primary-Used-Percent", "100")
	w.Header().Set("X-Codex-Primary-Window-Minutes", "300")
	w.Header().Set("X-Codex-Primary-Reset-At", reset)
	w.Header().Set("X-Codex-Rate-Limit-Reached-Type", "rate_limit_reached")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	io.WriteString(w, `{"error":{"type":"usage_limit_reached","message":"The usage limit has been reached","plan_type":"example","resets_at":`+reset+`}}`)
}

// TestAResendByFormat pins the resend of a limit refusal by the group's format: an
// anthropic-messages request goes again with the next key, and the session gets that
// answer, and the next key becomes active, as before; an openai-responses request goes
// once, the session gets the provider's 429, and the key stays active until the next
// join.
func TestAResendByFormat(t *testing.T) {
	cases := []struct {
		format, path string
		limited      func(http.ResponseWriter)
		status       int
		calls        string
		passed       bool
		active       string
	}{
		{modelkey.FormatAnthropicMessages, "/v1/messages", limited, http.StatusOK, "model,model-2", false, "model-2"},
		{modelkey.FormatOpenAIResponses, responsesPath, codexLimited, http.StatusTooManyRequests, "model", true, "model"},
	}
	for _, c := range cases {
		t.Run(c.format, func(t *testing.T) {
			f := newKeyFixtureOf(t, c.format, c.path)
			f.up.answers["model"] = c.limited
			status, _ := f.postTo(t, http.MethodPost, c.path, `{"model":"m"}`)
			if status != c.status {
				t.Errorf("the session got %d; want %d", status, c.status)
			}
			if got := strings.Join(keysOf(f.up.taken()), ","); got != c.calls {
				t.Errorf("the provider got %s; want %s", got, c.calls)
			}
			if f.g.Passed() != c.passed || f.g.Active() != c.active {
				t.Errorf("passed %v, active %s; want %v and %s", f.g.Passed(), f.g.Active(), c.passed, c.active)
			}
		})
	}
}

// TestAnOpenAIRefusalReachesTheSessionAndHoldsTheRest pins the first 429 of an
// openai-responses group: the provider's 429 reaches the session as it came, the key
// goes into cooldown at its rejected window, and the group is stopped. Every later
// request with the placeholder, on any path, gets the gateway's 429 with no
// Retry-After, and reaches no provider, until the next join makes the next key active.
func TestAnOpenAIRefusalReachesTheSessionAndHoldsTheRest(t *testing.T) {
	f := newKeyFixtureOf(t, modelkey.FormatOpenAIResponses, responsesPath)
	f.up.answers["model"] = codexLimited
	status, body := f.postTo(t, http.MethodPost, responsesPath, `{"model":"m","stream":true}`)
	if status != http.StatusTooManyRequests || !strings.Contains(body, "usage_limit_reached") {
		t.Fatalf("the session got %d %q; want the provider's 429", status, body)
	}
	if got := keysOf(f.up.taken()); strings.Join(got, ",") != "model" {
		t.Errorf("the provider got %v; want model alone", got)
	}
	if w := f.g.Windows(); len(w) != 1 || w[0].Credential != "model" || w[0].Window != "five_hour" || w[0].Status != modelkey.StatusRejected {
		t.Errorf("windows %+v; want model's five_hour rejected", w)
	}
	f.mu.Lock()
	logged := strings.Join(f.logged, "\n")
	f.mu.Unlock()
	if !strings.HasPrefix(logged, `model key "model": limit answer, status 429, error type usage_limit_reached, headers `) || strings.Contains(logged, "rate_limit_reached") {
		t.Errorf("the log of limit answers: %q", logged)
	}
	for _, path := range []string{responsesPath, "/v1/models"} {
		req, _ := http.NewRequest(http.MethodPost, "https://"+keyHost+path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+link.KeyPlaceholder("model"))
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "" || !strings.HasPrefix(string(b), "qory: the run pauses:") {
			t.Errorf("%s after the stop: %d, Retry-After %q, %q; want the gateway's 429 with no Retry-After", path, resp.StatusCode, resp.Header.Get("Retry-After"), b)
		}
	}
	if calls := f.up.taken(); len(calls) != 0 {
		t.Errorf("the provider got %v after the stop; want no call", calls)
	}
	if d := f.seen.at(-1); d.Outcome != Refused || d.Credential != "" || d.Status != 0 {
		t.Errorf("the record of the held request %+v", d)
	}
	if got := f.g.JoinKey(); got != "model-2" {
		t.Errorf("the next join's key %s; want model-2", got)
	}
	f.g.Resume()
	if status, _ := f.postTo(t, http.MethodPost, responsesPath, "{}"); status != http.StatusOK {
		t.Errorf("after the join: %d; want 200", status)
	}
	if got := keysOf(f.up.taken()); strings.Join(got, ",") != "model-2" {
		t.Errorf("after the join the provider got %v; want model-2", got)
	}
}

// TestAnOpenAIRequestHasNoCopy pins the body of an openai-responses request: the proxy
// keeps no copy, since it never sends the request again.
func TestAnOpenAIRequestHasNoCopy(t *testing.T) {
	g := modelkey.New([]modelkey.Key{{Name: "model", PauseFor: time.Hour}, {Name: "model-2", PauseFor: time.Hour}}, "model", nil)
	one := &Credential{Name: "model", Hosts: []string{keyHost}, Scheme: "bearer", Token: func() string { return fakeKeys["model"] }}
	k := &keyGroup{g: g, format: modelkey.FormatOpenAIResponses, messages: responsesPath, log: func(string) {}}
	r := httptest.NewRequest(http.MethodPost, "https://"+keyHost+responsesPath, strings.NewReader(`{"model":"m"}`))
	ctx := (&Proxy{}).withResend(r.Context(), r, k, one, []*Credential{one}, responsesPath, true)
	rs := resendOf(r.WithContext(ctx))
	if rs == nil || rs.body != nil || rs.copied {
		t.Fatalf("the resend %+v; want one with no copy", rs)
	}
	if _, ok := r.Body.(*copyReader); ok {
		t.Error("the request's body is a copy")
	}
}

// openaiStream returns a streamed 200 of the Responses API that ends with a
// response.failed event (from source) whose error has code.
func openaiStream(code string) (string, func(http.ResponseWriter)) {
	stream := "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\"}}\n\n" +
		"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"rate_limit_exceeded\"}\n\n" +
		"event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp_1\",\"status\":\"failed\",\"error\":{\"code\":\"" + code + "\",\"message\":\"m\"}}}\n\n"
	return stream, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, stream)
	}
}

// TestAnOpenAIStreamLimitStopsTheGroup pins a streamed 200 of an openai-responses
// group that ends with response.failed and a limit code: the bytes reach the session as
// they came, the key goes into cooldown and stays active, and the group is stopped, so
// the runtime's retry gets the gateway's 429 and reaches no provider. A response.failed
// of another code changes nothing.
func TestAnOpenAIStreamLimitStopsTheGroup(t *testing.T) {
	f := newKeyFixtureOf(t, modelkey.FormatOpenAIResponses, responsesPath)
	_, overloaded := openaiStream("server_is_overloaded")
	f.up.answers["model"] = overloaded
	f.postTo(t, http.MethodPost, responsesPath, `{"stream":true}`)
	if f.g.Active() != "model" || f.g.Passed() {
		t.Fatalf("after server_is_overloaded: active %s, passed %v; want model and no stop", f.g.Active(), f.g.Passed())
	}
	f.up.taken()
	stream, limit := openaiStream("rate_limit_exceeded")
	f.up.answers["model"] = limit
	status, body := f.postTo(t, http.MethodPost, responsesPath, `{"stream":true}`)
	if status != http.StatusOK || body != stream {
		t.Fatalf("the session got %d %q; want the stream as it came", status, body)
	}
	if !f.g.Passed() || f.g.Active() != "model" {
		t.Errorf("passed %v, active %s; want the stop and model", f.g.Passed(), f.g.Active())
	}
	if w := f.g.Windows(); len(w) != 1 || w[0].Window != modelkey.WindowKey || w[0].Status != modelkey.StatusRejected {
		t.Errorf("windows %+v; want model's key window rejected", w)
	}
	if status, _ := f.postTo(t, http.MethodPost, responsesPath, `{"stream":true}`); status != http.StatusTooManyRequests {
		t.Errorf("the retry got %d; want the gateway's 429", status)
	}
	if got := keysOf(f.up.taken()); strings.Join(got, ",") != "model" {
		t.Errorf("the provider got %v; want model alone", got)
	}
	f.mu.Lock()
	logged := strings.Join(f.logged, "\n")
	f.mu.Unlock()
	if !strings.HasPrefix(logged, `model key "model": limit answer, status 200, error type none, error code rate_limit_exceeded, headers `) {
		t.Errorf("the log of limit answers: %q", logged)
	}
}

// TestAnOpenAIKeyInCooldownMidSessionGetsTheProxys429 pins the active key of an
// openai-responses group that goes into cooldown with no refusal in the session: from a
// report's answer, or at its use_up_to_percent after a 200. The next request gets the
// proxy's 429, the provider gets no request with another key, and the group is stopped.
func TestAnOpenAIKeyInCooldownMidSessionGetsTheProxys429(t *testing.T) {
	f := newKeyFixtureOf(t, modelkey.FormatOpenAIResponses, responsesPath)
	f.g.Merge([]modelkey.Window{{Credential: "model", Window: "five_hour", Status: modelkey.StatusRejected, CooldownUntil: time.Now().Add(time.Hour), Source: modelkey.SourceProvider, ObservedAt: time.Now()}})
	if status, _ := f.postTo(t, http.MethodPost, responsesPath, "{}"); status != http.StatusTooManyRequests {
		t.Errorf("after a merged cooldown: %d; want the gateway's 429", status)
	}
	if calls := f.up.taken(); len(calls) != 0 || !f.g.Passed() {
		t.Errorf("after a merged cooldown the provider got %v, passed %v; want no call and the stop", calls, f.g.Passed())
	}

	u := newKeyFixtureOf(t, modelkey.FormatOpenAIResponses, responsesPath, func(k *modelkey.Key) { k.UseUpToPercent, k.UseUpToWindows = 90, []string{"five_hour"} })
	reset := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	u.up.answers["model"] = func(w http.ResponseWriter) {
		w.Header().Set("X-Codex-Primary-Used-Percent", "95")
		w.Header().Set("X-Codex-Primary-Window-Minutes", "300")
		w.Header().Set("X-Codex-Primary-Reset-At", reset)
		io.WriteString(w, `{"type":"response"}`)
	}
	if status, _ := u.postTo(t, http.MethodPost, responsesPath, "{}"); status != http.StatusOK {
		t.Fatalf("the request that reaches the percentage: %d; want 200", status)
	}
	if status, _ := u.postTo(t, http.MethodPost, responsesPath, "{}"); status != http.StatusTooManyRequests {
		t.Errorf("at use_up_to_percent: %d; want the gateway's 429", status)
	}
	if got := keysOf(u.up.taken()); strings.Join(got, ",") != "model" || !u.g.Passed() {
		t.Errorf("at use_up_to_percent the provider got %v, passed %v; want model once and the stop", got, u.g.Passed())
	}
}

// failedEvent is a response.failed event with the code rate_limit_exceeded whose data
// has size bytes, padded in its message.
func failedEvent(size int) string {
	head := `{"type":"response.failed","response":{"error":{"code":"rate_limit_exceeded","message":"`
	tail := `"}}}`
	return "event: response.failed\ndata: " + head + strings.Repeat("a", size-len(head)-len(tail)) + tail + "\n\n"
}

// TestAnEventsDataStaysWithinItsLimit pins the cap of an event's data: an event of one
// data line near the limit, then many data lines with no empty line, keeps at most
// maxFailedData bytes of data, for empty data lines and for data lines of one byte.
func TestAnEventsDataStaysWithinItsLimit(t *testing.T) {
	for _, more := range []string{"data:\n", "data: a\n"} {
		stream := "data: " + strings.Repeat("a", maxFailedData-len("data: ")-10) + "\n" + strings.Repeat(more, 1000)
		s := &streamWatch{ReadCloser: io.NopCloser(strings.NewReader(stream)), format: modelkey.FormatOpenAIResponses}
		if _, err := io.Copy(io.Discard, s); err != nil {
			t.Fatal(err)
		}
		if len(s.data) > maxFailedData || !s.over {
			t.Errorf("%q lines: %d bytes of data, over %v; want at most %d, over", more, len(s.data), s.over, maxFailedData)
		}
	}
}

// TestAResponseFailedEventHasALargerLimit pins the limit of an event's data in an
// openai-responses stream, maxFailedData: a response.failed event just over 4096 bytes
// counts, with its event field first, after its data line or with none, and one over
// the limit is passed on unread. A long event of another type before it changes
// nothing.
func TestAResponseFailedEventHasALargerLimit(t *testing.T) {
	cases := []struct {
		name  string
		event string
		cools bool
	}{
		{"just over 4096", failedEvent(maxLine + 1), true},
		{"at the limit", failedEvent(maxFailedData - len("data: ")), true},
		{"over the limit", failedEvent(maxFailedData + 1), false},
		{"data before the event field", "data: " + strings.TrimPrefix(strings.TrimSuffix(failedEvent(maxLine+1), "\n\n"), "event: response.failed\ndata: ") + "\nevent: response.failed\n\n", true},
		{"no event field", strings.TrimPrefix(failedEvent(maxLine+1), "event: response.failed\n"), true},
		{"another event over 4096, then another code", "event: response.in_progress\ndata: " + strings.Repeat("a", maxLine+1) + "\n\n" +
			"data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"server_is_overloaded\"}}}\n\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newKeyFixtureOf(t, modelkey.FormatOpenAIResponses, responsesPath)
			f.up.answers["model"] = func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, c.event)
			}
			status, body := f.postTo(t, http.MethodPost, responsesPath, `{"stream":true}`)
			if status != http.StatusOK || body != c.event {
				t.Fatalf("the session got %d and %d bytes; want the stream as it came", status, len(body))
			}
			if f.g.Passed() != c.cools {
				t.Errorf("passed %v; want %v", f.g.Passed(), c.cools)
			}
		})
	}
}
