package modelkey_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/modelkey"
)

// The fixtures of this file have fake values. The x-codex-* header names and shapes of
// a 200 are measured (probe 521, item 8). Each fixture marked "from source" follows the
// openai/codex source at 17a0e6f63f, to confirm with probe 1a/1c/8-api/burst-429: the
// x-codex-rate-limit-reached-type header, the API key's x-ratelimit-* headers, the 429
// bodies and the response.failed event.

// TestTheCodexHeadersGiveEachWindow pins the reading of a ChatGPT subscription's 200:
// window-minutes 300 is five_hour and 10080 is seven_day, used-percent is the
// utilization, the reset is reset-at, else the answer's time plus reset-after-seconds,
// and the other x-codex-* headers are no window.
func TestTheCodexHeadersGiveEachWindow(t *testing.T) {
	g, _ := group(t)
	reset5 := start.Add(2 * time.Hour)
	g.Answered("model", http.StatusOK, headers(
		"X-Codex-Primary-Used-Percent", "42",
		"X-Codex-Primary-Window-Minutes", "300",
		"X-Codex-Primary-Reset-At", epoch(reset5),
		"X-Codex-Primary-Reset-After-Seconds", "60",
		"X-Codex-Primary-Over-Secondary-Limit-Percent", "0",
		"X-Codex-Secondary-Used-Percent", "7.9",
		"X-Codex-Secondary-Window-Minutes", "10080",
		"X-Codex-Secondary-Reset-At", "",
		"X-Codex-Secondary-Reset-After-Seconds", "3600",
		"X-Codex-Active-Limit", "codex",
		"X-Codex-Plan-Type", "example",
		"X-Codex-Credits-Has-Credits", "false",
		"X-Codex-Credits-Unlimited", "false",
		"X-Codex-Credits-Balance", "0",
	))
	cases := []struct {
		window string
		util   int
		reset  time.Time
	}{
		{"five_hour", 42, reset5},
		{"seven_day", 7, start.Add(time.Hour)},
	}
	for _, c := range cases {
		w, ok := window(g, "model", c.window)
		if !ok || w.Status != modelkey.StatusAllowed || w.Utilization != c.util || !w.HasUtilization || !w.ResetsAt.Equal(c.reset) || w.Source != modelkey.SourceProvider {
			t.Errorf("window %s: %+v (found %v); want allowed, utilization %d, reset %v", c.window, w, ok, c.util, c.reset)
		}
	}
	if ws := g.Windows(); len(ws) != 2 {
		t.Errorf("windows %+v; want five_hour and seven_day alone", ws)
	}
}

// TestACodexWindowOfOtherMinutesIsLeftOut pins a window of another length: no window,
// and the limit answer's log line contains its -window-minutes header; a window of 0
// minutes, a plan with no such window, is none and is not in the line.
func TestACodexWindowOfOtherMinutesIsLeftOut(t *testing.T) {
	g, _ := group(t)
	h := headers(
		"x-codex-primary-used-percent", "10",
		"x-codex-primary-window-minutes", "1440",
		"x-codex-secondary-used-percent", "0",
		"x-codex-secondary-window-minutes", "0",
	)
	g.Answered("model", http.StatusOK, h)
	if ws := g.Windows(); len(ws) != 0 {
		t.Errorf("windows %+v; want none", ws)
	}
	line := modelkey.Shown("model", 429, h, "", "")
	if !strings.HasSuffix(line, "; no window for x-codex-primary-window-minutes") || strings.Contains(line, "1440") {
		t.Errorf("Shown: %s", line)
	}
}

// TestACodexRefusalRejectsTheWindowAtItsLimit pins a subscription's 429 (from source):
// x-codex-rate-limit-reached-type has no window in it, so it marks rejected the windows
// the answer shows at 100 percent or more; the key cools until the latest reset among
// them, and the next key becomes active. The body's type is read for the log, and the
// body has no code.
func TestACodexRefusalRejectsTheWindowAtItsLimit(t *testing.T) {
	g, _ := group(t)
	reset5, reset7 := start.Add(90*time.Minute), start.Add(96*time.Hour)
	body := `{"error":{"type":"usage_limit_reached","message":"The usage limit has been reached","plan_type":"example","resets_at":` + epoch(reset5) + `,"limit_window_minutes":300}}`
	kind, code := modelkey.ErrorOf([]byte(body))
	if kind != "usage_limit_reached" || code != "" {
		t.Errorf("ErrorOf: %q, %q; want usage_limit_reached and no code", kind, code)
	}
	next, ok := g.Refused("model", headers(
		"x-codex-primary-used-percent", "100",
		"x-codex-primary-window-minutes", "300",
		"x-codex-primary-reset-at", epoch(reset5),
		"x-codex-secondary-used-percent", "64",
		"x-codex-secondary-window-minutes", "10080",
		"x-codex-secondary-reset-at", epoch(reset7),
		"x-codex-rate-limit-reached-type", "rate_limit_reached",
	), code)
	if next != "model-2" || !ok {
		t.Errorf("Refused: %s, %v; want model-2 out of cooldown", next, ok)
	}
	if w, _ := window(g, "model", "five_hour"); w.Status != modelkey.StatusRejected || !w.CooldownUntil.Equal(reset5) || w.Utilization != 100 || w.Source != modelkey.SourceProvider {
		t.Errorf("five_hour: %+v; want rejected until %v at 100", w, reset5)
	}
	if w, _ := window(g, "model", "seven_day"); w.Status != modelkey.StatusAllowed || !w.CooldownUntil.IsZero() || w.Utilization != 64 {
		t.Errorf("seven_day: %+v; want allowed at 64", w)
	}
	if _, ok := window(g, "model", modelkey.WindowKey); ok {
		t.Error("a refusal that rejects a window has a key window too")
	}
}

// TestACodexRefusalWithoutAWindowAtItsLimitCoolsTheKey pins a 429 whose windows are
// all below 100 percent, or that has no x-codex-rate-limit-reached-type: it rejects no
// window, so the key window cools for pause_for_s.
func TestACodexRefusalWithoutAWindowAtItsLimitCoolsTheKey(t *testing.T) {
	g, _ := group(t)
	g.Refused("model", headers(
		"x-codex-primary-used-percent", "80",
		"x-codex-primary-window-minutes", "300",
		"x-codex-rate-limit-reached-type", "workspace_member_credits_depleted",
	), "")
	g.Refused("model-2", headers(
		"x-codex-primary-used-percent", "100",
		"x-codex-primary-window-minutes", "300",
	), "")
	for _, name := range []string{"model", "model-2"} {
		if w, ok := window(g, name, modelkey.WindowKey); !ok || w.Status != modelkey.StatusRejected || !w.CooldownUntil.Equal(start.Add(5*time.Hour)) || w.Source != modelkey.SourcePauseFor {
			t.Errorf("%s key: %+v (found %v); want rejected for pause_for_s", name, w, ok)
		}
		if w, _ := window(g, name, "five_hour"); w.Status != modelkey.StatusAllowed {
			t.Errorf("%s five_hour: %+v; want allowed", name, w)
		}
	}
}

// TestTheOpenAIHeadersGiveEachFamily pins an OpenAI API key's 200 (from source):
// x-ratelimit-{limit,remaining,reset}-{requests,tokens} are requests and tokens, the
// utilization is 100 x (1 - remaining / limit), rounded down, and the reset a duration
// after the answer. Another family is in the log line and is no window.
func TestTheOpenAIHeadersGiveEachFamily(t *testing.T) {
	g, _ := group(t)
	h := headers(
		"x-ratelimit-limit-requests", "500",
		"x-ratelimit-remaining-requests", "499",
		"x-ratelimit-reset-requests", "120ms",
		"x-ratelimit-limit-tokens", "30000",
		"x-ratelimit-remaining-tokens", "15000",
		"x-ratelimit-reset-tokens", "6m0s",
		"x-ratelimit-limit-images", "5",
	)
	g.Answered("model", http.StatusOK, h)
	cases := []struct {
		window string
		util   int
		reset  time.Time
	}{
		{"requests", 0, start.Add(120 * time.Millisecond)},
		{"tokens", 50, start.Add(6 * time.Minute)},
	}
	for _, c := range cases {
		w, ok := window(g, "model", c.window)
		if !ok || w.Status != modelkey.StatusAllowed || w.Utilization != c.util || !w.HasUtilization || !w.ResetsAt.Equal(c.reset) {
			t.Errorf("window %s: %+v (found %v); want allowed, utilization %d, reset %v", c.window, w, ok, c.util, c.reset)
		}
	}
	if ws := g.Windows(); len(ws) != 2 {
		t.Errorf("windows %+v; want requests and tokens alone", ws)
	}
	if line := modelkey.Shown("model", 429, h, "", ""); !strings.HasSuffix(line, "; no window for x-ratelimit-limit-images") {
		t.Errorf("Shown: %s", line)
	}
}

// TestAnOpenAIRateRefusalCoolsTheFamilyAtZero pins an API key's rate limit 429 (from
// source): the family with 0 remaining is rejected until its reset, the body's type and
// code are read, and the code is no spend cap.
func TestAnOpenAIRateRefusalCoolsTheFamilyAtZero(t *testing.T) {
	g, _ := group(t)
	body := `{"error":{"message":"Rate limit reached for tokens per min","type":"tokens","param":null,"code":"rate_limit_exceeded"}}`
	kind, code := modelkey.ErrorOf([]byte(body))
	if kind != "tokens" || code != "rate_limit_exceeded" {
		t.Errorf("ErrorOf: %q, %q; want tokens and rate_limit_exceeded", kind, code)
	}
	g.Refused("model", headers(
		"x-ratelimit-limit-tokens", "30000",
		"x-ratelimit-remaining-tokens", "0",
		"x-ratelimit-reset-tokens", "6m0s",
		"x-ratelimit-limit-requests", "500",
		"x-ratelimit-remaining-requests", "480",
		"x-ratelimit-reset-requests", "2s",
	), code)
	if w, _ := window(g, "model", "tokens"); w.Status != modelkey.StatusRejected || !w.CooldownUntil.Equal(start.Add(6*time.Minute)) || w.Utilization != 100 {
		t.Errorf("tokens: %+v; want rejected for 6 minutes at 100", w)
	}
	if w, _ := window(g, "model", "requests"); w.Status != modelkey.StatusAllowed || !w.CooldownUntil.IsZero() {
		t.Errorf("requests: %+v; want allowed", w)
	}
	if _, ok := window(g, "model", modelkey.WindowSpendLimit); ok {
		t.Error("a rate limit has the window spend_limit")
	}
}

// TestAnOpenAIQuotaIsTheSpendLimit pins an API key's quota 429 and stream event (from
// source): the code insufficient_quota rejects the window spend_limit alone.
func TestAnOpenAIQuotaIsTheSpendLimit(t *testing.T) {
	g, _ := group(t)
	body := `{"error":{"message":"You exceeded your current quota","type":"insufficient_quota","param":null,"code":"insufficient_quota"}}`
	kind, code := modelkey.ErrorOf([]byte(body))
	if kind != "insufficient_quota" || code != modelkey.QuotaCode {
		t.Errorf("ErrorOf: %q, %q; want insufficient_quota twice", kind, code)
	}
	g.Refused("model", headers(), code)
	g.Streamed("model-2", headers(), code)
	for _, name := range []string{"model", "model-2"} {
		w, ok := window(g, name, modelkey.WindowSpendLimit)
		if !ok || w.Status != modelkey.StatusRejected || !w.CooldownUntil.Equal(start.Add(5*time.Hour)) || w.Source != modelkey.SourcePauseFor {
			t.Errorf("%s spend_limit: %+v (found %v); want rejected for pause_for_s", name, w, ok)
		}
		if _, ok := window(g, name, modelkey.WindowKey); ok {
			t.Errorf("%s: a quota has the window key too", name)
		}
	}
}

// TestErrorOfLeavesOutACodeOfNoString pins a code that is no string, such as a number:
// the type is kept and the code left out. A details.error_code comes before error.code.
func TestErrorOfLeavesOutACodeOfNoString(t *testing.T) {
	if kind, code := modelkey.ErrorOf([]byte(`{"error":{"type":"rate_limit_error","code":429}}`)); kind != modelkey.RateLimitError || code != "" {
		t.Errorf("ErrorOf with a number: %q, %q", kind, code)
	}
	if _, code := modelkey.ErrorOf([]byte(`{"error":{"code":"insufficient_quota","details":{"error_code":"enforced_spend_limit_reached"}}}`)); code != modelkey.SpendLimitCode {
		t.Errorf("ErrorOf with both codes: %q; want the details' code", code)
	}
}

// TestTheStreamPathAndTheResendByFormat pins the path whose stream the proxy reads, and
// the formats whose requests the proxy sends again with another key.
func TestTheStreamPathAndTheResendByFormat(t *testing.T) {
	cases := []struct {
		format, endpoint, path string
		resends                bool
	}{
		{modelkey.FormatAnthropicMessages, "https://api.model.example/anthropic/", "/anthropic/v1/messages", true},
		{modelkey.FormatOpenAIResponses, "https://chatgpt.example/backend-api/codex", "/backend-api/codex/responses", false},
		{modelkey.FormatOpenAIResponses, "https://api.model.example/v1", "/v1/responses", false},
		{"openai-chat", "https://api.model.example/v1", "", true},
		{"gemini", "https://api.model.example", "", true},
	}
	for _, c := range cases {
		if got := modelkey.StreamPath(c.format, c.endpoint); got != c.path {
			t.Errorf("StreamPath(%s, %s) %q; want %q", c.format, c.endpoint, got, c.path)
		}
		if got := modelkey.Resends(c.format); got != c.resends {
			t.Errorf("Resends(%s) %v; want %v", c.format, got, c.resends)
		}
	}
}

// TestStreamLimitReadsEachFormatsEvent pins the limit event of a stream (the
// openai-responses events from source): for openai-responses, data of the type
// response.failed whose response's error has a limit code, with the event field
// response.failed or none; for anthropic-messages, an error event of the type
// rate_limit_error, as before. Any other event, code or format is no limit event.
func TestStreamLimitReadsEachFormatsEvent(t *testing.T) {
	failed := func(code string) string {
		return `{"type":"response.failed","sequence_number":3,"response":{"id":"resp_1","status":"failed","error":{"code":"` + code + `","message":"m"}}}`
	}
	anthropic := `{"type":"error","error":{"type":"rate_limit_error"}}`
	cases := []struct {
		format, event, data string
		code                string
		ok                  bool
	}{
		{modelkey.FormatOpenAIResponses, "response.failed", failed("rate_limit_exceeded"), "rate_limit_exceeded", true},
		{modelkey.FormatOpenAIResponses, "", failed("rate_limit_exceeded"), "rate_limit_exceeded", true},
		{modelkey.FormatOpenAIResponses, "response.failed", failed("insufficient_quota"), modelkey.QuotaCode, true},
		{modelkey.FormatOpenAIResponses, "response.failed", failed("server_is_overloaded"), "", false},
		{modelkey.FormatOpenAIResponses, "response.failed", failed("context_length_exceeded"), "", false},
		{modelkey.FormatOpenAIResponses, "response.output_text.delta", failed("rate_limit_exceeded"), "", false},
		{modelkey.FormatOpenAIResponses, "", `{"type":"response.output_text.delta","delta":"rate_limit_exceeded"}`, "", false},
		{modelkey.FormatOpenAIResponses, "", `{"type":"response.failed","response":{"error":null}}`, "", false},
		{modelkey.FormatOpenAIResponses, "error", anthropic, "", false},
		{modelkey.FormatAnthropicMessages, "error", anthropic, "", true},
		{modelkey.FormatAnthropicMessages, "", anthropic, "", false},
		{modelkey.FormatAnthropicMessages, "response.failed", failed("rate_limit_exceeded"), "", false},
		{"openai-chat", "", failed("rate_limit_exceeded"), "", false},
	}
	for i, c := range cases {
		_, code, ok := modelkey.StreamLimit(c.format, c.event, []byte(c.data))
		if code != c.code || ok != c.ok {
			t.Errorf("case %d (%s, %q): %q, %v; want %q, %v", i, c.format, c.event, code, ok, c.code, c.ok)
		}
	}
}

// TestShownHasTheErrorCode pins the log line of a limit answer with an error code: the
// code after the type.
func TestShownHasTheErrorCode(t *testing.T) {
	line := modelkey.Shown("model", 429, headers("x-ratelimit-remaining-tokens", "0"), "tokens", "rate_limit_exceeded")
	if want := "model key model: limit answer, status 429, error type tokens, error code rate_limit_exceeded, headers x-ratelimit-remaining-tokens"; line != want {
		t.Errorf("Shown:\n%s\nwant\n%s", line, want)
	}
}
