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

// openaiGroup is [group] with keys of the format openai-responses.
func openaiGroup(t *testing.T) (*modelkey.Group, *clock) {
	t.Helper()
	g, c := group(t)
	g.SetFormat(modelkey.FormatOpenAIResponses)
	return g, c
}

// TestTheCodexHeadersGiveEachWindow pins the reading of a ChatGPT subscription's 200:
// window-minutes 300 is five_hour and 10080 is seven_day, used-percent is the
// utilization, the reset is reset-at, else the answer's time plus reset-after-seconds,
// and the other x-codex-* headers are no window.
func TestTheCodexHeadersGiveEachWindow(t *testing.T) {
	g, _ := openaiGroup(t)
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
	g, _ := openaiGroup(t)
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
	line := g.Shown("model", 429, h, "", "")
	if !strings.HasSuffix(line, "; no window for x-codex-primary-window-minutes") || strings.Contains(line, "1440") {
		t.Errorf("Shown: %s", line)
	}
}

// TestACodexRefusalRejectsTheWindowAtItsLimit pins a subscription's 429 (from source):
// x-codex-rate-limit-reached-type has no window in it, so it marks rejected the windows
// the answer shows at 100 percent or more; the key cools until the latest reset among
// them, and stays active until the next join. The body's type is read for the log, and
// the body has no code.
func TestACodexRefusalRejectsTheWindowAtItsLimit(t *testing.T) {
	g, _ := openaiGroup(t)
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
	if next != "model" || ok {
		t.Errorf("Refused: %s, %v; want model, in cooldown", next, ok)
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

// TestACodexWindowAtItsLimitIsRejectedOnARefusal pins the windows a subscription's
// 429 rejects: a window at 100 percent or more, with x-codex-rate-limit-reached-type or
// without it; with none at 100 percent, the key window cools for pause_for_s. A 200 at
// 100 percent rejects nothing.
func TestACodexWindowAtItsLimitIsRejectedOnARefusal(t *testing.T) {
	g, _ := openaiGroup(t)
	g.Refused("model", headers(
		"x-codex-primary-used-percent", "80",
		"x-codex-primary-window-minutes", "300",
		"x-codex-rate-limit-reached-type", "workspace_member_credits_depleted",
	), "")
	if w, ok := window(g, "model", modelkey.WindowKey); !ok || w.Status != modelkey.StatusRejected || !w.CooldownUntil.Equal(start.Add(5*time.Hour)) || w.Source != modelkey.SourcePauseFor {
		t.Errorf("model key: %+v (found %v); want rejected for pause_for_s", w, ok)
	}
	if w, _ := window(g, "model", "five_hour"); w.Status != modelkey.StatusAllowed {
		t.Errorf("model five_hour: %+v; want allowed", w)
	}
	reset := start.Add(3 * time.Hour)
	g.Refused("model-2", headers(
		"x-codex-primary-used-percent", "100",
		"x-codex-primary-window-minutes", "300",
		"x-codex-primary-reset-at", epoch(reset),
	), "")
	if w, _ := window(g, "model-2", "five_hour"); w.Status != modelkey.StatusRejected || !w.CooldownUntil.Equal(reset) || w.Source != modelkey.SourceProvider {
		t.Errorf("model-2 five_hour: %+v; want rejected until %v", w, reset)
	}
	if _, ok := window(g, "model-2", modelkey.WindowKey); ok {
		t.Error("model-2 has the key window too")
	}
	g.Answered("model-3", http.StatusOK, headers(
		"x-codex-primary-used-percent", "100",
		"x-codex-primary-window-minutes", "300",
		"x-codex-primary-reset-at", epoch(reset),
	))
	if w, _ := window(g, "model-3", "five_hour"); w.Status != modelkey.StatusAllowed || !w.CooldownUntil.IsZero() {
		t.Errorf("model-3 five_hour after a 200: %+v; want allowed", w)
	}
}

// TestACodexResetAtThatHasPassedUsesResetAfterSeconds pins a reset-at that is not after
// the answer: the reset is the answer's time plus reset-after-seconds.
func TestACodexResetAtThatHasPassedUsesResetAfterSeconds(t *testing.T) {
	g, _ := openaiGroup(t)
	g.Answered("model", http.StatusOK, headers(
		"x-codex-primary-used-percent", "5",
		"x-codex-primary-window-minutes", "300",
		"x-codex-primary-reset-at", epoch(start.Add(-time.Minute)),
		"x-codex-primary-reset-after-seconds", "120",
	))
	if w, _ := window(g, "model", "five_hour"); !w.ResetsAt.Equal(start.Add(2 * time.Minute)) {
		t.Errorf("five_hour: %+v; want a reset 2 minutes after the answer", w)
	}
}

// TestTheClaudeFormatReadsNoOpenAIHeaders pins a group of another format: the x-codex-*
// and x-ratelimit-* headers are no window and are not in the log line.
func TestTheClaudeFormatReadsNoOpenAIHeaders(t *testing.T) {
	g, _ := group(t)
	g.SetFormat(modelkey.FormatAnthropicMessages)
	h := headers(
		"x-codex-primary-used-percent", "42",
		"x-codex-primary-window-minutes", "1440",
		"x-ratelimit-limit-requests", "500",
		"x-ratelimit-remaining-requests", "0",
		"x-ratelimit-limit-images", "5",
	)
	g.Answered("model", http.StatusOK, h)
	if ws := g.Windows(); len(ws) != 0 {
		t.Errorf("windows %+v; want none", ws)
	}
	if line := g.Shown("model", 429, h, "", ""); strings.Contains(line, "no window for") {
		t.Errorf("Shown: %s", line)
	}
}

// TestAnOpenAIGroupKeepsItsKeyUntilTheJoin pins the active key of an openai-responses
// group: a cooldown from a report's answer or at use_up_to_percent leaves the key
// active and Pick false, so the proxy sets no other key in the session; JoinKey makes
// the next key active.
func TestAnOpenAIGroupKeepsItsKeyUntilTheJoin(t *testing.T) {
	g, _ := openaiGroup(t)
	g.Merge([]modelkey.Window{{Credential: "model", Window: "five_hour", Status: modelkey.StatusRejected, CooldownUntil: start.Add(time.Hour), Source: modelkey.SourceProvider, ObservedAt: start}})
	if name, ok := g.Pick(); name != "model" || ok {
		t.Errorf("Pick after a merged cooldown: %s, %v; want model and false", name, ok)
	}
	if got := g.JoinKey(); got != "model-2" {
		t.Errorf("JoinKey %s; want model-2", got)
	}
	if name, ok := g.Pick(); name != "model-2" || !ok {
		t.Errorf("Pick after the join: %s, %v; want model-2", name, ok)
	}

	c := &clock{now: start}
	keys := []modelkey.Key{{Name: "model", PauseFor: time.Hour, UseUpToPercent: 90, UseUpToWindows: []string{"five_hour"}}, {Name: "model-2", PauseFor: time.Hour}}
	u := modelkey.New(keys, "model", c.Now)
	u.SetFormat(modelkey.FormatOpenAIResponses)
	u.Answered("model", http.StatusOK, headers(
		"x-codex-primary-used-percent", "95",
		"x-codex-primary-window-minutes", "300",
		"x-codex-primary-reset-at", epoch(start.Add(time.Hour)),
	))
	if name, ok := u.Pick(); name != "model" || ok {
		t.Errorf("Pick at use_up_to_percent: %s, %v; want model and false", name, ok)
	}
	if got := u.JoinKey(); got != "model-2" {
		t.Errorf("JoinKey at use_up_to_percent %s; want model-2", got)
	}
}

// TestTheOpenAIHeadersGiveEachFamily pins an OpenAI API key's 200 (from source):
// x-ratelimit-{limit,remaining,reset}-{requests,tokens} are requests and tokens, the
// utilization is 100 x (1 - remaining / limit), rounded down, and the reset a duration
// after the answer. Another family is in the log line and is no window.
func TestTheOpenAIHeadersGiveEachFamily(t *testing.T) {
	g, _ := openaiGroup(t)
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
	if line := g.Shown("model", 429, h, "", ""); !strings.HasSuffix(line, "; no window for x-ratelimit-limit-images") {
		t.Errorf("Shown: %s", line)
	}
}

// TestAnOpenAIRateRefusalCoolsTheFamilyAtZero pins an API key's rate limit 429 (from
// source): the family with 0 remaining is rejected until its reset, the body's type and
// code are read, and the code is no spend cap.
func TestAnOpenAIRateRefusalCoolsTheFamilyAtZero(t *testing.T) {
	g, _ := openaiGroup(t)
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
	g, _ := openaiGroup(t)
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

// TestEveryQuotaCodeIsTheSpendLimit pins the quota codes Codex reads, and the type
// insufficient_quota with no code, as spend_limit; a rate limit's code is not.
func TestEveryQuotaCodeIsTheSpendLimit(t *testing.T) {
	for _, code := range []string{"insufficient_quota", "credit_balance_exhausted", "organization_spend_limit_exceeded", "project_spend_limit_exceeded", "organization_usage_limit_exceeded", modelkey.SpendLimitCode} {
		if !modelkey.SpendLimit(code) {
			t.Errorf("SpendLimit(%s) false", code)
		}
	}
	for _, code := range []string{"rate_limit_exceeded", "slow_down", ""} {
		if modelkey.SpendLimit(code) {
			t.Errorf("SpendLimit(%q) true", code)
		}
	}
	if _, code := modelkey.ErrorOf([]byte(`{"error":{"type":"insufficient_quota","message":"m"}}`)); code != modelkey.QuotaCode {
		t.Errorf("ErrorOf of the type insufficient_quota with no code: %q", code)
	}
	g, _ := openaiGroup(t)
	g.Refused("model", headers(), "project_spend_limit_exceeded")
	if w, ok := window(g, "model", modelkey.WindowSpendLimit); !ok || w.Status != modelkey.StatusRejected {
		t.Errorf("spend_limit: %+v (found %v); want rejected", w, ok)
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
// The codes are those Codex reads in a stream (codex-api/src/sse/responses_error.rs).
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
		{modelkey.FormatOpenAIResponses, "response.failed", failed("slow_down"), "slow_down", true},
		{modelkey.FormatOpenAIResponses, "response.failed", failed("credit_balance_exhausted"), "credit_balance_exhausted", true},
		{modelkey.FormatOpenAIResponses, "response.failed", failed("organization_spend_limit_exceeded"), "organization_spend_limit_exceeded", true},
		{modelkey.FormatOpenAIResponses, "response.failed", failed("project_spend_limit_exceeded"), "project_spend_limit_exceeded", true},
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
	g, _ := openaiGroup(t)
	line := g.Shown("model", 429, headers("x-ratelimit-remaining-tokens", "0"), "tokens", "rate_limit_exceeded")
	if want := "model key model: limit answer, status 429, error type tokens, error code rate_limit_exceeded, headers x-ratelimit-remaining-tokens"; line != want {
		t.Errorf("Shown:\n%s\nwant\n%s", line, want)
	}
}

// TestAJoinSkipsAKeyThatIsOut pins JoinKey of an openai-responses group whose active
// key cools while the next key by the order is out: Pick reports false and keeps the
// key, and JoinKey makes the first key that is neither out nor in cooldown active. When
// no key is left, JoinKey keeps the active key and Pick stays false.
func TestAJoinSkipsAKeyThatIsOut(t *testing.T) {
	g, _ := openaiGroup(t)
	g.Out("model-2")
	cool := func(name string) {
		g.Merge([]modelkey.Window{{Credential: name, Window: "five_hour", Status: modelkey.StatusRejected, CooldownUntil: start.Add(time.Hour), Source: modelkey.SourceProvider, ObservedAt: start}})
	}
	cool("model")
	if name, ok := g.Pick(); name != "model" || ok {
		t.Errorf("Pick: %s, %v; want model and false", name, ok)
	}
	if got := g.JoinKey(); got != "model-3" {
		t.Errorf("JoinKey %s; want model-3, past model-2, which is out", got)
	}
	if name, ok := g.Pick(); name != "model-3" || !ok {
		t.Errorf("Pick after the join: %s, %v; want model-3", name, ok)
	}
	cool("model-3")
	if got := g.JoinKey(); got != "model-3" {
		t.Errorf("JoinKey with no key left %s; want model-3 kept", got)
	}
	if name, ok := g.Pick(); name != "model-3" || ok {
		t.Errorf("Pick with no key left: %s, %v; want model-3 and false", name, ok)
	}
}
