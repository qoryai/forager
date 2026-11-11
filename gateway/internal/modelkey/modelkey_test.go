package modelkey_test

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/modelkey"
)

// start is the fake clock's time when a test begins.
var start = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

// clock is a fake clock a test moves.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

// group is a group of three keys, model, model-2 and model-3, with pause_for_s of 5
// hours, on a fake clock at start.
func group(t *testing.T) (*modelkey.Group, *clock) {
	t.Helper()
	c := &clock{now: start}
	keys := []modelkey.Key{{Name: "model", PauseFor: 5 * time.Hour}, {Name: "model-2", PauseFor: 5 * time.Hour}, {Name: "model-3", PauseFor: 5 * time.Hour}}
	return modelkey.New(keys, "model", c.Now), c
}

// headers is a header of the pairs given.
func headers(pairs ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Set(pairs[i], pairs[i+1])
	}
	return h
}

// epoch is t in seconds since 1970, as the subscription's headers have it.
func epoch(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

// window is the window w of key name in g, and whether g has it.
func window(g *modelkey.Group, name, w string) (modelkey.Window, bool) {
	for _, have := range g.Windows() {
		if have.Credential == name && have.Window == w {
			return have, true
		}
	}
	return modelkey.Window{}, false
}

// TestTheSubscriptionHeadersGiveEachWindow pins the reading of the
// anthropic-ratelimit-unified-* headers of an answer that is no limit refusal: 5h, 7d
// and overage, the representative claim as its window, the fraction as whole percent
// rounded down, and the reset in epoch seconds.
func TestTheSubscriptionHeadersGiveEachWindow(t *testing.T) {
	g, _ := group(t)
	reset5, reset7 := start.Add(2*time.Hour), start.Add(72*time.Hour)
	g.Answered("model", http.StatusOK, headers(
		"Anthropic-Ratelimit-Unified-5h-Status", "allowed_warning",
		"Anthropic-Ratelimit-Unified-5h-Reset", epoch(reset5),
		"Anthropic-Ratelimit-Unified-5h-Utilization", "0.29",
		"Anthropic-Ratelimit-Unified-7d-Status", "allowed",
		"Anthropic-Ratelimit-Unified-7d-Reset", epoch(reset7),
		"Anthropic-Ratelimit-Unified-7d-Utilization", "0.5",
		"Anthropic-Ratelimit-Unified-Overage-Status", "allowed",
		"Anthropic-Ratelimit-Unified-Status", "allowed",
		"Anthropic-Ratelimit-Unified-Reset", epoch(reset7),
		"Anthropic-Ratelimit-Unified-Representative-Claim", "seven_day_opus",
	))
	cases := []struct {
		window, status string
		reset          time.Time
		util           int
		has            bool
	}{
		{"five_hour", modelkey.StatusAllowedWarning, reset5, 29, true},
		{"seven_day", modelkey.StatusAllowed, reset7, 50, true},
		{"overage", modelkey.StatusAllowed, time.Time{}, 0, false},
		{"seven_day_opus", modelkey.StatusAllowed, reset7, 0, false},
	}
	for _, c := range cases {
		w, ok := window(g, "model", c.window)
		if !ok || w.Status != c.status || !w.ResetsAt.Equal(c.reset) || w.Utilization != c.util || w.HasUtilization != c.has ||
			!w.CooldownUntil.IsZero() || w.Source != modelkey.SourceProvider || !w.ObservedAt.Equal(start) {
			t.Errorf("window %s: %+v (found %v); want status %s, reset %v, utilization %d", c.window, w, ok, c.status, c.reset, c.util)
		}
	}
	if len(g.Windows()) != 4 {
		t.Errorf("windows %+v; want 4", g.Windows())
	}
	if g.Active() != "model" {
		t.Errorf("active %s after an answer that is no refusal; want model", g.Active())
	}
}

// TestTheAPIHeadersGiveEachFamily pins the API key's four header families: the
// utilization is 100 x (1 - remaining / limit), rounded down, and the reset RFC 3339.
func TestTheAPIHeadersGiveEachFamily(t *testing.T) {
	g, _ := group(t)
	reset := start.Add(40 * time.Second)
	g.Answered("model-2", http.StatusOK, headers(
		"anthropic-ratelimit-requests-limit", "50",
		"anthropic-ratelimit-requests-remaining", "49",
		"anthropic-ratelimit-requests-reset", reset.Format(time.RFC3339),
		"anthropic-ratelimit-tokens-limit", "1000",
		"anthropic-ratelimit-tokens-remaining", "1000",
		"anthropic-ratelimit-input-tokens-limit", "3",
		"anthropic-ratelimit-input-tokens-remaining", "1",
		"anthropic-ratelimit-output-tokens-remaining", "7",
	))
	cases := []struct {
		window string
		util   int
		has    bool
		reset  time.Time
	}{
		{"requests", 2, true, reset},
		{"tokens", 0, true, time.Time{}},
		{"input_tokens", 66, true, time.Time{}},
		{"output_tokens", 0, false, time.Time{}},
	}
	for _, c := range cases {
		w, ok := window(g, "model-2", c.window)
		if !ok || w.Status != modelkey.StatusAllowed || w.Utilization != c.util || w.HasUtilization != c.has || !w.ResetsAt.Equal(c.reset) {
			t.Errorf("window %s: %+v (found %v); want allowed, utilization %d, reset %v", c.window, w, ok, c.util, c.reset)
		}
	}
}

// TestASubscriptionRefusalCoolsTheKeyUntilItsLatestRejectedReset pins step 1 for a
// subscription: the cooldown ends at the latest reset of the windows the refusal marks
// rejected, a window it allows is no cooldown, and the next key becomes active.
func TestASubscriptionRefusalCoolsTheKeyUntilItsLatestRejectedReset(t *testing.T) {
	g, _ := group(t)
	reset5, reset7 := start.Add(2*time.Hour), start.Add(30*time.Hour)
	next, ok := g.Refused("model", headers(
		"anthropic-ratelimit-unified-5h-status", "rejected",
		"anthropic-ratelimit-unified-5h-reset", epoch(reset5),
		"anthropic-ratelimit-unified-7d-status", "rejected",
		"anthropic-ratelimit-unified-7d-reset", epoch(reset7),
		"anthropic-ratelimit-unified-overage-status", "allowed",
		"retry-after", "60",
	), "")
	if next != "model-2" || !ok || g.Active() != "model-2" {
		t.Errorf("Refused: %s, %v, active %s; want model-2 out of cooldown", next, ok, g.Active())
	}
	for _, name := range []string{"five_hour", "seven_day"} {
		w, _ := window(g, "model", name)
		if w.Status != modelkey.StatusRejected || !w.CooldownUntil.Equal(reset7) || w.Source != modelkey.SourceProvider {
			t.Errorf("window %s: %+v; want rejected until %v from the provider", name, w, reset7)
		}
	}
	if w, _ := window(g, "model", "overage"); w.Status != modelkey.StatusAllowed || !w.CooldownUntil.IsZero() {
		t.Errorf("overage: %+v; want allowed with no cooldown", w)
	}
	if _, ok := window(g, "model", modelkey.WindowKey); ok {
		t.Error("a refusal that rejects a window has a key window too")
	}
}

// TestAnAPIRefusalCoolsTheKeyByItsFamiliesOrRetryAfter pins step 1 for an API key: the
// latest reset of the families with 0 remaining, else retry-after seconds after the
// refusal, in the window key.
func TestAnAPIRefusalCoolsTheKeyByItsFamiliesOrRetryAfter(t *testing.T) {
	g, _ := group(t)
	reset := start.Add(50 * time.Second)
	g.Refused("model", headers(
		"anthropic-ratelimit-tokens-limit", "1000",
		"anthropic-ratelimit-tokens-remaining", "0",
		"anthropic-ratelimit-tokens-reset", reset.Format(time.RFC3339),
		"anthropic-ratelimit-requests-limit", "50",
		"anthropic-ratelimit-requests-remaining", "10",
		"retry-after", "20",
	), "")
	if w, _ := window(g, "model", "tokens"); w.Status != modelkey.StatusRejected || !w.CooldownUntil.Equal(reset) || w.Utilization != 100 {
		t.Errorf("tokens: %+v; want rejected until %v at 100", w, reset)
	}
	if w, _ := window(g, "model", "requests"); w.Status != modelkey.StatusAllowed || !w.CooldownUntil.IsZero() {
		t.Errorf("requests: %+v; want allowed", w)
	}
	g.Refused("model-2", headers("retry-after", "20"), "")
	if w, ok := window(g, "model-2", modelkey.WindowKey); !ok || w.Status != modelkey.StatusRejected || !w.CooldownUntil.Equal(start.Add(20*time.Second)) || w.Source != modelkey.SourceProvider {
		t.Errorf("key: %+v (found %v); want rejected for 20 seconds", w, ok)
	}
}

// TestARefusalWithNoResetUsesTheScheduleOrPauseFor pins the cooldown of a refusal with
// no reset: the key's schedule_resets_at, plus 7 days once it has passed, or pause_for_s;
// and a spend cap's window spend_limit.
func TestARefusalWithNoResetUsesTheScheduleOrPauseFor(t *testing.T) {
	c := &clock{now: start}
	schedule := start.Add(-time.Hour)
	g := modelkey.New([]modelkey.Key{{Name: "model", ScheduleResetsAt: schedule, PauseFor: time.Hour}, {Name: "model-2", PauseFor: 90 * time.Second}}, "model", c.Now)
	g.Refused("model", headers(), modelkey.SpendLimitCode)
	w, ok := window(g, "model", modelkey.WindowSpendLimit)
	if !ok || w.Status != modelkey.StatusRejected || !w.CooldownUntil.Equal(schedule.Add(7*24*time.Hour)) || w.Source != modelkey.SourceSchedule {
		t.Errorf("spend_limit: %+v (found %v); want rejected until a week after the schedule", w, ok)
	}
	if _, ok := window(g, "model", modelkey.WindowKey); ok {
		t.Error("a spend cap has the window key too")
	}
	g.Refused("model-2", headers(), "")
	w, _ = window(g, "model-2", modelkey.WindowKey)
	if !w.CooldownUntil.Equal(start.Add(90*time.Second)) || w.Source != modelkey.SourcePauseFor {
		t.Errorf("key: %+v; want rejected for pause_for_s", w)
	}
}

// TestTheNextKeyIsTheNextByTheOrderOutOfCooldown pins step 2: the next key after the
// active one by the order, from the start again, skipping a key in cooldown; when none
// is left, the refused key stays active and Refused reports false.
func TestTheNextKeyIsTheNextByTheOrderOutOfCooldown(t *testing.T) {
	g, c := group(t)
	g.Refused("model-2", headers("retry-after", "60"), "")
	if g.Active() != "model" {
		t.Errorf("active %s after a refusal of a key that is not active; want model", g.Active())
	}
	if next, ok := g.Refused("model", headers("retry-after", "600"), ""); next != "model-3" || !ok {
		t.Errorf("Refused model: %s, %v; want model-3, skipping model-2 in cooldown", next, ok)
	}
	c.now = start.Add(2 * time.Minute)
	if next, ok := g.Refused("model-3", headers("retry-after", "600"), ""); next != "model-2" || !ok {
		t.Errorf("Refused model-3: %s, %v; want model-2, whose cooldown ended", next, ok)
	}
	if next, ok := g.Refused("model-2", headers("retry-after", "600"), ""); next != "model-2" || ok {
		t.Errorf("Refused model-2: %s, %v; want model-2 and false, no key left", next, ok)
	}
	c.now = start.Add(12 * time.Minute)
	if g.Active() != "model-2" {
		t.Errorf("active %s once every cooldown ended; want model-2", g.Active())
	}
}

// TestAStreamErrorCoolsTheKeyAndSwitches pins a rate_limit_error in a stream: the key
// goes into cooldown, with the answer's headers, and the next key becomes active.
func TestAStreamErrorCoolsTheKeyAndSwitches(t *testing.T) {
	g, _ := group(t)
	g.Streamed("model", headers())
	if g.Active() != "model-2" {
		t.Errorf("active %s; want model-2", g.Active())
	}
	if w, _ := window(g, "model", modelkey.WindowKey); w.Status != modelkey.StatusRejected || !w.CooldownUntil.Equal(start.Add(5*time.Hour)) {
		t.Errorf("key: %+v; want rejected for pause_for_s", w)
	}
}

// TestAnAnswerAfterTheCooldownAllowsTheWindowAgain pins a rejected window that an
// answer of the key allows after its cooldown, and a rejected status in an answer that
// is no limit refusal, recorded as allowed_warning with no cooldown.
func TestAnAnswerAfterTheCooldownAllowsTheWindowAgain(t *testing.T) {
	g, c := group(t)
	g.Refused("model", headers("anthropic-ratelimit-unified-5h-status", "rejected", "anthropic-ratelimit-unified-5h-reset", epoch(start.Add(time.Hour))), "")
	c.now = start.Add(2 * time.Hour)
	g.Answered("model", http.StatusOK, headers("anthropic-ratelimit-unified-5h-status", "allowed"))
	if w, _ := window(g, "model", "five_hour"); w.Status != modelkey.StatusAllowed || !w.CooldownUntil.IsZero() {
		t.Errorf("five_hour: %+v; want allowed with no cooldown", w)
	}
	g.Answered("model", http.StatusOK, headers("anthropic-ratelimit-unified-7d-status", "rejected"))
	if w, _ := window(g, "model", "seven_day"); w.Status != modelkey.StatusAllowedWarning || !w.CooldownUntil.IsZero() {
		t.Errorf("seven_day: %+v; want allowed_warning", w)
	}
	if g.Active() != "model-2" {
		t.Errorf("active %s; want model-2, active since the refusal until a refusal of model-2", g.Active())
	}
}

// TestUtilizationClearsAtItsReset pins that a window's utilization is left out once its
// reset has passed.
func TestUtilizationClearsAtItsReset(t *testing.T) {
	g, c := group(t)
	g.Answered("model", http.StatusOK, headers("anthropic-ratelimit-unified-5h-utilization", "0.88", "anthropic-ratelimit-unified-5h-reset", epoch(start.Add(time.Minute))))
	if w, _ := window(g, "model", "five_hour"); !w.HasUtilization || w.Utilization != 88 {
		t.Errorf("before the reset: %+v; want 88", w)
	}
	c.now = start.Add(time.Minute)
	if w, _ := window(g, "model", "five_hour"); w.HasUtilization {
		t.Errorf("at the reset: %+v; want no utilization", w)
	}
}

// TestAChangeCallsOnChangeOnce pins which changes call OnChange: a status, a reset or a
// cooldown, and the utilization by a whole percent; the same state again does not.
func TestAChangeCallsOnChangeOnce(t *testing.T) {
	g, _ := group(t)
	var n atomic.Int32
	g.OnChange(func() { n.Add(1) })
	reset := epoch(start.Add(time.Hour))
	answer := func(util string) {
		g.Answered("model", http.StatusOK, headers("anthropic-ratelimit-unified-5h-status", "allowed", "anthropic-ratelimit-unified-5h-reset", reset, "anthropic-ratelimit-unified-5h-utilization", util))
	}
	steps := []struct {
		util string
		want int32
	}{{"0.880", 1}, {"0.885", 1}, {"0.89", 2}, {"0.89", 2}}
	for _, s := range steps {
		answer(s.util)
		if got := n.Load(); got != s.want {
			t.Errorf("after utilization %s: %d calls; want %d", s.util, got, s.want)
		}
	}
	g.Refused("model", headers("retry-after", "5"), "")
	if n.Load() != 3 {
		t.Errorf("after a refusal: %d calls; want 3", n.Load())
	}
}

// TestMergeTakesNewerEntriesAndTheirCooldowns pins the answer's merge: an entry later
// than the group's state replaces it, an older one does not, an entry of a key outside
// the group is left out, and a cooldown in it bars the key.
func TestMergeTakesNewerEntriesAndTheirCooldowns(t *testing.T) {
	g, _ := group(t)
	g.Answered("model", http.StatusOK, headers("anthropic-ratelimit-unified-5h-status", "allowed"))
	g.Merge([]modelkey.Window{
		{Credential: "model", Window: "five_hour", Status: modelkey.StatusAllowedWarning, Source: modelkey.SourceProvider, ObservedAt: start.Add(-time.Second)},
		{Credential: "model-2", Window: "seven_day", Status: modelkey.StatusRejected, CooldownUntil: start.Add(time.Hour), Source: modelkey.SourceProvider, ObservedAt: start.Add(-time.Minute)},
		{Credential: "other", Window: "seven_day", Status: modelkey.StatusRejected, CooldownUntil: start.Add(time.Hour), Source: modelkey.SourceProvider, ObservedAt: start},
	})
	if w, _ := window(g, "model", "five_hour"); w.Status != modelkey.StatusAllowed {
		t.Errorf("five_hour: %+v; want the newer allowed kept", w)
	}
	if _, ok := window(g, "other", "seven_day"); ok {
		t.Error("an entry of a key outside the group was taken")
	}
	g.Merge([]modelkey.Window{{Credential: "model", Window: "five_hour", Status: modelkey.StatusRejected, CooldownUntil: start.Add(time.Hour), Source: modelkey.SourceProvider, ObservedAt: start.Add(time.Second)}})
	if g.Active() != "model-3" {
		t.Errorf("active %s; want model-3, model and model-2 in cooldown from the answer", g.Active())
	}
}

// TestPassHoldsUntilResume pins the passed refusal the batch's stop reads.
func TestPassHoldsUntilResume(t *testing.T) {
	g, _ := group(t)
	if g.Passed() {
		t.Error("a new group has passed a refusal")
	}
	g.Pass()
	if !g.Passed() {
		t.Error("Passed is false after Pass")
	}
	g.Resume()
	if g.Passed() {
		t.Error("Passed is true after Resume")
	}
	var none *modelkey.Group
	if none.Passed() || none.Has("model") {
		t.Error("a nil group passed a refusal or has a key")
	}
	none.Resume()
}

// TestShownHasNamesAndNoValues pins the log line of a limit answer: the status, the
// error type and the header names, a limit header of no window named apart, and no
// value.
func TestShownHasNamesAndNoValues(t *testing.T) {
	line := modelkey.Shown("model", 429, headers("Anthropic-Ratelimit-Unified-5h-Reset", "1762786800", "Anthropic-Ratelimit-Unified-7d_oi-Status", "rejected", "Retry-After", "31"), modelkey.RateLimitError)
	want := "model key model: limit answer, status 429, error type rate_limit_error, headers anthropic-ratelimit-unified-5h-reset anthropic-ratelimit-unified-7d_oi-status retry-after; no window for anthropic-ratelimit-unified-7d_oi-status"
	if line != want {
		t.Errorf("Shown:\n%s\nwant\n%s", line, want)
	}
	for _, v := range []string{"1762786800", "rejected", "31"} {
		if strings.Contains(line, v) {
			t.Errorf("Shown contains the value %s", v)
		}
	}
}

// TestErrorOfReadsTypeAndCode pins the reading of a provider's error body.
func TestErrorOfReadsTypeAndCode(t *testing.T) {
	kind, code := modelkey.ErrorOf([]byte(`{"type":"error","error":{"type":"rate_limit_error","message":"m","details":{"error_code":"enforced_spend_limit_reached"}}}`))
	if kind != modelkey.RateLimitError || code != modelkey.SpendLimitCode {
		t.Errorf("ErrorOf: %q, %q", kind, code)
	}
	if kind, code := modelkey.ErrorOf([]byte("not json")); kind != "" || code != "" {
		t.Errorf("ErrorOf of no JSON: %q, %q", kind, code)
	}
}

// TestASwitchTakesTheChosenKeyThenNoResetThenTheClosestReset pins the order of a switch
// among the keys out of cooldown: the chosen key first; then the keys with no known
// reset, or one that has passed, by the order; then the closest reset, from the
// answers' windows over the run configuration's resets_at.
func TestASwitchTakesTheChosenKeyThenNoResetThenTheClosestReset(t *testing.T) {
	c := &clock{now: start}
	keys := []modelkey.Key{
		{Name: "model", PauseFor: time.Hour, Chosen: true},
		{Name: "model-2", PauseFor: time.Hour, ResetsAt: start.Add(3 * time.Hour)},
		{Name: "model-3", PauseFor: time.Hour, ResetsAt: start.Add(-time.Hour)},
		{Name: "model-4", PauseFor: time.Hour, ResetsAt: start.Add(time.Hour)},
		{Name: "model-5", PauseFor: time.Hour},
	}
	g := modelkey.New(keys, "model", c.Now)
	// model-5's answer has a reset in 2 hours, before model-2's.
	g.Answered("model-5", http.StatusOK, headers("anthropic-ratelimit-unified-5h-status", "allowed", "anthropic-ratelimit-unified-5h-reset", epoch(start.Add(2*time.Hour))))
	refuse := func(name string) string {
		t.Helper()
		next, ok := g.Refused(name, headers("retry-after", "600"), "")
		if !ok {
			t.Fatalf("Refused %s: no key left", name)
		}
		return next
	}
	for _, step := range []struct{ refused, want string }{
		{"model", "model-3"},   // model-3's reset has passed: no known reset
		{"model-3", "model-4"}, // the closest reset, in 1 hour
		{"model-4", "model-5"}, // in 2 hours, from the answer
		{"model-5", "model-2"}, // in 3 hours
	} {
		if got := refuse(step.refused); got != step.want {
			t.Errorf("after %s: %s; want %s", step.refused, got, step.want)
		}
	}
	c.now = start.Add(11 * time.Minute)
	if got := refuse("model-2"); got != "model" {
		t.Errorf("after model-2, once model's cooldown ended: %s; want model, the chosen key", got)
	}
}

// TestResetsInOneMinuteGoByTheOrder pins a tie: two resets in the same minute go by the
// order of the keys, whatever their seconds.
func TestResetsInOneMinuteGoByTheOrder(t *testing.T) {
	c := &clock{now: start}
	g := modelkey.New([]modelkey.Key{
		{Name: "model", PauseFor: time.Hour},
		{Name: "model-2", PauseFor: time.Hour, ResetsAt: start.Add(time.Hour + 40*time.Second)},
		{Name: "model-3", PauseFor: time.Hour, ResetsAt: start.Add(time.Hour + 10*time.Second)},
	}, "model", c.Now)
	if next, ok := g.Refused("model", headers("retry-after", "600"), ""); next != "model-2" || !ok {
		t.Errorf("Refused model: %s, %v; want model-2, first by the order in the same minute", next, ok)
	}
}

// TestAKeyInCooldownAtTheClaimWaitsForItsEnd pins cooldown_until of the run
// configuration: the key is skipped until then, and a chosen key in cooldown comes first
// once its cooldown ends. The group pauses only when every key cools at once.
func TestAKeyInCooldownAtTheClaimWaitsForItsEnd(t *testing.T) {
	c := &clock{now: start}
	g := modelkey.New([]modelkey.Key{
		{Name: "model", PauseFor: time.Hour},
		{Name: "model-2", PauseFor: time.Hour},
		{Name: "model-3", PauseFor: time.Hour, Chosen: true, CooldownUntil: start.Add(30 * time.Minute)},
	}, "model", c.Now)
	if next, ok := g.Refused("model", headers("retry-after", "3600"), ""); next != "model-2" || !ok {
		t.Errorf("Refused model: %s, %v; want model-2, model-3 in cooldown", next, ok)
	}
	if next, ok := g.Refused("model-2", headers("retry-after", "3600"), ""); next != "model-2" || ok {
		t.Errorf("Refused model-2: %s, %v; want no key left while every key cools", next, ok)
	}
	c.now = start.Add(31 * time.Minute)
	if got := g.Active(); got != "model-3" {
		t.Errorf("active %s once model-3's cooldown ended; want model-3", got)
	}
}

// TestAClaimOutsideTheWindowsIsLeftOut pins -representative-claim: a value of the 11
// windows is a window, and any other value is no window and is named in the log of
// limit answers by its header, not its value.
func TestAClaimOutsideTheWindowsIsLeftOut(t *testing.T) {
	g, _ := group(t)
	reset := start.Add(time.Hour)
	g.Answered("model", http.StatusOK, headers("anthropic-ratelimit-unified-representative-claim", "seven_day_sonnet",
		"anthropic-ratelimit-unified-status", "allowed", "anthropic-ratelimit-unified-reset", epoch(reset)))
	if w, ok := window(g, "model", "seven_day_sonnet"); !ok || !w.ResetsAt.Equal(reset) {
		t.Errorf("seven_day_sonnet: %+v, %v", w, ok)
	}
	h := headers("anthropic-ratelimit-unified-representative-claim", "monthly_other",
		"anthropic-ratelimit-unified-status", "allowed", "anthropic-ratelimit-unified-reset", epoch(reset))
	g.Answered("model-2", http.StatusOK, h)
	if ws := g.Windows(); len(ws) != 1 {
		t.Errorf("windows %+v; want seven_day_sonnet alone", ws)
	}
	line := modelkey.Shown("model-2", 429, h, "")
	if !strings.Contains(line, "no window for anthropic-ratelimit-unified-representative-claim") || strings.Contains(line, "monthly_other") {
		t.Errorf("Shown: %s", line)
	}
}

// TestTheStartKeyIsActiveFirst pins a start key that is not first in the order: with the
// credentials model-a and model and the start key model, model is active at the start.
func TestTheStartKeyIsActiveFirst(t *testing.T) {
	c := &clock{now: start}
	g := modelkey.New([]modelkey.Key{{Name: "model-a", PauseFor: time.Hour}, {Name: "model", PauseFor: time.Hour}}, "model", c.Now)
	if got, ok := g.Pick(); got != "model" || !ok {
		t.Errorf("Pick at the start: %s, %v; want model, out of cooldown", got, ok)
	}
	if next, ok := g.Refused("model", headers("retry-after", "600"), ""); next != "model-a" || !ok {
		t.Errorf("Refused model: %s, %v; want model-a", next, ok)
	}
}

// TestResetsAcrossAMinuteBoundaryGoByTheReset pins the edge of the tie rule: resets at
// 13:00:59 and 13:01:01 fall in two minutes, so the earlier one goes first, against the
// order.
func TestResetsAcrossAMinuteBoundaryGoByTheReset(t *testing.T) {
	c := &clock{now: start}
	g := modelkey.New([]modelkey.Key{
		{Name: "model", PauseFor: time.Hour},
		{Name: "model-2", PauseFor: time.Hour, ResetsAt: start.Add(time.Hour + 61*time.Second)},
		{Name: "model-3", PauseFor: time.Hour, ResetsAt: start.Add(time.Hour + 59*time.Second)},
	}, "model", c.Now)
	if next, ok := g.Refused("model", headers("retry-after", "600"), ""); next != "model-3" || !ok {
		t.Errorf("Refused model: %s, %v; want model-3, whose reset is in the minute before model-2's", next, ok)
	}
}

// TestPickIsFalseWhileEveryKeyCools pins the state in which the proxy sets no key.
func TestPickIsFalseWhileEveryKeyCools(t *testing.T) {
	g, c := group(t)
	for _, name := range []string{"model", "model-2", "model-3"} {
		g.Refused(name, headers("retry-after", "600"), "")
	}
	if _, ok := g.Pick(); ok {
		t.Error("Pick while every key cools: true; want false")
	}
	c.now = start.Add(11 * time.Minute)
	if got, ok := g.Pick(); !ok || got != "model-3" {
		t.Errorf("Pick once the cooldowns ended: %s, %v; want model-3, the active key, out of cooldown", got, ok)
	}
}

// TestNonFiniteHeadersAreLeftOut pins NaN and infinities: a utilization, a reset or an
// API family's limit or remaining of no finite number is left out, and a fraction
// outside 0 to 1 is held to it.
func TestNonFiniteHeadersAreLeftOut(t *testing.T) {
	g, _ := group(t)
	g.Answered("model", http.StatusOK, headers(
		"anthropic-ratelimit-unified-5h-status", "allowed",
		"anthropic-ratelimit-unified-5h-utilization", "NaN",
		"anthropic-ratelimit-unified-5h-reset", "NaN",
		"anthropic-ratelimit-unified-7d-status", "allowed",
		"anthropic-ratelimit-unified-7d-utilization", "+Inf",
		"anthropic-ratelimit-unified-7d-reset", "Inf",
		"anthropic-ratelimit-requests-limit", "NaN",
		"anthropic-ratelimit-requests-remaining", "10",
	))
	for _, w := range []string{"five_hour", "seven_day", "requests"} {
		got, ok := window(g, "model", w)
		if !ok || got.HasUtilization || !got.ResetsAt.IsZero() {
			t.Errorf("%s: %+v, %v; want the window with no utilization and no reset", w, got, ok)
		}
	}
	g.Answered("model-2", http.StatusOK, headers(
		"anthropic-ratelimit-unified-5h-status", "allowed", "anthropic-ratelimit-unified-5h-utilization", "1.5",
		"anthropic-ratelimit-unified-7d-status", "allowed", "anthropic-ratelimit-unified-7d-utilization", "-0.2",
	))
	if w, _ := window(g, "model-2", "five_hour"); !w.HasUtilization || w.Utilization != 100 {
		t.Errorf("1.5: %+v; want 100", w)
	}
	if w, _ := window(g, "model-2", "seven_day"); !w.HasUtilization || w.Utilization != 0 {
		t.Errorf("-0.2: %+v; want 0", w)
	}
}

// TestAResetPastThirtyOneDaysIsCapped pins the cap: a reset, an API family's reset and a
// retry-after later than 31 days after the answer count as 31 days after it, so no time
// of a report has a year past 9999.
func TestAResetPastThirtyOneDaysIsCapped(t *testing.T) {
	g, _ := group(t)
	limit := start.Add(31 * 24 * time.Hour)
	g.Answered("model", http.StatusOK, headers(
		"anthropic-ratelimit-unified-5h-status", "allowed", "anthropic-ratelimit-unified-5h-reset", strconv.FormatInt(1<<39, 10),
		"anthropic-ratelimit-tokens-limit", "100", "anthropic-ratelimit-tokens-remaining", "50", "anthropic-ratelimit-tokens-reset", "9999-12-31T23:59:59Z",
	))
	for _, w := range []string{"five_hour", "tokens"} {
		if got, _ := window(g, "model", w); !got.ResetsAt.Equal(limit) {
			t.Errorf("%s resets at %v; want %v", w, got.ResetsAt, limit)
		}
	}
	g.Refused("model-2", headers("retry-after", "999999999999"), "")
	if w, _ := window(g, "model-2", "key"); !w.CooldownUntil.Equal(limit) {
		t.Errorf("the cooldown of a retry-after of 999999999999: %v; want %v", w.CooldownUntil, limit)
	}
}

// TestMergeTakesOnlyTheContractsWindows pins Merge: an entry of a window outside the 11
// of the contract is left out, so it never takes the place a refusal's window key needs,
// and a refusal with no window still cools the key.
func TestMergeTakesOnlyTheContractsWindows(t *testing.T) {
	g, c := group(t)
	var entries []modelkey.Window
	for i := range 11 {
		entries = append(entries, modelkey.Window{Credential: "model", Window: "monthly_" + strconv.Itoa(i), Status: modelkey.StatusAllowed, Source: modelkey.SourceProvider, ObservedAt: c.now})
	}
	g.Merge(entries)
	if ws := g.Windows(); len(ws) != 0 {
		t.Fatalf("windows %+v; want none", ws)
	}
	if next, ok := g.Refused("model", headers(), ""); next != "model-2" || !ok {
		t.Errorf("Refused model: %s, %v; want model-2", next, ok)
	}
	if w, ok := window(g, "model", "key"); !ok || w.Status != modelkey.StatusRejected {
		t.Errorf("key: %+v, %v; want rejected", w, ok)
	}
}

// TestALaterAllowedStateEndsTheClaimsCooldown pins cooldown_until of the run
// configuration: an entry of a report's answer that is not rejected and observed after
// the group was made ends it, an older one does not, and so does an answer of the
// provider to the key.
func TestALaterAllowedStateEndsTheClaimsCooldown(t *testing.T) {
	c := &clock{now: start}
	keys := []modelkey.Key{
		{Name: "model", PauseFor: time.Hour},
		{Name: "model-2", PauseFor: time.Hour, CooldownUntil: start.Add(5 * time.Hour)},
		{Name: "model-3", PauseFor: time.Hour, CooldownUntil: start.Add(5 * time.Hour)},
	}
	g := modelkey.New(keys, "model", c.Now)
	g.Merge([]modelkey.Window{{Credential: "model-2", Window: "five_hour", Status: modelkey.StatusAllowed, Source: modelkey.SourceProvider, ObservedAt: start.Add(-time.Minute)}})
	if _, ok := g.Refused("model", headers("retry-after", "600"), ""); ok {
		t.Fatal("Refused model: a key is left; want none, the older entry ends no cooldown")
	}
	g.Merge([]modelkey.Window{{Credential: "model-2", Window: "five_hour", Status: modelkey.StatusAllowed, Source: modelkey.SourceProvider, ObservedAt: start.Add(time.Minute)}})
	if got, ok := g.Pick(); got != "model-2" || !ok {
		t.Errorf("Pick after a later allowed entry of model-2: %s, %v; want model-2", got, ok)
	}
	g.Answered("model-3", http.StatusOK, headers("anthropic-ratelimit-unified-5h-status", "allowed"))
	if next, ok := g.Refused("model-2", headers("retry-after", "600"), ""); next != "model-3" || !ok {
		t.Errorf("Refused model-2: %s, %v; want model-3, which the provider served", next, ok)
	}
}

// TestOnlyA2xxAnswerEndsTheClaimsCooldown pins cooldown_until of the run
// configuration against the status of an answer: a 401 and a 503 of the provider to
// the key keep it, and a 200 ends it.
func TestOnlyA2xxAnswerEndsTheClaimsCooldown(t *testing.T) {
	c := &clock{now: start}
	keys := []modelkey.Key{
		{Name: "model", PauseFor: time.Hour},
		{Name: "model-2", PauseFor: time.Hour, CooldownUntil: start.Add(5 * time.Hour)},
	}
	g := modelkey.New(keys, "model", c.Now)
	g.Answered("model-2", http.StatusUnauthorized, http.Header{})
	g.Answered("model-2", http.StatusServiceUnavailable, http.Header{})
	if next, ok := g.Refused("model", headers("retry-after", "600"), ""); ok {
		t.Fatalf("Refused model after a 401 and a 503 of model-2: %s is left; want no key", next)
	}
	g.Answered("model-2", http.StatusOK, http.Header{})
	if got, ok := g.Pick(); got != "model-2" || !ok {
		t.Errorf("Pick after a 200 of model-2: %s, %v; want model-2", got, ok)
	}
}

// TestRefusalsAndSwitchesRunConcurrently runs refusals, answers, merges, picks and
// reads of the group at once, for the race detector, and checks that a key is left.
func TestRefusalsAndSwitchesRunConcurrently(t *testing.T) {
	g, _ := group(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for range 200 {
				name := []string{"model", "model-2"}[i%2]
				g.Refused(name, headers("retry-after", "600"), "")
				g.Answered("model-3", http.StatusOK, headers("anthropic-ratelimit-unified-5h-status", "allowed", "anthropic-ratelimit-unified-5h-utilization", "0.5"))
				g.Merge([]modelkey.Window{{Credential: "model-3", Window: "five_hour", Status: modelkey.StatusAllowed, Source: modelkey.SourceProvider, ObservedAt: start}})
				g.Pick()
				g.Windows()
			}
		})
	}
	wg.Wait()
	if got, ok := g.Pick(); got != "model-3" || !ok {
		t.Errorf("Pick: %s, %v; want model-3", got, ok)
	}
}
