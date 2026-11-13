package modelkey

import (
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/qoryai/forager/policy"
)

// The windows of an answer's headers, model-keys-report.schema.json's window.
const (
	// WindowKey is the window of a limit refusal that has no window.
	WindowKey = "key"
	// WindowSpendLimit is the window of an API key's spend cap: a refusal whose
	// error_code is [SpendLimitCode].
	WindowSpendLimit = "spend_limit"
)

// The statuses of a window, model-keys-report.schema.json's status.
const (
	StatusAllowed        = "allowed"
	StatusAllowedWarning = "allowed_warning"
	StatusRejected       = "rejected"
)

// The sources of a window's cooldown or reset, model-keys-report.schema.json's source.
const (
	SourceProvider = "provider"
	SourceSchedule = "schedule"
	SourcePauseFor = "pause_for"
)

// SpendLimitCode is the error_code of an API key's refusal at its spend cap.
const SpendLimitCode = "enforced_spend_limit_reached"

// QuotaCode is the error code of an OpenAI key's refusal at its quota, in a 429's body
// and in a stream's response.failed event: its window is spend_limit, as for
// [SpendLimitCode].
const QuotaCode = "insufficient_quota"

// rateLimitCode is the error code of an OpenAI rate limit in a stream's
// response.failed event.
const rateLimitCode = "rate_limit_exceeded"

// The API formats whose answers the gateway reads apart, api-format.schema.json.
const (
	FormatAnthropicMessages = "anthropic-messages"
	FormatOpenAIResponses   = "openai-responses"
)

// RateLimitError is the error type of a provider's limit refusal, in a 429's body and
// in a stream's error event.
const RateLimitError = "rate_limit_error"

// unifiedPrefix is the prefix of a subscription's limit headers, apiPrefix of an API
// key's. codexPrefix is the prefix of a ChatGPT subscription's two windows, primary and
// secondary, and codexReached the header that marks a refusal at a window's limit;
// openaiPrefix is the prefix of an OpenAI API key's limit headers.
const (
	unifiedPrefix = "anthropic-ratelimit-unified-"
	apiPrefix     = "anthropic-ratelimit-"
	codexPrefix   = "x-codex-"
	codexReached  = "x-codex-rate-limit-reached-type"
	openaiPrefix  = "x-ratelimit-"
)

// unifiedWindows are the infixes of the subscription's headers and their windows.
var unifiedWindows = map[string]string{"5h": "five_hour", "7d": "seven_day", "overage": "overage"}

// apiWindows are the header families of an API key and their windows.
var apiWindows = map[string]string{"requests": "requests", "tokens": "tokens", "input-tokens": "input_tokens", "output-tokens": "output_tokens"}

// codexSlots are the two windows of a ChatGPT subscription's x-codex-* headers, in the
// order the gateway reads them.
var codexSlots = []string{"primary", "secondary"}

// codexWindows are the -window-minutes of a subscription's x-codex-* window and their
// windows. A window of 0 minutes is none; any other value is a window the gateway does
// not read.
var codexWindows = map[int64]string{300: "five_hour", 10080: "seven_day"}

// openaiWindows are the header families of an OpenAI API key and their windows.
var openaiWindows = map[string]string{"requests": "requests", "tokens": "tokens"}

// windowName is the form of a window, the schema's pattern, and of an error's type and
// code.
var windowName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// claimWindows are the values of the subscription's -representative-claim that are a
// window of the report; another value is left out.
var claimWindows = map[string]bool{"five_hour": true, "seven_day": true, "seven_day_opus": true, "seven_day_sonnet": true, "overage": true}

// knownWindows are the 11 windows of the contract, model-keys-report.schema.json's
// window: the group keeps no other.
var knownWindows = map[string]bool{
	"five_hour": true, "seven_day": true, "seven_day_opus": true, "seven_day_sonnet": true, "overage": true,
	"requests": true, "tokens": true, "input_tokens": true, "output_tokens": true, WindowSpendLimit: true, WindowKey: true,
}

// maxReset is the furthest after an answer's arrival that the gateway takes a reset or a
// retry-after of the provider's: a later one counts as this far, so every time a report
// has is a year of four digits.
const maxReset = 31 * 24 * time.Hour

// seen is what one answer's headers contain of one window.
type seen struct {
	window   string
	status   string
	resetsAt time.Time
	// utilization is the use in whole percent; has is true when the answer contains it.
	utilization int
	has         bool
	// exhausted is true when an API key's family has 0 remaining.
	exhausted bool
	// cooldown and source are a limit refusal's, set on each window it rejects.
	cooldown time.Time
	source   string
}

// read is what one answer's headers contain: the windows in the order of their first
// header, a retry-after, and the names of limit headers of no window the gateway reads.
type read struct {
	windows    []*seen
	retryAfter time.Duration
	hasRetry   bool
	// overall is the subscription's -status and -reset with no infix, which counts for a
	// cooldown when the answer has no -representative-claim.
	overallStatus string
	overallReset  time.Time
	unknown       []string
}

// window is the entry of w in r, added when there is none.
func (r *read) window(w string) *seen {
	for _, s := range r.windows {
		if s.window == w {
			return s
		}
	}
	s := &seen{window: w}
	r.windows = append(r.windows, s)
	return s
}

// readHeaders reads the limit headers of an answer that arrived at now, in the order
// of their names. A header whose value has no form is left out.
func readHeaders(h http.Header, now time.Time) read {
	var r read
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, strings.ToLower(name))
	}
	slices.Sort(names)
	get := func(lower string) string { return strings.TrimSpace(h.Get(lower)) }
	claim := ""
	if c := get(unifiedPrefix + "representative-claim"); claimWindows[c] {
		claim = c
	} else if c != "" {
		r.unknown = append(r.unknown, unifiedPrefix+"representative-claim")
	}
	type family struct {
		window           string
		limit, remaining float64
		hasLimit, hasRem bool
		reset            time.Time
	}
	// families are an API key's header families, by their prefix and name.
	families := map[string]*family{}
	familyOf := func(key, window string) *family {
		f := families[key]
		if f == nil {
			f = &family{window: window}
			families[key] = f
			r.window(window)
		}
		return f
	}
	// slot is one window of a ChatGPT subscription's x-codex-* headers.
	type slot struct {
		minutes           float64
		used, after       float64
		hasMinutes        bool
		hasUsed, hasAfter bool
		resetAt           time.Time
	}
	slots := map[string]*slot{}
	for _, name := range names {
		value := get(name)
		switch {
		case name == "retry-after":
			if d, ok := retryAfter(value, now); ok {
				r.retryAfter, r.hasRetry = d, true
			}
		case strings.HasPrefix(name, unifiedPrefix):
			rest := strings.TrimPrefix(name, unifiedPrefix)
			switch rest {
			case "status":
				r.overallStatus = status(value)
				if claim != "" && r.overallStatus != "" {
					r.window(claim).status = r.overallStatus
				}
				continue
			case "reset":
				r.overallReset = capped(epoch(value), now, maxReset)
				if claim != "" && !r.overallReset.IsZero() {
					r.window(claim).resetsAt = r.overallReset
				}
				continue
			case "representative-claim":
				continue
			}
			infix, field, _ := strings.Cut(rest, "-")
			w, ok := unifiedWindows[infix]
			if !ok {
				r.unknown = append(r.unknown, name)
				continue
			}
			s := r.window(w)
			switch field {
			case "status":
				if v := status(value); v != "" {
					s.status = v
				}
			case "reset":
				if t := capped(epoch(value), now, maxReset); !t.IsZero() {
					s.resetsAt = t
				}
			case "utilization":
				if f, ok := finite(value); ok {
					s.utilization, s.has = percent(f), true
				}
			}
		case strings.HasPrefix(name, apiPrefix):
			rest := strings.TrimPrefix(name, apiPrefix)
			cut := strings.LastIndex(rest, "-")
			if cut < 0 {
				r.unknown = append(r.unknown, name)
				continue
			}
			fam, field := rest[:cut], rest[cut+1:]
			if _, ok := apiWindows[fam]; !ok {
				r.unknown = append(r.unknown, name)
				continue
			}
			f := familyOf(apiPrefix+fam, apiWindows[fam])
			switch field {
			case "limit":
				if v, ok := finite(value); ok {
					f.limit, f.hasLimit = v, true
				}
			case "remaining":
				if v, ok := finite(value); ok {
					f.remaining, f.hasRem = v, true
				}
			case "reset":
				if t, err := time.Parse(time.RFC3339, value); err == nil {
					f.reset = capped(t, now, maxReset)
				}
			}
		case strings.HasPrefix(name, openaiPrefix):
			// x-ratelimit-{limit,remaining,reset}-{requests,tokens}, the field first.
			field, fam, _ := strings.Cut(strings.TrimPrefix(name, openaiPrefix), "-")
			w, ok := openaiWindows[fam]
			if !ok || (field != "limit" && field != "remaining" && field != "reset") {
				r.unknown = append(r.unknown, name)
				continue
			}
			f := familyOf(openaiPrefix+fam, w)
			switch field {
			case "limit":
				if v, ok := finite(value); ok {
					f.limit, f.hasLimit = v, true
				}
			case "remaining":
				if v, ok := finite(value); ok {
					f.remaining, f.hasRem = v, true
				}
			case "reset":
				// A duration, such as 6m0s or 20ms.
				if d, err := time.ParseDuration(value); err == nil && d >= 0 {
					f.reset = now.Add(min(d, maxReset))
				}
			}
		case strings.HasPrefix(name, codexPrefix):
			rest := strings.TrimPrefix(name, codexPrefix)
			at, field, _ := strings.Cut(rest, "-")
			if !slices.Contains(codexSlots, at) {
				continue
			}
			sl := slots[at]
			if sl == nil {
				sl = &slot{}
				slots[at] = sl
			}
			// Another field, such as -over-secondary-limit-percent, has no window.
			switch field {
			case "window-minutes":
				sl.minutes, sl.hasMinutes = finite(value)
			case "used-percent":
				sl.used, sl.hasUsed = finite(value)
			case "reset-at":
				sl.resetAt = capped(epoch(value), now, maxReset)
			case "reset-after-seconds":
				if v, ok := finite(value); ok && v >= 0 {
					sl.after, sl.hasAfter = v, true
				}
			}
		}
	}
	reached := get(codexReached) != ""
	for _, at := range codexSlots {
		sl := slots[at]
		if sl == nil {
			continue
		}
		w, ok := "", false
		if sl.hasMinutes && sl.minutes == math.Trunc(sl.minutes) {
			w, ok = codexWindows[int64(sl.minutes)]
		}
		if !ok {
			if !sl.hasMinutes || sl.minutes != 0 {
				r.unknown = append(r.unknown, codexPrefix+at+"-window-minutes")
			}
			continue
		}
		s := r.window(w)
		if sl.hasUsed {
			s.utilization, s.has = percent(sl.used/100), true
		}
		switch {
		case !sl.resetAt.IsZero():
			s.resetsAt = sl.resetAt
		case sl.hasAfter:
			s.resetsAt = now.Add(time.Duration(min(sl.after, maxReset.Seconds()) * float64(time.Second)))
		}
		// The header has no window in it: it marks the windows the answer shows at
		// their limit.
		if reached && sl.hasUsed && sl.used >= 100 {
			s.status = StatusRejected
		}
	}
	for _, f := range families {
		s := r.window(f.window)
		s.resetsAt = f.reset
		s.exhausted = f.hasRem && f.remaining <= 0
		if f.hasLimit && f.hasRem && f.limit > 0 {
			s.utilization, s.has = percent(1-f.remaining/f.limit), true
		}
	}
	return r
}

// status is v when it is one of the three statuses, else empty.
func status(v string) string {
	switch v {
	case StatusAllowed, StatusAllowedWarning, StatusRejected:
		return v
	}
	return ""
}

// finite reads a decimal number, and reports false for one of no such form, NaN or an
// infinity.
func finite(v string) (float64, bool) {
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// epoch reads a time in seconds since 1970, zero when v has no such form.
func epoch(v string) time.Time {
	f, ok := finite(v)
	if !ok || f <= 0 || f > 1<<40 {
		return time.Time{}
	}
	return time.Unix(int64(f), 0).UTC()
}

// capped is t, or now plus most when t is later; the zero time stays zero.
func capped(t, now time.Time, most time.Duration) time.Time {
	if limit := now.Add(most); t.After(limit) {
		return limit
	}
	return t
}

// percent is a fraction, held to 0 to 1, as whole percent, rounded down. The small term
// keeps a fraction such as 0.29, whose product with 100 is just below 29, at 29.
func percent(f float64) int {
	f = min(max(f, 0), 1)
	return int(min(math.Floor(f*100+1e-9), 100))
}

// retryAfter reads a Retry-After of seconds or an HTTP date, at most [maxReset].
func retryAfter(v string, now time.Time) (time.Duration, bool) {
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
		return time.Duration(min(n, int64(maxReset/time.Second))) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return min(max(t.Sub(now), 0), maxReset), true
	}
	return 0, false
}

// ErrorOf reads the error type and code of a provider's error body: Anthropic's
// {"type":"error","error":{"type":"rate_limit_error","details":{"error_code":"..."}}},
// its error_code in details or in error, and else OpenAI's
// {"error":{"type":"insufficient_quota","code":"insufficient_quota"}}, its code in
// error. Empty for a body of another shape. A type or code of no window's form is left
// out, and so is a code that is no string.
func ErrorOf(body []byte) (kind, code string) {
	var doc struct {
		Error struct {
			Type      string          `json:"type"`
			ErrorCode string          `json:"error_code"`
			Code      json.RawMessage `json:"code"`
			Details   struct {
				ErrorCode string `json:"error_code"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return "", ""
	}
	kind, code = doc.Error.Type, doc.Error.Details.ErrorCode
	if code == "" {
		code = doc.Error.ErrorCode
	}
	if code == "" && len(doc.Error.Code) > 0 && json.Unmarshal(doc.Error.Code, &code) != nil {
		code = ""
	}
	if !windowName.MatchString(kind) {
		kind = ""
	}
	if !windowName.MatchString(code) {
		code = ""
	}
	return kind, code
}

// Resends reports whether the proxy sends a request of the format again with another
// key after a limit refusal: false for openai-responses, whose runtime sends reasoning
// encrypted for one account, so a session keeps one key; true for any other format.
func Resends(format string) bool { return format != FormatOpenAIResponses }

// StreamPath is the clean path of the request of a model API of the format at endpoint
// whose streamed answers the proxy reads for a limit event: for anthropic-messages, the
// endpoint's path, then /v1/messages, such as /anthropic/v1/messages for
// https://api.deepseek.com/anthropic; for openai-responses, the endpoint's path, then
// /responses, such as /backend-api/codex/responses for
// https://chatgpt.com/backend-api/codex. Empty for another format, whose stream the
// proxy does not read, and for an endpoint that does not parse.
func StreamPath(format, endpoint string) string {
	var tail string
	switch format {
	case FormatAnthropicMessages:
		tail = "/v1/messages"
	case FormatOpenAIResponses:
		tail = "/responses"
	default:
		return ""
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	clean, ok := policy.CleanPath(strings.TrimSuffix(u.EscapedPath(), "/") + tail)
	if !ok {
		return ""
	}
	return clean
}

// StreamLimit reports whether one event of a streamed answer of a model API of the
// format, its event field and its data, is a limit refusal, and returns the error type
// and code the gateway reads of it:
//   - anthropic-messages: an event whose event field is error and whose data is an error
//     of the type rate_limit_error; the code is empty, so the refusal rejects the
//     window key, as before openai-responses had a stream check.
//   - openai-responses: an event whose data has the type response.failed, with an event
//     field of response.failed or none, and whose response's error has the code
//     rate_limit_exceeded or insufficient_quota; the type is empty.
func StreamLimit(format, event string, data []byte) (kind, code string, ok bool) {
	switch format {
	case FormatAnthropicMessages:
		if kind, _ := ErrorOf(data); event == "error" && kind == RateLimitError {
			return kind, "", true
		}
	case FormatOpenAIResponses:
		if event != "" && event != "response.failed" {
			return "", "", false
		}
		var doc struct {
			Type     string `json:"type"`
			Response struct {
				Error struct {
					Code json.RawMessage `json:"code"`
				} `json:"error"`
			} `json:"response"`
		}
		if json.Unmarshal(data, &doc) != nil || doc.Type != "response.failed" || json.Unmarshal(doc.Response.Error.Code, &code) != nil {
			return "", "", false
		}
		if code == rateLimitCode || code == QuotaCode {
			return "", code, true
		}
	}
	return "", "", false
}
