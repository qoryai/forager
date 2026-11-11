package modelkey

import (
	"encoding/json"
	"math"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The windows of an answer's headers, model-keys-report.schema.json's window.
const (
	// WindowKey is the window of a limit refusal that names no window.
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

// RateLimitError is the error type of a provider's limit refusal, in a 429's body and
// in a stream's error event.
const RateLimitError = "rate_limit_error"

// unifiedPrefix is the prefix of a subscription's limit headers, apiPrefix of an API
// key's.
const (
	unifiedPrefix = "anthropic-ratelimit-unified-"
	apiPrefix     = "anthropic-ratelimit-"
)

// unifiedWindows are the infixes of the subscription's headers and their windows.
var unifiedWindows = map[string]string{"5h": "five_hour", "7d": "seven_day", "overage": "overage"}

// apiWindows are the header families of an API key and their windows.
var apiWindows = map[string]string{"requests": "requests", "tokens": "tokens", "input-tokens": "input_tokens", "output-tokens": "output_tokens"}

// windowName is the form of a window, the schema's pattern, and of an error's type and
// code.
var windowName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// claimWindows are the values of the subscription's -representative-claim that are a
// window of the report; another value is left out.
var claimWindows = map[string]bool{"five_hour": true, "seven_day": true, "seven_day_opus": true, "seven_day_sonnet": true, "overage": true}

// seen is what one answer's headers contain of one window.
type seen struct {
	window   string
	status   string
	resetsAt time.Time
	// utilization is the use in whole percent; has says the answer contains it.
	utilization int
	has         bool
	// exhausted says an API key's family has 0 remaining.
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
		limit, remaining float64
		hasLimit, hasRem bool
		reset            time.Time
	}
	families := map[string]*family{}
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
				r.overallReset = epoch(value)
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
				if t := epoch(value); !t.IsZero() {
					s.resetsAt = t
				}
			case "utilization":
				if f, err := strconv.ParseFloat(value, 64); err == nil {
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
			f := families[fam]
			if f == nil {
				f = &family{}
				families[fam] = f
				r.window(apiWindows[fam])
			}
			switch field {
			case "limit":
				if v, err := strconv.ParseFloat(value, 64); err == nil {
					f.limit, f.hasLimit = v, true
				}
			case "remaining":
				if v, err := strconv.ParseFloat(value, 64); err == nil {
					f.remaining, f.hasRem = v, true
				}
			case "reset":
				if t, err := time.Parse(time.RFC3339, value); err == nil {
					f.reset = t
				}
			}
		}
	}
	for fam, f := range families {
		s := r.window(apiWindows[fam])
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

// epoch reads a time in seconds since 1970, zero when v has no such form.
func epoch(v string) time.Time {
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 || math.IsInf(f, 0) || f > 1<<40 {
		return time.Time{}
	}
	return time.Unix(int64(f), 0).UTC()
}

// percent is a fraction as whole percent, rounded down, 0 to 100. The small term keeps
// a fraction such as 0.29, whose product with 100 is just below 29, at 29.
func percent(f float64) int {
	p := math.Floor(f*100 + 1e-9)
	return int(min(max(p, 0), 100))
}

// retryAfter reads a Retry-After of seconds or an HTTP date.
func retryAfter(v string, now time.Time) (time.Duration, bool) {
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 && n <= 1<<31 {
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(now), 0), true
	}
	return 0, false
}

// ErrorOf reads the error type and error_code of a provider's error body, such as
// {"type":"error","error":{"type":"rate_limit_error","details":{"error_code":"..."}}};
// empty for a body of another shape. A code of no window's form is left out.
func ErrorOf(body []byte) (kind, code string) {
	var doc struct {
		Error struct {
			Type      string `json:"type"`
			ErrorCode string `json:"error_code"`
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
	if !windowName.MatchString(kind) {
		kind = ""
	}
	if !windowName.MatchString(code) {
		code = ""
	}
	return kind, code
}
