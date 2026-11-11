// Package modelkey keeps the state of a run's key group: the model keys of one provider
// the run's proxy sets one at a time, the active key, each key's limit windows as the
// provider's answers show them, and each key's cooldown after a limit refusal (the
// contract's §Credentials, Several model keys, and §The server, The model keys).
package modelkey

import (
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MaxCopy is the largest request body the proxy keeps a copy of, to send the request
// again with another key after a limit refusal.
const MaxCopy = 8 << 20

// maxWindows is the most windows the group keeps of one key, the 11 windows of the
// report, [knownWindows]: 6 keys of 11 windows fit the report's 66 entries, and every
// key has room for the window key of a limit refusal.
const maxWindows = 11

// week is how far the gateway moves a key's schedule_resets_at once it has passed.
const week = 7 * 24 * time.Hour

// The cooldowns after a limit refusal with no reset of a key with no pause_for_s and no
// schedule_resets_at, [DefaultPauseFor]: one for an API key, one for a subscription.
const (
	DefaultPauseForAPIKey       = time.Minute
	DefaultPauseForSubscription = time.Hour
)

// DefaultPauseFor is the cooldown of a key with no pause_for_s: for a key whose auth has
// oauth, a subscription login's token, [DefaultPauseForSubscription]; for any other key,
// an API key, [DefaultPauseForAPIKey].
func DefaultPauseFor(oauth bool) time.Duration {
	if oauth {
		return DefaultPauseForSubscription
	}
	return DefaultPauseForAPIKey
}

// Key is one key of the group, from the run configuration's credentials: its name, its
// earliest reset as the server had it, zero for none, the next reset of its weekly
// schedule, zero for none, its pause_for_s, or [DefaultPauseFor] without one, the end of
// its cooldown at the claim, zero for none, and chosen, true for the key of the model
// choice.
type Key struct {
	Name             string
	ResetsAt         time.Time
	ScheduleResetsAt time.Time
	PauseFor         time.Duration
	CooldownUntil    time.Time
	Chosen           bool
}

// Window is the state of one limit window of one key, an entry of
// model-keys-report.schema.json's keys. Utilization is meaningful when HasUtilization
// is true; CooldownUntil is set with StatusRejected alone.
type Window struct {
	Credential, Window, Status string
	ResetsAt                   time.Time
	Utilization                int
	HasUtilization             bool
	CooldownUntil              time.Time
	Source                     string
	ObservedAt                 time.Time
}

// Group is the state of a run's key group. Its methods are safe for concurrent use.
type Group struct {
	keys []Key
	now  func() time.Time
	// made is the clock's time when the group was made, after the claim.
	made time.Time

	mu sync.Mutex
	// windows are each key's windows, by the key's place, in the order they first came.
	windows [][]*Window
	// claim is each key's cooldown_until of the run configuration, by the key's place,
	// zero once a later state of the key allows it.
	claim  []time.Time
	active int
	// passed is true once the proxy passed a limit refusal to the session: until
	// [Group.Resume], the proxy sends no request with the placeholder and the gateway's
	// answer to each batch has stop.
	passed bool
	// changed, when set, is called after a change a report sends.
	changed func()
}

// New makes the group of keys, in their order, with the key start active, the first
// key when start is none of them. now is the clock; nil is time.Now.
func New(keys []Key, start string, now func() time.Time) *Group {
	if now == nil {
		now = time.Now
	}
	g := &Group{keys: slices.Clone(keys), now: now, made: now(), windows: make([][]*Window, len(keys)), claim: make([]time.Time, len(keys))}
	for i, k := range keys {
		g.claim[i] = k.CooldownUntil
	}
	g.active = max(g.index(start), 0)
	return g
}

// OnChange sets f, called with no lock held after each change of a window's status,
// resets_at, cooldown_until or whole-percent utilization.
func (g *Group) OnChange(f func()) {
	g.mu.Lock()
	g.changed = f
	g.mu.Unlock()
}

// Names are the keys' names in their order.
func (g *Group) Names() []string {
	out := make([]string, len(g.keys))
	for i, k := range g.keys {
		out[i] = k.Name
	}
	return out
}

// Has reports whether name is a key of the group.
func (g *Group) Has(name string) bool { return g != nil && g.index(name) >= 0 }

// index is the place of the key name, -1 for none.
func (g *Group) index(name string) int {
	return slices.IndexFunc(g.keys, func(k Key) bool { return k.Name == name })
}

// Active is the active key's name, as [Group.Pick] returns it.
func (g *Group) Active() string {
	name, _ := g.Pick()
	return name
}

// Pick returns the active key's name, and false when every key of the group is in
// cooldown. When the active key is in cooldown, the first key of [Group.next] becomes
// active first; when every key is in cooldown, the active key stays, and the proxy sets
// no key.
func (g *Group) Pick() (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if g.coolingUntil(g.active, now).After(now) {
		next, ok := g.next(now)
		if !ok {
			return g.keys[g.active].Name, false
		}
		g.active = next
	}
	return g.keys[g.active].Name, true
}

// next is the key a switch makes active, among the keys not in cooldown at now: the
// chosen key first; then the keys with no known reset, or one that has passed, by the
// order; then the key with the closest reset, keys whose resets fall in the same minute
// by the order. It reports false when every key is in cooldown. Called with g.mu held.
func (g *Group) next(now time.Time) (int, bool) {
	best, bestReset := -1, time.Time{}
	for i, k := range g.keys {
		if g.coolingUntil(i, now).After(now) {
			continue
		}
		if k.Chosen {
			return i, true
		}
		reset := g.knownReset(i, now).Truncate(time.Minute)
		switch {
		case best < 0:
		case bestReset.IsZero():
			continue
		case !reset.IsZero() && !reset.Before(bestReset):
			continue
		}
		best, bestReset = i, reset
	}
	return best, best >= 0
}

// knownReset is key i's closest reset after now, the earliest of: the resets_at of its
// windows; while no window has a resets_at, the run configuration's resets_at; and its
// schedule_resets_at, or that time plus 7 days once it has passed. A time that is not
// after now counts as none; zero for none. Called with g.mu held.
func (g *Group) knownReset(i int, now time.Time) time.Time {
	var earliest time.Time
	take := func(t time.Time) {
		if t.After(now) && (earliest.IsZero() || t.Before(earliest)) {
			earliest = t
		}
	}
	seen := false
	for _, w := range g.windows[i] {
		if !w.ResetsAt.IsZero() {
			seen = true
			take(w.ResetsAt)
		}
	}
	if !seen {
		take(g.keys[i].ResetsAt)
	}
	if s := g.keys[i].ScheduleResetsAt; !s.IsZero() {
		if !s.After(now) {
			s = s.Add(week)
		}
		take(s)
	}
	return earliest
}

// coolingUntil is the end of key i's cooldown: the latest cooldown_until of its
// windows and of the run configuration. Called with g.mu held.
func (g *Group) coolingUntil(i int, _ time.Time) time.Time {
	until := g.claim[i]
	for _, w := range g.windows[i] {
		if w.Status == StatusRejected && w.CooldownUntil.After(until) {
			until = w.CooldownUntil
		}
	}
	return until
}

// Answered records the headers of an answer of the provider to a request with key
// name that is not a limit refusal, and its status. A window the answer marks rejected
// is recorded as allowed_warning: only a limit refusal puts a key in cooldown. A 2xx
// status ends the key's cooldown_until of the run configuration: the provider served
// the key. A 401 or a 5xx keeps it.
func (g *Group) Answered(name string, status int, h http.Header) {
	g.record(name, h, false, status >= 200 && status <= 299, "")
}

// Refused records a limit refusal of the provider to a request with key name, with its
// headers and the error_code of its body: the key goes into cooldown. When name is the
// active key, the first key of [Group.next] becomes active. It
// returns the active key and whether it is out of cooldown, which a resend needs.
func (g *Group) Refused(name string, h http.Header, code string) (string, bool) {
	g.record(name, h, true, false, code)
	return g.switched()
}

// Streamed records a stream of an answer to a request with key name that ended with a
// rate_limit_error event: the key goes into cooldown as after a limit refusal, with the
// answer's headers, and the next key becomes active.
func (g *Group) Streamed(name string, h http.Header) {
	g.record(name, h, true, false, "")
	g.switched()
}

// switched makes the first key of [Group.next] active when the active one is in cooldown,
// and returns the active key and whether it is out of cooldown.
func (g *Group) switched() (string, bool) { return g.Pick() }

// Pass records that the proxy passed a limit refusal to the session: no key of the
// group is left, or the refused body had no copy.
func (g *Group) Pass() {
	g.mu.Lock()
	g.passed = true
	g.mu.Unlock()
}

// Passed reports whether the proxy passed a limit refusal to the session since the
// last [Group.Resume].
func (g *Group) Passed() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.passed
}

// Resume clears [Group.Pass]: the gateway calls it when a join opens and when its
// session ends.
func (g *Group) Resume() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.passed = false
	g.mu.Unlock()
}

// record reads the answer's headers into key name's windows. limit is true for a limit
// refusal, and code is its error_code. served is true for a 2xx answer, which ends the
// key's cooldown_until of the run configuration: the provider served the key.
func (g *Group) record(name string, h http.Header, limit, served bool, code string) {
	i := g.index(name)
	if i < 0 {
		return
	}
	now := g.now()
	r := readHeaders(h, now)
	if limit {
		g.cool(i, &r, code, now)
	}
	g.mu.Lock()
	if served {
		g.claim[i] = time.Time{}
	}
	changed := false
	for _, s := range r.windows {
		w := g.window(i, s.window)
		if w == nil {
			continue
		}
		next := *w
		next.Credential, next.Window, next.ObservedAt = name, s.window, now
		switch {
		case s.status == StatusRejected && limit:
			// cool set the window's cooldown and source.
			next.Status = StatusRejected
			next.CooldownUntil, next.Source = s.cooldown, s.source
		case s.status == StatusRejected:
			next.Status, next.CooldownUntil, next.Source = StatusAllowedWarning, time.Time{}, SourceProvider
		case s.status != "":
			next.Status, next.CooldownUntil, next.Source = s.status, time.Time{}, SourceProvider
		case !limit || next.Status == "" || (next.Status == StatusRejected && !next.CooldownUntil.After(now)):
			// An API key's windows have no status: one the provider served the request
			// under is allowed. A limit refusal keeps a cooldown that has not ended.
			next.Status, next.CooldownUntil, next.Source = StatusAllowed, time.Time{}, SourceProvider
		}
		if !s.resetsAt.IsZero() {
			next.ResetsAt = s.resetsAt
		}
		if s.has {
			next.Utilization, next.HasUtilization = s.utilization, true
		}
		if differs(*w, next, now) {
			changed = true
		}
		*w = next
	}
	f := g.changed
	g.mu.Unlock()
	if changed && f != nil {
		f()
	}
}

// cool sets the cooldown of a limit refusal of key i on the windows of r it rejects:
// the windows the subscription's headers mark rejected, an API key's families with 0
// remaining, and spend_limit for a spend cap; key when the refusal rejects no window.
// The cooldown ends at the latest reset of those windows; with none, retry-after after
// now; with none, at the key's schedule_resets_at, moved by 7 days until it is after
// now; with none, pause_for_s after now.
func (g *Group) cool(i int, r *read, code string, now time.Time) {
	var rejected []*seen
	for _, s := range r.windows {
		if s.exhausted {
			s.status = StatusRejected
		}
		if s.status == StatusRejected {
			rejected = append(rejected, s)
		}
	}
	if code == SpendLimitCode {
		s := r.window(WindowSpendLimit)
		s.status = StatusRejected
		rejected = append(rejected, s)
	}
	var until time.Time
	for _, s := range rejected {
		if s.resetsAt.After(until) {
			until = s.resetsAt
		}
	}
	if len(rejected) == 0 {
		s := r.window(WindowKey)
		s.status = StatusRejected
		if r.overallStatus == StatusRejected && r.overallReset.After(now) {
			s.resetsAt = r.overallReset
			until = r.overallReset
		}
		rejected = append(rejected, s)
	}
	source := SourceProvider
	k := g.keys[i]
	switch {
	case until.After(now):
	case r.hasRetry:
		until = now.Add(r.retryAfter)
	case !k.ScheduleResetsAt.IsZero():
		until, source = k.ScheduleResetsAt, SourceSchedule
		for !until.After(now) {
			until = until.Add(week)
		}
	default:
		until, source = now.Add(k.PauseFor), SourcePauseFor
	}
	for _, s := range rejected {
		s.cooldown, s.source = until, source
	}
}

// window is key i's window w, added when the key has fewer than [maxWindows]; nil
// for a window outside the 11 of the contract. Called with g.mu held.
func (g *Group) window(i int, w string) *Window {
	if !knownWindows[w] {
		return nil
	}
	for _, have := range g.windows[i] {
		if have.Window == w {
			return have
		}
	}
	if len(g.windows[i]) >= maxWindows {
		return nil
	}
	n := &Window{Credential: g.keys[i].Name, Window: w}
	g.windows[i] = append(g.windows[i], n)
	return n
}

// differs reports whether b is a change of a that a report sends: its status, resets_at
// or cooldown_until, or its utilization by a whole percent, as of now.
func differs(a, b Window, now time.Time) bool {
	ua, ha := utilization(a, now)
	ub, hb := utilization(b, now)
	return a.Status != b.Status || !a.ResetsAt.Equal(b.ResetsAt) || !a.CooldownUntil.Equal(b.CooldownUntil) || ha != hb || ua != ub
}

// utilization is w's utilization as of now: none once its reset has passed.
func utilization(w Window, now time.Time) (int, bool) {
	if !w.HasUtilization || (!w.ResetsAt.IsZero() && !w.ResetsAt.After(now)) {
		return 0, false
	}
	return w.Utilization, true
}

// Windows are every window the group has, by the order of the keys and then of each
// key's windows, each utilization left out once its reset has passed.
func (g *Group) Windows() []Window {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	var out []Window
	for i := range g.keys {
		for _, w := range g.windows[i] {
			c := *w
			c.Utilization, c.HasUtilization = utilization(c, now)
			out = append(out, c)
		}
	}
	return out
}

// Merge takes each entry of an answer to a report that is of a key of the group, of
// one of the 11 windows, and later, by observed_at, than the state the group has of its
// key and window. A key whose entry has a cooldown_until after now is in cooldown until
// then. An entry that is not rejected, observed after the group was made, ends the
// key's cooldown_until of the run configuration. An entry of a status outside the
// three is left out.
func (g *Group) Merge(entries []Window) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, e := range entries {
		i := g.index(e.Credential)
		if i < 0 || status(e.Status) == "" {
			continue
		}
		w := g.window(i, e.Window)
		if w == nil || !e.ObservedAt.After(w.ObservedAt) {
			continue
		}
		*w = e
		if e.Status != StatusRejected {
			w.CooldownUntil = time.Time{}
			if e.ObservedAt.After(g.made) {
				g.claim[i] = time.Time{}
			}
		}
	}
}

// Shown is the line of the gateway's log of one limit answer of key name: its status,
// the names of its headers and its error type, never a value, and the limit headers of
// no window the gateway reads.
func Shown(name string, status int, h http.Header, kind string) string {
	names := make([]string, 0, len(h))
	for n := range h {
		names = append(names, strings.ToLower(n))
	}
	sort.Strings(names)
	if kind == "" {
		kind = "none"
	}
	line := "model key " + name + ": limit answer, status " + strconv.Itoa(status) + ", error type " + kind + ", headers " + strings.Join(names, " ")
	if u := readHeaders(h, time.Time{}).unknown; len(u) > 0 {
		line += "; no window for " + strings.Join(u, " ")
	}
	return line
}
