package run

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/routine"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/sealed"
	"github.com/qoryai/forager/server"
)

// Clock is the time a run's renewals of the server's values are judged by. Nil in
// [Config] is this machine's clock.
type Clock interface {
	Now() time.Time
	// After returns a channel that receives once d has passed.
	After(d time.Duration) <-chan time.Time
}

// machineClock is this machine's clock.
type machineClock struct{}

// Now returns this machine's time.
func (machineClock) Now() time.Time { return time.Now() }

// After returns [time.After] of d.
func (machineClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// renewer fetches again the values of the run configuration's credentials that have
// expires_at: [credential.RenewBefore] before each expires, and after a host answered
// 401 to a request one was set on, at most every [credential.RetryWait] per credential.
// The credentials due within RetryWait of each other go in one secrets request. A
// renewal that fails keeps the value and is reported; at expires_at with no renewal the
// run's record gets one line, and the value is set no more. It lives on the [Run], so a
// reload, which resolves the credentials again, starts no second one.
type renewer struct {
	r       *Run
	clock   Clock
	wake    chan struct{}
	done    chan struct{}
	stopped chan struct{}
	stop    sync.Once
	started bool
	// report is the gateway's report with the run's prefix, set by start.
	report func(string)

	mu sync.Mutex
	// entries are the credentials with expires_at, in the document's order.
	entries []*renewal
}

// renewal is one credential's state: when its value expires, when it was last asked
// for, whether a host refused it since, and whether it expired with no renewal.
type renewal struct {
	name    string
	expires time.Time
	asked   time.Time
	stale   bool
	expired bool
}

// newRenewer is the renewer of the opened values, asked for at now; nil when none has
// expires_at.
func newRenewer(r *Run, values sealed.Values, now time.Time) *renewer {
	w := &renewer{r: r, clock: r.clock(), wake: make(chan struct{}, 1), done: make(chan struct{}), stopped: make(chan struct{})}
	for _, c := range r.stored {
		if at, ok := values.ExpiresAt(c.Name); ok {
			w.entries = append(w.entries, &renewal{name: c.Name, expires: at, asked: now})
		}
	}
	if len(w.entries) == 0 {
		return nil
	}
	return w
}

// clock is the run's [Config.Clock], or this machine's.
func (r *Run) clock() Clock {
	if r.cfg.Clock != nil {
		return r.cfg.Clock
	}
	return machineClock{}
}

// expiresAt is when the value of the credential name expires, zero when it does not.
func (w *renewer) expiresAt(name string) time.Time {
	if w == nil {
		return time.Time{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range w.entries {
		if e.name == name {
			return e.expires
		}
	}
	return time.Time{}
}

// rejected is what a host's 401 to a request the value of name was set on calls: the
// value is asked for again once RetryWait has passed since the last asking. Nil for a
// credential without expires_at, whose 401 asks for nothing.
func (w *renewer) rejected(name string) func() {
	if w == nil || !w.has(name) {
		return nil
	}
	return func() {
		w.refused(name)
		select {
		case w.wake <- struct{}{}:
		default:
		}
	}
}

// refused marks name, unless it expired, as refused by a host.
func (w *renewer) refused(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range w.entries {
		if e.name == name && !e.expired {
			e.stale = true
		}
	}
}

// start starts the renewals; a renewal that panics is reported as [routine.Do] reports
// one, and the next waits as one after a failed renewal does.
func (w *renewer) start(report func(string)) {
	if w == nil {
		return
	}
	w.started, w.report = true, report
	routine.Go(report, func() {
		defer close(w.stopped)
		for routine.Do(report, w.loop) {
			now := w.clock.Now()
			w.asking(nil, now)
		}
	})
}

// close stops the renewals and waits until no renewal runs, so no value is put in
// place after it returns.
func (w *renewer) close() {
	if w == nil {
		return
	}
	w.stop.Do(func() { close(w.done) })
	if w.started {
		<-w.stopped
	}
}

// loop renews the values until the run ends.
func (w *renewer) loop() {
	for {
		now := w.clock.Now()
		due, next, gone := w.plan(now)
		for _, e := range gone {
			w.expire(e)
		}
		if len(due) > 0 {
			w.renew(due, now)
			continue
		}
		var timer <-chan time.Time
		if !next.IsZero() {
			timer = w.clock.After(next.Sub(now))
		}
		select {
		case <-w.done:
			return
		case <-w.wake:
		case <-timer:
		}
	}
}

// plan returns the credentials to ask for at now, the next time to look again, zero
// when there is none, and the credentials whose expires_at has passed, marked expired,
// for [renewer.expire]. A credential
// is due at its expires_at less RenewBefore, or at once after a host refused it, but
// never sooner than RetryWait after it was last asked for. The first due credential
// takes along every other whose time comes within RetryWait and that may be asked for
// now.
func (w *renewer) plan(now time.Time) (due []string, next time.Time, gone []*renewal) {
	w.mu.Lock()
	defer w.mu.Unlock()
	at := func(e *renewal) time.Time {
		least := e.asked.Add(credential.RetryWait)
		if e.stale {
			return least
		}
		if t := e.expires.Add(-credential.RenewBefore); t.After(least) {
			return t
		}
		return least
	}
	earliest := func(t time.Time) {
		if next.IsZero() || t.Before(next) {
			next = t
		}
	}
	first := false
	for _, e := range w.entries {
		if e.expired {
			continue
		}
		if !now.Before(e.expires) {
			e.expired = true
			gone = append(gone, e)
			continue
		}
		if !at(e).After(now) {
			first = true
		}
	}
	for _, e := range w.entries {
		if e.expired {
			continue
		}
		t := at(e)
		if first && !t.After(now.Add(credential.RetryWait)) && !e.asked.Add(credential.RetryWait).After(now) {
			due = append(due, e.name)
			continue
		}
		earliest(t)
		earliest(e.expires)
	}
	return due, next, gone
}

// expire stops setting the value of e, which expired with no renewal, and writes one
// line to the run's record.
func (w *renewer) expire(e *renewal) {
	r := w.r
	r.dropValue(e.name)
	if r.cfg.Log != nil {
		r.cfg.Log(fmt.Sprintf("Start another run once the control plane answers: credential %s expired at %s",
			accesskey.ShownName(e.name, true), e.expires.UTC().Format(time.RFC3339)))
	}
}

// dropValue overwrites the run's value of name with zeros and drops it.
func (r *Run) dropValue(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values.Drop(name)
}

// renew asks the server for the values of names under the digest of the run
// configuration in force, and puts each one that meets the start's rules in place of
// the one the run has. Each one refused, and every one of a request that failed, keeps
// its value and is reported.
func (w *renewer) renew(names []string, now time.Time) {
	w.asking(names, now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-w.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	r := w.r
	values, err := r.cfg.Secrets(ctx, r.computedDigest(), names)
	defer values.Clear()
	for _, name := range names {
		if !w.has(name) {
			// A harness credential whose renewals stopped at the run's first join request.
			continue
		}
		if err != nil {
			w.notRenewed(name, err)
			continue
		}
		if err := r.renewed(name, values, w.clock.Now()); err != nil {
			w.notRenewed(name, err)
			continue
		}
		at, _ := values.ExpiresAt(name)
		r.replaceValue(name, values)
		w.renewedAt(name, at)
	}
}

// asking marks names, every credential when names is nil, as asked for at now, which
// clears a host's refusal.
func (w *renewer) asking(names []string, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range w.entries {
		if names == nil || slices.Contains(names, e.name) {
			e.asked, e.stale = now, false
		}
	}
}

// renewedAt sets the expires_at of name to at.
func (w *renewer) renewedAt(name string, at time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range w.entries {
		if e.name == name {
			e.expires = at
		}
	}
}

// replaceValue puts the value of name that values has in place of the run's, unless
// name is a harness credential whose value [Run.CloseHarness] cleared.
func (r *Run) replaceValue(name string, values sealed.Values) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.harnessGone(name) {
		return
	}
	r.values.Replace(name, values)
}

// drop stops the renewals of names: they are planned no more, and a renewal in flight
// keeps no value of them.
func (w *renewer) drop(names []string) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.entries = slices.DeleteFunc(w.entries, func(e *renewal) bool { return slices.Contains(names, e.name) })
}

// has reports whether name is renewed still.
func (w *renewer) has(name string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.ContainsFunc(w.entries, func(e *renewal) bool { return e.name == name })
}

// notRenewed reports a renewal of the credential name that failed.
func (w *renewer) notRenewed(name string, err error) {
	select {
	case <-w.done:
		// The run ended during the request: nothing failed that the user needs to hear of.
		return
	default:
	}
	w.report(fmt.Sprintf("If this repeats, check the control plane: credential %s was not renewed: %v", accesskey.ShownName(name, true), accesskey.ShownError(err)))
}

// errNoExpiry, errExpiresPassed and errApplyMoved are the causes of a renewal refused
// for its form.
var (
	errNoExpiry      = errors.New("the answer has no expires_at")
	errExpiresPassed = errors.New("its expires_at has passed")
	errApplyMoved    = errors.New("its apply differs from the start")
)

// renewed checks the renewed value of name against the rules of the start: a value that
// is a valid header value, one that starts with a model key's key_prefixes, an
// expires_at after now, and the start's apply.
func (r *Run) renewed(name string, values sealed.Values, now time.Time) error {
	i := slices.IndexFunc(r.stored, func(c server.RunCredential) bool { return c.Name == name })
	v, ok := values.Value(name)
	switch {
	case i < 0 || !ok:
		return fmt.Errorf("the answer has no value of %s", accesskey.ShownName(name, true))
	case !HeaderValue(v):
		return errors.New("its value has a control character, or a space or tab at its start or end, which a header value cannot have")
	case !credential.KeyMatches(r.stored[i].KeyPrefixes, v):
		return errors.New("its value starts with none of its key_prefixes")
	}
	at, ok := values.ExpiresAt(name)
	switch {
	case !ok:
		return errNoExpiry
	case !at.After(now):
		return errExpiresPassed
	}
	if !reflect.DeepEqual(effectiveApply(r.stored[i], values), r.applies[name]) {
		return errApplyMoved
	}
	return nil
}

// effectiveApply is where the value of c is set: the answer's apply, or c's items when
// the answer has none.
func effectiveApply(c server.RunCredential, values sealed.Values) []credential.StoredApply {
	var out []credential.StoredApply
	if apply, ok := values.Apply(c.Name); ok {
		for _, a := range apply {
			out = append(out, credential.StoredApply{Hosts: a.Hosts, Scheme: a.Scheme, Username: a.Username, Header: a.Header, Paths: a.Paths})
		}
		return out
	}
	for _, a := range c.Applies() {
		out = append(out, credential.StoredApply{Hosts: slices.Clone(a.Hosts), Scheme: a.Scheme, Username: a.Username, Header: a.Header, Paths: slices.Clone(a.Paths)})
	}
	return out
}

// outside is what makes the answer's apply of c not within c's entry, as [within]
// decides, and whether something does: of its first item outside, a host that no
// entry item has, else of its first host that no entry item takes alone, the first of
// scheme, username, header and paths that no entry item with the host has; and when
// each host is within an entry item but no one item takes them all, the item's span.
func outside(c server.RunCredential, values sealed.Values) (string, bool) {
	apply, ok := values.Apply(c.Name)
	if !ok {
		return "", false
	}
	entry := c.Applies()
	for _, a := range apply {
		if slices.ContainsFunc(entry, func(e server.Apply) bool { return within(a, e) }) {
			continue
		}
		for _, h := range a.Hosts {
			if why, ok := differs(a, h, entry); ok {
				return why, true
			}
		}
		return "merges two apply items of its entry", true
	}
	return "", false
}

// differs is what no item of entry with the host h has of the answer's item a, and
// whether there is something: the host, the scheme, the username, the header or the
// paths, checked in that order.
func differs(a sealed.Apply, h string, entry []server.Apply) (string, bool) {
	shown := accesskey.ShownValue(h, false)
	one := sealed.Apply{Hosts: []string{h}, Scheme: a.Scheme, Username: a.Username, Header: a.Header, Paths: a.Paths}
	var with []server.Apply
	for _, e := range entry {
		if slices.Contains(e.Hosts, h) {
			with = append(with, e)
		}
	}
	same := func(keep func(e server.Apply) bool) bool {
		with = slices.DeleteFunc(with, func(e server.Apply) bool { return !keep(e) })
		return len(with) > 0
	}
	switch {
	case len(with) == 0:
		return "applies to " + shown + ", outside its entry", true
	case !same(func(e server.Apply) bool { return e.Scheme == a.Scheme }):
		return "sets " + shown + " with another scheme", true
	case !same(func(e server.Apply) bool { return e.Username == a.Username }):
		return "sets " + shown + " with another username", true
	case !same(func(e server.Apply) bool { return strings.EqualFold(e.Header, a.Header) }):
		return "sets " + shown + " with another header", true
	case !same(func(e server.Apply) bool { return within(one, e) }):
		return "sets " + shown + " on other paths", true
	}
	return "", false
}

// within reports whether the answer's item a narrows the entry's item e, or is it: its
// hosts among e's hosts, the same scheme, username and header, the header's case
// ignored, and paths that e's paths cover, every path when e has none.
func within(a sealed.Apply, e server.Apply) bool {
	if a.Scheme != e.Scheme || a.Username != e.Username || !strings.EqualFold(a.Header, e.Header) {
		return false
	}
	for _, h := range a.Hosts {
		if !slices.Contains(e.Hosts, h) {
			return false
		}
	}
	if e.Paths == nil {
		return true
	}
	if a.Paths == nil {
		return false
	}
	for _, p := range a.Paths {
		if !slices.ContainsFunc(e.Paths, func(entry string) bool { return policy.CoversPath(entry, p) }) {
			return false
		}
	}
	return true
}

// checkOpened refuses an opened value of c that expired before the run started, or
// whose apply is outside c's entry, run_configuration_invalid with c's name.
func checkOpened(c server.RunCredential, values sealed.Values, now time.Time) error {
	if at, ok := values.ExpiresAt(c.Name); ok && !at.After(now) {
		return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
			"Tell whoever runs the control plane: credential %s expired before the run started", accesskey.ShownName(c.Name, true))
	}
	if why, ok := outside(c, values); ok {
		return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
			"Tell whoever runs the control plane: credential %s %s", accesskey.ShownName(c.Name, true), why)
	}
	return nil
}
