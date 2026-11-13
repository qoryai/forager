package modelkey

import (
	"time"

	"github.com/qoryai/forager/event"
)

// maxUnauthorized is the most keys [Group.Unauthorized] lists, the most entries of a
// model keys report's unauthorized: Qory Apiary sends a run at most 6 model keys.
const maxUnauthorized = 6

// Unauthorized is a key of the group that got a 401 of the model provider and that no
// renewal brought back: its name, when the 401 arrived, and Out, true once the key left
// the group for the run ([Group.Revoked]); false while its renewal is pending.
type Unauthorized struct {
	Credential string
	At         time.Time
	Out        bool
}

// OnStop sets f, called with the reason of the stop once [Group.Stop] fixes it, with no
// lock of the group held, in the order of [Group.OnPassed]'s calls.
func (g *Group) OnStop(f func(string)) {
	g.mu.Lock()
	g.onStop = f
	g.mu.Unlock()
}

// OnUnauthorized sets f, called with [Group.Unauthorized] after each change of it, one
// call at a time, in the order of the changes, with the group's lock not held.
func (g *Group) OnUnauthorized(f func([]Unauthorized)) {
	g.mu.Lock()
	g.onUnauthorized = f
	g.mu.Unlock()
}

// Reject records the model provider's 401 to a request with key name, at the clock's
// time: the proxy sets the key no more. A key whose value renews, renews true, counts
// as in cooldown until its renewal ends, [Group.Renewed] or [Group.Revoked]; another
// key leaves the group at once. A key already out, or whose renewal is pending, keeps
// its state and the time of its first 401. A name of no key of the group changes
// nothing. For a format whose requests the proxy does not send again ([Resends]), a 401
// before any pass makes the 401 the cause of the next pass, as [Group.PassRejected]
// does: a [Group.Pass] between the two, a request that found no key usable, keeps it.
func (g *Group) Reject(name string, renews bool) {
	g.change(name, func(i int) bool {
		if !g.passed && !Resends(g.format) {
			g.rejected = true
		}
		if g.out[i] || !g.unauth[i].IsZero() {
			return false
		}
		g.unauth[i] = g.now()
		g.out[i] = !renews
		return true
	})
}

// Renewed puts key name back in the group after a renewal that followed its 401
// ([Group.Reject]) brought a value: the proxy sets it again. A key that is out, or
// that got no 401, keeps its state.
func (g *Group) Renewed(name string) {
	g.change(name, func(i int) bool {
		if g.out[i] || g.unauth[i].IsZero() {
			return false
		}
		g.unauth[i] = time.Time{}
		return true
	})
}

// Revoked takes key name out of the group for the rest of the run, after a renewal
// that followed its 401 ([Group.Reject]) ended with no value: the server's 409, or the
// value's expires_at with no renewal. A key that got no 401 keeps its state.
func (g *Group) Revoked(name string) {
	g.change(name, func(i int) bool {
		if g.out[i] || g.unauth[i].IsZero() {
			return false
		}
		g.out[i] = true
		return true
	})
}

// Restore gives the group the keys of a run's record after a 401 ([Group.Unauthorized]
// of the gateway before), for a gateway that reopens the run: each key with its time,
// out when Out is true. A name of no key of the group is left out. The caller renews
// each key that is not out again.
func (g *Group) Restore(keys []Unauthorized) {
	for _, k := range keys {
		g.change(k.Credential, func(i int) bool {
			if g.out[i] && g.unauth[i].IsZero() {
				// A key out for another reason, such as no account claim, stays so.
				return false
			}
			g.unauth[i], g.out[i] = k.At, k.Out
			return true
		})
	}
}

// Pending reports whether key name got a 401 ([Group.Reject]) and its renewal is
// pending: the renewal lists it as unauthorized.
func (g *Group) Pending(name string) bool {
	i := g.index(name)
	if i < 0 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.out[i] && !g.unauth[i].IsZero()
}

// Unauthorized are the keys that got a 401 and that no renewal brought back, by the
// order of the keys, at most [maxUnauthorized]; nil for none.
func (g *Group) Unauthorized() []Unauthorized {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.unauthorized()
}

// unauthorized is [Group.Unauthorized]. Called with g.mu held.
func (g *Group) unauthorized() []Unauthorized {
	var out []Unauthorized
	for i, k := range g.keys {
		if g.unauth[i].IsZero() || len(out) == maxUnauthorized {
			continue
		}
		out = append(out, Unauthorized{Credential: k.Name, At: g.unauth[i], Out: g.out[i]})
	}
	return out
}

// change runs f on the place of key name with g.mu held; when f reports a change, the
// hooks of [Group.OnUnauthorized] and [Group.OnChange] are called after it, with the
// lock not held. The calls of changes come one at a time, in their order.
func (g *Group) change(name string, f func(i int) bool) {
	i := g.index(name)
	if i < 0 {
		return
	}
	g.noting.Lock()
	defer g.noting.Unlock()
	g.mu.Lock()
	if !f(i) {
		g.mu.Unlock()
		return
	}
	g.changes++
	list, hook, changed := g.unauthorized(), g.onUnauthorized, g.changed
	g.mu.Unlock()
	if hook != nil {
		hook(list)
	}
	if changed != nil {
		changed()
	}
}

// PassRejected is [Group.Pass] for a 401 of the provider that the proxy passed to the
// session: the stop's reason may then be model_key_switch ([Group.Stop]). A group that
// passed a limit refusal before keeps it as the cause. [Group.Reject] sets the cause
// first for openai-responses, so a pass that comes between the two keeps it.
func (g *Group) PassRejected() {
	if g == nil {
		return
	}
	g.setPassed(true, func(was bool) {
		if !was {
			g.rejected = true
		}
	})
}

// PassWith is [Group.Pass] with the stop's reason fixed at reason, for a gateway that
// reopens a run whose record has the reason of its stop ([Group.Stop]). [Group.OnStop]'s
// hook is not called: the record has the reason.
func (g *Group) PassWith(reason string) {
	if g == nil {
		return
	}
	g.setPassed(true, func(bool) { g.reason = reason })
}

// Stop returns the reason of the stop in the gateway's answer to a batch, and false
// while the proxy passed nothing since the last [Group.Resume]. The first call after a
// pass fixes the reason until the next Resume, so each answer to the session has the
// same one, and calls [Group.OnStop]'s hook with it:
//   - model_key_unauthorized when every key is out and a 401 took at least one out
//     ([Group.Revoked]): no key is left for the run;
//   - model_key_switch when the proxy passed a 401 ([Group.PassRejected]), the
//     group's format is one whose requests the proxy does not send again ([Resends]),
//     and a key is usable: a continuation starts on it at once;
//   - model_key_limit otherwise: a key is in cooldown or has its renewal pending, or is
//     usable after a refusal the proxy could not send again.
func (g *Group) Stop() (string, bool) {
	if g == nil {
		return "", false
	}
	g.passing.Lock()
	defer g.passing.Unlock()
	g.mu.Lock()
	if !g.passed {
		g.mu.Unlock()
		return "", false
	}
	if g.reason != "" {
		reason := g.reason
		g.mu.Unlock()
		return reason, true
	}
	// The reason holds until Resume, whatever the keys do meanwhile: Core's
	// continuation of a paused run ends it with model_key_unauthorized when no key is
	// usable.
	g.reason = g.stopReason(g.now())
	reason, f := g.reason, g.onStop
	g.mu.Unlock()
	if f != nil {
		f(reason)
	}
	return reason, true
}

// stopReason is the reason [Group.Stop] fixes, at now. Called with g.mu held.
func (g *Group) stopReason(now time.Time) string {
	gone, revoked, usable := true, false, false
	for i := range g.keys {
		gone = gone && g.out[i]
		revoked = revoked || (g.out[i] && !g.unauth[i].IsZero())
		usable = usable || g.usable(i, now)
	}
	switch {
	case gone && revoked:
		return event.ReasonModelKeyUnauthorized
	case g.rejected && !Resends(g.format) && usable:
		return event.ReasonModelKeySwitch
	}
	return event.ReasonModelKeyLimit
}

// StopReason reports whether reason is one [Group.Stop] returns.
func StopReason(reason string) bool {
	switch reason {
	case event.ReasonModelKeyLimit, event.ReasonModelKeySwitch, event.ReasonModelKeyUnauthorized:
		return true
	}
	return false
}
