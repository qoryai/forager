package run

import (
	"regexp"
	"slices"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
)

// storedGroup is the key group of a run configuration's work credentials whose
// model_credential is model, [credential.KeyGroup]: the start key and every API
// credential with its format, auth and endpoint, in their order. The start key is model
// when it is the name of an API credential of creds, or, with model empty, the one API
// credential of creds; with neither, the run has no key group of creds. With model
// empty and a model key of the machine's beside the one, the run is refused later, when
// its start key is decided. The harness credentials are left out, as the proxy's group
// leaves them out ([Run.storedUses]).
func storedGroup(creds []server.RunCredential, model string) []server.RunCredential {
	work := slices.DeleteFunc(slices.Clone(creds), server.RunCredential.Harness)
	if model == "" {
		api := slices.IndexFunc(work, func(c server.RunCredential) bool { return c.Format != "" })
		if api >= 0 && slices.IndexFunc(work[api+1:], func(c server.RunCredential) bool { return c.Format != "" }) < 0 {
			model = work[api].Name
		}
	}
	entries := make([]credential.KeyEntry, len(work))
	for i, c := range work {
		entries[i] = keyEntry(c)
	}
	var out []server.RunCredential
	for _, name := range credential.KeyGroup(entries, model) {
		out = append(out, work[slices.IndexFunc(work, func(c server.RunCredential) bool { return c.Name == name })])
	}
	return out
}

// keyEntry is c as [credential.KeyGroup] reads it.
func keyEntry(c server.RunCredential) credential.KeyEntry {
	return credential.KeyEntry{Name: c.Name, Format: c.Format, Endpoint: c.Endpoint, Scheme: c.Auth.Scheme, Username: c.Auth.Username, Header: c.Auth.Header, OAuth: c.Auth.OAuth,
		AccountHeader: c.Auth.AccountHeader, AccountClaim: c.Auth.AccountClaim}
}

// checkKeyGroup returns a run_configuration_invalid error, with the key's name, for a
// key group of the run configuration the run starts with that has a key with a
// pause_for_s below 1, a use_up_to_percent outside 1 to 99, or one of use_up_to_percent
// and use_up_to_windows without the other, which each fail the schema too; a start key
// in cooldown at now, since the server picks the start key among the keys out of
// cooldown; and a second key with chosen. A key with no pause_for_s has
// [modelkey.DefaultPauseFor].
func (r *Run) checkKeyGroup(now time.Time) error {
	group := storedGroup(r.stored, r.storedModel)
	chosen := ""
	for _, c := range group {
		if c.PauseForS != nil && *c.PauseForS < 1 {
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
				"set pause_for_s on the model key %s to a value from 1 to 604800, or remove it for the default cooldown: pause_for_s is %d", accesskey.ShownName(c.Name, true), *c.PauseForS)
		}
		if err := checkUseUpTo(c); err != nil {
			return err
		}
		// The schema has refused a cooldown_until that is no RFC 3339 time.
		if until, err := time.Parse(time.RFC3339, c.CooldownUntil); err == nil && until.After(now) && c.Name == startName(group, r.storedModel) {
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
				"set model_credential to a model key out of cooldown: the start key %s is in cooldown until %s", accesskey.ShownName(c.Name, true), c.CooldownUntil)
		}
		if c.Chosen {
			if chosen != "" {
				return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
					"set chosen on one model key of the key group: %s and %s both have it", accesskey.ShownName(chosen, true), accesskey.ShownName(c.Name, true))
			}
			chosen = c.Name
		}
	}
	return nil
}

// windowShape is the grammar of a limit window's name, the window of
// model-keys-report.schema.json.
var windowShape = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// maxUseUpToWindows is the most windows use_up_to_windows lists, the 11 windows of a
// model keys report.
const maxUseUpToWindows = 11

// checkUseUpTo returns a run_configuration_invalid error, with the key's name, for a
// key c that breaks a rule of the schema on use_up_to_percent and use_up_to_windows: a
// use_up_to_percent outside 1 to 99; a use_up_to_percent without use_up_to_windows, or
// with an empty one; use_up_to_windows, empty or not, without use_up_to_percent; and
// use_up_to_windows with more than 11 windows, a window twice, or a window outside the
// grammar of a model keys report's window.
func checkUseUpTo(c server.RunCredential) error {
	name := accesskey.ShownName(c.Name, true)
	invalid := func(format string, args ...any) error {
		return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name), format, args...)
	}
	switch p := c.UseUpToPercent; {
	case p != nil && (*p < 1 || *p > 99):
		return invalid("set use_up_to_percent on the model key %s to a value from 1 to 99, or remove it and use_up_to_windows to use the key up to its limit: use_up_to_percent is %d", name, *p)
	case p != nil && len(c.UseUpToWindows) == 0:
		return invalid("set use_up_to_windows on the model key %s to the limit windows use_up_to_percent applies to, or remove use_up_to_percent: the key has use_up_to_percent %d and no use_up_to_windows", name, *p)
	case p == nil && c.UseUpToWindows != nil:
		return invalid("set use_up_to_percent on the model key %s to a value from 1 to 99, or remove use_up_to_windows: the key has use_up_to_windows and no use_up_to_percent", name)
	case len(c.UseUpToWindows) > maxUseUpToWindows:
		return invalid("list at most %d windows in use_up_to_windows of the model key %s: it lists %d", maxUseUpToWindows, name, len(c.UseUpToWindows))
	}
	for i, w := range c.UseUpToWindows {
		if !windowShape.MatchString(w) {
			return invalid("set each window in use_up_to_windows of the model key %s to 1 to 64 of a-z, 0-9 and underscore, starting with a letter, such as five_hour: window %d is %s", name, i+1, accesskey.ShownName(w, true))
		}
		if slices.Contains(c.UseUpToWindows[:i], w) {
			return invalid("list each window once in use_up_to_windows of the model key %s: %s is there twice", name, accesskey.ShownName(w, true))
		}
	}
	return nil
}

// startName is the name of the start key of group, the key group whose
// model_credential is model: model, or with model empty the group's one key.
func startName(group []server.RunCredential, model string) string {
	if model == "" && len(group) > 0 {
		return group[0].Name
	}
	return model
}

// ModelKeys are the keys of the run's key group, [credential.Held.Group], in their
// order, each with its resets_at, schedule_resets_at, pause_for_s or without it
// [modelkey.DefaultPauseFor] of its auth, cooldown_until, chosen, use_up_to_percent and
// use_up_to_windows; none when the run's start key is the machine's or the run has
// none. Call it after [Run.Hold].
func (r *Run) ModelKeys() []modelkey.Key {
	held := r.Held()
	if held == nil {
		return nil
	}
	var out []modelkey.Key
	for _, name := range held.Group {
		i := slices.IndexFunc(r.stored, func(c server.RunCredential) bool { return c.Name == name })
		if i < 0 {
			continue
		}
		c := r.stored[i]
		k := modelkey.Key{Name: name, PauseFor: modelkey.DefaultPauseFor(c.Auth.OAuth), Chosen: c.Chosen}
		if c.PauseForS != nil {
			k.PauseFor = time.Duration(*c.PauseForS) * time.Second
		}
		// The schema has refused a time that is no RFC 3339 time.
		k.ResetsAt, _ = time.Parse(time.RFC3339, c.ResetsAt)
		k.ScheduleResetsAt, _ = time.Parse(time.RFC3339, c.ScheduleResetsAt)
		k.CooldownUntil, _ = time.Parse(time.RFC3339, c.CooldownUntil)
		if c.UseUpToPercent != nil {
			k.UseUpToPercent, k.UseUpToWindows = *c.UseUpToPercent, slices.Clone(c.UseUpToWindows)
		}
		out = append(out, k)
	}
	return out
}

// Resume is the resume of the run configuration the run started with: the paused run
// the run continues, whose transcript its session may read. Nil when it has none.
func (r *Run) Resume() *server.LinkResume {
	if f := r.cfg.Fetched; f != nil && f.Document != nil {
		return f.Document.Resume
	}
	return nil
}

// MessagesPath is the clean path of the messages request of the model API of the run's
// key group, [modelkey.MessagesPath] of the start key's format and endpoint; empty when
// the run has no key group. Call it after [Run.Hold].
func (r *Run) MessagesPath() string {
	held := r.Held()
	if held == nil || len(held.Group) == 0 {
		return ""
	}
	i := slices.IndexFunc(r.stored, func(c server.RunCredential) bool { return c.Name == held.Start })
	if i < 0 {
		return ""
	}
	return modelkey.MessagesPath(r.stored[i].Format, r.stored[i].Endpoint)
}
