package run

import (
	"slices"
	"strings"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
)

// storedGroup is the key group of a run configuration's credentials whose
// model_credential is model: the start key and every API credential with its format,
// auth and endpoint, in their order. The start key is model when it names an API
// credential of creds, or, with model empty, the one API credential of creds; with
// neither, the run has no key group of creds. With model empty and a model key of the
// machine's beside the one, the run is refused later, when its start key is decided.
func storedGroup(creds []server.RunCredential, model string) []server.RunCredential {
	i := slices.IndexFunc(creds, func(c server.RunCredential) bool { return c.Format != "" && c.Name == model })
	if model == "" {
		api := slices.IndexFunc(creds, func(c server.RunCredential) bool { return c.Format != "" })
		if api >= 0 && slices.IndexFunc(creds[api+1:], func(c server.RunCredential) bool { return c.Format != "" }) < 0 {
			i = api
		}
	}
	if i < 0 {
		return nil
	}
	start := creds[i]
	var out []server.RunCredential
	for _, c := range creds {
		if c.Format == start.Format && c.Endpoint == start.Endpoint && c.Auth.Scheme == start.Auth.Scheme &&
			c.Auth.Username == start.Auth.Username && c.Auth.OAuth == start.Auth.OAuth && strings.EqualFold(c.Auth.Header, start.Auth.Header) {
			out = append(out, c)
		}
	}
	return out
}

// checkKeyGroup refuses, run_configuration_invalid with the key's name, a key group of
// the run configuration the run starts with that has a key with no pause_for_s, since
// the gateway has no default cooldown; a start key in cooldown at now, since the server
// picks the start key among the keys out of cooldown; and a second key with chosen.
func (r *Run) checkKeyGroup(now time.Time) error {
	group := storedGroup(r.stored, r.storedModel)
	chosen := ""
	for _, c := range group {
		if c.PauseForS < 1 {
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
				"set pause_for_s on the model key %s: every key of the key group needs a cooldown, and Forager has no default", accesskey.ShownName(c.Name, true))
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

// startName is the name of the start key of group, the key group whose
// model_credential is model: model, or with model empty the group's one key.
func startName(group []server.RunCredential, model string) string {
	if model == "" && len(group) > 0 {
		return group[0].Name
	}
	return model
}

// ModelKeys are the keys of the run's key group, [credential.Held.Group], in their
// order, each with its resets_at, schedule_resets_at, pause_for_s, cooldown_until and
// chosen; none when the run's start
// key is the machine's or the run has none. Call it after [Run.Hold].
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
		k := modelkey.Key{Name: name, PauseFor: time.Duration(c.PauseForS) * time.Second, Chosen: c.Chosen}
		// The schema has refused a time that is no RFC 3339 time.
		k.ResetsAt, _ = time.Parse(time.RFC3339, c.ResetsAt)
		k.ScheduleResetsAt, _ = time.Parse(time.RFC3339, c.ScheduleResetsAt)
		k.CooldownUntil, _ = time.Parse(time.RFC3339, c.CooldownUntil)
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
