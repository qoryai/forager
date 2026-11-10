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

// checkKeyGroup refuses, run_configuration_invalid with the key's name, a key of the
// key group of the run configuration the run starts with that has no pause_for_s: the
// gateway has no default cooldown.
func (r *Run) checkKeyGroup() error {
	for _, c := range storedGroup(r.stored, r.storedModel) {
		if c.PauseForS < 1 {
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
				"set pause_for_s on the model key %s: every key of the key group needs a cooldown, and Forager has no default", accesskey.ShownName(c.Name, true))
		}
	}
	return nil
}

// ModelKeys are the keys of the run's key group, [credential.Held.Group], in their
// order, each with its schedule_resets_at and pause_for_s; none when the run's start
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
		k := modelkey.Key{Name: name, PauseFor: time.Duration(c.PauseForS) * time.Second}
		// The schema has refused a schedule_resets_at that is no RFC 3339 time.
		k.ScheduleResetsAt, _ = time.Parse(time.RFC3339, c.ScheduleResetsAt)
		out = append(out, k)
	}
	return out
}
