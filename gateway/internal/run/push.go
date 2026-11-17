package run

import (
	"slices"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
)

// HasPush reports whether the run configuration the run started with has a push
// credential: only then does the gateway open the run's push proxy.
func (r *Run) HasPush() bool {
	return slices.ContainsFunc(r.stored, func(c server.RunCredential) bool { return c.Push() })
}

// checkPush refuses, run_configuration_invalid with the credential's name, a push
// credential of the run configuration the run starts with that the push proxy cannot
// set: one with placeholders, which no session gets, and two items of push credentials,
// of one credential or of two, that claim one exact host when one of them has no paths,
// or when their paths overlap. A work or harness credential on the same host is no
// conflict: no proxy sets two purposes.
func (r *Run) checkPush() error {
	type item struct {
		name  string
		hosts []string
		paths []string
	}
	var items []item
	for _, c := range r.stored {
		if !c.Push() {
			continue
		}
		if len(c.Placeholders) > 0 {
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
				"Remove the placeholders from each push credential: no session gets a push credential.\nThe push credential %s has placeholders.", accesskey.ShownName(c.Name, true))
		}
		for _, a := range c.Applies() {
			items = append(items, item{c.Name, a.Hosts, a.Paths})
		}
	}
	for i, u := range items {
		for _, other := range items[:i] {
			for _, host := range u.hosts {
				if !slices.Contains(other.hosts, host) {
					continue
				}
				first, second, shown := accesskey.ShownName(other.name, true), accesskey.ShownName(u.name, true), accesskey.ShownValue(host, false)
				one := other.name == u.name
				names := refusal.Shown(other.name, u.name)
				if one {
					names = refusal.Shown(u.name)
				}
				if len(u.paths) == 0 || len(other.paths) == 0 {
					if one {
						return refusal.New(refusal.RunConfigurationInvalid, names,
							pushNoPaths+"\nThe push credential %s claims %s in two apply items, and one of them has no paths.", first, shown)
					}
					return refusal.New(refusal.RunConfigurationInvalid, names,
						pushNoPaths+"\nThe push credentials %s and %s both claim %s, and one of them has no paths.", first, second, shown)
				}
				for _, x := range other.paths {
					if slices.ContainsFunc(u.paths, func(y string) bool { return policy.OverlapPaths(x, y) }) {
						if one {
							return refusal.New(refusal.RunConfigurationInvalid, names,
								pushOverlap+"\nThe push credential %s has apply items with overlapping paths on %s.", first, shown)
						}
						return refusal.New(refusal.RunConfigurationInvalid, names,
							pushOverlap+"\nThe push credentials %s and %s have overlapping paths on %s.", first, second, shown)
					}
				}
			}
		}
	}
	return nil
}

// The first lines of the refusals of push credentials whose items claim one host
// together.
const (
	pushNoPaths = "Give paths to each apply item of the push credentials that claims a host another item claims."
	pushOverlap = "Give the push credentials' apply items on one host paths that do not overlap."
)

// checkPushHosts refuses, under pol's enforce mode, a host of a push credential's items
// that the policy's egress allow list does not cover, as [credential.ResolveWith] does
// for a work credential: at the start and at every reload alike.
func (r *Run) checkPushHosts(pol *policy.Loaded) error {
	if pol.Policy.Egress.Mode != policy.Enforce {
		return nil
	}
	allow := pol.Policy.Egress.Listed()
	for _, c := range r.stored {
		if !c.Push() {
			continue
		}
		for _, a := range c.Applies() {
			for _, h := range a.Hosts {
				if slices.ContainsFunc(allow, func(entry string) bool { return policy.Covers(entry, h) }) {
					continue
				}
				name, shown := accesskey.ShownName(c.Name, true), accesskey.ShownValue(h, false)
				return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
					"Add each push credential's host to the run's egress allow list, or remove that credential.\nThe push credential %s is for %s, which no allow entry covers.", name, shown)
			}
		}
	}
	return nil
}

// PushUses are the run configuration's push credentials as the push proxy sets them,
// one per item of where the start's answer sets each ([Run.open]), nil when there are
// none. Each one's Value copies the value under r.mu, as [Run.storedUses]' do; a value
// with expires_at has the renewer's Rejected. Call it after [Run.Hold].
func (r *Run) PushUses() []proxy.Credential {
	var out []proxy.Credential
	for _, c := range r.stored {
		if !c.Push() {
			continue
		}
		name := c.Name
		value := func() []byte {
			r.mu.Lock()
			defer r.mu.Unlock()
			b, _ := r.values.Value(name)
			return slices.Clone(b)
		}
		for _, a := range r.applies[name] {
			out = append(out, proxy.Credential{Name: name, Hosts: slices.Clone(a.Hosts), Scheme: a.Scheme, Username: a.Username, Header: a.Header,
				Paths: slices.Clone(a.Paths), PushRef: a.PushRef, Value: value, Stored: true, Rejected: r.renew.rejected(name)})
		}
	}
	return out
}
