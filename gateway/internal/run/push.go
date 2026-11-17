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

// checkPush returns run_configuration_invalid, with the credential's name, for a push
// credential of the run configuration the run starts with that the push proxy cannot
// set: one with placeholders, which no session gets, and two items of push credentials,
// of one credential or of two, that are for one exact host when one of them has no
// paths, or when their paths overlap. A work or harness credential on the same host is
// no conflict: no proxy sets two purposes.
func (r *Run) checkPush() error {
	var items []claim
	for _, c := range r.stored {
		if !c.Push() {
			continue
		}
		if len(c.Placeholders) > 0 {
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
				"Remove placeholders from push credentials: no session gets a push credential.\nThe push credential %s has placeholders.", accesskey.ShownName(c.Name, true))
		}
		for _, a := range c.Applies() {
			items = append(items, claim{c.Name, a.Hosts, a.Paths})
		}
	}
	c, ok := firstConflict(items)
	if !ok {
		return nil
	}
	first, second, shown := accesskey.ShownName(c.first, true), accesskey.ShownName(c.second, true), accesskey.ShownValue(c.host, false)
	switch {
	case c.one && c.pathless:
		return refusal.New(refusal.RunConfigurationInvalid, c.names(),
			pushNoPaths+"\nThe push credential %s is for %s in two apply items, and one of them has no paths.", first, shown)
	case c.pathless:
		return refusal.New(refusal.RunConfigurationInvalid, c.names(),
			pushNoPaths+"\nThe push credentials %s and %s are both for %s, and one of them has no paths.", first, second, shown)
	case c.one:
		return refusal.New(refusal.RunConfigurationInvalid, c.names(),
			pushOverlap+"\nThe push credential %s has apply items with overlapping paths on %s.", first, shown)
	}
	return refusal.New(refusal.RunConfigurationInvalid, c.names(),
		pushOverlap+"\nThe push credentials %s and %s have overlapping paths on %s.", first, second, shown)
}

// The first lines of the refusals of push credential items on one host.
const (
	pushNoPaths = "Give paths to every apply item of a push credential on a host that another push item is for."
	pushOverlap = "Change the paths of push credential items on one host so that they do not overlap."
)

// checkPushHosts returns run_configuration_invalid for a host of a push credential's
// items that the push proxy would reach where the run's proxy would not: one that pol,
// the policy in force, under the node's policy, does not allow ([policy.Egress.Allows]),
// by a deny entry or, under enforce, by no allow entry, and one that a path rule of the
// node's covers, since the push proxy checks no path rule of a policy. Decide runs it
// before the secrets request, so a refused run fetches no value; [Run.hold] runs it
// again for each reload, whose policy may deny a push host that the start allowed.
func (r *Run) checkPushHosts(pol *policy.Loaded) error {
	egress := pol.Policy.Egress
	paths := slices.Clone(r.beside)
	if r.node != nil {
		paths = append(paths, r.node.Policy.Egress.Paths)
	}
	for _, c := range r.stored {
		if !c.Push() {
			continue
		}
		for _, a := range c.Applies() {
			for _, h := range a.Hosts {
				name, shown := accesskey.ShownName(c.Name, true), accesskey.ShownValue(h, false)
				if !egress.Allows(h) {
					if _, denied := policy.Match(egress.Deny, h); denied {
						return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
							"Remove each push credential's host from the egress deny lists.\nThe push credential %s is for %s, which a deny entry covers.", name, shown)
					}
					return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
						"Add each push credential's host to the run's egress allow list.\nThe push credential %s is for %s, which no allow entry covers.", name, shown)
				}
				for _, side := range paths {
					if _, _, ok := policy.HostPaths(side, h); ok {
						return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
							"Remove the node's path rules for each push credential's host: the push proxy checks none.\nThe push credential %s is for %s, which a path rule of the node covers.", name, shown)
					}
				}
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

// claim is one apply item of a harness or a push credential: the credential's name, and
// the item's hosts and paths.
type claim struct {
	name  string
	hosts []string
	paths []string
}

// conflict is two claims on one exact host that one proxy cannot set both of: first
// and second are the credentials' names, one whether they are one credential, and
// pathless whether one of the claims has no paths; otherwise their paths overlap.
type conflict struct {
	first, second, host string
	one, pathless       bool
}

// names are the names of a refusal of c: the credential once, or both.
func (c conflict) names() []string {
	if c.one {
		return refusal.Shown(c.first)
	}
	return refusal.Shown(c.first, c.second)
}

// firstConflict is the first conflict among items, in their order, and whether there is
// one.
func firstConflict(items []claim) (conflict, bool) {
	for i, u := range items {
		for _, other := range items[:i] {
			for _, host := range u.hosts {
				if !slices.Contains(other.hosts, host) {
					continue
				}
				c := conflict{first: other.name, second: u.name, host: host, one: other.name == u.name}
				if len(u.paths) == 0 || len(other.paths) == 0 {
					c.pathless = true
					return c, true
				}
				for _, x := range other.paths {
					if slices.ContainsFunc(u.paths, func(y string) bool { return policy.OverlapPaths(x, y) }) {
						return c, true
					}
				}
			}
		}
	}
	return conflict{}, false
}
