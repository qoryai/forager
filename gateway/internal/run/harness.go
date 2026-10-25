package run

import (
	"slices"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
)

// hasHarness reports whether the run configuration the run started with has a harness
// credential.
func (r *Run) hasHarness() bool {
	return slices.ContainsFunc(r.stored, func(c server.RunCredential) bool { return c.Harness() })
}

// HarnessHidden is harness_hidden of the run configuration the run started with: true
// when the run's harness belongs to an organisation other than the run's. It is fixed
// for the run.
func (r *Run) HarnessHidden() bool { return r.hidden }

// StackAllows reports whether the run's stack proxy allows host, an exact host: an
// entry of [Config.StackHosts] matches it, or [Run.StackChecked] allows it.
func (r *Run) StackAllows(host string) bool {
	if _, ok := policy.Match(r.cfg.StackHosts, host); ok {
		return true
	}
	return r.StackChecked(host) == StackAllowed
}

// checkHarness refuses, run_configuration_invalid with the credential's name, a harness
// credential of the run configuration the run starts with that the stack proxy cannot
// set: one with placeholders, which no session gets; one with a host the stack proxy
// does not allow ([Run.StackAllows]); and two items of harness credentials that claim
// one host when one of them has no paths, or when their paths overlap. A work
// credential on the same host is no conflict: no proxy sets both.
func (r *Run) checkHarness() error {
	type item struct {
		name  string
		hosts []string
		paths []string
	}
	var items []item
	for _, c := range r.stored {
		if !c.Harness() {
			continue
		}
		name := accesskey.ShownName(c.Name, true)
		if len(c.Placeholders) > 0 {
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
				"Remove placeholders from the harness credential %s: no session gets it", name)
		}
		for _, a := range c.Applies() {
			for _, h := range a.Hosts {
				if r.StackAllows(h) {
					continue
				}
				host := accesskey.ShownValue(h, false)
				switch r.StackChecked(h) {
				case StackNodeRefuses:
					return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
						"Allow %s in the node's policy: the harness credential %s is for it", host, name)
				case StackNodePaths:
					return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
						"List %s in gateway.stack_hosts: node path rules cover the harness credential %s", host, name)
				}
				return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
					"Add %s to a stack_hosts list: the harness credential %s is for it", host, name)
			}
			items = append(items, item{c.Name, a.Hosts, a.Paths})
		}
	}
	for i, u := range items {
		for _, other := range items[:i] {
			for _, host := range u.hosts {
				if !slices.ContainsFunc(other.hosts, func(theirs string) bool { return policy.Covers(theirs, host) || policy.Covers(host, theirs) }) {
					continue
				}
				first, second, shown := accesskey.ShownName(other.name, false), accesskey.ShownName(u.name, false), accesskey.ShownValue(host, false)
				names := refusal.Shown(other.name, u.name)
				if len(u.paths) == 0 || len(other.paths) == 0 {
					return refusal.New(refusal.RunConfigurationInvalid, names,
						"Claim %s in only one of the harness credentials %s and %s: one has no paths", shown, first, second)
				}
				for _, x := range other.paths {
					if slices.ContainsFunc(u.paths, func(y string) bool { return policy.CoversPath(x, y) || policy.CoversPath(y, x) }) {
						return refusal.New(refusal.RunConfigurationInvalid, names,
							"Give the harness credentials %s and %s paths that do not overlap on %s", first, second, shown)
					}
				}
			}
		}
	}
	return nil
}

// StackUses are the run configuration's harness credentials as the stack proxy sets
// them, one per item of where the start's answer sets each ([Run.open]), nil when there
// are none. Each one's Value copies the value under r.mu, as [Run.storedUses]' do; a
// value with expires_at has the renewer's Rejected. Call it after [Run.Hold].
func (r *Run) StackUses() []proxy.Credential {
	var out []proxy.Credential
	for _, c := range r.stored {
		if !c.Harness() {
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
				Paths: slices.Clone(a.Paths), Value: value, Stored: true, Rejected: r.renew.rejected(name)})
		}
	}
	return out
}

// CloseHarness stops the renewals of the run configuration's harness credentials and
// overwrites their values with zeros, once the stack proxy closes: from then on
// [Run.StackUses]' values are empty, and no renewal in flight puts one back.
func (r *Run) CloseHarness() {
	var names []string
	for _, c := range r.stored {
		if c.Harness() {
			names = append(names, c.Name)
		}
	}
	if len(names) == 0 {
		return
	}
	r.renew.drop(names)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.harnessClosed = true
	for _, name := range names {
		r.values.Drop(name)
	}
}

// harnessGone reports whether name is a harness credential whose value
// [Run.CloseHarness] cleared. Called with r.mu held.
func (r *Run) harnessGone(name string) bool {
	return r.harnessClosed && slices.ContainsFunc(r.stored, func(c server.RunCredential) bool { return c.Name == name && c.Harness() })
}
