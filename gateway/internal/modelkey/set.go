package modelkey

import "slices"

// Set is a run's key groups, one per group value of the run configuration's API
// credentials, in the order of each group's first key: each [Group] has its rotation,
// cooldowns, active key, pass and stop apart from every other group's. A key is in one
// group only. The methods of a nil Set report nothing and change nothing; they are safe
// for concurrent use.
type Set struct {
	groups []*Group
	// order are the keys of every group in the order of the run configuration's
	// credentials, which the windows and the keys out of use after a 401 follow.
	order []string
}

// NewSet makes the set of groups. order are the names of every group's keys in the
// order of the run configuration's credentials.
func NewSet(groups []*Group, order []string) *Set {
	return &Set{groups: slices.Clone(groups), order: slices.Clone(order)}
}

// Groups are the set's groups, in their order.
func (s *Set) Groups() []*Group {
	if s == nil {
		return nil
	}
	return slices.Clone(s.groups)
}

// Of is the group of key name, nil when name is no key of the set.
func (s *Set) Of(name string) *Group {
	if s == nil {
		return nil
	}
	for _, g := range s.groups {
		if g.Has(name) {
			return g
		}
	}
	return nil
}

// Has reports whether name is a key of a group of the set.
func (s *Set) Has(name string) bool { return s.Of(name) != nil }

// place is the place of key name in the order, len(order) for none.
func (s *Set) place(name string) int {
	if i := slices.Index(s.order, name); i >= 0 {
		return i
	}
	return len(s.order)
}

// OnChange sets f on every group, [Group.OnChange].
func (s *Set) OnChange(f func()) {
	if s == nil {
		return
	}
	for _, g := range s.groups {
		g.OnChange(f)
	}
}

// Snapshot is the windows of every group, by the order of the keys, and the sum of the
// groups' change counts: each group's windows and count are read under that group's
// lock, so the windows cover every change up to the sum.
func (s *Set) Snapshot() ([]Window, uint64) {
	if s == nil {
		return nil, 0
	}
	var out []Window
	var changes uint64
	for _, g := range s.groups {
		ws, n := g.Snapshot()
		out = append(out, ws...)
		changes += n
	}
	slices.SortStableFunc(out, func(a, b Window) int { return s.place(a.Credential) - s.place(b.Credential) })
	return out, changes
}

// Changes is the sum of the groups' change counts, [Group.Changes].
func (s *Set) Changes() uint64 {
	var n uint64
	for _, g := range s.Groups() {
		n += g.Changes()
	}
	return n
}

// Merge gives each group the entries of its keys, [Group.Merge].
func (s *Set) Merge(entries []Window) {
	for _, g := range s.Groups() {
		g.Merge(entries)
	}
}

// Unauthorized are the keys of every group that got a 401 and that no renewal brought
// back, [Group.Unauthorized], by the order of the keys, at most [maxUnauthorized] in
// all; nil for none.
func (s *Set) Unauthorized() []Unauthorized {
	var out []Unauthorized
	for _, g := range s.Groups() {
		out = append(out, g.Unauthorized()...)
	}
	if s != nil {
		slices.SortStableFunc(out, func(a, b Unauthorized) int { return s.place(a.Credential) - s.place(b.Credential) })
	}
	if len(out) > maxUnauthorized {
		out = out[:maxUnauthorized]
	}
	return out
}

// Restore gives each group the keys of a run's record after a 401 that are its keys,
// [Group.Restore].
func (s *Set) Restore(keys []Unauthorized) {
	for _, g := range s.Groups() {
		g.Restore(keys)
	}
}

// Pending reports whether key name got a 401 and its renewal is pending,
// [Group.Pending].
func (s *Set) Pending(name string) bool {
	if g := s.Of(name); g != nil {
		return g.Pending(name)
	}
	return false
}

// Renewed puts key name back in its group after a renewal that followed its 401,
// [Group.Renewed].
func (s *Set) Renewed(name string) {
	if g := s.Of(name); g != nil {
		g.Renewed(name)
	}
}

// Revoked takes key name out of its group after a renewal that ended with no value,
// [Group.Revoked].
func (s *Set) Revoked(name string) {
	if g := s.Of(name); g != nil {
		g.Revoked(name)
	}
}

// Passed reports whether a group of the set passed a limit refusal or a 401 to the
// session since its last [Group.Resume].
func (s *Set) Passed() bool {
	return slices.ContainsFunc(s.Groups(), (*Group).Passed)
}

// Resume clears the pass and the stop of every group, [Group.Resume].
func (s *Set) Resume() {
	for _, g := range s.Groups() {
		g.Resume()
	}
}
