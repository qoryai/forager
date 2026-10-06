// Package variables resolves the variables a run's agent receives: the server's,
// which lead, and the node's own, which only add names.
//
// [Resolve] takes the server's variables, from the run configuration, and the node's,
// and returns what the run applies with the names it left out and why, as
// dev.qory.run.policy_applied reports them. [Check] refuses a run whose own environment
// passes into the enclosure what must stay outside: the runner's own variables, a
// variable a machine value is read from, a variable the runtime declares or reserves,
// a value for a placeholder.
//
// The deny list is the contract's denied-variables.json, the run's runtime's denies
// and the node's own entries. An entry is a name or a pattern in which * matches any
// run of characters, the empty run included; it matches a whole name, regardless of
// case, because programs read http_proxy and HTTP_PROXY alike. Every other comparison
// of names is exact.
package variables

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/qoryai/runner/contracts"
	"github.com/qoryai/runner/internal/refusal"
)

// Ignore and Accept are the two ways an unwalled run takes the server's variables:
// Ignore, the default, leaves them all out, and Accept applies them as a walled run
// does.
const (
	Ignore = "ignore"
	Accept = "accept"
)

// The variables the runner sets for the session itself, the one QORY_ names a run's
// environment may contain.
const (
	envRunID  = "QORY_RUN_ID"
	envSocket = "QORY_RUN_SOCKET"
)

// Run is what the resolution of one run's variables takes.
type Run struct {
	// Server is the server's variables, by name; nil when the run has none.
	Server map[string]string
	// Node is the node's own variables, NAME=value; a later one replaces an earlier
	// one of the same name.
	Node []string
	// Walled says the run has a wall.
	Walled bool
	// Unwalled is how an unwalled run takes the server's variables: [Accept], or
	// [Ignore], which empty means.
	Unwalled string
	// Deny is the node's own entries for the deny list.
	Deny []string
	// RuntimeDenies is the run's runtime's denies.
	RuntimeDenies []string
	// Runtime is the variables the run's runtime declares or reserves.
	Runtime []string
	// Placeholders is the names of the run's placeholders.
	Placeholders []string
	// Machine is the names of the variables the machine's values are read from.
	Machine []string
	// Runner is the names the runtime's Prepare, the harness's launch and the wall set:
	// the runner's own, which win over a server's variable of the same name.
	Runner []string
}

// Resolved is what a run applies of the variables, and what it left out.
type Resolved struct {
	// Env is the variables the run applies, NAME=value, sorted by name: the server's
	// it applies and the node's it adds.
	Env []string
	// Names is the names of Env. Denied is the server's variables left out by the
	// deny list or because the run sets that name otherwise; Unwalled the server's
	// variables an unwalled run left out under [Ignore]; NodeIgnored the node's
	// variables left out because the run applies the server's value for that name.
	// Each list is sorted and is empty, not nil, when nothing is in it.
	Names, Denied, Unwalled, NodeIgnored []string
}

// Resolve resolves a run's variables. An unwalled run under [Ignore] leaves out every
// server variable. Otherwise a server variable is left out when the deny list matches
// its name, or when it is a variable the runtime declares or reserves, a placeholder, a
// variable a machine value is read from, or one the runner sets. A node's variable
// applies for every name whose server value the run does not apply, and is left out
// otherwise. The node's deny entries are checked first.
func Resolve(r Run) (Resolved, error) {
	if err := CheckDeny(r.Deny); err != nil {
		return Resolved{}, err
	}
	if r.Unwalled != "" && r.Unwalled != Ignore && r.Unwalled != Accept {
		return Resolved{}, fmt.Errorf("variables.unwalled is %q, neither %s nor %s", r.Unwalled, Accept, Ignore)
	}
	deny, err := List(append(slices.Clone(r.Deny), r.RuntimeDenies...))
	if err != nil {
		return Resolved{}, err
	}
	out := Resolved{Names: []string{}, Denied: []string{}, Unwalled: []string{}, NodeIgnored: []string{}}
	applied := map[string]string{}
	fromServer := map[string]bool{}
	setOtherwise := slices.Concat(r.Runtime, r.Placeholders, r.Machine, r.Runner)
	for _, name := range slices.Sorted(maps.Keys(r.Server)) {
		switch {
		case !r.Walled && r.Unwalled != Accept:
			out.Unwalled = append(out.Unwalled, name)
		case deny.Matches(name) || slices.Contains(setOtherwise, name):
			out.Denied = append(out.Denied, name)
		default:
			applied[name], fromServer[name] = r.Server[name], true
		}
	}
	node := map[string]string{}
	for _, kv := range r.Node {
		name, value, _ := strings.Cut(kv, "=")
		node[name] = value
	}
	for _, name := range slices.Sorted(maps.Keys(node)) {
		if fromServer[name] {
			out.NodeIgnored = append(out.NodeIgnored, name)
			continue
		}
		applied[name] = node[name]
	}
	out.Names = append(out.Names, slices.Sorted(maps.Keys(applied))...)
	for _, name := range out.Names {
		out.Env = append(out.Env, name+"="+applied[name])
	}
	return out, nil
}

// Check refuses a run whose own environment, env, NAME=value, passes into the
// enclosure what stays outside. In a walled run: a QORY_ variable other than the two
// the runner sets for the session, or a variable a machine value is read from, is
// [refusal.VariableReserved]; a variable the runtime declares or reserves is
// [refusal.RuntimeSecretConflict]. In any run, a value for a placeholder is
// [refusal.PlaceholderConflict].
func Check(env []string, walled bool, runtime, placeholders, machine []string) error {
	names := map[string]bool{}
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		names[name] = true
	}
	sorted := slices.Sorted(maps.Keys(names))
	pick := func(keep func(string) bool) []string {
		var out []string
		for _, name := range sorted {
			if keep(name) {
				out = append(out, name)
			}
		}
		return out
	}
	if walled {
		if reserved := pick(func(n string) bool {
			own := strings.HasPrefix(strings.ToUpper(n), "QORY_") && n != envRunID && n != envSocket
			return own || slices.Contains(machine, n)
		}); len(reserved) > 0 {
			return refusal.New(refusal.VariableReserved, reserved, "the run passes %s into the enclosure, the runner's own or what a value of the machine's is read from", strings.Join(reserved, ", "))
		}
		if conflict := pick(func(n string) bool { return slices.Contains(runtime, n) }); len(conflict) > 0 {
			return refusal.New(refusal.RuntimeSecretConflict, conflict, "the run passes %s into the enclosure, which the runtime reads its credential from; behind a wall the runtime's credential stays outside", strings.Join(conflict, ", "))
		}
	}
	if conflict := pick(func(n string) bool { return slices.Contains(placeholders, n) }); len(conflict) > 0 {
		return refusal.New(refusal.PlaceholderConflict, conflict, "the run passes a value for %s, a placeholder of what the runner holds outside the enclosure", strings.Join(conflict, ", "))
	}
	return nil
}

// entryShape is a deny entry's form: a name or a pattern of at most 128 characters
// with at least one character other than *.
var entryShape = regexp.MustCompile(`^[A-Za-z0-9_*]{1,128}$`)

// CheckDeny refuses a node's deny entries that are not names or patterns.
func CheckDeny(entries []string) error {
	for _, e := range entries {
		if !entryShape.MatchString(e) || strings.Trim(e, "*") == "" {
			return fmt.Errorf("variables.deny: %q is neither a variable's name nor a pattern of letters, digits, underscores and *", e)
		}
	}
	return nil
}

// Deny is a deny list: the contract's built-in names and patterns with a run's own
// entries.
type Deny struct {
	names    map[string]bool
	patterns []string
}

// List is the built-in deny list with the entries added.
func List(entries []string) (*Deny, error) {
	builtin, err := Builtin()
	if err != nil {
		return nil, err
	}
	d := &Deny{names: map[string]bool{}}
	for _, e := range slices.Concat(builtin.Names, builtin.Patterns, entries) {
		e = strings.ToUpper(e)
		if strings.Contains(e, "*") {
			d.patterns = append(d.patterns, e)
		} else {
			d.names[e] = true
		}
	}
	return d, nil
}

// Matches reports whether an entry of the list matches the whole name, regardless of
// case.
func (d *Deny) Matches(name string) bool {
	name = strings.ToUpper(name)
	if d.names[name] {
		return true
	}
	return slices.ContainsFunc(d.patterns, func(p string) bool { return glob(p, name) })
}

// glob reports whether pattern, in which * matches any run of characters, the empty
// run included, matches the whole of name.
func glob(pattern, name string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == name
	}
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	name = name[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(name, part)
		if i < 0 {
			return false
		}
		name = name[i+len(part):]
	}
	return len(name) >= len(last) && strings.HasSuffix(name, last)
}

// Denied is the document denied-variables.json.
type Denied struct {
	Version  int      `json:"version"`
	Names    []string `json:"names"`
	Patterns []string `json:"patterns"`
}

var builtin = sync.OnceValues(func() (*Denied, error) {
	b, err := fs.ReadFile(contracts.FS, "denied-variables.json")
	if err != nil {
		return nil, err
	}
	var d Denied
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("denied-variables.json: %w", err)
	}
	return &d, nil
})

// Builtin is the contract's built-in deny list, denied-variables.json.
func Builtin() (*Denied, error) { return builtin() }
