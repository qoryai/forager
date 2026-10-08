// Package variables resolves the variables a run's agent receives, name by name, from
// the sources that set them, and records where each came from and what lost.
//
// The sources form rungs, the highest first: the run's fixed names, the runner's, the
// wall's, the runtime preparation's, the placeholders and the values the harness
// computes; the server's, which it resolved among its own levels; the run's own, --env
// for qory; the machine's, wall.env; the harness's written defaults; and the
// environment the run inherits. For each name the highest rung that sets it wins.
//
// [Resolve] refuses first what must stay outside the enclosure, [Check], over every
// value the node passes. The deny list then leaves out a value of the server, the run,
// the machine or the harness's defaults; its built-in entries apply to the harness's
// computed values too. What loses never stops the run, and [Resolved.Applied] lists
// each name with its source and its losses, as dev.qory.run.policy_applied reports
// them.
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
	"github.com/qoryai/runner/refusal"
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

// The sources of a variable, the highest rung first, as the record names them.
const (
	FromFixed   = "fixed"
	FromApiary  = "apiary"
	FromRun     = "run"
	FromMachine = "machine"
	FromHarness = "harness"
	FromShell   = "shell"
)

// Why a source's value of a name lost: another source's value won, the deny list
// matched it, the name is one of the run's fixed names, or the run has no wall and
// takes none of the server's.
const (
	WhyOverridden = "overridden"
	WhyDenied     = "denied"
	WhyFixed      = "fixed"
	WhyUnwalled   = "unwalled"
)

// Inputs is what the resolution of one run's variables takes. Each list of values is
// NAME=value; within one list a later value replaces an earlier one of the same name.
type Inputs struct {
	// Fixed is the values the harness computes itself, the launch's fixed values.
	Fixed []string
	// Server is the server's variables, by name; nil when the run has none.
	Server map[string]string
	// Run is the run's own variables, --env for qory.
	Run []string
	// Machine is the machine's variables, wall.env for qory.
	Machine []string
	// Defaults is the harness's written defaults.
	Defaults []string
	// Shell is the environment the run inherits.
	Shell []string
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
	// ReadFrom is the names of the variables the machine's values are read from.
	ReadFrom []string
	// Runner is the names the runner, the wall and the runtime's preparation set: with
	// the placeholders and Fixed, the run's fixed names.
	Own []string
}

// Resolved is what a run applies of the variables, and the record of it.
type Resolved struct {
	// Env is the values of the server, the run, the machine and the harness's defaults
	// the run applies, NAME=value, sorted by name. What wins of the inherited
	// environment stays in it, and the fixed names go over both.
	Env []string
	// Fixed is the harness's computed values the built-in list leaves in, in order.
	Fixed []string
	// Applied is the record: one entry for each name a source below the fixed names
	// set, sorted by name. The inherited environment's value of a name is in it only
	// when such a source set the name too.
	Applied []Entry
}

// Entry is one name of the record: the source whose value the run applies, empty when
// none, and the values that lost, the highest rung first. A fixed name's From is
// [FromFixed].
type Entry struct {
	Name string `json:"name"`
	From string `json:"from,omitempty"`
	Lost []Loss `json:"lost"`
}

// Loss is one source's value that lost, and why.
type Loss struct {
	From string `json:"from"`
	Why  string `json:"why"`
}

// Resolve resolves a run's variables. It checks the node's deny entries and the
// unwalled mode, then refuses what the run passes into the enclosure ([Check]) over
// every value the node passes: Fixed, Run, Machine, Defaults and Shell. The server's
// values cannot be refused: the names Check refuses are on the built-in list, fixed or
// read from, and are left out.
//
// Then, name by name, the highest rung that sets it wins. The fixed names win over
// every other source. The server's value is left out in an unwalled run under
// [Ignore], when the deny list matches the name, and when the runtime declares or
// reserves it or a value of the machine's is read from it. A value of the run, the
// machine or the harness's defaults is left out when the deny list matches it. A value
// of the harness's computed ones is left out when the built-in list matches it; the
// runtime's denies and the node's entries leave it in. The inherited environment's
// values are not matched against the deny list.
func Resolve(in Inputs) (Resolved, error) {
	if err := CheckDeny(in.Deny); err != nil {
		return Resolved{}, err
	}
	if in.Unwalled != "" && in.Unwalled != Ignore && in.Unwalled != Accept {
		return Resolved{}, fmt.Errorf("variables.unwalled is %q, neither %s nor %s", in.Unwalled, Accept, Ignore)
	}
	passed := slices.Concat(in.Fixed, in.Run, in.Machine, in.Defaults, in.Shell)
	if err := Check(passed, in.Walled, in.Placeholders, in.ReadFrom); err != nil {
		return Resolved{}, err
	}
	deny, err := List(append(slices.Clone(in.Deny), in.RuntimeDenies...))
	if err != nil {
		return Resolved{}, err
	}
	builtin, err := List(nil)
	if err != nil {
		return Resolved{}, err
	}
	out := Resolved{Env: []string{}, Fixed: []string{}, Applied: []Entry{}}
	fixed := map[string]bool{}
	for _, name := range slices.Concat(in.Own, in.Placeholders) {
		fixed[name] = true
	}
	deniedFixed := map[string]bool{}
	for _, kv := range in.Fixed {
		name, _, _ := strings.Cut(kv, "=")
		if builtin.Matches(name) {
			deniedFixed[name] = true
			continue
		}
		out.Fixed = append(out.Fixed, kv)
		fixed[name] = true
	}
	run, machine, defaults, shell := byName(in.Run), byName(in.Machine), byName(in.Defaults), byName(in.Shell)
	names := maps.Clone(deniedFixed)
	for _, m := range []map[string]string{in.Server, run, machine, defaults} {
		for name := range m {
			names[name] = true
		}
	}
	setOtherwise := slices.Concat(in.Runtime, in.ReadFrom)
	for _, name := range slices.Sorted(maps.Keys(names)) {
		e := Entry{Name: name, Lost: []Loss{}}
		if deniedFixed[name] {
			e.Lost = append(e.Lost, Loss{FromFixed, WhyDenied})
		}
		if fixed[name] {
			e.From = FromFixed
		}
		value := ""
		take := func(from string, v string, ok bool, why string) {
			switch {
			case !ok:
			case why != "":
				e.Lost = append(e.Lost, Loss{from, why})
			case fixed[name]:
				e.Lost = append(e.Lost, Loss{from, WhyFixed})
			case e.From != "":
				e.Lost = append(e.Lost, Loss{from, WhyOverridden})
			default:
				e.From, value = from, v
			}
		}
		v, ok := in.Server[name]
		why := ""
		switch {
		case !in.Walled && in.Unwalled != Accept:
			why = WhyUnwalled
		case deny.Matches(name) || slices.Contains(setOtherwise, name):
			why = WhyDenied
		}
		take(FromApiary, v, ok, why)
		for _, s := range []struct {
			from string
			m    map[string]string
		}{{FromRun, run}, {FromMachine, machine}, {FromHarness, defaults}} {
			v, ok := s.m[name]
			why := ""
			if deny.Matches(name) {
				why = WhyDenied
			}
			take(s.from, v, ok, why)
		}
		v, ok = shell[name]
		take(FromShell, v, ok, "")
		switch e.From {
		case FromApiary, FromRun, FromMachine, FromHarness:
			out.Env = append(out.Env, name+"="+value)
		}
		out.Applied = append(out.Applied, e)
	}
	return out, nil
}

// byName are NAME=value entries by name, a later one replacing an earlier one.
func byName(env []string) map[string]string {
	out := map[string]string{}
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		out[name] = value
	}
	return out
}

// Check refuses a run whose own environment, env, NAME=value, passes into the
// enclosure what stays outside. In a walled run, a QORY_ variable other than the two
// the runner sets for the session, or a variable a machine value is read from, is
// [refusal.VariableReserved]. In any run, a value for a placeholder is
// [refusal.PlaceholderConflict].
func Check(env []string, walled bool, placeholders, machine []string) error {
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
