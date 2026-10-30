// Package variables resolves the variables a run's agent receives, name by name, from
// the sources that set them, and records where each came from and what lost.
//
// The sources form rungs, the highest first: the run's fixed names, Forager's, the
// wall's, the runtime preparation's, the placeholders and the values the harness
// computes; the server's, which it resolved among its own levels; the run's own, --env
// for qory; the machine's, wall.env; the harness's written defaults; and the
// environment the run inherits. For each name the highest rung that sets it wins.
//
// [Resolve] refuses first what must stay outside the enclosure, [Check], over every
// value the node passes. The deny list then leaves out a value of the server, the run,
// the machine or the harness's defaults; its built-in entries apply to the harness's
// computed values too. Behind a wall, the runtime's overrides join the deny list and
// apply to the harness's computed values as well. Behind a wall, the endpoint rule
// takes the place of the runtime's denies for the variable the runtime reads its model
// endpoint from: a value applies only when its host is a host of the run's model
// credential. What loses never stops the run, and [Resolved.Applied] lists each name
// with its source and its losses, as dev.qory.run.policy_applied reports them.
//
// The deny list is the contract's denied-variables.json, the run's runtime's denies
// and the node's own entries. An entry is a name or a pattern in which * matches any
// run of characters, the empty run included; it matches a whole name, regardless of
// case, because programs read http_proxy and HTTP_PROXY alike. Every other comparison
// of names is exact.
package variables

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
)

// Ignore and Accept are the two ways an unwalled run takes the server's variables:
// Ignore, the default, leaves them all out, and Accept applies them as a walled run
// does.
const (
	Ignore = "ignore"
	Accept = "accept"
)

// The variables Forager sets for the session itself, the one QORY_ names a run's
// environment may contain.
const (
	envRunID  = "QORY_RUN_ID"
	envSocket = "QORY_RUN_SOCKET"
)

// The QORY_ names the server's variables may set, by these names exactly: the system
// and the repositories a session's setup commands may use, as the server sets them. The
// built-in deny list leaves the server's values of them in; every other source that
// sets one is held to the rules of any QORY_ name.
const (
	envRunSystem       = "QORY_RUN_SYSTEM"
	envRunRepositories = "QORY_RUN_REPOSITORIES"
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
// matched it, the name is one of the run's fixed names, the run has no wall and takes
// none of the server's, or, of the endpoint's variable under the endpoint rule, the value's host
// is none of the hosts of the run's model credential or the value is not an https URL
// with a host [policy.EndpointHost] reads.
const (
	WhyOverridden         = "overridden"
	WhyDenied             = "denied"
	WhyFixed              = "fixed"
	WhyUnwalled           = "unwalled"
	WhyEndpointUncovered  = "endpoint_uncovered"
	WhyEndpointUnreadable = "endpoint_unreadable"
)

// KeptEndpointCovered is why a value of the endpoint's variable applies under the
// endpoint rule: its host is a host of the run's model credential.
const KeptEndpointCovered = "endpoint_covered"

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
	// Overrides is the run's runtime's model overrides: the variables that would
	// override the model id or effort value a composer writes. Only a walled run
	// applies them.
	Overrides []string
	// Runtime is the variables the run's runtime declares or reserves.
	Runtime []string
	// Placeholders is the names of the run's placeholders.
	Placeholders []string
	// ReadFrom is the names of the variables the machine's values are read from.
	ReadFrom []string
	// Own is the names Forager, the wall and the runtime's preparation set: with
	// the placeholders and Fixed, the run's fixed names.
	Own []string
	// Endpoint is the variable the run's runtime reads the base URL of its model API
	// from, its descriptor's model.endpoint.variable; empty when it has none. A walled
	// run applies the endpoint rule to it, and an unwalled one with Credentials.
	Endpoint string
	// EndpointFixed says the run's start key sets Endpoint, and Own lists it: every
	// value of it is left out as [WhyFixed], the harness's computed ones included, and
	// the endpoint rule does not apply.
	EndpointFixed bool
	// KeysFixed is the variables the run's runtime reads a model key from other than
	// the one the start key sets: a value of each, from every source the inherited
	// environment included, is left out as [WhyFixed], and none of them is set.
	KeysFixed []string
	// Credentials is each credential the gateway holds for the run, as the run
	// answer's credential_hosts lists them. A model credential is one with a
	// placeholder among Runtime.
	Credentials []Credential
}

// Credential is one credential the gateway holds for a run: its name, the hosts the
// gateway's proxy sets it on, and the variables set to a placeholder for it.
type Credential struct {
	Name         string
	Hosts        []string
	Placeholders []string
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
// [FromFixed]. Kept is set when the value that applies is a value of the endpoint's
// variable that the endpoint rule checked.
type Entry struct {
	Name string `json:"name"`
	From string `json:"from,omitempty"`
	Lost []Loss `json:"lost"`
	Kept *Kept  `json:"kept,omitempty"`
}

// Kept is why the endpoint rule kept a value: [KeptEndpointCovered], and the name of
// the model credential whose hosts include the value's host, as [accesskey.ShownName]
// prints it unquoted.
type Kept struct {
	Why        string `json:"why"`
	Credential string `json:"credential"`
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
// reserves it or a value of the machine's is read from it; of QORY_RUN_SYSTEM and
// QORY_RUN_REPOSITORIES, only the runtime's denies and the node's entries of the deny
// list leave it out, not the built-in list. A value of the run, the
// machine or the harness's defaults is left out when the deny list matches it. A value
// of the harness's computed ones is left out when the built-in list matches it; the
// runtime's denies and the node's entries leave it in. Behind a wall, the runtime's
// overrides are entries of the deny list, and a value of the harness's computed ones
// whose name is one of them is left out too. The inherited environment's values are
// not matched against the deny list.
//
// Behind a wall, and without one when in.Credentials is not empty, the endpoint rule
// applies to each value of in.Endpoint of the server,
// the run, the machine, the harness's defaults and the harness's computed ones, in
// place of the runtime's denies. The other entries of the deny list that cover the
// source, and the rules for the server's value, apply first, as for any name. Every
// computed value of the name is checked: when one is left out, all of them are, with
// the first one's reason, and when none is, the last one alone stays in Fixed. A value
// from which [policy.EndpointHost] reads no host is left out as
// [WhyEndpointUnreadable], and one whose host is in no model credential's hosts by
// [policy.CredentialFor] as [WhyEndpointUncovered]; another is not left out, and when
// it applies, the entry's Kept has the first model credential whose hosts include it.
// A value left out lets the next source's value apply, as a denied one does. With
// in.EndpointFixed, the start key's endpoint is in.Endpoint's one value: every other
// value of it, the harness's computed ones included, is left out as [WhyFixed]. Every
// value of a name of in.KeysFixed is left out as [WhyFixed] too, the inherited one
// included, and the entry has no from: the caller sets none of them.
func Resolve(in Inputs) (Resolved, error) {
	if err := CheckDeny(in.Deny); err != nil {
		return Resolved{}, err
	}
	if in.Unwalled != "" && in.Unwalled != Ignore && in.Unwalled != Accept {
		return Resolved{}, fmt.Errorf("variables.unwalled is %s, neither %s nor %s", accesskey.ShownValue(in.Unwalled, true), Accept, Ignore)
	}
	// Without a wall what the run inherits is the developer's environment, and a
	// placeholder wins over a value of it: it passes nothing into an enclosure.
	passed := slices.Concat(in.Fixed, in.Run, in.Machine, in.Defaults)
	if in.Walled {
		passed = append(passed, in.Shell...)
	}
	if err := Check(passed, in.Walled, in.Placeholders, in.ReadFrom); err != nil {
		return Resolved{}, err
	}
	added := append(slices.Clone(in.Deny), in.RuntimeDenies...)
	// Behind a wall, the runtime's overrides apply to every source the deny list
	// covers, and to the harness's computed values.
	var overrides []string
	if in.Walled {
		overrides = in.Overrides
	}
	added = append(added, overrides...)
	deny, err := List(added)
	if err != nil {
		return Resolved{}, err
	}
	// The server's two QORY_ names are matched against the entries the run adds alone.
	serverDeny := entriesOf(added)
	// The harness's computed values are matched against the built-in list and the
	// overrides that apply.
	computed, err := List(overrides)
	if err != nil {
		return Resolved{}, err
	}
	// Behind a wall, and without one for a run whose gateway holds credentials for it,
	// the endpoint's variable is matched against the deny list without the runtime's
	// denies, and then checked by the endpoint rule.
	var endpoint string
	endpointDeny := deny
	if !in.EndpointFixed && (in.Walled || len(in.Credentials) > 0) && in.Endpoint != "" {
		endpoint = in.Endpoint
		if endpointDeny, err = List(slices.Concat(in.Deny, overrides)); err != nil {
			return Resolved{}, err
		}
	}
	covers := endpointRule(in.Credentials, in.Runtime)
	// left is why the deny list, or for the endpoint's variable the endpoint rule,
	// leaves a value of the run, the machine or the harness's defaults out, and the
	// model credential whose hosts include a kept endpoint's host.
	left := func(name, v string) (why, credential string) {
		switch {
		case in.EndpointFixed && name == in.Endpoint:
			return "", ""
		case name != endpoint:
			if deny.Matches(name) {
				return WhyDenied, ""
			}
			return "", ""
		case endpointDeny.Matches(name):
			return WhyDenied, ""
		}
		return covers(v)
	}
	out := Resolved{Env: []string{}, Fixed: []string{}, Applied: []Entry{}}
	fixed := map[string]bool{}
	for _, name := range slices.Concat(in.Own, in.Placeholders) {
		fixed[name] = true
	}
	// Why the built-in list or the endpoint rule leaves the harness's computed value of
	// a name out, by name. The endpoint rule checks every computed value of the
	// endpoint's variable: when it leaves one out, all of them are left out, with the
	// first one's reason; otherwise the last one alone stays, lastEndpoint its index,
	// and keptFixed is the model credential whose hosts include its host.
	deniedFixed := map[string]string{}
	keptFixed, lastEndpoint := "", -1
	if endpoint != "" && !computed.Matches(endpoint) {
		for i, kv := range in.Fixed {
			name, v, _ := strings.Cut(kv, "=")
			if name != endpoint {
				continue
			}
			why, credential := covers(v)
			if why != "" {
				deniedFixed[endpoint], keptFixed, lastEndpoint = why, "", -1
				break
			}
			keptFixed, lastEndpoint = credential, i
		}
	}
	for i, kv := range in.Fixed {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case in.EndpointFixed && name == in.Endpoint, slices.Contains(in.KeysFixed, name):
			deniedFixed[name] = WhyFixed
		case computed.Matches(name):
			deniedFixed[name] = WhyDenied
		}
		if deniedFixed[name] != "" || (endpoint != "" && name == endpoint && i != lastEndpoint) {
			continue
		}
		out.Fixed = append(out.Fixed, kv)
		fixed[name] = true
	}
	run, machine, defaults, shell := byName(in.Run), byName(in.Machine), byName(in.Defaults), byName(in.Shell)
	names := map[string]bool{}
	for name := range deniedFixed {
		names[name] = true
	}
	for _, m := range []map[string]string{in.Server, run, machine, defaults} {
		for name := range m {
			names[name] = true
		}
	}
	for _, name := range in.KeysFixed {
		if _, ok := shell[name]; ok {
			names[name] = true
		}
	}
	setOtherwise := slices.Concat(in.Runtime, in.ReadFrom)
	for _, name := range slices.Sorted(maps.Keys(names)) {
		e := Entry{Name: name, Lost: []Loss{}}
		if why := deniedFixed[name]; why != "" {
			e.Lost = append(e.Lost, Loss{FromFixed, why})
		}
		if fixed[name] {
			e.From = FromFixed
			if name == endpoint && keptFixed != "" {
				e.Kept = &Kept{KeptEndpointCovered, keptFixed}
			}
		}
		value := ""
		take := func(from string, v string, ok bool, why, credential string) {
			switch {
			case !ok:
			case slices.Contains(in.KeysFixed, name):
				e.Lost = append(e.Lost, Loss{from, WhyFixed})
			case why != "":
				e.Lost = append(e.Lost, Loss{from, why})
			case fixed[name]:
				e.Lost = append(e.Lost, Loss{from, WhyFixed})
			case e.From != "":
				e.Lost = append(e.Lost, Loss{from, WhyOverridden})
			default:
				e.From, value = from, v
				if credential != "" {
					e.Kept = &Kept{KeptEndpointCovered, credential}
				}
			}
		}
		v, ok := in.Server[name]
		why, credential := "", ""
		switch {
		case !in.Walled && in.Unwalled != Accept:
			why = WhyUnwalled
		case slices.Contains(setOtherwise, name):
			why = WhyDenied
		case name == envRunSystem || name == envRunRepositories:
			if serverDeny.Matches(name) {
				why = WhyDenied
			}
		default:
			why, credential = left(name, v)
		}
		take(FromApiary, v, ok, why, credential)
		for _, s := range []struct {
			from string
			m    map[string]string
		}{{FromRun, run}, {FromMachine, machine}, {FromHarness, defaults}} {
			v, ok := s.m[name]
			why, credential := left(name, v)
			take(s.from, v, ok, why, credential)
		}
		v, ok = shell[name]
		take(FromShell, v, ok, "", "")
		switch e.From {
		case FromApiary, FromRun, FromMachine, FromHarness:
			out.Env = append(out.Env, name+"="+value)
		}
		out.Applied = append(out.Applied, e)
	}
	return out, nil
}

// endpointRule returns the endpoint rule for a run's credentials, of which the model
// credentials are those with a placeholder among runtime, the variables the runtime
// declares or reserves. For a value, it returns why the rule leaves the value out, or
// the shown name of the first model credential whose hosts include the value's host.
func endpointRule(credentials []Credential, runtime []string) func(v string) (why, credential string) {
	var model []Credential
	for _, c := range credentials {
		if slices.ContainsFunc(c.Placeholders, func(p string) bool { return slices.Contains(runtime, p) }) {
			model = append(model, c)
		}
	}
	return func(v string) (string, string) {
		host, ok := policy.EndpointHost(v)
		if !ok {
			return WhyEndpointUnreadable, ""
		}
		for _, c := range model {
			if policy.CredentialFor(c.Hosts, host) {
				return "", accesskey.ShownName(c.Name, false)
			}
		}
		return WhyEndpointUncovered, ""
	}
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
// Forager sets for the session, or a variable a machine value is read from, is
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
		if reserved := accesskey.ShownNames(pick(func(n string) bool {
			own := strings.HasPrefix(strings.ToUpper(n), "QORY_") && n != envRunID && n != envSocket
			return own || slices.Contains(machine, n)
		})); len(reserved) > 0 {
			return refusal.New(refusal.VariableReserved, reserved, "the run passes %s into the enclosure, Forager's names or what a value of the machine's is read from", strings.Join(reserved, ", "))
		}
	}
	if conflict := accesskey.ShownNames(pick(func(n string) bool { return slices.Contains(placeholders, n) })); len(conflict) > 0 {
		return refusal.New(refusal.PlaceholderConflict, conflict, "the run passes a value for %s, a placeholder of what the gateway holds outside the enclosure", strings.Join(conflict, ", "))
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
			return fmt.Errorf("variables.deny: %s is neither a variable's name nor a pattern of letters, digits, underscores and *", accesskey.ShownName(e, true))
		}
	}
	return nil
}

// Deny is a deny list: the names and patterns of denied-variables.json, its forge
// tokens' and model keys' names among the names, with the entries a run adds.
type Deny struct {
	names    map[string]bool
	patterns []string
}

// List is the built-in deny list, its names, patterns, forge tokens and model keys,
// with the entries added.
func List(entries []string) (*Deny, error) {
	builtin, err := Builtin()
	if err != nil {
		return nil, err
	}
	return entriesOf(slices.Concat(builtin.Names, builtin.Patterns, builtin.Credentials(), entries)), nil
}

// entriesOf is the deny list of the names and patterns given alone, without the
// built-in ones.
func entriesOf(list []string) *Deny {
	d := &Deny{names: map[string]bool{}}
	for _, e := range list {
		e = strings.ToUpper(e)
		if strings.Contains(e, "*") {
			d.patterns = append(d.patterns, e)
		} else {
			d.names[e] = true
		}
	}
	return d
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
type Denied = contracts.Denied

var builtin = sync.OnceValues(func() (*Denied, error) {
	d, err := contracts.DeniedVariables()
	if err != nil {
		return nil, err
	}
	return &d, nil
})

// Builtin is the contract's built-in deny list, denied-variables.json.
func Builtin() (*Denied, error) { return builtin() }
