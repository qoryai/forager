package session

import (
	"errors"
	"fmt"
	"maps"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session/internal/variables"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/wall"
)

// variableShape is a variable's name as the contract bounds it.
var variableShape = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// checkVariables refuses the variables section when it cannot be one: a run's or a
// machine's variable that is not NAME=value with a name of the contract's grammar, or
// whose value contains a NUL, a carriage return or a line feed, a deny entry that is
// neither a name nor a pattern, an unwalled mode other than the two. An error names a
// variable only by a name of the grammar, and never contains a value.
func checkVariables(v Variables) error {
	for _, set := range []struct {
		whose string
		env   []string
	}{{"run", v.Run}, {"machine", v.Machine}} {
		for _, kv := range set.env {
			name, value, ok := strings.Cut(kv, "=")
			switch {
			case !ok && variableShape.MatchString(name):
				return fmt.Errorf("the %s's variable %s has no value: each is NAME=value", set.whose, name)
			case !ok:
				return fmt.Errorf("a %s's variable is not NAME=value: each is NAME=value", set.whose)
			case !variableShape.MatchString(name):
				return fmt.Errorf("a %s's variable has a name other than letters, digits and underscores, starting with a letter or an underscore, of at most 128", set.whose)
			case strings.ContainsAny(value, "\x00\r\n"):
				return fmt.Errorf("the %s's variable %s holds a NUL, a carriage return or a line feed, which a variable's value does not", set.whose, name)
			}
		}
	}
	if err := variables.CheckDeny(v.Deny); err != nil {
		return err
	}
	if u := v.Unwalled; u != "" && u != UnwalledAccept && u != UnwalledIgnore {
		return fmt.Errorf("variables.unwalled is %q, neither %s nor %s", u, UnwalledAccept, UnwalledIgnore)
	}
	return nil
}

// checkHarnessHome refuses a harness home that is not an absolute path, or that
// contains a NUL, a carriage return or a line feed, which a variable's value does not.
func checkHarnessHome(home string) error {
	switch {
	case home == "":
		return nil
	case strings.ContainsAny(home, "\x00\r\n"):
		return errors.New("the harness home holds a NUL, a carriage return or a line feed, which a variable's value does not")
	case !path.IsAbs(home) && !filepath.IsAbs(home):
		return fmt.Errorf("the harness home %q is not an absolute path", home)
	}
	return nil
}

// passes are the names of the variables the run passes a value for from the node: in
// what it inherits, what the harness sets, or the run's or the machine's variables,
// sorted, each once. A name outside the grammar of a variable's name is left out: it
// can match no placeholder. The run request carries them, names alone, so the gateway
// refuses a placeholder the run passes a value for, as the session did.
func passes(spec Spec) []string {
	seen := map[string]bool{}
	for _, kv := range slices.Concat(spec.Env, spec.LaunchFixed, spec.LaunchDefaults, spec.Variables.Run, spec.Variables.Machine) {
		name, _, ok := strings.Cut(kv, "=")
		if ok && variableShape.MatchString(name) {
			seen[name] = true
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

// resolve resolves the run's variables, from the fixed names to what the run
// inherits, after refusing what the run passes into the enclosure: placeholders are the
// variables the agent sees in place of what the gateway holds, and reserved the names
// the gateway sets for the run, what a value of the machine's is read from. Behind a
// wall, the endpoint rule checks each value of the runtime's model endpoint variable
// against credentials, the run answer's credential_hosts after [chosen]. It returns the resolution
// and, for a walled run, the names to unset inside, which [Exec] takes out of the
// launch's environment: the runtime's declared and reserved variables and the names
// the runtime denies, lists in its model overrides or as its model endpoint, or the
// node's deny list removes, that nothing sets. Forager, the wall and the preparation
// set names too, [wall.Nest] among them for a run with nested Docker, docker, so none of theirs is
// ever unset; the wall's names for a run with an authority count as set only when the
// run has one, authority.
func resolve(spec Spec, rt runtimes.Runtime, served map[string]string, credentials []server.LinkCredentialHosts, prepared runtimes.Launch, placeholderNames, reserved []string, docker, authority bool) (variables.Resolved, []string, error) {
	var decl runtimes.Declarations
	if s, ok := rt.(runtimes.Secrets); ok {
		decl = s.Secrets()
	}
	var runtimeNames []string
	for _, d := range decl.Declares {
		runtimeNames = append(runtimeNames, d.Name)
	}
	runtimeNames = append(runtimeNames, decl.Reserves...)
	// overrides are the variables that would override the model id or effort value a
	// composer writes: a walled run leaves them out like a denied name, and unsets them
	// inside. endpoint is the variable the runtime reads its model endpoint from:
	// behind a wall the endpoint rule decides whether a value of it applies, and it is
	// unset inside when nothing sets it.
	var overrides []string
	var endpoint string
	if m, ok := rt.(runtimes.Model); ok {
		if places, ok := m.Model(); ok {
			overrides, endpoint = places.Overrides, places.Endpoint.Variable
		}
	}
	creds := make([]variables.Credential, 0, len(credentials))
	for _, c := range credentials {
		creds = append(creds, variables.Credential{Name: c.Name, Hosts: c.Hosts, Placeholders: c.Placeholders})
	}
	// What a value of the machine's is read from: the gateway's own names.
	readFrom := reserved
	// Forager's own names, the proxy's, the wall's and the preparation's: with the
	// placeholders and the harness's computed values, the run's fixed names.
	own := []string{EnvRunID, EnvSocket}
	if spec.HarnessHome != "" {
		own = append(own, EnvHarnessHome)
	}
	own = append(own, names(link.ProxyEnv(""))...)
	own = append(own, names(prepared.Env)...)
	// What Forager, the preparation and the wall set in this run, which the helper's
	// exec never unsets: a name the wall sets only for a run with an authority counts
	// when the run has one, and nested Docker's when the run has it.
	walls := slices.Clone(own)
	if s, ok := spec.Wall.(wall.Setter); ok {
		own = append(own, s.Sets()...)
		var only []string
		if a, ok := spec.Wall.(wall.AuthoritySetter); ok && !authority {
			only = a.SetsWithAuthority()
		}
		for _, name := range s.Sets() {
			if !slices.Contains(only, name) {
				walls = append(walls, name)
			}
		}
	}
	if docker {
		walls = append(walls, wall.NestSets()...)
	}
	vars, err := variables.Resolve(variables.Inputs{
		Fixed: spec.LaunchFixed, Server: served, Run: spec.Variables.Run, Machine: spec.Variables.Machine,
		Defaults: spec.LaunchDefaults, Shell: spec.Env,
		Walled: spec.Wall != nil, Unwalled: spec.Variables.Unwalled,
		Deny: spec.Variables.Deny, RuntimeDenies: decl.Denies, Overrides: overrides, Runtime: runtimeNames,
		Placeholders: placeholderNames, ReadFrom: readFrom, Own: own,
		Endpoint: endpoint, Credentials: creds,
	})
	if err != nil {
		return variables.Resolved{}, nil, err
	}
	// Behind a wall, a variable the runtime declares or reserves that nothing sets is
	// unset inside, so an image's value for it does not reach the runtime, and neither
	// does an empty one, which a program may read as set. A value the run passes for
	// one stays the agent's, one the preparation sets stays the runtime's, and a name
	// Forager or the wall sets, the nested daemon's DOCKER_CONFIG among them, keeps the
	// value they give it, since the helper's exec runs after them.
	var unset []string
	if spec.Wall != nil {
		set := slices.Concat(names(spec.Env), names(vars.Env), names(vars.Fixed), names(prepared.Env), placeholderNames, walls)
		for _, name := range runtimeNames {
			if !slices.Contains(set, name) && !slices.Contains(unset, name) {
				unset = append(unset, name)
			}
		}
		// A name the runtime denies, lists in its model overrides or as its model
		// endpoint, or the node's deny list removes, is unset too, so an image's value
		// for it does not reach the runtime either. A value that wins with it stays, a
		// kept endpoint's among them, and so does a name Forager, the wall or the
		// preparation sets. A pattern names no variable to unset.
		var endpoints []string
		if endpoint != "" {
			endpoints = []string{endpoint}
		}
		for _, name := range slices.Concat(decl.Denies, overrides, endpoints, spec.Variables.Deny) {
			if variableShape.MatchString(name) && !slices.Contains(set, name) && !slices.Contains(unset, name) {
				unset = append(unset, name)
			}
		}
	}
	return vars, unset, nil
}

// probeValue is the value a trial of [reachesFromRun] passes. It is not a secret, and
// no record or log carries it: the trial's resolution is discarded.
const probeValue = "forager-model-key-probe"

// reachesFromRun reports whether a value of name from the run, with the run's other
// values as they are, reaches the runtime's environment: try, which resolves spec as
// [resolve] does for the run, refuses none of the run's values and does not unset name,
// and the environment the launch writes behind a wall, with ownEnv and the
// placeholders, has name set to that value.
func reachesFromRun(spec Spec, name string, prepared runtimes.Launch, ownEnv, placeholderNames []string, try func(Spec) (variables.Resolved, []string, error)) bool {
	trial := spec
	trial.Variables.Run = slices.DeleteFunc(slices.Clone(spec.Variables.Run), func(kv string) bool {
		n, _, _ := strings.Cut(kv, "=")
		return n == name
	})
	trial.Variables.Run = append(trial.Variables.Run, name+"="+probeValue)
	vars, unset, err := try(trial)
	if err != nil || slices.Contains(unset, name) {
		return false
	}
	return slices.Contains(environment(trial.Env, vars.Env, vars.Fixed, prepared.Env, ownEnv, placeholders(placeholderNames)), name+"="+probeValue)
}

// names are the names of NAME=value entries.
func names(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		out = append(out, name)
	}
	return out
}

// secretsOf is what rt declares of a run's secrets; empty for a runtime that declares
// none.
func secretsOf(rt runtimes.Runtime) runtimes.Declarations {
	if s, ok := rt.(runtimes.Secrets); ok {
		return s.Secrets()
	}
	return runtimes.Declarations{}
}

// authWords is how a refusal writes how a value is set: the header with its name, the
// bearer or basic scheme, or no auth. The header's name goes through
// [accesskey.ShownName], since a server's entry may contain a secret pasted there.
func authWords(scheme, header string) string {
	switch scheme {
	case "header":
		return "the header " + accesskey.ShownName(header, false)
	case "":
		return "no auth"
	}
	return "the " + scheme + " scheme"
}

// shownNames are names as a refusal lists them, each through [accesskey.ShownName].
func shownNames(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = accesskey.ShownName(n, false)
	}
	return out
}

// chosen is the run answer's credentials and placeholders after the runtime's choice.
// For each credential from the server with key_variables, the one declaration of rt
// whose name is among them chooses its variable, which is added to the credential's
// placeholders and to the run's, each once. A credential of which rt declares none of
// the key_variables or more than one, whose auth differs from that declaration's in
// the scheme or, for a header, in the header's name, compared without case, is
// [refusal.RunConfigurationInvalid] with the credential's name, and so is a placeholder
// [checkPlaceholders] refuses; a placeholder rt does not declare stays. A credential without key_variables, every one of the machine's
// among them, is as the answer has it.
func chosen(rt runtimes.Runtime, credentials []server.LinkCredentialHosts, placeholders []string) ([]server.LinkCredentialHosts, []string, error) {
	decl := secretsOf(rt)
	declared := slices.Clone(decl.Reserves)
	var offered []string
	for _, d := range decl.Declares {
		declared = append(declared, d.Name)
		offered = append(offered, d.Name)
	}
	names := slices.Clone(placeholders)
	out := make([]server.LinkCredentialHosts, len(credentials))
	picked := make([]string, len(credentials))
	for i, c := range credentials {
		c.Placeholders = slices.Clone(c.Placeholders)
		if len(c.KeyVariables) == 0 {
			out[i] = c
			continue
		}
		var auth server.Auth
		if c.Auth != nil {
			auth = *c.Auth
		}
		shown := accesskey.ShownName(c.Name, true)
		listed := orList(shownNames(c.KeyVariables), ", ", " and ")
		var matches []runtimes.Declaration
		for _, d := range decl.Declares {
			if slices.Contains(c.KeyVariables, d.Name) {
				matches = append(matches, d)
			}
		}
		switch {
		case len(matches) == 0 && len(offered) == 0:
			return nil, nil, refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
				"run a runtime that reads a key from one of the key_variables of the credential %s in Qory Apiary's run configuration, or remove its key_variables: the runtime %s declares no variable for a key, and the credential's key_variables are %s",
				shown, rt.Name(), listed)
		case len(matches) == 0:
			return nil, nil, refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
				"add one of %s to the key_variables of the credential %s in Qory Apiary's run configuration: the runtime %s reads a key from these variables, and the credential's key_variables are %s",
				orList(offered, ", ", " or "), shown, rt.Name(), listed)
		case len(matches) > 1:
			var both []string
			for _, d := range matches {
				both = append(both, d.Name)
			}
			return nil, nil, refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
				"keep only one of %s in the key_variables of the credential %s in Qory Apiary's run configuration: the runtime %s reads a key from each of them, and a key goes into one variable",
				orList(both, ", ", " and "), shown, rt.Name())
		}
		d := matches[0]
		if d.Auth.Scheme != auth.Scheme || (d.Auth.Scheme == "header" && !strings.EqualFold(d.Auth.Header, auth.Header)) {
			return nil, nil, refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
				"set the auth of the credential %s in Qory Apiary's run configuration to %s, or list another variable in its key_variables: the runtime %s sends the key in %s with %s, and the credential's auth is set to %s",
				shown, authWords(d.Auth.Scheme, d.Auth.Header), rt.Name(), d.Name, authWords(d.Auth.Scheme, d.Auth.Header), authWords(auth.Scheme, auth.Header))
		}
		variable := d.Name
		picked[i] = variable
		if !slices.Contains(c.Placeholders, variable) {
			c.Placeholders = append(c.Placeholders, variable)
		}
		if !slices.Contains(names, variable) {
			names = append(names, variable)
		}
		out[i] = c
	}
	if err := checkPlaceholders(rt, declared, out, picked, names); err != nil {
		return nil, nil, err
	}
	return out, names, nil
}

// checkPlaceholders refuses a placeholder that goes into a variable for no
// credential, or into a key's variable that no credential chose, each
// [refusal.RunConfigurationInvalid]. A placeholder of a credential from the server, one
// with auth, may not be a variable rt denies, lists among its model overrides or reads
// its model endpoint from, nor a variable of declared, rt's declared and reserved
// variables, other than the one picked from its key_variables; its name is the
// refusal's. Of names, the run's placeholders, a placeholder may not be one of those
// rt denies, overrides or reads its endpoint from, nor one of declared that no
// credential has among its placeholders; the placeholder's name is the refusal's. A
// placeholder rt does not declare, such as a tool's GITHUB_TOKEN, passes, and so does a
// declared one of a credential of the machine's.
func checkPlaceholders(rt runtimes.Runtime, declared []string, credentials []server.LinkCredentialHosts, picked, names []string) error {
	decl := secretsOf(rt)
	var overrides []string
	var endpoint string
	if m, ok := rt.(runtimes.Model); ok {
		if places, ok := m.Model(); ok {
			overrides, endpoint = places.Overrides, places.Endpoint.Variable
		}
	}
	// takesNone is why the variable p takes no credential, empty when it may take one.
	takesNone := func(p string) string {
		switch {
		case slices.Contains(decl.Denies, p):
			return "lists it in denies"
		case slices.Contains(overrides, p):
			return "lists it in its model overrides"
		case endpoint != "" && p == endpoint:
			return "has it as its model endpoint's variable"
		}
		return ""
	}
	for i, c := range credentials {
		if c.Auth == nil {
			continue
		}
		shown := accesskey.ShownName(c.Name, true)
		for _, p := range c.Placeholders {
			switch why := takesNone(p); {
			case why != "":
				return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
					"remove %s from the placeholders of the credential %s in Qory Apiary's run configuration: the descriptor of the runtime %s %s, and a placeholder goes only into a variable for a credential",
					accesskey.ShownName(p, false), shown, rt.Name(), why)
			case p == picked[i] || !slices.Contains(declared, p):
			case picked[i] != "":
				return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
					"remove %s from the placeholders of the credential %s in Qory Apiary's run configuration: %s is the variable of its key_variables that the runtime %s declares, and a key goes into one variable",
					accesskey.ShownName(p, false), shown, picked[i], rt.Name())
			case !slices.ContainsFunc(decl.Declares, func(d runtimes.Declaration) bool { return d.Name == p }):
				return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
					"remove %s from the placeholders of the credential %s in Qory Apiary's run configuration: the descriptor of the runtime %s lists it in reserves, and a placeholder goes only into a variable for a credential",
					accesskey.ShownName(p, false), shown, rt.Name())
			default:
				return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
					"list %s in the key_variables of the credential %s in Qory Apiary's run configuration instead of its placeholders: the runtime %s reads a key from it, and a key's variable gets a credential's placeholder only through key_variables",
					accesskey.ShownName(p, false), shown, rt.Name())
			}
		}
	}
	for _, p := range names {
		if why := takesNone(p); why != "" {
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(p),
				"remove %s from the placeholders of the machine's credentials and tools in forager.yaml: the descriptor of the runtime %s %s, and a placeholder goes only into a variable for a credential",
				accesskey.ShownName(p, false), rt.Name(), why)
		}
		if slices.Contains(declared, p) && !slices.ContainsFunc(credentials, func(c server.LinkCredentialHosts) bool { return slices.Contains(c.Placeholders, p) }) {
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(p),
				"remove %s from the placeholders of the machine's tools in forager.yaml, or give it to a credential in forager.yaml: the runtime %s reads a key from it, and no credential of the run has it among its placeholders",
				accesskey.ShownName(p, false), rt.Name())
		}
	}
	return nil
}

// orList is items joined by sep, the last two by last.
func orList(items []string, sep, last string) string {
	if len(items) < 2 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], sep) + last + items[len(items)-1]
}

// credentialVariables is the record's credential_variables: one entry per credential
// and placeholder, in order; nil when none is left. An entry whose credential's name or
// placeholder contains an access key secret or a run key, [accesskey.ContainsSecret],
// is left out, so the record never carries one.
func credentialVariables(credentials []server.LinkCredentialHosts) []map[string]string {
	var out []map[string]string
	for _, c := range credentials {
		for _, p := range c.Placeholders {
			if accesskey.ContainsSecret(c.Name) || accesskey.ContainsSecret(p) {
				continue
			}
			out = append(out, map[string]string{"credential": c.Name, "name": p})
		}
	}
	return out
}

// checkModelKey refuses a walled run whose gateway holds credentials for it, when its
// runtime has a model section and declares model keys, its declarations, and the run
// has none: no value of a model key's variable reaches the
// runtime, from what the run inherits, the run, the machine, the harness or the
// runtime's preparation, and no credential of credentials, after [chosen], has a
// model key's variable among its placeholders and a host of the runtime's model among
// its hosts. The runtime's model host is the host of the value of its endpoint variable
// that reaches it, or, when none does, a host of a model key's declaration; a value
// from which [policy.EndpointHost] reads no host is covered by no credential. A run
// without a wall, or whose answer has no credential_hosts, is not checked: its key may
// come from what the session does not see, such as a login of the developer's, a
// mount or an image. The refusal is [refusal.ModelKeyMissing] with the model keys'
// variables. Its text offers a value only of a model key's variable for which passes
// reports true: a value of it from the run reaches the runtime's environment.
func checkModelKey(spec Spec, rt runtimes.Runtime, credentials []server.LinkCredentialHosts, vars variables.Resolved, prepared runtimes.Launch, passes func(name string) bool) error {
	if spec.Wall == nil || len(credentials) == 0 {
		return nil
	}
	m, ok := rt.(runtimes.Model)
	if !ok {
		return nil
	}
	places, ok := m.Model()
	if !ok {
		return nil
	}
	var keys, hosts []string
	for _, d := range secretsOf(rt).Declares {
		keys = append(keys, d.Name)
		for _, h := range d.Hosts {
			if !slices.Contains(hosts, h) {
				hosts = append(hosts, h)
			}
		}
	}
	if len(keys) == 0 {
		return nil
	}
	// What reaches the runtime, a later source's value over an earlier one's, as
	// environment writes the launch's.
	reaches := map[string]string{}
	for _, kv := range slices.Concat(spec.Env, vars.Env, vars.Fixed, prepared.Env) {
		name, value, _ := strings.Cut(kv, "=")
		reaches[name] = value
	}
	if slices.ContainsFunc(keys, func(k string) bool { return reaches[k] != "" }) {
		return nil
	}
	// values is the refusal's words for the variables of which a value from the run
	// reaches the runtime, by trial, empty for none. Only a refusal calls it, so a run
	// that starts runs no trial.
	values := func() string {
		var free []string
		for _, k := range keys {
			if passes(k) {
				free = append(free, k)
			}
		}
		switch {
		case len(free) == len(keys):
			return "one of these variables"
		case len(free) > 0:
			return orList(free, ", ", " or ")
		}
		return ""
	}
	endpoint := places.Endpoint.Variable
	if v := reaches[endpoint]; endpoint != "" && v != "" {
		host, ok := policy.EndpointHost(v)
		if !ok {
			give := ""
			if v := values(); v != "" {
				give = ", or give the run a value of " + v + " from the run or the machine"
			}
			listed := orList(keys, ", ", " or ")
			return refusal.New(refusal.ModelKeyMissing, keys,
				"set %s to an https URL, with no user name or password, whose host is a host of a credential whose key_variables list one of %s in Qory Apiary's run configuration or of a credential with a placeholder of %s in forager.yaml%s: the value of %s that reaches the runtime %s has no host that Forager reads, so no credential counts as its model key",
				endpoint, listed, listed, give, endpoint, rt.Name())
		}
		hosts = []string{host}
	}
	shownHosts := strings.Join(hosts, " or ")
	for _, c := range credentials {
		if !slices.ContainsFunc(c.Placeholders, func(p string) bool { return slices.Contains(keys, p) }) {
			continue
		}
		if slices.ContainsFunc(hosts, func(h string) bool { return policy.CredentialFor(c.Hosts, h) }) {
			return nil
		}
	}
	listed := orList(keys, ", ", " or ")
	ways := []string{
		"a credential for " + shownHosts + " whose key_variables list one of " + listed + " in Qory Apiary's run configuration",
		"a credential for " + shownHosts + " with a placeholder of " + listed + " in forager.yaml",
	}
	if v := values(); v != "" {
		ways = append(ways, "a value of "+v+" from the run or the machine")
	}
	return refusal.New(refusal.ModelKeyMissing, keys,
		"give the run a model key for the runtime %s: %s; the gateway holds credentials for the run, and none of them is a model key for %s",
		rt.Name(), orList(ways, ", ", ", or "), shownHosts)
}
