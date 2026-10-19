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

// schemeWords is how a refusal writes an auth scheme.
func schemeWords(scheme string) string {
	switch scheme {
	case "header":
		return "in a header"
	case "":
		return "with no auth"
	}
	return "as a " + scheme
}

// chosen is the run answer's credentials and placeholders after the runtime's choice.
// For each credential from the server with a key_form, the one declaration of rt with
// that key_form and the credential's auth scheme chooses its variable, which is added
// to the credential's placeholders and to the run's, each once. The header's name is
// not compared. A credential whose key_form and scheme no declaration has, or whose
// placeholders list another variable rt declares or reserves, is
// [refusal.RunConfigurationInvalid] with the credential's name; a placeholder rt does
// not declare stays. A credential without a key_form, every one of the machine's
// among them, is as the answer has it.
func chosen(rt runtimes.Runtime, credentials []server.LinkCredentialHosts, placeholders []string) ([]server.LinkCredentialHosts, []string, error) {
	decl := secretsOf(rt)
	declared := slices.Clone(decl.Reserves)
	var offered []string
	for _, d := range decl.Declares {
		declared = append(declared, d.Name)
		if d.KeyForm != "" {
			offered = append(offered, d.KeyForm+" "+schemeWords(d.Auth.Scheme)+" for "+d.Name)
		}
	}
	names := slices.Clone(placeholders)
	out := make([]server.LinkCredentialHosts, len(credentials))
	for i, c := range credentials {
		c.Placeholders = slices.Clone(c.Placeholders)
		if c.KeyForm != "" {
			scheme := ""
			if c.Auth != nil {
				scheme = c.Auth.Scheme
			}
			shown := accesskey.ShownName(c.Name, true)
			at := slices.IndexFunc(decl.Declares, func(d runtimes.Declaration) bool {
				return d.KeyForm == c.KeyForm && d.Auth.Scheme == scheme
			})
			switch {
			case at < 0 && len(offered) == 0:
				return nil, nil, refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
					"leave key_form out of the credential %s in Qory Apiary's run configuration, or run a runtime that reads a model key: the runtime %s declares no variable for one", shown, rt.Name())
			case at < 0:
				return nil, nil, refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
					"give the credential %s in Qory Apiary's run configuration a key_form and auth.scheme that the runtime %s reads: %s; the credential has %s %s",
					shown, rt.Name(), orList(offered, ", ", ", or "), c.KeyForm, schemeWords(scheme))
			}
			variable := decl.Declares[at].Name
			for _, p := range c.Placeholders {
				if p != variable && slices.Contains(declared, p) {
					return nil, nil, refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
						"remove %s from the placeholders of the credential %s in Qory Apiary's run configuration: its key_form %s and auth.scheme %s choose %s for the runtime %s, and a model key goes into one variable",
						p, shown, c.KeyForm, scheme, variable, rt.Name())
				}
			}
			if !slices.Contains(c.Placeholders, variable) {
				c.Placeholders = append(c.Placeholders, variable)
			}
			if !slices.Contains(names, variable) {
				names = append(names, variable)
			}
		}
		out[i] = c
	}
	return out, names, nil
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
// runtime has a model section and declares model keys, the declarations with a
// key_form, and the run has none: no value of a model key's variable reaches the
// runtime, from what the run inherits, the run, the machine, the harness or the
// runtime's preparation, and no credential of credentials, after [chosen], has a
// model key's variable among its placeholders and a host of the runtime's model among
// its hosts. The runtime's model host is the host of the value of its endpoint variable
// that reaches it, or, when none does, a host of a model key's declaration; a value
// from which [policy.EndpointHost] reads no host is covered by no credential. A run
// without a wall, or whose answer has no credential_hosts, is not checked: its key may
// come from what the session does not see, such as a login of the developer's, a
// mount or an image. The refusal is [refusal.ModelKeyMissing] with the model keys'
// variables. Its text offers a value only of a model key's variable that a value can
// reach the runtime in: one not among placeholderNames or a credential's placeholders,
// whose value is refused as [refusal.PlaceholderConflict]; not among reserved, whose
// value is refused as [refusal.VariableReserved]; and not matched by the deny list
// that [resolve] applies behind a wall, the built-in list with spec's Variables.Deny,
// the runtime's denies and its model overrides, whose value is left out.
func checkModelKey(spec Spec, rt runtimes.Runtime, credentials []server.LinkCredentialHosts, placeholderNames, reserved []string, vars variables.Resolved, prepared runtimes.Launch) error {
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
		if d.KeyForm == "" {
			continue
		}
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
	// A value the run may pass: one of a variable that no credential sets a placeholder
	// in, that is not reserved and that the node does not deny.
	deny, err := variables.List(slices.Concat(spec.Variables.Deny, secretsOf(rt).Denies, places.Overrides))
	if err != nil {
		return err
	}
	var free []string
	for _, k := range keys {
		placeholder := slices.Contains(placeholderNames, k) || slices.ContainsFunc(credentials, func(c server.LinkCredentialHosts) bool { return slices.Contains(c.Placeholders, k) })
		if !placeholder && !slices.Contains(reserved, k) && !deny.Matches(k) {
			free = append(free, k)
		}
	}
	values := ""
	switch {
	case len(free) == len(keys):
		values = "one of these variables"
	case len(free) > 0:
		values = orList(free, ", ", " or ")
	}
	endpoint := places.Endpoint.Variable
	if v := reaches[endpoint]; endpoint != "" && v != "" {
		host, ok := policy.EndpointHost(v)
		if !ok {
			give := ""
			if values != "" {
				give = ", or give the run a value of " + values + " from the run or the machine"
			}
			return refusal.New(refusal.ModelKeyMissing, keys,
				"set %s to an https URL, with no user name or password, whose host a credential with a placeholder of %s covers%s: the value of %s that reaches the runtime %s has no host that Forager reads, so no credential counts as its model key",
				endpoint, orList(keys, ", ", " or "), give, endpoint, rt.Name())
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
	give := ""
	if values != "" {
		give = ", or a value of " + values + " from the run or the machine"
	}
	return refusal.New(refusal.ModelKeyMissing, keys,
		"give the run a model key for the runtime %s: a credential for %s with a placeholder of %s, on this machine or in Qory Apiary's run configuration%s; the gateway holds credentials for the run, and none of them is a model key for %s",
		rt.Name(), shownHosts, orList(keys, ", ", " or "), give, shownHosts)
}
