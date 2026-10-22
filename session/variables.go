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
				return fmt.Errorf("the %s's variable %s has no value: each is NAME=value", set.whose, accesskey.ShownName(name, false))
			case !ok:
				return fmt.Errorf("a %s's variable is not NAME=value: each is NAME=value", set.whose)
			case !variableShape.MatchString(name):
				return fmt.Errorf("a %s's variable has a name other than letters, digits and underscores, starting with a letter or an underscore, of at most 128", set.whose)
			case strings.ContainsAny(value, "\x00\r\n"):
				return fmt.Errorf("the %s's variable %s holds a NUL, a carriage return or a line feed, which a variable's value does not", set.whose, accesskey.ShownName(name, false))
			}
		}
	}
	if err := variables.CheckDeny(v.Deny); err != nil {
		return err
	}
	if u := v.Unwalled; u != "" && u != UnwalledAccept && u != UnwalledIgnore {
		return fmt.Errorf("variables.unwalled is %s, neither %s nor %s", accesskey.ShownValue(u, true), UnwalledAccept, UnwalledIgnore)
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
		return fmt.Errorf("the harness home %s is not an absolute path", accesskey.ShownValue(home, true))
	}
	return nil
}

// checkInputsDir refuses an inputs directory that is not an absolute path.
func checkInputsDir(dir string) error {
	if dir != "" && !path.IsAbs(dir) && !filepath.IsAbs(dir) {
		return fmt.Errorf("set the inputs directory to an absolute path: %s is relative", accesskey.ShownValue(dir, true))
	}
	return nil
}

// passes are the names of the variables the run passes a value for from the node: in
// what it inherits, what the harness sets, or the run's or the machine's variables,
// sorted, each once. A name outside the grammar of a variable's name is left out: it
// can match no placeholder. The run request carries them, names alone, so the gateway
// refuses a placeholder the run passes a value for, as the session did. Without a wall
// what the run inherits is left out: a placeholder wins over an inherited value.
func passes(spec runSpec) []string {
	seen := map[string]bool{}
	inherited := spec.Env
	if spec.Wall == nil {
		inherited = nil
	}
	for _, kv := range slices.Concat(inherited, spec.LaunchFixed, spec.LaunchDefaults, spec.Variables.Run, spec.Variables.Machine) {
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
// wall, and without one for a run whose answer has credential_hosts, the endpoint rule
// checks each value of the runtime's model endpoint variable against credentials, the
// run answer's credential_hosts after [chosen]. It returns the resolution
// and, for a walled run, the names to unset inside, which [Exec] takes out of the
// launch's environment: the runtime's declared and reserved variables and the names
// the runtime denies, lists in its model overrides or as its model endpoint, or the
// node's deny list removes, that nothing sets. Forager, the wall and the preparation
// set names too, [wall.Nest] among them for a run with nested Docker, docker, so none of theirs is
// ever unset; the wall's names for a run with an authority count as set only when the
// run has one, authority. Without a wall, bundle are the variables Forager sets to the
// run's bundle, Forager's own names. When the run has a start key, key, its endpoint
// variable is one of the run's fixed names: every other value of it is left out, the
// harness's computed ones included, and the endpoint rule does not apply.
func resolve(spec runSpec, rt runtimes.Runtime, served map[string]string, credentials []server.LinkCredentialHosts, prepared runtimes.Launch, placeholderNames, reserved []string, docker, authority bool, bundle []string, key keyed) (variables.Resolved, []string, error) {
	var decl runtimes.Declarations
	if s, ok := rt.(runtimes.Secrets); ok {
		decl = s.Secrets()
	}
	var runtimeNames []string
	for _, d := range decl.Declares {
		runtimeNames = append(runtimeNames, d.Name)
	}
	runtimeNames = append(runtimeNames, decl.Reserves...)
	for _, k := range keyVariables(rt) {
		if !slices.Contains(runtimeNames, k) {
			runtimeNames = append(runtimeNames, k)
		}
	}
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
	own := foragerNames(spec, prepared, bundle, key)
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
		Endpoint: endpoint, EndpointFixed: key.Endpoint != "", KeysFixed: key.Others, Credentials: creds,
	})
	if err != nil {
		return variables.Resolved{}, nil, err
	}
	// Behind a wall, a variable the runtime declares or reserves that nothing sets is
	// unset inside, so an image's value for it does not reach the runtime, and neither
	// does an empty one, which a program may read as set. A value the run passes for
	// one stays the agent's, one the preparation sets stays the runtime's, and a name
	// Forager or the wall sets, the nested daemon's DOCKER_CONFIG among them, keeps the
	// value they give it, since the helper's exec runs after them. Run has already
	// removed key.Others from the preparation's values, so those names are unset.
	var unset []string
	if spec.Wall != nil {
		set := slices.Concat(names(withoutNames(spec.Env, key.Others)), names(vars.Env), names(vars.Fixed), names(prepared.Env), placeholderNames, walls)
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

// foragerNames are the names Forager and the runtime's preparation set for a session
// of spec, which win over every source of a variable: QORY_RUN_ID, QORY_RUN_SOCKET,
// QORY_HARNESS_HOME when spec has a harness home, the proxy's variables, the names of
// prepared.Env, bundle and the start key's endpoint variable. The wall's names are not
// among them.
func foragerNames(spec runSpec, prepared runtimes.Launch, bundle []string, key keyed) []string {
	own := []string{EnvRunID, EnvSocket}
	if spec.HarnessHome != "" {
		own = append(own, EnvHarnessHome)
	}
	own = append(own, names(link.ProxyEnv(""))...)
	own = append(own, names(prepared.Env)...)
	own = append(own, bundle...)
	if name := key.endpointName(); name != "" {
		own = append(own, name)
	}
	return own
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

// shownNames are names as a refusal lists them, each through [accesskey.ShownName].
func shownNames(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = accesskey.ShownName(n, false)
	}
	return out
}

// keyed is what the run's start key sets in the runtime's environment, NAME=value
// each: Variable, the variable the runtime reads the key from, set to the key's
// placeholder, [link.KeyPlaceholder]; and Endpoint, the runtime's endpoint variable set
// to the key's endpoint. Others is the names of the runtime's other model-key
// variables, which no value reaches: the runtime would send such a value to the start
// key's endpoint. Zero when the run has no API credential.
type keyed struct {
	Variable, Endpoint string
	Others             []string
}

// endpointName is the name of the variable Endpoint sets, empty when it sets none.
func (k keyed) endpointName() string {
	name, _, _ := strings.Cut(k.Endpoint, "=")
	return name
}

// modelVariables is the name of Variable, Others and the name Endpoint sets, each
// once; empty when the run has no start key.
func (k keyed) modelVariables() []string {
	if k.Variable == "" {
		return nil
	}
	name, _, _ := strings.Cut(k.Variable, "=")
	out := append([]string{name}, k.Others...)
	if e := k.endpointName(); e != "" && !slices.Contains(out, e) {
		out = append(out, e)
	}
	return out
}

// startKey is the index in credentials of the API credential the runtime starts with,
// or -1 when credentials have none: the one named model, the run answer's
// model_credential, or the one API credential when model is empty. An empty model
// beside two or more API credentials, and a model that names none of them, are
// [refusal.RunConfigurationInvalid]: the gateway refuses both first.
func startKey(credentials []server.LinkCredentialHosts, model string) (int, error) {
	var keys []string
	start := -1
	for i, c := range credentials {
		if c.Format == "" {
			continue
		}
		keys = append(keys, accesskey.ShownName(c.Name, false))
		if c.Name == model || (model == "" && start < 0) {
			start = i
		}
	}
	switch {
	case model == "" && len(keys) > 1:
		return -1, refusal.New(refusal.RunConfigurationInvalid, nil,
			"set model_credential in the run configuration, or give the run one model key: the run has the model keys %s", strings.Join(keys, ", "))
	case model != "" && (start < 0 || credentials[start].Name != model):
		return -1, refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(model),
			"set model_credential in the run configuration to one of the run's model keys, %s: the run has no model key %s", strings.Join(keys, ", "), accesskey.ShownName(model, true))
	}
	return start, nil
}

// chosen is the run answer's credentials and placeholders after the runtime's choice,
// and what the start key sets. Of the API credentials, the start key alone, by
// [startKey], gets the variable of rt's model key whose format is the credential's and
// whose auth has its scheme, its header's name, compared without case, and its oauth:
// the variable joins the credential's placeholders and the run's, and the start key
// sets it and the runtime's endpoint variable. The other API credentials stay as the
// answer has them, with no placeholder. A start key of a format rt lists no key for,
// or of an auth none of them has, is [refusal.RunConfigurationInvalid] with the
// credential's name, and so is a placeholder [checkPlaceholders] refuses. Every other
// credential is as the answer has it.
func chosen(rt runtimes.Runtime, credentials []server.LinkCredentialHosts, placeholders []string, model string) ([]server.LinkCredentialHosts, []string, keyed, error) {
	names := slices.Clone(placeholders)
	out := make([]server.LinkCredentialHosts, len(credentials))
	for i, c := range credentials {
		c.Placeholders = slices.Clone(c.Placeholders)
		out[i] = c
	}
	start, err := startKey(out, model)
	if err != nil {
		return nil, nil, keyed{}, err
	}
	var key keyed
	if start >= 0 {
		c := &out[start]
		shown, runtime, format := accesskey.ShownName(c.Name, true), accesskey.ShownName(rt.Name(), false), accesskey.ShownName(c.Format, false)
		var auth server.Auth
		if c.Auth != nil {
			auth = *c.Auth
		}
		places, ok := modelOf(rt)
		if !ok {
			return nil, nil, keyed{}, refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
				"run a runtime whose descriptor lists a key for %s, the API of the model key %s: the descriptor of the runtime %s has no model section",
				format, shown, runtime)
		}
		var ofFormat []runtimes.Key
		var formats []string
		for _, k := range places.Keys {
			if k.Format == c.Format {
				ofFormat = append(ofFormat, k)
			}
			if !slices.Contains(formats, k.Format) {
				formats = append(formats, k.Format)
			}
		}
		if len(ofFormat) == 0 {
			listed := "no API"
			if len(formats) > 0 {
				listed = orList(shownNames(formats), ", ", " and ")
			}
			return nil, nil, keyed{}, refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
				"give the model key %s a provider whose API the runtime %s reads keys for: the descriptor of the runtime lists keys for %s, and the key's API is %s",
				shown, runtime, listed, format)
		}
		i := slices.IndexFunc(ofFormat, func(k runtimes.Key) bool {
			return k.Auth.Scheme == auth.Scheme && strings.EqualFold(k.Auth.Header, auth.Header) && k.Auth.OAuth == auth.OAuth
		})
		if i < 0 {
			ways := make([]string, len(ofFormat))
			for j, k := range ofFormat {
				ways[j] = keyAuthWords(server.Auth{Scheme: k.Auth.Scheme, Header: k.Auth.Header, Username: k.Auth.Username, OAuth: k.Auth.OAuth})
			}
			return nil, nil, keyed{}, refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
				"set the auth of the model key %s to one the runtime %s reads: it reads %s keys as %s, and the key's auth is %s",
				shown, runtime, format, orList(ways, ", ", " or "), keyAuthWords(auth))
		}
		variable := ofFormat[i].Variable
		if !slices.Contains(c.Placeholders, variable) {
			c.Placeholders = append(c.Placeholders, variable)
		}
		if !slices.Contains(names, variable) {
			names = append(names, variable)
		}
		key = keyed{Variable: variable + "=" + link.KeyPlaceholder(c.Name), Endpoint: places.Endpoint.Variable + "=" + c.Endpoint}
		for _, k := range keyVariables(rt) {
			if k != variable {
				key.Others = append(key.Others, k)
			}
		}
	}
	if err := checkPlaceholders(rt, out, placeholders); err != nil {
		return nil, nil, keyed{}, err
	}
	return out, names, key, nil
}

// modelOf is rt's model section and true, or false when it has none.
func modelOf(rt runtimes.Runtime) (runtimes.ModelPlaces, bool) {
	if m, ok := rt.(runtimes.Model); ok {
		return m.Model()
	}
	return runtimes.ModelPlaces{}, false
}

// deniedVariables are rt's denies and, when walled, its model overrides, each once:
// the names [variables.Resolve] adds to the deny list.
func deniedVariables(rt runtimes.Runtime, walled bool) []string {
	out := slices.Clone(secretsOf(rt).Denies)
	if walled {
		places, _ := modelOf(rt)
		for _, name := range places.Overrides {
			if !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
	}
	return out
}

// keyVariables are the variables of rt's model keys, each once.
func keyVariables(rt runtimes.Runtime) []string {
	places, _ := modelOf(rt)
	var out []string
	for _, k := range places.Keys {
		if !slices.Contains(out, k.Variable) {
			out = append(out, k.Variable)
		}
	}
	return out
}

// keyAuthWords is how a refusal writes how a model key is sent: the header with its
// name, a bearer, a bearer with oauth, or the basic scheme. The header's name goes
// through [accesskey.ShownValue], since a server's entry may contain a secret pasted
// there.
func keyAuthWords(a server.Auth) string {
	switch {
	case a.Scheme == "header":
		return "the header " + accesskey.ShownValue(a.Header, false)
	case a.Scheme == "bearer" && a.OAuth:
		return "a bearer with oauth"
	case a.Scheme == "bearer":
		return "a bearer"
	case a.Scheme == "":
		return "no auth"
	}
	return "the " + a.Scheme + " scheme"
}

// checkPlaceholders refuses a placeholder that goes into a variable for no credential,
// each [refusal.RunConfigurationInvalid]. The variable of a model key of rt gets a
// placeholder only from the start key, which [chosen] gives it: a host credential, from
// the server or the machine's, whose placeholders list one is refused with the
// credential's name, and so is one of names, the run answer's placeholders, with the
// placeholder's name. A placeholder of a host credential from the server, one with
// auth, may not be a variable rt denies, lists among its model overrides or in its
// reserves, or reads its model endpoint from; its name is the refusal's. Of names, a
// placeholder may not be one of those rt denies, overrides or reads its endpoint from,
// nor one rt declares or reserves that no credential has among its placeholders; the
// placeholder's name is the refusal's. A placeholder rt does not declare, such as a
// tool's GITHUB_TOKEN, passes, and so does a declared one of a credential.
func checkPlaceholders(rt runtimes.Runtime, credentials []server.LinkCredentialHosts, names []string) error {
	decl := secretsOf(rt)
	places, _ := modelOf(rt)
	overrides, endpoint := places.Overrides, places.Endpoint.Variable
	keys := keyVariables(rt)
	declared := slices.Clone(decl.Reserves)
	for _, d := range decl.Declares {
		declared = append(declared, d.Name)
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
	runtime := accesskey.ShownName(rt.Name(), false)
	for _, c := range credentials {
		if c.Format != "" {
			continue
		}
		shown := accesskey.ShownName(c.Name, true)
		for _, p := range c.Placeholders {
			why := takesNone(p)
			switch {
			case slices.Contains(keys, p) && c.Auth == nil:
				return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
					"remove %s from the placeholders of the credential %s in forager.yaml: the runtime %s reads a model key from it, and only a model key sets it; a model key has format, endpoint and auth",
					accesskey.ShownName(p, false), shown, runtime)
			case c.Auth == nil:
			case slices.Contains(keys, p):
				return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
					"remove %s from the placeholders of the credential %s in the run configuration: the runtime %s reads a model key from it, and only a credential with an API sets it",
					accesskey.ShownName(p, false), shown, runtime)
			case why != "":
				return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
					"remove %s from the placeholders of the credential %s in the run configuration: the descriptor of the runtime %s %s, and a placeholder goes only into a variable for a credential",
					accesskey.ShownName(p, false), shown, runtime, why)
			case slices.Contains(decl.Reserves, p):
				return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(c.Name),
					"remove %s from the placeholders of the credential %s in the run configuration: the descriptor of the runtime %s lists it in reserves, and a placeholder goes only into a variable for a credential",
					accesskey.ShownName(p, false), shown, runtime)
			}
		}
	}
	for _, p := range names {
		if why := takesNone(p); why != "" {
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(p),
				"remove %s from the placeholders of the machine's credentials and tools in forager.yaml: the descriptor of the runtime %s %s, and a placeholder goes only into a variable for a credential",
				accesskey.ShownName(p, false), runtime, why)
		}
		if slices.Contains(keys, p) {
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(p),
				"remove %s from the placeholders of the machine's tools in forager.yaml: the runtime %s reads a model key from it, and only a credential with an API sets it",
				accesskey.ShownName(p, false), runtime)
		}
		if slices.Contains(declared, p) && !slices.ContainsFunc(credentials, func(c server.LinkCredentialHosts) bool { return slices.Contains(c.Placeholders, p) }) {
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(p),
				"remove %s from the placeholders of the machine's tools in forager.yaml, or give it to a credential in forager.yaml: the runtime %s reads a secret from it, and no credential of the run has it among its placeholders",
				accesskey.ShownName(p, false), runtime)
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
// and placeholder, in order; nil when there is none. A credential's name or a
// placeholder that contains an access key secret or a run key is
// [accesskey.ShownName]'s phrase in its place, so the record never carries one.
func credentialVariables(credentials []server.LinkCredentialHosts) []map[string]string {
	var out []map[string]string
	for _, c := range credentials {
		for _, p := range c.Placeholders {
			out = append(out, map[string]string{"credential": accesskey.ShownName(c.Name, false), "name": accesskey.ShownName(p, false)})
		}
	}
	return out
}

// checkModelKey refuses a run whose gateway holds credentials for it, behind a wall or,
// without one, when a credential has a model key's variable among its placeholders,
// when its runtime has a model section with model keys and the run has none: no
// credential of credentials is an API credential, and no value of a model key's
// variable reaches the runtime, from what the run inherits, the run, the machine, the
// harness or the runtime's preparation. A run whose answer has no credential_hosts is
// not checked: its key may come from what the session does not see, such as a login of
// the developer's, a mount or an image. [checkPlaceholders] has refused every model
// key's placeholder but the start key's, so a run without a wall and without an API
// credential is not refused: its runtime may use the developer's login. The refusal is [refusal.ModelKeyMissing] with the model keys'
// variables. Without a wall, an inherited value of one of placeholderNames reaches
// nothing: the placeholder is set over it.
func checkModelKey(spec runSpec, rt runtimes.Runtime, credentials []server.LinkCredentialHosts, vars variables.Resolved, prepared runtimes.Launch, placeholderNames []string) error {
	if len(credentials) == 0 {
		return nil
	}
	keys := keyVariables(rt)
	if _, ok := modelOf(rt); !ok || len(keys) == 0 {
		return nil
	}
	if slices.ContainsFunc(credentials, func(c server.LinkCredentialHosts) bool { return c.Format != "" }) {
		return nil
	}
	isKey := func(p string) bool { return slices.Contains(keys, p) }
	if spec.Wall == nil && !slices.ContainsFunc(credentials, func(c server.LinkCredentialHosts) bool {
		return slices.ContainsFunc(c.Placeholders, isKey)
	}) {
		return nil
	}
	// What reaches the runtime, a later source's value over an earlier one's, as
	// environment writes the launch's.
	inherited := spec.Env
	if spec.Wall == nil {
		inherited = withoutNames(spec.Env, placeholderNames)
	}
	reaches := map[string]string{}
	for _, kv := range slices.Concat(inherited, vars.Env, vars.Fixed, prepared.Env) {
		name, value, _ := strings.Cut(kv, "=")
		reaches[name] = value
	}
	if slices.ContainsFunc(keys, func(k string) bool { return reaches[k] != "" }) {
		return nil
	}
	runtime := accesskey.ShownName(rt.Name(), false)
	return refusal.New(refusal.ModelKeyMissing, refusal.Shown(keys...),
		"give the run a model key for the runtime %s, in the run configuration or in forager.yaml: the gateway holds credentials for the run, and none of them is a model key; a model key has format, endpoint and auth",
		runtime)
}
