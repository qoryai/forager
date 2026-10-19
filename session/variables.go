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
// the gateway sets for the run, what a value of the machine's is read from. It returns the
// resolution and, for a walled run, the names to unset inside, which [Exec] takes out
// of the launch's environment: the runtime's declared and reserved variables and the
// names the runtime denies or the node's deny list removes, that nothing sets. Forager,
// the wall and the preparation set names too, [wall.Nest] among them for a run with
// nested Docker, docker, so none of theirs is ever unset; the wall's names for a run
// with an authority count as set only when the run has one, authority.
func resolve(spec Spec, rt runtimes.Runtime, served map[string]string, prepared runtimes.Launch, placeholderNames, reserved []string, docker, authority bool) (variables.Resolved, []string, error) {
	var decl runtimes.Declarations
	if s, ok := rt.(runtimes.Secrets); ok {
		decl = s.Secrets()
	}
	var runtimeNames []string
	for _, d := range decl.Declares {
		runtimeNames = append(runtimeNames, d.Name)
	}
	runtimeNames = append(runtimeNames, decl.Reserves...)
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
		Deny: spec.Variables.Deny, RuntimeDenies: decl.Denies, Runtime: runtimeNames,
		Placeholders: placeholderNames, ReadFrom: readFrom, Own: own,
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
		// A name the runtime denies or the node's deny list removes is unset too, so an
		// image's value for it does not reach the runtime either. A value that wins with
		// it stays, and so does a name Forager, the wall or the preparation sets. A
		// pattern names no variable to unset.
		for _, name := range slices.Concat(decl.Denies, spec.Variables.Deny) {
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
