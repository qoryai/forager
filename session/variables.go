package session

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/qoryai/runner/gateway"
	"github.com/qoryai/runner/internal/variables"
	"github.com/qoryai/runner/link"
	"github.com/qoryai/runner/policy"
	"github.com/qoryai/runner/runtimes"
	"github.com/qoryai/runner/wall"
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

// passes reports whether the run passes a value for the variable from the node: in
// what it inherits, what the harness sets, or the run's or the machine's variables.
func passes(spec Spec, name string) bool {
	return slices.ContainsFunc(slices.Concat(spec.Env, spec.LaunchFixed, spec.LaunchDefaults, spec.Variables.Run, spec.Variables.Machine), func(kv string) bool {
		return strings.HasPrefix(kv, name+"=")
	})
}

// nodePaths is how many hosts the node's path rules list beside a server's policy.
func nodePaths(pol *policy.Loaded) int {
	if pol.Node == nil {
		return 0
	}
	return len(pol.Node.Paths)
}

// resolve resolves the run's variables, from the fixed names to what the run
// inherits, after refusing what the run passes into the enclosure. It returns the
// resolution and, for a walled run, the runtime's declared and reserved variables that
// neither a placeholder, the run nor the runtime's preparation sets, each as an empty
// value.
func resolve(spec Spec, rt runtimes.Runtime, served map[string]string, prepared runtimes.Launch, held *gateway.HeldCredentials, chosen []gateway.ChosenTool) (variables.Resolved, []string, error) {
	var decl runtimes.Declarations
	if s, ok := rt.(runtimes.Secrets); ok {
		decl = s.Secrets()
	}
	var runtimeNames []string
	for _, d := range decl.Declares {
		runtimeNames = append(runtimeNames, d.Name)
	}
	runtimeNames = append(runtimeNames, decl.Reserves...)
	placeholderNames := slices.Concat(held.Placeholders, gateway.ToolPlaceholders(chosen))
	// What a value of the machine's is read from: a credential's variable.
	var readFrom []string
	for _, c := range spec.Credentials {
		if c.Env != "" {
			readFrom = append(readFrom, c.Env)
		}
	}
	// The runner's own names, the proxy's, the wall's and the preparation's: with the
	// placeholders and the harness's computed values, the run's fixed names.
	runner := []string{EnvRunID, EnvSocket}
	if spec.HarnessHome != "" {
		runner = append(runner, EnvHarnessHome)
	}
	runner = append(runner, names(link.ProxyEnv(""))...)
	runner = append(runner, names(prepared.Env)...)
	if s, ok := spec.Wall.(wall.Setter); ok {
		runner = append(runner, s.Sets()...)
	}
	vars, err := variables.Resolve(variables.Inputs{
		Fixed: spec.LaunchFixed, Server: served, Run: spec.Variables.Run, Machine: spec.Variables.Machine,
		Defaults: spec.LaunchDefaults, Shell: spec.Env,
		Walled: spec.Wall != nil, Unwalled: spec.Variables.Unwalled,
		Deny: spec.Variables.Deny, RuntimeDenies: decl.Denies, Runtime: runtimeNames,
		Placeholders: placeholderNames, ReadFrom: readFrom, Runner: runner,
	})
	if err != nil {
		return variables.Resolved{}, nil, err
	}
	// Behind a wall, a variable the runtime declares or reserves that neither a
	// placeholder, the run nor the runtime's preparation sets goes in empty, so an
	// image's own value for it does not reach the runtime. A value the run passes for
	// one stays the agent's, and one the preparation sets stays the runtime's.
	var emptied []string
	if spec.Wall != nil {
		set := slices.Concat(names(spec.Env), names(vars.Env), names(vars.Fixed), names(prepared.Env))
		for _, name := range runtimeNames {
			if !slices.Contains(placeholderNames, name) && !slices.Contains(set, name) {
				emptied = append(emptied, name+"=")
			}
		}
	}
	return vars, emptied, nil
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
