package session

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/qoryai/runner/internal/credential"
	"github.com/qoryai/runner/internal/policy"
	"github.com/qoryai/runner/internal/tool"
	"github.com/qoryai/runner/internal/variables"
	"github.com/qoryai/runner/runtimes"
	"github.com/qoryai/runner/wall"
)

// variableShape is a variable's name as the contract bounds it.
var variableShape = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// checkVariables refuses the node's variables section when it cannot be one: a variable
// that is not NAME=value with a name of the contract's grammar, or whose value contains
// a NUL, a carriage return or a line feed, a deny entry that is neither a name nor a
// pattern, an unwalled mode other than the two. An error names a variable only by a
// name of the grammar, and never contains a value.
func checkVariables(v Variables) error {
	for _, kv := range v.Own {
		name, value, ok := strings.Cut(kv, "=")
		switch {
		case !ok && variableShape.MatchString(name):
			return fmt.Errorf("the node's variable %s has no value: each is NAME=value", name)
		case !ok:
			return errors.New("a node's variable is not NAME=value: each is NAME=value")
		case !variableShape.MatchString(name):
			return errors.New("a node's variable has a name other than letters, digits and underscores, starting with a letter or an underscore, of at most 128")
		case strings.ContainsAny(value, "\x00\r\n"):
			return fmt.Errorf("the node's variable %s holds a NUL, a carriage return or a line feed, which a variable's value does not", name)
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

// passes reports whether the run passes a value for the variable from the node: in
// what it inherits, what the harness sets or the node's own variables.
func passes(spec Spec, name string) bool {
	return slices.ContainsFunc(slices.Concat(spec.Env, spec.LaunchEnv, spec.Variables.Own), func(kv string) bool {
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

// resolve resolves the run's variables, the server's and the node's, and checks what
// the run passes into the enclosure. It returns the resolution and, for a walled run,
// the runtime's declared and reserved variables that neither a placeholder, the run
// nor the runtime's preparation sets, each as an empty value.
func resolve(spec Spec, rt runtimes.Runtime, served map[string]string, prepared runtimes.Launch, held *credential.Held, chosen []tool.Chosen) (variables.Resolved, []string, error) {
	var decl runtimes.Declarations
	if s, ok := rt.(runtimes.Secrets); ok {
		decl = s.Secrets()
	}
	var runtimeNames []string
	for _, d := range decl.Declares {
		runtimeNames = append(runtimeNames, d.Name)
	}
	runtimeNames = append(runtimeNames, decl.Reserves...)
	placeholderNames := slices.Concat(held.Placeholders, tool.Placeholders(chosen))
	// What a value of the machine's is read from: today a credential's variable. The
	// local values of the runner file's secrets section join it here.
	var machine []string
	for _, c := range spec.Credentials {
		if c.Env != "" {
			machine = append(machine, c.Env)
		}
	}
	runner := []string{EnvRunID, EnvSocket}
	runner = append(runner, names(prepared.Env)...)
	runner = append(runner, names(spec.LaunchEnv)...)
	if s, ok := spec.Wall.(wall.Setter); ok {
		runner = append(runner, s.Sets()...)
	}
	vars, err := variables.Resolve(variables.Run{
		Server: served, Node: spec.Variables.Own, Walled: spec.Wall != nil, Unwalled: spec.Variables.Unwalled,
		Deny: spec.Variables.Deny, RuntimeDenies: decl.Denies, Runtime: runtimeNames,
		Placeholders: placeholderNames, Machine: machine, Runner: runner,
	})
	if err != nil {
		return variables.Resolved{}, nil, err
	}
	passed := slices.Concat(spec.Env, spec.LaunchEnv, vars.Env)
	if err := variables.Check(passed, spec.Wall != nil, placeholderNames, machine); err != nil {
		return variables.Resolved{}, nil, err
	}
	// Behind a wall, a variable the runtime declares or reserves that neither a
	// placeholder, the run nor the runtime's preparation sets goes in empty, so an
	// image's own value for it does not reach the runtime. A value the run passes for
	// one stays the agent's, and one the preparation sets stays the runtime's.
	var emptied []string
	if spec.Wall != nil {
		set := append(names(passed), names(prepared.Env)...)
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
