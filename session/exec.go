package session

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"

	"github.com/qoryai/forager/accesskey"
)

// checkExec refuses an Exec a run cannot have: none behind a wall, one whose program is
// empty, and one with a NUL in a word.
func checkExec(spec runSpec) error {
	switch {
	case spec.Wall != nil && len(spec.Exec) == 0:
		return errors.New("a walled run starts its launch through Exec, the helper's exec, when it has names to unset, and the spec has none")
	case len(spec.Exec) > 0 && spec.Exec[0] == "":
		return errors.New("Exec's program is empty")
	case slices.ContainsFunc(spec.Exec, func(w string) bool { return strings.ContainsRune(w, 0) }):
		return errors.New("Exec holds a NUL, which no argument does")
	}
	return nil
}

// withExec is the launch of command and args started through the helper's exec, which
// unsets the names first; with no names, the launch as it is.
func withExec(helper, unset []string, command string, args []string) (string, []string) {
	if len(unset) == 0 {
		return command, args
	}
	words := slices.Clone(helper[1:])
	for _, name := range unset {
		words = append(words, "--unset", name)
	}
	return helper[0], append(append(words, "--", command), args...)
}

// Exec is the program that starts a walled run's launch with names taken out of its
// environment, the caller's binary running it inside the enclosure in a hidden mode,
// as it runs [Forward]: the session starts the launch through it, SessionSpec.Exec, when the
// run has names that nothing sets and wins with, the runtime's declared, reserved and
// denied names, its model overrides and the node's denied ones, so a value the image
// gives one never reaches the runtime, and neither does an empty one, which a program
// may read as set. It removes the names from its environment and executes the program, found in
// PATH by [exec.LookPath], in its place, with every other variable as it is: a program
// found only through . or an empty entry of PATH, which LookPath refuses, is not run.
//
// Its arguments are --unset NAME, any number of times, then -- and the program and
// its arguments, which no option of its reaches. A NAME is a variable's name: letters,
// digits and underscores, starting with a letter or an underscore. It returns only on
// an error, the exit status, as a shell does: 2 for arguments it cannot read, 127 for
// a program it does not find, or finds only through . or an empty entry of PATH, and
// 126 for one it cannot execute, its reason written to stderr.
func Exec(args []string, stderr io.Writer) int {
	names, argv, err := parseExec(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	for _, name := range names {
		os.Unsetenv(name)
	}
	path, err := exec.LookPath(argv[0])
	// program is the program as its messages print it.
	program := accesskey.ShownValue(argv[0], false)
	switch {
	case errors.Is(err, exec.ErrDot):
		fmt.Fprintf(stderr, "exec: %s: found only through . or an empty entry of PATH, which is not run\n", program)
		return 127
	case errors.Is(err, fs.ErrPermission), errors.Is(err, syscall.EISDIR):
		fmt.Fprintf(stderr, "exec: %s: cannot be executed: %v\n", program, accesskey.ShownError(err))
		return 126
	case err != nil:
		fmt.Fprintf(stderr, "exec: %s: not found\n", program)
		return 127
	}
	err = syscall.Exec(path, argv, os.Environ())
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(stderr, "exec: %s: not found: %v\n", program, accesskey.ShownError(err))
		return 127
	}
	fmt.Fprintf(stderr, "exec: %s: cannot be executed: %v\n", program, accesskey.ShownError(err))
	return 126
}

// parseExec reads [Exec]'s arguments: the names to unset, and the program and its
// arguments after --. A name outside a variable's grammar is refused without being
// quoted, since what is not a name may hold a value.
func parseExec(args []string) ([]string, []string, error) {
	var names []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--unset":
			if i+1 == len(args) {
				return nil, nil, errors.New("exec: --unset needs a name")
			}
			i++
			if !variableShape.MatchString(args[i]) {
				return nil, nil, errors.New("exec: an --unset is not a variable's name: letters, digits and underscores, starting with a letter or an underscore, of at most 128")
			}
			names = append(names, args[i])
		case "--":
			if i+1 == len(args) || args[i+1] == "" {
				return nil, nil, errors.New("exec: want --unset NAME ... -- program [args]: the program is missing")
			}
			return names, args[i+1:], nil
		default:
			return nil, nil, errors.New("exec: want --unset NAME ... -- program [args]")
		}
	}
	return nil, nil, errors.New("exec: want --unset NAME ... -- program [args]: -- is missing")
}
