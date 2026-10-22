package session

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/session/internal/runfile"
	"github.com/qoryai/forager/session/runtimes"
)

// PreparationScript is the script, in the session's directory, that the runtime of a
// session with setup commands is started through.
const PreparationScript = "preparation.sh"

// preparationScript runs the setup commands written in place of @SETUP@, one setup
// line each: setup, the runner's words, the command's number, -- and the command's
// words, each word quoted. It then starts the command and its arguments, once every
// setup command exits 0. A setup command that exits otherwise is the script's exit
// status, and neither a later setup command nor the command starts. Each runner runs
// in the background so a signal reaches the script while it runs: TERM, INT, HUP,
// QUIT, USR1 or USR2 asks the runner to leave with TERM, which a program in the
// background has not ignored, and the command never starts; the script exits with the
// runner's status. A stop between two setup commands, or after the last one and
// before the command starts, starts nothing more, and the script exits with the last
// runner's status.
const preparationScript = `# Runs the session's setup commands, one after another, then starts the command and
# its arguments once every one exits 0. Written by Forager for one run.
pid= stopped= status=0
stop() {
	stopped=1
	[ -z "$pid" ] || kill -TERM "$pid" 2>/dev/null
}
trap stop TERM INT HUP QUIT USR1 USR2
setup() {
	[ -z "$stopped" ] || exit "$status"
	"$@" </dev/null &
	pid=$!
	[ -z "$stopped" ] || kill -TERM "$pid" 2>/dev/null
	while :; do
		wait "$pid"
		status=$?
		kill -0 "$pid" 2>/dev/null || break
	done
	pid=
	[ "$status" -eq 0 ] && [ -z "$stopped" ] || exit "$status"
}
@SETUP@
trap - TERM INT HUP QUIT USR1 USR2
[ -z "$stopped" ] || exit "$status"
exec "$@"
`

// checkSetup refuses setup commands a session cannot have: any without a Wall or a
// SetupRunner, a runner whose program is empty or with a NUL, and a command with no
// name, an empty program or a NUL.
func checkSetup(spec runSpec) error {
	setup, runner := spec.SessionSpec.Setup, spec.SetupRunner
	hasNUL := func(w string) bool { return strings.ContainsRune(w, 0) }
	switch {
	case len(setup) == 0:
		return nil
	case spec.Wall == nil:
		return errors.New("Open the run with a wall to run its setup: setup runs in a container of the run's image.")
	case len(runner) == 0 || runner[0] == "":
		return errors.New("Set SessionSpec.SetupRunner to the command that runs one setup command, such as the helper's setup-command verb: SessionSpec.Setup runs each command through it.")
	case slices.ContainsFunc(runner, hasNUL):
		return errors.New("Remove the NUL from SessionSpec.SetupRunner: no argument contains one.")
	}
	for i, c := range setup {
		switch {
		case c.Name == "":
			return fmt.Errorf("Give setup command %d a name, such as %q.", i+1, "install")
		case len(c.Args) == 0 || c.Args[0] == "":
			return fmt.Errorf("Give setup command %d a program: its first word is empty.", i+1)
		case hasNUL(c.Name) || slices.ContainsFunc(c.Args, hasNUL):
			return fmt.Errorf("Remove the NUL from setup command %d: no argument contains one.", i+1)
		}
	}
	return nil
}

// withSetup starts the launch through the script of [PreparationScript], which it
// writes into the session's directory with a setup line for each command of setup,
// through runner: /bin/sh, the script, then the launch's command and arguments. No
// setup commands leave the launch as it is.
func withSetup(sessionDir string, runner []string, setup []SetupCommand, launch runtimes.Launch) (runtimes.Launch, error) {
	if len(setup) == 0 {
		return launch, nil
	}
	lines := make([]string, len(setup))
	for i, c := range setup {
		words := []string{"setup"}
		for _, w := range runner {
			words = append(words, quote(w))
		}
		words = append(words, strconv.Itoa(i+1), "--")
		for _, w := range c.Args {
			words = append(words, quote(w))
		}
		lines[i] = strings.Join(words, " ")
	}
	script := strings.Replace(preparationScript, "@SETUP@", strings.Join(lines, "\n"), 1)
	path := filepath.Join(sessionDir, PreparationScript)
	if err := runfile.Replace(path, []byte(script), 0o644); err != nil {
		return runtimes.Launch{}, accesskey.ShownError(err)
	}
	launch.Args = append([]string{path, launch.Command}, launch.Args...)
	launch.Command = "/bin/sh"
	return launch, nil
}

// insideSetup is setup with each word of each command's Args as inside writes it.
func insideSetup(setup []SetupCommand, inside func(string) string) []SetupCommand {
	out := make([]SetupCommand, len(setup))
	for i, c := range setup {
		out[i] = SetupCommand{Name: c.Name, Args: insideAll(c.Args, inside)}
	}
	return out
}

// quote is s as one word of the shell, in single quotes: nothing inside them is
// expanded, and a single quote inside ends them, is written escaped, and opens them
// again.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
