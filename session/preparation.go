package session

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/session/internal/runfile"
	"github.com/qoryai/forager/session/runtimes"
)

// PreparationScript is the script, in the run directory, that the runtime of a run
// with a preparation is started through.
const PreparationScript = "preparation.sh"

// preparationScript runs the preparation written in place of @PREPARATION@, each word
// quoted, with no input, and then starts the command its arguments hold, once the
// preparation exits 0. A preparation that exits otherwise is the script's exit status,
// and the command never starts. The preparation runs in the background so a signal
// reaches the script while it runs: TERM, INT, HUP, QUIT, USR1 or USR2 asks the
// preparation to leave with TERM, which a program in the background has not ignored,
// and the command never starts; the script exits with the preparation's status.
const preparationScript = `# Runs the run's preparation, then starts the command its arguments hold once the
# preparation exits 0. Written by Forager for one run.
pid= stopped=
stop() {
	stopped=1
	[ -z "$pid" ] || kill -TERM "$pid" 2>/dev/null
}
trap stop TERM INT HUP QUIT USR1 USR2
@PREPARATION@ </dev/null &
pid=$!
[ -z "$stopped" ] || kill -TERM "$pid" 2>/dev/null
while :; do
	wait "$pid"
	status=$?
	kill -0 "$pid" 2>/dev/null || break
done
trap - TERM INT HUP QUIT USR1 USR2
[ "$status" -eq 0 ] && [ -z "$stopped" ] || exit "$status"
exec "$@"
`

// checkPreparation refuses a preparation a run cannot have: one without a Wall, one
// whose program is empty, and one with a NUL in a word.
func checkPreparation(spec runSpec) error {
	switch {
	case len(spec.Preparation) == 0:
		return nil
	case spec.Wall == nil:
		return errors.New("a preparation runs inside the wall, and the spec has no Wall")
	case spec.Preparation[0] == "":
		return errors.New("the preparation's program is empty")
	case slices.ContainsFunc(spec.Preparation, func(w string) bool { return strings.ContainsRune(w, 0) }):
		return errors.New("the preparation holds a NUL, which no argument does")
	}
	return nil
}

// withPreparation starts the launch through the script of [PreparationScript], which
// it writes into the run directory with the preparation in it: /bin/sh, the script,
// then the launch's command and arguments. No preparation leaves the launch as it is.
func withPreparation(runDir string, preparation []string, launch runtimes.Launch) (runtimes.Launch, error) {
	if len(preparation) == 0 {
		return launch, nil
	}
	words := make([]string, len(preparation))
	for i, w := range preparation {
		words[i] = quote(w)
	}
	script := strings.Replace(preparationScript, "@PREPARATION@", strings.Join(words, " "), 1)
	path := filepath.Join(runDir, PreparationScript)
	if err := runfile.Replace(path, []byte(script), 0o644); err != nil {
		return runtimes.Launch{}, accesskey.ShownError(err)
	}
	launch.Args = append([]string{path, launch.Command}, launch.Args...)
	launch.Command = "/bin/sh"
	return launch, nil
}

// quote is s as one word of the shell, in single quotes: nothing inside them is
// expanded, and a single quote inside ends them, is written escaped, and opens them
// again.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
