package session

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestExecStopsWhenItCannotBeUndumpable pins Exec's first step: when prctl cannot
// clear its dumpable flag, Exec exits 125 without starting the program, and the line
// on stderr starts with the fix.
func TestExecStopsWhenItCannotBeUndumpable(t *testing.T) {
	was := prctl
	defer func() { prctl = was }()
	prctl = func(option int, _, _, _, _ uintptr) error {
		if option == unix.PR_SET_DUMPABLE {
			return unix.EPERM
		}
		return nil
	}
	var stderr strings.Builder
	code := Exec([]string{"--", "true"}, &stderr)
	if want := "exec: allow prctl(PR_SET_DUMPABLE) in the wall's seccomp profile: "; code != setupRunnerFailed || !strings.HasPrefix(stderr.String(), want) {
		t.Errorf("Exec: %d, %q; want 125 and a line that starts %q", code, stderr.String(), want)
	}
}
