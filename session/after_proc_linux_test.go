//go:build linux

package session_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
)

// TestAftersCommandCannotReadTheHelpersProcFiles pins the helper's first step in its
// --after-only mode: it makes itself not dumpable, so /proc denies its environment and
// descriptors to After's command, which has the helper's user. A helper that skips the
// step leaves both readable, and the connection to the session's socket with them.
func TestAftersCommandCannotReadTheHelpersProcFiles(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads the files whatever the helper's dumpable flag is")
	}
	sp, _ := afterSpec(t, "exit 0", "/bin/sh", "-c", `
cat /proc/$PPID/environ > after-environ 2> after-environ-err; echo "environ $?" > after-probe
ls /proc/$PPID/fd > after-fds 2> after-fds-err; echo "fds $?" >> after-probe`)
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.After == nil || res.After.State != event.StateSucceeded {
		t.Fatalf("Result.After %+v; want succeeded", res.After)
	}
	read := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(sp.Dir, name))
		return string(b)
	}
	if got := read("after-probe"); got != "environ 1\nfds 2\n" && got != "environ 1\nfds 1\n" {
		t.Errorf("the probe's results %q; want both reads denied", got)
	}
	for _, f := range []string{"after-environ", "after-fds"} {
		if b := read(f); b != "" {
			t.Errorf("After's command read the helper's %s: %q", f, b)
		}
	}
	if !strings.Contains(read("after-environ-err"), "Permission denied") {
		t.Errorf("the environment read's error %q; want Permission denied", read("after-environ-err"))
	}
}
