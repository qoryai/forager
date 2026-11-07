package session_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// parentScript writes what the program sees of its parent, the helper's exec, while
// it waits: each file descriptor and its target in $OUT/fds, the lines of its status
// that hold its users, groups, capabilities and no_new_privs in $OUT/parent, and the
// same lines of the program's status in $OUT/self.
const parentScript = `for f in /proc/$PPID/fd/*; do echo "${f##*/} $(readlink "$f")"; done > "$OUT/fds"
grep -E '^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):' /proc/$PPID/status > "$OUT/parent"
grep -E '^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):' /proc/$$/status > "$OUT/self"`

// TestTheHelpersExecWaitsWithNothingTheProgramLacks pins the helper's exec while it
// waits as the program's parent: no file descriptor above 2 but the Go runtime's
// poller, an eventpoll and an eventfd, even one its parent passed on; and the program's
// users, groups, capabilities and no_new_privs.
func TestTheHelpersExecWaitsWithNothingTheProgramLacks(t *testing.T) {
	dir := t.TempDir()
	passed, err := os.Create(filepath.Join(dir, "passed-on"))
	if err != nil {
		t.Fatal(err)
	}
	defer passed.Close()
	cmd := exec.Command(os.Args[0], "exec", "--", "sh", "-c", parentScript)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "OUT=" + dir}
	cmd.ExtraFiles = []*os.File{passed}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	fds, _ := os.ReadFile(filepath.Join(dir, "fds"))
	for _, line := range strings.Split(strings.TrimSpace(string(fds)), "\n") {
		fd, target, _ := strings.Cut(line, " ")
		switch {
		case fd == "0" || fd == "1" || fd == "2":
		case target == "anon_inode:[eventpoll]" || target == "anon_inode:[eventfd]":
		default:
			t.Errorf("the helper's exec waits with descriptor %s open on %s", fd, target)
		}
	}
	parent, _ := os.ReadFile(filepath.Join(dir, "parent"))
	self, _ := os.ReadFile(filepath.Join(dir, "self"))
	if len(parent) == 0 || string(parent) != string(self) {
		t.Errorf("the helper's exec waits with\n%s\nand the program runs with\n%s", parent, self)
	}
}

// TestTheHelpersExecEndsByAFaultsSignal pins the end of the helper's exec by a signal
// the Go runtime handles itself, QUIT, ABRT and SEGV, and of USR1: the same signal,
// with no goroutine dump in its place.
func TestTheHelpersExecEndsByAFaultsSignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGQUIT, syscall.SIGABRT, syscall.SIGSEGV, syscall.SIGUSR1} {
		helperEndsBy(t, sig)
	}
}
