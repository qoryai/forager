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
// it waits: the owner of its /proc fd directory in $OUT/owner, "denied" in $OUT/fds when
// its descriptors cannot be listed, the lines of its status that contain its users,
// groups, capabilities and no_new_privs in $OUT/parent, and the same lines of the
// program's status in $OUT/self.
const parentScript = `stat -c %u /proc/$PPID/fd > "$OUT/owner"
ls /proc/$PPID/fd > /dev/null 2>&1 || echo denied > "$OUT/fds"
grep -E '^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):' /proc/$PPID/status > "$OUT/parent"
grep -E '^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):' /proc/$$/status > "$OUT/self"`

// TestTheHelpersExecWaitsWithNothingTheProgramLacks pins the helper's exec while it
// waits as the program's parent: as it starts the program, no file descriptor above 2
// but the Go runtime's poller, an eventpoll and an eventfd, even one its parent passed
// on, as it lists them itself; not dumpable, so the program, unless it runs as root,
// cannot list them; and the program's users, groups, capabilities and no_new_privs.
func TestTheHelpersExecWaitsWithNothingTheProgramLacks(t *testing.T) {
	dir := t.TempDir()
	passed, err := os.Create(filepath.Join(dir, "passed-on"))
	if err != nil {
		t.Fatal(err)
	}
	defer passed.Close()
	cmd := exec.Command(os.Args[0], "exec", "--", "sh", "-c", parentScript)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "OUT=" + dir, "FAKE_FDS_OUT=" + filepath.Join(dir, "own-fds")}
	cmd.ExtraFiles = []*os.File{passed}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	fds, _ := os.ReadFile(filepath.Join(dir, "own-fds"))
	if len(fds) == 0 {
		t.Fatal("the helper's exec listed no descriptors")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(fds)), "\n") {
		fd, target, _ := strings.Cut(line, " ")
		switch {
		case fd == "0" || fd == "1" || fd == "2":
		case target == "anon_inode:[eventpoll]" || target == "anon_inode:[eventfd]":
		default:
			t.Errorf("the helper's exec starts the program with descriptor %s open on %s", fd, target)
		}
	}
	owner, _ := os.ReadFile(filepath.Join(dir, "owner"))
	denied, _ := os.ReadFile(filepath.Join(dir, "fds"))
	if os.Geteuid() != 0 && (strings.TrimSpace(string(owner)) != "0" || strings.TrimSpace(string(denied)) != "denied") {
		t.Errorf("the helper's exec waits dumpable: its /proc fd directory belongs to uid %q, and the program lists its descriptors: %v", owner, len(denied) == 0)
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
