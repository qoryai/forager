package gateway

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The first lines of lockAll's failure: memlockFix when the limit is the cause,
// mlockallFix when a seccomp filter is, and unreadFix when reading RLIMIT_MEMLOCK
// failed too.
const (
	memlockFix  = "raise RLIMIT_MEMLOCK to unlimited: LimitMEMLOCK=infinity in a systemd unit, or ulimit -l unlimited"
	mlockallFix = "allow mlockall in the gateway's seccomp profile, or set gateway.lock_memory to false"
	unreadFix   = "raise RLIMIT_MEMLOCK to unlimited, or allow mlockall and prlimit64 in the gateway's seccomp profile"
	dockerTail  = "; in Docker, pass --ulimit memlock=-1, or set gateway.lock_memory to false"
)

const (
	prctlFix   = "allow prctl in the gateway's seccomp profile: PR_SET_DUMPABLE 0 failed: "
	prlimitFix = "allow prlimit64 in the gateway's seccomp profile: RLIMIT_CORE 0 failed: "
)

// wantDumpsError is denyDumps' failure in the child r reports, from its errnos in
// order: prctl's when the process is still dumpable, then prlimit64's when the core
// size limit is not 0, one per line.
func wantDumpsError(r hardenResult) string {
	var lines []string
	if r.Dumpable == 1 {
		lines = append(lines, prctlFix)
	}
	if r.CoreCur != 0 || r.CoreMax != 0 {
		lines = append(lines, prlimitFix)
	}
	if len(lines) != len(r.Errnos) {
		return ""
	}
	for i, en := range r.Errnos {
		lines[i] += unix.Errno(en).Error()
	}
	return strings.Join(lines, "\n")
}

// fakeDenyDumps replaces denyDumps' system calls for the test t: each appends its name
// to calls and returns its error from fail, nil for none.
func fakeDenyDumps(t *testing.T, calls *[]string, fail map[string]error) {
	t.Helper()
	pr, rlimit := prctl, setrlimit
	t.Cleanup(func() { prctl, setrlimit = pr, rlimit })
	prctl = func(int, uintptr, uintptr, uintptr, uintptr) error {
		*calls = append(*calls, "prctl")
		return fail["prctl"]
	}
	setrlimit = func(int, *unix.Rlimit) error {
		*calls = append(*calls, "setrlimit")
		return fail["setrlimit"]
	}
}

// TestDenyDumpsMakesEveryCall pins that denyDumps makes both calls, prctl first, when
// either fails, and returns every failure, one per line in the order of the calls,
// each starting with its fix.
func TestDenyDumpsMakesEveryCall(t *testing.T) {
	for _, c := range []struct {
		fail map[string]error
		want string
	}{
		{map[string]error{"prctl": unix.EPERM}, prctlFix + unix.EPERM.Error()},
		{map[string]error{"setrlimit": unix.EPERM}, prlimitFix + unix.EPERM.Error()},
		{map[string]error{"prctl": unix.EPERM, "setrlimit": unix.ENOSYS}, prctlFix + unix.EPERM.Error() + "\n" + prlimitFix + unix.ENOSYS.Error()},
	} {
		var calls []string
		fakeDenyDumps(t, &calls, c.fail)
		err := denyDumps()
		if !slices.Equal(calls, []string{"prctl", "setrlimit"}) {
			t.Errorf("with %v failing, the calls are %v; want prctl and setrlimit", c.fail, calls)
		}
		if err == nil || err.Error() != c.want {
			t.Errorf("with %v failing, denyDumps: %v; want %q", c.fail, err, c.want)
			continue
		}
		for _, e := range c.fail {
			if !errors.Is(err, e) {
				t.Errorf("with %v failing, denyDumps' error wraps no %v", c.fail, e)
			}
		}
	}
}

// wantLockError is lockAll's failure in the child r reports, from its soft
// RLIMIT_MEMLOCK and mlockall's errno: the limit is the cause for ENOMEM under a finite
// limit and for EPERM under a limit of 0, and a seccomp filter otherwise.
func wantLockError(r hardenResult) string {
	en := unix.Errno(r.Errno)
	if r.MemlockErr != "" {
		return unreadFix + "\ngateway.lock_memory is true, mlockall failed: " + en.Error() + ", and reading RLIMIT_MEMLOCK failed: " + r.MemlockErr + dockerTail
	}
	limit := "unlimited"
	if r.MemlockCur != unix.RLIM_INFINITY {
		limit = fmt.Sprintf("at %d bytes", r.MemlockCur)
	}
	if r.MemlockCur != unix.RLIM_INFINITY && (en == unix.ENOMEM || en == unix.EPERM && r.MemlockCur == 0) {
		return memlockFix + "\ngateway.lock_memory is true, and mlockall failed with RLIMIT_MEMLOCK " + limit + ": " + en.Error() + dockerTail
	}
	return mlockallFix + "\ngateway.lock_memory is true, and mlockall failed with RLIMIT_MEMLOCK " + limit + ": " + en.Error()
}

// checkLockError checks that the child's failure is the one wantLockError gives, with
// a first line of at most 100 characters.
func checkLockError(t *testing.T, r hardenResult) {
	t.Helper()
	if want := wantLockError(r); r.Err != want {
		t.Errorf("lockAll: %q; want %q", r.Err, want)
	}
	if first, _, _ := strings.Cut(r.Err, "\n"); len(first) > 100 {
		t.Errorf("the first line is %d characters; want at most 100", len(first))
	}
}

// dumpable is PR_GET_DUMPABLE of this process, -1 when prctl fails.
func dumpable() int {
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return -1
	}
	return v
}

// statusField is the number of the field name of /proc/self/status, such as VmLck, the
// kB this process has locked in memory; -1 when reading it fails.
func statusField(name string) int64 {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return -1
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), name+":"); ok {
			n, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
			if err != nil {
				return -1
			}
			return n
		}
	}
	return -1
}

// TestLockAllLocksMemory pins lockAll with RLIMIT_MEMLOCK unlimited: every page is
// locked. When a seccomp filter refuses mlockall, it pins the one failure that gives:
// mlockallFix, and the limit unlimited.
func TestLockAllLocksMemory(t *testing.T) {
	var l unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &l); err != nil {
		t.Skipf("reading RLIMIT_MEMLOCK failed here: %v", err)
	}
	if l.Cur != unix.RLIM_INFINITY {
		t.Skipf("RLIMIT_MEMLOCK is %d bytes here; docker run --ulimit memlock=-1 runs this test", l.Cur)
	}
	r := runHardenChild(t, "lock")
	if r.Err != "" {
		want := mlockallFix + "\ngateway.lock_memory is true, and mlockall failed with RLIMIT_MEMLOCK unlimited: " + unix.Errno(r.Errno).Error()
		if r.Err != want {
			t.Fatalf("lockAll: %q; want %q", r.Err, want)
		}
		t.Skipf("a seccomp filter refuses mlockall here, and lockAll fails with the fix: %s", r.Err)
	}
	if r.LockedKB <= 0 {
		t.Errorf("VmLck is %d kB; want more than 0", r.LockedKB)
	}
}

// TestLockAllFailsWithTheFix pins lockAll's failure with RLIMIT_MEMLOCK at 0, EPERM:
// its first line is memlockFix, and the next names the limit.
func TestLockAllFailsWithTheFix(t *testing.T) {
	var l unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &l); err != nil {
		t.Skipf("reading RLIMIT_MEMLOCK failed here, so the child cannot set it to 0: %v", err)
	}
	r := runHardenChild(t, "lock-none")
	if r.Err == "" {
		t.Skip("the child locked its memory with RLIMIT_MEMLOCK at 0, so it has CAP_IPC_LOCK")
	}
	want := memlockFix + "\ngateway.lock_memory is true, and mlockall failed with RLIMIT_MEMLOCK at 0 bytes: operation not permitted" + dockerTail
	if r.Err != want {
		t.Errorf("lockAll: %q; want %q", r.Err, want)
	}
	checkLockError(t, r)
}
