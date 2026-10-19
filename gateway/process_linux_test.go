package gateway

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// dumpable is PR_GET_DUMPABLE of this process, -1 when prctl fails.
func dumpable() int {
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return -1
	}
	return v
}

// statusField is the number of the field name of /proc/self/status, such as VmLck, the
// kB this process has locked in memory, or Seccomp, its seccomp mode; -1 when it does
// not read.
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
// locked. Under a seccomp filter that refuses mlockall, it pins the failure's two lines
// instead.
func TestLockAllLocksMemory(t *testing.T) {
	var l unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &l); err != nil {
		t.Skipf("RLIMIT_MEMLOCK does not read here: %v", err)
	}
	if l.Cur != unix.RLIM_INFINITY {
		t.Skipf("RLIMIT_MEMLOCK is %d bytes here; docker run --ulimit memlock=-1 runs this test", l.Cur)
	}
	r := runHardenChild(t, "lock")
	if r.Err != "" {
		first, rest, _ := strings.Cut(r.Err, "\n")
		if r.Seccomp != seccompFilter || first != mlockallFix {
			t.Fatalf("lockAll: %s", r.Err)
		}
		if want := "gateway.lock_memory is true, and mlockall failed with RLIMIT_MEMLOCK unlimited: "; !strings.HasPrefix(rest, want) {
			t.Errorf("the second line %q; want it to start %q", rest, want)
		}
		t.Skipf("a seccomp filter refuses mlockall here, and lockAll fails with the fix: %s", r.Err)
	}
	if r.LockedKB <= 0 {
		t.Errorf("VmLck is %d kB; want more than 0", r.LockedKB)
	}
}

// TestLockAllFailsWithTheFix pins lockAll's failure with RLIMIT_MEMLOCK at 0: its first
// line is the fix, at most 100 characters, and the next names the limit.
func TestLockAllFailsWithTheFix(t *testing.T) {
	var l unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &l); err != nil {
		t.Skipf("RLIMIT_MEMLOCK does not read here, so the child cannot set it to 0: %v", err)
	}
	r := runHardenChild(t, "lock-none")
	if r.Err == "" {
		t.Skip("the child locked its memory with RLIMIT_MEMLOCK at 0, so it has CAP_IPC_LOCK")
	}
	first, rest, _ := strings.Cut(r.Err, "\n")
	if first != memlockFix || len(first) > 100 {
		t.Errorf("the first line %q; want %q", first, memlockFix)
	}
	if want := "gateway.lock_memory is true, and mlockall failed with RLIMIT_MEMLOCK at 0 bytes: "; !strings.HasPrefix(rest, want) {
		t.Errorf("the second line %q; want it to start %q", rest, want)
	}
}
