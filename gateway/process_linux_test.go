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

// lockedKB is VmLck of /proc/self/status, the kB this process has locked in memory, -1
// when it does not read.
func lockedKB() int64 {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return -1
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), "VmLck:"); ok {
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
// locked.
func TestLockAllLocksMemory(t *testing.T) {
	var l unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &l); err != nil {
		t.Fatal(err)
	}
	if l.Cur != unix.RLIM_INFINITY {
		t.Skipf("RLIMIT_MEMLOCK is %d bytes here; docker run --ulimit memlock=-1 runs this test", l.Cur)
	}
	r := runHardenChild(t, "lock")
	if r.Err != "" {
		t.Fatalf("lockAll: %s", r.Err)
	}
	if r.LockedKB <= 0 {
		t.Errorf("VmLck is %d kB; want more than 0", r.LockedKB)
	}
}

// TestLockAllFailsWithTheFix pins lockAll's failure with RLIMIT_MEMLOCK at 0: its first
// line is the fix, at most 100 characters, and the next names the limit.
func TestLockAllFailsWithTheFix(t *testing.T) {
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
