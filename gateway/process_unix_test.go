//go:build linux || darwin

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// envHarden, set in a child of a test, is what the child's TestHardenChild calls:
// dumps, lock, lock-none or start.
const envHarden = "GATEWAY_TEST_HARDEN"

// hardenPrefix starts the one line on which TestHardenChild reports.
const hardenPrefix = "harden-result: "

// hardenResult is what a child reports after the calls: the error and its errno, 0 for
// none; the core size limit, or why reading it failed; the soft RLIMIT_MEMLOCK, or why
// reading it failed; PR_GET_DUMPABLE on Linux and -1 elsewhere; and the kB of VmLck on
// Linux and -1 elsewhere.
type hardenResult struct {
	Err        string
	Errno      int
	CoreCur    uint64
	CoreMax    uint64
	CoreErr    string
	MemlockCur uint64
	MemlockErr string
	Dumpable   int
	LockedKB   int64
}

// TestHardenChild makes, in a child that runHardenChild starts, the calls that
// envHarden names, and reports what they left; in any other process it does nothing.
// The calls stay for the life of the process, so no test makes them in the test binary
// itself.
func TestHardenChild(t *testing.T) {
	var err error
	switch os.Getenv(envHarden) {
	case "":
		return
	case "dumps":
		err = harden(false, true)
	case "lock":
		err = harden(true, false)
	case "lock-none":
		var l unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &l); err != nil {
			t.Fatal(err)
		}
		l.Cur = 0
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &l); err != nil {
			t.Fatal(err)
		}
		err = harden(true, false)
	case "start":
		var g *Gateway
		g, err = Start(context.Background(), Config{Dir: t.TempDir(), NoLinkSocket: true, LockMemory: true})
		if err == nil {
			defer g.Close(context.Background())
		}
	default:
		t.Fatalf("%s=%s is none of dumps, lock, lock-none and start", envHarden, os.Getenv(envHarden))
	}
	r := hardenResult{Dumpable: dumpable(), LockedKB: statusField("VmLck")}
	if err != nil {
		r.Err = err.Error()
		var en unix.Errno
		if errors.As(err, &en) {
			r.Errno = int(en)
		}
	}
	var c unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &c); err != nil {
		r.CoreErr = err.Error()
	}
	r.CoreCur, r.CoreMax = uint64(c.Cur), uint64(c.Max)
	var m unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &m); err != nil {
		r.MemlockErr = err.Error()
	}
	r.MemlockCur = uint64(m.Cur)
	b, _ := json.Marshal(r)
	fmt.Println(hardenPrefix + string(b))
}

// runHardenChild runs TestHardenChild in a child of this test binary, with envHarden
// set to what, and returns its report.
func runHardenChild(t *testing.T, what string) hardenResult {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHardenChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), envHarden+"="+what)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the child for %s: %v\n%s", what, err, out)
	}
	for line := range bytes.Lines(out) {
		if rest, ok := bytes.CutPrefix(line, []byte(hardenPrefix)); ok {
			var r hardenResult
			if err := json.Unmarshal(rest, &r); err != nil {
				t.Fatal(err)
			}
			return r
		}
	}
	t.Fatalf("the child for %s reported nothing:\n%s", what, out)
	return hardenResult{}
}

// TestDenyDumpsLeavesNoCoreDump pins denyDumps: the core size limit is 0, soft and
// hard, and on Linux the process is not dumpable. On Linux, when a seccomp filter
// refuses prctl or prlimit64, it pins the one failure that call gives instead.
func TestDenyDumpsLeavesNoCoreDump(t *testing.T) {
	r := runHardenChild(t, "dumps")
	if r.Err != "" {
		want := wantDumpsError(r)
		if want == "" || r.Err != want {
			t.Fatalf("denyDumps: %q; want %q", r.Err, want)
		}
		t.Skipf("a seccomp filter refuses the call here, and denyDumps fails with the fix: %s", r.Err)
	}
	if r.CoreErr != "" {
		t.Fatalf("reading RLIMIT_CORE failed: %s", r.CoreErr)
	}
	if r.CoreCur != 0 || r.CoreMax != 0 {
		t.Errorf("RLIMIT_CORE is %d, hard %d; want 0 and 0", r.CoreCur, r.CoreMax)
	}
	if runtime.GOOS == "linux" && r.Dumpable != 0 {
		t.Errorf("PR_GET_DUMPABLE is %d; want 0", r.Dumpable)
	}
}

// TestAStartedTestBinaryKeepsItsDumps pins that Start in a test binary leaves the core
// size limit as it was: hardenProcess skips denyDumps there.
func TestAStartedTestBinaryKeepsItsDumps(t *testing.T) {
	var before unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &before); err != nil {
		t.Skipf("reading RLIMIT_CORE failed here: %v", err)
	}
	g, err := Start(context.Background(), Config{Dir: t.TempDir(), NoLinkSocket: true})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close(context.Background())
	var after unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("RLIMIT_CORE is %+v after Start; it was %+v", after, before)
	}
}

// TestStartWithLockMemory pins Config.LockMemory through Start: on Linux the memory is
// locked, or Start fails with the one error the limit and the errno give; elsewhere
// Start fails with the fix first.
func TestStartWithLockMemory(t *testing.T) {
	r := runHardenChild(t, "start")
	if runtime.GOOS != "linux" {
		want := "set gateway.lock_memory to false: Forager locks memory only on Linux, and this system is " + runtime.GOOS
		if r.Err != want {
			t.Errorf("Start: %q; want %q", r.Err, want)
		}
		return
	}
	if r.Err != "" {
		checkLockError(t, r)
		t.Skipf("Start failed with the fix, since RLIMIT_MEMLOCK is finite here or a seccomp filter refuses mlockall: %s", r.Err)
	}
	if r.LockedKB <= 0 {
		t.Errorf("VmLck is %d kB after Start; want more than 0", r.LockedKB)
	}
}
