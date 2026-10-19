//go:build linux || darwin

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// envHarden, set in a child of a test, is what the child's TestHardenChild calls:
// dumps, lock, lock-none or start.
const envHarden = "GATEWAY_TEST_HARDEN"

// memlockFix is the first line of lockAll's failure on Linux under a finite
// RLIMIT_MEMLOCK, and mlockallFix under RLIMIT_MEMLOCK unlimited.
const (
	memlockFix  = "raise RLIMIT_MEMLOCK to unlimited: LimitMEMLOCK=infinity in a systemd unit, or ulimit -l unlimited"
	mlockallFix = "allow mlockall in the gateway's seccomp profile, or set gateway.lock_memory to false"
	// unreadFix is the first line when RLIMIT_MEMLOCK does not read either.
	unreadFix = "raise RLIMIT_MEMLOCK to unlimited, or allow mlockall and prlimit64 in the gateway's seccomp profile"
)

// seccompFilter is the Seccomp of /proc/self/status under a seccomp filter.
const seccompFilter = 2

// hardenPrefix starts the one line on which TestHardenChild reports.
const hardenPrefix = "harden-result: "

// hardenResult is what a child reports after the calls: the error, the core size
// limit or why it did not read, PR_GET_DUMPABLE on Linux, the kB of VmLck on Linux, and
// the Seccomp mode of /proc/self/status on Linux; -1 for each of the last three
// elsewhere.
type hardenResult struct {
	Err      string
	CoreCur  uint64
	CoreMax  uint64
	CoreErr  string
	Dumpable int
	LockedKB int64
	Seccomp  int64
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
	r := hardenResult{Dumpable: dumpable(), LockedKB: statusField("VmLck"), Seccomp: statusField("Seccomp")}
	if err != nil {
		r.Err = err.Error()
	}
	var c unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &c); err != nil {
		r.CoreErr = err.Error()
	}
	r.CoreCur, r.CoreMax = uint64(c.Cur), uint64(c.Max)
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
// hard, and on Linux the process is not dumpable. Under a seccomp filter that refuses
// prctl or prlimit64, it pins the failure's fix instead.
func TestDenyDumpsLeavesNoCoreDump(t *testing.T) {
	r := runHardenChild(t, "dumps")
	if r.Err != "" {
		if r.Seccomp == seccompFilter {
			for _, fix := range []string{
				"allow prctl in the gateway's seccomp profile: PR_SET_DUMPABLE 0 failed: ",
				"allow prlimit64 in the gateway's seccomp profile: RLIMIT_CORE 0 failed: ",
			} {
				if strings.HasPrefix(r.Err, fix) {
					t.Skipf("a seccomp filter refuses the call here, and denyDumps fails with the fix: %s", r.Err)
				}
			}
		}
		t.Fatalf("denyDumps: %s", r.Err)
	}
	if r.CoreErr != "" {
		t.Fatalf("RLIMIT_CORE does not read: %s", r.CoreErr)
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
		t.Skipf("RLIMIT_CORE does not read here: %v", err)
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
// locked, or with a finite RLIMIT_MEMLOCK Start fails with the fix first; elsewhere
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
		first, _, _ := strings.Cut(r.Err, "\n")
		filtered := r.Seccomp == seccompFilter && (first == mlockallFix || first == unreadFix)
		if first != memlockFix && !filtered {
			t.Errorf("Start: %q; want the first line %q, or %q or %q under a seccomp filter", r.Err, memlockFix, mlockallFix, unreadFix)
		}
		if len(first) > 100 {
			t.Errorf("the first line is %d characters; want at most 100", len(first))
		}
		t.Skipf("Start failed with the fix, since RLIMIT_MEMLOCK is finite here or a seccomp filter refuses mlockall: %s", r.Err)
	}
	if r.LockedKB <= 0 {
		t.Errorf("VmLck is %d kB after Start; want more than 0", r.LockedKB)
	}
}
