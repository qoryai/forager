//go:build linux || darwin

package gateway_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/qoryai/forager/gateway"
)

// envHardenProcess, set in a child of a test, is how many times the child's
// TestHardenProcessChild calls gateway.HardenProcess.
const envHardenProcess = "GATEWAY_TEST_HARDEN_PROCESS"

// hardenProcessPrefix starts the one line on which TestHardenProcessChild reports.
const hardenProcessPrefix = "harden-process-result: "

// hardenProcessResult is what a child reports after its calls: the first failure, empty
// for none; the core size limit, or why reading it failed; and PR_GET_DUMPABLE on Linux
// and -1 elsewhere.
type hardenProcessResult struct {
	Err      string
	CoreCur  uint64
	CoreMax  uint64
	CoreErr  string
	Dumpable int
}

// TestHardenProcessChild calls gateway.HardenProcess as many times as envHardenProcess
// says, in a child that runHardenProcessChild starts, and reports what the calls left;
// in any other process it does nothing. The calls stay for the life of the process, so
// no test makes them in the test binary itself.
func TestHardenProcessChild(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv(envHardenProcess))
	if n <= 0 {
		return
	}
	var r hardenProcessResult
	for i := range n {
		if err := gateway.HardenProcess(); err != nil {
			r.Err = fmt.Sprintf("call %d: %v", i+1, err)
			break
		}
	}
	r.Dumpable = gateway.Dumpable()
	var c unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &c); err != nil {
		r.CoreErr = err.Error()
	}
	r.CoreCur, r.CoreMax = uint64(c.Cur), uint64(c.Max)
	b, _ := json.Marshal(r)
	fmt.Println(hardenProcessPrefix + string(b))
}

// runHardenProcessChild runs TestHardenProcessChild in a child of this test binary,
// which calls gateway.HardenProcess calls times, and returns its report.
func runHardenProcessChild(t *testing.T, calls int) hardenProcessResult {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHardenProcessChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), envHardenProcess+"="+strconv.Itoa(calls))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the child for %d calls: %v\n%s", calls, err, out)
	}
	for line := range bytes.Lines(out) {
		if rest, ok := bytes.CutPrefix(line, []byte(hardenProcessPrefix)); ok {
			var r hardenProcessResult
			if err := json.Unmarshal(rest, &r); err != nil {
				t.Fatal(err)
			}
			return r
		}
	}
	t.Fatalf("the child for %d calls reported nothing:\n%s", calls, out)
	return hardenProcessResult{}
}

// checkHardened checks what HardenProcess left in the child r reports: the core size
// limit is 0, soft and hard, and on Linux the process is not dumpable. On Linux, when a
// seccomp filter refuses prctl or prlimit64, the test is skipped with the failure,
// which starts with the fix.
func checkHardened(t *testing.T, r hardenProcessResult) {
	t.Helper()
	if r.Err != "" {
		if runtime.GOOS == "linux" && (strings.Contains(r.Err, ": allow prctl in this process's seccomp profile: ") || strings.Contains(r.Err, ": allow prlimit64 in this process's seccomp profile: ")) {
			t.Skipf("a seccomp filter refuses the call here, and HardenProcess fails with the fix: %s", r.Err)
		}
		t.Fatalf("HardenProcess: %s", r.Err)
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

// TestHardenProcessDeniesDumps pins gateway.HardenProcess, which a program calls first
// in main: the core size limit is 0, soft and hard, and on Linux the process is not
// dumpable.
func TestHardenProcessDeniesDumps(t *testing.T) {
	checkHardened(t, runHardenProcessChild(t, 1))
}

// TestHardenProcessTwice pins that a second call of gateway.HardenProcess succeeds and
// leaves the same, as Start's call does after the caller's outside a test binary.
func TestHardenProcessTwice(t *testing.T) {
	checkHardened(t, runHardenProcessChild(t, 2))
}
