package gateway

import (
	"errors"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// dumpable is -1 on macOS, which has no PR_GET_DUMPABLE.
func dumpable() int { return -1 }

// statusField is -1 on macOS, which has no /proc/self/status.
func statusField(string) int64 { return -1 }

// wantDumpsError is empty on macOS: no failure of denyDumps is expected there.
func wantDumpsError(hardenResult) string { return "" }

// checkLockError is not reached on macOS, where Start refuses LockMemory first.
func checkLockError(t *testing.T, r hardenResult) {
	t.Helper()
	t.Errorf("lockAll on macOS: %s", r.Err)
}

// fakeDenyDumps replaces denyDumps' system calls for the test t: each appends its name
// to calls and returns its error from fail, nil for none.
func fakeDenyDumps(t *testing.T, calls *[]string, fail map[string]error) {
	t.Helper()
	ptrace, rlimit := ptraceDenyAttach, setrlimit
	t.Cleanup(func() { ptraceDenyAttach, setrlimit = ptrace, rlimit })
	ptraceDenyAttach = func() error {
		*calls = append(*calls, "ptrace")
		return fail["ptrace"]
	}
	setrlimit = func(int, *unix.Rlimit) error {
		*calls = append(*calls, "setrlimit")
		return fail["setrlimit"]
	}
}

const (
	ptraceFix = "allow ptrace in the gateway's sandbox: PT_DENY_ATTACH failed: "
	rlimitFix = "allow setrlimit in the gateway's sandbox: RLIMIT_CORE 0 failed: "
)

// TestDenyDumpsMakesEveryCall pins that denyDumps makes both calls, PT_DENY_ATTACH
// first, when either fails, and returns every failure, one per line in the order of
// the calls, each starting with its fix.
func TestDenyDumpsMakesEveryCall(t *testing.T) {
	for _, c := range []struct {
		fail map[string]error
		want string
	}{
		{map[string]error{"ptrace": unix.ENOTSUP}, ptraceFix + unix.ENOTSUP.Error()},
		{map[string]error{"setrlimit": unix.EPERM}, rlimitFix + unix.EPERM.Error()},
		{map[string]error{"ptrace": unix.ENOTSUP, "setrlimit": unix.EPERM}, ptraceFix + unix.ENOTSUP.Error() + "\n" + rlimitFix + unix.EPERM.Error()},
	} {
		var calls []string
		fakeDenyDumps(t, &calls, c.fail)
		err := denyDumps()
		if !slices.Equal(calls, []string{"ptrace", "setrlimit"}) {
			t.Errorf("with %v failing, the calls are %v; want ptrace and setrlimit", c.fail, calls)
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

// TestHardenDeniesDumpsWhenLockAllFails pins that harden calls denyDumps after lockAll
// fails, which it does on macOS, and returns both failures, lockAll's first.
func TestHardenDeniesDumpsWhenLockAllFails(t *testing.T) {
	var calls []string
	fakeDenyDumps(t, &calls, map[string]error{"ptrace": unix.ENOTSUP})
	err := harden(true, true)
	if !slices.Equal(calls, []string{"ptrace", "setrlimit"}) {
		t.Errorf("the calls are %v; want ptrace and setrlimit", calls)
	}
	want := "set gateway.lock_memory to false: Forager locks memory only on Linux, and this system is darwin\n" + ptraceFix + unix.ENOTSUP.Error()
	if err == nil || err.Error() != want {
		t.Errorf("harden: %v; want %q", err, want)
	}
}
