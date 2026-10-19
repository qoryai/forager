package gateway

import "testing"

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
