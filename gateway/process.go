package gateway

import "testing"

// hardenProcess is what Start sets on this process before it starts anything: with
// lockMemory, lockAll, and then, in any process but a test binary, denyDumps. It
// returns the first failure, whose message starts with the fix.
//
// A test binary, the one `go test` builds, skips denyDumps: on macOS PT_DENY_ATTACH
// ends a process that a debugger traces, so `dlv test` could not debug a test that
// starts a gateway, and on Linux a non-dumpable test binary takes no debugger that
// attaches later. The tests of these calls make them in a child
// process, through harden.
func hardenProcess(lockMemory bool) error { return harden(lockMemory, !testing.Testing()) }

// harden calls lockAll when lockMemory is true, then denyDumps when dumps is true.
func harden(lockMemory, dumps bool) error {
	if lockMemory {
		if err := lockAll(); err != nil {
			return err
		}
	}
	if dumps {
		return denyDumps()
	}
	return nil
}
