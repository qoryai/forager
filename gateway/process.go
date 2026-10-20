package gateway

import (
	"errors"
	"testing"
)

// HardenProcess denies core dumps of this process and debugger attaches to it, for the
// life of the process. Call it first in main, before the program reads its
// configuration, a key or its environment: Start makes the same calls, but the
// caller's Config, the TLS key and the environment are in memory before Start runs, and
// a debugger that attaches before then can read them. Start makes the calls again,
// and the second call succeeds.
//
// On Linux it calls prctl(PR_SET_DUMPABLE, 0), so that the kernel writes no core dump
// of the process and a process of the same user without CAP_SYS_PTRACE can neither
// attach to it with ptrace nor read its memory or its environment under /proc; it then
// sets RLIMIT_CORE to 0, soft and hard. On macOS it calls ptrace(PT_DENY_ATTACH); a
// process that a debugger traces exits at that call, with status 45 (ENOTSUP). It then
// sets RLIMIT_CORE to 0, soft and hard. On other systems it does nothing. A program
// this process starts keeps RLIMIT_CORE at 0.
//
// HardenProcess locks no memory: Start does, with Config.LockMemory. Unlike Start, it
// makes its calls in a test binary too. It makes every call when one fails, and returns
// every failure, one per line in the order of the calls, each starting with its fix.
func HardenProcess() error { return denyDumps() }

// hardenProcess is what Start sets on this process before it starts anything: with
// lockMemory, lockAll, and then, in any process but a test binary, denyDumps. It
// returns every failure, in the order of the calls, each starting with its fix.
//
// A test binary, the one `go test` builds, skips denyDumps: on macOS PT_DENY_ATTACH
// ends a process that a debugger traces, so `dlv test` could not debug a test that
// starts a gateway, and on Linux a non-dumpable test binary takes no debugger that
// attaches later. The tests of these calls make them in a child
// process, through harden.
func hardenProcess(lockMemory bool) error { return harden(lockMemory, !testing.Testing()) }

// harden calls lockAll when lockMemory is true, then denyDumps when dumps is true, and
// returns every failure joined, lockAll's first. It calls denyDumps when lockAll fails
// too: Start then returns with the caller's Config in memory, and without denyDumps a
// debugger could attach to the process and read it until the process exits.
func harden(lockMemory, dumps bool) error {
	var errs []error
	if lockMemory {
		errs = append(errs, lockAll())
	}
	if dumps {
		errs = append(errs, denyDumps())
	}
	return errors.Join(errs...)
}
