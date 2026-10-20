//go:build darwin

package gateway

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// ptraceDenyAttach and setrlimit are the system calls denyDumps makes. Only tests
// replace them.
var (
	ptraceDenyAttach = unix.PtraceDenyAttach
	setrlimit        = unix.Setrlimit
)

// denyDumps calls ptrace(PT_DENY_ATTACH), so that no debugger attaches to this process
// with ptrace, and sets the core size limit, RLIMIT_CORE, soft and hard, to 0, so that
// the kernel writes no core dump of it. Root, or a debugger that macOS allows to call
// task_for_pid on the process, can still read its memory through its task port. A
// process that a debugger traces when it calls PT_DENY_ATTACH exits at once, with
// status 45 (ENOTSUP). A program this process starts keeps the limit of 0. denyDumps
// makes both calls when the first fails, and returns every failure, one per line in
// the order of the calls, each starting with its fix.
func denyDumps() error {
	var errs []error
	if err := ptraceDenyAttach(); err != nil {
		errs = append(errs, fmt.Errorf("allow ptrace in this process's sandbox: PT_DENY_ATTACH failed: %w", err))
	}
	if err := setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		errs = append(errs, fmt.Errorf("allow setrlimit in this process's sandbox: RLIMIT_CORE 0 failed: %w", err))
	}
	return errors.Join(errs...)
}
