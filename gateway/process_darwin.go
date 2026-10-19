//go:build darwin

package gateway

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// denyDumps sets the core size limit, RLIMIT_CORE, soft and hard, to 0, so that the
// kernel writes no core dump of this process, and calls ptrace(PT_DENY_ATTACH), so that
// no debugger attaches to it. A process that a debugger traces when it calls
// PT_DENY_ATTACH exits at once, with status 45 (ENOTSUP). A program this process starts
// keeps the limit of 0.
func denyDumps() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("allow setrlimit in the gateway's sandbox: RLIMIT_CORE 0 failed: %w", err)
	}
	if err := unix.PtraceDenyAttach(); err != nil {
		return fmt.Errorf("allow ptrace in the gateway's sandbox: PT_DENY_ATTACH failed: %w", err)
	}
	return nil
}
