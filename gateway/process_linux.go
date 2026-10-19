//go:build linux

package gateway

import (
	"fmt"
	"strconv"

	"golang.org/x/sys/unix"
)

// denyDumps makes this process non-dumpable, prctl(PR_SET_DUMPABLE, 0): the kernel
// writes no core dump of it, and a process of the same user without CAP_SYS_PTRACE can
// neither attach to it with ptrace nor read its memory or its environment under /proc.
// It then sets the core size limit, RLIMIT_CORE, soft and hard, to 0. A program this
// process starts is dumpable again after its execve, and keeps the limit of 0.
func denyDumps() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("allow prctl in the gateway's seccomp profile: PR_SET_DUMPABLE 0 failed: %w", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("allow setrlimit in the gateway's seccomp profile: RLIMIT_CORE 0 failed: %w", err)
	}
	return nil
}

// lockAll locks every page of this process in memory, mlockall(MCL_CURRENT|MCL_FUTURE):
// the pages mapped now, and each page mapped later as it is mapped, so that the kernel
// writes none of them to swap. Without CAP_IPC_LOCK the process's locked pages stay
// under RLIMIT_MEMLOCK: mlockall fails when the pages mapped now exceed it, and a
// mapping later that exceeds it fails, which ends a Go program. A program this process
// starts locks nothing: fork and execve clear the lock.
func lockAll() error {
	err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)
	if err == nil {
		return nil
	}
	limit := ""
	var l unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_MEMLOCK, &l) == nil {
		limit = " with RLIMIT_MEMLOCK at " + memlockShown(l.Cur)
	}
	return fmt.Errorf("raise RLIMIT_MEMLOCK to unlimited: LimitMEMLOCK=infinity in a systemd unit, or ulimit -l unlimited\n"+
		"gateway.lock_memory is true, and mlockall failed%s: %w; in Docker, pass --ulimit memlock=-1, or set gateway.lock_memory to false", limit, err)
}

// memlockShown is a limit of RLIMIT_MEMLOCK as the message words it: unlimited, or a
// number of bytes.
func memlockShown(v uint64) string {
	if v == unix.RLIM_INFINITY {
		return "unlimited"
	}
	return strconv.FormatUint(v, 10) + " bytes"
}
