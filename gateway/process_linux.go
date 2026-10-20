//go:build linux

package gateway

import (
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/sys/unix"
)

// prctl and setrlimit are the system calls denyDumps makes. Only tests replace them.
var (
	prctl     = unix.Prctl
	setrlimit = unix.Setrlimit
)

// denyDumps makes this process non-dumpable, prctl(PR_SET_DUMPABLE, 0): the kernel
// writes no core dump of it, and a process of the same user without CAP_SYS_PTRACE can
// neither attach to it with ptrace nor read its memory or its environment under /proc.
// It then sets the core size limit, RLIMIT_CORE, soft and hard, to 0, through
// prlimit64. A program this process starts is dumpable again after its execve, and
// keeps the limit of 0. denyDumps makes both calls when the first fails, and returns
// every failure, one per line in the order of the calls, each starting with its fix.
func denyDumps() error {
	var errs []error
	if err := prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		errs = append(errs, fmt.Errorf("allow prctl in this process's seccomp profile: PR_SET_DUMPABLE 0 failed: %w", err))
	}
	if err := setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		errs = append(errs, fmt.Errorf("allow prlimit64 in this process's seccomp profile: RLIMIT_CORE 0 failed: %w", err))
	}
	return errors.Join(errs...)
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
	var l unix.Rlimit
	if lerr := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &l); lerr != nil {
		return fmt.Errorf("raise RLIMIT_MEMLOCK to unlimited, or allow mlockall and prlimit64 in the gateway's seccomp profile\n"+
			"gateway.lock_memory is true, mlockall failed: %w, and reading RLIMIT_MEMLOCK failed: %v; %s", err, lerr, memlockElse)
	}
	if memlockCause(err, l.Cur) {
		return fmt.Errorf("raise RLIMIT_MEMLOCK to unlimited: LimitMEMLOCK=infinity in a systemd unit, or ulimit -l unlimited\n"+
			"gateway.lock_memory is true, and mlockall failed with RLIMIT_MEMLOCK %s: %w; %s", memlockShown(l.Cur), err, memlockElse)
	}
	// The limit is not the cause: a seccomp filter refused the call.
	return fmt.Errorf("allow mlockall in the gateway's seccomp profile, or set gateway.lock_memory to false\n"+
		"gateway.lock_memory is true, and mlockall failed with RLIMIT_MEMLOCK %s: %w", memlockShown(l.Cur), err)
}

// memlockElse ends the second line of lockAll's failure when the limit may be its
// cause.
const memlockElse = "in Docker, pass --ulimit memlock=-1, or set gateway.lock_memory to false"

// memlockCause says the soft RLIMIT_MEMLOCK cur is the cause of mlockall's err: ENOMEM
// under a finite limit, the pages mapped exceeding it, or EPERM under a limit of 0.
func memlockCause(err error, cur uint64) bool {
	if cur == unix.RLIM_INFINITY {
		return false
	}
	return errors.Is(err, unix.ENOMEM) || errors.Is(err, unix.EPERM) && cur == 0
}

// memlockShown is a soft RLIMIT_MEMLOCK as lockAll's failure words it: "unlimited", or
// "at" and a number of bytes.
func memlockShown(cur uint64) string {
	if cur == unix.RLIM_INFINITY {
		return "unlimited"
	}
	return "at " + strconv.FormatUint(cur, 10) + " bytes"
}
