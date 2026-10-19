//go:build linux

package gateway

import (
	"fmt"
	"strconv"

	"golang.org/x/sys/unix"
)

// denyDumps makes this process non-dumpable, prctl(PR_SET_DUMPABLE, 0): a process of
// the same user without CAP_SYS_PTRACE can neither attach to it with ptrace nor read its
// memory or its environment under /proc. It then sets the core size limit,
// RLIMIT_CORE, soft and hard, to 0, through prlimit64, so that the kernel writes no core
// file of it. With fs.suid_dumpable 2 and a kernel.core_pattern that pipes to a
// program, such as apport, that program can still get a core dump of it. A program this
// process starts is dumpable again after its execve, and keeps the limit of 0.
func denyDumps() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("allow prctl in the gateway's seccomp profile: PR_SET_DUMPABLE 0 failed: %w", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("allow prlimit64 in the gateway's seccomp profile: RLIMIT_CORE 0 failed: %w", err)
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
	var l unix.Rlimit
	if lerr := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &l); lerr != nil {
		return fmt.Errorf("raise RLIMIT_MEMLOCK to unlimited, or allow mlockall and prlimit64 in the gateway's seccomp profile\n"+
			"gateway.lock_memory is true, mlockall failed: %w, and RLIMIT_MEMLOCK does not read: %v; %s", err, lerr, memlockElse)
	}
	if l.Cur == unix.RLIM_INFINITY {
		// The limit is not the cause: a seccomp filter, or a security module, refused the
		// call.
		return fmt.Errorf("allow mlockall in the gateway's seccomp profile, or set gateway.lock_memory to false\n"+
			"gateway.lock_memory is true, and mlockall failed with RLIMIT_MEMLOCK unlimited: %w", err)
	}
	return fmt.Errorf("%s\ngateway.lock_memory is true, and mlockall failed with RLIMIT_MEMLOCK at %s bytes: %w; %s",
		memlockRaise, strconv.FormatUint(l.Cur, 10), err, memlockElse)
}

// memlockRaise is the first line of lockAll's failure under a finite RLIMIT_MEMLOCK,
// and memlockElse ends its second line.
const (
	memlockRaise = "raise RLIMIT_MEMLOCK to unlimited: LimitMEMLOCK=infinity in a systemd unit, or ulimit -l unlimited"
	memlockElse  = "in Docker, pass --ulimit memlock=-1, or set gateway.lock_memory to false"
)
