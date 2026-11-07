package session

import (
	"os"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// closeInherited closes every file descriptor above 2 of the process, apart from the
// Go runtime's poller, an eventpoll and an eventfd, which reach no file: closing one
// stops the runtime. It reads /proc/self/fd with system calls alone, so it opens no
// descriptor of the poller's.
func closeInherited() {
	dir, err := syscall.Open("/proc/self/fd", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	var fds []int
	buf := make([]byte, 4096)
	for {
		n, err := syscall.ReadDirent(dir, buf)
		if err != nil || n <= 0 {
			break
		}
		_, _, names := syscall.ParseDirent(buf[:n], -1, nil)
		for _, name := range names {
			fd, err := strconv.Atoi(name)
			if err != nil || fd <= 2 || fd == dir {
				continue
			}
			switch target, _ := os.Readlink("/proc/self/fd/" + name); target {
			case "anon_inode:[eventpoll]", "anon_inode:[eventfd]":
				continue
			}
			fds = append(fds, fd)
		}
	}
	syscall.Close(dir)
	for _, fd := range fds {
		syscall.Close(fd)
	}
}

// sigaction is the kernel's struct sigaction on Linux, as the Go runtime declares it
// for amd64 and arm64.
type sigaction struct {
	handler  uintptr
	flags    uint64
	restorer uintptr
	mask     uint64
}

// raise ends the process by sig: it sets no core file, sets sig's action to the
// default, which the Go runtime's handler would not apply for QUIT, ABRT or SEGV,
// unblocks it on this thread and sends it to this thread. It returns only when the
// process outlives the signal.
func raise(sig syscall.Signal) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{})
	var dfl sigaction
	unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(sig), uintptr(unsafe.Pointer(&dfl)), 0, unsafe.Sizeof(dfl.mask), 0, 0)
	set := uint64(1) << (uint(sig) - 1)
	unix.RawSyscall6(unix.SYS_RT_SIGPROCMASK, unix.SIG_UNBLOCK, uintptr(unsafe.Pointer(&set)), 0, unsafe.Sizeof(set), 0, 0)
	unix.Tgkill(unix.Getpid(), unix.Gettid(), sig)
}
