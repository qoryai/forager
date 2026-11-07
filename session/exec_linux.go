package session

import (
	"os"
	"strconv"
	"syscall"
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
