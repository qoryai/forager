package session

import (
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

// openBeneath opens the path of names below root for reading with openat2, resolved beneath
// root with no symbolic link among its names (RESOLVE_BENEATH, RESOLVE_NO_SYMLINKS,
// RESOLVE_NO_MAGICLINKS), with O_NOFOLLOW and O_NONBLOCK, so that a FIFO opens without
// a writer. A kernel without openat2, before Linux 5.6 or under a filter that denies
// it, gets [walkBeneath].
func openBeneath(root string, names []string) (int, error) {
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat2(rootFD, strings.Join(names, "/"), &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		return walkBeneath(root, names)
	}
	return fd, err
}
