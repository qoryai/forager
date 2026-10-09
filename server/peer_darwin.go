//go:build darwin

package server

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// xucredVersion is XUCRED_VERSION of sys/ucred.h, the version of struct xucred the
// kernel answers LOCAL_PEERCRED with.
const xucredVersion = 0

// peerUID returns the uid of the process at the other end of a Unix socket, as the
// kernel recorded it when the peer connected or listened: LOCAL_PEERCRED, the
// credentials getpeereid reads.
func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Xucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, serr
	}
	if cred.Version != xucredVersion {
		return 0, errors.New("the kernel answered credentials of another version")
	}
	return int(cred.Uid), nil
}
