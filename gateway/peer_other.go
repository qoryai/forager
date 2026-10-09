//go:build !linux && !darwin

package gateway

import (
	"errors"
	"net"
)

// peerUID refuses on a system whose socket peer this package cannot read: the local
// link serves only a peer known to be this user.
func peerUID(*net.UnixConn) (int, error) {
	return 0, errors.New("this system has no way Forager reads a Unix socket's peer uid, which the local link checks on every connection; the local link runs on Linux and macOS")
}
