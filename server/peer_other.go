//go:build !linux && !darwin

package server

import (
	"errors"
	"net"
)

// peerUID refuses on a system whose socket peer this package cannot read: the local
// link's secret is written only after its socket's peer is known to be this user.
func peerUID(*net.UnixConn) (int, error) {
	return 0, errors.New("this system has no way Forager reads a Unix socket's peer uid, which the local link checks before it sends its secret; the local link runs on Linux and macOS")
}
