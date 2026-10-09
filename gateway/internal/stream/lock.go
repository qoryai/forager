package stream

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// The locks in a run's record directory. The kernel holds each for as long as its
// process lives, however it ends, so a free lock says its holder is gone. The gateway
// holds lockFile while the run is open; the run's session holds sessionLockFile, the
// session's own, in the same directory on one machine. Two names, since a lock is held
// per open file and the gateway and the session may be one process.
const (
	lockFile        = "gateway.lock"
	sessionLockFile = "lock"
)

// lock takes a lock of the run directory without waiting; [ErrRunning] when another
// holds it. The returned function releases it. It is the session's lock, copied.
func lock(dir, name string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrRunning
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}
