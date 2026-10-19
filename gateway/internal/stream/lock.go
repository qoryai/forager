package stream

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/qoryai/forager/accesskey"
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
// holds it. The returned function releases it. It is the session's lock, copied. A
// lock that is a symbolic link is not opened.
func lock(dir, name string) (func(), error) {
	file := filepath.Join(dir, name)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		if fi, lerr := os.Lstat(file); lerr == nil && fi.Mode()&fs.ModeSymlink != 0 {
			return nil, linkError{"Remove the symbolic link at " + accesskey.ShownValue(file, false) +
				". The gateway does not open the run directory's lock through a link.", err}
		}
		return nil, accesskey.ShownError(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrRunning
		}
		return nil, accesskey.ShownError(err)
	}
	return func() { f.Close() }, nil
}

// linkError is an error whose text is text, and that wraps err.
type linkError struct {
	text string
	err  error
}

func (e linkError) Error() string { return e.text }
func (e linkError) Unwrap() error { return e.err }
