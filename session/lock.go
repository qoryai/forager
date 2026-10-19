package session

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/qoryai/forager/accesskey"
)

// lockFile is the file in a run directory its session holds locked for as long as it
// lives. The lock is the kernel's and ends with the process, however it ends, so a
// free lock says the session is gone and a held one that the run is still going.
const lockFile = "lock"

// ErrRunning says a run directory's session is still alive.
var ErrRunning = errors.New("the run is still going")

// lock takes the run directory's lock without waiting; [ErrRunning] when another
// process holds it. The returned function releases it. A lock that is a symbolic link
// is not opened.
func lock(dir string) (func(), error) {
	file := filepath.Join(dir, lockFile)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		if l := lockLink(file, "the run directory's lock", err); l != nil {
			return nil, l
		}
		return nil, accesskey.ShownError(err)
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

// lockLink is the error of a lock, file, that an open with O_NOFOLLOW failed to open,
// err, because it is a symbolic link: the fix, then what the lock is, and err under
// it. It is nil when file is no link.
func lockLink(file, what string, err error) error {
	if fi, lerr := os.Lstat(file); lerr != nil || fi.Mode()&fs.ModeSymlink == 0 {
		return nil
	}
	return linkError{"Remove the symbolic link at " + pathShown(file) + ". The session opens " + what +
		" only as a regular file, not through a link.", err}
}

// linkError is an error whose text is text, and that wraps err.
type linkError struct {
	text string
	err  error
}

func (e linkError) Error() string { return e.text }
func (e linkError) Unwrap() error { return e.err }
