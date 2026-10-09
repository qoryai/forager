package session

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// lockFile is the file in a run directory its session holds locked for as long as it
// lives. The lock is the kernel's and ends with the process, however it ends, so a
// free lock says the session is gone and a held one that the run is still going.
const lockFile = "lock"

// ErrRunning says a run directory's session is still alive.
var ErrRunning = errors.New("the run is still going")

// lock takes the run directory's lock without waiting; [ErrRunning] when another
// process holds it. The returned function releases it.
func lock(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, lockFile), os.O_CREATE|os.O_RDWR, 0o644)
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
