// Package hostfile reads a file of this machine that a run's caller names, such as a
// runtime's settings or descriptor, without following a link as its last part and
// without reading more than a bound.
package hostfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
)

// DotDot reports whether a path, as written, has a ".." name. The system applies ".."
// after the link before it, not to the name before it as written, so a path with one
// names another file than the path made clean names.
func DotDot(path string) bool {
	for _, n := range strings.Split(path, "/") {
		if n == ".." {
			return true
		}
	}
	return false
}

// ErrDotDot is the refusal of a path [DotDot] reports.
var ErrDotDot = errors.New(`it has a ".." part`)

// Read reads the file at path: never through a link as its last part, never a file
// that is not a regular one, and never more than max bytes. Both are refused from what
// the path's last part is before it is opened, and again from the file opened, which
// is opened without following a link as its last part and without blocking, so a FIFO
// or a device is never opened for what it does when it is. When want is not nil the
// file opened must be the one it describes. A file that does not exist is an error
// that wraps fs.ErrNotExist.
func Read(path string, max int64, want fs.FileInfo) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, errors.New("it is a link")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("it is not a regular file")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info, err = f.Stat(); err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("it is not a regular file")
	}
	if want != nil && !os.SameFile(info, want) {
		return nil, errors.New("it changed while it was checked")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("it is larger than %d bytes", max)
	}
	return b, nil
}
