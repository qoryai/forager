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
	"syscall"
)

// Read reads the file at path: never through a link as its last part, never a file
// that is not a regular one, and never more than max bytes. The file is opened without
// following a link and without blocking, so a FIFO is refused rather than waited on. A
// file that does not exist is an error that wraps fs.ErrNotExist.
func Read(path string, max int64) ([]byte, error) {
	if info, err := os.Lstat(path); err != nil {
		return nil, err
	} else if info.Mode()&fs.ModeSymlink != 0 {
		return nil, errors.New("it is a link")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("it is not a regular file")
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
