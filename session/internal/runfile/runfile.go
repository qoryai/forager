// Package runfile writes a file of a run, such as one in its run directory, through a
// new file beside it and a rename, so a link at the file's path is replaced, never
// followed.
package runfile

import (
	"errors"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// tries is how many names [Replace] tries for its new file before it returns the
// error of the last one that existed, as os.CreateTemp does.
const tries = 10000

// Replace writes b to path with mode perm less the process's umask, as os.WriteFile
// sets the mode of a file it creates. It creates a new file beside path with O_EXCL,
// in that mode from its creation, writes b, syncs the file, renames it to path and
// syncs the directory. A link at path is replaced, not followed, so the write reaches
// no file outside path's directory. If an error comes before the rename, the new file
// is removed and path is as it was; an error of the directory's sync comes after it.
// The sync's ENOTSUP and EINVAL are ignored: on macOS it is F_FULLFSYNC, which some
// network mounts do not support, and the file is in place by then.
func Replace(path string, b []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := create(dir, "."+filepath.Base(path)+"-", perm)
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EINVAL) {
		err = nil
	}
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// create creates a file in dir whose name is prefix and a random number, with O_EXCL
// and mode perm less the umask, trying another number while the name exists.
func create(dir, prefix string, perm os.FileMode) (*os.File, error) {
	for try := 1; ; try++ {
		name := filepath.Join(dir, prefix+strconv.FormatUint(uint64(rand.Uint32()), 10))
		f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, perm)
		if err == nil || !errors.Is(err, fs.ErrExist) || try == tries {
			return f, err
		}
	}
}
