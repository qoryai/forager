// Package runfile writes a file of a run, such as one in its run directory, through a
// new file beside it and a rename, so a link at the file's path is replaced, never
// followed.
package runfile

import (
	"os"
	"path/filepath"
)

// Replace writes b to path with mode perm. It creates a new file beside path, mode 0600
// and with O_EXCL, sets perm on it, writes b, syncs it to disk and renames it to path.
// A link at path is replaced, not followed, so the write reaches no file outside path's
// directory, and a file of mode 0600 is never readable by others. On an error the new
// file is removed and path is as it was.
func Replace(path string, b []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	err = f.Chmod(perm)
	if err == nil {
		_, err = f.Write(b)
	}
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
	}
	return err
}
