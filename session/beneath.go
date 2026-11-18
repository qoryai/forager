package session

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/qoryai/forager/server"
)

// maxTranscript is the largest transcript the session reads, with a wall or without
// one, [server.MaxTranscript], 64 MiB: the largest one a continuation restores.
const maxTranscript = server.MaxTranscript

// walledSessionID is the shape of a runtime's session id behind a wall: a UUID in
// lower case, as Claude Code writes its session ids. The session reads, and restores,
// a walled runtime's transcript only under a session id of this shape.
var walledSessionID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// beneathRefused is a transcript that the session does not read or write: fix is the
// change that lets it, and why the cause.
type beneathRefused struct{ fix, why string }

func (e *beneathRefused) Error() string { return e.why }

// errBeneathLinked is the refusal of a path with a symbolic link among its names, or
// with a name that is no directory where one is needed: an open with O_NOFOLLOW and
// O_DIRECTORY of a link fails with ELOOP on Linux and ENOTDIR on macOS.
var errBeneathLinked = &beneathRefused{"Replace the symbolic link or file on the transcript's path with a directory", "a name on its path is a symbolic link or no directory"}

// belowNames is the names of rel, a path below a transcript directory, the path the
// session reads or writes there; an error for an empty path, or one with an empty, .
// or .. name. The caller has checked rel against resume.path.
func belowNames(rel string) ([]string, error) {
	if rel == "" || dotted(rel) || strings.ContainsRune(rel, 0) {
		return nil, &beneathRefused{"Use a runtime whose resume.path lies below resume.prefix", "the path has an empty, . or .. name"}
	}
	return strings.Split(rel, "/"), nil
}

// readBeneath reads the transcript at rel below the transcript directory root, from
// offset on, and returns its bytes and the file's size. It opens the file with no
// symbolic link among its names and without waiting for a writer ([openBeneath]), and
// reads it only when it is a regular file with one link of at most [maxTranscript]
// bytes, in one read of at most that many bytes. A file that does not exist yet is an
// error of [fs.ErrNotExist]; a file the session does not read is a *beneathRefused.
func readBeneath(root, rel string, offset int64) ([]byte, int64, error) {
	names, err := belowNames(rel)
	if err != nil {
		return nil, 0, err
	}
	fd, err := openBeneath(root, names)
	if err != nil {
		return nil, 0, beneathError(err)
	}
	f := os.NewFile(uintptr(fd), names[len(names)-1])
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, 0, err
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, 0, &beneathRefused{"Keep the transcript a regular file", "it is no regular file"}
	case st.Nlink > 1:
		return nil, 0, &beneathRefused{"Remove the other hard links to the transcript", fmt.Sprintf("it has %d hard links, and the session reads a file with one", st.Nlink)}
	case st.Size > maxTranscript:
		return nil, 0, errTooLarge
	case st.Size < offset:
		return nil, st.Size, nil
	}
	b, err := io.ReadAll(io.NewSectionReader(f, offset, st.Size-offset))
	return b, st.Size, err
}

// errTooLarge is the refusal of a transcript over [maxTranscript] bytes.
var errTooLarge = &beneathRefused{"Keep the session's transcript at most 64 MiB, the most a continuation restores", fmt.Sprintf("it is over %d bytes (64 MiB)", maxTranscript)}

// writeBeneath writes b as the transcript at rel below the transcript directory root:
// it makes each directory of rel, mode 0700, that does not exist, opens each with no
// symbolic link among its names, and creates the file, mode 0600, where none exists,
// never through a link.
func writeBeneath(root, rel string, b []byte) error {
	names, err := belowNames(rel)
	if err != nil {
		return err
	}
	dirFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return beneathError(err)
	}
	for _, name := range names[:len(names)-1] {
		if err := unix.Mkdirat(dirFD, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			unix.Close(dirFD)
			return beneathError(err)
		}
		next, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(dirFD)
		if err != nil {
			return beneathError(err)
		}
		dirFD = next
	}
	defer unix.Close(dirFD)
	name := names[len(names)-1]
	fd, err := unix.Openat(dirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return beneathError(err)
	}
	f := os.NewFile(uintptr(fd), name)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// walkBeneath opens the path of names below root one name at a time: each directory
// with O_NOFOLLOW and O_DIRECTORY, the file with O_NOFOLLOW and O_NONBLOCK, so that no
// name is a symbolic link and a FIFO opens without a writer. It returns the file's
// descriptor.
func walkBeneath(root string, names []string) (int, error) {
	dirFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, name := range names[:len(names)-1] {
		next, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(dirFD)
		if err != nil {
			return -1, err
		}
		dirFD = next
	}
	defer unix.Close(dirFD)
	return unix.Openat(dirFD, names[len(names)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
}

// beneathError is err of an open below a transcript directory: a name that does not
// exist is [fs.ErrNotExist]; a symbolic link, a name that leads out of the directory
// and a name that is no directory where one is needed are [errBeneathLinked].
func beneathError(err error) error {
	switch {
	case errors.Is(err, unix.ENOENT):
		return fs.ErrNotExist
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.EXDEV), errors.Is(err, unix.ENOTDIR):
		return errBeneathLinked
	}
	return err
}
