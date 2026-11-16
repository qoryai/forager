package session

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/wall"
)

// checkRuntimeLinks checks /qory and /qory/runtime below root for a symbolic link, by
// lstat. The wall binds each runtime's installed folder at /qory/runtime/<runtime>; an
// image's link at either path leads the bind to where the link points, such as a
// folder inside a writable bind, and mountinfo then lists no mount at the path. A path
// that does not exist passes.
func checkRuntimeLinks(root string) error {
	for _, p := range []string{path.Dir(wall.RuntimeDir), wall.RuntimeDir} {
		info, err := os.Lstat(filepath.Join(root, p))
		switch {
		case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
			return nil
		case err != nil:
			return fmt.Errorf("make %s readable in the enclosure: the check for a symbolic link there failed: %w", p, accesskey.ShownError(err))
		case info.Mode()&fs.ModeSymlink != 0:
			return fmt.Errorf("replace the image's symbolic link %s with a folder: the runtime's installed folder is bound where the link leads", p)
		}
	}
	return nil
}

// checkRuntimeMounts checks mountinfo, the text of /proc/self/mountinfo, for a mount
// that could replace a runtime's installed folder inside an enclosure. The wall binds
// each folder at /qory/runtime/<runtime> and nothing else there; an image's symbolic
// link on a listed mount's target can lead that mount there. It returns an error for a
// mount at /qory or at /qory/runtime, for a mount below /qory/runtime/<runtime>, and
// for a second mount at /qory/runtime/<runtime>, apart from a shiftfs mount on the
// first: Sysbox in shiftfs mode, on a kernel without ID-mapped mounts, mounts one on
// each bind at the same mount point. When program, absolute and clean, lies below
// /qory/runtime/<runtime>, a folder with no mount there is an error too: the bind went
// where an image's link led it. It returns nil otherwise.
func checkRuntimeMounts(mountinfo, program string) error {
	qory := path.Dir(wall.RuntimeDir)
	at := map[string][]mountEntry{}
	for line := range strings.SplitSeq(mountinfo, "\n") {
		// The fifth field is the mount point, with space, tab, newline and backslash
		// written as octal escapes.
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		point := unescapeMountPoint(fields[4])
		if point == qory || point == wall.RuntimeDir {
			return fmt.Errorf("remove the image's symbolic link that leads a mount to %s: the mount there could replace the installed runtime", pathShown(point))
		}
		rest, ok := strings.CutPrefix(point, wall.RuntimeDir+"/")
		if !ok {
			continue
		}
		name, _, below := strings.Cut(rest, "/")
		e := mountEntry{id: fields[0], parent: fields[1], fsType: mountFSType(fields)}
		switch prev := at[name]; {
		case below, len(prev) > 1, len(prev) == 1 && !prev[0].shiftedBy(e):
			return fmt.Errorf("remove the image's symbolic link that leads a mount to %s: only the runtime's installed folder is mounted at %s", pathShown(point), path.Join(wall.RuntimeDir, name))
		}
		at[name] = append(at[name], e)
	}
	rest, ok := strings.CutPrefix(program, wall.RuntimeDir+"/")
	if name, _, _ := strings.Cut(rest, "/"); ok && name != "" && len(at[name]) == 0 {
		folder := path.Join(wall.RuntimeDir, name)
		return fmt.Errorf("remove the image's symbolic link at or above %s: the runtime's installed folder is not mounted there", pathShown(folder))
	}
	return nil
}

// mountEntry is one line of /proc/self/mountinfo: its mount id, its parent's mount id
// and its filesystem type.
type mountEntry struct{ id, parent, fsType string }

// shiftedBy reports whether e is a shiftfs mount on m, at the same mount point: e's
// parent is m.
func (m mountEntry) shiftedBy(e mountEntry) bool {
	return e.parent == m.id && e.fsType == "shiftfs"
}

// mountFSType is the filesystem type of a line of mountinfo split into fields: the
// field after the "-" that ends the optional fields, which start at the seventh; ""
// when there is none.
func mountFSType(fields []string) string {
	for i := 6; i < len(fields)-1; i++ {
		if fields[i] == "-" {
			return fields[i+1]
		}
	}
	return ""
}

// unescapeMountPoint is a mount point of /proc/self/mountinfo with its octal escapes,
// such as \040 for a space, written as the bytes they stand for.
func unescapeMountPoint(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
