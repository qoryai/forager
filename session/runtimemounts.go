package session

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/qoryai/forager/wall"
)

// checkRuntimeMounts checks mountinfo, the text of /proc/self/mountinfo, for a mount
// that could replace a runtime's installed folder inside an enclosure. The wall binds
// each folder at /qory/runtime/<runtime> and nothing else there; an image's symbolic
// link on a listed mount's target can lead that mount there. It returns an error for a
// mount at /qory or at /qory/runtime, for a second mount at /qory/runtime/<runtime>,
// and for a mount below one; nil otherwise.
func checkRuntimeMounts(mountinfo string) error {
	qory := path.Dir(wall.RuntimeDir)
	at := map[string]bool{}
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
		if below || at[name] {
			return fmt.Errorf("remove the image's symbolic link that leads a mount to %s: only the runtime's installed folder is mounted at %s", pathShown(point), path.Join(wall.RuntimeDir, name))
		}
		at[name] = true
	}
	return nil
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
