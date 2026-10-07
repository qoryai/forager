package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/qoryai/runner/internal/program"
	"github.com/qoryai/runner/internal/refusal"
	"github.com/qoryai/runner/internal/tool"
	"github.com/qoryai/runner/wall"
)

// Overlap says how a mount and a path stand to each other: "is" when they are the same
// file, "contains" when the path lies under the mount, "lies inside" when the mount lies
// under the path, and empty otherwise. Each is resolved through symbolic links, a part
// that does not exist yet through its nearest parent that does. The filesystem judges
// what exists: two directories are the same when they are one file, by device and
// inode, so a path written in another case on a disk that ignores case, a link or a
// bind mount names what it leads to. A part that does not exist yet is compared by
// name, regardless of case, and a name with *, ? or [ in it is a pattern of names,
// as the private directories of the tools' sockets are. The comparison is by whole
// components: /a/bc does not lie inside /a/b.
func Overlap(mount, path string) string {
	m, p := split(mount), split(path)
	if ok, same := holds(m, p); ok {
		if same {
			return "is"
		}
		return "contains"
	}
	if ok, same := holds(p, m); ok {
		if same {
			return "is"
		}
		return "lies inside"
	}
	return ""
}

// splitPath is a path as the filesystem has it: the resolved nearest part that exists,
// and the names below it that do not exist yet.
type splitPath struct {
	exists string
	tail   []string
}

// split resolves p, absolute and clean, through symbolic links as far as it exists.
func split(p string) splitPath {
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = filepath.Clean(p)
	}
	var tail []string
	for dir := abs; ; {
		if target, err := filepath.EvalSymlinks(dir); err == nil {
			return splitPath{target, tail}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return splitPath{dir, tail}
		}
		tail = append([]string{filepath.Base(dir)}, tail...)
		dir = parent
	}
}

// holds reports whether outer is inner or lies above it, and same when it is inner. It
// walks up inner's existing part, itself included, to the directory that is the same
// file as outer's existing part; the names below that one, inner's own included, must
// then begin with outer's names that do not exist yet.
func holds(outer, inner splitPath) (ok, same bool) {
	top, err := os.Stat(outer.exists)
	if err != nil {
		return false, false
	}
	below := inner.tail
	for dir := inner.exists; ; {
		if info, err := os.Stat(dir); err == nil && os.SameFile(top, info) {
			if len(outer.tail) > len(below) {
				return false, false
			}
			for i, name := range outer.tail {
				if !sameName(name, below[i]) {
					return false, false
				}
			}
			return true, len(outer.tail) == len(below)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false, false
		}
		below = append([]string{filepath.Base(dir)}, below...)
		dir = parent
	}
}

// sameName reports whether two names of a path may name the same file: equal
// regardless of case, or one a pattern the other matches, regardless of case. Refusing
// one mount too many is safe; one too few is not.
func sameName(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	a, b = strings.ToLower(a), strings.ToLower(b)
	if ok, _ := filepath.Match(a, b); ok {
		return true
	}
	ok, _ := filepath.Match(b, a)
	return ok
}

// runnerFile is one of the runner's files, and what it is, for the refusal's Detail.
type runnerFile struct {
	path, what string
}

// runnerFiles are the paths a walled run's mounts leave out: the caller's, and every one
// the runner knows itself. The programs are every one the machine defines, not only the
// ones the run's policy selects, because a server's policy selects after the check, and
// a reload may select another credential.
func runnerFiles(spec Spec) []runnerFile {
	var out []runnerFile
	for _, p := range spec.RunnerFiles {
		out = append(out, runnerFile{p, "one of the runner's files"})
	}
	for _, c := range spec.Credentials {
		if len(c.Adapter) > 0 {
			for _, d := range program.Dirs(c.Adapter[0]) {
				out = append(out, runnerFile{d, "the directory of the credential " + c.Name + "'s program"})
			}
		}
		if c.File != "" {
			out = append(out, runnerFile{c.File, "the file the credential " + c.Name + " is read from"})
		}
	}
	for _, t := range spec.Tools {
		if len(t.Command) > 0 {
			for _, d := range program.Dirs(t.Command[0]) {
				out = append(out, runnerFile{d, "the directory of the tool " + t.Name + "'s program"})
			}
		}
	}
	// The private directory of a tool's socket is made when the tool starts, in the
	// system's temporary directory; a mount that contains its pattern would contain it.
	if len(spec.Tools) > 0 {
		out = append(out, runnerFile{tool.SocketDirs(), "where the tools' sockets are made"})
	}
	if f, ok := spec.Wall.(wall.Filer); ok {
		for _, p := range f.Files() {
			out = append(out, runnerFile{p, "one of the " + spec.Wall.Name() + " wall's files"})
		}
	}
	// The files a run's secrets and variables are read from, the file: paths of
	// secrets.local and an integration's _file settings, join this list.
	return out
}

// checkMounts refuses a caller's runner file that is not an absolute path and, behind a
// wall, a mount or the workspace that is, contains or lies inside one of the runner's
// files: mount_contains_runner_files, with the mount and the file as its names, in that
// order. The run directory, which the runner mounts read-only, is the runner's own.
func checkMounts(spec Spec) error {
	for _, p := range spec.RunnerFiles {
		if strings.ContainsRune(p, 0) {
			return errors.New("a runner file's path holds a NUL byte")
		}
		if !filepath.IsAbs(p) {
			return fmt.Errorf("the runner file %q is not an absolute path", p)
		}
	}
	if spec.Wall == nil {
		return nil
	}
	type shown struct{ path, what string }
	var mounts []shown
	for _, m := range spec.Mounts {
		mounts = append(mounts, shown{m.Path, "the mount"})
	}
	mounts = append(mounts, shown{spec.Dir, "the workspace"})
	files := runnerFiles(spec)
	for _, m := range mounts {
		for _, f := range files {
			if how := Overlap(m.path, f.path); how != "" {
				return &Refusal{
					Code:   refusal.MountContainsRunnerFiles,
					Names:  []string{m.path, f.path},
					Detail: fmt.Sprintf("%s %s %s %s, %s", m.what, m.path, how, f.path, f.what),
				}
			}
		}
	}
	return nil
}
