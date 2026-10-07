package session

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/qoryai/runner/internal/program"
	"github.com/qoryai/runner/internal/refusal"
	"github.com/qoryai/runner/internal/tool"
	"github.com/qoryai/runner/wall"
)

// Overlap says how a mount and a path stand to each other, both resolved through
// symbolic links, a part that does not exist yet through its nearest parent that does,
// and compared by whole components: "is" when they are the same, "contains" when the
// path lies under the mount, "lies inside" when the mount lies under the path, and
// empty otherwise. /a/bc does not lie inside /a/b. The comparison is exact, byte for
// byte, also where the filesystem ignores case, as macOS's does by default: /Users/User
// and /Users/user are two paths to it.
func Overlap(mount, path string) string {
	m, p := realPath(mount), realPath(path)
	switch {
	case m == p:
		return "is"
	case under(m, p):
		return "contains"
	case under(p, m):
		return "lies inside"
	}
	return ""
}

// realPath is the absolute, clean path p leads to through symbolic links. A part that
// does not exist is kept as written after the resolved parent that does.
func realPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	rest := ""
	for dir := abs; ; {
		if target, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(target, rest)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return abs
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = parent
	}
}

// under reports whether inner lies under outer, both absolute and clean.
func under(outer, inner string) bool {
	prefix := outer
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return inner != outer && strings.HasPrefix(inner, prefix)
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
