package session

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/qoryai/runner/internal/program"
	"github.com/qoryai/runner/internal/refusal"
	"github.com/qoryai/runner/internal/socket"
	"github.com/qoryai/runner/internal/tool"
	"github.com/qoryai/runner/wall"
)

// Overlap says how a mount and a path stand to each other: "is" when they are the same
// file, "contains" when the path lies under the mount, "lies inside" when the mount lies
// under the path, and empty otherwise. Each is resolved through symbolic links, a part
// that does not exist yet through its nearest parent that does, and a link whose target
// does not exist yet through that target. The filesystem judges what exists: two
// directories are the same when they are one file, by device and inode, so a path
// written in another case on a disk that ignores case, a link or a bind mount names
// what it leads to. A part that does not exist yet is compared by name, regardless of
// case, and a name with *, ? or [ in it is a pattern of names, as the private
// directories of the tools' sockets are. The comparison is by whole components: /a/bc
// does not lie inside /a/b. A path that cannot be resolved, such as one through a
// directory this user cannot search, is empty here; [Run] refuses a mount of one.
func Overlap(mount, path string) string {
	how, _ := overlap(mount, path)
	return how
}

// overlap is [Overlap], with the error of a path that cannot be resolved.
func overlap(mount, path string) (string, error) {
	m, err := split(mount, 0)
	if err != nil {
		return "", fmt.Errorf("cannot resolve the mount %s: %w", mount, err)
	}
	p, err := split(path, 0)
	if err != nil {
		return "", fmt.Errorf("cannot resolve the runner's file %s: %w", path, err)
	}
	if ok, same := holds(m, p); ok {
		if same {
			return "is", nil
		}
		return "contains", nil
	}
	if ok, same := holds(p, m); ok {
		if same {
			return "is", nil
		}
		return "lies inside", nil
	}
	return "", nil
}

// splitPath is a path as the filesystem has it: the resolved nearest part that exists,
// and the names below it that do not exist yet.
type splitPath struct {
	exists string
	tail   []string
}

// maxLinks is how many links whose targets do not exist yet split follows in one path.
const maxLinks = 40

// split resolves p, absolute and clean, through symbolic links as far as it exists. It
// walks up only past what does not exist; a link whose target does not exist yet is
// followed to that target, and any other error is returned, so a path is never taken
// for one it may not be.
func split(p string, links int) (splitPath, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return splitPath{}, err
	}
	var tail []string
	for dir := abs; ; {
		target, err := filepath.EvalSymlinks(dir)
		if err == nil {
			return splitPath{target, tail}, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return splitPath{}, err
		}
		info, err := os.Lstat(dir)
		switch {
		case err == nil && info.Mode()&fs.ModeSymlink != 0:
			// A link whose target does not exist yet: the target, read from the
			// link's own directory, resolved, is where the path leads once it does.
			if links >= maxLinks {
				return splitPath{}, fmt.Errorf("%s: too many links", abs)
			}
			to, err := os.Readlink(dir)
			if err != nil {
				return splitPath{}, err
			}
			if !filepath.IsAbs(to) {
				parent, err := filepath.EvalSymlinks(filepath.Dir(dir))
				if err != nil {
					return splitPath{}, err
				}
				to = filepath.Join(parent, to)
			}
			return split(filepath.Join(append([]string{to}, tail...)...), links+1)
		case err == nil:
			return splitPath{}, fmt.Errorf("%s exists and does not resolve", dir)
		case !errors.Is(err, fs.ErrNotExist):
			return splitPath{}, err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return splitPath{dir, tail}, nil
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
	// It is checked whether or not the run has tools, since another run's on this
	// machine are there too. So are the private directories of the runs' record
	// sockets and of the Docker wall's environment files, which hold the proxy's
	// secret: this run's are made after the check, and other runs' exist.
	out = append(out,
		runnerFile{tool.SocketDirs(), "where the tools' sockets are made"},
		runnerFile{socket.Dirs(), "where the runs' record sockets are made"},
		runnerFile{wall.TempDirs(), "where the Docker wall's environment files are made"})
	if f, ok := spec.Wall.(wall.Filer); ok {
		for _, p := range f.Files() {
			out = append(out, runnerFile{p, "one of the " + spec.Wall.Name() + " wall's files"})
		}
	}
	// Later, the files a run's secrets and variables are read from (the file: paths of
	// secrets.local and an integration's _file settings) join this list.
	return out
}

// checkMounts refuses a caller's runner file that is not an absolute path and, behind a
// wall, a mount or the workspace that is, contains or lies inside one of the runner's
// files: mount_contains_runner_files, with the mount and the file as its names, in that
// order. The mounts are the run's own, Spec.Mounts and the workspace: what the runner
// shows the enclosure itself, the run directory read-only and its own hook socket's
// directory, is the runner's and is not checked.
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
			how, err := overlap(m.path, f.path)
			if err != nil {
				return err
			}
			if how != "" {
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
