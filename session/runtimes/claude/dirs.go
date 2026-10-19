package claude

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/session/runtimes"
)

// maxEntries is the most entries a walled launch's check reads under one --plugin-dir
// or --add-dir value.
const maxEntries = 10_000

// workspaceInside is where the enclosure shows the workspace of a run for which
// [runtimes.Attach.Inside] is set.
const workspaceInside = "/workspace"

// maxLinks is how many links [throughWorkspace] follows in one path before it refuses
// the path.
const maxLinks = 40

// errTooManyLinks is the error of a path [throughWorkspace] follows through more than
// maxLinks links. Forager counts the links itself, so the limit is the same on every
// system.
var errTooManyLinks = fmt.Errorf("more than %d links, the most Forager follows", maxLinks)

// checkDir checks the value of --plugin-dir, --plugin-dir-no-mcp or --add-dir in a
// walled launch. A directory must pass [runtimes.Attach.ReadableDir]: it may not lie
// in, be reached through or contain a place a walled run can write. Then every entry
// under it, for --add-dir only .claude and CLAUDE.md, is read without following a link
// as it is read: a link must pass Readable, and a link to a directory ReadableDir, and
// the directory it leads to is read the same way; a regular file, and a file a link
// leads to, must have one name. A link that leads into /workspace, for a run that sees
// its workspace there, is refused. The scan stops after maxEntries entries. Any other
// value, a .zip say, is checked as a file: it must pass Readable, be no link as its last
// part, be a regular file and have one name. For a run that sees its workspace at
// /workspace, a value whose path reaches /workspace is refused first, since the
// enclosure reads it from the workspace, not from where this machine has it. Each
// directory is read once, by the file it is. An --add-dir directory is not counted as
// read, since only part of it is: a link that leads back to it reads all of it.
func checkDir(v flagValue, a runtimes.Attach) error {
	if a.Inside != nil {
		through, err := throughWorkspace(v.value)
		if errors.Is(err, errTooManyLinks) {
			return tooManyLinks(v, "")
		}
		if err != nil {
			return checkFailed(v, err)
		}
		if through {
			// The value may not exist here: a value whose name ends in .zip is taken
			// for a file.
			info, err := os.Stat(v.value)
			file := err == nil && !info.IsDir() || err != nil && strings.EqualFold(filepath.Ext(v.value), ".zip")
			return writtenValue(v, file, &runtimes.WrittenError{How: "lies in", Place: workspaceInside})
		}
	}
	info, err := os.Stat(v.value)
	if err != nil {
		return checkFailed(v, err)
	}
	if !info.IsDir() {
		return checkPluginFile(v, a)
	}
	real, err := resolveWith(a.ReadableDir, v.value)
	if err != nil {
		var written *runtimes.WrittenError
		if errors.As(err, &written) {
			return writtenValue(v, false, written)
		}
		return checkFailed(v, err)
	}
	s := &scan{v: v, a: a, seen: map[fileID]bool{}}
	if v.flag != addDirFlag {
		if _, err := s.enter(real); err != nil {
			return err
		}
		err = s.dir(real, v.value)
	} else {
		for _, name := range []string{".claude", "CLAUDE.md"} {
			if err = s.entry(filepath.Join(real, name), filepath.Join(v.value, name)); err != nil {
				break
			}
		}
	}
	return err
}

// checkPluginFile checks a value of the flags of [checkDir] that is no directory.
func checkPluginFile(v flagValue, a runtimes.Attach) error {
	shown := accesskey.ShownValue(v.value, false)
	if _, err := resolveWith(a.Readable, v.value); err != nil {
		var written *runtimes.WrittenError
		if errors.As(err, &written) {
			return writtenValue(v, true, written)
		}
		return checkFailed(v, err)
	}
	info, err := os.Lstat(v.value)
	switch {
	case err != nil:
		return checkFailed(v, err)
	case info.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("Pass the path of the file that %s links to. This launch passes %s %s, and that file "+
			"is a link, so the run does not start.", shown, v.flag, shown)
	case !info.Mode().IsRegular():
		fix := "Pass a " + v.flag + " path to a directory or a regular file."
		if v.flag == addDirFlag {
			fix = "Pass an " + v.flag + " path to a directory."
		}
		return fmt.Errorf("%s This launch passes %s %s, and that file is not a regular file, so the run does not start.",
			fix, v.flag, shown)
	case links(info) > 1:
		return hardLinked(v, v.value)
	}
	return nil
}

// scan reads the entries under a directory of one value: the value, the Attach's
// checks, how many entries it read, and the directories it read, by device and inode,
// so a directory reached again, through a link or under another name, is not read
// again.
type scan struct {
	v    flagValue
	a    runtimes.Attach
	n    int
	seen map[fileID]bool
}

// fileID is a file by its device and inode.
type fileID struct{ dev, ino uint64 }

// enter reports whether the directory at p is one the scan has not read yet, and
// records it as read.
func (s *scan) enter(p string) (bool, error) {
	info, err := os.Stat(p)
	if err != nil {
		return false, checkFailed(s.v, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true, nil
	}
	id := fileID{uint64(st.Dev), uint64(st.Ino)}
	if s.seen[id] {
		return false, nil
	}
	s.seen[id] = true
	return true, nil
}

// dir reads every entry under the directory real, which a refusal shows by the path in
// `shown`, the path Claude Code reads it by. A directory under it that the scan read
// before is counted as an entry and not read again.
func (s *scan) dir(real, shown string) error {
	return filepath.WalkDir(real, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return checkFailed(s.v, err)
		}
		if p == real {
			return nil
		}
		rel, err := filepath.Rel(real, p)
		if err != nil {
			return checkFailed(s.v, err)
		}
		if err := s.count(); err != nil {
			return err
		}
		if d.IsDir() {
			fresh, err := s.enter(p)
			if err != nil {
				return err
			}
			if !fresh {
				return fs.SkipDir
			}
			return nil
		}
		return s.check(p, filepath.Join(shown, rel), d.Type())
	})
}

// entry reads the one entry at p and, when it is a directory, every entry under it.
// An entry that does not exist is no entry.
func (s *scan) entry(p, shown string) error {
	info, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return checkFailed(s.v, err)
	}
	if err := s.count(); err != nil {
		return err
	}
	if err := s.check(p, shown, info.Mode().Type()); err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}
	if fresh, err := s.enter(p); err != nil || !fresh {
		return err
	}
	return s.dir(p, shown)
}

// count counts one entry more, and refuses the value past maxEntries.
func (s *scan) count() error {
	if s.n++; s.n > maxEntries {
		what := "plugin directory"
		if s.v.flag == addDirFlag {
			what = "directory"
		}
		return fmt.Errorf("Pass a smaller %s. This launch passes %s %s, which has more than 10,000 entries, "+
			"the most Forager checks, so the run does not start.", what, s.v.flag, accesskey.ShownValue(s.v.value, false))
	}
	return nil
}

// check checks one entry at p of the type typ: a link, as [checkDir] says, and a
// regular file, which must have one name.
func (s *scan) check(p, shown string, typ fs.FileMode) error {
	if typ&fs.ModeSymlink != 0 {
		return s.link(p, shown)
	}
	if !typ.IsRegular() {
		return nil
	}
	info, err := os.Lstat(p)
	if err != nil {
		return checkFailed(s.v, err)
	}
	if links(info) > 1 {
		return hardLinked(s.v, shown)
	}
	return nil
}

// link checks the link at p and, when it leads to a directory, reads that directory.
func (s *scan) link(p, shown string) error {
	if s.a.Inside != nil {
		through, err := throughWorkspace(p)
		if errors.Is(err, errTooManyLinks) {
			return tooManyLinks(s.v, shown)
		}
		if err != nil {
			return checkFailed(s.v, fmt.Errorf("%s: %w", accesskey.ShownValue(shown, false), err))
		}
		if through {
			return linkInto(s.v, shown, workspaceInside)
		}
	}
	target, err := resolveWith(s.a.Readable, p)
	if err != nil {
		return s.linkRefused(shown, "", err)
	}
	info, err := os.Stat(target)
	if errors.Is(err, fs.ErrNotExist) {
		// Readable passed where the link leads, so no walled run can make it.
		return nil
	}
	if err != nil {
		return checkFailed(s.v, err)
	}
	if !info.IsDir() {
		if info.Mode().IsRegular() && links(info) > 1 {
			return hardLinked(s.v, shown)
		}
		return nil
	}
	if _, err := resolveWith(s.a.ReadableDir, p); err != nil {
		return s.linkRefused(shown, target, err)
	}
	if fresh, err := s.enter(target); err != nil || !fresh {
		return err
	}
	return s.dir(target, shown)
}

// linkRefused is the refusal of the link that leads to target, which a refusal shows
// by the path in `shown`, the path Claude Code reads it by: one that lies in a place a
// walled run can write, one whose path goes through such a place, and one that leads
// to a directory that contains one.
func (s *scan) linkRefused(shown, target string, err error) error {
	var written *runtimes.WrittenError
	if !errors.As(err, &written) {
		return checkFailed(s.v, err)
	}
	value := accesskey.ShownValue(s.v.value, false)
	link := accesskey.ShownValue(shown, false)
	switch written.How {
	case "is reached through":
		return fmt.Errorf("Replace the link %s with a copy, or point it at a path that does not go through %s. "+
			"This launch passes %s %s, and that link leads through %s, which a walled run can write, "+
			"so the run does not start.", link, written.Place, s.v.flag, value, written.Place)
	case "contains":
		to := accesskey.ShownValue(target, false)
		return fmt.Errorf("Replace the link %s with a copy, or link to a directory with no place a walled run "+
			"writes. This launch passes %s %s, and that link leads to %s, and %s contains %s, which a walled run "+
			"can write, so the run does not start.", link, s.v.flag, value, to, to, written.Place)
	}
	return linkInto(s.v, shown, written.Place)
}

// throughWorkspace reports whether the path p, followed a name at a time through every
// link as written, looks a name up in workspaceInside or below it. Past a name that
// does not exist the rest is taken as written. A path with more than maxLinks links,
// or a link that cannot be read, is an error.
func throughWorkspace(p string) (bool, error) {
	names := strings.Split(p, "/")
	cur, n, missing := "/", 0, false
	for i := 0; i < len(names); i++ {
		switch names[i] {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, names[i])
		if next == workspaceInside || strings.HasPrefix(next, workspaceInside+"/") {
			return true, nil
		}
		if !missing {
			info, err := os.Lstat(next)
			if err != nil {
				missing = true
			} else if info.Mode()&fs.ModeSymlink != 0 {
				if n++; n > maxLinks {
					return false, errTooManyLinks
				}
				to, err := os.Readlink(next)
				if err != nil {
					return false, err
				}
				if filepath.IsAbs(to) {
					cur = "/"
				}
				names = append(strings.Split(to, "/"), names[i+1:]...)
				i = -1
				continue
			}
		}
		cur = next
	}
	return false, nil
}

// resolveWith is where check, a check of the Attach, says the path p resolves, or
// where it resolves through every link when check is nil.
func resolveWith(check func(string) (string, error), p string) (string, error) {
	if check == nil {
		return filepath.EvalSymlinks(p)
	}
	return check(p)
}

// links is how many names the file of info has.
func links(info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 1
}

// dirFix is what a refusal of a value of [checkDir] for a place a walled run can write
// asks for.
func dirFix(v flagValue) string {
	shown := accesskey.ShownValue(v.value, false)
	if v.flag == addDirFlag {
		return "Remove " + v.flag + " " + shown + ", or add a directory no walled run writes."
	}
	return "Move the plugin " + shown + " to a directory no walled run writes."
}

// writtenValue is the refusal of a value of [checkDir], a directory or a file, for a
// place a walled run can write.
func writtenValue(v flagValue, file bool, written *runtimes.WrittenError) error {
	what := "directory"
	if file {
		what = "file"
	}
	return fmt.Errorf("%s This launch passes %s %s, and that %s %s %s, which a walled run can write, "+
		"so the run does not start.", dirFix(v), v.flag, accesskey.ShownValue(v.value, false), what, written.How, written.Place)
}

// linkInto is the refusal of a link under a directory that leads into a place a walled
// run can write.
func linkInto(v flagValue, link, place string) error {
	return fmt.Errorf("Replace the link %s with a copy, or move what it leads to out of %s. This launch passes %s %s, "+
		"and that link leads into %s, which a walled run can write, so the run does not start.",
		accesskey.ShownValue(link, false), place, v.flag, accesskey.ShownValue(v.value, false), place)
}

// tooManyLinks is the refusal of a value of [checkDir], or of the link link under it,
// whose path [throughWorkspace] follows through more than maxLinks links. The refusal
// shows link as Claude Code reads it; an empty link is the value itself.
func tooManyLinks(v flagValue, link string) error {
	if link == "" {
		return fmt.Errorf("Pass a %s path with fewer links. The check of %s %s failed: %w",
			v.flag, v.flag, accesskey.ShownValue(v.value, false), errTooManyLinks)
	}
	shown := accesskey.ShownValue(link, false)
	return fmt.Errorf("Replace the link %s with a copy, or point it at a path with fewer links. "+
		"The check of %s %s failed: %s: %w", shown, v.flag, accesskey.ShownValue(v.value, false), shown, errTooManyLinks)
}

// hardLinked is the refusal of a file with more than one name.
func hardLinked(v flagValue, file string) error {
	return fmt.Errorf("Replace %s with a copy that has one name. This launch passes %s %s, and that file has more "+
		"than one hard link, so a walled run could change it under another name, and the run does not start.",
		accesskey.ShownValue(file, false), v.flag, accesskey.ShownValue(v.value, false))
}
