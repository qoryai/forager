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

// maxLinks is how many links [throughWorkspace] follows in one path before it takes the
// path as one that leads into the workspace.
const maxLinks = 40

// errTooMany ends a scan that reads more than maxEntries entries.
var errTooMany = errors.New("too many entries")

// checkDir checks the value of --plugin-dir, --plugin-dir-no-mcp or --add-dir in a
// walled launch. A directory must pass [runtimes.Attach.ReadableDir]: it may not lie
// in, be reached through or contain a place a walled run can write. Then every entry
// under it, for --add-dir only .claude and CLAUDE.md, is read without following a link
// as it is read: a link must pass Readable, and a link to a directory ReadableDir, and
// the directory it leads to is read the same way; a regular file, and a file a link
// leads to, must have one name. A link that leads into /workspace, for a run that sees
// its workspace there, is refused. The scan stops after maxEntries entries. Any other
// value, a .zip say, is checked as a file: it must pass Readable, be no link as its last
// part, be a regular file and have one name.
func checkDir(v flagValue, a runtimes.Attach) error {
	info, err := os.Stat(v.value)
	if err != nil {
		return dirRefused(v, err)
	}
	if !info.IsDir() {
		return checkPluginFile(v, a)
	}
	real, err := resolveWith(a.ReadableDir, v.value)
	if err != nil {
		var written *runtimes.WrittenError
		if errors.As(err, &written) {
			return writtenDir(v, written)
		}
		return dirRefused(v, err)
	}
	s := &scan{v: v, a: a, seen: map[string]bool{real: true}}
	if v.flag != addDirFlag {
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
			return fmt.Errorf("This launch passes %s %s, and that file %s %s, which a walled run can write, "+
				"so the run does not start. %s", v.flag, shown, written.How, written.Place, dirFix(v))
		}
		return dirRefused(v, err)
	}
	info, err := os.Lstat(v.value)
	switch {
	case err != nil:
		return dirRefused(v, err)
	case info.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("This launch passes %s %s, and that file is a link, so the run does not start.", v.flag, shown)
	case !info.Mode().IsRegular():
		return fmt.Errorf("This launch passes %s %s, and that file is not a regular file, so the run does not start.", v.flag, shown)
	case links(info) > 1:
		return hardLinked(v, v.value)
	}
	return nil
}

// scan reads the entries under a directory of one value: the value, the Attach's
// checks, how many entries it read, and the directories it read, as they resolve, so a
// link back to one is not read again.
type scan struct {
	v    flagValue
	a    runtimes.Attach
	n    int
	seen map[string]bool
}

// dir reads every entry under the directory real, which a refusal names by shown, the
// path Claude Code reads it by.
func (s *scan) dir(real, shown string) error {
	return filepath.WalkDir(real, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return dirRefused(s.v, err)
		}
		if p == real {
			return nil
		}
		rel, err := filepath.Rel(real, p)
		if err != nil {
			return dirRefused(s.v, err)
		}
		if err := s.count(); err != nil {
			return err
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
		return dirRefused(s.v, err)
	}
	if err := s.count(); err != nil {
		return err
	}
	if err := s.check(p, shown, info.Mode().Type()); err != nil {
		return err
	}
	if info.IsDir() {
		return s.dir(p, shown)
	}
	return nil
}

// count counts one entry more, and refuses the value past maxEntries.
func (s *scan) count() error {
	if s.n++; s.n > maxEntries {
		what := "plugin directory"
		if s.v.flag == addDirFlag {
			what = "directory"
		}
		return fmt.Errorf("This launch passes %s %s, which has more than 10,000 entries, the most Forager checks, "+
			"so the run does not start. Pass a smaller %s.", s.v.flag, accesskey.ShownValue(s.v.value, false), what)
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
		return dirRefused(s.v, err)
	}
	if links(info) > 1 {
		return hardLinked(s.v, shown)
	}
	return nil
}

// link checks the link at p and, when it leads to a directory, reads that directory.
func (s *scan) link(p, shown string) error {
	if s.a.Inside != nil && throughWorkspace(p) {
		return linkInto(s.v, shown, workspaceInside)
	}
	target, err := resolveWith(s.a.Readable, p)
	if err != nil {
		return s.linkRefused(shown, err)
	}
	info, err := os.Stat(target)
	if errors.Is(err, fs.ErrNotExist) {
		// Readable passed where the link leads, so no walled run can make it.
		return nil
	}
	if err != nil {
		return dirRefused(s.v, err)
	}
	if !info.IsDir() {
		if info.Mode().IsRegular() && links(info) > 1 {
			return hardLinked(s.v, shown)
		}
		return nil
	}
	if _, err := resolveWith(s.a.ReadableDir, p); err != nil {
		return s.linkRefused(shown, err)
	}
	if s.seen[target] {
		return nil
	}
	s.seen[target] = true
	return s.dir(target, shown)
}

// linkRefused is the refusal of the link a refusal names by shown.
func (s *scan) linkRefused(shown string, err error) error {
	var written *runtimes.WrittenError
	if errors.As(err, &written) {
		return linkInto(s.v, shown, written.Place)
	}
	return dirRefused(s.v, err)
}

// throughWorkspace reports whether the path p, followed a name at a time through every
// link as written, looks a name up in workspaceInside or below it. Past a name that
// does not exist the rest is taken as written. A path with more than maxLinks links
// is taken as one that does.
func throughWorkspace(p string) bool {
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
			return true
		}
		if !missing {
			info, err := os.Lstat(next)
			if err != nil {
				missing = true
			} else if info.Mode()&fs.ModeSymlink != 0 {
				if n++; n > maxLinks {
					return true
				}
				to, err := os.Readlink(next)
				if err != nil {
					return true
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
	return false
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
	if v.flag == addDirFlag {
		shown := accesskey.ShownValue(v.value, false)
		return "Remove " + v.flag + " " + shown + ", or add a directory no walled run writes."
	}
	return "Move the plugin to a directory no walled run writes."
}

// writtenDir is the refusal of a directory for a place a walled run can write.
func writtenDir(v flagValue, written *runtimes.WrittenError) error {
	return fmt.Errorf("This launch passes %s %s, and that directory %s %s, which a walled run can write, "+
		"so the run does not start. %s", v.flag, accesskey.ShownValue(v.value, false), written.How, written.Place, dirFix(v))
}

// linkInto is the refusal of a link under a directory that leads into a place a walled
// run can write.
func linkInto(v flagValue, link, place string) error {
	return fmt.Errorf("This launch passes %s %s, and its link %s leads into %s, which a walled run can write, "+
		"so the run does not start. Replace the link with a copy, or move what it leads to out of %s.",
		v.flag, accesskey.ShownValue(v.value, false), accesskey.ShownValue(link, false), place, place)
}

// hardLinked is the refusal of a file with more than one name.
func hardLinked(v flagValue, file string) error {
	return fmt.Errorf("This launch passes %s %s, and %s has more than one hard link, so a walled run could change it "+
		"under another name, and the run does not start. Replace the file with a copy that has one name.",
		v.flag, accesskey.ShownValue(v.value, false), accesskey.ShownValue(file, false))
}

// dirRefused is the refusal of a value of [checkDir] for any other reason: the reason
// after the flag and the value, as the settings' refusals are.
func dirRefused(v flagValue, err error) error {
	return fmt.Errorf("%s %s: %w", v.flag, accesskey.ShownValue(v.value, false), accesskey.ShownError(err))
}
