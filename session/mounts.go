package session

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/program"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/session/internal/socket"
	"github.com/qoryai/forager/wall"
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
		return "", fmt.Errorf("cannot resolve Forager's file %s: %w", path, err)
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

// holds reports whether outer is inner or lies above it, and same when it is inner.
func holds(outer, inner splitPath) (ok, same bool) {
	rest, ok := within(outer, inner)
	return ok, ok && len(rest) == 0
}

// within reports whether outer is inner or lies above it, with the names of inner below
// outer: none when it is inner. It walks up inner's existing part, itself included, to
// the directory that is the same file as outer's existing part; the names below that
// one, inner's own included, must then begin with outer's names that do not exist yet.
func within(outer, inner splitPath) ([]string, bool) {
	top, err := os.Stat(outer.exists)
	if err != nil {
		return nil, false
	}
	below := inner.tail
	for dir := inner.exists; ; {
		if info, err := os.Stat(dir); err == nil && os.SameFile(top, info) {
			if len(outer.tail) > len(below) {
				return nil, false
			}
			for i, name := range outer.tail {
				if !sameName(name, below[i]) {
					return nil, false
				}
			}
			return below[len(outer.tail):], true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, false
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

// foragerFile is one of Forager's files, and what it is, for the refusal's Detail.
type foragerFile struct {
	path, what string
}

// foragerFiles are the paths a walled run's mounts leave out: the caller's, and every one
// Forager knows itself. The programs are every one the machine defines, not only the
// ones the run's policy selects, because a server's policy selects after the check, and
// a reload may select another credential.
func foragerFiles(spec Spec) []foragerFile {
	var out []foragerFile
	for _, p := range spec.ForagerFiles {
		out = append(out, foragerFile{p, "one of Forager's files"})
	}
	for _, c := range spec.Credentials {
		if len(c.Adapter) > 0 {
			for _, d := range program.Dirs(c.Adapter[0]) {
				out = append(out, foragerFile{d, "the directory of the credential " + c.Name + "'s program"})
			}
		}
		if c.File != "" {
			out = append(out, foragerFile{c.File, "the file the credential " + c.Name + " is read from"})
		}
	}
	for _, t := range spec.Tools {
		if len(t.Command) > 0 {
			for _, d := range program.Dirs(t.Command[0]) {
				out = append(out, foragerFile{d, "the directory of the tool " + t.Name + "'s program"})
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
		foragerFile{gateway.ToolSocketDirs(), "where the tools' sockets are made"},
		foragerFile{socket.Dirs(), "where the runs' record sockets are made"},
		foragerFile{wall.TempDirs(), "where the Docker wall's environment files are made"})
	if f, ok := spec.Wall.(wall.Filer); ok {
		for _, p := range f.Files() {
			out = append(out, foragerFile{p, "one of the " + spec.Wall.Name() + " wall's files"})
		}
	}
	// The run directories hold the record, and the session reads the runtime's settings
	// from them; a run's own is shown to its enclosure read-only, and to no other: no
	// place of this run's holds the runs directory, and a walled run with a bind that
	// is, holds or lies inside the run directory of another walled run still going does
	// not start (checkShared).
	out = append(out, foragerFile{spec.RunsDir, "where the run directories are kept"})
	if dir, err := walledDir(); err == nil {
		out = append(out, foragerFile{dir, "where Forager lists the walled runs still going"})
	}
	return out
}

// lookup is one name looked up on the way to a path: the directory it is looked up in,
// resolved, and the names from that one on, as the path continues from there.
type lookup struct {
	dir  string
	rest []string
	// at is dir as the filesystem has it.
	at splitPath
	// link says the name looked up is a link, which the walk followed.
	link bool
}

// entry is the path of the name looked up: what an agent that can write the directory
// replaces.
func (l lookup) entry() string { return filepath.Join(l.dir, l.rest[0]) }

// lookups walks p as written, a name at a time, and returns every directory a name is
// looked up in, in order: through a link, the names of its target, as written, before
// the rest. It stops after the first name that does not exist, since an agent that can
// write the directory it is looked up in can make it. An engine that binds the path
// looks up the same names in the same directories, so a path is bound as checked only
// while none of them can change.
func lookups(p string) ([]lookup, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return nil, err
	}
	names := parts(abs)
	cur := "/"
	var out []lookup
	links := 0
	for i := 0; i < len(names); i++ {
		switch names[i] {
		case ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		at, err := split(cur, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, lookup{dir: cur, rest: append([]string(nil), names[i:]...), at: at})
		next := filepath.Join(cur, names[i])
		info, err := os.Lstat(next)
		if errors.Is(err, fs.ErrNotExist) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		out[len(out)-1].link = true
		if links++; links > maxLinks {
			return nil, fmt.Errorf("%s: too many links", abs)
		}
		to, err := os.Readlink(next)
		if err != nil {
			return nil, err
		}
		if filepath.IsAbs(to) {
			cur = "/"
		}
		names = append(parts(to), names[i+1:]...)
		i = -1
	}
	return out, nil
}

// parts are the names of a path, as written.
func parts(p string) []string {
	var out []string
	for _, n := range strings.Split(p, "/") {
		if n != "" {
			out = append(out, n)
		}
	}
	return out
}

// linkIn is the path of the last link looked up inside the place out, the one whose
// target leads out of it, below the place's path as passed: absolute, clean, and a link
// when the walk followed it. A path without one is an error, so a refusal never names a
// link that is not one.
func linkIn(out shown, ls []lookup) (string, error) {
	for i := len(ls) - 1; i >= 0; i-- {
		l := ls[i]
		if !l.link {
			continue
		}
		rest, ok := within(out.at, l.at)
		if !ok {
			continue
		}
		link, err := filepath.Abs(filepath.Join(append(append([]string{out.path}, rest...),
			l.rest[0])...))
		if err != nil {
			return "", err
		}
		if info, err := os.Lstat(link); err != nil || info.Mode()&fs.ModeSymlink == 0 {
			return "", fmt.Errorf("the link on the way, %s, is no link now", link)
		}
		return link, nil
	}
	return "", errors.New("no link on the way lies inside it")
}

// lookedUpIn is the first of the lookups whose directory is dir or lies inside it, and
// whether there is one.
func lookedUpIn(dir splitPath, ls []lookup) (lookup, bool) {
	for _, l := range ls {
		if ok, _ := holds(dir, l.at); ok {
			return l, true
		}
	}
	return lookup{}, false
}

// shown is one of the places of this machine a walled run lists: a mount or the
// workspace, its path exactly as the caller passed it, which is what a refusal names.
type shown struct {
	path, what string
	writable   bool
	at         splitPath
	looks      []lookup
	// bound is the path the enclosure binds the place at: its own, clean.
	bound string
}

// mode is how a refusal words whether the enclosure can write a place.
func mode(writable bool) string {
	if writable {
		return "writable"
	}
	return "read-only"
}

// The kinds of a walled run's binds besides the places the run lists.
const (
	kindRun    = "run"
	kindHelper = "helper"
	kindDir    = "directory"
)

// bindSource is one bind of a walled run's: the path as the run passed it, the path
// as it resolved, the entries looked up on the way to it, and whether the enclosure
// can write it.
type bindSource struct {
	Path     string `json:"path"`
	Resolved string `json:"resolved"`
	// Lookups are the paths of the names looked up on the way to Path, each in a
	// resolved directory: an agent that can write one of those directories can change
	// where Path leads.
	Lookups  []string `json:"lookups"`
	Writable bool     `json:"writable"`
	// Kind is empty for a place the run lists, run for the run directory, helper for
	// Forager's helper and directory for another directory of Forager's a wall
	// binds.
	Kind string `json:"kind,omitempty"`
	// Pattern says Path is a pattern of the directories a session makes there later, each
	// its own: it stands for them until the run lists the one it made.
	Pattern bool `json:"pattern,omitempty"`
	// what names the bind in a refusal's sentence, at is where it resolved and looks
	// are its lookups: for this run's own checks alone.
	what  string
	at    splitPath
	looks []lookup
}

// source is the bind source of a path, resolved now.
func source(path, what, kind string, writable bool) (bindSource, error) {
	at, err := split(path, 0)
	if err != nil {
		return bindSource{}, fmt.Errorf("cannot resolve %s: %w", what, err)
	}
	looks, err := lookups(path)
	if err != nil {
		return bindSource{}, fmt.Errorf("cannot resolve %s: %w", what, err)
	}
	b := bindSource{Path: path, Resolved: at.String(), Writable: writable, Kind: kind,
		what: what, at: at, looks: looks}
	for _, l := range looks {
		b.Lookups = append(b.Lookups, l.entry())
	}
	return b, nil
}

// mountPlan is what the enclosure of a walled run binds: the outermost of the places
// the run lists, each once, and then the run directory, read-only.
type mountPlan struct {
	// Mounts are the binds, as [wall.Launch] lists them.
	Mounts []wall.Mount
	// Dir is the working directory inside: the workspace, reached through the bind
	// that holds it.
	Dir string
	// sources are the binds as the registry of walled runs lists them.
	sources []bindSource
}

// checkMounts refuses a caller's Forager file that is not an absolute path and, behind a
// wall, the places the run lists that it cannot bind as they are, and returns what the
// enclosure binds. The places are the run's own, Spec.Mounts and the workspace; the run
// directory, read-only, and the hook socket's directory are Forager's, which it
// keeps apart from every caller's place: the runs directory is one of Forager's
// files, and so is where the sockets are made. A refusal's first name is always one of
// the places exactly as the caller passed it:
//
//   - mount_contains_forager_files: a place that is, contains or lies inside one of
//     Forager's files, or a writable place that contains a directory a name on the way
//     to one is looked up in, a link say; the place and the file are its names, in that
//     order.
//   - mount_mode_conflict: a place inside another one, or the same, of the other mode:
//     a read-only part of a writable bind is one the agent replaces, and a writable
//     part of a read-only one writes what the run shows read-only. Its names are the
//     inner place and the outer one, in that order.
//   - mount_through_link: a place, of either mode, whose path goes through a link
//     inside a writable place and does not resolve into it: the agent that writes the
//     link chooses what is bound. Its names are the place, the link and the writable
//     place, in that order.
//
// A place inside another one of the same mode is no bind of its own: the enclosure
// reaches it through the outer one, at the same path. So no bound place is reached
// through a directory another bound place lets the agent write. The workspace is
// writable, and is the working directory inside, in one of the binds.
func checkMounts(spec Spec, runDir string) (mountPlan, error) {
	for _, p := range spec.ForagerFiles {
		if strings.ContainsRune(p, 0) {
			return mountPlan{}, errors.New("a Forager file's path holds a NUL byte")
		}
		if !filepath.IsAbs(p) {
			return mountPlan{}, fmt.Errorf("the Forager file %q is not an absolute path", p)
		}
	}
	if spec.Wall == nil {
		return mountPlan{}, nil
	}
	var places []shown
	for _, m := range spec.Mounts {
		places = append(places, shown{path: m.Path, what: "the mount", writable: !m.ReadOnly})
	}
	places = append(places, shown{path: spec.Dir, what: "the workspace", writable: true})
	files := foragerFiles(spec)
	fileLooks := make([][]lookup, len(files))
	for i, f := range files {
		ls, err := lookups(f.path)
		if err != nil {
			return mountPlan{}, fmt.Errorf("cannot resolve Forager's file %s: %w", f.path, err)
		}
		fileLooks[i] = ls
	}
	for i, m := range places {
		for _, f := range files {
			how, err := overlap(m.path, f.path)
			if err != nil {
				return mountPlan{}, err
			}
			if how != "" {
				return mountPlan{}, &Refusal{
					Code:   refusal.MountContainsForagerFiles,
					Names:  []string{m.path, f.path},
					Detail: fmt.Sprintf("%s %s %s %s, %s", m.what, m.path, how, f.path, f.what),
				}
			}
		}
		at, err := split(m.path, 0)
		if err != nil {
			return mountPlan{}, fmt.Errorf("cannot resolve %s %s: %w", m.what, m.path, err)
		}
		looks, err := lookups(m.path)
		if err != nil {
			return mountPlan{}, fmt.Errorf("cannot resolve %s %s: %w", m.what, m.path, err)
		}
		places[i].at, places[i].looks, places[i].bound = at, looks, filepath.Clean(m.path)
		if !m.writable {
			continue
		}
		// A link on the way to a file of Forager's, in a place the agent writes, is one the
		// agent points elsewhere.
		for j, f := range files {
			if l, ok := lookedUpIn(at, fileLooks[j]); ok {
				return mountPlan{}, &Refusal{
					Code:  refusal.MountContainsForagerFiles,
					Names: []string{m.path, f.path},
					Detail: fmt.Sprintf("%s %s contains %s, on the way to %s, %s",
						m.what, m.path, l.entry(), f.path, f.what),
				}
			}
		}
	}
	// A place, of either mode, whose path goes through a link inside a writable place of
	// the run's, and that does not resolve into that place, is no run: the link chooses
	// what is bound, and the agent that can write where the link lies chooses it. A
	// place that resolves into the writable one is reached through it, below, and
	// nothing is bound through the link.
	for i, in := range places {
		for j, out := range places {
			if j == i || !out.writable {
				continue
			}
			if ok, _ := holds(out.at, in.at); ok {
				continue
			}
			if _, ok := lookedUpIn(out.at, in.looks); !ok {
				continue
			}
			link, err := linkIn(out, in.looks)
			if err != nil {
				return mountPlan{}, fmt.Errorf("%s %s is looked up inside %s %s and resolves "+
					"outside it: %w", in.what, in.path, out.what, out.path, err)
			}
			return mountPlan{}, &Refusal{
				Code:  refusal.MountThroughLink,
				Names: []string{in.path, link, out.path},
				Detail: fmt.Sprintf("%s is reached through the link %s inside %s, which a "+
					"walled agent can change: list the link's target itself",
					in.path, link, out.path),
			}
		}
	}
	// outer[i] is the place i is bound through: the first other place that holds it, or
	// the earlier one of two that are the same; -1 when none is.
	outer := make([]int, len(places))
	for i, in := range places {
		outer[i] = -1
		for j, out := range places {
			if j == i {
				continue
			}
			ok, same := holds(out.at, in.at)
			if !ok || (same && j > i) {
				continue
			}
			if in.writable != out.writable {
				return mountPlan{}, modeConflict(in, out, same)
			}
			if outer[i] < 0 {
				outer[i] = j
			}
		}
	}
	var plan mountPlan
	for i, p := range places {
		if outer[i] >= 0 {
			continue
		}
		plan.Mounts = append(plan.Mounts, wall.Mount{Path: p.bound, ReadOnly: !p.writable})
		b := bindSource{Path: p.path, Resolved: p.at.String(), Writable: p.writable,
			what: p.what + " " + p.path, at: p.at, looks: p.looks}
		for _, l := range p.looks {
			b.Lookups = append(b.Lookups, l.entry())
		}
		plan.sources = append(plan.sources, b)
	}
	// The workspace is the last place: its root is the outermost place that holds it,
	// and inside it is the path that place is bound at with the names of the workspace
	// below it.
	ws := len(places) - 1
	root, seen := ws, map[int]bool{}
	for outer[root] >= 0 {
		if seen[root] {
			return mountPlan{}, fmt.Errorf("the places the run lists lie inside each other "+
				"through links: %s", places[root].path)
		}
		seen[root] = true
		root = outer[root]
	}
	plan.Dir = places[ws].bound
	if root != ws {
		if rest, ok := within(places[root].at, places[ws].at); ok {
			plan.Dir = filepath.Join(append([]string{places[root].bound}, rest...)...)
		}
	}
	if err := dirInBinds(plan.Dir, plan.Mounts); err != nil {
		return mountPlan{}, err
	}
	run, err := source(runDir, "the run directory "+runDir, kindRun, false)
	if err != nil {
		return mountPlan{}, err
	}
	plan.Mounts = append(plan.Mounts, wall.Mount{Path: runDir, ReadOnly: true})
	// The run directory is named by the runs directory the caller passed, in which the
	// session makes it.
	run.Path = spec.RunsDir
	plan.sources = append(plan.sources, run)
	return plan, nil
}

// dirInBinds fails a plan whose working directory lies, by its names, in none of its
// binds: the enclosure binds what the plan lists and nothing else, so it would be bound
// unchecked, or not at all.
func dirInBinds(dir string, mounts []wall.Mount) error {
	if slices.ContainsFunc(mounts, func(m wall.Mount) bool { return under(m.Path, dir) }) {
		return nil
	}
	return fmt.Errorf("the working directory inside, %s, lies in none of the places the "+
		"enclosure binds: %v", dir, paths(mounts))
}

// under reports whether path is dir or lies inside it, by the names of both, clean.
func under(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	up := ".." + string(filepath.Separator)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, up)
}

// modeConflict is the refusal of a place inside another one of the other mode.
func modeConflict(in, out shown, same bool) *Refusal {
	noun := "mount"
	if out.what == "the workspace" {
		noun = "place"
	}
	how, why := "lies inside", "a part of a writable "+noun+" can't be read-only"
	if in.writable {
		why = "a part of a read-only " + noun + " can't be writable"
	}
	if same {
		how, why = "is", "one place can't be both writable and read-only"
	}
	return &Refusal{
		Code:  refusal.MountModeConflict,
		Names: []string{in.path, out.path},
		Detail: fmt.Sprintf("%s %s (%s) %s %s %s (%s): %s",
			in.what, in.path, mode(in.writable), how, out.what, out.path, mode(out.writable), why),
	}
}

// String is the path as it resolved: the existing part and the names below it.
func (s splitPath) String() string {
	return filepath.Join(append([]string{s.exists}, s.tail...)...)
}

// samePlan fails a walled run whose places resolve otherwise just before the enclosure
// binds them than when the run started, or whose names are looked up in other
// directories.
func samePlan(start, now mountPlan) error {
	if !slices.Equal(start.Mounts, now.Mounts) || len(start.sources) != len(now.sources) {
		return fmt.Errorf("the places the run binds changed since it started: %v then, %v now",
			paths(start.Mounts), paths(now.Mounts))
	}
	for i, s := range start.sources {
		n := now.sources[i]
		if s.Resolved != n.Resolved {
			return fmt.Errorf("%s resolved to %s when the run started and resolves to %s now",
				s.what, s.Resolved, n.Resolved)
		}
		// A name that did not exist at the start, the run directory's own among them, is
		// looked up further now: the start's lookups are the first of now's, and a link
		// made since leads elsewhere, which Resolved shows.
		if len(n.Lookups) < len(s.Lookups) ||
			!slices.Equal(s.Lookups, n.Lookups[:len(s.Lookups)]) {
			return fmt.Errorf("the way to %s changed since the run started: its names were "+
				"looked up as %s, and are now looked up as %s", s.what,
				strings.Join(s.Lookups, ", "), strings.Join(n.Lookups, ", "))
		}
	}
	if start.Dir != now.Dir {
		return fmt.Errorf("the working directory inside was %s when the run started and is "+
			"%s now", start.Dir, now.Dir)
	}
	return nil
}

// paths are the paths of mounts.
func paths(ms []wall.Mount) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Path
	}
	return out
}

// firstWallBinds are the binds a wall makes of its own as it knows them when the run
// starts, as bind sources, and, when it binds any, the pattern of the private
// directories of the runs' record sockets, the hook socket's among them, writable:
// none when it lists none.
func firstWallBinds(w wall.Wall) ([]bindSource, error) {
	b, ok := w.(wall.Binder)
	if !ok {
		return nil, nil
	}
	binds, err := b.Binds(wall.Launch{})
	if err != nil {
		return nil, err
	}
	binds = append(binds, wall.Bind{Path: socket.Dirs(), Pattern: true})
	return bindSources(binds)
}

// wallBinds are the binds an enclosure makes of its own, as bind sources: none when
// it lists none.
func wallBinds(e wall.Enclosure, socketPath string, ca []byte) ([]bindSource, error) {
	b, ok := e.(wall.Binder)
	if !ok {
		return nil, nil
	}
	binds, err := b.Binds(wall.Launch{Socket: socketPath, CA: ca})
	if err != nil {
		return nil, err
	}
	return bindSources(binds)
}

// bindSources are a wall's own binds as bind sources.
func bindSources(binds []wall.Bind) ([]bindSource, error) {
	var out []bindSource
	for _, m := range binds {
		what, kind := "Forager's directory "+m.Path, kindDir
		if m.Helper {
			what, kind = "Forager's helper "+m.Path, kindHelper
		}
		src, err := source(m.Path, what, kind, !m.ReadOnly)
		if err != nil {
			return nil, err
		}
		src.Pattern = m.Pattern
		out = append(out, src)
	}
	return out, nil
}
