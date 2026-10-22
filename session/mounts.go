package session

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
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
// directory this user cannot search, is empty here; [Run.Join] refuses a mount of one.
func Overlap(mount, path string) string {
	how, _ := overlap(mount, path)
	return how
}

// overlap is [Overlap], with the error of a path that cannot be resolved.
func overlap(mount, path string) (string, error) {
	m, err := split(mount, 0)
	if err != nil {
		return "", fmt.Errorf("cannot resolve the mount %s: %w", pathShown(mount), accesskey.ShownError(err))
	}
	p, err := split(path, 0)
	if err != nil {
		return "", fmt.Errorf("cannot resolve Forager's file %s: %w", pathShown(path), accesskey.ShownError(err))
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
		return splitPath{}, accesskey.ShownError(err)
	}
	var tail []string
	for dir := abs; ; {
		target, err := filepath.EvalSymlinks(dir)
		if err == nil {
			return splitPath{target, tail}, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return splitPath{}, accesskey.ShownError(err)
		}
		info, err := os.Lstat(dir)
		switch {
		case err == nil && info.Mode()&fs.ModeSymlink != 0:
			// A link whose target does not exist yet: the target, read from the
			// link's own directory, resolved, is where the path leads once it does.
			if links >= maxLinks {
				return splitPath{}, fmt.Errorf("%s: too many links", pathShown(abs))
			}
			to, err := os.Readlink(dir)
			if err != nil {
				return splitPath{}, accesskey.ShownError(err)
			}
			if !filepath.IsAbs(to) {
				parent, err := filepath.EvalSymlinks(filepath.Dir(dir))
				if err != nil {
					return splitPath{}, accesskey.ShownError(err)
				}
				to = filepath.Join(parent, to)
			}
			return split(filepath.Join(append([]string{to}, tail...)...), links+1)
		case err == nil:
			return splitPath{}, fmt.Errorf("%s exists and does not resolve", pathShown(dir))
		case !errors.Is(err, fs.ErrNotExist):
			return splitPath{}, accesskey.ShownError(err)
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

// foragerFiles are the paths a walled run's mounts leave out: the caller's, the
// gateway's, and every one Forager knows itself. The gateway's programs are every one
// the machine defines, not only the ones the run's policy selects, because a server's
// policy selects after the check, and a reload may select another credential.
func foragerFiles(spec runSpec) []foragerFile {
	var out []foragerFile
	for _, p := range spec.ForagerFiles {
		out = append(out, foragerFile{p, "one of Forager's files"})
	}
	// The gateway's own files, which it hands the session with its link, each with what
	// it is: first the directories of its credentials' and tools' programs, its
	// credentials' files and the pattern of its tools' socket directories, in the order
	// they were checked in before the gateway was apart from the session; the
	// directories it keeps come last, below. So a mount refused before says what it
	// said.
	var kept []foragerFile
	for _, f := range gatewayFiles(spec.Gateway) {
		if f.Kept {
			kept = append(kept, foragerFile{f.Path, f.What})
			continue
		}
		out = append(out, foragerFile{f.Path, f.What})
	}
	// The private directory of a tool's socket is made when the tool starts, in the
	// system's temporary directory; a mount that contains its pattern would contain it.
	// It is checked whether or not the run has tools, since another run's on this
	// machine are there too. So are the private directories of the runs' record
	// sockets and of the Docker wall's environment files, which hold the proxy's
	// secret: this run's are made after the check, and other runs' exist.
	out = append(out,
		foragerFile{filepath.Join(os.TempDir(), link.ToolDirPrefix+"*"), "where the tools' sockets are made"},
		foragerFile{socket.Dirs(), "where the runs' record sockets are made"},
		foragerFile{wall.TempDirs(), "where the Docker wall's environment files are made"})
	if f, ok := spec.Wall.(wall.Filer); ok {
		for _, p := range f.Files() {
			out = append(out, foragerFile{p, "one of the " + accesskey.ShownName(spec.Wall.Name(), false) + " wall's files"})
		}
	}
	// The run directories hold the record, and the session reads the runtime's settings
	// from a session's directory in them; the directory of the session that runs is
	// shown to its enclosure read-only, and nothing else of a run directory is: no
	// place of this run's holds the runs directory, and a walled run with a bind that
	// is, holds or lies inside the run directory of another walled run still going does
	// not start (checkShared).
	out = append(out, foragerFile{spec.RunsDir, "where the run directories are kept"})
	if dir, err := walledDir(); err == nil {
		out = append(out, foragerFile{dir, "where Forager lists the walled runs still going"})
	}
	// The directories the gateway keeps come last, after every file a session checked
	// before the gateway was apart from it. The pattern of the gateways' link
	// directories, in the system's temporary directory, is among them whatever the
	// run's gateway: a local gateway lists it with its own files, and behind a separate
	// gateway another gateway's on this machine may be there.
	links := foragerFile{filepath.Join(os.TempDir(), link.LinkDirPrefix+"*"), "where the gateways' links are made"}
	if !slices.Contains(kept, links) {
		kept = append(kept, links)
	}
	return append(out, kept...)
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
	looks, _, err := lookupsOf(abs, parts(abs))
	return looks, err
}

// lookupsOf is [lookups] of the names of the absolute path abs, as they are given: a ..
// name among them is followed from the directory the walk is in, as the filesystem
// follows it, where a link may have led. It returns too where the walk ends when it
// follows every name, through every link, and empty when it stops at a name that
// does not exist.
func lookupsOf(abs string, names []string) ([]lookup, string, error) {
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
			return nil, "", accesskey.ShownError(err)
		}
		out = append(out, lookup{dir: cur, rest: append([]string(nil), names[i:]...), at: at})
		next := filepath.Join(cur, names[i])
		info, err := os.Lstat(next)
		if errors.Is(err, fs.ErrNotExist) {
			return out, "", nil
		}
		if err != nil {
			return nil, "", accesskey.ShownError(err)
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		out[len(out)-1].link = true
		if links++; links > maxLinks {
			return nil, "", fmt.Errorf("%s: too many links", pathShown(abs))
		}
		to, err := os.Readlink(next)
		if err != nil {
			return nil, "", accesskey.ShownError(err)
		}
		if filepath.IsAbs(to) {
			cur = "/"
		}
		names = append(parts(to), names[i+1:]...)
		i = -1
	}
	return out, cur, nil
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
			return "", fmt.Errorf("the link on the way, %s, is no link now", pathShown(link))
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
		return bindSource{}, fmt.Errorf("cannot resolve %s: %w", what, accesskey.ShownError(err))
	}
	looks, err := lookups(path)
	if err != nil {
		return bindSource{}, fmt.Errorf("cannot resolve %s: %w", what, accesskey.ShownError(err))
	}
	b := bindSource{Path: path, Resolved: at.String(), Writable: writable, Kind: kind,
		what: what, at: at, looks: looks}
	for _, l := range looks {
		b.Lookups = append(b.Lookups, l.entry())
	}
	return b, nil
}

// mountPlan is what the enclosure of a walled run binds: the outermost of the places
// the run lists, each once, and then the session's directory, read-only.
type mountPlan struct {
	// Mounts are the binds, as [wall.Launch] lists them.
	Mounts []wall.Mount
	// Dir is the working directory inside: the workspace, reached through the bind
	// that holds it.
	Dir string
	// root is the path of the bind that holds the workspace, as Mounts lists it.
	root string
	// sources are the binds as the registry of walled runs lists them.
	sources []bindSource
}

// workspaceInside is where a run whose policy names its image by its reference sees the
// bind that holds its workspace: the working directory is workspaceInside, or a
// directory under it, whatever its path on this machine.
const workspaceInside = "/workspace"

// atWorkspace is the plan of a run whose policy names its image by its reference: the
// bind that holds the workspace shown at [workspaceInside], the working directory under
// it, and inside, which writes a path of that bind's as the enclosure sees it, at
// whole components ([translate]). Every other bind stays at the same path; one whose
// path is, holds or lies under workspaceInside, the session's directory among them, is
// refused, with no code.
func (p mountPlan) atWorkspace() (mountPlan, func(string) string, error) {
	if p.root == "" || p.root == string(filepath.Separator) {
		return mountPlan{}, nil, fmt.Errorf("the workspace is reached through %s, which cannot be shown at %s", accesskey.ShownValue(p.root, true), workspaceInside)
	}
	out := p
	out.Mounts = slices.Clone(p.Mounts)
	for i, m := range out.Mounts {
		if m.Path == p.root {
			out.Mounts[i].Target = workspaceInside
			continue
		}
		if under(workspaceInside, m.Path) || under(m.Path, workspaceInside) {
			return mountPlan{}, nil, fmt.Errorf("%s is shown at the same path inside, which overlaps %s, where a run "+
				"whose image its policy names by reference sees its workspace", pathShown(m.Path), workspaceInside)
		}
	}
	inside := func(s string) string { return translate(s, p.root, workspaceInside) }
	out.Dir = inside(p.Dir)
	return out, inside, nil
}

// translate is s with every occurrence of the absolute path from, at whole components
// by [argPaths], written as to. /work/app becomes /workspace/app for /work, and
// /workshop, /a/work, ${A}/work and work stay as they are.
func translate(s, from, to string) string {
	if from == "" || from == to {
		return s
	}
	return replacePaths(s, []pathPair{{from, to}}, argPaths)
}

// pathPair is an absolute path, from, and the text written in its place, to.
type pathPair struct{ from, to string }

// pathRule is where replacePaths matches a path: start reports whether a path may start
// at byte i of s, and end whether a path that ends at byte end of s ends at a whole
// component there.
type pathRule struct {
	start func(s string, i int) bool
	end   func(s string, end int) bool
}

// argPaths is the rule for a value the agent gets, such as an argument or a variable,
// where a wrong replacement changes what the agent does. A path matches where it starts
// s, follows a separator of words or follows file://, and where it ends s, is followed
// by a slash, a separator of words, ] or }, or is followed by ., ? or ! that ends s or
// comes before white space, as at the end of a sentence. A separator of words is white
// space, a quote, a comma, a colon, as in a list of paths, an equals sign, as in
// --flag=path, or one of the shell's characters that end a word. ${A}/work stays as
// it is for /work.
var argPaths = pathRule{
	start: func(s string, i int) bool {
		return i == 0 || strings.IndexByte(wordSeparators, s[i-1]) >= 0 || strings.HasSuffix(s[:i], "file://")
	},
	end: func(s string, end int) bool {
		if end == len(s) || s[end] == '/' || strings.IndexByte(wordSeparators+"]}", s[end]) >= 0 {
			return true
		}
		return strings.IndexByte(".?!", s[end]) >= 0 && (end+1 == len(s) || strings.IndexByte(" \t\n\r", s[end+1]) >= 0)
	},
}

// wordSeparators are the characters of argPaths that separate a path from what is
// before it in a word or a line.
const wordSeparators = " \t\n\r\"'`:;=,&|()<>"

// shownPaths is the rule for a value that is only shown, such as an event's argument
// or prompt, where a path left in its real form costs more than a wrong replacement: a
// path matches wherever it is not part of a longer name. It matches where it starts s,
// follows a character other than a slash or a character of a name ([nameByte]), or
// follows file://, and where it ends s, is followed by a slash or by a character other
// than one of a name. Of ., ? and !, one or more of them match unless a character of a
// name follows them: /srv/in., /srv/in..., /srv/in.) and /srv/in? match /srv/in, and
// /srv/in.bak, /srv/in.d and /srv/in?x=1 do not. ${BASE}/srv/in becomes ${BASE}<inputs>
// for /srv/in, and https://host/srv/in and /a/srv/in stay as they are.
var shownPaths = pathRule{
	start: func(s string, i int) bool {
		return i == 0 || (s[i-1] != '/' && !nameByte(s[i-1])) || strings.HasSuffix(s[:i], "file://")
	},
	end: func(s string, end int) bool {
		k := end
		for k < len(s) && strings.IndexByte(".?!", s[k]) >= 0 {
			k++
		}
		if k == end {
			return end == len(s) || s[end] == '/' || !nameByte(s[end])
		}
		return k == len(s) || !nameByte(s[k])
	},
}

// nameByte reports whether c is a character of a name in a path: a letter or a digit
// of ASCII, ., _, ~ or -.
func nameByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("._~-", c) >= 0
}

// replacePaths is s with each path of pairs written as its to, in one pass over s: at
// each slash where rule lets a path start, the first path of pairs that matches there
// and ends where rule lets it end is replaced, and the text written in its place is
// not matched again. With the longer path first in pairs, the longer of two paths
// where one contains the other is replaced.
func replacePaths(s string, pairs []pathPair, rule pathRule) string {
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '/' || !rule.start(s, i) {
			continue
		}
		for _, p := range pairs {
			end := i + len(p.from)
			if p.from == "" || !strings.HasPrefix(s[i:], p.from) || !rule.end(s, end) {
				continue
			}
			b.WriteString(s[last:i])
			b.WriteString(p.to)
			last, i = end, end-1
			break
		}
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// checkMounts refuses a caller's Forager file that is not an absolute path and, behind a
// wall, the places the run lists that it cannot bind as they are, and returns what the
// enclosure binds. The places are the run's own, SessionSpec.Mounts and the workspace; the
// session's directory in the run directory, sessionDir, read-only, unless sessionDir is
// empty, as for the setup container, which has none, and the hook socket's
// directory are Forager's, which it keeps apart from every caller's place: the runs
// directory is one of Forager's files, and so is where the sockets are made. A
// refusal's first name is always one of
// the places exactly as the caller passed it, or [accesskey.ShownName]'s phrase in its
// place when it contains qak_ or qrk_ in any case. Detail prints such a path as
// [accesskey.ShownValue]'s phrase, and the names list each phrase once:
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
//     inside a writable place, or inside a place of SessionSpec.Written, and does not resolve
//     into it: the agent that writes the link chooses what is bound. Its names are the
//     place, the link and the writable or written place, in that order.
//
// A place inside another one of the same mode is no bind of its own: the enclosure
// reaches it through the outer one, at the same path. So no bound place is reached
// through a directory another bound place lets the agent write. The workspace is
// writable, and is the working directory inside, in one of the binds.
func checkMounts(spec runSpec, runDir, sessionDir string) (mountPlan, error) {
	for _, p := range spec.ForagerFiles {
		if strings.ContainsRune(p, 0) {
			return mountPlan{}, errors.New("a Forager file's path holds a NUL byte")
		}
		if !filepath.IsAbs(p) {
			return mountPlan{}, fmt.Errorf("the Forager file %s is not an absolute path", accesskey.ShownValue(p, true))
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
			return mountPlan{}, fmt.Errorf("cannot resolve Forager's file %s: %w", pathShown(f.path), accesskey.ShownError(err))
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
					Names:  pathsShown(m.path, f.path),
					Detail: fmt.Sprintf("%s %s %s %s, %s", m.what, pathShown(m.path), how, pathShown(f.path), f.what),
				}
			}
		}
		at, err := split(m.path, 0)
		if err != nil {
			return mountPlan{}, fmt.Errorf("cannot resolve %s %s: %w", m.what, pathShown(m.path), accesskey.ShownError(err))
		}
		looks, err := lookups(m.path)
		if err != nil {
			return mountPlan{}, fmt.Errorf("cannot resolve %s %s: %w", m.what, pathShown(m.path), accesskey.ShownError(err))
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
					Names: pathsShown(m.path, f.path),
					Detail: fmt.Sprintf("%s %s contains %s, on the way to %s, %s",
						m.what, pathShown(m.path), pathShown(l.entry()), pathShown(f.path), f.what),
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
			if err := throughLink(in, out); err != nil {
				return mountPlan{}, err
			}
		}
	}
	// So is a place whose path goes through a link inside a place of SessionSpec.Written and
	// does not resolve into it: an agent of an earlier walled run, ended or still going,
	// may have written the link, and it would choose what is bound.
	for _, w := range spec.Written {
		at, err := split(w, 0)
		if err != nil {
			return mountPlan{}, fmt.Errorf("Fix the error at the end of this message, then run the command again. Cannot resolve the written place %s: %w", pathShown(w), accesskey.ShownError(err))
		}
		out := shown{path: w, what: "the written place", writable: true, at: at}
		for _, in := range places {
			if err := throughLink(in, out); err != nil {
				return mountPlan{}, err
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
			what: p.what + " " + pathShown(p.path), at: p.at, looks: p.looks}
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
				"through links: %s", pathShown(places[root].path))
		}
		seen[root] = true
		root = outer[root]
	}
	plan.Dir, plan.root = places[ws].bound, places[root].bound
	if root != ws {
		if rest, ok := within(places[root].at, places[ws].at); ok {
			plan.Dir = filepath.Join(append([]string{places[root].bound}, rest...)...)
		}
	}
	if err := dirInBinds(plan.Dir, plan.Mounts); err != nil {
		return mountPlan{}, err
	}
	// The registry lists the run directory, which holds the session's: no other walled
	// run binds a part of it.
	run, err := runDirSource(spec.OpenSpec, runDir)
	if err != nil {
		return mountPlan{}, err
	}
	if sessionDir != "" {
		plan.Mounts = append(plan.Mounts, wall.Mount{Path: sessionDir, ReadOnly: true})
	}
	plan.sources = append(plan.sources, run)
	return plan, nil
}

// runDirSource is the run directory as the registry of walled runs lists it: named by
// the runs directory the caller passed, in which the open makes it.
func runDirSource(spec OpenSpec, runDir string) (bindSource, error) {
	run, err := source(runDir, "the run directory "+pathShown(runDir), kindRun, false)
	if err != nil {
		return bindSource{}, err
	}
	run.Path = spec.RunsDir
	return run, nil
}

// throughLink is the refusal of a place whose path goes through a link inside the
// writable place out and does not resolve into it, mount_through_link, or nil when its
// path does not. A place that resolves into out is reached through it, and nothing is
// bound through the link.
func throughLink(in, out shown) error {
	if ok, _ := holds(out.at, in.at); ok {
		return nil
	}
	if _, ok := lookedUpIn(out.at, in.looks); !ok {
		return nil
	}
	link, err := linkIn(out, in.looks)
	if err != nil {
		return fmt.Errorf("List the path that %s %s resolves to, in place of the path given. "+
			"The path is looked up inside %s %s and resolves outside it: %w", in.what, pathShown(in.path), out.what, pathShown(out.path),
			accesskey.ShownError(err))
	}
	return &Refusal{
		Code:  refusal.MountThroughLink,
		Names: pathsShown(in.path, link, out.path),
		Detail: fmt.Sprintf("List the path that %s resolves to, in place of %s. %s is reached "+
			"through the link %s inside %s, which a walled agent can change",
			pathShown(in.path), pathShown(in.path), pathShown(in.path), pathShown(link),
			pathShown(out.path)),
	}
}

// dirInBinds fails a plan whose working directory lies, by its names, in none of its
// binds: the enclosure binds what the plan lists and nothing else, so it would be bound
// unchecked, or not at all.
func dirInBinds(dir string, mounts []wall.Mount) error {
	if slices.ContainsFunc(mounts, func(m wall.Mount) bool { return under(m.Path, dir) }) {
		return nil
	}
	return fmt.Errorf("the working directory inside, %s, lies in none of the places the "+
		"enclosure binds: %v", pathShown(dir), eachShown(paths(mounts)))
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
		Names: pathsShown(in.path, out.path),
		Detail: fmt.Sprintf("%s %s (%s) %s %s %s (%s): %s", in.what, pathShown(in.path),
			mode(in.writable), how, out.what, pathShown(out.path), mode(out.writable), why),
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
			eachShown(paths(start.Mounts)), eachShown(paths(now.Mounts)))
	}
	for i, s := range start.sources {
		n := now.sources[i]
		if s.Resolved != n.Resolved {
			return fmt.Errorf("%s resolved to %s when the run started and resolves to %s now",
				s.what, pathShown(s.Resolved), pathShown(n.Resolved))
		}
		// A name that did not exist at the start, the run directory's own among them, is
		// looked up further now: the start's lookups are the first of now's, and a link
		// made since leads elsewhere, which Resolved shows.
		if len(n.Lookups) < len(s.Lookups) ||
			!slices.Equal(s.Lookups, n.Lookups[:len(s.Lookups)]) {
			return fmt.Errorf("the way to %s changed since the run started: its names were "+
				"looked up as %s, and are now looked up as %s", s.what,
				strings.Join(eachShown(s.Lookups), ", "), strings.Join(eachShown(n.Lookups), ", "))
		}
	}
	if start.Dir != now.Dir {
		return fmt.Errorf("the working directory inside was %s when the run started and is "+
			"%s now", pathShown(start.Dir), pathShown(now.Dir))
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

// pathShown is a path as a message prints it, bare: [accesskey.ShownValue]'s phrase in
// its place when it contains qak_ or qrk_ in any case.
func pathShown(p string) string { return accesskey.ShownValue(p, false) }

// pathsShown are paths as a refusal's Names lists them: as [accesskey.ShownNames] lists
// them, a name's phrase in place of a path that contains qak_ or qrk_ in any case, as
// run.refused's names are, each phrase once.
func pathsShown(ps ...string) []string { return accesskey.ShownNames(ps) }

// eachShown is each of the paths as [pathShown] prints it, in order, every one kept:
// for a message that lists them side by side.
func eachShown(ps []string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = pathShown(p)
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
		return nil, accesskey.ShownError(err)
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
		return nil, accesskey.ShownError(err)
	}
	return bindSources(binds)
}

// bindSources are a wall's own binds as bind sources.
func bindSources(binds []wall.Bind) ([]bindSource, error) {
	var out []bindSource
	for _, m := range binds {
		what, kind := "Forager's directory "+pathShown(m.Path), kindDir
		if m.Helper {
			what, kind = "Forager's helper "+pathShown(m.Path), kindHelper
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
