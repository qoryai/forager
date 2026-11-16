package session

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/wall"
)

var (
	// versionShape is a RuntimeInstall.Version the session accepts: it starts with a
	// letter or a digit, so - and .. are none.
	versionShape = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$`)
	// runtimeNameShape is a runtime's name the session binds a folder for: the
	// descriptor schema's pattern of runtime.
	runtimeNameShape = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
)

// installed is a RuntimeInstall the session checked: Dir as the caller gave it,
// resolved, the folder it leads to, and inside, where an enclosure sees it.
type installed struct {
	dir, resolved, inside, version string
}

// pairs are the folder, as given and as resolved, each with the path the enclosure
// sees it at, for one pass of [replacePaths].
func (i *installed) pairs() []pathPair {
	out := []pathPair{{i.dir, i.inside}}
	if i.resolved != i.dir {
		out = append(out, pathPair{i.resolved, i.inside})
	}
	return out
}

// qoryDir is the folder an enclosure has Forager's helper and the runtimes' folders
// in: /qory.
var qoryDir = path.Dir(wall.HelperPath)

// checkInstall checks a session's RuntimeInstall against its runtime and its program,
// as [RuntimeInstall] says, and returns it checked; nil for a session with no
// runtime, and for one with no RuntimeInstall whose runtime does not require one. rt
// is the runtime the caller set, nil for none; walled says the run has a wall.
func checkInstall(spec SessionSpec, rt runtimes.Runtime, walled bool) (*installed, error) {
	in := spec.RuntimeInstall
	if rt == nil {
		if in != nil {
			return nil, errors.New("leave SessionSpec.RuntimeInstall unset for a session with no runtime: only a runtime's session starts an installed program")
		}
		return nil, nil
	}
	name := rt.Name()
	if in == nil {
		// A runtime whose descriptor has no install_required, such as Codex, starts as
		// the caller names it, from the image or this machine's PATH, with no folder
		// bound.
		if r, ok := rt.(runtimes.InstallRequired); !ok || !r.InstallRequired() {
			return nil, nil
		}
		return nil, fmt.Errorf("set SessionSpec.RuntimeInstall for a session of the runtime %s: the session starts a runtime only from the folder it was installed in", accesskey.ShownName(name, false))
	}
	if !runtimeNameShape.MatchString(name) {
		return nil, fmt.Errorf("name the runtime with a lowercase letter and up to 63 lowercase letters, digits or -: %s is the name of the folder it is seen at behind a wall", accesskey.ShownName(name, true))
	}
	if !versionShape.MatchString(in.Version) {
		return nil, fmt.Errorf("set SessionSpec.RuntimeInstall.Version to the installed version, 1 to 64 letters, digits, ., + or -, the first a letter or a digit: %s is not one", accesskey.ShownValue(in.Version, true))
	}
	dir := in.Dir
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || strings.ContainsRune(dir, 0) {
		return nil, fmt.Errorf("set SessionSpec.RuntimeInstall.Dir to an absolute, clean path: %s is not one", accesskey.ShownValue(dir, true))
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("install the runtime in %s, or set SessionSpec.RuntimeInstall.Dir to its folder: %w", accesskey.ShownValue(dir, true), accesskey.ShownError(err))
	}
	// Behind a wall the enclosure sees the folder at /qory/runtime/<runtime>, beside
	// Forager's helper at /qory/qory: a folder at or around /qory here would make one
	// path stand for two.
	if walled {
		for _, p := range []string{dir, resolved} {
			if under(p, qoryDir) || under(qoryDir, p) {
				return nil, fmt.Errorf("install the runtime in a folder outside %s and set SessionSpec.RuntimeInstall.Dir to it: behind a wall the enclosure has Forager's helper and the runtimes' folders in %s, so %s would be seen at two paths", qoryDir, qoryDir, accesskey.ShownValue(p, true))
			}
		}
	}
	if err := enterable(resolved, dir); err != nil {
		return nil, err
	}
	program, field := spec.Command, "SessionSpec.Command"
	if walled && spec.Command == wall.HelperPath {
		// Behind a wall the caller may start the runtime through Forager's helper:
		// the program is the argument after the first --.
		i := slices.Index(spec.Args, "--")
		if i < 0 || i+1 == len(spec.Args) {
			return nil, fmt.Errorf("put the runtime's program inside SessionSpec.RuntimeInstall.Dir %s after -- in SessionSpec.Args: the session starts %s only in front of it", accesskey.ShownValue(dir, true), wall.HelperPath)
		}
		program, field = spec.Args[i+1], "the argument after -- in SessionSpec.Args"
	}
	command := filepath.Clean(program)
	rel, err := filepath.Rel(dir, command)
	if !filepath.IsAbs(program) || err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("set %s to a program inside SessionSpec.RuntimeInstall.Dir %s: %s is not inside it", field, accesskey.ShownValue(dir, true), accesskey.ShownValue(program, true))
	}
	// The session checks the names of the clean path, and the program starts by the
	// path as given: a .. after a link would lead the two apart.
	if command != program {
		return nil, fmt.Errorf("set %s to a clean path, with no . or .. name and no repeated or trailing /: %s is not one", field, accesskey.ShownValue(program, true))
	}
	// Each name below the folder is the file it is: a link there could lead,
	// inside an enclosure, to a file of the image's at the path it names.
	at := resolved
	names := strings.Split(rel, string(filepath.Separator))
	for i, n := range names {
		at = filepath.Join(at, n)
		shown := filepath.Join(dir, filepath.Join(names[:i+1]...))
		info, err := os.Lstat(at)
		if err != nil {
			return nil, fmt.Errorf("install the runtime's program at %s, or set %s to it: %w", accesskey.ShownValue(program, true), field, accesskey.ShownError(err))
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("replace the symbolic link %s with the file or folder it leads to: the session starts no runtime through a link inside SessionSpec.RuntimeInstall.Dir", accesskey.ShownValue(shown, true))
		}
		if i < len(names)-1 {
			if err := enterable(at, shown); err != nil {
				return nil, err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("set %s to the runtime's program, a regular file: %s is not one", field, accesskey.ShownValue(program, true))
		}
		if info.Mode().Perm()&0o005 != 0o005 {
			return nil, fmt.Errorf("let others read and execute %s (chmod o+rx): behind a wall the runtime runs as a user that may not own it", accesskey.ShownValue(program, true))
		}
		if err := unchangeable(info, program); err != nil {
			return nil, err
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || uint64(st.Nlink) != 1 {
			return nil, fmt.Errorf("copy %s to a file with no other hard link: a second name of the file, outside SessionSpec.RuntimeInstall.Dir, can change the program", accesskey.ShownValue(program, true))
		}
	}
	return &installed{dir: dir, resolved: resolved, inside: path.Join(wall.RuntimeDir, name), version: in.Version}, nil
}

// enterable checks that the folder at p, shown as shown, is a folder others can read
// and enter, and that only its owner, root or this process's user, can change.
func enterable(p, shown string) error {
	info, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("install the runtime in %s, or set SessionSpec.RuntimeInstall.Dir to its folder: %w", accesskey.ShownValue(shown, true), accesskey.ShownError(err))
	}
	if !info.IsDir() {
		return fmt.Errorf("set SessionSpec.RuntimeInstall.Dir to the runtime's folder: %s is not a folder", accesskey.ShownValue(shown, true))
	}
	if info.Mode().Perm()&0o005 != 0o005 {
		return fmt.Errorf("let others read and enter %s (chmod o+rx): behind a wall the runtime runs as a user that may not own it", accesskey.ShownValue(shown, true))
	}
	return unchangeable(info, shown)
}

// unchangeable checks that the file of info, shown as shown, is owned by root or by
// this process's user, and that neither its group nor others may write it. The
// folders above SessionSpec.RuntimeInstall.Dir are not checked: the caller keeps
// them as unchangeable.
func unchangeable(info fs.FileInfo, shown string) error {
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("remove the group's and others' write permission from %s (chmod go-w): another user could change the runtime", accesskey.ShownValue(shown, true))
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && int(st.Uid) != os.Getuid()) {
		return fmt.Errorf("make root or the user that runs Forager the owner of %s (chown): another user could change the runtime", accesskey.ShownValue(shown, true))
	}
	return nil
}

// runtimeFolder is the installed runtime's folder as a walled launch binds it: the
// folder Dir leads to, at /qory/runtime/<runtime>; the zero value for a session with
// no runtime.
func runtimeFolder(spec runSpec, rt runtimes.Runtime) wall.RuntimeFolder {
	if spec.install == nil {
		return wall.RuntimeFolder{}
	}
	return wall.RuntimeFolder{Path: spec.install.resolved, Name: rt.Name()}
}
