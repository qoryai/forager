package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/wall"
)

// The registry of walled runs is a private directory of Forager's, per user: a file
// for every walled run still going on this machine, named by its run id, which its
// session holds locked for the run's whole life and removes when the run ends. A file
// whose lock is free is a run whose session is gone, however it ended; the run is still
// going while a container labelled with its id exists, which an agent killed with its
// session can be.

// walledLock is the file in the registry a session holds locked while it reads the
// entries, checks its own binds against them and writes its own, so that two runs that
// start together are checked one after the other.
const walledLock = "lock"

// walledDir is the registry's directory, absolute: $XDG_STATE_HOME/qory-forager/walled
// when XDG_STATE_HOME is absolute, else ~/.local/state/qory-forager/walled, a relative
// HOME taken from the working directory. A test points it elsewhere.
var walledDir = func() (string, error) {
	if state := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(state) {
		return filepath.Join(state, "qory-forager", "walled"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Abs(filepath.Join(home, ".local", "state", "qory-forager", "walled"))
}

// runContainersExist reports whether the engine holds a container labelled with the
// run's id, in any state, asked through d, the Docker of the run that asks, or as
// [wall.RunContainersExist] asks when d is nil. A test points it elsewhere.
var runContainersExist = askContainers

// askContainers is what runContainersExist is, but in a test.
func askContainers(
	ctx context.Context, d *wall.Docker, e wall.Engine, runID string,
) (bool, error) {
	if d == nil {
		return wall.RunContainersExist(ctx, e, runID)
	}
	return d.RunContainersExist(ctx, e, runID)
}

// registerPause, when not nil, is called between a run's check and the writing of its
// entry, under the registry's lock: a test holds a run there.
var registerPause func(runID string)

// walledEntry is what a walled run's file in the registry holds.
type walledEntry struct {
	RunID string       `json:"run_id"`
	PID   int          `json:"pid"`
	Binds []bindSource `json:"binds"`
	// Engine is the container engine the run's enclosure is in, as its wall reaches
	// it, for another session to ask once the run's session is gone; nil for a wall
	// without one.
	Engine *wall.Engine `json:"engine,omitempty"`
}

// openRegistry makes the registry's directory when it does not exist, 0700, and refuses
// one that is not a directory of this user's that only this user writes.
func openRegistry() (string, error) {
	dir, err := walledDir()
	if err != nil {
		return "", fmt.Errorf("the registry of walled runs: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("the registry of walled runs: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("the registry of walled runs: %w", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.IsDir():
		return "", fmt.Errorf("the registry of walled runs %s is not a directory", dir)
	case !ok || int(st.Uid) != os.Getuid():
		return "", fmt.Errorf("the registry of walled runs %s is not this user's", dir)
	case info.Mode().Perm()&0o022 != 0:
		return "", fmt.Errorf("the registry of walled runs %s is writable by others than "+
			"its owner", dir)
	}
	return dir, nil
}

// registration is a walled run's entry in the registry, held for as long as the run
// goes.
type registration struct {
	dir, runID string
	engine     *wall.Engine
	// docker is the run's wall when it is a Docker, which asks the engine of another
	// run's entry; nil otherwise.
	docker *wall.Docker
	f      *os.File
	// kept says the entry stays when the run ends.
	kept bool
	// release removes the entry, unless it is kept, and frees its lock; it is safe to
	// call more than once.
	release func()
}

// keep leaves the entry in the registry when the run ends, its lock free: for a run
// whose containers may outlive it, which another session then asks the engine about.
func (r *registration) keep() { r.kept = true }

// register checks a walled run's binds against every other walled run of this user's
// still going and, when none conflicts, lists the run among them, all under the
// registry's lock. engine is the container engine of the run's wall, nil for a wall
// without one, and docker the run's wall when it is a Docker, nil otherwise.
func register(
	runID string, binds []bindSource, engine *wall.Engine, docker *wall.Docker,
) (*registration, error) {
	dir, err := openRegistry()
	if err != nil {
		return nil, err
	}
	unlock, err := lockRegistry(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := checkShared(docker, dir, runID, binds); err != nil {
		return nil, err
	}
	if registerPause != nil {
		registerPause(runID)
	}
	file := filepath.Join(dir, runID)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("the registry of walled runs: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		os.Remove(file)
		return nil, fmt.Errorf("the registry of walled runs: locking %s: %w", file, err)
	}
	r := &registration{dir: dir, runID: runID, engine: engine, docker: docker, f: f}
	// The file goes before its lock, so no session takes the lock of a file that is
	// still there for a run that is over and finds a run that is not.
	r.release = sync.OnceFunc(func() {
		if !r.kept {
			os.Remove(file)
		}
		f.Close()
	})
	if err := r.write(binds); err != nil {
		r.release()
		return nil, err
	}
	return r, nil
}

// write puts the run's binds in its entry. The caller holds the registry's lock.
func (r *registration) write(binds []bindSource) error {
	b, err := json.Marshal(walledEntry{RunID: r.runID, PID: os.Getpid(), Binds: binds,
		Engine: r.engine})
	if err != nil {
		return err
	}
	if err := r.f.Truncate(0); err != nil {
		return fmt.Errorf("the registry of walled runs: %w", err)
	}
	if _, err := r.f.WriteAt(b, 0); err != nil {
		return fmt.Errorf("the registry of walled runs: %w", err)
	}
	return nil
}

// askID asks the run's engine for its id again, when it gave none as the run started,
// now that the enclosure is prepared on it, and records the answer in the entry at its
// next write. With no answer, the entry stays as it was.
func (r *registration) askID(ctx context.Context, w wall.Wall) {
	e, ok := w.(wall.Engined)
	if !ok || r.engine == nil || r.engine.ID != "" {
		return
	}
	if id, err := e.EngineID(ctx); err == nil && id != "" {
		r.engine.ID = id
	}
}

// update checks a walled run's binds against every other walled run of this user's
// still going again, its own entry left out, and puts them in its entry, under the
// registry's lock.
func (r *registration) update(binds []bindSource) error {
	unlock, err := lockRegistry(r.dir)
	if err != nil {
		return err
	}
	defer unlock()
	if err := checkShared(r.docker, r.dir, r.runID, binds); err != nil {
		return err
	}
	return r.write(binds)
}

// lockRegistry takes the registry's lock, waiting for a session that holds it.
func lockRegistry(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, walledLock), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("the registry of walled runs: %w", err)
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("the registry of walled runs: locking: %w", err)
	}
	return func() { f.Close() }, nil
}

// checkShared refuses binds of this run's that a walled agent of another run still
// going can change, that hold one of that run's binds this run's agent could change, or
// that share that run's run directory. The caller holds the registry's lock. An entry
// whose lock is free is a run that is over: it is removed. docker, the run's wall when
// it is a Docker, asks the engine of an entry whose lock is free; nil asks as
// [wall.RunContainersExist] does.
func checkShared(docker *wall.Docker, dir, runID string, binds []bindSource) error {
	return goingEntries(context.Background(), docker, dir, runID,
		func(_ string, other walledEntry) error {
			for _, b := range other.Binds {
				ob, err := resolveOther(other.RunID, b)
				if err != nil {
					return err
				}
				for _, own := range binds {
					if err := shared(own, other.RunID, ob); err != nil {
						return err
					}
				}
			}
			return nil
		})
}

// goingEntries calls each with the file and the entry of every walled run in the
// registry dir still going, runID's left out, by [readEntry], in the order of their
// names, and returns the first error, of an entry or of each. The caller holds the
// registry's lock. An entry whose lock is free is a run that is over: it is removed.
// docker asks the engine of an entry whose lock is free, as [readEntry] says.
func goingEntries(
	ctx context.Context, docker *wall.Docker, dir, runID string,
	each func(file string, entry walledEntry) error,
) error {
	names, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("the registry of walled runs: %w", err)
	}
	for _, e := range names {
		name := e.Name()
		if name == runID || CheckRunID(name) != nil {
			continue
		}
		file := filepath.Join(dir, name)
		entry, live, err := readEntry(ctx, docker, file)
		if err != nil {
			return err
		}
		if !live {
			continue
		}
		if err := each(file, entry); err != nil {
			return err
		}
	}
	return nil
}

// WalledRun is a walled run of this user's still going on this machine, as the
// registry of walled runs lists it.
type WalledRun struct {
	// RunID is the run's id.
	RunID string
	// Entry is the path of the run's entry in the registry, absolute.
	Entry string
}

// RunsBinding returns the walled runs of this user's still going on this machine
// that bind a path overlapping p, an absolute path, each once, in the order of their
// entries' names. A bind overlaps p when it is p, holds p or lies inside p: a run that
// binds p, a directory p lies inside, or only a path inside p, such as p/.git, is
// returned. The paths are compared as written and as resolved through symbolic links,
// so that a link on neither side hides an overlap: p as passed and resolved now,
// against a bind's path as the run passed it, which its engine binds again when its
// container starts again, as written and resolved now, and against the path the bind
// resolved to when the run listed it, resolved again now. The run directory is
// compared by the path it resolved to alone, since its entry records the runs
// directory that holds it as its path. Names are compared whole, regardless of case,
// as [Overlap] compares them: /a/bc does not overlap /a/b.
//
// A run is still going while its session holds its entry's lock, or else while the
// container engine its entry records holds a container labelled with its run id, in
// any state, a stopped one included; an entry with neither is removed, as a run that
// starts removes it. When the engine cannot be asked, or an entry whose lock is free
// cannot be read or records no engine, the error is a *[Refusal] with the code
// engine_unreachable, whose Names are the run's id and the path of its entry; an entry
// whose lock is held and that cannot be read is a plain error. The registry's lock is
// held for the whole read; a registry that does not exist holds no run, and is not
// made. A relative p, or one that cannot be resolved, is an error.
//
// d is the Docker of the caller that asks, through which the engine of an entry whose
// lock is free is asked, by [wall.Docker.RunContainersExist]; nil asks as
// [wall.RunContainersExist] does.
func RunsBinding(ctx context.Context, d *wall.Docker, p string) ([]WalledRun, error) {
	if !filepath.IsAbs(p) {
		return nil, fmt.Errorf("the path %q is not absolute", p)
	}
	at, err := split(p, 0)
	if err != nil {
		return nil, err
	}
	place := []splitPath{written(p), at}
	dir, err := walledDir()
	if err != nil {
		return nil, fmt.Errorf("the registry of walled runs: %w", err)
	}
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if dir, err = openRegistry(); err != nil {
		return nil, err
	}
	unlock, err := lockRegistry(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	var out []WalledRun
	err = goingEntries(ctx, d, dir, "", func(file string, entry walledEntry) error {
		for _, b := range entry.Binds {
			forms, err := bindForms(entry.RunID, b)
			if err != nil {
				return err
			}
			if overlaps(place, forms) {
				out = append(out, WalledRun{RunID: entry.RunID, Entry: file})
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// bindForms are the forms of a bind of another run's [RunsBinding] compares: the path
// it resolved to, resolved again now, and, but for the run directory, the path the
// run passed, as written and resolved now. A failure to resolve one is the error of
// [resolveOther].
func bindForms(runID string, b bindSource) ([]splitPath, error) {
	at, err := resolveOtherPath(runID, b.Resolved)
	if err != nil {
		return nil, err
	}
	forms := []splitPath{at}
	if b.Kind == kindRun || !filepath.IsAbs(b.Path) {
		return forms, nil
	}
	now, err := resolveOtherPath(runID, b.Path)
	if err != nil {
		return nil, err
	}
	return append(forms, written(b.Path), now), nil
}

// overlaps reports whether a form of a place and a form of a bind overlap: one is the
// other, or lies inside it. It is the one rule of [RunsBinding].
func overlaps(place, bind []splitPath) bool {
	for _, p := range place {
		for _, b := range bind {
			if ok, _ := holds(b, p); ok {
				return true
			}
			if ok, _ := holds(p, b); ok {
				return true
			}
		}
	}
	return false
}

// written is p as written, absolute: its names alone, none of them resolved, so that
// [holds] compares it name by name with another path, written or resolved.
func written(p string) splitPath {
	return splitPath{exists: string(filepath.Separator), tail: parts(filepath.Clean(p))}
}

// resolveOther is a bind of another run's as the filesystem has it now: its resolved
// path and the directories its names are looked up in. A bind, or a directory on the
// way to it, that is gone resolves as far as it exists, with the missing names below,
// like a part that does not exist yet, and is compared by them. Any failure to resolve
// one is an error, a race with a link that changes included, since a bind this run
// cannot see may be one it shares.
func resolveOther(runID string, b bindSource) (bindSource, error) {
	at, err := resolveOtherPath(runID, b.Resolved)
	if err != nil {
		return bindSource{}, err
	}
	b.at = at
	for _, entry := range b.Lookups {
		dir := filepath.Dir(entry)
		dirAt, err := resolveOtherPath(runID, dir)
		if err != nil {
			return bindSource{}, err
		}
		b.looks = append(b.looks,
			lookup{dir: dir, rest: []string{filepath.Base(entry)}, at: dirAt})
	}
	return b, nil
}

// resolveOtherPath is a path of another run's bind as the filesystem has it now, for
// [resolveOther].
func resolveOtherPath(runID, p string) (splitPath, error) {
	at, err := split(p, 0)
	if err != nil {
		return splitPath{}, fmt.Errorf("the registry of walled runs: cannot "+
			"resolve %s of the walled run %s, which is still going: %w", p, runID, err)
	}
	return at, nil
}

// readEntry reads one entry of the registry. An entry whose lock is held is live. One
// whose lock is free is a run whose session is gone: it is live while the engine its
// entry records holds a container labelled with its run id, and is removed when the
// engine holds none. A run that cannot ask, for an entry that cannot be read, records
// no engine or an engine that fails, does not start. One whose file is gone already is
// not live. docker, the asking run's wall when it is a Docker, asks the engine; nil
// asks as [wall.RunContainersExist] does.
func readEntry(
	ctx context.Context, docker *wall.Docker, file string,
) (walledEntry, bool, error) {
	f, err := os.Open(file)
	if errors.Is(err, fs.ErrNotExist) {
		return walledEntry{}, false, nil
	}
	if err != nil {
		return walledEntry{}, false, fmt.Errorf("the registry of walled runs: %w", err)
	}
	defer f.Close()
	held := false
	switch err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); {
	case errors.Is(err, syscall.EWOULDBLOCK):
		held = true
	case err != nil:
		return walledEntry{}, false,
			fmt.Errorf("the registry of walled runs: locking %s: %w", file, err)
	}
	runID := filepath.Base(file)
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	var entry walledEntry
	if err == nil {
		err = json.Unmarshal(b, &entry)
	}
	if err == nil && entry.RunID != runID {
		err = errors.New("it names another run")
	}
	if held {
		if err != nil {
			return walledEntry{}, false, fmt.Errorf("the registry of walled runs: the "+
				"entry %s of a run still going cannot be read", file)
		}
		return entry, true, nil
	}
	if err != nil {
		return walledEntry{}, false, engineUnreachable(runID, file,
			fmt.Errorf("its entry %s cannot be read: %w", file, err))
	}
	if entry.Engine == nil {
		return walledEntry{}, false, engineUnreachable(runID, file,
			fmt.Errorf("its entry %s records no engine", file))
	}
	exists, err := runContainersExist(ctx, docker, *entry.Engine, runID)
	switch {
	case err != nil:
		return walledEntry{}, false, engineUnreachable(runID, file, err)
	case exists:
		return entry, true, nil
	}
	os.Remove(file)
	return walledEntry{}, false, nil
}

// othersWritable are the writable binds of the other walled runs of this user's in the
// registry, each by its path as resolved when that run listed it: the places their
// agents can write. An entry whose lock is free counts too, since its run's containers
// may still be going; one of those that cannot be read is skipped, and one of a run
// still going that cannot be read is an error. A registry that does not exist holds
// none, and is not made.
func othersWritable(runID string) ([]string, error) {
	dir, err := walledDir()
	if err != nil {
		return nil, fmt.Errorf("the registry of walled runs: %w", err)
	}
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if dir, err = openRegistry(); err != nil {
		return nil, err
	}
	unlock, err := lockRegistry(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	names, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("the registry of walled runs: %w", err)
	}
	var out []string
	for _, e := range names {
		name := e.Name()
		if name == runID || CheckRunID(name) != nil {
			continue
		}
		entry, ok, err := writtenEntry(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		for _, b := range entry.Binds {
			if b.Writable {
				out = append(out, b.Resolved)
			}
		}
	}
	return out, nil
}

// writtenEntry reads one entry of the registry for [othersWritable], and whether it
// counts: one that is gone, or whose lock is free and that cannot be read, does not.
func writtenEntry(file string) (walledEntry, bool, error) {
	f, err := os.Open(file)
	if errors.Is(err, fs.ErrNotExist) {
		return walledEntry{}, false, nil
	}
	if err != nil {
		return walledEntry{}, false, fmt.Errorf("the registry of walled runs: %w", err)
	}
	defer f.Close()
	held := false
	switch err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); {
	case errors.Is(err, syscall.EWOULDBLOCK):
		held = true
	case err != nil:
		return walledEntry{}, false,
			fmt.Errorf("the registry of walled runs: locking %s: %w", file, err)
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	var entry walledEntry
	if err == nil {
		err = json.Unmarshal(b, &entry)
	}
	if err == nil && entry.RunID != filepath.Base(file) {
		err = errors.New("it names another run")
	}
	switch {
	case err != nil && held:
		return walledEntry{}, false, fmt.Errorf("the registry of walled runs: the "+
			"entry %s of a run still going cannot be read", file)
	case err != nil:
		return walledEntry{}, false, nil
	}
	return entry, true, nil
}

// engineUnreachable is the refusal of a run that cannot ask the container engine
// whether an earlier walled run, whose session is gone, still has containers: nothing is
// bound while one may. Its names are the earlier run's id and file, the path of its
// entry, which the registry's directory makes absolute, so the entry can be found and
// looked at.
func engineUnreachable(runID, file string, err error) *Refusal {
	return &Refusal{
		Code:  refusal.EngineUnreachable,
		Names: []string{runID, file},
		Detail: fmt.Sprintf("Docker could not be asked whether the walled run %s is still "+
			"going, so the run does not start: %v", runID, err),
	}
}

// wallKind reports whether a bind is one a wall binds of its own: Forager's helper
// or another directory of Forager's.
func wallKind(b bindSource) bool { return b.Kind == kindHelper || b.Kind == kindDir }

// inside reports whether a bind lies inside dir, or is dir when orIs is set, by its
// resolved path, or whether a name on the way to it is looked up in dir or below it,
// and then the entry it is looked up as.
func inside(b bindSource, dir splitPath, orIs bool) (string, bool) {
	if ok, same := holds(dir, b.at); ok && (orIs || !same) {
		return "", true
	}
	if l, ok := lookedUpIn(dir, b.looks); ok {
		return l.entry(), true
	}
	return "", false
}

// shared is the error of one bind of this run's against one bind of another run's
// still going, or nil when they do not conflict.
//
//   - A wall's own bind, Forager's helper or a directory of Forager's, that is or
//     lies inside a writable bind of the other run's, or is reached through one, is a
//     plain error; one of the other run's that a writable bind of this run's is, holds
//     or reaches is refused, and so is a bind of this run's that is, lies inside or is
//     reached through a writable one of the other run's. Patterns of the directories
//     sessions make are each session's own, and never conflict with each other.
//   - A run directory is its session's alone: a bind that is, holds or lies inside the
//     other run's, or that the other run's is, holds or lies inside, whatever their
//     modes, is refused.
//   - Otherwise this run's bind is refused when it lies inside the other's, strictly,
//     and the other is writable, or when it is writable and holds the other's,
//     strictly, or when a name on the way to either is looked up inside the writable
//     one. Two binds of the same root never conflict: each root is looked up in its
//     parent, and an agent cannot replace its own bind's root.
func shared(own bindSource, otherID string, other bindSource) error {
	refuse := func(detail string, a ...any) error {
		return &Refusal{
			Code:   refusal.MountSharedWithRun,
			Names:  []string{own.Path, otherID, other.Path},
			Detail: fmt.Sprintf(detail, a...),
		}
	}
	still := " of the walled run " + otherID + ", which is still going: "
	switch {
	case wallKind(own) && wallKind(other) && (own.Pattern || other.Pattern):
		// Each session makes its private directories its own; the pattern stands for
		// those it has not made yet, not for another session's.
		return nil
	case wallKind(own):
		if _, ok := inside(own, other.at, true); ok && other.Writable {
			return fmt.Errorf("%s lies inside the writable bind %s%sa walled agent of that run "+
				"can change it", own.what, other.Path, still)
		}
		return nil
	case wallKind(other):
		what := "Forager's directory "
		if other.Kind == kindHelper {
			what = "Forager's helper "
		}
		if entry, ok := inside(other, own.at, true); ok && own.Writable {
			if entry != "" {
				return refuse("%s (writable) contains %s, on the way to %s%s%sthis run's "+
					"agent could change it", own.what, entry, what, other.Path, still)
			}
			return refuse("%s (writable) contains %s%s%sthis run's agent could change it",
				own.what, what, other.Path, still)
		}
		if entry, ok := inside(own, other.at, true); ok && other.Writable {
			how := "lies inside"
			if entry != "" {
				how = "is reached through " + entry + ", which lies inside"
			}
			return refuse("%s (%s) %s %s%s%sa walled agent of that run can change it",
				own.what, mode(own.Writable), how, what, other.Path, still)
		}
		return nil
	}
	if own.Kind == kindRun || other.Kind == kindRun {
		how := ""
		if ok, same := holds(other.at, own.at); ok && same {
			how = "is"
		} else if ok {
			how = "lies inside"
		} else if ok, _ := holds(own.at, other.at); ok {
			how = "contains"
		}
		if how != "" {
			theirs := "the " + mode(other.Writable) + " bind " + other.Path
			if other.Kind == kindRun {
				theirs = "the run directory " + other.Resolved
			}
			return refuse("%s (%s) %s %s%sa run directory is its session's alone",
				own.what, mode(own.Writable), how, theirs, still)
		}
	}
	if other.Writable {
		if entry, ok := inside(own, other.at, false); ok {
			how := "lies inside"
			if entry != "" {
				how = "is reached through " + entry + ", which lies inside"
			}
			return refuse("%s (%s) %s the writable bind %s%sa walled agent of that run can "+
				"change it", own.what, mode(own.Writable), how, other.Path, still)
		}
	}
	if own.Writable {
		if entry, ok := inside(other, own.at, false); ok {
			what := "the " + mode(other.Writable) + " bind " + other.Path
			if entry != "" {
				what = entry + ", on the way to " + what
			}
			return refuse("%s (writable) contains %s%sthis run's agent could change it",
				own.what, what, still)
		}
	}
	return nil
}
