package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/qoryai/runner/internal/refusal"
)

// The registry of walled runs is a private directory of the runner's, per user: a file
// for every walled run still going on this machine, named by its run id, which its
// runner holds locked for the run's whole life and removes when the run ends. A file
// whose lock is free is a run that is over, however its runner ended.

// walledLock is the file in the registry a runner holds locked while it reads the
// entries, checks its own binds against them and writes its own, so that two runs that
// start together are checked one after the other.
const walledLock = "lock"

// walledDir is the registry's directory: $XDG_STATE_HOME/qory-runner/walled, else
// ~/.local/state/qory-runner/walled. A test points it elsewhere.
var walledDir = func() (string, error) {
	if state := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(state) {
		return filepath.Join(state, "qory-runner", "walled"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "qory-runner", "walled"), nil
}

// walledEntry is what a walled run's file in the registry holds.
type walledEntry struct {
	RunID string       `json:"run_id"`
	PID   int          `json:"pid"`
	Binds []bindSource `json:"binds"`
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

// register checks a walled run's binds against every other walled run of this user's
// still going and, when none conflicts, lists the run among them, all under the
// registry's lock. The returned function removes the run's entry; it is safe to call
// more than once.
func register(runID string, binds []bindSource) (func(), error) {
	dir, err := openRegistry()
	if err != nil {
		return nil, err
	}
	unlock, err := lockRegistry(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := checkShared(dir, runID, binds); err != nil {
		return nil, err
	}
	b, err := json.Marshal(walledEntry{RunID: runID, PID: os.Getpid(), Binds: binds})
	if err != nil {
		return nil, err
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
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(file)
		return nil, fmt.Errorf("the registry of walled runs: %w", err)
	}
	// The file goes before its lock, so no runner takes the lock of a file that is
	// still there for a run that is over and finds a run that is not.
	return sync.OnceFunc(func() {
		os.Remove(file)
		f.Close()
	}), nil
}

// recheck checks a walled run's binds against every other walled run of this user's
// still going again, its own entry left out, under the registry's lock.
func recheck(runID string, binds []bindSource) error {
	dir, err := openRegistry()
	if err != nil {
		return err
	}
	unlock, err := lockRegistry(dir)
	if err != nil {
		return err
	}
	defer unlock()
	return checkShared(dir, runID, binds)
}

// lockRegistry takes the registry's lock, waiting for a runner that holds it.
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

// checkShared refuses binds of this run's that a walled agent of another run still going
// can change, or that hold one of that run's binds this run's agent could change. The
// caller holds the registry's lock. An entry whose lock is free is a run that is over:
// it is removed.
func checkShared(dir, runID string, binds []bindSource) error {
	names, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("the registry of walled runs: %w", err)
	}
	for _, e := range names {
		name := e.Name()
		if name == runID || CheckRunID(name) != nil {
			continue
		}
		other, live, err := readEntry(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if !live {
			continue
		}
		for _, b := range other.Binds {
			at, err := split(b.Resolved, 0)
			if err != nil {
				// A bind of another run's that no longer resolves is nothing a path of
				// this run's can lie in or hold.
				continue
			}
			for _, own := range binds {
				if r := shared(own, other.RunID, b, at); r != nil {
					return r
				}
			}
		}
	}
	return nil
}

// readEntry reads one entry of the registry. An entry whose lock is free is removed,
// and live is false; one whose file is gone already is not live either.
func readEntry(file string) (walledEntry, bool, error) {
	f, err := os.Open(file)
	if errors.Is(err, fs.ErrNotExist) {
		return walledEntry{}, false, nil
	}
	if err != nil {
		return walledEntry{}, false, fmt.Errorf("the registry of walled runs: %w", err)
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
	if err == nil {
		os.Remove(file)
		return walledEntry{}, false, nil
	}
	if !errors.Is(err, syscall.EWOULDBLOCK) {
		return walledEntry{}, false,
			fmt.Errorf("the registry of walled runs: locking %s: %w", file, err)
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return walledEntry{}, false, fmt.Errorf("the registry of walled runs: %w", err)
	}
	var entry walledEntry
	if err := json.Unmarshal(b, &entry); err != nil || entry.RunID != filepath.Base(file) {
		return walledEntry{}, false, fmt.Errorf("the registry of walled runs: the entry %s "+
			"of a run still going cannot be read", file)
	}
	return entry, true, nil
}

// shared is the refusal of one bind of this run's against one bind of another run's
// still going, or nil when they do not conflict: this run's lies inside the other's,
// strictly, and the other is writable, or this run's is writable and holds the other's,
// strictly. Two binds of the same root never conflict: an agent cannot replace its own
// bind's root.
func shared(own bindSource, otherID string, other bindSource, at splitPath) *Refusal {
	how, whose := "", "a walled agent of that run can change it"
	if ok, same := holds(at, own.at); ok && !same && other.Writable {
		how = "lies inside"
	} else if ok, same := holds(own.at, at); ok && !same && own.Writable {
		how, whose = "contains", "this run's agent could change it"
	}
	if how == "" {
		return nil
	}
	return &Refusal{
		Code:  refusal.MountSharedWithRun,
		Names: []string{own.Path, otherID, other.Path},
		Detail: fmt.Sprintf(
			"%s (%s) %s the %s bind %s of the walled run %s, which is still going: %s",
			own.what, mode(own.Writable), how, mode(other.Writable), other.Path, otherID, whose),
	}
}
