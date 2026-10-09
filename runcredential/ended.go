package runcredential

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

// EndedFile is the name of the file, in the gateway's state directory, that holds the
// ended run keys.
const EndedFile = "ended-run-keys.json"

// Ended is the set of run keys a gateway refuses, by issuer, those whose run the issuer
// ended, kept in a file of the gateway's state directory so a restart refuses them too.
// Each is kept until its run credential's exp plus [MaxLeeway], the latest a run
// credential of that exp is accepted under any issuer's leeway, and dropped after. It is safe for
// concurrent use; one gateway alone uses a state directory.
type Ended struct {
	path  string
	clock func() time.Time

	mu      sync.Mutex
	entries map[endedKey]time.Time
	// written are the entries as the file last held them: read at open, and each write
	// that succeeded.
	written map[endedKey]time.Time
}

// endedKey is a run key of an issuer.
type endedKey struct{ issuer, runKey string }

// endedDocument is the file's content. Ended is a pointer so a document without the
// array, or with null in its place, is told from an empty one, and refused.
type endedDocument struct {
	Ended *[]endedEntry `json:"ended"`
}

// endedEntry is one ended run key, kept until Until, in seconds since the epoch.
type endedEntry struct {
	Issuer string `json:"issuer"`
	RunKey string `json:"run_key"`
	Until  int64  `json:"until"`
}

// OpenEnded opens the ended run keys of the state directory dir. It makes dir, mode
// 0700, when it does not exist, and refuses one that is not a directory of this user's
// that only this user writes, and one this process cannot create a file in. It reads
// [EndedFile] when it exists, a regular file that others can neither read nor write,
// holding the array ended, and refuses one it cannot read, so a gateway never starts
// having forgotten a run key it refuses; the entries past their time are dropped, and
// the file is written again without them.
func OpenEnded(dir string) (*Ended, error) {
	return openEnded(dir, time.Now)
}

// openEnded is [OpenEnded] at the clock given, which the tests alone set.
func openEnded(dir string, clock func() time.Time) (*Ended, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("the ended run keys: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("the ended run keys: %w", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.IsDir():
		return nil, fmt.Errorf("the ended run keys: %s is not a directory", dir)
	case !ok || int(st.Uid) != os.Getuid():
		return nil, fmt.Errorf("the ended run keys: %s is not this user's", dir)
	case info.Mode().Perm()&0o022 != 0:
		return nil, fmt.Errorf("the ended run keys: %s is writable by others than its owner", dir)
	}
	// The file is written beside itself and renamed over, so a directory this process
	// cannot create a file in could never keep a run key: probed as the write does.
	probe, err := os.CreateTemp(dir, EndedFile+".*")
	if err != nil {
		return nil, fmt.Errorf("the ended run keys: %s cannot be written: %w", dir, err)
	}
	probe.Close()
	os.Remove(probe.Name())
	e := &Ended{path: filepath.Join(dir, EndedFile), clock: clock, entries: map[endedKey]time.Time{}, written: map[endedKey]time.Time{}}
	fi, err := os.Lstat(e.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return e, nil
	case err != nil:
		return nil, fmt.Errorf("the ended run keys: %w", err)
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("the ended run keys: %s is not a regular file", e.path)
	case fi.Mode().Perm()&0o077 != 0:
		return nil, fmt.Errorf("the ended run keys: %s is readable or writable by others than its owner", e.path)
	}
	b, err := os.ReadFile(e.path)
	if err != nil {
		return nil, fmt.Errorf("the ended run keys: %w", err)
	}
	var doc endedDocument
	if err := jsonv2.Unmarshal(b, &doc, jsonv2.RejectUnknownMembers(true)); err != nil || doc.Ended == nil {
		return nil, fmt.Errorf("the ended run keys: %s is not a document of ended run keys", e.path)
	}
	for _, x := range *doc.Ended {
		if x.Issuer == "" || x.RunKey == "" {
			return nil, fmt.Errorf("the ended run keys: %s holds an entry without an issuer or a run key", e.path)
		}
		k := endedKey{x.Issuer, x.RunKey}
		until := time.Unix(x.Until, 0)
		if until.After(e.entries[k]) {
			e.entries[k] = until
		}
	}
	n := len(e.entries)
	e.prune(clock())
	maps.Copy(e.written, e.entries)
	if len(e.entries) != n {
		if err := e.write(); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// Has reports whether the gateway refuses the run key of the issuer, still kept at now.
func (e *Ended) Has(issuer, runKey string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	until, ok := e.entries[endedKey{issuer, runKey}]
	return ok && now.Before(until)
}

// Written reports whether the file, as it was last read or written, refuses the run
// key of the issuer at now: whether a gateway started on it would, though a later
// [Ended.Add] failed to write.
func (e *Ended) Written(issuer, runKey string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	until, ok := e.written[endedKey{issuer, runKey}]
	return ok && now.Before(until)
}

// Add records that the run of the issuer's run key has ended, its run credential's exp
// being exp, and writes the file before it returns. The run key is kept until exp plus
// [MaxLeeway]; a run key already kept stays until the later of the two. The entries
// past their time are dropped.
func (e *Ended) Add(issuer, runKey string, exp time.Time) error {
	if issuer == "" || runKey == "" {
		return fmt.Errorf("the ended run keys: no issuer or no run key")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	k := endedKey{issuer, runKey}
	// Seconds, as the file keeps them, rounded up.
	until := exp.Add(MaxLeeway).Add(time.Second - 1).Truncate(time.Second)
	if until.After(e.entries[k]) {
		e.entries[k] = until
	}
	e.prune(e.clock())
	return e.write()
}

// prune drops the entries past their time at now.
func (e *Ended) prune(now time.Time) {
	for k, until := range e.entries {
		if !now.Before(until) {
			delete(e.entries, k)
		}
	}
}

// write writes the file atomically: a file of mode 0600 beside it, synced, renamed over
// it, and the directory synced.
func (e *Ended) write() error {
	list := []endedEntry{}
	for k, until := range e.entries {
		list = append(list, endedEntry{Issuer: k.issuer, RunKey: k.runKey, Until: until.Unix()})
	}
	sort.Slice(list, func(a, b int) bool {
		x, y := list[a], list[b]
		if x.Issuer != y.Issuer {
			return x.Issuer < y.Issuer
		}
		return x.RunKey < y.RunKey
	})
	doc := endedDocument{Ended: &list}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("the ended run keys: %w", err)
	}
	dir := filepath.Dir(e.path)
	f, err := os.CreateTemp(dir, EndedFile+".*")
	if err != nil {
		return fmt.Errorf("the ended run keys: %w", err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("the ended run keys: %w", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("the ended run keys: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("the ended run keys: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("the ended run keys: %w", err)
	}
	if err := os.Rename(tmp, e.path); err != nil {
		return fmt.Errorf("the ended run keys: %w", err)
	}
	ok = true
	e.written = maps.Clone(e.entries)
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
