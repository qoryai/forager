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

// Ended is the set of run keys a gateway refuses, by issuer, those whose run the run's
// starter ended, each with how the starter said the run ended, kept in a file of the
// gateway's state directory so a restart refuses them too, and ends their runs the same
// way. Each is kept until its run credential's exp plus [MaxLeeway], the latest a run
// credential of that exp is accepted under any issuer's leeway, and dropped after. It is
// safe for concurrent use; one gateway alone uses a state directory.
type Ended struct {
	path  string
	clock func() time.Time

	mu      sync.Mutex
	entries map[endedKey]endedRun
	// written are the entries as the file last held them: read at open, and each write
	// that succeeded.
	written map[endedKey]endedRun
}

// endedRun is how long a run key is kept, and how its run ended: the starter's outcome
// and reason, each empty for none.
type endedRun struct {
	until           time.Time
	outcome, reason string
}

// endedKey is a run key of an issuer.
type endedKey struct{ issuer, runKey string }

// endedDocument is the file's content. Ended is a pointer so a document without the
// array, or with null in its place, is told from an empty one, and refused.
type endedDocument struct {
	Ended *[]endedEntry `json:"ended"`
}

// endedEntry is one ended run key, kept until Until, in seconds since the epoch, with
// the outcome and the reason its starter gave, when it gave them: members a gateway
// before them refuses the file for.
type endedEntry struct {
	Issuer  string `json:"issuer"`
	RunKey  string `json:"run_key"`
	Until   int64  `json:"until"`
	Outcome string `json:"outcome,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// OpenEnded opens the ended run keys of the state directory dir. It makes dir, mode
// 0700, when it does not exist, and refuses one that is not a directory of this user's
// that only this user writes, and one this process cannot create a file in. It reads
// [EndedFile] when it exists, a regular file that others can neither read nor write,
// holding the array ended, and refuses one it cannot read, so a gateway never starts
// having forgotten a run key it refuses, or how its run ended: an entry without an
// issuer or a run key, or whose outcome or reason the run's starter could not have given
// ([StarterOutcome]), a reason without an outcome among them. The entries past their
// time are dropped, and the file is written again without them.
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
	e := &Ended{path: filepath.Join(dir, EndedFile), clock: clock, entries: map[endedKey]endedRun{}, written: map[endedKey]endedRun{}}
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
			return nil, fmt.Errorf("the ended run keys: %s holds an entry without a starter or a run key", e.path)
		}
		if outcome, reason := StarterOutcome(x.Outcome, x.Reason); outcome != x.Outcome || reason != x.Reason {
			return nil, fmt.Errorf("the ended run keys: %s holds an entry with an outcome or a reason a run's starter cannot give", e.path)
		}
		k := endedKey{x.Issuer, x.RunKey}
		kept, ok := e.entries[k]
		if !ok {
			kept.outcome, kept.reason = x.Outcome, x.Reason
		}
		if until := time.Unix(x.Until, 0); until.After(kept.until) {
			kept.until = until
		}
		e.entries[k] = kept
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
	_, _, ok := e.Outcome(issuer, runKey, now)
	return ok
}

// Outcome is how the run's starter said the run of the issuer's run key ended, as the
// first [Ended.AddOutcome] of it kept it: its outcome and its reason, each empty for
// none; ok says the run key is still kept at now.
func (e *Ended) Outcome(issuer, runKey string, now time.Time) (outcome, reason string, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	kept, ok := e.entries[endedKey{issuer, runKey}]
	if !ok || !now.Before(kept.until) {
		return "", "", false
	}
	return kept.outcome, kept.reason, true
}

// Written reports whether the file, as it was last read or written, refuses the run
// key of the issuer at now: whether a gateway started on it would, though a later
// [Ended.Add] failed to write.
func (e *Ended) Written(issuer, runKey string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	kept, ok := e.written[endedKey{issuer, runKey}]
	return ok && now.Before(kept.until)
}

// Add records that the run of the issuer's run key has ended, its run credential's exp
// being exp, and writes the file before it returns: [Ended.AddOutcome] with no outcome.
func (e *Ended) Add(issuer, runKey string, exp time.Time) error {
	return e.AddOutcome(issuer, runKey, exp, "", "")
}

// AddOutcome records that the run of the issuer's run key has ended, its run
// credential's exp being exp, with the outcome and the reason the run's starter gave,
// each empty for none, by the rules of [StarterOutcome], and writes the file before it
// returns. The run key is kept until exp plus [MaxLeeway]; a run key already kept stays
// until the later of the two, and keeps the outcome and the reason it was first kept
// with, so every later end of the run key, and a restart, gets the same. The entries
// past their time are dropped.
func (e *Ended) AddOutcome(issuer, runKey string, exp time.Time, outcome, reason string) error {
	if issuer == "" || runKey == "" {
		return fmt.Errorf("the ended run keys: no starter or no run key")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.clock()
	e.prune(now)
	k := endedKey{issuer, runKey}
	kept, ok := e.entries[k]
	if !ok {
		kept.outcome, kept.reason = StarterOutcome(outcome, reason)
	}
	// Seconds, as the file keeps them, rounded up.
	if until := exp.Add(MaxLeeway).Add(time.Second - 1).Truncate(time.Second); until.After(kept.until) {
		kept.until = until
	}
	e.entries[k] = kept
	e.prune(now)
	return e.write()
}

// prune drops the entries past their time at now.
func (e *Ended) prune(now time.Time) {
	for k, kept := range e.entries {
		if !now.Before(kept.until) {
			delete(e.entries, k)
		}
	}
}

// write writes the file atomically: a file of mode 0600 beside it, synced, renamed over
// it, and the directory synced.
func (e *Ended) write() error {
	list := []endedEntry{}
	for k, kept := range e.entries {
		list = append(list, endedEntry{Issuer: k.issuer, RunKey: k.runKey, Until: kept.until.Unix(), Outcome: kept.outcome, Reason: kept.reason})
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
