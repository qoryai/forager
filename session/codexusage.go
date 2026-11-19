package session

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/session/runtimes/codex"
)

// typeRuntimeResult is the event the session writes at the end of each launch of
// Codex, which prints no result line.
const typeRuntimeResult = "dev.qory.runtime.result"

// maxRollouts is the most rollout files the session reads in full at the end of one
// launch of Codex, 256: the launch's thread and its child agents that changed during
// the launch.
const maxRollouts = 256

// maxRolloutBytes is the most bytes of rollouts the session reads in full at the end
// of one launch of Codex, 256 MiB together; each file is at most [maxTranscript] bytes.
const maxRolloutBytes = 4 * maxTranscript

// maxRolloutHead is the most bytes of each other rollout the session reads to learn
// its thread and parent from the first line, 64 KiB. Codex 0.167.2 writes the base
// instructions in that line: 21802 bytes in the fixture's launch 1.
const maxRolloutHead = 64 << 10

// The fixes of the lines of a launch of Codex whose result has no usage: the first
// line of each, at most 100 characters with the period. The numbers are those of
// [maxFindEntries], [maxRollouts], [maxRolloutBytes], [maxTranscript] and
// [codex.MaxDepth].
const (
	fixRolloutEntries   = "Keep at most 10000 entries in the folders of Codex's rollouts"
	fixRolloutFolders   = "Check the folders of Codex's rollouts"
	fixRolloutCount     = "Keep at most 256 rollouts of the launch's thread and its child agents"
	fixRolloutBytes     = "Keep the rollouts of the launch's thread and its child agents at most 256 MiB together"
	fixRolloutLinked    = "Keep each rollout of the launch a regular file, with no symbolic link on its path"
	fixRolloutHardLinks = "Remove the other hard links to each rollout of the launch"
	fixRolloutSize      = "Keep each rollout of the launch at most 64 MiB"
	fixRolloutRead      = "Check the rollouts of the launch"
	fixThreadOne        = "Keep one rollout of the launch's thread"
	fixThreadShape      = "Check the rollout of the launch's thread"
	fixThreadMissing    = "Check that Codex writes the rollout of the launch's thread"
	fixRolloutDepth     = "Keep child agents at most 16 levels below the launch's thread"
	fixRolloutCounts    = "Check the token counts in the rollouts of the launch"
	fixNoTranscript     = "Let the session read Codex's transcript, which it needs to read the rollouts"
)

// noUsage is the line of a launch of Codex whose result has no usage: the fix on the
// first line, the cause on the second.
func noUsage(fix, cause string) string {
	return fix + ".\nThe session wrote no usage in the launch's dev.qory.runtime.result: " + cause
}

// clampedUsage is the line of a launch of Codex with a count of its usage below 0.
const clampedUsage = "No action needed.\nA count of the launch's usage from Codex's rollouts was below 0, and the session wrote 0 in dev.qory.runtime.result"

// noTranscriptUsage is the line of a launch of Codex for which the session reads no
// transcript, and so no rollout.
var noTranscriptUsage = noUsage(fixNoTranscript, "the session reads no transcript for this launch, so it reads no rollout below resume.prefix")

// rolloutState is a rollout file's device, inode and length in bytes.
type rolloutState struct {
	dev, ino uint64
	size     int64
}

// stateOf is the [rolloutState] of st.
func stateOf(st *unix.Stat_t) rolloutState {
	return rolloutState{dev: uint64(st.Dev), ino: st.Ino, size: st.Size}
}

// rolloutPatterns are the patterns of the part of resume.path below resume.prefix:
// thread with the session id id, and every with any id.
func (t *transcript) rolloutPatterns(id string) (thread, every *pathPattern) {
	below := strings.TrimPrefix(t.resume.Path, t.resume.Prefix)
	return newPathPattern(below, id, t.slug, false), newPathPattern(strings.ReplaceAll(below, "{session_id}", "*"), "", t.slug, false)
}

// searchRollouts returns the paths below resume.prefix of every file that every
// matches, with no cap on their count, and with states their [rolloutState]s. It
// searches as [transcript.find] does: behind a wall it lists at most [maxFindEntries]
// entries, and follows no symbolic link below the transcript directory. For a search
// that fails it returns the line instead; when is "before" or "after" the launch.
func (t *transcript) searchRollouts(every *pathPattern, states bool, when string) ([]string, map[string]rolloutState, string) {
	base, start, limit, follow := t.home, t.prefix(), 0, true
	if t.root != "" {
		base, start, limit, follow = t.root, t.under, maxFindEntries, false
	}
	s := &search{pattern: every, limit: limit, stop: math.MaxInt}
	if states {
		s.states = map[string]rolloutState{}
	}
	err := s.run(base, start, follow)
	switch {
	case errors.Is(err, errTooManyEntries):
		return nil, nil, noUsage(fixRolloutEntries, fmt.Sprintf("the search %s the launch listed more than %d entries below %s", when, maxFindEntries, t.resume.Prefix))
	case err != nil:
		return nil, nil, noUsage(fixRolloutFolders, fmt.Sprintf("the search %s the launch below %s failed: %s", when, t.resume.Prefix, accesskey.ShownError(err).Error()))
	}
	return s.found, s.states, ""
}

// codexBaseline records the state of every rollout of Codex below resume.prefix, its
// device, inode and length, before the launch starts and after a restore, with no read
// of a file ([transcript.searchRollouts]). A run with no wall that restored a
// transcript, copied, copies it to its place when the launch starts, after the
// baseline: [transcript.codexUsage] takes copied's length as that file's baseline.
func (t *transcript) codexBaseline(copied *restored) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.root == "" && t.home == "" {
		return
	}
	if t.root == "" {
		t.copied = copied
	}
	_, every := t.rolloutPatterns("")
	_, states, line := t.searchRollouts(every, true, "before")
	t.bases, t.baseFailed = states, line
}

// before is the count of bytes that the rollout at rel below resume.prefix, in the
// state st now, had before the launch: the copied transcript's length for the file a
// run with no wall copies after the baseline; for another file the length of its
// baseline, if its device and inode are the same and it is not shorter. A file the
// baseline does not have, one replaced since, and one shorter than its baseline, have
// 0: Codex 0.167.2 only appends to a rollout, so the totals of such a file are the
// launch's.
func (t *transcript) before(rel string, st rolloutState) int64 {
	if c := t.copied; c != nil && rel == strings.TrimPrefix(c.rel, t.prefix()) {
		if st.size < c.size {
			return 0
		}
		return c.size
	}
	b, ok := t.bases[rel]
	if !ok || b.dev != st.dev || b.ino != st.ino || st.size < b.size {
		return 0
	}
	return b.size
}

// errRolloutLinked is the error of a rollout with a symbolic link on its path.
var errRolloutLinked = errors.New("a symbolic link on its path")

// openRollout opens the file at rel below resume.prefix as the transcript's reads
// open theirs, without waiting for a writer: behind a wall with [openBeneath], without
// one with [openUnlinkedFile]. It returns the file and its fstat. A file that does not
// exist is [fs.ErrNotExist]; a symbolic link on its path is [errRolloutLinked].
func (t *transcript) openRollout(rel string) (*os.File, *unix.Stat_t, error) {
	var fd int
	var err error
	if t.root != "" {
		var names []string
		if names, err = belowNames(path.Join(t.under, rel)); err != nil {
			return nil, nil, errRolloutLinked
		}
		fd, err = openBeneath(t.root, names)
		if err != nil {
			err = beneathError(err)
		}
	} else {
		fd, err = openUnlinkedFile(filepath.Join(t.home, t.prefix()), rel)
	}
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, unix.ENOENT):
		return nil, nil, fs.ErrNotExist
	case errors.Is(err, errBeneathLinked), errors.Is(err, errLinked):
		return nil, nil, errRolloutLinked
	case err != nil:
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), rel)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, &st, nil
}

// rolloutMeta is the [codex.Meta] of the rollout at rel below resume.prefix, from at
// most its first [maxRolloutHead] bytes, and false for a file the session does not
// read that way: one gone, one with a symbolic link on its path, no regular file, or
// one whose first line is no session_meta with ids of at most [maxSessionID] bytes.
func (t *transcript) rolloutMeta(rel string) (codex.Meta, bool) {
	f, st, err := t.openRollout(rel)
	if err != nil {
		return codex.Meta{}, false
	}
	defer f.Close()
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return codex.Meta{}, false
	}
	head, err := io.ReadAll(io.NewSectionReader(f, 0, min(st.Size, maxRolloutHead)))
	if err != nil {
		return codex.Meta{}, false
	}
	m, err := codex.ParseMeta(head)
	if err != nil || len(m.ThreadID) > maxSessionID || len(m.ParentID) > maxSessionID {
		return codex.Meta{}, false
	}
	return m, true
}

// readCheck is the line for a rollout of the launch at shown, in the state st, that
// the session does not read in full, empty for one it reads: one that is no regular
// file, one with a second hard link behind a wall, and one over [maxTranscript] bytes.
func (t *transcript) readCheck(st *unix.Stat_t, shown string) string {
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return noUsage(fixRolloutLinked, "a rollout of the launch at "+shown+" is no regular file")
	case t.root != "" && st.Nlink > 1:
		return noUsage(fixRolloutHardLinks, fmt.Sprintf("a rollout of the launch at %s has %d hard links, and the session reads a file with one", shown, st.Nlink))
	case st.Size > maxTranscript:
		return noUsage(fixRolloutSize, fmt.Sprintf("a rollout of the launch at %s is over %d bytes (64 MiB)", shown, maxTranscript))
	}
	return ""
}

// openLine is the line for a rollout of the launch at shown whose open failed with
// err, other than for a file that does not exist.
func openLine(err error, shown string) string {
	if errors.Is(err, errRolloutLinked) {
		return noUsage(fixRolloutLinked, "a rollout of the launch at "+shown+" has a symbolic link on its path")
	}
	return noUsage(fixRolloutRead, "the open of a rollout at "+shown+" failed: "+accesskey.ShownError(err).Error())
}

// fullRollout is a rollout the session reads in full: its path below resume.prefix,
// the open file and its state.
type fullRollout struct {
	rel string
	f   *os.File
	st  rolloutState
}

// codexUsage reads the rollouts of the Codex launch whose thread is id, after the
// launch's end and [transcript.finish], and returns the launch's usage as
// dev.qory.runtime.result's usage has it, nil when it is unknown. The baseline
// ([transcript.codexBaseline]) has the state of each rollout before the launch.
//
// The thread's rollout is the one file below resume.prefix that resume.path matches
// with id. Of each other file that resume.path matches with any id, the session reads
// at most the first [maxRolloutHead] bytes, for the thread and parent of its
// session_meta ([transcript.rolloutMeta]), and skips a file it does not read so. The
// thread's child agents, at any depth, are the files whose parent is the thread or one
// of them ([codex.Descendants]). The session reads in full the thread's rollout and
// each child agent's that changed since the baseline, at most [maxRollouts] files and
// [maxRolloutBytes] bytes together, with the same rules as the transcript's reads. The
// usage is, over the thread and its child agents, the last total less the last total
// in the bytes the file had before the launch ([transcript.before],
// [codex.LaunchUsage]). A file that is gone by its read counts for nothing. For the
// thread's rollout or a child agent's that the session does not read, more files or
// bytes than the caps, a failed search, a rollout of the thread of another shape, or a
// count above 2^53, the session writes one line and returns nil; for a count below 0,
// one line, and the count is 0. The lines contain no name a * of resume.path matched.
func (t *transcript) codexUsage(id string) map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	if id == "" || len(id) > maxSessionID || (t.root != "" && !walledSessionID.MatchString(id)) || (t.root == "" && t.home == "") {
		return nil
	}
	if t.baseFailed != "" {
		t.line(t.baseFailed)
		return nil
	}
	thread, every := t.rolloutPatterns(id)
	shownThread, shownEvery := t.resume.Prefix+thread.shown, t.resume.Prefix+every.shown
	found, _, line := t.searchRollouts(every, false, "after")
	if line != "" {
		t.line(line)
		return nil
	}
	threadRel := ""
	var rels []string
	var metas []codex.Meta
	for _, rel := range found {
		if thread.matches(rel) {
			if threadRel != "" {
				t.line(noUsage(fixThreadOne, "more than one file matches "+shownThread))
				return nil
			}
			threadRel = rel
			continue
		}
		if m, ok := t.rolloutMeta(rel); ok {
			rels, metas = append(rels, rel), append(metas, m)
		}
	}
	missing := noUsage(fixThreadMissing, "no file matches "+shownThread)
	if threadRel == "" {
		t.line(missing)
		return nil
	}
	below, err := codex.Descendants(id, metas)
	if err != nil {
		t.line(noUsage(fixRolloutDepth, err.Error()))
		return nil
	}

	// The files to read in full stay open until the end, so that each read is of the
	// file its state is of.
	var full []fullRollout
	defer func() {
		for _, r := range full {
			r.f.Close()
		}
	}()
	// others has a rollout with no totals for each child agent that did not change: it
	// links the child agents below it to the thread, and adds nothing.
	var others []codex.Rollout
	var size int64
	for i, rel := range append([]string{threadRel}, pick(rels, below)...) {
		shown := shownEvery
		if i == 0 {
			shown = shownThread
		}
		f, st, err := t.openRollout(rel)
		switch {
		case errors.Is(err, fs.ErrNotExist) && i == 0:
			t.line(missing)
			return nil
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			t.line(openLine(err, shown))
			return nil
		}
		state := stateOf(st)
		if base, ok := t.bases[rel]; i > 0 && ok && base == state {
			f.Close()
			others = append(others, codex.Rollout{Meta: metas[below[i-1]]})
			continue
		}
		full = append(full, fullRollout{rel: rel, f: f, st: state})
		if line := t.readCheck(st, shown); line != "" {
			t.line(line)
			return nil
		}
		if len(full) > maxRollouts {
			t.line(noUsage(fixRolloutCount, fmt.Sprintf("more than %d of them changed during the launch, at %s", maxRollouts, shownEvery)))
			return nil
		}
		if size += st.Size; size > maxRolloutBytes {
			t.line(noUsage(fixRolloutBytes, fmt.Sprintf("those that changed during the launch, at %s, are larger", shownEvery)))
			return nil
		}
	}

	var parent codex.Rollout
	for i, r := range full {
		shown := shownEvery
		if i == 0 {
			shown = shownThread
		}
		b, err := io.ReadAll(io.NewSectionReader(r.f, 0, r.st.size))
		if err != nil {
			t.line(noUsage(fixRolloutRead, "a read of a rollout at "+shown+" failed: "+accesskey.ShownError(err).Error()))
			return nil
		}
		ro, err := codex.ParseRollout(b, t.before(r.rel, r.st))
		switch {
		case errors.Is(err, codex.ErrCount):
			t.line(noUsage(fixRolloutCounts, err.Error()+", at "+shown))
			return nil
		case err != nil && i == 0:
			t.line(noUsage(fixThreadShape, "the file at "+shown+": "+err.Error()))
			return nil
		case i == 0 && ro.ThreadID != id:
			t.line(noUsage(fixThreadShape, "the session_meta of the file at "+shown+" has the id of another thread"))
			return nil
		case err != nil, len(ro.ThreadID) > maxSessionID, len(ro.ParentID) > maxSessionID:
			continue
		case i == 0:
			parent = ro
		default:
			others = append(others, ro)
		}
	}
	u, counted, clamped, err := codex.LaunchUsage(parent, others)
	switch {
	case errors.Is(err, codex.ErrCount):
		t.line(noUsage(fixRolloutCounts, err.Error()+", at "+shownEvery))
		return nil
	case err != nil:
		t.line(noUsage(fixRolloutDepth, err.Error()))
		return nil
	case !counted:
		return nil
	case clamped:
		t.line(clampedUsage)
	}
	return map[string]any{"input": u.Input, "output": u.Output, "cache_read": u.CacheRead, "cache_write": u.CacheWrite}
}

// pick is the elements of s at the indexes in at, in that order.
func pick(s []string, at []int) []string {
	out := make([]string, len(at))
	for i, j := range at {
		out[i] = s[j]
	}
	return out
}

// codexResult is the data of the dev.qory.runtime.result of a launch of Codex whose
// thread is id, before the session's number: success with is_error false for a
// session that ended succeeded; error_during_execution with is_error false for one
// paused, with model_key_limit or model_key_switch; error_during_execution with
// is_error true for every other end, a timeout and an interrupt among them. usage is
// [transcript.codexUsage]'s, absent when nil. It has no turns, duration or cost: the
// rollouts contain none.
func codexResult(id, state string, usage map[string]any) map[string]any {
	data := map[string]any{"session_id": id, "outcome": "error_during_execution", "is_error": true}
	switch state {
	case event.StateSucceeded:
		data["outcome"], data["is_error"] = "success", false
	case event.StatePaused:
		data["is_error"] = false
	}
	if usage != nil {
		data["usage"] = usage
	}
	return data
}

// writeCodexResult writes the dev.qory.runtime.result of session n's launch of Codex
// ([codexResult]), its strings masked as the runtime's other events are.
func (r *Run) writeCodexResult(n int, id, state string, usage map[string]any, masker *mask.Masker, hidden *mask.Harness, text func(string) string) {
	masked := maskedRecord(texts{secrets: masker, harness: hidden}, codexResult(id, state, usage))
	r.write(typeRuntimeResult, withSession(neutralRecord(typeRuntimeResult, masked, text), n))
}
