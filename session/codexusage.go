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
// instructions in that line, after the ids and the source: 21802 bytes in the
// fixture's launch 1.
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
	fixRolloutMeta      = "Check the first line of each rollout that changed during the launch"
	fixRolloutSwapped   = "Leave the rollouts of the launch in place once Codex exits"
	fixRolloutBaseline  = "Check the permissions of Codex's rollouts and of their folders"
	fixNoTranscript     = "Fix the transcript line before this one, then start a new session"
)

// noUsage is the line of a launch of Codex whose result has no usage: the fix on the
// first line, the cause on the second.
func noUsage(fix, cause string) string {
	return fix + ".\nThe session wrote no usage in the launch's dev.qory.runtime.result: " + cause
}

// clampedUsage is the line of a launch of Codex with a count of its usage below 0.
const clampedUsage = "No action needed.\nA count of the launch's usage from Codex's rollouts was below 0, and the session wrote 0 in dev.qory.runtime.result"

// noTranscriptUsage is the line of a launch of Codex for which the session reads no
// transcript, and so no rollout. With Codex's descriptor, each cause of no transcript
// writes a line with its fix at the session's start, before this one.
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
// matches, with no cap on their count, and their [rolloutState]s, by fstatat. It
// searches as [transcript.find] does: behind a wall it lists at most [maxFindEntries]
// entries, and follows no symbolic link below the transcript directory. For a search
// that fails, and for a search before the launch with an fstatat that fails, which
// would leave a file with no baseline, it returns the line instead; when is "before"
// or "after" the launch. After the launch, a file whose fstatat fails counts as one
// that changed.
func (t *transcript) searchRollouts(every *pathPattern, when string) ([]string, map[string]rolloutState, string) {
	base, start, limit, follow := t.home, t.prefix(), 0, true
	if t.root != "" {
		base, start, limit, follow = t.root, t.under, maxFindEntries, false
	}
	s := &search{pattern: every, limit: limit, stop: math.MaxInt, states: map[string]rolloutState{}}
	err := s.run(base, start, follow)
	switch {
	case errors.Is(err, errTooManyEntries):
		return nil, nil, noUsage(fixRolloutEntries, fmt.Sprintf("the search %s the launch listed more than %d entries below %s", when, maxFindEntries, t.resume.Prefix))
	case err != nil:
		return nil, nil, noUsage(fixRolloutFolders, fmt.Sprintf("the search %s the launch below %s failed: %s", when, t.resume.Prefix, accesskey.ShownError(err).Error()))
	case s.statErr != nil && when == "before":
		return nil, nil, noUsage(fixRolloutBaseline, fmt.Sprintf("the fstatat of a rollout at %s before the launch failed: %s", t.resume.Prefix+every.shown, accesskey.ShownError(s.statErr).Error()))
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
	_, states, line := t.searchRollouts(every, "before")
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
	// The file has no name: an error of a read would contain it, and rel may contain
	// a name a * of resume.path matched.
	f := os.NewFile(uintptr(fd), "")
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, nil, err
	}
	if t.hooks != nil && t.hooks.opened != nil {
		t.hooks.opened(rel, f)
	}
	return f, &st, nil
}

// rolloutHooks are the calls a test gets from the reads of rollouts: opened after each
// open and fstat, head with the bytes of each read of a rollout's first bytes.
type rolloutHooks struct {
	opened func(rel string, f *os.File)
	head   func(rel string, n int)
}

// pathless is err with the path of an [fs.PathError] in it taken out: the operation
// and its cause.
func pathless(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s: %w", pe.Op, pe.Err)
	}
	return err
}

// headRead is what the session reads of the first bytes of a rollout: when ok, the
// [codex.Meta] of its session_meta and the file's state at that read; otherwise
// unread, the line for a file that the session could not read so, empty for a file
// that is gone.
type headRead struct {
	meta   codex.Meta
	st     rolloutState
	ok     bool
	unread string
}

// rolloutMeta reads the [headRead] of the rollout at rel below resume.prefix, from at
// most its first [maxRolloutHead] bytes, as its fstat has them. Its unread line is
// for a file with a symbolic link on its path, one that is no regular file, one whose
// open or read failed, and one whose first line is no session_meta with ids of at
// most [maxSessionID] bytes. It reads a file with a second hard link too, to learn its
// ids: behind a wall, a child agent's that changed then gets the line of
// [transcript.readCheck] and no usage, and the session reads no other such file in
// full. For a file whose first line is longer than those bytes and has no id and
// source in them ([codex.ErrMetaCut]), it returns the line instead; shown is the
// file's place in it.
func (t *transcript) rolloutMeta(rel, shown string) (headRead, string) {
	f, st, err := t.openRollout(rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return headRead{}, ""
	case err != nil:
		return headRead{unread: openLine(err, shown)}, ""
	}
	defer f.Close()
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return headRead{unread: noUsage(fixRolloutLinked, "a rollout of the launch at "+shown+" is no regular file")}, ""
	}
	head, err := io.ReadAll(io.NewSectionReader(f, 0, min(st.Size, maxRolloutHead)))
	if t.hooks != nil && t.hooks.head != nil {
		t.hooks.head(rel, len(head))
	}
	if err != nil {
		return headRead{unread: noUsage(fixRolloutRead, "a read of a rollout at "+shown+" failed: "+accesskey.ShownError(pathless(err)).Error())}, ""
	}
	m, err := codex.ParseMeta(head)
	switch {
	case errors.Is(err, codex.ErrMetaCut) && st.Size > maxRolloutHead:
		return headRead{}, noUsage(fixRolloutMeta, fmt.Sprintf("the first %d bytes (64 KiB) of a rollout at %s end before the id and source of its session_meta", maxRolloutHead, shown))
	case err != nil:
		return headRead{unread: noUsage(fixRolloutMeta, "the first line of a rollout at "+shown+" is no session_meta with an id")}, ""
	case len(m.ThreadID) > maxSessionID || len(m.ParentID) > maxSessionID:
		return headRead{unread: noUsage(fixRolloutMeta, fmt.Sprintf("the session_meta of a rollout at %s has an id longer than %d bytes", shown, maxSessionID))}, ""
	}
	return headRead{meta: m, st: stateOf(st), ok: true}, ""
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
// the open file, its state, and the [codex.Meta] of its first bytes, empty for the
// thread's.
type fullRollout struct {
	rel  string
	f    *os.File
	st   rolloutState
	meta codex.Meta
}

// unreadRollout is a file that changed since the baseline and whose first bytes the
// session could not read for its ids: its path below resume.prefix and the line of
// [headRead].
type unreadRollout struct {
	rel, line string
}

// unreadChild is the line of the first file of unread whose name resume.path matches
// with the id of a thread that a spawn_agent call in rollouts started: a child agent
// of the launch's thread or of one of its child agents that the session could not
// read. It is empty when no file of unread is such a file: a file of another thread
// counts for nothing. An id longer than [maxSessionID] bytes matches no file.
func (t *transcript) unreadChild(unread []unreadRollout, rollouts []codex.Rollout) string {
	if len(unread) == 0 {
		return ""
	}
	for _, r := range rollouts {
		for _, id := range r.Spawned {
			if id == "" || len(id) > maxSessionID {
				continue
			}
			var named *pathPattern
			for _, u := range unread {
				if !strings.Contains(path.Base(u.rel), id) {
					continue
				}
				if named == nil {
					named, _ = t.rolloutPatterns(id)
				}
				if named.matches(u.rel) {
					return u.line
				}
			}
		}
	}
	return ""
}

// codexUsage reads the rollouts of the Codex launch whose thread is id, after the
// launch's end and [transcript.finish], and returns the launch's usage as
// dev.qory.runtime.result's usage has it, nil when it is unknown. The baseline
// ([transcript.codexBaseline]) has the state of each rollout before the launch.
//
// The thread's rollout is the one file below resume.prefix that resume.path matches
// with id. Of each other file that resume.path matches with any id and that changed
// since the baseline, the session reads at most the first [maxRolloutHead] bytes, for
// the thread and parent of its session_meta ([transcript.rolloutMeta]). A file it
// does not read so is a child agent's when a spawn_agent call in the rollouts it reads
// in full started the thread whose id its name has ([transcript.unreadChild]), and
// counts for nothing otherwise. A file that did not change adds nothing, and the session
// reads its first bytes only to link a file that changed to the thread: when no file
// it read has the id of that file's parent, it reads each file that did not change and
// that resume.path matches with that id ([transcript.linkRollouts]). The thread's
// child agents, at any depth, are the files whose parent is the thread or one of them
// ([codex.Descendants]). The session reads in full the thread's rollout and each child
// agent's that changed, at most [maxRollouts] files and [maxRolloutBytes] bytes
// together, with the same rules as the transcript's reads. The usage is, over the thread
// and its child agents, the last total less the last total in the bytes the file had
// before the launch ([transcript.before], [codex.SumUsage]). A file that is gone by
// its read counts for nothing. For the thread's rollout or a child agent's that the
// session does not read, a child agent's that another file replaced or whose ids
// changed between the read of its first bytes and its read in full, a file whose first
// line has no ids in its first bytes, more files or bytes than the caps, a failed
// search, a baseline whose fstatat of a file failed, a rollout of the thread of
// another shape, or a count above 2^53, the session writes one line and returns nil; for a
// count below 0, one line, and the count is 0. The lines contain no name a * of
// resume.path matched.
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
	found, states, line := t.searchRollouts(every, "after")
	if line != "" {
		t.line(line)
		return nil
	}
	threadRel := ""
	var rels, unchanged []string
	var metas []codex.Meta
	var heads []rolloutState
	var unread []unreadRollout
	for _, rel := range found {
		if thread.matches(rel) {
			if threadRel != "" {
				t.line(noUsage(fixThreadOne, "more than one file matches "+shownThread))
				return nil
			}
			threadRel = rel
			continue
		}
		if st, ok := states[rel]; ok && t.unchanged(rel, st) {
			unchanged = append(unchanged, rel)
			continue
		}
		h, line := t.rolloutMeta(rel, shownEvery)
		switch {
		case line != "":
			t.line(line)
			return nil
		case h.ok:
			rels, metas, heads = append(rels, rel), append(metas, h.meta), append(heads, h.st)
		case h.unread != "":
			unread = append(unread, unreadRollout{rel: rel, line: h.unread})
		}
	}
	missing := noUsage(fixThreadMissing, "no file matches "+shownThread)
	if threadRel == "" {
		t.line(missing)
		return nil
	}
	changed := len(rels)
	rels, metas, line = t.linkRollouts(id, unchanged, rels, metas, shownEvery)
	if line != "" {
		t.line(line)
		return nil
	}
	below, err := codex.Descendants(id, metas)
	if err != nil {
		t.line(noUsage(fixRolloutDepth, err.Error()))
		return nil
	}

	// The files to read in full stay open until the end, so that each read is of the
	// file its state is of. A child agent's file that did not change adds nothing.
	var full []fullRollout
	defer func() {
		for _, r := range full {
			r.f.Close()
		}
	}()
	reads := []int{-1}
	for _, i := range below {
		if i < changed {
			reads = append(reads, i)
		}
	}
	var size int64
	for _, i := range reads {
		rel, shown, meta := threadRel, shownThread, codex.Meta{}
		if i >= 0 {
			rel, shown, meta = rels[i], shownEvery, metas[i]
		}
		f, st, err := t.openRollout(rel)
		switch {
		case errors.Is(err, fs.ErrNotExist) && i < 0:
			t.line(missing)
			return nil
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			t.line(openLine(err, shown))
			return nil
		}
		state := stateOf(st)
		if i >= 0 && (state.dev != heads[i].dev || state.ino != heads[i].ino) {
			f.Close()
			t.line(swappedLine(shown))
			return nil
		}
		if i >= 0 && t.unchanged(rel, state) {
			f.Close()
			continue
		}
		full = append(full, fullRollout{rel: rel, f: f, st: state, meta: meta})
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

	var rollouts []codex.Rollout
	for i, r := range full {
		shown := shownEvery
		if i == 0 {
			shown = shownThread
		}
		b, err := io.ReadAll(io.NewSectionReader(r.f, 0, r.st.size))
		if err != nil {
			t.line(noUsage(fixRolloutRead, "a read of a rollout at "+shown+" failed: "+accesskey.ShownError(pathless(err)).Error()))
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
		case i > 0 && (err != nil || ro.Meta != r.meta):
			// The file changed between the read of its first bytes and this read.
			t.line(swappedLine(shown))
			return nil
		}
		rollouts = append(rollouts, ro)
	}
	if line := t.unreadChild(unread, rollouts); line != "" {
		t.line(line)
		return nil
	}
	u, counted, clamped, err := codex.SumUsage(rollouts)
	switch {
	case errors.Is(err, codex.ErrCount):
		t.line(noUsage(fixRolloutCounts, err.Error()+", at "+shownEvery))
		return nil
	case !counted:
		return nil
	case clamped:
		t.line(clampedUsage)
	}
	return map[string]any{"input": u.Input, "output": u.Output, "cache_read": u.CacheRead, "cache_write": u.CacheWrite}
}

// swappedLine is the line for a child agent's rollout at shown that changed between
// the read of its first bytes and its read in full: another file at its path, or
// another session_meta.
func swappedLine(shown string) string {
	return noUsage(fixRolloutSwapped, "a rollout of a child agent at "+shown+" changed between the session's reads of it")
}

// unchanged reports whether the rollout at rel below resume.prefix is in the state st
// of its baseline: the same device, inode and length.
func (t *transcript) unchanged(rel string, st rolloutState) bool {
	base, ok := t.bases[rel]
	return ok && base == st
}

// linkRollouts adds to rels and metas, the files that changed since the baseline and
// their [codex.Meta]s, the files of unchanged that link them to the thread id. For
// each parent id that is neither id nor a thread of metas, it reads the first bytes
// of each file of unchanged that resume.path matches with that id, and adds the file
// when its session_meta has that id; then it does the same for the parents of the
// files it added. It looks up each id once. It returns the line of
// [transcript.rolloutMeta] instead, for a file whose first line has no ids in its
// first bytes; shown is the place of the files in it.
func (t *transcript) linkRollouts(id string, unchanged, rels []string, metas []codex.Meta, shown string) ([]string, []codex.Meta, string) {
	known := map[string]bool{id: true}
	for _, m := range metas {
		known[m.ThreadID] = true
	}
	looked := map[string]bool{}
	for i := 0; i < len(metas); i++ {
		parent := metas[i].ParentID
		if parent == "" || known[parent] || looked[parent] {
			continue
		}
		looked[parent] = true
		var named *pathPattern
		for _, rel := range unchanged {
			if !strings.Contains(path.Base(rel), parent) {
				continue
			}
			if named == nil {
				named, _ = t.rolloutPatterns(parent)
			}
			if !named.matches(rel) {
				continue
			}
			h, line := t.rolloutMeta(rel, shown)
			if line != "" {
				return nil, nil, line
			}
			if h.ok && h.meta.ThreadID == parent {
				known[parent] = true
				rels, metas = append(rels, rel), append(metas, h.meta)
			}
		}
	}
	return rels, metas, ""
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
