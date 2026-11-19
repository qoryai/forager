package session

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/session/runtimes/codex"
)

// typeRuntimeResult is the event the session writes at the end of each launch of
// Codex, which prints no result line.
const typeRuntimeResult = "dev.qory.runtime.result"

// maxRollouts is the most rollout files the session reads at the end of one launch of
// Codex, 256: the launch's thread and its child agents, and the other threads below
// CODEX_HOME/sessions.
const maxRollouts = 256

// maxRolloutBytes is the most bytes of rollouts the session reads at the end of one
// launch of Codex, 256 MiB together; each file is at most [maxTranscript] bytes.
const maxRolloutBytes = 4 * maxTranscript

// noUsage is the line of a launch of Codex whose result has no usage: fix, then
// cause.
func noUsage(fix, cause string) string {
	return fix + ". The session wrote no usage in the launch's dev.qory.runtime.result: " + cause
}

// codexUsage reads the rollouts of the Codex launch whose thread is id, after the
// launch's end and [transcript.finish], with the same rules as the transcript's reads
// ([readBeneath], [readUnlinked], [findUpTo]), and returns the launch's usage as
// dev.qory.runtime.result's usage has it, nil when it is unknown. restored is the count
// of bytes of the thread's rollout that the session restored before the launch, 0 for a
// fresh launch.
//
// The thread's rollout is the one file below resume.prefix that resume.path matches
// with id. The other files are those that resume.path matches with any id, at most
// [maxRollouts] together and [maxRolloutBytes] bytes. The usage is the thread's last
// total less the total in its restored bytes, plus the last total of each rollout
// whose parent_thread_id is the thread or one of its child agents
// ([codex.LaunchUsage]). A file that is gone by its read counts for nothing. For a
// file the session does not read, more files or bytes than the caps, or a rollout of
// the thread of another shape, the session writes one line and returns nil; for a
// count below 0, one line, and the count is 0.
// The lines contain no name a * of resume.path matched.
func (t *transcript) codexUsage(id string, restored int64) map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	if id == "" || len(id) > maxSessionID || (t.root != "" && !walledSessionID.MatchString(id)) || (t.root == "" && t.home == "") {
		return nil
	}
	below := strings.TrimPrefix(t.resume.Path, t.resume.Prefix)
	thread := newPathPattern(below, id, t.slug, false)
	every := newPathPattern(strings.ReplaceAll(below, "{session_id}", "*"), "", t.slug, false)
	shownThread, shownEvery := t.resume.Prefix+thread.shown, t.resume.Prefix+every.shown
	base, start, limit, follow := t.home, t.prefix(), 0, true
	if t.root != "" {
		base, start, limit, follow = t.root, t.under, maxFindEntries, false
	}
	found, err := findUpTo(base, start, every, limit, follow, maxRollouts+1)
	switch {
	case errors.Is(err, errTooManyEntries):
		t.line(noUsage(fmt.Sprintf("Keep at most %d entries in the directories below %s", maxFindEntries, t.resume.Prefix), "the search for the rollouts listed more"))
		return nil
	case err != nil:
		t.line(noUsage("Check the directories below "+t.resume.Prefix, "the search for the rollouts failed: "+accesskey.ShownError(err).Error()))
		return nil
	case len(found) > maxRollouts:
		t.line(noUsage(fmt.Sprintf("Keep at most %d rollouts at %s", maxRollouts, shownEvery), "more files match"))
		return nil
	}
	var parent *codex.Rollout
	var others []codex.Rollout
	var read int64
	for _, rel := range found {
		var b []byte
		if t.root != "" {
			b, _, err = readBeneath(t.root, path.Join(t.under, rel), 0)
		} else {
			b, _, err = readUnlinked(filepath.Join(t.home, t.prefix()), rel, 0)
		}
		var refused *beneathRefused
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case errors.As(err, &refused):
			t.line(noUsage(refused.fix, fmt.Sprintf("a file at %s is one the session does not read: %s", shownEvery, refused.why)))
			return nil
		case errors.Is(err, errLinked):
			t.line(noUsage("Keep each rollout at "+shownEvery+" a regular file, with no symbolic link on its path", "the session reads no rollout through a symbolic link or of another type"))
			return nil
		case err != nil:
			t.line(noUsage("Check the rollouts at "+shownEvery, "a read failed: "+accesskey.ShownError(err).Error()))
			return nil
		}
		if read += int64(len(b)); read > maxRolloutBytes {
			t.line(noUsage(fmt.Sprintf("Keep the rollouts at %s at most %d bytes (256 MiB) together", shownEvery, maxRolloutBytes), "they are larger"))
			return nil
		}
		if !thread.matches(rel) {
			if r, err := codex.ParseRollout(b, 0); err == nil {
				others = append(others, r)
			}
			continue
		}
		if parent != nil {
			t.line(noUsage("Keep one rollout of the launch's thread at "+shownThread, "more than one file matches it"))
			return nil
		}
		r, err := codex.ParseRollout(b, restored)
		switch {
		case err != nil:
			t.line(noUsage("Check the rollout of the launch's thread at "+shownThread, err.Error()))
			return nil
		case r.ThreadID != id:
			t.line(noUsage("Check the rollout of the launch's thread at "+shownThread, "its session_meta has the id of another thread"))
			return nil
		}
		parent = &r
	}
	if parent == nil {
		t.line(noUsage("Check that Codex writes the rollout of the launch's thread at "+shownThread, "no file matches"))
		return nil
	}
	u, counted, clamped, err := codex.LaunchUsage(*parent, others)
	switch {
	case err != nil:
		t.line(noUsage(fmt.Sprintf("Keep child agents at most %d levels below the launch's thread", codex.MaxDepth), err.Error()))
		return nil
	case !counted:
		return nil
	case clamped:
		t.line("No action needed. A count of the launch's usage from Codex's rollouts was below 0, and the session wrote 0 in dev.qory.runtime.result")
	}
	return map[string]any{"input": u.Input, "output": u.Output, "cache_read": u.CacheRead, "cache_write": u.CacheWrite}
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
