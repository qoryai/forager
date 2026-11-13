package session

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/qoryai/forager/session/runtimes"
)

// claudeResume is the Claude Code descriptor's resume.
var claudeResume = runtimes.Resume{PathFrom: "transcript_path", Path: "~/.claude/projects/{cwd_slug}/{session_id}.jsonl", Prefix: "~/.claude/projects/", Args: []string{"--resume", "{session_id}"}}

// sentTranscript is what a transcript under test sent: its events' data and its lines.
type sentTranscript struct {
	events []map[string]any
	lines  []string
}

// file is the masked file the events of path contain, joined in order, and false when
// an offset leaves a gap.
func (s *sentTranscript) file(t *testing.T, path string) ([]byte, bool) {
	t.Helper()
	var out []byte
	for _, e := range s.events {
		if e["path"] != path {
			continue
		}
		if e["offset"] != int64(len(out)) {
			return out, false
		}
		b, err := base64.StdEncoding.DecodeString(e["bytes"].(string))
		if err != nil || len(b) == 0 || len(b) > TranscriptChunk {
			t.Fatalf("a chunk of %d bytes: %v", len(b), err)
		}
		out = append(out, b...)
	}
	return out, true
}

// newTestTranscript is a transcript of a runtime with Claude Code's resume whose home
// is a new directory, working in /workspace, whose masker replaces sk-fake-secret.
func newTestTranscript(t *testing.T) (*transcript, *sentTranscript, string) {
	t.Helper()
	home := t.TempDir()
	s := &sentTranscript{}
	mask := func(l string) string { return strings.ReplaceAll(l, "sk-fake-secret", "[secret]") }
	tr := newTranscript(claudeResume, home, "/workspace", mask, func(m map[string]any) { s.events = append(s.events, m) }, func(l string) { s.lines = append(s.lines, l) })
	return tr, s, home
}

// appendTo appends b to the file at rel under home, making its directories.
func appendTo(t *testing.T, home, rel string, b []byte) {
	t.Helper()
	p := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
}

// TestTheTranscriptSendsWholeMaskedLinesInChunks pins the path from resume.path with the
// runtime's session id and the slug of its working directory, whole lines only while
// the runtime runs, each masked whole, chunks of at most 32 KiB with offsets from 0
// over the masked file, and the rest of the file at the end, after which nothing is
// sent.
func TestTheTranscriptSendsWholeMaskedLinesInChunks(t *testing.T) {
	tr, s, home := newTestTranscript(t)
	rel := ".claude/projects/-workspace/s-1.jsonl"
	appendTo(t, home, rel, []byte("{\"a\":\"sk-fake-secret\"}\n{\"b\":"))
	tr.poll(false)
	if len(s.events) != 0 {
		t.Fatalf("sent before the runtime's session id: %v", s.events)
	}
	tr.started("s-1")
	tr.poll(false)
	got, ok := s.file(t, "~/"+rel)
	if want := "{\"a\":\"[secret]\"}\n"; !ok || string(got) != want {
		t.Fatalf("after the first read: %q %v; want %q", got, ok, want)
	}
	if e := s.events[0]; e["session_id"] != "s-1" {
		t.Errorf("session_id %v", e["session_id"])
	}
	long := bytes.Repeat([]byte("x"), 70000)
	appendTo(t, home, rel, append(append([]byte("1}\n{\"c\":\""), long...), []byte("\"}\n{\"d\":")...))
	tr.poll(false)
	appendTo(t, home, rel, []byte("2}"))
	tr.finish()
	got, ok = s.file(t, "~/"+rel)
	want := "{\"a\":\"[secret]\"}\n{\"b\":1}\n{\"c\":\"" + string(long) + "\"}\n{\"d\":2}"
	if !ok || string(got) != want {
		t.Fatalf("the file: %d bytes, no gap %v; want %d bytes", len(got), ok, len(want))
	}
	if len(s.events) != 5 {
		t.Errorf("%d events; want 5: one, two cut at 32 KiB and their rest, and the end", len(s.events))
	}
	appendTo(t, home, rel, []byte("\n{\"e\":3}\n"))
	n := len(s.events)
	tr.poll(true)
	if len(s.events) != n || len(s.lines) != 0 {
		t.Errorf("sent after finish: %d events, lines %v", len(s.events)-n, s.lines)
	}
}

// TestTheTranscriptPathFromAHookWins pins the path of the first hook input that contains
// transcript_path: it takes the place of resume.path, starts its chunks at offset 0,
// and a later hook input changes nothing.
func TestTheTranscriptPathFromAHookWins(t *testing.T) {
	tr, s, home := newTestTranscript(t)
	appendTo(t, home, ".claude/projects/-workspace/s-1.jsonl", []byte("{\"template\":1}\n"))
	appendTo(t, home, ".claude/projects/-real-dir/s-1.jsonl", []byte("{\"hook\":1}\n"))
	appendTo(t, home, ".claude/projects/-other/s-1.jsonl", []byte("{\"later\":1}\n"))
	tr.started("s-1")
	tr.poll(false)
	tr.record(runtimes.Record{Source: runtimes.SourceHooks, Record: map[string]any{"session_id": "s-1", "transcript_path": filepath.Join(home, ".claude/projects/-real-dir/s-1.jsonl")}})
	tr.record(runtimes.Record{Source: runtimes.SourceHooks, Record: map[string]any{"session_id": "s-1", "transcript_path": filepath.Join(home, ".claude/projects/-other/s-1.jsonl")}})
	tr.finish()
	if got, ok := s.file(t, "~/.claude/projects/-real-dir/s-1.jsonl"); !ok || string(got) != "{\"hook\":1}\n" {
		t.Errorf("the hook's path: %q %v", got, ok)
	}
	if _, ok := s.file(t, "~/.claude/projects/-other/s-1.jsonl"); len(s.events) != 2 || !ok {
		t.Errorf("events %v", s.events)
	}
}

// TestTheTranscriptReadsNoPathOutsideThePrefix pins the paths the session reads none of:
// a hook's path outside the prefix or outside the home, one with a .. segment, and one
// through a symbolic link, each with no event; a path outside the prefix also has its
// line.
func TestTheTranscriptReadsNoPathOutsideThePrefix(t *testing.T) {
	for name, c := range map[string]struct {
		path func(home string) string
		line bool
	}{
		"outside the prefix": {func(home string) string { return filepath.Join(home, ".ssh/s-1.jsonl") }, true},
		"outside the home":   {func(string) string { return "/etc/s-1.jsonl" }, true},
		"a .. segment":       {func(home string) string { return home + "/.claude/projects/../../.ssh/s-1.jsonl" }, true},
		"a symbolic link": {func(home string) string {
			outside := t.TempDir()
			appendTo(t, outside, "s-1.jsonl", []byte("{\"outside\":1}\n"))
			if err := os.MkdirAll(filepath.Join(home, ".claude/projects"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(home, ".claude/projects/-linked")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(home, ".claude/projects/-linked/s-1.jsonl")
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			tr, s, home := newTestTranscript(t)
			appendTo(t, home, ".ssh/s-1.jsonl", []byte("{\"private\":1}\n"))
			tr.record(runtimes.Record{Source: runtimes.SourceHooks, Record: map[string]any{"session_id": "s-1", "transcript_path": c.path(home)}})
			tr.started("s-1")
			tr.finish()
			if len(s.events) != 0 {
				t.Errorf("sent %v", s.events)
			}
			if c.line != (len(s.lines) == 1) {
				t.Errorf("lines %q", s.lines)
			}
		})
	}
}

// TestATranscriptThatBecomesShorterStops pins a file shorter than the bytes already
// read: one line on stderr, and no event from then on.
func TestATranscriptThatBecomesShorterStops(t *testing.T) {
	tr, s, home := newTestTranscript(t)
	rel := ".claude/projects/-workspace/s-1.jsonl"
	appendTo(t, home, rel, []byte("{\"a\":1}\n{\"b\":2}\n"))
	tr.started("s-1")
	tr.poll(false)
	if err := os.WriteFile(filepath.Join(home, rel), []byte("{\"a\":1}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr.poll(false)
	appendTo(t, home, rel, []byte("{\"c\":3}\n{\"d\":4}\n"))
	tr.finish()
	want := "Let the runtime only append to its transcript. A continuation of this run starts the runtime without a resume: the transcript ~/" + rel + " became shorter than the 16 bytes read"
	if len(s.events) != 1 || len(s.lines) != 1 || s.lines[0] != want {
		t.Errorf("%d events, lines %q; want 1 and %q", len(s.events), s.lines, want)
	}
}

// TestTheCwdSlug pins the slug: every character other than an ASCII letter or digit is
// -.
func TestTheCwdSlug(t *testing.T) {
	for in, want := range map[string]string{"/workspace": "-workspace", "/home/a_b/c.d": "-home-a-b-c-d", "/x/é1": "-x---1"} {
		if got := cwdSlug(in); got != want {
			t.Errorf("cwdSlug(%q) = %q; want %q", in, got, want)
		}
	}
}

// TestAPollReadsOnlyTheBytesAppended pins the read of each poll: the bytes after the
// last read alone, with the part of a line an earlier read held completed from them.
// Bytes the poll already read and the runtime then changed are not read again.
func TestAPollReadsOnlyTheBytesAppended(t *testing.T) {
	tr, s, home := newTestTranscript(t)
	rel := ".claude/projects/-workspace/s-1.jsonl"
	appendTo(t, home, rel, []byte("{\"a\":1}\n{\"b\":"))
	tr.started("s-1")
	tr.poll(false)
	if err := os.WriteFile(filepath.Join(home, rel), []byte("{\"x\":9}\nXXXXX"), 0o644); err != nil {
		t.Fatal(err)
	}
	appendTo(t, home, rel, []byte("2}\n"))
	tr.poll(false)
	tr.finish()
	if got, ok := s.file(t, "~/"+rel); !ok || string(got) != "{\"a\":1}\n{\"b\":2}\n" || len(s.lines) != 0 {
		t.Errorf("sent %q %v, lines %q", got, ok, s.lines)
	}
}

// TestALineOverTheCapStopsTheTranscript pins a line over 8 MiB, whether the runtime has
// written its newline or not: the lines before it are sent, then one line on stderr,
// and nothing more.
func TestALineOverTheCapStopsTheTranscript(t *testing.T) {
	long := bytes.Repeat([]byte("x"), maxTranscriptLine+1)
	for name, tail := range map[string][]byte{"without its newline": long, "with its newline": append(slices.Clone(long), '\n')} {
		t.Run(name, func(t *testing.T) {
			tr, s, home := newTestTranscript(t)
			rel := ".claude/projects/-workspace/s-1.jsonl"
			appendTo(t, home, rel, append([]byte("{\"a\":1}\n"), tail...))
			tr.started("s-1")
			tr.poll(false)
			appendTo(t, home, rel, []byte("\n{\"c\":3}\n"))
			tr.finish()
			got, ok := s.file(t, "~/"+rel)
			want := "Keep each line of the transcript at most 8388608 bytes (8 MiB). A continuation of this run starts the runtime without a resume: a line of the transcript ~/" + rel + " is longer, so the session sends no more of it"
			if !ok || string(got) != "{\"a\":1}\n" || len(s.lines) != 1 || s.lines[0] != want {
				t.Errorf("sent %q %v, lines %q; want the first line and %q", got, ok, s.lines, want)
			}
		})
	}
}

// TestATranscriptOverTheLimitWithNoWallStops pins a transcript over 64 MiB with no
// wall: one line on stderr, and nothing sent, as behind a wall.
func TestATranscriptOverTheLimitWithNoWallStops(t *testing.T) {
	tr, s, home := newTestTranscript(t)
	rel := ".claude/projects/-workspace/s-1.jsonl"
	appendTo(t, home, rel, []byte("{\"a\":1}\n"))
	if err := os.Truncate(filepath.Join(home, rel), maxTranscript+1); err != nil {
		t.Fatal(err)
	}
	tr.started("s-1")
	tr.finish()
	if len(s.events) != 0 || len(s.lines) != 1 || !strings.HasSuffix(s.lines[0], ": it is over 67108864 bytes (64 MiB)") {
		t.Errorf("%d events, lines %q", len(s.events), s.lines)
	}
}

// TestARestoredTranscriptIsReadWithNoWall pins the session with no wall that restored a
// paused run's transcript: it reads the restored file from offset 0, whatever the
// working directory's slug, and a hook input that has the path of a file of another session id
// writes one line.
func TestARestoredTranscriptIsReadWithNoWall(t *testing.T) {
	tr, s, home := newTestTranscript(t)
	rel := ".claude/projects/-paused/s-1.jsonl"
	appendTo(t, home, rel, []byte("{\"restored\":1}\n"))
	tr.restore("s-1", rel)
	tr.record(runtimes.Record{Source: runtimes.SourceHooks, Record: map[string]any{"session_id": "s-1", "transcript_path": filepath.Join(home, ".claude/projects/-workspace/s-2.jsonl")}})
	tr.started("s-1")
	appendTo(t, home, rel, []byte("{\"appended\":2}\n"))
	tr.finish()
	if got, ok := s.file(t, "~/"+rel); !ok || string(got) != "{\"restored\":1}\n{\"appended\":2}\n" || len(s.lines) != 1 || !strings.HasPrefix(s.lines[0], "Check that the runtime resumes from ~/"+rel+". ") {
		t.Errorf("sent %q %v, lines %q", got, ok, s.lines)
	}
}

// TestTheLineOfKeptResumeArgumentsStartsWithTheFix pins the error of a launch the session
// cannot take its resume arguments off: the fix first, then the cause, then the guard.
func TestTheLineOfKeptResumeArgumentsStartsWithTheFix(t *testing.T) {
	got := resumeArgsKept("Make /home/dev a directory in the image", `"/home/dev" is a file in the image`)
	want := `Make /home/dev a directory in the image, then continue the paused run again: "/home/dev" is a file in the image. ` +
		"The session cannot take the resume arguments off the launch, because the launch has other arguments where they were added, which only a defect in Forager causes"
	if got != want {
		t.Errorf("the line:\n%s\nwant:\n%s", got, want)
	}
}

// TestTheEndOfATranscriptWaitsForItsReader pins the reader that start runs: end
// returns only once the reader returned, here after the read it was in, no read
// follows, and a second end does nothing.
func TestTheEndOfATranscriptWaitsForItsReader(t *testing.T) {
	tr, s, home := newTestTranscript(t)
	rel := ".claude/projects/-workspace/s-1.jsonl"
	tr.started("s-1")
	appendTo(t, home, rel, []byte("{\"a\":1}\n"))
	// With the lock held, the reader waits for it in a read.
	tr.mu.Lock()
	end := tr.start(time.Millisecond)
	deadline := time.Now().Add(10 * time.Second)
	for !slices.ContainsFunc(transcriptStacks(), func(g string) bool { return strings.Contains(g, "session.(*transcript).poll(") }) {
		if time.Now().After(deadline) {
			tr.mu.Unlock()
			t.Fatal("the reader started no read within 10 seconds")
		}
		time.Sleep(time.Millisecond)
	}
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		end()
	}()
	select {
	case <-ended:
		t.Error("end returned while the reader was in a read")
	case <-time.After(50 * time.Millisecond):
	}
	tr.mu.Unlock()
	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Fatal("end did not return within 10 seconds of the read's end")
	}
	if n := TranscriptReaders(); n != 0 {
		t.Fatalf("%d transcript readers after end", n)
	}
	if got, ok := s.file(t, "~/"+rel); !ok || string(got) != "{\"a\":1}\n" {
		t.Errorf("sent %q %v; want the line of the read", got, ok)
	}
	n := len(s.events)
	appendTo(t, home, rel, []byte("{\"b\":2}\n"))
	time.Sleep(20 * time.Millisecond)
	end()
	if len(s.events) != n {
		t.Errorf("%d events sent after end", len(s.events)-n)
	}
}

// TestATranscriptAtAFIFOIsNoRead pins a transcript path with no wall that leads to a
// FIFO with no writer: the read returns at once, sends nothing, and so cannot keep a
// join from returning.
func TestATranscriptAtAFIFOIsNoRead(t *testing.T) {
	tr, s, home := newTestTranscript(t)
	rel := ".claude/projects/-workspace/s-1.jsonl"
	if err := os.MkdirAll(filepath.Join(home, filepath.Dir(rel)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(home, rel), 0o600); err != nil {
		t.Fatal(err)
	}
	tr.started("s-1")
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.finish()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the read of a FIFO did not return within 10 seconds")
	}
	if len(s.events) != 0 {
		t.Errorf("%d events from a FIFO", len(s.events))
	}
}

// rolloutResume is a resume whose path has a * in three directory names and in the
// file's name, as Codex writes its rollouts, and whose arguments follow exec.
var rolloutResume = runtimes.Resume{Path: "~/.rollouts/sessions/*/*/*/rollout-*-{session_id}.jsonl", Prefix: "~/.rollouts/sessions/", Args: []string{"resume", "{session_id}"}, After: "exec"}

// rolloutRel is a file that rolloutResume's path matches for walledID, below the
// prefix.
const rolloutRel = "2026/11/13/rollout-2026-11-13T10-00-00-" + walledID + ".jsonl"

// TestAPathPatternMatchesInsideOneName pins the pattern of a resume.path: a * matches
// any characters inside one name and never a /, a name is never . or .., the session
// id is literal, a * in it included, and {cwd_slug} matches a slug alone when any slug
// is allowed.
func TestAPathPatternMatchesInsideOneName(t *testing.T) {
	below := strings.TrimPrefix(rolloutResume.Path, rolloutResume.Prefix)
	p := newPathPattern(below, walledID, "", false)
	for rel, want := range map[string]bool{
		rolloutRel:                                                        true,
		"x/y/z/rollout--" + walledID + ".jsonl":                           true,
		"2026/11/13/x/rollout-a-" + walledID + ".jsonl":                   false,
		"2026/11/rollout-a-" + walledID + ".jsonl":                        false,
		"../11/13/rollout-a-" + walledID + ".jsonl":                       false,
		"2026/./13/rollout-a-" + walledID + ".jsonl":                      false,
		"2026//13/rollout-a-" + walledID + ".jsonl":                       false,
		"2026/11/13/rollout-a-" + walledID + ".jsonl.bak":                 false,
		"2026/11/13/rollout-a-5d0c6a51-3b2e-4f7a-9c1d-8e6f4a2b0c37.jsonl": false,
		"2026/11/13/rollout" + walledID + ".jsonl":                        false,
	} {
		if got := p.matches(rel); got != want {
			t.Errorf("%s: %v; want %v", rel, got, want)
		}
	}
	if p.shown != "*/*/*/rollout-*-"+walledID+".jsonl" {
		t.Errorf("shown %q", p.shown)
	}
	for _, name := range []string{".", ".."} {
		if newPathPattern("*", "", "", false).matchName(0, name) {
			t.Errorf("* matches %q", name)
		}
	}
	literal := newPathPattern("{session_id}.jsonl", "a*b", "", false)
	if !literal.matches("a*b.jsonl") || literal.matches("axxb.jsonl") {
		t.Error("a * of the session id matches as a pattern")
	}
	slashed := newPathPattern("{session_id}.jsonl", "a/b", "", false)
	if slashed.matches("a/b.jsonl") {
		t.Error("a session id with / matches two names")
	}
	anySlug := newPathPattern("{cwd_slug}/{session_id}.jsonl", walledID, "", true)
	for rel, want := range map[string]bool{
		"-workspace/" + walledID + ".jsonl": true,
		"-paused/" + walledID + ".jsonl":    true,
		"we!rd/" + walledID + ".jsonl":      false,
		"../" + walledID + ".jsonl":         false,
		"-w/x/" + walledID + ".jsonl":       false,
		walledID + ".jsonl":                 false,
		"-workspace/probe.jsonl":            false,
	} {
		if got := anySlug.matches(rel); got != want {
			t.Errorf("any slug, %s: %v; want %v", rel, got, want)
		}
	}
}

// TestFindMatchesFollowsNoLink pins the search of a pattern: the files that match, at
// most two; a directory a * matches is followed only when it is a directory, never a
// symbolic link; the last name matches an entry of any type; a start below a link,
// and a start that does not exist, find nothing.
func TestFindMatchesFollowsNoLink(t *testing.T) {
	p := newPathPattern("*/*/*/rollout-*-{session_id}.jsonl", walledID, "", false)
	base := t.TempDir()
	if got, err := findMatches(base, "none/", p); err != nil || len(got) != 0 {
		t.Errorf("a start that does not exist: %v %v", got, err)
	}
	appendTo(t, base, "s/"+rolloutRel, []byte("{}\n"))
	appendTo(t, base, "s/2026/11/13/rollout-x-other.jsonl", []byte("{}\n"))
	if got, err := findMatches(base, "s/", p); err != nil || !slices.Equal(got, []string{rolloutRel}) {
		t.Errorf("one file: %v %v", got, err)
	}
	outside := t.TempDir()
	appendTo(t, outside, "11/13/rollout-y-"+walledID+".jsonl", []byte("{}\n"))
	symlink(t, outside, filepath.Join(base, "s", "2025"))
	if got, err := findMatches(base, "s/", p); err != nil || !slices.Equal(got, []string{rolloutRel}) {
		t.Errorf("through a linked directory: %v %v", got, err)
	}
	symlink(t, outside, filepath.Join(base, "linked"))
	if got, err := findMatches(base, "linked/", p); err == nil || len(got) != 0 {
		t.Errorf("a start below a link: %v %v", got, err)
	}
	symlink(t, filepath.Join(outside, "11/13/rollout-y-"+walledID+".jsonl"), filepath.Join(base, "s/2026/11/13/rollout-z-"+walledID+".jsonl"))
	got, err := findMatches(base, "s/", p)
	slices.Sort(got)
	if want := []string{rolloutRel, "2026/11/13/rollout-z-" + walledID + ".jsonl"}; err != nil || !slices.Equal(got, want) {
		t.Errorf("a link as the file: %v %v; want %v", got, err, want)
	}
	for i := range 3 {
		appendTo(t, base, fmt.Sprintf("s/2027/01/0%d/rollout-a-%s.jsonl", i, walledID), []byte("{}\n"))
	}
	if got, err := findMatches(base, "s/", p); err != nil || len(got) != 2 {
		t.Errorf("five files: %v %v; want two", got, err)
	}
}

// newRolloutTranscript is a transcript of rolloutResume, walled when walled is true,
// whose home or transcript directory is a new directory.
func newRolloutTranscript(t *testing.T, walled bool) (*transcript, *sentTranscript, string) {
	t.Helper()
	dir := t.TempDir()
	s := &sentTranscript{}
	mask := func(l string) string { return strings.ReplaceAll(l, "sk-fake-secret", "[secret]") }
	send, line := func(m map[string]any) { s.events = append(s.events, m) }, func(l string) { s.lines = append(s.lines, l) }
	if walled {
		return newWalledTranscript(rolloutResume, dir, "/workspace", mask, send, line), s, dir
	}
	return newTranscript(rolloutResume, dir, "/workspace", mask, send, line), s, dir
}

// TestATranscriptIsFoundByItsPattern pins a resume.path with a *, with a wall and
// without one: a read before the file exists finds nothing and writes no line; once the
// file exists the session reads it and sends it under its path, masked.
func TestATranscriptIsFoundByItsPattern(t *testing.T) {
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("walled ", walled), func(t *testing.T) {
			tr, s, dir := newRolloutTranscript(t, walled)
			below := rolloutRel
			if !walled {
				below = ".rollouts/sessions/" + rolloutRel
			}
			tr.started(walledID)
			tr.poll(false)
			appendTo(t, dir, below, []byte("{\"a\":\"sk-fake-secret\"}\n"))
			tr.poll(false)
			appendTo(t, dir, below, []byte("{\"b\":2}\n"))
			tr.finish()
			got, ok := s.file(t, "~/.rollouts/sessions/"+rolloutRel)
			if !ok || string(got) != "{\"a\":\"[secret]\"}\n{\"b\":2}\n" || len(s.lines) != 0 {
				t.Errorf("sent %q %v, lines %q", got, ok, s.lines)
			}
		})
	}
}

// TestATranscriptPatternWithTwoFilesReadsNone pins two files that match: one line, and
// nothing sent, with a wall and without one, also once one of them is gone.
func TestATranscriptPatternWithTwoFilesReadsNone(t *testing.T) {
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("walled ", walled), func(t *testing.T) {
			tr, s, dir := newRolloutTranscript(t, walled)
			at := ""
			if !walled {
				at = ".rollouts/sessions/"
			}
			appendTo(t, dir, at+rolloutRel, []byte("{\"a\":1}\n"))
			appendTo(t, dir, at+"2026/11/14/rollout-b-"+walledID+".jsonl", []byte("{\"b\":1}\n"))
			tr.started(walledID)
			tr.poll(false)
			if err := os.Remove(filepath.Join(dir, at+rolloutRel)); err != nil {
				t.Fatal(err)
			}
			tr.finish()
			want := "Keep one transcript of the runtime's session at ~/.rollouts/sessions/*/*/*/rollout-*-" + walledID + ".jsonl. A continuation of this run starts the runtime without a resume: more than one file matches it, so the session reads none of them"
			if len(s.events) != 0 || len(s.lines) != 1 || s.lines[0] != want {
				t.Errorf("%d events, lines %q; want %q", len(s.events), s.lines, want)
			}
		})
	}
}

// TestAWalledTranscriptPatternRefusesWhatTheAgentPlants pins the checks of a file a
// pattern found behind a wall, as for Claude Code's path: a symbolic link, a FIFO,
// which the session opens without blocking, a file with a second hard link, and one
// over 64 MiB each send nothing and write one line; a file below a linked directory
// is not found, and the end writes that no file matches.
func TestAWalledTranscriptPatternRefusesWhatTheAgentPlants(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret.jsonl")
	if err := os.WriteFile(outside, []byte("{\"host\":\"secret\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dirOf := filepath.Dir(rolloutRel)
	for name, c := range map[string]struct {
		plant func(t *testing.T, root string)
		want  string
	}{
		"a symbolic link": {func(t *testing.T, root string) {
			makeDir(t, filepath.Join(root, dirOf))
			symlink(t, outside, filepath.Join(root, rolloutRel))
		}, "the session reads no transcript at ~/.rollouts/sessions/" + rolloutRel + ": a name on its path is a symbolic link or no directory"},
		"a FIFO": {func(t *testing.T, root string) {
			makeDir(t, filepath.Join(root, dirOf))
			if err := syscall.Mkfifo(filepath.Join(root, rolloutRel), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "the session reads no transcript at ~/.rollouts/sessions/" + rolloutRel + ": it is no regular file"},
		"a hard link": {func(t *testing.T, root string) {
			makeDir(t, filepath.Join(root, dirOf))
			if err := os.Link(outside, filepath.Join(root, rolloutRel)); err != nil {
				t.Skip("no hard link between the test's directories:", err)
			}
		}, "the session reads no transcript at ~/.rollouts/sessions/" + rolloutRel + ": it has 2 hard links"},
		"a file over 64 MiB": {func(t *testing.T, root string) {
			makeDir(t, filepath.Join(root, dirOf))
			f, err := os.Create(filepath.Join(root, rolloutRel))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := f.Truncate(maxTranscript + 1); err != nil {
				t.Fatal(err)
			}
		}, "the session reads no transcript at ~/.rollouts/sessions/" + rolloutRel + ": it is over 67108864 bytes (64 MiB)"},
		"a linked directory": {func(t *testing.T, root string) {
			dir := t.TempDir()
			appendTo(t, dir, "13/"+filepath.Base(rolloutRel), []byte("{\"linked\":1}\n"))
			makeDir(t, filepath.Join(root, "2026"))
			symlink(t, dir, filepath.Join(root, "2026", "11"))
		}, "Check that the runtime writes its transcript at ~/.rollouts/sessions/*/*/*/rollout-*-" + walledID + ".jsonl. A continuation of this run starts the runtime without a resume: no file matches, so the session sent no transcript"},
	} {
		t.Run(name, func(t *testing.T) {
			tr, s, root := newRolloutTranscript(t, true)
			c.plant(t, root)
			tr.started(walledID)
			done := make(chan struct{})
			go func() {
				defer close(done)
				tr.poll(false)
				tr.finish()
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the read blocks")
			}
			if len(s.events) != 0 || len(s.lines) != 1 || !strings.Contains(s.lines[0], c.want) {
				t.Errorf("%d events, lines %q; want none and %q", len(s.events), s.lines, c.want)
			}
		})
	}
}

// TestAResumePathWithNoPathFromIgnoresHooks pins a resume with no path_from: a hook
// input's transcript_path sets nothing, and the session reads resume.path.
func TestAResumePathWithNoPathFromIgnoresHooks(t *testing.T) {
	tr, s, home := newRolloutTranscript(t, false)
	appendTo(t, home, ".rollouts/sessions/"+rolloutRel, []byte("{\"a\":1}\n"))
	appendTo(t, home, ".rollouts/sessions/hook.jsonl", []byte("{\"hook\":1}\n"))
	tr.record(hookRecord(walledID, filepath.Join(home, ".rollouts/sessions/hook.jsonl")))
	tr.started(walledID)
	tr.finish()
	if got, ok := s.file(t, "~/.rollouts/sessions/"+rolloutRel); !ok || string(got) != "{\"a\":1}\n" || len(s.lines) != 0 {
		t.Errorf("sent %q %v, lines %q", got, ok, s.lines)
	}
}

// TestTheSearchOpensNoFIFO pins the open of a directory in a search: a FIFO, and a
// link to one, at a name where a directory was listed fail the open at once, without a
// writer; a FIFO at a name of the start ends the search; and a walled transcript whose
// pattern reaches a FIFO ends, so the session can write its exit.
func TestTheSearchOpensNoFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink(t, fifo, filepath.Join(dir, "linked"))
	within := func(name string, f func()) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			defer close(done)
			f()
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s blocks", name)
		}
	}
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dirFD)
	for _, name := range []string{"fifo", "linked"} {
		within("the open of "+name, func() {
			if fd, err := openDirAt(dirFD, name); err == nil {
				unix.Close(fd)
				t.Errorf("%s opened as a directory", name)
			}
		})
	}
	p := newPathPattern("*/x.jsonl", walledID, "", false)
	for _, start := range []string{"fifo/", "linked/"} {
		within("the search from "+start, func() {
			if got, err := findMatches(dir, start, p); err == nil || len(got) != 0 {
				t.Errorf("%s: %v %v", start, got, err)
			}
		})
	}
	tr, s, root := newRolloutTranscript(t, true)
	if err := syscall.Mkfifo(filepath.Join(root, "2026"), 0o600); err != nil {
		t.Fatal(err)
	}
	tr.started(walledID)
	within("the transcript's end", func() {
		tr.poll(false)
		tr.finish()
	})
	if len(s.events) != 0 || len(s.lines) != 1 || !strings.Contains(s.lines[0], "no file matches") {
		t.Errorf("%d events, lines %q", len(s.events), s.lines)
	}
}

// TestAPatternPathWithASecretIsNotSent pins the path a * matched: a name with one of
// the run's secrets, or one that is no UTF-8, ends the transcript with one line that
// does not contain the path, and nothing is sent.
func TestAPatternPathWithASecretIsNotSent(t *testing.T) {
	for name, file := range map[string]string{
		"a secret": "rollout-sk-fake-secret-" + walledID + ".jsonl",
		"no UTF-8": "rollout-\xff\xfe-" + walledID + ".jsonl",
	} {
		t.Run(name, func(t *testing.T) {
			tr, s, root := newRolloutTranscript(t, true)
			makeDir(t, filepath.Join(root, "2026/11/13"))
			if err := os.WriteFile(filepath.Join(root, "2026/11/13", file), []byte("{\"a\":1}\n"), 0o600); err != nil {
				t.Skip("the file system takes no such name:", err)
			}
			tr.started(walledID)
			tr.finish()
			want := "Keep the run's secrets out of the names of the transcript's path, in UTF-8. A continuation of this run starts the runtime without a resume: the path of the file that matches ~/.rollouts/sessions/*/*/*/rollout-*-" + walledID + ".jsonl contains a secret or is no UTF-8, so the session reads no transcript"
			if len(s.events) != 0 || len(s.lines) != 1 || s.lines[0] != want {
				t.Errorf("%d events, lines %q; want %q", len(s.events), s.lines, want)
			}
		})
	}
}

// TestOnlyAPathWithNoSecretInUTF8IsSent pins the check of a path a * matched on
// every file system, one that takes names that are no UTF-8 included.
func TestOnlyAPathWithNoSecretInUTF8IsSent(t *testing.T) {
	mask := func(l string) string { return strings.ReplaceAll(l, "sk-fake-secret", "[secret]") }
	for rel, want := range map[string]bool{
		".rollouts/sessions/" + rolloutRel:                                      true,
		".rollouts/sessions/2026/11/13/rollout-sk-fake-secret-x.jsonl":          false,
		".rollouts/sessions/2026/11/13/rollout-\xff\xfe-" + walledID + ".jsonl": false,
	} {
		if got := sendablePath(rel, mask); got != want {
			t.Errorf("%q: %v; want %v", rel, got, want)
		}
	}
}

// TestASearchOverTheEntryCapEnds pins maxFindEntries: a search that lists more entries
// ends the transcript with one line, and nothing is sent.
func TestASearchOverTheEntryCapEnds(t *testing.T) {
	tr, s, root := newRolloutTranscript(t, true)
	for i := range maxFindEntries + 1 {
		f, err := os.Create(filepath.Join(root, fmt.Sprintf("e%05d", i)))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	tr.started(walledID)
	tr.finish()
	want := "Keep at most 10000 entries in the directories below ~/.rollouts/sessions/ that the transcript's pattern reaches. A continuation of this run starts the runtime without a resume: the search for ~/.rollouts/sessions/*/*/*/rollout-*-" + walledID + ".jsonl listed more, so the session reads no transcript"
	if len(s.events) != 0 || len(s.lines) != 1 || s.lines[0] != want {
		t.Errorf("%d events, lines %q; want %q", len(s.events), s.lines, want)
	}
}

// TestASearchSkipsADirectoryItCannotRead pins a directory whose open fails with
// EACCES: the search skips it and finds the file in another directory.
func TestASearchSkipsADirectoryItCannotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a directory of mode 0")
	}
	tr, s, root := newRolloutTranscript(t, true)
	appendTo(t, root, rolloutRel, []byte("{\"a\":1}\n"))
	closed := filepath.Join(root, "2025")
	makeDir(t, closed)
	if err := os.Chmod(closed, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(closed, 0o700) })
	tr.started(walledID)
	tr.finish()
	if got, ok := s.file(t, "~/.rollouts/sessions/"+rolloutRel); !ok || string(got) != "{\"a\":1}\n" || len(s.lines) != 0 {
		t.Errorf("sent %q %v, lines %q", got, ok, s.lines)
	}
}
