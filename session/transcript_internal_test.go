package session

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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
// working directory's slug, and a hook input that names a file of another session id
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
