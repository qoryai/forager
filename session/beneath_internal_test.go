package session

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/qoryai/forager/session/runtimes"
)

// walledID is a session id of the shape a walled transcript is read under.
const walledID = "0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e"

// walledRel is the transcript's path below a transcript directory for /workspace.
const walledRel = "-workspace/" + walledID + ".jsonl"

// newWalledTestTranscript is a walled transcript of Claude Code's resume whose
// transcript directory is a new directory, working in /workspace inside.
func newWalledTestTranscript(t *testing.T) (*transcript, *sentTranscript, string) {
	t.Helper()
	root := t.TempDir()
	s := &sentTranscript{}
	mask := func(l string) string { return strings.ReplaceAll(l, "sk-fake-secret", "[secret]") }
	tr := newWalledTranscript(claudeResume, root, "/workspace", mask, func(m map[string]any) { s.events = append(s.events, m) }, func(l string) { s.lines = append(s.lines, l) })
	return tr, s, root
}

// TestAWalledTranscriptIsReadBelowItsDirectory pins the read behind a wall: the file
// <slug>/<session id>.jsonl below the transcript directory, sent under the path
// ~/.claude/projects/<slug>/<session id>.jsonl, a hook's transcript_path left unread.
func TestAWalledTranscriptIsReadBelowItsDirectory(t *testing.T) {
	tr, s, root := newWalledTestTranscript(t)
	appendTo(t, root, walledRel, []byte("{\"a\":\"sk-fake-secret\"}\n"))
	appendTo(t, root, "-elsewhere/"+walledID+".jsonl", []byte("{\"hook\":1}\n"))
	tr.record(hookRecord(walledID, filepath.Join(root, "-elsewhere", walledID+".jsonl")))
	tr.finish()
	got, ok := s.file(t, "~/.claude/projects/"+walledRel)
	if !ok || string(got) != "{\"a\":\"[secret]\"}\n" || len(s.lines) != 0 {
		t.Errorf("sent %q %v, lines %q", got, ok, s.lines)
	}
}

// TestAWalledTranscriptReadsNoOtherSessionID pins a session id that is not a UUID in
// lower case: one line, and nothing read, also once a later id is one.
func TestAWalledTranscriptReadsNoOtherSessionID(t *testing.T) {
	for _, id := range []string{"probe", "../x", strings.ToUpper(walledID), walledID + "/x", "a\nA continuation" + strings.Repeat("x", 100)} {
		tr, s, root := newWalledTestTranscript(t)
		appendTo(t, root, walledRel, []byte("{\"a\":1}\n"))
		tr.started(id)
		tr.started(walledID)
		tr.finish()
		if len(s.events) != 0 || len(s.lines) != 1 || !strings.Contains(s.lines[0], "is not a UUID in lower case") || strings.Contains(s.lines[0], "\n") || len(s.lines[0]) > 300 {
			t.Errorf("%q: %d events, lines %q", id, len(s.events), s.lines)
		}
	}
}

// TestAWalledTranscriptRefusesWhatTheAgentPlants pins each file the session does not
// read: a symbolic link as the file or as the slug directory, a FIFO, which it opens
// without blocking, a file with a second hard link, and one over 64 MiB. Each sends
// nothing and writes one line, once.
func TestAWalledTranscriptRefusesWhatTheAgentPlants(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret.jsonl")
	if err := os.WriteFile(outside, []byte("{\"host\":\"secret\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		plant func(t *testing.T, root string)
		why   string
	}{
		"a symbolic link": {func(t *testing.T, root string) {
			makeDir(t, filepath.Join(root, "-workspace"))
			symlink(t, outside, filepath.Join(root, walledRel))
		}, "a name on its path is a symbolic link or no directory"},
		"a linked slug directory": {func(t *testing.T, root string) {
			dir := t.TempDir()
			appendTo(t, dir, walledID+".jsonl", []byte("{\"linked\":1}\n"))
			symlink(t, dir, filepath.Join(root, "-workspace"))
		}, "a name on its path is a symbolic link or no directory"},
		"a FIFO": {func(t *testing.T, root string) {
			makeDir(t, filepath.Join(root, "-workspace"))
			if err := syscall.Mkfifo(filepath.Join(root, walledRel), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "it is no regular file"},
		"a hard link": {func(t *testing.T, root string) {
			makeDir(t, filepath.Join(root, "-workspace"))
			if err := os.Link(outside, filepath.Join(root, walledRel)); err != nil {
				t.Skip("no hard link between the test's directories:", err)
			}
		}, "it has 2 hard links"},
		"a file over 64 MiB": {func(t *testing.T, root string) {
			makeDir(t, filepath.Join(root, "-workspace"))
			f, err := os.Create(filepath.Join(root, walledRel))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := f.Truncate(maxTranscript + 1); err != nil {
				t.Fatal(err)
			}
		}, "it is over 67108864 bytes (64 MiB)"},
	} {
		t.Run(name, func(t *testing.T) {
			tr, s, root := newWalledTestTranscript(t)
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
			want := ". A continuation of this run starts the runtime without a resume: the session reads no transcript at ~/.claude/projects/" + walledRel + ": " + c.why
			if len(s.events) != 0 || len(s.lines) != 1 || !strings.Contains(s.lines[0], want) || strings.HasPrefix(s.lines[0], ".") {
				t.Errorf("%d events, lines %q; want none and %q", len(s.events), s.lines, want)
			}
		})
	}
}

// TestAWalledTranscriptNotThereYetIsReadLater pins a file that does not exist yet: no
// line, and the file read once it exists.
func TestAWalledTranscriptNotThereYetIsReadLater(t *testing.T) {
	tr, s, root := newWalledTestTranscript(t)
	tr.started(walledID)
	tr.poll(false)
	appendTo(t, root, walledRel, []byte("{\"a\":1}\n"))
	tr.finish()
	if got, ok := s.file(t, "~/.claude/projects/"+walledRel); !ok || string(got) != "{\"a\":1}\n" || len(s.lines) != 0 {
		t.Errorf("sent %q %v, lines %q", got, ok, s.lines)
	}
}

// TestWriteBeneathCreatesTheFileOnce pins the restore's write: the slug directory and
// the file made, modes 0700 and 0600; a file that exists, a linked slug directory and
// a path of another shape are refused, and nothing is written through a link.
func TestWriteBeneathCreatesTheFileOnce(t *testing.T) {
	root := t.TempDir()
	if err := writeBeneath(root, walledRel, []byte("ok\n")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, walledRel))
	if err != nil || string(b) != "ok\n" {
		t.Fatalf("the file %q %v", b, err)
	}
	for p, want := range map[string]fs.FileMode{"-workspace": 0o700, walledRel: 0o600} {
		if fi, err := os.Stat(filepath.Join(root, p)); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v %v; want mode %v", p, fi, err, want)
		}
	}
	if err := writeBeneath(root, walledRel, []byte("again\n")); err == nil {
		t.Error("a file that exists was written again")
	}
	linked := t.TempDir()
	symlink(t, linked, filepath.Join(root, "-linked"))
	if err := writeBeneath(root, "-linked/"+walledID+".jsonl", []byte("x")); !errors.Is(err, errBeneathLinked) {
		t.Errorf("through a linked slug directory: %v", err)
	}
	target := filepath.Join(t.TempDir(), "target")
	makeDir(t, filepath.Join(root, "-file"))
	symlink(t, target, filepath.Join(root, "-file", walledID+".jsonl"))
	if err := writeBeneath(root, "-file/"+walledID+".jsonl", []byte("x")); err == nil {
		t.Error("a link as the file was written through")
	}
	if entries, _ := os.ReadDir(linked); len(entries) != 0 {
		t.Errorf("written through the link: %v", entries)
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("the link's target was created")
	}
	for _, rel := range []string{"../x/" + walledID + ".jsonl", "-workspace/probe.jsonl", walledID + ".jsonl", "-w/x/" + walledID + ".jsonl"} {
		if err := writeBeneath(root, rel, []byte("x")); err == nil {
			t.Errorf("%s was written", rel)
		}
	}
}

// hookRecord is a hook input with the session id and the transcript path.
func hookRecord(id, path string) runtimes.Record {
	return runtimes.Record{Source: runtimes.SourceHooks, Record: map[string]any{"session_id": id, "transcript_path": path}}
}

func makeDir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, to, at string) {
	t.Helper()
	if err := os.Symlink(to, at); err != nil {
		t.Fatal(err)
	}
}

// TestAWalledTranscriptNeverWrittenWritesALine pins a walled session whose runtime
// wrote no transcript by its end: one line on stderr, so the operator can read that no
// transcript was sent.
func TestAWalledTranscriptNeverWrittenWritesALine(t *testing.T) {
	tr, s, _ := newWalledTestTranscript(t)
	tr.started(walledID)
	tr.poll(false)
	tr.finish()
	want := "Check that the runtime writes its transcript at ~/.claude/projects/" + walledRel + ". A continuation of this run starts the runtime without a resume: the file does not exist, so the session sent no transcript"
	if len(s.events) != 0 || len(s.lines) != 1 || s.lines[0] != want {
		t.Errorf("%d events, lines %q; want %q", len(s.events), s.lines, want)
	}
}

// TestAWalledRestoredTranscriptIsReadUnderThePausedRunsSlug pins the session that
// restored a paused run's transcript: it reads the restored file, under the paused run's
// slug, from offset 0, not the file under its working directory's slug. A hook input
// whose transcript path has the restored file's name agrees, under any slug; one that
// is the path of a file of another session id writes one line, once, and the session goes on
// reading the restored file.
func TestAWalledRestoredTranscriptIsReadUnderThePausedRunsSlug(t *testing.T) {
	paused := "-paused/" + walledID + ".jsonl"
	for name, c := range map[string]struct {
		hook string
		line bool
	}{
		"no hook path":       {"", false},
		"the restored file":  {"/home/agent/.claude/projects/" + paused, false},
		"another slug":       {"/home/agent/.claude/projects/" + walledRel, false},
		"another session id": {"/home/agent/.claude/projects/-paused/5d0c6a51-3b2e-4f7a-9c1d-8e6f4a2b0c37.jsonl", true},
	} {
		t.Run(name, func(t *testing.T) {
			tr, s, root := newWalledTestTranscript(t)
			appendTo(t, root, paused, []byte("{\"restored\":1}\n"))
			appendTo(t, root, walledRel, []byte("{\"other\":1}\n"))
			tr.restore(walledID, ".claude/projects/"+paused)
			tr.started(walledID)
			if c.hook != "" {
				tr.record(hookRecord(walledID, c.hook))
				tr.record(hookRecord(walledID, c.hook))
			}
			tr.poll(false)
			appendTo(t, root, paused, []byte("{\"appended\":2}\n"))
			tr.finish()
			got, ok := s.file(t, "~/.claude/projects/"+paused)
			if !ok || string(got) != "{\"restored\":1}\n{\"appended\":2}\n" {
				t.Errorf("sent %q %v; want the restored line and the appended one", got, ok)
			}
			if c.line != (len(s.lines) == 1) || len(s.lines) > 1 || (c.line && !strings.HasPrefix(s.lines[0], "Check that the runtime resumes from ~/.claude/projects/"+paused+". ")) {
				t.Errorf("lines %q", s.lines)
			}
		})
	}
}
