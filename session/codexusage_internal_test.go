package session

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/qoryai/forager/session/runtimes/codex"
)

// The fixture of Codex 0.167.2's rollouts: launch 1's thread and its child, and
// launch 2's thread, launch 1's restored file with a turn appended
// (runtimes/codex/testdata/usage).
const (
	fixtureThread = "01a1f100-87f8-7123-a174-ba291730eec1"
	fixtureChild  = "01a1f100-885b-7140-a145-b604ffe0117a"
	fixtureDir    = "runtimes/codex/testdata/usage"
)

// The usage of launch 1 and launch 2 by the stub's numbers, as
// runtimes/codex/rollout_test.go derives them.
var (
	launch1Usage = map[string]any{"input": int64(2222), "output": int64(4444), "cache_read": int64(1111), "cache_write": int64(2222)}
	launch2Usage = map[string]any{"input": int64(20000), "output": int64(40000), "cache_read": int64(10000), "cache_write": int64(20000)}
)

// fixture reads the fixture's file name.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rolloutAt is the path below the prefix at which Codex writes the rollout of thread.
func rolloutAt(thread string) string {
	return "2026/11/18/rollout-2026-11-18T23-31-46-" + thread + ".jsonl"
}

// childAt is the path below the prefix of the fixture's child rollout.
const childAt = "2026/11/19/rollout-2026-11-19T00-00-00-" + fixtureChild + ".jsonl"

// codexUsageTranscript is a transcript of [rolloutResume] with a wall or without one,
// and the directory below which the files below the prefix go.
func codexUsageTranscript(t *testing.T, walled bool) (*transcript, *sentTranscript, string) {
	t.Helper()
	tr, s, dir := newRolloutTranscript(t, walled)
	if !walled {
		dir = filepath.Join(dir, ".rollouts", "sessions")
	}
	return tr, s, dir
}

// launch2Tail is what launch 2 appends to launch 1's file.
func launch2Tail(t *testing.T) []byte {
	t.Helper()
	return fixture(t, "launch2-parent-rollout.jsonl")[len(fixture(t, "launch1-parent-rollout.jsonl")):]
}

// checkLines fails the test unless s has one line per fix of fixes, in order, each
// with the fix and a period as its first line, of at most 100 characters.
func checkLines(t *testing.T, s *sentTranscript, fixes ...string) {
	t.Helper()
	if len(s.lines) != len(fixes) {
		t.Fatalf("lines %q; want %d", s.lines, len(fixes))
	}
	for i, l := range s.lines {
		first, _, _ := strings.Cut(l, "\n")
		if first != fixes[i]+"." || len(first) > 100 {
			t.Errorf("line %q; want the first line %q., at most 100 characters", l, fixes[i])
		}
	}
}

// TestCodexUsageReadsTheFixturesRollouts pins the usage of the fixture's two launches
// read from files below the prefix, with a wall and without one: launch 1 is the
// thread plus its child; launch 2 is the thread less its bytes before the launch,
// launch 1's file, whether the session restored it or it was there, and launch 1's
// child in the same folder adds nothing. A rollout of another thread, a file of
// another shape and a directory of another name count for nothing. Without a wall, a
// restored file that the resume script copies after the baseline has the restored
// length as its baseline.
func TestCodexUsageReadsTheFixturesRollouts(t *testing.T) {
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("walled ", walled), func(t *testing.T) {
			tr, s, dir := codexUsageTranscript(t, walled)
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(fixtureThread), fixture(t, "launch1-parent-rollout.jsonl"))
			appendTo(t, dir, childAt, fixture(t, "launch1-child-rollout.jsonl"))
			appendTo(t, dir, rolloutAt(walledID), []byte(`{"type":"session_meta","payload":{"id":"`+walledID+`"}}`+"\n"+
				`{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":7}}}}`+"\n"))
			appendTo(t, dir, "2026/11/18/notes.txt", []byte("x\n"))
			if got := tr.codexUsage(fixtureThread); !reflect.DeepEqual(got, launch1Usage) || len(s.lines) != 0 {
				t.Errorf("launch 1's usage %v, lines %q; want %v", got, s.lines, launch1Usage)
			}

			// Launch 2 in the same folder: launch 1's child is there before the launch.
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(fixtureThread), launch2Tail(t))
			if got := tr.codexUsage(fixtureThread); !reflect.DeepEqual(got, launch2Usage) || len(s.lines) != 0 {
				t.Errorf("launch 2 with launch 1's child: usage %v, lines %q; want %v", got, s.lines, launch2Usage)
			}

			// Launch 2 in a new folder, launch 1's file there before the launch: a
			// resume with no restore, or a restore behind a wall.
			tr, s, dir = codexUsageTranscript(t, walled)
			appendTo(t, dir, rolloutAt(fixtureThread), fixture(t, "launch1-parent-rollout.jsonl"))
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(fixtureThread), launch2Tail(t))
			if got := tr.codexUsage(fixtureThread); !reflect.DeepEqual(got, launch2Usage) || len(s.lines) != 0 {
				t.Errorf("launch 2: usage %v, lines %q; want %v", got, s.lines, launch2Usage)
			}
			if walled {
				return
			}

			// Without a wall the resume script copies the restored file after the
			// baseline, over an older copy or where none is.
			for _, older := range []bool{false, true} {
				tr, s, dir = codexUsageTranscript(t, false)
				if older {
					appendTo(t, dir, rolloutAt(fixtureThread), fixture(t, "launch1-parent-rollout.jsonl"))
				}
				launch1 := fixture(t, "launch1-parent-rollout.jsonl")
				tr.codexBaseline(&restored{sessionID: fixtureThread, rel: ".rollouts/sessions/" + rolloutAt(fixtureThread), size: int64(len(launch1))})
				if err := os.MkdirAll(filepath.Join(dir, "2026", "11", "18"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, rolloutAt(fixtureThread)), fixture(t, "launch2-parent-rollout.jsonl"), 0o644); err != nil {
					t.Fatal(err)
				}
				if got := tr.codexUsage(fixtureThread); !reflect.DeepEqual(got, launch2Usage) || len(s.lines) != 0 {
					t.Errorf("launch 2 copied, an older copy %v: usage %v, lines %q; want %v", older, got, s.lines, launch2Usage)
				}
			}
		})
	}
}

// meta is a session_meta line of id with parent.
func meta(id, parent string) string {
	return fmt.Sprintf(`{"type":"session_meta","payload":{"id":%q,"parent_thread_id":%q}}`+"\n", id, parent)
}

// count is a token_count line with the input 5n, cached n, cache write 2n and output
// 4n.
func count(n int) string {
	return fmt.Sprintf(`{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":%d,"cached_input_tokens":%d,"cache_write_input_tokens":%d,"output_tokens":%d}}}}`+"\n", 5*n, n, 2*n, 4*n)
}

// usage is the usage of count(n): 2n, 4n, n and 2n.
func usage(n int64) map[string]any {
	return map[string]any{"input": 2 * n, "output": 4 * n, "cache_read": n, "cache_write": 2 * n}
}

// TestCodexUsageCases pins a child whose file is missing, a child of a child, a child
// the launch continued, which adds its tokens since the baseline, a child replaced or
// shorter than its baseline, which adds all of its total, a child whose id or parent
// id is longer than 128 bytes, which counts for nothing, and a thread with no
// token_count, for which the usage is nil with no line; and a thread with no rollout,
// a thread id of another shape behind a wall, and an empty id, for which it is nil.
func TestCodexUsageCases(t *testing.T) {
	const child, grandchild = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	long := strings.Repeat("a", maxSessionID+1)
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("walled ", walled), func(t *testing.T) {
			tr, s, dir := codexUsageTranscript(t, walled)
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")+count(1)))
			appendTo(t, dir, rolloutAt(grandchild), []byte(meta(grandchild, child)+count(100)))
			if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, usage(1)) || len(s.lines) != 0 {
				t.Errorf("a missing child: usage %v, lines %q; want %v", got, s.lines, usage(1))
			}
			appendTo(t, dir, rolloutAt(child), []byte(meta(child, walledID)+count(10)))
			if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, usage(111)) || len(s.lines) != 0 {
				t.Errorf("a child of a child: usage %v, lines %q; want %v", got, s.lines, usage(111))
			}
			appendTo(t, dir, rolloutAt(long), []byte(meta(long, walledID)+count(1000)))
			appendTo(t, dir, rolloutAt("c-of-long"), []byte(meta("c-of-long", long)+count(1000)))
			appendTo(t, dir, rolloutAt("c-long-parent"), []byte(meta("c-long-parent", walledID+long)+count(1000)))
			if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, usage(111)) || len(s.lines) != 0 {
				t.Errorf("ids over 128 bytes: usage %v, lines %q; want %v", got, s.lines, usage(111))
			}

			// The next launch continues the child: it adds its tokens since the
			// baseline, the thread and the grandchild nothing.
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(walledID), []byte(count(1)))
			appendTo(t, dir, rolloutAt(child), []byte(count(13)))
			if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, usage(3)) || len(s.lines) != 0 {
				t.Errorf("a continued child: usage %v, lines %q; want %v", got, s.lines, usage(3))
			}

			// A child replaced, and a child shorter than its baseline, add all of
			// their total.
			tr.codexBaseline(nil)
			p := filepath.Join(dir, rolloutAt(child))
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			appendTo(t, dir, rolloutAt(child), []byte(meta(child, walledID)+count(20)))
			if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, usage(20)) || len(s.lines) != 0 {
				t.Errorf("a replaced child: usage %v, lines %q; want %v", got, s.lines, usage(20))
			}
			appendTo(t, dir, rolloutAt(child), []byte(count(30)))
			tr.codexBaseline(nil)
			if err := os.Truncate(p, int64(len(meta(child, walledID)+count(20)))); err != nil {
				t.Fatal(err)
			}
			if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, usage(20)) || len(s.lines) != 0 {
				t.Errorf("a shorter child: usage %v, lines %q; want %v", got, s.lines, usage(20))
			}

			tr, s, dir = codexUsageTranscript(t, walled)
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")))
			if got := tr.codexUsage(walledID); got != nil || len(s.lines) != 0 {
				t.Errorf("no token_count: usage %v, lines %q; want none", got, s.lines)
			}
			if got := tr.codexUsage(child); got != nil {
				t.Errorf("no rollout: usage %v", got)
			}
			checkLines(t, s, fixThreadMissing)
			if !strings.Contains(s.lines[0], "no file matches ~/.rollouts/sessions/*/*/*/rollout-*-"+child+".jsonl") {
				t.Errorf("no rollout: line %q", s.lines[0])
			}
			s.lines = nil
			if got := tr.codexUsage(""); got != nil || len(s.lines) != 0 {
				t.Errorf("no thread: usage %v, lines %q", got, s.lines)
			}
			if walled {
				if got := tr.codexUsage("Not-A-UUID"); got != nil || len(s.lines) != 0 {
					t.Errorf("an id of another shape: usage %v, lines %q", got, s.lines)
				}
			}
		})
	}
}

// sparse makes the file at rel below dir: the line first, then zeros up to size
// bytes, which take no space on disk.
func sparse(t *testing.T, dir, rel, first string, size int64) {
	t.Helper()
	appendTo(t, dir, rel, []byte(first))
	if err := os.Truncate(filepath.Join(dir, rel), size); err != nil {
		t.Fatal(err)
	}
}

// usageWithin is tr.codexUsage of the fixture's thread, which fails the test unless it
// returns within 10 seconds.
func usageWithin(t *testing.T, tr *transcript) map[string]any {
	t.Helper()
	done := make(chan map[string]any)
	go func() { done <- tr.codexUsage(fixtureThread) }()
	select {
	case got := <-done:
		return got
	case <-time.After(10 * time.Second):
		t.Fatal("the read did not return within 10 seconds")
		return nil
	}
}

// TestCodexUsageRefusesWhatTheAgentPlants pins the checks of the files the session
// reads in full, the thread's rollout and its child agents', with a wall and without
// one: a symbolic link, a FIFO, which the session opens without blocking, a file with
// a second hard link behind a wall, and a file over 64 MiB. For each the usage is nil,
// and the session writes one line that starts with the fix.
func TestCodexUsageRefusesWhatTheAgentPlants(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.jsonl")
	if err := os.WriteFile(outside, fixture(t, "launch1-parent-rollout.jsonl"), 0o600); err != nil {
		t.Fatal(err)
	}
	thread, child := filepath.FromSlash(rolloutAt(fixtureThread)), filepath.FromSlash(childAt)
	for name, c := range map[string]struct {
		plant  func(t *testing.T, dir string)
		walled bool // only behind a wall
		fix    string
	}{
		"the thread a link": {plant: func(t *testing.T, dir string) {
			if err := os.Symlink(outside, filepath.Join(dir, thread)); err != nil {
				t.Fatal(err)
			}
		}, fix: fixRolloutLinked},
		"the thread a FIFO": {plant: func(t *testing.T, dir string) {
			if err := unix.Mkfifo(filepath.Join(dir, thread), 0o600); err != nil {
				t.Fatal(err)
			}
		}, fix: fixRolloutLinked},
		"the thread with a hard link": {plant: func(t *testing.T, dir string) {
			appendTo(t, dir, thread, fixture(t, "launch1-parent-rollout.jsonl"))
			if err := os.Link(filepath.Join(dir, thread), filepath.Join(dir, "2026", "11", "18", "other")); err != nil {
				t.Fatal(err)
			}
		}, walled: true, fix: fixRolloutHardLinks},
		"the thread over 64 MiB": {plant: func(t *testing.T, dir string) {
			sparse(t, dir, thread, meta(fixtureThread, ""), maxTranscript+1)
		}, fix: fixRolloutSize},
		"a child with a hard link": {plant: func(t *testing.T, dir string) {
			appendTo(t, dir, thread, fixture(t, "launch1-parent-rollout.jsonl"))
			appendTo(t, dir, child, fixture(t, "launch1-child-rollout.jsonl"))
			if err := os.Link(filepath.Join(dir, child), filepath.Join(dir, "2026", "11", "19", "other")); err != nil {
				t.Fatal(err)
			}
		}, walled: true, fix: fixRolloutHardLinks},
		"a child over 64 MiB": {plant: func(t *testing.T, dir string) {
			appendTo(t, dir, thread, fixture(t, "launch1-parent-rollout.jsonl"))
			sparse(t, dir, child, meta(fixtureChild, fixtureThread), maxTranscript+1)
		}, fix: fixRolloutSize},
	} {
		for _, walled := range []bool{false, true} {
			if c.walled && !walled {
				continue
			}
			t.Run(fmt.Sprint(name, ", walled ", walled), func(t *testing.T) {
				tr, s, dir := codexUsageTranscript(t, walled)
				tr.codexBaseline(nil)
				if err := os.MkdirAll(filepath.Join(dir, "2026", "11", "18"), 0o755); err != nil {
					t.Fatal(err)
				}
				c.plant(t, dir)
				if got := usageWithin(t, tr); got != nil {
					t.Errorf("usage %v; want none", got)
				}
				checkLines(t, s, c.fix)
				if !strings.Contains(s.lines[0], "The session wrote no usage in the launch's dev.qory.runtime.result: ") {
					t.Errorf("line %q", s.lines[0])
				}
			})
		}
	}
}

// TestCodexUsageSkipsTheOtherFiles pins a shared folder with the fixture's launch 1
// and files that are no rollout of the launch, with a wall and without one: a symbolic
// link, a FIFO, a rollout of another thread over 64 MiB, 300 rollouts of other
// threads, and 300 child rollouts of an earlier launch that did not change, one of
// them over 64 MiB, over the caps together. The session skips them, and the usage is
// launch 1's with no line.
func TestCodexUsageSkipsTheOtherFiles(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.jsonl")
	if err := os.WriteFile(outside, []byte(meta(fixtureChild, fixtureThread)+count(1000)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("walled ", walled), func(t *testing.T) {
			tr, s, dir := codexUsageTranscript(t, walled)
			for i := range 300 {
				appendTo(t, dir, fmt.Sprintf("2026/11/17/rollout-%d-earlier-%d.jsonl", i, i), []byte(meta(fmt.Sprint("earlier-", i), fixtureThread)+count(1000)))
			}
			sparse(t, dir, "2026/11/17/rollout-big-earlier.jsonl", meta("big-earlier", fixtureThread), maxTranscript+1)
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(fixtureThread), fixture(t, "launch1-parent-rollout.jsonl"))
			appendTo(t, dir, childAt, fixture(t, "launch1-child-rollout.jsonl"))
			if err := os.Symlink(outside, filepath.Join(dir, "2026", "11", "19", "rollout-link-x.jsonl")); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(filepath.Join(dir, "2026", "11", "19", "rollout-fifo-x.jsonl"), 0o600); err != nil {
				t.Fatal(err)
			}
			sparse(t, dir, "2026/11/19/rollout-big-x.jsonl", meta("big-other", ""), 65<<20)
			for i := range 300 {
				appendTo(t, dir, fmt.Sprintf("2026/11/20/rollout-%d-x.jsonl", i), []byte(meta(fmt.Sprint("other-", i), "")+count(1000)))
			}
			if got := usageWithin(t, tr); !reflect.DeepEqual(got, launch1Usage) || len(s.lines) != 0 {
				t.Errorf("usage %v, lines %q; want %v", got, s.lines, launch1Usage)
			}
		})
	}
}

// TestCodexUsageCapsTheFilesReadInFull pins the caps on the thread's rollout and its
// child agents' that changed during the launch, with a wall and without one: more than
// 256 files, and more than 256 MiB together, each file at most 64 MiB. For each the
// usage is nil and the session writes one line, before it reads a file in full.
func TestCodexUsageCapsTheFilesReadInFull(t *testing.T) {
	for name, c := range map[string]struct {
		plant func(t *testing.T, dir string)
		fix   string
	}{
		"257 files": {plant: func(t *testing.T, dir string) {
			for i := range maxRollouts {
				appendTo(t, dir, fmt.Sprintf("2026/11/20/rollout-%d-x.jsonl", i), []byte(meta(fmt.Sprint("child-", i), fixtureThread)+count(1)))
			}
		}, fix: fixRolloutCount},
		"over 256 MiB": {plant: func(t *testing.T, dir string) {
			for i := range 4 {
				sparse(t, dir, fmt.Sprintf("2026/11/20/rollout-%d-x.jsonl", i), meta(fmt.Sprint("child-", i), fixtureThread), maxTranscript)
			}
		}, fix: fixRolloutBytes},
	} {
		for _, walled := range []bool{false, true} {
			t.Run(fmt.Sprint(name, ", walled ", walled), func(t *testing.T) {
				tr, s, dir := codexUsageTranscript(t, walled)
				tr.codexBaseline(nil)
				appendTo(t, dir, rolloutAt(fixtureThread), fixture(t, "launch1-parent-rollout.jsonl"))
				c.plant(t, dir)
				if got := usageWithin(t, tr); got != nil {
					t.Errorf("usage %v; want none", got)
				}
				checkLines(t, s, c.fix)
			})
		}
	}
}

// TestCodexUsageNeedsItsBaseline pins a baseline whose search listed more than 10000
// entries behind a wall: the usage at the end is nil, with the baseline's line, even
// once the entries are gone.
func TestCodexUsageNeedsItsBaseline(t *testing.T) {
	tr, s, dir := codexUsageTranscript(t, true)
	extra := filepath.Join(dir, "2026", "11", "20")
	for i := range maxFindEntries {
		appendTo(t, dir, fmt.Sprintf("2026/11/20/f%d", i), nil)
	}
	tr.codexBaseline(nil)
	if err := os.RemoveAll(extra); err != nil {
		t.Fatal(err)
	}
	appendTo(t, dir, rolloutAt(fixtureThread), fixture(t, "launch1-parent-rollout.jsonl"))
	if got := tr.codexUsage(fixtureThread); got != nil {
		t.Errorf("usage %v; want none", got)
	}
	checkLines(t, s, fixRolloutEntries)
	if !strings.Contains(s.lines[0], "the search before the launch listed more than 10000 entries below ~/.rollouts/sessions/") {
		t.Errorf("line %q", s.lines[0])
	}
}

// TestCodexUsageRefusesACountAbove2To53 pins a child's count above 2^53, and a sum of
// two children's counts above 2^53: the usage is nil, with one line.
func TestCodexUsageRefusesACountAbove2To53(t *testing.T) {
	out := func(n string) string {
		return `{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"output_tokens":` + n + `}}}}` + "\n"
	}
	for name, n := range map[string]string{"a count": "4611686018427387904", "a sum": "4503599627370497"} {
		t.Run(name, func(t *testing.T) {
			tr, s, dir := codexUsageTranscript(t, true)
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")+count(1)))
			appendTo(t, dir, rolloutAt("c1"), []byte(meta("c1", walledID)+out(n)))
			appendTo(t, dir, rolloutAt("c2"), []byte(meta("c2", walledID)+out(n)))
			if got := tr.codexUsage(walledID); got != nil {
				t.Errorf("usage %v; want none", got)
			}
			checkLines(t, s, fixRolloutCounts)
		})
	}
}

// TestCodexUsageClampsACountBelowZero pins a total whose cached tokens exceed its
// input tokens: input 0, and one line that no action is needed.
func TestCodexUsageClampsACountBelowZero(t *testing.T) {
	tr, s, dir := codexUsageTranscript(t, true)
	tr.codexBaseline(nil)
	appendTo(t, dir, rolloutAt(walledID), []byte(`{"type":"session_meta","payload":{"id":"`+walledID+`"}}`+"\n"+
		`{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":2,"cached_input_tokens":3,"output_tokens":1}}}}`+"\n"))
	want := map[string]any{"input": int64(0), "output": int64(1), "cache_read": int64(3), "cache_write": int64(0)}
	if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, want) {
		t.Errorf("usage %v; want %v", got, want)
	}
	checkLines(t, s, "No action needed")
}

// TestCodexUsageLinesStartWithTheFix pins each line of a launch whose result has no
// usage: the fix and a period on the first line, at most 100 characters, the cause on
// the second, and the numbers of the fixes those of the caps.
func TestCodexUsageLinesStartWithTheFix(t *testing.T) {
	fixes := []string{fixRolloutEntries, fixRolloutFolders, fixRolloutCount, fixRolloutBytes, fixRolloutLinked, fixRolloutHardLinks,
		fixRolloutSize, fixRolloutRead, fixThreadOne, fixThreadShape, fixThreadMissing, fixRolloutDepth, fixRolloutCounts, fixNoTranscript}
	for _, fix := range fixes {
		l := noUsage(fix, "a cause")
		first, second, ok := strings.Cut(l, "\n")
		if !ok || len(first) > 100 || first != fix+"." || strings.Contains(second, "\n") {
			t.Errorf("line %q; want the fix on the first line, at most 100 characters, and the cause on the second", l)
		}
	}
	for _, l := range []string{clampedUsage, noTranscriptUsage} {
		if first, _, _ := strings.Cut(l, "\n"); len(first) > 100 || strings.Count(l, "\n") != 1 {
			t.Errorf("line %q; want two lines, the first at most 100 characters", l)
		}
	}
	for fix, n := range map[string]int{fixRolloutEntries: maxFindEntries, fixRolloutCount: maxRollouts, fixRolloutBytes: maxRolloutBytes >> 20, fixRolloutSize: maxTranscript >> 20, fixRolloutDepth: codex.MaxDepth} {
		if !strings.Contains(fix, fmt.Sprint(" ", n, " ")) {
			t.Errorf("%q has no %d", fix, n)
		}
	}
}
