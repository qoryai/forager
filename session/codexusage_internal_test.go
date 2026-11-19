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
// one: a symbolic link, a FIFO, which the session opens without blocking, the thread's
// file with a second hard link behind a wall, and a file over 64 MiB. For each the
// usage is nil, and the session writes one line that starts with the fix. A child's
// file with a second hard link is in [TestCodexUsageRefusesAHardLinkedChildBehindAWall].
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
		fixRolloutSize, fixRolloutRead, fixThreadOne, fixThreadShape, fixThreadMissing, fixRolloutDepth, fixRolloutCounts, fixRolloutMeta, fixNoTranscript}
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

// Ids of child agents of the tests below.
const (
	childA = "33333333-3333-4333-8333-333333333333"
	childB = "44444444-4444-4444-8444-444444444444"
)

// longMeta is a session_meta line of id with parent, as Codex 0.167.2 writes a child
// agent's: the ids and the source first, then base instructions of 70 KiB, so that the
// line is longer than [maxRolloutHead].
func longMeta(id, parent string) string {
	return fmt.Sprintf(`{"type":"session_meta","payload":{"session_id":%q,"id":%q,"parent_thread_id":%q,"source":{"subagent":{"thread_spawn":{"parent_thread_id":%q,"depth":1}}},"base_instructions":{"text":%q}}}`+"\n",
		parent, id, parent, parent, strings.Repeat("x", 70<<10))
}

// TestCodexUsageReadsALongSessionMeta pins a child whose first line is longer than 64
// KiB, with a wall and without one: its ids come before the base instructions, so the
// thread with count 1 and the child with count 10 give the usage 11. A first line of
// 70 KiB with the ids after the first 64 KiB gives no usage and one line.
func TestCodexUsageReadsALongSessionMeta(t *testing.T) {
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("walled ", walled), func(t *testing.T) {
			tr, s, dir := codexUsageTranscript(t, walled)
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")+count(1)))
			appendTo(t, dir, rolloutAt(childA), []byte(longMeta(childA, walledID)+count(10)))
			if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, usage(11)) || len(s.lines) != 0 {
				t.Errorf("usage %v, lines %q; want %v", got, s.lines, usage(11))
			}

			late := fmt.Sprintf(`{"type":"session_meta","payload":{"cwd":%q,"id":%q,"parent_thread_id":%q}}`+"\n", strings.Repeat("x", 70<<10), childB, walledID)
			appendTo(t, dir, rolloutAt(childB), []byte(late+count(100)))
			if got := tr.codexUsage(walledID); got != nil {
				t.Errorf("ids after 64 KiB: usage %v; want none", got)
			}
			checkLines(t, s, fixRolloutMeta)
			if !strings.Contains(s.lines[0], "the first 65536 bytes (64 KiB) of a rollout at ~/.rollouts/sessions/*/*/*/rollout-*-*.jsonl end before the id and source of its session_meta") {
				t.Errorf("line %q", s.lines[0])
			}
		})
	}
}

// readCounts counts the opens of rollouts and the reads of their first bytes by
// [rolloutHooks], by path below the prefix, with the bytes of each head read.
type readCounts struct {
	opens, heads map[string]int
	headBytes    map[string][]int
}

// countReads sets tr's hooks to count into a new readCounts; opened, when not nil,
// also gets each open with its number for that path, from 1.
func countReads(tr *transcript, opened func(rel string, n int, f *os.File)) *readCounts {
	c := &readCounts{opens: map[string]int{}, heads: map[string]int{}, headBytes: map[string][]int{}}
	tr.hooks = &rolloutHooks{
		opened: func(rel string, f *os.File) {
			c.opens[rel]++
			if opened != nil {
				opened(rel, c.opens[rel], f)
			}
		},
		head: func(rel string, n int) {
			c.heads[rel]++
			c.headBytes[rel] = append(c.headBytes[rel], n)
		},
	}
	return c
}

// TestCodexUsageReadsOnlyChangedFiles pins the reads of a folder with 5000 rollouts
// of an earlier launch that did not change, children of the thread, with a wall and
// without one. A launch that changed the thread and one child opens the thread once,
// and the child twice, its first bytes and then in full. A child that did not change
// with a grandchild that changed costs one read of the child's first bytes, found by
// the id in its name, to link the grandchild to the thread. A file whose name has the
// id and whose session_meta has another id links nothing.
func TestCodexUsageReadsOnlyChangedFiles(t *testing.T) {
	const grandchild = "55555555-5555-4555-8555-555555555555"
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("walled ", walled), func(t *testing.T) {
			tr, s, dir := codexUsageTranscript(t, walled)
			for i := range 5000 {
				appendTo(t, dir, fmt.Sprintf("2026/11/17/rollout-%d-old-%d.jsonl", i, i), []byte(meta(fmt.Sprint("old-", i), walledID)+count(1000)))
			}
			appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")))
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(walledID), []byte(count(1)))
			appendTo(t, dir, rolloutAt(childA), []byte(meta(childA, walledID)+count(10)))
			c := countReads(tr, nil)
			if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, usage(11)) || len(s.lines) != 0 {
				t.Errorf("a changed child: usage %v, lines %q; want %v", got, s.lines, usage(11))
			}
			wantOpens := map[string]int{rolloutAt(walledID): 1, rolloutAt(childA): 2}
			if !reflect.DeepEqual(c.opens, wantOpens) || !reflect.DeepEqual(c.heads, map[string]int{rolloutAt(childA): 1}) {
				t.Errorf("a changed child: opens %v, head reads %v; want %v and the child's one", c.opens, c.heads, wantOpens)
			}

			// The next launch changes a grandchild below the child, which did not change.
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(walledID), []byte(count(2)))
			appendTo(t, dir, rolloutAt(grandchild), []byte(meta(grandchild, childA)+count(100)))
			c = countReads(tr, nil)
			if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, usage(101)) || len(s.lines) != 0 {
				t.Errorf("a changed grandchild: usage %v, lines %q; want %v", got, s.lines, usage(101))
			}
			wantHeads := map[string]int{rolloutAt(grandchild): 1, rolloutAt(childA): 1}
			if !reflect.DeepEqual(c.heads, wantHeads) || c.opens[rolloutAt(childA)] != 1 {
				t.Errorf("a changed grandchild: head reads %v, opens %v; want %v and one open of the child", c.heads, c.opens, wantHeads)
			}

			// A grandchild whose parent has no rollout, and a file whose name has the
			// parent's id and whose session_meta has another id: the grandchild adds
			// nothing.
			tr, s, dir = codexUsageTranscript(t, walled)
			decoy := "2026/11/17/rollout-decoy-" + childB + ".jsonl"
			appendTo(t, dir, decoy, []byte(meta("decoy", walledID)+count(1000)))
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")+count(1)))
			appendTo(t, dir, rolloutAt(grandchild), []byte(meta(grandchild, childB)+count(100)))
			c = countReads(tr, nil)
			if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, usage(1)) || len(s.lines) != 0 {
				t.Errorf("a decoy: usage %v, lines %q; want %v", got, s.lines, usage(1))
			}
			if c.heads[decoy] != 1 {
				t.Errorf("a decoy: head reads %v; want one of %s", c.heads, decoy)
			}
		})
	}
}

// TestCodexUsageComparesTheInode pins the device and inode of a child's baseline,
// with a wall and without one. A child replaced by a rename, a new inode, longer than
// its baseline, adds its full total, 40: the bytes up to its baseline's length are no
// bytes of the file before the launch. The test holds the old file open, so its inode
// is not reused. A child rewritten in place with longer content keeps its inode: its
// bytes up to the baseline's length count as the file's before the launch, since Codex
// 0.167.2 only appends to a rollout and the baseline reads no file, so the child adds
// 40 less the 21 in those bytes now, 19.
func TestCodexUsageComparesTheInode(t *testing.T) {
	old, now := meta(childA, walledID)+count(20), meta(childA, walledID)+count(21)+count(40)
	if len(old) != len(meta(childA, walledID)+count(21)) {
		t.Fatal("the counts 20 and 21 differ in length")
	}
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("walled ", walled), func(t *testing.T) {
			tr, s, dir := codexUsageTranscript(t, walled)
			p := filepath.Join(dir, rolloutAt(childA))
			appendTo(t, dir, rolloutAt(childA), []byte(old))
			held, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")+count(1)))
			if err := os.WriteFile(p+".new", []byte(now), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(p+".new", p); err != nil {
				t.Fatal(err)
			}
			if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, usage(41)) || len(s.lines) != 0 {
				t.Errorf("a child renamed over: usage %v, lines %q; want %v", got, s.lines, usage(41))
			}

			tr, s, dir = codexUsageTranscript(t, walled)
			p = filepath.Join(dir, rolloutAt(childA))
			appendTo(t, dir, rolloutAt(childA), []byte(old))
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")+count(1)))
			f, err := os.OpenFile(p, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteAt([]byte(now), 0); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, usage(20)) || len(s.lines) != 0 {
				t.Errorf("a child rewritten in place: usage %v, lines %q; want %v", got, s.lines, usage(20))
			}
		})
	}
}

// TestCodexUsageTakesACopiedShorterFileWhole pins a run with no wall whose resume
// script copies a restored file shorter than the restored length: its baseline is 0,
// and the usage is its full total, with no line.
func TestCodexUsageTakesACopiedShorterFileWhole(t *testing.T) {
	tr, s, dir := codexUsageTranscript(t, false)
	launch1 := fixture(t, "launch1-parent-rollout.jsonl")
	tr.codexBaseline(&restored{sessionID: fixtureThread, rel: ".rollouts/sessions/" + rolloutAt(fixtureThread), size: int64(len(launch1))})
	short := meta(fixtureThread, "") + count(5)
	if len(short) >= len(launch1) {
		t.Fatal("the copy is not shorter")
	}
	appendTo(t, dir, rolloutAt(fixtureThread), []byte(short))
	if got := tr.codexUsage(fixtureThread); !reflect.DeepEqual(got, usage(5)) || len(s.lines) != 0 {
		t.Errorf("usage %v, lines %q; want %v", got, s.lines, usage(5))
	}
}

// TestCodexUsageSkipsAFileSwappedBetweenItsReads pins a child whose file another file
// replaces between the read of its first bytes and its read in full, with a wall and
// without one: the new file's id is over 128 bytes, and the child adds nothing. A
// swap to another id of 128 bytes or fewer adds nothing too.
func TestCodexUsageSkipsAFileSwappedBetweenItsReads(t *testing.T) {
	for name, swapped := range map[string]string{"a long id": strings.Repeat("a", maxSessionID+1), "another id": childB} {
		for _, walled := range []bool{false, true} {
			t.Run(fmt.Sprint(name, ", walled ", walled), func(t *testing.T) {
				tr, s, dir := codexUsageTranscript(t, walled)
				tr.codexBaseline(nil)
				appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")+count(1)))
				appendTo(t, dir, rolloutAt(childA), []byte(meta(childA, walledID)+count(10)))
				p := filepath.Join(dir, rolloutAt(childA))
				countReads(tr, func(rel string, n int, _ *os.File) {
					if rel != rolloutAt(childA) || n != 1 {
						return
					}
					if err := os.WriteFile(p+".new", []byte(meta(swapped, walledID)+count(1000)), 0o644); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(p+".new", p); err != nil {
						t.Fatal(err)
					}
				})
				if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, usage(1)) || len(s.lines) != 0 {
					t.Errorf("usage %v, lines %q; want the thread's %v", got, s.lines, usage(1))
				}
			})
		}
	}
}

// TestCodexUsageReadsAtMost64KiBOfAHead pins the bytes of each read of a child's first
// bytes: 65536 of a file of 70 KiB, and of a smaller file the length its fstat has,
// though the file grows after the fstat.
func TestCodexUsageReadsAtMost64KiBOfAHead(t *testing.T) {
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("walled ", walled), func(t *testing.T) {
			tr, _, dir := codexUsageTranscript(t, walled)
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")+count(1)))
			appendTo(t, dir, rolloutAt(childA), []byte(longMeta(childA, walledID)+count(10)))
			small := meta(childB, walledID) + count(100)
			appendTo(t, dir, rolloutAt(childB), []byte(small))
			c := countReads(tr, func(rel string, n int, _ *os.File) {
				if rel == rolloutAt(childB) && n == 1 {
					appendTo(t, dir, rel, []byte(count(100)))
				}
			})
			tr.codexUsage(walledID)
			want := map[string][]int{rolloutAt(childA): {maxRolloutHead}, rolloutAt(childB): {len(small)}}
			if !reflect.DeepEqual(c.headBytes, want) {
				t.Errorf("head reads of %v bytes; want %v", c.headBytes, want)
			}
		})
	}
}

// TestCodexUsageReadErrorHasNoName pins a read in full that fails, of a child whose
// file name an agent chose, with a wall and without one: the usage is nil, and the
// line contains the cause and not the name.
func TestCodexUsageReadErrorHasNoName(t *testing.T) {
	const planted = "2026/11/19/rollout-plantedname-x.jsonl"
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("walled ", walled), func(t *testing.T) {
			tr, s, dir := codexUsageTranscript(t, walled)
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")+count(1)))
			appendTo(t, dir, planted, []byte(meta(childA, walledID)+count(10)))
			countReads(tr, func(rel string, n int, f *os.File) {
				if rel == planted && n == 2 {
					f.Close()
				}
			})
			if got := tr.codexUsage(walledID); got != nil {
				t.Errorf("usage %v; want none", got)
			}
			checkLines(t, s, fixRolloutRead)
			if l := s.lines[0]; strings.Contains(l, "plantedname") || !strings.Contains(l, "a read of a rollout at ~/.rollouts/sessions/*/*/*/rollout-*-*.jsonl failed: read: file already closed") {
				t.Errorf("line %q; want the cause and no name", l)
			}
		})
	}
}

// TestCodexUsageRefusesAHardLinkedChildBehindAWall pins rollouts with a second hard
// link. Behind a wall, a child that changed gives no usage and one line; without a
// wall the session reads the child. A file of another thread that changed, and a child
// that did not change, are not read in full, so the usage is the thread's with no
// line.
func TestCodexUsageRefusesAHardLinkedChildBehindAWall(t *testing.T) {
	link := func(t *testing.T, dir, rel string) {
		t.Helper()
		if err := os.Link(filepath.Join(dir, rel), filepath.Join(dir, "2026", "11", "18", "other")); err != nil {
			t.Fatal(err)
		}
	}
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("a changed child, walled ", walled), func(t *testing.T) {
			tr, s, dir := codexUsageTranscript(t, walled)
			tr.codexBaseline(nil)
			appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")+count(1)))
			appendTo(t, dir, rolloutAt(childA), []byte(meta(childA, walledID)+count(10)))
			link(t, dir, rolloutAt(childA))
			got := tr.codexUsage(walledID)
			if !walled {
				if !reflect.DeepEqual(got, usage(11)) || len(s.lines) != 0 {
					t.Errorf("usage %v, lines %q; want %v", got, s.lines, usage(11))
				}
				return
			}
			if got != nil {
				t.Errorf("usage %v; want none", got)
			}
			checkLines(t, s, fixRolloutHardLinks)
		})
	}
	t.Run("another thread's file, walled", func(t *testing.T) {
		tr, s, dir := codexUsageTranscript(t, true)
		tr.codexBaseline(nil)
		appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")+count(1)))
		appendTo(t, dir, rolloutAt(childB), []byte(meta(childB, "")+count(10)))
		link(t, dir, rolloutAt(childB))
		if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, usage(1)) || len(s.lines) != 0 {
			t.Errorf("usage %v, lines %q; want %v", got, s.lines, usage(1))
		}
	})
	t.Run("a child that did not change, walled", func(t *testing.T) {
		tr, s, dir := codexUsageTranscript(t, true)
		appendTo(t, dir, rolloutAt(childA), []byte(meta(childA, walledID)+count(10)))
		link(t, dir, rolloutAt(childA))
		tr.codexBaseline(nil)
		appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")+count(1)))
		c := countReads(tr, nil)
		if got := tr.codexUsage(walledID); !reflect.DeepEqual(got, usage(1)) || len(s.lines) != 0 {
			t.Errorf("usage %v, lines %q; want %v", got, s.lines, usage(1))
		}
		if c.opens[rolloutAt(childA)] != 0 {
			t.Errorf("opens %v; want none of the child", c.opens)
		}
	})
}
