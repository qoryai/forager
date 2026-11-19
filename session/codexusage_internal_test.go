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

// TestCodexUsageReadsTheFixturesRollouts pins the usage of the fixture's two launches
// read from files below the prefix, with a wall and without one: launch 1 is the
// thread plus its child, launch 2 the thread less its restored bytes, launch 1's
// file. A rollout of another thread, a file of another shape and a directory of
// another name count for nothing.
func TestCodexUsageReadsTheFixturesRollouts(t *testing.T) {
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("walled ", walled), func(t *testing.T) {
			tr, s, dir := codexUsageTranscript(t, walled)
			appendTo(t, dir, rolloutAt(fixtureThread), fixture(t, "launch1-parent-rollout.jsonl"))
			appendTo(t, dir, "2026/11/19/rollout-2026-11-19T00-00-00-"+fixtureChild+".jsonl", fixture(t, "launch1-child-rollout.jsonl"))
			appendTo(t, dir, rolloutAt(walledID), []byte(`{"type":"session_meta","payload":{"id":"`+walledID+`"}}`+"\n"+
				`{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":7}}}}`+"\n"))
			appendTo(t, dir, "2026/11/18/notes.txt", []byte("x\n"))
			if got := tr.codexUsage(fixtureThread, 0); !reflect.DeepEqual(got, launch1Usage) || len(s.lines) != 0 {
				t.Errorf("launch 1's usage %v, lines %q; want %v", got, s.lines, launch1Usage)
			}

			tr, s, dir = codexUsageTranscript(t, walled)
			appendTo(t, dir, rolloutAt(fixtureThread), fixture(t, "launch2-parent-rollout.jsonl"))
			restored := int64(len(fixture(t, "launch1-parent-rollout.jsonl")))
			if got := tr.codexUsage(fixtureThread, restored); !reflect.DeepEqual(got, launch2Usage) || len(s.lines) != 0 {
				t.Errorf("launch 2's usage %v, lines %q; want %v", got, s.lines, launch2Usage)
			}
		})
	}
}

// TestCodexUsageCases pins a child whose file is missing, a child of a child, a thread
// with no token_count, for which the usage is nil with no line, and a thread with no
// rollout, a thread id of another shape behind a wall, and an empty id, for which it is
// nil.
func TestCodexUsageCases(t *testing.T) {
	meta := func(id, parent string) string {
		return fmt.Sprintf(`{"type":"session_meta","payload":{"id":%q,"parent_thread_id":%q}}`+"\n", id, parent)
	}
	count := func(n int) string {
		return fmt.Sprintf(`{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":%d,"cached_input_tokens":%d,"cache_write_input_tokens":%d,"output_tokens":%d}}}}`+"\n", 5*n, n, 2*n, 4*n)
	}
	usage := func(n int64) map[string]any {
		return map[string]any{"input": 2 * n, "output": 4 * n, "cache_read": n, "cache_write": 2 * n}
	}
	const child, grandchild = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("walled ", walled), func(t *testing.T) {
			tr, s, dir := codexUsageTranscript(t, walled)
			appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")+count(1)))
			appendTo(t, dir, rolloutAt(grandchild), []byte(meta(grandchild, child)+count(100)))
			if got := tr.codexUsage(walledID, 0); !reflect.DeepEqual(got, usage(1)) || len(s.lines) != 0 {
				t.Errorf("a missing child: usage %v, lines %q; want %v", got, s.lines, usage(1))
			}
			appendTo(t, dir, rolloutAt(child), []byte(meta(child, walledID)+count(10)))
			if got := tr.codexUsage(walledID, 0); !reflect.DeepEqual(got, usage(111)) || len(s.lines) != 0 {
				t.Errorf("a child of a child: usage %v, lines %q; want %v", got, s.lines, usage(111))
			}

			tr, s, dir = codexUsageTranscript(t, walled)
			appendTo(t, dir, rolloutAt(walledID), []byte(meta(walledID, "")))
			if got := tr.codexUsage(walledID, 0); got != nil || len(s.lines) != 0 {
				t.Errorf("no token_count: usage %v, lines %q; want none", got, s.lines)
			}
			if got := tr.codexUsage(child, 0); got != nil || len(s.lines) != 1 || !strings.HasPrefix(s.lines[0], "Check that Codex writes the rollout of the launch's thread at ~/.rollouts/sessions/*/*/*/rollout-*-"+child+".jsonl. ") {
				t.Errorf("no rollout: usage %v, lines %q", got, s.lines)
			}
			s.lines = nil
			if got := tr.codexUsage("", 0); got != nil || len(s.lines) != 0 {
				t.Errorf("no thread: usage %v, lines %q", got, s.lines)
			}
			if walled {
				if got := tr.codexUsage("Not-A-UUID", 0); got != nil || len(s.lines) != 0 {
					t.Errorf("an id of another shape: usage %v, lines %q", got, s.lines)
				}
			}
		})
	}
}

// TestCodexUsageRefusesWhatTheAgentPlants pins the checks of every file the search
// finds, with a wall and without one: a symbolic link, a FIFO, which the session opens
// without blocking, a file with a second hard link behind a wall, a file over 64 MiB,
// and more than 256 rollouts: for each the usage is nil, and the session writes one
// line that starts with the fix.
func TestCodexUsageRefusesWhatTheAgentPlants(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.jsonl")
	if err := os.WriteFile(outside, fixture(t, "launch1-child-rollout.jsonl"), 0o600); err != nil {
		t.Fatal(err)
	}
	planted := filepath.FromSlash(rolloutAt(fixtureChild))
	for name, c := range map[string]struct {
		plant  func(t *testing.T, dir string)
		walled bool // only behind a wall
		fix    string
	}{
		"link": {plant: func(t *testing.T, dir string) {
			if err := os.Symlink(outside, filepath.Join(dir, planted)); err != nil {
				t.Fatal(err)
			}
		}, fix: "Replace the symbolic link|Keep each rollout at"},
		"fifo": {plant: func(t *testing.T, dir string) {
			if err := unix.Mkfifo(filepath.Join(dir, planted), 0o600); err != nil {
				t.Fatal(err)
			}
		}, fix: "Keep the transcript a regular file|Keep each rollout at"},
		"hard link": {plant: func(t *testing.T, dir string) {
			p := filepath.Join(dir, planted)
			if err := os.WriteFile(p, fixture(t, "launch1-child-rollout.jsonl"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(p, filepath.Join(dir, "2026", "11", "18", "other")); err != nil {
				t.Fatal(err)
			}
		}, walled: true, fix: "Remove the other hard links to the transcript"},
		"over 64 MiB": {plant: func(t *testing.T, dir string) {
			f, err := os.Create(filepath.Join(dir, planted))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := f.Truncate(maxTranscript + 1); err != nil {
				t.Fatal(err)
			}
		}, fix: "Keep the session's transcript at most 64 MiB"},
		"257 rollouts": {plant: func(t *testing.T, dir string) {
			for i := range maxRollouts {
				appendTo(t, dir, fmt.Sprintf("2026/11/20/rollout-%d-x.jsonl", i), []byte("{}\n"))
			}
		}, fix: "Keep at most 256 rollouts at ~/.rollouts/sessions/*/*/*/rollout-*-*.jsonl"},
	} {
		for _, walled := range []bool{false, true} {
			if c.walled && !walled {
				continue
			}
			t.Run(fmt.Sprint(name, ", walled ", walled), func(t *testing.T) {
				tr, s, dir := codexUsageTranscript(t, walled)
				appendTo(t, dir, rolloutAt(fixtureThread), fixture(t, "launch1-parent-rollout.jsonl"))
				c.plant(t, dir)
				done := make(chan map[string]any)
				go func() { done <- tr.codexUsage(fixtureThread, 0) }()
				var got map[string]any
				select {
				case got = <-done:
				case <-time.After(10 * time.Second):
					t.Fatal("the read did not return within 10 seconds")
				}
				ok := len(s.lines) == 1
				if ok {
					ok = false
					for _, fix := range strings.Split(c.fix, "|") {
						ok = ok || strings.HasPrefix(s.lines[0], fix)
					}
				}
				if got != nil || !ok || !strings.Contains(s.lines[0], "The session wrote no usage in the launch's dev.qory.runtime.result: ") {
					t.Errorf("usage %v, lines %q; want none and one line that starts with %q", got, s.lines, c.fix)
				}
			})
		}
	}
}

// TestCodexUsageClampsACountBelowZero pins a total whose cached tokens exceed its
// input tokens: input 0, and one line that no action is needed.
func TestCodexUsageClampsACountBelowZero(t *testing.T) {
	tr, s, dir := codexUsageTranscript(t, true)
	appendTo(t, dir, rolloutAt(walledID), []byte(`{"type":"session_meta","payload":{"id":"`+walledID+`"}}`+"\n"+
		`{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":2,"cached_input_tokens":3,"output_tokens":1}}}}`+"\n"))
	want := map[string]any{"input": int64(0), "output": int64(1), "cache_read": int64(3), "cache_write": int64(0)}
	if got := tr.codexUsage(walledID, 0); !reflect.DeepEqual(got, want) || len(s.lines) != 1 || !strings.HasPrefix(s.lines[0], "No action needed. ") {
		t.Errorf("usage %v, lines %q; want %v and one line", got, s.lines, want)
	}
}
