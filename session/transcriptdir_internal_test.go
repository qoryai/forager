package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qoryai/forager/session/runtimes"
)

// describedResume is a runtime written as data, with the resume entry given, or none
// when resume is empty.
func describedResume(t *testing.T, resume string) runtimes.Runtime {
	t.Helper()
	d := "version: 1\nruntime: r\nruntime_version: \"1\"\nsources:\n  output: {format: jsonl}\n" + resume +
		"rules:\n  - source: output\n    match: {type: start}\n    type: dev.qory.runtime.started\n    data: {session_id: session_id}\n"
	rt, err := runtimes.Described("r.yaml", []byte(d), nil)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// TestTheTranscriptDirectoryComesFromResume pins guard 2: a runtime whose resume.path is
// <prefix>{cwd_slug}/{session_id}.jsonl gets transcripts/<n>/ in the run directory, mode
// 0700, at the prefix without ~/; a runtime without resume, or with a path of another
// shape, gets none, and nothing is made.
func TestTheTranscriptDirectoryComesFromResume(t *testing.T) {
	resume := func(path string) string {
		return "resume:\n  path_from: transcript_path\n  path: " + path + "\n  prefix: ~/.claude/projects/\n  args: [--resume, '{session_id}']\n"
	}
	for name, c := range map[string]struct {
		resume string
		under  string
	}{
		"Claude Code's": {resume("'~/.claude/projects/{cwd_slug}/{session_id}.jsonl'"), ".claude/projects"},
		"no resume":     {"", ""},
		"a flat path":   {resume("'~/.claude/projects/{session_id}.jsonl'"), ""},
		"a deeper path": {resume("'~/.claude/projects/{cwd_slug}/x/{session_id}.jsonl'"), ""},
	} {
		t.Run(name, func(t *testing.T) {
			runDir, workspace := t.TempDir(), t.TempDir()
			dir, under, err := makeTranscriptDir(describedResume(t, c.resume), runDir, 2, workspace, nil)
			if err != nil {
				t.Fatal(err)
			}
			if under != c.under {
				t.Errorf("under %q; want %q", under, c.under)
			}
			if c.under == "" {
				if dir != "" {
					t.Errorf("a directory %s", dir)
				}
				if _, err := os.Stat(filepath.Join(runDir, transcriptsDir)); err == nil {
					t.Error("the transcript directories were made")
				}
				return
			}
			if want := filepath.Join(runDir, transcriptsDir, "2"); dir != want {
				t.Errorf("the directory %s; want %s", dir, want)
			}
			if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
				t.Errorf("%v %v; want mode 0700", fi, err)
			}
		})
	}
}

// TestATranscriptDirectoryInABindIsRefused pins guard 1: a transcript directory outside
// the run directory, or that lies in the workspace, in a place the enclosure binds or
// contains one, fails the check; one apart from all of them passes.
func TestATranscriptDirectoryInABindIsRefused(t *testing.T) {
	base := t.TempDir()
	runDir := filepath.Join(base, "runs", "r1")
	dir := filepath.Join(runDir, transcriptsDir, "1")
	other := filepath.Join(base, "runs", "r2", transcriptsDir, "1")
	for _, p := range []string{dir, other, filepath.Join(base, "work")} {
		makeDir(t, p)
	}
	bind := func(p string) bindSource {
		b, err := source(p, "a place "+p, "", true)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	runBind, err := source(runDir, "the run directory", kindRun, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkTranscriptDir(dir, runDir, filepath.Join(base, "work"), []bindSource{runBind, bind(filepath.Join(base, "work"))}); err != nil {
		t.Errorf("a directory apart from every bind: %v", err)
	}
	for name, c := range map[string]struct {
		dir, workspace string
		binds          []bindSource
		want           string
	}{
		"another run's":    {other, filepath.Join(base, "work"), nil, "lies outside the run directory"},
		"in the workspace": {dir, runDir, nil, "overlaps"},
		"in a bind":        {dir, filepath.Join(base, "work"), []bindSource{bind(filepath.Join(runDir, transcriptsDir))}, "overlaps"},
		"holding a bind":   {dir, filepath.Join(base, "work"), []bindSource{bind(filepath.Join(dir, "x"))}, "overlaps"},
		"the bind itself":  {dir, filepath.Join(base, "work"), []bindSource{bind(dir)}, "overlaps"},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkTranscriptDir(c.dir, runDir, c.workspace, c.binds)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%v; want an error with %q", err, c.want)
			}
		})
	}
}
