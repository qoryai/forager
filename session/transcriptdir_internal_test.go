package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/wall"
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

// TestTheTranscriptDirectoryComesFromResume pins guard 2: a runtime with resume gets
// transcripts/<n>/ in the run directory, mode 0700, at the prefix without ~/, whatever
// the shape of its resume.path below the prefix, a * in it included; a runtime without
// resume, or whose prefix is the home itself, gets none, and nothing is made.
func TestTheTranscriptDirectoryComesFromResume(t *testing.T) {
	resume := func(path string) string {
		return "resume:\n  path_from: transcript_path\n  path: " + path + "\n  prefix: ~/.claude/projects/\n  args: [--resume, '{session_id}']\n"
	}
	home := "resume:\n  path: '~//{session_id}.jsonl'\n  prefix: ~//\n  args: [--resume, '{session_id}']\n"
	for name, c := range map[string]struct {
		resume string
		under  string
	}{
		"Claude Code's": {resume("'~/.claude/projects/{cwd_slug}/{session_id}.jsonl'"), ".claude/projects"},
		"no resume":     {"", ""},
		"a flat path":   {resume("'~/.claude/projects/{session_id}.jsonl'"), ".claude/projects"},
		"a deeper path": {resume("'~/.claude/projects/{cwd_slug}/x/{session_id}.jsonl'"), ".claude/projects"},
		"a pattern":     {resume("'~/.claude/projects/*/*/rollout-*-{session_id}.jsonl'"), ".claude/projects"},
		"the home":      {home, ""},
	} {
		t.Run(name, func(t *testing.T) {
			runDir, workspace := t.TempDir(), t.TempDir()
			at, err := makeTranscriptDir(describedResume(t, c.resume), runDir, 2, workspace, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			dir, under := at.dir, at.bind
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

// TestAnAbsolutePrefixIsReadInTheMountThatHoldsIt pins the place of an absolute
// resume.prefix: inside a writable mount's place inside, the innermost one, it is read
// in that mount on this machine, with no transcript directory and no bind; inside a
// read-only mount's it gets none, and one line's fix and cause; a mount inside it fails
// the join; and with no mount around it, the wall binds the transcript directory at it.
// A prefix below the home is bound below the home whatever the mounts.
func TestAnAbsolutePrefixIsReadInTheMountThatHoldsIt(t *testing.T) {
	const home = "/var/lib/agent-home"
	absolute := "resume:\n  path: " + home + "/sessions/*/rollout-*-{session_id}.jsonl\n  prefix: " + home + "/sessions/\n  args: [resume, '{session_id}']\n"
	inHome := "resume:\n  path: '~/.agent/{session_id}.jsonl'\n  prefix: ~/.agent/\n  args: [--resume, '{session_id}']\n"
	hostHome, hostSessions, hostHooks := "/h/run/home", "/h/run/sessions", "/h/run/hooks.json"
	for name, c := range map[string]struct {
		resume string
		mounts []wall.Mount
		want   transcriptRoot
		// at is the place inside of the read-only mount the cause gives, empty for a
		// writable one.
		at string
	}{
		"in a writable mount": {absolute, []wall.Mount{{Path: hostHome, Target: home}},
			transcriptRoot{dir: hostHome, under: "sessions"}, ""},
		"at a writable mount": {absolute, []wall.Mount{{Path: hostSessions, Target: home + "/sessions"}},
			transcriptRoot{dir: hostSessions}, ""},
		"in a writable mount beside a read-only file": {absolute,
			[]wall.Mount{{Path: hostHome, Target: home}, {Path: hostHooks, ReadOnly: true, Target: home + "/hooks.json"}},
			transcriptRoot{dir: hostHome, under: "sessions"}, ""},
		"in a writable mount shown at its path": {absolute, []wall.Mount{{Path: "/var/lib"}},
			transcriptRoot{dir: "/var/lib", under: "agent-home/sessions"}, ""},
		"in a read-only mount": {absolute, []wall.Mount{{Path: hostHome, ReadOnly: true, Target: home}},
			transcriptRoot{}, home},
		"in a read-only mount inside a writable one": {absolute,
			[]wall.Mount{{Path: hostHome, Target: home}, {Path: hostSessions, ReadOnly: true, Target: home + "/sessions"}},
			transcriptRoot{}, home + "/sessions"},
	} {
		t.Run(name, func(t *testing.T) {
			runDir := t.TempDir()
			got, err := makeTranscriptDir(describedResume(t, c.resume), runDir, 1, t.TempDir(), nil, c.mounts)
			if err != nil {
				t.Fatal(err)
			}
			if c.at != "" {
				const fix = "Show resume.prefix in a writable mount, or use a descriptor whose resume.prefix lies outside read-only mounts"
				if got.unbound == nil || got.unbound.Fix != fix || !strings.Contains(got.unbound.Cause, ", at "+c.at+", read-only") ||
					got.dir != "" || got.bind != "" {
					t.Errorf("%+v; want unbound with the fix %q and the place %s", got, fix, c.at)
				}
				return
			}
			if got.dir != c.want.dir || got.under != c.want.under || got.bind != "" || got.unbound != nil {
				t.Errorf("%+v; want %+v", got, c.want)
			}
			if _, err := os.Stat(filepath.Join(runDir, transcriptsDir)); err == nil {
				t.Error("the transcript directories were made")
			}
		})
	}

	u, err := makeTranscriptDir(describedResume(t, absolute), t.TempDir(), 1, t.TempDir(), nil, []wall.Mount{{Path: hostHome, ReadOnly: true, Target: home}})
	if err != nil || u.unbound == nil {
		t.Fatalf("%+v, %v", u, err)
	}
	if want := "resume.prefix " + home + "/sessions/ lies inside it, at " + home + ", read-only, so the runtime cannot write its transcript there"; u.unbound.Cause != want {
		t.Errorf("the cause %q; want %q", u.unbound.Cause, want)
	}

	_, err = makeTranscriptDir(describedResume(t, absolute), t.TempDir(), 1, t.TempDir(), nil,
		[]wall.Mount{{Path: hostHome, Target: home}, {Path: hostHooks, ReadOnly: true, Target: home + "/sessions/2026"}})
	if want := "Show the mount " + hostHooks + " outside resume.prefix " + home + "/sessions/, or at a place that contains it"; err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("a mount inside the prefix: %v; want an error that starts with %q", err, want)
	}

	runDir := t.TempDir()
	got, err := makeTranscriptDir(describedResume(t, absolute), runDir, 3, t.TempDir(), nil, []wall.Mount{{Path: hostHome, Target: "/var/lib/other"}})
	if err != nil {
		t.Fatal(err)
	}
	want := transcriptRoot{dir: filepath.Join(runDir, transcriptsDir, "3"), bind: home + "/sessions"}
	if got.dir != want.dir || got.bind != want.bind || got.under != "" {
		t.Errorf("no mount around the prefix: %+v; want %+v", got, want)
	}
	if got.wallTranscript() != (wall.Transcript{Path: want.dir, Under: want.bind}) {
		t.Errorf("the wall's transcript %+v", got.wallTranscript())
	}

	runDir = t.TempDir()
	got, err = makeTranscriptDir(describedResume(t, inHome), runDir, 1, t.TempDir(), nil, []wall.Mount{{Path: hostHome, Target: "/"}})
	if err != nil || got.dir != filepath.Join(runDir, transcriptsDir, "1") || got.bind != ".agent" {
		t.Errorf("a prefix below the home: %+v, %v", got, err)
	}
}
