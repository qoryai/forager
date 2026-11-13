package session

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qoryai/forager/session/runtimes"
)

// TestTheResumeScriptWritesTheTranscriptThenResumes pins the script's two ends: with a
// home it can write, the transcript at its path under the home and the runtime started
// with the resume arguments added; with a home it cannot write, the line of a failed
// resume on stderr and the runtime started without them.
func TestTheResumeScriptWritesTheTranscriptThenResumes(t *testing.T) {
	dir := t.TempDir()
	transcript := filepath.Join(dir, ResumeTranscript)
	if err := os.WriteFile(transcript, []byte("{\"a\":1}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, ResumeScript)
	rel := ".agent/sessions/-w/it's.jsonl"
	text := resumeScript("0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d", transcript, "~/"+rel, []string{"--resume", "s 1"})
	if err := os.WriteFile(script, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(home string) (string, string) {
		t.Helper()
		cmd := exec.Command("/bin/sh", script, "/bin/sh", "-c", `for a; do echo "[$a]"; done`, "sh", "--print")
		cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%v: %s", err, stderr.String())
		}
		return string(out), stderr.String()
	}
	home := t.TempDir()
	out, stderr := run(home)
	if want := "[--print]\n[--resume]\n[s 1]\n"; out != want || stderr != "" {
		t.Errorf("the runtime got %q, stderr %q; want %q", out, stderr, want)
	}
	if b, err := os.ReadFile(filepath.Join(home, rel)); err != nil || string(b) != "{\"a\":1}\n" {
		t.Errorf("the transcript under the home: %q %v", b, err)
	}
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	out, stderr = run(blocked)
	if out != "[--print]\n" {
		t.Errorf("the runtime got %q; want no resume arguments", out)
	}
	want := "Check that HOME inside is writable. The runtime starts without a resume: the transcript of run 0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d could not be restored: the copy to ~/" + rel + " failed"
	last := ""
	for sc := bufio.NewScanner(strings.NewReader(stderr)); sc.Scan(); {
		last = sc.Text()
	}
	if last != want {
		t.Errorf("stderr %q; want its last line %q", stderr, want)
	}
}

// TestTheResumeScriptInsertsTheArgumentsAfterHead pins the script with the resume
// arguments after the first head words: the runtime gets them right after exec, the
// words after it kept in order, spaces and quotes included; with a home it cannot
// write, it gets its arguments as they were.
func TestTheResumeScriptInsertsTheArgumentsAfterHead(t *testing.T) {
	dir := t.TempDir()
	transcript := filepath.Join(dir, ResumeTranscript)
	if err := os.WriteFile(transcript, []byte("{\"a\":1}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, ResumeScript)
	rel := ".rollouts/sessions/2026/11/13/rollout-a-s.jsonl"
	launch := []string{"/bin/sh", "-c", `for a; do echo "[$a]"; done`, "sh", "exec", "--json", "it's a 'prompt'"}
	at := resumeAt(launch[1:], "exec")
	text := resumeScriptAt("0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d", transcript, "~/"+rel, []string{"resume", "s 1"}, 1+at)
	if err := os.WriteFile(script, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(home string) string {
		t.Helper()
		cmd := exec.Command("/bin/sh", append([]string{script}, launch...)...)
		cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	if out, want := run(t.TempDir()), "[exec]\n[resume]\n[s 1]\n[--json]\n[it's a 'prompt']\n"; out != want {
		t.Errorf("the runtime got %q; want %q", out, want)
	}
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, want := run(blocked), "[exec]\n[--json]\n[it's a 'prompt']\n"; out != want {
		t.Errorf("without a resume the runtime got %q; want %q", out, want)
	}
}

// TestTheResumeScriptWritesAnAbsolutePath pins the script of an absolute resume.path:
// it writes the transcript at that path, whatever HOME is, and with a directory it
// cannot write, the line of a failed resume names the directory and the runtime starts
// without the resume arguments.
func TestTheResumeScriptWritesAnAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	transcript := filepath.Join(dir, ResumeTranscript)
	if err := os.WriteFile(transcript, []byte("{\"a\":1}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(dst string) (string, string) {
		t.Helper()
		script := filepath.Join(dir, ResumeScript)
		text := resumeScript("0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d", transcript, dst, []string{"resume", "s 1"})
		if err := os.WriteFile(script, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/sh", script, "/bin/sh", "-c", `for a; do echo "[$a]"; done`, "sh")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%v: %s", err, stderr.String())
		}
		return string(out), stderr.String()
	}
	dst := filepath.Join(t.TempDir(), "codex-home", "sessions", "2026", "rollout-a-s.jsonl")
	if out, stderr := run(dst); out != "[resume]\n[s 1]\n" || stderr != "" {
		t.Errorf("the runtime got %q, stderr %q; want the resume arguments", out, stderr)
	}
	if b, err := os.ReadFile(dst); err != nil || string(b) != "{\"a\":1}\n" {
		t.Errorf("the transcript at its path: %q %v", b, err)
	}
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	dst = filepath.Join(blocked, "rollout-a-s.jsonl")
	out, stderr := run(dst)
	if out != "" {
		t.Errorf("the runtime got %q; want no resume arguments", out)
	}
	want := "Check that " + blocked + " is writable. The runtime starts without a resume: the transcript of run 0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d could not be restored: the copy to " + dst + " failed"
	if !strings.HasSuffix(strings.TrimSuffix(stderr, "\n"), want) {
		t.Errorf("stderr %q; want its last line %q", stderr, want)
	}
}

// TestResumeAtFollowsAfter pins where the resume arguments go: right after the first
// argument equal to resume.after, else at the end.
func TestResumeAtFollowsAfter(t *testing.T) {
	args := []string{"exec", "--json", "exec"}
	for after, want := range map[string]int{"exec": 1, "--json": 2, "": 3, "resume": 3} {
		if got := resumeAt(args, after); got != want {
			t.Errorf("after %q: %d; want %d", after, got, want)
		}
	}
	if got := resumeAt(nil, "exec"); got != 0 {
		t.Errorf("no arguments: %d", got)
	}
}

// TestResumePlaceBeforeLast pins resume.place before_last: the resume
// arguments go right before the first -- after resume.after, else right before the last
// argument; with no argument after resume.after, or none equal to it, there is no place.
// Without place, they go right after resume.after.
func TestResumePlaceBeforeLast(t *testing.T) {
	before := runtimes.Resume{After: "exec", Place: runtimes.PlaceBeforeLast}
	for _, c := range []struct {
		args []string
		want int
	}{
		{[]string{"exec", "--json", "--add-dir", "/in", "Say hi"}, 4},
		{[]string{"exec", "--json", "--", "Say hi"}, 2},
		{[]string{"--", "exec", "--json", "--", "--x", "--"}, 3},
		{[]string{"exec", "Say hi"}, 1},
		{[]string{"--model", "m", "exec", "--json", "Say hi"}, 4},
	} {
		if got, ok := resumePlace(c.args, before); !ok || got != c.want {
			t.Errorf("%q: %d, %v; want %d", c.args, got, ok, c.want)
		}
	}
	for _, args := range [][]string{{"exec"}, {"--json", "exec"}, {"--json", "Say hi"}, nil} {
		if got, ok := resumePlace(args, before); ok {
			t.Errorf("%q: %d; want no place", args, got)
		}
	}
	if got, ok := resumePlace([]string{"exec", "--json", "Say hi"}, runtimes.Resume{After: "exec"}); !ok || got != 1 {
		t.Errorf("without place: %d, %v; want 1", got, ok)
	}
}

// TestTheResumeScriptInsertsTheArgumentsBeforeThePrompt pins the script for resume.place
// before_last: the runtime gets the resume arguments right before its last argument, or
// right before the -- that comes before it.
func TestTheResumeScriptInsertsTheArgumentsBeforeThePrompt(t *testing.T) {
	dir := t.TempDir()
	transcript := filepath.Join(dir, ResumeTranscript)
	if err := os.WriteFile(transcript, []byte("{\"a\":1}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := runtimes.Resume{After: "exec", Place: runtimes.PlaceBeforeLast}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"exec", "--json", "--add-dir", "/in", "it's a 'prompt'"}, "[exec]\n[--json]\n[--add-dir]\n[/in]\n[resume]\n[s 1]\n[it's a 'prompt']\n"},
		{[]string{"exec", "--json", "--", "--prompt"}, "[exec]\n[--json]\n[resume]\n[s 1]\n[--]\n[--prompt]\n"},
	} {
		launch := append([]string{"/bin/sh", "-c", `for a; do echo "[$a]"; done`, "sh"}, c.args...)
		at, ok := resumePlace(launch[1:], before)
		if !ok {
			t.Fatalf("%q: no place", c.args)
		}
		script := filepath.Join(dir, ResumeScript)
		text := resumeScriptAt("0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d", transcript, "~/.rollouts/sessions/2026/11/13/rollout-a-s.jsonl", []string{"resume", "s 1"}, 1+at)
		if err := os.WriteFile(script, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/sh", append([]string{script}, launch...)...)
		cmd.Env = []string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != c.want {
			t.Errorf("%q: the runtime got %q; want %q", c.args, out, c.want)
		}
	}
}

// TestAWalledRestoreMatchesResumePath pins the shape check of a walled restore's
// resume.path below resume.prefix: Claude Code's <slug>/<session id>.jsonl with a
// slug of any working directory, and a pattern with *, each with the run
// configuration's session id. Other shapes, another session id and a . or .. name fail.
func TestAWalledRestoreMatchesResumePath(t *testing.T) {
	const id = "0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e"
	claude := newPathPattern("{cwd_slug}/{session_id}.jsonl", id, "", true)
	for rel, want := range map[string]bool{
		"-paused/" + id + ".jsonl":                      true,
		"-workspace/probe.jsonl":                        false,
		id + ".jsonl":                                   false,
		"-w/x/" + id + ".jsonl":                         false,
		"../" + id + ".jsonl":                           false,
		"-w/5d0c6a51-3b2e-4f7a-9c1d-8e6f4a2b0c37.jsonl": false,
		"-w/" + strings.ToUpper(id) + ".jsonl":          false,
		"we!rd/" + id + ".jsonl":                        false,
		strings.Repeat("a", 256) + "/" + id + ".jsonl":  false,
		strings.Repeat("a", 255) + "/" + id + ".jsonl":  true,
	} {
		if got := claude.matches(rel); got != want {
			t.Errorf("Claude Code's, %s: %v; want %v", rel, got, want)
		}
	}
	rollout := newPathPattern("*/*/*/rollout-*-{session_id}.jsonl", id, "", true)
	for rel, want := range map[string]bool{
		"2026/11/13/rollout-2026-11-13T10-00-00-" + id + ".jsonl": true,
		"2026/11/rollout-a-" + id + ".jsonl":                      false,
		"2026/../13/rollout-a-" + id + ".jsonl":                   false,
	} {
		if got := rollout.matches(rel); got != want {
			t.Errorf("a pattern, %s: %v; want %v", rel, got, want)
		}
	}
}
