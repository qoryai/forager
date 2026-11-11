package session

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	text := resumeScript("0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d", transcript, rel, []string{"--resume", "s 1"})
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
