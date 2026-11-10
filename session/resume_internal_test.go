package session

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestFetchTranscriptCountsOnlyACleanEnd pins the read of GET /resume/transcript: the
// bytes of a 200 that ends cleanly; an error that starts with what happened for a 404
// with its code, an empty transcript, one over the limit, and a stream that ends before
// its end, as the gateway ends one whose digest does not match.
func TestFetchTranscriptCountsOnlyACleanEnd(t *testing.T) {
	old := maxResumeTranscript
	maxResumeTranscript = 16
	t.Cleanup(func() { maxResumeTranscript = old })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/runs/r/resume/transcript" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		switch r.Header.Get("X-Case") {
		case "ok":
			w.Header().Set("Content-Type", "application/x-ndjson")
			io.WriteString(w, "{\"a\":1}\n")
		case "404":
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"not_found","message":"Continue a paused run of this work item."}`)
		case "empty":
		case "large":
			io.WriteString(w, strings.Repeat("x", 17))
		case "cut":
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "{\"a\":1}\n")
			c, buf, _ := w.(http.Hijacker).Hijack()
			buf.Flush()
			c.Close()
		}
	}))
	t.Cleanup(srv.Close)
	for c, want := range map[string]string{
		"ok":    "",
		"404":   "GET /resume/transcript returned 404 not_found",
		"empty": "GET /resume/transcript returned an empty transcript",
		"large": "GET /resume/transcript returned more than 16 bytes",
		"cut":   "the read of GET /resume/transcript ended before the transcript's end, so its digest is not verified",
	} {
		client := &http.Client{Transport: headerTransport{"X-Case", c}}
		b, err := fetchTranscript(context.Background(), client, srv.URL+"/v1/runs/r")
		switch {
		case want == "" && (err != nil || string(b) != "{\"a\":1}\n"):
			t.Errorf("%s: %q %v", c, b, err)
		case want != "" && (err == nil || !strings.HasPrefix(err.Error(), want)):
			t.Errorf("%s: %v; want %q", c, err, want)
		}
	}
}

// headerTransport sets one header on each request it sends.
type headerTransport struct{ name, value string }

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set(h.name, h.value)
	return http.DefaultTransport.RoundTrip(r)
}

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
	want := "The runtime starts without a resume: the transcript of run 0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d could not be restored: the copy to ~/" + rel + " failed"
	last := ""
	for sc := bufio.NewScanner(strings.NewReader(stderr)); sc.Scan(); {
		last = sc.Text()
	}
	if last != want {
		t.Errorf("stderr %q; want its last line %q", stderr, want)
	}
}
