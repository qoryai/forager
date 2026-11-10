package session_test

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/wall"
)

// resumer is a runtime with resume, written as data alone: its transcript lies under
// ~/.resumer/, and a line {"type":"start",...} of its output is its
// dev.qory.runtime.started.
const resumer = `version: 1
runtime: resumer
runtime_version: "1"
sources:
  output: {format: jsonl}
resume:
  path_from: transcript_path
  path: ~/.resumer/{cwd_slug}/{session_id}.jsonl
  prefix: ~/.resumer/
  args: [--resume, "{session_id}"]
rules:
  - source: output
    match: {type: start}
    type: dev.qory.runtime.started
    data: {session_id: session_id, source: source}
`

// resumerScript is the resumer's program: it prints the transcript it finds under its
// home and its arguments, then its start, then appends two lines to its transcript, the
// first with the run's secret.
const resumerScript = `f="$HOME/.resumer/$SLUG/s-1.jsonl"
mkdir -p "${f%/*}"
[ -f "$f" ] && echo "restored: $(cat "$f")"
echo "args: $*"
echo '{"type":"start","session_id":"s-1","source":"resume"}'
echo '{"line":1,"key":"sk-fake-resume-secret"}' >> "$f"
sleep 0.3
echo '{"line":2}' >> "$f"
`

// resumerSpec is a session of the resumer on the fake local link g, with a home of its
// own, and the run's masker with the resumer's secret; the run answer has resume, and
// the transcript request gets restored when restored is not empty, else the fake's 404.
func resumerSpec(t *testing.T, restored string) (runSpec, *linktest.Fake, string) {
	t.Helper()
	sp, g := specGateway(t)
	rt, err := runtimes.Described("resumer.yaml", []byte(resumer), nil)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	slug := cwdSlugOf(sp.Dir)
	sp.Runtime, sp.Forwarder = rt, nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", resumerScript, "sh"}
	sp.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "SLUG=" + slug}
	sp.Masker = &mask.Masker{}
	if err := sp.Masker.AddSecret([]byte("sk-fake-resume-secret")); err != nil {
		t.Fatal(err)
	}
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["resume"] = map[string]any{"run_id": "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d", "session_id": "s-1", "path": "~/.resumer/" + slug + "/s-1.jsonl"}
		return linktest.Reply{Status: 200, Body: a}
	})
	if restored != "" {
		g.OnTranscript(func(string) linktest.Reply { return linktest.Reply{Status: 200, Body: []byte(restored)} })
	}
	return sp, g, home
}

// cwdSlugOf is dir with every character other than an ASCII letter or digit replaced
// by -.
func cwdSlugOf(dir string) string {
	return strings.Map(func(r rune) rune {
		if 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' {
			return r
		}
		return '-'
	}, dir)
}

// TestARunWithResumeRestoresTheTranscriptAndResumes pins a run whose run answer has
// resume: before the runtime starts, the session reads the transcript over the link,
// GET <run.url>/<run_id>/transcript, the runtime finds the bytes at resume.path under its home and gets
// the resume arguments; and the session sends the transcript as
// dev.qory.session.transcript from offset 0, the restored bytes first, masked, between
// the session's start and its exit.
func TestARunWithResumeRestoresTheTranscriptAndResumes(t *testing.T) {
	session.SetTranscriptPoll(50 * time.Millisecond)
	sp, g, _ := resumerSpec(t, "ok\n")
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	out := runLogText(t, evs)
	if !strings.Contains(out, "restored: ok\n") || !strings.Contains(out, "args: --resume s-1\n") {
		t.Errorf("the runtime's output %q", out)
	}
	if got := g.Transcripts(); !slices.Equal(got, []string{res.RunID}) {
		t.Errorf("transcript requests %v", got)
	}
	chunks := ofType(evs, event.SessionTranscript)
	var file []byte
	for _, c := range chunks {
		d := data(c)
		if d["session"] != 1.0 || d["session_id"] != "s-1" || d["path"] != "~/.resumer/"+cwdSlugOf(sp.Dir)+"/s-1.jsonl" || d["offset"] != float64(len(file)) {
			t.Fatalf("chunk %v after %d bytes", d, len(file))
		}
		b, _ := base64.StdEncoding.DecodeString(d["bytes"].(string))
		file = append(file, b...)
	}
	if want := "ok\n{\"line\":1,\"key\":\"" + mask.Secret + "\"}\n{\"line\":2}\n"; string(file) != want {
		t.Errorf("the transcript %q; want %q", file, want)
	}
	started := slices.IndexFunc(evs, func(e map[string]any) bool { return e["type"] == event.SessionStarted })
	exited := slices.IndexFunc(evs, func(e map[string]any) bool { return e["type"] == event.SessionExited })
	for _, c := range chunks {
		if i := slices.IndexFunc(evs, func(e map[string]any) bool { return e["id"] == c["id"] }); i < started || i > exited {
			t.Errorf("a chunk at %d, outside the session's %d to %d", i, started, exited)
		}
	}
}

// TestAResumeThatFailsStartsTheRuntimeWithoutIt pins a run whose run answer has resume
// and whose read of the transcript fails, here with the gateway's 404: the runtime
// starts without the resume arguments, and the session writes the line of a
// failed resume on stderr.
func TestAResumeThatFailsStartsTheRuntimeWithoutIt(t *testing.T) {
	sp, _, home := resumerSpec(t, "")
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	out := runLogText(t, events(t, res))
	if strings.Contains(out, "restored: ok") || !strings.Contains(out, "args: \n") {
		t.Errorf("the runtime's output %q", out)
	}
	want := "The runtime starts without a resume: the transcript of run 0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d could not be restored: the gateway returned 404 not_found to the transcript request\n"
	if !strings.Contains(out, want) {
		t.Errorf("no line %q in %q", want, out)
	}
	if _, err := os.Stat(filepath.Join(res.SessionDir, session.ResumeScript)); err == nil {
		t.Error("a failed resume wrote its script")
	}
	if entries, _ := os.ReadDir(filepath.Join(home, ".resumer")); len(entries) != 1 {
		t.Errorf("the home's transcripts %v", entries)
	}
}

// TestAWalledRunResumesAndSendsNoTranscript pins a run behind a wall whose run answer has
// resume: the launch restores the transcript and resumes, through the script in the
// session's directory, which the wall binds read-only; and the session sends no
// dev.qory.session.transcript, since the runtime's home lies inside the agent's
// container, and writes one line that says so.
func TestAWalledRunResumesAndSendsNoTranscript(t *testing.T) {
	t.Setenv("QORY_TEST_HOST_ONLY", "1")
	sp, _, _ := resumerSpec(t, "ok\n")
	w := &openWall{}
	sp.Wall, sp.Image, sp.Mounts = w, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	out := runLogText(t, evs)
	if !strings.Contains(out, "restored: ok\n") || !strings.Contains(out, "args: --resume s-1\n") {
		t.Errorf("the runtime's output %q", out)
	}
	if want := "A continuation of this run starts the runtime without a resume: the runtime's transcript lies inside the agent's container, which the session does not read\n"; strings.Count(out, want) != 1 {
		t.Errorf("the runtime's output %q; want the line %q once", out, want)
	}
	if got := ofType(evs, event.SessionTranscript); len(got) != 0 {
		t.Errorf("transcript events behind a wall: %v", got)
	}
	if !slices.Contains(w.got.Mounts, wall.Mount{Path: res.SessionDir, ReadOnly: true}) {
		t.Errorf("mounts %v", w.got.Mounts)
	}
}
