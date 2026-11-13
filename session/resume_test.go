package session_test

import (
	"context"
	"encoding/base64"
	"fmt"
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
const resumerScript = `f="$HOME/.resumer/$SLUG/0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e.jsonl"
mkdir -p "${f%/*}"
[ -f "$f" ] && echo "restored: $(cat "$f")"
echo "args: $*"
echo '{"type":"start","session_id":"0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e","source":"resume"}'
echo '{"line":1,"key":"sk-fake-resume-secret"}' >> "$f"
sleep 0.3
echo '{"line":2}' >> "$f"
`

// resumerSpec is a session of the resumer on the fake local link g, with a home that no
// other session has, and the run's masker with the resumer's secret; the run answer has resume, and
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
		a["resume"] = map[string]any{"run_id": "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d", "session_id": "0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e", "path": "~/.resumer/" + slug + "/0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e.jsonl"}
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
	sp, g, _ := resumerSpec(t, "ok\n")
	session.SetTranscriptPoll(&sp.SessionSpec, 50*time.Millisecond)
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	out := runLogText(t, evs)
	if !strings.Contains(out, "restored: ok\n") || !strings.Contains(out, "args: --resume 0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e\n") {
		t.Errorf("the runtime's output %q", out)
	}
	if got := g.Transcripts(); !slices.Equal(got, []string{res.RunID}) {
		t.Errorf("transcript requests %v", got)
	}
	chunks := ofType(evs, event.SessionTranscript)
	var file []byte
	for _, c := range chunks {
		d := data(c)
		if d["session"] != 1.0 || d["session_id"] != "0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e" || d["path"] != "~/.resumer/"+cwdSlugOf(sp.Dir)+"/0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e.jsonl" || d["offset"] != float64(len(file)) {
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
	want := "Check that the control plane has the transcript of run 0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d. The runtime starts without a resume: the transcript of run 0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d could not be restored: the gateway returned 404 not_found to the transcript request\n"
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

// transcriptWall is an open wall that stands for the bind of the session's transcript
// directory with a link: ~/<Under> under home, the launch's HOME, leads to it.
type transcriptWall struct {
	openWall
	home string
}

func (w *transcriptWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *transcriptWall) Wrap(ctx context.Context, l wall.Launch) (wall.Launch, error) {
	if l.Transcript.Path != "" {
		if err := os.Symlink(l.Transcript.Path, filepath.Join(w.home, l.Transcript.Under)); err != nil {
			return wall.Launch{}, err
		}
	}
	return w.openWall.Wrap(ctx, l)
}

// TestAWalledRunRestoresTheTranscriptInItsDirectory pins a run behind a wall whose run
// answer has resume: the session writes the transcript in the session's transcript
// directory, transcripts/1/ in the run directory, mode 0700, which the wall binds at
// resume.prefix inside, and starts the runtime with the resume arguments, through no
// script; then it reads the transcript there and sends it from offset 0, the restored
// bytes first, masked.
func TestAWalledRunRestoresTheTranscriptInItsDirectory(t *testing.T) {
	t.Setenv("QORY_TEST_HOST_ONLY", "1")
	sp, _, home := resumerSpec(t, "ok\n")
	session.SetTranscriptPoll(&sp.SessionSpec, 50*time.Millisecond)
	w := &transcriptWall{home: home}
	sp.Wall, sp.Image, sp.Mounts = w, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	out := runLogText(t, evs)
	if !strings.Contains(out, "restored: ok\n") || !strings.Contains(out, "args: --resume 0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e\n") || strings.Contains(out, "without a resume") {
		t.Errorf("the runtime's output %q", out)
	}
	dir := filepath.Join(res.Dir, "transcripts", "1")
	if w.got.Transcript != (wall.Transcript{Path: dir, Under: ".resumer"}) {
		t.Errorf("the launch's transcript directory %+v; want %s at .resumer", w.got.Transcript, dir)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the transcript directory %v %v; want mode 0700", fi, err)
	}
	if _, err := os.Stat(filepath.Join(res.SessionDir, session.ResumeScript)); err == nil {
		t.Error("a walled resume wrote a script")
	}
	var file []byte
	for _, c := range ofType(evs, event.SessionTranscript) {
		d := data(c)
		if d["path"] != "~/.resumer/"+cwdSlugOf(sp.Dir)+"/0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e.jsonl" || d["offset"] != float64(len(file)) {
			t.Fatalf("chunk %v after %d bytes", d, len(file))
		}
		b, _ := base64.StdEncoding.DecodeString(d["bytes"].(string))
		file = append(file, b...)
	}
	if want := "ok\n{\"line\":1,\"key\":\"" + mask.Secret + "\"}\n{\"line\":2}\n"; string(file) != want {
		t.Errorf("the transcript %q; want %q", file, want)
	}
}

// TestAWalledResumeOfAnotherShapeFails pins a walled run whose run answer's resume has a
// session id that is not a UUID in lower case: the runtime starts without the resume
// arguments, with the line of a failed resume, and no restored file is written in the
// transcript directory.
func TestAWalledResumeOfAnotherShapeFails(t *testing.T) {
	t.Setenv("QORY_TEST_HOST_ONLY", "1")
	sp, g, home := resumerSpec(t, "ok\n")
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["resume"] = map[string]any{"run_id": "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d", "session_id": "s-1", "path": "~/.resumer/" + cwdSlugOf(sp.Dir) + "/s-1.jsonl"}
		return linktest.Reply{Status: 200, Body: a}
	})
	sp.Wall, sp.Image, sp.Mounts = &transcriptWall{home: home}, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	out := runLogText(t, events(t, res))
	want := "Check resume.session_id in the run configuration. The runtime starts without a resume: the transcript of run 0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d could not be restored: its session id s-1 is not a UUID in lower case\n"
	if !strings.Contains(out, want) || !strings.Contains(out, "args: \n") {
		t.Errorf("the runtime's output %q; want %q", out, want)
	}
	if _, err := os.Stat(filepath.Join(res.Dir, "transcripts", "1", cwdSlugOf(sp.Dir), "s-1.jsonl")); err == nil {
		t.Error("the restored file was written")
	}
}

// TestAJoinReturnsWithNoTranscriptReaderLeft pins that Join stops the transcript's
// reader before it returns: no goroutine reads the runtime's transcript once Join
// returns, before the run's Close, for a runtime that exits and for one whose start
// fails after the reads started. Both end the reads on Join's path after the runtime;
// the deferred end, which only a panic between the start and that path reaches, is
// not covered here.
func TestAJoinReturnsWithNoTranscriptReaderLeft(t *testing.T) {
	// joined opens a run of sp, joins it, counts the transcript readers, and closes the
	// run.
	joined := func(t *testing.T, sp runSpec) (*session.Result, int, error) {
		t.Helper()
		r, err := session.Open(context.Background(), opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		res, err := r.Join(context.Background(), sp.SessionSpec)
		readers := session.TranscriptReaders()
		if _, cerr := r.Close(context.Background(), outcomeOf(res, err)); cerr != nil {
			t.Fatal(cerr)
		}
		return res, readers, err
	}
	t.Run("a runtime that exits", func(t *testing.T) {
		sp, _, _ := resumerSpec(t, "ok\n")
		session.SetTranscriptPoll(&sp.SessionSpec, time.Millisecond)
		res, readers, err := joined(t, sp)
		if err != nil {
			t.Fatal(err)
		}
		if readers != 0 {
			t.Errorf("%d transcript readers after the join", readers)
		}
		if len(ofType(events(t, res), event.SessionTranscript)) == 0 {
			t.Error("no dev.qory.session.transcript before the join returned")
		}
	})
	t.Run("a runtime that does not start", func(t *testing.T) {
		sp, _, _ := resumerSpec(t, "")
		session.SetTranscriptPoll(&sp.SessionSpec, time.Millisecond)
		sp.Command = filepath.Join(t.TempDir(), "none")
		_, readers, err := joined(t, sp)
		if err == nil || !strings.Contains(err.Error(), "no such file or directory") {
			t.Fatalf("the join's error %v; want the failed start", err)
		}
		if readers != 0 {
			t.Errorf("%d transcript readers after the join", readers)
		}
	})
}

// rollouter is a runtime with resume, written as data alone, that writes its transcript
// as Codex writes its rollouts: below ~/.rollouter/ in a directory for each date, with
// the session id at the end of the file's name. Its resume has no path_from, and its
// arguments follow exec.
const rollouter = `version: 1
runtime: rollouter
runtime_version: "1"
sources:
  output: {format: jsonl}
resume:
  path: ~/.rollouter/*/*/*/rollout-*-{session_id}.jsonl
  prefix: ~/.rollouter/
  args: [resume, "{session_id}"]
  after: exec
rules:
  - source: output
    match: {type: start}
    type: dev.qory.runtime.started
    data: {session_id: session_id, source: source}
`

// rolloutID is the rollouter's session id.
const rolloutID = "0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e"

// rollouterScript is the rollouter's program: it prints the transcript it finds under
// its home and its arguments, then its start, then appends two lines to its
// transcript, or to a file it makes in a dated directory when it found none.
const rollouterScript = `f=$(ls "$HOME"/.rollouter/*/*/*/rollout-*-` + rolloutID + `.jsonl 2>/dev/null | head -n 1)
if [ -n "$f" ]; then echo "restored: $(cat "$f")"; else f="$HOME/.rollouter/2026/11/13/rollout-t-` + rolloutID + `.jsonl"; mkdir -p "${f%/*}"; fi
echo "args: $*"
echo '{"type":"start","session_id":"` + rolloutID + `","source":"exec"}'
echo '{"line":1}' >> "$f"
sleep 0.3
echo '{"line":2}' >> "$f"
`

// rollouterSpec is a session of the rollouter, started as exec --json, on the fake
// local link g, with a home that no other session has. With paused not empty, the run
// answer has resume with paused as its path, and the transcript request gets ok.
func rollouterSpec(t *testing.T, paused string) (runSpec, string) {
	t.Helper()
	sp, g := specGateway(t)
	rt, err := runtimes.Described("rollouter.yaml", []byte(rollouter), nil)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	sp.Runtime, sp.Forwarder = rt, nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", rollouterScript, "sh", "exec", "--json"}
	sp.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home}
	session.SetTranscriptPoll(&sp.SessionSpec, 50*time.Millisecond)
	if paused != "" {
		g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
			a := linktest.RunAnswer(req)
			a["resume"] = map[string]any{"run_id": "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d", "session_id": rolloutID, "path": paused}
			return linktest.Reply{Status: 200, Body: a}
		})
		g.OnTranscript(func(string) linktest.Reply { return linktest.Reply{Status: 200, Body: []byte("ok\n")} })
	}
	return sp, home
}

// transcriptOf is the file the dev.qory.session.transcript chunks of evs contain, in
// order, and the one path they have.
func transcriptOf(t *testing.T, evs []map[string]any) (string, string) {
	t.Helper()
	var file []byte
	path := ""
	for _, c := range ofType(evs, event.SessionTranscript) {
		d := data(c)
		if path == "" {
			path, _ = d["path"].(string)
		}
		if d["path"] != path || d["offset"] != float64(len(file)) {
			t.Fatalf("chunk %v after %d bytes of %s", d, len(file), path)
		}
		b, _ := base64.StdEncoding.DecodeString(d["bytes"].(string))
		file = append(file, b...)
	}
	return path, string(file)
}

// TestARolloutRunResumesWithItsArgumentsAfterExec pins a runtime whose resume.path has
// a * and whose resume has after, with a wall and without one: the session restores
// the paused run's transcript at the run configuration's resume.path, in dated
// directories, inserts the resume arguments right after exec, and sends the restored
// file as the transcript, the restored bytes first.
func TestARolloutRunResumesWithItsArgumentsAfterExec(t *testing.T) {
	paused := "~/.rollouter/2025/01/02/rollout-p-" + rolloutID + ".jsonl"
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("walled ", walled), func(t *testing.T) {
			sp, home := rollouterSpec(t, paused)
			if walled {
				t.Setenv("QORY_TEST_HOST_ONLY", "1")
				sp.Wall, sp.Image, sp.Mounts = &transcriptWall{home: home}, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
			}
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			evs := events(t, res)
			out := runLogText(t, evs)
			if !strings.Contains(out, "restored: ok\n") || !strings.Contains(out, "args: exec resume "+rolloutID+" --json\n") || strings.Contains(out, "without a resume") {
				t.Errorf("the runtime's output %q", out)
			}
			if path, file := transcriptOf(t, evs); path != paused || file != "ok\n{\"line\":1}\n{\"line\":2}\n" {
				t.Errorf("the transcript %s %q", path, file)
			}
			if _, err := os.Stat(filepath.Join(res.SessionDir, session.ResumeScript)); (err == nil) == walled {
				t.Errorf("the resume script: %v", err)
			}
		})
	}
}

// TestARolloutTranscriptIsFoundByItsPattern pins a runtime whose resume.path has a *,
// with no resume in the run answer: the session finds the file the runtime makes in
// a dated directory and sends it, with a wall and without one.
func TestARolloutTranscriptIsFoundByItsPattern(t *testing.T) {
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("walled ", walled), func(t *testing.T) {
			sp, home := rollouterSpec(t, "")
			if walled {
				t.Setenv("QORY_TEST_HOST_ONLY", "1")
				sp.Wall, sp.Image, sp.Mounts = &transcriptWall{home: home}, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
			}
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			evs := events(t, res)
			if out := runLogText(t, evs); !strings.Contains(out, "args: exec --json\n") || strings.Contains(out, "without a resume") {
				t.Errorf("the runtime's output %q", out)
			}
			want := "~/.rollouter/2026/11/13/rollout-t-" + rolloutID + ".jsonl"
			if path, file := transcriptOf(t, evs); path != want || file != "{\"line\":1}\n{\"line\":2}\n" {
				t.Errorf("the transcript %s %q; want %s", path, file, want)
			}
		})
	}
}

// unboundWall is an open wall that binds no transcript directory: the agent's user
// cannot reach its place inside.
type unboundWall struct{ openWall }

func (w *unboundWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *unboundWall) CheckTranscript(context.Context, []string, wall.Transcript) (*wall.Unbound, error) {
	return &wall.Unbound{Fix: "Set HOME in the image", Cause: "the home is a file in the image"}, nil
}

// TestAnUnboundWallTakesTheInsertedArgumentsOff pins a walled resume whose wall binds no
// transcript directory: the session takes the resume arguments off at the place it
// inserted them, after exec, so the runtime starts with exec --json, and writes the
// two lines of a failed resume.
func TestAnUnboundWallTakesTheInsertedArgumentsOff(t *testing.T) {
	t.Setenv("QORY_TEST_HOST_ONLY", "1")
	sp, _ := rollouterSpec(t, "~/.rollouter/2025/01/02/rollout-p-"+rolloutID+".jsonl")
	w := &unboundWall{}
	sp.Wall, sp.Image, sp.Mounts = w, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	out := runLogText(t, events(t, res))
	for _, want := range []string{
		"args: exec --json\n",
		"Set HOME in the image. The runtime starts without a resume: the transcript of run 0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d could not be restored: the home is a file in the image\n",
		"Set HOME in the image. A continuation of this run starts the runtime without a resume: the home is a file in the image\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in the output %q", want, out)
		}
	}
	if w.got.Transcript != (wall.Transcript{}) {
		t.Errorf("the launch's transcript directory %+v", w.got.Transcript)
	}
}

// TestAnUnwalledResumeChecksThePathAgainstThePattern pins the restore with no wall: a
// resume.path that does not match the descriptor's, here a deeper path, is a failed
// resume, as behind a wall, and the runtime starts without the resume arguments.
func TestAnUnwalledResumeChecksThePathAgainstThePattern(t *testing.T) {
	sp, g, home := resumerSpec(t, "ok\n")
	deeper := "~/.resumer/" + cwdSlugOf(sp.Dir) + "/x/0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e.jsonl"
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["resume"] = map[string]any{"run_id": "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d", "session_id": "0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e", "path": deeper}
		return linktest.Reply{Status: 200, Body: a}
	})
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	out := runLogText(t, events(t, res))
	want := "Check resume.path in the run configuration. The runtime starts without a resume: the transcript of run 0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d could not be restored: its path " + deeper + " does not match ~/.resumer/{cwd_slug}/0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e.jsonl, with {cwd_slug} a slug\n"
	if !strings.Contains(out, want) || !strings.Contains(out, "args: \n") {
		t.Errorf("the runtime's output %q; want %q", out, want)
	}
	if _, err := os.Stat(filepath.Join(home, strings.TrimPrefix(deeper, "~/"))); err == nil {
		t.Error("the transcript was restored")
	}
}

// absoluteResumer is a runtime with resume whose transcript lies under the absolute
// prefix, a home at a fixed place, at <prefix><session id>.jsonl; a line
// {"type":"start",...} of its output is its dev.qory.runtime.started. Its program,
// absoluteResumerScript, writes the transcript below $PREFIX, the prefix's directory on
// this machine.
func absoluteResumer(t *testing.T, prefix string) runtimes.Runtime {
	t.Helper()
	d := "version: 1\nruntime: resumer\nruntime_version: \"1\"\nsources:\n  output: {format: jsonl}\n" +
		"resume:\n  path: " + prefix + "{session_id}.jsonl\n  prefix: " + prefix + "\n  args: [--resume, \"{session_id}\"]\n" +
		"rules:\n  - source: output\n    match: {type: start}\n    type: dev.qory.runtime.started\n    data: {session_id: session_id, source: source}\n"
	rt, err := runtimes.Described("resumer.yaml", []byte(d), nil)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// absoluteResumerScript prints the transcript it finds below $PREFIX and its arguments,
// then its start, then appends two lines to its transcript.
const absoluteResumerScript = `f="$PREFIX/0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e.jsonl"
mkdir -p "${f%/*}"
[ -f "$f" ] && echo "restored: $(cat "$f")"
echo "args: $*"
echo '{"type":"start","session_id":"0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e","source":"resume"}'
echo '{"line":1}' >> "$f"
sleep 0.3
echo '{"line":2}' >> "$f"
`

// absoluteResumerSpec is a session of the absolute resumer with prefix, whose
// transcript lies below dir on this machine, on the fake local link; the run answer's
// resume restores "ok\n" at the prefix.
func absoluteResumerSpec(t *testing.T, prefix, dir string) runSpec {
	t.Helper()
	sp, g := specGateway(t)
	sp.Runtime, sp.Forwarder = absoluteResumer(t, prefix), nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", absoluteResumerScript, "sh"}
	sp.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "PREFIX=" + dir}
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["resume"] = map[string]any{"run_id": "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d", "session_id": "0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e", "path": prefix + "0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e.jsonl"}
		return linktest.Reply{Status: 200, Body: a}
	})
	g.OnTranscript(func(string) linktest.Reply { return linktest.Reply{Status: 200, Body: []byte("ok\n")} })
	session.SetTranscriptPoll(&sp.SessionSpec, 50*time.Millisecond)
	return sp
}

// sentTranscript is the transcript a run sent, its chunks joined, each of the path.
func sentTranscript(t *testing.T, evs []map[string]any, path string) string {
	t.Helper()
	var file []byte
	for _, c := range ofType(evs, event.SessionTranscript) {
		d := data(c)
		if d["path"] != path || d["offset"] != float64(len(file)) {
			t.Fatalf("chunk %v after %d bytes; want the path %s", d, len(file), path)
		}
		b, _ := base64.StdEncoding.DecodeString(d["bytes"].(string))
		file = append(file, b...)
	}
	return string(file)
}

// TestARunWithAnAbsolutePrefixRestoresAndSendsItsTranscript pins a run with no wall
// whose runtime's resume.prefix is absolute: the resume script writes the transcript at
// its absolute path, whatever HOME is, the runtime resumes from it, and the session
// sends the file under that path, which starts with /.
func TestARunWithAnAbsolutePrefixRestoresAndSendsItsTranscript(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent-home", "sessions")
	prefix := dir + "/"
	sp := absoluteResumerSpec(t, prefix, dir)
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	if out := runLogText(t, evs); !strings.Contains(out, "restored: ok\n") || !strings.Contains(out, "args: --resume 0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e\n") {
		t.Errorf("the runtime's output %q", out)
	}
	if got, want := sentTranscript(t, evs, prefix+"0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e.jsonl"), "ok\n{\"line\":1}\n{\"line\":2}\n"; got != want {
		t.Errorf("the transcript %q; want %q", got, want)
	}
}

// TestAWalledAbsolutePrefixIsReadInItsWritableMount pins a walled run whose runtime's
// resume.prefix is absolute and lies inside a writable mount's Target: the session
// makes no transcript directory and the wall binds none; the session writes the restored
// transcript in the mount on this machine, the runtime resumes from it, and the session
// reads it there and sends it under its path inside.
func TestAWalledAbsolutePrefixIsReadInItsWritableMount(t *testing.T) {
	t.Setenv("QORY_TEST_HOST_ONLY", "1")
	home := t.TempDir()
	prefix := homeInside + "/sessions/"
	sp := absoluteResumerSpec(t, prefix, filepath.Join(home, "sessions"))
	w := &openWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.Mounts = []wall.Mount{{Path: sp.Dir}, {Path: home, Target: homeInside}}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	if out := runLogText(t, evs); !strings.Contains(out, "restored: ok\n") || !strings.Contains(out, "args: --resume 0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e\n") || strings.Contains(out, "without a resume") {
		t.Errorf("the runtime's output %q", out)
	}
	if w.got.Transcript != (wall.Transcript{}) {
		t.Errorf("the launch's transcript directory %+v; want none", w.got.Transcript)
	}
	if _, err := os.Stat(filepath.Join(res.Dir, "transcripts")); err == nil {
		t.Error("the session made a transcript directory")
	}
	if got, want := sentTranscript(t, evs, prefix+"0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e.jsonl"), "ok\n{\"line\":1}\n{\"line\":2}\n"; got != want {
		t.Errorf("the transcript %q; want %q", got, want)
	}
}

// TestAWalledAbsolutePrefixInAReadOnlyMountGetsNoTranscript pins a walled run whose
// runtime's absolute resume.prefix lies inside a read-only mount's Target: the runtime
// starts without the resume arguments, the session restores nothing and sends no
// transcript, and writes the line of a failed resume, then the line of no transcript.
func TestAWalledAbsolutePrefixInAReadOnlyMountGetsNoTranscript(t *testing.T) {
	t.Setenv("QORY_TEST_HOST_ONLY", "1")
	home := t.TempDir()
	prefix := homeInside + "/sessions/"
	sp := absoluteResumerSpec(t, prefix, filepath.Join(t.TempDir(), "sessions"))
	w := &openWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.Mounts = []wall.Mount{{Path: sp.Dir}, {Path: home, ReadOnly: true, Target: homeInside}}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	out := runLogText(t, evs)
	fix := "Show resume.prefix in a writable mount, or use a descriptor whose resume.prefix lies outside read-only mounts"
	cause := "resume.prefix " + prefix + " lies inside it, at " + homeInside + ", read-only, so the runtime cannot write its transcript there"
	failed := fix + ". The runtime starts without a resume: the transcript of run 0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d could not be restored: " + cause + "\n"
	none := fix + ". A continuation of this run starts the runtime without a resume: " + cause + "\n"
	if i, j := strings.Index(out, failed), strings.Index(out, none); i < 0 || j < i || !strings.Contains(out, "args: \n") || strings.Contains(out, "restored: ok") {
		t.Errorf("the runtime's output %q\nwant %q, then %q", out, failed, none)
	}
	if n := len(ofType(evs, event.SessionTranscript)); n != 0 || w.got.Transcript != (wall.Transcript{}) {
		t.Errorf("%d transcript chunks, the launch's transcript directory %+v; want none", n, w.got.Transcript)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Errorf("the read-only mount holds %v", entries)
	}
}

// TestAWalledAbsolutePrefixOutsideEveryMountIsBound pins a walled run whose runtime's
// absolute resume.prefix lies in no mount's place: the session makes its transcript
// directory, writes the restored transcript there, and the wall binds it at the prefix;
// and a mount whose place lies inside the prefix fails the session.
func TestAWalledAbsolutePrefixOutsideEveryMountIsBound(t *testing.T) {
	t.Setenv("QORY_TEST_HOST_ONLY", "1")
	prefix := homeInside + "/sessions/"
	sp := absoluteResumerSpec(t, prefix, filepath.Join(t.TempDir(), "sessions"))
	w := &openWall{}
	sp.Wall, sp.Image, sp.Mounts = w, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(res.Dir, "transcripts", "1")
	if w.got.Transcript != (wall.Transcript{Path: dir, Under: homeInside + "/sessions"}) {
		t.Errorf("the launch's transcript directory %+v; want %s at %s/sessions", w.got.Transcript, dir, homeInside)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "0b5f4c1e-2d3a-4b6c-8d7e-9f0a1b2c3d4e.jsonl")); err != nil || string(b) != "ok\n" {
		t.Errorf("the restored transcript %q, %v", b, err)
	}

	sp = absoluteResumerSpec(t, prefix, filepath.Join(t.TempDir(), "sessions"))
	w = &openWall{}
	inner := t.TempDir()
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.Mounts = []wall.Mount{{Path: sp.Dir}, {Path: inner, Target: homeInside + "/sessions/2026"}}
	err = runErr(sp)
	if want := "Show the mount " + inner + " outside resume.prefix " + prefix + ", or at a place that contains it"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("a mount inside the prefix: %v; want %q", err, want)
	}
	if w.wrapped {
		t.Error("the wall was wrapped")
	}
}
