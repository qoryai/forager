package session_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/wall"
)

// homer is a runtime with resume, written as data alone, whose transcript lies below
// its home in HOMER_HOME, its resume.home_var, as Codex writes its rollouts below
// CODEX_HOME: in a directory for each date, with the session id at the end of the
// file's name. Its arguments follow exec, and its start has source startup, as
// Codex's does.
const homer = `version: 1
runtime: homer
runtime_version: "1"
sources:
  output: {format: jsonl}
resume:
  home_var: HOMER_HOME
  path: ${HOMER_HOME}/sessions/*/*/*/rollout-*-{session_id}.jsonl
  prefix: ${HOMER_HOME}/sessions/
  args: [resume, "{session_id}"]
  after: exec
rules:
  - source: output
    match: {type: start}
    type: dev.qory.runtime.started
    data: {session_id: session_id}
    set: {source: startup}
`

// homerScript is the homer's program: it prints the transcript it finds below
// $SESSIONS, the sessions directory on this machine, else below $HOMER_HOME/sessions,
// and its arguments, then its start, then appends two lines to its transcript, or to a
// file it makes in a dated directory when it found none.
const homerScript = `d="${SESSIONS:-$HOMER_HOME/sessions}"
f=$(ls "$d"/*/*/*/rollout-*-` + rolloutID + `.jsonl 2>/dev/null | head -n 1)
if [ -n "$f" ]; then echo "restored: $(cat "$f")"; else f="$d/2026/11/13/rollout-t-` + rolloutID + `.jsonl"; mkdir -p "${f%/*}"; fi
echo "args: $*"
echo '{"type":"start","session_id":"` + rolloutID + `","source":"exec"}'
echo '{"line":1}' >> "$f"
sleep 0.3
echo '{"line":2}' >> "$f"
`

// pausedRun is the id of the paused run the homer's sessions continue.
const pausedRun = "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d"

// homerSpec is a session of the homer, started as exec --json, on the fake local link,
// with HOMER_HOME=homeVar as a fixed value of the launch, as qory sets CODEX_HOME, or no
// HOMER_HOME when homeVar is "-". With paused not empty, the run answer has resume with
// paused as its path, and the transcript request gets ok.
func homerSpec(t *testing.T, homeVar, paused string) runSpec {
	t.Helper()
	sp, g := specGateway(t)
	rt, err := runtimes.Described("homer.yaml", []byte(homer), nil)
	if err != nil {
		t.Fatal(err)
	}
	sp.Runtime, sp.Forwarder = rt, nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", homerScript, "sh", "exec", "--json"}
	sp.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
	if homeVar != "-" {
		sp.LaunchFixed = []string{"HOMER_HOME=" + homeVar}
	}
	session.SetTranscriptPoll(&sp.SessionSpec, 50*time.Millisecond)
	if paused != "" {
		g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
			a := linktest.RunAnswer(req)
			a["resume"] = map[string]any{"run_id": pausedRun, "session_id": rolloutID, "path": paused}
			return linktest.Reply{Status: 200, Body: a}
		})
		g.OnTranscript(func(string) linktest.Reply { return linktest.Reply{Status: 200, Body: []byte("ok\n")} })
	}
	return sp
}

// TestAnUnwalledHomeVariableResumesBelowALinkedHome pins a run with no wall whose
// runtime's resume.prefix starts with ${HOMER_HOME}/, set as a fixed value of the launch
// to a folder below a home that is a symbolic link. The paused run's transcript lay
// below another HOMER_HOME: the session restores it at the same names below this run's,
// through the link, the runtime resumes with the arguments after exec, and the session
// sends the file under its path below this run's HOMER_HOME, the restored bytes first.
// The runtime's start, whose rule sets source startup, has source resume. A run with no
// resume finds and sends the file the runtime makes there, and its start has startup.
func TestAnUnwalledHomeVariableResumesBelowALinkedHome(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	homeVar := link + "/.homer"
	const below = "2025/01/02/rollout-p-" + rolloutID + ".jsonl"
	sp := homerSpec(t, homeVar, "/srv/another-home/sessions/"+below)
	sp.Env = append(sp.Env, "HOME="+link)
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	if out := runLogText(t, evs); !strings.Contains(out, "restored: ok\n") || !strings.Contains(out, "args: exec resume "+rolloutID+" --json\n") || strings.Contains(out, "without a resume") {
		t.Errorf("the runtime's output %q", out)
	}
	want := homeVar + "/sessions/" + below
	if path, file := transcriptOf(t, evs); path != want || file != "ok\n{\"line\":1}\n{\"line\":2}\n" {
		t.Errorf("the transcript %s %q; want %s", path, file, want)
	}
	if b, err := os.ReadFile(filepath.Join(real, ".homer", "sessions", below)); err != nil || !strings.HasPrefix(string(b), "ok\n") {
		t.Errorf("the restored file %q, %v", b, err)
	}
	startedFrom(t, evs, "resume")

	other := link + "/.homer-new"
	sp = homerSpec(t, other, "")
	res, err = run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	made := other + "/sessions/2026/11/13/rollout-t-" + rolloutID + ".jsonl"
	evs = events(t, res)
	if path, file := transcriptOf(t, evs); path != made || file != "{\"line\":1}\n{\"line\":2}\n" {
		t.Errorf("with no resume, the transcript %s %q; want %s", path, file, made)
	}
	startedFrom(t, evs, "startup")
}

// startedFrom checks that evs have one dev.qory.runtime.started, with source.
func startedFrom(t *testing.T, evs []map[string]any, source string) {
	t.Helper()
	started := ofType(evs, "dev.qory.runtime.started")
	if len(started) != 1 || data(started[0])["source"] != source {
		t.Errorf("dev.qory.runtime.started is %v; want one, from %s", started, source)
	}
}

// TestAWalledHomeVariableFollowsTheMountRules pins a walled run whose runtime's
// resume.prefix starts with ${HOMER_HOME}/, set as a fixed value of the launch to a
// place inside, with an empty environment otherwise, as qory starts Codex. The resolved
// prefix follows the rules of an absolute one: inside a writable mount's Target the
// session restores the paused run's transcript at the same names below this run's
// HOMER_HOME, in the mount on this machine, and sends it under its path inside; inside a
// read-only one the runtime starts without a resume, with the two lines; in no mount the
// wall binds the transcript directory at the resolved prefix.
func TestAWalledHomeVariableFollowsTheMountRules(t *testing.T) {
	t.Setenv("QORY_TEST_HOST_ONLY", "1")
	const below = "2025/01/02/rollout-p-" + rolloutID + ".jsonl"
	paused := "/var/lib/old-home/sessions/" + below
	t.Run("writable mount", func(t *testing.T) {
		home := t.TempDir()
		sp := homerSpec(t, homeInside, paused)
		sp.Env = append(sp.Env, "SESSIONS="+filepath.Join(home, "sessions"))
		w := &openWall{}
		sp.Wall, sp.Image = w, "example.com/agent:1"
		sp.Mounts = []wall.Mount{{Path: sp.Dir}, {Path: home, Target: homeInside}}
		res, err := run(context.Background(), sp)
		if err != nil {
			t.Fatal(err)
		}
		evs := events(t, res)
		if out := runLogText(t, evs); !strings.Contains(out, "restored: ok\n") || !strings.Contains(out, "args: exec resume "+rolloutID+" --json\n") || strings.Contains(out, "without a resume") {
			t.Errorf("the runtime's output %q", out)
		}
		if w.got.Transcript != (wall.Transcript{}) {
			t.Errorf("the launch's transcript directory %+v; want none", w.got.Transcript)
		}
		if got, want := sentTranscript(t, evs, homeInside+"/sessions/"+below), "ok\n{\"line\":1}\n{\"line\":2}\n"; got != want {
			t.Errorf("the transcript %q; want %q", got, want)
		}
		startedFrom(t, evs, "resume")
	})
	t.Run("read-only mount", func(t *testing.T) {
		home := t.TempDir()
		sp := homerSpec(t, homeInside, paused)
		sp.Env = append(sp.Env, "SESSIONS="+filepath.Join(t.TempDir(), "sessions"))
		sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		sp.Mounts = []wall.Mount{{Path: sp.Dir}, {Path: home, ReadOnly: true, Target: homeInside}}
		res, err := run(context.Background(), sp)
		if err != nil {
			t.Fatal(err)
		}
		evs := events(t, res)
		out := runLogText(t, evs)
		cause := "resume.prefix " + homeInside + "/sessions/ lies inside the mount " + home + ", shown at " + homeInside + ", read-only, so the runtime cannot write its transcript there"
		if !strings.Contains(out, "could not be restored: "+cause+"\n") || !strings.Contains(out, "A continuation of this run starts the runtime without a resume: "+cause+"\n") || !strings.Contains(out, "args: exec --json\n") {
			t.Errorf("the runtime's output %q", out)
		}
		if n := len(ofType(evs, event.SessionTranscript)); n != 0 {
			t.Errorf("%d transcript chunks; want none", n)
		}
		startedFrom(t, evs, "startup")
	})
	t.Run("no mount", func(t *testing.T) {
		sp := homerSpec(t, homeInside, paused)
		sp.Env = append(sp.Env, "SESSIONS="+filepath.Join(t.TempDir(), "sessions"))
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
		if b, err := os.ReadFile(filepath.Join(dir, below)); err != nil || string(b) != "ok\n" {
			t.Errorf("the restored transcript %q, %v", b, err)
		}
	})
}

// TestAHomeVariableWithNoUsableValueGetsNoResume pins a runtime whose resume.home_var,
// HOMER_HOME, is unset, empty, relative, or has a .. name, with a wall and without one:
// the runtime starts without the resume arguments, the session restores nothing and
// sends no transcript, and writes the line of a failed resume and the line of no
// transcript, each starting with the fix that contains the variable's name. The
// runtime's start keeps source startup.
func TestAHomeVariableWithNoUsableValueGetsNoResume(t *testing.T) {
	fix := "Set HOMER_HOME to an absolute path in UTF-8 in the launch's environment, with no . or .. name, no // or / at its end, and no space, non-printable character, *, $, {, }, comma or double quote"
	for _, c := range []struct{ value, cause string }{
		{"-", "HOMER_HOME is not set"},
		{"", "HOMER_HOME is empty"},
		{"relative/home", `HOMER_HOME is "relative/home"`},
		{"/var/lib/../home", `HOMER_HOME is "/var/lib/../home"`},
	} {
		for _, walled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%q walled %v", c.value, walled), func(t *testing.T) {
				sessions := filepath.Join(t.TempDir(), "sessions")
				sp := homerSpec(t, c.value, "/var/lib/old-home/sessions/2025/01/02/rollout-p-"+rolloutID+".jsonl")
				sp.Env = append(sp.Env, "SESSIONS="+sessions)
				if walled {
					t.Setenv("QORY_TEST_HOST_ONLY", "1")
					sp.Wall, sp.Image, sp.Mounts = &openWall{}, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
				}
				res, err := run(context.Background(), sp)
				if err != nil {
					t.Fatal(err)
				}
				evs := events(t, res)
				out := runLogText(t, evs)
				cause := c.cause + ", so resume.prefix ${HOMER_HOME}/sessions/ has no value"
				failed := fix + ". The runtime starts without a resume: the transcript of run " + pausedRun + " could not be restored: " + cause + "\n"
				none := fix + ". A continuation of this run starts the runtime without a resume: " + cause + "\n"
				if i, j := strings.Index(out, failed), strings.Index(out, none); i < 0 || j < i || !strings.Contains(out, "args: exec --json\n") || strings.Contains(out, "restored: ok") {
					t.Errorf("the runtime's output %q\nwant %q, then %q", out, failed, none)
				}
				if n := len(ofType(evs, event.SessionTranscript)); n != 0 {
					t.Errorf("%d transcript chunks; want none", n)
				}
				if _, err := os.Stat(filepath.Join(res.Dir, "transcripts")); err == nil {
					t.Error("the session made a transcript directory")
				}
				startedFrom(t, evs, "startup")
			})
		}
	}
}
