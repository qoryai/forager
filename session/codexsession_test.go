package session_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/session/runtimes/codex"
)

// codexScript stands in for codex exec --json: it prints the rollout it finds below
// $CODEX_HOME/sessions and its arguments, then thread.started and turn.completed as
// Codex prints them, and appends two lines to its rollout, or to a file it makes in a
// dated directory when it found none.
const codexScript = `#!/bin/sh
d="$CODEX_HOME/sessions"
f=$(ls "$d"/*/*/*/rollout-*-` + rolloutID + `.jsonl 2>/dev/null | head -n 1)
if [ -n "$f" ]; then echo "restored: $(cat "$f")"; else f="$d/2026/11/13/rollout-t-` + rolloutID + `.jsonl"; mkdir -p "${f%/*}"; fi
echo "args: $*"
echo '{"type":"thread.started","thread_id":"` + rolloutID + `"}'
echo '{"line":1}' >> "$f"
echo '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}'
sleep 0.3
echo '{"line":2}' >> "$f"
`

// codexSpec is a session of the contract's Codex runtime, started as codex exec --json
// with a prompt and no installed folder, with CODEX_HOME=home as a fixed value of the
// launch, as qory sets it. With paused not empty, the run answer has resume with paused
// as its path, and the transcript request gets ok.
func codexSpec(t *testing.T, home, paused string) runSpec {
	t.Helper()
	sp, g := specGateway(t)
	rt, err := codex.New()
	if err != nil {
		t.Fatal(err)
	}
	program := filepath.Join(t.TempDir(), "codex")
	if err := os.WriteFile(program, []byte(codexScript), 0o755); err != nil {
		t.Fatal(err)
	}
	// The helper sets an installed folder of Claude Code; a Codex session has none.
	sp.Runtime, sp.Forwarder, sp.RuntimeInstall = rt, nil, nil
	sp.Command, sp.Args = program, []string{"exec", "--json", "Fix the test"}
	sp.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
	sp.LaunchFixed = []string{"CODEX_HOME=" + home}
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

// TestACodexSessionStartsAndResumesWithNoInstalledFolder pins the contract's Codex
// runtime in a session with no SessionSpec.RuntimeInstall, which its descriptor allows
// with no install_required. The first run starts the command as named: its start has
// the thread's id and source startup, dev.qory.session.started has no runtime_version,
// and the session sends the rollout below CODEX_HOME. The next run restores the paused
// run's rollout at the same names below its CODEX_HOME and resumes before the prompt,
// as codex exec --json resume <id> "<prompt>".
func TestACodexSessionStartsAndResumesWithNoInstalledFolder(t *testing.T) {
	home := filepath.Join(t.TempDir(), "codex-home")
	res, err := run(context.Background(), codexSpec(t, home, ""))
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("the first run exited %d", res.ExitCode)
	}
	evs := events(t, res)
	for _, e := range ofType(evs, event.SessionStarted) {
		if v, ok := data(e)["runtime_version"]; ok {
			t.Errorf("session.started has runtime_version %v; want none with no installed folder", v)
		}
	}
	started := ofType(evs, "dev.qory.runtime.started")
	if len(started) != 1 || data(started[0])["session_id"] != rolloutID || data(started[0])["source"] != "startup" {
		t.Errorf("the runtime's starts %v", started)
	}
	if out := runLogText(t, evs); !strings.Contains(out, " exec --json Fix the test\n") || strings.Contains(out, "resume") {
		t.Errorf("the first run's output %q", out)
	}
	made := home + "/sessions/2026/11/13/rollout-t-" + rolloutID + ".jsonl"
	if path, file := transcriptOf(t, evs); path != made || file != "{\"line\":1}\n{\"line\":2}\n" {
		t.Errorf("the first transcript %s %q; want %s", path, file, made)
	}

	next := filepath.Join(t.TempDir(), "codex-home")
	const below = "2026/11/13/rollout-t-" + rolloutID + ".jsonl"
	res, err = run(context.Background(), codexSpec(t, next, home+"/sessions/"+below))
	if err != nil {
		t.Fatal(err)
	}
	evs = events(t, res)
	if out := runLogText(t, evs); !strings.Contains(out, "restored: ok\n") || !strings.Contains(out, " exec --json resume "+rolloutID+" Fix the test\n") || strings.Contains(out, "without a resume") {
		t.Errorf("the resumed run's output %q", out)
	}
	if path, file := transcriptOf(t, evs); path != next+"/sessions/"+below || file != "ok\n{\"line\":1}\n{\"line\":2}\n" {
		t.Errorf("the resumed transcript %s %q", path, file)
	}
	startedFrom(t, evs, "resume")
}
