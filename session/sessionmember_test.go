package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/creack/pty"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	refusals "github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/sink"
	"github.com/qoryai/forager/wall"
)

// sessionKind reports whether typ is one of the event types whose data has the number
// of the session that wrote them as session.
func sessionKind(typ string) bool {
	return typ == "dev.qory.run.log" || typ == "dev.qory.run.resized" || strings.HasPrefix(typ, "dev.qory.runtime.")
}

// sessionsOf fails the test unless every run.log, run.resized and runtime event of evs
// between a session.started and its session.exited has that session's number as
// session, and every run.log outside a session has no session; it returns, per type,
// the sessions seen, in order, with 0 for none.
func sessionsOf(t *testing.T, where string, evs []map[string]any) map[string][]int {
	t.Helper()
	seen := map[string][]int{}
	open := 0
	for _, e := range evs {
		typ := fmt.Sprint(e["type"])
		d := data(e)
		switch {
		case typ == "dev.qory.session.started":
			open = int(d["session"].(float64))
		case typ == "dev.qory.session.exited":
			open = 0
		case sessionKind(typ):
			got := 0
			if v, ok := d["session"]; ok {
				got = int(v.(float64))
			}
			if got != open {
				t.Errorf("%s: %s %v has session %d, with session %d open", where, typ, d, got, open)
			}
			seen[typ] = append(seen[typ], got)
		}
	}
	return seen
}

// distinct is s with each run of equal values cut to one value, in order.
func distinct(s []int) []int {
	var out []int
	for _, v := range s {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}

// TestEachSessionsEventsHaveItsNumber pins two joins of one run, with host lines before
// the first and between the two: every run.log and runtime event of a session has the
// session's number as session, 1 then 2, in the record and on the link, and the host
// lines have no session. Each session's output.log has the chunks of its session
// alone, and the run's has the host lines too.
func TestEachSessionsEventsHaveItsNumber(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	hostStep(t, r, event.StepFetch, "fetch example/app", "qory run: fetched example/app\n")
	for n := 1; n <= 2; n++ {
		if n == 2 {
			hostStep(t, r, event.StepCompose, "compose the harness", "qory run: composed the harness\n")
		}
		s := sp.SessionSpec
		s.Env = append(append([]string(nil), s.Env...), "FAKE_SETTINGS="+filepath.Join(r.Dir(), session.SessionsDir, fmt.Sprint(n), "settings.json"))
		res, err := r.Join(ctx, s)
		if err != nil {
			t.Fatal(err)
		}
		if res.Session != n {
			t.Fatalf("join %d is session %d", n, res.Session)
		}
	}
	closed, err := r.Close(ctx, session.Outcome{State: "succeeded"})
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, &session.Result{Dir: closed.Dir})
	for where, list := range map[string][]map[string]any{"the record": evs, "the link": g.Events()} {
		seen := sessionsOf(t, where, list)
		if got := fmt.Sprint(distinct(seen["dev.qory.run.log"])); got != "[0 1 0 2]" {
			t.Errorf("%s: run.log sessions %v, want [0 1 0 2]", where, got)
		}
		for _, typ := range []string{"dev.qory.runtime.ended", "dev.qory.runtime.result"} {
			if got := fmt.Sprint(seen[typ]); got != "[1 2]" {
				t.Errorf("%s: %s sessions %v, want [1 2]", where, typ, got)
			}
		}
	}
	batch, err := contracts.Compile("link-batch.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range g.Batches() {
		doc, err := contracts.Decode("batch.json", must(json.Marshal(b)))
		if err != nil {
			t.Fatal(err)
		}
		if err := batch.Validate(doc); err != nil {
			t.Errorf("batch %d: %v", i, err)
		}
	}
	all, _ := os.ReadFile(filepath.Join(closed.Dir, sink.OutputFile))
	if !strings.HasPrefix(string(all), "qory run: fetched example/app\n") || !strings.Contains(string(all), "qory run: composed the harness\n") {
		t.Errorf("the run's output.log has no host lines:\n%s", all)
	}
	for n := 1; n <= 2; n++ {
		out, _ := os.ReadFile(filepath.Join(closed.Dir, session.SessionsDir, fmt.Sprint(n), sink.OutputFile))
		if strings.Contains(string(out), "qory run:") || !strings.Contains(string(out), "fake runtime: starting") {
			t.Errorf("session %d's output.log:\n%s", n, out)
		}
	}
}

// TestEachSessionsResizeHasItsNumber pins two interactive joins of one run, each with
// one resize of the terminal: the first run.resized has session 1 and the second
// session 2, as every terminal chunk of each session does.
func TestEachSessionsResizeHasItsNumber(t *testing.T) {
	master, tty, err := pty.Open()
	if err != nil {
		t.Skip("no pseudo-terminal:", err)
	}
	defer master.Close()
	defer tty.Close()
	var out syncBuffer
	sp := spec(t)
	sp.Forwarder = nil
	sp.Interactive = true
	sp.Stdin = tty
	sp.Stdout = &out
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	record := filepath.Join(sp.RunsDir, sp.RunID, "session.jsonl")
	sp.Command = "sh"
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= 2; n++ {
		if err := pty.Setsize(master, &pty.Winsize{Cols: 100, Rows: 40}); err != nil {
			t.Fatal(err)
		}
		// The session ends once go exists: the caller's terminal is the input of every
		// session, so a line typed for one would reach the reader the session before left.
		gone := filepath.Join(t.TempDir(), "go")
		s := sp.SessionSpec
		s.Args = []string{"-c", `stty size; while [ ! -e "$0" ]; do sleep 0.05; done`, gone}
		done := make(chan error, 1)
		go func() {
			_, err := r.Join(ctx, s)
			done <- err
		}()
		waitFor(t, func() bool { return strings.Count(out.String(), "40 100") == n })
		if err := pty.Setsize(master, &pty.Winsize{Cols: 120, Rows: 50}); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
			t.Fatal(err)
		}
		waitFor(t, func() bool {
			b, _ := os.ReadFile(record)
			return strings.Count(string(b), `"dev.qory.run.resized"`) == n
		})
		if err := os.WriteFile(gone, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	closed, err := r.Close(ctx, session.Outcome{State: "succeeded"})
	if err != nil {
		t.Fatal(err)
	}
	seen := sessionsOf(t, "the record", events(t, &session.Result{Dir: closed.Dir}))
	if got := fmt.Sprint(seen["dev.qory.run.resized"]); got != "[1 2]" {
		t.Errorf("run.resized sessions %v, want [1 2]", got)
	}
	if got := fmt.Sprint(distinct(seen["dev.qory.run.log"])); got != "[1 2]" {
		t.Errorf("run.log sessions %v, want [1 2]", got)
	}
}

// TestAFailureWithNoCodeIsInTheSessionsOutput pins an image the engine does not hold and
// a wall's start that fail the wrap with no refusal code: the record and the link have
// the join step, session.started, the wall step, a stderr run.log of session 1 and of
// the wall step with the error's text, the wall step failed with -1, then session.exited
// failed with -1 and no reason; sessions/1/output.log has that text. The wall's refusal
// of an image by reference with a code, in the join's image step, is the reason of
// session.exited and writes no such chunk.
func TestAFailureWithNoCodeIsInTheSessionsOutput(t *testing.T) {
	held := errors.New("wall docker: fetch example.com/agent:1 with Pull before its first container starts: the engine does not hold it by its digest")
	start := errors.New("wall docker: start qory-relay: exit status 125")
	root := refusals.New(refusals.ImageUserRoot, []string{pinned}, "the image %s runs as root; a run's image runs as the wall's user", pinned)
	for _, c := range []struct {
		name   string
		wall   wall.Wall
		text   string
		reason string
		step   string
	}{
		{"held", &wrapFails{err: held}, held.Error(), "", "step 2 wall start the wall"},
		{"start", &wrapFails{err: start}, start.Error(), "", "step 2 wall start the wall"},
		{"refusal", &targetWall{refuse: root}, "", refusals.ImageUserRoot, "step 2 image " + pinned},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp, g := specGateway(t)
			sp.Wall, sp.Image = c.wall, "example.com/agent:1"
			if c.reason != "" {
				byReference(g)
				sp.ImagesAllow = []string{"registry.example/"}
			}
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Join(ctx, sp.SessionSpec); err == nil || !strings.Contains(err.Error(), c.text) {
				t.Errorf("the join: %v", err)
			}
			closed, err := r.Close(ctx, session.Outcome{State: "failed", ExitCode: -1})
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"step 1 join join session 1", "step 1 succeeded -1", "session 1 started", c.step}
			if c.text != "" {
				want = append(want, "log 1 2 "+c.text)
			}
			want = append(want, "step 2 failed -1", "session 1 exited", "run exited")
			for where, evs := range map[string][]map[string]any{"the record": events(t, &session.Result{Dir: closed.Dir}), "the link": g.Events()} {
				startedThenExited(t, where, evs, c.reason)
				if order := stepOrder(evs); !slices.Equal(order, want) {
					t.Errorf("%s:\n%q\nwant\n%q", where, order, want)
				}
			}
			out, _ := os.ReadFile(filepath.Join(closed.Dir, session.SessionsDir, "1", sink.OutputFile))
			if c.text != "" && string(out) != c.text+"\n" {
				t.Errorf("sessions/1/output.log %q", out)
			}
			if c.text == "" && len(out) != 0 {
				t.Errorf("sessions/1/output.log %q, want it empty", out)
			}
		})
	}
}
