package session_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/session"
)

// The tests of this file pin the steps of a run: the host steps the caller starts with
// StartStep, and the join, image and wall steps Join writes.

// stepOrder is the steps, the sessions and the run.log chunks of evs in order, each as
// one line: a step's start with its number, kind and name, its end with its number,
// state and exit code, a session's start and end with its number, and a chunk of the
// host work or of a step with its session, step and bytes.
func stepOrder(evs []map[string]any) []string {
	var out []string
	for _, e := range evs {
		d := data(e)
		switch e["type"] {
		case event.StepStarted:
			out = append(out, fmt.Sprintf("step %v %v %s", d["step"], d["kind"], d["name"]))
		case event.StepExited:
			out = append(out, fmt.Sprintf("step %v %v %v", d["step"], d["state"], d["exit_code"]))
		case event.SessionStarted:
			out = append(out, fmt.Sprintf("session %v started", d["session"]))
		case event.SessionExited:
			out = append(out, fmt.Sprintf("session %v exited", d["session"]))
		case event.RunLog:
			// A session's output outside its steps is left out.
			if d["session"] != nil && d["step"] == nil {
				continue
			}
			b, _ := base64.StdEncoding.DecodeString(d["bytes"].(string))
			out = append(out, fmt.Sprintf("log %v %v %s", d["session"], d["step"], strings.TrimSuffix(string(b), "\n")))
		case event.RunExited:
			out = append(out, "run exited")
		}
	}
	return out
}

// hostStep starts a host step of kind and name, writes line as its log and exits it
// succeeded with 0.
func hostStep(t *testing.T, r *session.Run, kind, name, line string) {
	t.Helper()
	s, err := r.StartStep(kind, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Log([]byte(line)); err != nil {
		t.Fatal(err)
	}
	if err := s.Exit(event.StateSucceeded, 0); err != nil {
		t.Fatal(err)
	}
}

// TestTheStepsOfARunWithHostStepsAJoinAndARefusedJoin pins a run with a fetch step, a
// join, a compose step and a join the gateway refuses: the steps are numbered 1 to 4
// across the host steps and the join steps; each join step ends before its session
// starts, succeeded with -1, or failed with -1 before the refused join's
// session.exited; a host step's line has its step and no session. The record and the
// link have the same steps, and every batch passes the link's schema.
func TestTheStepsOfARunWithHostStepsAJoinAndARefusedJoin(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	joins := 0
	g.OnJoin(func(linktest.Join) linktest.Reply {
		joins++
		if joins == 2 {
			return linktest.Reply{Status: 403, Body: linktest.Refusal("run_configuration_invalid", "gateway", "model")}
		}
		return linktest.Reply{Status: 200, Body: map[string]any{"version": 1, "session": joins}}
	})
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	hostStep(t, r, event.StepFetch, "fetch github.com/example-org/app", "Cloning into 'app'...\n")
	if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
		t.Fatal(err)
	}
	hostStep(t, r, event.StepCompose, "compose the harness", "qory run: composed 12 entries\n")
	if _, err := r.Join(ctx, sp.SessionSpec); err == nil {
		t.Fatal("the refused join returned no error")
	}
	if _, err := r.Close(ctx, session.Outcome{State: "failed", ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"step 1 fetch fetch github.com/example-org/app", "log <nil> 1 Cloning into 'app'...", "step 1 succeeded 0",
		"step 2 join join session 1", "step 2 succeeded -1", "session 1 started", "session 1 exited",
		"step 3 compose compose the harness", "log <nil> 3 qory run: composed 12 entries", "step 3 succeeded 0",
		"step 4 join join session 2", "step 4 failed -1", "session 2 exited",
		"run exited",
	}
	for where, evs := range map[string][]map[string]any{"the record": events(t, &session.Result{Dir: r.Dir()}), "the link": g.Events()} {
		if got := stepOrder(evs); !slices.Equal(got, want) {
			t.Errorf("%s:\n%q\nwant\n%q", where, got, want)
		}
	}
	batchesValid(t, g)
}

// batchesValid fails the test when a batch g received fails the link's schema.
func batchesValid(t *testing.T, g *linktest.Fake) {
	t.Helper()
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
}

// TestAPushStepRunsAfterTheLastJoinAndBeforeTheClose pins a host step of kind push after
// the run's last join: StartStep accepts it once Join returned, it has the next step
// number, and its start, its line and its exit lie between the session's exit and
// run.exited. The record and the link have the same steps, and every batch passes the
// link's schema.
func TestAPushStepRunsAfterTheLastJoinAndBeforeTheClose(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Join(ctx, sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	hostStep(t, r, event.StepPush, "push work to github.com/example-org/app", "To https://github.com/example-org/app.git\n")
	if _, err := r.Close(ctx, outcomeOf(res, nil)); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"step 1 join join session 1", "step 1 succeeded -1", "session 1 started", "session 1 exited",
		"step 2 push push work to github.com/example-org/app", "log <nil> 2 To https://github.com/example-org/app.git", "step 2 succeeded 0",
		"run exited",
	}
	for where, evs := range map[string][]map[string]any{"the record": events(t, &session.Result{Dir: r.Dir()}), "the link": g.Events()} {
		if got := stepOrder(evs); !slices.Equal(got, want) {
			t.Errorf("%s:\n%q\nwant\n%q", where, got, want)
		}
	}
	batchesValid(t, g)
}

// TestACopyStepRunsAfterTheLastJoinWithNoPush pins a host step of kind copy, host work
// that copies the session's work out of the wall: StartStep accepts it once Join
// returned, it has the next step number, and its start, its line and its exit lie
// between the session's exit and run.exited, with no push step after it. The record and
// the link have the same steps, and every batch passes the link's schema.
func TestACopyStepRunsAfterTheLastJoinWithNoPush(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Join(ctx, sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	hostStep(t, r, event.StepCopy, "copy the work of session 1 out of the wall", "copied 2 commits to work/session-1\n")
	if _, err := r.Close(ctx, outcomeOf(res, nil)); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"step 1 join join session 1", "step 1 succeeded -1", "session 1 started", "session 1 exited",
		"step 2 copy copy the work of session 1 out of the wall", "log <nil> 2 copied 2 commits to work/session-1", "step 2 succeeded 0",
		"run exited",
	}
	for where, evs := range map[string][]map[string]any{"the record": events(t, &session.Result{Dir: r.Dir()}), "the link": g.Events()} {
		if got := stepOrder(evs); !slices.Equal(got, want) {
			t.Errorf("%s:\n%q\nwant\n%q", where, got, want)
		}
	}
	batchesValid(t, g)
}

// bareSession is s as a session with no runtime that runs sh and exits 0, as the
// caller's copy of the work out of the wall.
func bareSession(s session.SessionSpec) session.SessionSpec {
	s.Runtime, s.Forwarder = nil, nil
	s.Command, s.Args = "sh", []string{"-c", "exit 0"}
	return s
}

// TestABareSessionJoinsDuringACopyStep pins a session with no runtime that joins while
// a copy step is open, walled or not: the join's steps take the next numbers and start
// and end inside the copy step, the copy step's Log and Exit return an error while the
// join runs and write nothing, and after Join returns the copy step writes its line and
// exits. The record and the link have the same steps, the bare session's
// session.started has bare true, and every batch passes the link's schema.
func TestABareSessionJoinsDuringACopyStep(t *testing.T) {
	for _, c := range []struct {
		name   string
		walled bool
		copied int
		want   []string
	}{
		{"no wall", false, 2, []string{
			"step 1 join join session 1", "step 1 succeeded -1", "session 1 started", "session 1 exited",
			"step 2 copy copy work out", "log <nil> 2 copy the work of session 1",
			"step 3 join join session 2", "step 3 succeeded -1", "session 2 started", "session 2 exited",
			"log <nil> 2 copied 2 commits to work/session-1", "step 2 succeeded 0",
			"run exited",
		}},
		{"a wall", true, 3, []string{
			"step 1 join join session 1", "step 1 succeeded -1", "session 1 started",
			"step 2 wall start the wall", "step 2 succeeded -1", "session 1 exited",
			"step 3 copy copy work out", "log <nil> 3 copy the work of session 1",
			"step 4 join join session 2", "step 4 succeeded -1", "session 2 started",
			"step 5 wall start the wall", "step 5 succeeded -1", "session 2 exited",
			"log <nil> 3 copied 2 commits to work/session-1", "step 3 succeeded 0",
			"run exited",
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp, g := specGateway(t, "FAKE_EXIT=0")
			if c.walled {
				sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			}
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			res, err := r.Join(ctx, sp.SessionSpec)
			if err != nil {
				t.Fatal(err)
			}
			cp, err := r.StartStep(event.StepCopy, "copy work out")
			if err != nil {
				t.Fatal(err)
			}
			if err := cp.Log([]byte("copy the work of session 1\n")); err != nil {
				t.Fatal(err)
			}
			var logDuring, exitDuring error
			j := bareSession(sp.SessionSpec)
			j.OnVariables = func(session.Applied) {
				logDuring = cp.Log([]byte("during the join\n"))
				exitDuring = cp.Exit(event.StateSucceeded, 0)
			}
			bare, err := r.Join(ctx, j)
			if err != nil {
				t.Fatal(err)
			}
			if bare.ExitCode != 0 {
				t.Errorf("the bare session exited %d", bare.ExitCode)
			}
			if want := fmt.Sprintf("write step %d's lines after Join returns", c.copied); logDuring == nil || !strings.HasPrefix(logDuring.Error(), want) {
				t.Errorf("a line during the join: %v, want an error that starts %q", logDuring, want)
			}
			if want := fmt.Sprintf("exit step %d after Join returns", c.copied); exitDuring == nil || !strings.HasPrefix(exitDuring.Error(), want) {
				t.Errorf("an exit during the join: %v, want an error that starts %q", exitDuring, want)
			}
			if err := cp.Log([]byte("copied 2 commits to work/session-1\n")); err != nil {
				t.Fatal(err)
			}
			if err := cp.Exit(event.StateSucceeded, 0); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Close(ctx, outcomeOf(res, nil)); err != nil {
				t.Fatal(err)
			}
			for where, evs := range map[string][]map[string]any{"the record": events(t, &session.Result{Dir: r.Dir()}), "the link": g.Events()} {
				if got := stepOrder(evs); !slices.Equal(got, c.want) {
					t.Errorf("%s:\n%q\nwant\n%q", where, got, c.want)
				}
				started := ofType(evs, event.SessionStarted)
				if len(started) != 2 || data(started[1])["bare"] != true {
					t.Errorf("%s: session.started %v, want bare true on session 2", where, started)
				}
			}
			batchesValid(t, g)
		})
	}
}

// TestACopyStepAfterABareJoin pins the copy step around the join of a session with no
// runtime: a second bare join in the same step, a join with a runtime after a bare one,
// a bare join that ends with a 403, and a close with the step still open. The record and
// the link have the same steps, and every batch passes the link's schema.
func TestACopyStepAfterABareJoin(t *testing.T) {
	ctx := context.Background()
	refusedJoin := func(linktest.Join) linktest.Reply {
		return linktest.Reply{Status: 403, Body: linktest.Refusal("run_configuration_invalid", "gateway", "model")}
	}
	for _, c := range []struct {
		name    string
		onJoin  func(linktest.Join) linktest.Reply
		during  func(t *testing.T, r *session.Run, sp runSpec, cp *session.Step)
		outcome session.Outcome
		want    []string
	}{
		{
			name: "a second bare join",
			during: func(t *testing.T, r *session.Run, sp runSpec, cp *session.Step) {
				for range 2 {
					if _, err := r.Join(ctx, bareSession(sp.SessionSpec)); err != nil {
						t.Fatal(err)
					}
				}
				if err := cp.Exit(event.StateSucceeded, 0); err != nil {
					t.Fatal(err)
				}
			},
			outcome: session.Outcome{State: event.StateSucceeded},
			want: []string{
				"step 1 copy copy work out",
				"step 2 join join session 1", "step 2 succeeded -1", "session 1 started", "session 1 exited",
				"step 3 join join session 2", "step 3 succeeded -1", "session 2 started", "session 2 exited",
				"step 1 succeeded 0", "run exited",
			},
		},
		{
			name: "a join with a runtime after a bare one",
			during: func(t *testing.T, r *session.Run, sp runSpec, cp *session.Step) {
				if _, err := r.Join(ctx, bareSession(sp.SessionSpec)); err != nil {
					t.Fatal(err)
				}
				_, err := r.Join(ctx, sp.SessionSpec)
				if want := "exit step 1 before the join: only a session with no runtime joins during a copy step"; err == nil || err.Error() != want {
					t.Errorf("the join with a runtime: %v, want %s", err, want)
				}
				if err := cp.Exit(event.StateSucceeded, 0); err != nil {
					t.Fatal(err)
				}
			},
			outcome: session.Outcome{State: event.StateSucceeded},
			want: []string{
				"step 1 copy copy work out",
				"step 2 join join session 1", "step 2 succeeded -1", "session 1 started", "session 1 exited",
				"step 1 succeeded 0", "run exited",
			},
		},
		{
			name:   "a bare join with a 403",
			onJoin: refusedJoin,
			during: func(t *testing.T, r *session.Run, sp runSpec, cp *session.Step) {
				if _, err := r.Join(ctx, bareSession(sp.SessionSpec)); err == nil {
					t.Error("the join with a 403 returned no error")
				}
				_, err := r.StartStep(event.StepFetch, "fetch github.com/example-org/app")
				if want := "exit step 1 before the next host step starts"; err == nil || !strings.HasPrefix(err.Error(), want) {
					t.Errorf("a step after the join with a 403: %v, want an error that starts %q", err, want)
				}
				if err := cp.Log([]byte("the copy failed\n")); err != nil {
					t.Fatal(err)
				}
				if err := cp.Exit(event.StateFailed, -1); err != nil {
					t.Fatal(err)
				}
			},
			outcome: session.Outcome{State: event.StateFailed, ExitCode: -1},
			want: []string{
				"step 1 copy copy work out",
				"step 2 join join session 1", "step 2 failed -1", "session 1 exited",
				"log <nil> 1 the copy failed", "step 1 failed -1", "run exited",
			},
		},
		{
			name: "a close with the step still open",
			during: func(t *testing.T, r *session.Run, sp runSpec, _ *session.Step) {
				if _, err := r.Join(ctx, bareSession(sp.SessionSpec)); err != nil {
					t.Fatal(err)
				}
			},
			outcome: session.Outcome{State: event.StateSucceeded},
			want: []string{
				"step 1 copy copy work out",
				"step 2 join join session 1", "step 2 succeeded -1", "session 1 started", "session 1 exited",
				"step 1 cancelled -1", "run exited",
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp, g := specGateway(t, "FAKE_EXIT=0")
			if c.onJoin != nil {
				g.OnJoin(c.onJoin)
			}
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			cp, err := r.StartStep(event.StepCopy, "copy work out")
			if err != nil {
				t.Fatal(err)
			}
			c.during(t, r, sp, cp)
			if _, err := r.Close(ctx, c.outcome); err != nil {
				t.Fatal(err)
			}
			for where, evs := range map[string][]map[string]any{"the record": events(t, &session.Result{Dir: r.Dir()}), "the link": g.Events()} {
				if got := stepOrder(evs); !slices.Equal(got, c.want) {
					t.Errorf("%s:\n%q\nwant\n%q", where, got, c.want)
				}
			}
			batchesValid(t, g)
		})
	}
}

// TestOnlyASessionWithNoRuntimeJoinsDuringACopyStep pins the calls that return an error
// during a copy step, each error starting with the fix and with nothing written: a join
// of a session with a runtime, the host proxy and the build's result. During a push
// step, the join of a session with or without a runtime returns an error.
func TestOnlyASessionWithNoRuntimeJoinsDuringACopyStep(t *testing.T) {
	sp := spec(t, "FAKE_EXIT=0")
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	refused := func(what string, err error, fix string) {
		t.Helper()
		if err == nil || !strings.HasPrefix(err.Error(), fix) {
			t.Errorf("%s: %v, want an error that starts %q", what, err, fix)
		}
	}
	push, err := r.StartStep(event.StepPush, "push work to github.com/example-org/app")
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Join(ctx, bareSession(sp.SessionSpec))
	refused("a session with no runtime during a push step", err, "exit step 1 before the join: a session does not join during a host step")
	_, err = r.Join(ctx, sp.SessionSpec)
	refused("a session with a runtime during a push step", err, "exit step 1 before the join: a session does not join during a host step")
	if err := push.Exit(event.StateSucceeded, 0); err != nil {
		t.Fatal(err)
	}
	cp, err := r.StartStep(event.StepCopy, "copy work out")
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Join(ctx, sp.SessionSpec)
	refused("a session with a runtime during a copy step", err, "exit step 2 before the join: only a session with no runtime joins during a copy step")
	_, err = r.HostProxy()
	refused("the host proxy during a copy step", err, "exit step 2 before you start the host proxy: a join during a copy step closes the host proxy")
	refused("a Built during a copy step", r.Built(aBuild()), "exit step 2 before you write the build's result")
	if err := cp.Exit(event.StateSucceeded, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"step 1 push push work to github.com/example-org/app", "step 1 succeeded 0",
		"step 2 copy copy work out", "step 2 succeeded 0",
		"run exited",
	}
	evs := events(t, &session.Result{Dir: r.Dir()})
	if got := stepOrder(evs); !slices.Equal(got, want) {
		t.Errorf("the record:\n%q\nwant\n%q", got, want)
	}
	if got := ofType(evs, event.RunBuilt); len(got) != 0 {
		t.Errorf("the record has %d run.built", len(got))
	}
}

// TestAMachineStepRunsRightAfterTheOpen pins a host step of kind machine, the start of
// the machine the run runs on: StartStep accepts it right after Open and before the first
// fetch, it is step 1, its lines are run.log chunks with stream stderr and its step, and
// it exits succeeded with -1 before the fetch step starts. The record and the link have
// the same steps, and every batch passes the link's schema.
func TestAMachineStepRunsRightAfterTheOpen(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	s, err := r.StartStep(event.StepMachine, "start machine")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Log([]byte("boot  14.8 s\nstart Docker  3.2 s\n")); err != nil {
		t.Fatal(err)
	}
	if err := s.Exit(event.StateSucceeded, -1); err != nil {
		t.Fatal(err)
	}
	hostStep(t, r, event.StepFetch, "fetch github.com/example-org/app", "Cloning into 'app'...\n")
	res, err := r.Join(ctx, sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, outcomeOf(res, nil)); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"step 1 machine start machine", "log <nil> 1 boot  14.8 s", "log <nil> 1 start Docker  3.2 s", "step 1 succeeded -1",
		"step 2 fetch fetch github.com/example-org/app", "log <nil> 2 Cloning into 'app'...", "step 2 succeeded 0",
		"step 3 join join session 1", "step 3 succeeded -1", "session 1 started", "session 1 exited",
		"run exited",
	}
	rec := events(t, &session.Result{Dir: r.Dir()})
	for where, evs := range map[string][]map[string]any{"the record": rec, "the link": g.Events()} {
		if got := stepOrder(evs); !slices.Equal(got, want) {
			t.Errorf("%s:\n%q\nwant\n%q", where, got, want)
		}
	}
	var streams []any
	for _, e := range rec {
		if d := data(e); e["type"] == event.RunLog && d["step"] == float64(1) {
			streams = append(streams, d["stream"])
		}
	}
	if !slices.Equal(streams, []any{"stderr", "stderr"}) {
		t.Errorf("the streams of the machine step's lines: %v, want stderr twice", streams)
	}
	batchesValid(t, g)
}

// TestCloseEndsAnOpenHostStep pins a host step the caller leaves open: the close writes
// its step_exited, cancelled with -1, right before run.exited, and the step's Log and
// Exit then return an error that starts with the fix.
func TestCloseEndsAnOpenHostStep(t *testing.T) {
	sp := spec(t)
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	s, err := r.StartStep(event.StepFetch, "fetch github.com/example-org/app")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Log([]byte("Cloning into 'app'...\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, session.Outcome{State: "failed", ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Log([]byte("after\n")); err == nil || !strings.HasPrefix(err.Error(), "start a new step for these lines") {
		t.Errorf("a line after the close: %v", err)
	}
	if err := s.Exit(event.StateSucceeded, 0); err == nil || !strings.HasPrefix(err.Error(), "start a new step") {
		t.Errorf("an exit after the close: %v", err)
	}
	if _, err := r.StartStep(event.StepFetch, "fetch again"); err == nil || !strings.HasPrefix(err.Error(), "open a new run for the host step") {
		t.Errorf("a step after the close: %v", err)
	}
	want := []string{"step 1 fetch fetch github.com/example-org/app", "log <nil> 1 Cloning into 'app'...", "step 1 cancelled -1", "run exited"}
	if got := stepOrder(events(t, &session.Result{Dir: r.Dir()})); !slices.Equal(got, want) {
		t.Errorf("the record:\n%q\nwant\n%q", got, want)
	}
}

// TestAStepsErrorsStartWithTheFix pins what a host step refuses, each with an error
// that starts with the fix and with nothing written: a kind other than fetch, compose,
// build, push, machine and copy, an empty name, a state outside the three, paused, a
// state of a run, among them, an exit
// code below -1, a second host step while one is open, a join while one is open, a line
// or an exit after the step exited, and a step while a session runs.
func TestAStepsErrorsStartWithTheFix(t *testing.T) {
	sp := spec(t, "FAKE_EXIT=0")
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	refused := func(what string, err error, fix string) {
		t.Helper()
		if err == nil || !strings.HasPrefix(err.Error(), fix) {
			t.Errorf("%s: %v, want an error that starts %q", what, err, fix)
		}
	}
	_, err = r.StartStep(event.StepSetup, "make setup")
	refused("a setup step", err, "start a host step of kind fetch, compose, build, push, machine or copy, not \"setup\"")
	_, err = r.StartStep(event.StepJoin, "join")
	refused("a join step", err, "start a host step of kind fetch, compose, build, push, machine or copy, not \"join\"")
	_, err = r.StartStep("checkout", "checkout the work")
	refused("an unknown kind", err, "start a host step of kind fetch, compose, build, push, machine or copy, not \"checkout\"")
	_, err = r.StartStep(event.StepFetch, "")
	refused("an empty name", err, "give the step a name")
	s, err := r.StartStep(event.StepFetch, "fetch github.com/example-org/app")
	if err != nil {
		t.Fatal(err)
	}
	refused("a state outside the three", s.Exit("skipped", 0), "exit the step with succeeded, failed or cancelled, not \"skipped\"")
	refused("paused", s.Exit(event.StatePaused, 0), "exit the step with succeeded, failed or cancelled, not \"paused\"")
	refused("an exit code of -2", s.Exit(event.StateFailed, -2), "exit the step with -1 when its process has no exit status")
	_, err = r.StartStep(event.StepCompose, "compose the harness")
	refused("a second host step", err, "exit step 1 before the next host step starts")
	_, err = r.Join(ctx, sp.SessionSpec)
	refused("a join during a host step", err, "exit step 1 before the join")
	if err := s.Exit(event.StateFailed, 128); err != nil {
		t.Fatal(err)
	}
	refused("a second exit", s.Exit(event.StateFailed, 128), "start a new step: step 1 exited already")
	refused("a line after the exit", s.Log([]byte("late\n")), "start a new step for these lines: step 1 exited")
	during := make(chan error, 1)
	j := sp.SessionSpec
	j.OnVariables = func(session.Applied) {
		_, err := r.StartStep(event.StepFetch, "fetch during the join")
		during <- err
	}
	if _, err := r.Join(ctx, j); err != nil {
		t.Fatal(err)
	}
	refused("a step during a join", <-during, "start the host step after Join returns")
	if _, err := r.Close(ctx, session.Outcome{State: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"step 1 fetch fetch github.com/example-org/app", "step 1 failed 128",
		"step 2 join join session 1", "step 2 succeeded -1", "session 1 started", "session 1 exited",
		"run exited",
	}
	if got := stepOrder(events(t, &session.Result{Dir: r.Dir()})); !slices.Equal(got, want) {
		t.Errorf("the record:\n%q\nwant\n%q", got, want)
	}
}

// TestAStepsNameAndLinesAreMasked pins a host step whose name and line contain the host
// proxy's URL and the base64 of its Proxy-Authorization: qory-proxy-password replaces
// the password in the name, in the step's run.log chunks, in output.log and in
// session.jsonl, and a line longer than 4096 bytes is two chunks, each stderr with the
// step and no session. A name that contains qak_ is the access key secret's phrase.
func TestAStepsNameAndLinesAreMasked(t *testing.T) {
	sp := spec(t)
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	h, err := r.HostProxy()
	if err != nil {
		t.Fatal(err)
	}
	password, _ := hostParts(t, h)
	basic := base64.StdEncoding.EncodeToString([]byte("qory:" + password))
	line := "git fetch through " + h.ProxyURL + " with Proxy-Authorization: Basic " + basic + "\n"
	long := strings.Repeat("x", 5000) + "\n"
	s, err := r.StartStep(event.StepFetch, "fetch through "+h.ProxyURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Log([]byte(line + long)); err != nil {
		t.Fatal(err)
	}
	if err := s.Exit(event.StateSucceeded, 0); err != nil {
		t.Fatal(err)
	}
	hostStep(t, r, event.StepCompose, "compose with qak_FAKE0123456789", "")
	if _, err := r.Close(ctx, session.Outcome{State: "failed", ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	res := &session.Result{Dir: r.Dir()}
	out := noPassword(t, res, password)
	noPassword(t, res, basic)
	want := strings.Replace(line, password, "qory-proxy-password", 1)
	want = strings.Replace(want, basic, base64.StdEncoding.EncodeToString([]byte("qory:qory-proxy-password")), 1)
	if out != want+long {
		t.Errorf("output.log\n%q\nwant\n%q", out, want+long)
	}
	evs := events(t, res)
	logs := ofType(evs, event.RunLog)
	if len(logs) != 3 {
		t.Fatalf("%d run.log chunks, want 3", len(logs))
	}
	for _, l := range logs {
		if d := data(l); d["stream"] != "stderr" || d["session"] != nil || d["step"] != float64(1) {
			t.Errorf("a host line's chunk %v; want stderr, step 1 and no session", d)
		}
	}
	names := []string{}
	for _, e := range ofType(evs, event.StepStarted) {
		names = append(names, data(e)["name"].(string))
	}
	wantNames := []string{"fetch through " + strings.Replace(h.ProxyURL, password, "qory-proxy-password", 1), "(a value that contains an access key secret)"}
	if !slices.Equal(names, wantNames) {
		t.Errorf("the step names %q, want %q", names, wantNames)
	}
}
