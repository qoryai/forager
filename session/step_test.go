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
// that starts with the fix and with nothing written: a kind other than fetch, compose
// and build, an empty name, a state outside the three, an exit code below -1, a second
// host step while one is open, a join while one is open, a line or an exit after the
// step exited, and a step while a session runs.
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
	refused("a setup step", err, "start a host step of kind fetch, compose or build, not \"setup\"")
	_, err = r.StartStep(event.StepJoin, "join")
	refused("a join step", err, "start a host step of kind fetch, compose or build")
	_, err = r.StartStep(event.StepFetch, "")
	refused("an empty name", err, "give the step a name")
	s, err := r.StartStep(event.StepFetch, "fetch github.com/example-org/app")
	if err != nil {
		t.Fatal(err)
	}
	refused("a state outside the three", s.Exit("skipped", 0), "exit the step with succeeded, failed or cancelled, not \"skipped\"")
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
