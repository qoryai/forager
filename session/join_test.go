package session_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/internal/linktest"
	refusals "github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// TestARunWithTwoJoins pins a run of two sessions: the open writes run.started and a
// policy_applied with no variables, each join gets its number from the join answer,
// 1 then 2, and writes its session.started, its policy_applied with its variables and
// its session.exited, in that order, and the close writes one run.exited, the last
// event. Each join request has its session's passes.
func TestARunWithTwoJoins(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	var results []*session.Result
	for _, value := range []string{"one", "two"} {
		s := sp.SessionSpec
		s.Variables.Run = []string{"JOIN_" + strings.ToUpper(value) + "=" + value}
		res, err := r.Join(ctx, s)
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, res)
	}
	closed, err := r.Close(ctx, session.Outcome{State: "succeeded"})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Session != 1 || results[1].Session != 2 || results[0].ExitCode != 0 || results[1].State != "succeeded" {
		t.Errorf("results %+v %+v", results[0], results[1])
	}
	if closed.State != "succeeded" || closed.ExitCode != 0 || closed.Undelivered != 0 || closed.Dir != results[0].Dir {
		t.Errorf("closed %+v", closed)
	}
	evs := events(t, &session.Result{Dir: closed.Dir})
	var order []string
	for _, e := range evs {
		switch e["type"] {
		case "dev.qory.run.started", "dev.qory.session.started", "dev.qory.session.exited", "dev.qory.run.exited":
			order = append(order, fmt.Sprintf("%s %v", e["type"], data(e)["session"]))
		case "dev.qory.run.policy_applied":
			vars := []string{}
			for _, v := range data(e)["variables"].([]any) {
				vars = append(vars, fmt.Sprint(v.(map[string]any)["name"]))
			}
			order = append(order, "policy_applied "+strings.Join(vars, ","))
		}
	}
	want := []string{
		"dev.qory.run.started <nil>", "policy_applied ",
		"dev.qory.session.started 1", "policy_applied JOIN_ONE", "dev.qory.session.exited 1",
		"dev.qory.session.started 2", "policy_applied JOIN_TWO", "dev.qory.session.exited 2",
		"dev.qory.run.exited <nil>",
	}
	if !slices.Equal(order, want) {
		t.Errorf("the record\n%q\nwant\n%q", order, want)
	}
	if last := evs[len(evs)-1]; last["type"] != "dev.qory.run.exited" || data(last)["state"] != "succeeded" {
		t.Errorf("the last event %v", last)
	}
	joins := g.Joins()
	if len(joins) != 2 || !slices.Equal(joins[0].Request.Passes, []string{"JOIN_ONE"}) || !slices.Equal(joins[1].Request.Passes, []string{"JOIN_TWO"}) {
		t.Errorf("join requests %+v", joins)
	}
	if got := ofType(g.Events(), "dev.qory.run.exited"); len(got) != 1 {
		t.Errorf("the link got %d run.exited", len(got))
	}
}

// TestJoinsFollowOneAnother pins the order the gateway needs: a join returns once the
// gateway accepted the batch with its session.exited, so the next join request
// follows that answer, even when the gateway answers that batch 300 ms late.
func TestJoinsFollowOneAnother(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	g.OnBatch(func(evs []map[string]any) linktest.Reply {
		if slices.ContainsFunc(evs, func(e map[string]any) bool { return e["type"] == "dev.qory.session.exited" }) {
			time.Sleep(300 * time.Millisecond)
		}
		return linktest.Reply{Status: 200}
	})
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Close(ctx, session.Outcome{State: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	// exitedIn is the index of the batch with the first session.exited.
	exitedIn := slices.IndexFunc(g.Batches(), func(b []map[string]any) bool {
		return slices.ContainsFunc(b, func(e map[string]any) bool { return e["type"] == "dev.qory.session.exited" })
	})
	joins := g.Joins()
	if len(joins) != 2 || exitedIn < 0 || joins[1].Answered <= exitedIn {
		t.Errorf("the second join request came after %d answered batches; the first session.exited was in batch %d", joins[1].Answered, exitedIn)
	}
}

// TestARefusedJoin pins a join the gateway answers 403: the join returns the refusal,
// its session.exited is failed with -1, the code as its reason and duration_ms 0, with
// no session.started, and the run stays open: the next join is session 2.
func TestARefusedJoin(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	refuse := true
	g.OnJoin(func(j linktest.Join) linktest.Reply {
		if refuse {
			refuse = false
			return linktest.Reply{Status: 403, Body: linktest.Refusal("run_configuration_invalid", "gateway", "model")}
		}
		return linktest.Reply{Status: 200, Body: map[string]any{"version": 1, "session": 2}}
	})
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Join(ctx, sp.SessionSpec)
	var ref *session.Refusal
	if !errors.As(err, &ref) || ref.Code != "run_configuration_invalid" || ref.Detail != "the gateway" {
		t.Fatalf("%v, want run_configuration_invalid", err)
	}
	res, err := r.Join(ctx, sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	if res.Session != 2 {
		t.Errorf("the second join is session %d", res.Session)
	}
	closed, err := r.Close(ctx, session.Outcome{State: res.State, ExitCode: res.ExitCode})
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, &session.Result{Dir: closed.Dir})
	exited := ofType(evs, "dev.qory.session.exited")
	want := map[string]any{"session": float64(1), "state": "failed", "exit_code": float64(-1), "reason": "run_configuration_invalid", "duration_ms": float64(0)}
	if len(exited) != 2 || !equalJSON(data(exited[0]), want) {
		t.Errorf("session.exited %v, want %v first", exited, want)
	}
	if started := ofType(evs, "dev.qory.session.started"); len(started) != 1 || data(started[0])["session"] != float64(2) {
		t.Errorf("session.started %v, want session 2's alone", started)
	}
}

// TestARunNoSessionJoinedIsNoSession pins the close of a run no join started: failed
// with -1 and no reason is no_session, both after no join at all and after a join the
// session refused before its request; another outcome stays as given.
func TestARunNoSessionJoinedIsNoSession(t *testing.T) {
	for name, join := range map[string]bool{"no join": false, "a join refused before its request": true} {
		t.Run(name, func(t *testing.T) {
			sp, g := specGateway(t)
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			if join {
				s := sp.SessionSpec
				s.Timeout = -time.Second
				if _, err := r.Join(ctx, s); err == nil {
					t.Fatal("a negative time limit joined")
				}
			}
			closed, err := r.Close(ctx, session.Outcome{State: "failed", ExitCode: -1})
			if err != nil {
				t.Fatal(err)
			}
			if closed.State != "failed" || closed.Reason != "no_session" || closed.ExitCode != -1 {
				t.Errorf("closed %+v", closed)
			}
			exited := ofType(g.Events(), "dev.qory.run.exited")
			if len(exited) != 1 || data(exited[0])["reason"] != "no_session" || data(exited[0])["exit_code"] != float64(-1) {
				t.Errorf("the link got %v", exited)
			}
			if len(g.Joins()) != 0 {
				t.Errorf("join requests %+v", g.Joins())
			}
		})
	}
	sp, _ := specGateway(t)
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	closed, err := r.Close(ctx, session.Outcome{State: "cancelled", Reason: "timeout", ExitCode: 124})
	if err != nil || closed.State != "cancelled" || closed.Reason != "timeout" || closed.ExitCode != 124 {
		t.Errorf("closed %+v, %v", closed, err)
	}
}

// TestCloseChecksTheOutcome pins the outcomes Close refuses, each with its text, before
// it writes anything, and that a run closes once.
func TestCloseChecksTheOutcome(t *testing.T) {
	sp, g := specGateway(t)
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		out  session.Outcome
		want string
	}{
		{session.Outcome{State: "done"}, `the outcome's state "done" is none of succeeded, failed and cancelled`},
		{session.Outcome{State: "failed", ExitCode: -2}, "the outcome's exit code -2 is under -1"},
		{session.Outcome{State: "cancelled", Reason: "timeout", ExitCode: 1}, "an outcome with the reason timeout is cancelled with the exit code 124"},
		{session.Outcome{State: "failed", Reason: "interrupted"}, "an outcome with the reason interrupted is cancelled"},
		{session.Outcome{State: "failed", Reason: "session_lost", ExitCode: -1}, `the outcome's reason "session_lost" is not a code of the caller's: a lower-case letter, then up to 63 lower-case letters, digits and _, and none of Forager's reserved codes`},
	} {
		if _, err := r.Close(ctx, c.out); err == nil || err.Error() != c.want {
			t.Errorf("%+v: %v, want %s", c.out, err, c.want)
		}
	}
	if got := ofType(g.Events(), "dev.qory.run.exited"); len(got) != 0 {
		t.Errorf("a refused outcome wrote %v", got)
	}
	if _, err := r.Close(ctx, session.Outcome{State: "failed", Reason: "fetch_failed", ExitCode: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, session.Outcome{State: "failed"}); err == nil || err.Error() != "the run is closed already" {
		t.Errorf("a second close: %v", err)
	}
	if _, err := r.Join(ctx, sp.SessionSpec); err == nil || err.Error() != "the run is closed" {
		t.Errorf("a join after the close: %v", err)
	}
	exited := ofType(g.Events(), "dev.qory.run.exited")
	if len(exited) != 1 || data(exited[0])["reason"] != "fetch_failed" || data(exited[0])["exit_code"] != float64(1) {
		t.Errorf("run.exited %v", exited)
	}
}

// TestTheHarnessSourcesAreInSessionStarted pins the harness member of session.started:
// each source and commit as the caller passes them, a source that contains qak_ or
// qrk_ as the value's phrase, the event valid against its schema; and a commit that is
// not a full one is refused before the join request.
func TestTheHarnessSourcesAreInSessionStarted(t *testing.T) {
	commit := strings.Repeat("a1", 20)
	sp, g := specGateway(t, "FAKE_EXIT=0")
	sp.Harness = []session.HarnessSource{
		{Source: "https://git.example/harness.git", Commit: commit},
		{Source: "https://git.example/qak_harness.git", Commit: strings.Repeat("b", 64)},
	}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	got := sessionStarted(t, events(t, res))["harness"]
	want := []any{
		map[string]any{"source": "https://git.example/harness.git", "commit": commit},
		map[string]any{"source": "(a value that contains an access key secret)", "commit": strings.Repeat("b", 64)},
	}
	if !equalJSON(map[string]any{"harness": got}, map[string]any{"harness": want}) {
		t.Errorf("harness %v, want %v", got, want)
	}
	if posted := sessionStarted(t, g.Events())["harness"]; !equalJSON(map[string]any{"harness": posted}, map[string]any{"harness": want}) {
		t.Errorf("the link got harness %v", posted)
	}

	sp, g = specGateway(t)
	sp.Harness = []session.HarnessSource{{Source: "https://git.example/harness.git", Commit: "a1b2c3d"}}
	_, err = run(context.Background(), sp)
	if want := "set the commit of the harness source 1 to a full commit id, 40 or 64 hexadecimal characters in lower case"; err == nil || err.Error() != want {
		t.Errorf("a short commit: %v, want %s", err, want)
	}
	if len(g.Joins()) != 0 {
		t.Error("a short commit reached the gateway's join")
	}
}

// TestTheMaskerIsTheRuns pins that the run masks every session's forwarder password:
// the second session prints the first one's, and output.log and session.jsonl have
// qory-proxy-password in its place.
func TestTheMaskerIsTheRuns(t *testing.T) {
	sp, _ := specGateway(t)
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	first := sp.SessionSpec
	envFile := filepath.Join(t.TempDir(), "env")
	first.Forwarder = nil
	first.Command, first.Args = "/bin/sh", []string{"-c", `env > "$0"`, envFile}
	if _, err := r.Join(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := sp.SessionSpec
	second.Forwarder = nil
	second.Command, second.Args = "/bin/sh", []string{"-c", `grep -o 'http://qory:[^@]*@' "$0"`, envFile}
	if _, err := r.Join(ctx, second); err != nil {
		t.Fatal(err)
	}
	closed, err := r.Close(ctx, session.Outcome{State: "succeeded"})
	if err != nil {
		t.Fatal(err)
	}
	password := forwarderPassword(t, envFile)
	out := noPassword(t, &session.Result{Dir: closed.Dir}, password)
	if !strings.Contains(out, "http://qory:qory-proxy-password@") {
		t.Errorf("output.log has no masked password:\n%s", out)
	}
	if b, _ := os.ReadFile(filepath.Join(closed.Dir, "session.jsonl")); strings.Contains(string(b), password) {
		t.Error("session.jsonl contains the first session's password")
	}
}

// TestTheRunGivesTheServersSystemAndRepositories pins System and Repositories: the
// values of QORY_RUN_SYSTEM and QORY_RUN_REPOSITORIES in the run answer's variables,
// empty when the answer has none.
func TestTheRunGivesTheServersSystemAndRepositories(t *testing.T) {
	sp, g := specGateway(t)
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["variables"] = map[string]any{"QORY_RUN_SYSTEM": map[string]any{"value": "tickets"}, "QORY_RUN_REPOSITORIES": map[string]any{"value": "example/app"}}
		return linktest.Reply{Status: 200, Body: a}
	})
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if r.System() != "tickets" || r.Repositories() != "example/app" {
		t.Errorf("system %q, repositories %q", r.System(), r.Repositories())
	}
	if _, err := r.Close(ctx, session.Outcome{State: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	sp, _ = specGateway(t)
	if r, err = session.Open(ctx, opened(sp)); err != nil {
		t.Fatal(err)
	}
	if r.System() != "" || r.Repositories() != "" {
		t.Errorf("system %q, repositories %q, want none", r.System(), r.Repositories())
	}
	if _, err := r.Close(ctx, session.Outcome{State: "succeeded"}); err != nil {
		t.Fatal(err)
	}
}

// TestAJoinAfterAReloadRecordsTheReload pins the policy a join records: a reload
// between the open and the join puts its members in force, and the join's
// policy_applied has the reload's source and digest, not the open's.
func TestAJoinAfterAReloadRecordsTheReload(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	g.SetRunDigest("sha256=" + strings.Repeat("1", 64))
	g.OnBatch(func([]map[string]any) linktest.Reply {
		g.SetRunDigest("sha256=" + strings.Repeat("2", 64))
		return linktest.Reply{Status: 200}
	})
	g.OnReload(func(string) linktest.Reply {
		return linktest.Reply{Status: 200, Body: map[string]any{"version": 1,
			"policy": map[string]any{"version": 1, "egress": map[string]any{"mode": "enforce", "allow": []string{"api.example"}}},
			"digest": strings.Repeat("e", 64),
			"applied": map[string]any{"mode": "enforce", "allow": []any{"api.example"}, "deny": []any{}, "source": "fetched", "digest": strings.Repeat("e", 64),
				"url": "https://apiary.example/v1/runs", "run_configuration": "sha256=" + strings.Repeat("2", 64)}}}
	})
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		return len(ofType(events(t, &session.Result{Dir: r.Dir()}), "dev.qory.run.policy_applied")) == 2
	})
	if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
		t.Fatal(err)
	}
	closed, err := r.Close(ctx, session.Outcome{State: "succeeded"})
	if err != nil {
		t.Fatal(err)
	}
	joined := joinApplied(events(t, &session.Result{Dir: closed.Dir}))
	if len(joined) != 1 || data(joined[0])["source"] != "fetched" || data(joined[0])["digest"] != strings.Repeat("e", 64) {
		t.Errorf("the join's policy_applied %v; want the reload's source and digest", joined)
	}
}

// prepareFailing is a wall whose Prepare fails with err: a refusal with a code, as an
// image that runs as root, or an error with none, as a network that cannot be made.
type prepareFailing struct {
	openWall
	err error
}

func (w *prepareFailing) Prepare(context.Context, wall.Request) (wall.Enclosure, error) {
	return nil, w.err
}

// TestAPrepareFailureIsAFailedOpen pins a wall that fails to prepare, with a refusal's
// code or with none: the wall is prepared as the run opens, so Open returns the error,
// the run's directory has no record of a session, and nothing is wrapped.
func TestAPrepareFailureIsAFailedOpen(t *testing.T) {
	for _, err := range []error{
		refusals.New(refusals.ImageUserRoot, []string{"example.com/agent:1"}, "the image %s runs as root; a run's image runs as the wall's user", "example.com/agent:1"),
		errors.New("wall docker: network create qory-x-inside: exit status 1"),
	} {
		sp, g := specGateway(t)
		w := &prepareFailing{err: err}
		sp.Wall, sp.Image = w, "example.com/agent:1"
		if _, got := session.Open(context.Background(), opened(sp)); !errors.Is(got, err) {
			t.Errorf("%v: the open: %v", err, got)
		}
		if w.wrapped || len(ofType(g.Events(), "dev.qory.session.started")) != 0 {
			t.Errorf("%v: wrapped %v, events %v", err, w.wrapped, g.Events())
		}
	}
}

// startedThenExited fails the test unless evs have one session.started, then one
// session.exited failed with -1 that its schema accepts, with reason as its reason, or
// no reason when reason is empty.
func startedThenExited(t *testing.T, where string, evs []map[string]any, reason string) {
	t.Helper()
	var order []string
	for _, e := range evs {
		if e["type"] == "dev.qory.session.started" || e["type"] == "dev.qory.session.exited" {
			order = append(order, fmt.Sprint(e["type"]))
		}
	}
	if !slices.Equal(order, []string{"dev.qory.session.started", "dev.qory.session.exited"}) {
		t.Fatalf("%s: %q", where, order)
	}
	exited := data(ofType(evs, "dev.qory.session.exited")[0])
	want := any(reason)
	if reason == "" {
		want = nil
	}
	if exited["state"] != "failed" || exited["exit_code"] != float64(-1) || exited["reason"] != want {
		t.Errorf("%s: session.exited %v, want failed, -1 and the reason %q", where, exited, reason)
	}
	schema, err := contracts.Compile("events/session.exited.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(exited); err != nil {
		t.Errorf("%s: the session.exited does not validate: %v", where, err)
	}
}
