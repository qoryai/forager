package session_test

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/session"
)

// joinStepBatch is the index of the first batch g received with the join step's
// dev.qory.run.step_started, -1 for none.
func joinStepBatch(g *linktest.Fake) int {
	return slices.IndexFunc(g.Batches(), func(b []map[string]any) bool {
		return slices.ContainsFunc(b, func(e map[string]any) bool {
			return e["type"] == "dev.qory.run.step_started" && data(e)["kind"] == "join"
		})
	})
}

// TestAJoinWithNoAnswerIsSentAgain pins a join request whose first two tries get no
// answer, the gateway closing the connection, and whose third gets 200, on the local
// link and behind a separate gateway: the join gets the one session number of the
// third answer, and before each try after the first the session's batches are
// flushed, so the batch with the join step's start reached the gateway before it.
func TestAJoinWithNoAnswerIsSentAgain(t *testing.T) {
	// The waits are shorter than the link's batch wait, so only the flush posts the
	// join step's start before the next try.
	t.Cleanup(session.SetJoinRetry(5*time.Second, 10*time.Millisecond))
	for _, where := range []string{"local", "separate"} {
		t.Run(where, func(t *testing.T) {
			var sp runSpec
			var g *linktest.Fake
			if where == "local" {
				sp, g = specGateway(t, "FAKE_EXIT=0")
			} else {
				sp, g, _ = remoteSpec(t, 0)
			}
			var mu sync.Mutex
			tries := 0
			g.OnJoin(func(linktest.Join) linktest.Reply {
				mu.Lock()
				defer mu.Unlock()
				if tries++; tries <= 2 {
					return linktest.Reply{Drop: true}
				}
				return linktest.Reply{Status: 200, Body: map[string]any{"version": 1, "session": 1}}
			})
			res, closed, err := runClosed(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if res.Session != 1 || closed.State != "succeeded" || closed.Undelivered != 0 {
				t.Errorf("result %+v, closed %+v", res, closed)
			}
			joins := g.Joins()
			if len(joins) != 3 {
				t.Fatalf("%d join requests, want 3", len(joins))
			}
			for i, j := range joins[1:] {
				if !slices.Equal(j.Request.Passes, joins[0].Request.Passes) || j.Request.ModelKey != joins[0].Request.ModelKey || j.Request.ModelCredential != joins[0].Request.ModelCredential {
					t.Errorf("try %d %+v is not the first try %+v", i+2, j.Request, joins[0].Request)
				}
				if step := joinStepBatch(g); step < 0 || j.Answered <= step {
					t.Errorf("try %d came after %d answered batches; the join step's start was in batch %d", i+2, j.Answered, step)
				}
			}
			evs := events(t, res)
			if started := ofType(evs, "dev.qory.session.started"); len(started) != 1 || data(started[0])["session"] != float64(1) {
				t.Errorf("session.started %v", started)
			}
			if exited := ofType(evs, "dev.qory.session.exited"); len(exited) != 1 || data(exited[0])["session"] != float64(1) {
				t.Errorf("session.exited %v", exited)
			}
		})
	}
}

// TestAJoinIsSentAgainOnlyAfterNoAnswerOrA503 pins which answers to a join request
// the session sends it again after: a 503 with no code, as no answer; a 403 with a
// code, a 410 and a 400 with a code are the gateway's answer, sent once.
func TestAJoinIsSentAgainOnlyAfterNoAnswerOrA503(t *testing.T) {
	t.Cleanup(session.SetJoinRetry(5*time.Second, 10*time.Millisecond))
	for _, c := range []struct {
		name  string
		first linktest.Reply
		joins int
	}{
		{"503", linktest.Reply{Status: 503}, 2},
		{"403", linktest.Reply{Status: 403, Body: linktest.Refusal("placeholder_conflict", "gateway", "HOME")}, 1},
		{"410", linktest.Reply{Status: 410, Body: linktest.Refusal("run_closed", "gateway")}, 1},
		{"coded 400", linktest.Reply{Status: 400, Body: linktest.Refusal("invalid_request", "gateway")}, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp, g := specGateway(t, "FAKE_EXIT=0")
			var mu sync.Mutex
			tries := 0
			g.OnJoin(func(linktest.Join) linktest.Reply {
				mu.Lock()
				defer mu.Unlock()
				if tries++; tries == 1 {
					return c.first
				}
				return linktest.Reply{Status: 200, Body: map[string]any{"version": 1, "session": 1}}
			})
			res, _, err := runClosed(context.Background(), sp)
			if got := len(g.Joins()); got != c.joins {
				t.Errorf("%d join requests, want %d", got, c.joins)
			}
			if c.joins == 2 {
				if err != nil || res.Session != 1 {
					t.Errorf("result %+v, %v", res, err)
				}
			} else if err == nil {
				t.Errorf("a join answered %d started session %d", c.first.Status, res.Session)
			}
		})
	}
}

// TestAJoinWithNoAnswerUntilTheWindowEnds pins the end of the tries: once the window
// ends the join fails as one try would, and the close's no_session follows what the
// tries got. A try with no answer may have been numbered, so a failed outcome with no
// reason stays failed with no reason; tries that each got a 503 numbered nothing, so
// it is no_session.
func TestAJoinWithNoAnswerUntilTheWindowEnds(t *testing.T) {
	t.Cleanup(session.SetJoinRetry(500*time.Millisecond, 50*time.Millisecond))
	for _, c := range []struct {
		name   string
		reply  func(try int) linktest.Reply
		reason string
	}{
		{"no answer", func(int) linktest.Reply { return linktest.Reply{Drop: true} }, ""},
		{"no answer, then 503", func(try int) linktest.Reply {
			if try == 1 {
				return linktest.Reply{Drop: true}
			}
			return linktest.Reply{Status: 503}
		}, ""},
		{"503", func(int) linktest.Reply { return linktest.Reply{Status: 503} }, "no_session"},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp, g := specGateway(t, "FAKE_EXIT=0")
			var mu sync.Mutex
			tries := 0
			g.OnJoin(func(linktest.Join) linktest.Reply {
				mu.Lock()
				defer mu.Unlock()
				tries++
				return c.reply(tries)
			})
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			if _, err := r.Join(ctx, sp.SessionSpec); err == nil {
				t.Fatal("a join with no answer started")
			}
			if took := time.Since(start); took < 500*time.Millisecond || took > 3*time.Second {
				t.Errorf("the join took %s, want the window of 500ms", took)
			}
			if got := len(g.Joins()); got < 3 {
				t.Errorf("%d join requests in the window", got)
			}
			closed, err := r.Close(ctx, session.Outcome{State: "failed", ExitCode: -1})
			if err != nil {
				t.Fatal(err)
			}
			if closed.State != "failed" || closed.Reason != c.reason || closed.ExitCode != -1 {
				t.Errorf("closed %+v, want failed with -1 and the reason %q", closed, c.reason)
			}
		})
	}
}

// TestTheFinalFlushWaitsForASeparateGateway pins the close's flush of the last batch,
// the one with run.exited, whose first try gets no answer: behind a separate gateway
// the close waits up to the final wait, longer than the other flushes, and returns
// once the gateway accepts the batch; on the local link it waits the close's wait
// alone. A 410 to that batch ends the close's flush at once.
func TestTheFinalFlushWaitsForASeparateGateway(t *testing.T) {
	closeWait, finalWait := session.SetCloseWait(300*time.Millisecond), session.SetFinalWait(10*time.Second)
	t.Cleanup(func() { session.SetCloseWait(closeWait); session.SetFinalWait(finalWait) })
	exitedOnce := func(g *linktest.Fake, last linktest.Reply) {
		var mu sync.Mutex
		tries := 0
		g.OnBatch(func(evs []map[string]any) linktest.Reply {
			if len(ofType(evs, "dev.qory.run.exited")) == 0 {
				return linktest.Reply{Status: 200}
			}
			mu.Lock()
			defer mu.Unlock()
			if tries++; tries == 1 {
				return last
			}
			return linktest.Reply{Status: 200}
		})
	}
	closeTook := func(t *testing.T, sp runSpec) (*session.Closed, time.Duration) {
		t.Helper()
		ctx := context.Background()
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		closed, err := r.Close(ctx, session.Outcome{State: "succeeded"})
		if err != nil {
			t.Fatal(err)
		}
		return closed, time.Since(start)
	}
	t.Run("separate", func(t *testing.T) {
		sp, g, _ := remoteSpec(t, 0)
		exitedOnce(g, linktest.Reply{Drop: true})
		closed, took := closeTook(t, sp)
		// The link sink tries the batch again after 1 s.
		if closed.Undelivered != 0 || took < time.Second || took > 5*time.Second {
			t.Errorf("closed %+v after %s, want the batch accepted after about 1s", closed, took)
		}
		if got := ofType(g.Events(), "dev.qory.run.exited"); len(got) != 2 {
			t.Errorf("the gateway got %d tries of run.exited, want 2", len(got))
		}
	})
	t.Run("local", func(t *testing.T) {
		sp, g := specGateway(t, "FAKE_EXIT=0")
		exitedOnce(g, linktest.Reply{Drop: true})
		closed, took := closeTook(t, sp)
		if closed.Undelivered == 0 || took > time.Second {
			t.Errorf("closed %+v after %s, want the batch undelivered after 300ms", closed, took)
		}
	})
	t.Run("410", func(t *testing.T) {
		sp, g, _ := remoteSpec(t, 0)
		exitedOnce(g, linktest.Reply{Status: 410, Body: linktest.Refusal("run_closed", "gateway")})
		closed, took := closeTook(t, sp)
		if took > 500*time.Millisecond {
			t.Errorf("closed %+v after %s, want at once", closed, took)
		}
		if got := ofType(g.Events(), "dev.qory.run.exited"); len(got) != 1 {
			t.Errorf("the gateway got %d tries of run.exited, want 1", len(got))
		}
	})
}
