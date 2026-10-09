package session_test

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/sink"
)

// remoteSpec is a spec whose runtime exits by itself with the status exit, behind a
// fake separate gateway, and the gateway; what the session reported is in reports.
func remoteSpec(t *testing.T, exit int) (session.Spec, *linktest.Fake, func() []string) {
	t.Helper()
	sp, _ := specGateway(t)
	sp.Forwarder = nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", fmt.Sprintf("exit %d", exit)}
	g := linktest.StartRemoteFake(t)
	g.SetInterval(30)
	sp.Gateway = session.RemoteGateway{URL: g.URL(), CAFile: g.CAFile(), Credential: linktest.Credential}
	var mu sync.Mutex
	var reports []string
	sp.Report = func(l string) {
		t.Log("report:", l)
		mu.Lock()
		reports = append(reports, l)
		mu.Unlock()
	}
	return sp, g, func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(reports) }
}

// exitedOf is the data of the one run.exited of the session's record, which is its
// last event, and of the one the gateway received, nil when it received none.
func exitedOf(t *testing.T, res *session.Result, g *linktest.Fake) (own, posted map[string]any) {
	t.Helper()
	evs := events(t, res)
	exited := ofType(evs, "dev.qory.run.exited")
	if len(exited) != 1 || evs[len(evs)-1]["type"] != "dev.qory.run.exited" {
		t.Fatalf("the record's run.exited %v", exited)
	}
	if got := ofType(g.Events(), "dev.qory.run.exited"); len(got) == 1 {
		posted = data(got[0])
	} else if len(got) > 1 {
		t.Errorf("the gateway received %d run.exited", len(got))
	}
	return data(exited[0]), posted
}

// TestTheOutcomeAtTheExitSetsTheStateAndTheReason pins the ask at the runtime's own
// exit behind a separate gateway: the session asks once, by the run's id and with its
// run secret, before it posts run.exited; the starter's outcome sets the state and the
// reason of run.exited, in the record and on the link, and of the result, whatever
// the exit status, which exit_code keeps; with no reason, run.exited has none. A reason
// that is no code, or one of Forager's reserved codes, is dropped alone, and the
// starter's state kept.
func TestTheOutcomeAtTheExitSetsTheStateAndTheReason(t *testing.T) {
	for name, c := range map[string]struct {
		exit          int
		answer        map[string]any
		state, reason string
	}{
		"failed over exit 0":       {0, map[string]any{"state": "failed", "reason": "checks_failed"}, "failed", "checks_failed"},
		"succeeded over exit 3":    {3, map[string]any{"state": "succeeded", "reason": "all_checks_passed"}, "succeeded", "all_checks_passed"},
		"cancelled over exit 0":    {0, map[string]any{"state": "cancelled", "reason": "no_longer_needed"}, "cancelled", "no_longer_needed"},
		"an outcome alone":         {3, map[string]any{"state": "cancelled"}, "cancelled", ""},
		"the same as the exit":     {0, map[string]any{"state": "succeeded", "reason": "all_checks_passed"}, "succeeded", "all_checks_passed"},
		"a reason that is no code": {0, map[string]any{"state": "failed", "reason": "Checks failed"}, "failed", ""},
		"a reserved reason":        {3, map[string]any{"state": "cancelled", "reason": "timeout"}, "cancelled", ""},
	} {
		t.Run(name, func(t *testing.T) {
			sp, g, reports := remoteSpec(t, c.exit)
			var exitedBefore []map[string]any
			g.OnOutcome(func(string) linktest.Reply {
				exitedBefore = ofType(g.Events(), "dev.qory.run.exited")
				return linktest.Reply{Status: 200, Body: c.answer}
			})
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if res.State != c.state || res.Reason != c.reason || res.ExitCode != c.exit || res.RunClosed || res.TimedOut {
				t.Errorf("result %+v, want %s %q with exit %d", res, c.state, c.reason, c.exit)
			}
			if got := g.Outcomes(); !slices.Equal(got, []string{res.RunID}) {
				t.Errorf("the outcome was asked for %v, want once for %s", got, res.RunID)
			}
			// Every request of the run's, the ask among them, carried the run's secret.
			secrets := g.RunSecrets()
			if len(secrets) != len(g.Batches())+len(g.Reloads())+len(g.Outcomes()) || slices.ContainsFunc(secrets, func(s string) bool { return s != linktest.RunSecret }) {
				t.Errorf("the run secrets %q", secrets)
			}
			if len(exitedBefore) != 0 {
				t.Errorf("run.exited was posted before the ask: %v", exitedBefore)
			}
			want := map[string]any{"state": c.state, "exit_code": float64(c.exit)}
			if c.reason != "" {
				want["reason"] = c.reason
			}
			own, posted := exitedOf(t, res, g)
			for _, got := range []map[string]any{own, posted} {
				delete(got, "duration_ms")
				if !maps.Equal(got, want) {
					t.Errorf("run.exited %v, want %v", got, want)
				}
			}
			if r := reports(); len(r) != 0 {
				t.Errorf("the session reported %q", r)
			}
		})
	}
}

// TestNoOutcomeLeavesTheExitToDecide pins every answer to the ask that is no outcome:
// {}, an answer that is not valid, a refusal, a 410 among them, and a 500. The runtime's exit decides, succeeded on 0 and failed otherwise, with no
// reason; nothing is added to the record or the result, and the session reports
// nothing.
func TestNoOutcomeLeavesTheExitToDecide(t *testing.T) {
	for name, reply := range map[string]linktest.Reply{
		"{}":                             {Status: 200, Body: map[string]any{}},
		"a state that is not one":        {Status: 200, Body: map[string]any{"state": "lost", "reason": "checks_failed"}},
		"a reason without a state":       {Status: 200, Body: map[string]any{"reason": "checks_failed"}},
		"a bad state with a bad reason":  {Status: 200, Body: map[string]any{"state": "Failed", "reason": "Checks failed"}},
		"not JSON":                       {Status: 200, Body: []byte("not json")},
		"a 404":                          {Status: 404, Body: map[string]any{"state": "failed", "reason": "checks_failed"}},
		"a 410":                          {Status: 410, Body: map[string]any{"error": "stopped", "from": "gateway", "state": "failed", "reason": "checks_failed"}},
		"the 401 run_credential_refused": {Status: 401, Body: linktest.Refusal("run_credential_refused", "gateway")},
		"a 500":                          {Status: 500},
	} {
		for _, exit := range []int{0, 3} {
			t.Run(fmt.Sprintf("%s, exit %d", name, exit), func(t *testing.T) {
				sp, g, reports := remoteSpec(t, exit)
				g.OnOutcome(func(string) linktest.Reply { return reply })
				res, err := session.Run(context.Background(), sp)
				if err != nil {
					t.Fatal(err)
				}
				state := "succeeded"
				if exit != 0 {
					state = "failed"
				}
				if res.State != state || res.Reason != "" || res.ExitCode != exit || res.RunClosed {
					t.Errorf("result %+v, want %s with no reason", res, state)
				}
				if len(g.Outcomes()) != 1 {
					t.Errorf("the outcome was asked for %d times", len(g.Outcomes()))
				}
				want := map[string]any{"state": state, "exit_code": float64(exit)}
				own, posted := exitedOf(t, res, g)
				for _, got := range []map[string]any{own, posted} {
					delete(got, "duration_ms")
					if !maps.Equal(got, want) {
						t.Errorf("run.exited %v, want %v", got, want)
					}
				}
				if r := reports(); len(r) != 0 {
					t.Errorf("the session reported %q", r)
				}
			})
		}
	}
}

// TestTheLocalLinkAsksNoOutcome pins that a run on the local link never asks: there
// is no starter to ask, so the exit decides at once.
func TestTheLocalLinkAsksNoOutcome(t *testing.T) {
	sp, g := specGateway(t)
	sleeps(&sp, 0)
	g.OnOutcome(func(string) linktest.Reply {
		return linktest.Reply{Status: 200, Body: map[string]any{"state": "failed", "reason": "checks_failed"}}
	})
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "succeeded" || res.Reason != "" || len(g.Outcomes()) != 0 {
		t.Errorf("result %+v, the outcome asked for %v", res, g.Outcomes())
	}
}

// TestARunNotEndedByItselfAsksNoOutcome pins the runs whose runtime did not exit by
// itself: one stopped at its time limit is cancelled with timeout; one the caller's
// context stopped is decided by its exit; one the gateway's 410 closed is recorded
// as the 410 says. None of them asks, behind a separate gateway, whatever the
// starter would answer.
func TestARunNotEndedByItselfAsksNoOutcome(t *testing.T) {
	for name, c := range map[string]struct {
		setup         func(*session.Spec, *linktest.Fake) (context.Context, context.CancelFunc)
		state, reason string
	}{
		"the time limit": {func(sp *session.Spec, _ *linktest.Fake) (context.Context, context.CancelFunc) {
			sp.Timeout = 300 * time.Millisecond
			return context.WithCancel(context.Background())
		}, "cancelled", "timeout"},
		"the caller's context": {func(sp *session.Spec, _ *linktest.Fake) (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 500*time.Millisecond)
		}, "failed", ""},
		"the gateway's 410": {func(sp *session.Spec, g *linktest.Fake) (context.Context, context.CancelFunc) {
			g.OnBatch(func([]map[string]any) linktest.Reply { return *gone("stopped", "cancelled", "no_longer_needed") })
			return context.WithCancel(context.Background())
		}, "cancelled", "no_longer_needed"},
	} {
		t.Run(name, func(t *testing.T) {
			sp, g, _ := remoteSpec(t, 0)
			sp.Args = []string{"-c", "sleep 30"}
			sp.StopGrace = time.Second
			g.SetInterval(1)
			g.OnOutcome(func(string) linktest.Reply {
				return linktest.Reply{Status: 200, Body: map[string]any{"state": "succeeded", "reason": "all_checks_passed"}}
			})
			ctx, cancel := c.setup(&sp, g)
			defer cancel()
			res, err := session.Run(ctx, sp)
			if err != nil {
				t.Fatal(err)
			}
			if res.State != c.state || res.Reason != c.reason {
				t.Errorf("result %+v, want %s %q", res, c.state, c.reason)
			}
			if got := g.Outcomes(); len(got) != 0 {
				t.Errorf("the outcome was asked for %v", got)
			}
		})
	}
}

// TestTheWaitForTheOutcomeIsBounded pins what a gateway that never answers the ask
// costs: the run waits for the outcome no longer than its bound, then the exit decides
// and nothing is added.
func TestTheWaitForTheOutcomeIsBounded(t *testing.T) {
	defer session.SetOutcomeWait(500 * time.Millisecond)()
	sp, g, reports := remoteSpec(t, 0)
	release := make(chan struct{})
	defer close(release)
	g.OnOutcome(func(string) linktest.Reply {
		<-release
		return linktest.Reply{Status: 200, Body: map[string]any{"state": "failed", "reason": "checks_failed"}}
	})
	start := time.Now()
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("the run took %s with a gateway that never answers the ask", took)
	}
	if res.State != "succeeded" || res.Reason != "" || len(g.Outcomes()) != 1 {
		t.Errorf("result %+v, the outcome asked for %v", res, g.Outcomes())
	}
	if r := reports(); len(r) != 0 {
		t.Errorf("the session reported %q", r)
	}
}

// undeliveredRun runs a session behind a fake separate gateway whose starter gives
// the outcome failed, checks_failed, at the exit, and which takes no batch after the
// run's start: run.exited is among what the record still owes. It returns the spec
// of its resend, and the gateway.
func undeliveredRun(t *testing.T) (session.ResendSpec, *linktest.Fake) {
	t.Helper()
	sp, g, _ := remoteSpec(t, 0)
	g.OnOutcome(func(string) linktest.Reply {
		return linktest.Reply{Status: 200, Body: map[string]any{"state": "failed", "reason": "checks_failed"}}
	})
	g.OnBatch(func(evs []map[string]any) linktest.Reply {
		if len(ofType(evs, "dev.qory.run.started")) > 0 {
			return linktest.Reply{Status: 200}
		}
		return linktest.Reply{Status: 503}
	})
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "failed" || res.Reason != "checks_failed" || res.Undelivered == 0 {
		t.Fatalf("result %+v", res)
	}
	return session.ResendSpec{Gateway: sp.Gateway.(session.RemoteGateway), Dir: res.Dir, ForagerVersion: "test"}, g
}

// TestAResendSaysHowTheRunEnded pins the state and the reason of a resend of a run
// whose starter gave its outcome at the exit, and whose batches the gateway did not
// take: the gateway's 410 that ends the run says how it ended, as the session records
// it; a 410 run_closed, which says only that the run had ended otherwise, leaves it to
// the record's own run.exited; and a gateway that takes the record gets run.exited
// again, the starter's reason with it, which says how the run ended.
func TestAResendSaysHowTheRunEnded(t *testing.T) {
	for name, c := range map[string]struct {
		reply         *linktest.Reply
		closed        string
		state, reason string
	}{
		"the gateway's end":   {gone("stopped", "cancelled", "no_longer_needed"), "stopped", "cancelled", "no_longer_needed"},
		"a 410 run_closed":    {gone("run_closed", "", ""), "run_closed", "failed", "checks_failed"},
		"the gateway took it": {&linktest.Reply{Status: 200}, "", "failed", "checks_failed"},
	} {
		t.Run(name, func(t *testing.T) {
			resend, g := undeliveredRun(t)
			g.OnBatch(func([]map[string]any) linktest.Reply { return *c.reply })
			got, err := session.Resend(context.Background(), resend)
			if err != nil || got.RunClosed != (c.closed != "") || got.ClosedReason != c.closed || got.State != c.state || got.Reason != c.reason {
				t.Errorf("the resend %+v %v, want closed %q, %s %q", got, err, c.closed, c.state, c.reason)
			}
			if c.closed != "" {
				return
			}
			exited := ofType(g.Events(), "dev.qory.run.exited")
			if got.Undelivered != 0 || len(exited) == 0 || data(exited[len(exited)-1])["reason"] != "checks_failed" {
				t.Errorf("the resend %+v; the gateway received run.exited %v", got, exited)
			}
		})
	}
}

// TestAResendOfARunAReloadEndedSendsNothing pins a run the gateway ended by its 410 to
// a reload, with the starter's state and reason or its state alone, once the gateway
// took every batch: the session's own run.exited, which holds that state, is in its
// record alone, and delivered.log says stopped. A resend owes nothing: it makes no
// request, and its result is the zero one.
func TestAResendOfARunAReloadEndedSendsNothing(t *testing.T) {
	for name, end := range map[string]*linktest.Reply{
		"failed with checks_failed": gone("stopped", "failed", "checks_failed"),
		"succeeded with no reason":  gone("stopped", "succeeded", ""),
	} {
		t.Run(name, func(t *testing.T) {
			sp, g, _ := remoteSpec(t, 0)
			sp.Args = []string{"-c", "sleep 30"}
			sp.StopGrace = time.Second
			g.SetInterval(1)
			g.SetRunDigest("sha256=" + strings.Repeat("1", 64))
			g.OnBatch(func([]map[string]any) linktest.Reply {
				g.SetRunDigest("sha256=" + strings.Repeat("2", 64))
				return linktest.Reply{Status: 200}
			})
			g.OnReload(func(string) linktest.Reply { return *end })
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if !res.RunClosed || res.ClosedReason != "stopped" {
				t.Fatalf("result %+v", res)
			}
			accepted, stopped, err := sink.Delivered(res.Dir)
			if err != nil || !stopped {
				t.Fatalf("delivered.log %v, stopped %v, %v", accepted, stopped, err)
			}
			for _, e := range events(t, res) {
				if e["type"] != "dev.qory.run.exited" && !accepted[fmt.Sprint(e["sequence"])] {
					t.Fatalf("the gateway did not take %v", e)
				}
			}
			batches := len(g.Batches())
			var asked atomic.Int32
			gw := sp.Gateway.(session.RemoteGateway)
			gw.Credential = func(ctx context.Context) (string, error) { asked.Add(1); return linktest.Credential(ctx) }
			got, err := session.Resend(context.Background(), session.ResendSpec{Gateway: gw, Dir: res.Dir, ForagerVersion: "test"})
			if err != nil || got != (session.ResendResult{}) || asked.Load() != 0 || len(g.Batches()) != batches {
				t.Errorf("the resend %+v %v, %d credential reads, %d batches", got, err, asked.Load(), len(g.Batches())-batches)
			}
		})
	}
}

// TestTheHeartbeatsGoOnWhileTheSessionAsks pins the heartbeats during the ask at the
// exit: a gateway with a short interval that takes its time to answer gets them
// meanwhile, and none after run.exited.
func TestTheHeartbeatsGoOnWhileTheSessionAsks(t *testing.T) {
	sp, g, _ := remoteSpec(t, 0)
	g.SetInterval(1)
	var during atomic.Int32
	g.OnOutcome(func(string) linktest.Reply {
		before := len(ofType(g.Events(), "dev.qory.run.heartbeat"))
		time.Sleep(3500 * time.Millisecond)
		during.Store(int32(len(ofType(g.Events(), "dev.qory.run.heartbeat")) - before))
		return linktest.Reply{Status: 200, Body: map[string]any{"state": "failed", "reason": "checks_failed"}}
	})
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "failed" || res.Reason != "checks_failed" {
		t.Errorf("result %+v", res)
	}
	if during.Load() < 2 {
		t.Errorf("the gateway got %d heartbeats while it was asked for 3.5s at an interval of 1s", during.Load())
	}
	evs := events(t, res)
	if evs[len(evs)-1]["type"] != "dev.qory.run.exited" {
		t.Errorf("the record ends with %v", evs[len(evs)-1]["type"])
	}
}

// TestARunClosedWhileItAsksEndsAsClosed pins a 410 that ends the run while the session
// asks for its outcome, the answer to a batch of the runtime's output: the run ends as
// the 410 says, in the session's record alone, and the outcome is not used.
func TestARunClosedWhileItAsksEndsAsClosed(t *testing.T) {
	sp, g, _ := remoteSpec(t, 0)
	sp.Args = []string{"-c", "echo the last line; exit 0"}
	var asked, refused atomic.Bool
	// The batch of the runtime's output is answered once the session asks, with the 410.
	g.OnBatch(func(evs []map[string]any) linktest.Reply {
		if len(ofType(evs, "dev.qory.run.log")) == 0 {
			return linktest.Reply{Status: 200}
		}
		for deadline := time.Now().Add(5 * time.Second); !asked.Load() && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
		refused.Store(true)
		return *gone("stopped", "cancelled", "no_longer_needed")
	})
	g.OnOutcome(func(string) linktest.Reply {
		asked.Store(true)
		for deadline := time.Now().Add(5 * time.Second); !refused.Load() && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
		return linktest.Reply{Status: 200, Body: map[string]any{"state": "failed", "reason": "checks_failed"}}
	})
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if !refused.Load() {
		t.Fatal("no batch reached the gateway while the session asked")
	}
	if !res.RunClosed || res.ClosedReason != "stopped" || res.State != "cancelled" || res.Reason != "no_longer_needed" || res.ExitCode != 0 {
		t.Errorf("result %+v", res)
	}
	own, posted := exitedOf(t, res, g)
	if own["state"] != "cancelled" || own["reason"] != "no_longer_needed" || posted != nil {
		t.Errorf("run.exited %v, posted %v", own, posted)
	}
}

// TestTheCallersEndAfterTheExitLeavesTheOutcome pins the caller's context ending once
// the runtime has exited by itself: as the exit is observed, or while the gateway is
// asked. The session asks once all the same and waits for the answer, the heartbeats go
// on meanwhile, and the starter's outcome decides: the record, the link and the result
// say failed and checks_failed for a runtime that exited 0, and Cancelled is false.
func TestTheCallersEndAfterTheExitLeavesTheOutcome(t *testing.T) {
	for name, inAsk := range map[string]bool{"as the exit is observed": false, "during the ask": true} {
		t.Run(name, func(t *testing.T) {
			sp, g, reports := remoteSpec(t, 0)
			g.SetInterval(1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if !inAsk {
				session.SetExitObserved(cancel)
				defer session.SetExitObserved(nil)
			}
			var during atomic.Int32
			var ended atomic.Bool
			g.OnOutcome(func(string) linktest.Reply {
				if inAsk {
					cancel()
				}
				ended.Store(ctx.Err() != nil)
				before := len(ofType(g.Events(), "dev.qory.run.heartbeat"))
				time.Sleep(3500 * time.Millisecond)
				during.Store(int32(len(ofType(g.Events(), "dev.qory.run.heartbeat")) - before))
				return linktest.Reply{Status: 200, Body: map[string]any{"state": "failed", "reason": "checks_failed"}}
			})
			res, err := session.Run(ctx, sp)
			if err != nil {
				t.Fatal(err)
			}
			if !ended.Load() {
				t.Fatal("the caller's context had not ended when the gateway was asked")
			}
			if res.State != "failed" || res.Reason != "checks_failed" || res.ExitCode != 0 || res.Cancelled || res.RunClosed || res.TimedOut || res.Undelivered != 0 {
				t.Errorf("result %+v, want failed checks_failed with exit 0, not cancelled", res)
			}
			if got := g.Outcomes(); len(got) != 1 {
				t.Errorf("the outcome was asked for %v", got)
			}
			if during.Load() < 2 {
				t.Errorf("the gateway got %d heartbeats while it was asked for 3.5s at an interval of 1s", during.Load())
			}
			want := map[string]any{"state": "failed", "reason": "checks_failed", "exit_code": float64(0)}
			own, posted := exitedOf(t, res, g)
			for _, got := range []map[string]any{own, posted} {
				delete(got, "duration_ms")
				if !maps.Equal(got, want) {
					t.Errorf("run.exited %v, want %v", got, want)
				}
			}
			if r := reports(); len(r) != 0 {
				t.Errorf("the session reported %q", r)
			}
		})
	}
}

// TestTheCallersEndWhileRunExitedIsPostedKeepsIt pins the caller's context ending
// while the gateway takes the batch with run.exited and the sinks close: run.exited
// stays in the record with the starter's outcome, the gateway takes it, and the result
// is the same, with Cancelled false.
func TestTheCallersEndWhileRunExitedIsPostedKeepsIt(t *testing.T) {
	sp, g, _ := remoteSpec(t, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.OnOutcome(func(string) linktest.Reply {
		return linktest.Reply{Status: 200, Body: map[string]any{"state": "failed", "reason": "checks_failed"}}
	})
	g.OnBatch(func(evs []map[string]any) linktest.Reply {
		if len(ofType(evs, "dev.qory.run.exited")) > 0 {
			cancel()
			time.Sleep(300 * time.Millisecond)
		}
		return linktest.Reply{Status: 200}
	})
	res, err := session.Run(ctx, sp)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil {
		t.Fatal("no batch with run.exited reached the gateway")
	}
	if res.State != "failed" || res.Reason != "checks_failed" || res.ExitCode != 0 || res.Cancelled || res.Undelivered != 0 {
		t.Errorf("result %+v", res)
	}
	accepted, _, err := sink.Delivered(res.Dir)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	if last := evs[len(evs)-1]; !accepted[fmt.Sprint(last["sequence"])] {
		t.Errorf("delivered.log does not have run.exited, %v", last)
	}
	want := map[string]any{"state": "failed", "reason": "checks_failed", "exit_code": float64(0)}
	own, posted := exitedOf(t, res, g)
	for _, got := range []map[string]any{own, posted} {
		delete(got, "duration_ms")
		if !maps.Equal(got, want) {
			t.Errorf("run.exited %v, want %v", got, want)
		}
	}
}

// TestARunClosedWhileItAsksEndsTheAsk pins a 410 that closes the run while the
// gateway, which never answers the ask, is asked, the caller's context having ended
// first or not: the ask ends at the close, long before its bound, and the run ends as
// the 410 says, with Cancelled false.
func TestARunClosedWhileItAsksEndsTheAsk(t *testing.T) {
	for name, callerEnds := range map[string]bool{"the context lasts": false, "the context ended first": true} {
		t.Run(name, func(t *testing.T) {
			defer session.SetOutcomeWait(8 * time.Second)()
			sp, g, _ := remoteSpec(t, 0)
			sp.Args = []string{"-c", "echo the last line; exit 0"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			asked := make(chan struct{})
			release := make(chan struct{})
			defer close(release)
			g.OnBatch(func(evs []map[string]any) linktest.Reply {
				if len(ofType(evs, "dev.qory.run.log")) == 0 {
					return linktest.Reply{Status: 200}
				}
				select {
				case <-asked:
				case <-time.After(5 * time.Second):
				}
				return *gone("stopped", "cancelled", "no_longer_needed")
			})
			g.OnOutcome(func(string) linktest.Reply {
				if callerEnds {
					cancel()
				}
				close(asked)
				<-release
				return linktest.Reply{Status: 200, Body: map[string]any{"state": "failed", "reason": "checks_failed"}}
			})
			start := time.Now()
			res, err := session.Run(ctx, sp)
			if err != nil {
				t.Fatal(err)
			}
			if took := time.Since(start); took > 4*time.Second {
				t.Errorf("the run took %s: the close did not end the ask", took)
			}
			if !res.RunClosed || res.ClosedReason != "stopped" || res.State != "cancelled" || res.Reason != "no_longer_needed" || res.ExitCode != 0 || res.Cancelled {
				t.Errorf("result %+v", res)
			}
			own, posted := exitedOf(t, res, g)
			if own["state"] != "cancelled" || own["reason"] != "no_longer_needed" || posted != nil {
				t.Errorf("run.exited %v, posted %v", own, posted)
			}
		})
	}
}

// TestTheWaitForTheOutcomeIsBoundedAfterTheCallersEnd pins the bound of the ask when
// the caller's context ends during it and the gateway never answers: the run waits no
// longer than the bound, then the exit decides, with Cancelled false.
func TestTheWaitForTheOutcomeIsBoundedAfterTheCallersEnd(t *testing.T) {
	defer session.SetOutcomeWait(500 * time.Millisecond)()
	sp, g, _ := remoteSpec(t, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	defer close(release)
	g.OnOutcome(func(string) linktest.Reply {
		cancel()
		<-release
		return linktest.Reply{Status: 200, Body: map[string]any{"state": "failed", "reason": "checks_failed"}}
	})
	start := time.Now()
	res, err := session.Run(ctx, sp)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 4*time.Second {
		t.Errorf("the run took %s with a gateway that never answers the ask", took)
	}
	if res.State != "succeeded" || res.Reason != "" || res.Cancelled || len(g.Outcomes()) != 1 {
		t.Errorf("result %+v, the outcome asked for %v", res, g.Outcomes())
	}
	own, _ := exitedOf(t, res, g)
	if own["state"] != "succeeded" {
		t.Errorf("run.exited %v", own)
	}
}
