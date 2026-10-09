package session_test

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/session"
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
// the exit status, which exit_code keeps; with no reason, run.exited has none.
func TestTheOutcomeAtTheExitSetsTheStateAndTheReason(t *testing.T) {
	for name, c := range map[string]struct {
		exit          int
		answer        map[string]any
		state, reason string
	}{
		"failed over exit 0":    {0, map[string]any{"state": "failed", "reason": "checks_failed"}, "failed", "checks_failed"},
		"succeeded over exit 3": {3, map[string]any{"state": "succeeded", "reason": "all_checks_passed"}, "succeeded", "all_checks_passed"},
		"cancelled over exit 0": {0, map[string]any{"state": "cancelled", "reason": "no_longer_needed"}, "cancelled", "no_longer_needed"},
		"an outcome alone":      {3, map[string]any{"state": "cancelled"}, "cancelled", ""},
		"the same as the exit":  {0, map[string]any{"state": "succeeded", "reason": "all_checks_passed"}, "succeeded", "all_checks_passed"},
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
// {}, an answer that is not valid, a reserved reason, a refusal, a 410 among them, and
// a 500. The runtime's exit decides, succeeded on 0 and failed otherwise, with no
// reason; nothing is added to the record or the result, and the session reports
// nothing.
func TestNoOutcomeLeavesTheExitToDecide(t *testing.T) {
	for name, reply := range map[string]linktest.Reply{
		"{}":                             {Status: 200, Body: map[string]any{}},
		"a state that is not one":        {Status: 200, Body: map[string]any{"state": "lost", "reason": "checks_failed"}},
		"a reason without a state":       {Status: 200, Body: map[string]any{"reason": "checks_failed"}},
		"a reason that is no code":       {Status: 200, Body: map[string]any{"state": "failed", "reason": "Checks failed"}},
		"a reserved reason":              {Status: 200, Body: map[string]any{"state": "cancelled", "reason": "timeout"}},
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

// TestAResendSaysHowTheRunEnded pins the state and the reason of a resend: a run whose
// starter gave its outcome at the exit, and whose batches the gateway did not take,
// sends its run.exited again, the starter's reason with it; the gateway's 410 that
// ends the run says how it ended, as the session records it; and once the gateway
// takes the record, the record's run.exited says it.
func TestAResendSaysHowTheRunEnded(t *testing.T) {
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
	resend := session.ResendSpec{Gateway: sp.Gateway.(session.RemoteGateway), Dir: res.Dir, ForagerVersion: "test"}

	g.OnBatch(func([]map[string]any) linktest.Reply { return *gone("stopped", "cancelled", "no_longer_needed") })
	got, err := session.Resend(context.Background(), resend)
	if err != nil || !got.RunClosed || got.ClosedReason != "stopped" || got.State != "cancelled" || got.Reason != "no_longer_needed" {
		t.Errorf("the resend after the gateway's end: %+v %v", got, err)
	}

	g.OnBatch(func([]map[string]any) linktest.Reply { return linktest.Reply{Status: 200} })
	got, err = session.Resend(context.Background(), resend)
	if err != nil || got.RunClosed || got.Undelivered != 0 || got.State != "failed" || got.Reason != "checks_failed" {
		t.Errorf("the resend the gateway took: %+v %v", got, err)
	}
	exited := ofType(g.Events(), "dev.qory.run.exited")
	if len(exited) == 0 || data(exited[len(exited)-1])["reason"] != "checks_failed" {
		t.Errorf("the gateway received run.exited %v", exited)
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
