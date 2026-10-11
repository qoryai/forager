package session_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
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
	sp.Gateway = session.RemoteGateway{URL: g.URL(), CAFile: g.CAFile()}
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

// undeliveredRun runs a session behind a fake separate gateway whose runtime exits 3,
// and which takes no batch after the run's start: run.exited is among what the record still owes. It returns the spec
// of its resend, and the gateway.
func undeliveredRun(t *testing.T) (session.ResendSpec, *linktest.Fake) {
	t.Helper()
	sp, g, _ := remoteSpec(t, 3)
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
	if res.State != "failed" || res.Reason != "" || res.ExitCode != 3 || res.Undelivered == 0 {
		t.Fatalf("result %+v", res)
	}
	// The record owes: the run directory keeps the run secret for the resend.
	keptRunSecret(t, res.Dir)
	return session.ResendSpec{Gateway: sp.Gateway.(session.RemoteGateway), Dir: res.Dir, ForagerVersion: "test"}, g
}

// TestAResendSaysHowTheRunEnded pins the state and the reason of a resend of a run
// whose runtime exited 3, and whose batches the gateway did not take: the gateway's 410
// that ends the run says how it ended, as the session records it; a 410 run_closed,
// which says only that the run had ended otherwise, leaves it to the record's own
// run.exited; and a gateway that takes the record gets run.exited again, which says
// how the run ended. Either way the run secret, kept while the record owed, is gone.
func TestAResendSaysHowTheRunEnded(t *testing.T) {
	for name, c := range map[string]struct {
		reply         *linktest.Reply
		closed        string
		state, reason string
	}{
		"the gateway's end":   {gone("stopped", "cancelled", "no_longer_needed"), "stopped", "cancelled", "no_longer_needed"},
		"a 410 run_closed":    {gone("run_closed", "", ""), "run_closed", "failed", ""},
		"the gateway took it": {&linktest.Reply{Status: 200}, "", "failed", ""},
	} {
		t.Run(name, func(t *testing.T) {
			resend, g := undeliveredRun(t)
			g.OnBatch(func([]map[string]any) linktest.Reply { return *c.reply })
			got, err := session.Resend(context.Background(), resend)
			if err != nil || got.RunClosed != (c.closed != "") || got.ClosedReason != c.closed || got.State != c.state || got.Reason != c.reason {
				t.Errorf("the resend %+v %v, want closed %q, %s %q", got, err, c.closed, c.state, c.reason)
			}
			// Nothing more is owed: the gateway ended the run or took everything.
			noRunSecret(t, name, resend.Dir)
			if c.closed != "" {
				return
			}
			exited := ofType(g.Events(), "dev.qory.run.exited")
			if got.Undelivered != 0 || len(exited) == 0 || data(exited[len(exited)-1])["exit_code"] != float64(3) {
				t.Errorf("the resend %+v; the gateway received run.exited %v", got, exited)
			}
		})
	}
}

// TestAResendOfARunAReloadEndedSendsNothing pins a run the gateway ended by its 410 to
// a reload, with a state and a reason or a state alone, once the gateway
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
			// A gateway no request could reach: a resend that asked anything would fail.
			nowhere := session.RemoteGateway{URL: "https://127.0.0.1:1", CAFile: g.CAFile()}
			got, err := session.Resend(context.Background(), session.ResendSpec{Gateway: nowhere, Dir: res.Dir, ForagerVersion: "test"})
			if err != nil || got != (session.ResendResult{}) {
				t.Errorf("the resend %+v %v", got, err)
			}
		})
	}
}

// TestTheCallersEndWhileRunExitedIsPostedKeepsIt pins the caller's context ending
// while the gateway takes the batch with run.exited and the sinks close: run.exited
// stays in the record as the runtime's exit decides it, the gateway takes it, and the
// result is the same, with Cancelled false.
func TestTheCallersEndWhileRunExitedIsPostedKeepsIt(t *testing.T) {
	sp, g, _ := remoteSpec(t, 3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	if res.State != "failed" || res.Reason != "" || res.ExitCode != 3 || res.Cancelled || res.Undelivered != 0 {
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
	want := map[string]any{"state": "failed", "exit_code": float64(3)}
	own, posted := exitedOf(t, res, g)
	for _, got := range []map[string]any{own, posted} {
		delete(got, "duration_ms")
		if !maps.Equal(got, want) {
			t.Errorf("run.exited %v, want %v", got, want)
		}
	}
}

// TestAResendOfARunRefusedAtOpenSendsNothing pins a run the separate gateway refused
// at its run request: its record holds the session's run.refused and no delivered.log,
// since the run never opened at the gateway, so the resend is NotOpened and makes no
// request at all.
func TestAResendOfARunRefusedAtOpenSendsNothing(t *testing.T) {
	sp, g, _ := remoteSpec(t, 0)
	g.OnRun(func(server.LinkRunRequest) linktest.Reply {
		return linktest.Reply{Status: 409, Body: linktest.Refusal("run_id_used", "gateway")}
	})
	var ref *session.Refusal
	if res, err := session.Run(context.Background(), sp); !errors.As(err, &ref) || ref.Code != "run_id_used" || res != nil {
		t.Fatalf("a refused run: %v %+v", err, res)
	}
	entries, _ := os.ReadDir(sp.RunsDir)
	if len(entries) != 1 {
		t.Fatalf("run directories %v", entries)
	}
	dir := filepath.Join(sp.RunsDir, entries[0].Name())
	if got := ofType(events(t, &session.Result{Dir: dir}), "dev.qory.run.refused"); len(got) != 1 || data(got[0])["code"] != "run_id_used" {
		t.Fatalf("the record's run.refused %v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, sink.DeliveredFile)); err == nil {
		t.Fatal("a run refused at open has a delivered.log")
	}
	// A gateway no request could reach: a resend that asked anything would fail.
	nowhere := session.ResendSpec{Gateway: session.RemoteGateway{URL: "https://127.0.0.1:1", CAFile: g.CAFile()}, Dir: dir, ForagerVersion: "test"}
	if got, err := session.Resend(context.Background(), nowhere); err != nil || got != (session.ResendResult{NotOpened: true}) {
		t.Errorf("the resend %+v %v", got, err)
	}
}
