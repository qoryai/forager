package session_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/sink"
)

// startRemote starts a fake separate gateway whose certificate the session trusts, until
// the test ends.
func startRemote(t *testing.T) *linktest.Fake {
	t.Helper()
	g := linktest.StartRemoteFake(t)
	t.Cleanup(session.TrustRemote(g.URL(), g.CAFile()))
	return g
}

// remoteSpec is a spec whose runtime exits by itself with the status exit, behind a
// fake separate gateway by a run key of its for a run of its own, and the gateway; what
// the session reported is in reports.
func remoteSpec(t *testing.T, exit int) (session.Spec, *linktest.Fake, func() []string) {
	t.Helper()
	sp, _ := specGateway(t)
	sp.Forwarder = nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", fmt.Sprintf("exit %d", exit)}
	g := startRemote(t)
	g.SetInterval(30)
	sp.Gateway = session.RemoteGateway{RunKey: g.RunKey(t, event.NewRunID())}
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
// and which takes no batch after the run's start: run.exited is among what the record
// still owes. It returns the spec of its resend, with the run's run key, and the
// gateway.
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
	noRunKey(t, res.Dir, sp.Gateway.(session.RemoteGateway).RunKey)
	return session.ResendSpec{Gateway: sp.Gateway.(session.RemoteGateway), Dir: res.Dir, ForagerVersion: "test"}, g
}

// TestAResendSaysHowTheRunEnded pins the state and the reason of a resend of a run
// whose runtime exited 3, and whose batches the gateway did not take: the gateway's 410
// that ends the run says how it ended, as the session records it; a 410 run_closed,
// which says only that the run had ended otherwise, leaves it to the record's own
// run.exited; and a gateway that takes the record gets run.exited again, which says
// how the run ended. Every request carries the run key, which no file holds.
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
			for _, b := range g.Bearers() {
				if b != "Bearer "+resend.Gateway.RunKey {
					t.Errorf("a request carried %q", b)
				}
			}
			noRunKey(t, resend.Dir, resend.Gateway.RunKey)
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
			if !res.RunClosed || res.ClosedReason != "stopped" || res.State != end.Body.(map[string]any)["state"] || res.Reason != reasonOf(end) {
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
			// A gateway no request could reach, and no run key: a resend that asked
			// anything would fail.
			got, err := session.Resend(context.Background(), session.ResendSpec{Dir: res.Dir, ForagerVersion: "test"})
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
	// No run key: a resend that asked anything would fail.
	nowhere := session.ResendSpec{Dir: dir, ForagerVersion: "test"}
	if got, err := session.Resend(context.Background(), nowhere); err != nil || got != (session.ResendResult{NotOpened: true}) {
		t.Errorf("the resend %+v %v", got, err)
	}
}

// reasonOf is the reason of a 410's body, empty for none.
func reasonOf(r *linktest.Reply) string {
	reason, _ := r.Body.(map[string]any)["reason"].(string)
	return reason
}

// noRunKey fails the test if a file of the run directory holds the run key, or any part
// of it.
func noRunKey(t *testing.T, dir, runKey string) {
	t.Helper()
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(runKey[4:40])) {
			t.Errorf("%s holds the run key", p)
		}
		return nil
	})
}

// TestAResendNeedsTheRunKey pins the run key of a resend that owes: without one the
// resend says so, and with one it cannot read, or one of another run, it says that,
// each before any request; and each refusal of the run key the gateway passes on stops
// the resend with that refusal, the gateway's text, what was not accepted under
// undelivered/.
func TestAResendNeedsTheRunKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resend, g := undeliveredRun(t)
	before := len(g.Bearers())
	key := resend.Gateway.RunKey
	for name, c := range map[string]struct {
		key, want string
	}{
		"no run key":       {"", "resend " + resend.Dir + ": the run key is needed to send to its gateway; set QORY_RUN_KEY"},
		"not a run key":    {"qrk_not-a-run-key", "QORY_RUN_KEY is not a run key: "},
		"another run's":    {g.RunKey(t, event.NewRunID()), "resend " + resend.Dir + ": QORY_RUN_KEY names the run "},
		"its wrong prefix": {"qrx_" + key[4:], "QORY_RUN_KEY is not a run key: "},
	} {
		sp := resend
		sp.Gateway = session.RemoteGateway{RunKey: c.key}
		_, err := session.Resend(ctx, sp)
		if err == nil || !strings.HasPrefix(err.Error(), c.want) || (c.key == "" && err.Error() != c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(g.Bearers()) != before {
		t.Error("a resend without its run key made a request")
	}
	for _, c := range []struct {
		status int
		code   string
	}{{400, "run_key_invalid"}, {409, "wrong_gateway"}, {409, "workspace_not_served"}, {409, "run_key_expired"}, {409, "run_attached"}} {
		text := "the gateway refused the run: " + c.code
		g.OnBatch(func([]map[string]any) linktest.Reply {
			return linktest.Reply{Status: c.status, Body: map[string]any{"error": c.code, "from": "gateway", "message": text}}
		})
		got, err := session.Resend(ctx, resend)
		var ref *session.Refusal
		if !errors.As(err, &ref) || ref.Code != c.code || ref.Status != c.status || ref.From != "gateway" || err.Error() != text {
			t.Errorf("%s: %+v %v", c.code, got, err)
		}
		if entries, _ := os.ReadDir(filepath.Join(resend.Dir, sink.UndeliveredDir)); len(entries) == 0 {
			t.Errorf("%s: nothing is under undelivered/", c.code)
		}
	}
	if ctx.Err() != nil {
		t.Fatal("the resends did not stop")
	}
}

// TestBehindGatewayTellsTheRecordsApart pins BehindGateway: a directory is a session's
// record behind a separate gateway when it holds the mark, a regular file, whatever
// else it holds; without the mark, or with a mark that is no regular file, it is not.
// A session behind a separate gateway writes the mark, and one on one machine does not.
func TestBehindGatewayTellsTheRecordsApart(t *testing.T) {
	dir := t.TempDir()
	check := func(what, dir string, want bool) {
		t.Helper()
		if got, err := session.BehindGateway(dir); err != nil || got != want {
			t.Errorf("%s: %v %v, want %v", what, got, err, want)
		}
	}
	check("an empty directory", dir, false)
	os.WriteFile(filepath.Join(dir, sink.SessionFile), nil, 0o600)
	check("the session's record alone", dir, false)
	os.WriteFile(filepath.Join(dir, session.GatewayMark), nil, 0o600)
	check("with the mark", dir, true)
	os.WriteFile(filepath.Join(dir, sink.EventsFile), nil, 0o600)
	check("with the mark and a run stream", dir, true)
	link := t.TempDir()
	os.Symlink(filepath.Join(dir, session.GatewayMark), filepath.Join(link, session.GatewayMark))
	check("a mark that is a symbolic link", link, false)
	check("a directory that does not exist", filepath.Join(dir, "none"), false)

	sp, _, _ := remoteSpec(t, 0)
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	check("a run behind a separate gateway", res.Dir, true)
	local, _ := specGateway(t)
	sleeps(&local, 0)
	if res, err = session.Run(context.Background(), local); err != nil {
		t.Fatal(err)
	}
	check("a run on one machine", res.Dir, false)
}

// TestAnEndUnderAnotherKeyDoesNotEndTheRun pins the gateway's signature mid-run: a 410
// to a batch signed under a key the run key does not name, or not signed, is no answer,
// so the run goes on to its runtime's own end and is not closed; what the gateway did
// not take stays owed.
func TestAnEndUnderAnotherKeyDoesNotEndTheRun(t *testing.T) {
	for name, signing := range map[string]linktest.Signing{"another key": linktest.SignedUnnamed, "no signature": linktest.Unsigned} {
		t.Run(name, func(t *testing.T) {
			sp, g, _ := remoteSpec(t, 0)
			sp.Args = []string{"-c", "sleep 3"}
			g.SetInterval(1)
			g.OnBatch(func(evs []map[string]any) linktest.Reply {
				if len(ofType(evs, "dev.qory.run.started")) > 0 {
					return linktest.Reply{Status: 200}
				}
				r := gone("stopped", "failed", "checks_failed")
				r.Signing = signing
				return *r
			})
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if res.RunClosed || res.State != "succeeded" || res.ExitCode != 0 || res.Undelivered == 0 {
				t.Errorf("result %+v", res)
			}
			if _, stopped, err := sink.Delivered(res.Dir); err != nil || stopped {
				t.Errorf("delivered.log stopped %v, %v", stopped, err)
			}
		})
	}
}
