package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/server"
)

// eventually waits up to ten seconds for ok.
func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("%s did not happen", what)
}

// TestARunWithAServer pins the server's path: the discovery at Start, the ping as the
// run's first event, the run configuration fetched by the run's labels, its policy in
// the answer, and the run's stream delivered.
func TestARunWithAServer(t *testing.T) {
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`, 'a')
	var found gateway.Discovery
	h := start(t, gateway.Config{Server: c.server(), Version: "1.2.3", Discovered: func(d gateway.Discovery) error { found = d; return nil }})
	if found.NodeID != testNode {
		t.Errorf("discovered %+v", found)
	}
	labels := map[string]string{"repository": "example-namespace/project", "run_key": "rk-0001"}
	a := h.open(server.LinkRunRequest{Labels: labels})
	c.mu.Lock()
	asked := maps.Clone(c.labels)
	c.mu.Unlock()
	if !maps.Equal(asked, labels) {
		t.Errorf("the run configuration was asked for %v", asked)
	}
	var pol struct {
		Egress struct {
			Mode  string
			Allow []string
		}
	}
	json.Unmarshal(a.Policy, &pol)
	if pol.Egress.Mode != "enforce" || !slices.Equal(pol.Egress.Allow, []string{"api.example"}) {
		t.Errorf("policy %s", a.Policy)
	}
	var members map[string]any
	json.Unmarshal(a.Applied, &members)
	if members["source"] != "fetched" || members["run_configuration"] != c.digest || members["url"] != c.srv.URL+"/v1/run-configuration" {
		t.Errorf("applied %s", a.Applied)
	}
	runID := a.RunID
	h.post(started(runID, labels), applied(runID, a.Applied), logged(runID))
	h.post(exited(runID))
	if d := h.close(); d != (gateway.Delivery{}) {
		t.Errorf("delivery %+v", d)
	}
	want := []string{event.Ping, event.RunStarted, event.PolicyApplied, event.RunLog, event.RunExited}
	lines := h.record(runID)
	if !slices.Equal(types(lines), want) {
		t.Fatalf("record %v", types(lines))
	}
	if p := lines[0].Data; p["forager_version"] != "1.2.3" || p["interval_seconds"] != 30.0 {
		t.Errorf("ping %v", p)
	}
	if got := types(c.lines(t)); !slices.Equal(got, want) {
		t.Errorf("the server holds %v", got)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "runs", runID, "delivered.log")); err != nil {
		t.Errorf("the delivery state: %v", err)
	}
}

// TestTheServerClosesARun pins the server's 410: the run ends at the gateway, which
// records run.exited run_closed in its record alone, and the session's next request is
// a 410 run_closed from apiary; Close says who closed it.
func TestTheServerClosesARun(t *testing.T) {
	c := newControl(t)
	h := start(t, gateway.Config{Server: c.server()})
	a := h.open(server.LinkRunRequest{})
	runID := a.RunID
	h.post(started(runID, nil), applied(runID, a.Applied))
	c.closed.Store(true)
	h.post(logged(runID))
	eventually(t, "the session's 410", func() bool {
		d := h.post(heartbeat(runID))
		if d.Status == http.StatusGone && (d.End != "run_closed" || d.From != "apiary") {
			t.Errorf("410 %+v", d)
		}
		return d.Status == http.StatusGone
	})
	if d := h.close(); !d.RunClosed || d.ClosedBy != "apiary" || d.Reason != "run_closed" {
		t.Errorf("delivery %+v", d)
	}
	lines := h.record(runID)
	if l := lines[len(lines)-1]; l.Type != event.RunExited || l.Data["reason"] != "run_closed" || l.Data["state"] != "failed" || l.Data["exit_code"] != -1.0 {
		t.Errorf("record ends %v", l)
	}
	if got := c.lines(t); got[len(got)-1].Type == event.RunExited {
		t.Error("the server was sent the gateway's run.exited")
	}
}

// TestTheServerClosesARunBeforeItStarts pins a close before run.started: the run ends
// at the gateway with run.refused run_closed in its record, as today's session records
// it, and the session hears 410 run_closed from apiary.
func TestTheServerClosesARunBeforeItStarts(t *testing.T) {
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"observe"}}`, 'a')
	c.closeOnFetch.Store(true)
	h := start(t, gateway.Config{Server: c.server()})
	runID := h.open(server.LinkRunRequest{}).RunID
	h.post(heartbeat(runID))
	eventually(t, "the session's 410", func() bool {
		d := h.post(heartbeat(runID))
		return d.Status == http.StatusGone && d.From == "apiary"
	})
	h.close()
	lines := h.record(runID)
	if l := lines[len(lines)-1]; l.Type != event.RunRefused || l.Data["code"] != "run_closed" || l.Data["status"] != 410.0 {
		t.Errorf("record %v, ends %v", types(lines), l)
	}
}

// TestRefusalsAtTheStartPassOn pins a refusal at a run's start: the server's reaches the
// session with its code and status, from apiary; one of the run's configuration the
// gateway decides is a 403 from the gateway.
func TestRefusalsAtTheStartPassOn(t *testing.T) {
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"bogus"}}`, 'a')
	h := start(t, gateway.Config{Server: c.server()})
	c.limit.Store(true)
	_, err := h.tryOpen(server.LinkRunRequest{})
	var r *accesskey.Refusal
	if !errors.As(err, &r) || r.Code != "instance_limit" || r.From != "apiary" || r.Status != http.StatusConflict {
		t.Errorf("the server's refusal: %v", err)
	}
	c.limit.Store(false)
	if _, err := h.tryOpen(server.LinkRunRequest{}); !errors.As(err, &r) || r.Code != "run_configuration_invalid" || r.From != "gateway" || r.Status != http.StatusForbidden {
		t.Errorf("an invalid run configuration: %v", err)
	}
}

// TestTheGatewayReloadsARun pins the reload: a server's answer that names another run
// configuration makes the gateway fetch it and put it in force on the run's proxy; the
// session's next answer carries another digest, and its reload GET the new policy.
func TestTheGatewayReloadsARun(t *testing.T) {
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["a.example"]}}`, 'a')
	h := start(t, gateway.Config{Server: c.server()})
	labels := map[string]string{"repository": "example-namespace/project"}
	a := h.open(server.LinkRunRequest{Labels: labels})
	runID := a.RunID
	h.mu.Lock()
	first := h.digests[len(h.digests)-1].RunConfiguration
	h.mu.Unlock()
	if d := h.post(started(runID, labels), applied(runID, a.Applied)); !d.Accepted() || d.Digests.RunConfiguration != first {
		t.Fatalf("the first batch: %+v, the answer's digest %s", d, first)
	}
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["b.example"]}}`, 'b')
	h.post(logged(runID))
	eventually(t, "the reload", func() bool {
		d := h.post(heartbeat(runID))
		return d.Accepted() && d.Digests.RunConfiguration != first
	})
	r, err := h.link.Reload(context.Background(), server.LocalOrigin+"/v1/run-configuration", runID)
	if err != nil {
		t.Fatal(err)
	}
	var pol struct{ Egress struct{ Allow []string } }
	json.Unmarshal(r.Policy, &pol)
	if !slices.Equal(pol.Egress.Allow, []string{"b.example"}) || r.Digest == a.Digest {
		t.Errorf("reload %s", r.Policy)
	}
	// The session writes policy_applied from the reload answer; the first one stays
	// one the gateway gave the run.
	if d := h.post(applied(runID, r.Applied)); !d.Accepted() {
		t.Errorf("the reload's policy_applied: %+v", d)
	}
	// A run configuration the gateway refuses fails the reload: the user is told as
	// today, and the policy in force stays, its digest too.
	c.serve(`{"version":1,"egress":{"mode":"bogus"}}`, 'c')
	h.post(logged(runID))
	eventually(t, "the failed reload's report", func() bool {
		h.post(heartbeat(runID))
		return h.reported("the reload failed: ")
	})
	again, err := h.link.Reload(context.Background(), server.LocalOrigin+"/v1/run-configuration", runID)
	if err != nil || again.Digest != r.Digest {
		t.Errorf("after a failed reload: %v %+v", err, again)
	}
	h.post(exited(runID))
	h.close()
	if got := types(h.record(runID)); !slices.Equal(got[len(got)-2:], []string{event.RunHeartbeat, event.RunExited}) {
		t.Errorf("record %v", got)
	}
}

// TestCloseAndResend pins delivery: events the server did not accept by Close are
// Undelivered, and a resend of the run's record directory sends them; a run Close did
// not see end is completed with gateway_lost.
func TestCloseAndResend(t *testing.T) {
	c := newControl(t)
	cfg := gateway.Config{Server: c.server()}
	gateway.SetCloseWait(&cfg, 300*time.Millisecond)
	h := start(t, cfg)
	a := h.open(server.LinkRunRequest{})
	lost := h.open(server.LinkRunRequest{})
	c.refuse.Store(http.StatusServiceUnavailable)
	h.post(started(a.RunID, nil), applied(a.RunID, a.Applied), logged(a.RunID))
	h.post(exited(a.RunID))
	h.post(started(lost.RunID, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	d, err := h.g.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d.Undelivered < 5 || d.RunClosed {
		t.Errorf("delivery %+v", d)
	}
	c.refuse.Store(0)
	dir := filepath.Join(h.dir, "runs", a.RunID)
	r, err := gateway.Resend(context.Background(), gateway.ResendConfig{Server: c.server(), Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if r.Sent != 4 || r.Undelivered != 0 || r.Completed {
		t.Errorf("resend %+v", r)
	}
	r, err = gateway.Resend(context.Background(), gateway.ResendConfig{Server: c.server(), Dir: filepath.Join(h.dir, "runs", lost.RunID)})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Completed || r.Sent != 2 {
		t.Errorf("resend of the lost run %+v", r)
	}
	lines := h.record(lost.RunID)
	if l := lines[len(lines)-1]; l.Type != event.RunExited || l.Data["reason"] != "gateway_lost" {
		t.Errorf("the lost run ends %v", l)
	}
	if _, err := gateway.Resend(context.Background(), gateway.ResendConfig{Server: c.server(), Dir: filepath.Join(h.dir, "runs", event.NewRunID())}); err == nil {
		t.Error("a resend of no record")
	}
}
