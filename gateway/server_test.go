package gateway_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
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

// TestARunWithAServer pins the server's path: the discovery at Start, the run's
// registration with its labels and the interval, its run configuration's policy in the
// answer, dev.qory.run.registered as the record's first event, never posted, and the
// run's stream delivered.
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
		t.Errorf("the run registered with %v", asked)
	}
	c.mu.Lock()
	regs := slices.Clone(c.registrations)
	c.mu.Unlock()
	var reg map[string]any
	if len(regs) != 1 || json.Unmarshal(regs[0], &reg) != nil || reg["run_id"] != a.RunID || reg["forager_version"] != "1.2.3" || reg["interval_seconds"] != 30.0 || reg["about"] != nil {
		t.Errorf("the registrations %q", regs)
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
	if members["source"] != "fetched" || members["run_configuration"] != c.digest || members["url"] != c.srv.URL+runsPath {
		t.Errorf("applied %s", a.Applied)
	}
	runID := a.RunID
	h.post(started(runID, labels), applied(runID, a.Applied), logged(runID))
	h.post(exited(runID))
	if d := h.close(); d != (gateway.Delivery{}) {
		t.Errorf("delivery %+v", d)
	}
	want := []string{event.RunRegistered, event.RunStarted, event.PolicyApplied, event.RunLog, event.RunExited}
	lines := h.record(runID)
	if !slices.Equal(types(lines), want) {
		t.Fatalf("record %v", types(lines))
	}
	if p := lines[0].Data; p["forager_version"] != "1.2.3" || p["interval_seconds"] != 30.0 || p["contract_version"] != 1.0 || len(p) != 4 {
		t.Errorf("run.registered %v", p)
	}
	if got := types(c.lines(t)); !slices.Equal(got, want[1:]) {
		t.Errorf("the server holds %v", got)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "runs", runID, "delivered.log")); err != nil {
		t.Errorf("the delivery state: %v", err)
	}
}

// stopLine is the gateway's report of a server's signed 410: the one line a stop
// gets, whatever its code.
const stopLine = "the server wants no more events of this run; the run goes on"

// TestAServersStopEndsNoRun pins a server's signed 410 during a run, run_closed among
// them: the gateway sends the server nothing more and reports it once, but the run goes
// on. The session's batches get 202 and are in the record, the run ends with the
// session's own run.exited, and Close says no run was closed.
func TestAServersStopEndsNoRun(t *testing.T) {
	c := newControl(t)
	h := start(t, gateway.Config{Server: c.server()})
	a := h.open(server.LinkRunRequest{})
	runID := a.RunID
	h.post(started(runID, nil), applied(runID, a.Applied))
	c.closed.Store(true)
	if d := h.post(logged(runID)); d.Status != http.StatusAccepted {
		t.Errorf("the batch the server answers 410: %+v", d)
	}
	eventually(t, "the server's 410", func() bool { return stopped(h, runID) })
	sent := c.deliveries.Load()
	for range 3 {
		if d := h.post(heartbeat(runID)); d.Status != http.StatusAccepted || d.End != "" {
			t.Errorf("a batch after the server's 410: %+v", d)
		}
	}
	if d := h.post(exited(runID)); d.Status != http.StatusAccepted || d.End != "" {
		t.Errorf("the run.exited after the server's 410: %+v", d)
	}
	if d := h.close(); d != (gateway.Delivery{}) {
		t.Errorf("delivery %+v", d)
	}
	lines := h.record(runID)
	want := []string{event.RunRegistered, event.RunStarted, event.PolicyApplied, event.RunLog, event.RunHeartbeat, event.RunHeartbeat, event.RunHeartbeat, event.RunExited}
	if !slices.Equal(types(lines), want) {
		t.Fatalf("record %v", types(lines))
	}
	if l := lines[len(lines)-1]; l.Data["state"] != "succeeded" || l.Data["reason"] != nil {
		t.Errorf("the record ends with %v, not the session's run.exited", l)
	}
	if n := c.deliveries.Load() - sent; n != 0 {
		t.Errorf("%d requests reached the server after its 410", n)
	}
	if got := h.reportsWith("wants no more events"); len(got) != 1 || got[0] != stopLine {
		t.Errorf("reports %q", got)
	}
}

// TestAServersStopAsTheRunOpensOpensIt pins a server that answers 410 from the moment
// it accepted the run's registration: the run opens with its run answer, the server is
// sent nothing, and the run goes on with no further batch sent.
func TestAServersStopAsTheRunOpensOpensIt(t *testing.T) {
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"observe"}}`, 'a')
	c.closeOnFetch.Store(true)
	h := start(t, gateway.Config{Server: c.server()})
	a, err := h.tryOpen(server.LinkRunRequest{})
	if err != nil || a.RunID == "" {
		t.Fatalf("the run answer %+v, %v", a, err)
	}
	runID := a.RunID
	if d := h.post(started(runID, nil), applied(runID, a.Applied)); d.Status != http.StatusAccepted {
		t.Errorf("the run.started: %+v", d)
	}
	eventually(t, "the server's 410", func() bool { return stopped(h, runID) })
	if d := h.post(heartbeat(runID)); d.Status != http.StatusAccepted || d.End != "" {
		t.Errorf("a batch after the server's 410: %+v", d)
	}
	if d := h.post(exited(runID)); d.Status != http.StatusAccepted || d.End != "" {
		t.Errorf("the run.exited after the server's 410: %+v", d)
	}
	if d := h.close(); d != (gateway.Delivery{}) {
		t.Errorf("delivery %+v", d)
	}
	want := []string{event.RunRegistered, event.RunStarted, event.PolicyApplied, event.RunHeartbeat, event.RunExited}
	if got := types(h.record(runID)); !slices.Equal(got, want) {
		t.Errorf("record %v", got)
	}
	if got := types(c.lines(t)); len(got) != 0 {
		t.Errorf("the server holds %v", got)
	}
	if got := h.reportsWith("wants no more events"); len(got) != 1 || got[0] != stopLine {
		t.Errorf("reports %q", got)
	}
}

// stopped reports whether the run's record is marked stopped: the server answered 410.
func stopped(h *harness, runID string) bool {
	b, _ := os.ReadFile(filepath.Join(h.dir, "runs", runID, "delivered.log"))
	return slices.Contains(strings.Split(string(b), "\n"), "stopped")
}

// TestASigned410ToTheRegistrationIsNoRun pins a server's signed 410 to the run's
// registration, with run_closed or without a code: the server takes no run here, so it
// does not open. The gateway answers 500 internal, from the gateway, the registration
// not accepted, and its record holds nothing: no run.registered, no run.refused.
func TestASigned410ToTheRegistrationIsNoRun(t *testing.T) {
	for _, code := range []string{"run_closed", ""} {
		c := newControl(t)
		h := start(t, gateway.Config{Server: c.server()})
		if code == "" {
			c.stop.Store(true)
		} else {
			c.goneOnFetch.Store(true)
		}
		runID := event.NewRunID()
		want := "register " + c.srv.URL + runsPath + ": status 410: the server did not accept the run"
		status, got := h.refusalOf("/v1/run-configuration", openBody(runID))
		if status != http.StatusInternalServerError || got["error"] != "internal" || got["message"] != want || got["from"] != "gateway" {
			t.Errorf("410 %q to the registration: %d %v, want 500 internal: %q", code, status, got, want)
		}
		var se *server.StatusError
		var r *accesskey.Refusal
		if _, err := h.tryOpen(server.LinkRunRequest{}); !errors.As(err, &se) || errors.As(err, &r) || se.Status != http.StatusInternalServerError || se.Message != want {
			t.Errorf("410 %q to the registration: the session's error %v", code, err)
		}
		h.close()
		if got := types(h.record(runID)); len(got) != 0 {
			t.Errorf("410 %q to the registration: record %v", code, got)
		}
		if got := c.lines(t); len(got) != 0 {
			t.Errorf("410 %q to the registration: the server holds %v", code, types(got))
		}
	}
}

// TestASigned410ToTheReloadStopsTheDeliveries pins a server's signed 410 to the reload
// of a run's run configuration by its id, which an answer's changed digest asks for: as
// a signed 410 to a delivery, the gateway sends the server nothing more and reports it
// once, the policy in force stays, and the run goes on to the session's own end.
func TestASigned410ToTheReloadStopsTheDeliveries(t *testing.T) {
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`, 'a')
	h := start(t, gateway.Config{Server: c.server()})
	a := h.open(server.LinkRunRequest{})
	runID := a.RunID
	sc := script(c)
	sc.then(runsPath+"/"+runID, coded(http.StatusGone, "run_closed"))
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["other.example"]}}`, 'b')
	h.post(started(runID, nil), applied(runID, a.Applied))
	eventually(t, "the reload's 410", func() bool { return stopped(h, runID) })
	if n := len(sc.requests(runsPath + "/" + runID)); n != 1 {
		t.Errorf("the run configuration was fetched again %d times", n)
	}
	sent := c.deliveries.Load()
	if d := h.post(exited(runID)); d.Status != http.StatusAccepted || d.End != "" {
		t.Errorf("the run.exited after the reload's 410: %+v", d)
	}
	if d := h.close(); d != (gateway.Delivery{}) {
		t.Errorf("delivery %+v", d)
	}
	if n := c.deliveries.Load() - sent; n != 0 {
		t.Errorf("%d requests reached the server after its 410", n)
	}
	if got := h.reportsWith("wants no more events"); len(got) != 1 || got[0] != stopLine {
		t.Errorf("reports %q", got)
	}
	if got := h.reportsWith("the reload failed"); len(got) != 0 {
		t.Errorf("reports %q", got)
	}
	want := []string{event.RunRegistered, event.RunStarted, event.PolicyApplied, event.RunExited}
	if got := types(h.record(runID)); !slices.Equal(got, want) {
		t.Errorf("record %v", got)
	}
}

// TestA404ToTheReloadKeepsThePolicy pins a server's signed 404 to the reload of a
// run's run configuration by its id, which a server answers a run it does not know
// under the access key: the reload fails, the user is told as of any failed reload,
// the policy in force stays, its digest too, and the deliveries go on.
func TestA404ToTheReloadKeepsThePolicy(t *testing.T) {
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`, 'a')
	h := start(t, gateway.Config{Server: c.server()})
	a := h.open(server.LinkRunRequest{})
	runID := a.RunID
	sc := script(c)
	sc.then(runsPath+"/"+runID, apiaryReply{status: http.StatusNotFound, signed: true})
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["other.example"]}}`, 'b')
	h.post(started(runID, nil), applied(runID, a.Applied))
	eventually(t, "the failed reload's report", func() bool { return h.reported("the reload failed: ") })
	if got := h.reportsWith("the reload failed"); len(got) != 1 || !strings.Contains(got[0], runsPath+"/"+runID) || !strings.Contains(got[0], "404") {
		t.Errorf("reports %q", got)
	}
	r, err := h.linkOf(runID).Reload(context.Background(), server.LocalOrigin+"/v1/run-configuration", runID)
	if err != nil {
		t.Fatal(err)
	}
	var pol struct{ Egress struct{ Allow []string } }
	json.Unmarshal(r.Policy, &pol)
	if r.Digest != a.Digest || !slices.Equal(pol.Egress.Allow, []string{"api.example"}) {
		t.Errorf("after a 404 to the reload: %s, digest %s, want %s", r.Policy, r.Digest, a.Digest)
	}
	if stopped(h, runID) {
		t.Error("a 404 to the reload stopped the deliveries")
	}
	sent := c.deliveries.Load()
	if d := h.post(exited(runID)); d.Status != http.StatusAccepted || d.End != "" {
		t.Errorf("the run.exited after the 404: %+v", d)
	}
	h.close()
	if c.deliveries.Load() == sent {
		t.Error("nothing reached the server after the 404")
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
	// Its message names the server's run endpoint.
	if status, got := h.refusalOf("/v1/run-configuration", openBody(event.NewRunID())); status != http.StatusConflict || got["message"] != "register "+c.srv.URL+runsPath+": instance_limit (status 409)" {
		t.Errorf("instance_limit: %d %v", status, got)
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
	r, err := h.linkOf(runID).Reload(context.Background(), server.LocalOrigin+"/v1/run-configuration", runID)
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
	again, err := h.linkOf(runID).Reload(context.Background(), server.LocalOrigin+"/v1/run-configuration", runID)
	if err != nil || again.Digest != r.Digest {
		t.Errorf("after a failed reload: %v %+v", err, again)
	}
	h.post(exited(runID))
	h.close()
	if got := types(h.record(runID)); !slices.Equal(got[len(got)-2:], []string{event.RunHeartbeat, event.RunExited}) {
		t.Errorf("record %v", got)
	}
}

// tunnel opens a CONNECT tunnel to target through the run's proxy, as the run's
// harness would.
func tunnel(t *testing.T, addr, secret, target string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	io.WriteString(c, link.Preamble(link.RelayPreamble, secret))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT %s: %d", target, resp.StatusCode)
	}
	return c
}

// TestAReloadRecordsTheTunnelsItClosesAfterItsPolicyApplied pins today's order of a
// reload, one-machine behaviour: the run.egress of a tunnel the new policy closes
// follows the session's run.policy_applied of the new policy, which the session writes
// after its reload; when the run ends before the session writes it, the egress comes
// right before the run's end.
func TestAReloadRecordsTheTunnelsItClosesAfterItsPolicyApplied(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	for _, writes := range []bool{true, false} {
		t.Run(fmt.Sprintf("policy_applied %v", writes), func(t *testing.T) {
			c := newControl(t)
			c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, 'a')
			h := start(t, gateway.Config{Server: c.server()})
			a := h.open(server.LinkRunRequest{})
			runID := a.RunID
			h.mu.Lock()
			first := h.digests[len(h.digests)-1].RunConfiguration
			h.mu.Unlock()
			h.post(started(runID, nil), applied(runID, a.Applied))
			conn := tunnel(t, h.g.Addr(), a.ProxySecret, origin.Addr().String())
			c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["b.example"]}}`, 'b')
			h.post(logged(runID))
			eventually(t, "the reload", func() bool {
				d := h.post(heartbeat(runID))
				return d.Accepted() && d.Digests.RunConfiguration != first
			})
			// The new policy closed the tunnel.
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("the tunnel the reload closed: %v", err)
			}
			denied := func(l recorded) bool { return l.Type == event.RunEgress && l.Data["decision"] == "denied" }
			if slices.ContainsFunc(h.record(runID), denied) {
				t.Errorf("the closed tunnel is recorded before the session's policy_applied: %v", types(h.record(runID)))
			}
			if writes {
				r, err := h.linkOf(runID).Reload(context.Background(), server.LocalOrigin+"/v1/run-configuration", runID)
				if err != nil {
					t.Fatal(err)
				}
				h.post(applied(runID, r.Applied), logged(runID))
			}
			h.post(exited(runID))
			h.close()
			lines := h.record(runID)
			i := slices.IndexFunc(lines, denied)
			if i < 1 || lines[i].Data["host"] != "127.0.0.1" || slices.ContainsFunc(lines[i+1:], denied) {
				t.Fatalf("record %v", types(lines))
			}
			want := []string{event.PolicyApplied, event.RunEgress, event.RunLog, event.RunExited}
			if !writes {
				want = []string{event.RunHeartbeat, event.RunEgress, event.RunExited}
			}
			if got := types(lines[i-1:]); !slices.Equal(got, want) {
				t.Errorf("after the reload %v, want %v", got, want)
			}
			if writes && !slices.Equal(anyStrings(lines[i-1].Data["allow"]), []string{"b.example"}) {
				t.Errorf("the egress follows the policy_applied %v", lines[i-1].Data)
			}
		})
	}
}

// TestANewConnectionAfterAReloadFollowsItsPolicyApplied pins today's order of a
// reload for every connection, not only the tunnels it closes: a connection the new
// policy decides, made before the session writes that policy's run.policy_applied, is
// recorded after it; one decided before the reload keeps its place.
func TestANewConnectionAfterAReloadFollowsItsPolicyApplied(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"observe"}}`, 'a')
	h := start(t, gateway.Config{Server: c.server()})
	a := h.open(server.LinkRunRequest{})
	runID := a.RunID
	h.mu.Lock()
	first := h.digests[len(h.digests)-1].RunConfiguration
	h.mu.Unlock()
	h.post(started(runID, nil), applied(runID, a.Applied))
	agent := relay(h.g.Addr(), a.ProxySecret)
	get := func(want int) {
		t.Helper()
		resp, err := agent.Get(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("GET %s: %d, want %d", origin.URL, resp.StatusCode, want)
		}
	}
	get(http.StatusOK)
	c.serve(`{"version":1,"egress":{"mode":"observe","deny":["127.0.0.1"]}}`, 'b')
	h.post(logged(runID))
	eventually(t, "the reload", func() bool {
		d := h.post(heartbeat(runID))
		return d.Accepted() && d.Digests.RunConfiguration != first
	})
	// The agent connects under the new policy before the session has written its event.
	get(http.StatusForbidden)
	denied := func(l recorded) bool { return l.Type == event.RunEgress && l.Data["decision"] == "denied" }
	if slices.ContainsFunc(h.record(runID), denied) {
		t.Errorf("a connection under the new policy is recorded before its policy_applied: %v", types(h.record(runID)))
	}
	r, err := h.linkOf(runID).Reload(context.Background(), server.LocalOrigin+"/v1/run-configuration", runID)
	if err != nil {
		t.Fatal(err)
	}
	h.post(applied(runID, r.Applied), logged(runID))
	h.post(exited(runID))
	h.close()
	lines := h.record(runID)
	i := slices.IndexFunc(lines, denied)
	if i < 1 || lines[i].Data["host"] != "127.0.0.1" || !slices.Equal(anyStrings(lines[i-1].Data["deny"]), []string{"127.0.0.1"}) {
		t.Fatalf("record %v", types(lines))
	}
	if got, want := types(lines[i-1:]), []string{event.PolicyApplied, event.RunEgress, event.RunLog, event.RunExited}; !slices.Equal(got, want) {
		t.Errorf("after the reload %v, want %v", got, want)
	}
	// The connection before the reload kept its place, before the reload's log.
	before := slices.IndexFunc(lines, func(l recorded) bool { return l.Type == event.RunEgress && l.Data["decision"] == "allowed" })
	if want := []string{event.RunRegistered, event.RunStarted, event.PolicyApplied, event.RunEgress, event.RunLog}; before != 3 || !slices.Equal(types(lines[:5]), want) {
		t.Errorf("before the reload %v", types(lines))
	}
}

// TestCloseAndResend pins delivery: events the server did not accept by Close are
// Undelivered, and a resend of the run's record directory sends them; a run still live
// at Close ends at once, without an exit, whatever the context allows, Close returning
// within the flush's bound, and a resend completes it with gateway_lost.
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
	begun := time.Now()
	closed := make(chan struct{})
	var d gateway.Delivery
	var err error
	go func() {
		defer close(closed)
		d, err = h.g.Close(context.Background())
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close waits for a live run")
	}
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(begun); took > 3*time.Second {
		t.Errorf("Close took %v", took)
	}
	if got := types(h.record(lost.RunID)); !slices.Equal(got, []string{event.RunRegistered, event.RunStarted}) {
		t.Errorf("the live run's record at Close %v", got)
	}
	if _, err := relay(h.g.Addr(), lost.ProxySecret).Get("http://a.example/"); err == nil {
		t.Error("the live run's secret was served after Close")
	}
	if d.Undelivered < 5 || d.RunClosed || d.Stopped {
		t.Errorf("delivery %+v", d)
	}
	c.refuse.Store(0)
	dir := filepath.Join(h.dir, "runs", a.RunID)
	r, err := gateway.Resend(context.Background(), gateway.ResendConfig{Server: c.server(), Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if r.Sent != 4 || r.Undelivered != 0 || r.Completed || r.NotOpened || r.Stopped || r.State != "" || r.Reason != "" {
		t.Errorf("resend %+v", r)
	}
	r, err = gateway.Resend(context.Background(), gateway.ResendConfig{Server: c.server(), Dir: filepath.Join(h.dir, "runs", lost.RunID)})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Completed || r.Sent != 2 || r.Stopped || r.State != "failed" || r.Reason != "gateway_lost" {
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

// TestAResendAfterAServersStop pins a resend the server answers with a signed 410,
// run_closed among them: it stops and closes no run, the record is marked stopped, and
// the next resend sends the server nothing and says why, once. Both are Stopped.
func TestAResendAfterAServersStop(t *testing.T) {
	c := newControl(t)
	cfg := gateway.Config{Server: c.server()}
	gateway.SetCloseWait(&cfg, 300*time.Millisecond)
	h := start(t, cfg)
	a := h.open(server.LinkRunRequest{})
	c.refuse.Store(http.StatusServiceUnavailable)
	h.post(started(a.RunID, nil), applied(a.RunID, a.Applied), logged(a.RunID))
	h.post(exited(a.RunID))
	if d := h.close(); d.Undelivered < 4 {
		t.Fatalf("delivery %+v", d)
	}
	c.refuse.Store(0)
	c.closed.Store(true)
	dir := filepath.Join(h.dir, "runs", a.RunID)
	d, err := gateway.Resend(context.Background(), gateway.ResendConfig{Server: c.server(), Dir: dir})
	if err != nil || d.RunClosed || d.ClosedReason != "" || d.Reason != "" || d.Sent != 0 || !d.Stopped {
		t.Errorf("the resend the server answers 410: %+v, %v", d, err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "delivered.log")); err != nil || !slices.Contains(strings.Split(string(b), "\n"), "stopped") {
		t.Errorf("the record is not marked stopped: %q, %v", b, err)
	}
	sent := c.deliveries.Load()
	var reports []string
	d, err = gateway.Resend(context.Background(), gateway.ResendConfig{Server: c.server(), Dir: dir, Report: func(l string) { reports = append(reports, l) }})
	if err != nil || d != (gateway.Delivery{Stopped: true}) {
		t.Errorf("the next resend: %+v, %v", d, err)
	}
	if n := c.deliveries.Load() - sent; n != 0 {
		t.Errorf("the next resend made %d deliveries", n)
	}
	if len(reports) != 1 || reports[0] != "the server said stop during the run; nothing is sent" {
		t.Errorf("the next resend reports %q", reports)
	}
}

// TestAResendTheServerStopsMidway pins a resend the server answers a signed 410 after
// it accepted its first batch: the delivery is Stopped, Sent the events of that batch
// alone, which the server holds, and Undelivered the rest, which are not spooled: there
// is no undelivered/, and they are in events.jsonl alone, which the resend left whole.
// The stop is reported once, and no line points to undelivered/.
func TestAResendTheServerStopsMidway(t *testing.T) {
	c := newControl(t)
	cfg := gateway.Config{Server: c.server()}
	gateway.SetCloseWait(&cfg, 300*time.Millisecond)
	h := start(t, cfg)
	a := h.open(server.LinkRunRequest{})
	c.refuse.Store(http.StatusServiceUnavailable)
	h.post(started(a.RunID, nil), applied(a.RunID, a.Applied))
	// More events than one batch holds, so the resend posts two.
	for range 2 {
		var logs []map[string]any
		for range 75 {
			logs = append(logs, logged(a.RunID))
		}
		h.post(logs...)
	}
	h.post(exited(a.RunID))
	if d := h.close(); d.Undelivered < 150 || d.Stopped {
		t.Fatalf("delivery %+v", d)
	}
	dir := filepath.Join(h.dir, "runs", a.RunID)
	before, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	owed := len(h.record(a.RunID)) - 1 // all but the run.registered, which is never posted
	c.refuse.Store(0)
	c.goneAfter.Store(c.deliveries.Load() + 1)
	stored := c.store.Count()
	var reports []string
	d, err := gateway.Resend(context.Background(), gateway.ResendConfig{Server: c.server(), Dir: dir, Report: func(l string) { reports = append(reports, l) }})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Stopped || d.Sent == 0 || d.Undelivered == 0 || d.Sent+d.Undelivered != owed || d.RunClosed || d.Completed || d.NotOpened {
		t.Errorf("the resend the server stops midway: %+v, %d owed", d, owed)
	}
	if n := c.store.Count() - stored; n != d.Sent {
		t.Errorf("the server stored %d events, Sent %d", n, d.Sent)
	}
	if !slices.Equal(reports, []string{stopLine}) {
		t.Errorf("reports %q", reports)
	}
	if _, err := os.Stat(filepath.Join(dir, "undelivered")); !os.IsNotExist(err) {
		t.Errorf("undelivered/ after the stop: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "events.jsonl")); string(after) != string(before) {
		t.Error("the resend changed events.jsonl")
	}
	if !stopped(h, a.RunID) {
		t.Error("the record is not marked stopped")
	}
}

// TestResendReadsOnPastATornLine pins a resend of a record with a line the gateway did
// not finish in its middle: the part of an event it holds is skipped, and every whole
// event after it reaches the server, in sequence order, then gateway_lost, numbered
// after the highest sequence.
func TestResendReadsOnPastATornLine(t *testing.T) {
	c := newControl(t)
	cfg := gateway.Config{Server: c.server()}
	gateway.SetCloseWait(&cfg, 300*time.Millisecond)
	h := start(t, cfg)
	a := h.open(server.LinkRunRequest{})
	c.refuse.Store(http.StatusServiceUnavailable)
	h.post(started(a.RunID, nil), applied(a.RunID, a.Applied), logged(a.RunID), logged(a.RunID))
	if _, err := h.g.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.refuse.Store(0)
	file := filepath.Join(h.dir, "runs", a.RunID, "events.jsonl")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(b), "\n")
	if want := []string{event.RunRegistered, event.RunStarted, event.PolicyApplied, event.RunLog, event.RunLog}; !slices.Equal(types(h.record(a.RunID)), want) {
		t.Fatalf("the record %v", types(h.record(a.RunID)))
	}
	// The first log's write did not finish, and the second's went on in its line.
	torn := lines[0] + lines[1] + lines[2] + lines[3][:len(lines[3])/2] + lines[4]
	if err := os.WriteFile(file, []byte(torn), 0o644); err != nil {
		t.Fatal(err)
	}
	var reports []string
	r, err := gateway.Resend(context.Background(), gateway.ResendConfig{Server: c.server(), Dir: filepath.Dir(file), Report: func(l string) { reports = append(reports, l) }})
	if err != nil {
		t.Fatal(err)
	}
	if want := "1 lines of " + file + " are not whole events and are not sent"; !slices.Equal(reports, []string{want}) {
		t.Errorf("reports %q, want %q", reports, want)
	}
	if !r.Completed || r.Sent != 4 || r.Undelivered != 0 {
		t.Errorf("resend %+v", r)
	}
	var got []string
	for _, l := range c.lines(t) {
		got = append(got, l.Type+" "+l.Sequence)
	}
	want := []string{event.RunStarted + " 0000000002", event.PolicyApplied + " 0000000003", event.RunLog + " 0000000005", event.RunExited + " 0000000006"}
	if !slices.Equal(got, want) {
		t.Errorf("the server has %v, want %v", got, want)
	}
	after, _ := os.ReadFile(file)
	if !strings.HasPrefix(string(after), torn) {
		t.Error("the record was changed before its end")
	}
}

// TestResendSendsNothingOfARunThatNeverOpened pins a resend of the record of a run whose
// registration the server refused, which holds no event, and of a run that had no
// server: neither opened at the server, so nothing of it is posted, the record is left
// as it is, and the delivery says the run never opened.
func TestResendSendsNothingOfARunThatNeverOpened(t *testing.T) {
	c := newControl(t)
	h := start(t, gateway.Config{Server: c.server()})
	c.limit.Store(true)
	id := event.NewRunID()
	if _, err := h.tryOpen(server.LinkRunRequest{RunID: id}); err == nil {
		t.Fatal("the server accepted the registration")
	}
	c.limit.Store(false)
	dir := filepath.Join(h.dir, "runs", id)
	before, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if got := types(h.record(id)); len(got) != 0 {
		t.Fatalf("the record %v", got)
	}
	stored := c.store.Count()
	var reports []string
	report := func(l string) { reports = append(reports, l) }
	r, err := gateway.Resend(context.Background(), gateway.ResendConfig{Server: c.server(), Dir: dir, Report: report})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"the run never opened at the server; nothing is sent"}; !slices.Equal(reports, want) {
		t.Errorf("reports %q", reports)
	}
	if r != (gateway.Delivery{NotOpened: true}) {
		t.Errorf("resend %+v", r)
	}
	if n := c.store.Count(); n != stored {
		t.Errorf("the server stored %d events, before %d", n, stored)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "events.jsonl")); string(after) != string(before) {
		t.Errorf("the record was changed:\n%s", after)
	}

	// A run of a gateway with no server: no run.registered and a run.started, so it
	// never opened at the server it is sent to.
	local := start(t, gateway.Config{})
	a := local.open(server.LinkRunRequest{})
	local.post(started(a.RunID, nil), applied(a.RunID, a.Applied))
	if _, err := local.g.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(local.dir, "runs", a.RunID)
	before, _ = os.ReadFile(filepath.Join(dir, "events.jsonl"))
	reports = nil
	if r, err = gateway.Resend(context.Background(), gateway.ResendConfig{Server: c.server(), Dir: dir, Report: report}); err != nil || r != (gateway.Delivery{NotOpened: true}) {
		t.Errorf("resend of a run with no server %+v, %v", r, err)
	}
	if want := []string{"the run had no server; nothing is sent"}; !slices.Equal(reports, want) {
		t.Errorf("a run with no server: reports %q", reports)
	}
	if n := c.store.Count(); n != stored {
		t.Errorf("a run with no server: the server stored %d events, before %d", n, stored)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "events.jsonl")); string(after) != string(before) {
		t.Errorf("a run with no server: the record was changed:\n%s", after)
	}
	if _, err := os.Stat(filepath.Join(dir, "delivered.log")); !os.IsNotExist(err) {
		t.Errorf("a run with no server: delivered.log: %v", err)
	}
}
