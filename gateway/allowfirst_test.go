package gateway_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/server"
)

// TestARunReachesItsAllowFirstHost pins allow_first through the gateway: under enforce
// with an empty allow list and an exact deny entry for the host, a host allow_first
// lists is reached and recorded as allowed with the entry as its rule, another host is
// denied, and the run's dev.qory.run.policy_applied reports allow_first beside allow
// and deny.
func TestARunReachesItsAllowFirstHost(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	h := start(t, gateway.Config{Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", AllowFirst: []string{"127.0.0.1"}, Deny: []string{"127.0.0.1"}}}})
	a := h.open(server.LinkRunRequest{})
	var members map[string]any
	if err := json.Unmarshal(a.Applied, &members); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(members["allow_first"], members["allow"], members["deny"]) != "[127.0.0.1] [] [127.0.0.1]" {
		t.Errorf("applied %s", a.Applied)
	}
	c := relay(h.g.Addr(), a.ProxySecret)
	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(b) != "ok" {
		t.Errorf("the allow_first host: %d %q", resp.StatusCode, b)
	}
	resp, err = c.Get("http://denied.example/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("another host: %d", resp.StatusCode)
	}
	if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied), exited(a.RunID)); !d.Accepted() {
		t.Fatalf("the batch: %+v", d)
	}
	h.close()
	lines := h.record(a.RunID)
	if want := []string{event.RunStarted, event.PolicyApplied, event.RunEgress, event.RunEgress, event.RunExited}; !slices.Equal(types(lines), want) {
		t.Fatalf("record %v", types(lines))
	}
	if got := fmt.Sprint(lines[1].Data["allow_first"]); got != "[127.0.0.1]" {
		t.Errorf("policy_applied allow_first %s", got)
	}
	if d := lines[2].Data; d["host"] != "127.0.0.1" || d["decision"] != "allowed" || d["rule"] != "127.0.0.1" {
		t.Errorf("the allow_first host's egress %v", d)
	}
	if d := lines[3].Data; d["host"] != "denied.example" || d["decision"] != "denied" {
		t.Errorf("another host's egress %v", d)
	}
}

// TestAReloadBringsItsAllowFirst pins that a reload puts the new policy's allow_first in
// force: a host the run's deny denied is reached once the reload lists it there, and the
// reload's applied reports it.
func TestAReloadBringsItsAllowFirst(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"observe","deny":["127.0.0.1"]}}`, 'a')
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
	get(http.StatusForbidden)
	c.serve(`{"version":1,"egress":{"mode":"observe","allow_first":["127.0.0.1"],"deny":["127.0.0.1"]}}`, 'b')
	h.post(logged(runID))
	eventually(t, "the reload", func() bool {
		d := h.post(heartbeat(runID))
		return d.Accepted() && d.Digests.RunConfiguration != first
	})
	get(http.StatusOK)
	r, err := h.linkOf(runID).Reload(context.Background(), server.LocalOrigin+"/v1/run-configuration", runID)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]any
	if err := json.Unmarshal(r.Applied, &members); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(members["allow_first"]); got != "[127.0.0.1]" {
		t.Errorf("the reload's applied %s", r.Applied)
	}
	h.post(applied(runID, r.Applied), exited(runID))
	h.close()
}
