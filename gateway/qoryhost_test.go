package gateway_test

import (
	"maps"
	"net/http"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// routeEgress is a session's dev.qory.run.egress of a request of the route to
// link.QoryHost, with the changes given.
func routeEgress(runID string, change map[string]any) map[string]any {
	d := map[string]any{
		"host": link.QoryHost, "port": 80, "method": "HTTP", "request_method": "POST", "path": "/tests",
		"request_id": "0123456789abcdef0123456789abcdef", "status": 201, "channel": link.QoryHostChannel,
		"decision": "allowed", "outcome": "connected", "mode": "enforce", "rule": link.QoryHostRule,
	}
	maps.Copy(d, change)
	return ev(runID, event.RunEgress, d)
}

// TestTheLinkTakesASessionsEgressOfTheRouteAlone pins the one dev.qory.run.egress the
// gateway takes from a session: channel qory_host, rule wall:qory-host, host
// host.qory.invalid, port 80 and method HTTP, with no credential, tool or path_rule.
// Another value in any of them is refused, the run ends failed, batch_refused, and the
// report contains the field and the value.
func TestTheLinkTakesASessionsEgressOfTheRouteAlone(t *testing.T) {
	h := start(t, gateway.Config{})
	for _, c := range []struct {
		name   string
		change map[string]any
		why    string // empty when the batch is taken
	}{
		{"the route's decision", nil, ""},
		{"another channel", map[string]any{"channel": "run_api"}, `whose channel is "run_api", not qory_host`},
		{"another rule", map[string]any{"rule": "api.example"}, `whose rule is "api.example", not wall:qory-host`},
		{"another host", map[string]any{"host": "api.example"}, `whose host is "api.example", not host.qory.invalid`},
		{"another port", map[string]any{"port": 443}, `whose port is 443, not 80`},
		{"another method", map[string]any{"method": "HTTPS"}, `whose method is "HTTPS", not HTTP`},
		{"a credential", map[string]any{"credential": "model"}, `whose credential is "model", not absent`},
		{"a tool", map[string]any{"tool": "search"}, `whose tool is "search", not absent`},
		{"a path rule", map[string]any{"path_rule": "/tests"}, `whose path_rule is "/tests", not absent`},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := h.open(server.LinkRunRequest{})
			if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
				t.Fatalf("the first batch: %+v", d)
			}
			d := h.post(routeEgress(a.RunID, c.change))
			if c.why == "" {
				if !d.Accepted() {
					t.Errorf("the batch was refused: %+v", d)
				}
				rec := h.record(a.RunID)
				if last := rec[len(rec)-1]; last.Type != event.RunEgress || last.Data["channel"] != link.QoryHostChannel {
					t.Errorf("the record ends %+v", last)
				}
				return
			}
			if d.Status != http.StatusBadRequest || d.Code != "invalid_request" || d.End != "batch_refused" {
				t.Errorf("the batch: %+v", d)
			}
			if got := h.reportsWith(a.RunID); len(got) != 1 || !strings.Contains(got[0], c.why) {
				t.Errorf("the report %q, want one with %q", got, c.why)
			}
		})
	}
}

// TestASessionsEgressWithoutAFieldIsRefused pins a session's dev.qory.run.egress with no
// channel, a decision the gateway writes: the report says the channel is absent.
func TestASessionsEgressWithoutAFieldIsRefused(t *testing.T) {
	h := start(t, gateway.Config{})
	a := h.open(server.LinkRunRequest{})
	if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	e := routeEgress(a.RunID, nil)
	delete(e["data"].(map[string]any), "channel")
	if d := h.post(e); d.End != "batch_refused" {
		t.Errorf("the batch: %+v", d)
	}
	if !h.reported("whose channel is absent, not qory_host") {
		t.Errorf("the reports %q", h.reportsWith(a.RunID))
	}
}
