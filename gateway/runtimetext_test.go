package gateway_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/server"
)

// TestTheLinkTakesTheRuntimesTextResultAndDenial pins that the gateway reads the event
// types from the contract it embeds: a session's batch with dev.qory.runtime.text,
// dev.qory.runtime.tool_result and dev.qory.runtime.tool_denied, and with line,
// truncated and summary, is taken; a member the schema does not list still ends the
// run, batch_refused, as for an older gateway that does not know the members.
func TestTheLinkTakesTheRuntimesTextResultAndDenial(t *testing.T) {
	h := start(t, gateway.Config{})
	a := h.open(server.LinkRunRequest{})
	if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	n := h.joined(a.RunID)
	sid := "0f3a9c2e-7b1d-4c6e-9a2f-5d8e1b4c7a90"
	batch := []map[string]any{
		sessionStarted(a.RunID, n),
		ev(a.RunID, "dev.qory.runtime.tool_started", map[string]any{"session_id": sid, "session": n, "tool": "Bash", "tool_use_id": "toolu_1", "input": map[string]any{"command": "ls"}, "summary": "ls"}),
		ev(a.RunID, "dev.qory.runtime.tool_denied", map[string]any{"session_id": sid, "session": n, "tool": "Bash", "tool_use_id": "toolu_1", "message": "Denied by a rule", "line": 4}),
		ev(a.RunID, "dev.qory.runtime.tool_result", map[string]any{"session_id": sid, "session": n, "tool_use_id": "toolu_1", "content": []any{map[string]any{"type": "text", "text": "Denied by a rule"}}, "is_error": true, "line": 5}),
		ev(a.RunID, "dev.qory.runtime.text", map[string]any{"session_id": sid, "session": n, "text": strings.Repeat("a", 10), "kind": "text", "role": "assistant", "message_id": "msg_1", "line": 6, "truncated": true}),
	}
	if d := h.post(batch...); !d.Accepted() {
		t.Fatalf("the runtime's batch: %+v", d)
	}
	unknown := ev(a.RunID, "dev.qory.runtime.text", map[string]any{"session_id": sid, "session": n, "text": "a", "kind": "text", "colour": "red"})
	if d := h.post(unknown); d.Status != http.StatusBadRequest || d.End != "batch_refused" {
		t.Errorf("a member the schema does not list: %+v", d)
	}
}
