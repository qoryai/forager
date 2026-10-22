package e2e

import (
	"bufio"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// script is a main conversation that starts a subagent, and the subagent's
// conversation, which reads a file and answers.
var script = Script{Conversations: []Conversation{
	{When: "Find the module", Answers: []Answer{
		{Agent: &AgentCall{Type: "general-purpose", Description: "Read go.mod", Prompt: "Read go.mod and give its module"}},
		{Text: "The module is example.com/app."},
	}},
	{When: "Read go.mod and give its module", Answers: []Answer{
		{Tool: &ToolCall{Name: "Read", Input: map[string]any{"file_path": "/workspace/go.mod"}}},
		{Text: "example.com/app"},
	}},
}}

// requestBody is a Messages API request whose first message is first, with the
// assistant turns given and the tools offered.
func requestBody(t *testing.T, stream bool, first string, assistant int, tools ...string) []byte {
	t.Helper()
	messages := []any{map[string]any{"role": "user", "content": []any{
		map[string]any{"type": "text", "text": "<system-reminder>context</system-reminder>"},
		map[string]any{"type": "text", "text": first},
	}}}
	for range assistant {
		messages = append(messages,
			map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "t", "name": "x", "input": map[string]any{}}}},
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "t", "content": "ok"}}})
	}
	var offered []any
	for _, n := range tools {
		offered = append(offered, map[string]any{"name": n, "input_schema": map[string]any{"type": "object"}})
	}
	b, err := json.Marshal(map[string]any{"model": "m", "stream": stream, "messages": messages, "tools": offered})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestTheRecorderReplaysItsScript pins the scripted answers, not streamed: an Agent
// call, a tool call and a text, each by its conversation and step; the fixed text for a
// request of no conversation, past the last answer, offered no tool of the call, and
// for a recorder without a script.
func TestTheRecorderReplaysItsScript(t *testing.T) {
	answerOf := func(s Script, body []byte) map[string]any {
		w := httptest.NewRecorder()
		answer(w, body, s)
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	text := func(s string) []any { return []any{map[string]any{"type": "text", "text": s}} }
	for name, c := range map[string]struct {
		s       Script
		body    []byte
		content []any
		stop    string
	}{
		"the agent call": {script, requestBody(t, false, "Find the module", 0, "Agent", "Read"), []any{map[string]any{"type": "tool_use", "id": "toolu_walltest_0_0", "name": "Agent",
			"input": map[string]any{"subagent_type": "general-purpose", "description": "Read go.mod", "prompt": "Read go.mod and give its module"}}}, "tool_use"},
		"the main answer": {script, requestBody(t, false, "Find the module", 1, "Agent"), text("The module is example.com/app."), "end_turn"},
		"the tool call": {script, requestBody(t, false, "Read go.mod and give its module", 0, "Read"), []any{map[string]any{"type": "tool_use", "id": "toolu_walltest_1_0", "name": "Read",
			"input": map[string]any{"file_path": "/workspace/go.mod"}}}, "tool_use"},
		"the subagent's answer": {script, requestBody(t, false, "Read go.mod and give its module", 1, "Read"), text("example.com/app"), "end_turn"},
		"past the last answer":  {script, requestBody(t, false, "Find the module", 2, "Agent"), text(recorderAnswer), "end_turn"},
		"no such conversation":  {script, requestBody(t, false, "Write a title", 0, "Agent"), text(recorderAnswer), "end_turn"},
		"no tool offered":       {script, requestBody(t, false, "Find the module", 0), text(recorderAnswer), "end_turn"},
		"no script":             {Script{}, requestBody(t, false, "Find the module", 0, "Agent"), text(recorderAnswer), "end_turn"},
	} {
		got := answerOf(c.s, c.body)
		if !reflect.DeepEqual(got["content"], c.content) || got["stop_reason"] != c.stop || got["model"] != "m" {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// TestTheRecorderStreamsAToolCall pins a streamed tool call: a tool_use block with an
// empty input, the input as one input_json_delta, and tool_use as the stop reason.
func TestTheRecorderStreamsAToolCall(t *testing.T) {
	w := httptest.NewRecorder()
	answer(w, requestBody(t, true, "Read go.mod and give its module", 0, "Read"), script)
	var events []map[string]any
	s := bufio.NewScanner(w.Body)
	for s.Scan() {
		if data, ok := strings.CutPrefix(s.Text(), "data: "); ok {
			var e map[string]any
			if err := json.Unmarshal([]byte(data), &e); err != nil {
				t.Fatal(err)
			}
			events = append(events, e)
		}
	}
	if len(events) != 6 {
		t.Fatalf("%d events: %v", len(events), events)
	}
	start := events[1]["content_block"].(map[string]any)
	delta := events[2]["delta"].(map[string]any)
	stop := events[4]["delta"].(map[string]any)
	if start["type"] != "tool_use" || start["name"] != "Read" || start["id"] != "toolu_walltest_1_0" || !reflect.DeepEqual(start["input"], map[string]any{}) {
		t.Errorf("content_block_start %v", start)
	}
	if delta["type"] != "input_json_delta" || delta["partial_json"] != `{"file_path":"/workspace/go.mod"}` {
		t.Errorf("content_block_delta %v", delta)
	}
	if stop["stop_reason"] != "tool_use" {
		t.Errorf("message_delta %v", stop)
	}
	if env, err := ScriptEnv(script); err != nil || !strings.HasPrefix(env, envScript+`={"conversations":[{"when":"Find the module"`) {
		t.Errorf("ScriptEnv = %s, %v", env, err)
	}
}
