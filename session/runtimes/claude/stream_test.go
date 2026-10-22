package claude_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/qoryai/forager/session/runtimes/claude"
	"github.com/qoryai/forager/session/runtimes/runtimetest"
)

// The cases of TestSubagentStreamLinesFromTheReference are written by hand from the
// Agent SDK TypeScript reference (SDKAssistantMessage, SDKUserMessage: agent_id and
// parent_tool_use_id) and the headless page's section on subagent messages, in the
// shape of the hooks fixtures beside the descriptor. None of them is a recording of
// Claude Code: the recorded fixtures come from an image of 2.1.292 or later.
const (
	sid  = `"session_id":"0f3a9c2e-7b1d-4c6e-9a2f-5d8e1b4c7a90"`
	hook = `{"source":"hooks","record":{` + sid + `,"cwd":"/home/dev/app","permission_mode":"default",`
	out  = `{"source":"output","record":{` + sid + `,`
)

// nestedRecords is a main agent that starts subagent a1 with the Agent call toolu_A,
// and a1 that starts a2 with toolu_B. a1's start comes before its first message, so
// the start and the hook event after it are written at that message, before the
// message's event; a2's first message comes before its start.
var nestedRecords = strings.Join([]string{
	out + `"type":"system","subtype":"init","claude_code_version":"2.1.292"}}`,
	hook + `"hook_event_name":"PreToolUse","tool_name":"Agent","tool_input":{"prompt":"Look for TODO markers","subagent_type":"Explore"},"tool_use_id":"toolu_A"}}`,
	hook + `"hook_event_name":"SubagentStart","agent_id":"a1","agent_type":"Explore"}}`,
	hook + `"hook_event_name":"PreToolUse","tool_name":"Agent","tool_input":{"prompt":"Read go.mod","subagent_type":"general-purpose"},"tool_use_id":"toolu_B","agent_id":"a1","agent_type":"Explore"}}`,
	out + `"type":"user","agent_id":"a1","parent_tool_use_id":"toolu_A","message":{"role":"user","content":[{"type":"text","text":"Look for TODO markers"}]}}}`,
	out + `"type":"user","agent_id":"a2","parent_tool_use_id":"toolu_B","message":{"role":"user","content":[{"type":"text","text":"Read go.mod"}]}}}`,
	hook + `"hook_event_name":"SubagentStart","agent_id":"a2","agent_type":"general-purpose"}}`,
}, "\n")

const nestedEvents = `{"type":"dev.qory.runtime.tool_started","data":{` + sid + `,"tool":"Agent","tool_use_id":"toolu_A","input":{"prompt":"Look for TODO markers","subagent_type":"Explore"}}}
{"type":"dev.qory.runtime.subagent_started","data":{` + sid + `,"agent_id":"a1","agent_type":"Explore"}}
{"type":"dev.qory.runtime.tool_started","data":{` + sid + `,"tool":"Agent","tool_use_id":"toolu_B","input":{"prompt":"Read go.mod","subagent_type":"general-purpose"},"agent_id":"a1","agent_type":"Explore"}}
{"type":"dev.qory.runtime.message","data":{` + sid + `,"agent_id":"a1","role":"user","text":"Look for TODO markers","kind":"text"}}
{"type":"dev.qory.runtime.message","data":{` + sid + `,"agent_id":"a2","role":"user","text":"Read go.mod","kind":"text"}}
{"type":"dev.qory.runtime.subagent_started","data":{` + sid + `,"agent_id":"a2","agent_type":"general-purpose","parent_agent_id":"a1"}}
`

// messageRecords is a subagent's assistant line with a thinking block before a text
// block, a redacted thinking block and a tool call, a subagent's tool result, and a
// main conversation's line.
var messageRecords = strings.Join([]string{
	out + `"type":"system","subtype":"init","claude_code_version":"2.1.292"}}`,
	out + `"type":"assistant","agent_id":"a1","parent_tool_use_id":"toolu_A","message":{"id":"msg_1","role":"assistant","content":[{"type":"thinking","thinking":"go.mod first","signature":"c2ln"},{"type":"text","text":"I read go.mod."},{"type":"redacted_thinking","data":"b3BhcXVl"},{"type":"tool_use","id":"toolu_C","name":"Read","input":{"file_path":"/home/dev/app/go.mod"}}]}}}`,
	out + `"type":"user","agent_id":"a1","parent_tool_use_id":"toolu_A","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_C","content":"module example.com/app"}]}}}`,
	out + `"type":"assistant","parent_tool_use_id":null,"message":{"id":"msg_2","role":"assistant","content":[{"type":"text","text":"Done."}]}}}`,
}, "\n")

const messageEvents = `{"type":"dev.qory.runtime.message","data":{` + sid + `,"agent_id":"a1","role":"assistant","text":"go.mod first","kind":"thinking"}}
{"type":"dev.qory.runtime.message","data":{` + sid + `,"agent_id":"a1","role":"assistant","text":"I read go.mod.","kind":"text"}}
`

// TestSubagentStreamLinesFromTheReference pins the parent member and the message rules
// on lines of the reference's shape: a nested subagent's start has its parent in both
// orders of start and link, a thinking block then a text block are two messages in that
// order, and neither a redacted thinking block, a tool result nor the main
// conversation's text is a message.
func TestSubagentStreamLinesFromTheReference(t *testing.T) {
	rt, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	runtimetest.Replays(t, rt, fstest.MapFS{
		"cases/subagent-nested/records.jsonl":           {Data: []byte(nestedRecords)},
		"cases/subagent-nested/expected/events.jsonl":   {Data: []byte(nestedEvents)},
		"cases/subagent-messages/records.jsonl":         {Data: []byte(messageRecords)},
		"cases/subagent-messages/expected/events.jsonl": {Data: []byte(messageEvents)},
	}, "cases")
}
