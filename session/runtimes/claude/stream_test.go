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
// parent_tool_use_id) and the headless page's section on subagent messages. None of them is a recording of
// Claude Code: the recorded fixtures come from an image of 2.1.292 or later.
const (
	sid = `"session_id":"0f3a9c2e-7b1d-4c6e-9a2f-5d8e1b4c7a90"`
	out = `{"source":"output","record":{` + sid + `,`
)

// messageRecords is a subagent's assistant line with a thinking block before a text
// block and a tool call, a main conversation's line, and a subagent's tool result.
var messageRecords = strings.Join([]string{
	out + `"type":"system","subtype":"init","claude_code_version":"2.1.292"}}`,
	out + `"type":"assistant","agent_id":"a1","parent_tool_use_id":"toolu_A","message":{"id":"msg_1","role":"assistant","content":[{"type":"thinking","thinking":"go.mod first","signature":"c2ln"},{"type":"text","text":"I read go.mod."},{"type":"tool_use","id":"toolu_C","name":"Read","input":{"file_path":"/home/dev/app/go.mod"}}]}}}`,
	out + `"type":"user","agent_id":"a1","parent_tool_use_id":"toolu_A","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_C","content":"module example.com/app"}]}}}`,
	out + `"type":"assistant","parent_tool_use_id":null,"message":{"id":"msg_2","role":"assistant","content":[{"type":"text","text":"Done."}]}}}`,
}, "\n")

const messageEvents = `{"type":"dev.qory.runtime.message","data":{` + sid + `,"agent_id":"a1","role":"assistant","text":"I read go.mod.","kind":"text"}}
`

// TestSubagentStreamLinesFromTheReference pins the message rules on lines of the
// reference's shape: a text block after a thinking block is mapped, and neither a tool
// result nor the main conversation's text is a message.
func TestSubagentStreamLinesFromTheReference(t *testing.T) {
	rt, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	runtimetest.Replays(t, rt, fstest.MapFS{
		"cases/subagent-messages/records.jsonl":         {Data: []byte(messageRecords)},
		"cases/subagent-messages/expected/events.jsonl": {Data: []byte(messageEvents)},
	}, "cases")
}
