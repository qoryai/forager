package descriptor_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/qoryai/forager/session/internal/descriptor"
)

// eachDoc is a descriptor with a rule with each for the text blocks of a message and a
// rule after it for any message.
const eachDoc = `version: 1
runtime: amp
runtime_version: "1"
sources: {output: {format: jsonl}}
rules:
  - source: output
    match: {type: assistant, agent_id: {present: true}, each.type: text}
    each: message.content
    type: dev.qory.runtime.message
    data: {session_id: session_id, agent_id: agent_id, role: message.role, text: each.text, kind: each.type}
  - source: output
    match: {type: assistant}
    type: dev.qory.runtime.notification
    data: {session_id: session_id, kind: type}
`

func parse(t *testing.T, doc string) *descriptor.Descriptor {
	t.Helper()
	d, err := descriptor.Parse("amp.yaml", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func output(t *testing.T, js string) descriptor.Record {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		t.Fatal(err)
	}
	return descriptor.Record{Source: descriptor.SourceOutput, Record: m}
}

// TestEachProducesAnEventPerElementThatMatches pins each: a line with a thinking block
// before a text block, a tool call and a second text block produces one event per
// text block, in the array's order, with the record's fields and the element's; a path
// with each. reads the element and any other path the record.
func TestEachProducesAnEventPerElementThatMatches(t *testing.T) {
	d := parse(t, eachDoc)
	got := d.Map(output(t, `{"type":"assistant","session_id":"s1","agent_id":"a1","parent_tool_use_id":"toolu_1",
		"message":{"role":"assistant","content":[
			{"type":"thinking","thinking":"first I look","signature":"sig"},
			{"type":"text","text":"one"},
			null,
			{"type":"tool_use","id":"toolu_2","name":"Read","input":{}},
			{"type":"text","text":"two"}]}}`))
	want := []descriptor.Event{
		{Type: "dev.qory.runtime.message", Data: map[string]any{"session_id": "s1", "agent_id": "a1", "role": "assistant", "text": "one", "kind": "text"}},
		{Type: "dev.qory.runtime.message", Data: map[string]any{"session_id": "s1", "agent_id": "a1", "role": "assistant", "text": "two", "kind": "text"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Map =\n %+v\nwant\n %+v", got, want)
	}
}

// TestEachThatMatchesNoElementLeavesTheRecordToTheNextRule pins that a rule with each
// holds only when an element matches: a line with no text block, a line whose path is
// no array and a line without the path go on to the next rule.
func TestEachThatMatchesNoElementLeavesTheRecordToTheNextRule(t *testing.T) {
	d := parse(t, eachDoc)
	for _, js := range []string{
		`{"type":"assistant","session_id":"s1","agent_id":"a1","message":{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"Read","input":{}}]}}`,
		`{"type":"assistant","session_id":"s1","agent_id":"a1","message":{"role":"assistant","content":"a string"}}`,
		`{"type":"assistant","session_id":"s1","agent_id":"a1","message":{"role":"assistant"}}`,
		`{"type":"assistant","session_id":"s1","message":{"role":"assistant","content":[{"type":"text","text":"main"}]}}`,
	} {
		got := d.Map(output(t, js))
		if len(got) != 1 || got[0].Type != "dev.qory.runtime.notification" {
			t.Errorf("%s: Map = %+v; want the second rule's event", js, got)
		}
	}
}

// TestEachIsChecked pins the schema: each is a path.
func TestEachIsChecked(t *testing.T) {
	doc := strings.Replace(eachDoc, "each: message.content", "each: message.content[0]", 1)
	if _, err := descriptor.Parse("amp.yaml", []byte(doc)); err == nil {
		t.Error("each that is no path: accepted")
	}
}
