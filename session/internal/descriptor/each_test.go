package descriptor_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/qoryai/forager/session/internal/descriptor"
)

// eachDoc is a descriptor with a rule with each for the text blocks of a message, a
// rule after it for any message, and a parent member.
const eachDoc = `version: 1
runtime: amp
runtime_version: "1"
sources: {output: {format: jsonl}}
parent:
  source: output
  match: {agent_id: {present: true}}
  agent_id: agent_id
  tool_use_id: parent_tool_use_id
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
// matches only when an element matches: a line with no text block, a line whose path is
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

// TestLinkReadsTheParentMember pins Link: for a record of the member's source that
// matches, Link returns the subagent's id and the call's id; for a record of another
// source, one that does not match, a call id that is null, empty or no string, and a
// descriptor without the member, it returns false.
func TestLinkReadsTheParentMember(t *testing.T) {
	d := parse(t, eachDoc)
	agent, call, ok := d.Link(output(t, `{"type":"user","agent_id":"a1","parent_tool_use_id":"toolu_1"}`))
	if !ok || agent != "a1" || call != "toolu_1" {
		t.Errorf("Link = %q %q %v", agent, call, ok)
	}
	for _, js := range []string{
		`{"type":"user","parent_tool_use_id":"toolu_1"}`,
		`{"type":"user","agent_id":"a1","parent_tool_use_id":null}`,
		`{"type":"user","agent_id":"a1","parent_tool_use_id":""}`,
		`{"type":"user","agent_id":"a1","parent_tool_use_id":7}`,
		`{"type":"user","agent_id":"a1"}`,
	} {
		if _, _, ok := d.Link(output(t, js)); ok {
			t.Errorf("%s linked", js)
		}
	}
	hooks := descriptor.Record{Source: descriptor.SourceHooks, Record: map[string]any{"agent_id": "a1", "parent_tool_use_id": "toolu_1"}}
	if _, _, ok := d.Link(hooks); ok {
		t.Error("a record of another source linked")
	}
	none := parse(t, strings.Replace(eachDoc, "parent:\n  source: output\n  match: {agent_id: {present: true}}\n  agent_id: agent_id\n  tool_use_id: parent_tool_use_id\n", "", 1))
	if none.Parent != nil {
		t.Fatal("the member was not removed")
	}
	if _, _, ok := none.Link(output(t, `{"agent_id":"a1","parent_tool_use_id":"toolu_1"}`)); ok {
		t.Error("a descriptor without parent linked")
	}
}

// TestParentAndEachAreChecked pins the schema: parent has its four members and no
// other, a path is dotted names, and each is a path.
func TestParentAndEachAreChecked(t *testing.T) {
	for name, doc := range map[string]string{
		"parent without tool_use_id": strings.Replace(eachDoc, "  tool_use_id: parent_tool_use_id\n", "", 1),
		"parent without match":       strings.Replace(eachDoc, "  match: {agent_id: {present: true}}\n", "", 1),
		"parent with another member": strings.Replace(eachDoc, "  agent_id: agent_id\n", "  agent_id: agent_id\n  depth: 2\n", 1),
		"parent of another source":   strings.Replace(eachDoc, "parent:\n  source: output", "parent:\n  source: setup", 1),
		"a parent path with a space": strings.Replace(eachDoc, "  agent_id: agent_id\n", "  agent_id: agent id\n", 1),
		"each that is no path":       strings.Replace(eachDoc, "each: message.content", "each: message.content[0]", 1),
	} {
		if _, err := descriptor.Parse("amp.yaml", []byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// blocksDoc has a rule with each for text blocks, a rule without each for any message
// of the main agent, and a rule with each for thinking blocks.
const blocksDoc = `version: 1
runtime: amp
runtime_version: "1"
sources: {output: {format: jsonl}}
rules:
  - source: output
    match: {type: assistant, agent_id: {present: true}, each.type: text}
    each: message.content
    type: dev.qory.runtime.message
    data: {agent_id: agent_id, text: each.text, kind: each.type}
  - source: output
    match: {type: assistant, main: true}
    type: dev.qory.runtime.notification
    data: {kind: type}
  - source: output
    match: {type: assistant, agent_id: {present: true}, each.type: thinking}
    each: message.content
    type: dev.qory.runtime.message
    data: {agent_id: agent_id, text: each.thinking, kind: each.type}
`

// TestEachChoosesARulePerElement pins the choice of a rule per element: a thinking
// block, then a text block, a redacted thinking block and a second thinking block
// produce one event each for the thinking and text blocks, in the array's order, each
// of the first rule with the same each that the element matches; a redacted thinking
// block matches no rule and produces nothing.
func TestEachChoosesARulePerElement(t *testing.T) {
	d := parse(t, blocksDoc)
	got := d.Map(output(t, `{"type":"assistant","agent_id":"a1","message":{"role":"assistant","content":[
		{"type":"thinking","thinking":"first I look","signature":"sig"},
		{"type":"text","text":"one"},
		{"type":"redacted_thinking","data":"opaque"},
		{"type":"thinking","thinking":"then I answer","signature":"sig"}]}}`))
	want := []descriptor.Event{
		{Type: "dev.qory.runtime.message", Data: map[string]any{"agent_id": "a1", "text": "first I look", "kind": "thinking"}},
		{Type: "dev.qory.runtime.message", Data: map[string]any{"agent_id": "a1", "text": "one", "kind": "text"}},
		{Type: "dev.qory.runtime.message", Data: map[string]any{"agent_id": "a1", "text": "then I answer", "kind": "thinking"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Map =\n %+v\nwant\n %+v", got, want)
	}
	if got := d.Map(output(t, `{"type":"assistant","agent_id":"a1","message":{"content":[{"type":"redacted_thinking","data":"opaque"}]}}`)); got != nil {
		t.Errorf("a redacted thinking block produced %+v", got)
	}
}

// TestTheFirstRuleThatMatchesTheRecordDecides pins that the rules still apply per
// record in order: a line whose only block is a thinking block, which the first rule
// with each does not match, goes to the rule without each before the thinking rule
// when that one matches, and to the thinking rule when it does not.
func TestTheFirstRuleThatMatchesTheRecordDecides(t *testing.T) {
	d := parse(t, blocksDoc)
	got := d.Map(output(t, `{"type":"assistant","agent_id":"a1","main":true,"message":{"content":[{"type":"thinking","thinking":"hm"}]}}`))
	if len(got) != 1 || got[0].Type != "dev.qory.runtime.notification" {
		t.Errorf("Map = %+v; want the rule without each", got)
	}
	got = d.Map(output(t, `{"type":"assistant","agent_id":"a1","message":{"content":[{"type":"thinking","thinking":"hm"}]}}`))
	if len(got) != 1 || got[0].Data["kind"] != "thinking" || got[0].Data["text"] != "hm" {
		t.Errorf("Map = %+v; want the thinking rule", got)
	}
}

// pickDoc has two rules with each for the text blocks of the output, and a rule of the
// hooks with the same each for thinking blocks.
const pickDoc = `version: 1
runtime: amp
runtime_version: "1"
sources: {output: {format: jsonl}}
rules:
  - source: output
    match: {each.type: text}
    each: message.content
    type: dev.qory.runtime.message
    data: {text: each.text, kind: each.type}
  - source: output
    match: {each.type: text}
    each: message.content
    type: dev.qory.runtime.notification
    data: {message: each.text}
  - source: hooks
    match: {each.type: thinking}
    each: message.content
    type: dev.qory.runtime.notification
    data: {message: each.thinking}
`

// TestAnElementTakesTheFirstRuleOfItsSource pins the choice per element: a text block
// that two rules match produces one event, of the first of them, and a thinking block
// that only a rule of another source matches produces nothing.
func TestAnElementTakesTheFirstRuleOfItsSource(t *testing.T) {
	d := parse(t, pickDoc)
	got := d.Map(output(t, `{"message":{"content":[{"type":"thinking","thinking":"hm"},{"type":"text","text":"one"}]}}`))
	want := []descriptor.Event{{Type: "dev.qory.runtime.message", Data: map[string]any{"text": "one", "kind": "text"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Map =\n %+v\nwant\n %+v", got, want)
	}
}
