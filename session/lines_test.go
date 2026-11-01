package session_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
)

// stdoutLines is the session's standard output as its dev.qory.run.log events with
// stream stdout have it, joined in order and split at each line break.
func stdoutLines(t *testing.T, evs []map[string]any) []string {
	t.Helper()
	var b strings.Builder
	for _, l := range ofType(evs, event.RunLog) {
		if data(l)["stream"] != "stdout" {
			continue
		}
		bytes, err := base64.StdEncoding.DecodeString(data(l)["bytes"].(string))
		if err != nil {
			t.Fatal(err)
		}
		b.Write(bytes)
	}
	return strings.Split(b.String(), "\n")
}

// TestAnOutputEventHasItsLineOnStandardOutput pins line end to end on pipes: each
// event the descriptor maps from a line of standard output has that line's number,
// counting the lines that are no JSON object and the empty ones; the same line of the
// run.log chunks is the record's line; a hook's event has no line. It also pins the
// rule order on a mixed user line: a main conversation's user line with a text block
// and a tool result gives the tool result alone.
func TestAnOutputEventHasItsLineOnStandardOutput(t *testing.T) {
	// The fake runtime prints its init line first, then these lines, then its result.
	lines := strings.Join([]string{
		`a line that is no JSON object`,
		`{"type":"assistant","session_id":"fake","message":{"id":"msg_1","role":"assistant","content":[{"type":"text","text":"Hello,\nDana"},{"type":"tool_use","id":"toolu_D","name":"Bash","input":{"command":"ls"}}]}}`,
		``,
		`{"type":"system","subtype":"permission_denied","tool_name":"Bash","tool_use_id":"toolu_D","message":"Quoted text in this command can't be checked before it runs","session_id":"fake"}`,
		`{"type":"user","session_id":"fake","message":{"role":"user","content":[{"type":"text","text":"Base directory for this skill"},{"type":"tool_result","tool_use_id":"toolu_D","content":"Quoted text in this command can't be checked before it runs","is_error":true}]}}`,
	}, "\n")
	res, err := runWithSettingsEnv(t, spec(t, "FAKE_LINES="+lines))
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	raw := stdoutLines(t, evs)
	want := map[string]struct {
		line int
		in   string
	}{
		"dev.qory.runtime.text":        {3, `"id":"msg_1"`},
		"dev.qory.runtime.tool_denied": {5, `"permission_denied"`},
		"dev.qory.runtime.tool_result": {6, `"tool_result"`},
		"dev.qory.runtime.result":      {7, `"type":"result"`},
	}
	for typ, w := range want {
		got := ofType(evs, typ)
		if len(got) != 1 {
			t.Errorf("%d %s, want 1", len(got), typ)
			continue
		}
		line, _ := data(got[0])["line"].(float64)
		if int(line) != w.line {
			t.Errorf("%s: line %v, want %d", typ, data(got[0])["line"], w.line)
			continue
		}
		if int(line) > len(raw) || !strings.Contains(raw[int(line)-1], w.in) {
			t.Errorf("%s: line %d of the run.log chunks is not the record's: %q", typ, w.line, raw)
		}
	}
	if text := ofType(evs, "dev.qory.runtime.text"); len(text) == 1 && data(text[0])["text"] != "Hello,\nDana" {
		t.Errorf("text %v", data(text[0]))
	}
	for _, e := range ofType(evs, "dev.qory.runtime.ended") {
		if _, ok := data(e)["line"]; ok {
			t.Errorf("a hook's event has line: %v", data(e))
		}
	}
}

// TestAHiddenHarnessKeepsTheLinesOfJSONLines pins how the masking of a hidden harness
// meets line: the result record, a JSON line whose string contains a skill's lines
// escaped, keeps its line breaks, so with the harness shown line is its line in the
// run.log chunks. Hidden, a skill printed as plain text before it, six lines, is one
// replacement there, so the record is line 7 by line and line 2 in the chunks: the
// exception the contract states.
func TestAHiddenHarnessKeepsTheLinesOfJSONLines(t *testing.T) {
	for _, hidden := range []bool{false, true} {
		res, _, _ := harnessRun(t, hidden)
		evs := events(t, res)
		r := ofType(evs, "dev.qory.runtime.result")
		if len(r) != 1 {
			t.Fatalf("hidden %v: runtime.result %v", hidden, r)
		}
		line, _ := data(r[0])["line"].(float64)
		raw := stdoutLines(t, evs)
		at := map[bool]int{false: 7, true: 2}[hidden]
		if line != 7 || !strings.HasPrefix(raw[at-1], `{"type":"result"`) {
			t.Errorf("hidden %v: line %v, want 7; line %d of the chunks %q", hidden, line, at, raw[at-1])
		}
	}
}
