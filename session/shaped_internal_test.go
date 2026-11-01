package session

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/claude"
)

// TestTextIsCutAt64KiBAtACharacterBoundary pins the cut of text and of a string
// content: up to 65536 bytes they stay as they are, with no truncated; past it they
// are cut to the longest prefix of whole characters within 65536 bytes, with
// truncated: true, also when a character of two or four bytes crosses the boundary.
func TestTextIsCutAt64KiBAtACharacterBoundary(t *testing.T) {
	cases := []struct {
		name, in string
		want     int
	}{
		{"65536 bytes", strings.Repeat("a", maxCut), maxCut},
		{"65536 bytes of two-byte characters", strings.Repeat("é", maxCut/2), maxCut},
		{"65537 bytes", strings.Repeat("a", maxCut+1), maxCut},
		{"a two-byte character across the boundary", "a" + strings.Repeat("é", maxCut/2), maxCut - 1},
		{"a four-byte character across the boundary", "ab" + strings.Repeat("😀", maxCut/4), maxCut - 2},
	}
	for _, c := range cases {
		for _, ev := range []struct{ typ, member string }{{typeText, "text"}, {typeToolResult, "content"}} {
			got := shapedRecord(ev.typ, map[string]any{"session_id": "s", ev.member: c.in, "kind": "text", "tool_use_id": "t"}, nil)
			s := got[ev.member].(string)
			if len(s) != c.want || !utf8.ValidString(s) || !strings.HasPrefix(c.in, s) {
				t.Errorf("%s, %s: %d bytes, valid %v; want a prefix of %d bytes", c.name, ev.typ, len(s), utf8.ValidString(s), c.want)
			}
			if cut := len(c.in) > maxCut; (got["truncated"] == true) != cut || !cut && got["truncated"] != nil {
				t.Errorf("%s, %s: truncated %v", c.name, ev.typ, got["truncated"])
			}
		}
	}
}

// TestAnArrayContentStaysWithin64KiBOfJSON pins the cut of an array content: an array
// whose JSON encoding fits stays as it is; otherwise the blocks that fit stay whole,
// the first that does not fit has its text cut so the encoding fits, characters that
// JSON escapes counted as escaped, and the blocks after it are left out; a block with
// no text that does not fit is left out with the ones after it.
func TestAnArrayContentStaysWithin64KiBOfJSON(t *testing.T) {
	block := func(text string) map[string]any { return map[string]any{"type": "text", "text": text} }
	small := []any{block("README.md"), block("go.mod")}
	if got := shapedRecord(typeToolResult, map[string]any{"content": small}, nil); got["truncated"] != nil || encodedLen(got["content"]) != encodedLen(small) {
		t.Errorf("an array that fits: %v", got)
	}
	cases := []struct {
		name  string
		in    []any
		kept  int
		whole int
	}{
		{"two text blocks", []any{block(strings.Repeat("a", 40000)), block(strings.Repeat("b", 40000)), block("c")}, 2, 1},
		{"escaped characters", []any{block(strings.Repeat("<é\n", 20000))}, 1, 0},
		{"a string element", []any{strings.Repeat("x", 70000)}, 1, 0},
		{"an image that does not fit", []any{block("see the picture"), map[string]any{"type": "image", "source": map[string]any{"type": "base64", "data": strings.Repeat("A", 90000)}}, block("after")}, 1, 1},
	}
	for _, c := range cases {
		got := shapedRecord(typeToolResult, map[string]any{"content": c.in}, nil)
		out, _ := got["content"].([]any)
		n := encodedLen(out)
		if got["truncated"] != true || len(out) != c.kept || n > maxCut {
			t.Errorf("%s: truncated %v, %d blocks of %d bytes; want %d blocks within %d", c.name, got["truncated"], len(out), n, c.kept, maxCut)
			continue
		}
		for i := 0; i < c.whole; i++ {
			if encodedLen(out[i]) != encodedLen(c.in[i]) {
				t.Errorf("%s: block %d was cut", c.name, i)
			}
		}
		if c.kept > c.whole {
			last := out[len(out)-1]
			text, _ := last.(string)
			if m, ok := last.(map[string]any); ok {
				text, _ = m["text"].(string)
			}
			// The cut keeps the longest prefix that fits: one more character would not.
			if !utf8.ValidString(text) || n < maxCut-6 {
				t.Errorf("%s: the cut block's text is valid %v, the array %d bytes; want within 6 bytes of %d", c.name, utf8.ValidString(text), n, maxCut)
			}
		}
	}
}

// TestASummaryIsOneInputMemberCopiedAndCutAt1KiB pins summary: the member of input that
// the Claude Code descriptor's tools.summary gives for the tool, on tool_started,
// tool_finished and tool_failed alone, cut at 1024 bytes at a character boundary with
// no flag; none for a tool the table does not list or a member that is no string; and
// a summary or a truncated that the runtime's Map returned is left out.
func TestASummaryIsOneInputMemberCopiedAndCutAt1KiB(t *testing.T) {
	rt, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	sum := rt.(runtimes.Summaries)
	long := strings.Repeat("€", 400)
	cases := []struct {
		typ, tool string
		input     map[string]any
		want      any
	}{
		{typeToolStarted, "Bash", map[string]any{"command": "make test", "description": "Run the tests"}, "make test"},
		{typeToolFinished, "Skill", map[string]any{"skill": "example:greet"}, "example:greet"},
		{typeToolFailed, "Read", map[string]any{"file_path": "/home/dev/app/go.mod"}, "/home/dev/app/go.mod"},
		{typeToolStarted, "Agent", map[string]any{"description": "Find the module", "prompt": "Read go.mod"}, "Find the module"},
		{typeToolStarted, "Task", map[string]any{"description": "Find the module"}, "Find the module"},
		{typeToolStarted, "Bash", map[string]any{"command": long}, long[:1023]},
		{typeToolStarted, "TodoWrite", map[string]any{"todos": []any{}}, nil},
		{typeToolStarted, "Bash", map[string]any{"command": []any{"ls"}}, nil},
		{"dev.qory.runtime.tool_denied", "Bash", map[string]any{"command": "ls"}, nil},
	}
	for _, c := range cases {
		got := shapedRecord(c.typ, map[string]any{"tool": c.tool, "input": c.input, "summary": "from Map", "truncated": true}, sum)
		if got["summary"] != c.want || got["truncated"] != nil {
			t.Errorf("%s %s: summary %q, truncated %v; want %v", c.typ, c.tool, got["summary"], got["truncated"], c.want)
		}
	}
	if got := shapedRecord(typeToolStarted, map[string]any{"tool": "Bash", "input": map[string]any{"command": "ls"}}, nil); got["summary"] != nil {
		t.Errorf("a runtime without summaries: %v", got)
	}
}

// TestTheCutComesAfterTheMask pins the order: a secret that crosses the 64 KiB
// boundary is replaced whole before the cut, so no part of it reaches the event, and
// the masked text, shorter than the boundary, is not cut.
func TestTheCutComesAfterTheMask(t *testing.T) {
	secret := "s3cr3t-fixture-value-0123456789"
	m := mask.New()
	if err := m.AddSecret([]byte(secret)); err != nil {
		t.Fatal(err)
	}
	text := strings.Repeat("a", maxCut-10) + secret
	masked := maskedRecord(texts{secrets: m}, map[string]any{"text": text, "kind": "text"})
	got := shapedRecord(typeText, masked, nil)
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), secret[:10]) || got["truncated"] != nil || got["text"] != strings.Repeat("a", maxCut-10)+mask.Secret {
		t.Errorf("text %q…, truncated %v", got["text"].(string)[maxCut-20:], got["truncated"])
	}
}
