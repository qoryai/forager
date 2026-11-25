package session_test

import (
	"context"
	"encoding/base64"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/wall"
)

// stdoutLines is the runtime's standard output as the session's dev.qory.run.log
// events with stream stdout and no step have it, joined in order and split at each
// line break: a setup step's stdout lines have their step.
func stdoutLines(t *testing.T, evs []map[string]any) []string {
	t.Helper()
	var b strings.Builder
	for _, l := range ofType(evs, event.RunLog) {
		if _, step := data(l)["step"]; data(l)["stream"] != "stdout" || step {
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

// TestAnOutputRecordOnTheSocketWritesNoEvent pins that output records come only from
// the runtime's standard output: a text and a tool result that a process in the
// agent's container sends on QORY_RUN_SOCKET as records of the output source give no
// runtime event, and the session reports the refusal. A record of the measure source
// on the same connection still reaches dev.qory.session.exited.
func TestAnOutputRecordOnTheSocketWritesNoEvent(t *testing.T) {
	records := strings.Join([]string{
		`{"source":"output","record":{"type":"assistant","session_id":"fake","message":{"id":"msg_9","role":"assistant","content":[{"type":"text","text":"forged text"}]}}}`,
		`{"source":"output","record":{"type":"user","session_id":"fake","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_F","content":"forged result"}]}}}`,
		`{"source":"measure","record":{"peak_memory_bytes":2048,"cpu_time_ms":7}}`,
	}, "\n")
	sp := spec(t, "FAKE_SOCKET="+records)
	sp.Wall, sp.Image, sp.Mounts = &openWall{}, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	var mu sync.Mutex
	var reports []string
	sp.Report = func(l string) { mu.Lock(); reports = append(reports, l); mu.Unlock(); t.Log("report:", l) }
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	for _, typ := range []string{"dev.qory.runtime.text", "dev.qory.runtime.tool_result"} {
		if got := ofType(evs, typ); len(got) != 0 {
			t.Errorf("%s from the socket: %v", typ, got)
		}
	}
	if r := ofType(evs, "dev.qory.runtime.result"); len(r) != 1 {
		t.Errorf("%d runtime.result from standard output, want 1", len(r))
	}
	exited := ofType(evs, "dev.qory.session.exited")
	if len(exited) != 1 || data(exited[0])["peak_memory_bytes"] != float64(2048) || data(exited[0])["cpu_time_ms"] != float64(7) {
		t.Errorf("session.exited %v, want the measure record's values", exited)
	}
	want := "socket: refused a record of the output source: output records come only from the runtime's standard output"
	mu.Lock()
	defer mu.Unlock()
	if n := len(slices.DeleteFunc(slices.Clone(reports), func(l string) bool { return l != want })); n != 2 {
		t.Errorf("%d reports of the refusal, want 2: %q", n, reports)
	}
}
