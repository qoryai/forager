package session_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestAToolsSummaryIsSetFromTheTableCutAndMasked pins summary end to end: the fake
// runtime calls the Claude descriptor's hooks, and the session writes tool_started,
// tool_finished and tool_failed with summary set to the input member that tools.summary
// selects for the tool, masked when that member contains a run secret and cut at 1 KiB
// (1024 bytes) of UTF-8 at a character boundary. A tool outside the table, and a tool in
// the table whose input lacks the member, have no summary.
func TestAToolsSummaryIsSetFromTheTableCutAndMasked(t *testing.T) {
	const secret = "fake-run-secret-0123456789"
	long := strings.Repeat("€", 400) // 1200 bytes; the cut keeps 341 characters, 1023 bytes
	line := func(m map[string]any) string { b, _ := json.Marshal(m); return string(b) }
	hook := func(event, tool, id string, input map[string]any) map[string]any {
		return map[string]any{"session_id": "fake", "hook_event_name": event, "tool_name": tool, "tool_use_id": id, "tool_input": input}
	}
	failed := hook("PostToolUseFailure", "Bash", "t3", map[string]any{"command": long})
	failed["error"] = "exit status 1"
	hooks := []string{
		line(hook("PreToolUse", "Bash", "t1", map[string]any{"command": "echo " + secret + " | wc -c"})),
		line(hook("PostToolUse", "Read", "t2", map[string]any{"file_path": "/workspace/README.md", "limit": 20})),
		line(failed),
		line(hook("PreToolUse", "TodoWrite", "t4", map[string]any{"todos": []any{}})),
		line(hook("PreToolUse", "Grep", "t5", map[string]any{"path": "/workspace"})),
	}
	sp := spec(t, "FAKE_HOOKS="+strings.Join(hooks, "\n"))
	sp.Masker = maskerOf(t, secret)
	res, err := runWithSettingsEnv(t, sp)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	got := map[string]map[string]any{}
	for _, typ := range []string{"dev.qory.runtime.tool_started", "dev.qory.runtime.tool_finished", "dev.qory.runtime.tool_failed"} {
		for _, e := range ofType(evs, typ) {
			d := data(e)
			got[d["tool_use_id"].(string)] = d
		}
	}
	cut := strings.Repeat("€", 341)
	for id, want := range map[string]any{
		"t1": "echo *** | wc -c",
		"t2": "/workspace/README.md",
		"t3": cut,
		"t4": nil,
		"t5": nil,
	} {
		d, ok := got[id]
		if !ok {
			t.Errorf("%s: no tool event; got %v", id, got)
			continue
		}
		if s, ok := d["summary"]; s != want || (want == nil && ok) {
			t.Errorf("%s: summary %q, want %q", id, s, want)
		}
	}
	if s, _ := got["t3"]["summary"].(string); len(s) != 1023 || !utf8.ValidString(s) {
		t.Errorf("t3: summary of %d bytes, want 1023 bytes of valid UTF-8", len(s))
	}
	b, err := os.ReadFile(filepath.Join(res.Dir, "session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) {
		t.Error("session.jsonl contains the run secret")
	}
}
