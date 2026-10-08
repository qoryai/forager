package claude_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qoryai/runner/contracts"
	"github.com/qoryai/runner/session/runtimes"
	"github.com/qoryai/runner/session/runtimes/claude"
	"github.com/qoryai/runner/session/runtimes/runtimetest"
)

func TestClaudeCodeIsARuntime(t *testing.T) {
	rt, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	if rt.Name() != claude.Name || rt.Version() == "" || !rt.ReadsOutput() {
		t.Errorf("name %q, version %q, reads output %v", rt.Name(), rt.Version(), rt.ReadsOutput())
	}
	runtimetest.Conforms(t, rt)
	runtimetest.Replays(t, rt, contracts.FS, "runtimes/claude/fixtures")
}

// TestSettingsKeepsWhatTheLaunchPassedAndAddsTheForwarder pins the installer: the
// settings the launch names are read, a file or a document, and not written; the run's
// copy holds them and a hook group per event; and the launch names the copy.
func TestSettingsKeepsWhatTheLaunchPassedAndAddsTheForwarder(t *testing.T) {
	passed := filepath.Join(t.TempDir(), "settings.json")
	before := `{"permissions":{"allow":["Bash"]},"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo existing"}]}]}}`
	if err := os.WriteFile(passed, []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"a file":         {"-p", "hi", "--settings", passed},
		"a file with =":  {"--settings=" + passed, "-p", "hi"},
		"a document":     {"--settings", before},
		"none":           {"-p", "hi"},
		"nothing at all": nil,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			got, err := claude.Settings([]string{"Stop", "SessionEnd"}, runtimes.Attach{
				Launch: runtimes.Launch{Command: "claude", Args: args}, RunDir: dir, Forwarder: []string{"/opt/q", "it's"},
			})
			if err != nil {
				t.Fatal(err)
			}
			written := filepath.Join(dir, "settings.json")
			at := -1
			for i, a := range got.Args {
				if a == "--settings" {
					at = i + 1
				}
			}
			if got.Command != "claude" || at < 0 || at >= len(got.Args) || got.Args[at] != written {
				t.Fatalf("launch %+v does not name %s", got, written)
			}
			b, _ := os.ReadFile(written)
			var doc struct {
				Permissions map[string]any `json:"permissions"`
				Hooks       map[string][]struct {
					Hooks []struct {
						Command string `json:"command"`
					} `json:"hooks"`
				} `json:"hooks"`
			}
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			for _, ev := range []string{"Stop", "SessionEnd"} {
				groups := doc.Hooks[ev]
				if len(groups) == 0 || groups[len(groups)-1].Hooks[0].Command != `/opt/q 'it'\''s'` {
					t.Errorf("%s: %+v", ev, groups)
				}
			}
			if name != "none" && name != "nothing at all" {
				if doc.Permissions == nil || len(doc.Hooks["Stop"]) != 2 || !strings.Contains(string(b), "echo existing") {
					t.Errorf("what the launch passed is not kept:\n%s", b)
				}
			}
			if after, _ := os.ReadFile(passed); string(after) != before {
				t.Error("the file the launch passed was written")
			}
		})
	}
	if _, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
		Launch: runtimes.Launch{Args: []string{"--settings", filepath.Join(t.TempDir(), "absent.json")}}, RunDir: t.TempDir(), Forwarder: []string{"q"},
	}); err == nil {
		t.Error("settings that cannot be read were passed over")
	}
}
