package claude_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/claude"
	"github.com/qoryai/forager/session/runtimes/runtimetest"
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

// TestSettingsReadsOnlyAPlainFileItIsLetRead pins what the installer reads of a file
// the launch names: only one Readable passes, never through a link as its last part,
// only a regular file and at most 1 MiB; a refusal names the file. A document the
// launch holds is no file, and Readable is not asked of it.
func TestSettingsReadsOnlyAPlainFileItIsLetRead(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	if err := os.WriteFile(p("plain.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(p("plain.json"), p("link.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p("dir.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(p("fifo.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	big := append([]byte(`{"x":"`), make([]byte, 1<<20)...)
	for i := 6; i < len(big); i++ {
		big[i] = 'a'
	}
	if err := os.WriteFile(p("big.json"), append(big, '"', '}'), 0o644); err != nil {
		t.Fatal(err)
	}
	// edge is 1 MiB exactly, the most the installer reads.
	edge := append([]byte(`{"x":"`), make([]byte, 1<<20-8)...)
	for i := 6; i < len(edge); i++ {
		edge[i] = 'a'
	}
	if err := os.WriteFile(p("edge.json"), append(edge, '"', '}'), 0o644); err != nil {
		t.Fatal(err)
	}
	refuseAll := func(string) error { return errors.New("refused here") }
	for _, c := range []struct {
		name     string
		arg      string
		readable func(string) error
		want     string
	}{
		{"a plain file", p("plain.json"), nil, ""},
		{"a plain file Readable passes", p("plain.json"), func(string) error { return nil }, ""},
		{"a file Readable refuses", p("plain.json"), refuseAll, "settings " + p("plain.json") + ": refused here"},
		{"a link as its last part", p("link.json"), nil, "settings " + p("link.json") + ": it is a link"},
		{"a directory", p("dir.json"), nil, "settings " + p("dir.json") + ": it is not a regular file"},
		{"a FIFO", p("fifo.json"), nil, "settings " + p("fifo.json") + ": it is not a regular file"},
		{"a file of 1 MiB", p("edge.json"), nil, ""},
		{"a file larger than 1 MiB", p("big.json"), nil, "settings " + p("big.json") + ": it is larger than 1048576 bytes"},
		{"a document", ` {"permissions":{}}`, refuseAll, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
				Launch: runtimes.Launch{Command: "claude", Args: []string{"--settings", c.arg}},
				RunDir: t.TempDir(), Forwarder: []string{"q"}, Readable: c.readable,
			})
			switch {
			case c.want == "" && err != nil:
				t.Errorf("refused: %v", err)
			case c.want != "" && (err == nil || err.Error() != c.want):
				t.Errorf("got %v, want %q", err, c.want)
			}
		})
	}
}
