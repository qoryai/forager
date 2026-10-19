package claude_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
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
	refuseAll := func(string) (string, error) { return "", errors.New("refused here") }
	pass := filepath.EvalSymlinks
	other := func(string) (string, error) { return filepath.EvalSymlinks(p("edge.json")) }
	for _, c := range []struct {
		name     string
		arg      string
		readable func(string) (string, error)
		want     string
	}{
		{"a plain file", p("plain.json"), nil, ""},
		{"a plain file Readable passes", p("plain.json"), pass, ""},
		{"a file other than the one Readable judged", p("plain.json"), other, "settings " + p("plain.json") + ": it changed while it was checked"},
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

// settingsMoreThanOnce is the refusal of a walled launch that passes --settings more
// than once.
const settingsMoreThanOnce = "This launch passes --settings more than once, and Claude Code reads only the last one, " +
	"so the run does not start. Pass one --settings file."

// TestSettingsRefusesAWalledLaunchThatPassesSettingsMoreThanOnce pins that a walled
// launch whose arguments pass --settings more than once, in either form, after -- or
// as the value of another option, is refused before any file is read or written, and
// that a walled launch with one --settings and an unwalled launch with two are
// prepared as before.
func TestSettingsRefusesAWalledLaunchThatPassesSettingsMoreThanOnce(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first.json"), filepath.Join(dir, "second.json")
	for _, f := range []string{first, second} {
		if err := os.WriteFile(f, []byte(`{"permissions":{}}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prepare := func(t *testing.T, walled bool, args []string) (runtimes.Launch, string, []string, error) {
		t.Helper()
		var asked []string
		run := t.TempDir()
		got, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
			Launch: runtimes.Launch{Command: "claude", Args: args}, RunDir: run, Forwarder: []string{"q"},
			Walled: walled,
			Readable: func(p string) (string, error) {
				asked = append(asked, p)
				return filepath.EvalSymlinks(p)
			},
		})
		return got, run, asked, err
	}
	for name, args := range map[string][]string{
		"--settings path twice":     {"--settings", first, "-p", "hi", "--settings", second},
		"--settings=path twice":     {"--settings=" + first, "--settings=" + second},
		"path, then =path":          {"--settings", first, "--settings=" + second},
		"=path, then path":          {"--settings=" + first, "--settings", second},
		"three flags":               {"--settings", first, "--settings=" + second, "--settings", first},
		"a document and a path":     {"--settings", `{"permissions":{}}`, "--settings", second},
		"a flag after --":           {"--settings", first, "--", "--settings", second},
		"a flag as an option value": {"--settings", first, "--model", "--settings", second},
		"two flags with no value":   {"--settings", "--settings"},
	} {
		t.Run(name, func(t *testing.T) {
			_, run, asked, err := prepare(t, true, args)
			if err == nil || err.Error() != settingsMoreThanOnce {
				t.Fatalf("got %v, want %q", err, settingsMoreThanOnce)
			}
			if len(asked) > 0 {
				t.Errorf("Readable was asked of %q", asked)
			}
			if _, err := os.Stat(filepath.Join(run, "settings.json")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the run's settings were written: %v", err)
			}
		})
	}
	for name, args := range map[string][]string{
		"a file":        {"-p", "hi", "--settings", first},
		"a file with =": {"--settings=" + first},
		"a document":    {"--settings", `{"permissions":{}}`},
		"none":          {"-p", "hi"},
	} {
		t.Run("walled, "+name, func(t *testing.T) {
			got, run, _, err := prepare(t, true, args)
			if err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(strings.Join(got.Args, "\x00")+"\x00", "--settings\x00"+filepath.Join(run, "settings.json")+"\x00"); n != 1 {
				t.Errorf("launch %q does not pass the run's settings once", got.Args)
			}
		})
	}
	t.Run("unwalled, two flags", func(t *testing.T) {
		got, run, _, err := prepare(t, false, []string{"--settings", first, "--settings=" + second})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"--settings", filepath.Join(run, "settings.json"), "--settings=" + second}
		if !slices.Equal(got.Args, want) {
			t.Errorf("launch %q, want %q", got.Args, want)
		}
	})
}
