package claude_test

import (
	"encoding/json"
	"errors"
	"fmt"
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
				Launch: runtimes.Launch{Command: "claude", Args: args}, SessionDir: dir, Forwarder: []string{"/opt/q", "it's"},
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
		Launch: runtimes.Launch{Args: []string{"--settings", filepath.Join(t.TempDir(), "absent.json")}}, SessionDir: t.TempDir(), Forwarder: []string{"q"},
	}); err == nil {
		t.Error("settings that cannot be read were passed over")
	}
}

// TestSettingsReadsOnlyAPlainFileItIsLetRead pins what the installer reads of a file
// whose path the launch passes: only one Readable passes, never through a link as its
// last part, only a regular file and at most 1 MiB; a refusal shows the file. A
// document passed in the launch is no file, and Readable is not asked of it.
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
		{"a file other than the one Readable judged", p("plain.json"), other, "Start the run again when no process is writing " +
			p("plain.json") + ". This launch passes --settings " + p("plain.json") + ", and that file changed while it was checked, " +
			"so the run does not start."},
		{"a file Readable refuses", p("plain.json"), refuseAll, "Fix the error at the end of this message, or pass another " +
			"--settings path. The check of --settings " + p("plain.json") + " failed: refused here"},
		{"a link as its last part", p("link.json"), nil, "Pass the path of the file that " + p("link.json") + " links to. " +
			"This launch passes --settings " + p("link.json") + ", and that file is a link, so the run does not start."},
		{"a directory", p("dir.json"), nil, "Pass a --settings path to a regular file. This launch passes --settings " +
			p("dir.json") + ", and that file is not a regular file, so the run does not start."},
		{"a FIFO", p("fifo.json"), nil, "Pass a --settings path to a regular file. This launch passes --settings " +
			p("fifo.json") + ", and that file is not a regular file, so the run does not start."},
		{"a file of 1 MiB", p("edge.json"), nil, ""},
		{"a file larger than 1 MiB", p("big.json"), nil, "Pass a --settings file of at most 1048576 bytes (1 MiB). This launch passes " +
			"--settings " + p("big.json") + ", and that file is larger than 1048576 bytes, so the run does not start."},
		{"a document", ` {"permissions":{}}`, refuseAll, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
				Launch:     runtimes.Launch{Command: "claude", Args: []string{"--settings", c.arg}},
				SessionDir: t.TempDir(), Forwarder: []string{"q"}, Readable: c.readable,
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

// settingsMoreThanOnce is the refusal of a launch that passes --settings more than
// once.
const settingsMoreThanOnce = "Pass one --settings file. This launch passes --settings more than once, " +
	"and Claude Code reads only the last one, so the run does not start."

// TestSettingsRefusesALaunchThatPassesSettingsMoreThanOnce pins that a launch whose
// arguments pass --settings more than once, in either form, after -- or as the value
// of another option, is refused before any file is read or written, walled or not, and
// that a launch with one --settings is prepared as before. A launch whose last
// argument is a bare --settings passes that one flag, with the run's settings, walled
// or not.
func TestSettingsRefusesALaunchThatPassesSettingsMoreThanOnce(t *testing.T) {
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
			Launch: runtimes.Launch{Command: "claude", Args: args}, SessionDir: run, Forwarder: []string{"q"},
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
		for _, walled := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, walled %v", name, walled), func(t *testing.T) {
				_, run, asked, err := prepare(t, walled, args)
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
	}
	for name, args := range map[string][]string{
		"a file":            {"-p", "hi", "--settings", first},
		"a file with =":     {"--settings=" + first},
		"a document":        {"--settings", `{"permissions":{}}`},
		"none":              {"-p", "hi"},
		"a bare last flag":  {"-p", "hi", "--settings"},
		"a bare flag alone": {"--settings"},
	} {
		for _, walled := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, walled %v", name, walled), func(t *testing.T) {
				got, run, _, err := prepare(t, walled, args)
				if err != nil {
					t.Fatal(err)
				}
				flags, at := 0, -1
				for i, a := range got.Args {
					if a == "--settings" || strings.HasPrefix(a, "--settings=") {
						flags, at = flags+1, i
					}
				}
				if flags != 1 || got.Args[at] != "--settings" || at+1 >= len(got.Args) || got.Args[at+1] != filepath.Join(run, "settings.json") {
					t.Errorf("launch %q does not pass --settings once, with the run's settings", got.Args)
				}
			})
		}
	}
}

// projectConfigRoot is the refusal of a walled launch that passes --project-config-root.
const projectConfigRoot = "Remove --project-config-root from the walled launch. This launch passes " +
	"--project-config-root, and Claude Code reads project settings, .mcp.json and the .claude trees from that " +
	"directory, which Forager does not check, so the run does not start."

// TestSettingsRefusesAWalledLaunchThatPassesProjectConfigRoot pins that a walled launch
// that passes --project-config-root, in either form, after --, as the value of another
// option or bare, is refused before any file is read or written, and that an unwalled
// launch keeps it.
func TestSettingsRefusesAWalledLaunchThatPassesProjectConfigRoot(t *testing.T) {
	root := t.TempDir()
	for name, args := range map[string][]string{
		"--project-config-root dir":  {"-p", "hi", "--project-config-root", root},
		"--project-config-root=dir":  {"--project-config-root=" + root, "-p", "hi"},
		"after --":                   {"-p", "hi", "--", "--project-config-root", root},
		"= after --":                 {"--", "--project-config-root=" + root},
		"as an option's value":       {"--model", "--project-config-root", root},
		"bare, last":                 {"-p", "hi", "--project-config-root"},
		"with a file to check first": {"--mcp-config", filepath.Join(root, "mcp.json"), "--project-config-root", root},
	} {
		t.Run(name, func(t *testing.T) {
			var asked []string
			run := t.TempDir()
			_, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
				Launch: runtimes.Launch{Command: "claude", Args: args}, SessionDir: run, Forwarder: []string{"q"}, Walled: true,
				Readable: func(p string) (string, error) {
					asked = append(asked, p)
					return filepath.EvalSymlinks(p)
				},
			})
			if err == nil || err.Error() != projectConfigRoot {
				t.Fatalf("got %v, want %q", err, projectConfigRoot)
			}
			if len(asked) > 0 {
				t.Errorf("Readable was asked of %q", asked)
			}
			if entries, _ := os.ReadDir(run); len(entries) > 0 {
				t.Errorf("the run directory has %d entries", len(entries))
			}
		})
	}
	t.Run("unwalled", func(t *testing.T) {
		args := []string{"--project-config-root", root, "--project-config-root=" + root}
		got, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
			Launch: runtimes.Launch{Command: "claude", Args: args}, SessionDir: t.TempDir(), Forwarder: []string{"q"},
		})
		if err != nil || !slices.Equal(got.Args[:len(args)], args) {
			t.Errorf("launch %q, %v", got.Args, err)
		}
	})
}

// TestSettingsThatAreNoJSONObjectComeWithAFix pins the fix that leads the text of a
// settings file whose content is no JSON object.
func TestSettingsThatAreNoJSONObjectComeWithAFix(t *testing.T) {
	for content, reason := range map[string]string{
		"[1]":  "json: cannot unmarshal array",
		"null": "it is null",
	} {
		t.Run(content, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "settings.json")
			if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
				Launch: runtimes.Launch{Args: []string{"--settings", f}}, SessionDir: t.TempDir(), Forwarder: []string{"q"},
			})
			prefix := "Make the file " + f + " a JSON object. The check of --settings " + f + " failed: " + reason
			if err == nil || !strings.HasPrefix(err.Error(), prefix) {
				t.Errorf("got %v, want the prefix %q", err, prefix)
			}
		})
	}
}
