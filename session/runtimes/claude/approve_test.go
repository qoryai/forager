package claude_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/runner/session/runtimes"
	"github.com/qoryai/runner/session/runtimes/claude"
)

// approvedEntry is what Claude Code 2.1.273 keeps for an approved key: the key trimmed,
// then its last 20 characters. The stand-in's are these.
const approvedEntry = "utside-the-enclosure"

func TestClaudeCodeDeclaresItsModelCredential(t *testing.T) {
	rt, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	s, ok := rt.(runtimes.Secrets)
	if !ok {
		t.Fatal("Claude Code does not implement runtimes.Secrets")
	}
	d := s.Secrets()
	var names []string
	for _, dc := range d.Declares {
		names = append(names, dc.ID+"="+dc.Name+" "+dc.Auth.Scheme)
	}
	if want := []string{"api_key=ANTHROPIC_API_KEY header", "oauth_token=CLAUDE_CODE_OAUTH_TOKEN bearer"}; !reflect.DeepEqual(names, want) {
		t.Errorf("declares %v, want %v", names, want)
	}
	if len(d.OneOf) != 1 || d.OneOf[0].ID != "model_key" || !d.OneOf[0].Required || !reflect.DeepEqual(d.OneOf[0].Of, []string{"api_key", "oauth_token"}) {
		t.Errorf("one_of %+v", d.OneOf)
	}
	if !reflect.DeepEqual(d.Reserves, []string{"ANTHROPIC_AUTH_TOKEN"}) || !slices.Contains(d.Denies, "CLAUDE_CONFIG_DIR") {
		t.Errorf("reserves %v, denies %v", d.Reserves, d.Denies)
	}
}

// prepare is the claude runtime's Prepare of `claude --model m` with a forwarder.
func prepare(t *testing.T, dir string, interactive bool, placeholders ...string) runtimes.Launch {
	t.Helper()
	rt, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	got, err := rt.Prepare(runtimes.Attach{
		Launch: runtimes.Launch{Command: "claude", Args: []string{"--model", "m"}}, RunDir: dir,
		Forwarder: []string{"/opt/q", "forward"}, Interactive: interactive, Placeholders: placeholders,
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// TestPrepareApprovesTheAPIKeyStandInAlone pins when the launch goes through the
// script: interactive, with ANTHROPIC_API_KEY among the stand-ins. With the OAuth
// credential's stand-in, with none, or headless, Claude Code shows no approval prompt,
// and the launch is the program itself.
func TestPrepareApprovesTheAPIKeyStandInAlone(t *testing.T) {
	for _, c := range []struct {
		name         string
		interactive  bool
		placeholders []string
		through      bool
	}{
		{"api key, interactive", true, []string{"GH_TOKEN", "ANTHROPIC_API_KEY"}, true},
		{"api key, headless", false, []string{"ANTHROPIC_API_KEY"}, false},
		{"oauth, interactive", true, []string{"CLAUDE_CODE_OAUTH_TOKEN"}, false},
		{"oauth, headless", false, []string{"CLAUDE_CODE_OAUTH_TOKEN"}, false},
		{"neither, interactive", true, nil, false},
		{"neither, headless", false, nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			got := prepare(t, dir, c.interactive, c.placeholders...)
			settings := []string{"--model", "m", "--settings", filepath.Join(dir, "settings.json")}
			script := filepath.Join(dir, claude.ApproveScript)
			_, err := os.Stat(script)
			if !c.through {
				if got.Command != "claude" || !reflect.DeepEqual(got.Args, settings) || len(got.Env) != 0 {
					t.Errorf("the launch is %+v, want claude %v", got, settings)
				}
				if err == nil {
					t.Error("the script was written for a launch that does not go through it")
				}
				return
			}
			if want := append([]string{script, "claude"}, settings...); got.Command != "/bin/sh" || !reflect.DeepEqual(got.Args, want) || len(got.Env) != 0 {
				t.Errorf("the launch is %+v, want /bin/sh %v", got, want)
			}
			b, err := os.ReadFile(script)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), `"approved":["`+approvedEntry+`"]`) || strings.Contains(string(b), "@APPROVED@") {
				t.Errorf("the script does not hold the stand-in's entry:\n%s", b)
			}
		})
	}
}

// TestTheScriptApprovesTheStandInAndKeepsTheRest runs the script with /bin/sh against
// each state the configuration can be in, and requires the program to start with its
// arguments in every one. The run's ANTHROPIC_API_KEY is a key of the person's own
// here, to show the script approves the stand-in's entry and reads no key.
func TestTheScriptApprovesTheStandInAndKeepsTheRest(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	pretty := "{\n  \"hasCompletedOnboarding\": true,\n  \"theme\": \"dark\",\n  \"projects\": {\n    \"/work\": {\n      \"hasTrustDialogAccepted\": true\n    }\n  }\n}\n"
	already := `{"customApiKeyResponses":{"approved":["another-key-0123456789"],"rejected":[]},"theme":"dark"}`
	for _, c := range []struct {
		name string
		// setup writes the configuration into home and returns the file the script
		// writes and the members expected there beside the approval, or no file when
		// the script writes none.
		setup func(t *testing.T, home string) (file string, want map[string]any)
		// unchanged lists files whose bytes stay as setup wrote them.
		unchanged []string
		env       func(home string) []string
		// exact is the file's bytes afterwards when not empty, with ENTRY in place of
		// the approval's member.
		exact string
	}{
		{name: "missing", setup: func(t *testing.T, home string) (string, map[string]any) {
			return filepath.Join(home, ".claude.json"), map[string]any{}
		}},
		{name: "empty", setup: func(t *testing.T, home string) (string, map[string]any) {
			write(t, filepath.Join(home, ".claude.json"), "")
			return filepath.Join(home, ".claude.json"), map[string]any{}
		}},
		{name: "an empty object", setup: func(t *testing.T, home string) (string, map[string]any) {
			write(t, filepath.Join(home, ".claude.json"), "  { \n }\n")
			return filepath.Join(home, ".claude.json"), map[string]any{}
		}, exact: "  {ENTRY \n }\n"},
		{name: "a person's own", setup: func(t *testing.T, home string) (string, map[string]any) {
			write(t, filepath.Join(home, ".claude.json"), pretty)
			return filepath.Join(home, ".claude.json"), decode(t, pretty)
		}, exact: "{ENTRY," + pretty[1:]},
		{name: "space before and newlines after", setup: func(t *testing.T, home string) (string, map[string]any) {
			write(t, filepath.Join(home, ".claude.json"), "\n\t{\"theme\":\"dark\"}\n\n\n")
			return filepath.Join(home, ".claude.json"), map[string]any{"theme": "dark"}
		}, exact: "\n\t{ENTRY,\"theme\":\"dark\"}\n"},
		{name: "a link to a person's own", setup: func(t *testing.T, home string) (string, map[string]any) {
			target := filepath.Join(home, "dotfiles", "claude.json")
			os.MkdirAll(filepath.Dir(target), 0o755)
			write(t, target, pretty)
			if err := os.Symlink(target, filepath.Join(home, ".claude.json")); err != nil {
				t.Fatal(err)
			}
			return target, decode(t, pretty)
		}},
		{name: "the legacy file", setup: func(t *testing.T, home string) (string, map[string]any) {
			os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
			write(t, filepath.Join(home, ".claude", ".config.json"), pretty)
			write(t, filepath.Join(home, ".claude.json"), pretty)
			return filepath.Join(home, ".claude", ".config.json"), decode(t, pretty)
		}, unchanged: []string{".claude.json"}},
		{name: "CLAUDE_CONFIG_DIR", setup: func(t *testing.T, home string) (string, map[string]any) {
			os.MkdirAll(filepath.Join(home, "config"), 0o755)
			write(t, filepath.Join(home, ".claude.json"), pretty)
			return filepath.Join(home, "config", ".claude.json"), map[string]any{}
		}, unchanged: []string{".claude.json"}, env: func(home string) []string {
			return []string{"CLAUDE_CONFIG_DIR=" + filepath.Join(home, "config")}
		}},
		{name: "responses already", setup: func(t *testing.T, home string) (string, map[string]any) {
			write(t, filepath.Join(home, ".claude.json"), already)
			return "", nil
		}, unchanged: []string{".claude.json"}},
		{name: "no object", setup: func(t *testing.T, home string) (string, map[string]any) {
			write(t, filepath.Join(home, ".claude.json"), "[1, 2]\n")
			return "", nil
		}, unchanged: []string{".claude.json"}},
		{name: "read-only", setup: func(t *testing.T, home string) (string, map[string]any) {
			if os.Geteuid() == 0 {
				t.Skip("root writes a read-only file")
			}
			write(t, filepath.Join(home, ".claude.json"), pretty)
			os.Chmod(filepath.Join(home, ".claude.json"), 0o444)
			return "", nil
		}, unchanged: []string{".claude.json"}},
		{name: "a FIFO", setup: func(t *testing.T, home string) (string, map[string]any) {
			if out, err := exec.Command("mkfifo", filepath.Join(home, ".claude.json")).CombinedOutput(); err != nil {
				t.Skipf("mkfifo: %v %s", err, out)
			}
			return "", nil
		}},
		{name: "a directory", setup: func(t *testing.T, home string) (string, map[string]any) {
			os.Mkdir(filepath.Join(home, ".claude.json"), 0o755)
			return "", nil
		}},
		{name: "no room for the temporary file", setup: func(t *testing.T, home string) (string, map[string]any) {
			if os.Geteuid() == 0 {
				t.Skip("root writes into a read-only directory")
			}
			write(t, filepath.Join(home, ".claude.json"), pretty)
			os.Chmod(home, 0o555)
			t.Cleanup(func() { os.Chmod(home, 0o755) })
			return "", nil
		}, unchanged: []string{".claude.json"}},
		{name: "no home", setup: func(t *testing.T, home string) (string, map[string]any) {
			return "", nil
		}, env: func(string) []string { return []string{"HOME="} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			file, want := c.setup(t, home)
			before := map[string][]byte{}
			for _, f := range c.unchanged {
				before[f], _ = os.ReadFile(filepath.Join(home, f))
			}
			var mode os.FileMode
			existed := false
			if file != "" {
				fi, err := os.Stat(file)
				if existed = err == nil; existed {
					mode = fi.Mode().Perm()
				}
			}

			dir := t.TempDir()
			rt, err := claude.New()
			if err != nil {
				t.Fatal(err)
			}
			launch, err := rt.Prepare(runtimes.Attach{
				Launch: runtimes.Launch{Command: "printf", Args: []string{"%s|", "an argument", "it's"}}, RunDir: dir,
				Forwarder: []string{"/opt/q", "forward"}, Interactive: true, Placeholders: []string{"ANTHROPIC_API_KEY"},
			})
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(launch.Command, launch.Args...)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "ANTHROPIC_API_KEY=sk-ant-api03-a-person-s-own-0123456789"}
			if c.env != nil {
				cmd.Env = append(cmd.Env, c.env(home)...)
			}
			out, err := cmd.CombinedOutput()
			if want := "an argument|it's|--settings|" + filepath.Join(dir, "settings.json") + "|"; err != nil || string(out) != want {
				t.Fatalf("the program printed %q, %v; want %q", out, err, want)
			}

			for f, b := range before {
				if after, _ := os.ReadFile(filepath.Join(home, f)); string(after) != string(b) {
					t.Errorf("%s changed:\n%s", f, after)
				}
			}
			filepath.WalkDir(home, func(path string, e fs.DirEntry, err error) error {
				if err == nil && strings.Contains(e.Name(), ".qory-") {
					t.Errorf("the temporary file %s stayed", path)
				}
				return nil
			})
			if file == "" {
				return
			}
			got, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(got, &doc); err != nil {
				t.Fatalf("%s is no JSON: %v\n%s", file, err, got)
			}
			responses, _ := doc["customApiKeyResponses"].(map[string]any)
			if !reflect.DeepEqual(responses, map[string]any{"approved": []any{approvedEntry}, "rejected": []any{}}) {
				t.Errorf("customApiKeyResponses is %v", doc["customApiKeyResponses"])
			}
			delete(doc, "customApiKeyResponses")
			if !reflect.DeepEqual(doc, want) {
				t.Errorf("the rest of the configuration is\n%v\nwant\n%v", doc, want)
			}
			entry := `"customApiKeyResponses":{"approved":["` + approvedEntry + `"],"rejected":[]}`
			if want := strings.Replace(c.exact, "ENTRY", entry, 1); c.exact != "" && string(got) != want {
				t.Errorf("the file is\n%q\nwant\n%q", got, want)
			}
			if !existed {
				mode = 0o600
			}
			if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != mode {
				t.Errorf("the configuration's mode is %v, %v; want %v", fi.Mode().Perm(), err, mode)
			}
			if fi, err := os.Lstat(filepath.Join(home, ".claude.json")); c.name == "a link to a person's own" && (err != nil || fi.Mode()&os.ModeSymlink == 0) {
				t.Error("the link was replaced by a file")
			}
		})
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}
