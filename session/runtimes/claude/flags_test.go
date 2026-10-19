package claude_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/claude"
)

// fakeWritten is a Readable that refuses every path that lies in written, as given or
// resolved, as the session refuses a file in a place a walled run can write, and
// records what it was asked.
type fakeWritten struct {
	written string
	asked   []string
}

func (f *fakeWritten) readable(p string) (string, error) {
	f.asked = append(f.asked, p)
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		resolved = p
	}
	real, err := filepath.EvalSymlinks(f.written)
	if err != nil {
		real = f.written
	}
	for _, path := range []string{p, resolved} {
		for _, place := range []string{f.written, real} {
			if path == place || strings.HasPrefix(path, place+"/") {
				return "", &runtimes.WrittenError{How: "lies in", Place: f.written}
			}
		}
	}
	return resolved, nil
}

// walled prepares a walled launch of args with the fake's Readable.
func walled(t *testing.T, f *fakeWritten, args []string) (runtimes.Launch, string, error) {
	t.Helper()
	run := t.TempDir()
	got, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
		Launch: runtimes.Launch{Command: "claude", Args: args}, RunDir: run, Forwarder: []string{"q"},
		Walled: true, Readable: f.readable,
	})
	return got, run, err
}

// writeFile writes content at path, making its directory.
func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// mcpInWork is the refusal of an --mcp-config file in a place a walled run can write.
func mcpInWork(file, place string) string {
	return "Move " + file + " to a directory no walled run can write, or pass the servers as a JSON string. " +
		"This launch passes --mcp-config " + file + ", which lies in " + place +
		", a place a walled run can write, so the run does not start."
}

// agentsInWork is the refusal of an --agents file in a place a walled run can write.
func agentsInWork(file, place string) string {
	return "Move " + file + " to a directory no walled run can write, or pass the agents as a JSON object. " +
		"This launch passes --agents " + file + ", which lies in " + place +
		", a place a walled run can write, so the run does not start."
}

// TestAWalledLaunchsFileInAWrittenPlaceIsRefused pins that a walled launch whose
// --mcp-config or --agents names a file in a place a walled run can write is refused
// with the text for the flag, in every form the flag takes: a value after a space or
// after "=", one of several values and one of several flags. Nothing is copied.
func TestAWalledLaunchsFileInAWrittenPlaceIsRefused(t *testing.T) {
	work := t.TempDir()
	ok := writeFile(t, filepath.Join(t.TempDir(), "ok.json"), `{"mcpServers":{}}`)
	bad := writeFile(t, filepath.Join(work, "mcp.json"), `{"mcpServers":{}}`)
	agents := writeFile(t, filepath.Join(work, "agents.json"), `{}`)
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"--mcp-config path":                  {[]string{"--mcp-config", bad, "-p", "hi"}, mcpInWork(bad, work)},
		"--mcp-config=path":                  {[]string{"--mcp-config=" + bad}, mcpInWork(bad, work)},
		"--mcp-config with several values":   {[]string{"--mcp-config", ok, `{"mcpServers":{}}`, bad, "-p", "hi"}, mcpInWork(bad, work)},
		"--mcp-config twice":                 {[]string{"--mcp-config", ok, "--mcp-config", bad}, mcpInWork(bad, work)},
		"--mcp-config= twice":                {[]string{"--mcp-config=" + ok, "--mcp-config=" + bad}, mcpInWork(bad, work)},
		"--agents path":                      {[]string{"--agents", agents, "-p", "hi"}, agentsInWork(agents, work)},
		"--agents=path":                      {[]string{"--agents=" + agents}, agentsInWork(agents, work)},
		"--agents twice":                     {[]string{"--agents", ok, "--agents", agents}, agentsInWork(agents, work)},
		"--agents twice, the first in place": {[]string{"--agents=" + agents, "--agents", ok}, agentsInWork(agents, work)},
	} {
		t.Run(name, func(t *testing.T) {
			_, run, err := walled(t, &fakeWritten{written: work}, c.args)
			if err == nil || err.Error() != c.want {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			if copies, _ := filepath.Glob(filepath.Join(run, "*-*.json")); len(copies) > 0 {
				t.Errorf("copies were written: %q", copies)
			}
		})
	}
}

// TestAWalledLaunchsFileReachedThroughAWrittenPlaceIsRefused pins the text for a file
// whose path is looked up in a place a walled run can write.
func TestAWalledLaunchsFileReachedThroughAWrittenPlaceIsRefused(t *testing.T) {
	file := writeFile(t, filepath.Join(t.TempDir(), "mcp.json"), `{}`)
	through := func(string) (string, error) {
		return "", &runtimes.WrittenError{How: "is reached through", Place: "/work"}
	}
	_, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
		Launch: runtimes.Launch{Args: []string{"--mcp-config", file}}, RunDir: t.TempDir(), Forwarder: []string{"q"},
		Walled: true, Readable: through,
	})
	want := "Move " + file + " to a directory no walled run can write, or pass the servers as a JSON string. " +
		"This launch passes --mcp-config " + file + ", which is reached through /work, a place a walled run can write, " +
		"so the run does not start."
	if err == nil || err.Error() != want {
		t.Errorf("got %v, want %q", err, want)
	}
}

// TestAWalledLaunchsValuesAreReadAsClaudeCodeReadsThem pins which words are values of
// the flags: none after a "--" that ends the options, those after a "--" that may be
// another option's value, and for --agents, which takes one value, not the word after
// its value.
func TestAWalledLaunchsValuesAreReadAsClaudeCodeReadsThem(t *testing.T) {
	work, elsewhere := t.TempDir(), t.TempDir()
	bad := writeFile(t, filepath.Join(work, "mcp.json"), `{}`)
	for name, c := range map[string]struct {
		args    []string
		refused bool
	}{
		"after --":                               {[]string{"-p", "hi", "--", "--mcp-config", bad}, false},
		"after -- first":                         {[]string{"--", "--mcp-config", bad}, false},
		"after a variadic value and --":          {[]string{"--add-dir", elsewhere, "--", "--mcp-config", bad}, false},
		"after -- that may be an option's value": {[]string{"--model", "--", "--mcp-config", bad}, true},
		"after a --name=value and --":            {[]string{"--model=x", "--", "--mcp-config", bad}, false},
		"after --agents' one value":              {[]string{"--agents", `{"a":{}}`, bad}, false},
		"a variadic value after another":         {[]string{"--mcp-config", `{"mcpServers":{}}`, bad}, true},
		"a variadic flag's value after one dash": {[]string{"--mcp-config", "-", bad}, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeWritten{written: work}
			_, _, err := walled(t, f, c.args)
			if c.refused != (err != nil) {
				t.Fatalf("refused %v: %v", c.refused, err)
			}
		})
	}
}

// TestAWalledLaunchsInlineJSONPassesAsItIs pins that a value Claude Code takes as JSON
// passes unchanged and is not asked of Readable, and which values those are: for
// --mcp-config a value that parses as JSON and is truthy, for --agents one that starts
// with "{" after white space or parses as JSON other than null. Any other value is a
// path.
func TestAWalledLaunchsInlineJSONPassesAsItIs(t *testing.T) {
	relative := func(flag, v string) string {
		return "Replace " + v + " with an absolute path outside the workspace. This launch passes " + flag + " " + v +
			", a relative path that Claude Code reads from the workspace, which a walled run can write, so the run does not start."
	}
	// The values that contain "{" or "[" or start with white space, which the text shows
	// as a phrase.
	phrase := map[[2]string]bool{{"--mcp-config", "{"}: true, {"--mcp-config", "  {"}: true,
		{"--mcp-config", "\u00a0{}"}: true, {"--agents", " null"}: true}
	for _, c := range []struct {
		flag, value string
		inline      bool
	}{
		{"--mcp-config", `{"mcpServers":{}}`, true},
		{"--mcp-config", "\n {\"mcpServers\":{}} \t", true},
		{"--mcp-config", "{", false},
		{"--mcp-config", "  {", false},
		{"--mcp-config", "[1]", true},
		{"--mcp-config", "null", false},
		{"--mcp-config", "0", false},
		{"--mcp-config", `""`, false},
		{"--mcp-config", "false", false},
		{"--mcp-config", "\u00a0{}", false},
		{"--mcp-config", "1e400", false},
		{"--mcp-config", "1", true},
		{"--mcp-config", "-0.0", false},
		{"--agents", `{"reviewer":{"description":"d","prompt":"p"}}`, true},
		{"--agents", "{", true},
		{"--agents", "  {", true},
		{"--agents", "[1]", true},
		{"--agents", "null", false},
		{"--agents", " null", false},
		{"--agents", "null\n", false},
		{"--agents", `"null"`, true},
		{"--agents", "agents.json", false},
	} {
		t.Run(c.flag+" "+c.value, func(t *testing.T) {
			f := &fakeWritten{written: t.TempDir()}
			args := []string{"-p", "hi", c.flag, c.value}
			got, _, err := walled(t, f, args)
			if !c.inline {
				shown := c.value
				if phrase[[2]string{c.flag, c.value}] {
					shown = "(an " + c.flag + " value)"
				}
				if want := relative(c.flag, shown); err == nil || err.Error() != want {
					t.Errorf("got %v, want %q", err, want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got.Args[:4], args) || len(f.asked) > 0 {
				t.Errorf("launch %q, Readable asked of %q", got.Args, f.asked)
			}
		})
	}
}

// TestAWalledLaunchsFilesAreCopied pins that each --mcp-config and --agents file is
// passed as a copy in the run directory with the same content, numbered by its place
// among the flag's files, in either form; the files passed are not written.
func TestAWalledLaunchsFilesAreCopied(t *testing.T) {
	dir := t.TempDir()
	one := writeFile(t, filepath.Join(dir, "one.json"), `{"mcpServers":{"a":{"command":"/opt/a"}}}`)
	two := writeFile(t, filepath.Join(dir, "two.json"), `{"mcpServers":{"b":{"command":"/opt/b"}}}`)
	agents := writeFile(t, filepath.Join(dir, "agents.json"), `{"r":{"description":"d","prompt":"p"}}`)
	doc := `{"mcpServers":{}}`
	got, run, err := walled(t, &fakeWritten{written: t.TempDir()},
		[]string{"--mcp-config", one, doc, "--agents=" + agents, "--mcp-config=" + two, "-p", "hi"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--mcp-config", filepath.Join(run, "mcp-config-1.json"), doc, "--agents=" + filepath.Join(run, "agents-1.json"),
		"--mcp-config=" + filepath.Join(run, "mcp-config-2.json"), "-p", "hi"}
	if !slices.Equal(got.Args[:len(want)], want) {
		t.Fatalf("launch %q, want %q", got.Args, want)
	}
	for copied, from := range map[string]string{"mcp-config-1.json": one, "mcp-config-2.json": two, "agents-1.json": agents} {
		a, _ := os.ReadFile(filepath.Join(run, copied))
		b, _ := os.ReadFile(from)
		if string(a) != string(b) {
			t.Errorf("%s: %s, want %s", copied, a, b)
		}
	}
	t.Run("unwalled", func(t *testing.T) {
		f := &fakeWritten{written: dir}
		args := []string{"--mcp-config", one, "--agents", agents, "--plugin-dir", "rel", "--add-dir", "~/x"}
		got, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
			Launch: runtimes.Launch{Args: args}, RunDir: t.TempDir(), Forwarder: []string{"q"}, Readable: f.readable,
		})
		if err != nil || !slices.Equal(got.Args[:len(args)], args) || len(f.asked) > 0 {
			t.Errorf("launch %q, %v, Readable asked of %q", got.Args, err, f.asked)
		}
	})
}

// TestAWalledLaunchsCopiesNameTheWorkspaceInside pins that a copy of a run whose
// workspace is at /workspace inside has every string written as the enclosure sees it,
// and that a file that is no JSON is copied as it is.
func TestAWalledLaunchsCopiesNameTheWorkspaceInside(t *testing.T) {
	dir := t.TempDir()
	mcp := writeFile(t, filepath.Join(dir, "mcp.json"), `{"mcpServers":{"a":{"command":"/home/ws/bin/a","args":["/home/ws/x"],"port":12345678901234567890}}}`)
	broken := writeFile(t, filepath.Join(dir, "agents.json"), `{"r": /home/ws`)
	run := t.TempDir()
	inside := func(s string) string { return strings.ReplaceAll(s, "/home/ws", "/workspace") }
	got, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
		Launch: runtimes.Launch{Args: []string{"--mcp-config", mcp, "--agents", broken}}, RunDir: run, Forwarder: []string{"q"},
		Walled: true, Inside: inside,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Args[1] != filepath.Join(run, "mcp-config-1.json") || got.Args[3] != filepath.Join(run, "agents-1.json") {
		t.Fatalf("launch %q", got.Args)
	}
	b, _ := os.ReadFile(got.Args[1])
	for _, want := range []string{`"/workspace/bin/a"`, `"/workspace/x"`, `12345678901234567890`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the copy lacks %s: %s", want, b)
		}
	}
	if b, _ := os.ReadFile(got.Args[3]); string(b) != `{"r": /home/ws` {
		t.Errorf("the copy of a file that is no JSON: %s", b)
	}
}

// promptFlags are the three system-prompt file flags and, for each, the flag that passes
// the text itself.
var promptFlags = map[string]string{
	"--system-prompt-file":                 "--system-prompt",
	"--append-system-prompt-file":          "--append-system-prompt",
	"--append-subagent-system-prompt-file": "--append-subagent-system-prompt",
}

// TestAWalledLaunchsPromptFileInAWrittenPlaceIsRefused pins that a walled launch whose
// system-prompt file flag passes a file in, or reached through, a place a walled run
// can write is refused with the flag's text, in both forms, and when the file is the
// second value of a repeated flag. Nothing is copied.
func TestAWalledLaunchsPromptFileInAWrittenPlaceIsRefused(t *testing.T) {
	work := t.TempDir()
	ok := writeFile(t, filepath.Join(t.TempDir(), "ok.md"), "# ok")
	bad := writeFile(t, filepath.Join(work, "p.md"), "# prompt")
	refusal := func(flag, how, place string) string {
		return "Move " + bad + " to a directory no walled run can write, or pass the text with " + promptFlags[flag] + ". " +
			"This launch passes " + flag + " " + bad + ", which " + how + " " + place +
			", a place a walled run can write, so the run does not start."
	}
	for flag := range promptFlags {
		for name, args := range map[string][]string{
			"path":                {flag, bad, "-p", "hi"},
			"=path":               {flag + "=" + bad},
			"twice":               {flag, ok, flag, bad},
			"twice, = then space": {flag + "=" + ok, flag, bad},
		} {
			t.Run(flag+" "+name, func(t *testing.T) {
				_, run, err := walled(t, &fakeWritten{written: work}, args)
				if want := refusal(flag, "lies in", work); err == nil || err.Error() != want {
					t.Fatalf("got %v, want %q", err, want)
				}
				if copies, _ := filepath.Glob(filepath.Join(run, "*-*.md")); len(copies) > 0 {
					t.Errorf("copies were written: %q", copies)
				}
			})
		}
		t.Run(flag+" reached through", func(t *testing.T) {
			through := func(string) (string, error) {
				return "", &runtimes.WrittenError{How: "is reached through", Place: "/work"}
			}
			_, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
				Launch: runtimes.Launch{Args: []string{flag, bad}}, RunDir: t.TempDir(), Forwarder: []string{"q"},
				Walled: true, Readable: through,
			})
			if want := refusal(flag, "is reached through", "/work"); err == nil || err.Error() != want {
				t.Errorf("got %v, want %q", err, want)
			}
		})
	}
}

// TestAWalledLaunchsPromptFilesAreCopiedUnchanged pins that each system-prompt file is
// passed as a copy in the run directory, <flag>-<n>.md, numbered by its place among the
// flag's files, in either form, byte for byte, even when the file is JSON and the
// workspace is at /workspace inside; and that an unwalled launch keeps its arguments.
func TestAWalledLaunchsPromptFilesAreCopiedUnchanged(t *testing.T) {
	dir := t.TempDir()
	one := writeFile(t, filepath.Join(dir, "one.md"), "# one\n/home/ws\n")
	two := writeFile(t, filepath.Join(dir, "two.md"), `{"a": "/home/ws"}`)
	inside := func(s string) string { return strings.ReplaceAll(s, "/home/ws", "/workspace") }
	for flag := range promptFlags {
		t.Run(flag, func(t *testing.T) {
			run := t.TempDir()
			f := &fakeWritten{written: t.TempDir()}
			got, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
				Launch: runtimes.Launch{Args: []string{flag, one, "-p", "hi", flag + "=" + two}}, RunDir: run,
				Forwarder: []string{"q"}, Walled: true, Readable: f.readable, Inside: inside,
			})
			if err != nil {
				t.Fatal(err)
			}
			first := filepath.Join(run, strings.TrimPrefix(flag, "--")+"-1.md")
			second := filepath.Join(run, strings.TrimPrefix(flag, "--")+"-2.md")
			if want := []string{flag, first, "-p", "hi", flag + "=" + second}; !slices.Equal(got.Args[:len(want)], want) {
				t.Fatalf("launch %q, want %q", got.Args, want)
			}
			for copied, from := range map[string]string{first: one, second: two} {
				a, _ := os.ReadFile(copied)
				b, _ := os.ReadFile(from)
				if string(a) != string(b) {
					t.Errorf("%s: %q, want %q", copied, a, b)
				}
			}
			if !slices.Equal(f.asked, []string{one, two}) {
				t.Errorf("Readable asked of %q", f.asked)
			}
		})
	}
	t.Run("unwalled", func(t *testing.T) {
		f := &fakeWritten{written: dir}
		args := []string{"--system-prompt-file", one, "--append-system-prompt-file=rel.md",
			"--append-subagent-system-prompt-file", "~/p.md", "--project-config-root", dir}
		got, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
			Launch: runtimes.Launch{Args: args}, RunDir: t.TempDir(), Forwarder: []string{"q"}, Readable: f.readable,
		})
		if err != nil || !slices.Equal(got.Args[:len(args)], args) || len(f.asked) > 0 {
			t.Errorf("launch %q, %v, Readable asked of %q", got.Args, err, f.asked)
		}
	})
}

// TestAWalledLaunchsJSONPathIsAPhrase pins that a value of --mcp-config or --agents
// taken as a path that contains "{" or "[", or starts with white space or a format
// character, is shown as a phrase, so a token in it is not printed.
func TestAWalledLaunchsJSONPathIsAPhrase(t *testing.T) {
	tok := `"Authorization":"Bearer fake-token-123"`
	for _, c := range []struct{ flag, value string }{
		{"--mcp-config", `{"headers":{` + tok + `},}`},
		{"--mcp-config", ` [{"headers":{` + tok + `}},]`},
		{"--mcp-config", "\ufeff" + `{"headers":{` + tok + `}}`},
		{"--mcp-config", "\u200b" + `{"headers":{` + tok + `}}`},
		{"--agents", `[{"x":{` + tok + `}},]`},
		{"--agents", "\ufeff" + `{"x":{` + tok + `}}`},
	} {
		for _, args := range [][]string{{c.flag, c.value}, {c.flag + "=" + c.value}} {
			t.Run(strings.Join(args, " "), func(t *testing.T) {
				shown := "(an " + c.flag + " value)"
				want := "Replace " + shown + " with an absolute path outside the workspace. This launch passes " +
					c.flag + " " + shown + ", a relative path that Claude Code reads from the workspace, " +
					"which a walled run can write, so the run does not start."
				_, _, err := walled(t, &fakeWritten{written: t.TempDir()}, args)
				if err == nil || err.Error() != want || strings.Contains(err.Error(), "fake-token-123") {
					t.Errorf("got %v, want %q", err, want)
				}
			})
		}
	}
	// An absolute path with "{" in it reaches the check of the file: the reason is a
	// phrase too, since the system's error contains the path.
	value := "/nowhere/{" + tok + "}.json"
	for _, args := range [][]string{{"--mcp-config", value}, {"--mcp-config=" + value}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			want := "Pass a --mcp-config path that exists on this machine. The check of --mcp-config " +
				"(an --mcp-config value) failed: it is no file"
			_, _, err := walled(t, &fakeWritten{written: t.TempDir()}, args)
			if err == nil || err.Error() != want || strings.Contains(err.Error(), "fake-token-123") {
				t.Errorf("got %v, want %q", err, want)
			}
		})
	}
}

// TestAWalledLaunchsPathsFollowThePathRules pins that a path value of any of the flags
// that starts with "~", is relative or has a ".." part is refused before it is read.
func TestAWalledLaunchsPathsFollowThePathRules(t *testing.T) {
	for _, flag := range []string{"--mcp-config", "--agents", "--plugin-dir", "--plugin-dir-no-mcp", "--add-dir",
		"--system-prompt-file", "--append-system-prompt-file", "--append-subagent-system-prompt-file"} {
		for value, want := range map[string]string{
			"~/ref": "Replace ~/ref with an absolute path. This launch passes " + flag + " ~/ref, and inside the wall ~ is " +
				"the home of the wall's user, which Forager cannot check, so the run does not start.",
			"~": "Replace ~ with an absolute path. This launch passes " + flag + " ~, and inside the wall ~ is " +
				"the home of the wall's user, which Forager cannot check, so the run does not start.",
			"mcp.json": "Replace mcp.json with an absolute path outside the workspace. This launch passes " + flag +
				" mcp.json, a relative path that Claude Code reads from the workspace, which a walled run can write, " +
				"so the run does not start.",
			"./x": "Replace ./x with an absolute path outside the workspace. This launch passes " + flag +
				" ./x, a relative path that Claude Code reads from the workspace, which a walled run can write, " +
				"so the run does not start.",
			"/a/../b.json": `Pass the path /a/../b.json without "..". This launch passes ` + flag +
				` /a/../b.json, and the path has a ".." part, so the run does not start.`,
		} {
			for _, args := range [][]string{{flag, value}, {flag + "=" + value}} {
				t.Run(strings.Join(args, " "), func(t *testing.T) {
					f := &fakeWritten{written: t.TempDir()}
					if _, _, err := walled(t, f, args); err == nil || err.Error() != want {
						t.Errorf("got %v, want %q", err, want)
					}
					if len(f.asked) > 0 {
						t.Errorf("Readable was asked of %q", f.asked)
					}
				})
			}
		}
	}
}

// TestAWalledLaunchsFileIsReadAsTheSettingsAre pins that a file of --mcp-config or
// --agents is read only when it is no link as its last part, a regular file, at most
// 1 MiB, and the file Readable judged, with the reason in the text.
func TestAWalledLaunchsFileIsReadAsTheSettingsAre(t *testing.T) {
	dir := t.TempDir()
	plain := writeFile(t, filepath.Join(dir, "plain.json"), "{}")
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(plain, link); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "dir.json")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	big := writeFile(t, filepath.Join(dir, "big.json"), `{"x":"`+strings.Repeat("a", 1<<20)+`"}`)
	other := func(string) (string, error) { return filepath.EvalSymlinks(big) }
	for _, flag := range []string{"--mcp-config", "--agents", "--system-prompt-file", "--append-system-prompt-file",
		"--append-subagent-system-prompt-file"} {
		for _, c := range []struct {
			name, file  string
			readable    func(string) (string, error)
			reason, fix string
		}{
			{"a link", link, nil, "is a link", "Pass the path of the file that " + link + " links to."},
			{"a directory", sub, nil, "is not a regular file", "Pass a " + flag + " path to a regular file."},
			{"larger than 1 MiB", big, nil, "is larger than 1048576 bytes", "Pass a " + flag + " file of at most 1048576 bytes (1 MiB)."},
			{"not the file judged", plain, other, "changed while it was checked",
				"Start the run again when no process is writing " + plain + "."},
		} {
			t.Run(flag+" "+c.name, func(t *testing.T) {
				_, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
					Launch: runtimes.Launch{Args: []string{flag, c.file}}, RunDir: t.TempDir(), Forwarder: []string{"q"},
					Walled: true, Readable: c.readable,
				})
				want := c.fix + " This launch passes " + flag + " " + c.file + ", and that file " + c.reason + ", so the run does not start."
				if err == nil || err.Error() != want {
					t.Errorf("got %v, want %q", err, want)
				}
			})
		}
		t.Run(flag+" a file that does not exist", func(t *testing.T) {
			absent := filepath.Join(dir, "absent.json")
			_, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
				Launch: runtimes.Launch{Args: []string{flag, absent}}, RunDir: t.TempDir(), Forwarder: []string{"q"}, Walled: true,
			})
			prefix := "Pass a " + flag + " path that exists on this machine. The check of " + flag + " " + absent + " failed: "
			if err == nil || !strings.HasPrefix(err.Error(), prefix) || !errors.Is(err, os.ErrNotExist) {
				t.Errorf("got %v", err)
			}
		})
	}
}

// TestAWalledLaunchsOtherReasonsComeWithAFix pins the fix that leads the text of a file
// the check could not read for any other reason: access for a path the check had no
// permission for, and otherwise the error at the end of the text.
func TestAWalledLaunchsOtherReasonsComeWithAFix(t *testing.T) {
	t.Run("no permission", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a directory of mode 0")
		}
		// The path is resolved first, so the path in the error is the one passed.
		dir, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		locked := filepath.Join(dir, "locked")
		f := writeFile(t, filepath.Join(locked, "mcp.json"), "{}")
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
		_, err = claude.Settings([]string{"Stop"}, runtimes.Attach{
			Launch: runtimes.Launch{Args: []string{"--mcp-config", f}}, RunDir: t.TempDir(), Forwarder: []string{"q"}, Walled: true,
		})
		prefix := "Give the user that runs Forager access to " + f + ", or pass another --mcp-config path. " +
			"The check of --mcp-config " + f + " failed: "
		if err == nil || !strings.HasPrefix(err.Error(), prefix) || !errors.Is(err, os.ErrPermission) {
			t.Errorf("got %v, want the prefix %q", err, prefix)
		}
	})
	t.Run("any other error", func(t *testing.T) {
		f := writeFile(t, filepath.Join(t.TempDir(), "mcp.json"), "{}")
		failed := errors.New("the registry could not be read")
		_, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
			Launch: runtimes.Launch{Args: []string{"--mcp-config", f}}, RunDir: t.TempDir(), Forwarder: []string{"q"},
			Walled: true, Readable: func(string) (string, error) { return "", failed },
		})
		want := "Fix the error at the end of this message, or pass another --mcp-config path. " +
			"The check of --mcp-config " + f + " failed: the registry could not be read"
		if err == nil || err.Error() != want || !errors.Is(err, failed) {
			t.Errorf("got %v, want %q", err, want)
		}
	})
}
