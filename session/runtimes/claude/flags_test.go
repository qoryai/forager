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
	return "This launch passes --mcp-config " + file + ", and that file lies in " + place +
		", which a walled run can write, so the run does not start. Move the file to a directory no walled run writes, " +
		"or pass the servers as a JSON string."
}

// agentsInWork is the refusal of an --agents file in a place a walled run can write.
func agentsInWork(file, place string) string {
	return "This launch passes --agents " + file + ", and that file lies in " + place +
		", which a walled run can write, so the run does not start. Move the file to a directory no walled run writes, " +
		"or pass the agents as a JSON object."
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
	want := "This launch passes --mcp-config " + file + ", and that file is reached through /work, which a walled run can write, " +
		"so the run does not start. Move the file to a directory no walled run writes, or pass the servers as a JSON string."
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
// with "{" after white space or parses as JSON. Any other value is a path.
func TestAWalledLaunchsInlineJSONPassesAsItIs(t *testing.T) {
	relative := func(flag, v string) string {
		return "This launch passes " + flag + " " + v + ", a relative path that Claude Code reads from the workspace, " +
			"which a walled run can write, so the run does not start. Pass an absolute path outside the workspace."
	}
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
		{"--mcp-config", " {}", false},
		{"--agents", `{"reviewer":{"description":"d","prompt":"p"}}`, true},
		{"--agents", "{", true},
		{"--agents", "  {", true},
		{"--agents", "[1]", true},
		{"--agents", "null", true},
		{"--agents", "agents.json", false},
	} {
		t.Run(c.flag+" "+c.value, func(t *testing.T) {
			f := &fakeWritten{written: t.TempDir()}
			args := []string{"-p", "hi", c.flag, c.value}
			got, _, err := walled(t, f, args)
			if !c.inline {
				if want := relative(c.flag, c.value); err == nil || err.Error() != want {
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

// TestAWalledLaunchsPathsFollowThePathRules pins that a path value of any of the flags
// that starts with "~", is relative or has a ".." part is refused before it is read.
func TestAWalledLaunchsPathsFollowThePathRules(t *testing.T) {
	for _, flag := range []string{"--mcp-config", "--agents", "--plugin-dir", "--plugin-dir-no-mcp", "--add-dir"} {
		for value, want := range map[string]string{
			"~/ref": "This launch passes " + flag + " ~/ref, and inside the wall ~ is the home of the wall's user, " +
				"which Forager cannot check, so the run does not start. Pass an absolute path.",
			"~": "This launch passes " + flag + " ~, and inside the wall ~ is the home of the wall's user, " +
				"which Forager cannot check, so the run does not start. Pass an absolute path.",
			"mcp.json": "This launch passes " + flag + " mcp.json, a relative path that Claude Code reads from the workspace, " +
				"which a walled run can write, so the run does not start. Pass an absolute path outside the workspace.",
			"./x": "This launch passes " + flag + " ./x, a relative path that Claude Code reads from the workspace, " +
				"which a walled run can write, so the run does not start. Pass an absolute path outside the workspace.",
			"/a/../b.json": "This launch passes " + flag + ` /a/../b.json, and the path has a ".." part, so the run does not start. ` +
				`Pass the path without "..".`,
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
	for _, flag := range []string{"--mcp-config", "--agents"} {
		for _, c := range []struct {
			name, file string
			readable   func(string) (string, error)
			reason     string
		}{
			{"a link", link, nil, "is a link"},
			{"a directory", sub, nil, "is not a regular file"},
			{"larger than 1 MiB", big, nil, "is larger than 1048576 bytes"},
			{"not the file judged", plain, other, "changed while it was checked"},
		} {
			t.Run(flag+" "+c.name, func(t *testing.T) {
				_, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
					Launch: runtimes.Launch{Args: []string{flag, c.file}}, RunDir: t.TempDir(), Forwarder: []string{"q"},
					Walled: true, Readable: c.readable,
				})
				want := "This launch passes " + flag + " " + c.file + ", and that file " + c.reason + ", so the run does not start."
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
			if err == nil || !strings.HasPrefix(err.Error(), flag+" "+absent+": ") || !errors.Is(err, os.ErrNotExist) {
				t.Errorf("got %v", err)
			}
		})
	}
}
