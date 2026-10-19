package session_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/claude"
	"github.com/qoryai/forager/wall"
)

// TestAFileInAWrittenPlaceIsNotReadable pins which files a runtime may read from this
// machine: none whose path, as given or through links, is or lies inside a place a
// walled run could have written, the place taken as given and through links, by whole
// names and regardless of case, and none whose names are looked up on the way in such a
// place, through a link in it that leads out of it say.
func TestAFileInAWrittenPlaceIsNotReadable(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"ws/sub", "ws2", "other", "safe"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p := func(rel string) string { return filepath.Join(root, rel) }
	for _, f := range []string{"ws/settings.json", "ws/sub/settings.json", "ws2/settings.json", "other/settings.json"} {
		if err := os.WriteFile(p(f), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// into leads into the place from outside it, out leads out of it from inside, and
	// place is a link the place is reached through.
	for link, to := range map[string]string{"safe/into": p("ws"), "ws/out": p("other"), "place": p("ws")} {
		if err := os.Symlink(to, p(link)); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name, place, path string
		refused           bool
	}{
		{"a file in the place", p("ws"), p("ws/settings.json"), true},
		{"a file below the place", p("ws"), p("ws/sub/settings.json"), true},
		{"the place itself", p("ws"), p("ws"), true},
		{"a file that does not exist yet", p("ws"), p("ws/later/settings.json"), true},
		{"unclean", p("ws"), p("ws") + "/./sub//settings.json", true},
		{"a link in a parent that leads into the place", p("ws"), p("safe/into/settings.json"), true},
		{"a link in the place that leads out of it", p("ws"), p("ws/out/settings.json"), true},
		{"a place reached through a link", p("place"), p("ws/settings.json"), true},
		{"a place reached through a link, the path through it", p("ws"), p("place/settings.json"), true},
		{"a place in another case", p("WS"), p("ws/settings.json"), true},
		{"a path in another case", p("ws"), p("Ws/Sub/settings.json"), true},
		{"a place that does not exist yet", p("ws/later"), p("ws/LATER/x/settings.json"), true},
		{"the filesystem's root", "/", p("other/settings.json"), true},
		{"a sibling with the place as prefix", p("ws"), p("ws2/settings.json"), false},
		{"a file outside every place", p("ws"), p("other/settings.json"), false},
		{"a path that goes through a link in the place and leads out of it", p("ws"), p("safe/into/out/settings.json"), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := session.Readable([]string{c.place})(c.path)
			if c.refused != (err != nil) {
				t.Fatalf("Readable(%q) for %q: %v", c.path, c.place, err)
			}
			if err != nil && !strings.Contains(err.Error(), c.place+", which a walled run can write") {
				t.Errorf("the refusal: %v", err)
			}
		})
	}
	want, err := filepath.EvalSymlinks(p("ws/settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := session.Readable(nil)(p("ws/settings.json")); err != nil || got != want {
		t.Errorf("no places: %q, %v, want %q", got, err, want)
	}
}

// TestASettingsFileAWalledRunCouldWriteIsNoRun pins that the session refuses the
// settings a launch passes when they lie in a place a walled run could have written:
// a place of Spec.Written, with or without a wall, and behind a wall the run's
// workspace and its writable mounts. The run stops before the wall is prepared. A
// read-only mount is no such place.
func TestASettingsFileAWalledRunCouldWriteIsNoRun(t *testing.T) {
	settingsIn := func(t *testing.T, sp *session.Spec, dir string) string {
		t.Helper()
		f := filepath.Join(dir, "launch-settings.json")
		if err := os.WriteFile(f, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		sp.Args = []string{"--settings", f}
		return f
	}
	t.Run("the workspace of a walled run", func(t *testing.T) {
		w := &openWall{}
		sp := spec(t, "FAKE_EXIT=0")
		sp.Wall, sp.Image = w, "example.com/agent:1"
		f := settingsIn(t, &sp, sp.Dir)
		err := runErr(sp)
		if err == nil || !strings.Contains(err.Error(), "runtime claude: settings "+f+": it lies in "+sp.Dir+", which a walled run can write") {
			t.Errorf("the run: %v", err)
		}
		if w.req.RunID != "" || w.wrapped {
			t.Errorf("the wall was prepared or wrapped: %+v", w.req)
		}
	})
	t.Run("a writable mount of a walled run", func(t *testing.T) {
		sp := spec(t, "FAKE_EXIT=0")
		mount := t.TempDir()
		sp.Wall, sp.Image, sp.Mounts = &openWall{}, "example.com/agent:1", []wall.Mount{{Path: mount}}
		settingsIn(t, &sp, mount)
		if err := runErr(sp); err == nil || !strings.Contains(err.Error(), "it lies in "+mount+",") {
			t.Errorf("the run: %v", err)
		}
	})
	t.Run("a read-only mount of a walled run", func(t *testing.T) {
		t.Setenv("QORY_TEST_HOST_ONLY", "1")
		sp := spec(t, "FAKE_EXIT=0")
		mount := t.TempDir()
		sp.Wall, sp.Image, sp.Mounts = &openWall{}, "example.com/agent:1", []wall.Mount{{Path: mount, ReadOnly: true}}
		settingsIn(t, &sp, mount)
		if res, err := runWithSettingsEnv(t, sp); err != nil || res.ExitCode != 0 {
			t.Errorf("the run: %+v, %v", res, err)
		}
	})
	t.Run("a place of Spec.Written without a wall", func(t *testing.T) {
		sp := spec(t, "FAKE_EXIT=0")
		place := t.TempDir()
		sp.Written = []string{place}
		settingsIn(t, &sp, place)
		if err := runErr(sp); err == nil || !strings.Contains(err.Error(), "it lies in "+place+",") {
			t.Errorf("the run: %v", err)
		}
	})
	t.Run("a file outside Spec.Written without a wall", func(t *testing.T) {
		sp := spec(t, "FAKE_EXIT=0")
		sp.Written = []string{t.TempDir()}
		settingsIn(t, &sp, t.TempDir())
		if res, err := runWithSettingsEnv(t, sp); err != nil || res.ExitCode != 0 {
			t.Errorf("the run: %+v, %v", res, err)
		}
	})
}

// TestAWalledLaunchThatPassesSettingsTwiceIsNoRun pins that a walled run whose launch
// passes --settings twice, each a file no walled run could write, stops before the
// wall is prepared, with the runtime's refusal.
func TestAWalledLaunchThatPassesSettingsTwiceIsNoRun(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first.json"), filepath.Join(dir, "second.json")
	for _, f := range []string{first, second} {
		if err := os.WriteFile(f, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w := &openWall{}
	sp := spec(t, "FAKE_EXIT=0")
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.Args = []string{"--settings", first, "--settings=" + second}
	want := "runtime claude: This launch passes --settings more than once, and Claude Code reads only the last one, " +
		"so the run does not start. Pass one --settings file."
	if err := runErr(sp); err == nil || err.Error() != want {
		t.Errorf("the run: %v, want %q", err, want)
	}
	if w.req.RunID != "" || w.wrapped {
		t.Errorf("the wall was prepared or wrapped: %+v", w.req)
	}
}

// TestASettingsFileInAnotherWalledRunsBindIsNoRun pins that the settings a launch
// passes are refused while they lie in a writable bind of another walled run still
// going, with or without a wall for this run, and read once that run has ended.
func TestASettingsFileInAnotherWalledRunsBindIsNoRun(t *testing.T) {
	m := t.TempDir()
	resolved, err := filepath.EvalSymlinks(m)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(m, "launch-settings.json")
	if err := os.WriteFile(f, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, finish := hold(t, []wall.Mount{{Path: m}}, m)
	for _, walled := range []bool{false, true} {
		sp := spec(t, "FAKE_EXIT=0")
		if walled {
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		}
		sp.Args = []string{"--settings", f}
		want := "runtime claude: settings " + f + ": it lies in " + resolved + ", which a walled run can write"
		if err := runErr(sp); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("walled %v: %v", walled, err)
		}
	}
	finish()
	sp := spec(t, "FAKE_EXIT=0")
	sp.Args = []string{"--settings", f}
	if res, err := runWithSettingsEnv(t, sp); err != nil || res.ExitCode != 0 {
		t.Errorf("after the other run ended: %+v, %v", res, err)
	}
}

// TestASettingsFileInABindThatRecordsNoModeIsNoRun pins that a bind of another walled
// run whose entry records no writable field for it counts as writable: the settings a
// launch passes are refused while they lie in it, and read once the bind is recorded
// read-only.
func TestASettingsFileInABindThatRecordsNoModeIsNoRun(t *testing.T) {
	m := t.TempDir()
	f := filepath.Join(m, "launch-settings.json")
	if err := os.WriteFile(f, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	file := bound(t, bind{m, resolved(t, m), ""})
	rebind(t, file, 0, func(b map[string]any) { delete(b, "writable") })
	sp := spec(t, "FAKE_EXIT=0")
	sp.Args = []string{"--settings", f}
	want := "runtime claude: settings " + f + ": it lies in " + resolved(t, m) +
		", which a walled run can write"
	if err := runErr(sp); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("a bind that records no mode: %v", err)
	}
	readOnly(t, file, 0)
	sp = spec(t, "FAKE_EXIT=0")
	sp.Args = []string{"--settings", f}
	if res, err := runWithSettingsEnv(t, sp); err != nil || res.ExitCode != 0 {
		t.Errorf("a read-only bind: %+v, %v", res, err)
	}
}

// TestAPathWithADotDotIsNotReadable pins that a path with a ".." name is refused, by
// Readable and by the installer it is given to: the system applies ".." after the link
// before it, so the clean path the check would judge names another file than the one
// opened. Each of these opens a file of the written place, though its clean path lies
// outside it.
func TestAPathWithADotDotIsNotReadable(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := func(rel string) string { return filepath.Join(root, rel) }
	mkdirs(t, p("ws/sub"), p("ws/a/b"), p("outside"))
	ws, outside := p("ws"), p("outside")
	for _, f := range []string{"ws/settings.json", "outside/settings.json", "ws/cfg.json", "cfg.json"} {
		if err := os.WriteFile(p(f), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// current, outside every place, leads into the written place; inner, inside it,
	// leads deeper into it.
	symlink(t, p("ws/sub"), p("outside/current"))
	symlink(t, p("ws/a/b"), p("ws/inner"))
	t.Chdir(outside)
	for name, path := range map[string]string{
		"after a link that leads into the place": p("outside/current") + "/../settings.json",
		"relative, after a link":                 "current/../settings.json",
		"after a link inside the place":          p("ws/inner") + "/../../cfg.json",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := session.Readable([]string{ws})(path); err == nil || err.Error() != `it has a ".." part` {
				t.Errorf("Readable: %v", err)
			}
			_, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
				Launch:   runtimes.Launch{Command: "claude", Args: []string{"--settings", path}},
				RunDir:   t.TempDir(),
				Readable: session.Readable([]string{ws}),
			})
			if want := "settings " + path + `: it has a ".." part`; err == nil || err.Error() != want {
				t.Errorf("the installer: %v, want %q", err, want)
			}
		})
	}
}

// TestARunWithoutASettingsFileLeavesTheRegistryAlone pins that the places are worked
// out only when a file is to be read: a run that passes no settings file, or passes
// them as a document, never reads the registry of walled runs, and starts where the
// registry cannot be opened; one that passes a file does not.
func TestARunWithoutASettingsFileLeavesTheRegistryAlone(t *testing.T) {
	notDir := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(notDir, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", notDir)
	for name, args := range map[string][]string{
		"no settings":            {"-p", "hi"},
		"settings in a document": {"--settings", `{"permissions":{}}`},
	} {
		t.Run(name, func(t *testing.T) {
			sp := spec(t, "FAKE_EXIT=0")
			sp.Args = args
			if res, err := runWithSettingsEnv(t, sp); err != nil || res.ExitCode != 0 {
				t.Errorf("the run: %+v, %v", res, err)
			}
		})
	}
	sp := spec(t, "FAKE_EXIT=0")
	if err := runErr(sp); err == nil || !strings.Contains(err.Error(), "the registry of walled runs") {
		t.Errorf("a run with a settings file: %v", err)
	}
}

// TestADirectoryThatHoldsAWrittenPlaceIsNotReadable pins the check of a directory a
// runtime passes to its program, in both directions: it is refused as a file is, when
// it lies in or is reached through a place a walled run could have written, and also
// when such a place is it or lies inside it, as given or through links, by whole names
// and regardless of case.
func TestADirectoryThatHoldsAWrittenPlaceIsNotReadable(t *testing.T) {
	root := t.TempDir()
	p := func(rel string) string { return filepath.Join(root, rel) }
	mkdirs(t, p("home/p/work"), p("home/q"), p("ws"), p("safe"), p("home/p2"))
	// into leads into the place from outside it, and home-link is a link a directory
	// is passed through.
	symlink(t, p("ws"), p("safe/into"))
	symlink(t, p("home/p"), p("home-link"))
	for _, c := range []struct {
		name, place, dir, how string
	}{
		{"a place inside the directory", p("home/p/work"), p("home/p"), "contains"},
		{"a place deeper inside", p("home/p/work/later"), p("home"), "contains"},
		{"a place inside, in another case", p("Home/P/Work"), p("home/p"), "contains"},
		{"the directory passed in another case", p("home/p/work"), p("HOME/P"), "contains"},
		{"a place inside, the directory through a link", p("home/p/work"), p("home-link"), "contains"},
		{"a place inside, through a link", p("home-link/work"), p("home/p"), "contains"},
		{"the filesystem's root holds every place", p("ws"), "/", "contains"},
		{"the directory is the place", p("ws"), p("ws"), "lies in"},
		{"the directory lies in the place", p("home"), p("home/q"), "lies in"},
		{"the directory is reached through the place", p("safe"), p("safe/into"), "lies in"},
		{"a link to the place", p("ws"), p("safe/into"), "lies in"},
		{"a sibling with the place as prefix", p("home/p"), p("home/p2"), ""},
		{"a directory beside the place", p("home/p/work"), p("home/q"), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := session.ReadableDir([]string{c.place})(c.dir)
			if c.how == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			var written *runtimes.WrittenError
			if !errors.As(err, &written) || written.How != c.how || written.Place != c.place {
				t.Errorf("ReadableDir(%q) for %q: %v, want it %s the place", c.dir, c.place, err, c.how)
			}
		})
	}
	want, err := filepath.EvalSymlinks(p("home/p"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := session.ReadableDir(nil)(p("home-link")); err != nil || got != want {
		t.Errorf("no places: %q, %v, want %q", got, err, want)
	}
}

// TestAWalledLaunchsMCPConfigInAWrittenPlaceIsNoRun pins that a walled run whose launch
// passes --mcp-config with a file in its workspace, or reached through a link in it,
// stops before the wall is prepared, with the runtime's text; and that a file outside
// every such place is passed as a copy in the run directory.
func TestAWalledLaunchsMCPConfigInAWrittenPlaceIsNoRun(t *testing.T) {
	t.Run("in the workspace", func(t *testing.T) {
		w := &openWall{}
		sp := spec(t, "FAKE_EXIT=0")
		sp.Wall, sp.Image = w, "example.com/agent:1"
		f := filepath.Join(sp.Dir, "mcp.json")
		if err := os.WriteFile(f, []byte(`{"mcpServers":{}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		sp.Args = append(sp.Args, "--mcp-config", f)
		want := "runtime claude: This launch passes --mcp-config " + f + ", and that file lies in " + sp.Dir +
			", which a walled run can write, so the run does not start. Move the file to a directory no walled run writes, " +
			"or pass the servers as a JSON string."
		if err := runErr(sp); err == nil || err.Error() != want {
			t.Errorf("the run: %v, want %q", err, want)
		}
		if w.req.RunID != "" || w.wrapped {
			t.Errorf("the wall was prepared or wrapped: %+v", w.req)
		}
	})
	t.Run("reached through the workspace", func(t *testing.T) {
		sp := spec(t, "FAKE_EXIT=0")
		sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "mcp.json"), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		// into, outside the workspace, leads into it, and out, in it, leads out of it.
		safe := t.TempDir()
		symlink(t, sp.Dir, filepath.Join(safe, "into"))
		symlink(t, outside, filepath.Join(sp.Dir, "out"))
		f := filepath.Join(safe, "into", "out", "mcp.json")
		sp.Args = append(sp.Args, "--mcp-config="+f)
		want := "runtime claude: This launch passes --mcp-config " + f + ", and that file is reached through " + sp.Dir +
			", which a walled run can write, so the run does not start. Move the file to a directory no walled run writes, " +
			"or pass the servers as a JSON string."
		if err := runErr(sp); err == nil || err.Error() != want {
			t.Errorf("the run: %v, want %q", err, want)
		}
	})
	t.Run("outside every written place", func(t *testing.T) {
		t.Setenv("QORY_TEST_HOST_ONLY", "1")
		sp := spec(t, "FAKE_EXIT=0")
		mount := t.TempDir()
		sp.Wall, sp.Image, sp.Mounts = &openWall{}, "example.com/agent:1", []wall.Mount{{Path: mount, ReadOnly: true}}
		f := filepath.Join(mount, "mcp.json")
		if err := os.WriteFile(f, []byte(`{"mcpServers":{}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		sp.Args = append(sp.Args, "--mcp-config", f)
		res, err := runWithSettingsEnv(t, sp)
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("the run: %+v, %v", res, err)
		}
		if b, err := os.ReadFile(filepath.Join(res.Dir, "mcp-config-1.json")); err != nil || string(b) != `{"mcpServers":{}}` {
			t.Errorf("the copy: %s, %v", b, err)
		}
	})
}

// qoryHome makes a harness home as qory renders one for Claude Code in a new directory:
// a plugin whose skill and command are links to the module's files under module, an
// agent copied, the settings, the servers and the launch's instructions. It returns the
// home and the launch's arguments, qory's four flags and --setting-sources.
func qoryHome(t *testing.T, module string) (string, []string) {
	t.Helper()
	home := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		mkdirs(t, filepath.Dir(path))
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(module, "skills", "review", "SKILL.md"), "# review")
	write(filepath.Join(module, "commands", "ship.md"), "# ship")
	plugin := filepath.Join(home, "plugin")
	write(filepath.Join(plugin, ".claude-plugin", "plugin.json"), `{"name":"harness"}`)
	write(filepath.Join(plugin, "agents", "reviewer.md"), "# reviewer")
	mkdirs(t, filepath.Join(plugin, "skills"), filepath.Join(plugin, "commands"))
	symlink(t, filepath.Join(module, "skills", "review"), filepath.Join(plugin, "skills", "review"))
	symlink(t, filepath.Join(module, "commands", "ship.md"), filepath.Join(plugin, "commands", "ship.md"))
	write(filepath.Join(home, "settings.json"), `{"permissions":{"allow":["Bash"]},"hooks":{"SessionEnd":[{"hooks":[{"type":"command","command":"echo existing"}]}]}}`)
	write(filepath.Join(home, "mcp.json"), `{"mcpServers":{"docs":{"command":"/usr/bin/true"}}}`)
	write(filepath.Join(home, "launch", "CLAUDE.md"), "# launch")
	return home, []string{
		"--plugin-dir", plugin,
		"--settings", filepath.Join(home, "settings.json"),
		"--mcp-config", filepath.Join(home, "mcp.json"),
		"--append-system-prompt-file", filepath.Join(home, "launch", "CLAUDE.md"),
		"--setting-sources", "user",
	}
}

// TestAQoryShapedWalledLaunchStarts pins that a walled launch as qory composes one
// starts when the harness home lies outside the checkout, bound read-only, and its
// module lies outside the checkout too: the servers are passed as a copy in the run
// directory, and the plugin as it is.
func TestAQoryShapedWalledLaunchStarts(t *testing.T) {
	t.Setenv("QORY_TEST_HOST_ONLY", "1")
	sp := spec(t, "FAKE_EXIT=0")
	home, args := qoryHome(t, t.TempDir())
	sp.Wall, sp.Image, sp.Mounts = &openWall{}, "example.com/agent:1", []wall.Mount{{Path: home, ReadOnly: true}}
	sp.Args = args
	res, err := runWithSettingsEnv(t, sp)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("the run: %+v, %v", res, err)
	}
	b, err := os.ReadFile(filepath.Join(res.Dir, "mcp-config-1.json"))
	if want, _ := os.ReadFile(filepath.Join(home, "mcp.json")); err != nil || string(b) != string(want) {
		t.Errorf("the copy of the servers: %s, %v", b, err)
	}
}

// TestAQoryShapedWalledLaunchWithAModuleInTheCheckoutIsNoRun pins that a walled launch
// as qory composes one, whose module lies in the checkout, as source: {path: ./harness}
// puts it, does not start: the plugin's skill is a link into the workspace.
func TestAQoryShapedWalledLaunchWithAModuleInTheCheckoutIsNoRun(t *testing.T) {
	w := &openWall{}
	sp := spec(t, "FAKE_EXIT=0")
	home, args := qoryHome(t, filepath.Join(sp.Dir, "harness"))
	sp.Wall, sp.Image, sp.Mounts = w, "example.com/agent:1", []wall.Mount{{Path: home, ReadOnly: true}}
	sp.Args = args
	plugin := filepath.Join(home, "plugin")
	want := "runtime claude: This launch passes --plugin-dir " + plugin + ", and its link " +
		filepath.Join(plugin, "commands", "ship.md") + " leads into " + sp.Dir + ", which a walled run can write, " +
		"so the run does not start. Replace the link with a copy, or move what it leads to out of " + sp.Dir + "."
	if err := runErr(sp); err == nil || err.Error() != want {
		t.Errorf("the run: %v, want %q", err, want)
	}
	if w.req.RunID != "" || w.wrapped {
		t.Errorf("the wall was prepared or wrapped: %+v", w.req)
	}
}

// TestAWalledLaunchsAddDirIsJudgedByItsPlace pins that a walled launch's --add-dir in
// the workspace is refused with the runtime's text, and that one in a read-only mount
// starts.
func TestAWalledLaunchsAddDirIsJudgedByItsPlace(t *testing.T) {
	t.Run("in the workspace", func(t *testing.T) {
		sp := spec(t, "FAKE_EXIT=0")
		sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		ref := mkdirs(t, filepath.Join(sp.Dir, "ref"))
		sp.Args = append(sp.Args, "--add-dir", ref)
		want := "runtime claude: This launch passes --add-dir " + ref + ", and that directory lies in " + sp.Dir +
			", which a walled run can write, so the run does not start. Remove --add-dir " + ref +
			", or add a directory no walled run writes."
		if err := runErr(sp); err == nil || err.Error() != want {
			t.Errorf("the run: %v, want %q", err, want)
		}
	})
	t.Run("a read-only mount", func(t *testing.T) {
		t.Setenv("QORY_TEST_HOST_ONLY", "1")
		sp := spec(t, "FAKE_EXIT=0")
		mount := t.TempDir()
		mkdirs(t, filepath.Join(mount, ".claude"))
		if err := os.WriteFile(filepath.Join(mount, ".claude", "settings.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		sp.Wall, sp.Image, sp.Mounts = &openWall{}, "example.com/agent:1", []wall.Mount{{Path: mount, ReadOnly: true}}
		sp.Args = append(sp.Args, "--add-dir", mount)
		if res, err := runWithSettingsEnv(t, sp); err != nil || res.ExitCode != 0 {
			t.Errorf("the run: %+v, %v", res, err)
		}
	})
	t.Run("a writable mount", func(t *testing.T) {
		sp := spec(t, "FAKE_EXIT=0")
		mount := t.TempDir()
		sp.Wall, sp.Image, sp.Mounts = &openWall{}, "example.com/agent:1", []wall.Mount{{Path: mount}}
		sp.Args = append(sp.Args, "--add-dir", mount)
		if err := runErr(sp); err == nil || !strings.Contains(err.Error(), "and that directory lies in "+mount+",") {
			t.Errorf("the run: %v", err)
		}
	})
}
