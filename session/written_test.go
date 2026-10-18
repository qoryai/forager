package session_test

import (
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
