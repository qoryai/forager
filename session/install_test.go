package session_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/wall"
)

// installAt installs this binary as a runtime is installed, in dir/rt/bin/claude, a
// copy with no other hard link, with dir/rt a folder others can read and enter and
// only its owner can write, and returns dir/rt.
func installAt(t *testing.T, dir string) string {
	t.Helper()
	rt := filepath.Join(dir, "rt")
	bin := mkdirs(t, filepath.Join(rt, "bin"))
	b, err := os.ReadFile(installedProgram)
	if err != nil {
		t.Fatal(err)
	}
	program := filepath.Join(bin, "claude")
	if err := os.WriteFile(program, b, 0o755); err != nil {
		t.Fatal(err)
	}
	// The mode the files are made with passes through the umask.
	for _, p := range []string{rt, bin, program} {
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return rt
}

// useInstall points sp at the runtime installed in dir: its program, and the folder at
// version 2.1.320.
func useInstall(sp *runSpec, dir string) {
	sp.RuntimeInstall = &session.RuntimeInstall{Dir: dir, Version: "2.1.320"}
	sp.Command = filepath.Join(dir, "bin", "claude")
}

// TestJoinRefusesARuntimeInstallItCannotStart pins each error of a RuntimeInstall
// Join returns before the join request: the first words say what to change, and no
// session starts.
func TestJoinRefusesARuntimeInstallItCannotStart(t *testing.T) {
	for name, c := range map[string]struct {
		change func(t *testing.T, sp *runSpec)
		want   string
	}{
		"a runtime with no install":  {func(_ *testing.T, sp *runSpec) { sp.RuntimeInstall = nil }, "set SessionSpec.RuntimeInstall for a session of the runtime claude"},
		"an install with no runtime": {func(_ *testing.T, sp *runSpec) { sp.Runtime = nil }, "leave SessionSpec.RuntimeInstall unset for a session with no runtime"},
		"a relative folder": {func(_ *testing.T, sp *runSpec) {
			sp.RuntimeInstall.Dir, sp.Command = "rt", "rt/bin/claude"
		}, "set SessionSpec.RuntimeInstall.Dir to an absolute, clean path"},
		"a folder that is not clean": {func(_ *testing.T, sp *runSpec) {
			sp.RuntimeInstall.Dir = sp.RuntimeInstall.Dir + "/../rt"
		}, "set SessionSpec.RuntimeInstall.Dir to an absolute, clean path"},
		"a missing folder": {func(t *testing.T, sp *runSpec) {
			useInstall(sp, filepath.Join(t.TempDir(), "none"))
		}, "install the runtime in"},
		"a file for a folder": {func(t *testing.T, sp *runSpec) {
			useInstall(sp, sp.Command)
		}, "set SessionSpec.RuntimeInstall.Dir to the runtime's folder"},
		"a folder others cannot enter": {func(t *testing.T, sp *runSpec) {
			if err := os.Chmod(sp.RuntimeInstall.Dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}, "let others read and enter"},
		"a folder on the way others cannot read": {func(t *testing.T, sp *runSpec) {
			if err := os.Chmod(filepath.Dir(sp.Command), 0o711); err != nil {
				t.Fatal(err)
			}
		}, "let others read and enter"},
		"a program outside the folder": {func(_ *testing.T, sp *runSpec) { sp.Command = installedProgram }, "set SessionSpec.Command to a program inside SessionSpec.RuntimeInstall.Dir"},
		"the folder as the program":    {func(_ *testing.T, sp *runSpec) { sp.Command = sp.RuntimeInstall.Dir }, "set SessionSpec.Command to a program inside SessionSpec.RuntimeInstall.Dir"},
		"a program by name":            {func(_ *testing.T, sp *runSpec) { sp.Command = "claude" }, "set SessionSpec.Command to a program inside SessionSpec.RuntimeInstall.Dir"},
		"a program out through ..": {func(_ *testing.T, sp *runSpec) {
			sp.Command = sp.RuntimeInstall.Dir + "/../../" + filepath.Base(sp.RuntimeInstall.Dir)
		}, "set SessionSpec.Command to a program inside SessionSpec.RuntimeInstall.Dir"},
		// x leads into the workspace: the clean path is the installed program, and the
		// path as given would start the workspace's file.
		"a program through a link and ..": {func(t *testing.T, sp *runSpec) {
			ws := mkdirs(t, filepath.Join(sp.Dir, "x"))
			if err := os.Symlink(ws, filepath.Join(sp.RuntimeInstall.Dir, "x")); err != nil {
				t.Fatal(err)
			}
			sp.Command = sp.RuntimeInstall.Dir + "/x/../bin/claude"
		}, "set SessionSpec.Command to a clean path"},
		"a program with a repeated /": {func(_ *testing.T, sp *runSpec) {
			sp.Command = sp.RuntimeInstall.Dir + "/bin//claude"
		}, "set SessionSpec.Command to a clean path"},
		"a folder others may write": {func(t *testing.T, sp *runSpec) {
			if err := os.Chmod(sp.RuntimeInstall.Dir, 0o777); err != nil {
				t.Fatal(err)
			}
		}, `remove the group's and others' write permission from "<dir>"`},
		"a folder on the way its group may write": {func(t *testing.T, sp *runSpec) {
			if err := os.Chmod(filepath.Dir(sp.Command), 0o775); err != nil {
				t.Fatal(err)
			}
		}, `remove the group's and others' write permission from "<dir>/bin"`},
		"a program others may write": {func(t *testing.T, sp *runSpec) {
			if err := os.Chmod(sp.Command, 0o777); err != nil {
				t.Fatal(err)
			}
		}, `remove the group's and others' write permission from "<dir>/bin/claude"`},
		"a program with a second hard link": {func(t *testing.T, sp *runSpec) {
			if err := os.Link(sp.Command, filepath.Join(t.TempDir(), "claude")); err != nil {
				t.Fatal(err)
			}
		}, `copy "<dir>/bin/claude" to a file with no other hard link`},
		"a missing program": {func(_ *testing.T, sp *runSpec) {
			sp.Command = filepath.Join(sp.RuntimeInstall.Dir, "bin", "none")
		}, "install the runtime's program at"},
		"a folder as the program": {func(_ *testing.T, sp *runSpec) {
			sp.Command = filepath.Dir(sp.Command)
		}, "set SessionSpec.Command to the runtime's program, a regular file"},
		"a program others cannot execute": {func(t *testing.T, sp *runSpec) {
			if err := os.Remove(sp.Command); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sp.Command, []byte("#!/bin/sh\n"), 0o754); err != nil {
				t.Fatal(err)
			}
		}, "let others read and execute"},
		"a link to the program inside the folder": {func(t *testing.T, sp *runSpec) {
			link := filepath.Join(filepath.Dir(sp.Command), "link")
			if err := os.Symlink("claude", link); err != nil {
				t.Fatal(err)
			}
			sp.Command = link
		}, "replace the symbolic link"},
		"a link on the way out of the folder": {func(t *testing.T, sp *runSpec) {
			bin := filepath.Dir(sp.Command)
			if err := os.Rename(bin, bin+"-elsewhere"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(bin+"-elsewhere", bin); err != nil {
				t.Fatal(err)
			}
		}, "replace the symbolic link"},
		"no version":       {func(_ *testing.T, sp *runSpec) { sp.RuntimeInstall.Version = "" }, "set SessionSpec.RuntimeInstall.Version to the installed version"},
		"a version with /": {func(_ *testing.T, sp *runSpec) { sp.RuntimeInstall.Version = "2.1/320" }, "set SessionSpec.RuntimeInstall.Version to the installed version"},
		"a version with a space": {func(_ *testing.T, sp *runSpec) {
			sp.RuntimeInstall.Version = "2.1.320 beta"
		}, "set SessionSpec.RuntimeInstall.Version to the installed version"},
		"a version of 65 bytes": {func(_ *testing.T, sp *runSpec) {
			sp.RuntimeInstall.Version = strings.Repeat("1", 65)
		}, "set SessionSpec.RuntimeInstall.Version to the installed version"},
		"a version of -":  {func(_ *testing.T, sp *runSpec) { sp.RuntimeInstall.Version = "-" }, "set SessionSpec.RuntimeInstall.Version to the installed version"},
		"a version of ..": {func(_ *testing.T, sp *runSpec) { sp.RuntimeInstall.Version = ".." }, "set SessionSpec.RuntimeInstall.Version to the installed version"},
		"a folder with a NUL": {func(_ *testing.T, sp *runSpec) {
			sp.RuntimeInstall.Dir += "\x00x"
		}, "set SessionSpec.RuntimeInstall.Dir to an absolute, clean path"},
		"a runtime whose name no folder has": {func(_ *testing.T, sp *runSpec) { sp.Runtime = runtimes.Bare("Other") }, "name the runtime with a lowercase letter"},
		// A runtime that does not require an install still has every check of one it is
		// given.
		"an install a runtime does not require": {func(_ *testing.T, sp *runSpec) {
			sp.Runtime, sp.Command = runtimes.Bare("codex"), installedProgram
		}, "set SessionSpec.Command to a program inside SessionSpec.RuntimeInstall.Dir"},
	} {
		t.Run(name, func(t *testing.T) {
			sp := spec(t, "FAKE_EXIT=0")
			useInstall(&sp, installAt(t, t.TempDir()))
			dir := sp.RuntimeInstall.Dir
			c.change(t, &sp)
			res, err := run(t.Context(), sp)
			want := strings.ReplaceAll(c.want, "<dir>", dir)
			if err == nil || !strings.HasPrefix(err.Error(), want) {
				t.Fatalf("got %+v, %v; want an error that starts %q", res, err, want)
			}
			var r *session.Refusal
			if errors.As(err, &r) {
				t.Errorf("a refusal, %s; want a plain error", r.Code)
			}
		})
	}
}

// TestTheEventShowsTheInstalledVersion pins runtime_version in
// dev.qory.session.started: the version the caller installed, not one of the
// descriptor's, with the program started as the caller gave it without a wall, also
// through a folder that is a link.
func TestTheEventShowsTheInstalledVersion(t *testing.T) {
	dir := installAt(t, t.TempDir())
	link := filepath.Join(t.TempDir(), "current")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for _, folder := range []string{dir, link} {
		sp := spec(t, "FAKE_EXIT=0")
		useInstall(&sp, folder)
		res, err := run(t.Context(), sp)
		if err != nil || res.ExitCode != 0 {
			t.Fatalf("%s: %+v, %v", folder, res, err)
		}
		started := sessionStarted(t, events(t, res))
		if started["runtime_version"] != "2.1.320" || started["command"] != sp.Command {
			t.Errorf("%s: runtime_version %v, command %v", folder, started["runtime_version"], started["command"])
		}
	}

	// A session with no runtime reports no version.
	sp := spec(t, "FAKE_EXIT=0")
	sp.Runtime, sp.RuntimeInstall = nil, nil
	res, err := run(t.Context(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := sessionStarted(t, events(t, res))["runtime_version"]; ok {
		t.Errorf("runtime_version %v for a session with no runtime", v)
	}
}

// TestAWalledRunStartsTheRuntimeFromTheBoundFolder pins the walled launch: the wall
// gets the folder the install leads to and the runtime's name, the program is
// /qory/runtime/claude/bin/claude, the path of the folder is written there in an
// argument and in a variable value, dev.qory.session.started shows the program there,
// and the folder is in the run's entry among the walled runs, read-only.
func TestAWalledRunStartsTheRuntimeFromTheBoundFolder(t *testing.T) {
	t.Setenv("QORY_TEST_HOST_ONLY", "1")
	dir := installAt(t, t.TempDir())
	link := filepath.Join(t.TempDir(), "current")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	w := &openWall{}
	sp := walledSpec(t, w)
	sp.Mounts = []wall.Mount{{Path: sp.Dir}}
	useInstall(&sp, link)
	sp.Args = append(sp.Args, link+"/share/notes.md")
	sp.LaunchFixed = []string{"EXAMPLE_TOOL=" + link + "/bin/tool"}
	res, err := run(t.Context(), sp)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("%+v, %v", res, err)
	}
	if want := (wall.RuntimeFolder{Path: resolved, Name: "claude"}); w.got.Runtime != want {
		t.Errorf("the wall got %+v, want %+v", w.got.Runtime, want)
	}
	const program = "/qory/runtime/claude/bin/claude"
	if !slices.Contains(w.got.Args, program) || !slices.Contains(w.got.Args, "/qory/runtime/claude/share/notes.md") {
		t.Errorf("the launch inside is %q %q", w.got.Command, w.got.Args)
	}
	if !slices.Contains(w.got.Env, "EXAMPLE_TOOL=/qory/runtime/claude/bin/tool") {
		t.Errorf("the environment inside is %q", w.got.Env)
	}
	if words := strings.Join(append([]string{w.got.Command}, w.got.Args...), " "); strings.Contains(words, dir) || strings.Contains(words, link) {
		t.Errorf("the launch inside has the folder's path on this machine: %s", words)
	}
	started := sessionStarted(t, events(t, res))
	if started["command"] != program || started["runtime_version"] != "2.1.320" {
		t.Errorf("command %v, runtime_version %v", started["command"], started["runtime_version"])
	}
}

// TestAPlaceOverTheRuntimeFolderIsNoRun pins the places a walled run lists against the
// installed runtime's folder: a mount that contains the folder or lies inside it,
// either mode, and a writable mount that contains a link on the way to it, are
// mount_contains_forager_files, and the wall wraps nothing.
func TestAPlaceOverTheRuntimeFolderIsNoRun(t *testing.T) {
	for name, place := range map[string]func(t *testing.T, sp *runSpec) wall.Mount{
		"a mount that contains it": func(t *testing.T, sp *runSpec) wall.Mount {
			return wall.Mount{Path: filepath.Dir(sp.RuntimeInstall.Dir), ReadOnly: true}
		},
		"a mount inside it": func(t *testing.T, sp *runSpec) wall.Mount {
			return wall.Mount{Path: filepath.Join(sp.RuntimeInstall.Dir, "bin"), ReadOnly: true}
		},
		"a writable mount with a link on the way": func(t *testing.T, sp *runSpec) wall.Mount {
			m := t.TempDir()
			if err := os.Symlink(filepath.Dir(sp.RuntimeInstall.Dir), filepath.Join(m, "l")); err != nil {
				t.Fatal(err)
			}
			useInstall(sp, filepath.Join(m, "l", "rt"))
			return wall.Mount{Path: m}
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := &openWall{}
			sp := walledSpec(t, w)
			useInstall(&sp, installAt(t, t.TempDir()))
			sp.Mounts = []wall.Mount{{Path: sp.Dir}, place(t, &sp)}
			refusalOf(t, "mount_contains_forager_files", runErr(sp))
			if w.wrapped {
				t.Error("the enclosure was wrapped")
			}
		})
	}
}

// TestAFolderAWalledRunWritesIsNoRuntime pins the install against the places walled
// runs write: a folder that lies in one of SessionSpec.Written, or that contains one,
// fails the session, walled or not.
func TestAFolderAWalledRunWritesIsNoRuntime(t *testing.T) {
	for _, walled := range []bool{false, true} {
		for name, written := range map[string]func(dir string) string{
			"lies in":  filepath.Dir,
			"contains": func(dir string) string { return filepath.Join(dir, "bin") },
		} {
			w := &openWall{}
			sp := spec(t, "FAKE_EXIT=0")
			if walled {
				sp = walledSpec(t, w)
				sp.Mounts = []wall.Mount{{Path: sp.Dir}}
			}
			dir := installAt(t, t.TempDir())
			useInstall(&sp, dir)
			sp.Written = []string{written(dir)}
			_, err := run(t.Context(), sp)
			if err == nil || !strings.HasPrefix(err.Error(), "install the runtime in a folder no walled run can write") {
				t.Errorf("walled %v, %s: %v", walled, name, err)
			}
			if w.wrapped {
				t.Errorf("walled %v, %s: the enclosure was wrapped", walled, name)
			}
		}
	}
}

// TestTheRuntimeFolderAgainstAnotherWalledRun pins the folder against the walled runs
// still going: a run whose folder lies inside another run's writable bind fails with
// a plain error; a writable mount over a folder another run binds is
// mount_shared_with_run; two runs bind one folder read-only side by side.
func TestTheRuntimeFolderAgainstAnotherWalledRun(t *testing.T) {
	root := t.TempDir()
	dir := installAt(t, root)
	_, finish := hold(t, []wall.Mount{{Path: root}}, root)
	w := &openWall{}
	sp := walledSpec(t, w)
	sp.Mounts = []wall.Mount{{Path: sp.Dir}}
	useInstall(&sp, dir)
	err := runErr(sp)
	var r *session.Refusal
	if err == nil || errors.As(err, &r) || !strings.HasPrefix(err.Error(), "the runtime's installed folder "+dir+" lies inside the writable bind "+root) {
		t.Errorf("got %v", err)
	}
	if w.wrapped {
		t.Error("the enclosure was wrapped")
	}
	finish()

	// The first run binds the folder; a second run that mounts its parent writable is
	// refused, and one that binds the same folder starts.
	first := walledSpec(t, newHoldingWall())
	useInstall(&first, dir)
	held, finishFirst := holdSpec(t, first)
	other := walledSpec(t, &openWall{})
	other.Mounts, other.Dir = []wall.Mount{{Path: root}}, root
	r = refusalOf(t, "mount_shared_with_run", runErr(other))
	// The registry has the folder Dir leads to.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Detail, "contains the runtime's installed folder "+resolved+" of the walled run "+held) {
		t.Errorf("detail %q", r.Detail)
	}
	same := walledSpec(t, &openWall{})
	same.Mounts = []wall.Mount{{Path: same.Dir}}
	useInstall(&same, dir)
	if res, err := run(t.Context(), same); err != nil || res.ExitCode != 0 {
		t.Errorf("a second run of the same folder: %+v, %v", res, err)
	}
	if s := finishFirst(); s.err != nil {
		t.Fatal(s.err)
	}
}

// holdSpec starts sp, a walled run behind a holding wall, and waits until its session
// is going. It returns the run's id and the function that lets it finish.
func holdSpec(t *testing.T, sp runSpec) (string, func() *started) {
	t.Helper()
	w := sp.Wall.(*holdingWall)
	s := start(sp)
	select {
	case <-w.reached:
	case <-s.done:
		t.Fatalf("the first run ended: %+v, %v", s.res, s.err)
	}
	var once sync.Once
	finish := func() *started {
		once.Do(func() { close(w.release) })
		<-s.done
		return s
	}
	t.Cleanup(func() { finish() })
	return w.id, finish
}

// TestAWalledRuntimeMayStartThroughTheHelper pins the second shape of the program
// behind a wall: Command is Forager's helper and the argument after the first -- is the
// program inside the folder, checked as Command is, and written at
// /qory/runtime/claude inside. The helper with no -- or with a program after it that
// lies outside the folder is refused, and so is the helper as Command without a wall.
func TestAWalledRuntimeMayStartThroughTheHelper(t *testing.T) {
	t.Setenv("QORY_TEST_HOST_ONLY", "1")
	helperShape := func(sp *runSpec, program string) {
		sp.Args = append([]string{"run", "agent-env", "--", program}, sp.Args...)
		sp.Command = wall.HelperPath
	}
	w := &openWall{}
	sp := walledSpec(t, w)
	sp.Mounts = []wall.Mount{{Path: sp.Dir}}
	dir := installAt(t, t.TempDir())
	useInstall(&sp, dir)
	helperShape(&sp, sp.Command)
	// The helper is no file of this machine's, so the launch fails once it starts: the
	// join passed its checks.
	if _, err := run(t.Context(), sp); err != nil {
		t.Fatalf("the helper's shape was refused: %v", err)
	}
	if i := slices.Index(w.got.Args, "--"); i < 0 || !slices.Contains(w.got.Args[i:], wall.HelperPath) {
		t.Fatalf("the launch inside is %q %q", w.got.Command, w.got.Args)
	}
	if !slices.Contains(w.got.Args, "/qory/runtime/claude/bin/claude") || slices.ContainsFunc(w.got.Args, func(a string) bool { return strings.HasPrefix(a, dir) }) {
		t.Errorf("the launch inside is %q %q", w.got.Command, w.got.Args)
	}

	for name, c := range map[string]struct {
		walled bool
		change func(sp *runSpec)
		want   string
	}{
		"a program after -- outside the folder": {true, func(sp *runSpec) { helperShape(sp, installedProgram) }, "set the argument after -- in SessionSpec.Args to a program inside SessionSpec.RuntimeInstall.Dir"},
		"no --": {true, func(sp *runSpec) {
			sp.Args, sp.Command = append([]string{sp.Command}, sp.Args...), wall.HelperPath
		}, "put the runtime's program inside SessionSpec.RuntimeInstall.Dir"},
		"nothing after --": {true, func(sp *runSpec) {
			sp.Args, sp.Command = []string{"run", "--"}, wall.HelperPath
		}, "put the runtime's program inside SessionSpec.RuntimeInstall.Dir"},
		"a link after --": {true, func(sp *runSpec) {
			link := filepath.Join(filepath.Dir(sp.Command), "link")
			if err := os.Symlink("claude", link); err != nil {
				t.Fatal(err)
			}
			helperShape(sp, link)
		}, "replace the symbolic link"},
		"the helper without a wall": {false, func(sp *runSpec) { helperShape(sp, sp.Command) }, "set SessionSpec.Command to a program inside SessionSpec.RuntimeInstall.Dir"},
	} {
		t.Run(name, func(t *testing.T) {
			w := &openWall{}
			sp := spec(t, "FAKE_EXIT=0")
			if c.walled {
				sp = walledSpec(t, w)
				sp.Mounts = []wall.Mount{{Path: sp.Dir}}
			}
			useInstall(&sp, installAt(t, t.TempDir()))
			c.change(&sp)
			_, err := run(t.Context(), sp)
			if err == nil || !strings.HasPrefix(err.Error(), c.want) {
				t.Fatalf("got %v; want an error that starts %q", err, c.want)
			}
			if w.wrapped {
				t.Error("the enclosure was wrapped")
			}
		})
	}
}

// TestJoinAcceptsTheEdgesOfARuntimeInstall pins what passes beside the refusals: a
// version of exactly 64 bytes, and a folder and program owned by this user with no
// write for the group or others. A folder of another user's is refused; the test
// makes one only when it runs as root, since chown needs root.
func TestJoinAcceptsTheEdgesOfARuntimeInstall(t *testing.T) {
	sp := spec(t, "FAKE_EXIT=0")
	useInstall(&sp, installAt(t, t.TempDir()))
	sp.RuntimeInstall.Version = "2" + strings.Repeat("0", 63)
	if res, err := run(t.Context(), sp); err != nil || res.ExitCode != 0 {
		t.Fatalf("a version of 64 bytes: %+v, %v", res, err)
	}

	if os.Getuid() != 0 {
		t.Skip("a folder of another user's needs chown, which needs root")
	}
	sp = spec(t, "FAKE_EXIT=0")
	useInstall(&sp, installAt(t, t.TempDir()))
	if err := os.Chown(sp.RuntimeInstall.Dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	want := `make root or the user that runs Forager the owner of "` + sp.RuntimeInstall.Dir + `"`
	if err := runErr(sp); err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("a folder of another user's: %v; want an error that starts %q", err, want)
	}
}

// TestAWalledRunRefusesAFolderAroundQory pins the folder against /qory, where the
// enclosure has Forager's helper and the runtimes' folders: behind a wall a folder
// that is, contains or lies inside /qory here is refused, since one path inside would
// stand for two. / contains /qory on every machine.
func TestAWalledRunRefusesAFolderAroundQory(t *testing.T) {
	w := &openWall{}
	sp := walledSpec(t, w)
	sp.Mounts = []wall.Mount{{Path: sp.Dir}}
	sp.RuntimeInstall = &session.RuntimeInstall{Dir: "/", Version: "2.1.320"}
	sp.Command = "/bin/sh"
	want := "install the runtime in a folder outside /qory and set SessionSpec.RuntimeInstall.Dir to it"
	if err := runErr(sp); err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("got %v; want an error that starts %q", err, want)
	}
	if w.wrapped {
		t.Error("the enclosure was wrapped")
	}
}

// TestAWalledRunWritesANestedLinkOnce pins the rewrite of a folder that is a link to
// a folder inside it: the folder as given and as resolved are written at
// /qory/runtime/claude in one pass, the longer path first, so the program is
// /qory/runtime/claude/bin/claude, not a path inside it.
func TestAWalledRunWritesANestedLinkOnce(t *testing.T) {
	t.Setenv("QORY_TEST_HOST_ONLY", "1")
	root := t.TempDir()
	dir := installAt(t, root)
	// root/current leads to root/rt: the folder as resolved lies inside the folder's
	// parent, and the folder as given is root/current.
	link := filepath.Join(root, "current")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	w := &openWall{}
	sp := walledSpec(t, w)
	sp.Mounts = []wall.Mount{{Path: sp.Dir}}
	useInstall(&sp, link)
	sp.Args = append(sp.Args, resolved+"/share/notes.md")
	if res, err := run(t.Context(), sp); err != nil || res.ExitCode != 0 {
		t.Fatalf("%+v, %v", res, err)
	}
	if !slices.Contains(w.got.Args, "/qory/runtime/claude/bin/claude") || !slices.Contains(w.got.Args, "/qory/runtime/claude/share/notes.md") {
		t.Errorf("the launch inside is %q %q", w.got.Command, w.got.Args)
	}
}

// TestAnUnwalledRuntimeIsListedAmongTheWalledRuns pins the entry of a session without
// a wall: while it runs, its installed folder is in the registry of walled runs,
// read-only, so a walled run that mounts the folder's parent writable is
// mount_shared_with_run; once it ends, its entry is gone and that run starts.
func TestAnUnwalledRuntimeIsListedAmongTheWalledRuns(t *testing.T) {
	root := t.TempDir()
	dir := installAt(t, root)
	wait := filepath.Join(t.TempDir(), "go")
	sp := spec(t, "FAKE_EXIT=0", "FAKE_WAIT="+wait)
	useInstall(&sp, dir)
	sp.RunID = event.NewRunID()
	s := start(sp)
	defer func() {
		os.WriteFile(wait, nil, 0o600)
		<-s.done
	}()
	entry := filepath.Join(os.Getenv("XDG_STATE_HOME"), "qory-forager", "walled", sp.RunID)
	for end := time.Now().Add(30 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(entry); err == nil {
			break
		}
		select {
		case <-s.done:
			t.Fatalf("the session ended: %+v, %v", s.res, s.err)
		default:
		}
		if time.Now().After(end) {
			t.Fatal("the session wrote no entry among the walled runs")
		}
	}
	b, err := os.ReadFile(entry)
	if err != nil {
		t.Fatal(err)
	}
	var listed struct {
		Unwalled bool `json:"unwalled"`
		Binds    []struct {
			Kind     string `json:"kind"`
			Writable bool   `json:"writable"`
		} `json:"binds"`
	}
	if err := json.Unmarshal(b, &listed); err != nil || !listed.Unwalled || len(listed.Binds) != 1 || listed.Binds[0].Kind != "runtime" || listed.Binds[0].Writable {
		t.Errorf("the entry is %s (%v)", b, err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	other := walledSpec(t, &openWall{})
	other.Mounts, other.Dir = []wall.Mount{{Path: root}}, root
	r := refusalOf(t, "mount_shared_with_run", runErr(other))
	if !strings.Contains(r.Detail, "contains the runtime's installed folder "+resolved+" of the run "+sp.RunID+", which is still going") {
		t.Errorf("detail %q", r.Detail)
	}

	if err := os.WriteFile(wait, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	<-s.done
	if s.err != nil || s.res.ExitCode != 0 {
		t.Fatalf("the session: %+v, %v", s.res, s.err)
	}
	if _, err := os.Stat(entry); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the entry is still there: %v", err)
	}
	other = walledSpec(t, &openWall{})
	other.Mounts, other.Dir = []wall.Mount{{Path: root}}, root
	if res, err := run(t.Context(), other); err != nil || res.ExitCode != 0 {
		t.Errorf("the walled run after the session: %+v, %v", res, err)
	}
}

// codexWithoutInstall is a Codex runtime of a descriptor that has no install_required,
// as a catalog directory may have one.
func codexWithoutInstall(t *testing.T) runtimes.Runtime {
	t.Helper()
	doc := "version: 1\nruntime: codex\nsources:\n  output: {format: jsonl}\nrules:\n  - {source: output, match: {type: end}, type: dev.qory.runtime.ended, data: {reason: why}}\n"
	rt, err := runtimes.Described("codex.yaml", []byte(doc), nil)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// TestOnlyARuntimeThatRequiresAnInstallNeedsOne pins install_required: Join refuses a
// Claude Code session with no RuntimeInstall, and a Codex session with none, bare or
// described, starts its program as the caller names it, with no runtime folder for the
// wall, the same launch and the same mounts as a session with no runtime, and no
// runtime_version.
func TestOnlyARuntimeThatRequiresAnInstallNeedsOne(t *testing.T) {
	sp := spec(t, "FAKE_EXIT=0")
	sp.RuntimeInstall = nil
	const want = "set SessionSpec.RuntimeInstall for a session of the runtime claude: the session starts a runtime only from the folder it was installed in"
	if res, err := run(t.Context(), sp); err == nil || err.Error() != want {
		t.Errorf("Claude Code with no install: %+v, %v; want %q", res, err, want)
	}

	for name, rt := range map[string]func(*testing.T) runtimes.Runtime{
		"bare":      func(*testing.T) runtimes.Runtime { return runtimes.Bare("codex") },
		"described": codexWithoutInstall,
	} {
		t.Run(name, func(t *testing.T) {
			sp := spec(t, "FAKE_EXIT=0")
			sp.Runtime, sp.RuntimeInstall = rt(t), nil
			res, err := run(t.Context(), sp)
			if err != nil || res.ExitCode != 0 {
				t.Fatalf("an unwalled session: %+v, %v", res, err)
			}
			started := sessionStarted(t, events(t, res))
			if v, ok := started["runtime_version"]; ok || started["command"] != installedProgram || started["runtime"] != "codex" {
				t.Errorf("runtime %v, command %v, runtime_version %v", started["runtime"], started["command"], v)
			}

			launches := map[bool]wall.Launch{}
			for _, codex := range []bool{true, false} {
				w := &openWall{}
				sp := walledSpec(t, w)
				sp.RuntimeInstall = nil
				sp.Runtime = nil
				if codex {
					sp.Runtime = rt(t)
				}
				res, err := run(t.Context(), sp)
				if err != nil || res.ExitCode != 0 {
					t.Fatalf("a walled session, codex %v: %+v, %v", codex, res, err)
				}
				if w.got.Runtime != (wall.RuntimeFolder{}) {
					t.Errorf("codex %v: the wall got the runtime folder %+v", codex, w.got.Runtime)
				}
				words := strings.Join(append([]string{w.got.Command}, w.got.Args...), " ")
				if !strings.Contains(words, installedProgram) || strings.Contains(words, wall.RuntimeDir) {
					t.Errorf("codex %v: the launch inside is %s", codex, words)
				}
				// The session directory differs per run: compare the rest.
				l := w.got
				l.Mounts = slices.DeleteFunc(slices.Clone(l.Mounts), func(m wall.Mount) bool { return m.Path == res.SessionDir })
				launches[codex] = l
			}
			if a, b := launches[true], launches[false]; a.Command != b.Command || len(a.Mounts) != len(b.Mounts) {
				t.Errorf("codex launch %q with mounts %v; with no runtime %q with mounts %v", a.Command, a.Mounts, b.Command, b.Mounts)
			}
		})
	}
}
