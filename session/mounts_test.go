package session_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/runner/session"
	"github.com/qoryai/runner/wall"
)

// TestOverlapComparesWholeComponentsThroughLinks pins how a mount and one of the
// runner's paths stand to each other: by whole components, after symbolic links, with a
// part that does not exist yet resolved through the parent that does.
func TestOverlapComparesWholeComponentsThroughLinks(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"a/b", "a/bc", "other"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// link leads to the runner's directory a/b, and m to its parent a.
	if err := os.Symlink(filepath.Join(root, "a", "b"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "m")); err != nil {
		t.Fatal(err)
	}
	p := func(rel string) string { return filepath.Join(root, rel) }
	for _, c := range []struct {
		name, mount, path, want string
	}{
		{"equal", p("a/b"), p("a/b"), "is"},
		{"contains", p("a"), p("a/b"), "contains"},
		{"inside", p("a/b/c"), p("a/b"), "lies inside"},
		{"unrelated", p("other"), p("a/b"), ""},
		{"sibling with the path as prefix", p("a/bc"), p("a/b"), ""},
		{"sibling the path is a prefix of", p("a/b"), p("a/bc"), ""},
		{"the filesystem's root", "/", p("a/b"), "contains"},
		{"a link to the runner's directory, as the path", p("a"), p("link"), "contains"},
		{"a link to the runner's directory, as the mount", p("link"), p("a/b"), "is"},
		{"a mount under a linked parent", p("m/b"), p("a/b"), "is"},
		{"a mount under a linked parent, above the path", p("m"), p("a/b/file"), "contains"},
		{"a path that does not exist yet", p("a"), p("a/b/new/deeper"), "contains"},
		{"a path that does not exist under a link", p("link/new"), p("a/b"), "lies inside"},
		{"a mount that does not exist beside the path", p("missing/x"), p("a/b"), ""},
		{"trailing slashes", p("a") + "/", p("a/b") + "/", "contains"},
		{"trailing slash on one side", p("a/b") + "/", p("a/b"), "is"},
		{"unclean", root + "/a/./b/../b", p("a/b"), "is"},
		{"a tail that does not exist, in another case", p("a/New/X"), p("a/new/x"), "is"},
		{"a tail in another case, below the mount", p("a/b/New"), p("a/b/new/deeper"), "contains"},
		{"a tail in another case, above the mount", p("a/b/NEW/deeper"), p("a/b/new"), "lies inside"},
		{"a tail that differs", p("a/b/new"), p("a/b/newer"), ""},
		{"a pattern of names that do not exist", p("a/b/x-1"), p("a/b/x-*"), "is"},
		{"a pattern below the mount", p("a"), p("a/b/x-*"), "contains"},
		{"a pattern above the mount", p("a/b/x-1/deeper"), p("a/b/x-*"), "lies inside"},
		{"a name beside the pattern", p("a/b/y-1"), p("a/b/x-*"), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := session.Overlap(c.mount, c.path); got != c.want {
				t.Errorf("Overlap(%q, %q) = %q, want %q", c.mount, c.path, got, c.want)
			}
		})
	}
}

// TestOverlapJudgesTheSameDirectoryByTheFilesystem pins that on a disk that ignores
// case, a path written in another case is the directory it names, and that an existing
// directory matching a pattern of the runner's is refused like the pattern.
func TestOverlapJudgesTheSameDirectoryByTheFilesystem(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"Home/User/.config/qory", "tmp/qory-tool-abc"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p := func(rel string) string { return filepath.Join(root, rel) }
	if got := session.Overlap(p("tmp/qory-tool-abc"), p("tmp/qory-tool-*")); got != "is" {
		t.Errorf("an existing directory the pattern matches: %q", got)
	}
	if got := session.Overlap(p("tmp"), p("tmp/qory-tool-*")); got != "contains" {
		t.Errorf("the pattern's parent: %q", got)
	}
	if _, err := os.Stat(p("HOME/USER")); err != nil {
		t.Skip("the test's volume tells case apart:", err)
	}
	for _, c := range []struct{ mount, path, want string }{
		{p("HOME/USER"), p("Home/User/.config/qory"), "contains"},
		{p("home/user/.CONFIG/QORY"), p("Home/User/.config/qory"), "is"},
		{p("Home/User"), p("home/user/.Config/Qory"), "contains"},
		{p("home/user/.config/qory/labels"), p("Home/User/.config/qory"), "lies inside"},
		{p("HOME/OTHER"), p("Home/User/.config/qory"), ""},
	} {
		if got := session.Overlap(c.mount, c.path); got != c.want {
			t.Errorf("Overlap(%q, %q) = %q, want %q", c.mount, c.path, got, c.want)
		}
	}
}

// runnerDir is a runner file's directory, a directory below a fresh one: the parent is
// what a careless mount lists.
func runnerDir(t *testing.T) (parent, dir string) {
	t.Helper()
	parent = t.TempDir()
	dir = filepath.Join(parent, ".config", "qory")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return parent, dir
}

// mountRefusal is the refusal a run returned, or fails the test.
func mountRefusal(t *testing.T, err error) *session.Refusal {
	t.Helper()
	var r *session.Refusal
	if !errors.As(err, &r) || r.Code != "mount_contains_runner_files" {
		t.Fatalf("want mount_contains_runner_files, got %v", err)
	}
	return r
}

// runErr is the error of a run that is not to start.
func runErr(sp session.Spec) error {
	_, err := session.Run(context.Background(), sp)
	return err
}

// TestAMountOfTheRunnersFilesIsNoRun pins the refusal of a walled run whose mount
// contains a runner file's directory: it names the mount, then the runner's path, the
// server is never contacted, the wall builds nothing and no run directory is made.
func TestAMountOfTheRunnersFilesIsNoRun(t *testing.T) {
	c := newControl(t)
	parent, dir := runnerDir(t)
	w := &openWall{}
	sp := spec(t, nil, "FAKE_EXIT=0")
	sp.Wall, sp.Image, sp.Server = w, "example.com/agent:1", c.server()
	sp.Mounts = []wall.Mount{{Path: sp.Dir}, {Path: parent, ReadOnly: true}}
	sp.RunnerFiles = []string{dir}
	r := mountRefusal(t, runErr(sp))
	if want := []string{parent, dir}; !slices.Equal(r.Names, want) {
		t.Errorf("names %q, want %q", r.Names, want)
	}
	if !strings.Contains(r.Detail, "the mount "+parent+" contains "+dir) {
		t.Errorf("detail %q", r.Detail)
	}
	if n := c.hits.Load(); n != 0 {
		t.Errorf("the server got %d requests", n)
	}
	if w.req.RunID != "" || w.wrapped {
		t.Errorf("the wall was prepared or wrapped: %+v", w.req)
	}
	if _, err := os.Stat(filepath.Join(sp.Dir, ".qory")); !os.IsNotExist(err) {
		t.Errorf("a run directory was made: %v", err)
	}

	// A mount inside the runner's directory, and the workspace itself, are refused too.
	sp.Mounts = []wall.Mount{{Path: filepath.Join(dir, "labels")}}
	r = mountRefusal(t, runErr(sp))
	if want := []string{filepath.Join(dir, "labels"), dir}; !slices.Equal(r.Names, want) || !strings.Contains(r.Detail, " lies inside ") {
		t.Errorf("names %q, detail %q", r.Names, r.Detail)
	}
	// On a disk that ignores case, the parent written in another case is the parent.
	if upper := strings.ToUpper(parent); upper != parent {
		if _, err := os.Stat(upper); err == nil {
			sp.Mounts = []wall.Mount{{Path: upper}}
			r = mountRefusal(t, runErr(sp))
			if want := []string{upper, dir}; !slices.Equal(r.Names, want) || !strings.Contains(r.Detail, " contains ") {
				t.Errorf("names %q, detail %q", r.Names, r.Detail)
			}
		}
	}
	sp.Mounts, sp.Dir = nil, parent
	r = mountRefusal(t, runErr(sp))
	if want := []string{parent, dir}; !slices.Equal(r.Names, want) || !strings.HasPrefix(r.Detail, "the workspace ") {
		t.Errorf("names %q, detail %q", r.Names, r.Detail)
	}
}

// TestAMountBesideTheRunnersFilesRuns pins that a mount that neither holds nor lies in
// one of the runner's files runs, and that a run without a wall checks nothing, having
// no mounts.
func TestAMountBesideTheRunnersFilesRuns(t *testing.T) {
	_, dir := runnerDir(t)
	w := &openWall{}
	sp := spec(t, nil, "FAKE_EXIT=0")
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.Mounts = []wall.Mount{{Path: sp.Dir}, {Path: t.TempDir(), ReadOnly: true}}
	sp.RunnerFiles = []string{dir}
	res, err := runWithSettingsEnv(t, sp)
	if err != nil || res.ExitCode != 0 || !w.wrapped {
		t.Fatalf("a walled run beside the runner's files: %+v, %v", res, err)
	}

	sp = spec(t, nil, "FAKE_EXIT=0")
	sp.Mounts = []wall.Mount{{Path: "/"}}
	sp.RunnerFiles = []string{dir}
	if res, err := runWithSettingsEnv(t, sp); err != nil || res.ExitCode != 0 {
		t.Fatalf("an unwalled run: %+v, %v", res, err)
	}
}

// TestAMountOfAToolsProgramIsNoRun pins that the directory of a tool's program is one
// of the runner's files, whether or not the run's policy selects the tool, and so is
// the directory a link to the program leads to.
func TestAMountOfAToolsProgramIsNoRun(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "bin")
	libexec := filepath.Join(t.TempDir(), "libexec")
	for _, d := range []string{bin, libexec} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(libexec, "files-tool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(libexec, "files-tool"), filepath.Join(bin, "files-tool")); err != nil {
		t.Fatal(err)
	}
	sp := spec(t, nil, "FAKE_EXIT=0")
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	sp.Tools = []session.Tool{{Name: "files", Command: []string{filepath.Join(bin, "files-tool")}, Serves: []string{"files.tools.internal"}}}
	for _, mount := range []string{filepath.Dir(bin), libexec} {
		sp.Mounts = []wall.Mount{{Path: sp.Dir}, {Path: mount}}
		r := mountRefusal(t, runErr(sp))
		if r.Names[0] != mount || !strings.Contains(r.Detail, "the tool files's program") {
			t.Errorf("mount %s: names %q, detail %q", mount, r.Names, r.Detail)
		}
	}

	// A mount that contains the system's temporary directory contains the private
	// directory a tool's socket is made in.
	sp.Tools[0].Command = []string{"/bin/sh"}
	sp.Mounts = []wall.Mount{{Path: os.TempDir()}}
	r := mountRefusal(t, runErr(sp))
	if r.Names[0] != os.TempDir() || !strings.HasSuffix(r.Names[1], "qory-tool-*") {
		t.Errorf("names %q, detail %q", r.Names, r.Detail)
	}
}

// TestRunnerFilesAreAbsolutePaths pins that a runner file that is no absolute path is
// a plain error, not a refusal, walled or not.
func TestRunnerFilesAreAbsolutePaths(t *testing.T) {
	for _, p := range []string{"relative/qory", "/home/user/\x00qory"} {
		sp := spec(t, nil, "FAKE_EXIT=0")
		sp.RunnerFiles = []string{p}
		_, err := session.Run(context.Background(), sp)
		var r *session.Refusal
		if err == nil || errors.As(err, &r) {
			t.Errorf("runner file %q: %v", p, err)
		}
	}
}

// TestAMountOfTheWallsFilesIsNoRun pins that the files a wall lists as its own are the
// runner's: the Docker adapter's helper among them.
func TestAMountOfTheWallsFilesIsNoRun(t *testing.T) {
	helpers := filepath.Join(t.TempDir(), "helpers")
	sp := spec(t, nil, "FAKE_EXIT=0")
	sp.Wall, sp.Image = &wall.Docker{Helper: filepath.Join(helpers, "qory"), RelayArgs: []string{"relay"}}, "example.com/agent:1"
	sp.Mounts = []wall.Mount{{Path: filepath.Dir(helpers), ReadOnly: true}}
	r := mountRefusal(t, runErr(sp))
	if want := []string{filepath.Dir(helpers), helpers}; !slices.Equal(r.Names, want) || !strings.Contains(r.Detail, "the docker wall's files") {
		t.Errorf("names %q, detail %q", r.Names, r.Detail)
	}
}
