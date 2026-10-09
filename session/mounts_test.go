package session_test

import (
	"context"
	"errors"
	"github.com/qoryai/forager/gateway"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// TestOverlapComparesWholeComponentsThroughLinks pins how a mount and one of
// Forager's paths stand to each other: by whole components, after symbolic links, with a
// part that does not exist yet resolved through the parent that does.
func TestOverlapComparesWholeComponentsThroughLinks(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"a/b", "a/bc", "other"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// link leads to Forager's directory a/b, and m to its parent a.
	if err := os.Symlink(filepath.Join(root, "a", "b"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "m")); err != nil {
		t.Fatal(err)
	}
	// dangling and relative lead into Forager's directory, to names that do not
	// exist yet.
	if err := os.Symlink(filepath.Join(root, "a", "b", "later"), filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("a", "b", "later", "deeper"), filepath.Join(root, "relative")); err != nil {
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
		{"a link to Forager's directory, as the path", p("a"), p("link"), "contains"},
		{"a link to Forager's directory, as the mount", p("link"), p("a/b"), "is"},
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
		{"a link whose target does not exist yet", p("dangling"), p("a/b"), "lies inside"},
		{"a name under a link whose target does not exist yet", p("dangling/x"), p("a/b/later"), "lies inside"},
		{"a relative link whose target does not exist yet", p("relative"), p("a/b/later"), "lies inside"},
		{"a link whose target does not exist yet, as the path", p("a"), p("dangling"), "contains"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := session.Overlap(c.mount, c.path); got != c.want {
				t.Errorf("Overlap(%q, %q) = %q, want %q", c.mount, c.path, got, c.want)
			}
		})
	}

	// A link in a directory Forager cannot search may lead anywhere: Overlap cannot
	// say, and a run with it as a mount does not start.
	t.Run("a link in a directory Forager cannot search", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root searches every directory")
		}
		locked := p("locked")
		if err := os.Mkdir(locked, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(p("a"), filepath.Join(locked, "link")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locked, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(locked, 0o755) })
		mount := filepath.Join(locked, "link")
		if got := session.Overlap(mount, p("a/b")); got != "" {
			t.Errorf("Overlap = %q", got)
		}
		sp := spec(t, "FAKE_EXIT=0")
		sp.Wall, sp.Image, sp.ForagerFiles = &openWall{}, "example.com/agent:1", []string{p("a/b")}
		sp.Mounts = []wall.Mount{{Path: mount}}
		err := runErr(sp)
		var r *session.Refusal
		if err == nil || errors.As(err, &r) || !strings.Contains(err.Error(), "cannot resolve the mount "+mount) {
			t.Errorf("a run with the mount: %v", err)
		}
	})
}

// TestOverlapJudgesTheSameDirectoryByTheFilesystem pins that on a disk that ignores
// case, a path written in another case is the directory it names, and that an existing
// directory matching a pattern of Forager's is refused like the pattern.
func TestOverlapJudgesTheSameDirectoryByTheFilesystem(t *testing.T) {
	t.Parallel()
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

// foragerDir is a Forager file's directory, a directory below a fresh one: the parent is
// what a careless mount lists.
func foragerDir(t *testing.T) (parent, dir string) {
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
	if !errors.As(err, &r) || r.Code != "mount_contains_forager_files" {
		t.Fatalf("want mount_contains_forager_files, got %v", err)
	}
	return r
}

// runErr is the error of a run that is not to start.
func runErr(sp session.Spec) error {
	_, err := session.Run(context.Background(), sp)
	return err
}

// TestAMountOfTheForagersFilesIsNoRun pins the refusal of a walled run whose mount
// contains a Forager file's directory: it names the mount, then Forager's path, the
// gateway is never contacted, the wall builds nothing and no run directory is made.
func TestAMountOfTheForagersFilesIsNoRun(t *testing.T) {
	parent, dir := foragerDir(t)
	w := &openWall{}
	sp, g := specGateway(t, "FAKE_EXIT=0")
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.Mounts = []wall.Mount{{Path: sp.Dir}, {Path: parent, ReadOnly: true}}
	sp.ForagerFiles = []string{dir}
	r := mountRefusal(t, runErr(sp))
	if want := []string{parent, dir}; !slices.Equal(r.Names, want) {
		t.Errorf("names %q, want %q", r.Names, want)
	}
	if !strings.Contains(r.Detail, "the mount "+parent+" contains "+dir) {
		t.Errorf("detail %q", r.Detail)
	}
	if n := g.Accepted.Load() + g.Rejected.Load(); n != 0 {
		t.Errorf("the gateway got %d connections", n)
	}
	if w.req.RunID != "" || w.wrapped {
		t.Errorf("the wall was prepared or wrapped: %+v", w.req)
	}
	if _, err := os.Stat(sp.RunsDir); !os.IsNotExist(err) {
		t.Errorf("a run directory was made: %v", err)
	}

	// A mount inside Forager's directory, and the workspace itself, are refused too.
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

// TestAMountBesideTheForagersFilesRuns pins that a mount that neither holds nor lies in
// one of Forager's files runs, and that a run without a wall checks nothing, having
// no mounts.
func TestAMountBesideTheForagersFilesRuns(t *testing.T) {
	_, dir := foragerDir(t)
	w := &openWall{}
	sp := spec(t, "FAKE_EXIT=0")
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.Mounts = []wall.Mount{{Path: sp.Dir}, {Path: t.TempDir(), ReadOnly: true}}
	sp.ForagerFiles = []string{dir}
	res, err := runWithSettingsEnv(t, sp)
	if err != nil || res.ExitCode != 0 || !w.wrapped {
		t.Fatalf("a walled run beside Forager's files: %+v, %v", res, err)
	}

	sp = spec(t, "FAKE_EXIT=0")
	sp.Mounts = []wall.Mount{{Path: "/"}}
	sp.ForagerFiles = []string{dir}
	if res, err := runWithSettingsEnv(t, sp); err != nil || res.ExitCode != 0 {
		t.Fatalf("an unwalled run: %+v, %v", res, err)
	}
}

// TestAMountOfTheGatewaysFilesIsNoRun pins that the files a gateway hands out with its
// link are Forager's files, refused in the words a run was always refused in: the
// directory of a tool's program and the one a link to it leads to, the file a
// credential is read from, and, in a mount that contains the system's temporary
// directory, the private directories the tools' sockets are made in, whatever the
// gateway's tools.
func TestAMountOfTheGatewaysFilesIsNoRun(t *testing.T) {
	bin, libexec, creds := filepath.Join(t.TempDir(), "bin"), filepath.Join(t.TempDir(), "libexec"), filepath.Join(t.TempDir(), "creds")
	for _, d := range []string{bin, libexec, creds} {
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
	key := filepath.Join(creds, "model.key")
	if err := os.WriteFile(key, []byte("a-credential-of-the-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sp := spec(t, "FAKE_EXIT=0")
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	startGateway(t, &sp, gateway.Config{
		Tools:       []gateway.Tool{{Name: "files", Command: []string{filepath.Join(bin, "files-tool")}, Serves: []string{"files.tools.internal"}}},
		Credentials: []gateway.Credential{{Name: "model", File: key, Hosts: []string{"api.model.example"}, Scheme: "bearer"}},
	})
	real := func(p string) string { r, _ := filepath.EvalSymlinks(p); return r }
	for _, c := range []struct{ mount, detail string }{
		{filepath.Dir(bin), "the mount " + filepath.Dir(bin) + " contains " + bin + ", the directory of the tool files's program"},
		{libexec, "the mount " + libexec + " is " + real(libexec) + ", the directory of the tool files's program"},
		{creds, "the mount " + creds + " contains " + key + ", the file the credential model is read from"},
	} {
		sp.Mounts = []wall.Mount{{Path: sp.Dir}, {Path: c.mount}}
		if r := mountRefusal(t, runErr(sp)); r.Names[0] != c.mount || r.Detail != c.detail {
			t.Errorf("mount %s: names %q, detail\n %q\nwant\n %q", c.mount, r.Names, r.Detail, c.detail)
		}
	}

	sp = spec(t, "FAKE_EXIT=0")
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	startGateway(t, &sp, gateway.Config{})
	sp.Mounts = []wall.Mount{{Path: os.TempDir()}}
	want := "the mount " + os.TempDir() + " contains " + filepath.Join(os.TempDir(), "qory-tool-*") + ", where the tools' sockets are made"
	if r := mountRefusal(t, runErr(sp)); r.Names[0] != os.TempDir() || r.Detail != want {
		t.Errorf("names %q, detail\n %q\nwant\n %q", r.Names, r.Detail, want)
	}
}

// TestTheGatewaysDirectoriesComeAfterTheWalls pins the order Forager's files are
// checked in, which decides what a mount that holds several is refused for: the
// directories the gateway keeps come last, after the wall's
// files and the run directories, so a Docker run that mounts a home holding both the
// gateway's directory and ~/.docker is refused for ~/.docker, and a mount of the state
// directory that holds the gateway's directory and the run directories for the run
// directories, as it always was.
func TestTheGatewaysDirectoriesComeAfterTheWalls(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DOCKER_CONFIG", "")
	sp := spec(t, "FAKE_EXIT=0")
	docker := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(docker, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sp.Wall, sp.Image = &wall.Docker{Command: docker, Helper: os.Args[0]}, "example.com/agent:1"
	startGateway(t, &sp, gateway.Config{Dir: filepath.Join(home, ".local", "state", "qory")})
	sp.Mounts = []wall.Mount{{Path: home}}
	want := "the mount " + home + " contains " + filepath.Join(home, ".docker") + ", one of the docker wall's files"
	if r := mountRefusal(t, runErr(sp)); r.Names[0] != home || r.Detail != want {
		t.Errorf("names %q, detail\n %q\nwant\n %q", r.Names, r.Detail, want)
	}

	// A mount of the state directory that holds the gateway's directory and the run
	// directories is refused for the run directories.
	state := filepath.Join(home, ".local", "state")
	sp = spec(t, "FAKE_EXIT=0")
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	sp.RunsDir = filepath.Join(state, "qory", "runs", "x")
	startGateway(t, &sp, gateway.Config{Dir: filepath.Join(state, "qory")})
	sp.Mounts = []wall.Mount{{Path: state}}
	want = "the mount " + state + " contains " + sp.RunsDir + ", where the run directories are kept"
	if r := mountRefusal(t, runErr(sp)); r.Names[0] != state || r.Detail != want {
		t.Errorf("names %q, detail\n %q\nwant\n %q", r.Names, r.Detail, want)
	}
}

// TestForagerFilesAreAbsolutePaths pins that a Forager file that is no absolute path is
// a plain error, not a refusal, walled or not.
func TestForagerFilesAreAbsolutePaths(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"relative/qory", "/home/user/\x00qory"} {
		sp := spec(t, "FAKE_EXIT=0")
		sp.ForagerFiles = []string{p}
		_, err := session.Run(context.Background(), sp)
		var r *session.Refusal
		if err == nil || errors.As(err, &r) {
			t.Errorf("Forager file %q: %v", p, err)
		}
	}
}

// TestAMountOfTheWallsFilesIsNoRun pins that the files a wall lists as its own are
// Forager's: the Docker adapter's helper among them.
func TestAMountOfTheWallsFilesIsNoRun(t *testing.T) {
	helpers := filepath.Join(t.TempDir(), "helpers")
	sp := spec(t, "FAKE_EXIT=0")
	sp.Wall, sp.Image = &wall.Docker{Helper: filepath.Join(helpers, "qory"), RelayArgs: []string{"relay"}}, "example.com/agent:1"
	sp.Mounts = []wall.Mount{{Path: filepath.Dir(helpers), ReadOnly: true}}
	r := mountRefusal(t, runErr(sp))
	if want := []string{filepath.Dir(helpers), helpers}; !slices.Equal(r.Names, want) || !strings.Contains(r.Detail, "the docker wall's files") {
		t.Errorf("names %q, detail %q", r.Names, r.Detail)
	}
}

// swappingWall is an open wall that, while it is prepared, puts a link where a mount
// was checked: what the enclosure would show changes between the start and the wrap.
type swappingWall struct {
	openWall
	link, to string
}

func (w *swappingWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	if err := os.Symlink(w.to, w.link); err != nil {
		return nil, err
	}
	return w.openWall.Prepare(ctx, req)
}

// TestTheMountsAreCheckedAgainBeforeTheWrap pins the second check: a mount that led
// nowhere at the start and is a link to Forager's files by the time the enclosure
// is wrapped is refused the same way, and the enclosure never shows it.
func TestTheMountsAreCheckedAgainBeforeTheWrap(t *testing.T) {
	parent, dir := foragerDir(t)
	link := filepath.Join(t.TempDir(), "later")
	w := &swappingWall{link: link, to: parent}
	sp := spec(t, "FAKE_EXIT=0")
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.Mounts = []wall.Mount{{Path: sp.Dir}, {Path: link}}
	sp.ForagerFiles = []string{dir}
	r := mountRefusal(t, runErr(sp))
	if want := []string{link, dir}; !slices.Equal(r.Names, want) {
		t.Errorf("names %q, want %q", r.Names, want)
	}
	if w.req.RunID == "" || w.wrapped || w.closed != 1 {
		t.Errorf("prepared %v, wrapped %v, closed %d times", w.req.RunID != "", w.wrapped, w.closed)
	}
}

// TestAMountOfAnotherRunsPrivateDirectoriesIsNoRun pins that the private directories
// runs make in the system's temporary directory, for their record sockets and for the
// Docker wall's environment files, are Forager's files whoever made them: a mount
// of the temporary directory while another run's exist is refused, and so is a mount
// of one of them, or of a file in one.
func TestAMountOfAnotherRunsPrivateDirectoriesIsNoRun(t *testing.T) {
	sp := spec(t, "FAKE_EXIT=0")
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	run, wallDir := filepath.Join(tmp, "qory-run-1234"), filepath.Join(tmp, "qory-wall-5678")
	for _, d := range []string{run, wallDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	patterns := []string{filepath.Join(tmp, "qory-tool-*"), filepath.Join(tmp, "qory-run-*"), filepath.Join(tmp, "qory-wall-*")}
	sp.Mounts = []wall.Mount{{Path: tmp}}
	r := mountRefusal(t, runErr(sp))
	if r.Names[0] != tmp || !slices.Contains(patterns, r.Names[1]) || !strings.Contains(r.Detail, " contains ") {
		t.Errorf("the temporary directory: names %q, detail %q", r.Names, r.Detail)
	}
	for _, c := range []struct{ mount, pattern, how string }{
		{run, patterns[1], " is "},
		{wallDir, patterns[2], " is "},
		{filepath.Join(wallDir, "relay-env"), patterns[2], " lies inside "},
	} {
		sp.Mounts = []wall.Mount{{Path: c.mount}}
		r := mountRefusal(t, runErr(sp))
		if want := []string{c.mount, c.pattern}; !slices.Equal(r.Names, want) || !strings.Contains(r.Detail, c.how) {
			t.Errorf("names %q, want %q, detail %q", r.Names, want, r.Detail)
		}
	}
}
