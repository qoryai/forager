package session_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/gateway"

	"github.com/qoryai/forager/event"
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
func runErr(sp runSpec) error {
	_, err := run(context.Background(), sp)
	return err
}

// TestAMountOfTheForagersFilesIsNoRun pins the refusal of a walled run whose mount
// contains a Forager file's directory: it names the mount, then Forager's path, the
// join's session.exited has the code, no session starts and the wall wraps nothing.
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
	joinRefusedOnLink(t, g, "mount_contains_forager_files")
	if w.wrapped {
		t.Errorf("the wall was wrapped: %+v", w.got)
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

// filedDocker is an open wall with the name and the files of a Docker adapter: a join
// checks its places against them, and no engine runs.
type filedDocker struct {
	openWall
	d *wall.Docker
}

func (w *filedDocker) Name() string    { return w.d.Name() }
func (w *filedDocker) Files() []string { return w.d.Files() }

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
	sp.Wall, sp.Image = &filedDocker{d: &wall.Docker{Command: docker, Helper: os.Args[0]}}, "example.com/agent:1"
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
	for _, p := range []string{"relative/qory", "/home/user/\x00qory"} {
		sp := spec(t, "FAKE_EXIT=0")
		sp.ForagerFiles = []string{p}
		_, err := run(context.Background(), sp)
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
	sp.Wall, sp.Image = &filedDocker{d: &wall.Docker{Helper: filepath.Join(helpers, "qory"), RelayArgs: []string{"relay"}}}, "example.com/agent:1"
	sp.Mounts = []wall.Mount{{Path: filepath.Dir(helpers), ReadOnly: true}}
	r := mountRefusal(t, runErr(sp))
	if want := []string{filepath.Dir(helpers), helpers}; !slices.Equal(r.Names, want) || !strings.Contains(r.Detail, "the docker wall's files") {
		t.Errorf("names %q, detail %q", r.Names, r.Detail)
	}
}

// TestAMountOfTheEnginesRegistryAuthoritiesIsNoRun pins that the directory the engine
// reads registry authorities from, the Docker wall's CertsDir, is one of the wall's
// files: a mount of it, or of a directory that holds it, is refused, so code in the
// wall cannot write a certificate the engine trusts for a registry.
func TestAMountOfTheEnginesRegistryAuthoritiesIsNoRun(t *testing.T) {
	certs := filepath.Join(t.TempDir(), "docker", "certs.d")
	if err := os.MkdirAll(certs, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, mounted := range []string{certs, filepath.Dir(certs)} {
		sp := spec(t, "FAKE_EXIT=0")
		sp.Wall, sp.Image = &filedDocker{d: &wall.Docker{Helper: filepath.Join(t.TempDir(), "qory"), RelayArgs: []string{"relay"}, CertsDir: certs}}, "example.com/agent:1"
		sp.Mounts = []wall.Mount{{Path: mounted}}
		r := mountRefusal(t, runErr(sp))
		if !slices.Contains(r.Names, certs) || !strings.Contains(r.Detail, "the docker wall's files") {
			t.Errorf("a mount of %s: names %q, detail %q", mounted, r.Names, r.Detail)
		}
	}
}

// afterTheJoinsCheck calls f once, after the join of the test's walled run checked its
// places and before its wall step checks them again: at the run's second check against
// the registry of walled runs, its open's being the first.
func afterTheJoinsCheck(t *testing.T, f func()) {
	t.Helper()
	calls := 0
	session.SetRegisterPause(func(string) {
		if calls++; calls == 2 {
			f()
		}
	})
	t.Cleanup(func() { session.SetRegisterPause(nil) })
}

// TestTheMountsAreCheckedAgainBeforeTheWrap pins the second check: a mount that led
// nowhere at the start and is a link to Forager's files by the time the enclosure
// is wrapped is refused the same way, and the enclosure never shows it.
func TestTheMountsAreCheckedAgainBeforeTheWrap(t *testing.T) {
	parent, dir := foragerDir(t)
	link := filepath.Join(t.TempDir(), "later")
	afterTheJoinsCheck(t, func() {
		if err := os.Symlink(parent, link); err != nil {
			t.Error(err)
		}
	})
	w := &openWall{}
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

// TestARemoteGatewaysRunRefusesAMountOfALinkDirectory pins that the private directories
// gateways make their links in, in the system's temporary directory, are Forager's
// files behind a separate gateway too, which hands the session no files of its own: a
// mount of a local gateway's link directory on this machine, or of a file in one, is
// refused at the join, and the runtime never starts.
func TestARemoteGatewaysRunRefusesAMountOfALinkDirectory(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	linkDir := filepath.Join(tmp, "qory-link-1234")
	if err := os.Mkdir(linkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	g := startRemote(t)
	pattern := filepath.Join(tmp, "qory-link-*")
	for _, c := range []struct{ mount, how string }{
		{linkDir, " is "},
		{filepath.Join(linkDir, "sock"), " lies inside "},
	} {
		r := newSepRun(t, remoteGateway(g, g.RunKey(t, event.NewRunID())))
		r.sp.Wall, r.sp.Image = &openWall{}, "example.com/agent:1"
		r.sp.Mounts = []wall.Mount{{Path: c.mount}}
		got := mountRefusal(t, runErr(r.sp))
		if want := []string{c.mount, pattern}; !slices.Equal(got.Names, want) || !strings.Contains(got.Detail, c.how) || !strings.HasSuffix(got.Detail, ", where the gateways' links are made") {
			t.Errorf("names %q, want %q, detail %q", got.Names, want, got.Detail)
		}
		if r.started() {
			t.Error("the runtime of a refused mount started")
		}
	}
}

// TestAReadOnlyWorkspaceKeepsTheChecksOfAWritablePlace pins that
// SessionSpec.WorkspaceReadOnly changes the bind alone: a place through a link inside
// the workspace is still mount_through_link, and a link in the workspace on the way to
// the runs directory is still mount_contains_forager_files, since the setup container
// and the host steps still write the workspace.
func TestAReadOnlyWorkspaceKeepsTheChecksOfAWritablePlace(t *testing.T) {
	ws, outside := t.TempDir(), t.TempDir()
	home := filepath.Join(ws, "home")
	symlink(t, outside, home)
	w := &openWall{}
	sp := walledSpec(t, w)
	sp.Mounts, sp.Dir, sp.WorkspaceReadOnly = []wall.Mount{{Path: home, ReadOnly: true}}, ws, true
	throughLink(t, runErr(sp), home, home, ws)
	if w.wrapped {
		t.Error("the wall was wrapped")
	}

	ws = t.TempDir()
	runs := filepath.Join(ws, "runs")
	symlink(t, t.TempDir(), runs)
	w = &openWall{}
	sp = walledSpec(t, w)
	sp.Dir, sp.RunsDir, sp.WorkspaceReadOnly = ws, runs, true
	r := mountRefusal(t, runErr(sp))
	want := "the workspace " + ws + " contains " + entry(t, runs) + ", on the way to " + runs +
		", where the run directories are kept"
	if !slices.Equal(r.Names, []string{ws, runs}) || r.Detail != want {
		t.Errorf("names %q, detail %q\nwant names %q, detail %q", r.Names, r.Detail, []string{ws, runs}, want)
	}
	if w.wrapped {
		t.Error("the wall was wrapped")
	}
}

// TestAReadOnlyWorkspaceNeedsAWallAndNoSetupInside pins the two specs with
// SessionSpec.WorkspaceReadOnly that Join and AgentEnv refuse before the join request,
// with the fix first: a run with no wall, and SessionSpec.Setup, which runs in the
// agent's container. No join request is sent, the record gets no event and the runtime
// does not start.
func TestAReadOnlyWorkspaceNeedsAWallAndNoSetupInside(t *testing.T) {
	for name, c := range map[string]struct {
		walled bool
		setup  []session.SetupCommand
		want   string
	}{
		"no wall": {false, nil,
			"Open the run with a wall to mount the workspace read-only: a run with no wall starts the agent on this machine."},
		"no wall, setup inside": {false, []session.SetupCommand{{Name: "install", Args: []string{"true"}}},
			"Open the run with a wall to mount the workspace read-only: a run with no wall starts the agent on this machine."},
		"setup inside": {true, []session.SetupCommand{{Name: "install", Args: []string{"true"}}},
			"Run the setup with Run.Setup, or leave SessionSpec.WorkspaceReadOnly unset: SessionSpec.Setup runs in the agent's container, which sees the workspace read-only."},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			sp, g := specGateway(t, "FAKE_EXIT=0")
			sp.Command, sp.Args, sp.Forwarder = "/bin/sh", []string{"-c", "touch runtime-ran"}, nil
			if c.walled {
				sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			}
			sp.SetupRunner, sp.SessionSpec.Setup, sp.WorkspaceReadOnly = setupRunner, c.setup, true
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			record := filepath.Join(r.Dir(), "session.jsonl")
			before, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.AgentEnv(sp.SessionSpec); err == nil || err.Error() != c.want {
				t.Errorf("AgentEnv: %v\nwant %s", err, c.want)
			}
			res, err := r.Join(ctx, sp.SessionSpec)
			if err == nil || err.Error() != c.want {
				t.Errorf("Join: %v\nwant %s", err, c.want)
			}
			after, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Errorf("the join wrote to the record:\n%s", after[len(before):])
			}
			if joins := g.Joins(); len(joins) != 0 {
				t.Errorf("join requests %+v; want none", joins)
			}
			if _, err := os.Stat(filepath.Join(sp.Dir, "runtime-ran")); err == nil {
				t.Error("the runtime started")
			}
			r.Close(ctx, outcomeOf(res, err))
		})
	}
}

// homeInside is where the tests show a writable home directory inside, by its Target.
const homeInside = "/var/lib/agent-home"

// TestAMountTargetIsAbsoluteCleanAndApartFromQory pins the rules of a mount's Target:
// one that is not absolute or clean, that is, holds or lies inside /qory, or that has a
// comma, a double quote or a newline fails the join with no code, its fix first, before
// the wall is wrapped; a Target that follows them is kept in the launch's mounts.
func TestAMountTargetIsAbsoluteCleanAndApartFromQory(t *testing.T) {
	home := t.TempDir()
	for target, want := range map[string]string{
		"var/lib/agent-home":     "Set the target of the mount " + home + " to an absolute, clean path",
		"/var/lib/../agent-home": "Set the target of the mount " + home + " to an absolute, clean path",
		"/var/lib/agent-home/":   "Set the target of the mount " + home + " to an absolute, clean path",
		"/qory":                  "Set the target of the mount " + home + " to a place apart from /qory",
		"/qory/home":             "Set the target of the mount " + home + " to a place apart from /qory",
		"/":                      "Set the target of the mount " + home + " to a place apart from /qory",
		"/var/lib/docker":        "Set the target of the mount " + home + " to a place apart from /var/lib/docker: \"/var/lib/docker\" overlaps it, and the wall keeps the store of nested Docker there",
		"/var/lib":               "Set the target of the mount " + home + " to a place apart from /var/lib/docker: \"/var/lib\" overlaps it",
		"/var/lib/docker/agent":  "Set the target of the mount " + home + " to a place apart from /var/lib/docker",
		"/proc":                  "Set the target of the mount " + home + " to a place apart from /proc: \"/proc\" overlaps it, and the engine mounts a kernel file system there",
		"/proc/self":             "Set the target of the mount " + home + " to a place apart from /proc",
		"/sys":                   "Set the target of the mount " + home + " to a place apart from /sys: \"/sys\" overlaps it, and the engine mounts a kernel file system there",
		"/sys/fs/cgroup":         "Set the target of the mount " + home + " to a place apart from /sys",
		"/dev":                   "Set the target of the mount " + home + " to a place apart from /dev: \"/dev\" overlaps it, and the engine mounts the container's devices there",
		"/dev/shm":               "Set the target of the mount " + home + " to a place apart from /dev",
		"/etc/hosts":             "Set the target of the mount " + home + " to a place apart from /etc/hosts: \"/etc/hosts\" overlaps it, and the engine binds the container's name lookup files there",
		"/etc/hostname":          "Set the target of the mount " + home + " to a place apart from /etc/hostname: \"/etc/hostname\" overlaps it, and the engine binds the container's name lookup files there",
		"/etc/resolv.conf":       "Set the target of the mount " + home + " to a place apart from /etc/resolv.conf: \"/etc/resolv.conf\" overlaps it, and the engine binds the container's name lookup files there",
		"/etc":                   "Set the target of the mount " + home + " to a place apart from /etc/hosts: \"/etc\" overlaps it",
		"/sbin/docker-init":      "Set the target of the mount " + home + " to a place apart from /sbin/docker-init: \"/sbin/docker-init\" overlaps it, and the engine binds the init process there under nested Docker",
		"/sbin":                  "Set the target of the mount " + home + " to a place apart from /sbin/docker-init: \"/sbin\" overlaps it",
		"/var/lib/agent,home":    "Remove the comma, double quote or newline from the target of the mount " + home,
		"/var/lib/agent\"home":   "Remove the comma, double quote or newline from the target of the mount " + home,
		"/var/lib/agent\nhome":   "Remove the comma, double quote or newline from the target of the mount " + home,
	} {
		w := &openWall{}
		sp := walledSpec(t, w)
		sp.Mounts = []wall.Mount{{Path: home, Target: target}}
		err := runErr(sp)
		var r *session.Refusal
		if err == nil || errors.As(err, &r) || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("the target %q: %v; want an error that starts with %q", target, err, want)
		}
		if w.wrapped {
			t.Errorf("the target %q: the wall was wrapped", target)
		}
	}
	w := &openWall{}
	sp := walledSpec(t, w)
	sp.Mounts = []wall.Mount{{Path: home, Target: homeInside}}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if want := (wall.Mount{Path: home, Target: homeInside}); !slices.Contains(w.got.Mounts, want) {
		t.Errorf("mounts %v; want %v among them", w.got.Mounts, want)
	}
	if w.got.Dir != sp.Dir || !slices.Contains(w.got.Mounts, wall.Mount{Path: res.SessionDir, ReadOnly: true}) {
		t.Errorf("mounts %v, working directory %q", w.got.Mounts, w.got.Dir)
	}
}

// TestReadOnlyFilesLieInsideAWritableTarget pins a writable directory shown at a Target
// with a read-only file and a read-only folder inside it, each at a Target inside it
// and with a path on this machine apart from the others: the join binds each, the
// directory first, then the file and the folder, in the order of their places inside,
// fewer names first, whatever the order the caller gives. The workspace and the
// session's directory lie inside none of them, and their places inside are their
// paths on this machine: where they come among the others depends on the depth of the
// temporary directory, so the test pins that each is bound, and not where.
func TestReadOnlyFilesLieInsideAWritableTarget(t *testing.T) {
	home, files := t.TempDir(), t.TempDir()
	hooks := filepath.Join(files, "hooks.json")
	if err := os.WriteFile(hooks, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	skills := mkdirs(t, filepath.Join(files, "skills"))
	w := &openWall{}
	sp := walledSpec(t, w)
	sp.Mounts = []wall.Mount{
		{Path: skills, ReadOnly: true, Target: homeInside + "/skills"},
		{Path: hooks, ReadOnly: true, Target: homeInside + "/hooks.json"},
		{Path: home, Target: homeInside},
	}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	want := []wall.Mount{
		{Path: home, Target: homeInside},
		{Path: skills, ReadOnly: true, Target: homeInside + "/skills"},
		{Path: hooks, ReadOnly: true, Target: homeInside + "/hooks.json"},
	}
	var targeted []wall.Mount
	for _, m := range w.got.Mounts {
		if m.Target != "" {
			targeted = append(targeted, m)
		}
	}
	if !slices.Equal(targeted, want) {
		t.Errorf("mounts at a Target %v\nwant %v", targeted, want)
	}
	byPath := func(a, b wall.Mount) int { return strings.Compare(a.Path, b.Path) }
	got := slices.SortedFunc(slices.Values(w.got.Mounts), byPath)
	all := slices.SortedFunc(slices.Values(append(want, wall.Mount{Path: sp.Dir}, wall.Mount{Path: res.SessionDir, ReadOnly: true})), byPath)
	if !slices.Equal(got, all) {
		t.Errorf("mounts %v\nwant %v in any order", w.got.Mounts, all)
	}
}

// TestTargetConflictsAreNoRun pins the refusals of mounts with a Target, each with the
// inner place and the outer one as its names, as passed, and its sentence: a writable
// mount inside a read-only one by their places inside is mount_mode_conflict; two
// mounts at one place inside, and a Target that is, holds or lies inside the workspace
// or the session's directory, are mount_target_conflict; and a mount with a Target whose
// path on this machine is, holds or lies inside another place's is mount_mode_conflict
// for the other mode and mount_target_conflict for the same one.
func TestTargetConflictsAreNoRun(t *testing.T) {
	home, other, mid := t.TempDir(), t.TempDir(), t.TempDir()
	ws := t.TempDir()
	inWS := mkdirs(t, filepath.Join(ws, "config"))
	for _, c := range []struct {
		name, code string
		mounts     []wall.Mount
		names      []string
		detail     string
	}{
		{"writable inside read-only, inside", "mount_mode_conflict",
			[]wall.Mount{{Path: home, ReadOnly: true, Target: homeInside}, {Path: other, Target: homeInside + "/sessions"}},
			[]string{other, home},
			"the mount " + other + " at " + homeInside + "/sessions (writable) lies inside the mount " + home + " at " +
				homeInside + " (read-only): a part of a read-only mount can't be writable"},
		{"one target twice", "mount_target_conflict",
			[]wall.Mount{{Path: home, Target: homeInside}, {Path: other, Target: homeInside}},
			[]string{other, home},
			"Show the mount " + other + " at " + homeInside + " at a place inside other than the mount " + home + " at " +
				homeInside + ": one place inside can't show two places"},
		{"a target at a mount's path", "mount_target_conflict",
			[]wall.Mount{{Path: home}, {Path: other, ReadOnly: true, Target: home}},
			[]string{other, home},
			"Show the mount " + other + " at " + home + " at a place inside other than the mount " + home +
				": one place inside can't show two places"},
		{"a target at the workspace", "mount_target_conflict",
			[]wall.Mount{{Path: other, Target: ws}},
			[]string{other, ws},
			"Show the mount " + other + " at " + ws + " at a place inside other than the workspace " + ws +
				": one place inside can't show two places"},
		{"a target inside the workspace", "mount_target_conflict",
			[]wall.Mount{{Path: other, ReadOnly: true, Target: ws + "/config"}},
			[]string{other, ws},
			"Show the mount " + other + " at " + ws + "/config at a place inside apart from the workspace " + ws +
				": the mount " + other + " at " + ws + "/config lies inside the workspace " + ws +
				", and a mount's target can't overlap the workspace inside"},
		{"a target around the workspace", "mount_target_conflict",
			[]wall.Mount{{Path: other, Target: filepath.Dir(ws)}},
			[]string{ws, other},
			"Show the mount " + other + " at " + filepath.Dir(ws) + " at a place inside apart from the workspace " + ws +
				": the workspace " + ws + " lies inside the mount " + other + " at " + filepath.Dir(ws) +
				", and a mount's target can't overlap the workspace inside"},
		{"a read-only file in a writable folder on this machine", "mount_mode_conflict",
			[]wall.Mount{{Path: home}, {Path: filepath.Join(home, "hooks.json"), ReadOnly: true, Target: homeInside + "/hooks.json"}},
			[]string{filepath.Join(home, "hooks.json"), home},
			"List the mount " + filepath.Join(home, "hooks.json") + " at " + homeInside + "/hooks.json and the mount " + home +
				" with paths on this machine apart from each other: the mount " + filepath.Join(home, "hooks.json") + " at " +
				homeInside + "/hooks.json (read-only) lies inside the mount " + home +
				" (writable) on this machine, and a mount with a target can't share a path with a place of the other mode"},
		{"a writable target in a writable folder on this machine", "mount_target_conflict",
			[]wall.Mount{{Path: home, Target: homeInside}, {Path: filepath.Join(home, "sessions")}},
			[]string{filepath.Join(home, "sessions"), home},
			"List the mount " + filepath.Join(home, "sessions") + " and the mount " + home + " at " + homeInside +
				" with paths on this machine apart from each other: the mount " + filepath.Join(home, "sessions") +
				" (writable) lies inside the mount " + home + " at " + homeInside +
				" (writable) on this machine, and a mount with a target can't share a path with another place"},
		{"a read-only file two names inside a writable target", "mount_mode_conflict",
			[]wall.Mount{{Path: home, Target: homeInside}, {Path: other, ReadOnly: true, Target: homeInside + "/a/hooks.json"}},
			[]string{other, home},
			"Show the mount " + other + " at " + homeInside + "/a/hooks.json one name below the mount " + home + " at " +
				homeInside + ", or make each directory between them a read-only place: the agent can rename " + homeInside +
				"/a, and the bind moves with it"},
		{"a read-only file below a writable place inside a writable target", "mount_mode_conflict",
			[]wall.Mount{{Path: home, Target: homeInside}, {Path: mid, Target: homeInside + "/a"},
				{Path: other, ReadOnly: true, Target: homeInside + "/a/hooks.json"}},
			[]string{other, home},
			"Show the mount " + other + " at " + homeInside + "/a/hooks.json one name below the mount " + home + " at " +
				homeInside + ", or make each directory between them a read-only place: the agent can rename " + homeInside +
				"/a, and the bind moves with it"},
		{"a target at the workspace's path on this machine", "mount_target_conflict",
			[]wall.Mount{{Path: inWS, Target: homeInside}},
			[]string{inWS, ws},
			"List the mount " + inWS + " at " + homeInside + " and the workspace " + ws +
				" with paths on this machine apart from each other: the mount " + inWS + " at " + homeInside +
				" (writable) lies inside the workspace " + ws +
				" (writable) on this machine, and a mount with a target can't share a path with another place"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := &openWall{}
			sp := walledSpec(t, w)
			sp.Mounts, sp.Dir = c.mounts, ws
			r := refusalOf(t, c.code, runErr(sp))
			if !slices.Equal(r.Names, c.names) || r.Detail != c.detail {
				t.Errorf("names %q, detail %q\nwant names %q, detail %q", r.Names, r.Detail, c.names, c.detail)
			}
			if w.wrapped {
				t.Error("the wall was wrapped")
			}
		})
	}

	// A Target that holds the session's directory, which lies in the runs directory.
	w := &openWall{}
	sp := walledSpec(t, w)
	sp.Mounts = []wall.Mount{{Path: other, ReadOnly: true, Target: sp.RunsDir}}
	r := refusalOf(t, "mount_target_conflict", runErr(sp))
	if len(r.Names) != 2 || r.Names[0] != other || !strings.HasPrefix(r.Names[1], sp.RunsDir+"/") ||
		r.Detail != "Set the target of the mount "+other+" at "+sp.RunsDir+" outside the session's directory "+r.Names[1]+
			": the enclosure shows that directory at its path, and a mount's target can't overlap it" {
		t.Errorf("names %q, detail %q", r.Names, r.Detail)
	}
	if w.wrapped {
		t.Error("the wall was wrapped")
	}
}

// TestAReadOnlyPlaceBelowReadOnlyPlacesInAWritableTargetIsBound pins the other case of a
// read-only place more than one name inside a writable one: each directory between
// them is a read-only place, so the agent can rename none of them.
func TestAReadOnlyPlaceBelowReadOnlyPlacesInAWritableTargetIsBound(t *testing.T) {
	home, files := t.TempDir(), t.TempDir()
	skills := mkdirs(t, filepath.Join(files, "skills"))
	hooks := filepath.Join(files, "hooks.json")
	if err := os.WriteFile(hooks, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := &openWall{}
	sp := walledSpec(t, w)
	sp.Mounts = []wall.Mount{
		{Path: home, Target: homeInside},
		{Path: skills, ReadOnly: true, Target: homeInside + "/skills"},
		{Path: hooks, ReadOnly: true, Target: homeInside + "/skills/hooks.json"},
	}
	if _, err := run(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(w.got.Mounts, wall.Mount{Path: hooks, ReadOnly: true, Target: homeInside + "/skills/hooks.json"}) {
		t.Errorf("mounts %v", w.got.Mounts)
	}
}

// TestALinkInAWritableTargetOnTheWayToAPlaceIsNoRun pins the check of the names from a
// writable place's path on this machine down to a place inside it: a symbolic link
// among them, which an agent of an earlier session may have written and which the
// engine follows, is mount_target_conflict, with the inner place and the writable one as
// its names, at the join and again just before the wall binds the places.
func TestALinkInAWritableTargetOnTheWayToAPlaceIsNoRun(t *testing.T) {
	files := t.TempDir()
	hooks := filepath.Join(files, "hooks.json")
	if err := os.WriteFile(hooks, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inner := mkdirs(t, filepath.Join(files, "sessions"))
	for name, c := range map[string]struct {
		link   string
		mounts func(home string) []wall.Mount
		names  func(home string) []string
		detail func(home string) string
	}{
		"at the file": {"hooks.json", func(home string) []wall.Mount {
			return []wall.Mount{{Path: home, Target: homeInside}, {Path: hooks, ReadOnly: true, Target: homeInside + "/hooks.json"}}
		}, func(home string) []string { return []string{hooks, home} }, func(home string) string {
			return "Remove the symbolic link " + filepath.Join(home, "hooks.json") + " from the mount " + home + " at " + homeInside +
				": the engine binds the mount " + hooks + " at " + homeInside + "/hooks.json through it and follows the link, " +
				"so the bind could resolve to a place outside the mount"
		}},
		"above a writable place": {"a", func(home string) []wall.Mount {
			return []wall.Mount{{Path: home, Target: homeInside}, {Path: inner, Target: homeInside + "/a/sessions"}}
		}, func(home string) []string { return []string{inner, home} }, func(home string) string {
			return "Remove the symbolic link " + filepath.Join(home, "a") + " from the mount " + home + " at " + homeInside +
				": the engine binds the mount " + inner + " at " + homeInside + "/a/sessions through it and follows the link, " +
				"so the bind could resolve to a place outside the mount"
		}},
	} {
		t.Run(name+", at the join", func(t *testing.T) {
			home := t.TempDir()
			symlink(t, t.TempDir(), filepath.Join(home, c.link))
			w := &openWall{}
			sp := walledSpec(t, w)
			sp.Mounts = c.mounts(home)
			r := refusalOf(t, "mount_target_conflict", runErr(sp))
			if !slices.Equal(r.Names, c.names(home)) || r.Detail != c.detail(home) {
				t.Errorf("names %q, detail %q\nwant %q", r.Names, r.Detail, c.detail(home))
			}
			if w.wrapped {
				t.Error("the wall was wrapped")
			}
		})
		t.Run(name+", before the wrap", func(t *testing.T) {
			home := t.TempDir()
			afterTheJoinsCheck(t, func() { symlink(t, t.TempDir(), filepath.Join(home, c.link)) })
			w := &openWall{}
			sp := walledSpec(t, w)
			sp.Mounts = c.mounts(home)
			r := refusalOf(t, "mount_target_conflict", runErr(sp))
			if r.Detail != c.detail(home) {
				t.Errorf("detail %q\nwant %q", r.Detail, c.detail(home))
			}
			if w.wrapped {
				t.Error("the wall was wrapped")
			}
		})
	}
}

// TestALinkBetweenReadOnlyPlacesIsNoRun pins the check of the names on this machine from
// a read-only place's path down to a place inside it: a symbolic link there, which the
// engine follows to bind the inner place, is mount_target_conflict, as in a writable
// place. The walk from an outer place stops at a nearer place, whose pair with the inner
// one checks the rest: a link in the outer place's directory below the nearer place's
// place inside is not on the way to the bind.
func TestALinkBetweenReadOnlyPlacesIsNoRun(t *testing.T) {
	outer, inner := t.TempDir(), t.TempDir()
	symlink(t, t.TempDir(), filepath.Join(outer, "c"))
	w := &openWall{}
	sp := walledSpec(t, w)
	sp.Mounts = []wall.Mount{{Path: outer, ReadOnly: true, Target: homeInside}, {Path: inner, ReadOnly: true, Target: homeInside + "/c"}}
	r := refusalOf(t, "mount_target_conflict", runErr(sp))
	want := "Remove the symbolic link " + filepath.Join(outer, "c") + " from the mount " + outer + " at " + homeInside +
		": the engine binds the mount " + inner + " at " + homeInside + "/c through it and follows the link, so the bind " +
		"could resolve to a place outside the mount"
	if !slices.Equal(r.Names, []string{inner, outer}) || r.Detail != want {
		t.Errorf("names %q, detail %q\nwant %q", r.Names, r.Detail, want)
	}
	if w.wrapped {
		t.Error("the wall was wrapped")
	}

	// A writable home, a read-only folder at b in it and a read-only file at b/c in the
	// folder: a link at b/c in the home's directory lies under the folder's bind.
	home, folder, file := t.TempDir(), t.TempDir(), filepath.Join(t.TempDir(), "c")
	if err := os.WriteFile(file, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mkdirs(t, filepath.Join(home, "b"))
	symlink(t, t.TempDir(), filepath.Join(home, "b", "c"))
	w = &openWall{}
	sp = walledSpec(t, w)
	sp.Mounts = []wall.Mount{{Path: home, Target: homeInside}, {Path: folder, ReadOnly: true, Target: homeInside + "/b"},
		{Path: file, ReadOnly: true, Target: homeInside + "/b/c"}}
	if _, err := run(context.Background(), sp); err != nil {
		t.Fatalf("a link under the folder's bind: %v", err)
	}

	// The same link in the folder's directory is on the way to the file's bind.
	symlink(t, t.TempDir(), filepath.Join(folder, "c"))
	w = &openWall{}
	sp = walledSpec(t, w)
	sp.Mounts = []wall.Mount{{Path: home, Target: homeInside}, {Path: folder, ReadOnly: true, Target: homeInside + "/b"},
		{Path: file, ReadOnly: true, Target: homeInside + "/b/c"}}
	r = refusalOf(t, "mount_target_conflict", runErr(sp))
	if !slices.Equal(r.Names, []string{file, folder}) || !strings.HasPrefix(r.Detail, "Remove the symbolic link "+filepath.Join(folder, "c")+" from the mount "+folder+" at "+homeInside+"/b:") {
		t.Errorf("names %q, detail %q", r.Names, r.Detail)
	}
}
