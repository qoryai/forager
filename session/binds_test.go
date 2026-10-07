package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/runner/session"
	"github.com/qoryai/runner/wall"
)

// refusalOf is the refusal with the code a run returned, or fails the test.
func refusalOf(t *testing.T, code string, err error) *session.Refusal {
	t.Helper()
	var r *session.Refusal
	if !errors.As(err, &r) || r.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
	return r
}

// mkdirs makes the directories and returns the first.
func mkdirs(t *testing.T, dirs ...string) string {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dirs[0]
}

// walledSpec is a walled run of the fake runtime behind an open wall.
func walledSpec(t *testing.T, w wall.Wall) session.Spec {
	t.Helper()
	sp := spec(t, nil, "FAKE_EXIT=0")
	sp.Wall, sp.Image = w, "example.com/agent:1"
	return sp
}

// TestTheWorkspaceIsReachedThroughTheMountThatHoldsIt pins one bind for a checkout: a
// workspace below a mount gets no bind of its own, and is the working directory inside;
// a workspace no mount holds is bound at its own path, writable.
func TestTheWorkspaceIsReachedThroughTheMountThatHoldsIt(t *testing.T) {
	root := t.TempDir()
	sub := mkdirs(t, filepath.Join(root, "src", "app"))
	w := &openWall{}
	sp := walledSpec(t, w)
	sp.Mounts, sp.Dir = []wall.Mount{{Path: root}}, sub
	res, err := session.Run(context.Background(), sp)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("%+v, %v", res, err)
	}
	want := []wall.Mount{{Path: root}, {Path: res.Dir, ReadOnly: true}}
	if !slices.Equal(w.got.Mounts, want) {
		t.Errorf("mounts %v, want %v", w.got.Mounts, want)
	}
	if w.got.Dir != sub {
		t.Errorf("the working directory %q, want %q", w.got.Dir, sub)
	}

	// A workspace that lies inside a link to the mount is reached through the mount, at
	// the mount's path.
	link := filepath.Join(t.TempDir(), "checkout")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	w = &openWall{}
	sp = walledSpec(t, w)
	sp.Mounts, sp.Dir = []wall.Mount{{Path: root}}, filepath.Join(link, "src", "app")
	if _, err := session.Run(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	if len(w.got.Mounts) != 2 || w.got.Mounts[0].Path != root || w.got.Dir != sub {
		t.Errorf("mounts %v, working directory %q", w.got.Mounts, w.got.Dir)
	}

	// No mount holds the workspace: it is bound at its own path, writable.
	home := t.TempDir()
	w = &openWall{}
	sp = walledSpec(t, w)
	sp.Mounts = []wall.Mount{{Path: home, ReadOnly: true}}
	res, err = session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	want = []wall.Mount{
		{Path: home, ReadOnly: true}, {Path: sp.Dir}, {Path: res.Dir, ReadOnly: true},
	}
	if !slices.Equal(w.got.Mounts, want) || w.got.Dir != sp.Dir {
		t.Errorf("mounts %v, working directory %q", w.got.Mounts, w.got.Dir)
	}
}

// TestNestedMountsOfOneModeAreOneBind pins that a mount inside another one of the
// same mode is reached through the outer one, which alone is bound, whichever comes
// first, and that two of one path are one bind.
func TestNestedMountsOfOneModeAreOneBind(t *testing.T) {
	root := t.TempDir()
	vendor := mkdirs(t, filepath.Join(root, "vendor"))
	ro := t.TempDir()
	docs := mkdirs(t, filepath.Join(ro, "docs"))
	w := &openWall{}
	sp := walledSpec(t, w)
	sp.Dir = root
	sp.Mounts = []wall.Mount{
		{Path: vendor}, {Path: root}, {Path: docs, ReadOnly: true}, {Path: ro, ReadOnly: true},
		{Path: root + "/"},
	}
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	want := []wall.Mount{
		{Path: root}, {Path: ro, ReadOnly: true}, {Path: res.Dir, ReadOnly: true},
	}
	if !slices.Equal(w.got.Mounts, want) {
		t.Errorf("mounts %v, want %v", w.got.Mounts, want)
	}
}

// TestNestedMountsOfTwoModesAreNoRun pins mount_mode_conflict: a read-only mount inside
// a writable one, a writable one inside a read-only one, and the workspace inside a
// read-only one, each with the inner path and the outer one exactly as passed.
func TestNestedMountsOfTwoModesAreNoRun(t *testing.T) {
	root := t.TempDir()
	vendor := mkdirs(t, filepath.Join(root, "vendor"))
	for _, c := range []struct {
		name   string
		mounts []wall.Mount
		dir    string
		names  []string
		detail string
	}{
		{"read-only inside writable",
			[]wall.Mount{{Path: root}, {Path: vendor + "/", ReadOnly: true}}, root,
			[]string{vendor + "/", root},
			"the mount " + vendor + "/ (read-only) lies inside the mount " + root +
				" (writable): a part of a writable mount can't be read-only"},
		{"writable inside read-only",
			[]wall.Mount{{Path: root + "/./vendor"}, {Path: root, ReadOnly: true}}, t.TempDir(),
			[]string{root + "/./vendor", root},
			"the mount " + root + "/./vendor (writable) lies inside the mount " + root +
				" (read-only): a part of a read-only mount can't be writable"},
		{"the workspace inside read-only",
			[]wall.Mount{{Path: root, ReadOnly: true}}, vendor + "/",
			[]string{vendor + "/", root},
			"the workspace " + vendor + "/ (writable) lies inside the mount " + root +
				" (read-only): a part of a read-only mount can't be writable"},
		{"one path in both modes",
			[]wall.Mount{{Path: root}, {Path: root + "/", ReadOnly: true}}, root,
			[]string{root + "/", root},
			"the mount " + root + "/ (read-only) is the mount " + root +
				" (writable): one place can't be both writable and read-only"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := &openWall{}
			sp := walledSpec(t, w)
			sp.Mounts, sp.Dir = c.mounts, c.dir
			r := refusalOf(t, "mount_mode_conflict", runErr(sp))
			if !slices.Equal(r.Names, c.names) || r.Detail != c.detail {
				t.Errorf("names %q, detail %q", r.Names, r.Detail)
			}
			if w.req.RunID != "" {
				t.Error("the wall was prepared")
			}
		})
	}
}

// TestTheRunsDirectoryIsOneOfTheRunnersFiles pins that a walled run's mount, or its
// workspace, that is, holds or lies inside the runs directory is no run, the default
// one inside the workspace included, and that a run without a wall keeps its default.
func TestTheRunsDirectoryIsOneOfTheRunnersFiles(t *testing.T) {
	sp := walledSpec(t, &openWall{})
	parent := filepath.Dir(sp.RunsDir)
	sp.Mounts = []wall.Mount{{Path: parent + "/"}}
	r := mountRefusal(t, runErr(sp))
	if want := []string{parent + "/", sp.RunsDir}; !slices.Equal(r.Names, want) ||
		r.Detail != "the mount "+parent+"/ contains "+sp.RunsDir+
			", where the run directories are kept" {
		t.Errorf("names %q, detail %q", r.Names, r.Detail)
	}

	sp = walledSpec(t, &openWall{})
	sp.RunsDir = ""
	sp.Mounts = []wall.Mount{{Path: sp.Dir}}
	r = mountRefusal(t, runErr(sp))
	want := []string{sp.Dir, filepath.Join(sp.Dir, ".qory", "runs")}
	if !slices.Equal(r.Names, want) {
		t.Errorf("names %q", r.Names)
	}

	sp = spec(t, nil, "FAKE_EXIT=0")
	sp.RunsDir = ""
	res, err := session.Run(context.Background(), sp)
	if err != nil || res.Dir != filepath.Join(sp.Dir, ".qory", "runs", res.RunID) {
		t.Errorf("an unwalled run: %+v, %v", res, err)
	}
}

// TestTheRegistryIsOneOfTheRunnersFiles pins that a mount of the registry of walled
// runs, or of a directory above it, is no run.
func TestTheRegistryIsOneOfTheRunnersFiles(t *testing.T) {
	reg := registry(t)
	for _, mount := range []string{reg, filepath.Dir(reg)} {
		sp := walledSpec(t, &openWall{})
		sp.Mounts = []wall.Mount{{Path: mount}}
		r := mountRefusal(t, runErr(sp))
		if want := []string{mount, reg}; !slices.Equal(r.Names, want) ||
			!strings.Contains(r.Detail, "where the runner lists the walled runs still going") {
			t.Errorf("names %q, detail %q", r.Names, r.Detail)
		}
	}
}

// TestALinkedRunnerFileIsKeptAsAPattern pins that a runner file passed as a pattern of
// one name, the way a caller keeps a link from being replaced, is refused by the
// mount of its directory, with the pattern as passed as the refusal's second name.
func TestALinkedRunnerFileIsKeptAsAPattern(t *testing.T) {
	dir := mkdirs(t, filepath.Join(t.TempDir(), "conf"))
	target := filepath.Join(t.TempDir(), "x.yaml")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "x.yaml")); err != nil {
		t.Fatal(err)
	}
	pattern := dir + "/[x].yaml"
	for _, mount := range []string{dir, filepath.Dir(dir)} {
		sp := walledSpec(t, &openWall{})
		sp.RunnerFiles = []string{pattern}
		sp.Mounts = []wall.Mount{{Path: mount}}
		r := mountRefusal(t, runErr(sp))
		if r.Names[0] != mount || r.Names[1] != pattern {
			t.Errorf("names %q", r.Names)
		}
	}
}

// registry is the directory of the registry of walled runs the tests use.
func registry(t *testing.T) string {
	t.Helper()
	state := os.Getenv("XDG_STATE_HOME")
	if state == "" {
		t.Fatal("the tests' XDG_STATE_HOME is not set")
	}
	return filepath.Join(state, "qory-runner", "walled")
}

// holdingWall is an open wall whose Prepare waits until it is released, so its run is
// a walled run still going for as long as the test needs.
type holdingWall struct {
	openWall
	reached chan struct{}
	release chan struct{}
	fail    error
	// id is the run's id, set before reached is signalled.
	id string
}

func newHoldingWall() *holdingWall {
	return &holdingWall{reached: make(chan struct{}, 1), release: make(chan struct{})}
}

func (w *holdingWall) Prepare(
	ctx context.Context, req wall.Request,
) (wall.Enclosure, error) {
	w.id = req.RunID
	w.reached <- struct{}{}
	<-w.release
	if w.fail != nil {
		return nil, w.fail
	}
	return w.openWall.Prepare(ctx, req)
}

// started is a run started in the background, and what it came to.
type started struct {
	done chan struct{}
	res  *session.Result
	err  error
}

func start(sp session.Spec) *started {
	s := &started{done: make(chan struct{})}
	go func() {
		defer close(s.done)
		s.res, s.err = session.Run(context.Background(), sp)
	}()
	return s
}

// hold starts a walled run with the mounts and waits until it is going. The returned
// function lets it finish and waits for it.
func hold(t *testing.T, mounts []wall.Mount, dir string) (session.Spec, func() *started) {
	t.Helper()
	w := newHoldingWall()
	sp := walledSpec(t, w)
	sp.Mounts, sp.Dir = mounts, dir
	s := start(sp)
	select {
	case <-w.reached:
		sp.RunID = w.id
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
	return sp, finish
}

// TestABindInsideAnotherWalledRunsIsNoRun pins mount_shared_with_run: a run whose mount
// lies inside a writable bind of a walled run still going, and one whose writable mount
// holds a bind of such a run, are refused with this run's path, the other run's id and
// its path, each as passed; once that run ends, the same run starts.
func TestABindInsideAnotherWalledRunsIsNoRun(t *testing.T) {
	root := t.TempDir()
	sub := mkdirs(t, filepath.Join(root, "sub"))
	first, finish := hold(t, []wall.Mount{{Path: root + "/"}}, root)

	sp := walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir = []wall.Mount{{Path: sub + "/"}}, sub
	r := refusalOf(t, "mount_shared_with_run", runErr(sp))
	if want := []string{sub + "/", first.RunID, root + "/"}; !slices.Equal(r.Names, want) {
		t.Errorf("names %q, want %q", r.Names, want)
	}
	want := "the mount " + sub + "/ (writable) lies inside the writable bind " + root +
		"/ of the walled run " + first.RunID +
		", which is still going: a walled agent of that run can change it"
	if r.Detail != want {
		t.Errorf("detail %q\nwant   %q", r.Detail, want)
	}
	if got := session.Overlap(r.Names[0], r.Names[2]); got != "lies inside" {
		t.Errorf("Overlap = %q", got)
	}
	// Read-only, the same.
	sp.Mounts = []wall.Mount{{Path: sub, ReadOnly: true}}
	sp.Dir = t.TempDir()
	refusalOf(t, "mount_shared_with_run", runErr(sp))

	// The reverse: this run's writable mount holds the other run's bind.
	s := finish()
	if s.err != nil {
		t.Fatal(s.err)
	}
	first, _ = hold(t, []wall.Mount{{Path: sub}}, sub)
	sp = walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir = []wall.Mount{{Path: root}}, root
	r = refusalOf(t, "mount_shared_with_run", runErr(sp))
	if want := []string{root, first.RunID, sub}; !slices.Equal(r.Names, want) {
		t.Errorf("names %q, want %q", r.Names, want)
	}
	want = "the mount " + root + " (writable) contains the writable bind " + sub +
		" of the walled run " + first.RunID +
		", which is still going: this run's agent could change it"
	if r.Detail != want {
		t.Errorf("detail %q\nwant   %q", r.Detail, want)
	}
	if got := session.Overlap(r.Names[0], r.Names[2]); got != "contains" {
		t.Errorf("Overlap = %q", got)
	}
}

// TestTheEntryOfAWalledRunLastsAsLongAsTheRun pins the registry's entry: the run's id,
// its process and its binds, each as passed, as resolved and whether writable, in a
// file only its user reads, removed when the run ends, so the run that was refused
// starts.
func TestTheEntryOfAWalledRunLastsAsLongAsTheRun(t *testing.T) {
	root := t.TempDir()
	sub := mkdirs(t, filepath.Join(root, "sub"))
	first, finish := hold(t, []wall.Mount{{Path: root}}, sub)
	reg := registry(t)
	if info, err := os.Stat(reg); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("the registry: %v, %v", info, err)
	}
	file := filepath.Join(reg, first.RunID)
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the entry: %v, %v", info, err)
	}
	b, _ := os.ReadFile(file)
	var entry struct {
		RunID string `json:"run_id"`
		PID   int    `json:"pid"`
		Binds []struct {
			Path, Resolved string
			Writable       bool
		} `json:"binds"`
	}
	if err := json.Unmarshal(b, &entry); err != nil || entry.RunID != first.RunID ||
		entry.PID != os.Getpid() || len(entry.Binds) != 2 {
		t.Fatalf("the entry %s: %v", b, err)
	}
	real, _ := filepath.EvalSymlinks(root)
	runs, _ := filepath.EvalSymlinks(filepath.Dir(first.RunsDir))
	if bd := entry.Binds[0]; bd.Path != root || bd.Resolved != real || !bd.Writable {
		t.Errorf("the checkout's bind %+v", bd)
	}
	bd := entry.Binds[1]
	if bd.Path != first.RunsDir || bd.Resolved != filepath.Join(runs, "runs", first.RunID) ||
		bd.Writable {
		t.Errorf("the run directory's bind %+v", bd)
	}

	sp := walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir = []wall.Mount{{Path: sub}}, sub
	refusalOf(t, "mount_shared_with_run", runErr(sp))
	if s := finish(); s.err != nil || s.res.ExitCode != 0 {
		t.Fatalf("the first run: %+v, %v", s.res, s.err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("the entry is still there: %v", err)
	}
	if res, err := session.Run(context.Background(), sp); err != nil || res.ExitCode != 0 {
		t.Errorf("the run after the first ended: %+v, %v", res, err)
	}
}

// TestAWalledRunThatFailsLeavesTheRegistry pins that a run that fails after it was
// listed, here when its wall fails, is listed no more.
func TestAWalledRunThatFailsLeavesTheRegistry(t *testing.T) {
	root := t.TempDir()
	w := newHoldingWall()
	w.fail = errors.New("the engine is gone")
	close(w.release)
	sp := walledSpec(t, w)
	sp.RunID = "0191f2a4-0000-7000-8000-00000000000b"
	sp.Mounts, sp.Dir = []wall.Mount{{Path: root}}, root
	err := runErr(sp)
	if err == nil || !strings.Contains(err.Error(), "the engine is gone") {
		t.Fatalf("the failing run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(registry(t), sp.RunID)); !os.IsNotExist(err) {
		t.Errorf("the entry is still there: %v", err)
	}
	sp = walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir = []wall.Mount{{Path: root}}, root
	if res, err := session.Run(context.Background(), sp); err != nil || res.ExitCode != 0 {
		t.Errorf("the run after it: %+v, %v", res, err)
	}
}

// TestBindsThatMayShareRunSideBySide pins what two walled runs share: the same root,
// both writable, and a read-only bind inside another run's read-only one.
func TestBindsThatMayShareRunSideBySide(t *testing.T) {
	root := t.TempDir()
	sub := mkdirs(t, filepath.Join(root, "sub"))
	hold(t, []wall.Mount{{Path: root}}, sub)
	sp := walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir = []wall.Mount{{Path: root + "/"}}, root
	if res, err := session.Run(context.Background(), sp); err != nil || res.ExitCode != 0 {
		t.Errorf("the same root: %+v, %v", res, err)
	}

	ro := t.TempDir()
	docs := mkdirs(t, filepath.Join(ro, "docs"))
	hold(t, []wall.Mount{{Path: ro, ReadOnly: true}}, t.TempDir())
	sp = walledSpec(t, &openWall{})
	sp.Mounts = []wall.Mount{{Path: docs, ReadOnly: true}}
	if res, err := session.Run(context.Background(), sp); err != nil || res.ExitCode != 0 {
		t.Errorf("read-only inside read-only: %+v, %v", res, err)
	}
}

// TestAStaleEntryIsRemoved pins that an entry no runner holds, that of a run whose
// runner died, decides nothing and is removed.
func TestAStaleEntryIsRemoved(t *testing.T) {
	root := t.TempDir()
	reg := registry(t)
	if err := os.MkdirAll(reg, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(reg, "0191f2a4-0000-7000-8000-0000000000ff")
	b, _ := json.Marshal(map[string]any{
		"run_id": filepath.Base(stale), "pid": 1,
		"binds": []map[string]any{{"path": "/", "resolved": "/", "writable": true}},
	})
	if err := os.WriteFile(stale, b, 0o600); err != nil {
		t.Fatal(err)
	}
	sp := walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir = []wall.Mount{{Path: root}}, root
	if res, err := session.Run(context.Background(), sp); err != nil || res.ExitCode != 0 {
		t.Fatalf("a run beside a stale entry: %+v, %v", res, err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("the stale entry is still there: %v", err)
	}
}

// TestRunsThatStartTogetherAreCheckedInTurn pins the registry's lock: of two walled
// runs that start at once, one inside the other's writable bind, one is listed and the
// other refused, whichever comes first.
func TestRunsThatStartTogetherAreCheckedInTurn(t *testing.T) {
	for range 5 {
		root := t.TempDir()
		sub := mkdirs(t, filepath.Join(root, "sub"))
		walls := []*holdingWall{newHoldingWall(), newHoldingWall()}
		var runs []*started
		for i, m := range []string{root, sub} {
			sp := walledSpec(t, walls[i])
			sp.Mounts, sp.Dir = []wall.Mount{{Path: m}}, m
			runs = append(runs, start(sp))
		}
		reached, refused := 0, 0
		for i, s := range runs {
			select {
			case <-walls[i].reached:
				reached++
			case <-s.done:
				var r *session.Refusal
				if errors.As(s.err, &r) && r.Code == "mount_shared_with_run" {
					refused++
				} else {
					t.Errorf("run %d: %+v, %v", i, s.res, s.err)
				}
			}
		}
		for i, s := range runs {
			close(walls[i].release)
			<-s.done
		}
		if reached != 1 || refused != 1 {
			t.Fatalf("%d runs went on, %d were refused", reached, refused)
		}
	}
}

// TestARegistryOthersWriteIsRefused pins that the runner uses its registry only while
// it is a directory of this user's that no one else writes.
func TestARegistryOthersWriteIsRefused(t *testing.T) {
	reg := registry(t)
	if err := os.MkdirAll(reg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(reg, 0o770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(reg, 0o700) })
	sp := walledSpec(t, &openWall{})
	err := runErr(sp)
	var r *session.Refusal
	if err == nil || errors.As(err, &r) ||
		!strings.Contains(err.Error(), "writable by others than its owner") {
		t.Errorf("a run with the registry open to its group: %v", err)
	}
}
