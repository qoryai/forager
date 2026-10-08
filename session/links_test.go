package session_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/runner/internal/event"
	"github.com/qoryai/runner/session"
	"github.com/qoryai/runner/wall"
)

// entry is a path as the runner looks its name up: in its parent, resolved.
func entry(t *testing.T, p string) string {
	t.Helper()
	parent, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, filepath.Base(p))
}

// link makes a symbolic link at at to to.
func link(t *testing.T, to, at string) {
	t.Helper()
	if err := os.Symlink(to, at); err != nil {
		t.Fatal(err)
	}
}

// TestAPlaceReachedThroughAnotherRunsBindIsNoRun pins that a place whose path goes
// through a link inside another walled run's writable bind is refused, though it
// resolves outside it: the other run's agent can point the link elsewhere before the
// engine binds the place. It holds for a mount and for a workspace alone.
func TestAPlaceReachedThroughAnotherRunsBindIsNoRun(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	out := filepath.Join(root, "out")
	link(t, outside, out)
	first, _ := hold(t, []wall.Mount{{Path: root}}, root)
	for _, mounts := range [][]wall.Mount{{{Path: out}}, nil} {
		sp := walledSpec(t, &openWall{})
		sp.Mounts, sp.Dir = mounts, out
		r := refusalOf(t, "mount_shared_with_run", runErr(sp))
		if want := []string{out, first.RunID, root}; !slices.Equal(r.Names, want) {
			t.Errorf("names %q, want %q", r.Names, want)
		}
		what := "the mount "
		if mounts == nil {
			what = "the workspace "
		}
		want := what + out + " (writable) is reached through " + entry(t, out) +
			", which lies inside " +
			"the writable bind " + root + " of the walled run " + first.RunID +
			", which is still going: a walled agent of that run can change it"
		if r.Detail != want {
			t.Errorf("detail %q\nwant   %q", r.Detail, want)
		}
	}
}

// TestABindOverAnotherRunsWayIsNoRun pins the reverse: a writable bind that holds a
// directory another walled run's place is looked up through is refused, though that
// place resolves outside it.
func TestABindOverAnotherRunsWayIsNoRun(t *testing.T) {
	p, elsewhere := t.TempDir(), t.TempDir()
	l := filepath.Join(p, "link")
	link(t, elsewhere, l)
	first, _ := hold(t, nil, l)
	sp := walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir = []wall.Mount{{Path: p}}, p
	r := refusalOf(t, "mount_shared_with_run", runErr(sp))
	if want := []string{p, first.RunID, l}; !slices.Equal(r.Names, want) {
		t.Errorf("names %q, want %q", r.Names, want)
	}
	want := "the mount " + p + " (writable) contains " + entry(t, l) +
		", on the way to the writable bind " +
		l + " of the walled run " + first.RunID + ", which is still going: this run's agent " +
		"could change it"
	if r.Detail != want {
		t.Errorf("detail %q\nwant   %q", r.Detail, want)
	}
}

// TestAWorkspaceThroughALinkInItsOwnRootIsThatRoot pins two runs with the same root,
// the second's workspace a link in it to elsewhere: the workspace lies inside the
// root it is looked up in, so the run binds the root alone, beside the other run's,
// and works at the link's path inside.
func TestAWorkspaceThroughALinkInItsOwnRootIsThatRoot(t *testing.T) {
	w, outside := t.TempDir(), t.TempDir()
	ws := filepath.Join(w, "ws")
	link(t, outside, ws)
	hold(t, []wall.Mount{{Path: w}}, w)
	o := &openWall{}
	sp := walledSpec(t, o)
	sp.Mounts, sp.Dir = []wall.Mount{{Path: w}}, ws
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	want := []wall.Mount{{Path: w}, {Path: res.Dir, ReadOnly: true}}
	if !slices.Equal(o.got.Mounts, want) || o.got.Dir != ws {
		t.Errorf("mounts %v, working directory %q", o.got.Mounts, o.got.Dir)
	}
}

// TestARunsDirectoryThroughAnotherRunsBindIsNoRun pins a runs directory that is a link
// inside another walled run's writable bind: refused before the runner writes the
// record through it, with the runs directory exactly as passed as the first name.
func TestARunsDirectoryThroughAnotherRunsBindIsNoRun(t *testing.T) {
	w, target := t.TempDir(), t.TempDir()
	runs := filepath.Join(w, "runs")
	link(t, target, runs)
	first, _ := hold(t, []wall.Mount{{Path: w}}, w)
	sp := walledSpec(t, &openWall{})
	sp.RunsDir = runs + "/"
	r := refusalOf(t, "mount_shared_with_run", runErr(sp))
	if want := []string{runs + "/", first.RunID, w}; !slices.Equal(r.Names, want) {
		t.Errorf("names %q, want %q", r.Names, want)
	}
	if !strings.HasPrefix(r.Detail, "the run directory "+runs+"/") ||
		!strings.Contains(r.Detail, " is reached through "+entry(t, runs)+
			", which lies inside the writable bind "+w) {
		t.Errorf("detail %q", r.Detail)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Errorf("the runner wrote through the link: %v", entries)
	}

	// A runs directory inside the other run's bind, by its path, written with a
	// component the comparison cleans away: the first name is the runs directory as
	// passed, byte for byte.
	sp = walledSpec(t, &openWall{})
	sp.RunsDir = w + "/./records"
	r = refusalOf(t, "mount_shared_with_run", runErr(sp))
	if r.Names[0] != w+"/./records" || r.Names[2] != w {
		t.Errorf("names %q", r.Names)
	}
}

// TestAPlaceThroughALinkInAWritablePlaceOfItsOwn pins one run whose read-only place is
// a link inside its own writable one: it lies inside that one, through the link, and
// is mount_mode_conflict. A runs directory that is such a link is
// mount_contains_runner_files.
func TestAPlaceThroughALinkInAWritablePlaceOfItsOwn(t *testing.T) {
	w, outside := t.TempDir(), t.TempDir()
	home := filepath.Join(w, "home")
	link(t, outside, home)
	sp := walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir = []wall.Mount{{Path: w}, {Path: home, ReadOnly: true}}, w
	r := refusalOf(t, "mount_mode_conflict", runErr(sp))
	want := "the mount " + home + " (read-only) is reached through " + entry(t, home) +
		", which lies " +
		"inside the mount " + w + " (writable): a part of a writable mount can't be read-only"
	if !slices.Equal(r.Names, []string{home, w}) || r.Detail != want {
		t.Errorf("names %q, detail %q", r.Names, r.Detail)
	}

	runs := filepath.Join(w, "runs")
	link(t, t.TempDir(), runs)
	sp = walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir, sp.RunsDir = []wall.Mount{{Path: w}}, w, runs
	r = mountRefusal(t, runErr(sp))
	want = "the mount " + w + " contains " + entry(t, runs) + ", on the way to " + runs +
		", where the run directories are kept"
	if !slices.Equal(r.Names, []string{w, runs}) || r.Detail != want {
		t.Errorf("names %q, detail %q", r.Names, r.Detail)
	}
}

// TestAModeConflictInTheWorkspaceSaysPlace pins the wording when the outer place is
// the workspace.
func TestAModeConflictInTheWorkspaceSaysPlace(t *testing.T) {
	ws := t.TempDir()
	vendor := mkdirs(t, filepath.Join(ws, "vendor"))
	sp := walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir = []wall.Mount{{Path: vendor, ReadOnly: true}}, ws
	r := refusalOf(t, "mount_mode_conflict", runErr(sp))
	want := "the mount " + vendor + " (read-only) lies inside the workspace " + ws +
		" (writable): a part of a writable place can't be read-only"
	if r.Detail != want {
		t.Errorf("detail %q", r.Detail)
	}
}

// repointingWall is an open wall that, while it is prepared, points a link elsewhere.
type repointingWall struct {
	openWall
	link, to string
}

func (w *repointingWall) Prepare(
	ctx context.Context, req wall.Request,
) (wall.Enclosure, error) {
	if err := os.Remove(w.link); err != nil {
		return nil, err
	}
	if err := os.Symlink(w.to, w.link); err != nil {
		return nil, err
	}
	return w.openWall.Prepare(ctx, req)
}

// TestALinkPointedElsewhereBeforeTheWrapFailsTheRun pins the second check: a workspace
// that is a link pointed elsewhere between the start and the wrap fails the run, and
// the enclosure is never wrapped.
func TestALinkPointedElsewhereBeforeTheWrapFailsTheRun(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	ws := filepath.Join(t.TempDir(), "ws")
	link(t, a, ws)
	w := &repointingWall{link: ws, to: b}
	sp := walledSpec(t, w)
	sp.Dir = ws
	err := runErr(sp)
	ra, _ := filepath.EvalSymlinks(a)
	rb, _ := filepath.EvalSymlinks(b)
	want := "the workspace " + ws + " resolved to " + ra +
		" when the run started and resolves to " + rb + " now"
	var r *session.Refusal
	if err == nil || errors.As(err, &r) || err.Error() != want {
		t.Errorf("got %v\nwant %s", err, want)
	}
	if w.wrapped || w.closed != 1 {
		t.Errorf("wrapped %v, closed %d times", w.wrapped, w.closed)
	}
}

// bindingWall is an open wall with binds of its own, which waits in Wrap until it is
// released, after the run has listed them.
type bindingWall struct {
	openWall
	binds   []wall.Bind
	reached chan struct{}
	release chan struct{}
	id      string
}

func (w *bindingWall) Binds(wall.Launch) ([]wall.Bind, error) { return w.binds, nil }

func (w *bindingWall) Prepare(_ context.Context, req wall.Request) (wall.Enclosure, error) {
	w.id = req.RunID
	return w, nil
}

func (w *bindingWall) Wrap(ctx context.Context, l wall.Launch) (wall.Launch, error) {
	if w.reached != nil {
		w.reached <- struct{}{}
		<-w.release
	}
	return w.openWall.Wrap(ctx, l)
}

// TestTheWallsOwnBindsAreAnotherRunsToo pins the binds a wall makes of its own: a
// writable bind that holds another walled run's helper, or directory, is refused, and
// a run whose own helper, or directory, lies inside another run's writable bind fails
// with a plain error.
func TestTheWallsOwnBindsAreAnotherRunsToo(t *testing.T) {
	h := t.TempDir()
	helper, dir := filepath.Join(h, "bin", "qory"), mkdirs(t, filepath.Join(h, "hooks"))
	mkdirs(t, filepath.Dir(helper))
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := &bindingWall{
		binds:   []wall.Bind{{Path: helper, ReadOnly: true, Helper: true}, {Path: dir}},
		reached: make(chan struct{}, 1), release: make(chan struct{}),
	}
	sp := walledSpec(t, w)
	s := start(sp)
	select {
	case <-w.reached:
	case <-s.done:
		t.Fatalf("the first run ended: %+v, %v", s.res, s.err)
	}
	for _, c := range []struct{ mount, name, what string }{
		{filepath.Dir(helper), helper, "the runner's helper "},
		{dir, dir, "the runner's directory "},
	} {
		other := walledSpec(t, &openWall{})
		other.Mounts = []wall.Mount{{Path: c.mount}}
		r := refusalOf(t, "mount_shared_with_run", runErr(other))
		want := "the mount " + c.mount + " (writable) contains " + c.what + c.name +
			" of the walled run " + w.id +
			", which is still going: this run's agent could change it"
		if !slices.Equal(r.Names, []string{c.mount, w.id, c.name}) || r.Detail != want {
			t.Errorf("names %q, detail %q", r.Names, r.Detail)
		}
	}
	close(w.release)
	<-s.done
	if s.err != nil {
		t.Fatal(s.err)
	}

	first, _ := hold(t, []wall.Mount{{Path: h}}, h)
	own := []wall.Bind{{Path: helper, ReadOnly: true, Helper: true}, {Path: dir}}
	for _, b := range own {
		mine := &bindingWall{binds: []wall.Bind{b}}
		sp := walledSpec(t, mine)
		err := runErr(sp)
		what := "the runner's directory "
		if b.Helper {
			what = "the runner's helper "
		}
		want := what + b.Path + " lies inside the writable bind " + h + " of the walled run " +
			first.RunID + ", which is still going: a walled agent of that run can change it"
		var r *session.Refusal
		if err == nil || errors.As(err, &r) || err.Error() != want {
			t.Errorf("got %v\nwant %s", err, want)
		}
		if mine.wrapped {
			t.Error("the enclosure was wrapped")
		}
	}
}

// TestAnotherRunsRunDirectoryIsItsAlone pins that a bind that is, holds or lies inside
// another walled run's run directory is refused, read-only included, with that run's
// runs directory as passed.
func TestAnotherRunsRunDirectoryIsItsAlone(t *testing.T) {
	first, _ := hold(t, nil, t.TempDir())
	runDir := filepath.Join(first.RunsDir, first.RunID)
	for _, c := range []struct{ mount, how string }{
		{runDir, " is "},
		{first.RunsDir, " contains "},
		{filepath.Join(runDir, "events.jsonl"), " lies inside "},
	} {
		sp := walledSpec(t, &openWall{})
		sp.Mounts = []wall.Mount{{Path: c.mount, ReadOnly: true}}
		r := refusalOf(t, "mount_shared_with_run", runErr(sp))
		if !slices.Equal(r.Names, []string{c.mount, first.RunID, first.RunsDir}) ||
			!strings.Contains(r.Detail, "(read-only)"+c.how+"the run directory ") ||
			!strings.HasSuffix(r.Detail,
				"which is still going: a run directory is its runner's alone") {
			t.Errorf("names %q, detail %q", r.Names, r.Detail)
		}
	}
}

// TestARunWaitsForTheRegistrysLock pins the lock: a run held between its check and its
// entry keeps a second run from checking until it is listed, and the second is then
// refused. Without the lock the second checks at once, finds no entry and goes on.
func TestARunWaitsForTheRegistrysLock(t *testing.T) {
	root := t.TempDir()
	sub := mkdirs(t, filepath.Join(root, "sub"))
	firstID := event.NewRunID()
	paused, resume := make(chan struct{}), make(chan struct{})
	var resumeOnce sync.Once
	letGo := func() { resumeOnce.Do(func() { close(resume) }) }
	session.SetRegisterPause(func(id string) {
		if id == firstID {
			close(paused)
			<-resume
		}
	})
	w := newHoldingWall()
	var releaseOnce sync.Once
	t.Cleanup(func() {
		letGo()
		releaseOnce.Do(func() { close(w.release) })
		session.SetRegisterPause(nil)
	})
	sp := walledSpec(t, w)
	sp.RunID, sp.Mounts, sp.Dir = firstID, []wall.Mount{{Path: root}}, root
	first := start(sp)
	// Cleanups run last first: this one waits for the run the one above lets go.
	t.Cleanup(func() {
		letGo()
		releaseOnce.Do(func() { close(w.release) })
		<-first.done
	})
	wait := func(c <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-c:
		case <-time.After(30 * time.Second):
			t.Fatal("timed out waiting for " + what)
		}
	}
	wait(paused, "the first run's check")
	other := walledSpec(t, &openWall{})
	other.Mounts, other.Dir = []wall.Mount{{Path: sub}}, sub
	second := start(other)
	select {
	case <-second.done:
		t.Fatalf("the second run went on while the first held the lock: %+v, %v",
			second.res, second.err)
	case <-time.After(500 * time.Millisecond):
	}
	letGo()
	wait(w.reached, "the first run's wall")
	wait(second.done, "the second run")
	refusalOf(t, "mount_shared_with_run", second.err)
}

// TestAnotherRunsBindThatCannotBeResolvedFailsTheRun pins that a bind of another
// walled run's this run cannot resolve stops the run, rather than being passed over.
func TestAnotherRunsBindThatCannotBeResolvedFailsTheRun(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root searches every directory")
	}
	locked := t.TempDir()
	inner := mkdirs(t, filepath.Join(locked, "inner"))
	first, _ := hold(t, nil, inner)
	if err := os.Chmod(locked, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })
	sp := walledSpec(t, &openWall{})
	err := runErr(sp)
	var r *session.Refusal
	if err == nil || errors.As(err, &r) ||
		!strings.Contains(err.Error(), "of the walled run "+first.RunID+", which is still going") {
		t.Errorf("got %v", err)
	}
	os.Chmod(locked, 0o755)
}
