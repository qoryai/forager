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

// throughLink checks a mount_through_link refusal: its names, and its sentence.
func throughLink(t *testing.T, err error, place, link, outer string) {
	t.Helper()
	r := refusalOf(t, "mount_through_link", err)
	want := place + " is reached through the link " + link + " inside " + outer +
		", which a walled agent can change: list the link's target itself"
	if !slices.Equal(r.Names, []string{place, link, outer}) || r.Detail != want {
		t.Errorf("names %q, detail %q\nwant names %q, detail %q",
			r.Names, r.Detail, []string{place, link, outer}, want)
	}
}

// TestAPlaceThroughALinkInAWritablePlaceIsNoRun pins a link an agent plants inside a
// writable place, at a directory of this machine's such as one a login session reads
// programs from, listed as a second place: the link would choose what is bound, so the
// run is refused, writable or read-only, the place itself the link.
func TestAPlaceThroughALinkInAWritablePlaceIsNoRun(t *testing.T) {
	root := t.TempDir()
	agents := mkdirs(t, filepath.Join(t.TempDir(), "Library", "LaunchAgents"))
	out := filepath.Join(root, "out")
	link(t, agents, out)
	for _, readOnly := range []bool{false, true} {
		sp := walledSpec(t, &openWall{})
		sp.Mounts = []wall.Mount{{Path: root}, {Path: out, ReadOnly: readOnly}}
		sp.Dir = root
		throughLink(t, runErr(sp), out, out, root)
	}
}

// TestAWorkspaceThroughALinkInItsOwnRootIsNoRun pins two runs with the same root, the
// second's workspace a link in it that the first run's agent can plant: the workspace
// is refused, so that agent does not choose what the second run binds.
func TestAWorkspaceThroughALinkInItsOwnRootIsNoRun(t *testing.T) {
	w, outside := t.TempDir(), t.TempDir()
	ws := filepath.Join(w, "ws")
	link(t, outside, ws)
	hold(t, []wall.Mount{{Path: w}}, w)
	sp := walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir = []wall.Mount{{Path: w}}, ws
	throughLink(t, runErr(sp), ws, ws, w)
}

// TestTheLinkNamedIsTheOneThatLeadsOut pins the link a mount_through_link refusal
// names: a link, absolute and clean, inside the writable place, the last one on the
// way, whether it lies deeper than the first name, follows another link inside, or
// has a target with "..".
func TestTheLinkNamedIsTheOneThatLeadsOut(t *testing.T) {
	top := t.TempDir()
	w, x := mkdirs(t, filepath.Join(top, "w")), mkdirs(t, filepath.Join(top, "x"))
	mkdirs(t, filepath.Join(x, "c"))
	run := func(place string) error {
		sp := walledSpec(t, &openWall{})
		sp.Mounts, sp.Dir = []wall.Mount{{Path: w}, {Path: place}}, w
		return runErr(sp)
	}

	deep := filepath.Join(mkdirs(t, filepath.Join(w, "a")), "l")
	link(t, x, deep)
	place := filepath.Join(deep, "c")
	throughLink(t, run(place), place, deep, w)

	d := mkdirs(t, filepath.Join(w, "d"))
	l1, l2 := filepath.Join(w, "l1"), filepath.Join(d, "l2")
	link(t, d, l1)
	link(t, x, l2)
	place = filepath.Join(l1, "l2")
	throughLink(t, run(place), place, l2, w)

	up := filepath.Join(w, "up")
	link(t, "a/../../x", up)
	throughLink(t, run(up), up, up, w)
}

// TestALinkThatLeadsBackIntoItsPlaceIsReachedThroughIt pins a link inside a writable
// place to a directory of that place: the place lies inside it, and is reached through
// it with nothing bound through the link.
func TestALinkThatLeadsBackIntoItsPlaceIsReachedThroughIt(t *testing.T) {
	w := t.TempDir()
	v2 := mkdirs(t, filepath.Join(w, "v2"))
	cur := filepath.Join(w, "current")
	link(t, v2, cur)
	o := &openWall{}
	sp := walledSpec(t, o)
	sp.Mounts, sp.Dir = []wall.Mount{{Path: w}, {Path: cur}}, cur
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	want := []wall.Mount{{Path: w}, {Path: res.Dir, ReadOnly: true}}
	if !slices.Equal(o.got.Mounts, want) || o.got.Dir != v2 {
		t.Errorf("mounts %v, working directory %q", o.got.Mounts, o.got.Dir)
	}
}

// TestALinkInsideNoPlaceIsFollowedWhereItLeads pins a place whose own path has a link
// that lies inside none of the run's places: it is bound at its path as passed, which
// the engine follows to the link's target.
func TestALinkInsideNoPlaceIsFollowedWhereItLeads(t *testing.T) {
	ws, outside := t.TempDir(), t.TempDir()
	home := filepath.Join(t.TempDir(), "home")
	link(t, outside, home)
	o := &openWall{}
	sp := walledSpec(t, o)
	sp.Mounts, sp.Dir = []wall.Mount{{Path: ws}, {Path: home, ReadOnly: true}}, ws
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	want := []wall.Mount{{Path: ws}, {Path: home, ReadOnly: true},
		{Path: res.Dir, ReadOnly: true}}
	if !slices.Equal(o.got.Mounts, want) || o.got.Dir != ws {
		t.Errorf("mounts %v, working directory %q", o.got.Mounts, o.got.Dir)
	}
}

// TestALinkToTheRunnersFilesInsideAPlaceIsTheirs pins a place that is a link inside a
// writable place to a runs directory: it is one of the runner's files, as every place
// that resolves to one is.
func TestALinkToTheRunnersFilesInsideAPlaceIsTheirs(t *testing.T) {
	root, runs := t.TempDir(), t.TempDir()
	to := filepath.Join(root, "records")
	link(t, runs, to)
	sp := walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir, sp.RunsDir = []wall.Mount{{Path: root}, {Path: to}}, root, runs
	if r := mountRefusal(t, runErr(sp)); !slices.Equal(r.Names, []string{to, runs}) {
		t.Errorf("names %q, detail %q", r.Names, r.Detail)
	}
}

// TestAChainOfLinkedPlacesIsNoRun pins a chain: a mount through a link in another
// mount, to the root another walled run binds, and the workspace inside that root. The
// linked mount is refused, so nothing is bound that the run did not list as it is.
func TestAChainOfLinkedPlacesIsNoRun(t *testing.T) {
	e, w := t.TempDir(), t.TempDir()
	mkdirs(t, filepath.Join(e, "ws"))
	hold(t, []wall.Mount{{Path: e}}, e)
	l := filepath.Join(w, "link")
	link(t, e, l)
	sp := walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir = []wall.Mount{{Path: w}, {Path: l}}, filepath.Join(e, "ws")
	throughLink(t, runErr(sp), l, l, w)
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
// a link inside its own writable one: mount_through_link, as a writable one is. A runs
// directory that is such a link is mount_contains_runner_files.
func TestAPlaceThroughALinkInAWritablePlaceOfItsOwn(t *testing.T) {
	w, outside := t.TempDir(), t.TempDir()
	home := filepath.Join(w, "home")
	link(t, outside, home)
	sp := walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir = []wall.Mount{{Path: w}, {Path: home, ReadOnly: true}}, w
	throughLink(t, runErr(sp), home, home, w)

	runs := filepath.Join(w, "runs")
	link(t, t.TempDir(), runs)
	sp = walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir, sp.RunsDir = []wall.Mount{{Path: w}}, w, runs
	r := mountRefusal(t, runErr(sp))
	want := "the mount " + w + " contains " + entry(t, runs) + ", on the way to " + runs +
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

// heldBinder is a wall that binds a helper and directories of its own and holds the run
// after its first check, before its enclosure is prepared.
type heldBinder struct {
	*holdingWall
	binds []wall.Bind
}

func (w heldBinder) Binds(wall.Launch) ([]wall.Bind, error) { return w.binds, nil }

// TestAWallsHelperIsListedFromTheStart pins that the wall's own binds are listed when
// the run starts: a run whose writable mount holds the helper of a walled run that has
// not reached its enclosure yet is refused, and a run whose wall lists the same
// patterns of private directories runs beside it.
func TestAWallsHelperIsListedFromTheStart(t *testing.T) {
	h := t.TempDir()
	helper := filepath.Join(mkdirs(t, filepath.Join(h, "bin")), "qory")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	own := []wall.Bind{
		{Path: helper, ReadOnly: true, Helper: true},
		{Path: wall.TempDirs(), ReadOnly: true, Pattern: true},
	}
	w := heldBinder{newHoldingWall(), own}
	s := start(walledSpec(t, w))
	select {
	case <-w.reached:
	case <-s.done:
		t.Fatalf("the first run ended: %+v, %v", s.res, s.err)
	}
	t.Cleanup(func() {
		close(w.release)
		<-s.done
	})
	other := walledSpec(t, &openWall{})
	other.Mounts = []wall.Mount{{Path: h}}
	r := refusalOf(t, "mount_shared_with_run", runErr(other))
	want := "the mount " + h + " (writable) contains the runner's helper " + helper +
		" of the walled run " + w.id +
		", which is still going: this run's agent could change it"
	if !slices.Equal(r.Names, []string{h, w.id, helper}) || r.Detail != want {
		t.Errorf("names %q, detail %q", r.Names, r.Detail)
	}
	beside := walledSpec(t, &bindingWall{binds: own})
	if _, err := session.Run(context.Background(), beside); err != nil {
		t.Errorf("a run with the same helper and patterns: %v", err)
	}
}

// TestAPlaceInsideAnotherRunsWritableDirectoryIsNoRun pins a place that lies inside a
// writable directory a wall binds of its own for another walled run still going.
func TestAPlaceInsideAnotherRunsWritableDirectoryIsNoRun(t *testing.T) {
	dir := t.TempDir()
	w := heldBinder{newHoldingWall(), []wall.Bind{{Path: dir}}}
	s := start(walledSpec(t, w))
	select {
	case <-w.reached:
	case <-s.done:
		t.Fatalf("the first run ended: %+v, %v", s.res, s.err)
	}
	t.Cleanup(func() {
		close(w.release)
		<-s.done
	})
	sub := mkdirs(t, filepath.Join(dir, "sub"))
	other := walledSpec(t, &openWall{})
	other.Mounts = []wall.Mount{{Path: sub, ReadOnly: true}}
	r := refusalOf(t, "mount_shared_with_run", runErr(other))
	want := "the mount " + sub + " (read-only) lies inside the runner's directory " + dir +
		" of the walled run " + w.id + ", which is still going: a walled agent of that " +
		"run can change it"
	if !slices.Equal(r.Names, []string{sub, w.id, dir}) || r.Detail != want {
		t.Errorf("names %q, detail %q", r.Names, r.Detail)
	}
}

// TestAWorkingDirectoryInNoBindIsNoPlan pins the last check of a plan: the enclosure
// binds what the plan lists alone, so a working directory in none of them fails.
func TestAWorkingDirectoryInNoBindIsNoPlan(t *testing.T) {
	mounts := []wall.Mount{{Path: "/w"}, {Path: "/e/link"}}
	if err := session.DirInBinds("/e/link/ws", mounts); err != nil {
		t.Error(err)
	}
	for _, dir := range []string{"/e/ws", "/wide", "/e"} {
		err := session.DirInBinds(dir, mounts)
		want := "the working directory inside, " + dir + ", lies in none of the places the " +
			"enclosure binds: [/w /e/link]"
		if err == nil || err.Error() != want {
			t.Errorf("%s: %v", dir, err)
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

// TestAnotherRunsBindThatIsGoneIsComparedByItsNames pins a writable bind of another
// walled run's that is deleted while it goes: it is compared by its names, like a part
// that does not exist yet, so a mount inside it is refused, before the mount's own
// directory is made again and after.
func TestAnotherRunsBindThatIsGoneIsComparedByItsNames(t *testing.T) {
	x := mkdirs(t, filepath.Join(t.TempDir(), "x"))
	first, _ := hold(t, []wall.Mount{{Path: x}}, x)
	if err := os.RemoveAll(x); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(x, "sub")
	for _, made := range []bool{false, true} {
		if made {
			mkdirs(t, sub)
		}
		sp := walledSpec(t, &openWall{})
		sp.Mounts = []wall.Mount{{Path: sub}}
		r := refusalOf(t, "mount_shared_with_run", runErr(sp))
		if !slices.Equal(r.Names, []string{sub, first.RunID, x}) {
			t.Errorf("made %v: names %q, detail %q", made, r.Names, r.Detail)
		}
	}
}

// TestAnotherRunsBindThatCannotBeResolvedFailsTheRun pins that a bind of another
// walled run's this run cannot resolve stops the run.
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
