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
	"syscall"
	"testing"

	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// boundID is the run id of the entries the tests of RunsBinding write.
const boundID = "0191f2a4-0000-7000-8000-0000000b1d01"

// bind is one bind of an entry RunsBinding reads: the path as the run passed it, and
// the path it resolved to then.
type bind struct {
	path, resolved, kind string
}

// resolved is dir resolved through its links, as a run lists a bind it makes.
func resolved(t *testing.T, dir string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

// bound writes the entry of the walled run boundID, its lock free, recording leftEngine
// and the binds, each with the entries looked up on the way to it now, as a run records
// them, the run directory's on the way to its resolved path, and returns its file, which
// goes when the test ends.
func bound(t *testing.T, binds ...bind) string {
	t.Helper()
	reg := registry(t)
	if err := os.MkdirAll(reg, 0o700); err != nil {
		t.Fatal(err)
	}
	var bs []map[string]any
	for _, b := range binds {
		m := map[string]any{"path": b.path, "resolved": b.resolved, "writable": true}
		looked := b.path
		if b.kind != "" {
			m["kind"], looked = b.kind, b.resolved
		}
		looks, err := session.BindLookups(looked)
		if err != nil {
			t.Fatal(err)
		}
		m["lookups"] = looks
		bs = append(bs, m)
	}
	data, _ := json.Marshal(map[string]any{"run_id": boundID, "pid": 1, "binds": bs,
		"engine": leftEngine})
	file := filepath.Join(reg, boundID)
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(file) })
	return file
}

// TestRunsBindingCountsAStoppedContainer pins an entry whose lock is free and whose run
// still has a container, a stopped one as much as one running, which the engine its
// entry records answers for alike: the run is still going, returned once with its
// entry however many of its binds overlap, and its entry stays.
func TestRunsBindingCountsAStoppedContainer(t *testing.T) {
	root := t.TempDir()
	sub := mkdirs(t, filepath.Join(root, "sub"))
	file := bound(t, bind{root, resolved(t, root), ""}, bind{sub, resolved(t, sub), ""})
	a := answer(t, true, nil)
	runs, err := session.RunsBinding(context.Background(), nil, root)
	if err != nil {
		t.Fatal(err)
	}
	want := []session.WalledRun{{RunID: boundID, Entry: file}}
	if !slices.Equal(runs, want) || !filepath.IsAbs(runs[0].Entry) {
		t.Errorf("runs %+v, want %+v", runs, want)
	}
	if len(a.asked) != 1 || a.asked[0].Command != leftEngine.Command ||
		!slices.Equal(a.asked[0].Env, leftEngine.Env) || a.ids[0] != boundID {
		t.Errorf("asked %+v for %q", a.asked, a.ids)
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("the entry of a run with a container is gone: %v", err)
	}
}

// TestRunsBindingRemovesAnEntryWithoutAContainer pins an entry whose lock is free and
// whose run has no container left: the run is over, it is not returned, and its entry
// is removed, as a run that starts removes it.
func TestRunsBindingRemovesAnEntryWithoutAContainer(t *testing.T) {
	root := t.TempDir()
	file := bound(t, bind{root, resolved(t, root), ""})
	answer(t, false, nil)
	runs, err := session.RunsBinding(context.Background(), nil, root)
	if err != nil || len(runs) != 0 {
		t.Fatalf("runs %+v, %v", runs, err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("the entry is still there: %v", err)
	}
}

// TestRunsBindingRefusesWithoutAnEngine pins an entry whose lock is free, whose binds
// overlap p and whose engine cannot be asked: the read is refused with
// engine_unreachable, naming the run and its entry, in a sentence that counts the run as
// still going and says nothing of a run that starts, and the entry stays.
func TestRunsBindingRefusesWithoutAnEngine(t *testing.T) {
	root := t.TempDir()
	file := bound(t, bind{root, resolved(t, root), ""})
	answer(t, false, errors.New("Cannot connect to the Docker daemon"))
	runs, err := session.RunsBinding(context.Background(), nil, root)
	var r *session.Refusal
	if !errors.As(err, &r) || r.Code != "engine_unreachable" ||
		!slices.Equal(r.Names, []string{boundID, file}) {
		t.Fatalf("runs %+v, %v", runs, err)
	}
	want := "The check for a container of the walled run " + boundID +
		" failed, so the run counts as still going: Cannot connect to the Docker daemon"
	if r.Detail != want {
		t.Errorf("detail %q, want %q", r.Detail, want)
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("the entry is gone: %v", err)
	}
}

// TestRunsBindingLeavesAnUnaskedEngineApart pins an entry whose lock is free and whose
// engine cannot be asked, none of whose binds overlaps p: the engine is not asked, the
// read returns no run and no error, and the entry stays.
func TestRunsBindingLeavesAnUnaskedEngineApart(t *testing.T) {
	root := t.TempDir()
	file := bound(t, bind{root, resolved(t, root), ""})
	a := answer(t, false, errors.New("Cannot connect to the Docker daemon"))
	runs, err := session.RunsBinding(context.Background(), nil, t.TempDir())
	if err != nil || len(runs) != 0 {
		t.Fatalf("runs %+v, %v", runs, err)
	}
	if len(a.ids) != 0 {
		t.Errorf("the engine was asked for %q", a.ids)
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("the entry is gone: %v", err)
	}
}

// TestRunsBindingRefusesAnEntryThatRecordsNoEngine pins an entry whose lock is free,
// that can be read and records no engine: when one of its binds overlaps p, the read is
// refused with engine_unreachable, naming the run and its entry, an entry that can be
// read; when none does, the read returns no run and no error.
func TestRunsBindingRefusesAnEntryThatRecordsNoEngine(t *testing.T) {
	root := t.TempDir()
	file := leave(t, root, nil)
	a := answer(t, true, nil)
	runs, err := session.RunsBinding(context.Background(), nil, t.TempDir())
	if err != nil || len(runs) != 0 {
		t.Fatalf("apart: runs %+v, %v", runs, err)
	}
	_, err = session.RunsBinding(context.Background(), nil, root)
	r := refusalOf(t, "engine_unreachable", err)
	want := "The check for a container of the walled run " + leftID +
		" failed, so the run counts as still going: its entry " + file +
		" records no engine"
	if !slices.Equal(r.Names, []string{leftID, file}) || r.Detail != want ||
		r.EntryUnreadable {
		t.Errorf("refusal %+v, want the detail %q", r, want)
	}
	if len(a.ids) != 0 {
		t.Errorf("the engine was asked for %q", a.ids)
	}
}

// TestRunsBindingRefusesAnUnreadableEntry pins an entry whose lock is free and that
// cannot be read, whose binds cannot be compared with p: the read is refused with
// engine_unreachable, naming the run and its entry, in the sentence of an engine that
// cannot be asked, and marked as an entry that cannot be read, which a caller tells
// apart from an engine that cannot be asked; the engine is not asked, and the entry
// stays.
func TestRunsBindingRefusesAnUnreadableEntry(t *testing.T) {
	reg := registry(t)
	if err := os.MkdirAll(reg, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(reg, boundID)
	if err := os.WriteFile(file, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(file) })
	a := answer(t, true, nil)
	_, err := session.RunsBinding(context.Background(), nil, t.TempDir())
	r := refusalOf(t, "engine_unreachable", err)
	prefix := "The check for a container of the walled run " + boundID +
		" failed, so the run counts as still going: its entry " + file +
		" cannot be read: "
	if !slices.Equal(r.Names, []string{boundID, file}) ||
		!strings.HasPrefix(r.Detail, prefix) || !r.EntryUnreadable {
		t.Errorf("refusal %+v, want the detail to begin %q", r, prefix)
	}
	if len(a.ids) != 0 {
		t.Errorf("the engine was asked for %q", a.ids)
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("the entry is gone: %v", err)
	}
}

// readOnly makes the i-th bind of the entry in file read-only, as a run records a bind
// its enclosure cannot write.
func readOnly(t *testing.T, file string, i int) {
	t.Helper()
	rebind(t, file, i, func(b map[string]any) { b["writable"] = false })
}

// rebind changes the i-th bind of the entry in file by change.
func rebind(t *testing.T, file string, i int, change func(b map[string]any)) {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]any
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	change(entry["binds"].([]any)[i].(map[string]any))
	if data, err = json.Marshal(entry); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRunsBindingLeavesAReadOnlyBindApart pins an entry whose only bind that overlaps
// p is read-only: its run's agent cannot change p through it, so the run is not
// returned, its engine is not asked, and the read is no error.
func TestRunsBindingLeavesAReadOnlyBindApart(t *testing.T) {
	root := t.TempDir()
	file := bound(t, bind{root, resolved(t, root), ""})
	readOnly(t, file, 0)
	a := answer(t, true, nil)
	runs, err := session.RunsBinding(context.Background(), nil, root)
	if err != nil || len(runs) != 0 {
		t.Fatalf("runs %+v, %v", runs, err)
	}
	if len(a.ids) != 0 {
		t.Errorf("the engine was asked for %q", a.ids)
	}
}

// TestRunsBindingCountsAWritableBindBesideAReadOnlyOne pins an entry with a read-only
// bind and a writable one that both overlap p: the writable one counts, and the run is
// returned.
func TestRunsBindingCountsAWritableBindBesideAReadOnlyOne(t *testing.T) {
	root := t.TempDir()
	sub := mkdirs(t, filepath.Join(root, "sub"))
	file := bound(t, bind{root, resolved(t, root), ""}, bind{sub, resolved(t, sub), ""})
	readOnly(t, file, 0)
	answer(t, true, nil)
	runs, err := session.RunsBinding(context.Background(), nil, root)
	want := []session.WalledRun{{RunID: boundID, Entry: file}}
	if err != nil || !slices.Equal(runs, want) {
		t.Fatalf("runs %+v, %v; want %+v", runs, err, want)
	}
}

// TestRunsBindingLeavesTheRunDirectoryApart pins a run whose only overlap with p is its
// run directory, recorded as a run records it, read-only: the run is not returned, and
// its engine is not asked.
func TestRunsBindingLeavesTheRunDirectoryApart(t *testing.T) {
	runs := t.TempDir()
	one := mkdirs(t, filepath.Join(runs, "one"))
	file := bound(t, bind{runs, resolved(t, one), "run"})
	readOnly(t, file, 0)
	a := answer(t, true, nil)
	got, err := session.RunsBinding(context.Background(), nil, filepath.Join(one, "x"))
	if err != nil || len(got) != 0 {
		t.Fatalf("runs %+v, %v", got, err)
	}
	if len(a.ids) != 0 {
		t.Errorf("the engine was asked for %q", a.ids)
	}
}

// TestRunsBindingCountsABindThatRecordsNoMode pins a bind whose entry records no
// writable field for it: it counts as writable, so the run is returned while its
// engine holds a container, and the read is refused with engine_unreachable, naming the
// run and its entry, when its engine cannot be asked.
func TestRunsBindingCountsABindThatRecordsNoMode(t *testing.T) {
	root := t.TempDir()
	file := bound(t, bind{root, resolved(t, root), ""})
	rebind(t, file, 0, func(b map[string]any) { delete(b, "writable") })
	answer(t, true, nil)
	runs, err := session.RunsBinding(context.Background(), nil, root)
	want := []session.WalledRun{{RunID: boundID, Entry: file}}
	if err != nil || !slices.Equal(runs, want) {
		t.Fatalf("runs %+v, %v; want %+v", runs, err, want)
	}
	answer(t, false, errors.New("Cannot connect to the Docker daemon"))
	_, err = session.RunsBinding(context.Background(), nil, root)
	r := refusalOf(t, "engine_unreachable", err)
	if !slices.Equal(r.Names, []string{boundID, file}) {
		t.Errorf("names %q", r.Names)
	}
}

// TestRunsBindingCountsAHeldEntry pins an entry whose session still holds its lock: the
// run is still going whatever the engine would say, and the engine is not asked.
func TestRunsBindingCountsAHeldEntry(t *testing.T) {
	root := t.TempDir()
	file := bound(t, bind{root, resolved(t, root), ""})
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	a := answer(t, false, errors.New("Cannot connect to the Docker daemon"))
	runs, err := session.RunsBinding(context.Background(), nil, root)
	want := []session.WalledRun{{RunID: boundID, Entry: file}}
	if err != nil || !slices.Equal(runs, want) {
		t.Fatalf("runs %+v, %v; want %+v", runs, err, want)
	}
	if len(a.ids) != 0 {
		t.Errorf("the engine was asked for %q", a.ids)
	}
}

// TestRunsBindingOverlaps pins which binds overlap p: p itself, a directory that holds
// p and a path inside p, compared as written and as resolved through links on either
// side, a link that has changed since the run listed its bind and a bind through a link
// inside p that leads out of it included; a bind a name on the way to p is looked up
// in, and one whose names are looked up in p, through a chain of links or a spelling of
// p through another link; p with a .. name after a link, resolved as the filesystem
// resolves it, after a link to ., / or .. too; not a sibling of p, nor one whose name
// only begins with p's, nor another run directory in the same runs directory, nor the
// directory a .. name after a link would name if p were cleaned.
func TestRunsBindingOverlaps(t *testing.T) {
	base := t.TempDir()
	p := filepath.Join(base, "a", "b")
	mkdirs(t, filepath.Join(p, "sub"), filepath.Join(p, ".git", "refs"),
		filepath.Join(base, "a", "bc"), filepath.Join(base, "a", "b2"),
		filepath.Join(base, "before"), filepath.Join(base, "runs", "one"),
		filepath.Join(base, "runs", "two"))
	link := func(name, to string) string {
		l := filepath.Join(base, name)
		if err := os.Symlink(to, l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	toP, toSub := link("to-p", p), link("to-sub", filepath.Join(p, "sub"))
	// moved led to before when the run listed it, and leads to p now.
	moved := link("moved", p)
	// out lies inside p and leads out of it.
	out := filepath.Join(p, "out")
	if err := os.Symlink(filepath.Join(base, "before"), out); err != nil {
		t.Fatal(err)
	}
	// home/l leads to the directory new, and l2 to home: a run that binds l2 can
	// change where home/l/repo leads.
	home := mkdirs(t, filepath.Join(base, "home"), filepath.Join(base, "new", "repo"))
	link(filepath.Join("home", "l"), filepath.Join(base, "new"))
	l2 := link("l2", home)
	// repo/.git leads to gitdirs/x, and alias to base itself; a1 leads through repo/l3
	// to elsewhere.
	repo := mkdirs(t, filepath.Join(base, "repo"), filepath.Join(base, "gitdirs", "x"),
		filepath.Join(base, "elsewhere"))
	gitdir := filepath.Join(base, "gitdirs", "x")
	dotGit := link(filepath.Join("repo", ".git"), gitdir)
	alias := link("alias", base)
	link(filepath.Join("repo", "l3"), filepath.Join(base, "elsewhere"))
	a1 := link("a1", filepath.Join(repo, "l3"))
	// lk leads to deep/dir, so lk/.. is deep, not base.
	mkdirs(t, filepath.Join(base, "deep", "dir"), filepath.Join(base, "deep", "repo"),
		filepath.Join(base, "repo9"))
	link("lk", filepath.Join(base, "deep", "dir"))
	// w/dot leads to ., w/root to / and w/up to ..: a .. after each is the directory
	// the link leads to's parent, not w.
	mkdirs(t, filepath.Join(base, "w"))
	link(filepath.Join("w", "dot"), ".")
	link(filepath.Join("w", "root"), "/")
	link(filepath.Join("w", "up"), "..")
	answer(t, true, nil)
	for _, c := range []struct {
		name  string
		bind  bind
		query string
		want  bool
	}{
		{"a bind a name on the way to p is looked up in", bind{l2, resolved(t, home), ""},
			filepath.Join(home, "l", "repo"), true},
		{"p/.git through a link, p spelled as resolved", bind{dotGit,
			resolved(t, gitdir), ""}, resolved(t, repo), true},
		{"p/.git through a link, reached through another", bind{
			filepath.Join(alias, "repo", ".git"), resolved(t, gitdir), ""}, repo, true},
		{"a chain of links through p", bind{a1, resolved(t, filepath.Join(base, "elsewhere")),
			""}, repo, true},
		{"p with .. after a link", bind{filepath.Join(base, "deep", "repo"),
			resolved(t, filepath.Join(base, "deep", "repo")), ""},
			base + "/lk/../repo", true},
		{"p with .. after a link, cleaned", bind{filepath.Join(base, "repo9"),
			resolved(t, filepath.Join(base, "repo9")), ""}, base + "/lk/../repo9", false},
		{"p with .. after a link to .", bind{filepath.Join(base, "before"),
			resolved(t, filepath.Join(base, "before")), ""}, base + "/w/dot/..", true},
		{"p with .. after a link to /", bind{filepath.Join(base, "before"),
			resolved(t, filepath.Join(base, "before")), ""}, base + "/w/root/..", true},
		{"p with .. after a link to ..", bind{filepath.Join(base, "before"),
			resolved(t, filepath.Join(base, "before")), ""}, base + "/w/up/..", true},
		{"p itself", bind{p, resolved(t, p), ""}, p, true},
		{"a directory holding p", bind{filepath.Join(base, "a"),
			resolved(t, filepath.Join(base, "a")), ""}, p, true},
		{"p/.git/refs alone", bind{filepath.Join(p, ".git", "refs"),
			resolved(t, filepath.Join(p, ".git", "refs")), ""}, p, true},
		{"p by a link", bind{filepath.Join(p, "sub"),
			resolved(t, filepath.Join(p, "sub")), ""}, toP, true},
		{"a bind by a link", bind{toSub, resolved(t, toSub), ""}, p, true},
		{"a bind resolved by its written path alone", bind{p, filepath.Join(p, "nowhere"),
			""}, filepath.Join(p, "sub"), true},
		{"a link changed since", bind{moved, resolved(t, filepath.Join(base, "before")),
			""}, p, true},
		{"a link as written", bind{moved, resolved(t, filepath.Join(base, "before")),
			""}, moved, true},
		{"a bind through a link inside p", bind{out, resolved(t, out), ""}, p, true},
		{"a sibling", bind{filepath.Join(base, "a", "b2"),
			resolved(t, filepath.Join(base, "a", "b2")), ""}, p, false},
		{"a name beginning with p's", bind{filepath.Join(base, "a", "bc"),
			resolved(t, filepath.Join(base, "a", "bc")), ""}, p, false},
		{"another run directory", bind{filepath.Join(base, "runs"),
			resolved(t, filepath.Join(base, "runs", "one")), "run"},
			filepath.Join(base, "runs", "two"), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			file := bound(t, c.bind)
			runs, err := session.RunsBinding(context.Background(), nil, c.query)
			if err != nil {
				t.Fatal(err)
			}
			var want []session.WalledRun
			if c.want {
				want = []session.WalledRun{{RunID: boundID, Entry: file}}
			}
			if !slices.Equal(runs, want) {
				t.Errorf("%+v against %s: runs %+v, want %+v", c.bind, c.query, runs, want)
			}
		})
	}
}

// TestRunsBindingRefusesARelativePath pins a relative p: it is an error, not a
// refusal, and no entry is read.
func TestRunsBindingRefusesARelativePath(t *testing.T) {
	a := answer(t, true, nil)
	bound(t, bind{"/", "/", ""})
	_, err := session.RunsBinding(context.Background(), nil, "places/x")
	var r *session.Refusal
	if err == nil || errors.As(err, &r) || err.Error() != `the path "places/x" is not absolute` {
		t.Errorf("err %v", err)
	}
	if len(a.ids) != 0 {
		t.Errorf("the engine was asked for %q", a.ids)
	}
}

// askedThrough points the registry's question at a fake engine that answers that the
// run's containers exist, and records the Docker each question is asked through.
func askedThrough(t *testing.T) *[]*wall.Docker {
	t.Helper()
	var mu sync.Mutex
	var asked []*wall.Docker
	session.SetRunContainersAsked(
		func(_ context.Context, d *wall.Docker, _ wall.Engine, _ string) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			asked = append(asked, d)
			return true, nil
		})
	t.Cleanup(func() { session.SetRunContainersAsked(nil) })
	return &asked
}

// TestRunsBindingAsksThroughTheDocker pins the Docker RunsBinding is passed: the engine
// of an entry whose lock is free is asked through it, and with nil as the package's
// function asks.
func TestRunsBindingAsksThroughTheDocker(t *testing.T) {
	root := t.TempDir()
	bound(t, bind{root, resolved(t, root), ""})
	asked := askedThrough(t)
	d := &wall.Docker{Command: "/opt/asker/docker"}
	for _, by := range []*wall.Docker{d, nil} {
		*asked = nil
		runs, err := session.RunsBinding(context.Background(), by, root)
		if err != nil || len(runs) != 1 {
			t.Fatalf("runs %+v, %v", runs, err)
		}
		if !slices.Equal(*asked, []*wall.Docker{by}) {
			t.Errorf("asked through %p, want %p", *asked, by)
		}
	}
}

// TestTheRegistryAsksThroughTheRunsDocker pins the Docker a run's check against the
// registry asks through: the run's wall when it is a Docker, and none for another wall.
// The check is the open's: the run's helper lies inside a writable bind of a walled run
// whose entry's lock is free, so its engine is asked, and the run does not start.
func TestTheRegistryAsksThroughTheRunsDocker(t *testing.T) {
	bin := t.TempDir()
	command := filepath.Join(bin, "docker")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(bin, "helper")
	if err := os.WriteFile(helper, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	d := &wall.Docker{Command: command, Helper: helper}
	for _, c := range []struct {
		name string
		w    wall.Wall
		want *wall.Docker
	}{
		{"a Docker", d, d},
		{"another wall", &bindingWall{binds: []wall.Bind{{Path: helper, ReadOnly: true, Helper: true}}}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			leave(t, bin, &leftEngine)
			asked := askedThrough(t)
			err := runErr(walledSpec(t, c.w))
			if err == nil || !strings.Contains(err.Error(), "Forager's helper "+helper+" lies inside the writable bind "+bin) {
				t.Errorf("the run: %v", err)
			}
			if len(*asked) == 0 || slices.ContainsFunc(*asked,
				func(by *wall.Docker) bool { return by != c.want }) {
				t.Errorf("asked through %p, want %p", *asked, c.want)
			}
		})
	}
}
