package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/qoryai/forager/session"
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
// and the binds, and returns its file, which goes when the test ends.
func bound(t *testing.T, binds ...bind) string {
	t.Helper()
	reg := registry(t)
	if err := os.MkdirAll(reg, 0o700); err != nil {
		t.Fatal(err)
	}
	var bs []map[string]any
	for _, b := range binds {
		m := map[string]any{"path": b.path, "resolved": b.resolved, "writable": true}
		if b.kind != "" {
			m["kind"] = b.kind
		}
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
	runs, err := session.RunsBinding(context.Background(), root)
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
	runs, err := session.RunsBinding(context.Background(), root)
	if err != nil || len(runs) != 0 {
		t.Fatalf("runs %+v, %v", runs, err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("the entry is still there: %v", err)
	}
}

// TestRunsBindingRefusesWithoutAnEngine pins an entry whose lock is free and whose
// engine cannot be asked: the read is refused with engine_unreachable, naming the run
// and its entry, and the entry stays.
func TestRunsBindingRefusesWithoutAnEngine(t *testing.T) {
	root := t.TempDir()
	file := bound(t, bind{root, resolved(t, root), ""})
	answer(t, false, errors.New("Cannot connect to the Docker daemon"))
	runs, err := session.RunsBinding(context.Background(), t.TempDir())
	var r *session.Refusal
	if !errors.As(err, &r) || r.Code != "engine_unreachable" ||
		!slices.Equal(r.Names, []string{boundID, file}) {
		t.Fatalf("runs %+v, %v", runs, err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("the entry is gone: %v", err)
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
	runs, err := session.RunsBinding(context.Background(), root)
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
// inside p that leads out of it included; not a sibling of p, nor one whose name only
// begins with p's, nor another run directory in the same runs directory.
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
	answer(t, true, nil)
	for _, c := range []struct {
		name  string
		bind  bind
		query string
		want  bool
	}{
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
		{"its run directory", bind{filepath.Join(base, "runs"),
			resolved(t, filepath.Join(base, "runs", "one")), "run"},
			filepath.Join(base, "runs", "one", "x"), true},
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
			runs, err := session.RunsBinding(context.Background(), c.query)
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
	_, err := session.RunsBinding(context.Background(), "places/x")
	var r *session.Refusal
	if err == nil || errors.As(err, &r) || err.Error() != `the path "places/x" is not absolute` {
		t.Errorf("err %v", err)
	}
	if len(a.ids) != 0 {
		t.Errorf("the engine was asked for %q", a.ids)
	}
}
