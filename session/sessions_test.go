package session_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/qoryai/forager/internal/linktest"
	refusals "github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/sink"
	"github.com/qoryai/forager/wall"
)

// TestEachSessionHasItsDirectory pins the run directory of a walled run of two joins:
// each session writes its preparation.sh, its settings.json and its output.log under
// sessions/<n>/, the enclosure of each binds that session's directory alone,
// read-only, so session 2's wall reaches no file of session 1's and no record, each
// session's output.log is its run.log chunks, and the run's output.log is every chunk
// in sequence order, which here is session 1's output.log and then session 2's.
func TestEachSessionHasItsDirectory(t *testing.T) {
	sp, _ := specGateway(t, "FAKE_EXIT=0")
	w := &openWall{}
	sp.Wall, sp.Image, sp.Mounts = w, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	var results []*session.Result
	var mounts [][]wall.Mount
	for _, word := range []string{"one", "two"} {
		s := sp.SessionSpec
		s.SetupRunner = setupRunner
		s.Setup = []session.SetupCommand{{Name: "install", Args: []string{"/bin/sh", "-c", "echo preparing session " + word}}}
		res, err := r.Join(ctx, s)
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, res)
		mounts = append(mounts, slices.Clone(w.got.Mounts))
	}
	if _, err := r.Close(ctx, session.Outcome{State: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	run := results[0].Dir
	for i, res := range results {
		n := i + 1
		want := filepath.Join(run, session.SessionsDir, strconv.Itoa(n))
		if res.Session != n || res.SessionDir != want || res.State != "succeeded" {
			t.Fatalf("session %d: result %+v, want its directory %s", n, res, want)
		}
		script, err := os.ReadFile(filepath.Join(want, session.PreparationScript))
		if err != nil || !strings.Contains(string(script), "'echo preparing session "+[]string{"one", "two"}[i]+"'") {
			t.Errorf("session %d: preparation.sh %q, %v", n, script, err)
		}
		if settings, err := os.ReadFile(filepath.Join(want, "settings.json")); err != nil || !strings.Contains(string(settings), `"echo existing"`) {
			t.Errorf("session %d: settings.json %q, %v", n, settings, err)
		}
		if got := []wall.Mount{{Path: sp.Dir}, {Path: want, ReadOnly: true}}; !slices.Equal(mounts[i], got) {
			t.Errorf("session %d: the enclosure binds %v, want %v", n, mounts[i], got)
		}
	}
	// No bind of session 2's is, holds or lies inside a file of session 1's or the
	// session's record.
	one := results[0].SessionDir
	for _, f := range []string{filepath.Join(one, "settings.json"), filepath.Join(one, session.PreparationScript), filepath.Join(run, sink.SessionFile)} {
		for _, m := range mounts[1] {
			if how := session.Overlap(m.Path, f); how != "" {
				t.Errorf("session 2's bind %s %s %s", m.Path, how, f)
			}
		}
	}
	for _, name := range []string{session.PreparationScript, "settings.json"} {
		if _, err := os.Lstat(filepath.Join(run, name)); err == nil {
			t.Errorf("the run directory has %s", name)
		}
	}
	all, bySession := chunks(t, run)
	out, _ := os.ReadFile(filepath.Join(run, sink.OutputFile))
	if !bytes.Equal(out, all) || len(all) == 0 {
		t.Errorf("the run's output.log\n%q\nwant every run.log chunk in sequence order\n%q", out, all)
	}
	var both []byte
	for i, res := range results {
		got, _ := os.ReadFile(filepath.Join(res.SessionDir, sink.OutputFile))
		if want := bySession[i+1]; !bytes.Equal(got, want) || !bytes.Contains(got, []byte("preparing session "+[]string{"one", "two"}[i])) {
			t.Errorf("session %d: output.log\n%q\nwant its run.log chunks\n%q", i+1, got, want)
		}
		both = append(both, got...)
	}
	if !bytes.Equal(out, both) {
		t.Errorf("the run's output.log\n%q\nis not session 1's output.log and then session 2's\n%q", out, both)
	}
}

// chunks are the bytes of the run.log chunks in the session's record of the run in
// dir, every one in sequence order and each session's apart: a chunk belongs to the
// session whose session.started is the last one before it.
func chunks(t *testing.T, dir string) ([]byte, map[int][]byte) {
	t.Helper()
	var all []byte
	bySession := map[int][]byte{}
	n := 0
	for _, e := range events(t, &session.Result{Dir: dir}) {
		switch e["type"] {
		case "dev.qory.session.started":
			n = int(data(e)["session"].(float64))
		case "dev.qory.run.log":
			b, err := base64.StdEncoding.DecodeString(data(e)["bytes"].(string))
			if err != nil {
				t.Fatal(err)
			}
			all = append(all, b...)
			bySession[n] = append(bySession[n], b...)
		}
	}
	return all, bySession
}

// TestASessionHasADirectoryOnceItStarts pins that sessions/<n>/ exists exactly for the
// sessions whose dev.qory.session.started is written. A join the gateway refuses, a
// join whose checks refuse a mount, before the directory is made, and a join whose
// runtime's preparation fails, after it is made, leave none. A join whose wall fails to
// start the agent's container is started, and keeps sessions/4/ with its settings.json
// and its output.log. Session 5 then starts in sessions/5/.
func TestASessionHasADirectoryOnceItStarts(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	joins := 0
	g.OnJoin(func(linktest.Join) linktest.Reply {
		joins++
		if joins == 1 {
			return linktest.Reply{Status: 403, Body: linktest.Refusal("run_configuration_invalid", "gateway", "model")}
		}
		return linktest.Reply{Status: 200, Body: map[string]any{"version": 1, "session": joins}}
	})
	walls := &switchWall{}
	sp.Wall, sp.Image, sp.Mounts = walls, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: "succeeded"})
	var ref *session.Refusal
	if _, err := r.Join(ctx, sp.SessionSpec); !errors.As(err, &ref) {
		t.Fatalf("the gateway's refusal: %v", err)
	}
	inRuns := sp.SessionSpec
	inRuns.Mounts = append(slices.Clone(sp.Mounts), wall.Mount{Path: sp.RunsDir, ReadOnly: true})
	if _, err := r.Join(ctx, inRuns); !errors.As(err, &ref) || ref.Code != refusals.MountContainsForagerFiles {
		t.Fatalf("a mount of the runs directory: %v", err)
	}
	absent := sp.SessionSpec
	absent.Args = []string{"--settings", filepath.Join(t.TempDir(), "absent.json")}
	if _, err := r.Join(ctx, absent); err == nil || !strings.HasPrefix(err.Error(), "runtime claude: ") {
		t.Fatalf("a settings file that does not exist: %v", err)
	}
	walls.refuse = true
	if _, err := r.Join(ctx, sp.SessionSpec); err == nil || !strings.HasPrefix(err.Error(), "wall open: ") {
		t.Fatalf("the wall's failure: %v", err)
	}
	walls.refuse = false
	res, err := r.Join(ctx, sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(res.Dir, session.SessionsDir))
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if err != nil || res.Session != 5 || !slices.Equal(names, []string{"4", "5"}) {
		t.Errorf("session %d; sessions/ has %v, %v; want 4 and 5", res.Session, names, err)
	}
	refused := filepath.Join(res.Dir, session.SessionsDir, "4")
	for _, name := range []string{"settings.json", sink.OutputFile} {
		if _, err := os.Stat(filepath.Join(refused, name)); err != nil {
			t.Errorf("the session whose wall failed: %v", err)
		}
	}
	var started []any
	for _, e := range ofType(events(t, res), "dev.qory.session.started") {
		started = append(started, data(e)["session"])
	}
	if !slices.Equal(started, []any{float64(4), float64(5)}) {
		t.Errorf("session.started for sessions %v, want 4 and 5", started)
	}
}

// switchWall is an open wall whose Wrap fails while refuse is set, as a wall whose
// agent's container does not start: after the runtime's preparation wrote the
// session's settings.
type switchWall struct {
	openWall
	refuse bool
}

func (w *switchWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *switchWall) Wrap(ctx context.Context, l wall.Launch) (wall.Launch, error) {
	if w.refuse {
		return wall.Launch{}, errors.New("wall open: start the agent's container: exit status 125")
	}
	return w.openWall.Wrap(ctx, l)
}
