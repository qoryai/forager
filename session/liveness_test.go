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

// leftID is the run id of an entry whose runner is gone.
const leftID = "0191f2a4-0000-7000-8000-00000000a11e"

// leftEngine is the engine an entry whose runner is gone records.
var leftEngine = wall.Engine{Wall: "docker", Command: "/opt/left/docker",
	Env: []string{"DOCKER_CONTEXT=left"}, Pinned: true}

// leave writes the entry of a walled run whose runner is gone: its lock is free, and it
// binds dir writable, with the engine when it is not nil.
func leave(t *testing.T, dir string, engine *wall.Engine) string {
	t.Helper()
	reg := registry(t)
	if err := os.MkdirAll(reg, 0o700); err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	entry := map[string]any{
		"run_id": leftID, "pid": 1,
		"binds": []map[string]any{{"path": dir, "resolved": real, "writable": true}},
	}
	if engine != nil {
		entry["engine"] = engine
	}
	b, _ := json.Marshal(entry)
	file := filepath.Join(reg, leftID)
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(file) })
	return file
}

// engineAnswers points the registry's question at a fake engine for the test, which
// records what it is asked with.
type engineAnswers struct {
	mu     sync.Mutex
	exists bool
	err    error
	asked  []wall.Engine
	ids    []string
}

func answer(t *testing.T, exists bool, err error) *engineAnswers {
	a := &engineAnswers{exists: exists, err: err}
	session.SetRunContainersExist(
		func(_ context.Context, e wall.Engine, id string) (bool, error) {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.asked, a.ids = append(a.asked, e), append(a.ids, id)
			return a.exists, a.err
		})
	t.Cleanup(func() { session.SetRunContainersExist(nil) })
	return a
}

// enginedWall is an open wall in a container engine, whose engine is this test's.
type enginedWall struct {
	openWall
	engine wall.Engine
	// id and idErr are what the engine answers when it is asked for its id again.
	id    string
	idErr error
}

func (w *enginedWall) Engine(context.Context) wall.Engine { return w.engine }

func (w *enginedWall) EngineID(context.Context) (string, error) { return w.id, w.idErr }

// TestAnEntryWithAContainerIsLive pins an entry whose runner is gone and whose run
// still has a container, in whatever state, on the engine the entry records: it is a
// run still going, so a bind inside its writable bind is refused, exactly as for an
// entry whose lock is held, and the entry stays. The engine asked is the entry's, not
// this run's.
func TestAnEntryWithAContainerIsLive(t *testing.T) {
	root := t.TempDir()
	sub := mkdirs(t, filepath.Join(root, "sub"))
	file := leave(t, root, &leftEngine)
	a := answer(t, true, nil)
	w := &enginedWall{engine: wall.Engine{Wall: "docker", Command: "/opt/mine/docker"}}
	sp := walledSpec(t, w)
	sp.Mounts, sp.Dir = []wall.Mount{{Path: sub}}, sub
	r := refusalOf(t, "mount_shared_with_run", runErr(sp))
	want := "the mount " + sub + " (writable) lies inside the writable bind " + root +
		" of the walled run " + leftID +
		", which is still going: a walled agent of that run can change it"
	if !slices.Equal(r.Names, []string{sub, leftID, root}) || r.Detail != want {
		t.Errorf("names %q, detail %q", r.Names, r.Detail)
	}
	if len(a.asked) == 0 || !slices.EqualFunc(a.asked, []wall.Engine{leftEngine},
		func(x, y wall.Engine) bool {
			return x.Wall == y.Wall && x.Command == y.Command && slices.Equal(x.Env, y.Env)
		}) || a.ids[0] != leftID {
		t.Errorf("asked %+v for %q", a.asked, a.ids)
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("the entry of a run with a container is gone: %v", err)
	}
	if w.wrapped {
		t.Error("the enclosure was wrapped")
	}
}

// TestAnEntryWithoutAContainerIsRemoved pins an entry whose runner is gone and whose
// run has no container left: the run is over, its entry is removed, and a run inside
// its bind starts.
func TestAnEntryWithoutAContainerIsRemoved(t *testing.T) {
	root := t.TempDir()
	sub := mkdirs(t, filepath.Join(root, "sub"))
	file := leave(t, root, &leftEngine)
	a := answer(t, false, nil)
	sp := walledSpec(t, &openWall{})
	sp.Mounts, sp.Dir = []wall.Mount{{Path: sub}}, sub
	if res, err := session.Run(context.Background(), sp); err != nil || res.ExitCode != 0 {
		t.Fatalf("a run beside an entry whose run is over: %+v, %v", res, err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("the entry is still there: %v", err)
	}
	if len(a.ids) == 0 || a.ids[0] != leftID {
		t.Errorf("asked for %q", a.ids)
	}
}

// TestAnEngineThatCannotBeAskedStopsTheRun pins that a run that cannot tell whether an
// entry whose runner is gone still has containers does not start, and binds nothing:
// for an engine that fails, an entry that records no engine, and one that cannot be
// read. The entry stays.
func TestAnEngineThatCannotBeAskedStopsTheRun(t *testing.T) {
	answer(t, false, errors.New("wall docker: /opt/left/docker ps: exit status 1: "+
		"Cannot connect to the Docker daemon"))
	for _, c := range []struct {
		name   string
		engine *wall.Engine
		write  string
		cause  string
	}{
		{"the engine fails", &leftEngine, "", "Cannot connect to the Docker daemon"},
		{"no engine", nil, "", "records no engine"},
		{"unreadable", &leftEngine, "{", "cannot be read"},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			file := leave(t, root, c.engine)
			if c.write != "" {
				if err := os.WriteFile(file, []byte(c.write), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			w := &openWall{}
			sp := walledSpec(t, w)
			sp.Mounts, sp.Dir = []wall.Mount{{Path: t.TempDir()}}, t.TempDir()
			r := refusalOf(t, "engine_unreachable", runErr(sp))
			prefix := "Docker could not be asked whether the walled run " + leftID +
				" is still going, so the run does not start: "
			if !slices.Equal(r.Names, []string{leftID}) ||
				!strings.HasPrefix(r.Detail, prefix) || !strings.Contains(r.Detail, c.cause) {
				t.Errorf("names %q, detail %q", r.Names, r.Detail)
			}
			if w.req.RunID != "" || w.wrapped {
				t.Error("the wall was prepared")
			}
			if _, err := os.Stat(file); err != nil {
				t.Errorf("the entry is gone: %v", err)
			}
		})
	}
}

// TestAWalledRunRecordsItsEngine pins the entry of a run whose wall is in a container
// engine: it records the engine, as the wall reaches it, for another runner to ask.
func TestAWalledRunRecordsItsEngine(t *testing.T) {
	w := &heldEngined{holdingWall: newHoldingWall(), engine: leftEngine}
	s := start(walledSpec(t, w))
	select {
	case <-w.reached:
	case <-s.done:
		t.Fatalf("the run ended: %+v, %v", s.res, s.err)
	}
	b, err := os.ReadFile(filepath.Join(registry(t), w.id))
	close(w.release)
	<-s.done
	if err != nil {
		t.Fatal(err)
	}
	var entry struct {
		Engine *wall.Engine `json:"engine"`
	}
	if err := json.Unmarshal(b, &entry); err != nil || entry.Engine == nil ||
		entry.Engine.Command != leftEngine.Command ||
		!slices.Equal(entry.Engine.Env, leftEngine.Env) || entry.Engine.Wall != "docker" {
		t.Errorf("entry %s: %v", b, err)
	}
}

// heldEngined is a holding wall in a container engine.
type heldEngined struct {
	*holdingWall
	engine wall.Engine
}

func (w *heldEngined) Engine(context.Context) wall.Engine { return w.engine }

func (w *heldEngined) EngineID(context.Context) (string, error) { return "", nil }

// closeFailing is a wall in a container engine whose Close fails, as one whose
// containers could not be removed.
type closeFailing struct{ enginedWall }

func (w *closeFailing) Prepare(
	_ context.Context, req wall.Request,
) (wall.Enclosure, error) {
	w.req = req
	return w, nil
}

func (w *closeFailing) Close(context.Context) error {
	return errors.New("wall docker: rm: exit status 1")
}

// TestAnEntryStaysWhenTheWallIsNotRemoved pins a run whose wall could not be removed:
// its containers may outlive it, so its entry stays, its lock free, and is a run still
// going while the engine holds one of them.
func TestAnEntryStaysWhenTheWallIsNotRemoved(t *testing.T) {
	root := t.TempDir()
	w := &closeFailing{enginedWall{engine: leftEngine}}
	sp := walledSpec(t, w)
	sp.Mounts, sp.Dir = []wall.Mount{{Path: root}}, root
	if _, err := session.Run(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(registry(t), w.req.RunID)
	t.Cleanup(func() { os.Remove(file) })
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("the entry of a run whose wall stays is gone: %v", err)
	}
	answer(t, true, nil)
	sub := mkdirs(t, filepath.Join(root, "sub"))
	other := walledSpec(t, &openWall{})
	other.Mounts, other.Dir = []wall.Mount{{Path: sub}}, sub
	r := refusalOf(t, "mount_shared_with_run", runErr(other))
	if !slices.Equal(r.Names, []string{sub, w.req.RunID, root}) {
		t.Errorf("names %q", r.Names)
	}
}

// TestAnUnpinnedEntryWithoutAnIDIsNoAnswer pins an entry whose engine was recorded with
// neither a pinned selection nor an id: podman's with nothing set, or with DOCKER_HOST
// alone, which podman does not read. Whatever engine answers now may be another, so a
// later run gets no answer and does not start, and the entry stays.
func TestAnUnpinnedEntryWithoutAnIDIsNoAnswer(t *testing.T) {
	session.SetRunContainersExist(nil)
	for _, env := range [][]string{nil, {"DOCKER_HOST=unix:///run/docker.sock"}} {
		root := t.TempDir()
		file := leave(t, root, &wall.Engine{Wall: "docker", Command: "podman", Env: env})
		w := &openWall{}
		sp := walledSpec(t, w)
		sp.Mounts, sp.Dir = []wall.Mount{{Path: t.TempDir()}}, t.TempDir()
		r := refusalOf(t, "engine_unreachable", runErr(sp))
		if !slices.Equal(r.Names, []string{leftID}) ||
			!strings.Contains(r.Detail, "neither a pinned selection nor an id") {
			t.Errorf("%q: names %q, detail %q", env, r.Names, r.Detail)
		}
		if w.req.RunID != "" {
			t.Errorf("%q: the wall was prepared", env)
		}
		if _, err := os.Stat(file); err != nil {
			t.Errorf("%q: the entry is gone: %v", env, err)
		}
	}
}

// TestTheIDIsRecordedOnceTheEnclosureIsPrepared pins an engine that gave no id when the
// run started: it is asked again once the enclosure is prepared, and its answer goes in
// the entry; with no answer, the entry records none. The entry stays here because the
// wall is not removed.
func TestTheIDIsRecordedOnceTheEnclosureIsPrepared(t *testing.T) {
	for _, c := range []struct {
		name, id string
		err      error
		want     string
	}{
		{"an answer", "4c1f0a2e-engine", nil, "4c1f0a2e-engine"},
		{"no answer", "", errors.New("Cannot connect to the Docker daemon"), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			w := &closeFailing{enginedWall{engine: leftEngine, id: c.id, idErr: c.err}}
			sp := walledSpec(t, w)
			sp.Mounts, sp.Dir = []wall.Mount{{Path: root}}, root
			if _, err := session.Run(context.Background(), sp); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(registry(t), w.req.RunID)
			t.Cleanup(func() { os.Remove(file) })
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var entry struct {
				Engine *wall.Engine `json:"engine"`
			}
			if err := json.Unmarshal(b, &entry); err != nil || entry.Engine == nil ||
				entry.Engine.ID != c.want || !entry.Engine.Pinned {
				t.Errorf("entry %s: %v", b, err)
			}
		})
	}
}
