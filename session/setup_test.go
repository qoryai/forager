package session_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// The tests of this file pin (*session.Run).Setup: the run's setup commands in the
// setup container, a container of the run's image apart from the agent's.

// setupWall is a targetWall whose enclosure starts a setup container, as the Docker
// adapter's does: StartSetup notes its launch, and ExecSetup notes each command, writes
// out <words> to stdout and err <words> to stderr, and exits with the code that codes maps
// the command's first word to, 0 for none. RemoveSetup counts its calls. startErr,
// execErr and removeErr, when set, are the errors of StartSetup, ExecSetup and
// RemoveSetup.
type setupWall struct {
	targetWall
	mu        sync.Mutex
	setup     wall.Launch
	starts    int
	execs     [][]string
	codes     map[string]int
	removes   int
	startErr  error
	execErr   error
	removeErr error
}

func (w *setupWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *setupWall) StartSetup(_ context.Context, l wall.Launch) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.setup = l
	w.starts++
	return w.startErr
}

func (w *setupWall) ExecSetup(_ context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	w.mu.Lock()
	w.execs = append(w.execs, args)
	w.mu.Unlock()
	if w.execErr != nil {
		return -1, w.execErr
	}
	words := strings.Join(args, " ")
	fmt.Fprintf(stdout, "out %s\n", words)
	fmt.Fprintf(stderr, "err %s\n", words)
	return w.codes[args[0]], nil
}

func (w *setupWall) RemoveSetup(context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.removes++
	return w.removeErr
}

// twoCommands are an install and a service's start, as a caller passes them.
var twoCommands = []session.SetupCommand{
	{Name: "install", Args: []string{"make", "deps"}},
	{Name: "start services", Args: []string{"sh", "-c", "pg_ctl start >/tmp/pg.log 2>&1"}},
}

// streamsOf are the dev.qory.run.log chunks of step in evs, as "<stream> <text>".
func streamsOf(evs []map[string]any, step int) []string {
	var out []string
	for _, e := range ofType(evs, event.RunLog) {
		d := data(e)
		if d["step"] != float64(step) {
			continue
		}
		b, _ := base64.StdEncoding.DecodeString(d["bytes"].(string))
		if _, ok := d["session"]; ok {
			out = append(out, "session "+fmt.Sprint(d["session"]))
		}
		out = append(out, fmt.Sprintf("%v %s", d["stream"], strings.TrimSuffix(string(b), "\n")))
	}
	return out
}

// TestTheSetupRunsInTheSetupContainer pins Setup with setup outside, as qory runs it
// after a fetch: the wall step "start the setup container" and a setup step per command
// follow the run's last step, each command's stdout and stderr are its step's lines with
// no session, and the join's steps come after. The setup container gets the working
// folder as its one mount, the run's forwarder and proxy secret, the caller's variables,
// QORY_RUN_SYSTEM among them, and no proxy variable, and SetupSpec.Limits, and the agent's
// container reaches the same forwarder.
func TestTheSetupRunsInTheSetupContainer(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	hostStep(t, r, event.StepFetch, "fetch github.com/example-org/app", "Cloning into 'app'...\n")
	env := []string{"APP_ENV=test", "QORY_RUN_SYSTEM=tickets"}
	limits := wall.Limits{CPUs: "2", Memory: "4g", PIDs: 512, ShmSize: "1g"}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Env: env, Commands: twoCommands, Limits: limits}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
	if w.setup.Limits != limits {
		t.Errorf("the setup container's limits %+v, want %+v", w.setup.Limits, limits)
	}
	want := []string{
		"step 1 fetch fetch github.com/example-org/app", "log <nil> 1 Cloning into 'app'...", "step 1 succeeded 0",
		"step 2 wall start the setup container", "step 2 succeeded -1",
		"step 3 setup install", "log <nil> 3 out make deps", "log <nil> 3 err make deps", "step 3 succeeded 0",
		"step 4 setup start services", "log <nil> 4 out sh -c pg_ctl start >/tmp/pg.log 2>&1", "log <nil> 4 err sh -c pg_ctl start >/tmp/pg.log 2>&1", "step 4 succeeded 0",
		"step 5 join join session 1", "step 5 succeeded -1", "session 1 started",
		"step 6 wall start the wall", "step 6 succeeded -1", "session 1 exited", "run exited",
	}
	evs := events(t, &session.Result{Dir: r.Dir()})
	for where, evs := range map[string][]map[string]any{"the record": evs, "the link": g.Events()} {
		if got := stepOrder(evs); !slices.Equal(got, want) {
			t.Errorf("%s:\n%q\nwant\n%q", where, got, want)
		}
	}
	if got := streamsOf(evs, 3); !slices.Equal(got, []string{"stdout out make deps", "stderr err make deps"}) {
		t.Errorf("step 3's lines %q", got)
	}
	if w.starts != 1 || !slices.EqualFunc(w.execs, [][]string{twoCommands[0].Args, twoCommands[1].Args}, slices.Equal[[]string]) {
		t.Errorf("started %d times, ran %q", w.starts, w.execs)
	}
	if w.setup.Dir != sp.Dir || !slices.Equal(w.setup.Mounts, []wall.Mount{{Path: sp.Dir}}) {
		t.Errorf("the setup container's folder %q, mounts %v", w.setup.Dir, w.setup.Mounts)
	}
	if w.setup.Proxy == "" || w.setup.Proxy != w.got.Proxy || w.setup.ProxyToken != linktest.ProxySecret {
		t.Errorf("the setup container's proxy %q and token %q; the agent's proxy %q", w.setup.Proxy, w.setup.ProxyToken, w.got.Proxy)
	}
	setupEnv := strings.Join(w.setup.Env, "\n")
	if !slices.Contains(w.setup.Env, "APP_ENV=test") || !slices.Contains(w.setup.Env, "QORY_RUN_SYSTEM=tickets") || strings.Contains(setupEnv, "PROXY") {
		t.Errorf("the setup container's variables:\n%s", setupEnv)
	}
}

// TestTheSetupWritesTheWorkspaceTheAgentReads pins Setup beside a join with
// SessionSpec.WorkspaceReadOnly: the setup container binds the working folder writable,
// and the agent's container binds it read-only.
func TestTheSetupWritesTheWorkspaceTheAgentReads(t *testing.T) {
	sp, _ := specGateway(t, "FAKE_EXIT=0")
	w := &setupWall{}
	sp.Wall, sp.Image, sp.WorkspaceReadOnly = w, "example.com/agent:1", true
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
		t.Fatal(err)
	}
	res, err := r.Join(ctx, sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(w.setup.Mounts, []wall.Mount{{Path: sp.Dir}}) {
		t.Errorf("the setup container's mounts %v, want %s writable", w.setup.Mounts, sp.Dir)
	}
	want := []wall.Mount{{Path: sp.Dir, ReadOnly: true}, {Path: res.SessionDir, ReadOnly: true}}
	if !slices.Equal(w.got.Mounts, want) {
		t.Errorf("the agent's mounts %v, want %v", w.got.Mounts, want)
	}
}

// TestTheSetupFetchesTheImageFirst pins Setup in a run whose image is a reference no
// step fetched: its image step comes first, then the wall step and the setup steps, and
// the join that follows fetches nothing.
func TestTheSetupFetchesTheImageFirst(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	byReference(g)
	w := &setupWall{}
	sp.Wall, sp.Image, sp.ImagesAllow = w, "example.com/agent:1", []string{"registry.example/"}
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
	got := stepOrder(events(t, &session.Result{Dir: r.Dir()}))
	want := []string{
		"step 1 image " + pinned, "step 1 succeeded -1",
		"step 2 wall start the setup container", "step 2 succeeded -1",
		"step 3 setup install", "log <nil> 3 out make deps", "log <nil> 3 err make deps", "step 3 succeeded 0",
		"step 4 join join session 1",
	}
	if len(got) < len(want) || !slices.Equal(got[:len(want)], want) || slices.Contains(got, "step 6 image "+pinned) {
		t.Errorf("the steps:\n%q\nwant them to start with\n%q", got, want)
	}
	if len(w.pulls) != 1 || w.setup.Dir != "/workspace" {
		t.Errorf("pulled %d times; the setup container's folder %q", len(w.pulls), w.setup.Dir)
	}
}

// TestASetupCommandThatFailsFailsTheRun pins a setup command that exits otherwise than
// 0: its step ends failed with its exit status, Setup returns a *SetupError whose text
// starts with the fix, no later command runs, and every later join returns an error and
// writes nothing.
func TestASetupCommandThatFailsFailsTheRun(t *testing.T) {
	sp := spec(t, "FAKE_EXIT=0")
	w := &setupWall{codes: map[string]int{"make": 2}}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	err = r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands})
	var se *session.SetupError
	if !errors.As(err, &se) || se.Name != "install" || se.Step != 2 || se.ExitCode != 2 ||
		err.Error() != "Fix install: setup step 2 exited with 2." {
		t.Fatalf("the setup: %#v", err)
	}
	if len(w.execs) != 1 {
		t.Errorf("ran %q, want the first command alone", w.execs)
	}
	_, err = r.Join(ctx, sp.SessionSpec)
	if want := "Open another run: setup step 2 of this run failed, so no session can join it."; err == nil || err.Error() != want {
		t.Errorf("the join: %v, want %q", err, want)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	got := stepOrder(events(t, &session.Result{Dir: r.Dir()}))
	want := []string{
		"step 1 wall start the setup container", "step 1 succeeded -1",
		"step 2 setup install", "log <nil> 2 out make deps", "log <nil> 2 err make deps", "step 2 failed 2",
		"run exited",
	}
	if !slices.Equal(got, want) {
		t.Errorf("the steps:\n%q\nwant\n%q", got, want)
	}
}

// TestASetupStepThatCannotRunFailsTheRun pins a setup container that does not start and
// a command that does not run: the step ends failed with -1 after the error's line, the
// error is Setup's, and a later join returns an error and writes nothing.
func TestASetupStepThatCannotRunFailsTheRun(t *testing.T) {
	for _, c := range []struct {
		name string
		w    *setupWall
		want []string
	}{
		{"the start", &setupWall{startErr: errors.New("wall docker: start qory-x-setup: exit status 125")}, []string{
			"step 1 wall start the setup container", "log <nil> 1 wall docker: start qory-x-setup: exit status 125", "step 1 failed -1", "run exited",
		}},
		{"a command", &setupWall{execErr: errors.New("wall docker: the setup container stopped: hold: told to stop")}, []string{
			"step 1 wall start the setup container", "step 1 succeeded -1",
			"step 2 setup install", "log <nil> 2 wall docker: the setup container stopped: hold: told to stop", "step 2 failed -1", "run exited",
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp := spec(t, "FAKE_EXIT=0")
			sp.Wall, sp.Image = c.w, "example.com/agent:1"
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands}); err == nil || errors.As(err, new(*session.SetupError)) {
				t.Errorf("the setup: %v", err)
			}
			if _, err := r.Join(ctx, sp.SessionSpec); err == nil || !strings.HasPrefix(err.Error(), "Open another run: setup step ") {
				t.Errorf("the join: %v", err)
			}
			if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
				t.Fatal(err)
			}
			if got := stepOrder(events(t, &session.Result{Dir: r.Dir()})); !slices.Equal(got, c.want) {
				t.Errorf("the steps:\n%q\nwant\n%q", got, c.want)
			}
		})
	}
}

// noRemoveWall is an open wall whose enclosure starts a setup container and has no
// RemoveSetup.
type noRemoveWall struct{ openWall }

func (w *noRemoveWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	return w, nil
}

func (*noRemoveWall) StartSetup(context.Context, wall.Launch) error { return nil }

func (*noRemoveWall) ExecSetup(context.Context, []string, io.Writer, io.Writer) (int, error) {
	return 0, nil
}

// TestASetupThatCannotStartWritesNothing pins each error of Setup before its steps,
// with its text, and that the record then has no step of it.
func TestASetupThatCannotStartWritesNothing(t *testing.T) {
	ctx := context.Background()
	open := func(t *testing.T, w wall.Wall) (runSpec, *session.Run) {
		t.Helper()
		sp := spec(t, "FAKE_EXIT=0")
		if w != nil {
			sp.Wall, sp.Image = w, "example.com/agent:1"
		}
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { r.Close(ctx, session.Outcome{State: event.StateSucceeded}) })
		return sp, r
	}
	setup := func(sp runSpec) session.SetupSpec {
		return session.SetupSpec{Dir: sp.Dir, Commands: twoCommands}
	}
	for _, c := range []struct {
		name   string
		wall   func() wall.Wall
		before func(t *testing.T, sp runSpec, r *session.Run) session.SetupSpec
		want   string
	}{
		{"no wall", func() wall.Wall { return nil }, func(_ *testing.T, sp runSpec, _ *session.Run) session.SetupSpec { return setup(sp) },
			"Open the run with a wall to run its setup: setup runs in a container of the run's image."},
		{"after a join", nil, func(t *testing.T, sp runSpec, r *session.Run) session.SetupSpec {
			if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
				t.Fatal(err)
			}
			return setup(sp)
		}, "Run the setup before the first join: session 1 joined the run."},
		{"twice", nil, func(t *testing.T, sp runSpec, r *session.Run) session.SetupSpec {
			if err := r.Setup(ctx, setup(sp)); err != nil {
				t.Fatal(err)
			}
			return setup(sp)
		}, "Run the setup once per run: it ran in steps 1 to 3."},
		{"a host step open", nil, func(t *testing.T, sp runSpec, r *session.Run) session.SetupSpec {
			if _, err := r.StartStep(event.StepFetch, "fetch github.com/example-org/app"); err != nil {
				t.Fatal(err)
			}
			return setup(sp)
		}, "Exit step 1 before the setup: one host step is open at a time."},
		{"a copy step open", nil, func(t *testing.T, sp runSpec, r *session.Run) session.SetupSpec {
			if _, err := r.StartStep(event.StepCopy, "copy work out"); err != nil {
				t.Fatal(err)
			}
			return setup(sp)
		}, "Exit step 1 before the setup: one host step is open at a time."},
		{"no command", nil, func(_ *testing.T, sp runSpec, _ *session.Run) session.SetupSpec {
			return session.SetupSpec{Dir: sp.Dir}
		}, "Give the setup at least one command."},
		{"a command without a name", nil, func(_ *testing.T, sp runSpec, _ *session.Run) session.SetupSpec {
			return session.SetupSpec{Dir: sp.Dir, Commands: []session.SetupCommand{twoCommands[0], {Args: []string{"true"}}}}
		}, `Give setup command 2 a name, such as "install".`},
		{"a command without a program", nil, func(_ *testing.T, sp runSpec, _ *session.Run) session.SetupSpec {
			return session.SetupSpec{Dir: sp.Dir, Commands: []session.SetupCommand{{Name: "install", Args: []string{""}}}}
		}, "Give setup command 1 a program: its first word is empty."},
		{"a NUL", nil, func(_ *testing.T, sp runSpec, _ *session.Run) session.SetupSpec {
			return session.SetupSpec{Dir: sp.Dir, Commands: []session.SetupCommand{{Name: "install", Args: []string{"make", "a\x00b"}}}}
		}, "Remove the NUL from setup command 1: no argument contains one."},
		{"the host proxy's URL", nil, func(t *testing.T, sp runSpec, r *session.Run) session.SetupSpec {
			h, err := r.HostProxy()
			if err != nil {
				t.Fatal(err)
			}
			s := setup(sp)
			s.Env = []string{"APP_URL=" + h.ProxyURL}
			return s
		}, "Leave the host proxy's URL out of the setup's variables: APP_URL contains its password, which the setup container never gets."},
		{"a closed run", nil, func(t *testing.T, sp runSpec, r *session.Run) session.SetupSpec {
			if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
				t.Fatal(err)
			}
			return setup(sp)
		}, "Open another run to run its setup: the run is closed."},
		{"a wall without a setup container", func() wall.Wall { return &openWall{} }, func(_ *testing.T, sp runSpec, _ *session.Run) session.SetupSpec {
			return setup(sp)
		}, "Run the setup behind the Docker wall: the open wall does not implement StartSetup, ExecSetup and RemoveSetup."},
		{"a wall with no RemoveSetup", func() wall.Wall { return &noRemoveWall{} }, func(_ *testing.T, sp runSpec, _ *session.Run) session.SetupSpec {
			return setup(sp)
		}, "Run the setup behind the Docker wall: the open wall does not implement StartSetup, ExecSetup and RemoveSetup."},
	} {
		t.Run(c.name, func(t *testing.T) {
			var w wall.Wall = &setupWall{}
			if c.wall != nil {
				w = c.wall()
			}
			sp, r := open(t, w)
			s := c.before(t, sp, r)
			steps := len(ofType(events(t, &session.Result{Dir: r.Dir()}), event.StepStarted))
			if err := r.Setup(ctx, s); err == nil || err.Error() != c.want {
				t.Errorf("got %v\nwant %s", err, c.want)
			}
			if got := len(ofType(events(t, &session.Result{Dir: r.Dir()}), event.StepStarted)); got != steps {
				t.Errorf("the setup wrote %d steps", got-steps)
			}
			if sw, ok := w.(*setupWall); ok && c.name != "twice" && sw.starts != 0 {
				t.Errorf("the setup container started %d times", sw.starts)
			}
		})
	}
}

// TestASetupFolderOfForagersFilesIsNoSetup pins that the setup's working folder gets a
// join's checks of its places: a folder that contains the run directories is refused with
// mount_contains_forager_files, before any step, and the setup container never starts.
func TestASetupFolderOfForagersFilesIsNoSetup(t *testing.T) {
	sp := spec(t, "FAKE_EXIT=0")
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
	err = r.Setup(ctx, session.SetupSpec{Dir: filepath.Dir(sp.RunsDir), Commands: twoCommands})
	var ref *session.Refusal
	if !errors.As(err, &ref) || ref.Code != "mount_contains_forager_files" {
		t.Fatalf("the setup: %v", err)
	}
	if w.starts != 0 || len(ofType(events(t, &session.Result{Dir: r.Dir()}), event.StepStarted)) != 0 {
		t.Errorf("started %d times, with steps", w.starts)
	}
}

// TestASetupWhileASessionRunsIsRefused pins Setup while a session of the run is
// running: it returns an error that starts with the fix and writes nothing.
func TestASetupWhileASessionRunsIsRefused(t *testing.T) {
	w := newHoldingWall()
	sp := walledSpec(t, w)
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	joined := make(chan error, 1)
	go func() {
		_, err := r.Join(ctx, sp.SessionSpec)
		joined <- err
	}()
	<-w.reached
	err = r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands})
	close(w.release)
	if err := <-joined; err != nil {
		t.Fatal(err)
	}
	if want := "Run the setup before the first join: a session of the run is still running."; err == nil || err.Error() != want {
		t.Errorf("got %v\nwant %s", err, want)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
	if got := stepOrder(events(t, &session.Result{Dir: r.Dir()})); slices.Contains(got, "step 3 wall start the setup container") || len(got) == 0 {
		t.Errorf("the steps %q", got)
	}
}

// TestASetupFolderThatContainsForagersFilesIsNoSetup pins SetupSpec.ForagerFiles: a
// working folder that contains one of them is refused with mount_contains_forager_files,
// before any step, and the setup container never starts.
func TestASetupFolderThatContainsForagersFilesIsNoSetup(t *testing.T) {
	sp := spec(t, "FAKE_EXIT=0")
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	config := mkdirs(t, filepath.Join(sp.Dir, "config"))
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
	err = r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands, ForagerFiles: []string{config}})
	var ref *session.Refusal
	if !errors.As(err, &ref) || ref.Code != "mount_contains_forager_files" {
		t.Fatalf("the setup: %v", err)
	}
	if w.starts != 0 || len(ofType(events(t, &session.Result{Dir: r.Dir()}), event.StepStarted)) != 0 {
		t.Errorf("started %d times, with steps", w.starts)
	}
}

// TestASetupFolderThroughALinkInAWrittenPlaceIsNoSetup pins SetupSpec.Written: a
// working folder whose path goes through a link inside a written place, and does not
// resolve into it, is refused with mount_through_link, before any step, and the setup
// container never starts.
func TestASetupFolderThroughALinkInAWrittenPlaceIsNoSetup(t *testing.T) {
	repo, secret := t.TempDir(), t.TempDir()
	trees := mkdirs(t, filepath.Join(repo, ".claude", "worktrees"))
	wt := filepath.Join(trees, "wt")
	symlink(t, secret, wt)
	sp := spec(t, "FAKE_EXIT=0")
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
	err = r.Setup(ctx, session.SetupSpec{Dir: wt, Commands: twoCommands, Written: []string{repo}})
	throughLink(t, err, wt, wt, repo)
	if w.starts != 0 || len(ofType(events(t, &session.Result{Dir: r.Dir()}), event.StepStarted)) != 0 {
		t.Errorf("started %d times, with steps", w.starts)
	}
}

// TestASetupVariableWithTheEngineProxysPasswordIsRefused pins a value of SetupSpec.Env
// that contains the password of OpenSpec.EngineProxy, in a run whose image no step
// fetched yet, so the run's masker does not have it: the password as it is, in a proxy
// URL, and as the base64 of qory:<password> are each refused before the image step,
// with the line of a host proxy's URL, and nothing is pulled or started.
func TestASetupVariableWithTheEngineProxysPasswordIsRefused(t *testing.T) {
	basic := base64.StdEncoding.EncodeToString([]byte("qory:" + enginePassword))
	for name, value := range map[string]string{
		"as it is":  enginePassword,
		"in a URL":  "http://qory:" + enginePassword + "@" + engineProxyAddr,
		"in base64": "Basic " + basic,
	} {
		t.Run(name, func(t *testing.T) {
			sp, g := specGateway(t, "FAKE_EXIT=0")
			byReference(g)
			w := &setupWall{}
			sp.Wall, sp.Image, sp.ImagesAllow = w, "example.com/agent:1", []string{"registry.example/"}
			sp.EngineProxy = &session.EngineProxy{Addr: engineProxyAddr, Password: enginePassword}
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
			err = r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Env: []string{"APP_URL=" + value}, Commands: twoCommands})
			want := "Leave the host proxy's URL out of the setup's variables: APP_URL contains its password, which the setup container never gets."
			if err == nil || err.Error() != want {
				t.Errorf("got %v\nwant %s", err, want)
			}
			if w.starts != 0 || len(w.pulls) != 0 || len(ofType(events(t, &session.Result{Dir: r.Dir()}), event.StepStarted)) != 0 {
				t.Errorf("started %d times, pulled %d times, with steps", w.starts, len(w.pulls))
			}
		})
	}
}

// heldSetupWall is a holdingWall whose enclosure starts a setup container that runs
// every command with 0, so the Wrap of a session of a run with setup returns only once
// the test releases it.
type heldSetupWall struct{ *holdingWall }

func (w heldSetupWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	if _, err := w.holdingWall.Prepare(ctx, req); err != nil {
		return nil, err
	}
	return w, nil
}

func (heldSetupWall) StartSetup(context.Context, wall.Launch) error { return nil }

func (heldSetupWall) ExecSetup(context.Context, []string, io.Writer, io.Writer) (int, error) {
	return 0, nil
}

func (heldSetupWall) RemoveSetup(context.Context) error { return nil }

// TestTheRunsEntryListsTheSetupFolderDuringASession pins the run's entry among the walled
// runs still going while a session runs after Setup: it lists the setup container's
// working folder, apart from the session's workspace, after Setup, after the join's
// check, after its wall step and after the session, so no other walled run binds a
// place inside it. The run's checks against the registry are its open's, two of
// Setup's and then the join's two: at the fifth, the entry is the join check's.
func TestTheRunsEntryListsTheSetupFolderDuringASession(t *testing.T) {
	var joined []byte
	calls := 0
	session.SetRegisterPause(func(runID string) {
		if calls++; calls == 5 {
			joined, _ = os.ReadFile(filepath.Join(registry(t), runID))
		}
	})
	t.Cleanup(func() { session.SetRegisterPause(nil) })
	w := heldSetupWall{newHoldingWall()}
	sp := walledSpec(t, w)
	other := t.TempDir()
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: other, Commands: twoCommands}); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(registry(t), w.id)
	lists := func(when string) {
		t.Helper()
		b, err := os.ReadFile(entry)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), other) {
			t.Errorf("%s, the run's entry does not list the setup folder %s:\n%s", when, other, b)
		}
	}
	lists("after Setup")
	done := make(chan error, 1)
	go func() {
		_, err := r.Join(ctx, sp.SessionSpec)
		done <- err
	}()
	<-w.reached
	if !strings.Contains(string(joined), other) {
		t.Errorf("after the join's check, the run's entry does not list the setup folder %s:\n%s", other, joined)
	}
	lists("after the wall step")
	close(w.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	lists("after the session")
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
}

// TestRemoveSetupComesBetweenTheSetupAndTheJoin pins RemoveSetup as qory calls it for a
// read run: its wall step follows the setup's steps and comes before the join's, in the
// record and on the link, the wall removes the setup container once, and the close that
// follows works. The second call returns nil, removes nothing and writes nothing, and
// Setup still returns its error, with the steps of the setup alone in its text.
func TestRemoveSetupComesBetweenTheSetupAndTheJoin(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	w := &setupWall{}
	sp.Wall, sp.Image, sp.WorkspaceReadOnly = w, "example.com/agent:1", true
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
		t.Fatal(err)
	}
	if err := r.RemoveSetup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.RemoveSetup(ctx); err != nil {
		t.Errorf("the second call: %v", err)
	}
	err = r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]})
	if want := "Run the setup once per run: it ran in steps 1 to 2."; err == nil || err.Error() != want {
		t.Errorf("a setup after the removal: %v, want %q", err, want)
	}
	if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
	if w.removes != 1 || w.starts != 1 {
		t.Errorf("the setup container started %d times and was removed %d times, want 1 of each", w.starts, w.removes)
	}
	want := []string{
		"step 1 wall start the setup container", "step 1 succeeded -1",
		"step 2 setup install", "log <nil> 2 out make deps", "log <nil> 2 err make deps", "step 2 succeeded 0",
		"step 3 wall remove the setup container", "step 3 succeeded -1",
		"step 4 join join session 1", "step 4 succeeded -1", "session 1 started",
		"step 5 wall start the wall", "step 5 succeeded -1", "session 1 exited", "run exited",
	}
	for where, evs := range map[string][]map[string]any{"the record": events(t, &session.Result{Dir: r.Dir()}), "the link": g.Events()} {
		if got := stepOrder(evs); !slices.Equal(got, want) {
			t.Errorf("%s:\n%q\nwant\n%q", where, got, want)
		}
	}
}

// removedAfterASession is the end of the steps of a run with one setup command and one
// session that then removes the setup container and runs a push step.
var removedAfterASession = []string{
	"session 1 exited",
	"step 5 wall remove the setup container", "step 5 succeeded -1",
	"step 6 push push work to github.com/example-org/app", "step 6 succeeded 0",
	"run exited",
}

// TestRemoveSetupAfterASessionEnded pins RemoveSetup as qory calls it for a write run:
// the setup container runs through the session, then its removal's wall step follows
// dev.qory.session.exited and comes before the push step, the wall removes it once, and
// the second call returns nil and writes nothing.
func TestRemoveSetupAfterASessionEnded(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
		t.Fatal(err)
	}
	if w.removes != 0 {
		t.Errorf("the wall removed the setup container %d times before the call", w.removes)
	}
	if err := r.RemoveSetup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.RemoveSetup(ctx); err != nil {
		t.Errorf("the second call: %v", err)
	}
	hostStep(t, r, event.StepPush, "push work to github.com/example-org/app", "pushed\n")
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
	if w.removes != 1 {
		t.Errorf("the wall removed the setup container %d times, want 1", w.removes)
	}
	for where, evs := range map[string][]map[string]any{"the record": events(t, &session.Result{Dir: r.Dir()}), "the link": g.Events()} {
		got := slices.DeleteFunc(stepOrder(evs), func(s string) bool { return strings.HasPrefix(s, "log ") })
		if len(got) < len(removedAfterASession) || !slices.Equal(got[len(got)-len(removedAfterASession):], removedAfterASession) {
			t.Errorf("%s:\n%q\nwant them to end with\n%q", where, got, removedAfterASession)
		}
	}
}

// TestARemovalAfterASessionReachesTheGatewaysRecord pins the same run through a real
// gateway: the link accepts the removal's wall step and the push step after
// dev.qory.session.exited, the gateway's record has them in that order, and the run ends
// with the close's outcome, not batch_refused.
func TestARemovalAfterASessionReachesTheGatewaysRecord(t *testing.T) {
	sp := spec(t, "FAKE_EXIT=0")
	startGateway(t, &sp, gateway.Config{})
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
		t.Fatal(err)
	}
	res, err := r.Join(ctx, sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.RemoveSetup(ctx); err != nil {
		t.Fatal(err)
	}
	hostStep(t, r, event.StepPush, "push work to github.com/example-org/app", "pushed\n")
	closed, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded})
	if err != nil {
		t.Fatal(err)
	}
	if closed.RunClosed || closed.Undelivered != 0 {
		t.Errorf("the close: %+v", closed)
	}
	evs := record(t, res)
	got := slices.DeleteFunc(stepOrder(evs), func(s string) bool { return strings.HasPrefix(s, "log ") })
	if len(got) < len(removedAfterASession) || !slices.Equal(got[len(got)-len(removedAfterASession):], removedAfterASession) {
		t.Errorf("the gateway's record:\n%q\nwant it to end with\n%q", got, removedAfterASession)
	}
	if d := data(ofType(evs, event.RunExited)[0]); d["state"] != event.StateSucceeded || d["reason"] != nil {
		t.Errorf("the run's end: %v", d)
	}
}

// TestARemovalThatFailsAfterASessionFailsItsStep pins a removal that fails after a
// session: its wall step ends failed with its line, after dev.qory.session.exited, the
// error starts with the close, and a later join returns the error of that step.
func TestARemovalThatFailsAfterASessionFailsItsStep(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	w := &setupWall{removeErr: errors.New("wall docker: docker rm --force: exit status 1: told to fail")}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
		t.Fatal(err)
	}
	const line = "Close the run: the setup container may still run, so no session can join: wall docker: docker rm --force: exit status 1: told to fail"
	if err := r.RemoveSetup(ctx); err == nil || err.Error() != line {
		t.Fatalf("the removal: %v, want %q", err, line)
	}
	_, err = r.Join(ctx, sp.SessionSpec)
	if want := "Open another run: setup step 5 of this run failed, so no session can join it."; err == nil || err.Error() != want {
		t.Errorf("a later join: %v, want %q", err, want)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	want := []string{"session 1 exited", "step 5 wall remove the setup container", "log <nil> 5 " + line, "step 5 failed -1", "run exited"}
	for where, evs := range map[string][]map[string]any{"the record": events(t, &session.Result{Dir: r.Dir()}), "the link": g.Events()} {
		if got := stepOrder(evs); len(got) < len(want) || !slices.Equal(got[len(got)-len(want):], want) {
			t.Errorf("%s:\n%q\nwant them to end with\n%q", where, got, want)
		}
	}
}

// TestALaterJoinAfterARemovalAfterASession pins a join after the setup container went:
// session 2 starts as session 1 did, the removal's wall step lies between them, and the
// run's entry still lists the setup folder through session 2, because what the setup
// container wrote there stays.
func TestALaterJoinAfterARemovalAfterASession(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	other := t.TempDir()
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: other, Commands: twoCommands[:1]}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
		t.Fatal(err)
	}
	if err := r.RemoveSetup(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := r.Join(ctx, sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	if res.Session != 2 || res.ExitCode != 0 {
		t.Errorf("the later join: %+v", res)
	}
	entry, err := os.ReadFile(filepath.Join(registry(t), r.ID()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(entry), other) {
		t.Errorf("the run's entry does not list the setup folder %s:\n%s", other, entry)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
	got := slices.DeleteFunc(stepOrder(g.Events()), func(s string) bool { return strings.HasPrefix(s, "log ") })
	want := []string{
		"session 1 exited", "step 5 wall remove the setup container", "step 5 succeeded -1",
		"step 6 join join session 2", "step 6 succeeded -1", "session 2 started",
		"step 7 wall start the wall", "step 7 succeeded -1", "session 2 exited", "run exited",
	}
	if len(got) < len(want) || !slices.Equal(got[len(got)-len(want):], want) {
		t.Errorf("the steps:\n%q\nwant them to end with\n%q", got, want)
	}
	if w.removes != 1 {
		t.Errorf("the wall removed the setup container %d times, want 1", w.removes)
	}
}

// TestRemoveSetupWithNoSetupContainerWritesNothing pins a run with no setup container:
// a run with no wall, a wall that has none and a setup that never ran. RemoveSetup
// returns nil, calls no removal and writes no step, and the join that follows starts as
// it would without the call.
func TestRemoveSetupWithNoSetupContainerWritesNothing(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name string
		open func(*testing.T, *runSpec) *setupWall
		want []string
	}{
		{"no wall", func(*testing.T, *runSpec) *setupWall { return nil },
			[]string{"step 1 join join session 1", "step 1 succeeded -1", "session 1 started", "session 1 exited", "run exited"}},
		{"a wall with no setup container", func(_ *testing.T, sp *runSpec) *setupWall {
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			return nil
		}, []string{"step 1 join join session 1", "step 1 succeeded -1", "session 1 started", "step 2 wall start the wall", "step 2 succeeded -1", "session 1 exited", "run exited"}},
		{"a setup that never ran", func(_ *testing.T, sp *runSpec) *setupWall {
			w := &setupWall{}
			sp.Wall, sp.Image = w, "example.com/agent:1"
			return w
		}, []string{"step 1 join join session 1", "step 1 succeeded -1", "session 1 started", "step 2 wall start the wall", "step 2 succeeded -1", "session 1 exited", "run exited"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp := spec(t, "FAKE_EXIT=0")
			w := c.open(t, &sp)
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			if err := r.RemoveSetup(ctx); err != nil {
				t.Errorf("RemoveSetup: %v", err)
			}
			res, err := r.Join(ctx, sp.SessionSpec)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Close(ctx, session.Outcome{State: res.State, ExitCode: res.ExitCode}); err != nil {
				t.Fatal(err)
			}
			if w != nil && w.removes != 0 {
				t.Errorf("the wall removed %d setup containers", w.removes)
			}
			if got := stepOrder(events(t, &session.Result{Dir: r.Dir()})); !slices.Equal(got, c.want) {
				t.Errorf("the steps:\n%q\nwant\n%q", got, c.want)
			}
		})
	}
}

// TestRemoveSetupAfterAStartThatFailed pins a start of the setup container that returned
// an error after the engine may have started the container, as when ctx ends during
// docker run: RemoveSetup calls the removal and writes its step, the setup's failure
// stays, so a join after it returns the setup's error and writes nothing, and a removal
// that fails is the failed step from then on and sets Run.ContainerKept.
func TestRemoveSetupAfterAStartThatFailed(t *testing.T) {
	ctx := context.Background()
	const started = "wall docker: start qory-x-setup: context canceled"
	for _, c := range []struct {
		name      string
		removeErr error
		want      []string
		kept      bool
		// failed is the step whose failure the join's error contains.
		failed int
	}{
		{"the removal succeeds", nil, []string{
			"step 1 wall start the setup container", "log <nil> 1 " + started, "step 1 failed -1",
			"step 2 wall remove the setup container", "step 2 succeeded -1", "run exited",
		}, false, 1},
		{"the removal fails", errors.New("wall docker: docker rm --force: exit status 1"), []string{
			"step 1 wall start the setup container", "log <nil> 1 " + started, "step 1 failed -1",
			"step 2 wall remove the setup container",
			"log <nil> 2 Close the run: the setup container may still run, so no session can join: wall docker: docker rm --force: exit status 1",
			"step 2 failed -1", "run exited",
		}, true, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp := spec(t, "FAKE_EXIT=0")
			w := &setupWall{startErr: errors.New(started), removeErr: c.removeErr}
			sp.Wall, sp.Image = w, "example.com/agent:1"
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Remove(filepath.Join(registry(t), r.ID())) })
			if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands}); err == nil || err.Error() != started {
				t.Fatalf("the setup: %v, want %q", err, started)
			}
			if err := r.RemoveSetup(ctx); (err != nil) != (c.removeErr != nil) {
				t.Errorf("RemoveSetup: %v, want an error: %v", err, c.removeErr != nil)
			}
			if w.removes != 1 {
				t.Errorf("the wall tried %d removals, want 1", w.removes)
			}
			if got := r.ContainerKept(); got != c.kept {
				t.Errorf("ContainerKept %v, want %v", got, c.kept)
			}
			want := fmt.Sprintf("Open another run: setup step %d of this run failed, so no session can join it.", c.failed)
			if _, err := r.Join(ctx, sp.SessionSpec); err == nil || err.Error() != want {
				t.Errorf("the join: %v, want %q", err, want)
			}
			closed, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1})
			if err != nil {
				t.Fatal(err)
			}
			if closed.WallKept != c.kept {
				t.Errorf("WallKept %v, want %v", closed.WallKept, c.kept)
			}
			if got := stepOrder(events(t, &session.Result{Dir: r.Dir()})); !slices.Equal(got, c.want) {
				t.Errorf("the steps:\n%q\nwant\n%q", got, c.want)
			}
		})
	}
}

// TestRemoveSetupAfterAJoinWithNoSetupContainerReturnsNil pins a run that has no setup
// container and gets none later: after a join and during a host step RemoveSetup
// returns nil and writes nothing, in a run whose setup never ran and in one whose
// setup container RemoveSetup removed before the join. A closed run stays an error.
func TestRemoveSetupAfterAJoinWithNoSetupContainerReturnsNil(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name  string
		setup bool
		want  int
	}{{"a setup that never ran", false, 0}, {"a setup container already removed", true, 1}} {
		t.Run(c.name, func(t *testing.T) {
			sp := spec(t, "FAKE_EXIT=0")
			w := &setupWall{}
			sp.Wall, sp.Image = w, "example.com/agent:1"
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			if c.setup {
				if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
					t.Fatal(err)
				}
				if err := r.RemoveSetup(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
				t.Fatal(err)
			}
			before := len(stepOrder(events(t, &session.Result{Dir: r.Dir()})))
			if err := r.RemoveSetup(ctx); err != nil {
				t.Errorf("after the join: %v", err)
			}
			step, err := r.StartStep(event.StepPush, "push the run's commits")
			if err != nil {
				t.Fatal(err)
			}
			if err := r.RemoveSetup(ctx); err != nil {
				t.Errorf("during a host step: %v", err)
			}
			if err := step.Exit(event.StateSucceeded, 0); err != nil {
				t.Fatal(err)
			}
			got := stepOrder(events(t, &session.Result{Dir: r.Dir()}))[before:]
			if want := 2; len(got) != want {
				t.Errorf("wrote %q, want the host step alone", got)
			}
			if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
				t.Fatal(err)
			}
			if err := r.RemoveSetup(ctx); err == nil || err.Error() != "Remove the setup container before the close: the run is closed." {
				t.Errorf("after the close: %v", err)
			}
			if w.removes != c.want {
				t.Errorf("the wall removed %d setup containers, want %d", w.removes, c.want)
			}
		})
	}
}

// TestRemoveSetupThatCannotStartRemovesNothing pins each error of RemoveSetup before its
// step, with its text: the setup container stays, and the record has no step of it.
func TestRemoveSetupThatCannotStartRemovesNothing(t *testing.T) {
	ctx := context.Background()
	const removal = "wall remove the setup container"
	opens := func(t *testing.T) (*setupWall, runSpec, *session.Run) {
		t.Helper()
		sp := spec(t, "FAKE_EXIT=0")
		w := &setupWall{}
		sp.Wall, sp.Image = w, "example.com/agent:1"
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
			t.Fatal(err)
		}
		return w, sp, r
	}
	check := func(t *testing.T, w *setupWall, r *session.Run, got error, want string) {
		t.Helper()
		if got == nil || got.Error() != want {
			t.Errorf("got %v\nwant %s", got, want)
		}
		if w.removes != 0 {
			t.Errorf("the wall removed %d setup containers", w.removes)
		}
		if steps := stepOrder(events(t, &session.Result{Dir: r.Dir()})); slices.ContainsFunc(steps, func(s string) bool { return strings.HasSuffix(s, removal) }) {
			t.Errorf("the steps %q", steps)
		}
	}
	t.Run("a session runs", func(t *testing.T) {
		held := newHoldingWall()
		w := &setupWall{}
		sp := walledSpec(t, heldRemoveWall{heldSetupWall{held}, w})
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
			t.Fatal(err)
		}
		joined := make(chan error, 1)
		go func() {
			_, err := r.Join(ctx, sp.SessionSpec)
			joined <- err
		}()
		<-held.reached
		got := r.RemoveSetup(ctx)
		close(held.release)
		if err := <-joined; err != nil {
			t.Fatal(err)
		}
		if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
			t.Fatal(err)
		}
		check(t, w, r, got, "Call RemoveSetup after the run's other call returns: another call of the run is running.")
	})
	t.Run("the agent's container may still run", func(t *testing.T) {
		kept := &keptSetupWall{unwrapErr: errors.New("wall docker: rm: exit status 1")}
		sp := walledSpec(t, kept)
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(filepath.Join(registry(t), r.ID())) })
		got := r.RemoveSetup(ctx)
		if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
			t.Fatal(err)
		}
		check(t, &kept.setupWall, r, got, "Close the run: the agent's container of session 1 could not be removed and may still run, so the setup container stays until the close.")
		if !errors.Is(got, wall.ErrContainerKept) {
			t.Errorf("the error %v does not match wall.ErrContainerKept", got)
		}
		if !r.ContainerKept() {
			t.Error("ContainerKept is false after the agent's container could not be removed")
		}
	})
	t.Run("a host step is open after a session", func(t *testing.T) {
		w, sp, r := opens(t)
		if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
			t.Fatal(err)
		}
		step, err := r.StartStep(event.StepPush, "push work to github.com/example-org/app")
		if err != nil {
			t.Fatal(err)
		}
		got := r.RemoveSetup(ctx)
		if err := step.Exit(event.StateSucceeded, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
			t.Fatal(err)
		}
		check(t, w, r, got, "Exit step 5 before you remove the setup container: one host step is open at a time.")
	})
	t.Run("a copy step is open after a session", func(t *testing.T) {
		w, sp, r := opens(t)
		if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
			t.Fatal(err)
		}
		step, err := r.StartStep(event.StepCopy, "copy work out")
		if err != nil {
			t.Fatal(err)
		}
		got := r.RemoveSetup(ctx)
		if err := step.Exit(event.StateSucceeded, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
			t.Fatal(err)
		}
		check(t, w, r, got, "Exit step 5 before you remove the setup container: one host step is open at a time.")
	})
	t.Run("a host step is open", func(t *testing.T) {
		w, _, r := opens(t)
		step, err := r.StartStep(event.StepFetch, "fetch github.com/example-org/app")
		if err != nil {
			t.Fatal(err)
		}
		got := r.RemoveSetup(ctx)
		if err := step.Exit(event.StateSucceeded, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
			t.Fatal(err)
		}
		check(t, w, r, got, "Exit step 3 before you remove the setup container: one host step is open at a time.")
	})
	t.Run("the run is closed", func(t *testing.T) {
		w, _, r := opens(t)
		if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
			t.Fatal(err)
		}
		check(t, w, r, r.RemoveSetup(ctx), "Remove the setup container before the close: the run is closed.")
	})
}

// keptSetupWall is a setupWall whose Unwrap fails, as an engine's that could not remove
// the agent's container.
type keptSetupWall struct {
	setupWall
	unwrapErr error
}

func (w *keptSetupWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *keptSetupWall) Unwrap(context.Context) error { return w.unwrapErr }

// TestAnEngineThatCannotBeReachedEndsTheRunsHostWork pins what the run does with the
// error the Docker wall's Unwrap returns once its engine cannot be reached, as when the
// socket goes and live-restore keeps the agent's container running: the run keeps its
// entry among the walled runs still going, a report line has the error, a later join and
// HostProxy return the join's error, and RemoveSetup leaves the setup container.
func TestAnEngineThatCannotBeReachedEndsTheRunsHostWork(t *testing.T) {
	const gone = "wall docker: docker rm --force: exit status 1: failed to connect to the docker API at unix:///var/run/docker.sock: dial unix /var/run/docker.sock: connect: no such file or directory"
	w := &keptSetupWall{unwrapErr: errors.New(gone)}
	sp := walledSpec(t, w)
	var mu sync.Mutex
	var reports []string
	sp.Report = func(l string) {
		mu.Lock()
		defer mu.Unlock()
		reports = append(reports, l)
	}
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(registry(t), r.ID())
	t.Cleanup(func() { os.Remove(entry) })
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
		t.Fatal(err)
	}
	const want = "Open a new run. The wall of session 1 could not be removed and may still run, so this run takes no more sessions."
	if _, err := r.Join(ctx, sp.SessionSpec); err == nil || err.Error() != want {
		t.Errorf("a later join: %v, want %q", err, want)
	}
	if _, err := r.HostProxy(); err == nil || err.Error() != want {
		t.Errorf("HostProxy: %v, want %q", err, want)
	}
	if err := r.RemoveSetup(ctx); err == nil {
		t.Error("RemoveSetup returned nil beside the agent's container")
	}
	if w.removes != 0 {
		t.Errorf("the wall removed %d setup containers", w.removes)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(entry); err != nil {
		t.Errorf("the run's entry after the close: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := "removing the wall: " + gone; !slices.Contains(reports, want) {
		t.Errorf("the Report lines %q have no %q", reports, want)
	}
}

// heldRemoveWall is a heldSetupWall that counts its removals in removed.
type heldRemoveWall struct {
	heldSetupWall
	removed *setupWall
}

func (w heldRemoveWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	if _, err := w.heldSetupWall.Prepare(ctx, req); err != nil {
		return nil, err
	}
	return w, nil
}

func (w heldRemoveWall) RemoveSetup(ctx context.Context) error { return w.removed.RemoveSetup(ctx) }

// TestARemovalThatFailsFailsTheRun pins a removal that fails: its step ends failed with
// -1 after the error's line, or cancelled when the context ended, the error starts with
// the fix and contains the wall's error, a later join returns an error and writes
// nothing, and a second call tries the removal again.
func TestARemovalThatFailsFailsTheRun(t *testing.T) {
	const failure = "wall docker: docker rm --force: exit status 1: Error response from daemon: told to fail"
	want := "Close the run: the setup container may still run, so no session can join: " + failure
	for _, c := range []struct {
		name, state string
		cancel      bool
	}{{"failed", event.StateFailed, false}, {"cancelled", event.StateCancelled, true}} {
		t.Run(c.name, func(t *testing.T) {
			sp := spec(t, "FAKE_EXIT=0")
			w := &setupWall{removeErr: errors.New(failure)}
			sp.Wall, sp.Image = w, "example.com/agent:1"
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
				t.Fatal(err)
			}
			removing, cancel := context.WithCancel(ctx)
			defer cancel()
			if c.cancel {
				cancel()
			}
			if err := r.RemoveSetup(removing); err == nil || err.Error() != want {
				t.Errorf("got %v\nwant %s", err, want)
			}
			_, err = r.Join(ctx, sp.SessionSpec)
			if want := "Open another run: setup step 3 of this run failed, so no session can join it."; err == nil || err.Error() != want {
				t.Errorf("the join: %v, want %q", err, want)
			}
			if err := r.RemoveSetup(ctx); err == nil || err.Error() != want {
				t.Errorf("the second call: %v\nwant %s", err, want)
			}
			if w.removes != 2 {
				t.Errorf("the wall tried %d removals, want 2", w.removes)
			}
			if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
				t.Fatal(err)
			}
			got := stepOrder(events(t, &session.Result{Dir: r.Dir()}))
			steps := []string{
				"step 1 wall start the setup container", "step 1 succeeded -1",
				"step 2 setup install", "log <nil> 2 out make deps", "log <nil> 2 err make deps", "step 2 succeeded 0",
				"step 3 wall remove the setup container", "log <nil> 3 " + want, "step 3 " + c.state + " -1",
				"step 4 wall remove the setup container", "log <nil> 4 " + want, "step 4 failed -1",
				"run exited",
			}
			if !slices.Equal(got, steps) {
				t.Errorf("the steps:\n%q\nwant\n%q", got, steps)
			}
		})
	}
}

// TestARetryAfterAFailedRemovalLeavesTheJoinBlocked pins a removal that fails once: a
// second call that succeeds removes the setup container, and the join still returns the
// error of the first failure's step, since the caller must stop the run after it.
func TestARetryAfterAFailedRemovalLeavesTheJoinBlocked(t *testing.T) {
	sp := spec(t, "FAKE_EXIT=0")
	w := &setupWall{removeErr: errors.New("wall docker: docker rm --force: exit status 1: told to fail")}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
		t.Fatal(err)
	}
	if err := r.RemoveSetup(ctx); err == nil {
		t.Fatal("the first removal succeeded")
	}
	w.removeErr = nil
	if err := r.RemoveSetup(ctx); err != nil {
		t.Errorf("the retry: %v", err)
	}
	if err := r.RemoveSetup(ctx); err != nil {
		t.Errorf("the third call: %v", err)
	}
	_, err = r.Join(ctx, sp.SessionSpec)
	if want := "Open another run: setup step 3 of this run failed, so no session can join it."; err == nil || err.Error() != want {
		t.Errorf("the join: %v, want %q", err, want)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	if w.removes != 2 {
		t.Errorf("the wall tried %d removals, want 2", w.removes)
	}
	got := stepOrder(events(t, &session.Result{Dir: r.Dir()}))
	want := []string{
		"step 3 wall remove the setup container", "log <nil> 3 Close the run: the setup container may still run, so no session can join: wall docker: docker rm --force: exit status 1: told to fail", "step 3 failed -1",
		"step 4 wall remove the setup container", "step 4 succeeded -1",
		"run exited",
	}
	if len(got) < len(want) || !slices.Equal(got[len(got)-len(want):], want) {
		t.Errorf("the steps:\n%q\nwant them to end with\n%q", got, want)
	}
}

// TestRemoveSetupAfterAFailedSetupRemovesItAndNoSessionJoins pins RemoveSetup after a
// setup command that failed: the setup container runs, so the call removes it, and the
// setup's failure stays, so the join still returns an error.
func TestRemoveSetupAfterAFailedSetupRemovesItAndNoSessionJoins(t *testing.T) {
	sp := spec(t, "FAKE_EXIT=0")
	w := &setupWall{codes: map[string]int{"make": 2}}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands}); err == nil {
		t.Fatal("the setup succeeded")
	}
	if err := r.RemoveSetup(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = r.Join(ctx, sp.SessionSpec)
	if want := "Open another run: setup step 2 of this run failed, so no session can join it."; err == nil || err.Error() != want {
		t.Errorf("the join: %v, want %q", err, want)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	if w.removes != 1 {
		t.Errorf("the wall removed %d setup containers, want 1", w.removes)
	}
}

// TestTheRunsEntryListsTheSetupFolderAfterTheRemoval pins what RemoveSetup leaves in the
// run's entry among the walled runs still going: the setup folder stays listed through a
// session, because what the setup container wrote there stays.
func TestTheRunsEntryListsTheSetupFolderAfterTheRemoval(t *testing.T) {
	w := heldSetupWall{newHoldingWall()}
	sp := walledSpec(t, w)
	other := t.TempDir()
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: other, Commands: twoCommands}); err != nil {
		t.Fatal(err)
	}
	if err := r.RemoveSetup(ctx); err != nil {
		t.Fatal(err)
	}
	lists := func(when string) {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(registry(t), w.id))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), other) {
			t.Errorf("%s, the run's entry does not list the setup folder %s:\n%s", when, other, b)
		}
	}
	lists("after RemoveSetup")
	done := make(chan error, 1)
	go func() {
		_, err := r.Join(ctx, sp.SessionSpec)
		done <- err
	}()
	<-w.reached
	lists("during the session")
	close(w.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	lists("after the session")
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
}

// TestASetupVariableTheAgentCannotGetIsRefused pins the two ways a setup variable
// could reach the setup container while the agent gets no such value, each refused
// before any step and before the setup container starts. A value for TOOL_TOKEN, a
// placeholder of a separate gateway's run answer, is placeholder_conflict, from
// AgentEnv for --env and from Setup. LD_PRELOAD from wall.env is left out by AgentEnv,
// as by the join, and refused by Setup. A QORY_ name other than QORY_RUN_SYSTEM and
// QORY_RUN_REPOSITORIES, in any case, is variable_reserved, QORY_RUN_ID and
// QORY_RUN_SOCKET among them, and so is a name the machine's credentials are read from. Each text starts
// with the fix.
func TestASetupVariableTheAgentCannotGetIsRefused(t *testing.T) {
	ctx := context.Background()
	setupRefused := func(t *testing.T, r *session.Run, w *setupWall, env []string) error {
		t.Helper()
		steps := len(ofType(events(t, &session.Result{Dir: r.Dir()}), event.StepStarted))
		err := r.Setup(ctx, session.SetupSpec{Dir: w.got.Dir, Env: env, Commands: twoCommands})
		if got := len(ofType(events(t, &session.Result{Dir: r.Dir()}), event.StepStarted)); got != steps {
			t.Errorf("the setup wrote %d steps", got-steps)
		}
		if w.starts != 0 {
			t.Errorf("the setup container started %d times", w.starts)
		}
		return err
	}
	t.Run("a placeholder of a separate gateway", func(t *testing.T) {
		sp, g, _ := remoteSpec(t, 0)
		g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
			a := linktest.RunAnswer(req)
			a["placeholders"] = []string{"TOOL_TOKEN"}
			return linktest.Reply{Status: 200, Body: a}
		})
		w := &setupWall{}
		sp.Wall, sp.Image = w, "example.com/agent:1"
		sp.Variables.Run = []string{"TOOL_TOKEN=a-value-not-in-errors"}
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
		_, err = r.AgentEnv(sp.SessionSpec)
		var ref *session.Refusal
		if !errors.As(err, &ref) || ref.Code != "placeholder_conflict" || !slices.Equal(ref.Names, []string{"TOOL_TOKEN"}) {
			t.Errorf("AgentEnv: %v, want placeholder_conflict TOOL_TOKEN", err)
		}
		w.got.Dir = sp.Dir
		err = setupRefused(t, r, w, []string{"APP_ENV=test", "TOOL_TOKEN=a-value-not-in-errors"})
		if !errors.As(err, &ref) || ref.Code != "placeholder_conflict" || !slices.Equal(ref.Names, []string{"TOOL_TOKEN"}) {
			t.Errorf("Setup: %v, want placeholder_conflict TOOL_TOKEN", err)
		}
		if want := "Leave TOOL_TOKEN out of the setup's variables: the run's placeholder takes its place."; err == nil || err.Error() != want {
			t.Errorf("Setup: %v\nwant %s", err, want)
		}
	})
	t.Run("LD_PRELOAD from wall.env", func(t *testing.T) {
		sp := spec(t)
		w := &setupWall{}
		sp.Wall, sp.Image = w, "example.com/agent:1"
		sp.Variables.Machine = []string{"LD_PRELOAD=/lib/inject.so", "APP_ENV=test"}
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
		env, err := r.AgentEnv(sp.SessionSpec)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(env, "APP_ENV=test") || slices.ContainsFunc(env, func(kv string) bool { return strings.HasPrefix(kv, "LD_PRELOAD=") }) {
			t.Errorf("AgentEnv %q, want APP_ENV and no LD_PRELOAD", env)
		}
		w.got.Dir = sp.Dir
		err = setupRefused(t, r, w, append(env, "LD_PRELOAD=/lib/inject.so"))
		want := "Leave LD_PRELOAD out of the setup's variables: denied-variables.json lists it."
		if err == nil || err.Error() != want {
			t.Errorf("Setup: %v\nwant %s", err, want)
		}
	})
	for _, name := range []string{"ANTHROPIC_API_KEY", "GH_TOKEN"} {
		t.Run(name+" from wall.env", func(t *testing.T) {
			sp := spec(t)
			w := &setupWall{}
			sp.Wall, sp.Image = w, "example.com/agent:1"
			sp.Variables.Machine = []string{name + "=fake-credential-value", "APP_ENV=test"}
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
			env, err := r.AgentEnv(sp.SessionSpec)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(env, "APP_ENV=test") || slices.ContainsFunc(env, func(kv string) bool { return strings.HasPrefix(kv, name+"=") }) {
				t.Errorf("AgentEnv %q, want APP_ENV and no %s", env, name)
			}
			w.got.Dir = sp.Dir
			err = setupRefused(t, r, w, append(env, strings.ToLower(name)+"=fake-credential-value"))
			want := "Move " + strings.ToLower(name) + " to the gateway's credentials in forager.yaml: denied-variables.json lists it as a forge token or a model key, which the setup's variables may not pass into the wall."
			if err == nil || err.Error() != want {
				t.Errorf("Setup: %v\nwant %s", err, want)
			}
			if strings.Contains(fmt.Sprint(err), "fake-credential-value") {
				t.Errorf("Setup: %v has the value", err)
			}
		})
	}
	t.Run("a QORY_ name", func(t *testing.T) {
		sp := spec(t)
		w := &setupWall{}
		sp.Wall, sp.Image = w, "example.com/agent:1"
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
		w.got.Dir = sp.Dir
		env := []string{"QORY_RUN_SYSTEM=tickets", "QORY_RUN_REPOSITORIES=a b", "QORY_RUN_KEY=forged", "QORY_RUN_ID=forged", "QORY_RUN_SOCKET=forged"}
		err = setupRefused(t, r, w, env)
		var ref *session.Refusal
		if !errors.As(err, &ref) || ref.Code != "variable_reserved" || !slices.Equal(ref.Names, []string{"QORY_RUN_ID", "QORY_RUN_KEY", "QORY_RUN_SOCKET"}) {
			t.Errorf("Setup: %v, want variable_reserved QORY_RUN_ID, QORY_RUN_KEY and QORY_RUN_SOCKET", err)
		}
		want := "Leave these out of the setup's variables, the QORY_ names are Forager's: QORY_RUN_ID, QORY_RUN_KEY and QORY_RUN_SOCKET."
		if err == nil || err.Error() != want {
			t.Errorf("Setup: %v\nwant %s", err, want)
		}
		err = setupRefused(t, r, w, []string{"qory_run_key=forged"})
		if !errors.As(err, &ref) || ref.Code != "variable_reserved" || !slices.Equal(ref.Names, []string{"qory_run_key"}) {
			t.Errorf("Setup: %v, want variable_reserved qory_run_key", err)
		}
		if want := "Leave qory_run_key out of the setup's variables: the QORY_ names are Forager's."; err == nil || err.Error() != want {
			t.Errorf("Setup: %v\nwant %s", err, want)
		}
	})
	t.Run("a name the machine's credentials are read from", func(t *testing.T) {
		sp, g := specGateway(t)
		g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
			a := linktest.RunAnswer(req)
			a["reserved"] = []string{"MACHINE_TOKEN"}
			return linktest.Reply{Status: 200, Body: a}
		})
		w := &setupWall{}
		sp.Wall, sp.Image = w, "example.com/agent:1"
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
		w.got.Dir = sp.Dir
		err = setupRefused(t, r, w, []string{"APP_ENV=test", "MACHINE_TOKEN=fake-machine-value"})
		var ref *session.Refusal
		if !errors.As(err, &ref) || ref.Code != "variable_reserved" || !slices.Equal(ref.Names, []string{"MACHINE_TOKEN"}) {
			t.Errorf("Setup: %v, want variable_reserved MACHINE_TOKEN", err)
		}
		want := "Leave MACHINE_TOKEN out of the setup's variables: the machine's credentials are read from it."
		if err == nil || err.Error() != want || strings.Contains(err.Error(), "fake-machine-value") {
			t.Errorf("Setup: %v\nwant %s", err, want)
		}
	})
}
