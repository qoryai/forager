package session_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// The tests of this file pin (*session.Run).Setup: the run's setup commands in the
// setup container, a container of the run's image apart from the agent's.

// setupWall is a targetWall whose enclosure starts a setup container, as the Docker
// adapter's does: StartSetup notes its launch, and ExecSetup notes each command, writes
// out <words> to stdout and err <words> to stderr, and exits with the code codes gives
// the command's first word, 0 for none. startErr and execErr, when set, are the
// errors of StartSetup and ExecSetup.
type setupWall struct {
	targetWall
	mu       sync.Mutex
	setup    wall.Launch
	starts   int
	execs    [][]string
	codes    map[string]int
	startErr error
	execErr  error
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
// folder as its one mount, the run's forwarder and proxy secret, the caller's variables
// without the reserved ones and no proxy variable, and the agent's container reaches
// the same forwarder.
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
	env := []string{"APP_ENV=test", "QORY_ACCESS_KEY_SECRET=forged", "QORY_RUN_KEY=forged"}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Env: env, Commands: twoCommands}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
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
	if !slices.Contains(w.setup.Env, "APP_ENV=test") || strings.Contains(setupEnv, "forged") || strings.Contains(setupEnv, "PROXY") {
		t.Errorf("the setup container's variables:\n%s", setupEnv)
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
			s.Env = []string{"APP_PROXY=" + h.ProxyURL}
			return s
		}, "Leave the host proxy's URL out of the setup's variables: APP_PROXY contains its password, which the setup container never gets."},
		{"a closed run", nil, func(t *testing.T, sp runSpec, r *session.Run) session.SetupSpec {
			if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
				t.Fatal(err)
			}
			return setup(sp)
		}, "Open another run to run its setup: the run is closed."},
		{"a wall without a setup container", func() wall.Wall { return &openWall{} }, func(_ *testing.T, sp runSpec, _ *session.Run) session.SetupSpec {
			return setup(sp)
		}, "Run the setup behind the Docker wall: the open wall starts no setup container."},
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
// join's checks of its places: a folder that holds the run directories is refused with
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
