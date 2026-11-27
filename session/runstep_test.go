package session_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// stepWall is a setupWall whose enclosure runs step containers: WrapStep notes its
// launch and returns wrapErr, or a launch that runs the step's command on this machine
// through [fakeStep], until the command ends or UnwrapStep creates the step's stop file,
// which kills its process group.
// UnwrapStep returns exit and unwrapErr, Kept returns kept, and Unwrap removes nothing.
type stepWall struct {
	setupWall
	dir       string
	steps     []wall.Launch
	stops     []string
	unwraps   int
	exit      wall.StepExit
	unwrapErr error
	wrapErr   error
	kept      []wall.KeptContainer
	// hold, when set, keeps UnwrapStep from returning until it is closed.
	hold chan struct{}
}

func newStepWall(t *testing.T) *stepWall { return &stepWall{dir: t.TempDir()} }

func (w *stepWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	return w, nil
}

// Unwrap removes the agent's container, as the Docker wall's does, so it does not stay
// after the session.
func (w *stepWall) Unwrap(context.Context) error { return nil }

// fakeStep is the test binary's mode fake-step, the step container of stepWall: it
// runs command in a new process group, as a container's processes share one, kills the
// group with SIGTERM once the file stop exists, and exits with the command's exit
// status, or 128+N after signal N. The group's kill also ends a process that a shell of
// the command started, such as sleep under a /bin/sh -c that does not exec its last
// command, as dash does, which would keep the output's pipe open until it exits.
func fakeStep(stop string, command []string) int {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 127
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for killed := false; ; {
		select {
		case <-done:
			if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				return 128 + int(ws.Signal())
			}
			return cmd.ProcessState.ExitCode()
		case <-tick.C:
			if _, err := os.Stat(stop); err == nil && !killed {
				syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
				killed = true
			}
		}
	}
}

func (w *stepWall) WrapStep(_ context.Context, l wall.Launch) (wall.Launch, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	stop := filepath.Join(w.dir, fmt.Sprint("stop-", len(w.steps)))
	w.steps, w.stops = append(w.steps, l), append(w.stops, stop)
	if w.wrapErr != nil {
		return wall.Launch{}, w.wrapErr
	}
	exe, err := os.Executable()
	if err != nil {
		return wall.Launch{}, err
	}
	return wall.Launch{Command: exe, Args: append([]string{"fake-step", stop, l.Command}, l.Args...)}, nil
}

func (w *stepWall) UnwrapStep(context.Context, time.Duration) (wall.StepExit, error) {
	if w.hold != nil {
		<-w.hold
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.unwraps++
	os.WriteFile(w.stops[len(w.stops)-1], nil, 0o600)
	return w.exit, w.unwrapErr
}

func (w *stepWall) Kept() []wall.KeptContainer {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.kept
}

// started is the number of step containers WrapStep made.
func (w *stepWall) started() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.steps)
}

// openStepRun opens a walled run with w, with a run API, and closes it at the end.
func openStepRun(t *testing.T, w wall.Wall, masked ...string) (runSpec, *session.Run) {
	t.Helper()
	sp, g := specGateway(t, "FAKE_EXIT=0")
	hasRunAPI(g)
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.RunID = event.NewRunID()
	if len(masked) > 0 {
		sp.Masker = maskerOf(t, masked...)
	}
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(ctx, session.Outcome{State: event.StateSucceeded}) })
	return sp, r
}

// stepExited is the data of the dev.qory.run.step_exited of step n in the run's record.
func stepExited(t *testing.T, r *session.Run, n int) map[string]any {
	t.Helper()
	for _, e := range ofType(events(t, &session.Result{Dir: r.Dir()}), event.StepExited) {
		if d := data(e); d["step"] == float64(n) {
			return d
		}
	}
	t.Fatalf("no step_exited of step %d", n)
	return nil
}

// TestRunStepRunsTheCommandInAStepContainer pins a step: one step of kind container with
// the caller's name as it is, the command's output as its lines and in Output, and its
// exit status; the step container's launch has the step's command, the working folder as
// its one mount, the relay's token and no variable at all, so no run secret and no
// QORY_RUN_API.
func TestRunStepRunsTheCommandInAStepContainer(t *testing.T) {
	w := newStepWall(t)
	w.exit = wall.StepExit{Started: true}
	sp, r := openStepRun(t, w)
	res, err := r.RunStep(context.Background(), session.StepSpec{Name: "step first/ac-1-x", Command: []string{"/bin/sh", "-c", "echo out; echo err >&2"}, Dir: sp.Dir})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || res.Signal != 0 || res.TimedOut || res.OOMKilled || res.OutputCut || res.Step != 1 || res.Ended.Before(res.Started) {
		t.Errorf("the result %+v", res)
	}
	if out := string(res.Output); !strings.Contains(out, "out\n") || !strings.Contains(out, "err\n") {
		t.Errorf("Output %q", out)
	}
	l := w.steps[0]
	if l.Command != "/bin/sh" || !slices.Equal(l.Args, []string{"-c", "echo out; echo err >&2"}) || l.Dir != "/workspace" || !slices.Equal(l.Mounts, []wall.Mount{{Path: sp.Dir, Target: "/workspace"}}) {
		t.Errorf("the step container's launch %+v", l)
	}
	if len(l.Env) != 0 || l.ProxyToken == "" {
		t.Errorf("the step container's variables %q, token %q", l.Env, l.ProxyToken)
	}
	got := stepOrder(events(t, &session.Result{Dir: r.Dir()}))
	want := []string{"step 1 container step first/ac-1-x", "step 1 succeeded 0"}
	if len(got) < 2 || got[0] != want[0] || got[len(got)-1] != want[1] || !slices.Contains(got, "log <nil> 1 out") || !slices.Contains(got, "log <nil> 1 err") {
		t.Errorf("the record:\n%q", got)
	}
}

// TestRunStepEndsAsTheContainerEnded pins the end of a step from the step container's
// exit: an exit status otherwise than 0 is failed, out of memory is failed with reason
// out_of_memory, a time limit that passes is cancelled with reason timeout, and 128+N is
// signal N; none of them is an error of RunStep.
func TestRunStepEndsAsTheContainerEnded(t *testing.T) {
	for _, c := range []struct {
		name    string
		command string
		timeout time.Duration
		exit    wall.StepExit
		state   string
		reason  any
		signal  int
	}{
		{"exit 3", "exit 3", 0, wall.StepExit{Started: true, ExitCode: 3}, event.StateFailed, nil, 0},
		// The init of the Docker wall's step container exits 127 for a program the image
		// does not have.
		{"a program the image lacks", "exit 127", 0, wall.StepExit{Started: true, ExitCode: 127}, event.StateFailed, nil, 0},
		{"out of memory", "true", 0, wall.StepExit{Started: true, ExitCode: 137, OOMKilled: true}, event.StateFailed, "out_of_memory", 9},
		{"time limit", "sleep 30", 200 * time.Millisecond, wall.StepExit{Started: true, ExitCode: 143}, event.StateCancelled, "timeout", 15},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newStepWall(t)
			w.exit = c.exit
			sp, r := openStepRun(t, w)
			begin := time.Now()
			res, err := r.RunStep(context.Background(), session.StepSpec{Name: c.name, Command: []string{"/bin/sh", "-c", c.command}, Dir: sp.Dir, Timeout: c.timeout})
			if err != nil {
				t.Fatal(err)
			}
			if time.Since(begin) > 10*time.Second {
				t.Errorf("the step took %s", time.Since(begin))
			}
			if res.ExitCode != c.exit.ExitCode || res.OOMKilled != c.exit.OOMKilled || res.TimedOut != (c.timeout > 0) || res.Signal != c.signal {
				t.Errorf("the result %+v", res)
			}
			d := stepExited(t, r, 1)
			if d["state"] != c.state || d["exit_code"] != float64(c.exit.ExitCode) || d["reason"] != c.reason {
				t.Errorf("step_exited %v", d)
			}
		})
	}
}

// TestAStepContainerThatDidNotStart pins a step container in which the engine started
// nothing, as without an init when the image lacks the program: RunStep returns the fix
// and the wall command's exit, the step ends failed with -1, and the engine's message
// is in the step's lines and in Output.
func TestAStepContainerThatDidNotStart(t *testing.T) {
	w := newStepWall(t)
	w.exit = wall.StepExit{ExitCode: 127}
	sp, r := openStepRun(t, w)
	res, err := r.RunStep(context.Background(), session.StepSpec{Name: "x", Command: []string{"/bin/sh", "-c", "echo engine: no such file >&2; exit 1"}, Dir: sp.Dir})
	if err == nil || !strings.HasPrefix(err.Error(), "Check the step's command and the run's image: the step container did not start.\n") || !strings.HasSuffix(err.Error(), ": exit status 1") {
		t.Fatalf("RunStep: %v", err)
	}
	if res == nil || res.ExitCode != -1 || !strings.Contains(string(res.Output), "engine: no such file") {
		t.Errorf("the result %+v", res)
	}
	if d := stepExited(t, r, 1); d["state"] != event.StateFailed || d["exit_code"] != float64(-1) {
		t.Errorf("step_exited %v", d)
	}
	if got := stepOrder(events(t, &session.Result{Dir: r.Dir()})); !slices.Contains(got, "log <nil> 1 engine: no such file") {
		t.Errorf("the record:\n%q", got)
	}
}

// TestRunStepMasksAndCutsTheOutput pins Output: the run's secrets replaced, as in the
// step's lines, and the first 1 MiB of a longer output with OutputCut.
func TestRunStepMasksAndCutsTheOutput(t *testing.T) {
	const secret = "not-a-real-secret-7f3a9c"
	w := newStepWall(t)
	w.exit = wall.StepExit{Started: true}
	sp, r := openStepRun(t, w, secret)
	res, err := r.RunStep(context.Background(), session.StepSpec{Name: "print", Command: []string{"/bin/sh", "-c", "echo " + secret}, Dir: sp.Dir})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Output), secret) || len(res.Output) == 0 {
		t.Errorf("Output %q", res.Output)
	}
	for _, l := range stepOrder(events(t, &session.Result{Dir: r.Dir()})) {
		if strings.Contains(l, secret) {
			t.Errorf("the record has %q", l)
		}
	}
	res, err = r.RunStep(context.Background(), session.StepSpec{Name: "long", Command: []string{"/bin/sh", "-c", "head -c 1100000 /dev/zero | tr '\\0' a"}, Dir: sp.Dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Output) != 1<<20 || !res.OutputCut {
		t.Errorf("Output has %d bytes, cut %v", len(res.Output), res.OutputCut)
	}
}

// TestStepsEndTheirWindowAtTheJoin pins the window of step containers: steps one after
// another start the relay again never; the first join after them starts it once, with a
// new token that the agent's launch and the next step's launch get; a second join does
// not; a step after the join opens a new window, which the next join ends.
func TestStepsEndTheirWindowAtTheJoin(t *testing.T) {
	w := newStepWall(t)
	w.exit = wall.StepExit{Started: true}
	sp, r := openStepRun(t, w)
	ctx := context.Background()
	step := func() {
		t.Helper()
		if _, err := r.RunStep(ctx, session.StepSpec{Name: "check", Command: []string{"true"}, Dir: sp.Dir}); err != nil {
			t.Fatal(err)
		}
	}
	join := func() {
		t.Helper()
		if res, err := r.Join(ctx, sp.SessionSpec); err != nil || res.ExitCode != 0 {
			t.Fatalf("the join: %v, %+v", err, res)
		}
	}
	step()
	step()
	if len(w.restarts) != 0 {
		t.Fatalf("the relay started again %d times between steps", len(w.restarts))
	}
	join()
	join()
	if len(w.restarts) != 1 || w.restarts[0] == w.steps[0].ProxyToken || w.got.ProxyToken != w.restarts[0] {
		t.Fatalf("after one window: %d restarts", len(w.restarts))
	}
	step()
	if w.steps[2].ProxyToken != w.restarts[0] {
		t.Error("the step after the join did not get the relay's new token")
	}
	join()
	if len(w.restarts) != 2 || w.restarts[1] == w.restarts[0] {
		t.Errorf("after two windows: %d restarts", len(w.restarts))
	}
}

// TestASetupAfterAStep pins that a setup without Unprivileged after a step starts the
// relay again before the setup container, which gets the new token.
func TestASetupAfterAStep(t *testing.T) {
	w := newStepWall(t)
	w.exit = wall.StepExit{Started: true}
	sp, r := openStepRun(t, w)
	ctx := context.Background()
	if _, err := r.RunStep(ctx, session.StepSpec{Name: "check", Command: []string{"true"}, Dir: sp.Dir}); err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands}); err != nil {
		t.Fatal(err)
	}
	if len(w.restarts) != 1 || w.setup.ProxyToken != w.restarts[0] {
		t.Errorf("%d restarts; the setup container's token is the new one %v", len(w.restarts), len(w.restarts) > 0 && w.setup.ProxyToken == w.restarts[0])
	}
}

// TestAFailedRestartRefusesTheSetup pins a setup without Unprivileged after a step whose
// restart of the relay fails: Setup returns the fix for a setup, starts no container and
// writes no step, and the setup runs once the restart succeeds.
func TestAFailedRestartRefusesTheSetup(t *testing.T) {
	w := newStepWall(t)
	w.exit = wall.StepExit{Started: true}
	sp, r := openStepRun(t, w)
	ctx := context.Background()
	if _, err := r.RunStep(ctx, session.StepSpec{Name: "check", Command: []string{"true"}, Dir: sp.Dir}); err != nil {
		t.Fatal(err)
	}
	steps := len(stepOrder(events(t, &session.Result{Dir: r.Dir()})))
	w.mu.Lock()
	w.restartErr = errors.New("docker start: told to fail")
	w.mu.Unlock()
	err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands})
	if err == nil || !strings.HasPrefix(err.Error(), "Run the setup again, or close the run: the relay did not start again after the steps.\n") || w.starts != 0 {
		t.Fatalf("a setup whose restart fails: %v, %d starts", err, w.starts)
	}
	if n := len(stepOrder(events(t, &session.Result{Dir: r.Dir()}))); n != steps {
		t.Errorf("the refused setup wrote %d lines of the record", n-steps)
	}
	w.mu.Lock()
	w.restartErr = nil
	w.mu.Unlock()
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands}); err != nil || w.starts != 1 || len(w.restarts) != 2 {
		t.Fatalf("the setup again: %v, %d starts, %d restarts", err, w.starts, len(w.restarts))
	}
}

// TestAStepBesideTheSetupContainer pins that a step runs beside a setup container that
// started with Unprivileged and is refused beside one that started without.
func TestAStepBesideTheSetupContainer(t *testing.T) {
	ctx := context.Background()
	for _, unprivileged := range []bool{true, false} {
		t.Run(fmt.Sprint("Unprivileged ", unprivileged), func(t *testing.T) {
			w := newStepWall(t)
			w.exit = wall.StepExit{Started: true}
			sp, r := openStepRun(t, w)
			if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands, Unprivileged: unprivileged}); err != nil {
				t.Fatal(err)
			}
			_, err := r.RunStep(ctx, session.StepSpec{Name: "check", Command: []string{"true"}, Dir: sp.Dir})
			switch {
			case unprivileged && err != nil:
				t.Errorf("a step beside the unprivileged setup container: %v", err)
			case !unprivileged && (err == nil || err.Error() != "Start the setup with Unprivileged to run steps: the setup container gets credentials."):
				t.Errorf("a step beside the setup container: %v", err)
			}
		})
	}
}

// TestRunStepRefuses pins the refusals before a step, which write nothing.
func TestRunStepRefuses(t *testing.T) {
	ctx := context.Background()
	w := newStepWall(t)
	sp, r := openStepRun(t, w)
	for _, c := range []struct {
		spec session.StepSpec
		want string
	}{
		{session.StepSpec{Command: []string{"true"}}, "Give the step a name"},
		{session.StepSpec{Name: "x"}, "Give the step a command"},
		{session.StepSpec{Name: "x", Command: []string{"true"}, Timeout: -time.Second}, "Give the step a time limit of 0 or more"},
		{session.StepSpec{Name: "x", Command: []string{"true"}, Image: "example.com/other:1"}, "Leave Image empty: a step runs in the run's image"},
	} {
		c.spec.Dir = sp.Dir
		if _, err := r.RunStep(ctx, c.spec); err == nil || !strings.HasPrefix(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.spec, err, c.want)
		}
	}
	if w.started() != 0 {
		t.Errorf("a refused step made %d step containers", w.started())
	}
	sp, r = openStepRun(t, &setupWall{})
	if _, err := r.RunStep(ctx, session.StepSpec{Name: "x", Command: []string{"true"}, Dir: sp.Dir}); err == nil || !strings.HasPrefix(err.Error(), "Run the step behind the Docker wall") {
		t.Errorf("a wall with no step containers: %v", err)
	}
}

// TestAStepContainerKeptStopsTheRun pins a step container whose removal failed: the step
// fails with the container's name and the command to remove it, ContainerKept is true,
// and a later step, which starts no container, a join and a setup are refused with the
// same text; SetRunAPICheck is refused after a step.
func TestAStepContainerKeptStopsTheRun(t *testing.T) {
	// A container that stays leaves the run's entry among the walled runs still going.
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	ctx := context.Background()
	w := newStepWall(t)
	w.exit = wall.StepExit{Started: true}
	w.unwrapErr = wall.ContainerKeptError(errors.New("docker rm: told to fail"))
	w.kept = []wall.KeptContainer{{Name: "qory-run-step", Remove: "engine rm qory-run-step"}}
	sp, r := openStepRun(t, w)
	const want = "Remove the kept container, then close the run: Forager could not remove it, and it may still run.\n" +
		`The kept container is qory-run-step; remove it with "engine rm qory-run-step".`
	_, err := r.RunStep(ctx, session.StepSpec{Name: "x", Command: []string{"true"}, Dir: sp.Dir})
	if err == nil || err.Error() != want || !errors.Is(err, wall.ErrContainerKept) || !r.ContainerKept() {
		t.Fatalf("the step: %v, kept %v", err, r.ContainerKept())
	}
	if d := stepExited(t, r, 1); d["state"] != event.StateFailed || d["exit_code"] != float64(-1) {
		t.Errorf("step_exited %v", d)
	}
	steps := len(stepOrder(events(t, &session.Result{Dir: r.Dir()})))
	if _, err := r.RunStep(ctx, session.StepSpec{Name: "x", Command: []string{"true"}, Dir: sp.Dir}); err == nil || err.Error() != want || !errors.Is(err, wall.ErrContainerKept) || w.started() != 1 {
		t.Errorf("the next step: %v, %d step containers", err, w.started())
	}
	if _, err := r.Join(ctx, sp.SessionSpec); err == nil || err.Error() != want || !errors.Is(err, wall.ErrContainerKept) {
		t.Errorf("the join: %v", err)
	}
	for _, unprivileged := range []bool{false, true} {
		err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands, Unprivileged: unprivileged})
		if err == nil || err.Error() != want || !errors.Is(err, wall.ErrContainerKept) || w.starts != 0 || len(w.restarts) != 0 {
			t.Errorf("the setup, Unprivileged %v: %v, %d starts, %d restarts", unprivileged, err, w.starts, len(w.restarts))
		}
	}
	if n := len(stepOrder(events(t, &session.Result{Dir: r.Dir()}))); n != steps {
		t.Errorf("the refusals wrote %d lines of the record", n-steps)
	}
	check := func(context.Context, session.RunAPIRequest) (*session.RunAPIRefusal, error) { return nil, nil }
	if err := r.SetRunAPICheck(check); err == nil || err.Error() != "Call SetRunAPICheck before the first step: a step container ran." {
		t.Errorf("SetRunAPICheck after a step: %v", err)
	}
}

// TestCloseStopsAStep pins Close during a step: it stops the step container, waits for
// RunStep, which returns the result, cancelled, and the close's cause, and closes the
// run.
func TestCloseStopsAStep(t *testing.T) {
	ctx := context.Background()
	w := newStepWall(t)
	w.exit = wall.StepExit{Started: true, ExitCode: 143}
	sp, r := openStepRun(t, w)
	type result struct {
		res *session.StepResult
		err error
	}
	got := make(chan result, 1)
	go func() {
		res, err := r.RunStep(ctx, session.StepSpec{Name: "long", Command: []string{"sleep", "30"}, Dir: sp.Dir})
		got <- result{res, err}
	}()
	for deadline := time.Now().Add(10 * time.Second); w.started() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the step container did not start")
		}
	}
	begin := time.Now()
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
	if time.Since(begin) > 10*time.Second {
		t.Errorf("Close took %s", time.Since(begin))
	}
	g := <-got
	if g.err == nil || g.res == nil || g.res.Signal != 15 {
		t.Fatalf("RunStep: %+v, %v", g.res, g.err)
	}
	if d := stepExited(t, r, 1); d["state"] != event.StateCancelled {
		t.Errorf("step_exited %v", d)
	}
}

// startLongStep runs a step of sleep 30 in r in the background, waits until its step
// container started, and returns the channel of RunStep's error.
func startLongStep(t *testing.T, w *stepWall, r *session.Run, dir string) <-chan error {
	t.Helper()
	got := make(chan error, 1)
	go func() {
		_, err := r.RunStep(context.Background(), session.StepSpec{Name: "long", Command: []string{"sleep", "30"}, Dir: dir})
		got <- err
	}()
	for deadline := time.Now().Add(10 * time.Second); w.started() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the step container did not start")
		}
	}
	return got
}

// TestCloseChecksTheOutcomeFirst pins Close during a step with an outcome it refuses: it
// returns the refusal and leaves the step running, and a Close with a valid outcome
// then stops the step and closes the run.
func TestCloseChecksTheOutcomeFirst(t *testing.T) {
	ctx := context.Background()
	w := newStepWall(t)
	w.exit = wall.StepExit{Started: true, ExitCode: 143}
	sp, r := openStepRun(t, w)
	got := startLongStep(t, w, r, sp.Dir)
	if _, err := r.Close(ctx, session.Outcome{State: "finished"}); err == nil || !strings.Contains(err.Error(), "is none of succeeded") {
		t.Fatalf("Close with a refused outcome: %v", err)
	}
	select {
	case err := <-got:
		t.Fatalf("the refused Close stopped the step: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
	if err := <-got; err == nil {
		t.Error("RunStep returned no error after Close stopped it")
	}
}

// TestCloseWaitsForAStepUntilItsContextEnds pins Close during a step whose RunStep does
// not return in time: Close returns the fix once its context ends and the run stays open;
// once RunStep returned, Close closes the run.
func TestCloseWaitsForAStepUntilItsContextEnds(t *testing.T) {
	w := newStepWall(t)
	w.exit = wall.StepExit{Started: true, ExitCode: 143}
	w.hold = make(chan struct{})
	sp, r := openStepRun(t, w)
	got := startLongStep(t, w, r, sp.Dir)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err == nil || !strings.HasPrefix(err.Error(), "Call Close again: the step is stopping") {
		t.Fatalf("Close past its context: %v", err)
	}
	close(w.hold)
	if err := <-got; err == nil {
		t.Error("RunStep returned no error after Close stopped it")
	}
	if _, err := r.Close(context.Background(), session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
}

// TestRunStepRefusesInTheRunsState pins the refusals of a step from the run's state,
// which start no step container and write nothing: a host step is open, the run is
// closed, a setup step failed, the run's image by reference was not fetched, and
// another call of the run is running.
func TestRunStepRefusesInTheRunsState(t *testing.T) {
	ctx := context.Background()
	step := func(r *session.Run, dir string) error {
		_, err := r.RunStep(ctx, session.StepSpec{Name: "x", Command: []string{"true"}, Dir: dir})
		return err
	}
	for _, c := range []struct {
		name   string
		before func(t *testing.T, w *stepWall, sp runSpec, r *session.Run)
		want   string
	}{
		{"a host step open", func(t *testing.T, _ *stepWall, _ runSpec, r *session.Run) {
			if _, err := r.StartStep(event.StepFetch, "fetch github.com/example-org/app"); err != nil {
				t.Fatal(err)
			}
		}, "Exit step 1 before the step: one host step is open at a time."},
		{"a closed run", func(t *testing.T, _ *stepWall, _ runSpec, r *session.Run) {
			if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
				t.Fatal(err)
			}
		}, "Open another run to run a step: the run is closed."},
		{"a failed setup", func(t *testing.T, w *stepWall, sp runSpec, r *session.Run) {
			w.codes = map[string]int{"make": 2}
			if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands, Unprivileged: true}); err == nil {
				t.Fatal("the setup did not fail")
			}
		}, "Open another run: setup step 2 of this run failed, so no step runs in it."},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newStepWall(t)
			sp, r := openStepRun(t, w)
			c.before(t, w, sp, r)
			before := len(stepOrder(events(t, &session.Result{Dir: r.Dir()})))
			if err := step(r, sp.Dir); err == nil || err.Error() != c.want || w.started() != 0 {
				t.Errorf("RunStep: %v, %d step containers; want %q", err, w.started(), c.want)
			}
			if n := len(stepOrder(events(t, &session.Result{Dir: r.Dir()}))); n != before {
				t.Errorf("the refusal wrote %d lines of the record", n-before)
			}
		})
	}
	t.Run("an image not fetched", func(t *testing.T) {
		sp, g := specGateway(t, "FAKE_EXIT=0")
		byReference(g)
		w := newStepWall(t)
		sp.Wall = w
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
		if err := step(r, sp.Dir); err == nil || err.Error() != "Call FetchImage before the step: the run's image is not on this machine yet." || w.started() != 0 {
			t.Errorf("RunStep: %v, %d step containers", err, w.started())
		}
	})
	t.Run("another call running", func(t *testing.T) {
		w := newStepWall(t)
		w.exit = wall.StepExit{Started: true, ExitCode: 143}
		sp, r := openStepRun(t, w)
		got := startLongStep(t, w, r, sp.Dir)
		if err := step(r, sp.Dir); err == nil || err.Error() != "Run the step after the run's other call returns: another call of the run is running." || w.started() != 1 {
			t.Errorf("a second RunStep: %v, %d step containers", err, w.started())
		}
		if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
			t.Fatal(err)
		}
		<-got
	})
}

// TestAStepWhoseWrapFails pins a WrapStep that fails: RunStep returns its error, the
// step ends failed with -1, and UnwrapStep removes what WrapStep may have made.
func TestAStepWhoseWrapFails(t *testing.T) {
	w := newStepWall(t)
	w.wrapErr = errors.New("wall docker: docker create: told to fail")
	sp, r := openStepRun(t, w)
	_, err := r.RunStep(context.Background(), session.StepSpec{Name: "x", Command: []string{"true"}, Dir: sp.Dir})
	if err == nil || err.Error() != w.wrapErr.Error() || w.unwraps != 1 {
		t.Fatalf("RunStep: %v, %d unwraps", err, w.unwraps)
	}
	if d := stepExited(t, r, 1); d["state"] != event.StateFailed || d["exit_code"] != float64(-1) {
		t.Errorf("step_exited %v", d)
	}
}

// TestAStepStoppedByItsContext pins a step whose ctx ends: the step container is
// stopped, RunStep returns the result with the signal and ctx's cause, and the step
// ends cancelled; the run takes the next step.
func TestAStepStoppedByItsContext(t *testing.T) {
	w := newStepWall(t)
	w.exit = wall.StepExit{Started: true, ExitCode: 143}
	sp, r := openStepRun(t, w)
	ctx, cancel := context.WithCancelCause(context.Background())
	stop := errors.New("the caller stopped the step")
	go func() {
		for w.started() == 0 {
			time.Sleep(10 * time.Millisecond)
		}
		cancel(stop)
	}()
	res, err := r.RunStep(ctx, session.StepSpec{Name: "long", Command: []string{"sleep", "30"}, Dir: sp.Dir})
	if !errors.Is(err, stop) || res == nil || res.Signal != 15 || w.unwraps != 1 {
		t.Fatalf("RunStep: %+v, %v, %d unwraps", res, err, w.unwraps)
	}
	if d := stepExited(t, r, 1); d["state"] != event.StateCancelled {
		t.Errorf("step_exited %v", d)
	}
	w.exit = wall.StepExit{Started: true}
	if _, err := r.RunStep(context.Background(), session.StepSpec{Name: "next", Command: []string{"true"}, Dir: sp.Dir}); err != nil {
		t.Errorf("the next step: %v", err)
	}
}

// TestTheHostProxiesRefuseAfterAKeptStepContainer pins HostProxy and PushProxy after a
// step container whose removal failed: both return the refusal with the container's
// name, which matches ErrContainerKept, and start no forwarder.
func TestTheHostProxiesRefuseAfterAKeptStepContainer(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	ctx := context.Background()
	sp, g := specGateway(t, "FAKE_EXIT=0")
	withPush(g, true)
	w := newStepWall(t)
	w.exit = wall.StepExit{Started: true}
	w.unwrapErr = wall.ContainerKeptError(errors.New("docker rm: told to fail"))
	w.kept = []wall.KeptContainer{{Name: "qory-run-step", Remove: "engine rm qory-run-step"}}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
	_, kept := r.RunStep(ctx, session.StepSpec{Name: "x", Command: []string{"true"}, Dir: sp.Dir})
	if !errors.Is(kept, wall.ErrContainerKept) {
		t.Fatalf("the step: %v", kept)
	}
	if _, err := r.HostProxy(); err == nil || err.Error() != kept.Error() || !errors.Is(err, wall.ErrContainerKept) {
		t.Errorf("HostProxy: %v", err)
	}
	if _, err := r.PushProxy(); err == nil || err.Error() != kept.Error() || !errors.Is(err, wall.ErrContainerKept) {
		t.Errorf("PushProxy: %v", err)
	}
}

// TestAStepWhoseWallCommandDoesNotStart pins a launch whose program does not exist on
// this machine: RunStep returns the fix with the program's name, and UnwrapStep removes
// what WrapStep made.
func TestAStepWhoseWallCommandDoesNotStart(t *testing.T) {
	w := &missingCommandWall{stepWall: newStepWall(t)}
	sp, r := openStepRun(t, w)
	_, err := r.RunStep(context.Background(), session.StepSpec{Name: "x", Command: []string{"true"}, Dir: sp.Dir})
	if err == nil || !strings.HasPrefix(err.Error(), "Check that no-such-engine-cli runs on this machine, then run the step again: the wall's command did not start (") || w.unwraps != 1 {
		t.Fatalf("RunStep: %v, %d unwraps", err, w.unwraps)
	}
}

// missingCommandWall is a stepWall whose step launch runs a program this machine does
// not have.
type missingCommandWall struct{ *stepWall }

func (w *missingCommandWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *missingCommandWall) WrapStep(ctx context.Context, l wall.Launch) (wall.Launch, error) {
	if _, err := w.stepWall.WrapStep(ctx, l); err != nil {
		return wall.Launch{}, err
	}
	return wall.Launch{Command: filepath.Join(w.dir, "no-such-engine-cli")}, nil
}

// stepPlaces makes, below the working folder dir, the places of a check bound over it,
// and returns its mounts in an order apart from the binds': dir/top.txt read-only, one
// name below; dir/checks writable; dir/checks/locked, a read-only folder; and
// dir/checks/run writable with dir/checks/run/check.sh read-only in it.
func stepPlaces(t *testing.T, dir string) []wall.Mount {
	t.Helper()
	checks := filepath.Join(dir, "checks")
	mkdirs(t, filepath.Join(checks, "locked"), filepath.Join(checks, "run"))
	for _, f := range []string{filepath.Join(dir, "top.txt"), filepath.Join(checks, "run", "check.sh")} {
		if err := os.WriteFile(f, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return []wall.Mount{
		{Path: filepath.Join(checks, "run", "check.sh"), ReadOnly: true},
		{Path: filepath.Join(checks, "locked"), ReadOnly: true},
		{Path: filepath.Join(checks, "run")},
		{Path: filepath.Join(dir, "top.txt"), ReadOnly: true},
		{Path: checks},
	}
}

// stepPlacesShown are the binds of [stepPlaces] below dir, in the order a step container
// gets them: dir at /workspace first, and each place after the one it lies in, at its
// names below /workspace.
func stepPlacesShown(dir string) []wall.Mount {
	checks := filepath.Join(dir, "checks")
	return []wall.Mount{
		{Path: dir, Target: "/workspace"},
		{Path: filepath.Join(dir, "top.txt"), ReadOnly: true, Target: "/workspace/top.txt"},
		{Path: checks, Target: "/workspace/checks"},
		{Path: filepath.Join(checks, "locked"), ReadOnly: true, Target: "/workspace/checks/locked"},
		{Path: filepath.Join(checks, "run"), Target: "/workspace/checks/run"},
		{Path: filepath.Join(checks, "run", "check.sh"), ReadOnly: true, Target: "/workspace/checks/run/check.sh"},
	}
}

// TestRunStepBindsPlacesOverItsWorkingFolder pins a step's places below its working
// folder: a read-only file one name below it, a read-only folder and file below writable
// folders listed at their paths, and those folders are each bound, the working folder
// first and each place after the one it lies in, each with its mode. A second step
// with the same places, and a join after them, run.
func TestRunStepBindsPlacesOverItsWorkingFolder(t *testing.T) {
	w := newStepWall(t)
	w.exit = wall.StepExit{Started: true}
	sp, r := openStepRun(t, w)
	ctx := context.Background()
	mounts := stepPlaces(t, sp.Dir)
	for range 2 {
		if _, err := r.RunStep(ctx, session.StepSpec{Name: "x", Command: []string{"true"}, Dir: sp.Dir, Mounts: mounts}); err != nil {
			t.Fatal(err)
		}
	}
	if res, err := r.Join(ctx, sp.SessionSpec); err != nil || res.ExitCode != 0 {
		t.Fatalf("the join after the steps: %v, %+v", err, res)
	}
	want := stepPlacesShown(sp.Dir)
	for _, l := range w.steps {
		if !slices.Equal(l.Mounts, want) || l.Dir != "/workspace" {
			t.Errorf("the step container's mounts %+v in %s\nwant %+v", l.Mounts, l.Dir, want)
		}
	}
}

// TestRunStepRefusesAPlaceItCannotBindOverItsWorkingFolder pins the refusals of a step's
// places below its working folder: a read-only file two names below it, with no mount of
// the folder between; one reached through a link inside the working folder; one that is
// a link; one with a second hard link; a writable folder inside a read-only one; a
// read-only mount with a Target whose path lies inside the working folder; and a
// read-only file in a working folder that lies inside a writable mount, or that is
// listed as a mount, so that it is no mount point. No step container starts.
func TestRunStepRefusesAPlaceItCannotBindOverItsWorkingFolder(t *testing.T) {
	w := newStepWall(t)
	sp, r := openStepRun(t, w)
	dir := sp.Dir
	deep, real, ro := filepath.Join(dir, "a", "b.txt"), filepath.Join(dir, "real"), filepath.Join(dir, "ro")
	mkdirs(t, filepath.Join(dir, "a"), real, filepath.Join(ro, "w"))
	for _, f := range []string{deep, filepath.Join(real, "f")} {
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "link")
	symlink(t, real, link)
	app := mkdirs(t, filepath.Join(dir, "app"))
	inApp, top, hard := filepath.Join(app, "c.txt"), filepath.Join(dir, "top.txt"), filepath.Join(dir, "hard.sh")
	for _, f := range []string{inApp, top, hard, filepath.Join(dir, "real.sh")} {
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(hard, filepath.Join(dir, "other.sh")); err != nil {
		t.Fatal(err)
	}
	isLink := filepath.Join(dir, "check.sh")
	symlink(t, filepath.Join(dir, "real.sh"), isLink)
	for _, c := range []struct {
		name   string
		dir    string
		mounts []wall.Mount
		code   string
		detail string
	}{
		{"a working folder inside a writable mount", app, []wall.Mount{{Path: dir}, {Path: inApp, ReadOnly: true}}, "mount_mode_conflict",
			"the mount " + inApp + " (read-only) lies inside the mount " + dir + " (writable): a part of a writable mount can't be read-only"},
		{"a working folder listed as a mount", "", []wall.Mount{{Path: dir}, {Path: top, ReadOnly: true}}, "mount_mode_conflict",
			"the mount " + top + " (read-only) lies inside the mount " + dir + " (writable): a part of a writable mount can't be read-only"},
		{"two names below", "", []wall.Mount{{Path: deep, ReadOnly: true}}, "mount_mode_conflict",
			"List " + filepath.Join(dir, "a") + " as a mount, or move the mount " + deep + " one name below the workspace " + dir + ".\n" +
				"The step can rename " + filepath.Join(dir, "a") + ", and the bind moves with it"},
		{"through a link", "", []wall.Mount{{Path: filepath.Join(link, "f"), ReadOnly: true}}, "mount_target_conflict",
			"Remove the symbolic link " + link + " from the workspace " + dir + ", or list the path it resolves to.\n" +
				"The step can change the link, and the mount " + filepath.Join(link, "f") + " is then shown at another path"},
		{"a link", "", []wall.Mount{{Path: isLink, ReadOnly: true}}, "mount_target_conflict",
			"Remove the symbolic link " + isLink + " from the workspace " + dir + ", or list the path it resolves to.\n" +
				"The step can change the link, and the mount " + isLink + " is then shown at another path"},
		{"a hard link", "", []wall.Mount{{Path: hard, ReadOnly: true}}, "mount_mode_conflict",
			"Remove the other hard links to the mount " + hard + ", or write it again as a new file.\n" +
				"It has 2 names, and a process can write it through one that is not read-only"},
		{"writable inside read-only", "", []wall.Mount{{Path: ro, ReadOnly: true}, {Path: filepath.Join(ro, "w")}}, "mount_mode_conflict",
			"the mount " + filepath.Join(ro, "w") + " (writable) lies inside the mount " + ro + " (read-only): a part of a read-only mount can't be writable"},
		{"a target", "", []wall.Mount{{Path: deep, ReadOnly: true, Target: "/opt/b.txt"}}, "mount_mode_conflict",
			"List the mount " + deep + " at /opt/b.txt and the workspace " + dir + " with paths on this machine apart from each other: " +
				"the mount " + deep + " at /opt/b.txt (read-only) lies inside the workspace " + dir + " (writable) on this machine, " +
				"and a mount with a target can't share a path with a place of the other mode"},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := dir
			if c.dir != "" {
				in = c.dir
			}
			_, err := r.RunStep(context.Background(), session.StepSpec{Name: "x", Command: []string{"true"}, Dir: in, Mounts: c.mounts})
			if got := refusalOf(t, c.code, err); got.Detail != c.detail {
				t.Errorf("detail %q\nwant   %q", got.Detail, c.detail)
			}
		})
	}
	if w.started() != 0 {
		t.Errorf("a refused step made %d step containers", w.started())
	}
}

// TestRunStepBindsAWritableFileAndMergesReadOnlyPlaces pins two more cases of a step's
// places below its working folder: a writable file listed at its path is bound, a mount
// point; a read-only file inside a read-only folder is reached through the folder's
// bind, as for a join, with no mount of the folder between them.
func TestRunStepBindsAWritableFileAndMergesReadOnlyPlaces(t *testing.T) {
	w := newStepWall(t)
	w.exit = wall.StepExit{Started: true}
	sp, r := openStepRun(t, w)
	out, ro := filepath.Join(sp.Dir, "out.txt"), filepath.Join(sp.Dir, "ro")
	inRo := filepath.Join(ro, "b", "c.txt")
	mkdirs(t, filepath.Dir(inRo))
	for _, f := range []string{out, inRo} {
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mounts := []wall.Mount{{Path: inRo, ReadOnly: true}, {Path: out}, {Path: ro, ReadOnly: true}}
	if _, err := r.RunStep(context.Background(), session.StepSpec{Name: "x", Command: []string{"true"}, Dir: sp.Dir, Mounts: mounts}); err != nil {
		t.Fatal(err)
	}
	want := []wall.Mount{{Path: sp.Dir, Target: "/workspace"}, {Path: out, Target: "/workspace/out.txt"}, {Path: ro, ReadOnly: true, Target: "/workspace/ro"}}
	if l := w.steps[0]; !slices.Equal(l.Mounts, want) {
		t.Errorf("the step container's mounts %+v\nwant %+v", l.Mounts, want)
	}
}

// TestAStepFolderListedInAnotherCase pins, on a file system that ignores case, a step
// whose folder between the working folder and a read-only file is listed in another case
// than the file's path spells it: the text asks for the same spelling.
func TestAStepFolderListedInAnotherCase(t *testing.T) {
	w := newStepWall(t)
	sp, r := openStepRun(t, w)
	checks := mkdirs(t, filepath.Join(sp.Dir, "checks"))
	file := filepath.Join(checks, "check.sh")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	upper := filepath.Join(sp.Dir, "CHECKS")
	if _, err := os.Stat(upper); err != nil {
		t.Skip("the file system is case-sensitive")
	}
	_, err := r.RunStep(context.Background(), session.StepSpec{Name: "x", Command: []string{"true"}, Dir: sp.Dir,
		Mounts: []wall.Mount{{Path: upper}, {Path: file, ReadOnly: true}}})
	want := "List the mount " + upper + " as " + checks + ", as the mount " + file + " spells it.\n" +
		"The step can rename " + checks + ", and the bind moves with it"
	if got := refusalOf(t, "mount_mode_conflict", err); got.Detail != want {
		t.Errorf("detail %q\nwant   %q", got.Detail, want)
	}
}

// TestAStepWithPlacesBesideTheSetupContainer pins a step beside an unprivileged setup
// container in the same working folder: with a place bound over the folder, which the
// setup container can write, it is an error and starts nothing; with none it runs.
func TestAStepWithPlacesBesideTheSetupContainer(t *testing.T) {
	ctx := context.Background()
	w := newStepWall(t)
	w.exit = wall.StepExit{Started: true}
	sp, r := openStepRun(t, w)
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands, Unprivileged: true}); err != nil {
		t.Fatal(err)
	}
	top := filepath.Join(sp.Dir, "top.txt")
	if err := os.WriteFile(top, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := r.RunStep(ctx, session.StepSpec{Name: "x", Command: []string{"true"}, Dir: sp.Dir, Mounts: []wall.Mount{{Path: top, ReadOnly: true}}})
	want := "Call RemoveSetup before the step: the setup container can write " + sp.Dir + ", where the step binds " + top + "."
	if err == nil || err.Error() != want || w.started() != 0 {
		t.Errorf("RunStep: %v, %d step containers; want %q", err, w.started(), want)
	}
	if _, err := r.RunStep(ctx, session.StepSpec{Name: "x", Command: []string{"true"}, Dir: sp.Dir}); err != nil || w.started() != 1 {
		t.Errorf("a step with no place below its working folder: %v, %d step containers", err, w.started())
	}
}

// TestAJoinRefusesAStepsPlacesOverTheWorkspace pins that only a step binds a read-only
// place over the workspace: a join with the same places is mount_mode_conflict, as
// before steps had them.
func TestAJoinRefusesAStepsPlacesOverTheWorkspace(t *testing.T) {
	sp := walledSpec(t, &openWall{})
	sp.Mounts = stepPlaces(t, sp.Dir)
	r := refusalOf(t, "mount_mode_conflict", runErr(sp))
	file := filepath.Join(sp.Dir, "checks", "run", "check.sh")
	run := filepath.Dir(file)
	want := "the mount " + file + " (read-only) lies inside the mount " + run + " (writable): a part of a writable mount can't be read-only"
	if r.Detail != want {
		t.Errorf("detail %q\nwant   %q", r.Detail, want)
	}
}

// pullingStepWall is a stepWall that fetches a run's image by reference.
type pullingStepWall struct{ *stepWall }

func (pullingStepWall) Pull(context.Context, wall.Request, []byte, []string) error { return nil }

// TestAStepBindsItsPlacesUnderTheWorkspace pins a step of a run whose policy sets its
// image by name, and of one that sets it by reference: in both, the working folder is
// shown at /workspace, each place over it at the same names below /workspace, in the
// same order, and a path of the working folder in the command is written as
// /workspace. A mount with a Target below /workspace is mount_target_conflict in both.
func TestAStepBindsItsPlacesUnderTheWorkspace(t *testing.T) {
	ctx := context.Background()
	for _, byRef := range []bool{false, true} {
		t.Run(fmt.Sprint("by reference ", byRef), func(t *testing.T) {
			sp, g := specGateway(t, "FAKE_EXIT=0")
			w := pullingStepWall{newStepWall(t)}
			w.exit = wall.StepExit{Started: true}
			sp.Wall = w
			if byRef {
				byReference(g)
			} else {
				sp.Image = "example.com/agent:1"
			}
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
			if byRef {
				if err := r.FetchImage(ctx); err != nil {
					t.Fatal(err)
				}
			}
			mounts := stepPlaces(t, sp.Dir)
			command := []string{"/bin/sh", "-c", "test -f " + filepath.Join(sp.Dir, "top.txt")}
			if _, err := r.RunStep(ctx, session.StepSpec{Name: "x", Command: command, Dir: sp.Dir, Mounts: mounts}); err != nil {
				t.Fatal(err)
			}
			want := stepPlacesShown(sp.Dir)
			if l := w.steps[0]; !slices.Equal(l.Mounts, want) || l.Dir != "/workspace" || l.Args[1] != "test -f /workspace/top.txt" {
				t.Errorf("the step container's launch %+v in %s\nwant %+v", l, l.Dir, want)
			}
			_, err = r.RunStep(ctx, session.StepSpec{Name: "x", Command: []string{"true"}, Dir: sp.Dir,
				Mounts: []wall.Mount{{Path: t.TempDir(), ReadOnly: true, Target: "/workspace/tools"}}})
			if refusalOf(t, "mount_target_conflict", err); w.started() != 1 {
				t.Errorf("a refused step made a step container")
			}
		})
	}
}
