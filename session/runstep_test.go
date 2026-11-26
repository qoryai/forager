package session_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// stepWall is a setupWall whose enclosure runs step containers: WrapStep notes its
// launch and returns wrapErr, or a launch that runs the step's command on this machine,
// until the command ends or UnwrapStep creates the step's stop file, which kills it.
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

// stepScript runs "$@" in the background and kills it once the file $1 exists.
const stepScript = `stop=$1; shift
"$@" & p=$!
( while [ ! -e "$stop" ]; do sleep 0.02; done; kill $p ) >/dev/null 2>&1 & k=$!
wait $p; c=$?
kill $k 2>/dev/null
exit $c`

func (w *stepWall) WrapStep(_ context.Context, l wall.Launch) (wall.Launch, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	stop := filepath.Join(w.dir, fmt.Sprint("stop-", len(w.steps)))
	w.steps, w.stops = append(w.steps, l), append(w.stops, stop)
	if w.wrapErr != nil {
		return wall.Launch{}, w.wrapErr
	}
	return wall.Launch{Command: "/bin/sh", Args: append([]string{"-c", stepScript, "sh", stop, l.Command}, l.Args...)}, nil
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
	if l.Command != "/bin/sh" || !slices.Equal(l.Args, []string{"-c", "echo out; echo err >&2"}) || l.Dir != sp.Dir || !slices.Equal(l.Mounts, []wall.Mount{{Path: sp.Dir}}) {
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
	if err == nil || err.Error() != "Check the step's command and the run's image: the step container did not start.\nsh: exit status 1" {
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
