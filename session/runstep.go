package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/session/internal/chunk"
	"github.com/qoryai/forager/wall"
)

// StepSpec is what [Run.RunStep] is given: the step's name, its image, its command,
// its working folder and mounts, its time limit, the paths its places are checked
// against and its limits.
type StepSpec struct {
	// Name is the step's name in its dev.qory.run.step_started and its log lines, such
	// as "step first/ac-1-x". Any text but an empty one: spaces and slashes are kept.
	// It is not the name of a container or a file.
	Name string
	// Image is the image the step container starts from: the run's image, by its name
	// or its reference, the one the node's policy sets for the run. Empty is the run's
	// image. Any other image is refused before the step starts.
	Image string
	// Command is the program the step container runs and its arguments: Command[0] is
	// the container's entrypoint, as the image's file system has it. It must not be
	// empty.
	Command []string
	// Dir is the working folder, bound writable and the working directory inside, as
	// SetupSpec.Dir is. Empty is the working directory of this process.
	Dir string
	// Mounts are further places of this machine the step container binds, each at its
	// path or at its Target, read-only or writable, with the checks of
	// SessionSpec.Mounts.
	Mounts []wall.Mount
	// Timeout is how long the command may run, from the container's start. When it
	// passes, the container gets SIGTERM, then SIGKILL 5 seconds later, and the result
	// has TimedOut. Zero is no limit of the step's: the step then ends with its
	// command, with ctx, or with [Run.Close].
	Timeout time.Duration
	// ForagerFiles are the absolute paths of the caller's files that are Forager's, as
	// in SetupSpec.ForagerFiles.
	ForagerFiles []string
	// Written are the places of this machine that the caller records as writable by a
	// walled run, as in SetupSpec.Written.
	Written []string
	// Limits are the resources the step container may use, as SetupSpec.Limits are the
	// setup container's.
	Limits wall.Limits
}

// StepResult is what a step's command did. An exit status other than 0 is a result,
// not an error of [Run.RunStep].
type StepResult struct {
	// Step is the number of the step in the run's steps.
	Step int
	// ExitCode is the exit status of the command, or -1 when the command has none, as
	// when the step was stopped before the container's start.
	ExitCode int
	// Signal is the number of the signal that ended the command, such as 9 for
	// SIGKILL, and 0 when no signal ended it. Under the container's init, an exit
	// status of 128+N is signal N.
	Signal int
	// TimedOut is true when StepSpec.Timeout ended the command.
	TimedOut bool
	// OOMKilled is true when the engine ended the command at the memory limit.
	OOMKilled bool
	// Output is the first 1 MiB of the command's standard output and standard error,
	// in the order they arrived, after the run's masker replaced the run's secrets in
	// them. The step's log lines have all of it.
	Output []byte
	// OutputCut is true when the command wrote more than Output has.
	OutputCut bool
	// Started and Ended are when the step started and ended.
	Started, Ended time.Time
}

// stepOutputLimit is how many bytes of a step's masked output StepResult.Output has.
const stepOutputLimit = 1 << 20

// runningStep is the step that RunStep runs: cancel stops it, and done is closed once
// RunStep let go of r.joining.
type runningStep struct {
	cancel context.CancelCauseFunc
	done   chan struct{}
}

// RunStep runs spec.Command in a step container: a new container of the run's image on
// the run's inside network, as the wall's user with the flags of the setup container,
// with the working folder writable, spec.Mounts, the helper and, for a run with an
// authority, the bundle. Its environment is the relay's proxy variables and the
// bundle's: no run secret, no placeholder and no QORY_RUN_API. It has no nested Docker
// daemon, no hook socket and no home. While a step container may run, every connection
// of the wall's relay is unprivileged: the gateway's proxy applies the run's allow list
// to its requests and records them, sets no credential on them, sends none of them to
// a tool and returns 403 for each run API request. A service that an unprivileged
// setup container runs is reached by the name qory-setup, as from a session.
//
// RunStep writes one step, numbered on from the run's last step, of kind
// event.StepContainer, with the run's masker applied to spec.Name, the command's output
// as its lines on stdout and stderr, and its exit status. It ends succeeded for exit
// status 0; failed for any other, and with reason out_of_memory when the engine ended
// the command at the memory limit; cancelled with reason timeout when spec.Timeout
// ended it; and cancelled when ctx ended or the run was closed, which stop the command
// with SIGTERM and then SIGKILL 5 seconds later. A stopped step returns its result and
// the stop's cause as the error. RunStep removes the step container before it returns;
// [Run.Close] during a step stops it, waits for RunStep to return, and closes the run.
//
// A step runs between joins and outside every host step, before the first join or
// after the last one, and beside the setup container only when the setup started with
// SetupSpec.Unprivileged. The first join after one or more steps starts the wall's
// relay again with a new token, so no connection of a step container reaches the proxy
// after it; a join whose restart fails returns an error, and the next join tries again.
//
// An error before the step means nothing is written: the run has no wall, or one that
// does not implement step containers; another call of the run runs; a host step is
// open; the run is closed; the setup failed; the setup container runs without
// Unprivileged; a container of the run may still run (ContainerKept); the run's image
// by reference was not fetched; spec is refused; or a place fails a check. A failure of
// the wall after the step's start ends the step failed, or cancelled when ctx ended,
// with -1, after its line, and is the error. A step container that could not be
// removed may still run: ContainerKept is true from then on, and no session joins.
// The run's masker replaces the run's secrets in the error, as in Open's.
func (r *Run) RunStep(ctx context.Context, spec StepSpec) (res *StepResult, err error) {
	defer func() { err = maskError(r.masker, err) }()
	if r.open.Wall == nil {
		return nil, errors.New("Open the run with a wall to run a step: a step runs in a container of the run's image.")
	}
	if err := r.checkStep(spec); err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	running := &runningStep{cancel: cancel, done: make(chan struct{})}
	// The lock is taken under stepMu, so a Close that finds it taken reads stepping set.
	r.stepMu.Lock()
	if !r.joining.TryLock() {
		r.stepMu.Unlock()
		return nil, errors.New("Run the step after the run's other call returns: another call of the run is running.")
	}
	r.stepping = running
	r.stepMu.Unlock()
	defer func() {
		r.joining.Unlock()
		r.stepMu.Lock()
		r.stepping = nil
		r.stepMu.Unlock()
		close(running.done)
	}()
	stopFollow := context.AfterFunc(r.closing, func() { cancel(errRunClosed) })
	defer stopFollow()
	switch {
	case r.closed:
		return nil, errors.New("Open another run to run a step: the run is closed.")
	case r.hostStep != nil:
		return nil, fmt.Errorf("Exit step %d before the step: one host step is open at a time.", r.hostStep.n)
	case r.setupFailed > 0:
		return nil, fmt.Errorf("Open another run: setup step %d of this run failed, so no step runs in it.", r.setupFailed)
	case r.setupUp != nil && !r.setupUnprivileged:
		return nil, errors.New("Start the setup with Unprivileged to run steps: the setup container gets credentials.")
	case r.ContainerKept():
		return nil, r.keptError()
	case r.byReference && r.imageStep == 0:
		return nil, errors.New("Call FetchImage before the step: the run's image is not on this machine yet.")
	}
	stepper, ok := r.enclosure.(wall.StepWrapper)
	_, restarts := r.enclosure.(relayRestarter)
	if !ok || !restarts {
		return nil, fmt.Errorf("Run the step behind the Docker wall: the %s wall does not implement step containers.", accesskey.ShownName(r.open.Wall.Name(), false))
	}
	if spec.Dir == "" {
		spec.Dir, _ = os.Getwd()
	}
	ws := runSpec{OpenSpec: r.open, SessionSpec: SessionSpec{Dir: spec.Dir, Mounts: spec.Mounts, ForagerFiles: spec.ForagerFiles, Written: spec.Written}}
	plan, err := checkMounts(ws, r.dir, "")
	if err != nil {
		return nil, err
	}
	shown, inside := plan, func(s string) string { return s }
	if r.byReference {
		if shown, inside, err = plan.atWorkspace(); err != nil {
			return nil, err
		}
	}
	if r.listed != nil {
		if err := r.listed.update(append(slices.Clone(r.openBinds), plan.sources...)); err != nil {
			return nil, err
		}
	}
	command := insideAll(spec.Command, inside)
	// The step container may reach the run's forwarder from here on.
	r.shutCheck(errCheckAfterStep, false)
	// No push runs while the step container can write the run's binds.
	r.pushes.closeAll()

	step := r.startStep(event.StepContainer, spec.Name)
	res = &StepResult{Step: step.n, ExitCode: -1, Started: step.start}
	// A panic that a caller recovers leaves no step open.
	defer step.end(event.StateFailed, -1)
	fail := func(err error) (*StepResult, error) {
		r.writeLog("stderr", 0, step.n, failureLine(err))
		state := event.StateFailed
		if runCtx.Err() != nil {
			state = event.StateCancelled
		}
		step.end(state, -1)
		res.Ended = time.Now()
		return res, err
	}
	// The places again, just before the step container binds them, as Setup checks them.
	again, err := checkMounts(ws, r.dir, "")
	if err == nil {
		err = samePlan(plan, again)
	}
	if err != nil {
		return fail(err)
	}
	binds, err := wallBinds(r.enclosure, "", r.authority, wall.Transcript{})
	if err != nil {
		return fail(err)
	}
	if r.listed != nil {
		r.listed.askID(runCtx, r.open.Wall)
		all := slices.Concat(r.openBinds, again.sources, binds)
		if err := r.listed.update(all); err != nil {
			return fail(err)
		}
		// What the step container writes stays after its removal, so each join lists
		// its places with the setup container's, until the run closes.
		r.openBinds = all
		r.setupBinds = slices.Concat(r.setupBinds, again.sources, binds)
	}
	// Every connection of the relay is unprivileged from here until the next privileged
	// container's start ends the window.
	r.openWindow()
	launch, err := stepper.WrapStep(runCtx, wall.Launch{
		Command: command[0], Args: command[1:], Dir: shown.Dir, CA: r.authority, Mounts: shown.Mounts,
		Limits: spec.Limits, Proxy: r.wallFwd.Addr(), ProxyToken: r.relayToken, ProxyPeer: r.route != nil,
	})
	if err != nil {
		if kept := r.unwrapStep(ctx, stepper, res); kept != nil {
			err = errors.Join(err, kept)
		}
		return fail(accesskey.ShownError(err))
	}
	out := &limitedBuffer{limit: stepOutputLimit}
	stdout, stderr := r.stepLines("stdout", step.n, out), r.stepLines("stderr", step.n, out)
	cmd := exec.Command(launch.Command, launch.Args...)
	cmd.Env, cmd.Dir, cmd.Stdout, cmd.Stderr = launch.Env, launch.Dir, stdout, stderr
	if err := cmd.Start(); err != nil {
		if kept := r.unwrapStep(ctx, stepper, res); kept != nil {
			err = errors.Join(err, kept)
		}
		return fail(fmt.Errorf("Check that the docker command runs on this machine, then run the step again.\nThe step container could not be started: %w", accesskey.ShownError(err)))
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var limit <-chan time.Time
	if spec.Timeout > 0 {
		t := time.NewTimer(spec.Timeout)
		defer t.Stop()
		limit = t.C
	}
	stopped := false
	select {
	case <-done:
		done = nil
	case <-limit:
		res.TimedOut = true
	case <-runCtx.Done():
		stopped = true
	}
	// The container is stopped, read and removed in every case: docker start --attach
	// ends once it stops.
	kept := r.unwrapStep(ctx, stepper, res)
	if done != nil {
		select {
		case <-done:
		case <-time.After(closeWait):
			cmd.Process.Kill()
			<-done
		}
	}
	stdout.flush()
	stderr.flush()
	res.Output, res.OutputCut, res.Ended = []byte(out.String()), out.cutOff(), time.Now()
	if kept != nil {
		return fail(kept)
	}
	switch {
	case stopped:
		step.end(event.StateCancelled, res.ExitCode)
		return res, context.Cause(runCtx)
	case res.TimedOut:
		step.endWith(event.StateCancelled, res.ExitCode, afterReasonTimeout)
	case res.OOMKilled:
		step.endWith(event.StateFailed, res.ExitCode, afterReasonOutOfMemo)
	case res.ExitCode == 0:
		step.end(event.StateSucceeded, 0)
	default:
		step.end(event.StateFailed, res.ExitCode)
	}
	return res, nil
}

// checkStep refuses a spec RunStep cannot run, before anything is written.
func (r *Run) checkStep(spec StepSpec) error {
	switch {
	case spec.Name == "":
		return fmt.Errorf("Give the step a name, such as %q: a step's name is never empty.", "step first/ac-1-x")
	case len(spec.Command) == 0 || spec.Command[0] == "":
		return errors.New("Give the step a command: Command[0] is the program the step container runs.")
	case spec.Timeout < 0:
		return fmt.Errorf("Give the step a time limit of 0 or more, not %s.", spec.Timeout)
	case spec.Image != "" && spec.Image != r.img.Name && spec.Image != r.img.Ref:
		return fmt.Errorf("Leave Image empty: a step runs in the run's image %s alone.", accesskey.ShownName(r.imageShown(), false))
	}
	return nil
}

// unwrapStep stops, reads and removes the step container within the stop's 5 seconds
// and the removal's limit, whatever ctx's state, and fills res from its exit. A removal
// that failed lists the run among the walled runs kept, sets wallFailed and stepKept,
// and is the error, with the container's name: the container may still run and write
// the run's binds.
func (r *Run) unwrapStep(ctx context.Context, stepper wall.StepWrapper, res *StepResult) error {
	exit, err := stepper.UnwrapStep(context.WithoutCancel(ctx), afterKillWait)
	if exit.Started {
		res.ExitCode, res.OOMKilled = exit.ExitCode, exit.OOMKilled
		if exit.ExitCode > 128 && exit.ExitCode < 256 {
			res.Signal = exit.ExitCode - 128
		}
	}
	if err == nil {
		return nil
	}
	if !errors.Is(err, wall.ErrContainerKept) {
		return fmt.Errorf("Run the step again: how the step container ended could not be read.\n%w", accesskey.ShownError(err))
	}
	r.wallFailed.Store(true)
	r.stepKept = true
	if r.listed != nil {
		r.listed.keep()
	}
	r.open.Report("removing the wall: " + accesskey.ShownError(err).Error())
	return wall.ContainerKeptError(r.keptError())
}

// keptError is the refusal of a call while a container of the run may still run: with
// the name of the first such container the wall lists, else with none.
func (r *Run) keptError() error {
	if s, ok := r.enclosure.(wall.StepWrapper); ok {
		if kept := s.Kept(); len(kept) > 0 {
			name := kept[0]
			return fmt.Errorf("Remove the container %s with \"docker rm -f %s\", then close the run: Forager could not remove it, and it may still run.", name, name)
		}
	}
	return errors.New("Close the run: a container of the run could not be removed and may still run.")
}

// stepLines is what writes one stream of the step's output: through the run's masker,
// once, then into the step's log lines and into out, which both streams share.
func (r *Run) stepLines(stream string, step int, out io.Writer) *stepStream {
	masker := r.masker
	if masker.Empty() {
		masker = nil
	}
	chunks := chunk.New(r.logEmit(stream, 0, step))
	return &stepStream{chunks: chunks, masked: mask.NewWriter(io.MultiWriter(chunks, out), masker)}
}

// stepStream is one stream of a step's output, masked once.
type stepStream struct {
	chunks *chunk.Writer
	masked *mask.Writer
}

func (s *stepStream) Write(p []byte) (int, error) { return s.masked.Write(p) }

// flush writes what the masker and the chunks hold back, once the stream ended.
func (s *stepStream) flush() {
	s.masked.Flush()
	s.chunks.Flush()
}

// lockForClose takes r.joining for [Run.Close]: at once, or, while RunStep runs, once
// the step stopped and RunStep returned. It reports false while any other call of the
// run runs, a Join among them.
func (r *Run) lockForClose() bool {
	for {
		if r.joining.TryLock() {
			return true
		}
		r.stepMu.Lock()
		s := r.stepping
		r.stepMu.Unlock()
		if s == nil {
			return r.joining.TryLock()
		}
		s.cancel(errRunClosed)
		<-s.done
	}
}
