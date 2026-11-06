package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/session/internal/variables"
	"github.com/qoryai/forager/wall"
)

// SetupSpec is what [Run.Setup] is given: the working folder, the setup container's
// variables, the setup commands, the paths the working folder is checked against and
// the setup container's limits.
type SetupSpec struct {
	Dir      string         // the working folder
	Env      []string       // NAME=value
	Commands []SetupCommand // one setup step each
	// ForagerFiles are the absolute paths of the caller's files that are Forager's,
	// as in SessionSpec.ForagerFiles. Setup refuses a Dir that is, contains or lies
	// inside one of them, one of the gateway's files, or one of the paths Forager
	// knows, RunsDir among them, mount_contains_forager_files: see [Overlap].
	ForagerFiles []string
	// Written are the places of this machine, directories, that the caller records as
	// writable by a walled run, as in SessionSpec.Written. Setup refuses a Dir whose
	// path goes through a link inside one of them and does not resolve into it,
	// mount_through_link. A relative path is taken from the working directory.
	Written []string
	// Limits are the resources the setup container may use, as SessionSpec.Limits
	// are the runtime's.
	Limits wall.Limits
}

// SetupError is the error of [Run.Setup] when a setup command exits otherwise than 0:
// Name is the command's name as its step shows it, Step the number of its setup step and
// ExitCode its exit status. No session joins the run after it.
type SetupError struct {
	Name     string
	Step     int
	ExitCode int
}

// Error is the fix first: Fix install: setup step 5 exited with 1.
func (e *SetupError) Error() string {
	return fmt.Sprintf("Fix %s: setup step %d exited with %d.", e.Name, e.Step, e.ExitCode)
}

// relayStarter is an enclosure whose relay starts apart from Wrap, once the run's
// forwarder listens, as the run opens: the Docker wall's.
type relayStarter interface {
	StartRelay(ctx context.Context, l wall.Launch) error
}

// unwrapper is an enclosure that removes what the launch of one Wrap started, as its
// session ends: the Docker wall's, which removes the agent's container.
type unwrapper interface {
	Unwrap(ctx context.Context) error
}

// setupContainer is an enclosure that runs the run's setup commands in a container of
// the run's image apart from the agent's, the setup container: the Docker wall's.
// StartSetup starts it with l's Dir, Env, CA, Mounts, Limits, Proxy and ProxyToken, and
// ExecSetup runs one command in it and returns its exit status.
//
// RemoveSetup removes the setup container, and returns nil only once it is gone: every
// process in it has ended, by force when it does not end by itself, and the name
// qory-setup no longer resolves inside the enclosure. What the container wrote to its
// mounts stays. A container that is gone already is not an error, but a failure that
// leaves its state unknown is. RemoveSetup bounds its wait and returns an error when ctx
// ends or the container does not end in time, so the call never blocks the run without
// limit. After an error the container may still run: accept a second call of RemoveSetup,
// which tries again, and Close tries the removal again too. The session calls
// RemoveSetup after a StartSetup that returned nil, while no launch of Wrap runs: before
// the run's first Wrap, or after a session's launch ended and, for an enclosure with
// Unwrap, its Unwrap returned nil. A later Wrap may follow, so RemoveSetup leaves
// everything else of the enclosure as it is.
type setupContainer interface {
	StartSetup(ctx context.Context, l wall.Launch) error
	ExecSetup(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error)
	RemoveSetup(ctx context.Context) error
}

// openWall builds the run's wall as the run opens: the wall's preparation, the run's
// forwarder at the address the enclosure's ProxyAddr returns, and, for an enclosure that starts
// its relay apart from Wrap, the relay. On one machine the relay opens every connection
// with the run's proxy secret, and the forwarder passes on what arrives as it is.
// Behind a separate gateway the relay opens each with the run's hop token, which the
// forwarder checks and takes off before it opens the gateway's proxy with the run key
// inside TLS. What it made is the caller's to remove with closeWall, also when it fails.
func (r *Run) openWall(ctx context.Context) error {
	enclosure, err := r.open.Wall.Prepare(ctx, r.wallRequest())
	if err != nil {
		return err
	}
	r.enclosure = enclosure
	bind := enclosure.ProxyAddr()
	r.relayToken = r.answer.ProxySecret
	var fwd *forwarder
	if r.remote == nil {
		fwd, err = listenForwarder(bind, r.disc.Proxy.Address, "", "")
	} else {
		if r.relayToken, err = newForwarderSecret(); err != nil {
			return err
		}
		fwd, err = listenForwarding(bind, forwarding{dial: r.link.DialProxy, hop: r.relayToken})
	}
	if err != nil {
		return err
	}
	r.wallFwd = fwd
	if s, ok := enclosure.(relayStarter); ok {
		return s.StartRelay(ctx, wall.Launch{Proxy: fwd.Addr(), ProxyToken: r.relayToken})
	}
	return nil
}

// closeWall removes the run's wall, the enclosure and then the run's forwarder. A wall
// that could not be removed may still run, so it is reported and the run's entry among
// the walled runs still going stays.
func (r *Run) closeWall(ctx context.Context) {
	if r.enclosure != nil {
		if err := r.enclosure.Close(ctx); err != nil {
			r.open.Report("removing the wall: " + accesskey.ShownError(err).Error())
			if r.listed != nil {
				r.listed.keep()
			}
		}
		r.enclosure = nil
	}
	if r.wallFwd != nil {
		r.wallFwd.Close()
		r.wallFwd = nil
	}
}

// Setup runs the run's setup commands in the setup container: a separate container of
// the run's image on the wall's internal network, which runs until [Run.RemoveSetup]
// removes it, or else until [Run.Close]. It runs once per walled run, before the first
// join and outside every host step. While the setup container runs, the agent reaches it
// by the name qory-setup, so a service that a setup command starts stays reachable by
// that name, such as qory-setup:5432. A service sends its output to a file, so its
// command returns.
//
// Setup writes its steps, numbered on from the run's last step: the image step, when the
// policy's image is a reference that no step fetched yet, as [Run.FetchImage] writes it;
// the wall step, "start the setup container"; and a setup step for each command, with
// the command's Name as its name, its output as its lines, on stdout and stderr, and its
// exit status. The commands run one after another, as the wall's user, with no input,
// in Dir as the setup container sees it: at /workspace for an image by reference. Dir
// gets a join's checks of its workspace, with ForagerFiles and Written in place of the
// join's SessionSpec.ForagerFiles and SessionSpec.Written.
//
// The setup container runs with the flags of the agent's container without nested
// Docker, and with the flags of Limits that the agent's container gets for
// SessionSpec.Limits. It gets Dir, writable, and the helper and, for a run
// with an authority, the bundle, read-only: no harness home, run directory, hook socket
// or engine socket. Its environment is the relay's proxy variables, the bundle's
// variables, QORY_RUN_API for a run with a control plane, the run's placeholders, and
// then Env, which a caller fills from
// [Run.AgentEnv]. Env is refused before any step when it has a value for one of the
// run's placeholders, [refusal.PlaceholderConflict]; a QORY_ name other than
// QORY_RUN_SYSTEM and QORY_RUN_REPOSITORIES, or a name the machine's credentials are
// read from, [refusal.VariableReserved]; or a name the built-in deny list matches, such
// as LD_PRELOAD. It gets no host proxy's URL or password. A value of Env is refused when it contains the password
// of one of the run's forwarders or of OpenSpec.EngineProxy: as it is, as in a proxy URL
// such as http://qory:<password>@host, or as the base64 of qory:<password> that
// Proxy-Authorization: Basic has. The setup container has no Docker daemon: a command
// that calls docker fails with Docker's error, in its step's lines.
//
// An error before the steps means nothing is written: the run has no wall, a session of
// the run is running or joined it, the setup ran already, a host step is open, the run
// is closed, the commands or Env are refused, Dir fails a check, or the run's wall
// does not implement the setup container's calls. A setup command that exits otherwise
// than 0 ends its step failed with its exit status and returns a [*SetupError]. Any
// other failure in a step ends the step failed, or cancelled when ctx ended, with -1,
// after its line, and is the error. After a step that fails no later step starts, and
// no session joins the run.
// The run's masker replaces the run's secrets in the error, as in Open's.
func (r *Run) Setup(ctx context.Context, spec SetupSpec) (err error) {
	defer func() { err = maskError(r.masker, err) }()
	if r.open.Wall == nil {
		return errors.New("Open the run with a wall to run its setup: setup runs in a container of the run's image.")
	}
	if !r.joining.TryLock() {
		return errors.New("Run the setup before the first join: a session of the run is still running.")
	}
	defer r.joining.Unlock()
	switch {
	case r.closed:
		return errors.New("Open another run to run its setup: the run is closed.")
	case r.numbered > 0:
		return fmt.Errorf("Run the setup before the first join: session %d joined the run.", r.numbered)
	case r.setupFirst > 0:
		return fmt.Errorf("Run the setup once per run: it ran in steps %d to %d.", r.setupFirst, r.setupLast)
	case r.hostStep != nil:
		return fmt.Errorf("Exit step %d before the setup: one host step is open at a time.", r.hostStep.n)
	case len(spec.Commands) == 0:
		return errors.New("Give the setup at least one command.")
	}
	if err := checkSetupCommands(spec.Commands); err != nil {
		return err
	}
	env, err := r.setupEnv(spec.Env)
	if err != nil {
		return err
	}
	container, ok := r.enclosure.(setupContainer)
	if !ok {
		return fmt.Errorf("Run the setup behind the Docker wall: the %s wall does not implement StartSetup, ExecSetup and RemoveSetup.", accesskey.ShownName(r.open.Wall.Name(), false))
	}
	puller, pulls := r.open.Wall.(wall.Puller)
	pulls = pulls && r.byReference && r.imageStep == 0
	if pulls {
		if err := checkEngineProxy(r.open.EngineProxy); err != nil {
			return err
		}
	}
	if spec.Dir == "" {
		spec.Dir, _ = os.Getwd()
	}
	ws := runSpec{OpenSpec: r.open, SessionSpec: SessionSpec{Dir: spec.Dir, ForagerFiles: spec.ForagerFiles, Written: spec.Written}}
	plan, err := checkMounts(ws, r.dir, "")
	if err != nil {
		return err
	}
	shown, inside := plan, func(s string) string { return s }
	if r.byReference {
		if shown, inside, err = plan.atWorkspace(); err != nil {
			return err
		}
	}
	// The setup container's places are checked against the walled runs still going
	// before anything starts, and the run's entry lists them until the run closes.
	if r.listed != nil {
		if err := r.listed.update(append(slices.Clone(r.openBinds), plan.sources...)); err != nil {
			return err
		}
	}
	commands := insideSetup(spec.Commands, inside)

	// open is the setup's step that runs, nil for none. A panic that a caller recovers
	// leaves no step open, and the setup failed.
	var open *Step
	defer func() {
		if open != nil {
			r.setupFailed = open.n
			open.end(event.StateFailed, -1)
		}
	}()
	begin := func(kind, name string) {
		open = r.startStep(kind, name)
		if r.setupFirst == 0 {
			r.setupFirst = open.n
		}
		r.setupLast = open.n
	}
	end := func(state string, code int) {
		open.end(state, code)
		open = nil
	}
	fail := func(err error) error {
		r.writeLog("stderr", 0, open.n, failureLine(err))
		state := event.StateFailed
		if ctx.Err() != nil {
			state = event.StateCancelled
		}
		r.setupFailed = open.n
		end(state, -1)
		return err
	}
	if pulls {
		begin(event.StepImage, r.img.Ref)
		if err := r.pullImage(ctx, puller); err != nil {
			return fail(err)
		}
		r.imageStep = open.n
		end(event.StateSucceeded, -1)
	}
	// The wall step checks the places again, just before the setup container binds
	// them, as a join's wall step does, and lists the wall's binds, which exist by now.
	begin(event.StepWall, "start the setup container")
	again, err := checkMounts(ws, r.dir, "")
	if err == nil {
		err = samePlan(plan, again)
	}
	if err != nil {
		return fail(err)
	}
	binds, err := wallBinds(r.enclosure, "", r.authority)
	if err != nil {
		return fail(err)
	}
	if r.listed != nil {
		r.listed.askID(ctx, r.open.Wall)
		all := slices.Concat(r.openBinds, again.sources, binds)
		if err := r.listed.update(all); err != nil {
			return fail(err)
		}
		// What the setup container writes stays after RemoveSetup removes it, so each join
		// lists its binds with the session's, and each session's end rewrites the run's
		// entry with them, until the run closes.
		r.openBinds = all
		r.setupBinds = slices.Concat(again.sources, binds)
	}
	err = container.StartSetup(ctx, wall.Launch{
		Dir: shown.Dir, Env: env, CA: r.authority, Mounts: shown.Mounts,
		Limits: spec.Limits, Proxy: r.wallFwd.Addr(), ProxyToken: r.relayToken,
	})
	if err != nil {
		return fail(accesskey.ShownError(err))
	}
	r.setupUp = container
	end(event.StateSucceeded, -1)
	for _, c := range commands {
		begin(event.StepSetup, c.Name)
		step := open.n
		var mu sync.Mutex
		line := func(stream string, b []byte) { r.writeLog(stream, 0, step, b) }
		stdout := &setupLines{mu: &mu, stream: "stdout", line: line}
		stderr := &setupLines{mu: &mu, stream: "stderr", line: line}
		code, err := container.ExecSetup(ctx, c.Args, stdout, stderr)
		stdout.flush()
		stderr.flush()
		if err != nil {
			return fail(accesskey.ShownError(err))
		}
		if code != 0 {
			r.setupFailed = step
			end(event.StateFailed, code)
			return &SetupError{Name: r.stepName(c.Name), Step: step, ExitCode: code}
		}
		end(event.StateSucceeded, 0)
	}
	return nil
}

// RemoveSetup removes the run's setup container and returns once it is gone: every
// process in it has ended, and the name qory-setup no longer resolves. Call it when no
// session is running and no host step is open: between [Run.Setup] and the first
// [Run.Join], so a service that a setup command started does not run beside the agent
// and a join with SessionSpec.WorkspaceReadOnly has no process in the run's containers
// that can write the workspace; or after a session ended, before a host step that reads
// the working folder, such as a push, when the agent needed the setup container. A
// request to qory-setup fails from then on, a later join's too. What the setup commands
// wrote in the working folder stays. The run's entry among the walled runs still going
// lists the setup container's places until the run closes, and a settings file in them
// still stops a join, because a setup command may have written it. [Run.Setup] does not
// run again: it runs once per run.
//
// In an open run with no setup container RemoveSetup returns nil and writes nothing, also
// after a join or during a host step, so a caller needs no condition: a run with no
// wall, a run whose setup container did not start, and a run whose setup container
// RemoveSetup removed already. After a join a run gets no setup container: Setup does
// not run after a join.
//
// RemoveSetup writes one step, numbered on from the run's last step: the wall step
// "remove the setup container", which ends succeeded with -1. A run whose setup failed
// keeps its failure: RemoveSetup removes the container, and still no session joins.
//
// An error before the step means nothing is removed and nothing is written: another call
// of the run is running, a [Run.Join] with its session among them; the run is closed; or
// the setup container runs and a host step is open, or the agent's container of a session
// could not be removed and may still run. A removal that fails ends the step failed, or
// cancelled when ctx ended, with -1, after its line, and is the error. The setup
// container may then still run and change the working folder, so close the run, and run
// no push or other host step that reads the working folder after this error: no session
// joins the run after it, also when a later RemoveSetup succeeds, and [Run.Close] tries
// the removal again. The run's masker replaces the run's secrets in the error, as in
// Open's.
func (r *Run) RemoveSetup(ctx context.Context) (err error) {
	defer func() { err = maskError(r.masker, err) }()
	if !r.joining.TryLock() {
		return errors.New("Call RemoveSetup after the run's other call returns: another call of the run is running.")
	}
	defer r.joining.Unlock()
	switch {
	case r.closed:
		return errors.New("Remove the setup container before the close: the run is closed.")
	case r.setupUp == nil:
		return nil
	case r.hostStep != nil:
		return fmt.Errorf("Exit step %d before you remove the setup container: one host step is open at a time.", r.hostStep.n)
	// A session runs while Join holds r.joining, and the enclosure's Unwrap returned
	// before Join lets go: only an Unwrap that failed leaves the agent's container behind.
	case r.keptBy > 0:
		return fmt.Errorf("Close the run: the agent's container of session %d could not be removed and may still run, so the setup container stays until the close.", r.keptBy)
	}
	step := r.startStep(event.StepWall, "remove the setup container")
	// A panic that a caller recovers leaves no step open, and no session joins.
	defer func() {
		if !step.exited {
			r.setupFailed = step.n
			step.end(event.StateFailed, -1)
		}
	}()
	if err := r.setupUp.RemoveSetup(ctx); err != nil {
		err = fmt.Errorf("Close the run: the setup container may still run, so no session can join: %w", accesskey.ShownError(err))
		r.writeLog("stderr", 0, step.n, failureLine(err))
		state := event.StateFailed
		if ctx.Err() != nil {
			state = event.StateCancelled
		}
		r.setupFailed = step.n
		step.end(state, -1)
		return err
	}
	r.setupUp = nil
	step.end(event.StateSucceeded, -1)
	return nil
}

// setupEnv is the part of the setup container's environment that comes after the
// wall's variables: QORY_RUN_API for a run with a control plane, the run's placeholders,
// then env, which [checkSetupEnv] checks first, without the access key's variables and
// QORY_RUN_KEY. A
// value is refused when it contains, in a form the run's masker replaces, the password
// of one of the run's forwarders or of OpenSpec.EngineProxy: the run's masker gets the
// engine proxy's password only in the image step, which comes after this check. A value
// that contains a value of OpenSpec.Masker or a server's variable value is not refused.
func (r *Run) setupEnv(env []string) ([]string, error) {
	if err := checkSetupEnv(env, r.answer.Placeholders, r.reserved); err != nil {
		return nil, err
	}
	kept := accesskey.WithoutVariables(env)
	var engine *mask.Masker
	if p := r.open.EngineProxy; p != nil {
		engine = mask.Proxy(proxyUser, p.Password)
	}
	for _, kv := range kept {
		name, value, _ := strings.Cut(kv, "=")
		if r.passwords.Replace(value) != value || engine.Replace(value) != value {
			return nil, fmt.Errorf("Leave the host proxy's URL out of the setup's variables: %s contains its password, which the setup container never gets.", accesskey.ShownName(name, false))
		}
	}
	var runAPI []string
	if r.answer.RunAPI != "" {
		runAPI = []string{EnvRunAPI + "=" + r.answer.RunAPI}
	}
	return slices.Concat(runAPI, placeholders(r.answer.Placeholders, keyed{}), kept), nil
}

// checkSetupEnv refuses a setup variable of env by the rules that hold for every
// session of a walled run, each text starting with the fix. A QORY_ name, in any case,
// is [refusal.VariableReserved], QORY_RUN_ID and QORY_RUN_SOCKET among them; only
// QORY_RUN_SYSTEM and QORY_RUN_REPOSITORIES, the server's names a setup command may
// use, are not refused. A name of reserved, the names the machine's credentials are
// read from, is [refusal.VariableReserved] too, and a value for one of placeholders,
// the run's placeholders, is [refusal.PlaceholderConflict]. A name the built-in deny
// list, denied-variables.json, matches is refused with no code, such as LD_PRELOAD or
// HTTPS_PROXY; a credential's name of that list, such as GH_TOKEN, with the fix of
// moving it to the gateway's credentials. The deny entries of a session, Variables.Deny and the runtime's denies,
// apply in [Run.AgentEnv].
func checkSetupEnv(env, placeholders, reserved []string) error {
	checked := names(withoutNames(env, []string{envRunSystem, envRunRepositories}))
	slices.Sort(checked)
	checked = slices.Compact(checked)
	pick := func(keep func(string) bool) []string {
		var out []string
		for _, name := range checked {
			if keep(name) {
				out = append(out, accesskey.ShownName(name, false))
			}
		}
		return out
	}
	// leave is the refusal of names with code, its text the fix and then why: one, with
	// the name in the fix, when names has one name; otherwise many, with the names after
	// it, so the first words of the text are the fix for any number of names.
	leave := func(code string, names []string, one, many string) error {
		r := refusal.New(code, names, "")
		if len(names) == 1 {
			r.Text = "Leave " + names[0] + " out of the setup's variables: " + one + "."
		} else {
			r.Text = "Leave these out of the setup's variables, " + many + ": " + orList(names, ", ", " and ") + "."
		}
		return r
	}
	if qory := pick(func(n string) bool { return strings.HasPrefix(strings.ToUpper(n), "QORY_") }); len(qory) > 0 {
		return leave(refusal.VariableReserved, qory, "the QORY_ names are Forager's", "the QORY_ names are Forager's")
	}
	if machine := pick(func(n string) bool { return slices.Contains(reserved, n) }); len(machine) > 0 {
		return leave(refusal.VariableReserved, machine, "the machine's credentials are read from it", "the machine's credentials are read from them")
	}
	if conflict := pick(func(n string) bool { return slices.Contains(placeholders, n) }); len(conflict) > 0 {
		return leave(refusal.PlaceholderConflict, conflict, "the run's placeholder takes its place", "the run's placeholders take their place")
	}
	deny, err := variables.List(nil)
	if err != nil {
		return err
	}
	builtin, err := variables.Builtin()
	if err != nil {
		return err
	}
	for _, name := range checked {
		if slices.ContainsFunc(builtin.Credentials(), func(c string) bool { return strings.EqualFold(c, name) }) {
			return fmt.Errorf("Move %s to the gateway's credentials in forager.yaml: denied-variables.json lists it as a forge token or a model key, which the setup's variables may not pass into the wall.", accesskey.ShownName(name, false))
		}
		if deny.Matches(name) {
			return fmt.Errorf("Leave %s out of the setup's variables: denied-variables.json lists it.", accesskey.ShownName(name, false))
		}
	}
	return nil
}
