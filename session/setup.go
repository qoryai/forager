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
type setupContainer interface {
	StartSetup(ctx context.Context, l wall.Launch) error
	ExecSetup(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error)
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
// the run's image on the wall's internal network, which runs until [Run.Close]. It runs
// once per walled run, before the first join and outside every host step. The agent
// reaches the setup container by the name qory-setup, so a service that a setup command
// starts stays reachable by that name, such as qory-setup:5432. A service sends its
// output to a file, so its command returns.
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
// variables, the run's placeholders, and then Env, which a caller fills from
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
// starts no setup container. A setup command that exits otherwise than 0 ends its step
// failed with its exit status and returns a [*SetupError]. Any other failure in a step
// ends the step failed, or cancelled when ctx ended, with -1, after its line, and is the
// error. After a step that fails no later step starts, and no session joins the run.
func (r *Run) Setup(ctx context.Context, spec SetupSpec) error {
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
		return fmt.Errorf("Run the setup behind the Docker wall: the %s wall starts no setup container.", accesskey.ShownName(r.open.Wall.Name(), false))
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
		// The setup container runs until the run closes: each join lists its binds with
		// the session's, and each session's end rewrites the run's entry with them.
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

// setupEnv is the part of the setup container's environment that comes after the
// wall's variables: the run's placeholders, then env, which [checkSetupEnv] checks
// first, without the access key's variables and QORY_RUN_KEY. A
// value is refused when it contains, in a form the run's masker replaces, the password
// of one of the run's forwarders or of OpenSpec.EngineProxy: the run's masker gets the
// engine proxy's password only in the image step, which comes after this check.
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
		if r.masker.Replace(value) != value || engine.Replace(value) != value {
			return nil, fmt.Errorf("Leave the host proxy's URL out of the setup's variables: %s contains its password, which the setup container never gets.", accesskey.ShownName(name, false))
		}
	}
	return append(placeholders(r.answer.Placeholders, keyed{}), kept...), nil
}

// checkSetupEnv refuses a setup variable of env that the agent of the run could not
// get, by the rules that hold for every session of a walled run, as [variables.Check]
// refuses them for a join: a value for one of placeholders, the run's placeholders, is
// [refusal.PlaceholderConflict], and a QORY_ name or one of reserved, the names the
// machine's credentials are read from, is [refusal.VariableReserved]. QORY_RUN_SYSTEM
// and QORY_RUN_REPOSITORIES, the server's names a setup command may use, are not
// refused. A name the built-in deny list, denied-variables.json, matches is refused
// too, such as LD_PRELOAD or HTTPS_PROXY: a join leaves its value out of the agent's
// environment. The deny entries of a session, Variables.Deny and the runtime's denies,
// apply in [Run.AgentEnv].
func checkSetupEnv(env, placeholders, reserved []string) error {
	checked := withoutNames(env, []string{envRunSystem, envRunRepositories})
	if err := variables.Check(checked, true, placeholders, reserved); err != nil {
		return err
	}
	deny, err := variables.List(nil)
	if err != nil {
		return err
	}
	for _, name := range names(checked) {
		if deny.Matches(name) {
			return fmt.Errorf("Leave %s out of the setup's variables: the deny list, denied-variables.json, leaves it out of the agent's environment.", accesskey.ShownName(name, false))
		}
	}
	return nil
}
