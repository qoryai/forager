package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session/internal/parents"
	"github.com/qoryai/forager/session/internal/socket"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/wall"
)

// exitObserved is called the moment the runtime's exit is observed, once Cancelled is
// decided; a test sets it, and it is nil otherwise.
var exitObserved func()

// SessionsDir is the directory in the run directory that holds a directory per session
// that started, sessions/<n>/ with n the session's number: the session's output.log, its
// PreparationScript and the files its runtime writes, such as Claude Code's
// settings.json. Behind a wall the enclosure binds the session's directory alone,
// read-only.
const SessionsDir = "sessions"

// endedBeforeJoin is what a refusal of a session whose run the gateway closed before
// its runtime started says.
const endedBeforeJoin = "the session did not start: the run has ended already"

// Join runs one session in the open run and returns when the runtime has exited, the
// session's dev.qory.session.exited is written and the gateway accepted it, within 15
// seconds, so the next join may follow. It sends the gateway the join request with the
// names of the variables the session passes a value for and its model key, then checks
// the session's places, prepares the runtime, resolves the variables, writes
// dev.qory.session.started and the session's dev.qory.run.policy_applied, behind a
// wall wraps the launch in the wall that [Open] built, and starts the runtime. Behind
// the Docker wall the wrap writes the docker run of the agent's container, which
// starts with the launch, after the wall step, and the session's end removes it; the
// rest of the wall stays until [Run.Close]. Sessions of one run join one after
// another.
//
// An error means the session did not start. An error before the join request, of a
// spec the session refuses or of a run whose setup step of [Run.Setup] failed, writes
// nothing. A join the gateway refuses with a 403, or that fails the session's checks,
// writes dev.qory.session.exited, failed with -1, the refusal's code as its reason when
// the session decides that code, and duration_ms 0; a refusal with a code is a
// [*Refusal]. A failure in the image or the wall step, such as an image that runs as
// root, an image that cannot be fetched or a launch the wall cannot wrap, writes
// dev.qory.session.started, then dev.qory.session.exited, failed with -1, with the
// refusal's code as its reason when the wall refused with a code the session decides,
// and no reason otherwise; a failure with no reason has its text as a dev.qory.run.log
// chunk of the session on stderr before that dev.qory.session.exited. A docker run of
// the agent's container that fails ends the session with docker's exit status as the
// runtime's.
// The run stays open: what follows is the caller's.
//
// Every dev.qory.run.log, dev.qory.run.resized and dev.qory.runtime.* event of the
// session has the session's number as session.
//
// The join writes its steps, numbered on from the run's last step: the join step, join
// session <n>, from the join request to right before dev.qory.session.started, and,
// behind a wall, the image step, when the policy's image is a reference that no step
// fetched yet ([Run.FetchImage]), and the wall step, up to the launch's start, then a
// setup step for each command of SessionSpec.Setup, from the records of its runner. A
// refused join ends its join step failed with -1 before its dev.qory.session.exited.
// Join returns an error and writes nothing while a host step of [Run.StartStep] is
// open.
//
// A session that starts has a directory in the run directory, sessions/<n>/ with n its
// number ([Result.SessionDir]): its output.log, the bytes of its dev.qory.run.log
// chunks, its PreparationScript and the files its runtime writes. A join that writes
// no dev.qory.session.started leaves no directory there.
//
// Once the runtime runs, its exit is the result and not an error. The context ending
// stops the runtime, and so does the run being closed from outside; a runtime that
// exits 0 at that stop, or at the time limit's, has exited 0, and its
// dev.qory.session.exited is recorded and its Result returned like any other.
func (r *Run) Join(ctx context.Context, spec SessionSpec) (*Result, error) {
	if !r.joining.TryLock() {
		return nil, errors.New("a session of the run is still running: sessions of one run join one after another")
	}
	defer r.joining.Unlock()
	if r.closed {
		return nil, errors.New("the run is closed")
	}
	if r.hostStep != nil {
		return nil, fmt.Errorf("exit step %d before the join: a session does not join during a host step", r.hostStep.n)
	}
	// A wall whose removal failed may still run, with the places its entry lists: a
	// join would rewrite that entry with the join's places alone.
	if r.keptBy > 0 {
		return nil, fmt.Errorf("Open a new run. The wall of session %d could not be removed and may still run, so this run takes no more sessions.", r.keptBy)
	}
	// A run whose setup failed is not set up as its sessions need.
	if r.setupFailed > 0 {
		return nil, fmt.Errorf("Open another run: setup step %d of this run failed, so no session can join it.", r.setupFailed)
	}
	spec = sessionDefaults(spec, r.open.Wall != nil)
	s := runSpec{OpenSpec: r.open, SessionSpec: spec}
	if err := checkVariables(spec.Variables); err != nil {
		return nil, err
	}
	if err := checkHarnessHome(spec.HarnessHome); err != nil {
		return nil, err
	}
	if err := checkHarness(spec.Harness); err != nil {
		return nil, err
	}
	if err := checkSetup(s); err != nil {
		return nil, err
	}
	if err := checkExec(s); err != nil {
		return nil, err
	}
	rt := spec.Runtime
	if rt == nil {
		rt = runtimes.Bare(filepath.Base(spec.Command))
	}
	leave := rt.Stop()
	if err := CheckStopSignal(leave.Signal); err != nil {
		return nil, fmt.Errorf("runtime %s: %w", accesskey.ShownName(rt.Name(), false), err)
	}
	if s.StopSignal == "" {
		s.StopSignal = leave.Signal
	}
	if s.StopGrace == 0 && leave.Grace > 0 {
		s.StopGrace = leave.Grace
	}
	if s.StopSignal == "" {
		s.StopSignal = DefaultStopSignal
	}
	if s.StopGrace == 0 {
		s.StopGrace = DefaultStopGrace
	}
	if s.Timeout < 0 || s.StopGrace < 0 {
		return nil, errors.New("the timeout or the stop grace is negative")
	}
	if err := CheckStopSignal(s.StopSignal); err != nil {
		return nil, err
	}
	// The run's host proxies and its engine proxy end before the join request and the
	// wall's start, so their passwords open nothing while the session runs.
	r.hosts.closeAll()
	r.closeEngine()

	// runCtx ends when the join's context ends or the run is closed from outside: the
	// start stops, or the runtime is stopped as at its time limit.
	runCtx, cancelRun := context.WithCancelCause(ctx)
	defer cancelRun(nil)
	stopFollow := context.AfterFunc(r.closing, func() { cancelRun(errRunClosed) })
	defer stopFollow()
	// The join step spans the join request and the session's checks, up to the
	// session's dev.qory.session.started; the session lies outside it. Its name has the
	// number the gateway gives the next join it answers.
	step := r.startStep(event.StepJoin, fmt.Sprintf("join session %d", r.numbered+1))
	answer, number, err := r.joinRequest(runCtx, s, step)
	var res *Result
	if err == nil {
		res, err = r.session(ctx, runCtx, s, rt, answer, number, step)
	}
	// The next join may follow only once the gateway accepted this session's
	// dev.qory.session.exited, or the run ended.
	flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeWait)
	defer cancel()
	if r.posts.Flush(flushCtx) != nil {
		r.open.Report(fmt.Sprintf("the gateway did not accept the session's last events within %s; the next join may be refused", closeWait))
	}
	return res, err
}

// joinRequest sends the join request and returns the gateway's answer and the
// session's number. A failure ends step, the join step: failed with -1, or cancelled
// with -1 when the run ended. A 403 with a code, numbered by the gateway as the next
// join, writes the refused join's dev.qory.session.exited after it. A 410 ends the
// run. A failure that leaves unknown whether the gateway numbered the join keeps the
// close from writing no_session.
func (r *Run) joinRequest(ctx context.Context, s runSpec, step *Step) (*server.LinkJoinAnswer, int, error) {
	answer, err := r.link.Join(ctx, r.disc.Run.URL, r.id, server.LinkJoinRequest{Passes: passes(s), ModelCredential: s.ModelCredential})
	if err == nil {
		r.numbered = answer.Session
		return answer, answer.Session, nil
	}
	if e, ok := server.Ended(err); ok {
		r.end(e)
		step.end(event.StateCancelled, -1)
		return nil, 0, &Refusal{Code: e.Code, Status: http.StatusGone, From: e.From, Text: endedBeforeJoin}
	}
	var ref *Refusal
	if errors.As(err, &ref) && ref.Status == http.StatusForbidden {
		// The gateway numbers the joins it answers 200 or 403 in the order they arrive,
		// and the run's joins arrive one after another: this one is the next number.
		r.numbered++
		ref.Detail = "the gateway"
		step.end(event.StateFailed, -1)
		r.refusedJoin(r.numbered, ref)
		return nil, 0, ref
	}
	var status *server.StatusError
	if !errors.As(err, &status) && !errors.As(err, &ref) {
		r.maybeJoined = true
	}
	step.end(event.StateFailed, -1)
	return nil, 0, err
}

// refusedJoin writes the dev.qory.session.exited of a join that did not start, n:
// failed with -1 and duration_ms 0, with the refusal's code as the reason when the
// session decides it.
func (r *Run) refusedJoin(n int, err error) {
	exited := map[string]any{"session": n, "state": event.StateFailed, "exit_code": -1, "duration_ms": 0}
	var ref *Refusal
	if errors.As(err, &ref) && refusal.Decides(ref.Code) {
		exited["reason"] = ref.Code
	}
	r.write(event.SessionExited, exited)
}

// session runs the session that joined as number n, from its checks to its
// dev.qory.session.exited. joined is the join step, open: it ends succeeded with -1
// right before dev.qory.session.started, or failed with -1 before the
// dev.qory.session.exited of a join that fails the session's checks.
//
// Behind a wall the session's start has two steps after dev.qory.session.started. The
// image step, when the policy's image is a reference and no step fetched it yet, spans
// the wall's pull and the check of the image's user, wall.Puller. The wall step spans
// the rest: the wall's preparation, its networks, the forwarder, the hook socket, the
// second check of the places and the wall's Wrap, up to the launch's start. Each setup
// command of SessionSpec.Setup then has a setup step, which the session writes from its
// runner's records. The runtime runs in no step. A failure in the image or the wall
// step ends it failed with -1, after the failure's line with the session's number and
// the step's when the failure has no refusal code, and before the session's
// dev.qory.session.exited.
func (r *Run) session(ctx, runCtx context.Context, spec runSpec, rt runtimes.Runtime, answer *server.LinkJoinAnswer, n int, joined *Step) (*Result, error) {
	dir := r.dir
	// sessionDir is the session's directory, made once the session's checks before the
	// runtime's preparation pass. It stays exactly when dev.qory.session.started is
	// written: a failure before that removes it, with what the preparation wrote, and
	// the record has the join's dev.qory.session.exited.
	sessionDir := filepath.Join(dir, SessionsDir, strconv.Itoa(n))
	made := false
	discard := func() {
		if !made {
			return
		}
		if err := r.files.EndSession(); err != nil {
			r.open.Report("closing the session's output.log: " + accesskey.ShownError(err).Error())
		}
		if err := os.RemoveAll(sessionDir); err != nil {
			r.open.Report("removing the directory of a session that did not start: " + accesskey.ShownError(err).Error())
		}
	}
	// started says dev.qory.session.started is written, and start is when; open is the
	// session's step that is open, the join step first, nil for none.
	started := false
	var start time.Time
	open := joined
	endStep := func(state string) {
		if open != nil {
			open.end(state, -1)
			open = nil
		}
	}
	// failWith ends a session that does not start, with its dev.qory.session.exited:
	// the one of a refused join before dev.qory.session.started, and after it failed
	// with -1, with reason as its reason unless reason is empty.
	// A run the gateway closed meanwhile has the gateway's dev.qory.session.exited in
	// its stream already: the session's goes to its record alone, with the state and
	// the reason the run was closed with.
	failWith := func(err error, reason string) (*Result, error) {
		if !started {
			discard()
		}
		if errors.Is(context.Cause(runCtx), errRunClosed) {
			e := r.closedBy.get()
			state, reason := recorded(e)
			exited := map[string]any{"session": n, "state": state, "reason": reason, "exit_code": -1, "duration_ms": 0}
			if started {
				exited["duration_ms"] = time.Since(start).Milliseconds()
			}
			if reason == "" {
				delete(exited, "reason")
			}
			endStep(event.StateCancelled)
			r.own(event.SessionExited, exited)
			r.lastExit = -1
			return nil, &Refusal{Code: e.Code, Status: http.StatusGone, From: e.From, Text: endedBeforeJoin}
		}
		if !started {
			endStep(event.StateFailed)
			r.refusedJoin(n, err)
			return nil, err
		}
		exited := map[string]any{"session": n, "state": event.StateFailed, "exit_code": -1, "duration_ms": time.Since(start).Milliseconds()}
		if reason != "" {
			exited["reason"] = reason
		} else {
			// A failure with no refusal code, such as a pull or the wall's start, has its
			// text in the record as a stderr chunk of the session, and of the step that
			// failed, before its dev.qory.session.exited, which has no reason.
			step := 0
			if open != nil {
				step = open.n
			}
			r.writeLog("stderr", n, step, failureLine(err))
		}
		endStep(event.StateFailed)
		r.write(event.SessionExited, exited)
		r.lastExit = -1
		return nil, err
	}
	fail := func(err error) (*Result, error) { return failWith(err, "") }
	// Behind a wall, a place the session lists that contains one of Forager's files, or
	// that a walled agent of another run still going can change, is a refused join,
	// before anything starts. The run's entry among the walled runs still going lists
	// the session's places until the session ends.
	plan, err := checkMounts(spec, dir, sessionDir)
	if err != nil {
		return fail(err)
	}
	if r.listed != nil {
		if err := r.listed.update(slices.Concat(plan.sources, r.wallOwn, r.setupBinds)); err != nil {
			return fail(err)
		}
		defer func() {
			if !r.listed.kept {
				if err := r.listed.rewrite(r.openBinds); err != nil {
					r.open.Report(accesskey.ShownError(err).Error())
				}
			}
		}()
	}
	// Interactive is what the caller has; interactive is what the session is. An
	// argument the runtime lists as headless means pipes whatever the caller has.
	interactive := spec.Interactive && !rt.Headless(spec.Args)
	// A run whose policy names its image by its reference sees its workspace at
	// /workspace, whatever its path here, and every path Forager puts inside is written
	// as the enclosure sees it. What the server, the session or the machine set is
	// theirs, and left as it is. Any other run sees each place at its path.
	shown, inside := plan, func(s string) string { return s }
	if r.byReference {
		if shown, inside, err = plan.atWorkspace(); err != nil {
			return fail(err)
		}
	}
	// Without a wall the session inherits the starting process's environment, which may
	// contain the variables the machine's credentials are read from: their values stay
	// the gateway's, so the agent's environment has only the placeholders.
	if spec.Wall == nil {
		spec.Env = withoutNames(spec.Env, r.reserved)
	}
	// The runtime chooses the variable of the start key, the API credential the session
	// starts with, the join answer's: from here on it is one of the credential's
	// placeholders and of the run's, and key sets it and the runtime's endpoint variable.
	model := answer.ModelCredential
	if model == "" {
		model = r.answer.ModelCredential
	}
	credentialHosts, placeholderNames, key, err := chosen(rt, r.answer.CredentialHosts, r.answer.Placeholders, model)
	if err != nil {
		return fail(err)
	}
	// The session's directory holds the session's output.log and what the session
	// writes for its runtime, from here on; every log event of the session goes to its
	// output.log as well as to the run's, until the session ends.
	if err := os.MkdirAll(filepath.Join(dir, SessionsDir), 0o755); err != nil {
		return fail(accesskey.ShownError(err))
	}
	if err := os.Mkdir(sessionDir, 0o755); err != nil {
		return fail(accesskey.ShownError(err))
	}
	made = true
	if err := r.files.StartSession(sessionDir); err != nil {
		return fail(err)
	}
	defer func() {
		if err := r.files.EndSession(); err != nil {
			r.open.Report("closing the session's output.log: " + accesskey.ShownError(err).Error())
		}
	}()
	// The runtime prepares the launch before the variables are resolved, because what it
	// sets is Forager's and wins over a server's variable of the same name. Behind a wall
	// the session's directory goes in read-only, apart from every place the session
	// binds, and nothing else of the run directory: the settings are read from it, the
	// record is not the agent's to read or rewrite, and another session's settings are
	// not its to read. The runtime learns whether the run is walled, and the
	// placeholders the run sets, with or without a wall. A file the runtime reads from this machine is refused
	// when a walled run could have written it: one in a place of SessionSpec.Written, in
	// a writable bind of another walled run in the registry or, behind a wall, in a
	// writable bind of this session's. A directory the runtime passes is refused as well
	// when it contains such a place. The places are worked out once, for both.
	written := sync.OnceValues(func() ([]string, error) { return writtenPlaces(spec, r.id, plan, r.wallOwn) })
	prepared := runtimes.Launch{Command: spec.Command, Args: spec.Args}
	attach := runtimes.Attach{Launch: prepared, SessionDir: sessionDir, Forwarder: spec.Forwarder, Interactive: interactive,
		Readable: readable(written), ReadableDir: readableDir(written),
		Walled: spec.Wall != nil, Placeholders: append([]string(nil), placeholderNames...), ModelVariables: key.modelVariables(),
		DeniedVariables: deniedVariables(rt, spec.Wall != nil)}
	if r.byReference {
		attach.Inside = inside
	}
	if prepared, err = rt.Prepare(attach); err != nil {
		return fail(fmt.Errorf("runtime %s: %w", accesskey.ShownName(rt.Name(), false), accesskey.ShownError(err)))
	}
	// The session's setup commands run inside, after the runtime's preparation, and then
	// start the launch as the runtime prepared it.
	if prepared, err = withSetup(sessionDir, spec.SetupRunner, insideSetup(spec.SessionSpec.Setup, inside), prepared); err != nil {
		return fail(err)
	}
	prepared.Command, prepared.Args, prepared.Env = inside(prepared.Command), insideAll(prepared.Args, inside), insideValues(prepared.Env, inside)
	// A value the runtime's preparation sets for one of key.Others is left out, walled
	// or not; behind a wall the name is then unset inside.
	prepared.Env = withoutNames(prepared.Env, key.Others)
	// The harness's values are Forager's to write as the enclosure sees them.
	harness := spec
	harness.LaunchFixed, harness.LaunchDefaults = insideValues(spec.LaunchFixed, inside), insideValues(spec.LaunchDefaults, inside)
	vars, unset, err := resolve(harness, rt, r.answer.Values(), credentialHosts, prepared, placeholderNames, r.reserved, r.img.Docker, r.authority != nil, names(r.caVars), key)
	if err != nil {
		return fail(err)
	}
	// The runtime's other model-key variables do not reach it from the environment the
	// session inherits either, walled or not: it would send their values to the start
	// key's endpoint.
	spec.Env = withoutNames(spec.Env, key.Others)
	ownEnv := []string{EnvRunID + "=" + r.id}
	if spec.HarnessHome != "" {
		ownEnv = append(ownEnv, EnvHarnessHome+"="+inside(spec.HarnessHome))
	}
	if key.Endpoint != "" {
		ownEnv = append(ownEnv, key.Endpoint)
	}
	if err := checkModelKey(harness, rt, credentialHosts, vars, prepared, placeholderNames); err != nil {
		return fail(err)
	}
	if spec.OnVariables != nil {
		spec.OnVariables(applied(vars.Applied))
	}
	// password is what the first request of every connection to an unwalled forwarder
	// must contain, the password of the agent's proxy URL, a secret of this session's
	// forwarder: without a wall the agent's proxy is a port on loopback any process of
	// the machine reaches. The run's masker replaces it, as every forwarder password of
	// the run, in the runtime's output and in its output and hook records before they
	// are events.
	var password string
	if spec.Wall == nil {
		if password, err = newForwarderSecret(); err != nil {
			return fail(err)
		}
		r.masker.AddProxy(proxyUser, password)
	}
	masker := r.masker
	if masker.Empty() {
		masker = nil
	}
	// Behind a wall the run's wall, its forwarder and its relay started as the run
	// opened, and the session's launch starts the agent's container alone. The session starts
	// before the wall step: dev.qory.session.started and the session's policy_applied
	// come first, then the image and wall steps, so a failure of the wall follows the
	// session's dev.qory.session.started.
	var enclosure wall.Enclosure
	var cols, rows int
	if interactive {
		cols, rows = terminalSize(spec.Stdin)
	}
	// The join ends here, and the session starts: every failure of the wall follows
	// the session's start.
	endStep(event.StateSucceeded)
	started, start = true, time.Now()
	r.write(event.SessionStarted, r.sessionStarted(spec, rt, n, prepared, shown, interactive, cols, rows))
	// policyApplied is this session's members of policy_applied: its variables as
	// resolved, the variables its credentials' placeholders are in, and the harness's
	// hosts. Each reload while the session runs records them too.
	sessionMembers := map[string]any{"variables": shownVariables(vars.Applied)}
	if cv := credentialVariables(credentialHosts); cv != nil {
		sessionMembers["credential_variables"] = cv
	}
	if spec.Declared != nil {
		sessionMembers["harness_hosts"] = shownValues(spec.Declared)
	}
	r.emitMu.Lock()
	r.sessionApplied = sessionMembers
	r.record(event.PolicyApplied, r.policyApplied(r.members))
	r.emitMu.Unlock()
	defer r.setApplied(nil)
	if spec.Wall != nil {
		// refused is a failure of the image or the wall step: a refusal's code, such as
		// an image that runs as root, is the reason the session ended; another failure,
		// such as a pull, has no reason.
		refused := func(err error) (*Result, error) {
			var ref *Refusal
			if errors.As(err, &ref) && refusal.Decides(ref.Code) {
				return failWith(err, ref.Code)
			}
			return fail(err)
		}
		// The image step, for an image by reference no step fetched yet, spans the
		// wall's pull and the check of the image's user. After a fetch, the wall finds
		// the image by its digest and the join writes no image step.
		if puller, ok := spec.Wall.(wall.Puller); ok && r.byReference && r.imageStep == 0 {
			open = r.startStep(event.StepImage, r.img.Ref)
			if err := r.pullImage(runCtx, puller); err != nil {
				return refused(err)
			}
			r.imageStep = open.n
			endStep(event.StateSucceeded)
		}
		open = r.startStep(event.StepWall, "start the wall")
		enclosure = r.enclosure
		if u, ok := enclosure.(unwrapper); ok {
			defer func() {
				// The session's context may be what ended it; the agent's container is
				// removed regardless.
				if err := u.Unwrap(context.WithoutCancel(ctx)); err != nil {
					r.open.Report("removing the wall: " + accesskey.ShownError(err).Error())
					// The agent's container may outlive the session: the entry stays, and
					// is the run's while one of the run's containers exists.
					r.listed.keep()
					r.keptBy = n
				}
			}()
		}
	}
	// Behind a wall the run's forwarder passes on what the wall's relay sends. Without
	// one, the session's forwarder on loopback takes a connection only with the
	// password: on one machine it opens the connection to the gateway's proxy with the
	// run's proxy secret, and behind a separate gateway it sends it to the gateway
	// inside TLS, bound, opened with the run key.
	fwd := r.wallFwd
	if spec.Wall == nil {
		if r.remote == nil {
			fwd, err = listenForwarder(link.Loopback, r.disc.Proxy.Address, r.answer.ProxySecret, password)
		} else {
			fwd, err = listenForwarding(link.Loopback, forwarding{dial: r.link.DialProxy, password: password})
		}
		if err != nil {
			return fail(err)
		}
		defer fwd.Close()
	}

	sock, err := socket.Listen(spec.SocketGrace)
	if err != nil {
		return fail(err)
	}
	// An event mapped from a record of the session's runtime has the session's number
	// as session, as each chunk of its output and each resize below has. A record of the
	// setup source is one of the session's setup steps, which the runtime does not map.
	// The terminal gets each setup line the session writes, as it gets the runtime's
	// output: stdout and stderr share one lock, so the two writers never write at once.
	var terminalMu sync.Mutex
	stdout, stderr := &terminalWriter{mu: &terminalMu, w: spec.Stdout}, &terminalWriter{mu: &terminalMu, w: spec.Stderr}
	setupSteps := r.newSetupSteps(n, spec.SessionSpec.Setup, setupTerminal(interactive, stdout, stderr))
	// The mapper is reached from the socket's goroutine and the output's: it sets
	// parent_agent_id on a subagent's start, which it may keep back for a while, and
	// writes every event of the session's runtime in order.
	mapper := parents.New(rt, func(e runtimes.Event) {
		r.write(e.Type, withSession(maskedRecord(masker, e.Data), n))
	}, parents.Real)
	records := func(rec runtimes.Record) {
		if rec.Source == runtimes.SourceSetup {
			setupSteps.handle(rec)
			return
		}
		mapper.Handle(rec)
	}
	go sock.Serve(records, func(err error) { r.open.Report("socket: " + accesskey.ShownError(err).Error()) })
	closeSocket := sync.OnceFunc(func() { sock.Close() })
	defer closeSocket()
	defer mapper.Close()

	command, args := prepared.Command, prepared.Args
	// What is started: the runtime itself, or under a wall the adapter's command that
	// starts it inside, which sets the proxy and socket variables by the addresses the
	// enclosure reaches them on. The environment is what the session inherits, then the
	// variables as resolved, the harness's computed values, what the runtime's
	// preparation sets and Forager's names, each over the ones before, without a wall
	// the variables of the run's bundle, and last the placeholders, so a placeholder wins
	// over a value the session inherits. The resolution has left out every value of a
	// fixed name, so what wins here by position is what the record says. Behind a wall
	// the launch starts through Exec when the session has names to unset, which unsets
	// the runtime's declared, reserved and denied variables, its model overrides and the
	// node's denied ones that nothing sets, so an image's value for one does not reach
	// the runtime; the record lists the launch without it. ownEnv is set before the
	// variables are checked.
	launch := wall.Launch{
		Command: command, Args: args, Dir: spec.Dir,
		Env: environment(spec.Env, vars.Env, vars.Fixed, prepared.Env, fwd.Env(), []string{EnvSocket + "=" + sock.Path()}, ownEnv, r.caVars, placeholders(placeholderNames, key)),
	}
	if enclosure != nil {
		// The places again, just before the enclosure binds them, and the wall's binds,
		// which exist by now, against the walled runs still going; the run's entry then
		// lists them all. No walled agent of this user's can change a directory a name
		// on the way to a place or the session's directory is looked up in, the join's
		// checks
		// saw to that; the user, or a process outside every wall, can. A place that
		// resolves otherwise than at the join, or whose names are looked up in other
		// directories, fails the session; what changes after this point is not seen.
		again, err := checkMounts(spec, dir, sessionDir)
		if err != nil {
			return fail(err)
		}
		if err := samePlan(plan, again); err != nil {
			return fail(err)
		}
		binds, err := wallBinds(enclosure, sock.Path(), r.authority)
		if err != nil {
			return fail(err)
		}
		r.listed.askID(runCtx, spec.Wall)
		if err := r.listed.update(slices.Concat(again.sources, binds, r.wallOwn, r.setupBinds)); err != nil {
			return fail(err)
		}
		inner, innerArgs := withExec(spec.Exec, unset, command, args)
		launch, err = enclosure.Wrap(runCtx, wall.Launch{
			Command: inner, Args: innerArgs, Dir: shown.Dir, Interactive: interactive,
			Env:   environment(spec.Env, vars.Env, vars.Fixed, prepared.Env, ownEnv, placeholders(placeholderNames, key)),
			CA:    r.authority,
			Proxy: fwd.Addr(), Socket: sock.Path(), Mounts: shown.Mounts, Limits: spec.Limits,
			ProxyToken: r.relayToken,
		})
		if err != nil {
			return fail(accesskey.ShownError(err))
		}
	}

	// A run closed during the join's start does not start the runtime: the start's steps
	// run under runCtx, and whatever they reached ends here.
	if errors.Is(context.Cause(runCtx), errRunClosed) {
		return fail(errRunClosed)
	}
	// The wall step ends as the launch starts: the setup commands, each in its setup
	// step, then the runtime, which runs in no step.
	endStep(event.StateSucceeded)
	logs := func(stream string) func([]byte) {
		return func(b []byte) {
			r.write(event.RunLog, map[string]any{"stream": stream, "bytes": encode(b), "session": n})
		}
	}
	output := func(m map[string]any) { records(runtimes.Record{Source: runtimes.SourceOutput, Record: m}) }
	if !rt.ReadsOutput() {
		output = nil
	}
	resized := func(cols, rows int) {
		r.write(event.RunResized, map[string]any{"cols": cols, "rows": rows, "session": n})
	}
	proc := &process{stop: runtimes.StopSignal(spec.StopSignal), grace: spec.StopGrace, command: launch.Command, args: launch.Args, env: launch.Env, dir: launch.Dir, stdin: spec.Stdin, stdout: stdout, stderr: stderr, logs: logs, masker: masker, output: output, cols: cols, rows: rows, resized: resized}
	// The limit ends the runtime and nothing else: the wall is closed on the caller's
	// context, as after any exit. The run being closed from outside ends it the same
	// way.
	limited, cancelLimit := context.WithCancel(runCtx)
	if spec.Timeout > 0 {
		limited, cancelLimit = context.WithTimeoutCause(runCtx, spec.Timeout, errTimeout)
	}
	// Whether the session was cancelled, and whether it timed out, is decided the moment
	// the runtime's exit is observed. Cancelled: the caller's context had ended by then,
	// and neither the limit nor the gateway's close had ended the runtime's context
	// first; the first end is the cause. Timed out: the limit ended it first, and its
	// stop signal reached the runtime before the exit was observed; a runtime that
	// exited by itself before that signal, whatever its status, is decided by its exit.
	// What ends the context later changes nothing.
	var cancelled, timedOut bool
	proc.exited = func() {
		cause := context.Cause(limited)
		cancelled = ctx.Err() != nil && !errors.Is(cause, errTimeout) && !errors.Is(cause, errRunClosed)
		timedOut = errors.Is(cause, errTimeout) && proc.stopped.Load()
		if exitObserved != nil {
			exitObserved()
		}
	}
	// The setup's records are recorded once the launch starts; a command that exits
	// otherwise than 0 once the session stops the launch, at the limit, the context's
	// end or the run's close, was cancelled. The end of limited once the launch exited
	// is no stop.
	setupSteps.start(func() bool {
		return errors.Is(context.Cause(limited), errTimeout) || ctx.Err() != nil || errors.Is(context.Cause(runCtx), errRunClosed)
	})
	var exit exitStatus
	if interactive {
		exit, err = proc.runPTY(limited)
	} else {
		exit, err = proc.runPipes(limited)
	}
	// A run closed from outside has nothing further posted, whatever the runtime's
	// status.
	closed := errors.Is(context.Cause(runCtx), errRunClosed)
	cancelLimit()
	closeSocket()
	// The events the mapper still keeps back come before the session's exit.
	mapper.Close()
	// A setup step still open when the launch ended has no exit status.
	setupSteps.finish(closed || timedOut || cancelled)
	if err != nil && !closed {
		r.write(event.SessionExited, map[string]any{"session": n, "state": event.StateFailed, "exit_code": -1, "duration_ms": time.Since(start).Milliseconds()})
		r.lastExit = -1
		return nil, err
	}
	// A runtime the close kept from starting has no status: the session ends as a
	// closed one, with -1.
	if err != nil {
		exit = exitStatus{code: -1}
	}
	state, reason := event.StateFailed, ""
	switch {
	case closed:
		state, reason = recorded(r.closedBy.get())
	case timedOut:
		// The time limit stopped the runtime before it said how it went.
		state, reason = event.StateCancelled, event.ReasonTimeout
	case cancelled:
		// It was stopped from where it was started, a Ctrl-C, before it said how it went.
		state, reason = event.StateCancelled, event.ReasonInterrupted
	case exit.code == 0:
		state = event.StateSucceeded
	}
	exited := map[string]any{"session": n, "state": state, "exit_code": exit.code, "duration_ms": time.Since(start).Milliseconds()}
	if exit.signal != "" {
		exited["signal"] = exit.signal
	}
	if reason != "" {
		exited["reason"] = reason
	}
	r.lastExit = exit.code
	if closed {
		// The session was open at the gateway's 410: it has no exit status in the run's
		// record.
		r.lastExit = -1
	}
	res := &Result{RunID: r.id, Dir: dir, SessionDir: sessionDir, Session: n, ExitCode: exit.code, Signal: exit.signal, State: state, Reason: reason, TimedOut: timedOut && !closed, Cancelled: cancelled, RunClosed: closed}
	switch {
	case closed:
		// The gateway wrote the session's dev.qory.session.exited in its stream when it
		// ended the run: the session records it with the state and the reason the run
		// was closed with, and -1, in its record alone.
		res.ClosedReason = r.closedBy.get().Code
		delete(exited, "signal")
		exited["exit_code"] = -1
		r.own(event.SessionExited, exited)
	case timedOut:
		r.open.Report(fmt.Sprintf("the runtime was stopped at the limit of %s", spec.Timeout))
		r.write(event.SessionExited, exited)
	default:
		r.write(event.SessionExited, exited)
	}
	return res, nil
}

// sessionStarted is the data of the session's dev.qory.session.started. A value of the
// session's that contains qak_ or qrk_ in any case is sent as a phrase in its place:
// accesskey.ShownName's for the runtime, the image, its name and its container
// runtime; accesskey.ShownValue's for the directory, the command, each argument, the
// runtime's version, the name of each setup command and each harness source.
func (r *Run) sessionStarted(spec runSpec, rt runtimes.Runtime, n int, prepared runtimes.Launch, shown mountPlan, interactive bool, cols, rows int) map[string]any {
	started := map[string]any{
		"session": n, "runtime": accesskey.ShownName(rt.Name(), false), "command": accesskey.ShownValue(prepared.Command, false), "args": shownValues(prepared.Args),
		"dir": accesskey.ShownValue(spec.Dir, false), "interactive": interactive,
	}
	if r.byReference {
		started["dir"] = accesskey.ShownValue(shown.Dir, false)
	}
	if v := rt.Version(); v != "" {
		started["runtime_version"] = accesskey.ShownValue(v, false)
	}
	if setup := spec.SessionSpec.Setup; len(setup) > 0 {
		names := make([]string, len(setup))
		for i, c := range setup {
			names[i] = c.Name
		}
		started["setup_commands"] = shownValues(names)
	}
	// The pseudo-terminal's size is in the record, so a replay can lay the redraws of
	// a full-screen program over each other: the size it starts with here, each change
	// as run.resized.
	if interactive {
		started["terminal"] = map[string]any{"cols": cols, "rows": rows}
	}
	if spec.Wall != nil {
		started["image"] = accesskey.ShownName(r.img.Ref, false)
		if r.img.Name != "" {
			started["image_name"] = accesskey.ShownName(r.img.Name, false)
		}
		if r.img.Runtime != "" {
			started["container_runtime"] = accesskey.ShownName(r.img.Runtime, false)
		}
		if r.img.Docker {
			started["docker"] = true
		}
	}
	if len(spec.Harness) > 0 {
		harness := make([]map[string]any, len(spec.Harness))
		for i, h := range spec.Harness {
			harness[i] = map[string]any{"source": accesskey.ShownValue(h.Source, false), "commit": h.Commit}
		}
		started["harness"] = harness
	}
	return started
}
