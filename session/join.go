package session

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session/internal/parents"
	"github.com/qoryai/forager/session/internal/socket"
	"github.com/qoryai/forager/session/internal/variables"
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
// open, apart from one case: a session with no runtime (SessionSpec.Runtime nil) joins
// during a copy step (event.StepCopy). Its steps then start and end inside the copy
// step, and the copy step stays open until the caller exits it.
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
//
// The run's masker replaces the run's secrets in the error's text and in a refusal's,
// and errors.As gives a refusal's masked copy with its code.
func (r *Run) Join(ctx context.Context, spec SessionSpec) (*Result, error) {
	res, err := r.join(ctx, spec)
	return res, maskError(r.masker, err)
}

// join is Join with its error as the session made it, unmasked.
func (r *Run) join(ctx context.Context, spec SessionSpec) (*Result, error) {
	if !r.joining.TryLock() {
		return nil, errors.New("a session of the run is still running: sessions of one run join one after another")
	}
	defer r.joining.Unlock()
	if r.closed {
		return nil, errors.New("the run is closed")
	}
	// A session with no runtime, such as the caller's copy of the work out of the wall,
	// joins during a copy step, and the join's steps start and end inside that step.
	if h := r.hostStep; h != nil {
		if h.kind != event.StepCopy {
			return nil, fmt.Errorf("exit step %d before the join: a session does not join during a host step", h.n)
		}
		if spec.Runtime != nil {
			return nil, fmt.Errorf("exit step %d before the join: only a session with no runtime joins during a copy step", h.n)
		}
	}
	// A wall whose removal failed may still run, with the places its entry lists: a
	// join would rewrite that entry with the join's places alone.
	if err := r.wallKept(); err != nil {
		return nil, err
	}
	// A run whose setup failed is not set up as its sessions need.
	if r.setupFailed > 0 {
		return nil, fmt.Errorf("Open another run: setup step %d of this run failed, so no session can join it.", r.setupFailed)
	}
	s, rt, err := r.checkSession(spec)
	if err != nil {
		return nil, err
	}
	// The session may reach the run's forwarder from here on.
	r.shutCheck(errCheckAfterJoin, false)
	// The run's host proxies and its engine proxy end before the join request and the
	// wall's start, so their passwords open nothing while the session runs. The join
	// request closes the run's stack proxy at the gateway.
	r.hosts.closeAll()
	r.closeEngine()
	r.joinAsked.Store(true)

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

// checkSession is the spec of a session of the run with its defaults filled, and its
// runtime, after the checks a join runs before the join request: the variables, the
// harness's home and sources, the read-only workspace, the setup, the helper's exec and
// the stop signal and grace. It writes nothing and sends nothing.
func (r *Run) checkSession(spec SessionSpec) (runSpec, runtimes.Runtime, error) {
	spec = sessionDefaults(spec, r.open.Wall != nil)
	s := runSpec{OpenSpec: r.open, SessionSpec: spec}
	if err := checkVariables(spec.Variables); err != nil {
		return runSpec{}, nil, err
	}
	if err := checkHarnessHome(spec.HarnessHome); err != nil {
		return runSpec{}, nil, err
	}
	if err := checkInputsDir(spec.InputsDir); err != nil {
		return runSpec{}, nil, err
	}
	if r.remote != nil {
		if err := checkNeutral(spec); err != nil {
			return runSpec{}, nil, err
		}
	}
	if err := checkHarness(spec.Harness); err != nil {
		return runSpec{}, nil, err
	}
	if err := checkWorkspaceReadOnly(s); err != nil {
		return runSpec{}, nil, err
	}
	if err := checkSetup(s); err != nil {
		return runSpec{}, nil, err
	}
	if err := checkExec(s); err != nil {
		return runSpec{}, nil, err
	}
	rt := spec.Runtime
	if rt == nil {
		// A session with no runtime has no start key, so it names none.
		if spec.ModelCredential != "" {
			return runSpec{}, nil, fmt.Errorf("set SessionSpec.Runtime, or leave SessionSpec.ModelCredential empty: a session with no runtime starts with no model key, and the spec names the model key %s",
				accesskey.ShownName(spec.ModelCredential, true))
		}
		rt = runtimes.Bare(filepath.Base(spec.Command))
	}
	leave := rt.Stop()
	if err := CheckStopSignal(leave.Signal); err != nil {
		return runSpec{}, nil, fmt.Errorf("runtime %s: %w", accesskey.ShownName(rt.Name(), false), err)
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
		return runSpec{}, nil, errors.New("the timeout or the stop grace is negative")
	}
	if err := CheckStopSignal(s.StopSignal); err != nil {
		return runSpec{}, nil, err
	}
	return s, rt, nil
}

// joinRequest sends the join request and returns the gateway's answer and the
// session's number. Behind a separate gateway a try with no answer, or a 503 with no
// code, is sent again, [Run.tryJoin]. A failure ends step, the join step: failed with
// -1, or cancelled with -1 when the run ended. A 403 with a code, numbered by the
// gateway as the next join, writes the refused join's dev.qory.session.exited after
// it. A 410 ends the run. A failure that leaves unknown whether the gateway numbered
// the join keeps the close from writing no_session. The request asks the gateway to
// set no model key for a session with no runtime, which has no start key.
func (r *Run) joinRequest(ctx context.Context, s runSpec, step *Step) (*server.LinkJoinAnswer, int, error) {
	answer, unanswered, err := r.tryJoin(ctx, server.LinkJoinRequest{Passes: passes(s), ModelKey: s.Runtime != nil, ModelCredential: s.ModelCredential})
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
	// A try with no answer, an answer document that fails the session's checks, or an
	// answer under a key the run key does not name may follow a join the gateway
	// numbered.
	var status *server.StatusError
	if unanswered || !errors.As(err, &status) && !errors.As(err, &ref) {
		r.maybeJoined = true
	}
	step.end(event.StateFailed, -1)
	return nil, 0, err
}

// tryJoin sends the join request req. Behind a separate gateway, which may be
// restarting, it sends the request again while a try gets no answer ([joinUnanswered])
// or a 503 with no code, for up to joinWindow, with joinWaits between the tries
// ([Run.pauseJoin]). It returns the last try's answer or error, and unanswered when any
// try got no answer, which leaves unknown whether the gateway numbered the join. The
// context ending stops the tries.
//
// A try that got no answer may have reached the gateway, which then numbered the join.
// The tries rely on the gateway's answer to a join request equal to the last one it
// numbered, whose session has neither started nor exited: the same answer again, 200
// with the same session number and model key or 403 with the same refusal, and
// nothing numbered anew.
//
// On the local link the gateway runs in qory's process and a try fails only when that
// gateway is gone, so the request is sent once.
func (r *Run) tryJoin(ctx context.Context, req server.LinkJoinRequest) (*server.LinkJoinAnswer, bool, error) {
	window, cancel := context.WithTimeout(ctx, joinWindow)
	defer cancel()
	unanswered := false
	for i := 0; ; i++ {
		answer, err := r.link.Join(ctx, r.disc.Run.URL, r.id, req)
		if err == nil {
			return answer, unanswered, nil
		}
		none := joinUnanswered(err)
		unanswered = unanswered || none
		var status *server.StatusError
		busy := errors.As(err, &status) && status.Status == http.StatusServiceUnavailable && status.Code == ""
		if r.remote == nil || ctx.Err() != nil || !none && !busy {
			return nil, unanswered, err
		}
		var ok bool
		if i, ok = r.pauseJoin(window, i); !ok {
			return nil, unanswered, err
		}
	}
}

// pauseJoin waits the i-th of joinWaits, the last one repeated, then flushes the
// session's batches, so the previous session's dev.qory.session.exited reaches the
// gateway before the join. A flush that has not returned after the next wait is called
// again: each call ends the link sink's wait between two tries of a batch, so a gateway
// back after a restart gets the batch within one wait, not up to sink.MaxBackoff
// later. It returns the index of the last wait, and false when the window ends first.
func (r *Run) pauseJoin(window context.Context, i int) (int, bool) {
	wait := func(i int) time.Duration { return joinWaits[min(i, len(joinWaits)-1)] }
	t := time.NewTimer(wait(i))
	defer t.Stop()
	select {
	case <-t.C:
	case <-window.Done():
		return i, false
	}
	for {
		flushCtx, cancel := context.WithTimeout(window, wait(i+1))
		err := r.posts.Flush(flushCtx)
		cancel()
		if err == nil {
			return i, true
		}
		if window.Err() != nil {
			return i, false
		}
		i++
	}
}

// joinUnanswered reports whether a join request's error is a try that got no answer:
// a connection that did not open, its TLS or its binding failing, a connection reset,
// or no answer in time. An answer is a 410, a refusal with a code, a status, an answer
// document that fails the session's checks, or a separate gateway's answer under a key
// the run key does not name.
func joinUnanswered(err error) bool {
	var key *server.GatewayKeyError
	if errors.As(err, &key) {
		return key.Unproven
	}
	var ref *Refusal
	var status *server.StatusError
	var doc *server.DocumentError
	return !errors.As(err, &ref) && !errors.As(err, &status) && !errors.As(err, &doc)
}

// wallKept is the error of a call that must not run beside the wall of a session whose
// removal failed, nil for a run with no such wall: [Run.Join], since the wall may still
// run, and [Run.HostProxy], since the agent's container may still change what a push
// sends. A timed-out or cancelled session ends by killing the docker client, which does
// not prove the container stopped.
func (r *Run) wallKept() error {
	if r.keptBy > 0 {
		return fmt.Errorf("Open a new run. The wall of session %d could not be removed and may still run, so this run takes no more sessions.", r.keptBy)
	}
	return nil
}

// refusedJoin writes the dev.qory.session.exited of a join that did not start, n:
// failed with -1 and duration_ms 0, with the refusal's code as the reason when the
// session decides it.
func (r *Run) refusedJoin(n int, err error) {
	exited := map[string]any{"session": n, "state": event.StateFailed, "exit_code": -1, "duration_ms": 0}
	r.lastReason = ""
	var ref *Refusal
	if errors.As(err, &ref) && refusal.Decides(ref.Code) {
		exited["reason"] = ref.Code
		r.lastReason = ref.Code
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
// the check of the image's manifest at its registry, the wall's pull and the check of
// the image's user, wall.Puller. The wall step spans
// the rest: the wall's preparation, its networks, the forwarder, the hook socket, the
// second check of the places and the wall's Wrap, up to the launch's start. Each setup
// command of SessionSpec.Setup then has a setup step, which the session writes from its
// runner's records. The runtime runs in no step. The command of a session with no
// runtime that joins during a copy step runs while that step is open. A failure in the
// image or the wall step ends it failed with -1, after the failure's line with the
// session's number and the step's when the failure has no refusal code, and before the
// session's dev.qory.session.exited.
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
	// neutral and neutralText write what the session writes after its
	// dev.qory.session.started: as it is, or in a run with a run key with the
	// placeholders of neutralPaths, and in neutralText the working directory as
	// /workspace as well.
	neutral, neutralText := func(s string) string { return s }, func(s string) string { return s }
	// hidden masks the text of a hidden harness in what the session reports, once the
	// session has read the harness's files; nil until then, and for a harness not hidden.
	var hidden *mask.Harness
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
			r.lastExit, r.lastReason = -1, reason
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
			r.writeLog("stderr", n, step, []byte(neutral(hidden.Replace(string(failureLine(err))))))
		}
		endStep(event.StateFailed)
		r.write(event.SessionExited, exited)
		r.lastExit, r.lastReason = -1, reason
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
	markSetup(plan.sources, r.setupUp != nil)
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
	// A session whose spec has no runtime has no start key.
	model := answer.ModelCredential
	if model == "" {
		model = r.answer.ModelCredential
	}
	credentialHosts, placeholderNames, key, err := chosen(rt, spec.Runtime == nil, r.answer.CredentialHosts, r.answer.Placeholders, model)
	if err != nil {
		return fail(err)
	}
	// A run whose harness is hidden masks the text of the harness's files, as they are
	// at this point, in what the session reports.
	if r.open.HarnessHidden && spec.HarnessHome != "" {
		if hidden, err = readHarness(spec.HarnessHome, r.open.Report); err != nil {
			return fail(err)
		}
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
	// Behind a wall, a runtime with resume gets the session's transcript directory,
	// transcripts/<n>/ in the run directory, which the wall binds writable at
	// resume.prefix inside: the session reads the transcript, and writes a restored one,
	// there. It lies outside every place the enclosure binds.
	var transcriptDir, transcriptUnder string
	if spec.Wall != nil {
		if transcriptDir, transcriptUnder, err = makeTranscriptDir(rt, dir, n, spec.Dir, slices.Concat(plan.sources, r.wallOwn, r.setupBinds)); err != nil {
			return fail(err)
		}
	}
	// The runtime prepares the launch before the variables are resolved, because what it
	// sets is Forager's and wins over a server's variable of the same name. Behind a wall
	// the session's directory goes in read-only, apart from every place the session
	// binds, and nothing else of the run directory: the settings are read from it, the
	// record is not the agent's to read or rewrite, and another session's settings are
	// not its to read. The runtime learns whether the run is walled, and the
	// placeholders the run sets, with or without a wall. A file the runtime reads from this machine is refused
	// when a walled run could have written it: one in a place of SessionSpec.Written, in
	// a writable bind of another walled run in the registry or, behind a wall, in the
	// workspace, in a writable bind of this session's or in one of the setup container's.
	// A directory the runtime passes is refused as well when it contains such a place. The places are worked out once, for both.
	written := sync.OnceValues(func() ([]string, error) {
		return writtenPlaces(spec, r.id, plan, slices.Concat(r.wallOwn, r.setupBinds))
	})
	prepared := runtimes.Launch{Command: spec.Command, Args: spec.Args}
	denied, err := deniedVariables(rt, spec.Wall != nil)
	if err != nil {
		return fail(err)
	}
	attach := runtimes.Attach{Launch: prepared, SessionDir: sessionDir, Forwarder: spec.Forwarder, Interactive: interactive,
		Readable: readable(written), ReadableDir: readableDir(written),
		Walled: spec.Wall != nil, Placeholders: append([]string(nil), placeholderNames...), ModelVariables: key.modelVariables(),
		DeniedVariables: denied}
	if r.byReference {
		attach.Inside = inside
	}
	if prepared, err = rt.Prepare(attach); err != nil {
		return fail(fmt.Errorf("runtime %s: %w", accesskey.ShownName(rt.Name(), false), accesskey.ShownError(err)))
	}
	// The run's first session whose runtime has resume continues the runtime session of
	// the paused run in the run answer's resume: the launch writes its transcript under
	// the runtime's home and resumes it. A failure starts the runtime without a resume,
	// with resumeLine on stderr once the session started.
	prepared, resumeLine, restore := r.resumeLaunch(runCtx, rt, sessionDir, spec.Wall != nil, transcriptDir, inside, prepared)
	// The session's setup commands run inside, after the runtime's preparation, and then
	// start the launch as the runtime prepared it.
	if prepared, err = withSetup(sessionDir, spec.SetupRunner, insideSetup(spec.SessionSpec.Setup, inside), prepared); err != nil {
		return fail(err)
	}
	prepared.Command, prepared.Args, prepared.Env = inside(prepared.Command), insideAll(prepared.Args, inside), insideValues(prepared.Env, inside)
	if r.remote != nil {
		neutral = r.neutralPaths(spec.HarnessHome, spec.InputsDir, "", inside)
		neutralText = r.neutralPaths(spec.HarnessHome, spec.InputsDir, spec.Dir, inside)
	}
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
	// A session without a wall may inherit QORY_RUN_API from another run: this run's value
	// replaces it, and a run with no control plane has none. Behind a wall the value is
	// variable_reserved, when the variables are resolved.
	if spec.Wall == nil {
		spec.Env = withoutNames(spec.Env, []string{EnvRunAPI})
	}
	ownEnv := []string{EnvRunID + "=" + r.id}
	if r.answer.RunAPI != "" {
		ownEnv = append(ownEnv, EnvRunAPI+"="+r.answer.RunAPI)
	}
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
	for _, line := range leftOutCredentials(vars.Applied, prepared.LeftOut, placeholderNames, key.modelVariables()) {
		r.open.Report(line)
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
		r.addPassword(password)
	}
	// The session masks with the run's masker even while it is empty: a reload may add
	// a server's variable value to it while the session runs.
	masker := r.masker
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
	r.write(event.SessionStarted, r.sessionStarted(spec, rt, n, prepared, shown, neutral, interactive, cols, rows))
	if resumeLine != "" {
		r.writeLog("stderr", n, 0, []byte(neutral(resumeLine)+"\n"))
	}
	if r.remote != nil {
		r.open.Report(r.launchLine(spec, n, prepared))
	}
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
	r.record(event.PolicyApplied, r.policyApplied(withoutHarness(r.members)))
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
		// check of the image's manifest, the wall's pull and the check of its user. After a fetch, the wall finds
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
					r.wallFailed.Store(true)
				}
			}()
		} else if enclosure != nil {
			// With no Unwrap the agent's container stays until the close, and may still
			// run and write the run's binds after the session ended.
			defer r.unwrapless.Store(true)
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
			fwd, err = listenForwarding(link.Loopback, forwarding{dial: r.link.DialProxy, hold: gatewayHold, password: password})
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
	setupSteps := r.newSetupSteps(n, spec.SessionSpec.Setup, setupTerminal(interactive, stdout, stderr), neutral, hidden)
	// The mapper is reached from the socket's goroutine and the output's: it sets
	// parent_agent_id on a subagent's start, which it may keep back for a while, and
	// writes every event of the session's runtime in order. Each event is masked first,
	// then cut and given its summary (shapedRecord), so a cut never splits a secret
	// before the masker sees it whole.
	summaries, _ := rt.(runtimes.Summaries)
	// tr sends the runtime's transcript, for a runtime with resume; nil otherwise.
	var tr *transcript
	mapper := parents.New(rt, func(e runtimes.Event) {
		if tr != nil && e.Type == "dev.qory.runtime.started" {
			if id, ok := e.Data["session_id"].(string); ok {
				tr.started(id)
			}
		}
		masked := maskedRecord(texts{secrets: masker, harness: hidden}, e.Data)
		r.write(e.Type, withSession(neutralRecord(e.Type, shapedRecord(e.Type, masked, summaries), neutralText), n))
	}, parents.Real)
	// A record of the measure source is the enclosure's peak memory and CPU time, which
	// the helper's exec sends as the runtime exits. Only the launch reaches this socket:
	// the session opens it for this launch alone, the setup container gets no socket,
	// and host steps run outside the enclosure. The last record read before the socket
	// is drained counts, and only behind a wall: without one there is no enclosure.
	var measureMu sync.Mutex
	var measure map[string]any
	records := func(rec runtimes.Record) {
		switch rec.Source {
		case runtimes.SourceSetup:
			setupSteps.handle(rec)
			return
		case runtimes.SourceMeasure:
			if spec.Wall != nil {
				measureMu.Lock()
				measure = measured(rec.Record)
				measureMu.Unlock()
			}
			return
		}
		if tr != nil {
			tr.record(rec)
		}
		mapper.Handle(rec)
	}
	go sock.Serve(records, func(err error) { r.open.Report("socket: " + accesskey.ShownError(err).Error()) })
	closeSocket := sync.OnceFunc(func() { sock.Close() })
	defer closeSocket()
	defer mapper.Close()

	// The environment the enclosure's launch gets, below.
	wrapEnv := environment(spec.Env, vars.Env, vars.Fixed, prepared.Env, ownEnv, placeholders(placeholderNames, key))
	// Behind a wall the enclosure works out, once the image is there, whether it binds
	// the session's transcript directory where the agent's user can write it. When it
	// does not, the session binds no directory, takes off the resume arguments it added,
	// sends no transcript and writes one line, and with a restored transcript a second
	// one: the runtime starts without a resume.
	if checker, ok := enclosure.(wall.TranscriptChecker); ok && transcriptDir != "" {
		unbound, err := checker.CheckTranscript(runCtx, wrapEnv, wall.Transcript{Path: transcriptDir, Under: transcriptUnder})
		if err != nil {
			return fail(accesskey.ShownError(err))
		}
		if unbound != nil {
			transcriptDir, transcriptUnder = "", ""
			if restore != nil {
				added := insideAll(restore.args, inside)
				if !slices.Equal(prepared.Args[max(len(prepared.Args)-len(added), 0):], added) {
					return fail(errors.New(resumeArgsKept(unbound.Fix, unbound.Cause)))
				}
				prepared.Args = prepared.Args[:len(prepared.Args)-len(added)]
				r.writeLog("stderr", n, 0, []byte(neutral(resumeFailed(r.answer.Resume.RunID, unbound.Fix, unbound.Cause))+"\n"))
				restore = nil
			}
			r.writeLog("stderr", n, 0, []byte(neutral(noResume(unbound.Fix, unbound.Cause))+"\n"))
		}
	}
	command, args := prepared.Command, prepared.Args
	// What is started: the runtime itself, or under a wall the adapter's command that
	// starts it inside, which sets the proxy and socket variables by the addresses the
	// enclosure reaches them on. The environment is what the session inherits, then the
	// variables as resolved, the harness's computed values, what the runtime's
	// preparation sets and Forager's names, each over the ones before, without a wall
	// the variables of the run's bundle, and last the placeholders, so a placeholder wins
	// over a value the session inherits. The resolution has left out every value of a
	// fixed name, so what wins here by position is what the record says. Behind a wall
	// every launch starts through Exec, which unsets the runtime's declared, reserved
	// and denied variables, its model overrides and the node's denied ones that nothing
	// sets, so an image's value for one does not reach the runtime, and which measures
	// the enclosure when the runtime exits; the record lists the launch without it.
	// ownEnv is set before the variables are checked.
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
		markSetup(again.sources, r.setupUp != nil)
		if err := samePlan(plan, again); err != nil {
			return fail(err)
		}
		binds, err := wallBinds(enclosure, sock.Path(), r.authority, wall.Transcript{Path: transcriptDir, Under: transcriptUnder})
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
			Env:   wrapEnv,
			CA:    r.authority,
			Proxy: fwd.Addr(), Socket: sock.Path(), Mounts: shown.Mounts, Limits: spec.Limits,
			ProxyToken: r.relayToken,
			Transcript: wall.Transcript{Path: transcriptDir, Under: transcriptUnder},
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
	// step, then the runtime, which runs in none of the join's steps.
	endStep(event.StateSucceeded)
	logs := func(stream string) func([]byte) {
		return func(b []byte) {
			r.write(event.RunLog, map[string]any{"stream": stream, "bytes": encode(b), "session": n})
		}
	}
	output := func(m map[string]any, line int) {
		records(runtimes.Record{Source: runtimes.SourceOutput, Record: m, Line: line})
	}
	if !rt.ReadsOutput() {
		output = nil
	}
	resized := func(cols, rows int) {
		r.write(event.RunResized, map[string]any{"cols": cols, "rows": rows, "session": n})
	}
	trDir := spec.Dir
	if spec.Wall != nil {
		trDir = shown.Dir
	}
	tr = r.sessionTranscript(rt, n, spec.Wall != nil, transcriptDir, launch.Env, trDir, masker, hidden, restore)
	// The transcript's reads end before the join returns, on every path: the end of
	// the runtime below, and a panic in between.
	endTranscript := func() {}
	if tr != nil {
		endTranscript = tr.start(cmp.Or(spec.transcriptPoll, transcriptPoll))
	}
	defer endTranscript()
	proc := &process{stop: runtimes.StopSignal(spec.StopSignal), grace: spec.StopGrace, command: launch.Command, args: launch.Args, env: launch.Env, dir: launch.Dir, stdin: spec.Stdin, stdout: stdout, stderr: stderr, logs: logs, masker: masker, harness: hidden, output: output, cols: cols, rows: rows, resized: resized}
	// The limit ends the runtime and nothing else: the wall is closed on the caller's
	// context, as after any exit. The run being closed from outside ends it the same
	// way.
	// A stop in the gateway's answer to a batch ends it as the limit does, with the
	// stop's cause, from the runtime's start until its exit is decided.
	stoppable, stopRuntime := context.WithCancelCause(runCtx)
	defer stopRuntime(nil)
	limited, cancelLimit := context.WithCancel(stoppable)
	if spec.Timeout > 0 {
		limited, cancelLimit = context.WithTimeoutCause(stoppable, spec.Timeout, errTimeout)
	}
	r.stops.arm(stopRuntime)
	// Whether the session was cancelled, and whether it timed out, is decided the moment
	// the runtime's exit is observed. Cancelled: the caller's context had ended by then,
	// and neither the limit nor the gateway's close had ended the runtime's context
	// first; the first end is the cause. Timed out: the limit ended it first, and its
	// stop signal reached the runtime before the exit was observed; a runtime that
	// exited by itself before that signal, whatever its status, is decided by its exit.
	// What ends the context later changes nothing. A stop in the gateway's answer to a
	// batch is decided after the exit, below.
	var cancelled, timedOut bool
	proc.exited = func() {
		cause := context.Cause(limited)
		cancelled = ctx.Err() != nil && !errors.Is(cause, errTimeout) && !errors.Is(cause, errRunClosed) && !errors.Is(cause, errModelKeyLimit)
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
		cause := context.Cause(limited)
		return errors.Is(cause, errTimeout) || errors.Is(cause, errModelKeyLimit) || ctx.Err() != nil || errors.Is(context.Cause(runCtx), errRunClosed)
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
	// The events the mapper still keeps back come before the session's exit, and so
	// does the end of the runtime's transcript.
	mapper.Close()
	endTranscript()
	if tr != nil && !closed {
		tr.finish()
	}
	// A setup step still open when the launch ended has no exit status.
	setupSteps.finish(closed || timedOut || cancelled)
	if err != nil && !closed {
		r.stops.end()
		r.write(event.SessionExited, map[string]any{"session": n, "state": event.StateFailed, "exit_code": -1, "duration_ms": time.Since(start).Milliseconds()})
		r.lastExit, r.lastReason = -1, ""
		return nil, err
	}
	// A runtime the close kept from starting has no status: the session ends as a
	// closed one, with -1.
	if err != nil {
		exit = exitStatus{code: -1}
	}
	// Before the dev.qory.session.exited of a runtime that exited by itself, the
	// session posts the batch it holds and reads the answer, so a stop that comes as the
	// runtime exits still sets the reason.
	if !closed && !timedOut && !cancelled {
		flushCtx, cancelFlush := context.WithTimeout(context.WithoutCancel(ctx), closeWait)
		r.posts.Flush(flushCtx)
		cancelFlush()
	}
	keyLimit := r.stops.end() == event.ReasonModelKeyLimit
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
	case keyLimit:
		// The gateway's answer to a batch had stop: the run's proxy passed a model
		// provider's limit refusal to the runtime, and the run pauses.
		state, reason = event.StatePaused, event.ReasonModelKeyLimit
	case exit.code == 0:
		state = event.StateSucceeded
	}
	exited := map[string]any{"session": n, "state": state, "exit_code": exit.code, "duration_ms": time.Since(start).Milliseconds()}
	if exit.signal != "" {
		exited["signal"] = exit.signal
	}
	if !closed {
		// The socket is closed by now: the measure is here when it reached the session
		// within the close's grace.
		measureMu.Lock()
		maps.Copy(exited, measure)
		measureMu.Unlock()
	}
	if reason != "" {
		exited["reason"] = reason
	}
	r.lastExit, r.lastReason = exit.code, reason
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
	case keyLimit:
		r.open.Report("the runtime was stopped and the run pauses: every model key of the run is at its provider's limit or at its Use up to percentage, or the gateway could not send a refused request again with the next key (a request over 8 MiB, or a key whose credential does not cover the path)")
		r.write(event.SessionExited, exited)
	default:
		r.write(event.SessionExited, exited)
	}
	return res, nil
}

// measured are the members of a record of the measure source that the session puts on
// dev.qory.session.exited: peak_memory_bytes and cpu_time_ms, each when it is a whole
// number from 0 to 2^53-1.
func measured(rec map[string]any) map[string]any {
	out := map[string]any{}
	for _, name := range []string{"peak_memory_bytes", "cpu_time_ms"} {
		if v, ok := rec[name].(float64); ok && v >= 0 && v <= maxMeasure && v == math.Trunc(v) {
			out[name] = int64(v)
		}
	}
	return out
}

// sessionStarted is the data of the session's dev.qory.session.started. A value of the
// session's that contains qak_, qrk_, qecr_, qecn_, qecp_, qecg_, qeci_ or qecd_ in any
// case is sent as a phrase in its place: accesskey.ShownName's for the runtime, the
// image, its name and its container runtime; accesskey.ShownValue's for the directory,
// the command, each argument, the runtime's version, the name of each setup command and
// each harness source. In a run with a run key, dir is /workspace, the command and the
// arguments have <run>, <home> and <inputs> in place of the run directory, the harness
// home and the inputs directory (neutralPaths), and harness is left out: launchLine
// reports the values of this machine.
func (r *Run) sessionStarted(spec runSpec, rt runtimes.Runtime, n int, prepared runtimes.Launch, shown mountPlan, neutral func(string) string, interactive bool, cols, rows int) map[string]any {
	command, args, dir := prepared.Command, prepared.Args, spec.Dir
	if r.byReference {
		dir = shown.Dir
	}
	if r.remote != nil {
		command, args, dir = neutral(command), make([]string, len(prepared.Args)), workspaceInside
		for i, a := range prepared.Args {
			args[i] = neutral(a)
		}
	}
	started := map[string]any{
		"session": n, "runtime": accesskey.ShownName(rt.Name(), false), "command": accesskey.ShownValue(command, false), "args": shownValues(args),
		"dir": accesskey.ShownValue(dir, false), "interactive": interactive,
	}
	if v := rt.Version(); v != "" {
		started["runtime_version"] = accesskey.ShownValue(v, false)
	}
	// rt is a bare runtime for a nil Runtime and for a bare one the caller set. A session
	// whose runtime the caller set has no bare.
	if spec.SessionSpec.Runtime == nil {
		started["bare"] = true
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
	if len(spec.Harness) > 0 && r.remote == nil {
		harness := make([]any, len(spec.Harness))
		for i, h := range spec.Harness {
			harness[i] = map[string]any{"source": accesskey.ShownValue(h.Source, false), "commit": h.Commit}
		}
		started["harness"] = harness
	}
	// The run's masker replaces the run's secrets in every string, such as a query value
	// of a harness source's URL or a value in the args.
	return maskedValue(texts{secrets: r.masker}, started).(map[string]any)
}

// neutralPaths writes, in a value of a run with a run key, <run> in place of the run
// directory, <home> in place of the harness home, <inputs> in place of the inputs
// directory and, when dir is not empty, /workspace in place of the working directory
// dir. Each is replaced wherever it is not part of a longer name, by [shownPaths], in
// one pass over the value: the home, the inputs and dir at their path on this machine
// and, when it differs, at their path inside the enclosure. Of two paths where one
// contains the other, the longer is replaced, and the text written in its place is not
// replaced again. Join refuses / as the home or the inputs of a run with a run key
// (checkNeutral).
func (r *Run) neutralPaths(home, inputs, dir string, inside func(string) string) func(string) string {
	pairs := []pathPair{{r.dir, "<run>"}}
	for _, p := range []pathPair{{home, "<home>"}, {inputs, "<inputs>"}, {dir, workspaceInside}} {
		if p.from == "" {
			continue
		}
		p.from = filepath.Clean(p.from)
		pairs = append(pairs, p)
		if in := inside(p.from); in != p.from {
			pairs = append(pairs, pathPair{in, p.to})
		}
	}
	slices.SortStableFunc(pairs, func(a, b pathPair) int { return len(b.from) - len(a.from) })
	return func(s string) string { return replacePaths(s, pairs, shownPaths) }
}

// neutralRecord is data of an event of type typ mapped from a runtime's record, with
// text written by neutral in cwd of dev.qory.runtime.started and in prompt of
// dev.qory.runtime.prompt_submitted. Every other member, and every other event, such
// as a tool's input and output, is as the runtime wrote it.
func neutralRecord(typ string, data map[string]any, text func(string) string) map[string]any {
	key := map[string]string{"dev.qory.runtime.started": "cwd", "dev.qory.runtime.prompt_submitted": "prompt"}[typ]
	v, ok := data[key].(string)
	if !ok {
		return data
	}
	out := maps.Clone(data)
	out[key] = text(v)
	return out
}

// checkNeutral refuses / as the harness home or the inputs directory of a run with a
// run key. By shownPaths, / is replaced only where it is not part of a longer name, as
// in /, //x or --a=/, and every path below it, such as /usr, keeps its real form.
func checkNeutral(spec SessionSpec) error {
	if spec.HarnessHome != "" && filepath.Clean(spec.HarnessHome) == string(filepath.Separator) {
		return errors.New("Set the harness home to a directory below /.\n" + neutralRoot("<home>"))
	}
	if spec.InputsDir != "" && filepath.Clean(spec.InputsDir) == string(filepath.Separator) {
		return errors.New("Set the inputs directory to a directory below /.\n" + neutralRoot("<inputs>"))
	}
	return nil
}

// neutralRoot is the second line of checkNeutral's error for / as the directory that
// placeholder stands for.
func neutralRoot(placeholder string) string {
	return "A run with a run key writes " + placeholder + " in place of the directory in command, args, cwd, prompt and failure lines. " +
		"Forager replaces / only where it is not part of a longer name, so paths below / would keep their real form."
}

// launchLine is the line a run with a run key reports for session n, in place of the
// values its dev.qory.session.started leaves out: the host name, and the working
// directory, the harness home and the inputs directory on this machine; the command and
// the arguments as the session starts them, which in a run whose policy has its image by
// reference are the paths inside, under /workspace; and each harness source with its
// commit. A value that contains qak_, qrk_, qecr_, qecn_, qecp_, qecg_, qeci_ or qecd_
// is the phrase in its place. The run's masker replaces the run's secrets in the line
// once, as OpenSpec.Report passes it on.
func (r *Run) launchLine(spec runSpec, n int, prepared runtimes.Launch) string {
	var b strings.Builder
	fmt.Fprintf(&b, "session %d starts on this machine:", n)
	if h := hostname(); h != "" {
		fmt.Fprintf(&b, " host %s,", accesskey.ShownName(h, false))
	}
	fmt.Fprintf(&b, " dir %q,", accesskey.ShownValue(spec.Dir, false))
	if spec.HarnessHome != "" {
		fmt.Fprintf(&b, " home %q,", accesskey.ShownValue(spec.HarnessHome, false))
	}
	if spec.InputsDir != "" {
		fmt.Fprintf(&b, " inputs %q,", accesskey.ShownValue(spec.InputsDir, false))
	}
	fmt.Fprintf(&b, " command %q, args %q", accesskey.ShownValue(prepared.Command, false), shownValues(prepared.Args))
	for _, h := range spec.Harness {
		fmt.Fprintf(&b, ", harness %q at %s", accesskey.ShownValue(h.Source, false), h.Commit)
	}
	return b.String()
}

// leftOutCredentials is the lines for the names that denied-variables.json lists in
// forge_tokens or model_keys and whose value a source passed and the run left out: a
// value of the record the deny list left out, and a name of settings, what the runtime
// left out of the file it copied. A name has a line for the server's value, whose fix
// is in the run configuration, and one for the node's sources, whose fix is in
// forager.yaml; each line has its sources in the record's order, the highest source
// first, then the env of --settings. A placeholder of the run, and a model key's
// variable the session sets or leaves out for the start key, model, have no line: the
// gateway already has the credential.
func leftOutCredentials(entries []variables.Entry, settings, placeholderNames, model []string) []string {
	builtin, err := variables.Builtin()
	if err != nil {
		return nil
	}
	server, node := map[string]bool{}, map[string][]string{}
	var names []string
	add := func(name, from string) {
		if slices.Contains(placeholderNames, name) || slices.Contains(model, name) {
			return
		}
		if !server[name] && node[name] == nil {
			names = append(names, name)
		}
		if from == variables.FromApiary {
			server[name] = true
		} else if source := sourceOf(from); !slices.Contains(node[name], source) {
			node[name] = append(node[name], source)
		}
	}
	for _, e := range entries {
		for _, l := range e.Lost {
			if l.Why == variables.WhyDenied {
				add(e.Name, l.From)
			}
		}
	}
	for _, name := range settings {
		add(name, fromSettings)
	}
	slices.Sort(names)
	var lines []string
	for _, name := range names {
		kind := "forge token"
		if !slices.ContainsFunc(builtin.ForgeTokens, func(c string) bool { return strings.EqualFold(c, name) }) {
			if !slices.ContainsFunc(builtin.ModelKeys, func(c string) bool { return strings.EqualFold(c, name) }) {
				continue
			}
			kind = "model key"
		}
		shown := accesskey.ShownName(name, false)
		if server[name] {
			lines = append(lines, fmt.Sprintf("Define %s as a credential in the run configuration, not as a variable: the run leaves out the value that the server passes, since denied-variables.json lists it as a %s.", shown, kind))
		}
		if from := node[name]; len(from) > 0 {
			what := "the value that " + from[0] + " passes"
			if len(from) > 1 {
				what = "the values that " + strings.Join(from, " and ") + " pass"
			}
			lines = append(lines, fmt.Sprintf("Move %s to the gateway's credentials in forager.yaml: the run leaves out %s, since denied-variables.json lists it as a %s.", shown, what, kind))
		}
	}
	return lines
}

// fromSettings is the source of a name the runtime left out of the file it copied.
const fromSettings = "settings"

// sourceOf is how a line names a source of the record.
func sourceOf(from string) string {
	switch from {
	case variables.FromRun:
		return "--env"
	case variables.FromMachine:
		return "wall.env"
	case variables.FromHarness:
		return "the harness's defaults"
	case variables.FromFixed:
		return "the harness"
	case fromSettings:
		return "the env of --settings"
	}
	return from
}
