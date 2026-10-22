package session

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session/internal/variables"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/sink"
	"github.com/qoryai/forager/wall"
)

// Run is a run open at its gateway: [Open] opens it, [Run.Join] runs each of its
// sessions, one after another, and [Run.Close] closes it. Between the open and the
// close the run's heartbeats go on, its reloads are recorded, and its record and its
// batches to the gateway are written. A Run is for one goroutine: its methods are not
// called at the same time.
type Run struct {
	open    OpenSpec
	local   *localGateway
	remote  *RemoteGateway
	id, dir string
	link    *server.Link
	disc    *server.LinkDiscovery
	answer  *server.LinkRunAnswer
	// members are the members of policy_applied the gateway decides, the run answer's
	// and then each reload's; under emitMu once the reloads start.
	members     map[string]any
	img         Image
	byReference bool
	relayImage  string
	authority   []byte
	// bundle is the path of the run's ca-bundle.pem, empty for a run with none, and
	// bundleVars the variables of OpenSpec.CAEnv set to it; caVars are
	// bundleVars without a wall, for the session's runtime, and nil behind one.
	bundle     string
	bundleVars []string
	caVars     []string
	// bundleErr is why a walled run with an authority has no bundle, which
	// [Run.HostProxy] returns; nil otherwise.
	bundleErr   error
	hosts       hostProxies
	engine      engineProxies
	reserved    []string
	listed      *registration
	wallOwn     []bindSource
	openBinds   []bindSource
	setupBinds  []bindSource
	files       *sink.File
	posts       *sink.Server
	reload      *reloader
	stopBeat    func()
	unlock      func()
	startedAt   time.Time
	closedBy    ended
	closing     context.Context
	markClosed  context.CancelCauseFunc
	emitMu      sync.Mutex
	emit        *event.Emitter
	sinks       sink.Multi
	masker      *mask.Masker
	joining     sync.Mutex
	numbered    int
	maybeJoined bool
	lastExit    int
	// joinAsked says a Join reached its join request: the gateway closed the run's
	// stack proxy then, and [Run.StackProxy] starts none from then on. It is read
	// without the joining lock too, by a StackProxy that finds the lock taken.
	joinAsked atomic.Bool
	// keptBy is the number of the session whose wall's removal failed, 0 for none:
	// its entry among the walled runs still going stays, and no session joins after it.
	keptBy         int
	closed         bool
	sessionApplied map[string]any
	// steps is the number of the run's last step, host steps and Join's alike, and
	// hostStep the host step open, nil for none.
	steps    int
	hostStep *Step
	// imageStep is the number of the step that fetched the run's image by reference, 0
	// until one did.
	imageStep int
	// built is true once [Run.Built] wrote the run's dev.qory.run.built.
	built bool
	// enclosure is the run's wall, built as the run opens, nil for a run without one;
	// wallFwd is the run's forwarder behind it, where the wall's relay sends every
	// connection, and relayToken what the relay opens each of them with.
	enclosure  wall.Enclosure
	wallFwd    *forwarder
	relayToken string
	// setupFirst and setupLast are the numbers of the first and the last step of
	// [Run.Setup], 0 until it wrote one, and setupFailed the number of its step that
	// failed, 0 for none: no session joins after it.
	setupFirst, setupLast, setupFailed int
}

// Open opens a run at its gateway and returns it once dev.qory.run.started and the
// open's dev.qory.run.policy_applied, with an empty variables, are written. It checks
// the spec, discovers the gateway's link, takes the run directory's lock, lists a walled
// run among the walled runs still going, sends the run request, writes the run's
// bundle for a run whose answer has an authority, when the machine has a CA bundle,
// prepares a walled run's wall and starts the run's forwarder for it, for the Docker
// wall its networks and its relay too, and starts the heartbeats and the reloads, which
// last until [Run.Close]. An error means the run did not open: the spec is refused, the
// gateway's link could not be reached, the gateway refused the run request, or the wall
// did not start. A refusal with a code is a [*Refusal]; a failure without one at the
// gateway is its text as the user is told it.
func Open(ctx context.Context, spec OpenSpec) (*Run, error) {
	spec = openDefaults(spec)
	local, remote, err := gatewayOf(spec.Gateway)
	if err != nil {
		return nil, err
	}
	// Behind a separate gateway the run is the run key's, read before anything else, and
	// its TLS is checked before the run directory exists.
	var keyRunID string
	if remote != nil {
		key, err := remote.key()
		if err != nil {
			return nil, err
		}
		keyRunID = key.RunID
		if err := remote.checkTLS(); err != nil {
			return nil, err
		}
	}
	runID := spec.RunID
	switch {
	case runID == "" && keyRunID != "":
		runID = keyRunID
	case runID == "":
		runID = event.NewRunID()
	default:
		if err := CheckRunID(runID); err != nil {
			return nil, err
		}
		if keyRunID != "" && runID != keyRunID {
			return nil, fmt.Errorf("the run id %s is not the one QORY_RUN_KEY names, %s", runID, keyRunID)
		}
	}
	if err := CheckAbout(spec.About); err != nil {
		return nil, err
	}
	if err := CheckLabels(spec.Labels); err != nil {
		return nil, err
	}
	if err := checkMachine(spec); err != nil {
		return nil, err
	}
	// The checks of the machine's image table have no code: the open makes them before
	// the run request, as before the gateway resolves a selection.
	if spec.Wall != nil {
		if err := checkImages(spec); err != nil {
			return nil, err
		}
	}
	r := &Run{open: spec, local: local, remote: remote, id: runID, dir: filepath.Join(spec.RunsDir, runID), lastExit: -1, masker: &mask.Masker{}}
	r.closing, r.markClosed = context.WithCancelCause(context.Background())
	if err := r.start(ctx); err != nil {
		r.markClosed(nil)
		return nil, err
	}
	return r, nil
}

// start is the open of r once its spec is checked. On an error everything it made is
// undone: the heartbeats, the sinks, the lock, the registry entry and the link.
func (r *Run) start(ctx context.Context) (err error) {
	spec := r.open
	var undo []func()
	defer func() {
		if err != nil {
			for i := len(undo) - 1; i >= 0; i-- {
				undo[i]()
			}
		}
	}()
	// A walled run is listed among the walled runs still going from the open until its
	// close, with the wall's binds as far as it knows them and its run directory, so a
	// run that starts and ends before this one binds them is checked against them. Each
	// join adds its places.
	if spec.Wall != nil {
		if r.wallOwn, err = firstWallBinds(spec.Wall); err != nil {
			return err
		}
		runDir, err := runDirSource(spec, r.dir)
		if err != nil {
			return err
		}
		r.openBinds = append(slices.Clone(r.wallOwn), runDir)
		var engine *wall.Engine
		if e, ok := spec.Wall.(wall.Engined); ok {
			v := e.Engine(ctx)
			engine = &v
		}
		docker, _ := spec.Wall.(*wall.Docker)
		if r.listed, err = register(r.id, r.openBinds, engine, docker); err != nil {
			return err
		}
		undo = append(undo, r.listed.release)
	}
	// answered is the run-configuration digest of the link's last answer to a
	// discovery, a run request or a reload.
	var answeredMu sync.Mutex
	var answered server.Digests
	digests := func(d server.Digests) {
		answeredMu.Lock()
		answered = d
		answeredMu.Unlock()
	}
	if r.remote != nil {
		// A separate gateway: TLS 1.3 to its one address.
		r.link, err = r.remote.link(spec.ForagerVersion, digests)
	} else {
		r.link, err = server.NewLocalLink(r.local.local, accesskey.UserAgent(spec.ForagerVersion), digests)
	}
	if err != nil {
		return err
	}
	undo = append(undo, func() { r.link.Close() })
	lastAnswered := func() string {
		answeredMu.Lock()
		defer answeredMu.Unlock()
		return answered.RunConfiguration
	}
	disc, err := r.link.Discover(ctx)
	if err == nil && disc.Proxy == nil {
		err = errors.New("the link's discovery names no proxy")
	}
	// The local link's proxy is on loopback; a separate gateway's is its one address,
	// which the link's discovery checked.
	if err == nil && r.local != nil && !loopback(disc.Proxy.Address) {
		err = fmt.Errorf("the gateway's discovery names the proxy %s, which is no address on loopback: the local link's proxy is on this machine", accesskey.ShownValue(disc.Proxy.Address, true))
	}
	if err == nil && disc.Events.IntervalSeconds < 1 {
		err = errors.New("the link's discovery names no heartbeat interval")
	}
	if err != nil {
		return err
	}
	r.disc = disc
	// A run id that has a record is no run, as it always was: the run's stream, which
	// the gateway writes beside the session's record, is checked first.
	if _, err := os.Lstat(filepath.Join(r.dir, sink.EventsFile)); err == nil {
		return accesskey.ShownError(&fs.PathError{Op: "open", Path: filepath.Join(r.dir, sink.EventsFile), Err: syscall.EEXIST})
	}
	discovered := time.Now()
	interval := time.Duration(disc.Events.IntervalSeconds) * time.Second
	r.emit = event.NewEmitter(r.id, nil)
	if r.files, err = sink.NewFileAs(r.dir, sink.SessionFile); err != nil {
		return err
	}
	closeFiles := func() { r.files.Close(context.WithoutCancel(ctx)) }
	if r.remote != nil {
		// The mark of a session's record behind a separate gateway, which BehindGateway
		// reads.
		if err := markBehindGateway(r.dir); err != nil {
			closeFiles()
			return err
		}
	}
	if r.unlock, err = lock(r.dir); err != nil {
		closeFiles()
		return err
	}
	undo = append(undo, r.unlock)
	r.sinks = sink.Multi{r.files}
	// The heartbeats run from the link's discovery, every interval it announces, until
	// the run's final event, and end with the run being closed from outside.
	r.stopBeat = heartbeat(r.closing, interval, discovered, r.write)
	// quit ends a run that does not open: the heartbeats stop, and the sinks are closed,
	// within closeWait.
	quit := func(err error) error {
		r.stopBeat()
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeWait)
		defer cancel()
		r.closeSinks(closeCtx)
		return err
	}
	// fail is quit with the record of why. A run the gateway closed before it opened
	// records dev.qory.run.refused with its code in the session's record alone. A
	// refusal of the session's, with a code it decides, is posted on the link too once
	// the run is open at the gateway, which ends it there.
	fail := func(err error) error {
		var ref *Refusal
		switch {
		case r.closing.Err() != nil:
			e := r.closedBy.get()
			r.own(event.RunRefused, map[string]any{"code": e.Code, "status": http.StatusGone})
			err = &Refusal{Code: e.Code, Status: http.StatusGone, From: e.From, Text: endedBeforeStart}
		case errors.As(err, &ref) && refusal.Decides(ref.Code):
			data := map[string]any{"code": ref.Code}
			if len(ref.Names) > 0 {
				data["names"] = eventNames(ref.Names)
			}
			r.write(event.RunRefused, data)
		}
		return quit(err)
	}
	req := server.LinkRunRequest{RunID: r.id, Wall: spec.Wall != nil}
	if r.remote == nil {
		// Behind a separate gateway the labels and what the run is about are the
		// starter's registration's.
		req.Labels, req.About = spec.Labels, server.ReportedAbout(spec.About)
	}
	if spec.Wall != nil {
		req.Images = linkImages(spec)
	}
	answer, err := r.link.OpenRun(ctx, disc.Run.URL, req)
	if err != nil {
		return refused(err, fail, quit, r.own, r.end)
	}
	r.answer = answer
	r.reload = newReloader(r.closing, r.link, disc.Run.URL, r.id, lastAnswered(), lastAnswered, spec.Report)
	// Behind a separate gateway the run directory keeps what the gateway accepted and
	// what it did not, delivered.log and undelivered/, so a resend knows what it still
	// owes; on one machine the gateway keeps the run's delivery state.
	spool := ""
	if r.remote != nil {
		spool = r.dir
	}
	r.posts = sink.New(sink.Config{
		To: r.link, Target: sink.Target{URL: disc.Events.URL, Types: disc.Events.Types}, Spool: spool,
		Report: spec.Report, OnDigests: r.reload.digests, OnEnded: r.end,
		Wait: sink.LinkBatchWait, Link: true,
	})
	r.posts.SetRunDigest(lastAnswered())
	r.emitMu.Lock()
	r.sinks = append(r.sinks, r.posts)
	r.emitMu.Unlock()
	fail2 := func(err error) error {
		r.reload.stop()
		return fail(err)
	}
	// What the gateway decided the run with, which the run applies and decides none of
	// again: the image, the authority and the members of policy_applied it decides; each
	// session applies the placeholders, the names it sets and the variables.
	// An answer without an image is a machine whose default names none: the wall is
	// asked for none, and refuses it as it always has.
	// An image the policy names by its reference starts as the default does, and the
	// relay starts from the machine's default whatever the run's image is.
	if spec.Wall != nil && answer.Image != nil {
		r.img = Image{Name: answer.Image.Name, Ref: answer.Image.Ref, Runtime: answer.Image.Runtime, Docker: answer.Image.Docker}
		r.byReference, r.relayImage = answer.Image.Reference, answer.RelayImage
	}
	if r.members, err = appliedMembers(answer.Applied); err != nil {
		return fail2(err)
	}
	r.reserved = slices.Concat(answer.Reserved, reservedOf(spec.Gateway))
	if answer.CertificateAuthority != "" {
		r.authority = []byte(answer.CertificateAuthority)
	}
	// The run's host work, walled or not, and without a wall the run's tools, trust the
	// authority through a bundle in the run directory, the machine's authorities and the
	// run's certificate, which the variables of caEnv point at, as the wall's do inside.
	// A run without a wall does not open without the bundle; a walled run opens, and
	// its host proxy does not start.
	if r.authority != nil {
		r.bundleVars, err = writeBundle(r.dir, caEnv(spec), r.authority)
		switch {
		case err == nil:
			r.bundle = filepath.Join(r.dir, BundleFile)
			if spec.Wall == nil {
				r.caVars = r.bundleVars
			}
		case spec.Wall == nil:
			return fail2(err)
		case errors.Is(err, errNoMachineBundle):
			r.bundleErr = errNoHostBundle
		default:
			r.bundleErr = err
		}
	}
	// On one machine the proxy secret opens every connection to the gateway's proxy,
	// written by a forwarder or by the wall's relay, and the stack proxy secret every
	// connection of the stack proxy's forwarder: one no preamble contains is no run.
	// Behind a separate gateway the run key opens them, and the answer has neither.
	if r.remote == nil {
		if err := link.CheckSecret(answer.ProxySecret); err != nil {
			return fail2(fmt.Errorf("the gateway's proxy secret: %w", err))
		}
		if err := link.CheckSecret(answer.StackProxySecret); err != nil {
			return fail2(fmt.Errorf("Use a gateway that sends stack_proxy_secret on its local link: the run answer's stack_proxy_secret is missing or malformed: %w", err))
		}
	}
	// Behind a wall, the run's wall is built as the run opens: its networks, the run's
	// forwarder at the enclosure's ProxyAddr, and the relay towards that forwarder. Each
	// session then starts the agent's container alone, and the close removes the rest.
	if spec.Wall != nil {
		undo = append(undo, func() { r.closeWall(context.WithoutCancel(ctx)) })
		if err := r.openWall(ctx); err != nil {
			return fail2(err)
		}
	}
	// A run closed during its open does not open.
	if r.closing.Err() != nil {
		return fail2(errRunClosed)
	}
	r.startedAt = time.Now()
	// A value of the run's that contains qak_ or qrk_ in any case is sent as a phrase in
	// its place: accesskey.ShownName's for the host and the wall, and server.ShownLabels'
	// and server.ShownAbout's for the labels and about.
	started := map[string]any{"opened_by": event.OpenedByRun, "forager_version": spec.ForagerVersion, "host": accesskey.ShownName(hostname(), false)}
	if spec.Wall != nil {
		started["wall"] = accesskey.ShownName(spec.Wall.Name(), false)
	}
	// Open checked both: neither contains qak_ or qrk_, since neither contains _.
	if spec.Machine != "" {
		started["machine"] = spec.Machine
	}
	if spec.Setup != "" {
		started["setup"] = spec.Setup
	}
	// The labels are the run's as the gateway has them. Behind a separate gateway
	// neither they nor what the run is about are the session's: the starter's
	// registration has them.
	if len(answer.Labels) > 0 && r.remote == nil {
		started["labels"] = server.ShownLabels(answer.Labels)
	}
	if about := server.ReportedAbout(spec.About); about != nil && r.remote == nil {
		started["about"] = server.ShownAbout(about)
	}
	r.write(event.RunStarted, started)
	r.write(event.PolicyApplied, r.policyApplied(r.members))
	// A reload fetches what the gateway put in force and records it, at the sequence
	// where it takes effect; batches from then on contain its digest.
	r.reload.start(func(a *server.LinkReloadAnswer, held string) {
		members, err := appliedMembers(a.Applied)
		if err != nil {
			spec.Report("the reload failed: " + err.Error())
			return
		}
		r.emitMu.Lock()
		defer r.emitMu.Unlock()
		r.posts.SetRunDigest(held)
		// A join from here on records the reload's members, not the open's.
		r.members = members
		r.record(event.PolicyApplied, r.policyApplied(members))
	}, r.end)
	return nil
}

// ID is the run's id.
func (r *Run) ID() string { return r.id }

// Dir is the run directory.
func (r *Run) Dir() string { return r.dir }

// System is the server's value of QORY_RUN_SYSTEM in the run answer's variables, the
// system the run's work is for; empty when the server sets none.
func (r *Run) System() string { return r.answer.Values()[envRunSystem] }

// Repositories is the server's value of QORY_RUN_REPOSITORIES in the run answer's
// variables, the repositories the run may fetch; empty when the server sets none.
func (r *Run) Repositories() string { return r.answer.Values()[envRunRepositories] }

// AgentEnv is the environment a session of spec gets from the server's variables,
// Variables.Run, Variables.Machine, LaunchDefaults and SessionSpec.Env, as [Run.Join]
// resolves it for spec: NAME=value, sorted by name, in a new slice on every call. The
// deny lists, the endpoint rule and the run's placeholders apply as in Join. It leaves
// out the names Forager, the proxy, the wall and the bundle set, LaunchFixed, the
// placeholders and the access key's variables. The result matches what the agent gets
// from those sources, apart from a name the runtime preparation sets, which overrides
// the value in the agent: AgentEnv runs no runtime preparation, writes nothing and
// sends no request. It also leaves out a value of SessionSpec.Env whose name the
// built-in deny list, denied-variables.json, matches, such as PATH, which Join passes
// to the agent and [Run.Setup] refuses. For a run whose image is a reference, a path in
// the workspace in LaunchDefaults is written at /workspace, as Join writes it.
// AgentEnv masks no value: apart from that rewrite, it returns each value as the
// server, the caller or the machine passed it, and no value the gateway holds for a
// placeholder. A caller that runs the setup passes the result as [SetupSpec.Env]. The result has QORY_RUN_SYSTEM and
// QORY_RUN_REPOSITORIES when the server sets them, and Setup accepts both. The error
// is the one Join returns for spec before its join request, as it checks the places of
// a run whose image is a reference, or as it resolves the variables, the same
// [refusal.VariableReserved] or [refusal.PlaceholderConflict] among them, or that the
// run is closed or another call of the run is running.
func (r *Run) AgentEnv(spec SessionSpec) ([]string, error) {
	if !r.joining.TryLock() {
		return nil, errors.New("call AgentEnv after the run's other call returns: another call of the run is running")
	}
	defer r.joining.Unlock()
	if r.closed {
		return nil, errors.New("open a new run for the agent's environment: the run is closed")
	}
	s, rt, err := r.checkSession(spec)
	if err != nil {
		return nil, err
	}
	// As in Join: without a wall the variables the machine's credentials are read from
	// are left out of what the session inherits. The session starts with
	// spec.ModelCredential, or with the run's start key when spec has none: the join
	// answer's model_credential is one of the two, by link-join-answer.schema.json.
	if s.Wall == nil {
		s.Env = withoutNames(s.Env, r.reserved)
	}
	// As in Join: a run whose policy names its image by its reference sees its
	// workspace at /workspace, and the harness's values are written as the enclosure
	// sees them. The places get the join's checks, for the session the next join
	// numbers.
	if r.byReference {
		plan, err := checkMounts(s, r.dir, filepath.Join(r.dir, SessionsDir, strconv.Itoa(r.numbered+1)))
		if err != nil {
			return nil, err
		}
		_, inside, err := plan.atWorkspace()
		if err != nil {
			return nil, err
		}
		s.LaunchFixed, s.LaunchDefaults = insideValues(s.LaunchFixed, inside), insideValues(s.LaunchDefaults, inside)
	}
	model := s.ModelCredential
	if model == "" {
		model = r.answer.ModelCredential
	}
	credentialHosts, placeholderNames, key, err := chosen(rt, r.answer.CredentialHosts, r.answer.Placeholders, model)
	if err != nil {
		return nil, err
	}
	prepared := runtimes.Launch{Command: s.Command, Args: s.Args}
	bundle := names(r.caVars)
	vars, _, err := resolve(s, rt, r.answer.Values(), credentialHosts, prepared, placeholderNames, r.reserved, r.img.Docker, r.authority != nil, bundle, key)
	if err != nil {
		return nil, err
	}
	fixed := slices.Concat(foragerNames(s, prepared, bundle, key), names(vars.Fixed), placeholderNames)
	if w, ok := s.Wall.(wall.Setter); ok {
		fixed = append(fixed, w.Sets()...)
	}
	if r.img.Docker {
		fixed = append(fixed, wall.NestSets()...)
	}
	// What the session inherits goes under the resolved values, without the runtime's
	// other model-key variables, as environment writes the agent's. A name of the
	// built-in deny list is left out of it too, which Join leaves in: Setup refuses
	// such a name.
	deny, err := variables.List(nil)
	if err != nil {
		return nil, err
	}
	var inherited []string
	for _, kv := range withoutNames(s.Env, key.Others) {
		if name, _, _ := strings.Cut(kv, "="); !deny.Matches(name) {
			inherited = append(inherited, kv)
		}
	}
	env := withoutNames(environment(inherited, vars.Env), fixed)
	last := map[string]string{}
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		last[name] = value
	}
	out := make([]string, 0, len(last))
	for _, name := range slices.Sorted(maps.Keys(last)) {
		out = append(out, name+"="+last[name])
	}
	return out, nil
}

// The server's variables a [Run] gives its caller.
const (
	envRunSystem       = "QORY_RUN_SYSTEM"
	envRunRepositories = "QORY_RUN_REPOSITORIES"
)

// end is how the run is closed from outside, a 410 on the link or the gateway's 400 to
// a batch: the first end is kept, and r.closing ends.
func (r *Run) end(e server.RunEnd) {
	r.closedBy.set(e)
	r.markClosed(errRunClosed)
}

// record numbers and writes an event to every sink; the caller holds r.emitMu, so the
// order in the sinks is the order of the sequence whichever goroutine emits: the
// socket, the heartbeat, a reload.
func (r *Run) record(typ string, data any) { r.sinks.Write(r.emit.Make(typ, data)) }

// write is record under r.emitMu.
func (r *Run) write(typ string, data any) {
	r.emitMu.Lock()
	defer r.emitMu.Unlock()
	r.record(typ, data)
}

// own writes an event to the session's record alone.
func (r *Run) own(typ string, data any) {
	r.emitMu.Lock()
	defer r.emitMu.Unlock()
	r.files.Write(r.emit.Make(typ, data))
}

// closeSinks closes every sink of the run within ctx.
func (r *Run) closeSinks(ctx context.Context) error {
	r.emitMu.Lock()
	all := r.sinks
	r.emitMu.Unlock()
	return all.Close(ctx)
}

// policyApplied is the policy_applied event of the members the gateway decides, for the
// policy in force at the open and for each one a reload puts in its place: those
// members as the gateway gives them, and the members of the session that runs, its
// variables, the variables its credentials' placeholders are in and the harness's
// hosts; with no session running, an empty variables. Called with r.emitMu held, or
// before the reloads start.
func (r *Run) policyApplied(members map[string]any) map[string]any {
	a := maps.Clone(members)
	if a == nil {
		a = map[string]any{}
	}
	delete(a, "credential_variables")
	delete(a, "harness_hosts")
	a["variables"] = shownVariables(nil)
	maps.Copy(a, r.sessionApplied)
	return a
}

// setApplied sets the members of policy_applied of the session that runs, nil when
// none runs.
func (r *Run) setApplied(m map[string]any) {
	r.emitMu.Lock()
	defer r.emitMu.Unlock()
	r.sessionApplied = m
}

// Close writes the run's dev.qory.run.exited with the caller's outcome, once, and
// closes the run: a host step still open ends cancelled with -1 first, then the run's
// wall is removed, the heartbeats and the reloads stop, the sinks are flushed within 15
// seconds, and the lock, the registry entry and the link are let go. A wall that could
// not be removed is reported, and its entry among the walled runs still going stays. A
// failed outcome with no reason of a run no session joined is written as failed with
// no_session and -1. A run the gateway closed
// before the close has its dev.qory.run.exited in the session's record alone, with the
// state and the reason of the gateway's 410 and the last session's exit code. An error
// means the outcome is refused, and nothing is written: the run stays open, and Close
// may be called again; or the run is closed already.
func (r *Run) Close(ctx context.Context, out Outcome) (*Closed, error) {
	if !r.joining.TryLock() {
		return nil, errors.New("a session of the run is still running: close the run after Join returns")
	}
	defer r.joining.Unlock()
	if r.closed {
		return nil, errors.New("the run is closed already")
	}
	joined := r.numbered > 0 || r.maybeJoined
	if err := checkOutcome(out, joined); err != nil {
		return nil, err
	}
	if !joined && out.State == event.StateFailed && out.Reason == "" {
		out.Reason, out.ExitCode = event.ReasonNoSession, -1
	}
	r.closed = true
	r.hosts.closeAll()
	r.closeEngine()
	// A host step still open ends before run.exited, as one the caller stopped.
	if r.hostStep != nil {
		r.hostStep.end(event.StateCancelled, -1)
	}
	// The run's wall goes before run.exited: its containers, the setup container's
	// among them, its networks and its private directory, then the run's forwarder.
	r.closeWall(context.WithoutCancel(ctx))
	// Nothing of a reload goes after run.exited, and the heartbeats stop before it.
	r.reload.stop()
	r.stopBeat()
	closed := r.closing.Err() != nil
	res := &Closed{RunID: r.id, Dir: r.dir, State: out.State, Reason: out.Reason, ExitCode: out.ExitCode}
	if closed {
		e := r.closedBy.get()
		res.State, res.Reason = recorded(e)
		res.ExitCode, res.RunClosed, res.ClosedReason = r.lastExit, true, e.Code
	}
	exited := map[string]any{"state": res.State, "exit_code": res.ExitCode, "duration_ms": time.Since(r.startedAt).Milliseconds()}
	if res.Reason != "" {
		exited["reason"] = res.Reason
	}
	if closed {
		// The end of the run at the gateway is in its stream already: the session
		// records its run.exited, with the state and the reason the run was closed with,
		// in its record alone, once delivered.log says the gateway ended the run, which
		// a reload's 410 leaves to the session to say: a resend never sends it.
		r.posts.RunEnded()
		r.own(event.RunExited, exited)
	} else {
		r.write(event.RunExited, exited)
	}
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeWait)
	defer cancel()
	if err := r.closeSinks(closeCtx); err != nil {
		r.open.Report("closing the sinks: " + accesskey.ShownError(err).Error())
	}
	res.Undelivered = r.posts.Undelivered()
	r.unlock()
	if r.listed != nil {
		r.listed.release()
	}
	r.link.Close()
	r.markClosed(nil)
	return res, nil
}
