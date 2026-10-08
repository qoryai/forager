package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/runner/accesskey"
	"github.com/qoryai/runner/internal/credential"
	"github.com/qoryai/runner/internal/event"
	"github.com/qoryai/runner/internal/policy"
	"github.com/qoryai/runner/internal/proxy"
	"github.com/qoryai/runner/internal/refusal"
	"github.com/qoryai/runner/internal/server"
	"github.com/qoryai/runner/internal/sink"
	"github.com/qoryai/runner/internal/socket"
	"github.com/qoryai/runner/internal/tool"
	"github.com/qoryai/runner/runtimes"
	"github.com/qoryai/runner/wall"
)

// Spec is what one run is given.
type Spec struct {
	// Runtime is the program that is run: what is prepared before it starts, what its
	// records mean and how it is asked to leave. The catalog package resolves a name to
	// one. Nil means a bare runtime named after the Command: the run is recorded, the
	// session inside it is not.
	Runtime runtimes.Runtime
	// Command, Args and Dir are what to start; an empty Dir is the working directory.
	Command string
	Args    []string
	// Env is the environment the run inherits, NAME=value: a nil Env is the process's
	// own, or nothing under a Wall, where only what the run lists goes in. It is the
	// lowest of the run's sources of variables: LaunchDefaults, Variables and the
	// server's variables win over it, apart from it, so the runner distinguishes them
	// from what is merely inherited (contracts/runner/v1/README.md §Variables). The
	// access key's variables, QORY_ACCESS_KEY_SECRET, QORY_ACCESS_KEY_ID and
	// QORY_APIARY_PUBLIC_KEY, are left out of what the session gets from any of them,
	// and out of every tool's and credential program's environment too.
	Env []string
	Dir string
	// LaunchFixed is the values the harness computes itself, NAME=value. They are fixed
	// names of the run: they win over every other source of a variable, the built-in
	// deny list, denied-variables.json, leaves one out, and the runtime's denies and
	// Variables.Deny do not. The runner's, the wall's and the runtime preparation's
	// names win over them.
	LaunchFixed []string
	// LaunchDefaults is the values the harness's author wrote as defaults, NAME=value.
	// They win over Env and lose to every other source.
	LaunchDefaults []string
	// Variables are the run's and the machine's variables, and how the run takes the
	// variables of the server's run configuration.
	Variables Variables
	// HarnessHome is the harness's home as the agent's process sees it, an absolute
	// path; empty means none. When set, the runner sets QORY_HARNESS_HOME to it, as one
	// of its own names, like QORY_RUN_ID.
	HarnessHome string
	// OnVariables, when not nil, is called once the run's variables are resolved,
	// before the tools, the wall and the agent start, with each name, its source and
	// the values that lost, as dev.qory.run.policy_applied records them: qory prints a
	// line for an --env value that lost. A run refused before then does not call it.
	OnVariables func(Applied)
	// Interactive says the caller has a terminal: the session runs on a pseudo-terminal
	// attached to Stdin and Stdout, unless Args holds an argument the Runtime names as
	// headless, -p for Claude Code, in which case it runs on pipes as if the caller had
	// said so. Otherwise it runs on pipes with Stdin as its input and its output copied
	// to Stdout and Stderr. A nil stream is the process's own.
	Interactive bool
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	// Policy is the node's policy, the one the command passes; nil means none. Without
	// a server's policy it is the run's, and none is mode observe. With a Server whose
	// run configuration has a policy, it narrows that one: the node only takes away
	// (contracts/runner/v1/README.md §The server).
	Policy *Policy
	// Server is the server the run reports to and takes its run configuration from;
	// nil means files only, the machine's policy. Local ignores it: the server is not
	// contacted.
	Server *Server
	Local  bool
	// AccessKey is the access key every request to the Server is signed with, held from
	// its secret, which the caller reads; for qory from a file descriptor, else
	// QORY_ACCESS_KEY_SECRET, else the file access-key-secret. A Server needs it.
	AccessKey *accesskey.Key
	// InstanceID is this instance's id, sent in X-Qory-Instance-Id and signed into every
	// request to the Server; for qory the id of its instance-id file. A Server needs it,
	// and it matches ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$.
	InstanceID string
	// InstanceName is this instance's display name, sent in X-Qory-Instance-Name on
	// every request to the Server, unsigned and for display alone; empty sends none.
	InstanceName string
	// Discovered, when not nil, is called once the Server's signed configuration
	// document is read, before the ping, with what it lists of the access key: qory
	// prints the node id. An error it returns is no run, and nothing more is sent.
	Discovered func(Discovery) error
	// Events, when not nil, gets every event as one JSON line as well, the line
	// events.jsonl holds: a run with no receiver is followed on standard output this
	// way. Local does not silence it.
	Events io.Writer
	// ProxyBind is the address the proxy listens on, host:port; empty means a loopback
	// port. A caller that builds an enclosure of its own names the address the
	// enclosure reaches here. It is not set together with Wall, which names its own.
	ProxyBind string
	// Wall, when not nil, encloses the runtime: the command is started inside an
	// enclosure whose only route out leads to the proxy, in Image, with Dir as its
	// workspace and working directory. Command, Args and Forwarder are then paths
	// inside the enclosure. Nil means no wall: the runtime is this machine's process,
	// and enforcement is cooperative.
	Wall wall.Wall
	// Image is the agent's image under a Wall when the policy selects none: the name
	// of one of Images, or a reference.
	Image string
	// Images are the images this machine defines; the run's policy selects among them
	// by name, as it selects credentials and tools, and a selection needs a Wall. The
	// image a run starts in is fixed when it starts.
	Images []Image
	// Mounts are what the enclosure shows of this machine, each at its own path: the
	// checkout around Dir, a composed home outside it. A mount, or Dir, inside another
	// one of the same mode is reached through the outer one, which alone is bound; one of
	// the other mode is no run, mount_mode_conflict. One whose path goes through a link
	// inside a writable one, and that does not resolve into it, is no run, whatever its
	// mode, mount_through_link. Dir is writable, and is bound at its own path when no mount
	// holds it. The runner adds the run directory, read-only. A walled run refuses a
	// bind that lies inside, or is reached through, a writable bind of another walled
	// run of this user's still going, apart from the same root, a writable one that
	// holds one of that run's binds or the way to one, and one that is, holds or lies
	// inside that run's run directory: mount_shared_with_run. Without a Wall they mean
	// nothing.
	Mounts []wall.Mount
	// RunnerFiles are the absolute paths of the caller's files that are the runner's
	// own, such as the directory of qory's runner file with the access key secret. A
	// walled run refuses a mount, or a workspace, that is, contains or lies inside one of
	// them, or one of the paths the runner knows itself, RunsDir among them,
	// mount_contains_runner_files: see [Overlap].
	RunnerFiles []string
	// Credentials are the credentials this machine defines; the run's policy selects
	// among them by name. A selected credential, like a path rule, needs a Wall: the
	// proxy then terminates TLS for the hosts concerned, with an authority made for the
	// run whose certificate the enclosure is given to trust.
	Credentials []Credential
	// Tools are the tools this machine defines; the run's policy selects among them by
	// name. A selected tool needs a Wall, as a credential does: the proxy terminates TLS
	// for the hosts it serves. The runner starts each selected tool before the runtime
	// and stops it when the run ends; the tools a run has are fixed when it starts.
	Tools []Tool
	// Declared is the egress the harness declared, nil when nothing was. It is
	// reported in dev.qory.run.policy_applied as harness_hosts and decides nothing:
	// the policy alone decides.
	Declared []string
	// RunsDir holds the run directories; empty means Dir/.qory/runs. It is one of the
	// runner's files, so a walled run needs one outside its mounts and Dir.
	RunsDir string
	// Forwarder is the command the Runtime installs as the program's hook: it reads the
	// hook's input and forwards it to the socket. Empty means no hooks are installed.
	Forwarder []string
	// RunnerVersion is reported in the events.
	RunnerVersion string
	// RunID is the run's id when a parent already made one; empty means a new one. It is
	// a UUID in the canonical lower-case form, because it is the events' subject and names
	// the run directory; anything else is refused.
	RunID string
	// Labels are the caller's own names for the run, its key in a queue, a repository, an
	// issue: reported in run.started and no other event, so a receiver ties the run id to
	// what it knows, and sent, all of them, as the query of the run configuration request,
	// so the server chooses the run's policy by them. The runner reads nothing into them.
	// At most MaxLabels; a key is 1 to 64 of a-z, 0-9, underscore, dot and dash, a value
	// at most 256 bytes.
	Labels map[string]string
	// About is what the run is about, as the caller passed it: the kind of run, a title,
	// the subjects it works on and details. It is reported in run.started and no other
	// event, so a receiver shows the run by it; it is never sent on the run configuration
	// request and never selects a policy. The runner reads nothing into it. CheckAbout
	// holds it to its bounds before the server is contacted. Nil, or an About whose every
	// member is empty, is left out. Details is shown to every reader of the run, so it
	// never holds a secret.
	About *About
	// Timeout is how long the runtime may run; zero means no limit. At the limit the
	// runtime is stopped the way the context ending stops it, and run.exited carries
	// the reason.
	Timeout time.Duration
	// StopSignal is the signal that asks the runtime to leave when the runner stops it,
	// at the Timeout or the context's end: one CheckStopSignal passes. A runtime may
	// close a session on one signal and drop it on another, and which is the runtime's
	// to say, not the runner's. Empty means the Runtime's, and DefaultStopSignal when it
	// names none.
	StopSignal string
	// StopGrace is how long the runtime gets between the stop signal and SIGKILL: the
	// time a session needs to close what it has open. Zero means the Runtime's, and
	// DefaultStopGrace when it names none.
	StopGrace time.Duration
	// Limits are the resources the enclosure gives the runtime. Without a Wall they mean
	// nothing.
	Limits wall.Limits
	// Heartbeat is the interval between heartbeats; zero means 30 seconds. With a
	// Server, heartbeats run from the accepted ping, which announces the interval, a
	// whole number of seconds from 1 to 300; without one, from run.started.
	Heartbeat time.Duration
	// Report receives one line per thing the runner tells its user; nil means Stderr.
	Report func(string)
}

// Result is what a run came to.
type Result struct {
	RunID string
	// Dir is the run directory holding events.jsonl and output.log.
	Dir string
	// ExitCode is the runtime's, or -1 when a signal killed it.
	ExitCode int
	// Signal names the signal that killed the runtime, if one did.
	Signal string
	// State is succeeded or failed.
	State string
	// TimedOut says the runtime was stopped at the spec's Timeout.
	TimedOut bool
	// Undelivered is how many events the server did not accept.
	Undelivered int
	// RunClosed says the server closed the run, a signed 410 run_closed: the runtime
	// was stopped as at its time limit, and run.exited has the reason run_closed.
	RunClosed bool
}

// Discovery is what the Server's configuration document lists of the run's access key.
type Discovery struct {
	// NodeID is the id of the access key's node, nd_, or node pool, np_.
	NodeID string
	// Secrets is true when the document lists a secrets section.
	Secrets bool
}

// Refusal is a run that did not start, and why: its refusal code, and the status of
// the server's answer when the code came from one. A server's run, for one, is refused
// with apiary_public_key_missing without a pin, unauthorized on a 401,
// answer_unsigned on an answer that does not verify under the pin, instance_limit when
// the node's live instances are at its limit, and run_closed when the server closes
// the run before it starts. The runner's own refusals are Refusals too, with the names
// they concern and never a value: run_configuration_invalid, variable_reserved,
// placeholder_conflict, tool_unknown, image_unknown, mount_contains_runner_files,
// mount_mode_conflict and mount_shared_with_run among them. errors.As finds one in
// what [Run] returns.
type Refusal = accesskey.Refusal

// The environment variables the session gets from the runner. EnvHarnessHome is set
// when the spec has a HarnessHome.
const (
	EnvRunID       = "QORY_RUN_ID"
	EnvSocket      = socket.Env
	EnvHarnessHome = "QORY_HARNESS_HOME"
)

// MaxLabels is how many labels a run may carry.
const MaxLabels = server.MaxLabels

// errTimeout is the cause of the runtime's context ending at the spec's Timeout.
var errTimeout = errors.New("the run's time limit")

// errRunClosed is the cause of the run's context ending when the server closes the
// run.
var errRunClosed = errors.New("the server closed the run")

var runIDShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// CheckRunID refuses a caller's run id that is not a UUID in the canonical lower-case
// form. [Run] checks it; a command checks it first to call it a mistake of its user's.
func CheckRunID(id string) error {
	if !runIDShape.MatchString(id) {
		return fmt.Errorf("the run id %q is not a UUID in the canonical lower-case form", id)
	}
	return nil
}

// CheckLabels refuses labels the contract's schema would: too many, a key outside its
// grammar, a value too long. [Run] checks them; a command may first.
func CheckLabels(labels map[string]string) error { return server.CheckLabels(labels) }

// About is what a run is about, as the caller passed it: see [Spec.About].
type About = server.About

// Subject is one thing a run works on, identified by its Type and Ref.
type Subject = server.Subject

// AboutError is why CheckAbout refuses an About: the Field, such as
// about.subjects[0].ref, and the Reason.
type AboutError = server.AboutError

// CheckAbout refuses an About the contract's rules refuse: a member over its bound in
// bytes, a string that is not UTF-8 or has a control character, a subject type outside
// its form, a URL that is not an absolute http or https one, two subjects with the same
// type and ref, and details that are not a JSON object of at most 8192 bytes compacted
// and 4 levels. It returns the first failure as an [*AboutError]. [Run] checks it before
// it contacts the server; a command may first.
func CheckAbout(a *About) error { return server.CheckAbout(a) }

// closeWait is how long the sinks get to flush after the runtime exits.
const closeWait = 15 * time.Second

// Run runs one session and returns when the runtime has exited and the sinks are
// flushed. An error means the run did not start: the policy or the server document
// could not be read, the server's configuration document or run configuration could
// not be fetched, the server did not accept the ping, the descriptor is unknown, the
// wall could not be built, or the program could not be started. A refusal with a code
// is a [*Refusal]. Once the runtime runs, its exit is the result and not an error. The
// context ending stops the runtime, and so does the server closing the run.
func Run(ctx context.Context, spec Spec) (*Result, error) {
	spec = withDefaults(spec)
	// runCtx ends when the server closes the run, a signed 410 run_closed to a
	// delivery: the start stops, or the runtime is stopped as at its time limit.
	runCtx, closeRun := context.WithCancelCause(ctx)
	defer closeRun(nil)
	// node is the node's policy, the one the command passes: the run's while no server's
	// policy is in force, and what narrows a server's.
	var node *policy.Loaded
	pol := policy.None()
	if spec.Policy != nil {
		var err error
		b, _ := json.Marshal(spec.Policy)
		if node, err = policy.Read("policy", b); err != nil {
			return nil, err
		}
		pol = node
	}
	if err := checkVariables(spec.Variables); err != nil {
		return nil, err
	}
	if err := checkHarnessHome(spec.HarnessHome); err != nil {
		return nil, err
	}
	runID := spec.RunID
	if runID == "" {
		runID = event.NewRunID()
	} else if err := CheckRunID(runID); err != nil {
		return nil, err
	}
	if err := CheckAbout(spec.About); err != nil {
		return nil, err
	}
	dir := filepath.Join(spec.RunsDir, runID)
	// Behind a wall, a place the run lists that holds one of the runner's files, or that
	// a walled agent of another run still going can change, is no run, before the server
	// is contacted and before anything starts. The run is then listed among the walled
	// runs still going until it ends, however it ends.
	plan, err := checkMounts(spec, dir)
	if err != nil {
		return nil, err
	}
	var listed *registration
	if spec.Wall != nil {
		// The wall's own binds are listed from the start, as far as it knows them, so a
		// run that starts and ends before this one binds them is checked against them.
		own, err := firstWallBinds(spec.Wall)
		if err != nil {
			return nil, err
		}
		var engine *wall.Engine
		if e, ok := spec.Wall.(wall.Engined); ok {
			v := e.Engine(ctx)
			engine = &v
		}
		if listed, err = register(runID, append(plan.sources, own...), engine); err != nil {
			return nil, err
		}
		defer listed.release()
	}
	// The server, when the run has one: discovered before anything else. The run
	// configuration it names is fetched after the ping; its policy, narrowed by the
	// node's, is then the run's, and its variables are the run's for its whole life.
	var srv *live
	var served map[string]string
	if !spec.Local && spec.Server != nil {
		b, _ := json.Marshal(spec.Server)
		cfg, err := server.Read("server", b)
		if err != nil {
			return nil, err
		}
		if spec.Heartbeat > server.MaxInterval*time.Second || spec.Heartbeat%time.Second != 0 {
			return nil, fmt.Errorf("the heartbeat interval %s is not a whole number of seconds from 1 to the %d a ping announces at most", spec.Heartbeat, server.MaxInterval)
		}
		if srv, err = discover(runCtx, cfg, spec); err != nil {
			return nil, err
		}
		srv.node = node
		if spec.Discovered != nil {
			if err := spec.Discovered(Discovery{NodeID: srv.conf.NodeID, Secrets: srv.conf.Secrets != nil}); err != nil {
				return nil, err
			}
		}
	}
	rt := spec.Runtime
	if rt == nil {
		rt = runtimes.Bare(filepath.Base(spec.Command))
	}
	// Interactive is what the caller has; interactive is what the session is. An
	// argument the runtime names as headless means pipes whatever the caller has.
	interactive := spec.Interactive && !rt.Headless(spec.Args)
	leave := rt.Stop()
	if err := CheckStopSignal(leave.Signal); err != nil {
		return nil, fmt.Errorf("runtime %s: %w", rt.Name(), err)
	}
	if spec.StopSignal == "" {
		spec.StopSignal = leave.Signal
	}
	if spec.StopGrace == 0 && leave.Grace > 0 {
		spec.StopGrace = leave.Grace
	}
	if spec.StopSignal == "" {
		spec.StopSignal = DefaultStopSignal
	}
	if spec.StopGrace == 0 {
		spec.StopGrace = DefaultStopGrace
	}
	if spec.Wall != nil && spec.ProxyBind != "" {
		return nil, errors.New("the spec names a wall and a proxy address; the wall names its own")
	}
	if spec.Timeout < 0 || spec.StopGrace < 0 || spec.Heartbeat < 0 {
		return nil, errors.New("the timeout, the stop grace or the heartbeat interval is negative")
	}
	if err := CheckStopSignal(spec.StopSignal); err != nil {
		return nil, err
	}
	if err := CheckLabels(spec.Labels); err != nil {
		return nil, err
	}
	emit := event.NewEmitter(runID, nil)
	files, err := sink.NewFile(dir)
	if err != nil {
		return nil, err
	}
	unlock, err := lock(dir)
	if err != nil {
		files.Close(ctx)
		return nil, err
	}
	defer unlock()
	sinks := sink.Multi{files}
	if spec.Events != nil {
		sinks = append(sinks, sink.NewWriter(spec.Events))
	}
	// record numbers and writes under one lock, so the order in the sinks is the order
	// of the sequence whichever goroutine emits: the proxy, the socket, the heartbeat,
	// a reload. write takes the lock; record is for a caller that holds it.
	var mu sync.Mutex
	record := func(typ string, data any) { sinks.Write(emit.Make(typ, data)) }
	write := func(typ string, data any) {
		mu.Lock()
		defer mu.Unlock()
		record(typ, data)
	}
	// The heartbeats run from the accepted ping, or from run.started without a server,
	// until the final event.
	stopBeat := func() {}
	// fail ends a run that does not start: the heartbeats stop, and the sinks are
	// closed, within closeWait. A run the server closed before it started records
	// dev.qory.run.refused with run_closed, which reaches the file sink alone.
	fail := func(err error) (*Result, error) {
		stopBeat()
		if errors.Is(context.Cause(runCtx), errRunClosed) {
			write(event.RunRefused, map[string]any{"code": accesskey.CodeRunClosed, "status": 410})
			err = &Refusal{Code: accesskey.CodeRunClosed, Status: 410, Detail: "the server closed the run before it started"}
		}
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeWait)
		defer cancel()
		sinks.Close(closeCtx)
		return nil, err
	}
	var posts *sink.Server
	var beatFrom time.Time
	if srv != nil {
		interval := int(spec.Heartbeat / time.Second)
		ping := emit.Make(event.Ping, map[string]any{"runner_version": spec.RunnerVersion, "events": srv.conf.Events.Types, "contract_version": server.Revision, "interval_seconds": interval})
		sinks.Write(ping)
		body, _ := ping.JSON()
		pingID := event.NewID()
		if err := srv.client.Ping(ctx, srv.conf.Events.URL, pingID, []byte("["+string(body)+"]")); err != nil {
			sinks.Close(ctx)
			return nil, err
		}
		beatFrom = time.Now()
		posts = sink.NewServer(srv.client, sink.Target{URL: srv.conf.Events.URL, Types: srv.conf.Events.Types}, dir, spec.Report, srv.digests, func() { closeRun(errRunClosed) })
		posts.Accepted(pingID, ping.Sequence)
		sinks = append(sinks, posts)
		srv.posts = posts
		defer srv.stop()
		stopBeat = heartbeat(runCtx, spec.Heartbeat, beatFrom, write)
		// The run configuration, when the server names one: its policy, narrowed by the
		// node's, or the node's own when it has none, and its variables.
		if srv.conf.Run != nil {
			if pol, served, err = srv.fetch(runCtx, srv.conf.Run.URL); err != nil {
				return fail(err)
			}
			srv.holds(pol.RunConfiguration)
			posts.SetRunDigest(pol.RunConfiguration)
		}
	}
	allow := pol.Policy.Egress.Allow
	if (len(pol.Policy.Credentials) > 0 || len(pol.Policy.Tools) > 0 || len(pol.Policy.Egress.Paths) > 0 || nodePaths(pol) > 0) && spec.Wall == nil {
		return fail(errors.New("the policy selects credentials or tools or has path rules, which need a wall: without one a program that ignores the proxy is bound by none of them"))
	}
	if pol.Policy.Image != "" && spec.Wall == nil {
		return fail(fmt.Errorf("the policy selects the image %q, which needs a wall: without one the runtime is this machine's process", pol.Policy.Image))
	}
	var img Image
	if spec.Wall != nil {
		if img, err = image(spec, pol.Policy.Image); err != nil {
			return fail(err)
		}
	}
	defs := make([]credential.Definition, len(spec.Credentials))
	for i, c := range spec.Credentials {
		defs[i] = credential.Definition(c)
	}
	held, err := hold(runCtx, spec, defs, pol)
	if err != nil {
		return fail(err)
	}
	// held is replaced by a reload, which is over before this runs.
	defer func() {
		if srv != nil {
			srv.stop()
		}
		held.Close()
	}()
	// The tools, started before anything else is: a tool that does not listen is no
	// run. They are stopped after the proxy is closed, so no request reaches a tool
	// that is gone.
	toolDefs := make([]tool.Definition, len(spec.Tools))
	for i, t := range spec.Tools {
		toolDefs[i] = tool.Definition(t)
	}
	chosen, err := choose(spec, toolDefs, pol, held)
	if err != nil {
		return fail(err)
	}
	// The runtime prepares the launch before the variables are resolved, because what it
	// sets is the runner's own and wins over a server's variable of the same name. Behind
	// a wall the run directory goes in read-only, apart from every place the run binds:
	// the settings are read from it, and the record in it is not the agent's to rewrite
	// or move. Behind a wall the runtime learns the placeholders the run sets.
	prepared := runtimes.Launch{Command: spec.Command, Args: spec.Args}
	attach := runtimes.Attach{Launch: prepared, RunDir: dir, Forwarder: spec.Forwarder, Interactive: interactive}
	if spec.Wall != nil {
		attach.Placeholders = append(slices.Clone(held.Placeholders), tool.Placeholders(chosen)...)
	}
	if prepared, err = rt.Prepare(attach); err != nil {
		return fail(fmt.Errorf("runtime %s: %w", rt.Name(), err))
	}
	vars, emptied, err := resolve(spec, rt, served, prepared, held, chosen)
	if err != nil {
		return fail(err)
	}
	if spec.OnVariables != nil {
		spec.OnVariables(applied(vars.Applied))
	}
	tools, err := tool.Start(runCtx, chosen, runID, toolEnv(spec.Credentials), spec.Report)
	if err != nil {
		return fail(err)
	}
	defer tools.Close()
	// The wall comes before the proxy, because it says where the proxy must listen, and
	// goes after everything else, because the proxy outlives the last connection.
	var enclosure wall.Enclosure
	bind := spec.ProxyBind
	if spec.Wall != nil {
		if enclosure, err = spec.Wall.Prepare(runCtx, wall.Request{RunID: runID, Image: img.Ref, Runtime: img.Runtime, Docker: img.Docker}); err != nil {
			return fail(err)
		}
		defer func() {
			// The run's context may be what ended the run; the wall is removed regardless.
			if err := enclosure.Close(context.WithoutCancel(ctx)); err != nil {
				spec.Report("removing the wall: " + err.Error())
				// Its containers may outlive the run: the entry stays, and is the run's
				// while one of them exists.
				listed.keep()
			}
		}()
		bind = enclosure.ProxyAddr()
	}

	px, err := proxy.Listen(bind, pol.Policy.Egress.Mode, allow, pol.Policy.Egress.Deny, func(d proxy.Decision) { write(event.RunEgress, egress(d)) })
	if err != nil {
		return fail(err)
	}
	defer px.Close()
	if spec.Wall != nil || spec.ProxyBind != "" {
		// The proxy serves something that is not on this machine, so this machine's own
		// addresses are not its to reach.
		px.Guard(pol.Policy.Egress.Allow)
	}
	// The node's path rules, beside a server's: fixed for the run, so a reload that
	// brings a server's policy is narrowed by them as the start is.
	if node != nil && srv != nil {
		px.NodePaths(node.Policy.Egress.Paths)
	}
	// The run's authority: for the hosts a credential is for and the hosts with path
	// rules, and behind a wall with a server always, since a reload may bring a run
	// configuration with path rules or credentials, and the enclosure trusts only what
	// it was given at start.
	var authority []byte
	if len(held.Uses) > 0 || len(chosen) > 0 || len(pol.Policy.Egress.Paths) > 0 || nodePaths(pol) > 0 || (spec.Wall != nil && srv != nil) {
		ca, err := proxy.NewCA(runID)
		if err != nil {
			return fail(err)
		}
		px.Terminate(ca, proxyUses(held), pol.Policy.Egress.Paths, proxyTools(tools))
		authority = ca.PEM()
	}
	// Behind a wall the proxy listens where other containers of the engine, or other
	// processes of the machine, may reach it. It serves the run's relay alone.
	token := ""
	if spec.Wall != nil {
		token = event.NewID() + event.NewID()
		var once sync.Once
		px.Require(token, func() {
			once.Do(func() { spec.Report("a connection to the proxy that was not the run's relay was refused") })
		})
	}

	sock, err := socket.Listen()
	if err != nil {
		return fail(err)
	}
	records := func(r runtimes.Record) {
		if typ, data, ok := rt.Map(r); ok {
			write(typ, data)
		}
	}
	go sock.Serve(records, func(err error) { spec.Report("socket: " + err.Error()) })
	closeSocket := sync.OnceFunc(func() { sock.Close() })
	defer closeSocket()

	command, args := prepared.Command, prepared.Args
	// What is started: the runtime itself, or under a wall the adapter's command that
	// starts it inside, which sets the proxy and socket variables by the addresses the
	// enclosure reaches them on. The environment is what the run inherits, then the
	// variables as resolved, the harness's computed values, what the runtime's
	// preparation sets and the runner's own, each over the ones before, and behind a
	// wall the placeholders and, empty, the runtime's declared and reserved variables
	// nothing sets, so an image's own value for one does not reach the runtime. The
	// resolution has left out every value of a fixed name, so what wins here by position
	// is what the record says.
	own := []string{EnvRunID + "=" + runID}
	if spec.HarnessHome != "" {
		own = append(own, EnvHarnessHome+"="+spec.HarnessHome)
	}
	launch := wall.Launch{
		Command: command, Args: args, Dir: spec.Dir,
		Env: environment(spec.Env, vars.Env, vars.Fixed, prepared.Env, px.Env(), []string{EnvSocket + "=" + sock.Path()}, own),
	}
	if enclosure != nil {
		// The places again, just before the enclosure binds them, and the wall's own
		// binds, which exist by now, against the walled runs still going; the run's entry
		// then lists them all. No walled agent of this user's can change a directory a
		// name on the way to a place or the run directory is looked up in, the start's
		// checks saw to that; the user, or a process outside every wall, can. A place
		// that resolves otherwise than at the start, or whose names are looked up in
		// other directories, fails the run; what changes after this point is not seen.
		again, err := checkMounts(spec, dir)
		if err != nil {
			return fail(err)
		}
		if err := samePlan(plan, again); err != nil {
			return fail(err)
		}
		binds, err := wallBinds(enclosure, sock.Path(), authority)
		if err != nil {
			return fail(err)
		}
		listed.askID(runCtx, spec.Wall)
		if err := listed.update(append(again.sources, binds...)); err != nil {
			return fail(err)
		}
		launch, err = enclosure.Wrap(runCtx, wall.Launch{
			Command: command, Args: args, Dir: plan.Dir, Interactive: interactive,
			Env:   environment(spec.Env, vars.Env, vars.Fixed, prepared.Env, own, placeholders(held.Placeholders), placeholders(tool.Placeholders(chosen)), emptied),
			CA:    authority,
			Proxy: px.Addr(), Socket: sock.Path(), Mounts: plan.Mounts, Limits: spec.Limits,
			ProxyToken: token,
		})
		if err != nil {
			return fail(err)
		}
	}

	// A run the server closed during its start does not start: the start's steps run
	// under runCtx, and whatever they reached ends here.
	if errors.Is(context.Cause(runCtx), errRunClosed) {
		return fail(errRunClosed)
	}
	start := time.Now()
	started := map[string]any{
		"runtime": rt.Name(), "command": command, "args": args,
		"dir": spec.Dir, "interactive": interactive, "runner_version": spec.RunnerVersion, "host": hostname(),
	}
	if v := rt.Version(); v != "" {
		started["runtime_version"] = v
	}
	// The pseudo-terminal's size is in the record, so a replay can lay the redraws of
	// a full-screen program over each other: the size it starts with here, each change
	// as run.resized.
	var cols, rows int
	if interactive {
		cols, rows = terminalSize(spec.Stdin)
		started["terminal"] = map[string]any{"cols": cols, "rows": rows}
	}
	if spec.Wall != nil {
		started["wall"] = spec.Wall.Name()
		started["image"] = img.Ref
		if img.Name != "" {
			started["image_name"] = img.Name
		}
		if img.Runtime != "" {
			started["container_runtime"] = img.Runtime
		}
		if img.Docker {
			started["docker"] = true
		}
	}
	if len(spec.Labels) > 0 {
		started["labels"] = spec.Labels
	}
	if about := server.ReportedAbout(spec.About); about != nil {
		started["about"] = about
	}
	write(event.RunStarted, started)
	// policyApplied is the policy_applied event of a policy: the one pinned at start,
	// and each one a reload puts in its place.
	policyApplied := func(pol *policy.Loaded, held *credential.Held) map[string]any {
		allow, deny := pol.Policy.Egress.Allow, pol.Policy.Egress.Deny
		if allow == nil {
			allow = []string{}
		}
		if deny == nil {
			deny = []string{}
		}
		a := map[string]any{"mode": string(pol.Policy.Egress.Mode), "allow": allow, "deny": deny, "source": pol.Source}
		if pol.Source != "none" {
			a["digest"] = pol.Digest
		}
		if pol.URL != "" {
			a["url"], a["run_configuration"] = pol.URL, pol.RunConfiguration
		}
		if pol.Node != nil {
			np := map[string]any{"digest": pol.Node.Digest}
			if len(pol.Node.Paths) > 0 {
				np["paths"] = pol.Node.Paths
			}
			a["node_policy"] = np
		}
		a["variables"] = vars.Applied
		if spec.Declared != nil {
			a["harness_hosts"] = spec.Declared
		}
		if len(pol.Policy.Egress.Paths) > 0 {
			a["paths"] = pol.Policy.Egress.Paths
		}
		if len(held.Uses) > 0 {
			uses := make([]map[string]any, len(held.Uses))
			for i, u := range held.Uses {
				uses[i] = map[string]any{"name": u.Name, "hosts": u.Hosts, "scheme": u.Scheme}
				if u.Argument != "" {
					uses[i]["argument"] = u.Argument
				}
				if u.Paths != nil {
					uses[i]["paths"] = u.Paths
				}
			}
			a["credentials"] = uses
		}
		if len(chosen) > 0 {
			used := make([]map[string]any, len(chosen))
			for i, c := range chosen {
				used[i] = map[string]any{"name": c.Name, "hosts": c.Serves}
				if c.Argument != "" {
					used[i]["argument"] = c.Argument
				}
			}
			a["tools"] = used
		}
		if pol.Policy.Image != "" {
			a["image"] = pol.Policy.Image
		}
		if hosts := px.Terminated(); len(hosts) > 0 {
			a["terminated"] = hosts
		}
		return a
	}
	write(event.PolicyApplied, policyApplied(pol, held))
	if srv != nil {
		// A reload is as strict as a start. What a start refuses, a policy that selects
		// credentials without a wall, a credential that does not resolve, fails the
		// reload and leaves the policy in force. Path rules the proxy cannot hold,
		// for want of the run's authority, take their hosts out of the allow list
		// instead, so they are not reached on every path. Then it takes effect under the
		// record's lock: the policy and its credentials go to the proxy in one step, the
		// event is written, and the tunnels it closed are recorded after it, before any
		// other event.
		srv.start(func(next *policy.Loaded) error {
			in := *next
			if !sameTools(in.Policy.Tools, pol.Policy.Tools) {
				return errors.New("the run configuration selects other tools than the run started with; a run's tools are fixed when it starts")
			}
			// The image compared is the one the selection resolves to, so naming the
			// machine's default, or no longer naming it, is no change.
			if spec.Wall == nil {
				if in.Policy.Image != "" {
					return fmt.Errorf("the run configuration selects the image %q, which needs a wall", in.Policy.Image)
				}
			} else if next, err := image(spec, in.Policy.Image); err != nil {
				return err
			} else if next != img {
				return errors.New("the run configuration selects another image than the run started in; a run's image is fixed when it starts")
			}
			if !px.Terminates() {
				if len(in.Policy.Credentials) > 0 {
					return errors.New("the run configuration selects credentials, which need a wall")
				}
				if len(in.Policy.Egress.Paths) > 0 {
					in.Policy.Egress.Allow = withoutHeld(in.Policy.Egress.Allow, in.Policy.Egress.Paths)
					in.Policy.Egress.Paths = nil
					spec.Report("the run configuration has path rules, which need a wall; the hosts they hold are taken out of the allow list")
				}
			}
			fresh, err := hold(ctx, spec, defs, &in)
			if err != nil {
				return err
			}
			if err := tool.Check(chosen, in.Policy.Egress.Mode, in.Policy.Egress.Allow, claimedBy(fresh)); err != nil {
				fresh.Close()
				return err
			}
			mu.Lock()
			refused := px.SetPolicy(in.Policy.Egress.Mode, in.Policy.Egress.Allow, in.Policy.Egress.Deny, in.Policy.Egress.Paths, proxyUses(fresh))
			old := held
			held = fresh
			posts.SetRunDigest(in.RunConfiguration)
			record(event.PolicyApplied, policyApplied(&in, fresh))
			for _, d := range refused {
				record(event.RunEgress, egress(d))
			}
			mu.Unlock()
			old.Close()
			return nil
		})
	}

	logs := func(stream string) func([]byte) {
		return func(b []byte) { write(event.RunLog, map[string]any{"stream": stream, "bytes": encode(b)}) }
	}
	output := func(r map[string]any) { records(runtimes.Record{Source: runtimes.SourceOutput, Record: r}) }
	if !rt.ReadsOutput() {
		output = nil
	}
	resized := func(cols, rows int) { write(event.RunResized, map[string]any{"cols": cols, "rows": rows}) }
	proc := &process{stop: stopSignals[spec.StopSignal], grace: spec.StopGrace, command: launch.Command, args: launch.Args, env: launch.Env, dir: launch.Dir, stdin: spec.Stdin, stdout: spec.Stdout, stderr: spec.Stderr, logs: logs, output: output, cols: cols, rows: rows, resized: resized}
	if srv == nil {
		stopBeat = heartbeat(runCtx, spec.Heartbeat, start, write)
	}
	// The limit ends the runtime and nothing else: the sinks and the wall are closed on
	// the caller's context, as after any exit. The server closing the run ends it the
	// same way.
	limited, cancelLimit := context.WithCancel(runCtx)
	if spec.Timeout > 0 {
		limited, cancelLimit = context.WithTimeoutCause(runCtx, spec.Timeout, errTimeout)
	}
	var exit exitStatus
	if interactive {
		exit, err = proc.runPTY(limited)
	} else {
		exit, err = proc.runPipes(limited)
	}
	// A runtime that exited with 0 as the limit fell finished; the limit was not why.
	timedOut := exit.code != 0 && errors.Is(context.Cause(limited), errTimeout)
	// A run the server closed has nothing further sent, whatever the runtime's status.
	closed := errors.Is(context.Cause(runCtx), errRunClosed)
	cancelLimit()
	stopBeat()
	closeSocket()
	if srv != nil {
		// A reload still in flight ends here: nothing of it goes after run.exited.
		srv.stop()
	}
	if err != nil && !closed {
		sinks.Close(ctx)
		return nil, err
	}
	// A runtime the close kept from starting has no status of its own: the run ends as
	// a closed one, with -1.
	if err != nil {
		exit = exitStatus{code: -1}
	}
	state := "failed"
	if exit.code == 0 && !closed {
		state = "succeeded"
	}
	exited := map[string]any{"state": state, "exit_code": exit.code, "duration_ms": time.Since(start).Milliseconds()}
	if exit.signal != "" {
		exited["signal"] = exit.signal
	}
	switch {
	case closed:
		exited["reason"] = accesskey.CodeRunClosed
	case timedOut:
		exited["reason"] = "timeout"
		spec.Report(fmt.Sprintf("the runtime was stopped at the limit of %s", spec.Timeout))
	}
	write(event.RunExited, exited)
	closeCtx, cancel := context.WithTimeout(context.Background(), closeWait)
	defer cancel()
	if err := sinks.Close(closeCtx); err != nil {
		spec.Report("closing the sinks: " + err.Error())
	}
	res := &Result{RunID: runID, Dir: dir, ExitCode: exit.code, Signal: exit.signal, State: state, TimedOut: timedOut && !closed, RunClosed: closed}
	if posts != nil {
		res.Undelivered = posts.Undelivered()
	}
	return res, nil
}

// withDefaults fills what the spec left empty.
func withDefaults(spec Spec) Spec {
	if spec.Dir == "" {
		spec.Dir, _ = os.Getwd()
	}
	if spec.RunsDir == "" {
		spec.RunsDir = filepath.Join(spec.Dir, ".qory", "runs")
	}
	if spec.Env == nil && spec.Wall == nil {
		spec.Env = os.Environ()
	}
	if spec.Heartbeat == 0 {
		spec.Heartbeat = 30 * time.Second
	}
	if spec.Stdin == nil {
		spec.Stdin = os.Stdin
	}
	if spec.Stdout == nil {
		spec.Stdout = os.Stdout
	}
	if spec.Stderr == nil {
		spec.Stderr = os.Stderr
	}
	if spec.Report == nil {
		stderr := spec.Stderr
		spec.Report = func(line string) { fmt.Fprintln(stderr, "qory run:", line) }
	}
	if spec.RunnerVersion == "" {
		spec.RunnerVersion = "dev"
	}
	return spec
}

// placeholders are the variables a program wants set before it starts, with a value
// that is no credential.
func placeholders(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = n + "=" + credential.Placeholder
	}
	return out
}

// environment is the session's environment: base with the runner's variables set,
// replacing any of the same names, and without the access key's variables, whichever
// of them brought one.
func environment(base []string, sets ...[]string) []string {
	var extra []string
	for _, s := range sets {
		extra = append(extra, s...)
	}
	names := map[string]bool{}
	for _, kv := range extra {
		name, _, _ := strings.Cut(kv, "=")
		names[name] = true
	}
	out := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		if !names[name] {
			out = append(out, kv)
		}
	}
	return accesskey.WithoutVariables(append(out, extra...))
}

// heartbeat emits run.heartbeat every interval, its elapsed seconds counted from
// start, until the returned function is called; calling it again does nothing.
func heartbeat(ctx context.Context, interval time.Duration, start time.Time, write func(string, any)) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				write(event.RunHeartbeat, map[string]any{"elapsed_seconds": int(time.Since(start).Seconds()), "interval_seconds": int(math.Ceil(interval.Seconds()))})
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return sync.OnceFunc(func() { close(done); <-stopped })
}

// hold resolves the credentials a policy selects, as the machine defines them, and
// refuses a placeholder the run passes a value for: at the start and at every reload
// alike.
func hold(ctx context.Context, spec Spec, defs []credential.Definition, pol *policy.Loaded) (*credential.Held, error) {
	held, err := credential.Resolve(ctx, defs, pol.Policy.Credentials, pol.Policy.Egress.Mode, pol.Policy.Egress.Allow, spec.Report)
	if err != nil {
		return nil, err
	}
	for _, name := range held.Placeholders {
		if passes(spec, name) {
			held.Close()
			return nil, refusal.New(refusal.PlaceholderConflict, []string{name}, "%s is a placeholder of a credential the runner holds outside the enclosure, and the run passes a value for it inside", name)
		}
	}
	return held, nil
}

// choose resolves the tools a policy selects, as the machine defines them, beside the
// credentials the run holds, and refuses a placeholder the run passes a value for.
func choose(spec Spec, defs []tool.Definition, pol *policy.Loaded, held *credential.Held) ([]tool.Chosen, error) {
	chosen, err := tool.Choose(defs, pol.Policy.Tools)
	if err != nil {
		return nil, err
	}
	if err := tool.Check(chosen, pol.Policy.Egress.Mode, pol.Policy.Egress.Allow, claimedBy(held)); err != nil {
		return nil, err
	}
	for _, name := range tool.Placeholders(chosen) {
		if passes(spec, name) {
			return nil, refusal.New(refusal.PlaceholderConflict, []string{name}, "%s is a placeholder of a tool the runner starts outside the enclosure, and the run passes a value for it inside", name)
		}
	}
	return chosen, nil
}

// claimedBy names the held credential that is for a host, or above or below it; empty
// when none is.
func claimedBy(held *credential.Held) func(string) string {
	return func(host string) string {
		for _, u := range held.Uses {
			for _, h := range u.Hosts {
				if policy.Covers(h, host) || policy.Covers(host, h) {
					return u.Name
				}
			}
		}
		return ""
	}
}

// sameTools reports whether two selections of tools are the same, in any order.
func sameTools(a, b []policy.Selected) bool {
	order := func(s []policy.Selected) []policy.Selected {
		s = slices.Clone(s)
		slices.SortFunc(s, func(x, y policy.Selected) int {
			return strings.Compare(x.Name+"\x00"+x.Argument, y.Name+"\x00"+y.Argument)
		})
		return s
	}
	return slices.Equal(order(a), order(b))
}

// toolEnv is the environment a tool gets: the runner's own, without the variables the
// machine's credentials and the access key are read from, which are the runner's to
// hold and no tool's.
func toolEnv(creds []Credential) []string {
	var out []string
	for _, kv := range accesskey.WithoutVariables(os.Environ()) {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.ContainsFunc(creds, func(c Credential) bool { return c.Env == name }) {
			out = append(out, kv)
		}
	}
	return out
}

// proxyTools are the running tools as the proxy reaches them.
func proxyTools(set *tool.Set) []proxy.Tool {
	out := make([]proxy.Tool, len(set.Tools))
	for i, t := range set.Tools {
		out[i] = proxy.Tool{Name: t.Name, Hosts: t.Serves, Socket: t.Socket}
	}
	return out
}

// proxyUses are the held credentials as the proxy sets them.
func proxyUses(held *credential.Held) []proxy.Credential {
	uses := make([]proxy.Credential, len(held.Uses))
	for i, u := range held.Uses {
		uses[i] = proxy.Credential{Name: u.Name, Hosts: u.Hosts, Scheme: u.Scheme, Username: u.Username, Header: u.Header, Paths: u.Paths, Token: u.Token, Rejected: u.Rejected}
	}
	return uses
}

// withoutHeld is an allow list without the hosts path rules hold, for a proxy that
// cannot hold them: an entry goes when it is a held host, stands under one or stands
// above one, since what stays would be reached on every path. Under enforce the hosts
// are then denied and recorded like any other.
func withoutHeld(allow []string, paths map[string][]string) []string {
	out := []string{}
	for _, entry := range allow {
		keep := true
		for host := range paths {
			if policy.Covers(host, entry) || policy.Covers(entry, host) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, entry)
		}
	}
	return out
}

// egress is the egress event of one decision.
func egress(d proxy.Decision) map[string]any {
	decision := "denied"
	if d.Allowed {
		decision = "allowed"
	}
	data := map[string]any{"host": d.Host, "port": d.Port, "method": d.Method, "decision": decision, "mode": string(d.Mode), "rule": d.Rule, "outcome": d.Outcome}
	if d.Path != "" {
		data["request_method"], data["path"], data["path_rule"] = d.RequestMethod, d.Path, d.PathRule
	}
	if d.Credential != "" {
		data["credential"] = d.Credential
	}
	if d.Tool != "" {
		data["tool"] = d.Tool
	}
	if d.RequestID != "" {
		data["request_id"] = d.RequestID
	}
	if d.Status != 0 {
		data["status"] = d.Status
	}
	return data
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// ErrNotStarted wraps a failure to start the program, so a caller tells it from the
// runtime's own failure.
var ErrNotStarted = errors.New("the runtime did not start")
