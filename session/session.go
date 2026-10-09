package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session/internal/socket"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/sink"
	"github.com/qoryai/forager/wall"
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
	// server's variables win over it, apart from it, so the session distinguishes them
	// from what is merely inherited (contracts/forager/v1/README.md §Variables). The
	// access key's variables, QORY_ACCESS_KEY_SECRET, QORY_ACCESS_KEY_ID and
	// QORY_APIARY_PUBLIC_KEY, are left out of what the session gets from any of them.
	Env []string
	Dir string
	// LaunchFixed is the values the harness computes itself, NAME=value. They are fixed
	// names of the run: they win over every other source of a variable, the built-in
	// deny list, denied-variables.json, leaves one out, and the runtime's denies and
	// Variables.Deny do not. Forager's, the wall's and the runtime preparation's
	// names win over them.
	LaunchFixed []string
	// LaunchDefaults is the values the harness's author wrote as defaults, NAME=value.
	// They win over Env and lose to every other source.
	LaunchDefaults []string
	// Variables are the run's and the machine's variables, and how the run takes the
	// variables of the server's run configuration, which the gateway's run answer
	// carries.
	Variables Variables
	// HarnessHome is the harness's home as the agent's process sees it, an absolute
	// path; empty means none. When set, the session sets QORY_HARNESS_HOME to it, as one
	// of its own names, like QORY_RUN_ID.
	HarnessHome string
	// OnVariables, when not nil, is called once the run's variables are resolved,
	// before the wall and the agent start, with each name, its source and the values
	// that lost, as dev.qory.run.policy_applied records them: qory prints a line for an
	// --env value that lost. A run refused before then does not call it.
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
	// Gateway is the gateway the run speaks to, [LocalGateway] on this machine or a
	// [RemoteGateway] on a machine of its own: it holds the run's proxy, its policy, its
	// credentials and its tools, decides the run's policy and image, numbers the run's
	// events and is the node toward the server. The session speaks to it alone, over its
	// link. A run needs one.
	Gateway Gateway
	// Wall, when not nil, encloses the runtime: the command is started inside an
	// enclosure whose only route out leads to the gateway's proxy, in the image the
	// gateway's run answer gives, with Dir as its workspace and working directory.
	// Command, Args and Forwarder are then paths inside the enclosure. Nil means no wall:
	// the runtime is this machine's process, and enforcement is cooperative.
	Wall wall.Wall
	// Image is the agent's image under a Wall when the policy selects none: the name
	// of one of Images, or a reference.
	Image string
	// Images are the images this machine defines; the run's policy selects among them
	// by name, as it selects credentials and tools, and a selection needs a Wall. The
	// image a run starts in is fixed when it starts. The run request carries them, so
	// the gateway resolves the policy's selection against them.
	Images []Image
	// Mounts are what the enclosure shows of this machine, each at its own path: the
	// checkout around Dir, a composed home outside it. A mount, or Dir, inside another
	// one of the same mode is reached through the outer one, which alone is bound; one of
	// the other mode is no run, mount_mode_conflict. One whose path goes through a link
	// inside a writable one, and that does not resolve into it, is no run, whatever its
	// mode, mount_through_link. Dir is writable, and is bound at its own path when no mount
	// holds it. The session adds the run directory, read-only. A walled run refuses a
	// bind that lies inside, or is reached through, a writable bind of another walled
	// run of this user's still going, apart from the same root, a writable one that
	// holds one of that run's binds or the way to one, and one that is, holds or lies
	// inside that run's run directory: mount_shared_with_run. Without a Wall they mean
	// nothing.
	Mounts []wall.Mount
	// ForagerFiles are the absolute paths of the caller's files that are Forager's
	// own, such as the directory of qory's forager.yaml with the access key secret. A
	// walled run refuses a mount, or a workspace, that is, contains or lies inside one of
	// them, one of the gateway's files, or one of the paths Forager knows itself,
	// RunsDir among them, mount_contains_forager_files: see [Overlap].
	ForagerFiles []string
	// Declared is the egress the harness declared, nil when nothing was. It is
	// reported in dev.qory.run.policy_applied as harness_hosts and decides nothing:
	// the policy alone decides.
	Declared []string
	// RunsDir holds the run directories; empty means Dir/.qory/runs. It is one of
	// Forager's files, so a walled run needs one outside its mounts and Dir.
	RunsDir string
	// Forwarder is the command the Runtime installs as the program's hook: it reads the
	// hook's input and forwards it to the socket. Empty means no hooks are installed.
	Forwarder []string
	// ForagerVersion is reported in the events.
	ForagerVersion string
	// RunID is the run's id when a parent already made one; empty means a new one. It is
	// a UUID in the canonical lower-case form, because it is the events' subject and names
	// the run directory; anything else is refused.
	RunID string
	// Labels are the caller's own names for the run, its key in a queue, a repository, an
	// issue: sent on the run request, so the gateway asks the server for the run's policy
	// by them, and reported in run.started, as the gateway's run answer holds them, and
	// no other event. Behind a [RemoteGateway] the run's labels are the run credential's,
	// and a label sent here with another value is refused. Forager reads nothing into
	// them. At most MaxLabels; a key is 1 to 64 of a-z, 0-9, underscore, dot and dash, a
	// value at most 256 bytes.
	Labels map[string]string
	// About is what the run is about, as the caller passed it: the kind of run, a title,
	// the subjects it works on and details. It is sent on the run request and reported in
	// run.started and no other event, so a receiver shows the run by it; it never selects
	// a policy. Forager reads nothing into it. CheckAbout holds it to its bounds before
	// the gateway is contacted. Nil, or an About whose every member is empty, is left
	// out. An empty Kind, Title or Subjects counts as absent and is left out of the
	// event. Details is shown to every reader of the run, so it never holds a secret.
	About *About
	// Timeout is how long the runtime may run; zero means no limit. At the limit the
	// runtime is stopped the way the context ending stops it, and run.exited carries
	// the reason.
	Timeout time.Duration
	// StopSignal is the signal that asks the runtime to leave when the session stops it,
	// at the Timeout or the context's end: one CheckStopSignal passes. A runtime may
	// close a session on one signal and drop it on another, and which is the runtime's
	// to say, not the session's. Empty means the Runtime's, and DefaultStopSignal when it
	// names none.
	StopSignal string
	// StopGrace is how long the runtime gets between the stop signal and SIGKILL: the
	// time a session needs to close what it has open. Zero means the Runtime's, and
	// DefaultStopGrace when it names none.
	StopGrace time.Duration
	// Limits are the resources the enclosure gives the runtime. Without a Wall they mean
	// nothing.
	Limits wall.Limits
	// Report receives one line per thing the session reports to its user; nil means Stderr.
	Report func(string)
}

// Result is what a run came to: what the session knows of it. What reached the server
// is the gateway's to say.
type Result struct {
	RunID string
	// Dir is the run directory holding the session's record, session.jsonl and
	// output.log; on one machine the gateway writes the run's stream, events.jsonl,
	// beside them.
	Dir string
	// ExitCode is the runtime's, or -1 when a signal killed it.
	ExitCode int
	// Signal names the signal that killed the runtime, if one did.
	Signal string
	// State is succeeded or failed.
	State string
	// TimedOut says the runtime was stopped at the spec's Timeout.
	TimedOut bool
	// Undelivered is how many of the session's events the gateway did not accept.
	Undelivered int
	// RunClosed says the run was closed from outside, a 410 on the gateway's link, or
	// the gateway's 400 to a batch, which ends the run there: the runtime was stopped as
	// at its time limit, and the session's record has run.exited with ClosedReason as
	// its reason.
	RunClosed bool
	// ClosedBy is who closed the run when RunClosed: "apiary", the server, or
	// "gateway", the gateway itself.
	ClosedBy string
	// ClosedReason is the code the run was closed with when RunClosed, the 410's code
	// as the gateway answered it: run_closed, credential_expired or
	// run_ended_at_issuer; from the gateway, issuer_unreachable when its issuer's
	// introspection endpoint could not be reached, issuer_answer_invalid when it gave no
	// valid answer, session_lost when it heard nothing from the session for three
	// heartbeat intervals, and batch_refused when it refused a batch of the session's.
	ClosedReason string
}

// Refusal is a run that did not start, and why: its refusal code, the status of the
// answer when the code came from one, and who refused, From. A refusal the gateway
// passes on from the server, From apiary, keeps the server's code and status, such as
// run_closed when the server closes the run before it starts; the gateway's own, From
// gateway, are run_id_used and the codes Forager decides, run_configuration_invalid,
// placeholder_conflict, tool_unknown and image_unknown among them. The session's own
// refusals have no From: variable_reserved, mount_contains_forager_files,
// mount_mode_conflict and mount_shared_with_run among them, with the names they concern
// and never a value. errors.As finds one in what [Run] returns.
type Refusal = accesskey.Refusal

// The environment variables the session gets from Forager. EnvHarnessHome is set
// when the spec has a HarnessHome.
const (
	EnvRunID       = "QORY_RUN_ID"
	EnvSocket      = link.EnvRunSocket
	EnvHarnessHome = "QORY_HARNESS_HOME"
)

// MaxLabels is how many labels a run may carry.
const MaxLabels = server.MaxLabels

// errTimeout is the cause of the runtime's context ending at the spec's Timeout.
var errTimeout = errors.New("the run's time limit")

// errRunClosed is the cause of the run's context ending when the run is closed from
// outside: a 410 on the link, or the gateway's 400 to a batch.
var errRunClosed = errors.New("the run was closed")

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
// its form, a URL that is not an absolute http or https one or that has a user name or
// password, two subjects with the same type and ref, and details that are not a JSON
// object of at most 8192 bytes as the event contains them and 4 levels. It returns the
// first failure as an [*AboutError]. [Run] checks it before it contacts the gateway; a
// command may first.
func CheckAbout(a *About) error { return server.CheckAbout(a) }

// closeWait is how long the sinks get to flush after the runtime exits.
const closeWait = 15 * time.Second

// ended is how a run was closed from outside: the code and who closed it, set once.
type ended struct {
	mu         sync.Mutex
	code, from string
}

func (e *ended) set(code, from string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.code == "" {
		e.code, e.from = code, from
	}
}

func (e *ended) get() (string, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.code, e.from
}

// Run runs one session and returns when the runtime has exited and the sinks are
// flushed. An error means the run did not start: the spec is refused, the gateway's
// link could not be reached, the gateway refused the run request, the descriptor is
// unknown, the wall could not be built, or the program could not be started. A refusal
// with a code is a [*Refusal]; a failure without one at the gateway is its text as the
// user is told it. Once the runtime runs, its exit is the result and not an error. The
// context ending stops the runtime, and so does the run being closed from outside.
func Run(ctx context.Context, spec Spec) (*Result, error) {
	spec = withDefaults(spec)
	local, remote, err := gatewayOf(spec.Gateway)
	if err != nil {
		return nil, err
	}
	// runCtx ends when the run is closed from outside, a 410 on the link or the
	// gateway's 400 to a batch: the start stops, or the runtime is stopped as at its
	// time limit.
	runCtx, closeRun := context.WithCancelCause(ctx)
	defer closeRun(nil)
	var closedBy ended
	end := func(code, from string) {
		closedBy.set(code, from)
		closeRun(errRunClosed)
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
	// Behind a wall, a place the run lists that holds one of Forager's files, or that
	// a walled agent of another run still going can change, is no run, before the
	// gateway is contacted and before anything starts. The run is then listed among the
	// walled runs still going until it ends, however it ends.
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
	if spec.Timeout < 0 || spec.StopGrace < 0 {
		return nil, errors.New("the timeout or the stop grace is negative")
	}
	if err := CheckStopSignal(spec.StopSignal); err != nil {
		return nil, err
	}
	if err := CheckLabels(spec.Labels); err != nil {
		return nil, err
	}
	// The checks of the machine's own image table have no code: the session makes
	// them before the run request, as before the gateway resolves a selection.
	if spec.Wall != nil {
		if err := checkImages(spec); err != nil {
			return nil, err
		}
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
	var k *server.Link
	if remote != nil {
		// A separate gateway: TLS 1.3 to its one address, and the run credential on every
		// request.
		k, err = remote.link(spec.ForagerVersion, digests)
	} else {
		k, err = server.NewLocalLink(local.local, accesskey.UserAgent(spec.ForagerVersion), digests)
	}
	if err != nil {
		return nil, err
	}
	defer k.Close()
	lastAnswered := func() string {
		answeredMu.Lock()
		defer answeredMu.Unlock()
		return answered.RunConfiguration
	}
	disc, err := k.Discover(runCtx)
	if err == nil && disc.Proxy == nil {
		err = errors.New("the link's discovery names no proxy")
	}
	// The local link's proxy is on loopback; a separate gateway's is its one address,
	// which the link's discovery checked.
	if err == nil && local != nil && !loopback(disc.Proxy.Address) {
		err = fmt.Errorf("the gateway's discovery names the proxy %q, which is no address on loopback: the local link's proxy is on this machine", disc.Proxy.Address)
	}
	if err == nil && disc.Events.IntervalSeconds < 1 {
		err = errors.New("the link's discovery names no heartbeat interval")
	}
	if err != nil {
		return nil, err
	}
	// A run id that has a record is no run, as it always was: the run's stream, which
	// the gateway writes beside the session's record, is checked first.
	if _, err := os.Lstat(filepath.Join(dir, sink.EventsFile)); err == nil {
		return nil, &fs.PathError{Op: "open", Path: filepath.Join(dir, sink.EventsFile), Err: syscall.EEXIST}
	}
	discovered := time.Now()
	interval := time.Duration(disc.Events.IntervalSeconds) * time.Second
	emit := event.NewEmitter(runID, nil)
	files, err := sink.NewFileAs(dir, sink.SessionFile)
	if err != nil {
		return nil, err
	}
	unlock, err := lock(dir)
	if err != nil {
		files.Close(ctx)
		return nil, err
	}
	defer unlock()
	// record numbers and writes under one lock, so the order in the sinks is the order
	// of the sequence whichever goroutine emits: the socket, the heartbeat, a reload.
	// write takes the lock; record is for a caller that holds it. own writes to the
	// session's record alone. The link's sink joins the sinks once the run is open at
	// the gateway.
	var mu sync.Mutex
	sinks := sink.Multi{files}
	record := func(typ string, data any) { sinks.Write(emit.Make(typ, data)) }
	write := func(typ string, data any) {
		mu.Lock()
		defer mu.Unlock()
		record(typ, data)
	}
	own := func(typ string, data any) {
		mu.Lock()
		defer mu.Unlock()
		files.Write(emit.Make(typ, data))
	}
	closeSinks := func(ctx context.Context) error {
		mu.Lock()
		all := sinks
		mu.Unlock()
		return all.Close(ctx)
	}
	// The heartbeats run from the link's discovery, every interval it announces, until
	// the final event.
	stopBeat := heartbeat(runCtx, interval, discovered, write)
	// quit ends a run that does not start: the heartbeats stop, and the sinks are
	// closed, within closeWait.
	quit := func(err error) (*Result, error) {
		stopBeat()
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeWait)
		defer cancel()
		closeSinks(closeCtx)
		return nil, err
	}
	// fail is quit with the record of why. A run closed from outside before it started
	// records dev.qory.run.refused with its code in the session's record alone. A
	// refusal of the session's own, with a code it decides, is posted on the link too
	// once the run is open at the gateway, which ends it there.
	fail := func(err error) (*Result, error) {
		var r *Refusal
		switch {
		case errors.Is(context.Cause(runCtx), errRunClosed):
			code, from := closedBy.get()
			own(event.RunRefused, map[string]any{"code": code, "status": http.StatusGone})
			err = &Refusal{Code: code, Status: http.StatusGone, From: from, Detail: closedDetail(from)}
		case errors.As(err, &r) && refusal.Decides(r.Code):
			data := map[string]any{"code": r.Code}
			if len(r.Names) > 0 {
				data["names"] = r.Names
			}
			write(event.RunRefused, data)
		}
		return quit(err)
	}
	req := server.LinkRunRequest{RunID: runID, Wall: spec.Wall != nil, Labels: spec.Labels, About: server.ReportedAbout(spec.About), Passes: passes(spec)}
	if spec.Wall != nil {
		req.Images = linkImages(spec)
	}
	answer, err := k.OpenRun(runCtx, disc.Run.URL, req)
	if err != nil {
		return refused(err, fail, quit, own, end)
	}
	reload := newReloader(runCtx, k, disc.Run.URL, runID, lastAnswered(), lastAnswered, spec.Report)
	defer reload.stop()
	// Behind a separate gateway the run directory keeps what the gateway accepted and
	// what it did not, delivered.log and undelivered/, so a resend knows what it still
	// owes; on one machine the gateway keeps the run's delivery state itself.
	spool := ""
	if remote != nil {
		spool = dir
	}
	posts := sink.New(sink.Config{
		To: k, Target: sink.Target{URL: disc.Events.URL, Types: disc.Events.Types}, Spool: spool,
		Report: spec.Report, OnDigests: reload.digests, OnEnded: end,
		Wait: sink.LinkBatchWait, Link: true,
	})
	posts.SetRunDigest(lastAnswered())
	mu.Lock()
	sinks = append(sinks, posts)
	mu.Unlock()
	// What the gateway decided the run with, which the session applies and decides
	// none of again: the image, the placeholders, the names it sets, the variables, the
	// authority and the members of policy_applied it decides.
	// An answer without an image is a machine whose default names none: the wall is
	// asked for none, and refuses it as it always has.
	var img Image
	if spec.Wall != nil && answer.Image != nil {
		img = Image{Name: answer.Image.Name, Ref: answer.Image.Ref, Runtime: answer.Image.Runtime, Docker: answer.Image.Docker}
	}
	members, err := appliedMembers(answer.Applied)
	if err != nil {
		return fail(err)
	}
	reserved := slices.Concat(answer.Reserved, reservedOf(spec.Gateway))
	var authority []byte
	if spec.Wall != nil && answer.CertificateAuthority != "" {
		authority = []byte(answer.CertificateAuthority)
	}
	// The runtime prepares the launch before the variables are resolved, because what it
	// sets is Forager's own and wins over a server's variable of the same name. Behind
	// a wall the run directory goes in read-only, apart from every place the run binds:
	// the settings are read from it, and the record in it is not the agent's to rewrite
	// or move. Behind a wall the runtime learns the placeholders the run sets.
	prepared := runtimes.Launch{Command: spec.Command, Args: spec.Args}
	attach := runtimes.Attach{Launch: prepared, RunDir: dir, Forwarder: spec.Forwarder, Interactive: interactive}
	if spec.Wall != nil {
		attach.Placeholders = slices.Clone(answer.Placeholders)
	}
	if prepared, err = rt.Prepare(attach); err != nil {
		return fail(fmt.Errorf("runtime %s: %w", rt.Name(), err))
	}
	vars, emptied, err := resolve(spec, rt, answer.Values(), prepared, answer.Placeholders, reserved)
	if err != nil {
		return fail(err)
	}
	if spec.OnVariables != nil {
		spec.OnVariables(applied(vars.Applied))
	}
	// The wall comes before the forwarder, because it says where the forwarder must
	// listen, and goes after everything else, because the forwarder outlives the last
	// connection.
	// The proxy secret opens every connection to the gateway's proxy, written by the
	// forwarder or by the wall's relay: one no preamble carries is no run.
	if err := link.CheckSecret(answer.ProxySecret); err != nil {
		return fail(fmt.Errorf("the gateway's proxy secret: %w", err))
	}
	var enclosure wall.Enclosure
	// relayToken is what the wall's relay opens every connection with: the run's proxy
	// secret on one machine; behind a separate gateway a secret of this run's forwarder
	// alone, which the forwarder replaces with the proxy secret inside TLS.
	bind, secret, relayToken := link.Loopback, answer.ProxySecret, answer.ProxySecret
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
		// Behind a wall the wall's relay opens every connection with the run's proxy
		// secret itself, and the forwarder passes on what arrives as it is.
		bind, secret = enclosure.ProxyAddr(), ""
	}
	var fwd *forwarder
	switch {
	case remote == nil:
		fwd, err = listenForwarder(bind, disc.Proxy.Address, secret)
	case spec.Wall != nil:
		// Behind a wall and a separate gateway: the relay opens every connection with the
		// hop secret, and the forwarder, which checks it, opens the connection to the
		// gateway over TLS with the run's proxy secret.
		if relayToken, err = newHopSecret(); err != nil {
			return fail(err)
		}
		fwd, err = listenForwarding(bind, forwarding{dial: k.DialProxy, secret: answer.ProxySecret, hop: relayToken})
	default:
		// Without a wall, behind a separate gateway: the agent's proxy URL carries the
		// run's proxy secret as its password, as the contract has it, and the forwarder
		// on loopback carries each connection to the gateway inside TLS.
		fwd, err = listenForwarding(bind, forwarding{dial: k.DialProxy, password: answer.ProxySecret})
	}
	if err != nil {
		return fail(err)
	}
	defer fwd.Close()

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
	// preparation sets and Forager's own, each over the ones before, and behind a
	// wall the placeholders and, empty, the runtime's declared and reserved variables
	// nothing sets, so an image's own value for one does not reach the runtime. The
	// resolution has left out every value of a fixed name, so what wins here by position
	// is what the record says.
	ownEnv := []string{EnvRunID + "=" + runID}
	if spec.HarnessHome != "" {
		ownEnv = append(ownEnv, EnvHarnessHome+"="+spec.HarnessHome)
	}
	launch := wall.Launch{
		Command: command, Args: args, Dir: spec.Dir,
		Env: environment(spec.Env, vars.Env, vars.Fixed, prepared.Env, fwd.Env(), []string{EnvSocket + "=" + sock.Path()}, ownEnv),
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
			Env:   environment(spec.Env, vars.Env, vars.Fixed, prepared.Env, ownEnv, placeholders(answer.Placeholders), emptied),
			CA:    authority,
			Proxy: fwd.Addr(), Socket: sock.Path(), Mounts: plan.Mounts, Limits: spec.Limits,
			ProxyToken: relayToken,
		})
		if err != nil {
			return fail(err)
		}
	}

	// A run closed during its start does not start: the start's steps run under
	// runCtx, and whatever they reached ends here.
	if errors.Is(context.Cause(runCtx), errRunClosed) {
		return fail(errRunClosed)
	}
	start := time.Now()
	started := map[string]any{
		"opened_by": event.OpenedBySession, "credential": answer.Credential, "runtime": rt.Name(), "command": command, "args": args,
		"dir": spec.Dir, "interactive": interactive, "forager_version": spec.ForagerVersion, "host": hostname(),
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
	// The labels are the run's as the gateway holds them, and the details it decides
	// are its values.
	if len(answer.Labels) > 0 {
		started["labels"] = answer.Labels
	}
	about, err := reportedAbout(spec.About, answer.Details)
	if err != nil {
		return fail(err)
	}
	if about != nil {
		started["about"] = about
	}
	write(event.RunStarted, started)
	// policyApplied is the policy_applied event of the members the gateway decides, for
	// the policy in force at the start and for each one a reload puts in its place:
	// those members as the gateway gives them, and the session's own, the run's
	// variables as resolved at the start and the harness's hosts.
	policyApplied := func(members map[string]any) map[string]any {
		a := maps.Clone(members)
		if a == nil {
			a = map[string]any{}
		}
		a["variables"] = vars.Applied
		if spec.Declared != nil {
			a["harness_hosts"] = spec.Declared
		} else {
			delete(a, "harness_hosts")
		}
		return a
	}
	write(event.PolicyApplied, policyApplied(members))
	// A reload fetches what the gateway put in force and records it, at the sequence
	// where it takes effect; batches from then on carry its digest.
	reload.start(func(a *server.LinkReloadAnswer, held string) {
		members, err := appliedMembers(a.Applied)
		if err != nil {
			spec.Report("the reload failed: " + err.Error())
			return
		}
		mu.Lock()
		posts.SetRunDigest(held)
		record(event.PolicyApplied, policyApplied(members))
		mu.Unlock()
	}, end)

	logs := func(stream string) func([]byte) {
		return func(b []byte) { write(event.RunLog, map[string]any{"stream": stream, "bytes": encode(b)}) }
	}
	output := func(r map[string]any) { records(runtimes.Record{Source: runtimes.SourceOutput, Record: r}) }
	if !rt.ReadsOutput() {
		output = nil
	}
	resized := func(cols, rows int) { write(event.RunResized, map[string]any{"cols": cols, "rows": rows}) }
	proc := &process{stop: runtimes.StopSignal(spec.StopSignal), grace: spec.StopGrace, command: launch.Command, args: launch.Args, env: launch.Env, dir: launch.Dir, stdin: spec.Stdin, stdout: spec.Stdout, stderr: spec.Stderr, logs: logs, output: output, cols: cols, rows: rows, resized: resized}
	// The limit ends the runtime and nothing else: the sinks and the wall are closed on
	// the caller's context, as after any exit. The run being closed from outside ends
	// it the same way.
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
	// A run closed from outside has nothing further posted, whatever the runtime's
	// status.
	closed := errors.Is(context.Cause(runCtx), errRunClosed)
	cancelLimit()
	stopBeat()
	closeSocket()
	// A reload still in flight ends here: nothing of it goes after run.exited.
	reload.stop()
	if err != nil && !closed {
		closeSinks(ctx)
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
	res := &Result{RunID: runID, Dir: dir, ExitCode: exit.code, Signal: exit.signal, State: state, TimedOut: timedOut && !closed, RunClosed: closed}
	switch {
	case closed:
		// The end of the run at the gateway is in its stream already: the session
		// records its own run.exited, with the code it was closed with, in its record
		// alone.
		res.ClosedReason, res.ClosedBy = closedBy.get()
		exited["reason"] = res.ClosedReason
		own(event.RunExited, exited)
	case timedOut:
		exited["reason"] = event.ReasonTimeout
		spec.Report(fmt.Sprintf("the runtime was stopped at the limit of %s", spec.Timeout))
		write(event.RunExited, exited)
	default:
		write(event.RunExited, exited)
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), closeWait)
	defer cancel()
	if err := closeSinks(closeCtx); err != nil {
		spec.Report("closing the sinks: " + err.Error())
	}
	res.Undelivered = posts.Undelivered()
	return res, nil
}

// closedDetail is what a refusal of a run closed before it started says, by who closed
// it.
func closedDetail(from string) string {
	if from == accesskey.FromGateway {
		return "the gateway closed the run before it started"
	}
	return "the server closed the run before it started"
}

// refused ends a run the gateway did not open, with fail when it records why and quit
// when it records nothing. A 410 is the run closed before it started. wall_required is the error the session gave for it before there was a
// gateway, word for word, and is recorded nowhere. Any other refusal with a code is
// returned as the gateway gave it, From and all, and its dev.qory.run.refused is in the
// session's record alone: the refusal opened no run at the gateway. A 5xx is a failure
// without a code at the gateway: its message, the error's text as the user is told it,
// when it carries one, recorded nowhere. Nothing is posted on the link.
func refused(err error, fail, quit func(error) (*Result, error), own func(string, any), end func(code, from string)) (*Result, error) {
	var r *Refusal
	if code, ok := server.Ended(err); ok && errors.As(err, &r) {
		end(code, r.From)
		return fail(err)
	}
	if errors.As(err, &r) {
		if r.Code == refusal.WallRequired {
			return quit(&refusal.NeedsWall{Names: r.Names})
		}
		// The refusal is told as one of the gateway's, never by the link's own URL.
		r.Detail = "the gateway"
		data := map[string]any{"code": r.Code}
		if len(r.Names) > 0 {
			data["names"] = r.Names
		}
		if r.From == accesskey.FromApiary && r.Status != 0 {
			data["status"] = r.Status
		}
		own(event.RunRefused, data)
		return quit(r)
	}
	var status *server.StatusError
	if errors.As(err, &status) && status.Status >= 500 {
		if status.Message != "" {
			return quit(errors.New(status.Message))
		}
		return quit(fmt.Errorf("the gateway answered the run request with status %d", status.Status))
	}
	return quit(err)
}

// linkImages are the machine's images as the run request carries them.
func linkImages(spec Spec) *server.LinkImages {
	if spec.Image == "" && len(spec.Images) == 0 {
		return nil
	}
	out := &server.LinkImages{Default: spec.Image}
	for _, d := range spec.Images {
		out.Definitions = append(out.Definitions, server.LinkImage{Name: d.Name, Ref: d.Ref, Runtime: d.Runtime, Docker: d.Docker})
	}
	return out
}

// appliedMembers are the members of dev.qory.run.policy_applied the gateway decides,
// as its answer carries them; none when it carries none.
func appliedMembers(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return nil, errors.New("the gateway's answer: applied is not a JSON object")
	}
	return out, nil
}

// reportedAbout is what run.started reports of the run's About: [server.ReportedAbout],
// with each key of about.details the gateway decides set to its value.
func reportedAbout(a *About, decided json.RawMessage) (*About, error) {
	out := server.ReportedAbout(a)
	if len(decided) == 0 {
		return out, nil
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(decided, &keys); err != nil || len(keys) == 0 {
		return out, nil
	}
	if out == nil {
		out = &About{}
	}
	details := map[string]json.RawMessage{}
	if len(out.Details) > 0 {
		if err := json.Unmarshal(out.Details, &details); err != nil {
			return nil, errors.New("about.details is not a JSON object")
		}
	}
	maps.Copy(details, keys)
	b, err := json.Marshal(details)
	if err != nil {
		return nil, err
	}
	var compact, escaped bytes.Buffer
	if err := json.Compact(&compact, b); err != nil {
		return nil, err
	}
	json.HTMLEscape(&escaped, compact.Bytes())
	out.Details = escaped.Bytes()
	return out, nil
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
	if spec.ForagerVersion == "" {
		spec.ForagerVersion = "dev"
	}
	return spec
}

// placeholders are the variables a program wants set before it starts, with a value
// that is no credential.
func placeholders(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = n + "=" + link.Placeholder
	}
	return out
}

// envRunCredential is the variable qory may read a run credential from. qory takes it
// out of the agent's environment; the session does too, whatever brought it.
const envRunCredential = "QORY_RUN_CREDENTIAL_SECRET"

// environment is the session's environment: base with Forager's variables set,
// replacing any of the same names, and without the access key's variables or the run
// credential's, whichever of them brought one.
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
	return slices.DeleteFunc(accesskey.WithoutVariables(append(out, extra...)), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return name == envRunCredential
	})
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

// loopback reports whether addr is host:port with an IP address on loopback as its
// host.
func loopback(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
