package session

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/wall"
)

// OpenSpec is what the open of a run is given: the gateway, the wall and the images of
// the run, where its directory goes, and how it is named and shown. Every session of
// the run joins with a [SessionSpec].
type OpenSpec struct {
	// Gateway is the gateway the run speaks to, [LocalGateway] on this machine or a
	// [RemoteGateway] on a machine of its own: it holds the run's proxy, its policy, its
	// credentials and its tools, decides the run's policy and image, numbers the run's
	// events and is the node toward the server. The run speaks to it alone, over its
	// link. A run needs one. A RemoteGateway's run key that the session cannot read is
	// no run: "QORY_RUN_KEY is not a run key: " and the part that is wrong.
	Gateway Gateway
	// Wall, when not nil, encloses each session's runtime: the command is started
	// inside an enclosure whose only route out leads to the gateway's proxy, in the image
	// the gateway's run answer gives, with the session's Dir as its workspace and
	// working directory. The session's Command, Args, Forwarder and Exec are then paths
	// inside the enclosure. Nil means no wall: the runtime is this machine's process, and
	// enforcement is cooperative. The gateway sets the values of the run's credentials
	// either way: the runtime sees only their placeholders. The wall is the run's: every
	// session of the run has it.
	Wall wall.Wall
	// CAEnv are the variables that point a program at the run's bundle when the gateway
	// gives the run an authority: in [HostProxy.Env], walled or not, and in the
	// session's environment when the run has no Wall; qory is to set it from
	// wall.ca_env. Nil means [wall.DefaultCAEnv]. Behind a Wall the wall sets its names
	// for the bundle inside instead.
	CAEnv []string
	// Image is the agent's image under a Wall when the policy selects none: the name
	// of one of Images, or a reference.
	Image string
	// Images are the images this machine defines; the run's policy selects among them
	// by name, as it selects credentials and tools, and a selection needs a Wall. The
	// image the run's sessions start in is fixed at the open. The run request carries
	// them, so the gateway resolves the policy's selection against them.
	Images []Image
	// ImagesAllow are the prefixes of the references pinned by digest a run's policy may
	// name its image by, for qory images.allow: an entry covers a reference that starts
	// with it when the entry ends in / or @, or the reference's next character is / or
	// @. Nil allows no reference. A list needs an Image, the default: an image by
	// reference starts under the default's runtime, with no nested Docker,
	// as the wall's user, its workspace at /workspace inside, and the wall fetches it,
	// unless the engine holds it by that digest, and refuses one whose user is root,
	// image_user_root. A reference no entry covers is no run, image_not_allowed.
	ImagesAllow []string
	// RunsDir holds the run directories; empty means .qory/runs in the working
	// directory. It is one of Forager's files, so a walled run needs one outside the
	// mounts and the Dir of each of its sessions.
	RunsDir string
	// ForagerVersion is reported in the events.
	ForagerVersion string
	// RunID is the run's id when a parent already made one; empty means a new one, or
	// behind a RemoteGateway the one its run key names. It is a UUID in the canonical
	// lower-case form, because it is the events' subject and names the run directory;
	// anything else is refused, and so is one that is not the run key's behind a
	// RemoteGateway.
	RunID string
	// Labels are the caller's names for the run, its key in a queue, a repository, an
	// issue: sent on the run request, so the gateway asks the server for the run's policy
	// by them, and reported in run.started, as the gateway's run answer has them, and
	// no other event. Forager reads nothing into them. At most MaxLabels; a key is 1 to
	// 64 of a-z, 0-9, underscore, dot and dash, a value at most 256 bytes. Behind a
	// RemoteGateway the run's labels are its starter's registration's: Labels are
	// neither sent nor reported.
	Labels map[string]string
	// About is what the run is about, as the caller passed it: the kind of run, a title,
	// the subjects it works on and details. It is sent on the run request and reported in
	// run.started and no other event, so a receiver shows the run by it; it never selects
	// a policy. Forager reads nothing into it. CheckAbout checks it against its bounds
	// before the gateway is contacted. Nil, or an About whose every member is empty, is
	// left out. An empty Kind, Title or Subjects counts as absent and is left out of the
	// event. Details is shown to every reader of the run, so it never contains a secret.
	// Behind a RemoteGateway what the run is about is its starter's registration's:
	// About is neither sent nor reported.
	About *About
	// Machine is the adapter that made the machine the run runs on, such as aws-ec2, or
	// [event.MachineNone] when no adapter made it. run.started reports it as machine. It
	// is 1 to 64 of a-z, 0-9 and -, and starts with a letter; [Open] refuses anything
	// else. Empty leaves machine out of run.started.
	Machine string
	// Setup is where the run's setup commands run: [event.SetupOutside], in a container
	// apart from the agent's, or [event.SetupInside], in the agent's container. run.started reports it as
	// setup. [Open] refuses any other value. Empty leaves setup out of run.started, for a
	// run with no setup commands.
	Setup string
	// Report receives one line per thing the run reports to its user; nil means
	// os.Stderr, each line after "qory run: ".
	Report func(string)
}

// SessionSpec is what one session of an open run is given: the program to start and
// how, its variables, its places and its limits.
type SessionSpec struct {
	// Runtime is the program that is run: what is prepared before it starts, what its
	// records mean and how it is asked to leave. The catalog package resolves a name to
	// one. Nil means a bare runtime named after the Command: the session is recorded,
	// the runtime's session inside it is not.
	Runtime runtimes.Runtime
	// Command, Args and Dir are what to start; an empty Dir is the working directory.
	Command string
	Args    []string
	// Env is the environment the session inherits, NAME=value: a nil Env is the
	// process's, or nothing under a Wall, where only what the session lists goes in. It
	// is the lowest of the session's sources of variables: LaunchDefaults, Variables and
	// the server's variables win over it, apart from it, so the session distinguishes
	// them from what is merely inherited (contracts/forager/v1/README.md §Variables). The
	// access key's variables, QORY_ACCESS_KEY_SECRET, QORY_ACCESS_KEY_ID and
	// QORY_APIARY_PUBLIC_KEY, are left out of what the session gets from any of them.
	// Without a Wall the variables the machine's credentials are read from are left out
	// of it too, and a placeholder wins over a value of it.
	Env []string
	Dir string
	// LaunchFixed is the values the harness computes, NAME=value. They are fixed names
	// of the session: they win over every other source of a variable, the built-in deny
	// list, denied-variables.json, leaves one out, and the runtime's denies and
	// Variables.Deny do not. Forager's, the wall's and the runtime preparation's names
	// win over them.
	LaunchFixed []string
	// LaunchDefaults is the values the harness's author wrote as defaults, NAME=value.
	// They win over Env and lose to every other source.
	LaunchDefaults []string
	// Variables are the run's and the machine's variables, and how the session takes
	// the variables of the server's run configuration, which the gateway's run answer
	// contains.
	Variables Variables
	// HarnessHome is the harness's home as the agent's process sees it, an absolute
	// path; empty means none. When set, the session sets QORY_HARNESS_HOME to it, as one
	// of Forager's names, like QORY_RUN_ID.
	HarnessHome string
	// Harness are the harness sources the session's compose used, each with the commit
	// compose used, reported in dev.qory.session.started as harness; nil reports none.
	Harness []HarnessSource
	// ModelCredential is the name of the model key the session starts with, one of the
	// model keys the gateway holds for the run; empty means the run's start key. The join
	// request contains it.
	ModelCredential string
	// OnVariables, when not nil, is called once the session's variables are resolved,
	// before the wall and the agent start, with each name, its source and the values
	// that lost, as dev.qory.run.policy_applied records them: qory prints a line for an
	// --env value that lost. A session refused before then does not call it.
	OnVariables func(Applied)
	// Interactive says the caller has a terminal: the session runs on a pseudo-terminal
	// attached to Stdin and Stdout, unless Args contains an argument the Runtime lists as
	// headless, -p for Claude Code, in which case it runs on pipes as if the caller had
	// said so. Otherwise it runs on pipes with Stdin as its input and its output copied
	// to Stdout and Stderr. A nil stream is the process's.
	Interactive bool
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	// Preparation is the session's preparation, the program and then its arguments,
	// which the session runs inside the wall before the runtime: after the runtime's
	// preparation, as the runtime's user, in Dir, with the runtime's environment, through
	// the run's proxy and with its placeholders, so it reaches what the policy allows
	// with the credentials the policy selects. The session starts the runtime through a
	// script it writes into the session's directory, PreparationScript, with /bin/sh, so an
	// image for such a run contains /bin/sh. The script runs the preparation with no
	// input and its output where the runtime's goes, and starts the runtime once the
	// preparation exits 0. A preparation that exits otherwise ends the session with its
	// exit status, and the runtime never starts. A stop during the preparation asks it to
	// leave with SIGTERM, whatever the stop signal, and the runtime never starts.
	// dev.qory.session.started reports the preparation as given, and the script as its
	// command and args. Empty means none. A preparation needs the run's Wall and a
	// program that is not empty.
	Preparation []string
	// Mounts are what the enclosure shows of this machine, each at its path: the
	// checkout around Dir, a composed home outside it. A mount, or Dir, inside another
	// one of the same mode is reached through the outer one, which alone is bound; one of
	// the other mode is a refused join, mount_mode_conflict. One whose path goes through a
	// link inside a writable one, and that does not resolve into it, is a refused join,
	// whatever its mode, mount_through_link. Dir is writable, and is bound at its path
	// when no mount contains it. The session adds the session's directory in the run
	// directory, sessions/<n>/, read-only. A walled
	// session refuses a bind that lies inside, or is reached through, a writable bind of
	// another walled run of this user's still going, apart from the same root, a writable
	// one that contains one of that run's binds or the way to one, and one that is,
	// contains or lies inside that run's run directory: mount_shared_with_run. Without a
	// Wall they mean nothing.
	Mounts []wall.Mount
	// ForagerFiles are the absolute paths of the caller's files that are Forager's,
	// such as the directory of qory's forager.yaml with the access key secret. A walled
	// session refuses a mount, or a workspace, that is, contains or lies inside one of
	// them, one of the gateway's files, or one of the paths Forager knows, RunsDir among
	// them, mount_contains_forager_files: see [Overlap].
	ForagerFiles []string
	// Written are the places of this machine, directories, that the caller records as
	// writable by a walled run: the workspaces and the writable mounts of the walled runs
	// it starts. A file the Runtime reads from this machine as the session starts, the
	// settings Claude Code is passed say, is refused when its path is or lies inside one
	// of them, as given or through links, or is reached through one; so is one in a
	// writable bind of another walled run in the registry and, behind a Wall, one in a
	// writable bind of this session's, Dir among them. Behind a Wall, a mount or Dir whose
	// path goes through a link inside one of them and does not resolve into it is a
	// refused join, mount_through_link. A relative path is taken from the working
	// directory.
	Written []string
	// Declared is the egress the harness declared, nil when nothing was. It is
	// reported in the session's dev.qory.run.policy_applied as harness_hosts, a host
	// that contains qak_ or qrk_ in any case as accesskey.ShownValue's phrase, and
	// decides nothing: the policy alone decides.
	Declared []string
	// Forwarder is the command the Runtime installs as the program's hook: it reads the
	// hook's input and forwards it to the socket. Empty means no hooks are installed.
	Forwarder []string
	// Exec is the command, a path inside the enclosure, that makes the caller's binary
	// run [Exec] there: {wall.HelperPath, "exec"} for a binary that runs it in its exec
	// mode. Behind a wall the session starts the launch through it when the session has
	// names to unset, in front of everything else the launch starts, after the wall's
	// programs, with the names the session has that nothing sets and wins with, the
	// runtime's declared, reserved and denied names, its model overrides and the node's
	// denied ones, so the runtime sees them unset, never as the image's values or empty.
	// dev.qory.session.started reports the launch without it. The run's Wall needs one.
	Exec []string
	// Timeout is how long the runtime may run, the session's preparation included; zero
	// means no limit. At the limit the runtime is stopped the way the context ending
	// stops it, and dev.qory.session.exited contains the reason. qory passes the time
	// left of the run's limit.
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
	// SocketGrace is how long the run socket keeps accepting after the runtime exits,
	// so a hook on its last event is still read; zero or less means 200 ms. For tests:
	// production leaves it zero.
	SocketGrace time.Duration
}

// HarnessSource is one harness source a session's compose used: Source as it is
// configured, such as https://git.example/example-org/harness#main, and Commit, the
// full commit id compose used, 40 or 64 hexadecimal characters in lower case.
type HarnessSource struct {
	Source string
	Commit string
}

// commitShape is a full commit id: SHA-1's 40 or SHA-256's 64 hexadecimal characters,
// in lower case.
var commitShape = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// checkHarness refuses a harness source the event's schema would: an empty source, or
// a commit that is not a full commit id.
func checkHarness(sources []HarnessSource) error {
	for i, h := range sources {
		switch {
		case h.Source == "":
			return fmt.Errorf("the harness source %d is empty", i+1)
		case !commitShape.MatchString(h.Commit):
			return fmt.Errorf("set the commit of the harness source %d to a full commit id, 40 or 64 hexadecimal characters in lower case", i+1)
		}
	}
	return nil
}

// machineShape is the form of run.started's machine.
var machineShape = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// checkMachine refuses a Machine and a Setup that run.started's schema refuses. An
// empty one is absent and passes.
func checkMachine(spec OpenSpec) error {
	if spec.Machine != "" && !machineShape.MatchString(spec.Machine) {
		return fmt.Errorf("set OpenSpec.Machine to none or to 1 to 64 of a-z, 0-9 and -, the first a letter: %s", accesskey.ShownValue(spec.Machine, true))
	}
	switch spec.Setup {
	case "", event.SetupOutside, event.SetupInside:
		return nil
	}
	return fmt.Errorf("set OpenSpec.Setup to outside or inside, or leave it empty: %s", accesskey.ShownValue(spec.Setup, true))
}

// Outcome is how the caller says the run ended, which [Run.Close] writes in
// dev.qory.run.exited: State, succeeded, failed or cancelled; Reason, empty for none,
// timeout or interrupted with cancelled, timeout with ExitCode 124, or a code of the
// caller's, which is none of Forager's reserved codes; and ExitCode, the run's exit
// code: the last session's, 124 at the run's time limit, -1 when no session ran. A
// failed run with no reason that no session joined is closed as failed with no_session
// and -1.
type Outcome struct {
	State    string
	Reason   string
	ExitCode int
}

// checkOutcome refuses an outcome the close cannot write: a state outside the three, an
// exit code under -1, a reason outside the pattern or one of Forager's reserved codes
// other than timeout, interrupted and no_session, and those three with another state
// or exit code than they take. joined says a join of the run was numbered, or may have
// been.
func checkOutcome(o Outcome, joined bool) error {
	switch {
	case !event.IsState(o.State):
		return fmt.Errorf("the outcome's state %q is none of succeeded, failed and cancelled", o.State)
	case o.ExitCode < -1:
		return fmt.Errorf("the outcome's exit code %d is under -1", o.ExitCode)
	case o.Reason == "", event.StarterReason(o.Reason):
		return nil
	case o.Reason == event.ReasonTimeout:
		if o.State != event.StateCancelled || o.ExitCode != 124 {
			return errors.New("an outcome with the reason timeout is cancelled with the exit code 124")
		}
	case o.Reason == event.ReasonInterrupted:
		if o.State != event.StateCancelled {
			return errors.New("an outcome with the reason interrupted is cancelled")
		}
	case o.Reason == event.ReasonNoSession:
		if o.State != event.StateFailed || o.ExitCode != -1 || joined {
			return errors.New("an outcome with the reason no_session is failed with the exit code -1, of a run no session joined")
		}
	default:
		return fmt.Errorf("the outcome's reason %s is not a code of the caller's: a lower-case letter, then up to 63 lower-case letters, digits and _, and none of Forager's reserved codes", accesskey.ShownValue(o.Reason, true))
	}
	return nil
}

// Result is what a session came to: what the session knows of it. What reached the
// server is the gateway's to say.
type Result struct {
	RunID string
	// Dir is the run directory, with the session's record, session.jsonl and
	// output.log; on one machine the gateway writes the run's stream, events.jsonl,
	// beside them.
	Dir string
	// SessionDir is the session's directory in Dir, sessions/<n>/ with n the session's
	// number: its output.log, its preparation.sh and the files its runtime writes.
	SessionDir string
	// Session is the session's number in the run, from 1, as the gateway's join answer
	// gave it.
	Session int
	// ExitCode is the runtime's, or -1 when a signal killed it, whatever State says.
	ExitCode int
	// Signal names the signal that killed the runtime, if one did.
	Signal string
	// State and Reason are the state and the reason of the session's
	// dev.qory.session.exited: succeeded, failed or cancelled, and the reason, empty
	// when there is none. When the runtime exits by itself, its exit decides, succeeded
	// on 0 and failed otherwise, with no reason. At the spec's Timeout, TimedOut, they
	// are cancelled and timeout. When the session was stopped from where it was started,
	// Cancelled, they are cancelled and interrupted. In both, ExitCode and Signal are the
	// runtime's, whatever they are. When the gateway closed the run, RunClosed, they are
	// the state and the reason its 410 says, but batch_refused after a refused batch,
	// and failed with ClosedReason for an end that has no state, run_closed among them.
	State  string
	Reason string
	// TimedOut says the runtime was stopped at the spec's Timeout: the session's stop
	// signal reached it at the limit before its exit was observed. A runtime that exited
	// by itself before that signal is decided by its exit, and TimedOut is false.
	TimedOut bool
	// Cancelled says the join's context had ended when the session observed the
	// runtime's exit, whatever the exit status or the signal, and whoever stopped the
	// runtime: the session at the context's end, or the runtime itself, at a Ctrl-C
	// that reached both. In a race it is whichever the session saw first: a context
	// that had ended when the exit was observed makes it true. A context that ends
	// later leaves it false, as do the time limit, which is TimedOut, a run the gateway
	// closed before the context ended, which is RunClosed, and a signal from elsewhere
	// while the context lasts: Cancelled is never true with TimedOut or with RunClosed.
	// When it is true, dev.qory.session.exited is cancelled with interrupted.
	Cancelled bool
	// RunClosed says the gateway closed the run, a 410 on the gateway's link, or the
	// gateway's 400 to a batch, which ends the run there: the runtime was stopped as at
	// its time limit, and the session's record has the session's
	// dev.qory.session.exited with State and Reason. A server's 410 never closes a run:
	// the gateway only stops sending it events.
	RunClosed bool
	// ClosedReason is the code the run was closed with when RunClosed, the 410's code
	// as the gateway answered it: run_closed, stopped when the run's starter ended it,
	// session_lost when it heard nothing from the session for three heartbeat
	// intervals, and batch_refused when it refused a batch from the run's session.
	ClosedReason string
}

// Closed is what the close of a run came to.
type Closed struct {
	RunID string
	// Dir is the run directory.
	Dir string
	// State, Reason and ExitCode are those of the run's dev.qory.run.exited: the
	// caller's outcome, failed with no_session and -1 for a failed run no session joined,
	// or, when RunClosed, the state and the reason the gateway's 410 says, with the exit
	// code of the last session, -1 when a session was open at the 410.
	State    string
	Reason   string
	ExitCode int
	// Undelivered is how many of the run's events the gateway did not accept.
	Undelivered int
	// RunClosed says the gateway closed the run before the close: the session's record
	// has the run's dev.qory.run.exited, which no batch carries.
	RunClosed bool
	// ClosedReason is the 410's code when RunClosed, as [Result.ClosedReason] is.
	ClosedReason string
}

// runSpec is a session's spec with the open's spec of its run, as the checks and the
// resolution of a session read them.
type runSpec struct {
	OpenSpec
	SessionSpec
}

// openDefaults fills what the open's spec left empty.
func openDefaults(o OpenSpec) OpenSpec {
	if o.RunsDir == "" {
		wd, _ := os.Getwd()
		o.RunsDir = filepath.Join(wd, ".qory", "runs")
	}
	if o.Report == nil {
		o.Report = func(line string) { fmt.Fprintln(os.Stderr, "qory run:", line) }
	}
	if o.ForagerVersion == "" {
		o.ForagerVersion = "dev"
	}
	return o
}

// sessionDefaults fills what a session's spec left empty, for a run with a wall or
// without one.
func sessionDefaults(s SessionSpec, walled bool) SessionSpec {
	if s.Dir == "" {
		s.Dir, _ = os.Getwd()
	}
	if s.Env == nil && !walled {
		s.Env = os.Environ()
	}
	if s.Stdin == nil {
		s.Stdin = os.Stdin
	}
	if s.Stdout == nil {
		s.Stdout = os.Stdout
	}
	if s.Stderr == nil {
		s.Stderr = os.Stderr
	}
	return s
}
