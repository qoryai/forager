// Package runtimes is the boundary between the session and the program it runs: an agent
// runtime such as Claude Code, Codex or one of a caller's own. The session starts a
// process, records it and stops it; what is particular to a program, how it is made to
// report, what its records mean and how it is asked to leave, is behind [Runtime].
//
// There are three ways to a Runtime. [Bare] is a program Forager knows nothing
// about: the run is recorded, the session inside it is not. [Described] is a runtime
// written as data, a descriptor of the contract that matches records and copies fields
// and names an [Installer] among the ones it is given; nothing of a descriptor runs.
// And a caller that embeds Forager implements the interface itself. The catalog
// package resolves a name to the first two.
package runtimes

import (
	"fmt"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/session/internal/descriptor"
)

// Runtime is one program Forager can run a session of.
type Runtime interface {
	// Name is the runtime's name as events report it: claude, codex.
	Name() string
	// Version is the version of the program the adapter was written against, reported
	// in run.started and not checked against what is installed. Empty when the adapter
	// was written against none.
	Version() string
	// Prepare makes a launch one the session can follow: it installs the forwarder as
	// the program's hook, writes what that takes into the session's directory, and returns
	// the launch to start in place of the one given, command and arguments. A program
	// that waits for a person to approve a stand-in of [Attach.Placeholders] may be
	// started through a script Prepare writes there, which records the approval where
	// the program reads it and then starts the program. A runtime with nothing to
	// prepare returns the launch as it is.
	Prepare(Attach) (Launch, error)
	// ReadsOutput reports whether the program's standard output, when the session runs
	// on pipes, is JSON lines the session passes to Map as records of [SourceOutput].
	ReadsOutput() bool
	// Map turns one record of the program into one event of the contract, its type and
	// data, or reports that the record is none.
	Map(Record) (typ string, data map[string]any, ok bool)
	// Stop is how the program is asked to leave. A run that names its own signal or
	// grace overrides it.
	Stop() Stop
	// Headless reports whether the arguments the program is started with mean it runs
	// without an interface, so the session runs on pipes even at a terminal, exactly
	// as if the caller had asked for that. A runtime that names no such argument
	// reports false, and the caller alone decides.
	Headless(args []string) bool
}

// Launch is what is started: the program, its arguments, and variables for its
// environment beside the run's own, each NAME=value.
type Launch struct {
	Command string
	Args    []string
	Env     []string
}

// Attach is what Prepare is given.
type Attach struct {
	// Launch is what the caller asked to start. Its Env is empty: a runtime adds
	// variables, it does not see the run's.
	Launch Launch
	// SessionDir is the session's directory, sessions/<n>/ in the run directory, which
	// no other session of the run writes to. What Prepare writes goes here; under a wall
	// the enclosure sees it read-only at the same path, and nothing else of the run
	// directory.
	SessionDir string
	// Forwarder is the command to install as the program's hook: it reads a hook's
	// input and forwards it to the session as a record of [SourceHooks]. Empty means the
	// run has none, and no hooks are installed.
	Forwarder []string
	// Interactive says the session runs on a pseudo-terminal, not on pipes.
	Interactive bool
	// Walled is true when the program runs behind a wall.
	Walled bool
	// Placeholders are the variables the session sets to [Placeholder] in the
	// program's environment: a credential's, whose value the proxy sets outside the
	// enclosure, and a tool's, whose host the tool serves outside it. The session sets
	// them with or without a wall.
	Placeholders []string
	// ModelVariables, in a run with a start key, are the variables of the runtime's
	// model keys, the start key's among them, and its model endpoint variable, from its
	// descriptor's model section. The session sets the start key's variable and the
	// endpoint's and leaves out the others; a runtime that copies a file whose values
	// reach the program's environment leaves these names out of the copy. Empty when
	// the run has no start key.
	ModelVariables []string
	// DeniedVariables are the runtime's denies and, behind a wall, its model
	// overrides, from its descriptor: the names the session leaves out of the values
	// of the server, the run, the machine and the harness's defaults, with or without
	// a start key. A runtime that copies a file whose values reach the program's
	// environment leaves these names out of the copy, regardless of case.
	DeniedVariables []string
	// Inside, when not nil, writes a path of this machine's as the enclosure sees it,
	// in a string that may hold one: a runtime applies it to what it copies into
	// SessionDir from the caller's files, so a path it names still leads where it led. The
	// session sets it for a run whose workspace is at /workspace inside. Nil leaves
	// every path as it is.
	Inside func(string) string
	// Readable is asked of a file of this machine before Prepare reads it, such as the
	// settings Claude Code is passed, by its absolute path, which Prepare then opens as
	// it is: where the path resolves through every link, which is the file Prepare may
	// read, or why it may not read it. The session refuses a file a walled run could
	// have written or replaced: one whose path is or lies inside, as given or through
	// links, or is reached through, a place the caller lists as written by a walled run,
	// a writable bind of another walled run still listed, or a writable bind of this
	// run's; and a path with a ".." name, whose clean form names another file than the
	// system opens. Nil refuses none. A refusal for a place a walled run can write is a
	// [*WrittenError].
	Readable func(path string) (string, error)
	// ReadableDir is asked of a directory of this machine before Prepare passes it to
	// the program, such as a plugin directory Claude Code is passed, by its absolute
	// path: where the path resolves through every link, or why the program may not read
	// it. It refuses what Readable refuses and also a directory that is or contains,
	// as given or resolved, by whole names and regardless of case, a place a walled run
	// could have written. Nil refuses none.
	ReadableDir func(path string) (string, error)
}

// WrittenError is how [Attach.Readable] and [Attach.ReadableDir] refuse a path for a
// place a walled run can write: How is "lies in", "is reached through" or "contains",
// and Place is the place as a message prints it.
type WrittenError struct {
	How, Place string
}

// Error is "it lies in /work, which a walled run can write", with the error's How and
// Place.
func (e *WrittenError) Error() string {
	return "it " + e.How + " " + e.Place + ", which a walled run can write"
}

// Placeholder is the value of every variable of [Attach.Placeholders]: a stand-in that
// is no credential and says what it is to whoever reads it.
const Placeholder = link.Placeholder

// Secrets is implemented by a runtime that declares the secrets it needs. It is
// optional and checked by type assertion, so [Runtime] keeps its methods: a runtime
// without it declares nothing.
type Secrets interface {
	// Secrets is what the runtime declares. The lists are the caller's to keep: a
	// runtime returns a copy of its own.
	Secrets() Declarations
}

// Declarations is what a runtime declares of a run's secrets, the secrets section of a
// descriptor: Declares, the secrets it reads, each from one variable; OneOf, the
// groups of them of which the runtime needs one at most; Reserves, the
// variables it reads a credential from beside the declared ones; Denies, the
// variables the session leaves out of a server's set for it; and CredentialFiles, the
// files in which it keeps a credential of its own, ~ being the home of the user
// Forager runs as.
type Declarations = descriptor.Secrets

// Declaration is one secret a runtime reads: its id, a title for a person, the
// variable it is read from, the exact hosts and the optional paths its value is set
// on, and how it is set.
type Declaration = descriptor.Declaration

// Auth is how a value is set on a request: Scheme is bearer, header or basic, Header
// the header of header, Username the fixed user of basic, and OAuth marks a bearer as
// an OAuth token.
type Auth = descriptor.Auth

// Group is a set of declarations of which the runtime needs one at most, and exactly
// one when Required.
type Group = descriptor.Group

// Model is implemented by a runtime that can report a descriptor's model section. It
// is optional and checked by type assertion, so [Runtime] keeps its methods: a runtime
// without it has no model section.
type Model interface {
	// Model is the runtime's model section and true, or the zero ModelPlaces and false
	// when the runtime has none. The lists are the caller's to keep: a runtime returns
	// a copy.
	Model() (ModelPlaces, bool)
}

// ModelPlaces is a descriptor's model section: Formats, the model API formats the
// runtime sends its requests in, from the contract's api-format.schema.json; Model,
// where a run's model id goes; Effort, where an effort value goes, nil when the runtime
// has no place for one; Endpoint, the variable the runtime reads the base URL of its
// model API from; Keys, the variables it reads a model key from, one per API format
// and auth; and Overrides, the variables that would override the model id or effort
// value a composer writes, which a walled run leaves out and unsets inside.
type ModelPlaces = descriptor.Model

// Key is one variable a runtime reads a model key from: Format, the API format the key
// is for; Auth, how the runtime sends it; and Variable.
type Key = descriptor.Key

// Place is where a value goes, exactly one of its fields set: Flag, an argument the
// runtime is started with, which takes the value; Setting, a dotted key in the JSON
// settings file the launch passes; Variable, an environment variable.
type Place = descriptor.Place

// ValuedPlace is a [Place] and the values the runtime accepts there.
type ValuedPlace = descriptor.ValuedPlace

// AgentPlace is where a value goes in an agent's file: Frontmatter, a key of the file's
// frontmatter, and the values the runtime accepts there.
type AgentPlace = descriptor.AgentPlace

// Effort is where an effort value goes: Run, the run's; Agent, an agent's, nil when the
// runtime has no place for an agent's effort.
type Effort = descriptor.Effort

// Endpoint is the variable a runtime reads the base URL of its model API from.
type Endpoint = descriptor.Endpoint

// Record is one unit of what a program reports.
type Record = descriptor.Record

// The sources of a record. A runtime maps records of SourceOutput and SourceHooks;
// the session reads the records of SourceSetup, a setup command's, and passes none of
// them to a runtime.
const (
	SourceOutput = descriptor.SourceOutput
	SourceHooks  = descriptor.SourceHooks
	SourceSetup  = descriptor.SourceSetup
)

// Stop is how a program is asked to leave: Signal, one [CheckStopSignal] passes, and
// Grace, the time until SIGKILL. Empty and zero are Forager's defaults.
type Stop struct {
	Signal string
	Grace  time.Duration
}

// Installer installs the forwarder as a program's hook for each of the events named,
// the way one program takes hooks, and returns the launch that reads them. A descriptor
// names an installer; it never brings one.
type Installer func(events []string, a Attach) (Launch, error)

// Bare is a program Forager knows nothing about: nothing is prepared, no record is
// read, and it is asked to leave the default way. The run itself, its process, its
// output and its egress, is recorded all the same.
func Bare(name string) Runtime { return bare(name) }

type bare string

// Name is the name it was given.
func (b bare) Name() string { return string(b) }

// Version is empty: nothing was written against a version.
func (bare) Version() string { return "" }

// Prepare returns the launch as it is.
func (bare) Prepare(a Attach) (Launch, error) { return a.Launch, nil }

// ReadsOutput is false: the output is logged and not read.
func (bare) ReadsOutput() bool { return false }

// Map finds no event in any record.
func (bare) Map(Record) (string, map[string]any, bool) { return "", nil, false }

// Stop is Forager's defaults.
func (bare) Stop() Stop { return Stop{} }

// Headless is false: nothing is known of the arguments.
func (bare) Headless([]string) bool { return false }

// Described is the runtime a descriptor describes. name names the document in messages
// and says by its extension whether it is YAML or JSON; the document is checked against
// the contract's schema. installers are the ones the descriptor may name; one it names
// that is not among them is an error.
func Described(name string, document []byte, installers map[string]Installer) (Runtime, error) {
	d, err := descriptor.Parse(name, document)
	if err != nil {
		return nil, err
	}
	r := &described{d: d}
	if h := d.Sources.Hooks; h != nil {
		r.install = installers[h.Install]
		if r.install == nil {
			return nil, fmt.Errorf("%s: hook installer %q is not one Forager implements", accesskey.ShownValue(name, false), h.Install)
		}
	}
	if s := d.Stop; s != nil {
		r.stop.Signal = s.Signal
		if s.Grace != "" {
			if r.stop.Grace, err = time.ParseDuration(s.Grace); err != nil || r.stop.Grace <= 0 {
				return nil, fmt.Errorf("%s: stop.grace %q is not a duration above zero", accesskey.ShownValue(name, false), s.Grace)
			}
		}
	}
	if h := d.Headless; h != nil {
		r.headless = h.Args
	}
	return r, nil
}

type described struct {
	d        *descriptor.Descriptor
	install  Installer
	stop     Stop
	headless []string
}

// Name is the descriptor's runtime.
func (r *described) Name() string { return r.d.Runtime }

// Version is the descriptor's runtime_version.
func (r *described) Version() string { return r.d.RuntimeVersion }

// ReadsOutput reports whether the descriptor has an output source.
func (r *described) ReadsOutput() bool { return r.d.Sources.Output != nil }

// Stop is the descriptor's stop section.
func (r *described) Stop() Stop { return r.stop }

// Headless reports whether one of the arguments the descriptor's headless section names
// is among args.
func (r *described) Headless(args []string) bool { return namesHeadless(r.headless, args) }

// namesHeadless is the matching rule: a short argument, one dash, matches a token
// that is exactly it; a long one, two dashes, matches the token or the token up to an
// equals sign, its --name=value form. Tokens are compared one by one and no flag
// grammar is parsed: which tokens are values of the flags before them is the program's
// to know, and Forager does not guess at it, so a value that happens to spell a
// named argument counts as one.
func namesHeadless(named, args []string) bool {
	for _, arg := range args {
		for _, n := range named {
			if arg == n {
				return true
			}
			if strings.HasPrefix(n, "--") && strings.HasPrefix(arg, n+"=") {
				return true
			}
		}
	}
	return false
}

// Prepare has the installer the descriptor names install the forwarder for the events
// it lists, when it has a hooks source and the run a forwarder.
func (r *described) Prepare(a Attach) (Launch, error) {
	if r.install == nil || len(a.Forwarder) == 0 {
		return a.Launch, nil
	}
	return r.install(r.d.Sources.Hooks.Events, a)
}

// Map applies the descriptor's rules.
func (r *described) Map(rec Record) (string, map[string]any, bool) { return r.d.Map(rec) }

// Secrets is the descriptor's secrets section, a copy; empty when it has none.
func (r *described) Secrets() Declarations {
	s := r.d.Secrets
	if s == nil {
		return Declarations{}
	}
	out := Declarations{
		Reserves:        slices.Clone(s.Reserves),
		Denies:          slices.Clone(s.Denies),
		CredentialFiles: slices.Clone(s.CredentialFiles),
	}
	for _, d := range s.Declares {
		d.Hosts, d.Paths = slices.Clone(d.Hosts), slices.Clone(d.Paths)
		out.Declares = append(out.Declares, d)
	}
	for _, g := range s.OneOf {
		g.Of = slices.Clone(g.Of)
		out.OneOf = append(out.OneOf, g)
	}
	return out
}

// Model is the descriptor's model section, a copy, and true; the zero ModelPlaces and
// false when it has none.
func (r *described) Model() (ModelPlaces, bool) {
	m := r.d.Model
	if m == nil {
		return ModelPlaces{}, false
	}
	out := ModelPlaces{Formats: slices.Clone(m.Formats), Model: m.Model, Endpoint: m.Endpoint, Keys: slices.Clone(m.Keys), Overrides: slices.Clone(m.Overrides)}
	if e := m.Effort; e != nil {
		effort := Effort{Run: e.Run}
		effort.Run.Values = slices.Clone(e.Run.Values)
		if a := e.Agent; a != nil {
			effort.Agent = &AgentPlace{Frontmatter: a.Frontmatter, Values: slices.Clone(a.Values)}
		}
		out.Effort = &effort
	}
	return out, true
}

// stopSignals are the signals a spec may name: the ones a program is written to leave
// on. SIGKILL is not one, it is what follows the grace.
var stopSignals = map[string]syscall.Signal{
	"SIGTERM": syscall.SIGTERM,
	"SIGINT":  syscall.SIGINT,
	"SIGHUP":  syscall.SIGHUP,
	"SIGQUIT": syscall.SIGQUIT,
	"SIGUSR1": syscall.SIGUSR1,
	"SIGUSR2": syscall.SIGUSR2,
}

// CheckStopSignal reports whether a spec may name the signal: SIGTERM, SIGINT, SIGHUP,
// SIGQUIT, SIGUSR1 or SIGUSR2, written that way. Empty is the default and passes.
func CheckStopSignal(name string) error {
	if name == "" {
		return nil
	}
	if _, ok := stopSignals[name]; !ok {
		return fmt.Errorf("the stop signal %s is not one of SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2", accesskey.ShownName(name, true))
	}
	return nil
}

// StopSignal is the signal [CheckStopSignal] passes by that name; zero for a name it
// does not pass.
func StopSignal(name string) syscall.Signal { return stopSignals[name] }
