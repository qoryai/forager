// Package runtimes is the boundary between the runner and the program it runs: an agent
// runtime such as Claude Code, Codex or one of a caller's own. The runner starts a
// process, records it and stops it; what is particular to a program, how it is made to
// report, what its records mean and how it is asked to leave, is behind [Runtime].
//
// There are three ways to a Runtime. [Bare] is a program the runner knows nothing
// about: the run is recorded, the session inside it is not. [Described] is a runtime
// written as data, a descriptor of the contract that matches records and copies fields
// and names an [Installer] among the ones it is given; nothing of a descriptor runs.
// And a caller that embeds the runner implements the interface itself. The catalog
// package resolves a name to the first two.
package runtimes

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/qoryai/runner/internal/credential"
	"github.com/qoryai/runner/internal/descriptor"
)

// Runtime is one program the runner can run a session of.
type Runtime interface {
	// Name is the runtime's name as events report it: claude, codex.
	Name() string
	// Version is the version of the program the adapter was written against, reported
	// in run.started and not checked against what is installed. Empty when the adapter
	// was written against none.
	Version() string
	// Prepare makes a launch one the runner can follow: it installs the forwarder as
	// the program's hook, writes what that takes into the run directory, and returns
	// the launch to start in place of the one given, command and arguments. A program
	// that waits for a person to approve a stand-in of [Attach.Placeholders] may be
	// started through a script Prepare writes there, which records the approval where
	// the program reads it and then starts the program. A runtime with nothing to
	// prepare returns the launch as it is.
	Prepare(Attach) (Launch, error)
	// ReadsOutput reports whether the program's standard output, when the session runs
	// on pipes, is JSON lines the runner hands to Map as records of [SourceOutput].
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
	// RunDir is the run directory. What Prepare writes goes here; under a wall the
	// enclosure sees it read-only at the same path.
	RunDir string
	// Forwarder is the command to install as the program's hook: it reads a hook's
	// input and forwards it to the runner as a record of [SourceHooks]. Empty means the
	// run has none, and no hooks are installed.
	Forwarder []string
	// Interactive says the session runs on a pseudo-terminal, not on pipes.
	Interactive bool
	// Placeholders are the variables the session sets to [Placeholder] in the
	// program's environment: a credential's, whose value the proxy sets outside the
	// enclosure, and a tool's, whose host the tool serves outside it. Empty without a
	// wall.
	Placeholders []string
}

// Placeholder is the value of every variable of [Attach.Placeholders]: a stand-in that
// is no credential and says what it is to whoever reads it.
const Placeholder = credential.Placeholder

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
// groups of them of which a runtime connection supplies one at most; Reserves, the
// variables it reads a credential from beside the declared ones; Denies, the
// variables the runner leaves out of a server's set for it; and CredentialFiles, the
// files in which it keeps a credential of its own, ~ being the home of the user the
// runner runs as.
type Declarations = descriptor.Secrets

// Declaration is one secret a runtime reads: its id, a title for a person, the
// variable it is read from, the exact hosts and the optional paths its value is set
// on, and how it is set.
type Declaration = descriptor.Declaration

// Auth is how a value is set on a request: Scheme is bearer, header or basic, Header
// the header of header, Username the fixed user of basic.
type Auth = descriptor.Auth

// Group is a set of declarations of which a runtime connection supplies one at most,
// and exactly one when Required.
type Group = descriptor.Group

// Record is one unit of what a program reports.
type Record = descriptor.Record

// The sources of a record.
const (
	SourceOutput = descriptor.SourceOutput
	SourceHooks  = descriptor.SourceHooks
)

// Stop is how a program is asked to leave: Signal, one the session package's
// CheckStopSignal passes, and Grace, the time until SIGKILL. Empty and zero are the
// runner's defaults.
type Stop struct {
	Signal string
	Grace  time.Duration
}

// Installer installs the forwarder as a program's hook for each of the events named,
// the way one program takes hooks, and returns the launch that reads them. A descriptor
// names an installer; it never brings one.
type Installer func(events []string, a Attach) (Launch, error)

// Bare is a program the runner knows nothing about: nothing is prepared, no record is
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

// Stop is the runner's defaults.
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
			return nil, fmt.Errorf("%s: hook installer %q is not one this runner implements", name, h.Install)
		}
	}
	if s := d.Stop; s != nil {
		r.stop.Signal = s.Signal
		if s.Grace != "" {
			if r.stop.Grace, err = time.ParseDuration(s.Grace); err != nil || r.stop.Grace <= 0 {
				return nil, fmt.Errorf("%s: stop.grace %q is not a duration above zero", name, s.Grace)
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
// to know, and the runner does not guess at it, so a value that happens to spell a
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
