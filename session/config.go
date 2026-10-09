package session

import (
	"fmt"
	"regexp"

	"github.com/qoryai/forager/session/internal/variables"
)

// Variables are the run's and the machine's variables and how a run takes the
// server's: for qory, --env and wall.env.
//
// For each name the highest source that sets it wins: the run's fixed names, those
// Forager, the wall, the runtime's preparation and the placeholders set and
// [Spec.LaunchFixed]; the server's variables, which it resolved among its own levels;
// Run; Machine; [Spec.LaunchDefaults]; [Spec.Env]. A walled run refuses first what
// must stay outside the enclosure: a QORY_ name other than QORY_RUN_ID and
// QORY_RUN_SOCKET, or a variable a machine value is read from, from any of them,
// variable_reserved; any run refuses a value for a placeholder, placeholder_conflict.
// The deny list, the contract's denied-variables.json, the runtime's denies and Deny,
// then leaves out a value of the server, Run, Machine or LaunchDefaults; the built-in
// list alone leaves out one of LaunchFixed. The server's are left out of a run without
// a wall unless Unwalled is [UnwalledAccept]. A value that loses is left out and the
// run starts; dev.qory.run.policy_applied records each name, its source and what lost,
// never a value, and [Spec.OnVariables] receives the same.
type Variables struct {
	// Run are the run's own variables, NAME=value: for qory, --env. They apply with or
	// without a wall.
	Run []string
	// Machine are the machine's variables, NAME=value: for qory, wall.env.
	Machine []string
	// Deny are names and patterns, in which * matches any run of characters, of
	// variables the run leaves out of the server's, Run, Machine and
	// [Spec.LaunchDefaults], matched regardless of case. qory sets none.
	Deny []string
	// Unwalled is how a run without a Wall takes the server's variables:
	// [UnwalledAccept] applies them as a walled run does, after the deny list;
	// [UnwalledIgnore], which empty means, leaves them all out. The deny list keeps the
	// wall and Forager whole, not the developer's shell, which accept opens to the
	// server.
	Unwalled string
}

// Applied is the run's variables as resolved: one entry per name, sorted by name, as
// dev.qory.run.policy_applied records them. A name is in it when the server, the run,
// the machine or the harness's defaults set it; a fixed name, and a name of the
// environment the run inherits, only beside one of those.
type Applied []AppliedVariable

// AppliedVariable is one name: the source whose value the run applies, empty when none
// does, and the values that lost, the highest source first.
type AppliedVariable struct {
	Name, From string
	Lost       []Loss
}

// Loss is one source's value that lost, and why.
type Loss struct {
	From, Why string
}

// The sources of a variable, the highest first, and why a value lost, as
// [AppliedVariable] and [Loss] contain them.
const (
	FromFixed   = variables.FromFixed
	FromApiary  = variables.FromApiary
	FromRun     = variables.FromRun
	FromMachine = variables.FromMachine
	FromHarness = variables.FromHarness
	FromShell   = variables.FromShell

	WhyOverridden = variables.WhyOverridden
	WhyDenied     = variables.WhyDenied
	WhyFixed      = variables.WhyFixed
	WhyUnwalled   = variables.WhyUnwalled
)

// applied is the record of a resolution as [Spec.OnVariables] receives it.
func applied(entries []variables.Entry) Applied {
	out := make(Applied, len(entries))
	for i, e := range entries {
		lost := make([]Loss, len(e.Lost))
		for j, l := range e.Lost {
			lost[j] = Loss{From: l.From, Why: l.Why}
		}
		out[i] = AppliedVariable{Name: e.Name, From: e.From, Lost: lost}
	}
	return out
}

// The two values of [Variables.Unwalled].
const (
	UnwalledAccept = variables.Accept
	UnwalledIgnore = variables.Ignore
)

// Image is one image as the machine defines it, [Spec.Images]: what an agent's
// enclosure is started from, and how. A run's policy selects images by name and names
// no reference, so a repository never chooses what it runs under.
type Image struct {
	// Name is what a policy, or [Spec.Image], selects it by.
	Name string
	// Ref is the image's reference, pinned by digest where the machine wants the same
	// image every time.
	Ref string
	// Runtime is the container runtime the wall starts the image under, one the
	// machine's engine has: sysbox-runc. Empty is the engine's default.
	Runtime string
	// Docker gives the agent a Docker daemon of its own, inside the enclosure: the
	// image holds dockerd, and the wall starts it before the agent. It needs a Runtime
	// that runs a daemon in a container without privileges. Experimental: see contracts/forager/v1/README.md §The wall.
	Docker bool
}

// Check refuses a definition that cannot be one, so a command reading the machine's
// configuration says so before any run selects it.
func (i Image) Check() error {
	if !imageNameShape.MatchString(i.Name) {
		return fmt.Errorf("the image name %q is not 1 to 64 of a-z, 0-9, underscore, dot and dash", i.Name)
	}
	if i.Ref == "" {
		return fmt.Errorf("image %s: the reference is empty", i.Name)
	}
	if i.Docker && i.Runtime == "" {
		return fmt.Errorf("image %s: a Docker of the agent's own needs a runtime that runs one without privileges, such as sysbox-runc", i.Name)
	}
	return nil
}

var imageNameShape = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// checkImages refuses the machine's image table when it cannot be one, before the run
// request is sent: a definition that cannot be one, a Docker of the agent's own without
// a runtime among them, and a name defined twice. The gateway resolves the policy's
// selection against the table; these checks have no code.
func checkImages(spec Spec) error {
	for _, d := range spec.Images {
		if err := d.Check(); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, d := range spec.Images {
		if seen[d.Name] {
			return fmt.Errorf("the image %s is defined twice", d.Name)
		}
		seen[d.Name] = true
	}
	return nil
}
