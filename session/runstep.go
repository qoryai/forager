package session

import (
	"context"
	"errors"
	"time"

	"github.com/qoryai/forager/wall"
)

// StepSpec is what [Run.RunStep] is given: the step's name, its image, its command,
// its working folder and mounts, its time limit, the paths its places are checked
// against and its limits.
type StepSpec struct {
	// Name is the step's name in its dev.qory.run.step_started and its log lines, such
	// as "step first/ac-1-x". Any text but an empty one: spaces and slashes are kept.
	// It is not the name of a container or a file.
	Name string
	// Image is the image the step container starts from: the run's image, by its name
	// or its reference, the one the node's policy sets for the run. Empty is the run's
	// image. Any other image is refused before the step starts.
	Image string
	// Command is the program the step container runs and its arguments: Command[0] is
	// the container's entrypoint, as the image's file system has it. It must not be
	// empty.
	Command []string
	// Dir is the working folder, bound writable and the working directory inside, as
	// SetupSpec.Dir is. Empty is the working directory of this process.
	Dir string
	// Mounts are further places of this machine the step container binds, each at its
	// path or at its Target, read-only or writable, with the checks of
	// SessionSpec.Mounts.
	Mounts []wall.Mount
	// Timeout is how long the command may run, from the container's start. When it
	// passes, the container gets SIGTERM, then SIGKILL 5 seconds later, and the result
	// has TimedOut. Zero is no limit of the step's: the step then ends with its
	// command, with ctx, or with [Run.Close].
	Timeout time.Duration
	// ForagerFiles are the absolute paths of the caller's files that are Forager's, as
	// in SetupSpec.ForagerFiles.
	ForagerFiles []string
	// Written are the places of this machine that the caller records as writable by a
	// walled run, as in SetupSpec.Written.
	Written []string
	// Limits are the resources the step container may use, as SetupSpec.Limits are the
	// setup container's.
	Limits wall.Limits
}

// StepResult is what a step's command did. An exit status other than 0 is a result,
// not an error of [Run.RunStep].
type StepResult struct {
	// Step is the number of the step in the run's steps.
	Step int
	// ExitCode is the exit status of the command, or -1 when the command has none, as
	// when the step was stopped before the container's start.
	ExitCode int
	// Signal is the number of the signal that ended the command, such as 9 for
	// SIGKILL, and 0 when no signal ended it. Under the container's init, an exit
	// status of 128+N is signal N.
	Signal int
	// TimedOut is true when StepSpec.Timeout ended the command.
	TimedOut bool
	// OOMKilled is true when the engine ended the command at the memory limit.
	OOMKilled bool
	// Output is the first 1 MiB of the command's standard output and standard error,
	// in the order they arrived, after the run's masker replaced the run's secrets in
	// them. The step's log lines have all of it.
	Output []byte
	// OutputCut is true when the command wrote more than Output has.
	OutputCut bool
	// Started and Ended are when the step started and ended.
	Started, Ended time.Time
}

// RunStep runs one command in a step container of the run's image on the run's inside
// network. A step container has no credential and no run API access.
func (r *Run) RunStep(ctx context.Context, spec StepSpec) (*StepResult, error) {
	// shortcut: no step runs until the mark of step traffic is built, in this change.
	return nil, errors.New("Run the step with a Forager that has RunStep: this build has none.")
}
