package wall

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
)

// StepWrapper is an enclosure that runs a step: a caller's command in a step container,
// a new container of the run's image on the inside network, whose only way out is the
// relay. The session marks every connection of the relay while a step container may run,
// so the gateway's proxy applies the run's allow list to its requests and records them,
// sets no credential on them and returns 403 for its run API requests. A step container
// gets no nested Docker daemon, no hook socket, no home and no transcript.
type StepWrapper interface {
	// WrapStep creates the step container and returns the launch that starts it and
	// attaches to its output, on the pipes of whoever starts it and with no input. Only
	// l.Command, l.Args, l.Env, l.Dir, l.Proxy, l.CA, l.Mounts and l.Limits are read:
	// l.Command is the container's entrypoint, inside the image. After an error the
	// container may exist: call UnwrapStep.
	WrapStep(ctx context.Context, l Launch) (Launch, error)
	// UnwrapStep stops the step container, with SIGTERM and then SIGKILL after grace
	// when its command still runs, reads how it ended, and removes it, as
	// [Enclosure.Close] would, returning once the engine removed it. A container that is
	// gone is not an error, and returns the zero StepExit. A failed removal matches
	// [ErrContainerKept]: the container may still run, and Close tries again.
	UnwrapStep(ctx context.Context, grace time.Duration) (StepExit, error)
	// Kept lists the run's containers whose last removal failed and that may still run:
	// the agent's, After's, the setup container or the step container. The relay, which
	// binds the helper alone, is not listed.
	Kept() []KeptContainer
}

// KeptContainer is a container of the run whose last removal failed.
type KeptContainer struct {
	// Name is the container's name.
	Name string
	// Remove is the command line that removes the container on this machine, for a
	// person to run.
	Remove string
}

// StepExit is how a step container ended, as the engine reports it.
type StepExit struct {
	// Started is true when the container's command started.
	Started bool
	// ExitCode is the exit status of the container's init: the command's, or 128+N when
	// signal N ended the command.
	ExitCode int
	// OOMKilled is true when the kernel ended a process of the container for lack of
	// memory.
	OOMKilled bool
}

// step is the name of the run's step container.
func (e *dockerEnclosure) step() string { return e.base + "-step" }

// WrapStep creates the step container with docker create, as WrapAfter's container
// starts: on the inside network, from the run's image under the run's container
// runtime, as the wall's user with no capability and none to gain, with the launch's
// mounts at their paths or their Targets, the working directory, with l.CA the bundle,
// and the launch's limits; the helper is not mounted, since nothing in the step
// container runs it. Its environment, through a file, is l.Env, the
// proxy variables, set to the relay's address with no password, and, with l.CA, the variables
// that point at the bundle. It has no --rm, so UnwrapStep reads its exit before it
// removes it, and no hook socket. With nested Docker it runs under the same runtime,
// with no root, no daemon, no store volume and no IPv6 sysctl. The entrypoint is
// l.Command. It starts the relay and runs the run's first use of the enclosure when
// neither ran, as Wrap does, and returns docker start --attach of the container.
func (e *dockerEnclosure) WrapStep(ctx context.Context, l Launch) (Launch, error) {
	l.Socket = ""
	mounts, dir, err := e.mounts(l)
	if err != nil {
		return Launch{}, err
	}
	limits, err := limits(l.Limits)
	if err != nil {
		return Launch{}, err
	}
	env := append([]string(nil), l.Env...)
	env = append(env, link.ProxyEnv(relayURL(""))...)
	if len(l.CA) > 0 {
		for _, n := range e.d.SetsWithAuthority() {
			env = append(env, n+"="+BundlePath)
		}
	}
	envFile, err := e.envFile("step-env", env)
	if err != nil {
		return Launch{}, err
	}
	if err := e.StartRelay(ctx, l); err != nil {
		return Launch{}, err
	}
	bundle, err := e.firstUse(ctx, l.CA)
	if err != nil {
		return Launch{}, err
	}
	create := []string{"create", "--name", e.step(), "--label", e.label(), "--network", e.inside()}
	if e.req.Runtime != "" {
		create = append(create, "--runtime", e.req.Runtime)
	}
	create = append(create, e.hardening()...)
	create = append(create, "--no-healthcheck")
	if !e.req.Docker {
		// As After's container, which follows the agent's.
		create = append(create, "--sysctl", "net.ipv6.conf.default.disable_ipv6=1")
	}
	create = append(create, limits...)
	create = append(create, "--env-file", envFile, "--workdir", l.Dir)
	for _, m := range mounts {
		create = append(create, "--mount", m)
	}
	if bundle != "" {
		create = append(create, "--mount", bundle)
	}
	create = append(create, e.neverPull()...)
	create = append(create, "--entrypoint", l.Command, e.req.Image)
	create = append(create, l.Args...)
	if rm := []string{"rm", "--force", "--volumes", e.step()}; !slices.ContainsFunc(e.made, func(c []string) bool { return slices.Equal(c, rm) }) {
		e.made = append(e.made, rm)
	}
	made, cancel := context.WithTimeout(ctx, relayWait)
	out, err := e.docker(made, create...)
	cancel()
	if err != nil {
		return Launch{}, e.unpulled(e.req.Image, out, err)
	}
	cli := accesskey.WithoutVariables(os.Environ())
	if e.env != nil {
		cli = withSelection(cli, e.env)
	}
	return Launch{Command: e.command(), Args: []string{"start", "--attach", e.step()}, Env: cli, Dir: dir}, nil
}

// UnwrapStep stops the step container with docker stop -t, reads its state with
// docker inspect and removes it with docker rm --force, within the stop's grace and
// closeWait. For a container that is gone it returns the zero StepExit and no error.
func (e *dockerEnclosure) UnwrapStep(ctx context.Context, grace time.Duration) (StepExit, error) {
	if !slices.ContainsFunc(e.made, func(c []string) bool { return slices.Equal(c, []string{"rm", "--force", "--volumes", e.step()}) }) {
		return StepExit{}, nil
	}
	stop, cancel := context.WithTimeout(ctx, grace+closeWait)
	defer cancel()
	seconds := strconv.Itoa(int(grace.Round(time.Second) / time.Second))
	var exit StepExit
	var readErr error
	if out, err := e.docker(stop, "stop", "-t", seconds, e.step()); err != nil && !noSuchContainer(string(out)) {
		readErr = err
	}
	if readErr == nil {
		out, err := e.docker(stop, "inspect", "--type", "container", "--format", "{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}", e.step())
		switch {
		case err != nil && noSuchContainer(string(out)):
		case err != nil:
			readErr = err
		default:
			exit, readErr = stepExit(string(out))
		}
	}
	if err := e.removeContainer(ctx, e.step(), noSuchContainer); err != nil {
		return exit, err
	}
	return exit, readErr
}

// stepExit reads docker inspect's status, exit code and OOMKilled of the step container.
func stepExit(out string) (StepExit, error) {
	f := strings.Fields(out)
	if len(f) != 3 {
		return StepExit{}, fmt.Errorf("wall docker: the step container's state %s", accesskey.ShownValue(strings.TrimSpace(out), false))
	}
	code, err := strconv.Atoi(f[1])
	if err != nil {
		return StepExit{}, fmt.Errorf("wall docker: the step container's exit code %s", accesskey.ShownValue(f[1], false))
	}
	return StepExit{Started: f[0] != "created", ExitCode: code, OOMKilled: f[2] == "true"}, nil
}

// Kept lists the containers whose last removal failed, apart from the relay, in the
// order the removals failed, each with docker rm -f of its name as Remove.
func (e *dockerEnclosure) Kept() []KeptContainer {
	var out []KeptContainer
	for _, name := range e.kept {
		if name != e.relay() {
			// shortcut: Remove has none of the engine selection in e.env, such as
			// DOCKER_HOST, so it removes from the shell's default engine; add the
			// selection when a run selects an engine other than the default.
			out = append(out, KeptContainer{Name: name, Remove: e.command() + " rm -f " + name})
		}
	}
	return out
}
