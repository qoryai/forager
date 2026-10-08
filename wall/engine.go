package wall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Engine is what reaches the container engine a run's enclosure is in, as a runner
// records it for another runner to ask whether the run's containers still exist: the
// wall, the command and the variables that select the engine. It holds no secret.
type Engine struct {
	// Wall is the adapter's name: docker.
	Wall string `json:"wall"`
	// Command is the program the adapter runs, absolute when it is found in PATH.
	Command string `json:"command"`
	// Env are the variables that select the engine, NAME=value, as the adapter's
	// command reads them; a password in an address is left out.
	Env []string `json:"env,omitempty"`
}

// Engined is a wall whose enclosures are containers of an engine, which outlive a
// runner that is killed before it closes them.
type Engined interface {
	// Engine is the engine the wall's enclosures are in, as the wall reaches it now.
	Engine() Engine
}

// engineVariables are the variables that select the engine the docker command, podman
// or nerdctl reaches.
var engineVariables = []string{
	"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH",
	"DOCKER_TLS_VERIFY", "CONTAINER_HOST", "CONTAINER_CONNECTION", "CONTAINERD_ADDRESS",
	"CONTAINERD_NAMESPACE",
}

// existsWait is how long the engine has to list a run's containers.
const existsWait = 30 * time.Second

// Engine is the engine the adapter's command reaches: the command, absolute when it is
// found in PATH, and the variables of this process's environment that select the
// engine, DOCKER_CONFIG and DOCKER_CERT_PATH made absolute.
func (d *Docker) Engine() Engine {
	e := Engine{Wall: d.Name(), Command: d.command()}
	if abs, err := exec.LookPath(e.Command); err == nil {
		if abs, err = filepath.Abs(abs); err == nil {
			e.Command = abs
		}
	}
	for _, name := range engineVariables {
		value, ok := os.LookupEnv(name)
		if !ok {
			continue
		}
		switch name {
		case "DOCKER_CONFIG", "DOCKER_CERT_PATH":
			if abs, err := filepath.Abs(value); err == nil && value != "" {
				value = abs
			}
		case "DOCKER_HOST", "CONTAINER_HOST":
			value = withoutPassword(value)
		}
		e.Env = append(e.Env, name+"="+value)
	}
	return e
}

// withoutPassword is an address with the password of its user information left out.
func withoutPassword(address string) string {
	u, err := url.Parse(address)
	if err != nil || u.User == nil {
		return address
	}
	if _, set := u.User.Password(); !set {
		return address
	}
	u.User = url.User(u.User.Username())
	return u.String()
}

// RunContainersExist reports whether the engine holds a container labelled with the
// run's id, in any state: a container that is created, paused or stopped can be started
// again with its binds.
func RunContainersExist(ctx context.Context, e Engine, runID string) (bool, error) {
	return runContainersExist(ctx, hostSystem{}, e, runID)
}

func runContainersExist(
	ctx context.Context, sys system, e Engine, runID string,
) (bool, error) {
	if e.Wall != "docker" {
		return false, fmt.Errorf("wall: the %q wall's engine cannot be asked", e.Wall)
	}
	if !runIDShape.MatchString(runID) {
		return false, fmt.Errorf("wall docker: the run id %q cannot name a container", runID)
	}
	if e.Command == "" {
		return false, errors.New("wall docker: the engine has no command")
	}
	for _, kv := range e.Env {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(engineVariables, name) {
			return false, fmt.Errorf("wall docker: %s does not select an engine", name)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, existsWait)
	defer cancel()
	argv := []string{e.Command, "ps", "--all", "--quiet",
		"--filter", "label=dev.qory.run=" + runID}
	out, err := sys.engine(ctx, argv, e.Env)
	if err != nil {
		return false, fmt.Errorf("wall docker: %s ps: %w", e.Command, err)
	}
	return len(bytes.TrimSpace(out)) > 0, nil
}

// engineCommand is a command of the machine's run against a recorded engine: the
// runner's environment without the access key's variables and without any variable
// that selects an engine, and then the engine's own.
func engineCommand(ctx context.Context, argv, env []string) *exec.Cmd {
	cmd := hostCommand(ctx, argv)
	kept := cmd.Env[:0]
	for _, kv := range cmd.Env {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(engineVariables, name) {
			kept = append(kept, kv)
		}
	}
	cmd.Env = append(kept, env...)
	return cmd
}

func (hostSystem) engine(ctx context.Context, argv, env []string) ([]byte, error) {
	out, err := engineCommand(ctx, argv, env).Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) && len(bytes.TrimSpace(exit.Stderr)) > 0 {
		return out, fmt.Errorf("%w: %s", err, bytes.TrimSpace(exit.Stderr))
	}
	return out, err
}
