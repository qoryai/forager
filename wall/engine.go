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
// adapter, the command, the variables that select the engine and the engine's own id.
// It holds no secret.
type Engine struct {
	// Wall is the adapter: docker, whichever command it runs.
	Wall string `json:"wall"`
	// Command is the program the adapter runs, absolute when it is found in PATH.
	Command string `json:"command"`
	// Env are the variables that select the engine, NAME=value, as the adapter's
	// command reads them, and the selection pinned where the command would read it
	// from its configuration; a password in an address is left out.
	Env []string `json:"env,omitempty"`
	// ID is the engine's own id, as it answered when the run started; empty when it
	// gave none.
	ID string `json:"id,omitempty"`
}

// Engined is a wall whose enclosures are containers of an engine, which outlive a
// runner that is killed before it closes them.
type Engined interface {
	// Engine is the engine the wall's enclosures are in, as the wall reaches it now.
	Engine(ctx context.Context) Engine
}

// engineVariables are the variables that select the engine the docker command, podman
// or nerdctl reaches.
var engineVariables = []string{
	"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH",
	"DOCKER_TLS_VERIFY", "CONTAINER_HOST", "CONTAINER_CONNECTION", "CONTAINERD_ADDRESS",
	"CONTAINERD_NAMESPACE",
}

// existsWait is how long the engine has to answer one question.
const existsWait = 30 * time.Second

// idArgs ask the engine for its own id.
var idArgs = []string{"info", "--format", "{{.ID}}"}

// Engine is the engine the adapter's command reaches, pinned: the command, absolute
// when it is found in PATH; the variables of this process's environment that select
// the engine, DOCKER_CONFIG and DOCKER_CERT_PATH made absolute and DOCKER_CONFIG
// ~/.docker when it is not set; the context the command uses, when neither DOCKER_HOST
// nor DOCKER_CONTEXT is set, since the command would read it from its configuration,
// which can change; and the engine's id, when it gives one.
func (d *Docker) Engine(ctx context.Context) Engine {
	sys := d.sys
	if sys == nil {
		sys = hostSystem{}
	}
	e := Engine{Wall: "docker", Command: d.command()}
	if abs, err := exec.LookPath(e.Command); err == nil {
		if abs, err = filepath.Abs(abs); err == nil {
			e.Command = abs
		}
	}
	set := map[string]bool{}
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
			if value, ok = withoutPassword(value); !ok {
				continue
			}
		}
		e.Env, set[name] = append(e.Env, name+"="+value), true
	}
	if home, err := os.UserHomeDir(); err == nil && !set["DOCKER_CONFIG"] {
		e.Env = append(e.Env, "DOCKER_CONFIG="+filepath.Join(home, ".docker"))
	}
	ctx, cancel := context.WithTimeout(ctx, existsWait)
	defer cancel()
	if !set["DOCKER_HOST"] && !set["DOCKER_CONTEXT"] {
		out, err := sys.engine(ctx, []string{e.Command, "context", "show"}, e.Env)
		if name := oneWord(out); err == nil && name != "" {
			e.Env = append(e.Env, "DOCKER_CONTEXT="+name)
		}
	}
	out, err := sys.engine(ctx, append([]string{e.Command}, idArgs...), e.Env)
	if err == nil {
		e.ID = oneWord(out)
	}
	return e
}

// oneWord is a command's answer when it is one word, else empty.
func oneWord(out []byte) string {
	word := string(bytes.TrimSpace(out))
	if word == "" || word == "<no value>" || strings.ContainsAny(word, " \t\n=") {
		return ""
	}
	return word
}

// withoutPassword is an address with the password of its user information left out,
// and false for one that cannot be read, which is left out whole.
func withoutPassword(address string) (string, bool) {
	u, err := url.Parse(address)
	if err != nil {
		return "", false
	}
	if u.User == nil {
		return address, true
	}
	if _, set := u.User.Password(); !set {
		return address, true
	}
	u.User = url.User(u.User.Username())
	return u.String(), true
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
	// The engine reached is the one the run was in, or the answer says nothing of it.
	if e.ID != "" {
		out, err := sys.engine(ctx, append([]string{e.Command}, idArgs...), e.Env)
		if err != nil {
			return false, fmt.Errorf("wall docker: %s info: %w", e.Command, err)
		}
		if id := oneWord(out); id != e.ID {
			return false, fmt.Errorf("wall docker: %s reaches the engine %q, not %q, the "+
				"one the run was in", e.Command, id, e.ID)
		}
	}
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
