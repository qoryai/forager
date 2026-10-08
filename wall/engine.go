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
	// Pinned says Env selects one engine whatever the command's configuration holds.
	// For the command named podman, CONTAINER_HOST or CONTAINER_CONNECTION was set and
	// recorded, and such an engine is asked by its selection when it gave no ID. For any
	// other command, DOCKER_HOST or DOCKER_CONTEXT was, or the context the command
	// showed is; such an engine is asked by its ID, through this selection, and one that
	// gave no ID is no answer. A variable of the other kind never pins.
	Pinned bool `json:"pinned,omitempty"`
	// ID is the engine's own id, as it answered when the run started, or once the
	// enclosure was prepared; empty when it gave none.
	ID string `json:"id,omitempty"`
}

// Engined is a wall whose enclosures are containers of an engine, which outlive a
// runner that is killed before it closes them.
type Engined interface {
	// Engine is the engine the wall's enclosures are in, as the wall reaches it now.
	Engine(ctx context.Context) Engine
	// EngineID is the engine's id, asked again through the selection Engine recorded,
	// for an engine that gave none then; empty when it gives none.
	EngineID(ctx context.Context) (string, error)
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

// Engine is the engine the adapter's command reaches: the command, absolute when it is
// found in PATH; the variables of this process's environment that select the engine,
// DOCKER_CONFIG and DOCKER_CERT_PATH made absolute and DOCKER_CONFIG ~/.docker when it
// is not set; for a command other than podman, when neither DOCKER_HOST nor
// DOCKER_CONTEXT is set, the context the command shows, since the command would read it
// from its configuration, which can change; whether that selection is pinned, as
// [Engine.Pinned] says; and the engine's id, when it gives one, which a command other
// than podman is asked by later. A variable left out as
// unreadable leaves the selection unpinned, and then neither the context nor the id is
// asked, since they would be another engine's.
//
// Every engine command of the adapter's, from then on, runs with this selection in
// place of the runner's own, so the run's containers are on the engine recorded. With a
// variable left out, the commands keep the runner's own environment.
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
	set, dropped := map[string]bool{}, false
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
				dropped = true
				continue
			}
		}
		e.Env, set[name] = append(e.Env, name+"="+value), true
	}
	if home, err := os.UserHomeDir(); err == nil && !set["DOCKER_CONFIG"] {
		e.Env = append(e.Env, "DOCKER_CONFIG="+filepath.Join(home, ".docker"))
	}
	// The selection is pinned by the variables the command itself reads; the others
	// stay recorded, and the run's commands keep them.
	byName := podman(e.Command)
	if byName {
		e.Pinned = !dropped && (set["CONTAINER_HOST"] || set["CONTAINER_CONNECTION"])
	} else {
		e.Pinned = !dropped && (set["DOCKER_HOST"] || set["DOCKER_CONTEXT"])
	}
	ctx, cancel := context.WithTimeout(ctx, existsWait)
	defer cancel()
	if !dropped && !byName && !e.Pinned {
		out, err := sys.engine(ctx, []string{e.Command, "context", "show"}, e.Env)
		if name := oneWord(out); err == nil && name != "" {
			e.Env, e.Pinned = append(e.Env, "DOCKER_CONTEXT="+name), true
		}
	}
	if dropped {
		return e
	}
	e.ID, _ = engineID(ctx, sys, e)
	d.selectionMu.Lock()
	d.recorded = &Engine{Command: e.Command, Env: append([]string{}, e.Env...)}
	d.selectionMu.Unlock()
	return e
}

// EngineID is the id the engine gives now, asked through the selection [Docker.Engine]
// recorded; empty when it gives none, and an error when no selection is recorded.
func (d *Docker) EngineID(ctx context.Context) (string, error) {
	d.selectionMu.Lock()
	recorded := d.recorded
	d.selectionMu.Unlock()
	if recorded == nil {
		return "", errors.New("wall docker: no engine's selection is recorded")
	}
	sys := d.sys
	if sys == nil {
		sys = hostSystem{}
	}
	ctx, cancel := context.WithTimeout(ctx, existsWait)
	defer cancel()
	return engineID(ctx, sys, *recorded)
}

func engineID(ctx context.Context, sys system, e Engine) (string, error) {
	out, err := sys.engine(ctx, append([]string{e.Command}, idArgs...), e.Env)
	if err != nil {
		return "", err
	}
	return oneWord(out), nil
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

// podman reports whether the command is podman by its name, the one command whose
// selection pins its engine without an id.
func podman(command string) bool { return filepath.Base(command) == "podman" }

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
	// The engine reached is the one the run was in, or the answer says nothing of it. A
	// command other than podman is asked by its id: every Docker engine gives one, and
	// podman under another name reads none of the DOCKER_ variables that pin it.
	switch {
	case e.ID == "" && !podman(e.Command):
		return false, errors.New("wall docker: the run's engine was recorded without " +
			"an id, so another engine may answer")
	case e.ID == "" && !e.Pinned:
		return false, errors.New("wall docker: the run's engine was recorded with neither " +
			"a pinned selection nor an id, so another engine may answer")
	}
	if e.ID != "" {
		id, err := engineID(ctx, sys, e)
		if err != nil {
			return false, fmt.Errorf("wall docker: %s info: %w", e.Command, err)
		}
		if id != e.ID {
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
	cmd.Env = withSelection(cmd.Env, env)
	return cmd
}

// withSelection is an environment without any variable that selects an engine, and then
// the engine's selection.
func withSelection(environ, selection []string) []string {
	var kept []string
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(engineVariables, name) {
			kept = append(kept, kv)
		}
	}
	return append(kept, selection...)
}

func (hostSystem) engine(ctx context.Context, argv, env []string) ([]byte, error) {
	out, err := engineCommand(ctx, argv, env).Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) && len(bytes.TrimSpace(exit.Stderr)) > 0 {
		return out, fmt.Errorf("%w: %s", err, bytes.TrimSpace(exit.Stderr))
	}
	return out, err
}
