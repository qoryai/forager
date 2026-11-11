package wall

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

// setupLaunch is what the session starts the setup container with: the working folder,
// the run's placeholders and the caller's variables, the run's CA and its forwarder.
func setupLaunch() Launch {
	return Launch{
		Dir: "/work", Env: []string{"APP_ENV=test"}, CA: []byte("not-a-real-ca"),
		Proxy: "127.0.0.1:50123", ProxyToken: "not-a-real-token", Mounts: []Mount{{Path: "/work"}},
	}
}

// TestDockerSetupCommandLines pins every command of a run with setup outside, from
// Prepare to Close: the relay as the run opens, the setup container, detached on the
// internal network alone with the alias qory-setup, the agent's flags, the working
// folder, the helper and the bundle, and the helper with HoldArgs as its command; each
// setup command through docker exec; the agent's container, removed by Unwrap; and the
// rest at Close. The setup container's environment file has the relay's proxy
// variables, the bundle's variables and the launch's, and no proxy token.
func TestDockerSetupCommandLines(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", local_: true, uid: 1000, execOut: "installed\n", execErr: "warning\n"}
	d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"run", "relay"}, HoldArgs: []string{"run", "hold"}, sys: rec}
	enc, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1"})
	if err != nil {
		t.Fatal(err)
	}
	e := enc.(*dockerEnclosure)
	ctx := context.Background()
	l := setupLaunch()
	l.Proxy = "172.30.0.1:50123"
	if err := e.StartRelay(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err := e.StartSetup(ctx, l); err != nil {
		t.Fatal(err)
	}
	temp := e.temp
	env, err := os.ReadFile(e.setupEnv)
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(e.setupEnv); info.Mode().Perm() != 0o600 {
		t.Errorf("the setup container's environment file's mode is %v", info.Mode().Perm())
	}
	var stdout, stderr bytes.Buffer
	code, err := e.ExecSetup(ctx, []string{"make", "deps"}, &stdout, &stderr)
	if err != nil || code != 0 || stdout.String() != "installed\n" || stderr.String() != "warning\n" {
		t.Errorf("the command: %d, %v, stdout %q, stderr %q", code, err, stdout.String(), stderr.String())
	}
	agent := launch()
	agent.Proxy = l.Proxy
	agent.CA = l.CA
	if _, err := e.Wrap(ctx, agent); err != nil {
		t.Fatal(err)
	}
	if err := e.Unwrap(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(ctx); err != nil {
		t.Fatal(err)
	}
	lines := strings.ReplaceAll(strings.Join(rec.lines, "\n"), temp, "PRIVATEDIR")
	if strings.Count(lines, "rm --force --volumes qory-"+runID+"-agent\n") != 1 {
		t.Errorf("the agent's container was removed other than once:\n%s", lines)
	}
	if strings.Contains(lines+string(env), "not-a-real-token") {
		t.Error("the proxy's token is on a command line or in the setup container's environment file")
	}
	golden(t, "setup", lines+"\n\nsetup environment:\n"+string(env))
}

// TestDockerRemoveSetup pins the removal of the setup container: the one command is
// docker rm --force --volumes with the container's name, Close does not run it again
// and works, and a docker rm that fails with "no such container" is not an error. Any
// other failure returns docker's error, keeps the container's entry in e.made, and Close
// runs the command again: a missing engine socket and a container runtime that fails
// leave the container up, though their text has "no such" or "not found". Each error
// matches ErrContainerKept.
func TestDockerRemoveSetup(t *testing.T) {
	ctx := context.Background()
	rm := "docker rm --force --volumes qory-" + runID + "-setup"
	const noSuch = "Error response from daemon: No such container: qory-x-setup"
	const socket = "failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory"
	const runtime = "Error response from daemon: Could not kill running container, cannot remove: OCI runtime kill failed: runtime \"runsc\": executable file not found in $PATH"
	for _, c := range []struct {
		name, failOut, wantErr string
		fail                   string
		atClose                int
	}{
		{name: "removed", atClose: 0},
		{name: "gone already", fail: rm, failOut: noSuch, atClose: 0},
		{name: "fails", fail: rm, atClose: 1,
			wantErr: "wall docker: docker rm --force: exit status 1: Error response from daemon: told to fail"},
		{name: "no engine socket", fail: rm, failOut: socket, atClose: 1,
			wantErr: "wall docker: docker rm --force: exit status 1: " + socket},
		{name: "a runtime that fails", fail: rm, failOut: runtime, atClose: 1,
			wantErr: "wall docker: docker rm --force: exit status 1: " + runtime},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := &recorder{t: t, gateway: "172.30.0.1", local_: true, uid: 1000}
			d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"run", "relay"}, HoldArgs: []string{"run", "hold"}, sys: rec}
			enc, err := d.Prepare(ctx, Request{RunID: runID, Image: "example.com/agent:1"})
			if err != nil {
				t.Fatal(err)
			}
			e := enc.(*dockerEnclosure)
			l := setupLaunch()
			l.Proxy = "172.30.0.1:50123"
			if err := e.StartSetup(ctx, l); err != nil {
				t.Fatal(err)
			}
			before := len(rec.lines)
			rec.fail, rec.failOut = c.fail, c.failOut
			err = e.RemoveSetup(ctx)
			if (err == nil) != (c.wantErr == "") || (err != nil && err.Error() != c.wantErr) {
				t.Errorf("RemoveSetup: %v, want %q", err, c.wantErr)
			}
			if err != nil && !errors.Is(err, ErrContainerKept) {
				t.Errorf("RemoveSetup's error %v does not match ErrContainerKept", err)
			}
			if got := rec.lines[before:]; len(got) != 1 || got[0] != rm {
				t.Errorf("the commands %q, want %q alone", got, rm)
			}
			entry := []string{"rm", "--force", "--volumes", "qory-" + runID + "-setup"}
			if got := slices.ContainsFunc(e.made, func(m []string) bool { return slices.Equal(m, entry) }); got != (c.atClose == 1) {
				t.Errorf("the entry in e.made: %v, want %v", got, c.atClose == 1)
			}
			rec.fail, rec.failOut = "", ""
			before = len(rec.lines)
			if err := e.Close(ctx); err != nil {
				t.Errorf("Close: %v", err)
			}
			if got := strings.Count(strings.Join(rec.lines[before:], "\n")+"\n", rm+"\n"); got != c.atClose {
				t.Errorf("Close ran %q %d times, want %d:\n%s", rm, got, c.atClose, strings.Join(rec.lines[before:], "\n"))
			}
		})
	}
}

// TestDockerRemoveSetupAfterUnwrap pins the removal after a session: the setup container
// runs through the session, RemoveSetup after Unwrap runs its one docker rm and leaves
// the relay and the networks, a later Wrap starts the agent's container, and Close
// removes the rest without the setup container.
func TestDockerRemoveSetupAfterUnwrap(t *testing.T) {
	ctx := context.Background()
	rec := &recorder{t: t, gateway: "172.30.0.1", local_: true, uid: 1000}
	d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"run", "relay"}, HoldArgs: []string{"run", "hold"}, sys: rec}
	enc, err := d.Prepare(ctx, Request{RunID: runID, Image: "example.com/agent:1"})
	if err != nil {
		t.Fatal(err)
	}
	e := enc.(*dockerEnclosure)
	l := setupLaunch()
	l.Proxy = "172.30.0.1:50123"
	if err := e.StartSetup(ctx, l); err != nil {
		t.Fatal(err)
	}
	agent := l
	agent.Command = "agent"
	if _, err := e.Wrap(ctx, agent); err != nil {
		t.Fatal(err)
	}
	if err := e.Unwrap(ctx); err != nil {
		t.Fatal(err)
	}
	made := slices.Clone(e.made)
	before := len(rec.lines)
	if err := e.RemoveSetup(ctx); err != nil {
		t.Fatal(err)
	}
	rm := "docker rm --force --volumes qory-" + runID + "-setup"
	if got := rec.lines[before:]; len(got) != 1 || got[0] != rm {
		t.Errorf("the commands %q, want %q alone", got, rm)
	}
	entry := []string{"rm", "--force", "--volumes", "qory-" + runID + "-setup"}
	want := slices.DeleteFunc(made, func(m []string) bool { return slices.Equal(m, entry) })
	if !slices.EqualFunc(e.made, want, slices.Equal[[]string]) {
		t.Errorf("e.made %q, want %q", e.made, want)
	}
	if _, err := e.Wrap(ctx, agent); err != nil {
		t.Errorf("a later Wrap: %v", err)
	}
	if err := e.Unwrap(ctx); err != nil {
		t.Fatal(err)
	}
	before = len(rec.lines)
	if err := e.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(rec.lines[before:], "\n"); strings.Contains(got, "-setup") {
		t.Errorf("Close touched the setup container:\n%s", got)
	}
}

// TestDockerUnwrapKeepsItsCheck pins Unwrap's reading of a docker rm that fails: only "no
// such container", which docker run --rm leaves for a container that exits, counts as
// gone, in any case. Any other failure is an error and keeps the container's entry in
// e.made, and Close, with the failure still there, returns an error too: a missing engine
// socket and a missing docker command leave the container's state unknown, though their
// text has "no such" or "not found". Each error of Unwrap matches ErrContainerKept.
func TestDockerUnwrapKeepsItsCheck(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		failOut string
		wantErr bool
	}{
		{"Error response from daemon: No such container: qory-x-agent", false},
		{"Error: no container with name or ID \"qory-x-agent\" found: no such container", false},
		{"dial unix /var/run/docker.sock: connect: no such file or directory", true},
		{"failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory", true},
		{"executable file not found in $PATH", true},
		{"Error response from daemon: told to fail", true},
	} {
		rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000}
		d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
		enc, err := d.Prepare(ctx, Request{RunID: runID, Image: "i"})
		if err != nil {
			t.Fatal(err)
		}
		e := enc.(*dockerEnclosure)
		rec.fail, rec.failOut = "-agent", c.failOut
		entry := []string{"rm", "--force", "--volumes", e.agent()}
		e.made = append(e.made, entry)
		err = e.Unwrap(ctx)
		if (err != nil) != c.wantErr {
			t.Errorf("%q: %v, want an error: %v", c.failOut, err, c.wantErr)
		}
		if err != nil && !errors.Is(err, ErrContainerKept) {
			t.Errorf("%q: Unwrap's error %v does not match ErrContainerKept", c.failOut, err)
		}
		if kept := slices.ContainsFunc(e.made, func(m []string) bool { return slices.Equal(m, entry) }); kept != c.wantErr {
			t.Errorf("%q: the container's entry in e.made: %v, want %v", c.failOut, kept, c.wantErr)
		}
		if err := e.Close(ctx); (err != nil) != c.wantErr {
			t.Errorf("%q: Close with the failure still there: %v, want an error: %v", c.failOut, err, c.wantErr)
		}
		rec.fail, rec.failOut = "", ""
	}
}

// TestDockerCloseReadsEachKindOfRemoval pins what Close counts as gone: for a container,
// only "no such container", so a missing engine socket is an error while the container
// may still run; for a network, also "not found" and a missing engine socket's text. The
// error of a failed container's removal matches ErrContainerKept, and so does a
// network's whose output shows a container still attached, "active endpoints" or "in
// use" in any case; any other network's matches ErrNoContainerKept alone. Each error's
// text is docker's failure.
func TestDockerCloseReadsEachKindOfRemoval(t *testing.T) {
	ctx := context.Background()
	const socket = "dial unix /var/run/docker.sock: connect: no such file or directory"
	const endpoints = "Error response from daemon: error while removing network: network qory-x-inside has active endpoints"
	const inUse = "Error: network qory-x-inside is IN USE by container 0123abcd"
	const told = "Error response from daemon: told to fail"
	const containerRm = "wall docker: docker rm --force: exit status 1: "
	const networkRm = "wall docker: docker network rm: exit status 1: "
	for _, c := range []struct {
		name, fail, failOut string
		// wantErr is Close's error text, empty for none.
		wantErr string
		// kept has one entry per failure of Close, in order: true for one that matches
		// ErrContainerKept alone, false for one that matches ErrNoContainerKept alone.
		kept []bool
	}{
		{name: "nothing fails"},
		{name: "a container, no engine socket", fail: "docker rm", failOut: socket, wantErr: containerRm + socket, kept: []bool{true}},
		{name: "a container that is gone", fail: "docker rm", failOut: "Error response from daemon: No such container: qory-x-agent"},
		{name: "a container that is gone, in Podman's form", fail: "docker rm", failOut: "Error: no container with name or ID \"qory-x-agent\" found: no such container"},
		{name: "a container, another failure", fail: "docker rm", wantErr: containerRm + told, kept: []bool{true}},
		{name: "a network that is gone", fail: "docker network rm", failOut: "Error response from daemon: network qory-x-inside not found"},
		{name: "a network, no engine socket", fail: "docker network rm", failOut: socket},
		{name: "a network, another failure", fail: "docker network rm", wantErr: networkRm + told + "\n" + networkRm + told, kept: []bool{false, false}},
		{name: "a network with active endpoints", fail: "docker network rm", failOut: endpoints,
			wantErr: networkRm + endpoints + "\n" + networkRm + endpoints, kept: []bool{true, true}},
		{name: "a network in use", fail: "docker network rm", failOut: inUse,
			wantErr: networkRm + inUse + "\n" + networkRm + inUse, kept: []bool{true, true}},
		{name: "a network and a container", fail: "docker network rm|docker rm",
			wantErr: containerRm + told + "\n" + networkRm + told + "\n" + networkRm + told, kept: []bool{true, false, false}},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000}
			d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
			enc, err := d.Prepare(ctx, Request{RunID: runID, Image: "i"})
			if err != nil {
				t.Fatal(err)
			}
			e := enc.(*dockerEnclosure)
			e.made = append(e.made, []string{"rm", "--force", "--volumes", e.agent()})
			rec.fail, rec.failOut = c.fail, c.failOut
			err = e.Close(ctx)
			if (err == nil) != (c.wantErr == "") || (err != nil && err.Error() != c.wantErr) {
				t.Errorf("Close: %v, want %q", err, c.wantErr)
			}
			if got, want := errors.Is(err, ErrContainerKept), slices.Contains(c.kept, true); got != want {
				t.Errorf("Close's error %v matches ErrContainerKept: %v, want %v", err, got, want)
			}
			var failures []error
			if err != nil {
				failures = err.(interface{ Unwrap() []error }).Unwrap()
			}
			if len(failures) != len(c.kept) {
				t.Fatalf("Close's failures %q, want %d", failures, len(c.kept))
			}
			for i, f := range failures {
				if errors.Is(f, ErrContainerKept) != c.kept[i] || errors.Is(f, ErrNoContainerKept) == c.kept[i] {
					t.Errorf("the failure %v matches ErrContainerKept: %v and ErrNoContainerKept: %v, want %v and %v",
						f, errors.Is(f, ErrContainerKept), errors.Is(f, ErrNoContainerKept), c.kept[i], !c.kept[i])
				}
			}
		})
	}
}

// TestDockerCloseOnAPrivateDirectoryThatStays pins Close when only the removal of the
// private directory fails: an error with os.RemoveAll's text, which matches
// ErrNoContainerKept and not ErrContainerKept, since nothing of the run runs in a
// directory.
func TestDockerCloseOnAPrivateDirectoryThatStays(t *testing.T) {
	ctx := context.Background()
	rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000}
	d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, sys: rec}
	enc, err := d.Prepare(ctx, Request{RunID: runID, Image: "i"})
	if err != nil {
		t.Fatal(err)
	}
	e := enc.(*dockerEnclosure)
	e.made = append(e.made, []string{"rm", "--force", "--volumes", e.agent()})
	// os.RemoveAll returns an error for a path whose last name is ".", and removes
	// nothing, also for root.
	temp := t.TempDir() + "/."
	e.temp = temp
	err = e.Close(ctx)
	if want := "RemoveAll " + temp + ": invalid argument"; err == nil || err.Error() != want {
		t.Errorf("Close: %v, want %q", err, want)
	}
	if errors.Is(err, ErrContainerKept) || !errors.Is(err, ErrNoContainerKept) {
		t.Errorf("Close's error %v matches ErrContainerKept, or does not match ErrNoContainerKept", err)
	}
}

// TestContainerKeptError pins ContainerKeptError: the error has err's text, matches
// ErrContainerKept and what err matches, and not ErrNoContainerKept; a nil err stays nil.
func TestContainerKeptError(t *testing.T) {
	failure := errors.New("wall docker: docker rm --force: exit status 1")
	err := ContainerKeptError(failure)
	if err.Error() != failure.Error() {
		t.Errorf("the text %q, want %q", err, failure)
	}
	if !errors.Is(err, ErrContainerKept) || !errors.Is(err, failure) || errors.Is(err, ErrNoContainerKept) {
		t.Errorf("%v matches ErrContainerKept: %v, the failure: %v, ErrNoContainerKept: %v",
			err, errors.Is(err, ErrContainerKept), errors.Is(err, failure), errors.Is(err, ErrNoContainerKept))
	}
	if err := ContainerKeptError(nil); err != nil {
		t.Errorf("ContainerKeptError(nil) = %v", err)
	}
}

// TestDockerSetupRefuses pins what stops the setup container before anything starts: no
// HoldArgs, and a second start; and a command before the start.
func TestDockerSetupRefuses(t *testing.T) {
	ctx := context.Background()
	prepared := func(hold []string) (*dockerEnclosure, *recorder) {
		rec := &recorder{t: t, gateway: "172.30.0.1", uid: 1000}
		d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, HoldArgs: hold, sys: rec}
		enc, err := d.Prepare(ctx, Request{RunID: runID, Image: "i"})
		if err != nil {
			t.Fatal(err)
		}
		return enc.(*dockerEnclosure), rec
	}
	e, rec := prepared(nil)
	before := len(rec.lines)
	err := e.StartSetup(ctx, setupLaunch())
	if want := "wall docker: setup needs the helper's arguments that keep the setup container running, HoldArgs"; err == nil || err.Error() != want {
		t.Errorf("no HoldArgs: %v", err)
	}
	if len(rec.lines) != before {
		t.Errorf("commands ran before the refusal: %v", rec.lines[before:])
	}
	e.Close(ctx)

	e, rec = prepared([]string{"run", "hold"})
	if _, err := e.ExecSetup(ctx, []string{"true"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || err.Error() != "wall docker: start the setup container before its commands" {
		t.Errorf("a command before the start: %v", err)
	}
	if err := e.StartSetup(ctx, setupLaunch()); err != nil {
		t.Fatal(err)
	}
	before = len(rec.lines)
	if err := e.StartSetup(ctx, setupLaunch()); err == nil || err.Error() != "wall docker: the setup container of the run started already" {
		t.Errorf("a second start: %v", err)
	}
	if len(rec.lines) != before {
		t.Errorf("commands ran before the refusal: %v", rec.lines[before:])
	}
	e.Close(ctx)
}

// TestASetupCommandsExitStatusIsItsOwn pins the exit status of a setup command: one
// other than 0 is returned while the setup container runs, and is an error with the
// container's output once the container stopped; a docker exec that does not run is an
// error.
func TestASetupCommandsExitStatusIsItsOwn(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name    string
		rec     *recorder
		code    int
		wantErr string
	}{
		{"running", &recorder{execCode: 3}, 3, ""},
		{"stopped", &recorder{execCode: 137, setupStopped: true}, -1, "wall docker: the setup container stopped: hold: told to stop"},
		{"no exec", &recorder{fail: " exec --user "}, -1, "wall docker: docker exec: exec: told to fail"},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.rec.t, c.rec.gateway, c.rec.uid = t, "172.30.0.1", 1000
			d := &Docker{Helper: "/h", RelayArgs: []string{"relay"}, HoldArgs: []string{"run", "hold"}, sys: c.rec}
			enc, err := d.Prepare(ctx, Request{RunID: runID, Image: "i"})
			if err != nil {
				t.Fatal(err)
			}
			defer enc.Close(ctx)
			e := enc.(*dockerEnclosure)
			if err := e.StartSetup(ctx, setupLaunch()); err != nil {
				t.Fatal(err)
			}
			code, err := e.ExecSetup(ctx, []string{"false"}, &bytes.Buffer{}, &bytes.Buffer{})
			if code != c.code || (err == nil) != (c.wantErr == "") || (err != nil && err.Error() != c.wantErr) {
				t.Errorf("code %d, err %v; want %d, %q", code, err, c.code, c.wantErr)
			}
		})
	}
}

// TestTheSetupContainerGetsTheLaunchsLimits pins that the launch's limits reach the setup
// container's docker run with the flags the agent's container gets, and that the zero
// Limits adds no limit flag.
func TestTheSetupContainerGetsTheLaunchsLimits(t *testing.T) {
	flags := []string{"--cpus", "--memory", "--shm-size", "--pids-limit"}
	for _, c := range []struct {
		name   string
		limits Limits
		want   string
	}{
		{"set", Limits{CPUs: "1.5", Memory: "8g", PIDs: 4096, ShmSize: "2g"}, "--cpus 1.5 --memory 8g --shm-size 2g --pids-limit 4096"},
		{"zero", Limits{}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := &recorder{t: t, gateway: "172.30.0.1", local_: true, uid: 1000}
			d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"run", "relay"}, HoldArgs: []string{"run", "hold"}, sys: rec}
			enc, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1"})
			if err != nil {
				t.Fatal(err)
			}
			e := enc.(*dockerEnclosure)
			defer e.Close(context.Background())
			l := setupLaunch()
			l.Proxy = "172.30.0.1:50123"
			l.Limits = c.limits
			if err := e.StartSetup(context.Background(), l); err != nil {
				t.Fatal(err)
			}
			var run string
			for _, line := range rec.lines {
				if strings.Contains(line, " run --detach --name qory-"+runID+"-setup ") {
					run = line
				}
			}
			if run == "" {
				t.Fatalf("no docker run of the setup container:\n%s", strings.Join(rec.lines, "\n"))
			}
			if c.want != "" && !strings.Contains(run, c.want) {
				t.Errorf("the setup container's docker run has no %s: %s", c.want, run)
			}
			if c.want == "" {
				for _, f := range flags {
					if strings.Contains(run, " "+f+" ") {
						t.Errorf("the zero Limits added %s: %s", f, run)
					}
				}
			}
		})
	}
}
