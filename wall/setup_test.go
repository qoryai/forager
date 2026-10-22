package wall

import (
	"bytes"
	"context"
	"os"
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
