package wall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// stepLaunch is a step's launch as the session passes it: a shell command, the working
// folder, the bundle and limits, and no environment of the caller's.
func stepLaunch() Launch {
	return Launch{
		Command: "/bin/sh", Args: []string{"-c", "make test"}, Dir: "/work", CA: []byte("not-a-real-ca"),
		Proxy: "172.30.0.1:50123", ProxyToken: "not-a-real-token", Mounts: []Mount{{Path: "/work"}, {Path: "/data", ReadOnly: true}},
		Limits: Limits{Memory: "1g"},
	}
}

// TestDockerStepCommandLines pins WrapStep and UnwrapStep: the step container is created
// on the inside network with the hardening flags, the limits, the mounts, the helper and
// the bundle, no --rm, no hook socket, no nested Docker and no token, its environment
// file has the proxy variables with no password and the bundle's variables; the launch
// is docker start --attach; UnwrapStep stops it with the grace, reads its state and
// removes it, and Close does not remove it again.
func TestDockerStepCommandLines(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", local_: true, uid: 1000, stepState: "exited 2 false"}
	d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"run", "relay"}, sys: rec}
	enc, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1", Runtime: "runsc"})
	if err != nil {
		t.Fatal(err)
	}
	e := enc.(*dockerEnclosure)
	ctx := context.Background()
	got, err := e.WrapStep(ctx, stepLaunch())
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != "docker" || got.Dir != "/work" || !slices.Equal(got.Args, []string{"start", "--attach", "qory-" + runID + "-step"}) {
		t.Errorf("the launch %+v", got)
	}
	temp := e.temp
	env, err := os.ReadFile(filepath.Join(temp, "step-env"))
	if err != nil {
		t.Fatal(err)
	}
	exit, err := e.UnwrapStep(ctx, 5*time.Second)
	if err != nil || exit != (StepExit{Started: true, ExitCode: 2}) {
		t.Fatalf("UnwrapStep: %+v, %v", exit, err)
	}
	if kept := e.Kept(); len(kept) != 0 {
		t.Errorf("kept %v", kept)
	}
	if err := e.Close(ctx); err != nil {
		t.Fatal(err)
	}
	lines := strings.ReplaceAll(strings.Join(rec.lines, "\n"), temp, "PRIVATEDIR")
	create := ""
	for _, l := range rec.lines {
		if strings.HasPrefix(l, "docker create --name qory-"+runID+"-step ") {
			create = strings.ReplaceAll(l, temp, "PRIVATEDIR")
		}
	}
	for _, want := range []string{"--network qory-" + runID + "-in", "--runtime runsc", "--cap-drop ALL", "--security-opt no-new-privileges", "--memory 1g", "type=bind,src=/data,dst=/data,readonly", "--entrypoint /bin/sh example.com/agent:1 -c 'make test'"} {
		if !strings.Contains(create, want) {
			t.Errorf("the docker create %q has no %q", create, want)
		}
	}
	for _, not := range []string{"--rm", "--interactive", "/qory/hooks", "--user 0:0", "type=volume", "not-a-real-token"} {
		if strings.Contains(create, not) {
			t.Errorf("the docker create %q has %q", create, not)
		}
	}
	if strings.Contains(string(env), "not-a-real-token") || strings.Contains(string(env), "QORY_RUN_API") || !strings.Contains(string(env), "HTTPS_PROXY=http://qory-proxy:3128\n") {
		t.Errorf("the environment file:\n%s", env)
	}
	if n := strings.Count(lines, "rm --force --volumes qory-"+runID+"-step\n"); n != 1 {
		t.Errorf("the step container was removed %d times, want once:\n%s", n, lines)
	}
	golden(t, "step", lines+"\n\nstep environment:\n"+string(env))
}

// TestStepExit pins how docker inspect's state of the step container is read: a
// container that never started has no exit, 128+N is kept as the exit code, and
// OOMKilled is read; anything else is an error.
func TestStepExit(t *testing.T) {
	for out, want := range map[string]StepExit{
		"exited 0 false\n":   {Started: true},
		"exited 137 true\n":  {Started: true, ExitCode: 137, OOMKilled: true},
		"exited 143 false\n": {Started: true, ExitCode: 143},
		"created 0 false\n":  {},
	} {
		if got, err := stepExit(out); err != nil || got != want {
			t.Errorf("%q: %+v, %v; want %+v", out, got, err, want)
		}
	}
	for _, out := range []string{"", "exited", "exited x false"} {
		if _, err := stepExit(out); err == nil {
			t.Errorf("%q is no error", out)
		}
	}
}

// TestDockerUnwrapStepKeepsAFailedRemoval pins UnwrapStep when docker rm fails: the error
// matches ErrContainerKept, Kept lists the step container, and a later UnwrapStep that
// removes it clears the list. Without a WrapStep, UnwrapStep runs nothing.
func TestDockerUnwrapStepKeepsAFailedRemoval(t *testing.T) {
	rec := &recorder{t: t, gateway: "172.30.0.1", local_: true, uid: 1000}
	d := &Docker{Helper: "/opt/qory/qory-linux", RelayArgs: []string{"run", "relay"}, sys: rec}
	enc, err := d.Prepare(context.Background(), Request{RunID: runID, Image: "example.com/agent:1"})
	if err != nil {
		t.Fatal(err)
	}
	e := enc.(*dockerEnclosure)
	ctx := context.Background()
	before := len(rec.lines)
	if exit, err := e.UnwrapStep(ctx, time.Second); err != nil || exit != (StepExit{}) || len(rec.lines) != before {
		t.Fatalf("UnwrapStep with no step container: %+v, %v, ran %q", exit, err, rec.lines[before:])
	}
	if _, err := e.WrapStep(ctx, stepLaunch()); err != nil {
		t.Fatal(err)
	}
	rec.rms = []string{"Error response from daemon: told to fail", ""}
	exit, err := e.UnwrapStep(ctx, time.Second)
	if !errors.Is(err, ErrContainerKept) || !exit.Started {
		t.Fatalf("a failed removal: %+v, %v", exit, err)
	}
	if kept := e.Kept(); !slices.Equal(kept, []string{"qory-" + runID + "-step"}) {
		t.Errorf("kept %v", kept)
	}
	if _, err := e.UnwrapStep(ctx, time.Second); err != nil || len(e.Kept()) != 0 {
		t.Errorf("the second UnwrapStep: %v, kept %v", err, e.Kept())
	}
}
