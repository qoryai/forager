package session_test

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
)

// The tests of this file pin dev.qory.run.built, the result of a build of an image
// that the run's caller writes with Run.Built.

// aBuild is a build's result of the forms dev.qory.run.built accepts.
func aBuild() session.Built {
	return session.Built{
		Image:          "registry.example/example-org/env@sha256:" + strings.Repeat("3f", 32),
		Size:           734003200,
		Commit:         strings.Repeat("9b2e4c1d", 5),
		EnvironmentRef: "env-example-01",
	}
}

// buildStep writes a host step of kind build that succeeds, then the build's result.
func buildStep(t *testing.T, r *session.Run) {
	t.Helper()
	hostStep(t, r, event.StepBuild, "build the environment image", "qory run: built the image\n")
	if err := r.Built(aBuild()); err != nil {
		t.Fatal(err)
	}
}

// builtIn is the one dev.qory.run.built of evs, with the members aBuild gives; the
// test fails on any other count or value.
func builtIn(t *testing.T, where string, evs []map[string]any) {
	t.Helper()
	got := ofType(evs, event.RunBuilt)
	if len(got) != 1 {
		t.Fatalf("%s has %d run.built, want 1: %v", where, len(got), types(evs))
	}
	b, d := aBuild(), data(got[0])
	if d["image"] != b.Image || d["size"] != float64(b.Size) || d["commit"] != b.Commit || d["environment_ref"] != b.EnvironmentRef || len(d) != 4 {
		t.Errorf("%s: run.built %v", where, d)
	}
}

// TestBuiltPassesThroughARealGateway pins a run on one machine that writes a build
// step and its result before a join: the gateway accepts the batch, numbers the
// run.built between the step's step_exited and the join's step, and its record and the
// session's agree; a second Built returns an error that starts with the fix and writes
// nothing.
func TestBuiltPassesThroughARealGateway(t *testing.T) {
	sp := spec(t, "FAKE_EXIT=0")
	rg := startGateway(t, &sp, gateway.Config{Version: "test", Heartbeat: time.Second,
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example"}}}})
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	buildStep(t, r)
	if err := r.Built(aBuild()); err == nil || !strings.HasPrefix(err.Error(), "write the build's result once per run") {
		t.Errorf("a second Built: %v", err)
	}
	if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
		t.Fatal(err)
	}
	closed, err := r.Close(ctx, session.Outcome{State: "succeeded"})
	if err != nil {
		t.Fatal(err)
	}
	if d := rg.close(t); d != (gateway.Delivery{}) || closed.Undelivered != 0 || closed.RunClosed {
		t.Errorf("delivery %+v, closed %+v", d, closed)
	}
	res := &session.Result{Dir: r.Dir()}
	own, numbered := events(t, res), record(t, res)
	builtIn(t, "the session's record", own)
	builtIn(t, "the gateway's record", numbered)
	want := []string{event.StepStarted, event.StepExited, event.RunBuilt, event.StepStarted}
	if got := ofTypes(numbered, []string{event.StepStarted, event.StepExited, event.RunBuilt}); len(got) < 4 || !slices.Equal(got[:4], want) {
		t.Errorf("the gateway numbered %v, want %v first", got, want)
	}
	if !slices.Equal(types(own), ofTypes(numbered, types(own))) {
		t.Errorf("the session recorded %v, the gateway numbered %v", types(own), types(numbered))
	}
}

// TestBuiltPassesThroughARealSeparateGateway pins a run behind a separate gateway that
// writes a build step and its result and closes with no session: the gateway accepts
// the batch and numbers the run.built, the server receives it before run.exited, and
// the session's record has it too.
func TestBuiltPassesThroughARealSeparateGateway(t *testing.T) {
	a := newApiary(t)
	certFile, keyFile, caFile := separateCertificate(t)
	records := t.TempDir()
	g, err := gateway.Start(context.Background(), gateway.Config{
		RunDir: func(id string) string { return filepath.Join(records, id) }, Listen: "127.0.0.1:0", Heartbeat: time.Second, Version: "test",
		TLS:    &gateway.TLS{CertFile: certFile, KeyFile: keyFile},
		Server: &gateway.Server{Version: 1, URL: a.srv.URL, AccessKeyID: "ak_f1xt0re00000000g", ApiaryPublicKey: a.pin, AccessKey: a.key, InstanceID: "i_test"},
		Report: func(l string) { t.Log("the gateway reported:", l) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		g.Close(ctx)
	})
	sp := spec(t)
	sp.RunID = event.NewRunID()
	sp.Gateway = session.RemoteGateway{RunKey: a.runKey(t, sp.RunID, "https://"+g.Addr(), a.key), TLS: server.RemoteTLS{CAFile: caFile}}
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	buildStep(t, r)
	closed, err := r.Close(ctx, session.Outcome{State: "failed", ExitCode: -1})
	if err != nil {
		t.Fatal(err)
	}
	if closed.Undelivered != 0 || closed.RunClosed {
		t.Errorf("closed %+v", closed)
	}
	waitFor(t, func() bool {
		got := a.receivedTypes()
		return len(got) > 0 && got[len(got)-1] == event.RunExited
	})
	if got := a.receivedTypes(); !slices.Contains(got, event.RunBuilt) {
		t.Errorf("the server received %v", got)
	}
	a.mu.Lock()
	builtIn(t, "the server's events", a.received)
	a.mu.Unlock()
	builtIn(t, "the gateway's record", record(t, &session.Result{Dir: filepath.Join(records, sp.RunID)}))
	builtIn(t, "the session's record", events(t, &session.Result{Dir: r.Dir()}))
}

// TestBuiltRefusesAndWritesNothing pins what Built refuses, each with an error that
// starts with the fix and with nothing written: an image with a tag, a size of 0, a
// commit in upper case or of 39 characters, an empty environment reference, a call
// while a host step is open, during a join and after the close. A Built after the
// join is the run's one run.built.
func TestBuiltRefusesAndWritesNothing(t *testing.T) {
	sp := spec(t, "FAKE_EXIT=0")
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	refused := func(what string, err error, fix string) {
		t.Helper()
		if err == nil || !strings.HasPrefix(err.Error(), fix) {
			t.Errorf("%s: %v, want an error that starts %q", what, err, fix)
		}
	}
	with := func(change func(*session.Built)) session.Built {
		b := aBuild()
		change(&b)
		return b
	}
	refused("an image with a tag", r.Built(with(func(b *session.Built) { b.Image = "registry.example/example-org/env:latest" })),
		"set the built image to NAME@sha256: and 64 lower-case hexadecimal digits")
	refused("a size of 0", r.Built(with(func(b *session.Built) { b.Size = 0 })), "set the built image's size to its bytes, 1 or more, not 0")
	refused("a commit in upper case", r.Built(with(func(b *session.Built) { b.Commit = strings.ToUpper(b.Commit) })),
		"set the commit of the build to a full commit id")
	refused("a commit of 39 characters", r.Built(with(func(b *session.Built) { b.Commit = b.Commit[:39] })),
		"set the commit of the build to a full commit id")
	refused("an empty environment reference", r.Built(with(func(b *session.Built) { b.EnvironmentRef = "" })),
		"set the build's environment reference")
	s, err := r.StartStep(event.StepBuild, "build the environment image")
	if err != nil {
		t.Fatal(err)
	}
	refused("a Built during the build step", r.Built(aBuild()), "exit step 1 before the build's result")
	if err := s.Exit(event.StateSucceeded, 0); err != nil {
		t.Fatal(err)
	}
	during := make(chan error, 1)
	j := sp.SessionSpec
	j.OnVariables = func(session.Applied) { during <- r.Built(aBuild()) }
	if _, err := r.Join(ctx, j); err != nil {
		t.Fatal(err)
	}
	refused("a Built during a join", <-during, "write the build's result after Join returns")
	if err := r.Built(aBuild()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, session.Outcome{State: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	refused("a Built after the close", r.Built(aBuild()), "open a new run for the build's result")
	evs := events(t, &session.Result{Dir: r.Dir()})
	builtIn(t, "the record", evs)
	want := []string{event.StepStarted, event.StepExited, event.StepStarted, event.StepExited, event.SessionStarted, event.SessionExited, event.RunBuilt, event.RunExited}
	if got := ofTypes(evs, []string{event.StepStarted, event.StepExited, event.SessionStarted, event.SessionExited, event.RunBuilt, event.RunExited}); !slices.Equal(got, want) {
		t.Errorf("the record:\n%q\nwant\n%q", got, want)
	}
}
