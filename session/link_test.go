package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
)

// sleeps makes the spec's runtime a program that waits the given time, long enough
// for what a test does to a live run.
func sleeps(sp *session.Spec, d time.Duration) {
	sp.Forwarder = nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", fmt.Sprintf("sleep %.3f", d.Seconds())}
}

// posted are the types of the events the gateway received.
func posted(g *linktest.Fake) []string { return types(g.Events()) }

// TestARunWithoutAGatewayIsNone pins that a session speaks to a gateway alone: a spec
// without one is no run, before anything is made, and a link whose socket is gone is
// an error before a run directory is made.
func TestARunWithoutAGatewayIsNone(t *testing.T) {
	sp := spec(t)
	sp.Gateway = session.Gateway{}
	if _, err := session.Run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), "no gateway") {
		t.Errorf("a run without a gateway: %v", err)
	}
	sp = spec(t)
	sp.Gateway = session.LocalGateway(link.Local{Socket: filepath.Join(t.TempDir(), "sock"), Secret: "a-link-secret-of-the-test"})
	if _, err := session.Run(context.Background(), sp); err == nil {
		t.Error("a run whose gateway is gone started")
	}
	if entries, _ := os.ReadDir(sp.RunsDir); len(entries) > 0 {
		t.Errorf("a run directory was made: %v", entries)
	}
}

// TestTheGatewayPrintsNoSecret pins that a Gateway is printed by its socket alone.
func TestTheGatewayPrintsNoSecret(t *testing.T) {
	g := session.LocalGateway(link.Local{Socket: "/tmp/qory-link-x/sock", Secret: "the-link-secret-of-the-test"})
	for _, s := range []string{g.String(), g.GoString()} {
		if strings.Contains(s, "the-link-secret") || !strings.Contains(s, "/tmp/qory-link-x/sock") {
			t.Errorf("printed as %q", s)
		}
	}
}

// TestTheRunRequestSaysWhatTheGatewayDecidesBy pins the run request: the session's run
// id, no wall, the labels, what the run is about, and the names of the variables the
// run passes a value for, from what it inherits, what the harness sets and its
// variables, sorted, never a value, and none outside a variable name's grammar.
func TestTheRunRequestSaysWhatTheGatewayDecidesBy(t *testing.T) {
	const value = "a-value-no-request-carries"
	sp, g := specGateway(t, "INHERITED="+value, "not a name="+value, "1BAD="+value)
	sleeps(&sp, 0)
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	sp.Labels = map[string]string{"repository": "example-namespace/project"}
	sp.About = &session.About{Title: "Example title"}
	sp.LaunchFixed = []string{"FIXED_ONE=" + value}
	sp.LaunchDefaults = []string{"DEFAULT_ONE=" + value}
	sp.Variables = session.Variables{Run: []string{"RUN_ONE=" + value}, Machine: []string{"MACHINE_ONE=" + value}}
	if _, err := session.Run(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	reqs := g.Requests()
	if len(reqs) != 1 {
		t.Fatalf("%d run requests", len(reqs))
	}
	req := reqs[0]
	want := []string{"DEFAULT_ONE", "FAKE_RUNTIME", "FIXED_ONE", "INHERITED", "MACHINE_ONE", "PATH", "RUN_ONE"}
	if req.RunID != sp.RunID || req.Wall || req.Labels["repository"] != "example-namespace/project" || req.About == nil || req.About.Title != "Example title" || !slices.Equal(req.Passes, want) || req.Images != nil || req.Narrowing != nil {
		t.Errorf("the run request %+v, passes want %q", req, want)
	}
	if raw := string(g.RawRequests()[0]); strings.Contains(raw, value) {
		t.Errorf("the run request carries a value: %s", raw)
	}
}

// TestTheGatewaysRefusalsAreTheRuns pins what a refused run request comes to: a coded
// refusal is a session.Refusal with its code, names and who refused, recorded as
// run.refused in the session's record alone, the server's with its status; the
// gateway's wall_required is the error a run without a wall always had, word for
// word, recorded nowhere; a 410 is the run closed before it started; and a 500 is the
// failure the gateway's message says, word for word, or one naming its status without
// one, recorded nowhere. Nothing is posted for any of them.
func TestTheGatewaysRefusalsAreTheRuns(t *testing.T) {
	for name, c := range map[string]struct {
		reply   linktest.Reply
		code    string
		from    string
		names   []string
		text    string
		refused map[string]any
	}{
		"placeholder_conflict": {linktest.Reply{Status: 403, Body: linktest.Refusal("placeholder_conflict", "gateway", "MODEL_TOKEN")},
			"placeholder_conflict", accesskey.FromGateway, []string{"MODEL_TOKEN"}, "placeholder_conflict (status 403): MODEL_TOKEN",
			map[string]any{"code": "placeholder_conflict", "names": []any{"MODEL_TOKEN"}}},
		"run_id_used": {linktest.Reply{Status: 409, Body: linktest.Refusal("run_id_used", "gateway")},
			"run_id_used", accesskey.FromGateway, nil, "run_id_used (status 409)", map[string]any{"code": "run_id_used"}},
		"the server's instance_limit": {linktest.Reply{Status: 409, Body: linktest.Refusal("instance_limit", "apiary")},
			"instance_limit", accesskey.FromApiary, nil, "instance_limit (status 409)", map[string]any{"code": "instance_limit", "status": 409.0}},
		"wall_required for credentials": {linktest.Reply{Status: 403, Body: linktest.Refusal("wall_required", "gateway", "credentials", "paths")},
			"", "", nil, "the policy selects credentials or tools or has path rules, which need a wall: without one a program that ignores the proxy is bound by none of them", nil},
		"wall_required for an image": {linktest.Reply{Status: 403, Body: linktest.Refusal("wall_required", "gateway", "image=with-docker")},
			"", "", nil, `the policy selects the image "with-docker", which needs a wall: without one the runtime is this machine's process`, nil},
		"the server's close": {linktest.Reply{Status: 410, Body: linktest.Refusal("run_closed", "apiary")},
			"run_closed", accesskey.FromApiary, nil, "the server closed the run before it started: run_closed (status 410)",
			map[string]any{"code": "run_closed", "status": 410.0}},
		"a 500 with a message": {linktest.Reply{Status: 500, Body: map[string]any{"message": "credential git: the adapter exited with status 1"}},
			"", "", nil, "credential git: the adapter exited with status 1", nil},
		"a bare 500": {linktest.Reply{Status: 500}, "", "", nil, "the gateway answered the run request with status 500", nil},
	} {
		t.Run(name, func(t *testing.T) {
			sp, g := specGateway(t)
			sleeps(&sp, 0)
			sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
			sp.OnVariables = func(session.Applied) { t.Error("OnVariables was called for a refused run") }
			g.OnRun(func(server.LinkRunRequest) linktest.Reply { return c.reply })
			_, err := session.Run(context.Background(), sp)
			if err == nil || !strings.Contains(err.Error(), c.text) {
				t.Fatalf("%v, want %q", err, c.text)
			}
			var r *session.Refusal
			if c.code != "" && (!errors.As(err, &r) || r.Code != c.code || r.From != c.from || !slices.Equal(r.Names, c.names)) {
				t.Errorf("%#v, want %s from %s %q", r, c.code, c.from, c.names)
			}
			if c.code == "" && errors.As(err, &r) {
				t.Errorf("a refusal %v, want an error that is none", r)
			}
			if c.code == "" && err.Error() != c.text {
				t.Errorf("%q, want exactly %q", err, c.text)
			}
			evs := events(t, &session.Result{Dir: filepath.Join(sp.RunsDir, sp.RunID)})
			got := ofType(evs, "dev.qory.run.refused")
			switch {
			case c.refused == nil && len(got) != 0:
				t.Errorf("run.refused %v, want none", got)
			case c.refused != nil && (len(got) != 1 || !equalJSON(data(got[0]), c.refused)):
				t.Errorf("run.refused %v, want %v", got, c.refused)
			}
			if len(g.Batches()) != 0 {
				t.Errorf("the gateway received batches: %v", posted(g))
			}
		})
	}
}

// equalJSON compares two decoded JSON values by their printing.
func equalJSON(a, b map[string]any) bool {
	return must(jsonString(a)) == must(jsonString(b))
}

// TestRunStartedHasTheGatewaysLabelsAndDetails pins run.started of a run whose labels
// the gateway holds otherwise than the session sent them, and whose details the
// gateway decides: the record has exactly the gateway's labels, and each detail the
// gateway decides with its value beside the run's own.
func TestRunStartedHasTheGatewaysLabelsAndDetails(t *testing.T) {
	sp, g := specGateway(t)
	sleeps(&sp, 0)
	sp.Labels = map[string]string{"repository": "example-namespace/project"}
	sp.About = &session.About{Title: "Example", Details: []byte(`{"requester":"someone","note":"kept"}`)}
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["labels"] = map[string]string{"repository": "example-namespace/project", "run_key": "rk-0001"}
		a["details"] = map[string]string{"requester": "requester"}
		return linktest.Reply{Status: 200, Body: a}
	})
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	started := data(ofType(events(t, res), "dev.qory.run.started")[0])
	labels, _ := started["labels"].(map[string]any)
	about, _ := started["about"].(map[string]any)
	details, _ := about["details"].(map[string]any)
	if len(labels) != 2 || labels["run_key"] != "rk-0001" || details["requester"] != "requester" || details["note"] != "kept" || about["title"] != "Example" {
		t.Errorf("run.started %v", started)
	}
}

// TestHeartbeatsRunEveryIntervalTheDiscoveryAnnounces pins the heartbeats: every
// interval of the link's discovery, recorded and posted, with that interval.
func TestHeartbeatsRunEveryIntervalTheDiscoveryAnnounces(t *testing.T) {
	sp, g := specGateway(t)
	g.SetInterval(1)
	sleeps(&sp, 2500*time.Millisecond)
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	beats := ofType(events(t, res), "dev.qory.run.heartbeat")
	if len(beats) < 2 || data(beats[0])["interval_seconds"] != 1.0 {
		t.Errorf("heartbeats %v", beats)
	}
	if n := len(ofType(g.Events(), "dev.qory.run.heartbeat")); n != len(beats) {
		t.Errorf("the gateway received %d heartbeats, the record holds %d", n, len(beats))
	}
}

// TestADigestThatChangesIsReloaded pins the reload: the run answer's digest is the one
// the run holds and its first batch carries; a batch answer with another makes the
// session fetch the run's configuration again, once, record it in a policy_applied of
// the members the reload answer gives beside its own, and carry the new digest from
// then on.
func TestADigestThatChangesIsReloaded(t *testing.T) {
	first, second := "sha256="+strings.Repeat("1", 64), "sha256="+strings.Repeat("2", 64)
	sp, g := specGateway(t)
	sleeps(&sp, 2*time.Second)
	sp.Declared = []string{"registry.example"}
	g.SetRunDigest(first)
	g.OnBatch(func([]map[string]any) linktest.Reply {
		g.SetRunDigest(second)
		return linktest.Reply{Status: 200}
	})
	reloaded := map[string]any{"mode": "enforce", "allow": []any{"api.example"}, "deny": []any{}, "source": "fetched", "digest": strings.Repeat("e", 64),
		"url": "https://apiary.example/v1/run-configuration", "run_configuration": second}
	g.OnReload(func(string) linktest.Reply {
		return linktest.Reply{Status: 200, Body: map[string]any{"version": 1,
			"policy": map[string]any{"version": 1, "egress": map[string]any{"mode": "enforce", "allow": []string{"api.example"}}},
			"digest": strings.Repeat("e", 64), "applied": reloaded}}
	})
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if got := g.Reloads(); !slices.Equal(got, []string{res.RunID}) {
		t.Errorf("reloads %q, want the run's once", got)
	}
	pa := ofType(events(t, res), "dev.qory.run.policy_applied")
	if len(pa) != 2 {
		t.Fatalf("policy_applied %v", pa)
	}
	then := data(pa[1])
	for k, v := range reloaded {
		if !equalJSON(map[string]any{k: then[k]}, map[string]any{k: v}) {
			t.Errorf("the second policy_applied %s = %v, want %v", k, then[k], v)
		}
	}
	if then["harness_hosts"] == nil || then["variables"] == nil || len(then) != len(reloaded)+2 {
		t.Errorf("the second policy_applied %v", then)
	}
	digests := g.BatchDigests()
	if len(digests) < 2 || digests[0] != first || digests[len(digests)-1] != second {
		t.Errorf("the batches carried %q", digests)
	}
}

// TestTheRunEndsWhenItIsClosed pins the end of a run from outside: a 410 to a batch
// from the server or from the gateway, a 410 to a reload, and the gateway's 400 to a
// batch, which ends the run there. The runtime is stopped as at its time limit, the
// result says who closed it and with what, run.exited with that code as its reason is
// in the session's record alone, and nothing more is posted.
func TestTheRunEndsWhenItIsClosed(t *testing.T) {
	for name, c := range map[string]struct {
		batch, reload *linktest.Reply
		code, from    string
	}{
		"the server's 410": {batch: &linktest.Reply{Status: 410, Body: linktest.Refusal("run_closed", "apiary")}, code: "run_closed", from: "apiary"},
		"the gateway's 410": {batch: &linktest.Reply{Status: 410, Body: linktest.Refusal("credential_expired", "gateway")},
			code: "credential_expired", from: "gateway"},
		"a 410 to a reload": {reload: &linktest.Reply{Status: 410, Body: linktest.Refusal("run_ended_at_issuer", "gateway")},
			code: "run_ended_at_issuer", from: "gateway"},
		"the gateway's 400": {batch: &linktest.Reply{Status: 400, Body: linktest.Refusal("invalid_request", "gateway")}, code: "run_closed", from: "gateway"},
	} {
		t.Run(name, func(t *testing.T) {
			sp, g := specGateway(t)
			sleeps(&sp, 30*time.Second)
			sp.StopGrace = time.Second
			if c.batch != nil {
				g.OnBatch(func([]map[string]any) linktest.Reply { return *c.batch })
			}
			if c.reload != nil {
				g.SetRunDigest("sha256=" + strings.Repeat("1", 64))
				g.OnBatch(func([]map[string]any) linktest.Reply {
					g.SetRunDigest("sha256=" + strings.Repeat("2", 64))
					return linktest.Reply{Status: 200}
				})
				g.OnReload(func(string) linktest.Reply { return *c.reload })
			}
			start := time.Now()
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if time.Since(start) > 15*time.Second {
				t.Errorf("the run took %s", time.Since(start))
			}
			if !res.RunClosed || res.ClosedBy != c.from || res.ClosedReason != c.code || res.State != "failed" || res.TimedOut {
				t.Errorf("result %+v", res)
			}
			evs := events(t, res)
			exited := ofType(evs, "dev.qory.run.exited")
			if len(exited) != 1 || data(exited[0])["reason"] != c.code || evs[len(evs)-1]["type"] != "dev.qory.run.exited" {
				t.Errorf("run.exited %v", exited)
			}
			if slices.Contains(posted(g), "dev.qory.run.exited") {
				t.Errorf("run.exited was posted: %v", posted(g))
			}
		})
	}
}

// TestAFailureAfterTheAnswerIsPosted pins a run the session refuses after the
// gateway's run answer, with a code the session decides: its run.refused is in the
// record and posted on the link, which ends the run at the gateway, and nothing
// started.
func TestAFailureAfterTheAnswerIsPosted(t *testing.T) {
	sp, g := specGateway(t)
	sleeps(&sp, 0)
	sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
	sp.Variables.Run = []string{"QORY_X=a-value"}
	_, err := session.Run(context.Background(), sp)
	var r *session.Refusal
	if !errors.As(err, &r) || r.Code != "variable_reserved" || r.From != "" {
		t.Fatalf("%v, want variable_reserved of the session's own", err)
	}
	if got := posted(g); !slices.Equal(got, []string{"dev.qory.run.refused"}) {
		t.Errorf("posted %v", got)
	}
	if ev := g.Events(); len(ev) == 1 && !equalJSON(data(ev[0]), map[string]any{"code": "variable_reserved", "names": []any{"QORY_X"}}) {
		t.Errorf("posted %v", ev[0])
	}
}

// jsonString is v as JSON.
func jsonString(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
