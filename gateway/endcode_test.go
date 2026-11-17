package gateway_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/server"
)

// TestAPushRefusedOutcomeReachesTheReceiver runs the end code push_refused, one of the
// codes of $defs end_codes of integrations' contracts/run/v1/outcome.schema.json, from
// the run's starter to the receiver's record of the run, behind a separate gateway and
// against the reference receiver, without Docker. It pins the code unchanged at the
// control plane, and does not reach closeRule: the starter's outcome ends the run, and
// the gateway writes the run's dev.qory.run.exited. A node pool registers the run and
// the gateway attaches it; a session joins and exits, and the run's push step exits
// failed with exit code 1, the order of qory's run; the pool posts the outcome failed
// with push_refused through the gateway's relay, with Via set. The receiver keeps the
// outcome and sends it as the end member, the gateway ends the run with it, and the
// session's next batch is a 410 stopped, failed with push_refused. The run's
// dev.qory.run.exited, in the gateway's record and in the receiver's store, is failed
// with push_refused and the exit code -1.
func TestAPushRefusedOutcomeReachesTheReceiver(t *testing.T) {
	ref := newReference(t, "localhost")
	node := &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost"}}}
	r := startRemote(t, nil, gateway.Config{Server: ref.server(refGatewayKey), Policy: node})
	runID := event.NewRunID()
	e := r.open(t, ref.registerThroughGateway(t, runID), server.LinkRunRequest{})
	j := r.do(t, e.key, http.MethodPost, "/qory-link/run-configuration/"+runID+"/sessions", []byte(`{"version":1,"passes":[],"model_key":false}`))
	var joined server.LinkJoinAnswer
	if json.Unmarshal(j.body, &joined); j.status != http.StatusOK || joined.Session != 1 {
		t.Fatalf("the join: %d %s", j.status, j.body)
	}
	if got := e.post(t, sessionStarted(runID, 1), sessionExited(runID, 1)); got.status != http.StatusAccepted {
		t.Fatalf("the session's batch: %d %s", got.status, got.body)
	}
	if got := e.post(t,
		ev(runID, event.StepStarted, map[string]any{"step": 1, "name": "push work to git.example/example-org/app", "kind": event.StepPush}),
		ev(runID, event.StepExited, map[string]any{"step": 1, "state": event.StateFailed, "exit_code": 1, "duration_ms": 5}),
	); got.status != http.StatusAccepted {
		t.Fatalf("the push step's batch: %d %s", got.status, got.body)
	}

	starter := &server.Client{Config: &server.Config{Version: 1, URL: ref.srv.URL, AccessKeyID: refPoolKey, ApiaryPublicKey: testPin,
		Via: &server.Via{URL: "https://" + r.g.Addr(), CAFile: r.cfg.TLS.CertFile}}, Key: refPoolSecret, InstanceID: "i_pool", UserAgent: "qory-forager/test"}
	if err := starter.PostOutcome(context.Background(), ref.srv.URL+receiver.DefaultRunPath, runID, server.Outcome{State: event.StateFailed, Reason: "push_refused"}); err != nil {
		t.Fatalf("the outcome through the relay: %v", err)
	}

	var last answer
	eventually(t, "the 410", func() bool {
		last = e.post(t, heartbeat(runID))
		return last.status == http.StatusGone
	})
	if got := last.refusal(); got["error"] != "stopped" || got["state"] != event.StateFailed || got["reason"] != "push_refused" {
		t.Errorf("the 410 %s; want stopped, failed with push_refused", last.body)
	}
	validDocument(t, "link-refusal.schema.json", last.body)

	// exitedIn is the data of the run's one dev.qory.run.exited in rec, nil without one.
	exitedIn := func(rec []recorded) map[string]any {
		var data map[string]any
		n := 0
		for _, l := range rec {
			if l.Type == event.RunExited && l.Subject == runID {
				data = l.Data
				n++
			}
		}
		if n > 1 {
			t.Errorf("%d run.exited of the run", n)
		}
		return data
	}
	want := func(where string, x map[string]any) {
		t.Helper()
		if x["state"] != event.StateFailed || x["reason"] != "push_refused" || x["exit_code"] != float64(-1) {
			t.Errorf("%s: run.exited %v; want failed with push_refused and -1", where, x)
		}
	}
	rec := r.record(runID)
	validEvents(t, rec)
	want("the gateway's record", exitedIn(rec))
	eventually(t, "the run.exited at the receiver", func() bool {
		return exitedIn(readLines(t, ref.stored)) != nil
	})
	want("the receiver's store", exitedIn(readLines(t, ref.stored)))
}

// TestAStartersEndCodeInTheCloseReachesTheControl pins a session's dev.qory.run.exited
// with a starter's reason: each of the end codes qory closes a run with, $defs end_codes
// of integrations' contracts/run/v1/outcome.schema.json, and push_window_closed, a code
// of the pattern outside that list, failed after a session. The run's push step exits
// failed with exit code 1 before each push code, and the close is failed with exit code
// 1, as qory's push step closes a run. prebuilt_image_too_large and
// environment_image_missing come from inside the prebuild's step session, with no push
// step, and the close is failed with exit code -1. push_credential_missing closes a run
// with no join too, failed with exit code -1, as qory closes a run that fails before
// any session. The link accepts the batch, and the run's dev.qory.run.exited, in the
// gateway's record and at the control, is failed with the code and the exit code
// unchanged.
func TestAStartersEndCodeInTheCloseReachesTheControl(t *testing.T) {
	ctl := newControl(t)
	h := start(t, gateway.Config{Server: ctl.server()})
	for _, c := range []struct {
		code string
		exit int
		push bool // a push step that exits failed with exit code 1 before the close
		join bool // a session that joins and exits before the close
	}{
		{"push_credential_missing", 1, true, true},
		{"push_refused", 1, true, true},
		{"prebuilt_image_too_large", -1, false, true},
		{"push_not_recorded", 1, true, true},
		{"environment_image_missing", -1, false, true},
		{"push_head_changed", 1, true, true},
		{"push_window_closed", 1, true, true},
		{"push_credential_missing", -1, false, false},
	} {
		code, name := c.code, c.code
		a := h.open(server.LinkRunRequest{})
		runID := a.RunID
		if d := h.post(started(runID, nil), applied(runID, a.Applied)); !d.Accepted() {
			t.Fatalf("%s: the first batch: %+v", name, d)
		}
		if c.join {
			n := h.joined(runID)
			if d := h.post(sessionStarted(runID, n), sessionExited(runID, n)); !d.Accepted() {
				t.Fatalf("%s: the session's batch: %+v", name, d)
			}
		} else {
			name += " with no join"
		}
		var evs []map[string]any
		if c.push {
			evs = append(evs,
				ev(runID, event.StepStarted, map[string]any{"step": 1, "name": "push work to git.example/example-org/app", "kind": event.StepPush}),
				ev(runID, event.StepExited, map[string]any{"step": 1, "state": event.StateFailed, "exit_code": 1, "duration_ms": 5}),
			)
		}
		evs = append(evs, exitedWith(runID, map[string]any{"state": event.StateFailed, "exit_code": c.exit, "reason": code}))
		if d := h.post(evs...); !d.Accepted() {
			t.Errorf("%s: the close's batch: %+v", name, d)
			continue
		}
		check := func(where string, rec []recorded) {
			t.Helper()
			var exits []map[string]any
			for _, l := range rec {
				if l.Type == event.RunExited && l.Subject == runID {
					exits = append(exits, l.Data)
				}
			}
			if len(exits) != 1 || exits[0]["state"] != event.StateFailed || exits[0]["reason"] != code || exits[0]["exit_code"] != float64(c.exit) {
				t.Errorf("%s: %s: run.exited %v; want one, failed with %s and %d", name, where, exits, code, c.exit)
			}
		}
		rec := h.record(runID)
		validEvents(t, rec)
		check("the gateway's record", rec)
		eventually(t, name+": the run.exited at the control", func() bool {
			for _, l := range ctl.lines(t) {
				if l.Type == event.RunExited && l.Subject == runID {
					return true
				}
			}
			return false
		})
		check("the control", ctl.lines(t))
	}
}
