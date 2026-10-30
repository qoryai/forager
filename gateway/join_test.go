package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/server"
)

// joinPath is the path of a join of the run on the local link.
func joinPath(runID string) string { return "/v1/run-configuration/" + runID + "/sessions" }

// TestJoinsAreNumberedInTheOrderTheyArrive pins the join route on the local link: the
// first join is session 1, valid under link-join-answer.schema.json, and the next one,
// after session 1 exited, is session 2; each session's dev.qory.session.started and
// dev.qory.session.exited are numbered into the run's record.
func TestJoinsAreNumberedInTheOrderTheyArrive(t *testing.T) {
	h := start(t, gateway.Config{})
	a := h.open(server.LinkRunRequest{})
	runID := a.RunID
	if d := h.post(started(runID, nil), applied(runID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	body := `{"version":1,"passes":["HOME"],"model_key":true}`
	status, got := rawPost(t, raw(t, h.g.LocalLink()), joinPath(runID), server.LinkContentType, body)
	if status != http.StatusOK {
		t.Fatalf("the first join: %d %s", status, got)
	}
	validDocument(t, "link-join-answer.schema.json", []byte(got))
	var first server.LinkJoinAnswer
	if err := json.Unmarshal([]byte(got), &first); err != nil || first.Version != 1 || first.Session != 1 || first.ModelCredential != "" {
		t.Errorf("the first join's answer %s", got)
	}
	if d := h.post(sessionStarted(runID, 1), logged(runID), sessionExited(runID, 1)); !d.Accepted() {
		t.Fatalf("session 1: %+v", d)
	}
	if n := h.joined(runID, "HOME"); n != 2 {
		t.Errorf("the second join is session %d", n)
	}
	if d := h.post(sessionStarted(runID, 2), sessionExited(runID, 2), exited(runID)); !d.Accepted() {
		t.Fatalf("session 2: %+v", d)
	}
	want := []string{event.RunStarted, event.PolicyApplied, event.SessionStarted, event.RunLog, event.SessionExited, event.SessionStarted, event.SessionExited, event.RunExited}
	if got := types(h.record(runID)); !slices.Equal(got, want) {
		t.Errorf("record %v", got)
	}
	// The run ended: a join is the 410 of its end.
	if _, err := h.join(runID); err == nil {
		t.Error("a join after the run's end was answered")
	} else if end, ok := server.Ended(err); !ok || end.Code != "run_closed" {
		t.Errorf("a join after the run's end: %v", err)
	}
}

// TestAJoinTheGatewayDoesNotAccept pins the join refusals that number no session: 400
// invalid_request for a body the schema refuses, a member it does not define among
// them, for another content type, for a model_credential of no model key of the run,
// and for a run id of no run here; the run stays open, and the next join is session 1.
func TestAJoinTheGatewayDoesNotAccept(t *testing.T) {
	h := start(t, gateway.Config{})
	a := h.open(server.LinkRunRequest{})
	c := raw(t, h.g.LocalLink())
	for name, req := range map[string]struct{ path, contentType, body string }{
		"no passes":             {joinPath(a.RunID), server.LinkContentType, `{"version":1,"model_key":true}`},
		"a member undefined":    {joinPath(a.RunID), server.LinkContentType, `{"version":1,"passes":[],"model_key":true,"wall":true}`},
		"a value in passes":     {joinPath(a.RunID), server.LinkContentType, `{"version":1,"passes":["HOME=/root"],"model_key":true}`},
		"another content type":  {joinPath(a.RunID), "text/plain", `{"version":1,"passes":[],"model_key":true}`},
		"no model key":          {joinPath(a.RunID), server.LinkContentType, `{"version":1,"passes":[],"model_key":true,"model_credential":"backup"}`},
		"a run of no run here":  {joinPath(event.NewRunID()), server.LinkContentType, `{"version":1,"passes":[],"model_key":true}`},
		"a member name twice":   {joinPath(a.RunID), server.LinkContentType, `{"version":1,"passes":[],"passes":["HOME"],"model_key":true}`},
		"a run id of no format": {"/v1/run-configuration/x/sessions", server.LinkContentType, `{"version":1,"passes":[],"model_key":true}`},
	} {
		status, got := rawPost(t, c, req.path, req.contentType, req.body)
		if r := refusalOf([]byte(got)); status != http.StatusBadRequest || r["error"] != "invalid_request" || r["from"] != "gateway" {
			t.Errorf("%s: %d %s", name, status, got)
		}
	}
	if n := h.joined(a.RunID); n != 1 {
		t.Errorf("the join after the refusals is session %d", n)
	}
}

// TestAJoinWhileAnotherJoinIsOpen pins the join while another join of the run is open,
// from that join's 200 until the gateway numbers its dev.qory.session.exited: 400
// invalid_request from the gateway, numbered not, before and after the open join's
// dev.qory.session.started; once that session exited, the next join is session 2.
func TestAJoinWhileAnotherJoinIsOpen(t *testing.T) {
	h := start(t, gateway.Config{})
	a := h.open(server.LinkRunRequest{})
	runID := a.RunID
	if d := h.post(started(runID, nil), applied(runID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	h.joined(runID)
	refused := func(when string) {
		t.Helper()
		var r *accesskey.Refusal
		if _, err := h.join(runID); !errors.As(err, &r) || r.Status != http.StatusBadRequest || r.Code != "invalid_request" || r.From != "gateway" || r.Error() != "a join while another join of the run is open" {
			t.Errorf("a join %s: %v", when, err)
		}
	}
	refused("before session 1 started")
	if d := h.post(sessionStarted(runID, 1)); !d.Accepted() {
		t.Fatalf("session 1: %+v", d)
	}
	refused("while session 1 runs")
	if d := h.post(sessionExited(runID, 1)); !d.Accepted() {
		t.Fatalf("session 1's exit: %+v", d)
	}
	if n := h.joined(runID); n != 2 {
		t.Errorf("the join after session 1 exited is session %d", n)
	}
	h.post(sessionStarted(runID, 2), sessionExited(runID, 2), exited(runID))
}

// TestAPlaceholderConflictFailsOnlyThatJoin pins a join whose passes contain a
// credential's placeholder: a 403 placeholder_conflict from the gateway, numbered, so
// the session's dev.qory.session.exited of it is taken and its
// dev.qory.session.started is not; the run stays open, and the next join is session 2
// and runs.
func TestAPlaceholderConflictFailsOnlyThatJoin(t *testing.T) {
	t.Setenv("GATEWAY_TEST_SECRET", "s3cret-value-of-the-test")
	h := start(t, gateway.Config{
		Credentials: []gateway.Credential{{Name: "api", Env: "GATEWAY_TEST_SECRET", Hosts: []string{"api.example"}, Scheme: "bearer", Placeholders: []string{"API_TOKEN"}}},
		Policy:      &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example"}}, Credentials: []gateway.PolicyCredential{{Name: "api"}}},
	})
	h.secrets = append(h.secrets, "s3cret-value-of-the-test")
	a := h.open(server.LinkRunRequest{})
	runID := a.RunID
	if d := h.post(started(runID, nil), applied(runID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	var r *accesskey.Refusal
	if _, err := h.join(runID, "HOME", "API_TOKEN"); !errors.As(err, &r) || r.Code != "placeholder_conflict" || r.Status != http.StatusForbidden || r.From != "gateway" || !slices.Equal(r.Names, []string{"API_TOKEN"}) {
		t.Fatalf("the conflicting join: %v", err)
	}
	refusedJoin := ev(runID, event.SessionExited, map[string]any{"session": 1, "state": "failed", "exit_code": -1, "reason": "placeholder_conflict", "duration_ms": 0})
	if d := h.post(refusedJoin); !d.Accepted() {
		t.Fatalf("the refused join's session.exited: %+v", d)
	}
	n := h.joined(runID, "HOME")
	if n != 2 {
		t.Errorf("the join after the refused one is session %d", n)
	}
	if d := h.post(sessionStarted(runID, 2), sessionExited(runID, 2), exited(runID)); !d.Accepted() {
		t.Fatalf("session 2: %+v", d)
	}
	want := []string{event.RunStarted, event.PolicyApplied, event.SessionExited, event.SessionStarted, event.SessionExited, event.RunExited}
	if got := types(h.record(runID)); !slices.Equal(got, want) {
		t.Errorf("record %v", got)
	}

	// The session.started of a join the gateway refused is refused.
	b := h.open(server.LinkRunRequest{})
	if d := h.post(started(b.RunID, nil), applied(b.RunID, b.Applied)); !d.Accepted() {
		t.Fatalf("the second run's first batch: %+v", d)
	}
	if _, err := h.join(b.RunID, "API_TOKEN"); !errors.As(err, &r) || r.Code != "placeholder_conflict" {
		t.Fatalf("the second run's join: %v", err)
	}
	if d := h.post(sessionStarted(b.RunID, 1)); d.Status != http.StatusBadRequest || d.End != "batch_refused" {
		t.Errorf("the session.started of a refused join: %+v", d)
	}
	if !h.reported("a session.started of no join the gateway accepted") {
		t.Error("the refusal is not reported")
	}
}

// TestTheSessionEventsFollowTheJoins pins the batch checks of the session events,
// each in a run that no other case uses: a dev.qory.session.started of a number no
// join was given, a second dev.qory.session.started of one session, one after the
// session's dev.qory.session.exited, a dev.qory.session.exited of no join, a second one
// of one session, and a dev.qory.run.exited while a join is open are refused, and the
// run ends failed, batch_refused. The internal test
// TestASessionStartedWhileAnotherJoinIsOpen pins the session.started while another
// join is open, which the join route never lets happen.
func TestTheSessionEventsFollowTheJoins(t *testing.T) {
	h := start(t, gateway.Config{})
	for _, c := range []struct {
		name  string
		joins int
		evs   func(runID string) []map[string]any
		why   string
	}{
		{"no join", 0, func(id string) []map[string]any { return []map[string]any{sessionStarted(id, 1)} }, "a session.started of no join the gateway accepted"},
		{"another number", 1, func(id string) []map[string]any { return []map[string]any{sessionStarted(id, 2)} }, "a session.started of no join the gateway accepted"},
		{"twice", 1, func(id string) []map[string]any {
			return []map[string]any{sessionStarted(id, 1), sessionStarted(id, 1)}
		}, "a second session.started of one session"},
		{"again after its exit", 1, func(id string) []map[string]any {
			return []map[string]any{sessionStarted(id, 1), sessionExited(id, 1), sessionStarted(id, 1)}
		}, "a second session.started of one session"},
		{"after its exit", 1, func(id string) []map[string]any {
			return []map[string]any{sessionExited(id, 1), sessionStarted(id, 1)}
		}, "a session.started after its session.exited"},
		{"an exit of no join", 1, func(id string) []map[string]any { return []map[string]any{sessionExited(id, 2)} }, "a session.exited of no join the gateway numbered"},
		{"two exits", 1, func(id string) []map[string]any {
			return []map[string]any{sessionStarted(id, 1), sessionExited(id, 1), sessionExited(id, 1)}
		}, "a second session.exited of one session"},
		{"a run.exited while a session runs", 1, func(id string) []map[string]any {
			return []map[string]any{sessionStarted(id, 1), exited(id)}
		}, "a run.exited while a join is open"},
		{"a run.exited before an open join's session started", 1, func(id string) []map[string]any {
			return []map[string]any{exited(id)}
		}, "a run.exited while a join is open"},
	} {
		a := h.open(server.LinkRunRequest{})
		if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
			t.Fatalf("%s: the first batch: %+v", c.name, d)
		}
		for range c.joins {
			h.joined(a.RunID)
		}
		if d := h.post(c.evs(a.RunID)...); d.Status != http.StatusBadRequest || d.End != "batch_refused" {
			t.Errorf("%s: %+v", c.name, d)
		}
		line := "run " + a.RunID + ": the gateway refused a batch from the run's session, " + c.why + "; the run ends: failed"
		if !h.reported(line) {
			t.Errorf("%s: not reported: %s", c.name, line)
		}
	}
}

// TestTheGatewaysSessionExitedComesBeforeItsRunExited pins the end of a run at the
// gateway while a join is open: the gateway writes that session's
// dev.qory.session.exited, with the state and the reason of its ending and exit_code
// -1, then the run's dev.qory.run.exited. A join the gateway answered whose session
// has no dev.qory.session.started gets no event: the record ends with the run's
// dev.qory.run.exited alone.
func TestTheGatewaysSessionExitedComesBeforeItsRunExited(t *testing.T) {
	h := start(t, gateway.Config{})
	for _, startSession := range []bool{true, false} {
		a := h.open(server.LinkRunRequest{})
		runID := a.RunID
		if d := h.post(started(runID, nil), applied(runID, a.Applied)); !d.Accepted() {
			t.Fatalf("the first batch: %+v", d)
		}
		h.joined(runID)
		if startSession {
			if d := h.post(sessionStarted(runID, 1)); !d.Accepted() {
				t.Fatalf("session 1: %+v", d)
			}
		}
		// A batch the link refuses ends the run at the gateway, batch_refused.
		if d := h.post(ev(runID, event.RunRegistered, map[string]any{})); d.End != "batch_refused" {
			t.Fatalf("the refused batch: %+v", d)
		}
		eventually(t, "the record's end", func() bool {
			rec := h.record(runID)
			return rec[len(rec)-1].Type == event.RunExited
		})
		rec := h.record(runID)
		validEvents(t, rec)
		n := len(rec)
		s, r := rec[n-2], rec[n-1]
		if !startSession {
			if want := []string{event.RunStarted, event.PolicyApplied, event.RunExited}; !slices.Equal(types(rec), want) {
				t.Errorf("a session not started: record %v", types(rec))
			}
		} else if s.Type != event.SessionExited || s.Data["session"] != 1.0 || s.Data["state"] != "failed" || s.Data["reason"] != "batch_refused" || s.Data["exit_code"] != -1.0 || s.Data["signal"] != nil {
			t.Errorf("the gateway's session.exited %s %v", s.Type, s.Data)
		}
		if r.Data["state"] != "failed" || r.Data["reason"] != "batch_refused" || r.Data["exit_code"] != -1.0 {
			t.Errorf("started %v: the gateway's run.exited %v", startSession, r.Data)
		}
	}

	// A run whose session exited ends with no session.exited of the gateway's.
	a := h.open(server.LinkRunRequest{})
	h.post(started(a.RunID, nil), applied(a.RunID, a.Applied))
	h.joined(a.RunID)
	h.post(sessionStarted(a.RunID, 1), sessionExited(a.RunID, 1))
	h.post(ev(a.RunID, event.RunRegistered, map[string]any{}))
	eventually(t, "the record's end", func() bool {
		rec := h.record(a.RunID)
		return rec[len(rec)-1].Type == event.RunExited
	})
	want := []string{event.RunStarted, event.PolicyApplied, event.SessionStarted, event.SessionExited, event.RunExited}
	if got := types(h.record(a.RunID)); !slices.Equal(got, want) {
		t.Errorf("record %v", got)
	}
}

// TestAReloadIsCheckedAgainstTheOpenJoinsPasses pins the reload's placeholder check:
// a reload that brings a credential whose placeholder an open join passes fails,
// placeholder_conflict, and the policy in force stays; once that session exited, the
// same reload is put in force.
func TestAReloadIsCheckedAgainstTheOpenJoinsPasses(t *testing.T) {
	t.Setenv("GATEWAY_TEST_SECRET", "s3cret-value-of-the-test")
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["a.example"]}}`, 'a')
	h := start(t, gateway.Config{
		Server:      c.server(),
		Credentials: []gateway.Credential{{Name: "api", Env: "GATEWAY_TEST_SECRET", Hosts: []string{"api.example"}, Scheme: "bearer", Placeholders: []string{"API_TOKEN"}}},
	})
	h.secrets = append(h.secrets, "s3cret-value-of-the-test")
	a := h.open(server.LinkRunRequest{})
	runID := a.RunID
	if d := h.post(started(runID, nil), applied(runID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	h.joined(runID, "API_TOKEN")
	if d := h.post(sessionStarted(runID, 1)); !d.Accepted() {
		t.Fatalf("session 1: %+v", d)
	}
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]},"credentials":[{"name":"api"}]}`, 'b')
	eventually(t, "the failed reload's report", func() bool {
		h.post(heartbeat(runID))
		return h.reported("placeholder_conflict")
	})
	reload := func() *server.LinkReloadAnswer {
		r, err := h.linkOf(runID).Reload(context.Background(), server.LocalOrigin+"/v1/run-configuration", runID)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := reload(); r.Digest != a.Digest || slices.Contains(r.Placeholders, "API_TOKEN") {
		t.Errorf("the reload in force with session 1 open: %s %v", r.Policy, r.Placeholders)
	}
	if d := h.post(sessionExited(runID, 1)); !d.Accepted() {
		t.Fatalf("session 1's exit: %+v", d)
	}
	// Another document: the server's answers carry the digest of its bytes, and the
	// document refused before is not fetched again.
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.example","c.example"]},"credentials":[{"name":"api"}]}`, 'c')
	eventually(t, "the reload once session 1 exited", func() bool {
		h.post(heartbeat(runID))
		return slices.Contains(reload().Placeholders, "API_TOKEN")
	})
	// A join that passes the placeholder of the policy in force is refused.
	var r *accesskey.Refusal
	if _, err := h.join(runID, "API_TOKEN"); !errors.As(err, &r) || r.Code != "placeholder_conflict" {
		t.Errorf("a join after the reload: %v", err)
	}
	h.post(exited(runID))
}

// TestAResendEndsTheOpenSessionGatewayLost pins the resend of the record of a run whose
// gateway stopped while session 1 ran: the record gets that session's
// dev.qory.session.exited, failed, exit_code -1 and gateway_lost, then the run's
// dev.qory.run.exited, and every event validates against its schema.
func TestAResendEndsTheOpenSessionGatewayLost(t *testing.T) {
	c := newControl(t)
	cfg := gateway.Config{Server: c.server()}
	gateway.SetCloseWait(&cfg, 300*time.Millisecond)
	h := start(t, cfg)
	a := h.open(server.LinkRunRequest{})
	h.post(started(a.RunID, nil), applied(a.RunID, a.Applied))
	h.joined(a.RunID)
	if d := h.post(sessionStarted(a.RunID, 1), logged(a.RunID)); !d.Accepted() {
		t.Fatalf("session 1: %+v", d)
	}
	if _, err := h.g.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	r, err := gateway.Resend(context.Background(), gateway.ResendConfig{Server: c.server(), Dir: filepath.Join(h.dir, "runs", a.RunID)})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Completed || r.State != "failed" || r.Reason != "gateway_lost" {
		t.Errorf("resend %+v", r)
	}
	rec := h.record(a.RunID)
	validEvents(t, rec)
	n := len(rec)
	if n < 2 {
		t.Fatalf("record %v", types(rec))
	}
	s, e := rec[n-2], rec[n-1]
	if s.Type != event.SessionExited || s.Data["session"] != 1.0 || s.Data["state"] != "failed" || s.Data["exit_code"] != -1.0 || s.Data["reason"] != "gateway_lost" {
		t.Errorf("the open session ends %s %v", s.Type, s.Data)
	}
	if e.Type != event.RunExited || e.Data["state"] != "failed" || e.Data["exit_code"] != -1.0 || e.Data["reason"] != "gateway_lost" {
		t.Errorf("the run ends %s %v", e.Type, e.Data)
	}
}
