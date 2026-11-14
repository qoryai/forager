package server_test

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"testing"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/server"
)

// TestPostModelKeys pins the model keys report: a signed POST to
// <run.url>/<run_id>/model-keys of a body model-keys-report.schema.json accepts, the
// answer's keys from a signed 200, and the error of every other answer: its status and
// whether it is signed, a DocumentError for a 200 that fails the schema, 66 entries of the
// longest names taken, and a report over 32 KiB refused before anything is sent.
func TestPostModelKeys(t *testing.T) {
	a := newApiary(t)
	c := a.client()
	ctx := context.Background()
	answer, err := fs.ReadFile(contracts.FS, "fixtures/model-keys-answer/answer.json")
	if err != nil {
		t.Fatal(err)
	}
	a.answer = func(*http.Request, []byte) (int, http.Header, string) { return 200, nil, string(answer) }
	hundred := 100
	rep := server.ModelKeysReport{Time: "2026-11-10T12:00:05Z", Keys: []server.ModelKeyState{{Credential: "model", Window: "five_hour", Status: "rejected",
		ResetsAt: "2026-11-10T14:00:00Z", Utilization: &hundred, CooldownUntil: "2026-11-10T14:00:00Z", Source: "provider", ObservedAt: "2026-11-10T12:00:04Z"}}}
	keys, err := c.PostModelKeys(ctx, a.runURL(), gatewayRunID, rep)
	if err != nil {
		t.Fatal(err)
	}
	if a.target != "/v1/runs/"+gatewayRunID+"/model-keys" {
		t.Errorf("sent to %s", a.target)
	}
	want := `{"version":1,"run_id":"` + gatewayRunID + `","time":"2026-11-10T12:00:05Z","keys":[{"credential":"model","window":"five_hour","status":"rejected",` +
		`"resets_at":"2026-11-10T14:00:00Z","utilization":100,"cooldown_until":"2026-11-10T14:00:00Z","source":"provider","observed_at":"2026-11-10T12:00:04Z"}]}`
	if string(a.body) != want {
		t.Errorf("sent %s\nwant %s", a.body, want)
	}
	validDocument(t, "model-keys-report.schema.json", a.body)
	if len(keys) == 0 || keys[0].Credential == "" || keys[0].ObservedAt == "" {
		t.Errorf("the answer's keys %+v", keys)
	}
	// The keys out of use after a 401 go in unauthorized, at most 6.
	out := server.ModelKeysReport{Time: "2026-11-10T12:00:05Z", Unauthorized: []server.UnauthorizedKey{{Credential: "subscription", At: "2026-11-10T12:00:04Z"}}}
	if _, err := c.PostModelKeys(ctx, a.runURL(), gatewayRunID, out); err != nil {
		t.Fatal(err)
	}
	if want := `{"version":1,"run_id":"` + gatewayRunID + `","time":"2026-11-10T12:00:05Z","keys":[],"unauthorized":[{"credential":"subscription","at":"2026-11-10T12:00:04Z"}]}`; string(a.body) != want {
		t.Errorf("sent %s\nwant %s", a.body, want)
	}
	validDocument(t, "model-keys-report.schema.json", a.body)
	sent := string(a.body)
	for range 6 {
		out.Unauthorized = append(out.Unauthorized, out.Unauthorized[0])
	}
	if _, err := c.PostModelKeys(ctx, a.runURL(), gatewayRunID, out); err == nil || string(a.body) != sent {
		t.Errorf("7 unauthorized keys: %v; want refused before anything is sent", err)
	}
	if _, err := c.PostModelKeys(ctx, a.runURL(), gatewayRunID, server.ModelKeysReport{}); err != nil || !strings.Contains(string(a.body), `"keys":[]`) || strings.Contains(string(a.body), "unauthorized") {
		t.Errorf("an empty report sent %s, %v", a.body, err)
	}
	validDocument(t, "model-keys-report.schema.json", a.body)

	for _, c2 := range []struct {
		status   int
		unsigned bool
	}{{http.StatusBadRequest, false}, {http.StatusGone, false}, {http.StatusNotFound, true}, {http.StatusTooManyRequests, false}, {http.StatusServiceUnavailable, true}} {
		a.unsigned = c2.unsigned
		a.answer = coded(c2.status, "invalid_request")
		_, err := c.PostModelKeys(ctx, a.runURL(), gatewayRunID, rep)
		var ae *server.ModelKeysAnswerError
		if !errors.As(err, &ae) || ae.Status != c2.status || ae.Signed == c2.unsigned {
			t.Errorf("%d (unsigned %v): %v", c2.status, c2.unsigned, err)
		}
	}
	a.unsigned = false
	a.answer = func(*http.Request, []byte) (int, http.Header, string) { return 200, nil, `{"keys":[]}` }
	if _, err := c.PostModelKeys(ctx, a.runURL(), gatewayRunID, rep); !errors.As(err, new(*server.DocumentError)) {
		t.Errorf("an answer with no version: %v; want a DocumentError", err)
	}
	// 66 entries of the longest names and every member fit the 32 KiB, and the schema
	// takes them.
	a.answer = func(*http.Request, []byte) (int, http.Header, string) { return 200, nil, string(answer) }
	full := server.ModelKeysReport{Time: "2026-11-10T12:00:05Z"}
	for range 66 {
		full.Keys = append(full.Keys, server.ModelKeyState{Credential: strings.Repeat("k", 64), Window: "seven_day_sonnet", Status: "rejected",
			ResetsAt: "2026-11-10T14:00:00Z", Utilization: &hundred, CooldownUntil: "2026-11-10T14:00:00Z", Source: "pause_for", ObservedAt: "2026-11-10T12:00:04Z"})
	}
	if _, err := c.PostModelKeys(ctx, a.runURL(), gatewayRunID, full); err != nil {
		t.Errorf("66 entries of the longest names: %v", err)
	}
	validDocument(t, "model-keys-report.schema.json", a.body)
	hits := a.hits.Load()
	big := server.ModelKeysReport{}
	for range 200 {
		big.Keys = append(big.Keys, server.ModelKeyState{Credential: strings.Repeat("k", 64), Window: strings.Repeat("w", 64), Status: "allowed", Source: "provider", ObservedAt: "2026-11-10T12:00:04Z"})
	}
	if _, err := c.PostModelKeys(ctx, a.runURL(), gatewayRunID, big); err == nil || a.hits.Load() != hits {
		t.Errorf("a report over 32 KiB: %v, sent %v", err, a.hits.Load() != hits)
	}
	if _, err := c.PostModelKeys(ctx, a.runURL(), "nope", rep); err == nil || a.hits.Load() != hits {
		t.Error("a report of a run id outside its form was accepted or sent")
	}
}

// validDocument fails t unless body passes the schema named.
func validDocument(t *testing.T, schemaName string, body []byte) {
	t.Helper()
	schema, err := contracts.Compile(schemaName)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := contracts.Decode(schemaName, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Errorf("%s fails %s: %v", body, schemaName, err)
	}
}
