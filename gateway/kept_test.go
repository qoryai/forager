package gateway_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// keptNames are the files a separate gateway writes in a run's record directory to
// reopen the run.
var keptNames = []string{"request.json", "ca.pem", "ca.key", "given.jsonl", "joins.jsonl", "model-key-limit"}

// caConfig is a gateway configuration whose runs have the model key first, from the
// node's credentials, on an endpoint at localhost, so each run's proxy ends TLS with
// the run's CA; c serves the run configuration that lists it.
func caConfig(t *testing.T, c *control) gateway.Config {
	t.Setenv("GATEWAY_TEST_FIRST_KEY", "fake-first-value-0001")
	c.serveDocument(`{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["localhost"]},"credentials":[{"name":"first"}]},"model_credential":"first"}`, 'a')
	creds := []gateway.Credential{{Name: "first", Env: "GATEWAY_TEST_FIRST_KEY", Format: "anthropic-messages", Endpoint: "https://localhost:9/v1", Scheme: "header", Header: "x-api-key"}}
	node := &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost"}}}
	return gateway.Config{Server: c.server(), Credentials: creds, Policy: node}
}

// modeOf is the permission bits of file, or an error.
func modeOf(file string) (fs.FileMode, error) {
	info, err := os.Lstat(file)
	if err != nil {
		return 0, err
	}
	return info.Mode().Perm(), nil
}

// exists reports whether file exists.
func exists(file string) bool {
	_, err := os.Lstat(file)
	return err == nil
}

// lineMaps are the lines of a JSON lines file, each decoded.
func lineMaps(t *testing.T, file string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("a line of %s: %v", file, err)
		}
		out = append(out, m)
	}
	return out
}

// TestASeparateGatewayKeepsWhatReopensARun pins the files a separate gateway writes
// in a run's record directory, each mode 0600: request.json, the CA files and
// given.jsonl before the record is marked answered, and joins.jsonl with each join
// before its answer. request.json has the run request's wall, narrowing and images;
// given.jsonl the run answer's applied; ca.pem the run answer's certificate_authority;
// joins.jsonl one line per join decision. A join whose line cannot be written is a 500
// and is not numbered.
func TestASeparateGatewayKeepsWhatReopensARun(t *testing.T) {
	c := gatewayControl(t)
	cfg := caConfig(t, c)
	cfg.Dir = t.TempDir()
	runID := event.NewRunID()
	dir := filepath.Join(cfg.Dir, "runs", runID)
	var mu sync.Mutex
	var atOpen []string
	gateway.SetOpened(&cfg, func() {
		mu.Lock()
		defer mu.Unlock()
		if exists(filepath.Join(dir, "answered")) {
			atOpen = append(atOpen, "answered")
		}
		for _, name := range []string{"request.json", "ca.pem", "ca.key", "given.jsonl"} {
			if mode, err := modeOf(filepath.Join(dir, name)); err != nil || mode != 0o600 {
				atOpen = append(atOpen, name)
			}
		}
	})
	r := startRemote(t, c, cfg)
	req := server.LinkRunRequest{Wall: true, Narrowing: &server.LinkNarrowing{Egress: server.LinkNarrowingEgress{Allow: []string{"localhost"}}},
		Images: &server.LinkImages{Default: "base", Definitions: []server.LinkImage{{Name: "base", Ref: "registry.example/base:1"}}}}
	e := r.open(t, runKeyFor(t, runID, nil), req)
	mu.Lock()
	if len(atOpen) > 0 {
		t.Errorf("before the record was marked answered: %v answered, missing or not mode 0600", atOpen)
	}
	mu.Unlock()

	b, err := os.ReadFile(filepath.Join(dir, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var kept struct {
		Version   int                   `json:"version"`
		Wall      bool                  `json:"wall"`
		Narrowing *server.LinkNarrowing `json:"narrowing"`
		Images    *server.LinkImages    `json:"images"`
	}
	if err := json.Unmarshal(b, &kept); err != nil || kept.Version != 1 || !kept.Wall || !reflect.DeepEqual(kept.Narrowing, req.Narrowing) || !reflect.DeepEqual(kept.Images, req.Images) {
		t.Errorf("request.json %s", b)
	}
	if pem, _ := os.ReadFile(filepath.Join(dir, "ca.pem")); e.a.CertificateAuthority == "" || string(pem) != e.a.CertificateAuthority {
		t.Errorf("ca.pem is not the run answer's certificate_authority")
	}
	var applied map[string]any
	json.Unmarshal(e.a.Applied, &applied)
	if given := lineMaps(t, filepath.Join(dir, "given.jsonl")); len(given) != 1 || !reflect.DeepEqual(given[0], applied) {
		t.Errorf("given.jsonl %v; want the run answer's applied %v", given, applied)
	}
	if exists(filepath.Join(dir, "joins.jsonl")) || exists(filepath.Join(dir, "model-key-limit")) {
		t.Error("joins.jsonl or model-key-limit before any join or limit")
	}

	// A join whose line cannot be written: joins.jsonl is a directory.
	if err := os.Mkdir(filepath.Join(dir, "joins.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	joinPath := "/qory-link/run-configuration/" + runID + "/sessions"
	body := []byte(`{"version":1,"passes":["HOME"],"model_key":true}`)
	if a := r.do(t, e.key, http.MethodPost, joinPath, body); a.status != http.StatusInternalServerError {
		t.Errorf("a join whose line cannot be written: %d %s", a.status, a.body)
	}
	os.Remove(filepath.Join(dir, "joins.jsonl"))
	a := r.do(t, e.key, http.MethodPost, joinPath, body)
	var joined server.LinkJoinAnswer
	if json.Unmarshal(a.body, &joined); a.status != http.StatusOK || joined.Session != 1 || joined.ModelCredential != "first" {
		t.Fatalf("the join: %d %s", a.status, a.body)
	}
	if mode, err := modeOf(filepath.Join(dir, "joins.jsonl")); err != nil || mode != 0o600 {
		t.Errorf("joins.jsonl: mode %v, %v", mode, err)
	}
	want := []map[string]any{{"session": float64(1), "accepted": true, "passes": []any{"HOME"}, "model": "first", "no_key": false}}
	if got := lineMaps(t, filepath.Join(dir, "joins.jsonl")); !reflect.DeepEqual(got, want) {
		t.Errorf("joins.jsonl %v; want %v", got, want)
	}
}

// TestAJoinSentAgainGetsItsAnswerAgain pins the replay of a join on the one address:
// the run's last join, answered 200 and with neither session.started nor
// session.exited numbered, sent again with the same passes, model_key and
// model_credential, gets the same 200, session number and model key, and nothing new
// is numbered or written; another join while it is open is the 400 of a join while
// another is open; once its session.started is numbered, the same request is that 400
// too. On the local link the same request is that 400 at once.
func TestAJoinSentAgainGetsItsAnswerAgain(t *testing.T) {
	c := gatewayControl(t)
	cfg := caConfig(t, c)
	r := startRemote(t, c, cfg)
	runID := event.NewRunID()
	e := r.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{Wall: true})
	dir := filepath.Join(r.cfg.Dir, "runs", runID)
	joinPath := "/qory-link/run-configuration/" + runID + "/sessions"
	same := []byte(`{"version":1,"passes":["HOME"],"model_key":true,"model_credential":"first"}`)
	for i := range 2 {
		a := r.do(t, e.key, http.MethodPost, joinPath, same)
		var joined server.LinkJoinAnswer
		if json.Unmarshal(a.body, &joined); a.status != http.StatusOK || joined.Session != 1 || joined.ModelCredential != "first" {
			t.Fatalf("join try %d: %d %s", i+1, a.status, a.body)
		}
	}
	for _, other := range []string{
		`{"version":1,"passes":["HOME","PATH"],"model_key":true,"model_credential":"first"}`,
		`{"version":1,"passes":["HOME"],"model_key":true}`,
		`{"version":1,"passes":["HOME"],"model_key":false}`,
	} {
		if a := r.do(t, e.key, http.MethodPost, joinPath, []byte(other)); a.status != http.StatusBadRequest || a.refusal()["error"] != "invalid_request" {
			t.Errorf("another join while session 1 is open, %s: %d %s", other, a.status, a.body)
		}
	}
	if got := lineMaps(t, filepath.Join(dir, "joins.jsonl")); len(got) != 1 || got[0]["model_credential"] != "first" {
		t.Errorf("joins.jsonl %v; want the one join", got)
	}
	if got := e.post(t, sessionStarted(runID, 1)); got.status != http.StatusAccepted {
		t.Fatalf("session 1's session.started: %d %s", got.status, got.body)
	}
	if a := r.do(t, e.key, http.MethodPost, joinPath, same); a.status != http.StatusBadRequest {
		t.Errorf("the join again after its session.started: %d %s", a.status, a.body)
	}
	if got := e.post(t, sessionExited(runID, 1)); got.status != http.StatusAccepted {
		t.Fatalf("session 1's session.exited: %d %s", got.status, got.body)
	}
	a := r.do(t, e.key, http.MethodPost, joinPath, same)
	var joined server.LinkJoinAnswer
	if json.Unmarshal(a.body, &joined); a.status != http.StatusOK || joined.Session != 2 {
		t.Errorf("a join after session 1 exited: %d %s", a.status, a.body)
	}
	if got := lineMaps(t, filepath.Join(dir, "joins.jsonl")); len(got) != 2 || got[1]["session"] != float64(2) {
		t.Errorf("joins.jsonl %v; want two joins", got)
	}

	t.Run("local", func(t *testing.T) {
		lc := newControl(t)
		h := start(t, caConfig(t, lc))
		la := h.open(server.LinkRunRequest{Wall: true})
		if d := h.post(started(la.RunID, nil), applied(la.RunID, la.Applied)); !d.Accepted() {
			t.Fatalf("the first batch: %+v", d)
		}
		if n := h.joined(la.RunID, "HOME"); n != 1 {
			t.Fatalf("the join: session %d", n)
		}
		if _, err := h.join(la.RunID, "HOME"); err == nil {
			t.Error("the same join again on the local link was answered 200")
		}
		for _, name := range keptNames {
			if exists(filepath.Join(h.dir, "runs", la.RunID, name)) {
				t.Errorf("the local link wrote %s", name)
			}
		}
	})
}

// TestARefusedJoinSentAgainGetsItsRefusalAgain pins the replay of a join answered 403
// on the one address: the run's last join, refused with placeholder_conflict and with
// no session.exited numbered, sent again with the same passes, model_key and
// model_credential, gets the same 403, and nothing new is numbered or written; once
// the refused join's session.exited is numbered, the next join is session 2.
func TestARefusedJoinSentAgainGetsItsRefusalAgain(t *testing.T) {
	t.Setenv("GATEWAY_TEST_SECRET", "s3cret-value-of-the-test")
	c := gatewayControl(t)
	c.serveDocument(`{"version":1}`, 'a')
	r := startRemote(t, c, gateway.Config{
		Credentials: []gateway.Credential{{Name: "api", Env: "GATEWAY_TEST_SECRET", Hosts: []string{"api.example"}, Scheme: "bearer", Placeholders: []string{"API_TOKEN"}}},
		Policy:      &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example"}}, Credentials: []gateway.PolicyCredential{{Name: "api"}}},
	})
	runID := event.NewRunID()
	e := r.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{})
	dir := filepath.Join(r.cfg.Dir, "runs", runID)
	joinPath := "/qory-link/run-configuration/" + runID + "/sessions"
	conflicting := []byte(`{"version":1,"passes":["HOME","API_TOKEN"],"model_key":false}`)
	for i := range 2 {
		a := r.do(t, e.key, http.MethodPost, joinPath, conflicting)
		if a.status != http.StatusForbidden || a.refusal()["error"] != "placeholder_conflict" || !slices.Equal(anyStrings(a.refusal()["names"]), []string{"API_TOKEN"}) {
			t.Fatalf("join try %d: %d %s", i+1, a.status, a.body)
		}
	}
	if got := lineMaps(t, filepath.Join(dir, "joins.jsonl")); len(got) != 1 || got[0]["session"] != float64(1) || got[0]["accepted"] != false {
		t.Errorf("joins.jsonl %v; want the one refused join", got)
	}
	refusedJoin := ev(runID, event.SessionExited, map[string]any{"session": 1, "state": "failed", "exit_code": -1, "reason": "placeholder_conflict", "duration_ms": 0})
	if got := e.post(t, refusedJoin); got.status != http.StatusAccepted {
		t.Fatalf("the refused join's session.exited: %d %s", got.status, got.body)
	}
	a := r.do(t, e.key, http.MethodPost, joinPath, []byte(`{"version":1,"passes":["HOME"],"model_key":false}`))
	var joined server.LinkJoinAnswer
	if json.Unmarshal(a.body, &joined); a.status != http.StatusOK || joined.Session != 2 {
		t.Errorf("the join after the refused one: %d %s", a.status, a.body)
	}
}

// TestTheReloadAnswerIsTheSameAfterAReopen pins an image reference with user
// information: the run answer gives it whole, the reload answer and request.json
// without it, and the reload answer of the reopened run has the same bytes and the same
// digest as before the restart, so the session reloads nothing and records no
// policy_applied more.
func TestTheReloadAnswerIsTheSameAfterAReopen(t *testing.T) {
	const digest = "@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	const bare = "registry.example/agents/base" + digest
	// A password with / and @ in it.
	const secret = "user:pa/ss@wo@rd@"
	c := gatewayControl(t)
	cfg := gateway.Config{Dir: t.TempDir()}
	before := startRemote(t, c, cfg)
	runID := event.NewRunID()
	images := &server.LinkImages{Default: "base", Definitions: []server.LinkImage{{Name: "base", Ref: secret + bare, Runtime: "sysbox-runc"}}}
	e := before.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{Wall: true, Images: images})
	if e.a.Image == nil || e.a.Image.Ref != secret+bare {
		t.Errorf("the run answer's image: %+v", e.a.Image)
	}
	first := e.reload(t)
	var reloaded server.LinkReloadAnswer
	if err := json.Unmarshal(first.body, &reloaded); first.status != http.StatusOK || err != nil || reloaded.Image == nil || reloaded.Image.Ref != bare {
		t.Fatalf("the reload: %d %s", first.status, first.body)
	}
	if b, err := os.ReadFile(filepath.Join(cfg.Dir, "runs", runID, "request.json")); err != nil || strings.Contains(string(b), "pa/ss") {
		t.Errorf("request.json: %s, %v", b, err)
	}
	held := strings.Trim(first.header.Get("ETag"), `"`)
	if got := first.header.Get(server.HeaderRunConfiguration); got != held {
		t.Errorf("the reload's run configuration %q; want its ETag's %q", got, held)
	}
	e.r = before.restart(t, cfg)
	if got := e.post(t, heartbeat(runID)); got.status != http.StatusAccepted || got.header.Get(server.HeaderRunConfiguration) != held {
		t.Errorf("the first batch after the restart: %d, run configuration %q; want %q", got.status, got.header.Get(server.HeaderRunConfiguration), held)
	}
	again := e.reload(t)
	if again.status != http.StatusOK || string(again.body) != string(first.body) || again.header.Get("ETag") != first.header.Get("ETag") {
		t.Errorf("the reload after the reopen: %d %s, ETag %q; want %s, ETag %q", again.status, again.body, again.header.Get("ETag"), first.body, first.header.Get("ETag"))
	}
}

// TestACAIsKeptUntilTheRunsFinalEnd pins the CA files of a run on the one address:
// Close keeps them, which ends the run with no final event; the run's final end
// removes them with every other file kept to reopen the run: the session's run.exited,
// and the server's end member, stopped.
func TestACAIsKeptUntilTheRunsFinalEnd(t *testing.T) {
	caOf := func(dir string) (bool, bool) {
		return exists(filepath.Join(dir, "ca.pem")), exists(filepath.Join(dir, "ca.key"))
	}
	t.Run("close", func(t *testing.T) {
		c := gatewayControl(t)
		r := startRemote(t, c, caConfig(t, c))
		runID := event.NewRunID()
		r.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{Wall: true})
		if _, err := r.g.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		if pem, key := caOf(filepath.Join(r.cfg.Dir, "runs", runID)); !pem || !key {
			t.Errorf("after Close: ca.pem %v, ca.key %v; want both", pem, key)
		}
	})
	t.Run("run.exited", func(t *testing.T) {
		c := gatewayControl(t)
		r := startRemote(t, c, caConfig(t, c))
		runID := event.NewRunID()
		e := r.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{Wall: true})
		dir := filepath.Join(r.cfg.Dir, "runs", runID)
		if pem, key := caOf(dir); !pem || !key || !exists(filepath.Join(dir, "given.jsonl")) {
			t.Fatalf("a live run: ca.pem %v, ca.key %v, given.jsonl missing", pem, key)
		}
		if got := e.post(t, exited(runID)); got.status != http.StatusAccepted {
			t.Fatalf("the last batch: %d %s", got.status, got.body)
		}
		eventually(t, "the kept files removed", func() bool { return len(keptLeft(r.cfg.Dir, runID)) == 0 })
	})
	t.Run("stopped", func(t *testing.T) {
		c := gatewayControl(t)
		r := startRemote(t, c, caConfig(t, c))
		runID := event.NewRunID()
		e := r.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{Wall: true})
		c.end.Store(&server.ServerEnd{State: "cancelled"})
		eventually(t, "the 410", func() bool { return e.post(t, heartbeat(runID)).status == http.StatusGone })
		eventually(t, "the kept files removed", func() bool { return len(keptLeft(r.cfg.Dir, runID)) == 0 })
	})
}

// fakeRecord makes a run record under dir/runs with events.jsonl of the event types
// given, changed at changed, and every file kept to reopen a run with fake contents.
func fakeRecord(t *testing.T, dir string, changed time.Time, types ...string) string {
	t.Helper()
	runID := event.NewRunID()
	rec := filepath.Join(dir, "runs", runID)
	if err := os.MkdirAll(rec, 0o700); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for i, typ := range types {
		lines = append(lines, `{"specversion":"1.0","id":"`+event.NewID()+`","type":"`+typ+`","sequence":"`+strings.Repeat("0", 19)+string(rune('1'+i))+`"}`)
	}
	events := filepath.Join(rec, "events.jsonl")
	if err := os.WriteFile(events, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range finalNames {
		if err := os.WriteFile(filepath.Join(rec, name), []byte("fake "+name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(events, changed, changed); err != nil {
		t.Fatal(err)
	}
	return runID
}

// TestTheSweepRemovesTheCAOfRecordsNoRunIsOpenOn pins the CA key sweep: at Start and
// on each tick it removes the files kept to reopen a run of a record the gateway
// does not hold whose events.jsonl has not changed for longer than the sweep's age,
// with a final event or without; a record that changed since and the record of a run
// the gateway holds keep theirs.
func TestTheSweepRemovesTheCAOfRecordsNoRunIsOpenOn(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-2 * time.Minute)
	atStart := fakeRecord(t, dir, old, event.RunRegistered, event.RunStarted)
	exitedRec := fakeRecord(t, dir, old, event.RunRegistered, event.RunStarted, event.RunExited)
	refusedRec := fakeRecord(t, dir, old, event.RunRegistered, event.RunRefused)
	fresh := fakeRecord(t, dir, time.Now(), event.RunRegistered)
	cfg := gateway.Config{Dir: dir}
	gateway.SetCASweep(&cfg, time.Hour, time.Minute)
	r := startRemote(t, nil, cfg)
	gone := func(runID string) bool { return len(keptLeft(dir, runID)) == 0 }
	eventually(t, "the sweep at Start", func() bool { return gone(atStart) })

	// A run the gateway holds, its record unchanged as long, with CA files.
	held := event.NewRunID()
	r.open(t, runKeyFor(t, held, nil), server.LinkRunRequest{})
	heldRec := filepath.Join(dir, "runs", held)
	for _, name := range []string{"ca.pem", "ca.key"} {
		if err := os.WriteFile(filepath.Join(heldRec, name), []byte("fake\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(filepath.Join(heldRec, "events.jsonl"), old, old); err != nil {
		t.Fatal(err)
	}
	later := fakeRecord(t, dir, old, event.RunRegistered)
	gateway.SweepCA(r.g, time.Now())
	for name, runID := range map[string]string{"with no final event": later, "with run.exited": exitedRec, "with run.refused": refusedRec} {
		if !gone(runID) {
			t.Errorf("a record not held, %s, unchanged for 2 minutes keeps its CA files", name)
		}
	}
	for name, runID := range map[string]string{"held": held, "changed now": fresh} {
		if gone(runID) {
			t.Errorf("the record %s lost its CA files", name)
		}
	}
	// 30 minutes on, the fresh record is old too.
	gateway.SweepCA(r.g, time.Now().Add(30*time.Minute))
	if !gone(fresh) {
		t.Error("the record changed 30 minutes ago keeps its CA files")
	}
}

// TestTheSweepRunsEvery10MinutesOnRecordsOlderThan15 pins the CA key sweep's values,
// the user's "545 (a)": the sweep's ticker has an interval of 10 minutes, and a pass
// removes the kept files of a record whose events.jsonl has not changed for more than
// 15 minutes, not those of one unchanged for 14 minutes.
func TestTheSweepRunsEvery10MinutesOnRecordsOlderThan15(t *testing.T) {
	dir := t.TempDir()
	older := fakeRecord(t, dir, time.Now().Add(-16*time.Minute), event.RunRegistered)
	younger := fakeRecord(t, dir, time.Now().Add(-14*time.Minute), event.RunRegistered)
	ticks, every := make(chan time.Time), make(chan time.Duration, 1)
	cfg := gateway.Config{Dir: dir}
	gateway.SetSweepTicker(&cfg, func(d time.Duration) <-chan time.Time {
		every <- d
		return ticks
	})
	startRemote(t, nil, cfg)
	if got := <-every; got != 10*time.Minute {
		t.Errorf("the sweep's interval is %s, want 10m0s", got)
	}
	eventually(t, "the sweep at Start", func() bool { return len(keptLeft(dir, older)) == 0 })
	if left := keptLeft(dir, younger); len(left) != len(finalNames) {
		t.Errorf("the record unchanged for 14 minutes keeps only %v", left)
	}
	// The younger record ages past 15 minutes; the next tick removes its files.
	past := time.Now().Add(-16 * time.Minute)
	if err := os.Chtimes(filepath.Join(dir, "runs", younger, "events.jsonl"), past, past); err != nil {
		t.Fatal(err)
	}
	ticks <- time.Now()
	eventually(t, "the sweep at a tick", func() bool { return len(keptLeft(dir, younger)) == 0 })
}

// TestTheSweepTicks pins the sweep's ticker: a record that ages after Start loses its
// CA files at a later tick, and Close stops the ticker.
func TestTheSweepTicks(t *testing.T) {
	dir := t.TempDir()
	cfg := gateway.Config{Dir: dir}
	gateway.SetCASweep(&cfg, 20*time.Millisecond, time.Minute)
	r := startRemote(t, nil, cfg)
	later := fakeRecord(t, dir, time.Now().Add(-2*time.Minute), event.RunRegistered)
	eventually(t, "the sweep at a tick", func() bool { return !exists(filepath.Join(dir, "runs", later, "ca.key")) })
	if _, err := r.g.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	after := fakeRecord(t, dir, time.Now().Add(-2*time.Minute), event.RunRegistered)
	time.Sleep(100 * time.Millisecond)
	if !exists(filepath.Join(dir, "runs", after, "ca.key")) {
		t.Error("the sweep ran after Close")
	}
}

// TestTheModelKeyMarkFollowsPassAndResume pins model-key-limit on the one address: the
// proxy passing a limit refusal to the session makes the empty file, mode 0600, and the
// next join, which resumes the keys, removes it.
func TestTheModelKeyMarkFollowsPassAndResume(t *testing.T) {
	certFile, keyFile, roots := testCertificate(t, t.TempDir())
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Anthropic-Ratelimit-Unified-5h-Status", "rejected")
		w.Header().Set("Anthropic-Ratelimit-Unified-5h-Reset", "4102444800")
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"type":"error","error":{"type":"rate_limit_error"}}`)
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	url := "https://localhost:" + port + "/v1"
	entry := func(name string) string {
		return `{"name":"` + name + `","format":"anthropic-messages","endpoint":"` + url + `","auth":{"scheme":"header","header":"x-api-key"},"pause_for_s":3600}`
	}
	c := gatewayControl(t)
	c.serveDocument(`{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["localhost"]}},"model_credential":"model","credentials":[`+entry("model")+`,`+entry("model-2")+`]}`, 'a')
	c.mu.Lock()
	c.secrets = map[string]string{"model": "fake-group-value-0001", "model-2": "fake-group-value-0002"}
	c.mu.Unlock()
	node := &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost"}}}
	cfg := gateway.Config{Policy: node}
	gateway.SetUpstreamRoots(&cfg, roots)
	r := startRemote(t, c, cfg)
	runID := event.NewRunID()
	key := runKeyFor(t, runID, nil)
	e := r.open(t, key, server.LinkRunRequest{Wall: true})
	mark := filepath.Join(r.cfg.Dir, "runs", runID, "model-key-limit")

	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM([]byte(e.a.CertificateAuthority))
	agent := r.relay(t, key)
	agent.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: trusted}
	req, _ := http.NewRequest(http.MethodPost, url+"/messages", strings.NewReader(`{"model":"m"}`))
	req.Header.Set("X-Api-Key", link.KeyPlaceholder("model"))
	resp, err := agent.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("with no key left: %d", resp.StatusCode)
	}
	eventually(t, "the mark", func() bool { return exists(mark) })
	if mode, err := modeOf(mark); err != nil || mode != 0o600 {
		t.Errorf("model-key-limit: mode %v, %v", mode, err)
	}
	if info, err := os.Stat(mark); err != nil || info.Size() != 0 {
		t.Errorf("model-key-limit is not empty: %v", err)
	}
	if got := e.post(t, heartbeat(runID)); got.status != http.StatusAccepted || !strings.Contains(string(got.body), "model_key_limit") {
		t.Errorf("a batch after the pass: %d %s", got.status, got.body)
	}
	if a := r.do(t, key, http.MethodPost, "/qory-link/run-configuration/"+runID+"/sessions", []byte(`{"version":1,"passes":[],"model_key":true}`)); a.status != http.StatusOK {
		t.Fatalf("the join: %d %s", a.status, a.body)
	}
	if _, err := os.Lstat(mark); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("model-key-limit after the join: %v", err)
	}
}
