package gateway_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/sink"
)

// secretNames are the run request and the CA files, which a record kept for a reopen
// has whatever else happened in the run.
var secretNames = []string{"request.json", "ca.pem", "ca.key"}

// finalNames are the kept files a run's final end removes: every file a separate gateway
// keeps to reopen the run.
var finalNames = []string{"request.json", "ca.pem", "ca.key", "given.jsonl", "joins.jsonl", "model-key-limit", "held.jsonl"}

// keptLeft are those of finalNames still in the record directory of the run of runID
// under dir.
func keptLeft(dir, runID string) []string {
	var left []string
	for _, name := range finalNames {
		if exists(filepath.Join(dir, "runs", runID, name)) {
			left = append(left, name)
		}
	}
	return left
}

// secretsLeft are those of secretNames still in the record directory of the run of
// runID under dir.
func secretsLeft(dir, runID string) []string {
	var left []string
	for _, name := range secretNames {
		if exists(filepath.Join(dir, "runs", runID, name)) {
			left = append(left, name)
		}
	}
	return left
}

// denied makes one request through the run's proxy to a host its policy does not
// allow, which the proxy denies with a 403 and numbers as a run.egress.
func denied(t *testing.T, r *remote, key string) {
	t.Helper()
	resp, err := r.relay(t, key).Get("http://denied.example/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a denied host through the proxy: %d", resp.StatusCode)
	}
}

// indexOf is the index of the first line of rec of the type typ for which ok returns
// true, -1 for none.
func indexOf(rec []recorded, typ string, ok func(recorded) bool) int {
	return slices.IndexFunc(rec, func(l recorded) bool { return l.Type == typ && (ok == nil || ok(l)) })
}

// allows matches a policy_applied whose members allow host.
func allows(host string) func(recorded) bool {
	return func(l recorded) bool {
		allow, _ := l.Data["allow"].([]any)
		return slices.Contains(allow, any(host))
	}
}

// appliedOf is the applied member of a reload answer's body.
func appliedOf(t *testing.T, body []byte) json.RawMessage {
	t.Helper()
	var doc struct {
		Applied json.RawMessage `json:"applied"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Applied == nil {
		t.Fatalf("a reload answer with no applied: %s", body)
	}
	return doc.Applied
}

// TestAMarkWithNoKeyGroupIsIgnored pins the mark of a passed limit refusal in the
// record of a run whose run configuration has no key group: the reopen goes on, and
// the first batch is a 202 with no stop.
func TestAMarkWithNoKeyGroupIsIgnored(t *testing.T) {
	c := gatewayControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`, 'a')
	cfg := gateway.Config{Dir: t.TempDir()}
	before := startRemote(t, c, cfg)
	runID := event.NewRunID()
	e := before.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{})
	if err := os.WriteFile(filepath.Join(cfg.Dir, "runs", runID, "model-key-limit"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e.r = before.restart(t, cfg)
	if got := e.post(t, heartbeat(runID)); got.status != http.StatusAccepted || len(got.body) != 0 {
		t.Errorf("the first batch: %d %q", got.status, got.body)
	}
}

// TestARecordThatCannotReopenEndsWithoutAnAttach pins a suspended run whose record a
// reopen cannot read: one no longer marked answered, one with a final event, and one
// whose CA key does not read back. The first batch is a 410 run_closed, no attach
// reaches Qory Apiary, and every file kept to reopen it goes.
func TestARecordThatCannotReopenEndsWithoutAnAttach(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, dir string){
		"not answered": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "answered")); err != nil {
				t.Fatal(err)
			}
		},
		"ended": func(t *testing.T, dir string) {
			f, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := f.WriteString(`{"specversion":"1.0","id":"` + event.NewID() + `","type":"` + event.RunExited + `","sequence":"0000000099"}` + "\n"); err != nil {
				t.Fatal(err)
			}
		},
		"a CA key that does not read back": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "ca.key"), []byte("fake\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := gatewayControl(t)
			cfg := caConfig(t, c)
			cfg.Dir = t.TempDir()
			before := startRemote(t, c, cfg)
			runID := event.NewRunID()
			e := before.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{Wall: true})
			after := before.restart(t, cfg)
			change(t, filepath.Join(cfg.Dir, "runs", runID))
			e.r = after
			for range 2 {
				if got := e.post(t, heartbeat(runID)); got.status != http.StatusGone || got.refusal()["error"] != "run_closed" {
					t.Errorf("a batch: %d %s", got.status, got.body)
				}
			}
			if got := len(c.attached()); got != 1 {
				t.Errorf("%d attaches; want the open's alone", got)
			}
			if left := keptLeft(cfg.Dir, runID); len(left) > 0 {
				t.Errorf("the record keeps %v", left)
			}
		})
	}
}

// TestAReopenWhoseAttachIsRefused pins the signed 4xx of a reopen's attach: a 401, or
// any 4xx that does not end the run at once, is tried again within the tries' window,
// and a reopen whose attach is answered within it opens; a 403 with a code all through
// the window ends the run, a 410 run_closed with no attach after, and the run request
// and CA files go.
func TestAReopenWhoseAttachIsRefused(t *testing.T) {
	t.Run("401", func(t *testing.T) {
		c := gatewayControl(t)
		cfg := gateway.Config{Dir: t.TempDir()}
		gateway.SetOpenTries(&cfg, []time.Duration{20 * time.Millisecond}, time.Minute)
		before := startRemote(t, c, cfg)
		runID := event.NewRunID()
		e := before.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{})
		c.attachRefusal.Store(&receiver.Refusal{Status: http.StatusUnauthorized, Code: "unauthorized"})
		e.r = before.restart(t, cfg)
		got := make(chan answer, 1)
		go func() { got <- e.post(t, heartbeat(runID)) }()
		eventually(t, "two attaches after the restart", func() bool { return len(c.attached()) >= 3 })
		c.attachRefusal.Store(nil)
		if a := <-got; a.status != http.StatusAccepted {
			t.Errorf("a batch whose reopen's attach was a 401 at first: %d %s", a.status, a.body)
		}
	})
	t.Run("403", func(t *testing.T) {
		c := gatewayControl(t)
		cfg := gateway.Config{Dir: t.TempDir()}
		before := startRemote(t, c, cfg)
		runID := event.NewRunID()
		e := before.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{})
		c.attachRefusal.Store(&receiver.Refusal{Status: http.StatusForbidden, Code: "forbidden"})
		gateway.SetOpenTries(&cfg, []time.Duration{20 * time.Millisecond}, 300*time.Millisecond)
		e.r = before.restart(t, cfg)
		if got := e.post(t, heartbeat(runID)); got.status != http.StatusGone || got.refusal()["error"] != "run_closed" {
			t.Errorf("a batch whose reopen's attach was a 403 all through: %d %s", got.status, got.body)
		}
		attaches := len(c.attached())
		if attaches < 3 {
			t.Errorf("%d attaches; want the 403 tried again", attaches)
		}
		if got := e.post(t, heartbeat(runID)); got.status != http.StatusGone || got.refusal()["error"] != "run_closed" {
			t.Errorf("the next batch: %d %s", got.status, got.body)
		}
		if got := len(c.attached()); got != attaches {
			t.Errorf("%d attaches after the final failure; want %d", got, attaches)
		}
		if left := keptLeft(cfg.Dir, runID); len(left) > 0 {
			t.Errorf("the record keeps %v", left)
		}
	})
}

// TestAReopenWhoseOwedEventsWait pins the resend of the events Qory Apiary did not
// accept before the stop, more than the run's sink queues: while the server takes none
// of them, the resend waits for room in the queue until the tries' window ends, and the
// reopen fails then, a 503 with no body, the run keeping its record; once the server
// takes them, the session's next batch reopens the run.
func TestAReopenWhoseOwedEventsWait(t *testing.T) {
	c := gatewayControl(t)
	var fail atomic.Bool
	failDeliveries(c, &fail)
	cfg := gateway.Config{Dir: t.TempDir()}
	gateway.SetCloseWait(&cfg, 300*time.Millisecond)
	gateway.SetOpenTries(&cfg, []time.Duration{20 * time.Millisecond}, time.Second)
	before := startRemote(t, c, cfg)
	runID := event.NewRunID()
	e := before.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{})
	eventually(t, "the first batch at the server", func() bool { return len(c.lines(t)) == 2 })
	fail.Store(true)
	if got := e.post(t, heartbeat(runID)); got.status != http.StatusAccepted {
		t.Fatalf("the batch before the stop: %d %s", got.status, got.body)
	}
	e.r = before.restart(t, cfg)
	// More owed heartbeats than the sink's queue holds, each the last one's line with a
	// fresh id and the next sequence.
	file := filepath.Join(cfg.Dir, "runs", runID, "events.jsonl")
	rec := e.r.record(runID)
	var last map[string]any
	b, _ := os.ReadFile(file)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		t.Fatal(err)
	}
	var more []byte
	for i := range sink.QueueSize + 1000 {
		last["id"], last["sequence"] = event.NewID(), fmt.Sprintf("%010d", len(rec)+1+i)
		line, _ := json.Marshal(last)
		more = append(append(more, line...), '\n')
	}
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(more)
	f.Close()

	begin := time.Now()
	if got := e.post(t, heartbeat(runID)); got.status != http.StatusServiceUnavailable || len(got.body) != 0 {
		t.Errorf("a batch while the server takes no event: %d %s", got.status, got.body)
	}
	if took := time.Since(begin); took > 10*time.Second {
		t.Errorf("the reopen took %s", took)
	}
	if left := secretsLeft(cfg.Dir, runID); len(left) != len(secretNames) {
		t.Errorf("the record keeps only %v", left)
	}
	fail.Store(false)
	if got := e.post(t, heartbeat(runID)); got.status != http.StatusAccepted {
		t.Errorf("a batch once the server takes events: %d %s", got.status, got.body)
	}
}

// TestAPolicyPutBackIsAppliedAgain pins the members in force at the suspend: a run
// opened under policy A, reopened under policy B, whose session applies B, is reopened
// under A again. The second reopen compares A with B, the members in force, not with
// every member given: every run.egress waits for the session's policy_applied of A.
func TestAPolicyPutBackIsAppliedAgain(t *testing.T) {
	const a, b = `{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`, `{"version":1,"egress":{"mode":"enforce","allow":["other.example"]}}`
	c := gatewayControl(t)
	c.serve(a, 'a')
	cfg := gateway.Config{Dir: t.TempDir()}
	r := startRemote(t, c, cfg)
	runID := event.NewRunID()
	key := runKeyFor(t, runID, nil)
	e := r.open(t, key, server.LinkRunRequest{})
	for i, policy := range []struct {
		doc  string
		d    byte
		host string
	}{{b, 'b', "other.example"}, {a, 'a', "api.example"}} {
		c.serve(policy.doc, policy.d)
		r = r.restart(t, cfg)
		e.r = r
		reloaded := e.reload(t)
		if reloaded.status != http.StatusOK || !strings.Contains(string(reloaded.body), policy.host) {
			t.Fatalf("restart %d: the reload: %d %s", i+1, reloaded.status, reloaded.body)
		}
		egress := func() int { return count(r.record(runID), event.RunEgress) }
		n := egress()
		denied(t, r, key)
		time.Sleep(200 * time.Millisecond)
		if egress() != n {
			t.Fatalf("restart %d: a run.egress before the policy_applied allowing %s: %v", i+1, policy.host, types(r.record(runID)))
		}
		if got := e.post(t, applied(runID, appliedOf(t, reloaded.body))); got.status != http.StatusAccepted {
			t.Fatalf("restart %d: the policy_applied: %d %s", i+1, got.status, got.body)
		}
		eventually(t, "the run.egress", func() bool { return egress() == n+1 })
		rec := r.record(runID)
		if last := rec[len(rec)-1]; last.Type != event.RunEgress || rec[len(rec)-2].Type != event.PolicyApplied || !allows(policy.host)(rec[len(rec)-2]) {
			t.Errorf("restart %d: the record ends %v; want the policy_applied allowing %s, then the run.egress", i+1, types(rec[len(rec)-2:]), policy.host)
		}
	}
}

// count is how many lines of rec have the type typ.
func count(rec []recorded, typ string) int {
	n := 0
	for _, l := range rec {
		if l.Type == typ {
			n++
		}
	}
	return n
}

// TestABatchRefusedWhileTheRunReopensIsNumberedOnce pins a batch the session sends
// while the reopen's attach fails in a way that may pass: a 503, then a 202 once the
// attach is answered, and the batch sent again is numbered once.
func TestABatchRefusedWhileTheRunReopensIsNumberedOnce(t *testing.T) {
	c := gatewayControl(t)
	cfg := gateway.Config{Dir: t.TempDir()}
	gateway.SetOpenTries(&cfg, []time.Duration{20 * time.Millisecond}, 100*time.Millisecond)
	before := startRemote(t, c, cfg)
	runID := event.NewRunID()
	e := before.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{})
	c.attachRefusal.Store(&receiver.Refusal{Status: http.StatusServiceUnavailable, Code: "unavailable"})
	e.r = before.restart(t, cfg)
	beat := heartbeat(runID)
	if got := e.post(t, beat); got.status != http.StatusServiceUnavailable || len(got.body) != 0 {
		t.Fatalf("a batch while the attach is answered 503: %d %s", got.status, got.body)
	}
	c.attachRefusal.Store(nil)
	for range 2 {
		if got := e.post(t, beat); got.status != http.StatusAccepted {
			t.Fatalf("the batch sent again: %d %s", got.status, got.body)
		}
	}
	n := 0
	for _, l := range e.r.record(runID) {
		if l.ID == beat["id"] {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the batch is numbered %d times", n)
	}
}

// TestHeldEgressIsKeptAcrossARestart pins a run.egress the proxy decided before the
// run's run.started, which waits for it: the gateway's stop keeps it, and once the
// reopened run numbers run.started and its policy_applied, the run.egress follows
// them, once.
func TestHeldEgressIsKeptAcrossARestart(t *testing.T) {
	c := gatewayControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`, 'a')
	cfg := gateway.Config{Dir: t.TempDir()}
	before := startRemote(t, c, cfg)
	runID := event.NewRunID()
	key := runKeyFor(t, runID, nil)
	a := before.tryOpen(t, key, server.LinkRunRequest{})
	if a.status != http.StatusOK {
		t.Fatalf("the run request: %d %s", a.status, a.body)
	}
	var ans server.LinkRunAnswer
	if err := json.Unmarshal(a.body, &ans); err != nil {
		t.Fatal(err)
	}
	denied(t, before, key)
	after := before.restart(t, cfg)
	if rec := after.record(runID); indexOf(rec, event.RunEgress, nil) >= 0 {
		t.Fatalf("a run.egress before run.started: %v", types(rec))
	}
	e := &edgeRun{r: after, key: key, a: &ans}
	if got := e.post(t, started(runID, nil), applied(runID, ans.Applied)); got.status != http.StatusAccepted {
		t.Fatalf("the first batch: %d %s", got.status, got.body)
	}
	want := []string{event.RunRegistered, event.RunStarted, event.PolicyApplied, event.RunEgress}
	if got := types(after.record(runID)); !slices.Equal(got, want) {
		t.Errorf("the record %v; want %v", got, want)
	}
}

// TestATerminatedHostAfterAReopen pins the run's CA across a restart: a request through
// the reopened run's proxy to a host it ends TLS for, from a client that trusts the run
// answer's certificate_authority alone, reaches the host.
func TestATerminatedHostAfterAReopen(t *testing.T) {
	certFile, keyFile, roots := testCertificate(t, t.TempDir())
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, `{"type":"message"}`)
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	url := "https://localhost:" + port + "/v1"
	c := gatewayControl(t)
	cfg := caConfig(t, c)
	cfg.Dir = t.TempDir()
	cfg.Credentials[0].Endpoint = url
	gateway.SetUpstreamRoots(&cfg, roots)
	before := startRemote(t, c, cfg)
	runID := event.NewRunID()
	key := runKeyFor(t, runID, nil)
	e := before.open(t, key, server.LinkRunRequest{Wall: true})
	after := before.restart(t, cfg)

	trusted := x509.NewCertPool()
	if !trusted.AppendCertsFromPEM([]byte(e.a.CertificateAuthority)) {
		t.Fatal("the run answer has no certificate_authority")
	}
	agent := after.relay(t, key)
	agent.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: trusted}
	req, _ := http.NewRequest(http.MethodPost, url+"/messages", strings.NewReader(`{"model":"m"}`))
	req.Header.Set("X-Api-Key", link.KeyPlaceholder("first"))
	resp, err := agent.Do(req)
	if err != nil {
		t.Fatalf("a request to the terminated host after the reopen: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(b) != `{"type":"message"}` {
		t.Errorf("the terminated host's answer: %d %s", resp.StatusCode, b)
	}
	if got := len(c.attached()); got != 2 {
		t.Errorf("%d attaches; want 2", got)
	}
}

// TestTheSweepReadsTheRunDirectories pins the CA key sweep of a separate gateway whose
// records RunDir makes as <directory>/<run id>: the sweep removes the files kept to
// reopen a run of a record there that has not changed for longer than its age.
func TestTheSweepReadsTheRunDirectories(t *testing.T) {
	dir := t.TempDir()
	runs := filepath.Join(dir, "runs")
	old := fakeRecord(t, dir, time.Now().Add(-2*time.Minute), event.RunRegistered, event.RunStarted)
	fresh := fakeRecord(t, dir, time.Now(), event.RunRegistered)
	cfg := gateway.Config{RunDir: func(id string) string { return filepath.Join(runs, id) }}
	gateway.SetCASweep(&cfg, time.Hour, time.Minute)
	r := startRemote(t, nil, cfg)
	eventually(t, "the sweep at Start", func() bool { return len(keptLeft(dir, old)) == 0 })
	gateway.SweepCA(r.g, time.Now())
	if left := secretsLeft(dir, fresh); len(left) != len(secretNames) {
		t.Errorf("the record changed now keeps only %v", left)
	}
}
