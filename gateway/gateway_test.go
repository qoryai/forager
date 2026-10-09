package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// TestStartRefusesWhatItDoesNotServe pins the checks before anything starts: a separate
// gateway, a heartbeat the discovery cannot announce, no place for the records.
func TestStartRefusesWhatItDoesNotServe(t *testing.T) {
	dir := t.TempDir()
	for name, cfg := range map[string]gateway.Config{
		"an address":                  {Dir: dir, Listen: "127.0.0.1:0"},
		"a certificate":               {Dir: dir, TLS: &gateway.TLS{}},
		"a heartbeat of a part":       {Dir: dir, Heartbeat: 1500 * time.Millisecond},
		"a heartbeat over the bound":  {Dir: dir, Heartbeat: 301 * time.Second},
		"no directory":                {},
		"a policy the schema refuses": {Dir: dir, Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "everything"}}},
	} {
		if g, err := gateway.Start(context.Background(), cfg); err == nil {
			g.Close(context.Background())
			t.Errorf("%s: started", name)
		}
	}
}

// TestTheLocalLink pins the link: a private directory and a socket of the user's
// alone, the discovery on it, and a connection that opens without the secret closed
// unanswered.
func TestTheLocalLink(t *testing.T) {
	h := start(t, gateway.Config{Heartbeat: 5 * time.Second})
	l := h.g.LocalLink()
	dir := filepath.Dir(l.Socket)
	if !strings.HasPrefix(filepath.Base(dir), link.LinkDirPrefix) || filepath.Base(l.Socket) != link.LinkSocketName {
		t.Errorf("socket %s", l.Socket)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != link.LinkDirMode {
		t.Errorf("the link's directory: %v %v", fi.Mode(), err)
	}
	if fi, err := os.Lstat(l.Socket); err != nil || fi.Mode().Perm() != link.LinkSocketMode {
		t.Errorf("the socket: %v %v", fi.Mode(), err)
	}
	if len(l.Secret) < 22 || l.Proxy != h.g.Addr() || !slices.Contains(l.Files, link.File{Path: dir, What: "the gateway's link directory", Kept: true}) || !slices.Contains(l.Files, link.File{Path: h.dir, What: "the gateway's directory", Kept: true}) {
		t.Errorf("local %+v", l)
	}
	d, err := h.link.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.Events.URL != "http://localhost/v1/events" || !slices.Equal(d.Events.Types, []string{"*"}) || d.Events.IntervalSeconds != 5 ||
		d.Run.URL != "http://localhost/v1/run-configuration" || d.Proxy == nil || d.Proxy.Address != h.g.Addr() {
		t.Errorf("discovery %+v", d)
	}
	for name, open := range map[string]string{
		"a wrong secret": "QORY-LINK " + strings.Repeat("x", len(l.Secret)) + "\nGET /.well-known/qory-configuration HTTP/1.1\r\nHost: localhost\r\n\r\n",
		"no preamble":    "GET /.well-known/qory-configuration HTTP/1.1\r\nHost: localhost\r\n\r\n" + strings.Repeat("\r\n", 40),
	} {
		c, err := net.Dial("unix", l.Socket)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, open)
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if b, err := io.ReadAll(c); len(b) != 0 || err != nil {
			t.Errorf("%s: answered %q, %v", name, b, err)
		}
		c.Close()
	}
	h.close()
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the link's directory after Close: %v", err)
	}
}

// TestTheLinkRefusesAnotherUsersPeer pins the link's first check: a peer that is not
// the gateway's user, by the uid the kernel recorded, is closed unanswered, even with
// the right preamble and secret.
func TestTheLinkRefusesAnotherUsersPeer(t *testing.T) {
	cfg := gateway.Config{}
	gateway.SetLinkUID(&cfg, os.Getuid()+1)
	h := start(t, cfg)
	l := h.g.LocalLink()
	c, err := net.Dial("unix", l.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := link.WriteLinkPreamble(c, l.Secret); err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "GET /.well-known/qory-configuration HTTP/1.1\r\nHost: localhost\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if b, err := io.ReadAll(c); len(b) != 0 || err != nil {
		t.Errorf("answered %q, %v", b, err)
	}
	if _, err := h.link.Discover(context.Background()); err == nil {
		t.Error("the session's client of another user was answered")
	}
}

// TestARunWithNoServer pins a run with files only: the answer, the session's events
// numbered once each into the run's record, and its run.exited ending the run's
// gateway side.
func TestARunWithNoServer(t *testing.T) {
	var events strings.Builder
	h := start(t, gateway.Config{
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example"}}},
		Events: &syncWriter{w: &events},
	})
	labels := map[string]string{"repository": "example-namespace/project"}
	a := h.open(server.LinkRunRequest{Labels: labels, Passes: []string{"HOME"}})
	var pol map[string]any
	if err := json.Unmarshal(a.Policy, &pol); err != nil || a.Digest == "" || pol["egress"].(map[string]any)["mode"] != "enforce" {
		t.Errorf("policy %s, digest %q", a.Policy, a.Digest)
	}
	if a.CertificateAuthority != "" || len(a.ProxySecret) < 22 || a.Labels["repository"] != "example-namespace/project" || a.Applied == nil {
		t.Errorf("answer %+v", a)
	}
	runID := a.RunID
	if lines := h.record(runID); len(lines) != 0 {
		t.Errorf("before the session's first batch: %v", types(lines))
	}
	first := []map[string]any{started(runID, labels), applied(runID, a.Applied), logged(runID)}
	if d := h.post(first...); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	// The same batch again, as a session sends one whose answer it did not read.
	if d := h.post(first...); !d.Accepted() {
		t.Fatalf("the first batch again: %+v", d)
	}
	if d := h.post(heartbeat(runID), exited(runID)); !d.Accepted() {
		t.Fatalf("the last batch: %+v", d)
	}
	if d := h.post(heartbeat(runID)); d.Status != http.StatusGone || d.End != "run_closed" || d.From != "gateway" {
		t.Errorf("after run.exited: %+v", d)
	}
	if d := h.close(); d != (gateway.Delivery{}) {
		t.Errorf("delivery %+v", d)
	}
	lines := h.record(runID)
	want := []string{event.RunStarted, event.PolicyApplied, event.RunLog, event.RunHeartbeat, event.RunExited}
	if !slices.Equal(types(lines), want) {
		t.Fatalf("record %v", types(lines))
	}
	for i, l := range lines {
		if l.Sequence != seq(i+1) || l.Subject != runID {
			t.Errorf("event %d: %+v", i, l)
		}
	}
	if n := strings.Count(events.String(), "\n"); n != len(want) {
		t.Errorf("events printed: %d", n)
	}
}

// TestRunRequestsTheLinkRefuses pins the refusals of a run request: a body the schema
// refuses and a narrowing, invalid_request; a run id already used, run_id_used; and a
// reload or a batch of a run the gateway does not hold.
func TestRunRequestsTheLinkRefuses(t *testing.T) {
	h := start(t, gateway.Config{})
	a := h.open(server.LinkRunRequest{})
	_, err := h.tryOpen(server.LinkRunRequest{RunID: a.RunID})
	var r *accesskey.Refusal
	if !errors.As(err, &r) || r.Code != "run_id_used" || r.Status != http.StatusConflict || r.From != "gateway" {
		t.Errorf("the same run id: %v", err)
	}
	c := raw(t, h.g.LocalLink())
	id := event.NewRunID()
	for name, body := range map[string]string{
		"a narrowing":       `{"version":1,"run_id":"` + id + `","wall":false,"narrowing":{"egress":{"allow":["api.example"]}}}`,
		"an unknown member": `{"version":1,"run_id":"` + id + `","wall":false,"policy":{}}`,
		"an upper-case id":  `{"version":1,"run_id":"` + strings.ToUpper(id) + `","wall":false}`,
		"no wall":           `{"version":1,"run_id":"` + id + `"}`,
		"a member twice":    `{"version":1,"run_id":"` + id + `","wall":false,"wall":true}`,
		"a pass no name":    `{"version":1,"run_id":"` + id + `","wall":false,"passes":["A B"]}`,
		"an image no ref":   `{"version":1,"run_id":"` + id + `","wall":false,"images":{"definitions":[{"name":"a"}]}}`,
		"an image member":   `{"version":1,"run_id":"` + id + `","wall":false,"images":{"default":"a","extra":1}}`,
		"no JSON":           `{`,
	} {
		if status, body := rawPost(t, c, "/v1/run-configuration", "application/json", body); status != http.StatusBadRequest || !strings.Contains(body, `"invalid_request"`) || !strings.Contains(body, `"gateway"`) {
			t.Errorf("%s: %d %s", name, status, body)
		}
	}
	// The gateway's own codes read as the gateway's refusal, with the code alone.
	if status, got := h.refusalOf("/v1/run-configuration", openBody(a.RunID)); status != http.StatusConflict || got["message"] != "the gateway refused the run: run_id_used" {
		t.Errorf("the same run id: %d %v", status, got)
	}
	if status, got := h.refusalOf("/v1/run-configuration", `{`); status != http.StatusBadRequest || got["message"] != "the gateway refused the run: invalid_request" {
		t.Errorf("no JSON: %d %v", status, got)
	}
	// None of those opened a run, so the id is unused still.
	if _, err := h.tryOpen(server.LinkRunRequest{RunID: id}); err != nil {
		t.Errorf("the id after refusals: %v", err)
	}
	if _, err := h.link.Reload(context.Background(), server.LocalOrigin+"/v1/run-configuration", event.NewRunID()); !errors.As(err, &r) || r.Code != "invalid_request" {
		t.Errorf("a reload of no run: %v", err)
	}
	if d := h.post(heartbeat(event.NewRunID())); d.Status != http.StatusBadRequest || d.Code != "invalid_request" {
		t.Errorf("a batch of no run: %+v", d)
	}
	if status, _ := rawPost(t, c, "/v1/nothing", "application/json", "{}"); status != http.StatusNotFound {
		t.Errorf("another path: %d", status)
	}
}

// TestTheSharedProxyServesARunBySecret pins agent traffic: a connection that opens with
// the run's proxy secret is decided by the run's policy, and each decision is the run's
// dev.qory.run.egress, after its run.started and policy_applied; another secret is
// refused unanswered.
func TestTheSharedProxyServesARunBySecret(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	h := start(t, gateway.Config{Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"127.0.0.1"}}}})
	a := h.open(server.LinkRunRequest{})
	runID := a.RunID
	c := relay(h.g.Addr(), a.ProxySecret)
	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(b) != "ok" {
		t.Errorf("allowed: %d %q", resp.StatusCode, b)
	}
	resp, err = c.Get("http://denied.example/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("denied: %d", resp.StatusCode)
	}
	for range 2 {
		if _, err := relay(h.g.Addr(), strings.Repeat("x", len(a.ProxySecret))).Get(origin.URL); err == nil {
			t.Error("another secret was served")
		}
	}
	// Told once per gateway, in today's session's words.
	eventually(t, "the refusal's report", func() bool { return h.reported("was refused") })
	if got := h.reportsWith("was refused"); len(got) != 1 || got[0] != "a connection to the proxy that was not the run's relay was refused" {
		t.Errorf("reports %q", got)
	}
	h.post(started(runID, nil), applied(runID, a.Applied))
	// The session's own exit at its time limit is the one reason its batch carries.
	timedOut := exited(runID)
	timedOut["data"].(map[string]any)["reason"] = "timeout"
	if d := h.post(timedOut); !d.Accepted() {
		t.Errorf("a run.exited timeout: %+v", d)
	}
	h.close()
	lines := h.record(runID)
	if want := []string{event.RunStarted, event.PolicyApplied, event.RunEgress, event.RunEgress, event.RunExited}; !slices.Equal(types(lines), want) {
		t.Fatalf("record %v", types(lines))
	}
	if lines[2].Data["host"] != "127.0.0.1" || lines[2].Data["decision"] != "allowed" || lines[3].Data["host"] != "denied.example" || lines[3].Data["decision"] != "denied" {
		t.Errorf("egress %v %v", lines[2].Data, lines[3].Data)
	}
	// The run ended: its secret is refused now.
	if _, err := c.Get(origin.URL); err == nil {
		t.Error("an ended run's secret was served")
	}
}

// TestBatchesTheLinkRefuses pins each of the README's batch rules: a batch that breaks
// one is a 400 invalid_request, nothing of it is numbered, and the run ends at the
// gateway, session_lost; every later request of the run's is a 410 run_closed from the
// gateway.
func TestBatchesTheLinkRefuses(t *testing.T) {
	h := start(t, gateway.Config{})
	labels := map[string]string{"repository": "example-namespace/project"}
	cases := map[string]func(runID string, a *server.LinkRunAnswer) []map[string]any{
		"another run's event": func(id string, _ *server.LinkRunAnswer) []map[string]any {
			return []map[string]any{heartbeat(id), heartbeat(event.NewRunID())}
		},
		"a ping": func(id string, _ *server.LinkRunAnswer) []map[string]any {
			return []map[string]any{ev(id, event.Ping, map[string]any{"forager_version": "x", "events": []string{"*"}, "contract_version": 1, "interval_seconds": 30})}
		},
		"an egress": func(id string, _ *server.LinkRunAnswer) []map[string]any {
			return []map[string]any{ev(id, event.RunEgress, map[string]any{"host": "a.example", "port": 443, "method": "CONNECT", "decision": "allowed", "mode": "observe", "rule": "", "outcome": "connected"})}
		},
		"a run.started the gateway opened": func(id string, _ *server.LinkRunAnswer) []map[string]any {
			s := started(id, labels)
			s["data"].(map[string]any)["opened_by"] = "gateway"
			return []map[string]any{s}
		},
		"a second run.started": func(id string, _ *server.LinkRunAnswer) []map[string]any {
			return []map[string]any{started(id, labels)}
		},
		"an event after run.exited": func(id string, _ *server.LinkRunAnswer) []map[string]any {
			return []map[string]any{exited(id), heartbeat(id)}
		},
		"a run.exited session_lost": func(id string, _ *server.LinkRunAnswer) []map[string]any {
			e := exited(id)
			e["data"].(map[string]any)["reason"] = "session_lost"
			return []map[string]any{e}
		},
		"a run.exited run_closed": func(id string, _ *server.LinkRunAnswer) []map[string]any {
			e := exited(id)
			e["data"].(map[string]any)["reason"] = "run_closed"
			return []map[string]any{e}
		},
		"a policy_applied of another mode": func(id string, a *server.LinkRunAnswer) []map[string]any {
			p := applied(id, a.Applied)
			p["data"].(map[string]any)["mode"] = "enforce"
			return []map[string]any{p}
		},
		"a policy_applied without its source": func(id string, a *server.LinkRunAnswer) []map[string]any {
			p := applied(id, a.Applied)
			p["data"].(map[string]any)["terminated"] = []string{"a.example"}
			return []map[string]any{p}
		},
		"a run.exited quiet": func(id string, _ *server.LinkRunAnswer) []map[string]any {
			e := exited(id)
			e["data"].(map[string]any)["reason"] = "quiet"
			return []map[string]any{e}
		},
		"a run.refused after run.started": func(id string, _ *server.LinkRunAnswer) []map[string]any {
			return []map[string]any{ev(id, event.RunRefused, map[string]any{"code": "image_unknown", "names": []string{"base"}})}
		},
		"a run.refused of a gateway's code": func(id string, _ *server.LinkRunAnswer) []map[string]any {
			return []map[string]any{ev(id, event.RunRefused, map[string]any{"code": "run_id_used"})}
		},
		"a run.refused of the server's code": func(id string, _ *server.LinkRunAnswer) []map[string]any {
			return []map[string]any{ev(id, event.RunRefused, map[string]any{"code": "run_closed"})}
		},
		"a run.refused with a gateway's name": func(id string, _ *server.LinkRunAnswer) []map[string]any {
			return []map[string]any{ev(id, event.RunRefused, map[string]any{"code": "image_unknown", "names": []string{"labels.repository=x"}})}
		},
	}
	runs := map[string]string{}
	for name, batch := range cases {
		a := h.open(server.LinkRunRequest{Labels: labels})
		runs[name] = a.RunID
		if d := h.post(started(a.RunID, labels), applied(a.RunID, a.Applied)); !d.Accepted() {
			t.Fatalf("%s: the first batch: %+v", name, d)
		}
		if d := h.post(batch(a.RunID, a)...); d.Status != http.StatusBadRequest || d.Code != "invalid_request" || d.End != "run_closed" || d.From != "gateway" {
			t.Errorf("%s: %+v", name, d)
		}
		if d := h.post(heartbeat(a.RunID)); d.Status != http.StatusGone || d.End != "run_closed" || d.From != "gateway" {
			t.Errorf("%s: after the refusal: %+v", name, d)
		}
		b, _ := json.Marshal([]map[string]any{heartbeat(a.RunID)})
		if status, got := h.refusalOf("/v1/events", string(b)); status != http.StatusGone || got["message"] != "the gateway refused the run: run_closed" {
			t.Errorf("%s: the 410's message: %d %v", name, status, got)
		}
		var r *accesskey.Refusal
		if _, err := h.link.Reload(context.Background(), server.LocalOrigin+"/v1/run-configuration", a.RunID); !errors.As(err, &r) || r.Status != http.StatusGone || r.Code != "run_closed" || r.From != "gateway" {
			t.Errorf("%s: a reload after the refusal: %v", name, err)
		}
	}
	// What the lenient decoder reads one way and the record's reader another: a member
	// name twice in one object, where a decoder may keep either copy, and bytes that
	// are not UTF-8. Each is a batch of its own, after the first when it says so.
	twice := func(evs []map[string]any, one, both string) []byte {
		b, err := json.Marshal(evs)
		if err != nil || !bytes.Contains(b, []byte(one)) {
			t.Fatalf("%s is not in %s", one, b)
		}
		return bytes.Replace(b, []byte(one), []byte(both), 1)
	}
	rawCases := map[string]func(runID string, a *server.LinkRunAnswer) (bool, []byte){
		"a run.exited with its reason twice": func(id string, _ *server.LinkRunAnswer) (bool, []byte) {
			e := exited(id)
			e["data"].(map[string]any)["reason"] = "timeout"
			return true, twice([]map[string]any{e}, `"reason":"timeout"`, `"reason":"session_lost","reason":"timeout"`)
		},
		"a run.started with opened_by twice": func(id string, _ *server.LinkRunAnswer) (bool, []byte) {
			return false, twice([]map[string]any{started(id, labels)}, `"opened_by":"session"`, `"opened_by":"gateway","opened_by":"session"`)
		},
		"a policy_applied with its mode twice": func(id string, a *server.LinkRunAnswer) (bool, []byte) {
			p := applied(id, a.Applied)
			mode := p["data"].(map[string]any)["mode"].(string)
			return true, twice([]map[string]any{p}, `"mode":"`+mode+`"`, `"mode":"enforce","mode":"`+mode+`"`)
		},
		"a run.started not in UTF-8": func(id string, _ *server.LinkRunAnswer) (bool, []byte) {
			return false, twice([]map[string]any{started(id, labels)}, `"command":"true"`, "\"command\":\"tr\xffue\"")
		},
	}
	rawRuns := map[string]string{}
	for name, batch := range rawCases {
		a := h.open(server.LinkRunRequest{Labels: labels})
		first, body := batch(a.RunID, a)
		if first {
			rawRuns[name] = a.RunID
			if d := h.post(started(a.RunID, labels), applied(a.RunID, a.Applied)); !d.Accepted() {
				t.Fatalf("%s: the first batch: %+v", name, d)
			}
		}
		d, err := h.link.Deliver(context.Background(), server.LocalOrigin+"/v1/events", event.NewID(), body, "")
		if err != nil {
			t.Fatal(err)
		}
		if d.Status != http.StatusBadRequest || d.Code != "invalid_request" || d.End != "run_closed" || d.From != "gateway" {
			t.Errorf("%s: %+v", name, d)
		}
		if d := h.post(heartbeat(a.RunID)); d.Status != http.StatusGone || d.End != "run_closed" || d.From != "gateway" {
			t.Errorf("%s: after the refusal: %+v", name, d)
		}
		if !first {
			if lines := h.record(a.RunID); len(lines) != 0 {
				t.Errorf("%s: record %v", name, types(lines))
			}
		}
	}
	maps.Copy(runs, rawRuns)
	// A run.started whose labels are not the run's, before any.
	a := h.open(server.LinkRunRequest{Labels: labels})
	if d := h.post(started(a.RunID, map[string]string{"repository": "other"})); d.Status != http.StatusBadRequest || d.End != "run_closed" {
		t.Errorf("other labels: %+v", d)
	}
	if d := h.close(); !d.RunClosed || d.ClosedBy != "gateway" || d.Reason != "run_closed" {
		t.Errorf("delivery %+v", d)
	}
	for name, runID := range runs {
		lines := h.record(runID)
		if want := []string{event.RunStarted, event.PolicyApplied, event.RunExited}; !slices.Equal(types(lines), want) {
			t.Errorf("%s: record %v", name, types(lines))
			continue
		}
		if x := lines[2].Data; x["reason"] != "session_lost" || x["state"] != "failed" || x["exit_code"] != -1.0 {
			t.Errorf("%s: run.exited %v", name, x)
		}
	}
	if lines := h.record(a.RunID); len(lines) != 0 {
		t.Errorf("a run that never started: %v", types(lines))
	}
}

// TestASessionThatSendsNothingIsLost pins liveness: a run whose session asks nothing
// for the quiet time ends, session_lost, and its session's next request is a 410; one
// that keeps asking lives.
func TestASessionThatSendsNothingIsLost(t *testing.T) {
	cfg := gateway.Config{}
	gateway.SetQuiet(&cfg, 400*time.Millisecond)
	h := start(t, cfg)
	lost := h.open(server.LinkRunRequest{})
	kept := h.open(server.LinkRunRequest{})
	h.post(started(lost.RunID, nil))
	h.post(started(kept.RunID, nil))
	for range 8 {
		time.Sleep(100 * time.Millisecond)
		if d := h.post(heartbeat(kept.RunID)); !d.Accepted() {
			t.Fatalf("a run that keeps asking: %+v", d)
		}
	}
	if d := h.post(heartbeat(lost.RunID)); d.Status != http.StatusGone || d.End != "run_closed" || d.From != "gateway" {
		t.Errorf("a lost run: %+v", d)
	}
	h.post(exited(kept.RunID))
	if d := h.close(); !d.RunClosed || d.ClosedBy != "gateway" {
		t.Errorf("delivery %+v", d)
	}
	lines := h.record(lost.RunID)
	if l := lines[len(lines)-1]; l.Type != event.RunExited || l.Data["reason"] != "session_lost" || l.Data["exit_code"] != -1.0 || l.Data["state"] != "failed" {
		t.Errorf("lost: %v", l)
	}
	if lines := h.record(kept.RunID); lines[len(lines)-1].Data["reason"] != nil {
		t.Errorf("kept: %v", lines[len(lines)-1])
	}
	if !h.reported("session_lost") {
		t.Error("the user was not told")
	}
}

// syncWriter is a writer safe for the gateway's goroutines.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(b)
}

func seq(n int) string { return fmt.Sprintf("%010d", n) }

// TestAWalledRunWithACredential pins what a run behind a wall is given: the run's
// authority, the credential's placeholder, the variable it is read from as reserved,
// the image the policy resolves to, and in applied the credential and the terminated
// host; a placeholder the run passes is placeholder_conflict, and the same policy
// without a wall wall_required, each a 403 from the gateway.
func TestAWalledRunWithACredential(t *testing.T) {
	t.Setenv("GATEWAY_TEST_SECRET", "s3cret-value-of-the-test")
	ref := "registry.example/agents/base@sha256:" + strings.Repeat("0", 64)
	h := start(t, gateway.Config{
		Credentials: []gateway.Credential{{Name: "api", Env: "GATEWAY_TEST_SECRET", Hosts: []string{"api.example"}, Scheme: "bearer", Placeholders: []string{"API_TOKEN"}}},
		Policy:      &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example"}}, Credentials: []gateway.PolicyCredential{{Name: "api"}}},
	})
	h.secrets = append(h.secrets, "s3cret-value-of-the-test", ref)
	if l := h.g.LocalLink(); !slices.Equal(l.Reserved, []string{"GATEWAY_TEST_SECRET"}) {
		t.Errorf("reserved %v", l.Reserved)
	}
	images := &server.LinkImages{Default: "base", Definitions: []server.LinkImage{{Name: "base", Ref: ref, Runtime: "sysbox-runc"}}}
	a := h.open(server.LinkRunRequest{Wall: true, Images: images, Passes: []string{"HOME"}})
	if !strings.HasPrefix(a.CertificateAuthority, "-----BEGIN CERTIFICATE-----") || !slices.Equal(a.Placeholders, []string{"API_TOKEN"}) ||
		!slices.Equal(a.Reserved, []string{"GATEWAY_TEST_SECRET"}) || a.Image == nil || a.Image.Name != "base" || a.Image.Ref != ref || a.Image.Runtime != "sysbox-runc" {
		t.Errorf("answer %+v", a)
	}
	var members map[string]any
	json.Unmarshal(a.Applied, &members)
	if creds, _ := members["credentials"].([]any); len(creds) != 1 || !slices.Equal(anyStrings(members["terminated"]), []string{"api.example"}) {
		t.Errorf("applied %s", a.Applied)
	}
	if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
		t.Errorf("the session's policy_applied: %+v", d)
	}
	var r *accesskey.Refusal
	if _, err := h.tryOpen(server.LinkRunRequest{Wall: true, Images: images, Passes: []string{"API_TOKEN"}}); !errors.As(err, &r) || r.Code != "placeholder_conflict" || r.Status != http.StatusForbidden || r.From != "gateway" || !slices.Equal(r.Names, []string{"API_TOKEN"}) {
		t.Errorf("a placeholder the run passes: %v", err)
	}
	if _, err := h.tryOpen(server.LinkRunRequest{}); !errors.As(err, &r) || r.Code != "wall_required" || r.Status != http.StatusForbidden || r.From != "gateway" || !slices.Equal(r.Names, []string{"credentials"}) {
		t.Errorf("no wall: %v", err)
	}
	// Each message is today's session's error text.
	want := "API_TOKEN is a placeholder of a credential the gateway holds outside the enclosure, and the run passes a value for it inside: placeholder_conflict: API_TOKEN"
	body, _ := json.Marshal(server.LinkRunRequest{Version: 1, RunID: event.NewRunID(), Wall: true, Images: images, Passes: []string{"API_TOKEN"}})
	if _, got := h.refusalOf("/v1/run-configuration", string(body)); got["message"] != want {
		t.Errorf("placeholder_conflict's message %q", got["message"])
	}
	want = "the policy selects credentials or tools or has path rules, which need a wall: without one a program that ignores the proxy is bound by none of them"
	if _, got := h.refusalOf("/v1/run-configuration", openBody(event.NewRunID())); got["message"] != want {
		t.Errorf("wall_required's message %q", got["message"])
	}
	h.post(exited(a.RunID))
	h.close()
}

func anyStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, len(list))
	for i, x := range list {
		out[i], _ = x.(string)
	}
	return out
}

// TestARunThatFailsWithoutACodeIsAnInternal500 pins a failure without a code: the
// gateway tells the user nothing of it, and answers 500 internal from the gateway with
// the error's text, which the session returns as its error.
func TestARunThatFailsWithoutACodeIsAnInternal500(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h := start(t, gateway.Config{RunDir: func(id string) string { return filepath.Join(file, id) }})
	runID := event.NewRunID()
	status, body := rawPost(t, raw(t, h.g.LocalLink()), "/v1/run-configuration", server.LinkContentType, `{"version":1,"run_id":"`+runID+`","wall":false}`)
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("%d %s", status, body)
	}
	want := "mkdir " + file + ": not a directory"
	if status != http.StatusInternalServerError || got["error"] != "internal" || got["from"] != "gateway" || got["message"] != want || len(got) != 3 {
		t.Errorf("%d %s, want the message %q", status, body, want)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.reports) != 0 {
		t.Errorf("reported %q", h.reports)
	}
}

// TestRefuseOpen pins how a refusal passes on: the server's keeps its status and from
// apiary, a code Forager decides among them; the gateway's own of such a code is a
// 403; and an error's text in a 500's message keeps tab and newline, has a space for
// any other control character, and is cut to 8192 characters.
func TestRefuseOpen(t *testing.T) {
	for _, c := range []struct {
		err    error
		status int
		from   string
	}{
		{&accesskey.Refusal{Code: "run_configuration_invalid", Status: http.StatusUnprocessableEntity, From: "apiary"}, http.StatusUnprocessableEntity, "apiary"},
		{&accesskey.Refusal{Code: "run_configuration_invalid", Status: http.StatusOK}, http.StatusForbidden, "gateway"},
		{&accesskey.Refusal{Code: "instance_limit", Status: http.StatusConflict, From: "apiary"}, http.StatusConflict, "apiary"},
	} {
		w := httptest.NewRecorder()
		gateway.RefuseOpen(w, c.err)
		var r server.LinkRefusal
		json.Unmarshal(w.Body.Bytes(), &r)
		if w.Code != c.status || r.From != c.from {
			t.Errorf("%v: %d %s", c.err, w.Code, w.Body)
		}
	}
	if got := gateway.MessageOf(errors.New("one\ttwo\nthree\rfour\x00five\x1bsix\x7fseven\u009beight\u0080nine\u009fend")); got != "one\ttwo\nthree four five six seven eight nine end" {
		t.Errorf("%q", got)
	}
	long := gateway.MessageOf(errors.New(strings.Repeat("é", 9000)))
	if n := len([]rune(long)); n != 8192 || long != strings.Repeat("é", 8192) {
		t.Errorf("a long text: %d characters", n)
	}
	w := httptest.NewRecorder()
	gateway.RefuseOpen(w, errors.New("a\rb"))
	if w.Code != http.StatusInternalServerError || w.Body.String() != `{"error":"internal","message":"a b","from":"gateway"}` {
		t.Errorf("%d %s", w.Code, w.Body)
	}
	schema, err := contracts.Compile("link-refusal.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	gateway.RefuseOpen(w, errors.New("a\u009bb\x01c\nd\t"+strings.Repeat("x", 9000)))
	doc, err := contracts.Decode("link-refusal.json", w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Errorf("link-refusal.schema.json refuses %s: %v", w.Body, err)
	}
}
