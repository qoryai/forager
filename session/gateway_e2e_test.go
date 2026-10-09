package session_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
)

// The runs of this file are end to end: a real session.Run speaks to a real gateway,
// gateway.Start, on its local link, the gateway alone without a server and then in
// front of a server of the contract, the reference receiver.

// realGateway is a gateway the spec's run speaks to, started with cfg, which keeps each
// run's record, events.jsonl, in the spec's run directory beside the session's own.
type realGateway struct {
	g *gateway.Gateway

	mu      sync.Mutex
	reports []string
}

// startGateway starts a gateway with cfg for the spec's run and points the spec at it,
// until the test ends.
func startGateway(t *testing.T, sp *session.Spec, cfg gateway.Config) *realGateway {
	t.Helper()
	rg := &realGateway{}
	runs := sp.RunsDir
	cfg.RunDir = func(id string) string { return filepath.Join(runs, id) }
	cfg.Report = func(l string) {
		t.Log("the gateway reported:", l)
		rg.mu.Lock()
		rg.reports = append(rg.reports, l)
		rg.mu.Unlock()
	}
	g, err := gateway.Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	rg.g = g
	t.Cleanup(func() { rg.close(t) })
	sp.Gateway = session.LocalGateway(g.LocalLink())
	return rg
}

// close ends the gateway, which numbers each run's last events, and says what its runs
// came to.
func (rg *realGateway) close(t *testing.T) gateway.Delivery {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, err := rg.g.Close(ctx)
	if err != nil {
		t.Errorf("the gateway's close: %v", err)
	}
	return d
}

// record is the gateway's record of a run: its events.jsonl, decoded.
func record(t *testing.T, res *session.Result) []map[string]any {
	t.Helper()
	f, err := os.Open(filepath.Join(res.Dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 4<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// TestARunThroughARealGateway is a run end to end through the gateway alone: the
// gateway opens it with the machine's policy, the agent's request reaches the gateway's
// proxy through the forwarder and is decided there, the gateway numbers the run's
// stream, the session's events among it, and its record and the session's agree on
// what happened; nothing is undelivered and no secret is in either.
func TestARunThroughARealGateway(t *testing.T) {
	t.Parallel()
	sp := spec(t, "FAKE_DENIED_URL=http://denied.invalid/a", "FAKE_EXIT=0")
	sp.Labels = map[string]string{"repository": "example-namespace/project"}
	rg := startGateway(t, &sp, gateway.Config{Version: "test", Heartbeat: time.Second,
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example"}}}})
	link := rg.g.LocalLink()
	res, err := runWithSettingsEnv(t, sp)
	if err != nil {
		t.Fatal(err)
	}
	if d := rg.close(t); d != (gateway.Delivery{}) {
		t.Errorf("delivery %+v", d)
	}
	if res.ExitCode != 0 || res.State != "succeeded" || res.RunClosed || res.Undelivered != 0 {
		t.Errorf("result %+v", res)
	}
	own, numbered := events(t, res), record(t, res)
	if got := types(numbered); len(got) < 4 || got[0] != "dev.qory.run.started" || got[1] != "dev.qory.run.policy_applied" || got[len(got)-1] != "dev.qory.run.exited" {
		t.Fatalf("the gateway's record %v", got)
	}
	if !slices.Equal(types(own), ofTypes(numbered, types(own))) {
		t.Errorf("the session recorded %v, the gateway numbered %v", types(own), types(numbered))
	}
	if l := data(numbered[0])["labels"].(map[string]any); l["repository"] != "example-namespace/project" {
		t.Errorf("run.started labels %v", l)
	}
	if c := data(numbered[0])["credential"]; c != "none" {
		t.Errorf("run.started credential %v; want none on the local link", c)
	}
	applied := data(numbered[1])
	if applied["mode"] != "enforce" || applied["source"] != "config" || fmt.Sprint(applied["allow"]) != "[api.example]" || applied["variables"] == nil {
		t.Errorf("policy_applied %v", applied)
	}
	egress := ofType(numbered, "dev.qory.run.egress")
	if len(egress) != 1 || data(egress[0])["host"] != "denied.invalid" || data(egress[0])["decision"] != "denied" {
		t.Errorf("run.egress %v", egress)
	}
	for _, name := range []string{"events.jsonl", "session.jsonl"} {
		b, _ := os.ReadFile(filepath.Join(res.Dir, name))
		if strings.Contains(string(b), link.Secret) {
			t.Errorf("%s holds the link secret", name)
		}
	}
}

// ofTypes are the types of the events of evs whose type is among those given, in order.
func ofTypes(evs []map[string]any, among []string) []string {
	var out []string
	for _, ty := range types(evs) {
		if slices.Contains(among, ty) {
			out = append(out, ty)
		}
	}
	return out
}

// TestARealGatewayRefusesARunThatNeedsAWall pins wall_required end to end: a machine
// policy with path rules and a run without a wall is no run, with the error such a run
// always had, word for word, and no run at the gateway.
func TestARealGatewayRefusesARunThatNeedsAWall(t *testing.T) {
	t.Parallel()
	sp := spec(t)
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	startGateway(t, &sp, gateway.Config{Policy: &gateway.Policy{Version: 1,
		Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example"}, Paths: map[string][]string{"api.example": {"/v1/*"}}}}})
	_, err := session.Run(context.Background(), sp)
	const want = "the policy selects credentials or tools or has path rules, which need a wall: without one a program that ignores the proxy is bound by none of them"
	if err == nil || err.Error() != want {
		t.Fatalf("%v, want %q", err, want)
	}
	if got := types(record(t, &session.Result{Dir: filepath.Join(sp.RunsDir, sp.RunID)})); len(got) != 0 {
		t.Errorf("the gateway recorded %v", got)
	}
	if own := events(t, &session.Result{Dir: filepath.Join(sp.RunsDir, sp.RunID)}); len(own) != 0 {
		t.Errorf("the session recorded %v", types(own))
	}
}

// control is a server of the contract in front of the reference receiver, with a run
// configuration the test may change during a run and close every run with.
type control struct {
	srv   *httptest.Server
	key   *accesskey.Key
	pin   accesskey.Pin
	store *receiver.File
	// closed makes every run closed; closeOnFetch closes every run once the run
	// configuration is fetched; limit admits no instance.
	closed, closeOnFetch, limit atomic.Bool

	mu     sync.Mutex
	run    []byte
	digest string
}

func newControl(t *testing.T) *control {
	t.Helper()
	key, signer := mustKey(t), mustKey(t)
	store, err := receiver.OpenFile(filepath.Join(t.TempDir(), "received.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	c := &control{key: key, store: store, pin: accesskey.Pin{{Alg: "ed25519", PublicKey: signer.PublicKey().String()}}}
	h := &receiver.Handler{
		Keys: func(k string) (receiver.AccessKey, bool) {
			return receiver.AccessKey{PublicKey: key.PublicKey()}, k == testKeyID
		},
		Signer: signer,
		Store:  store,
		Closed: func(string) bool { return c.closed.Load() },
		Admit:  func(string, string) bool { return !c.limit.Load() },
		Configuration: func() ([]byte, string) {
			pin, _ := json.Marshal(c.pin)
			doc := `{"version":1,"node_id":"nd_f1xt0re000000000","apiary_public_key":` + string(pin) +
				`,"events":{"url":"` + c.srv.URL + `/v1/events","types":["*"]},"run":{"url":"` + c.srv.URL + `/v1/run-configuration"}}`
			return []byte(doc), "sha256=" + fmt.Sprint(len(doc))
		},
		RunConfiguration: func(map[string]string) ([]byte, string, bool) {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.run, c.digest, c.run != nil
		},
	}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/run-configuration" && c.closeOnFetch.Load() {
			c.closed.Store(true)
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(c.srv.Close)
	t.Cleanup(func() { store.Close() })
	return c
}

// testKeyID is the access key's id the control knows.
const testKeyID = "ak_f1xt0re000000000"

func mustKey(t *testing.T) *accesskey.Key {
	k, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// serve makes the control serve a run configuration with the policy, under the digest
// sha256= and 64 of the digit.
func (c *control) serve(policy string, digit byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.run, c.digest = []byte(`{"version":1,"security_policy":`+policy+`}`), "sha256="+strings.Repeat(string(digit), 64)
}

func (c *control) server() *gateway.Server {
	return &gateway.Server{Version: 1, URL: c.srv.URL, AccessKeyID: testKeyID, ApiaryPublicKey: c.pin, AccessKey: c.key, InstanceID: "i_test"}
}

// TestARealGatewayReloadsARun pins the reload end to end: the server changes the run's
// configuration during the run, the gateway's answers carry its new digest, and the
// session fetches it and records it in a second policy_applied, which the gateway
// numbers and the server receives.
func TestARealGatewayReloadsARun(t *testing.T) {
	t.Parallel()
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["a.example"]}}`, 'a')
	sp := spec(t)
	sleeps(&sp, 30*time.Second)
	rg := startGateway(t, &sp, gateway.Config{Server: c.server(), Heartbeat: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sp.Timeout = 20 * time.Second
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	own := filepath.Join(sp.RunsDir, sp.RunID, "session.jsonl")
	applied := func() []map[string]any {
		return ofType(events(t, &session.Result{Dir: filepath.Dir(own)}), "dev.qory.run.policy_applied")
	}
	done := make(chan *session.Result, 1)
	go func() {
		res, err := session.Run(ctx, sp)
		if err != nil {
			t.Error(err)
		}
		done <- res
	}()
	waitFor(t, func() bool { _, err := os.Stat(own); return err == nil && len(applied()) == 1 })
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["b.example"]}}`, 'b')
	waitFor(t, func() bool { return len(applied()) == 2 })
	pa := applied()
	if fmt.Sprint(data(pa[0])["allow"]) != "[a.example]" || fmt.Sprint(data(pa[1])["allow"]) != "[b.example]" || data(pa[1])["run_configuration"] != "sha256="+strings.Repeat("b", 64) {
		t.Errorf("policy_applied %v then %v", data(pa[0]), data(pa[1]))
	}
	cancel()
	res := <-done
	rg.close(t)
	if res == nil {
		t.FailNow()
	}
	if got := ofType(record(t, res), "dev.qory.run.policy_applied"); len(got) != 2 {
		t.Errorf("the gateway numbered %d policy_applied", len(got))
	}
}

// TestARealGatewayPassesOnTheServersClose pins the server's 410 end to end: closed
// during the run, the runtime is stopped and the result says the server closed it,
// with run.exited run_closed in each record; closed before it started, the run is
// refused as one the server closed, from apiary.
func TestARealGatewayPassesOnTheServersClose(t *testing.T) {
	t.Parallel()
	t.Run("during the run", func(t *testing.T) {
		t.Parallel()
		c := newControl(t)
		c.serve(`{"version":1,"egress":{"mode":"observe"}}`, 'a')
		sp := spec(t)
		sleeps(&sp, 30*time.Second)
		sp.StopGrace = time.Second
		sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
		rg := startGateway(t, &sp, gateway.Config{Server: c.server(), Heartbeat: time.Second})
		own := filepath.Join(sp.RunsDir, sp.RunID, "session.jsonl")
		// The server closes the run once it is going: once its session has sent a
		// heartbeat.
		go func() {
			waitFor(t, func() bool {
				_, err := os.Stat(own)
				return err == nil && len(ofType(events(t, &session.Result{Dir: filepath.Dir(own)}), "dev.qory.run.heartbeat")) > 0
			})
			c.closed.Store(true)
		}()
		start := time.Now()
		res, err := session.Run(context.Background(), sp)
		if err != nil {
			t.Fatal(err)
		}
		if time.Since(start) > 20*time.Second {
			t.Errorf("the run took %s", time.Since(start))
		}
		if !res.RunClosed || res.ClosedBy != accesskey.FromApiary || res.ClosedReason != "run_closed" || res.State != "failed" {
			t.Errorf("result %+v", res)
		}
		if d := rg.close(t); !d.RunClosed || d.ClosedBy != "apiary" || d.Reason != "run_closed" {
			t.Errorf("delivery %+v", d)
		}
		for name, evs := range map[string][]map[string]any{"the session's": events(t, res), "the gateway's": record(t, res)} {
			if l := evs[len(evs)-1]; l["type"] != "dev.qory.run.exited" || data(l)["reason"] != "run_closed" {
				t.Errorf("%s record ends %v", name, l)
			}
		}
	})
	t.Run("before it started", func(t *testing.T) {
		t.Parallel()
		c := newControl(t)
		c.serve(`{"version":1,"egress":{"mode":"observe"}}`, 'a')
		c.closeOnFetch.Store(true)
		sp := spec(t)
		sleeps(&sp, 30*time.Second)
		sp.StopGrace = time.Second
		startGateway(t, &sp, gateway.Config{Server: c.server(), Heartbeat: time.Second})
		res, err := session.Run(context.Background(), sp)
		var r *session.Refusal
		switch {
		case err == nil:
			// The gateway opened the run before the server's close reached it: it ends
			// on its first batch.
			if !res.RunClosed || res.ClosedBy != accesskey.FromApiary || res.ClosedReason != "run_closed" {
				t.Errorf("result %+v", res)
			}
		case !errors.As(err, &r) || r.Code != "run_closed" || r.From != accesskey.FromApiary:
			t.Errorf("%v, want the server's run_closed", err)
		}
	})
}

// gate holds back what the session writes to its gateway while it is shut.
type gate struct{ mu sync.RWMutex }

// gatedConn is a connection to the gateway whose writes wait while its gate is shut.
type gatedConn struct {
	net.Conn
	g *gate
}

func (c gatedConn) Write(b []byte) (int, error) {
	c.g.mu.RLock()
	defer c.g.mu.RUnlock()
	return c.Conn.Write(b)
}

// TestARealGatewaysCloseCarriesItsCause pins the gateway's own end of a session's run
// end to end: a session it hears nothing from for three heartbeat intervals gets a 410
// session_lost, and one whose batch it refused a 410 batch_refused. The runtime is
// stopped, the result says the gateway closed the run with that code, and the
// session's record ends with run.exited of that reason, while the gateway's says
// session_lost for both.
func TestARealGatewaysCloseCarriesItsCause(t *testing.T) {
	t.Parallel()
	for _, cause := range []string{"session_lost", "batch_refused"} {
		t.Run(cause, func(t *testing.T) {
			t.Parallel()
			sp := spec(t)
			sleeps(&sp, 30*time.Second)
			sp.StopGrace = time.Second
			sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
			rg := startGateway(t, &sp, gateway.Config{Heartbeat: time.Second})
			local := rg.g.LocalLink()
			var shut gate
			sp.Gateway = session.LocalGateway(local.InMemory(func(ctx context.Context) (net.Conn, error) {
				c, err := local.DialContext(ctx)
				if err != nil {
					return nil, err
				}
				return gatedConn{Conn: c, g: &shut}, nil
			}))
			dir := filepath.Join(sp.RunsDir, sp.RunID)
			going := func() bool {
				_, err := os.Stat(filepath.Join(dir, "session.jsonl"))
				return err == nil && len(ofType(events(t, &session.Result{Dir: dir}), "dev.qory.run.heartbeat")) > 0
			}
			ended := func() bool {
				_, err := os.Stat(filepath.Join(dir, "events.jsonl"))
				return err == nil && len(ofType(record(t, &session.Result{Dir: dir}), "dev.qory.run.exited")) > 0
			}
			go func() {
				waitFor(t, going)
				if cause == "session_lost" {
					// The session's writes wait until the gateway has ended the run.
					shut.mu.Lock()
					defer shut.mu.Unlock()
					waitFor(t, ended)
					return
				}
				// A batch of the run's the gateway refuses: a ping, which the gateway
				// alone writes.
				k, err := server.NewLocalLink(local, "test", nil)
				if err != nil {
					t.Error(err)
					return
				}
				body, _ := json.Marshal([]map[string]any{{
					"specversion": "1.0", "id": event.NewID(), "source": event.Source(sp.RunID), "type": event.Ping, "subject": sp.RunID,
					"time": time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00"), "dataschema": event.DataSchema(event.Ping),
					"data": map[string]any{"forager_version": "x", "events": []string{"*"}, "contract_version": 1, "interval_seconds": 30},
				}})
				d, err := k.Deliver(context.Background(), server.LocalOrigin+"/v1/events", event.NewID(), body, "")
				if err != nil || d.Status != http.StatusBadRequest || d.End != "batch_refused" {
					t.Errorf("the refused batch: %+v %v", d, err)
				}
			}()
			start := time.Now()
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if time.Since(start) > 20*time.Second {
				t.Errorf("the run took %s", time.Since(start))
			}
			if !res.RunClosed || res.ClosedBy != accesskey.FromGateway || res.ClosedReason != cause || res.State != "failed" || res.TimedOut {
				t.Errorf("result %+v", res)
			}
			if d := rg.close(t); !d.RunClosed || d.ClosedBy != "gateway" || d.Reason != cause {
				t.Errorf("delivery %+v", d)
			}
			for name, want := range map[string]struct {
				evs    []map[string]any
				reason string
			}{"the session's": {events(t, res), cause}, "the gateway's": {record(t, res), "session_lost"}} {
				if l := want.evs[len(want.evs)-1]; l["type"] != "dev.qory.run.exited" || data(l)["reason"] != want.reason {
					t.Errorf("%s record ends %v", name, l)
				}
			}
		})
	}
}

// TestARealGatewayPassesOnTheServersRefusal pins a refusal of the server's end to end:
// the run is a *session.Refusal from apiary whose Error is the text the run always
// had, word for word, the request the server refused, its code and its status.
func TestARealGatewayPassesOnTheServersRefusal(t *testing.T) {
	t.Parallel()
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"observe"}}`, 'a')
	c.limit.Store(true)
	sp := spec(t)
	sleeps(&sp, 0)
	startGateway(t, &sp, gateway.Config{Server: c.server()})
	_, err := session.Run(context.Background(), sp)
	var r *session.Refusal
	if !errors.As(err, &r) || r.Code != "instance_limit" || r.From != accesskey.FromApiary {
		t.Fatalf("%v, want the server's instance_limit", err)
	}
	if want := "ping " + c.srv.URL + "/v1/events: instance_limit (status 409)"; err.Error() != want {
		t.Errorf("%q, want %q", err, want)
	}
}

// TestARunIDWithARecordIsNoRun pins a run id used again on this machine: the run is
// refused with the error it always had, that the run's stream exists.
func TestARunIDWithARecordIsNoRun(t *testing.T) {
	t.Parallel()
	sp := spec(t, "FAKE_EXIT=0")
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	startGateway(t, &sp, gateway.Config{})
	if _, err := runWithSettingsEnv(t, sp); err != nil {
		t.Fatal(err)
	}
	_, err := session.Run(context.Background(), sp)
	if want := "open " + filepath.Join(sp.RunsDir, sp.RunID, "events.jsonl") + ": file exists"; err == nil || err.Error() != want {
		t.Errorf("%v, want %q", err, want)
	}
}

// TestARunThroughAGatewayWithNoLinkSocket is a run end to end through a gateway that
// makes no link socket, as qory run starts it: the session reaches it in memory alone,
// the run goes as through one with a socket, and no link directory is ever made.
func TestARunThroughAGatewayWithNoLinkSocket(t *testing.T) {
	// A short one, as the session's own sockets' paths are bounded.
	tmp, err := os.MkdirTemp("/tmp", "qt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	t.Setenv("TMPDIR", tmp)
	links := func() []string {
		m, _ := filepath.Glob(filepath.Join(tmp, "qory-link-*"))
		return m
	}
	sp := spec(t, "FAKE_DENIED_URL=http://denied.invalid/a", "FAKE_EXIT=0")
	// The spec's own fake gateway has its link; the real one makes none beside it.
	before := links()
	rg := startGateway(t, &sp, gateway.Config{Version: "test", Heartbeat: time.Second, NoLinkSocket: true,
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example"}}}})
	if l := rg.g.LocalLink(); l.Socket != "" || !l.IsInMemory() {
		t.Fatalf("the gateway's link: socket %q, in memory %v", l.Socket, l.IsInMemory())
	}
	res, err := runWithSettingsEnv(t, sp)
	if err != nil {
		t.Fatal(err)
	}
	if got := links(); !slices.Equal(got, before) {
		t.Errorf("link directories during the run %v, the fake's %v", got, before)
	}
	if d := rg.close(t); d != (gateway.Delivery{}) {
		t.Errorf("delivery %+v", d)
	}
	if res.ExitCode != 0 || res.State != "succeeded" || res.Undelivered != 0 {
		t.Errorf("result %+v", res)
	}
	numbered := record(t, res)
	if got := types(numbered); len(got) < 4 || got[0] != "dev.qory.run.started" || got[len(got)-1] != "dev.qory.run.exited" {
		t.Fatalf("the gateway's record %v", got)
	}
	if egress := ofType(numbered, "dev.qory.run.egress"); len(egress) != 1 || data(egress[0])["decision"] != "denied" {
		t.Errorf("run.egress %v", egress)
	}
	if got := links(); !slices.Equal(got, before) {
		t.Errorf("link directories after Close %v, the fake's %v", got, before)
	}
}
