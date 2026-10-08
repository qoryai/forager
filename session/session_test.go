package session_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/qoryai/runner/accesskey"
	"github.com/qoryai/runner/contracts"
	"github.com/qoryai/runner/policy"
	"github.com/qoryai/runner/receiver"
	"github.com/qoryai/runner/session"
	"github.com/qoryai/runner/session/internal/socket"
	"github.com/qoryai/runner/session/runtimes"
	"github.com/qoryai/runner/session/runtimes/claude"
)

const (
	testKey      = "ak_f1xt0re000000000"
	testInstance = "i_test"
)

// The keys of the tests: the access key runs sign with, and the control's own signing
// key, which runs pin; each fresh, so no published key is used.
var (
	testAccessKey = mustGenerate()
	testSigner    = mustGenerate()
	testPin       = accesskey.Pin{{Alg: "ed25519", PublicKey: testSigner.PublicKey().String()}}
)

func mustGenerate() *accesskey.Key {
	k, err := accesskey.Generate()
	if err != nil {
		panic(err)
	}
	return k
}

// signedReply answers a request the way a server of the contract does, signed under
// the test's signing key and bound to the request.
func signedReply(w http.ResponseWriter, r *http.Request, status int, body string) {
	a := accesskey.Answer{Status: status, RequestSignature: r.Header.Get(accesskey.HeaderSignature), Body: []byte(body),
		Configuration: w.Header().Get(accesskey.HeaderConfiguration), RunConfiguration: w.Header().Get(accesskey.HeaderRunConfiguration)}
	w.Header().Set(accesskey.HeaderSignature, testSigner.SignAnswer(a))
	w.WriteHeader(status)
	io.WriteString(w, body)
}

// refusal returns the code of a refusal, or the error's text.
func refusal(err error) string {
	var r *session.Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	if err == nil {
		return "nil"
	}
	return err.Error()
}

// control is a server of the contract for the tests: the reference receiver in front
// of a store, whose configuration document names its own events endpoint and, when
// the test gives it one, a run configuration it may change during a run.
type control struct {
	srv   *httptest.Server
	store *receiver.File
	// received is the store's file.
	received string
	// refuse, when set, is the status every request gets instead of an answer,
	// unsigned.
	refuse atomic.Int32
	// closed makes every run closed; limit refuses every instance's ping.
	closed, limit atomic.Bool
	// slow delays the run configuration's answer; closeOnFetch closes every run once
	// the run configuration is fetched.
	slow         atomic.Int64
	closeOnFetch atomic.Bool
	// closedAnswers counts the answers run_closed was given to.
	closedAnswers atomic.Int32
	// hits counts every request; discoveries the discovery fetches; fetches the run
	// configuration fetches.
	hits, discoveries, fetches atomic.Int32
	// run is the run configuration served, nil for none; digest is its digest.
	mu     sync.Mutex
	run    []byte
	digest string
	// answered, when set, is the run configuration digest the answers to a delivery
	// carry instead of the served document's.
	answered string
	// query is the last run configuration request's query as sent, and labels the
	// labels the receiver handed its hook for it.
	query  string
	labels map[string]string
}

// answering sets the run configuration digest on a delivery's empty answer, and signs
// the answer again over it.
type answering struct {
	http.ResponseWriter
	digest    string
	signature string
}

func (a answering) WriteHeader(code int) {
	if a.Header().Get("X-Qory-Run-Configuration") != "" {
		a.Header().Set("X-Qory-Run-Configuration", a.digest)
		a.Header().Set(accesskey.HeaderSignature, testSigner.SignAnswer(accesskey.Answer{Status: code, RequestSignature: a.signature,
			Configuration: a.Header().Get(accesskey.HeaderConfiguration), RunConfiguration: a.digest}))
	}
	a.ResponseWriter.WriteHeader(code)
}

func newControl(t *testing.T) *control {
	t.Helper()
	received := filepath.Join(t.TempDir(), "received.jsonl")
	store, err := receiver.OpenFile(received)
	if err != nil {
		t.Fatal(err)
	}
	c := &control{store: store, received: received}
	h := &receiver.Handler{
		Keys: func(k string) (receiver.AccessKey, bool) {
			return receiver.AccessKey{PublicKey: testAccessKey.PublicKey()}, k == testKey
		},
		Signer: testSigner,
		Store:  store,
		Closed: func(string) bool {
			if c.closed.Load() {
				c.closedAnswers.Add(1)
				return true
			}
			return false
		},
		Admit: func(string, string) bool { return !c.limit.Load() },
		Configuration: func() ([]byte, string) {
			doc := `{"version":1,"node_id":"nd_f1xt0re000000000","apiary_public_key":` + string(must(json.Marshal(testPin))) + `,"events":{"url":"` + c.srv.URL + `/v1/events","types":["*"]}`
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.run != nil {
				doc += `,"run":{"url":"` + c.srv.URL + `/v1/run-configuration"}`
			}
			doc += "}"
			return []byte(doc), "sha256=" + fmt.Sprint(len(doc))
		},
		RunConfiguration: func(labels map[string]string) ([]byte, string, bool) {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.labels = maps.Clone(labels)
			return c.run, c.digest, c.run != nil
		},
	}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.hits.Add(1)
		if r.URL.Path == "/.well-known/qory-configuration" {
			c.discoveries.Add(1)
		}
		if r.URL.Path == "/v1/run-configuration" {
			c.fetches.Add(1)
			c.mu.Lock()
			c.query = r.URL.RawQuery
			c.mu.Unlock()
			if c.closeOnFetch.Load() {
				c.closed.Store(true)
			}
			time.Sleep(time.Duration(c.slow.Load()) * time.Millisecond)
		}
		if code := c.refuse.Load(); code != 0 {
			w.WriteHeader(int(code))
			return
		}
		c.mu.Lock()
		answered := c.answered
		c.mu.Unlock()
		if answered != "" && r.Method == http.MethodPost {
			w = answering{w, answered, r.Header.Get(accesskey.HeaderSignature)}
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(c.srv.Close)
	t.Cleanup(func() { store.Close() })
	return c
}

// serve makes the control serve a run configuration with the policy, under a digest
// of the test's choosing.
func (c *control) serve(policy, digest string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.run, c.digest = []byte(`{"version":1,"security_policy":`+policy+`}`), digest
}

func (c *control) server() *session.Server {
	return &session.Server{Version: 1, URL: c.srv.URL, AccessKeyID: testKey, ApiaryPublicKey: testPin}
}

// resend is the spec of a resend of the run directory to the server, as the test's
// instance.
func resend(dir string, cfg *session.Server) session.ResendSpec {
	return session.ResendSpec{Dir: dir, Server: cfg, AccessKey: testAccessKey, InstanceID: testInstance}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// TestMain lets the test binary stand in for a runtime, for the hook forwarder and for a
// tool, so no real runtime and no shell script are needed: with FAKE_RUNTIME set it
// acts as a runtime, with QORY_TEST_FORWARD set as the forwarder, and with toolMode as
// its first argument as a tool.
func TestMain(m *testing.M) {
	switch {
	case os.Getenv("QORY_TEST_FORWARD") != "":
		if err := socket.Forward(context.Background(), os.Getenv(session.EnvSocket), os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	case os.Getenv("FAKE_RUNTIME") != "":
		os.Exit(fakeRuntime())
	case len(os.Args) > 2 && os.Args[1] == toolMode:
		os.Exit(fakeTool(os.Args[2:]))
	}
	// The registry of walled runs is the tests' own, not this user's.
	state, err := os.MkdirTemp("", "session-state-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Setenv("XDG_STATE_HOME", state)
	code := m.Run()
	os.RemoveAll(state)
	os.Exit(code)
}

// fakeRuntime prints what a headless runtime prints, reaches two hosts through the
// proxy, calls its hook the way a runtime calls a command hook, and exits as told. It
// sends its requests through HTTP_PROXY explicitly, because the origins are on
// loopback, which the runner's NO_PROXY exempts and Go never proxies.
func fakeRuntime() int {
	fmt.Println(`{"type":"system","subtype":"init","session_id":"fake","model":"m"}`)
	fmt.Fprintln(os.Stderr, "fake runtime: starting")
	proxyURL, _ := url.Parse(os.Getenv("HTTP_PROXY"))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	for _, u := range []string{os.Getenv("FAKE_ALLOWED_URL"), os.Getenv("FAKE_DENIED_URL")} {
		if u == "" {
			continue
		}
		resp, err := client.Get(u)
		if err != nil {
			fmt.Fprintln(os.Stderr, "get:", err)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		fmt.Fprintf(os.Stderr, "get %s: %d\n", u, resp.StatusCode)
	}
	if settings := os.Getenv("FAKE_SETTINGS"); settings != "" {
		// Call the hook the settings name, as the runtime would, with a SessionEnd input.
		b, _ := os.ReadFile(settings)
		var s struct {
			Hooks map[string][]struct {
				Hooks []struct{ Command string } `json:"hooks"`
			} `json:"hooks"`
		}
		if err := json.Unmarshal(b, &s); err != nil || len(s.Hooks["SessionEnd"]) == 0 {
			fmt.Fprintln(os.Stderr, "no SessionEnd hook installed:", err)
			return 90
		}
		// Every group's every hook runs, as the runtime runs them: the launch's own and
		// the runner's forwarder.
		for _, group := range s.Hooks["SessionEnd"] {
			for _, h := range group.Hooks {
				cmd := shell(h.Command)
				cmd.Stdin = strings.NewReader(`{"session_id":"fake","hook_event_name":"SessionEnd","reason":"other","cwd":"/"}`)
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					fmt.Fprintln(os.Stderr, "hook:", err)
					return 91
				}
			}
		}
	}
	fmt.Println(`{"type":"result","subtype":"success","session_id":"fake","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.01,"result":"done"}`)
	time.Sleep(60 * time.Millisecond)
	code := 0
	fmt.Sscan(os.Getenv("FAKE_EXIT"), &code)
	return code
}

// spec returns a spec running the fake runtime with the given policy path and
// environment, in a fresh checkout directory, with its run directories beside it.
func spec(t *testing.T, pol *session.Policy, env ...string) session.Spec {
	t.Helper()
	dir := t.TempDir()
	var out, errs bytes.Buffer
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("stdout:\n%s\nstderr:\n%s", out.String(), errs.String())
		}
	})
	return session.Spec{
		Runtime:       claudeCode(t),
		Command:       os.Args[0],
		Args:          []string{"--settings", writeSettings(t, dir)},
		Env:           append([]string{"FAKE_RUNTIME=1", "PATH=" + os.Getenv("PATH")}, env...),
		Dir:           dir,
		RunsDir:       filepath.Join(t.TempDir(), "runs"),
		Stdin:         strings.NewReader(""),
		Stdout:        &out,
		Stderr:        &errs,
		Policy:        pol,
		Forwarder:     []string{"env", "QORY_TEST_FORWARD=1", os.Args[0]},
		RunnerVersion: "test",
		AccessKey:     testAccessKey,
		InstanceID:    testInstance,
		InstanceName:  "build-01",
		Heartbeat:     10 * time.Millisecond,
		Report:        func(l string) { t.Log("report:", l) },
	}
}

// claudeCode is the runtime most tests run as: the contract's descriptor for Claude
// Code, in front of a program of the test's own.
func claudeCode(t *testing.T) runtimes.Runtime {
	t.Helper()
	rt, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func writeSettings(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "launch-settings.json")
	if err := os.WriteFile(p, []byte(`{"permissions":{"allow":["Bash"]},"hooks":{"SessionEnd":[{"hooks":[{"type":"command","command":"echo existing"}]}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// events reads and validates the run's events.jsonl and returns them by index.
func events(t *testing.T, res *session.Result) []map[string]any {
	t.Helper()
	schema, err := contracts.Compile("event.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(res.Dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	s := bufio.NewScanner(f)
	s.Buffer(nil, 1<<20)
	for n := 1; s.Scan(); n++ {
		doc, err := contracts.Decode("events.jsonl", s.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("events.jsonl:%d: %v\n%s", n, err, s.Bytes())
		}
		var m map[string]any
		json.Unmarshal(s.Bytes(), &m)
		if want := fmt.Sprintf("%010d", n); m["sequence"] != want {
			t.Errorf("events.jsonl:%d: sequence %v", n, m["sequence"])
		}
		out = append(out, m)
	}
	return out
}

func ofType(evs []map[string]any, typ string) []map[string]any {
	var out []map[string]any
	for _, e := range evs {
		if e["type"] == typ {
			out = append(out, e)
		}
	}
	return out
}

func data(e map[string]any) map[string]any { return e["data"].(map[string]any) }

// TestRunEnforcesRecordsAndExitsWithTheRuntimesStatus is the run end to end on pipes:
// the policy is pinned and applied as it is, the harness's hosts reported and deciding
// nothing, the allowed host goes through and the denied one does not, both are
// recorded with their outcome, the runtime's output is logged per stream and mapped to
// session.result, the installed hook reaches the socket and becomes session.ended, the
// heartbeat ticks, and the exit status is the runtime's.
func TestRunEnforcesRecordsAndExitsWithTheRuntimesStatus(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	pol := &session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "enforce", Allow: []string{"127.0.0.1", "api.anthropic.com"}, Deny: []string{"tracker.example"}}}
	sp := spec(t, pol, "FAKE_ALLOWED_URL="+origin.URL+"/allowed", "FAKE_DENIED_URL="+strings.Replace(origin.URL, "127.0.0.1", "localhost", 1)+"/denied", "FAKE_EXIT=3")
	sp.Declared = []string{"127.0.0.1", "registry.npmjs.org"}
	res, err := runWithSettingsEnv(t, sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 3 || res.State != "failed" || res.Signal != "" {
		t.Errorf("result %+v", res)
	}
	evs := events(t, res)
	if len(evs) < 8 || evs[0]["type"] != "dev.qory.run.started" || evs[1]["type"] != "dev.qory.run.policy_applied" || evs[len(evs)-1]["type"] != "dev.qory.run.exited" {
		t.Fatalf("event order: %v", types(evs))
	}
	applied := data(evs[1])
	if applied["mode"] != "enforce" || applied["source"] != "config" || fmt.Sprint(applied["allow"]) != "[127.0.0.1 api.anthropic.com]" || fmt.Sprint(applied["harness_hosts"]) != "[127.0.0.1 registry.npmjs.org]" || fmt.Sprint(applied["deny"]) != "[tracker.example]" || applied["digest"] == nil || applied["declared"] != nil || applied["url"] != nil {
		t.Errorf("policy_applied %v", applied)
	}
	egress := ofType(evs, "dev.qory.run.egress")
	if len(egress) != 2 || data(egress[0])["decision"] != "allowed" || data(egress[0])["rule"] != "127.0.0.1" || data(egress[0])["outcome"] != "connected" || data(egress[1])["decision"] != "denied" || data(egress[1])["host"] != "localhost" || data(egress[1])["outcome"] != "refused" {
		t.Errorf("egress %v", egress)
	}
	streams := map[string]bool{}
	for _, l := range ofType(evs, "dev.qory.run.log") {
		streams[data(l)["stream"].(string)] = true
	}
	if !streams["stdout"] || !streams["stderr"] {
		t.Errorf("log streams %v", streams)
	}
	if r := ofType(evs, "dev.qory.session.result"); len(r) != 1 || data(r[0])["outcome"] != "success" || data(r[0])["result"] != "done" {
		t.Errorf("session.result %v", r)
	}
	if e := ofType(evs, "dev.qory.session.ended"); len(e) != 1 || data(e[0])["reason"] != "other" {
		t.Errorf("session.ended %v", e)
	}
	if len(ofType(evs, "dev.qory.run.heartbeat")) == 0 {
		t.Error("no heartbeat")
	}
	exited := data(evs[len(evs)-1])
	if exited["state"] != "failed" || exited["exit_code"] != 3.0 {
		t.Errorf("exited %v", exited)
	}
	out, _ := os.ReadFile(filepath.Join(res.Dir, "output.log"))
	if !strings.Contains(string(out), `"type":"result"`) || !strings.Contains(string(out), "fake runtime: starting") {
		t.Errorf("output.log %q", out)
	}
	settings, _ := os.ReadFile(filepath.Join(res.Dir, "settings.json"))
	if !strings.Contains(string(settings), `"echo existing"`) || !strings.Contains(string(settings), `"permissions"`) || strings.Count(string(settings), os.Args[0]) != 11 {
		t.Errorf("settings.json:\n%s", settings)
	}
	if _, err := os.Stat(filepath.Join(res.Dir, "undelivered")); !os.IsNotExist(err) {
		t.Error("an undelivered directory exists with no server")
	}
}

// runWithSettingsEnv runs the spec with FAKE_SETTINGS pointing at the settings file
// the runner writes, which is only known once the run directory exists: the run id is
// fixed in advance so the path is known.
func runWithSettingsEnv(t *testing.T, sp session.Spec) (*session.Result, error) {
	t.Helper()
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	sp.Env = append(sp.Env, "FAKE_SETTINGS="+filepath.Join(sp.RunsDir, sp.RunID, "settings.json"))
	return session.Run(context.Background(), sp)
}

func types(evs []map[string]any) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e["type"].(string))
	}
	return out
}

// TestNoPolicyObservesAndNoServerNeedsNoPing pins the defaults: no policy is observe
// with source none, a denied host is not denied, and nothing is posted.
func TestNoPolicyObservesAndNoServerNeedsNoPing(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	sp := spec(t, nil, "FAKE_DENIED_URL="+strings.Replace(origin.URL, "127.0.0.1", "localhost", 1))
	sp.Forwarder = nil
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	if a := data(evs[1]); a["mode"] != "observe" || a["source"] != "none" || a["digest"] != nil {
		t.Errorf("policy_applied %v", a)
	}
	if e := ofType(evs, "dev.qory.run.egress"); len(e) != 1 || data(e[0])["decision"] != "allowed" || data(e[0])["rule"] != "" || data(e[0])["outcome"] != "connected" {
		t.Errorf("egress %v", e)
	}
	if len(ofType(evs, "dev.qory.ping")) != 0 || res.ExitCode != 0 || res.State != "succeeded" {
		t.Errorf("result %+v", res)
	}
	if _, err := os.Stat(filepath.Join(res.Dir, "settings.json")); !os.IsNotExist(err) {
		t.Error("hooks were installed with no forwarder")
	}
}

// TestInvalidPolicyMeansNoRun pins the rule: a policy the schema refuses is an error
// before anything starts, and no run directory is made.
func TestInvalidPolicyMeansNoRun(t *testing.T) {
	sp := spec(t, &session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "log"}})
	_, err := session.Run(context.Background(), sp)
	var pe *policy.Error
	if !errors.As(err, &pe) {
		t.Fatalf("err %v", err)
	}
	if entries, _ := os.ReadDir(sp.RunsDir); len(entries) != 0 {
		t.Error("a run directory was made")
	}
}

// TestServerIsDiscoveredPingedAndDelivered pins the server side: the configuration
// document is fetched first and the caller's hook gets the node id it lists, the ping
// is the first event with the contract revision, and every event reaches the store; a
// hook that returns an error is no run, with no ping; with a server that refuses the
// discovery, no run and no run directory; with one that refuses the ping, no run; with
// --local, the server is not contacted.
func TestServerIsDiscoveredPingedAndDelivered(t *testing.T) {
	c := newControl(t)
	cfg := c.server()

	sp := spec(t, nil)
	sp.Forwarder = nil
	sp.Server, sp.Heartbeat = cfg, time.Second
	var discovered []session.Discovery
	sp.Discovered = func(d session.Discovery) error {
		discovered = append(discovered, d)
		return nil
	}
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if len(discovered) != 1 || discovered[0].NodeID != "nd_f1xt0re000000000" || discovered[0].Secrets {
		t.Errorf("discovered %+v", discovered)
	}
	evs := events(t, res)
	if evs[0]["type"] != "dev.qory.ping" || fmt.Sprint(data(evs[0])["events"]) != "[*]" || data(evs[0])["contract_version"] != 1.0 {
		t.Errorf("first event %v", evs[0])
	}
	if c.store.Count() != len(evs) || res.Undelivered != 0 || c.discoveries.Load() != 1 {
		t.Errorf("store holds %d of %d events, %d undelivered, %d discoveries", c.store.Count(), len(evs), res.Undelivered, c.discoveries.Load())
	}
	if a := data(evs[2]); evs[2]["type"] != "dev.qory.run.policy_applied" || a["source"] != "none" || a["url"] != nil {
		t.Errorf("a server with no run section: policy_applied %v", a)
	}
	// Everything was accepted during the run, the ping too, so nothing is owed after it.
	if again, err := session.Resend(context.Background(), resend(res.Dir, cfg)); err != nil || again.Sent != 0 || again.Closed || c.store.Count() != len(evs) {
		t.Errorf("resend after a delivered run: %+v, %v", again, err)
	}

	pings := c.hits.Load()
	sp = spec(t, nil)
	sp.Forwarder = nil
	sp.Server, sp.Heartbeat = cfg, time.Second
	sp.Discovered = func(session.Discovery) error { return errors.New("the marker cannot be written") }
	if _, err := session.Run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), "marker") || c.hits.Load() != pings+1 {
		t.Errorf("a refusing discovery hook: %v, %d requests", err, c.hits.Load()-pings)
	}

	c.refuse.Store(500)
	sp = spec(t, nil)
	sp.Forwarder = nil
	sp.Server, sp.Heartbeat = cfg, time.Second
	if _, err := session.Run(context.Background(), sp); refusal(err) != "answer_unsigned" || !strings.Contains(err.Error(), "configuration "+c.srv.URL+"/.well-known/qory-configuration") || !strings.Contains(err.Error(), "status 500") {
		t.Errorf("refused discovery: %v", err)
	}
	if entries, _ := os.ReadDir(sp.RunsDir); len(entries) != 0 {
		t.Errorf("run directories after a refused discovery: %d", len(entries))
	}

	c.refuse.Store(0)
	refusePing := &session.Server{Version: 1, URL: c.srv.URL, AccessKeyID: "ak_0000000000000000", ApiaryPublicKey: testPin}
	sp = spec(t, nil)
	sp.Forwarder = nil
	sp.Server, sp.Heartbeat = refusePing, time.Second
	if _, err := session.Run(context.Background(), sp); refusal(err) != "unauthorized" || !strings.Contains(err.Error(), "status 401") {
		t.Errorf("an unknown key: %v", err)
	}
	c.refuse.Store(0)
	c.mu.Lock()
	c.run = nil
	c.mu.Unlock()
	sp = spec(t, nil)
	sp.Forwarder = nil
	sp.Server, sp.Heartbeat = cfg, time.Second
	sp.Labels = map[string]string{"forge": "example.test"}
	pinged := false
	stopPing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/qory-configuration" {
			w.Header().Set("X-Qory-Configuration", "sha256=x")
			signedReply(w, r, 200, `{"version":1,"node_id":"nd_f1xt0re000000000","apiary_public_key":`+string(must(json.Marshal(testPin)))+`,"events":{"url":"`+c.srv.URL+`/nowhere","types":["*"]}}`)
			return
		}
		pinged = true
		w.WriteHeader(500)
	}))
	defer stopPing.Close()
	sp.Server, sp.Heartbeat = &session.Server{Version: 1, URL: stopPing.URL, AccessKeyID: testKey, ApiaryPublicKey: testPin}, time.Second
	if _, err := session.Run(context.Background(), sp); refusal(err) != "answer_unsigned" || !strings.Contains(err.Error(), "ping "+c.srv.URL+"/nowhere") || !strings.Contains(err.Error(), "status 404") {
		t.Errorf("refused ping: %v", err)
	}
	if entries, _ := os.ReadDir(sp.RunsDir); len(entries) != 1 {
		t.Errorf("run directories after a refused ping: %d", len(entries))
	} else if evs, _ := os.ReadFile(filepath.Join(sp.RunsDir, entries[0].Name(), "events.jsonl")); strings.Count(string(evs), "\n") != 1 {
		t.Errorf("the refused run's file holds more than the ping:\n%s", evs)
	}
	_ = pinged

	before := c.hits.Load()
	sp = spec(t, nil)
	sp.Forwarder = nil
	sp.Server, sp.Heartbeat = cfg, time.Second
	sp.Local = true
	if res, err := session.Run(context.Background(), sp); err != nil || len(ofType(events(t, res), "dev.qory.ping")) != 0 || c.hits.Load() != before {
		t.Errorf("local run: %v, the server was contacted %d times", err, c.hits.Load()-before)
	}
}

// TestRunConfigurationIsThePolicyAndReloadsOnTheDigest pins the run configuration:
// with a server that names one, it is asked for with every label of the run, its
// policy is the run's, over the spec's own, with the source fetched and both digests;
// and when an answer says another is in force, it is fetched and put in force with a
// second policy_applied, and the next connection is decided by it.
func TestRunConfigurationIsThePolicyAndReloadsOnTheDigest(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	c := newControl(t)
	first, second := "sha256="+strings.Repeat("1", 64), "sha256="+strings.Repeat("2", 64)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, first)
	dir := t.TempDir()
	sp := spec(t, &session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "observe"}}, "FAKE_ALLOWED_URL="+origin.URL+"/after")
	sp.Forwarder = nil
	sp.Server, sp.Heartbeat = c.server(), time.Second
	sp.Labels = map[string]string{"forge": "github.com", "issue": "77", "repository": "acme/shop"}
	// The runtime waits for the test's go-ahead, then reaches the origin.
	sp.Command, sp.Args = "sh", []string{"-c", `while [ ! -f "$1" ]; do sleep 0.05; done; exec "$0"`, os.Args[0], filepath.Join(dir, "go")}
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	runDir := filepath.Join(sp.RunsDir, sp.RunID)
	done := make(chan struct{})
	var res *session.Result
	var runErr error
	go func() {
		defer close(done)
		res, runErr = session.Run(context.Background(), sp)
	}()
	applied := func() int {
		b, _ := os.ReadFile(filepath.Join(runDir, "events.jsonl"))
		return strings.Count(string(b), `"dev.qory.run.policy_applied"`)
	}
	waitFor(t, func() bool { return applied() == 1 })
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":[]}}`, second)
	waitFor(t, func() bool { return applied() == 2 })
	if err := os.WriteFile(filepath.Join(dir, "go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	<-done
	if runErr != nil {
		t.Fatal(runErr)
	}
	evs := events(t, res)
	pa := ofType(evs, "dev.qory.run.policy_applied")
	if len(pa) != 2 {
		t.Fatalf("policy_applied events: %v", pa)
	}
	at, then := data(pa[0]), data(pa[1])
	if at["source"] != "fetched" || at["mode"] != "enforce" || fmt.Sprint(at["allow"]) != "[127.0.0.1]" || at["run_configuration"] != first || at["url"] != c.srv.URL+"/v1/run-configuration" || at["digest"] == nil {
		t.Errorf("the first policy_applied %v", at)
	}
	if then["source"] != "fetched" || fmt.Sprint(then["allow"]) != "[]" || then["run_configuration"] != second || then["digest"] == at["digest"] {
		t.Errorf("the second policy_applied %v", then)
	}
	egress := ofType(evs, "dev.qory.run.egress")
	if len(egress) != 1 || data(egress[0])["decision"] != "denied" || data(egress[0])["outcome"] != "refused" || data(egress[0])["mode"] != "enforce" {
		t.Errorf("egress after the reload %v", egress)
	}
	if c.store.Count() != len(evs) {
		t.Errorf("the store holds %d of %d events", c.store.Count(), len(evs))
	}
	// The run configuration was asked for with every label of the run, and the
	// receiver read them all back.
	c.mu.Lock()
	query, labels := c.query, c.labels
	c.mu.Unlock()
	if query != "forge=github.com&issue=77&repository=acme%2Fshop" || !maps.Equal(labels, sp.Labels) {
		t.Errorf("the run configuration request's query %q, read as %v", query, labels)
	}
	// A run section that does not answer is no run.
	c.mu.Lock()
	c.run = []byte("not json")
	c.mu.Unlock()
	sp = spec(t, nil)
	sp.Forwarder = nil
	sp.Server, sp.Heartbeat = c.server(), time.Second
	if _, err := session.Run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), "run configuration "+c.srv.URL+"/v1/run-configuration") {
		t.Errorf("a run configuration that is not one: %v", err)
	}
}

// waiting is a run whose runtime waits for the test's go-ahead and then, as the fake
// runtime, reaches what its environment names: a run to reload under.
type waiting struct {
	t    *testing.T
	dir  string
	gate string
	done chan struct{}
	res  *session.Result
	err  error
	mu   sync.Mutex
	said []string
}

func startWaiting(t *testing.T, sp session.Spec) *waiting {
	t.Helper()
	w := &waiting{t: t, gate: filepath.Join(t.TempDir(), "go"), done: make(chan struct{})}
	sp.Forwarder = nil
	sp.Command, sp.Args = "sh", []string{"-c", `while [ ! -f "$1" ]; do sleep 0.05; done; exec "$0"`, os.Args[0], w.gate}
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	sp.Report = func(l string) {
		t.Log("report:", l)
		w.mu.Lock()
		w.said = append(w.said, l)
		w.mu.Unlock()
	}
	w.dir = filepath.Join(sp.RunsDir, sp.RunID)
	go func() {
		defer close(w.done)
		w.res, w.err = session.Run(context.Background(), sp)
	}()
	return w
}

// applied is how many policy_applied events the record holds so far.
func (w *waiting) applied() int {
	b, _ := os.ReadFile(filepath.Join(w.dir, "events.jsonl"))
	return strings.Count(string(b), `"dev.qory.run.policy_applied"`)
}

// reported says whether a report line holding the text was made.
func (w *waiting) reported(text string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.ContainsFunc(w.said, func(l string) bool { return strings.Contains(l, text) })
}

// finish lets the runtime go and returns the run's events.
func (w *waiting) finish() []map[string]any {
	w.t.Helper()
	if err := os.WriteFile(w.gate, nil, 0o644); err != nil {
		w.t.Fatal(err)
	}
	<-w.done
	if w.err != nil {
		w.t.Fatal(w.err)
	}
	return events(w.t, w.res)
}

func digest(c byte) string { return "sha256=" + strings.Repeat(string(c), 64) }

// TestAReloadIsAsStrictAsAStart pins a reload without a wall: path rules the proxy
// cannot hold take their hosts out of the allow list, so they are denied and the event
// claims no paths; a policy that selects credentials, which a start refuses without a
// wall, fails the reload and leaves the policy in force; and a run configuration the
// server answered is not fetched again until the answered digest changes, nor is one
// that turns out to be the one in force put in force again.
func TestAReloadIsAsStrictAsAStart(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, digest('1'))
	sp := spec(t, nil, "FAKE_ALLOWED_URL="+origin.URL+"/after")
	sp.Server, sp.Heartbeat = c.server(), time.Second
	w := startWaiting(t, sp)
	waitFor(t, func() bool { return w.applied() == 1 })

	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1","api.example"],"paths":{"127.0.0.1":["/ok/*"]}}}`, digest('2'))
	waitFor(t, func() bool { return w.applied() == 2 })
	if !w.reported("path rules, which need a wall") {
		t.Error("nobody was told the path rules are not held")
	}

	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]},"credentials":[{"name":"model"}]}`, digest('3'))
	waitFor(t, func() bool { return w.reported("selects credentials, which need a wall") })
	fetched := c.fetches.Load()
	time.Sleep(2500 * time.Millisecond)
	if n := c.fetches.Load(); n != fetched {
		t.Errorf("a run configuration that was refused was fetched %d more times under the same answered digest", n-fetched)
	}

	// The answers name a digest the run does not hold, and the fetch finds the
	// document in force: fetched once, nothing put in force, nothing said.
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1","api.example"],"paths":{"127.0.0.1":["/ok/*"]}}}`, digest('2'))
	c.mu.Lock()
	c.answered = digest('4')
	c.mu.Unlock()
	waitFor(t, func() bool { return c.fetches.Load() == fetched+1 })
	time.Sleep(2500 * time.Millisecond)
	if n := c.fetches.Load(); n != fetched+1 || w.applied() != 2 {
		t.Errorf("the document in force under another answered digest: %d fetches, %d policy_applied", n-fetched, w.applied())
	}
	evs := w.finish()
	pa := ofType(evs, "dev.qory.run.policy_applied")
	if len(pa) != 2 {
		t.Fatalf("policy_applied events: %v", pa)
	}
	then := data(pa[1])
	if fmt.Sprint(then["allow"]) != "[api.example]" || then["paths"] != nil || then["run_configuration"] != digest('2') || then["credentials"] != nil {
		t.Errorf("the second policy_applied %v", then)
	}
	egress := ofType(evs, "dev.qory.run.egress")
	if len(egress) != 1 || data(egress[0])["decision"] != "denied" || data(egress[0])["host"] != "127.0.0.1" || data(egress[0])["outcome"] != "refused" {
		t.Errorf("egress to a host whose paths cannot be held %v", egress)
	}
	if w.reported("context canceled") {
		t.Error("the run's end was reported as a failed reload")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestInteractiveRunsOnAPseudoTerminal pins the PTY path: the output is one terminal
// stream with the terminal's line endings, and the exit status is the program's.
func TestInteractiveRunsOnAPseudoTerminal(t *testing.T) {
	sp := spec(t, nil)
	sp.Forwarder = nil
	sp.Interactive = true
	sp.Command = "sh"
	sp.Args = []string{"-c", "echo hello; exit 4"}
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 4 {
		t.Errorf("exit %d", res.ExitCode)
	}
	out, _ := os.ReadFile(filepath.Join(res.Dir, "output.log"))
	if string(out) != "hello\r\n" {
		t.Errorf("output.log %q", out)
	}
	if l := ofType(events(t, res), "dev.qory.run.log"); len(l) != 1 || data(l[0])["stream"] != "terminal" {
		t.Errorf("log %v", l)
	}
	if size := data(events(t, res)[0])["terminal"]; fmt.Sprint(size) != "map[cols:80 rows:24]" {
		t.Errorf("run.started terminal %v; want the default when stdin is not a terminal", size)
	}
}

// TestAHeadlessArgumentRunsOnPipesWhateverTheCallerHas pins the inference: a caller at
// a terminal that starts the runtime with an argument its descriptor names as headless,
// -p for Claude Code, gets a session on pipes, recorded as not interactive and with its
// structured output read, exactly as if it had said headless. A runtime that names no
// such argument keeps the caller's pseudo-terminal, -p or not.
func TestAHeadlessArgumentRunsOnPipesWhateverTheCallerHas(t *testing.T) {
	t.Run("the descriptor names it", func(t *testing.T) {
		sp := spec(t, nil)
		sp.Interactive = true
		sp.Args = append(sp.Args, "-p", "Reply pong")
		res, err := session.Run(context.Background(), sp)
		if err != nil {
			t.Fatal(err)
		}
		evs := events(t, res)
		started := data(evs[0])
		if started["interactive"] != false || started["terminal"] != nil {
			t.Errorf("run.started %v; want not interactive and no terminal size", started)
		}
		if l := ofType(evs, "dev.qory.run.log"); len(l) == 0 || data(l[0])["stream"] == "terminal" {
			t.Errorf("log %v; want the streams of pipes", l)
		}
		if r := ofType(evs, "dev.qory.session.result"); len(r) != 1 || data(r[0])["result"] != "done" {
			t.Errorf("session.result %v; want the output read", r)
		}
	})
	t.Run("the runtime names none", func(t *testing.T) {
		sp := spec(t, nil)
		sp.Forwarder = nil
		sp.Interactive = true
		sp.Runtime = runtimes.Bare("other-agent")
		sp.Command = "sh"
		sp.Args = []string{"-c", "echo hello", "sh", "-p"}
		res, err := session.Run(context.Background(), sp)
		if err != nil {
			t.Fatal(err)
		}
		evs := events(t, res)
		if started := data(evs[0]); started["interactive"] != true || started["terminal"] == nil {
			t.Errorf("run.started %v; want the caller's terminal kept", started)
		}
		if l := ofType(evs, "dev.qory.run.log"); len(l) != 1 || data(l[0])["stream"] != "terminal" {
			t.Errorf("log %v", l)
		}
	})
}

// TestInteractiveRunFollowsTheTerminalSize pins the size in the record: the
// pseudo-terminal starts at the size of the terminal stdin is, reported in run.started,
// and when that terminal is resized the pseudo-terminal follows and run.resized says so
// at the sequence where it did, before the output drawn on the new size.
func TestInteractiveRunFollowsTheTerminalSize(t *testing.T) {
	master, tty, err := pty.Open()
	if err != nil {
		t.Skip("no pseudo-terminal:", err)
	}
	defer master.Close()
	defer tty.Close()
	if err := pty.Setsize(master, &pty.Winsize{Cols: 100, Rows: 40}); err != nil {
		t.Fatal(err)
	}
	var stream, out syncBuffer
	sp := spec(t, nil)
	sp.Forwarder = nil
	sp.Interactive = true
	sp.Stdin = tty
	sp.Stdout = &out
	sp.Events = &stream
	sp.Command = "sh"
	sp.Args = []string{"-c", "stty size; read line; stty size"}
	done := make(chan *session.Result, 1)
	go func() {
		res, err := session.Run(context.Background(), sp)
		if err != nil {
			t.Error(err)
		}
		done <- res
	}()
	waitFor(t, func() bool { return strings.Contains(out.String(), "40 100") })
	if err := pty.Setsize(master, &pty.Winsize{Cols: 120, Rows: 50}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return strings.Contains(stream.String(), `"dev.qory.run.resized"`) })
	if _, err := io.WriteString(master, "go\n"); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res == nil {
		t.FailNow()
	}
	evs := events(t, res)
	if size := data(evs[0])["terminal"]; fmt.Sprint(size) != "map[cols:100 rows:40]" {
		t.Errorf("run.started terminal %v", size)
	}
	resized := ofType(evs, "dev.qory.run.resized")
	if len(resized) != 1 || fmt.Sprint(data(resized[0])) != "map[cols:120 rows:50]" {
		t.Fatalf("run.resized %v", resized)
	}
	// The sequence: what was drawn before the resize is logged before it, what was
	// drawn after it after.
	var before, after []byte
	seen := false
	for _, e := range evs {
		if e["type"] == "dev.qory.run.resized" {
			seen = true
		} else if e["type"] == "dev.qory.run.log" {
			b, _ := base64.StdEncoding.DecodeString(data(e)["bytes"].(string))
			if seen {
				after = append(after, b...)
			} else {
				before = append(before, b...)
			}
		}
	}
	if !strings.Contains(string(before), "40 100") || strings.Contains(string(before), "50 120") {
		t.Errorf("logged before the resize: %q", before)
	}
	if !strings.Contains(string(after), "50 120") {
		t.Errorf("logged after the resize: %q", after)
	}
}

// syncBuffer is a buffer written from the run and read by the test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestContextEndStopsTheRuntime pins that a cancelled context ends the session with a
// signal, recorded as such.
func TestContextEndStopsTheRuntime(t *testing.T) {
	sp := spec(t, nil)
	sp.Forwarder = nil
	sp.Command = "sh"
	sp.Args = []string{"-c", "sleep 30"}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	res, err := session.Run(ctx, sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != -1 || res.Signal != "SIGTERM" || res.State != "failed" {
		t.Errorf("result %+v", res)
	}
}

func TestTimeoutStopsTheRuntimeAndIsTheReason(t *testing.T) {
	sp := spec(t, nil)
	sp.Forwarder = nil
	sp.Command = "sh"
	sp.Args = []string{"-c", "sleep 30"}
	sp.Timeout = 300 * time.Millisecond
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.Signal != "SIGTERM" || res.State != "failed" {
		t.Errorf("result %+v", res)
	}
	exited := ofType(events(t, res), "dev.qory.run.exited")
	if len(exited) != 1 || data(exited[0])["reason"] != "timeout" {
		t.Errorf("run.exited %v", exited)
	}
	// A limit that was not reached is not a reason.
	sp = spec(t, nil)
	sp.Timeout = time.Minute
	if res, err = runWithSettingsEnv(t, sp); err != nil {
		t.Fatal(err)
	}
	if exited := ofType(events(t, res), "dev.qory.run.exited"); res.TimedOut || data(exited[0])["reason"] != nil {
		t.Errorf("a run within its limit timed out: %+v %v", res, exited)
	}
}

func TestRunIDAndLabelsAreTheCallers(t *testing.T) {
	const id = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	sp := spec(t, nil)
	sp.RunID = id
	sp.Labels = map[string]string{"run_key": "queue/1234", "repository": "acme/shop", "issue": "77"}
	res, err := runWithSettingsEnv(t, sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.RunID != id || filepath.Base(res.Dir) != id {
		t.Errorf("result %+v", res)
	}
	started := ofType(events(t, res), "dev.qory.run.started")
	if labels, _ := data(started[0])["labels"].(map[string]any); len(labels) != 3 || labels["run_key"] != "queue/1234" {
		t.Errorf("run.started %v", started)
	}
	many := map[string]string{}
	for i := range session.MaxLabels + 1 {
		many[fmt.Sprint("k", i)] = "v"
	}
	for name, change := range map[string]func(*session.Spec){
		"a path as the run id":  func(s *session.Spec) { s.RunID = "../../elsewhere" },
		"an upper-case run id":  func(s *session.Spec) { s.RunID = strings.ToUpper(id) },
		"an upper-case key":     func(s *session.Spec) { s.Labels = map[string]string{"Repo": "x"} },
		"an empty key":          func(s *session.Spec) { s.Labels = map[string]string{"": "x"} },
		"a long value":          func(s *session.Spec) { s.Labels = map[string]string{"k": strings.Repeat("v", 257)} },
		"too many labels":       func(s *session.Spec) { s.Labels = many },
		"a negative time limit": func(s *session.Spec) { s.Timeout = -time.Second },
	} {
		sp := spec(t, nil)
		change(&sp)
		if _, err := session.Run(context.Background(), sp); err == nil {
			t.Errorf("%s: the run started", name)
		}
		if entries, _ := os.ReadDir(sp.RunsDir); len(entries) > 0 {
			t.Errorf("%s: a run directory was made: %v", name, entries)
		}
	}
}

// TestAboutIsInRunStartedAlone pins what the run is about: an About CheckAbout refuses
// is no run, before the server sees a request or a run directory is made; a valid one
// is in run.started as the caller passed it, details compacted, and in no other event
// and not in the run configuration request's query; an empty one leaves no about.
func TestAboutIsInRunStartedAlone(t *testing.T) {
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"observe"}}`, "sha256="+strings.Repeat("3", 64))
	sp := spec(t, nil)
	sp.Forwarder = nil
	sp.Server, sp.Heartbeat = c.server(), time.Second
	sp.About = &session.About{Title: "Example",
		Subjects: []session.Subject{{Type: "example"}}}
	_, err := session.Run(context.Background(), sp)
	var ae *session.AboutError
	if !errors.As(err, &ae) || err.Error() != "about.subjects[0].ref is empty" {
		t.Errorf("an About without a ref: %v", err)
	}
	if n := c.hits.Load(); n != 0 {
		t.Errorf("the server saw %d requests of a refused run", n)
	}
	if entries, _ := os.ReadDir(sp.RunsDir); len(entries) > 0 {
		t.Errorf("a run directory was made: %v", entries)
	}

	sp = spec(t, nil)
	sp.Forwarder = nil
	sp.Server, sp.Heartbeat = c.server(), time.Second
	sp.Labels = map[string]string{"forge": "example.test"}
	sp.About = &session.About{
		Kind:  "example-kind",
		Title: "Example title of the run",
		Subjects: []session.Subject{
			{Type: "example", Ref: "example-ref-7", URL: "https://qory.example/examples/7",
				Title: "Example subject title"},
			{Type: "example.other", Ref: "example-ref-8"},
		},
		Details: json.RawMessage(`{ "example-key" : [ 1, { "b" : { "c" : true } } ] }`),
	}
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	want := `"about":{"kind":"example-kind","title":"Example title of the run",` +
		`"subjects":[{"type":"example","ref":"example-ref-7",` +
		`"url":"https://qory.example/examples/7","title":"Example subject title"},` +
		`{"type":"example.other","ref":"example-ref-8"}],` +
		`"details":{"example-key":[1,{"b":{"c":true}}]}}`
	b, err := os.ReadFile(filepath.Join(res.Dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != len(evs) {
		t.Fatalf("%d lines for %d events", len(lines), len(evs))
	}
	started := 0
	for i, line := range lines {
		if evs[i]["type"] == "dev.qory.run.started" {
			started++
			if !strings.Contains(line, want) {
				t.Errorf("run.started does not contain %s:\n%s", want, line)
			}
			continue
		}
		_, ok := data(evs[i])["about"]
		if ok || strings.Contains(line, "example-ref-7") ||
			strings.Contains(line, "example-key") ||
			strings.Contains(line, "Example title of the run") {
			t.Errorf("%s contains the about:\n%s", evs[i]["type"], line)
		}
	}
	if started != 1 {
		t.Errorf("%d run.started events", started)
	}
	c.mu.Lock()
	query := c.query
	c.mu.Unlock()
	if query != "forge=example.test" {
		t.Errorf("the run configuration request's query %q; want the labels alone", query)
	}

	sp = spec(t, nil)
	sp.Forwarder = nil
	sp.About = &session.About{Details: json.RawMessage(" { } ")}
	if res, err = session.Run(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	if st := ofType(events(t, res), "dev.qory.run.started"); len(st) != 1 {
		t.Errorf("run.started events %v", st)
	} else if about, ok := data(st[0])["about"]; ok {
		t.Errorf("an empty About is in run.started as %v", about)
	}
}

func TestPolicyUnderACeilingNarrowsOnly(t *testing.T) {
	enforce := func(allow ...string) *session.Policy {
		return &session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "enforce", Allow: allow}}
	}
	observe := &session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: "observe"}}
	run := enforce("api.github.com", "pypi.org")
	if got := run.Under(nil); got != run {
		t.Errorf("under no ceiling %+v", got)
	}
	if got := run.Under(observe); got != run {
		t.Errorf("under an observing ceiling %+v", got)
	}
	got := run.Under(enforce("*.github.com", "api.anthropic.com"))
	if got.Egress.Mode != "enforce" || len(got.Egress.Allow) != 1 || got.Egress.Allow[0] != "api.github.com" {
		t.Errorf("under an enforcing ceiling %+v", got)
	}
	if got := observe.Under(enforce("api.anthropic.com")); got.Egress.Mode != "enforce" || len(got.Egress.Allow) != 1 {
		t.Errorf("an observing policy under an enforcing ceiling %+v", got)
	}
	if _, err := session.ReadPolicy("run.yaml", []byte("version: 1\negress:\n  mode: enforce\n  allow: [api.github.com]\n")); err != nil {
		t.Error(err)
	}
	if _, err := session.ReadPolicy("run.yaml", []byte("version: 1\negress:\n  mode: enforce\n  allow: [\"api.github.com:443\"]\n")); err == nil {
		t.Error("an allow entry with a port was read")
	}
}

func TestStopGraceIsHowLongTheRuntimeHasToLeave(t *testing.T) {
	sp := spec(t, nil)
	sp.Forwarder = nil
	sp.Command = "sh"
	sp.Args = []string{"-c", "trap '' TERM; sleep 30 & wait; wait"}
	sp.Timeout = 200 * time.Millisecond
	sp.StopGrace = 300 * time.Millisecond
	start := time.Now()
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.Signal != "SIGKILL" {
		t.Errorf("result %+v", res)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("a runtime that ignores SIGTERM ran %s, past the grace", took)
	}
}

func TestStopSignalIsTheOneTheRunNames(t *testing.T) {
	sp := spec(t, nil)
	sp.Forwarder = nil
	sp.Command = "sh"
	sp.Args = []string{"-c", "trap 'exit 7' INT; trap '' TERM; sleep 30 & wait"}
	sp.Timeout = 300 * time.Millisecond
	sp.StopSignal = "SIGINT"
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.ExitCode != 7 || res.Signal != "" {
		t.Errorf("a runtime that leaves on SIGINT alone: result %+v", res)
	}
	for _, name := range []string{"SIGKILL", "INT", "sigint", "9"} {
		sp := spec(t, nil)
		sp.StopSignal = name
		if _, err := session.Run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), "stop signal") {
			t.Errorf("stop signal %q: %v", name, err)
		}
	}
}

// TestResendCompletesAndDeliversTheRecordOfARunThatIsOver pins what a job's last step
// relies on: what the receiver did not get is sent, once; a record its runner left
// unfinished is closed with the reason; and a run that still goes is left alone.
func TestResendCompletesAndDeliversTheRecordOfARunThatIsOver(t *testing.T) {
	c := newControl(t)
	store := c.store
	cfg := c.server()

	// A run nobody received, as one whose receiver was away.
	sp := spec(t, nil)
	sp.Local = true
	res, err := runWithSettingsEnv(t, sp)
	if err != nil {
		t.Fatal(err)
	}
	all := len(events(t, res))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sent, err := session.Resend(ctx, resend(res.Dir, cfg))
	if err != nil {
		t.Fatal(err)
	}
	if sent.Sent != all || sent.Undelivered != 0 || sent.Closed || store.Count() != all {
		t.Errorf("first resend %+v, store holds %d of %d", sent, store.Count(), all)
	}
	if again, err := session.Resend(ctx, resend(res.Dir, cfg)); err != nil || again.Sent != 0 || store.Count() != all {
		t.Errorf("second resend %+v, %v, store holds %d", again, err, store.Count())
	}

	// A record its runner died over: no run.exited, and half a line at the end.
	sp = spec(t, nil)
	sp.Local = true
	if res, err = runWithSettingsEnv(t, sp); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(res.Dir, "events.jsonl")
	b, _ := os.ReadFile(file)
	lines := strings.SplitAfter(strings.TrimSuffix(string(b), "\n"), "\n")
	cut := strings.Join(lines[:len(lines)-1], "") + `{"specversion":"1.0","id":"half`
	if err := os.WriteFile(file, []byte(cut), 0o644); err != nil {
		t.Fatal(err)
	}
	before := store.Count()
	sent, err = session.Resend(ctx, resend(res.Dir, cfg))
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	last := evs[len(evs)-1]
	if !sent.Closed || last["type"] != "dev.qory.run.exited" || data(last)["reason"] != "runner_lost" || data(last)["state"] != "failed" {
		t.Errorf("the record was not closed: %+v, last event %v", sent, last)
	}
	if len(evs) != len(lines) || store.Count()-before != len(evs) {
		t.Errorf("%d events in the file, want %d; the store got %d", len(evs), len(lines), store.Count()-before)
	}

	// A run that still goes.
	sp = spec(t, nil)
	sp.Forwarder = nil
	sp.Local = true
	sp.Command = "sh"
	sp.Args = []string{"-c", "sleep 30"}
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); session.Run(runCtx, sp) }()
	dir := filepath.Join(sp.RunsDir, sp.RunID)
	for range 100 {
		if _, err := os.Stat(filepath.Join(dir, "lock")); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := session.Resend(ctx, resend(dir, cfg)); !errors.Is(err, session.ErrRunning) {
		t.Errorf("resend of a run that still goes: %v", err)
	}
	stop()
	<-done
}

// leaves is a runtime of the test's own, to show that the session asks the interface
// and knows no runtime: it prepares nothing, reads nothing, and names how it is asked to
// leave.
type leaves struct {
	runtimes.Runtime
	stop     runtimes.Stop
	prepared *runtimes.Attach
}

func (l leaves) Stop() runtimes.Stop { return l.stop }
func (l leaves) Prepare(a runtimes.Attach) (runtimes.Launch, error) {
	*l.prepared = a
	launch := a.Launch
	launch.Env = []string{"ADDED_BY_THE_RUNTIME=yes"}
	return launch, nil
}

func TestTheRuntimeSaysHowItIsAskedToLeaveAndTheRunMaySayOtherwise(t *testing.T) {
	script := `test "$ADDED_BY_THE_RUNTIME" = yes || exit 9; trap 'exit 7' INT; trap 'exit 8' HUP; trap '' TERM; sleep 30 & wait`
	for name, c := range map[string]struct {
		named string
		code  int
	}{"the runtime's": {"", 7}, "the run's": {"SIGHUP", 8}} {
		t.Run(name, func(t *testing.T) {
			sp := spec(t, nil)
			var got runtimes.Attach
			sp.Runtime = leaves{Runtime: runtimes.Bare("other-agent"), stop: runtimes.Stop{Signal: "SIGINT", Grace: 20 * time.Second}, prepared: &got}
			sp.Command, sp.Args = "sh", []string{"-c", script}
			sp.Timeout = 300 * time.Millisecond
			sp.StopSignal = c.named
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if !res.TimedOut || res.ExitCode != c.code {
				t.Errorf("result %+v", res)
			}
			if got.RunDir != res.Dir || got.Launch.Command != "sh" || len(got.Forwarder) == 0 {
				t.Errorf("Prepare was given %+v", got)
			}
			started := ofType(events(t, res), "dev.qory.run.started")
			if len(started) != 1 || data(started[0])["runtime"] != "other-agent" {
				t.Errorf("run.started %v", started)
			}
		})
	}
	sp := spec(t, nil)
	sp.Runtime = leaves{Runtime: runtimes.Bare("other-agent"), stop: runtimes.Stop{Signal: "SIGKILL"}, prepared: new(runtimes.Attach)}
	if _, err := session.Run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), "runtime other-agent") {
		t.Errorf("a runtime that names SIGKILL: %v", err)
	}
}

func TestNoRuntimeIsABareOneNamedAfterTheCommand(t *testing.T) {
	sp := spec(t, nil)
	sp.Runtime = nil
	sp.Command, sp.Args = "sh", []string{"-c", "exit 3"}
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	started := ofType(events(t, res), "dev.qory.run.started")
	if res.ExitCode != 3 || len(started) != 1 || data(started[0])["runtime"] != "sh" {
		t.Errorf("%+v %v", res, started)
	}
	if _, err := os.Stat(filepath.Join(res.Dir, "settings.json")); !os.IsNotExist(err) {
		t.Error("something was prepared for a runtime the runner does not know")
	}
}

// TestPolicyUnderACeilingKeepsBothDenyLists pins that a deny holds whatever the modes:
// the ceiling's deny list is kept under observe, where the ceiling forbids nothing
// else; both lists meet, the ceiling's first, under enforce and when an observing
// policy takes the ceiling; and a policy with no deny under no deny carries none.
func TestPolicyUnderACeilingKeepsBothDenyLists(t *testing.T) {
	mk := func(mode string, allow, deny []string) *session.Policy {
		return &session.Policy{Version: 1, Egress: session.PolicyEgress{Mode: mode, Allow: allow, Deny: deny}}
	}
	join := func(p *session.Policy) string {
		return p.Egress.Mode + " " + strings.Join(p.Egress.Allow, ",") + " " + strings.Join(p.Egress.Deny, ",")
	}
	for _, c := range []struct {
		name         string
		run, ceiling *session.Policy
		want         string
	}{
		{"observe ceiling with a deny", mk("observe", nil, []string{"tracker.example"}), mk("observe", nil, []string{"*.ads.example"}), "observe  *.ads.example,tracker.example"},
		{"observe ceiling without a deny", mk("enforce", []string{"api.example"}, []string{"tracker.example"}), mk("observe", nil, nil), "enforce api.example tracker.example"},
		{"enforce ceiling, enforce run", mk("enforce", []string{"api.example"}, []string{"tracker.example"}), mk("enforce", []string{"*.example"}, []string{"*.ads.example", "tracker.example"}), "enforce api.example *.ads.example,tracker.example"},
		{"enforce ceiling, observe run", mk("observe", nil, []string{"tracker.example"}), mk("enforce", []string{"*.example"}, nil), "enforce *.example tracker.example"},
		{"no deny anywhere", mk("enforce", []string{"api.example"}, nil), mk("enforce", []string{"*.example"}, nil), "enforce api.example "},
	} {
		if got := join(c.run.Under(c.ceiling)); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if got := mk("enforce", []string{"api.example"}, nil).Under(mk("enforce", []string{"*.example"}, nil)); got.Egress.Deny != nil {
		t.Errorf("a deny list from nowhere: %v", got.Egress.Deny)
	}
	p, err := session.ReadPolicy("run.yaml", []byte("version: 1\negress:\n  mode: observe\n  deny: [tracker.example]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Egress.Deny, " ") != "tracker.example" {
		t.Errorf("deny read as %v", p.Egress.Deny)
	}
	if _, err := session.ReadPolicy("run.yaml", []byte("version: 1\negress:\n  mode: observe\n  deny: [\"tracker.example:443\"]\n")); err == nil {
		t.Error("a deny entry with a port was read")
	}
}

// TestServerRefusalsAreCoded pins the refusals of a run with a server, each no run
// with its code: no pin is apiary_public_key_missing before any request; a pin of
// another key is answer_unsigned; a refused instance is instance_limit at the ping,
// whose record holds the ping alone; and a run without its access key, or with a
// heartbeat interval the ping cannot announce, sends nothing.
func TestServerRefusalsAreCoded(t *testing.T) {
	c := newControl(t)
	run := func(change func(*session.Spec)) (session.Spec, error) {
		sp := spec(t, nil)
		sp.Forwarder = nil
		sp.Server, sp.Heartbeat = c.server(), time.Second
		change(&sp)
		_, err := session.Run(context.Background(), sp)
		return sp, err
	}
	runs := func(sp session.Spec) int {
		entries, _ := os.ReadDir(sp.RunsDir)
		return len(entries)
	}
	before := c.hits.Load()
	for name, change := range map[string]func(*session.Spec){
		"no pin":                            func(sp *session.Spec) { sp.Server.ApiaryPublicKey = nil },
		"no access key":                     func(sp *session.Spec) { sp.AccessKey = nil },
		"no instance id":                    func(sp *session.Spec) { sp.InstanceID = "" },
		"a long heartbeat":                  func(sp *session.Spec) { sp.Heartbeat = 301 * time.Second },
		"a heartbeat of a part of a second": func(sp *session.Spec) { sp.Heartbeat = 1500 * time.Millisecond },
		"an odd instance name":              func(sp *session.Spec) { sp.InstanceName = "build 01" },
	} {
		sp, err := run(change)
		if err == nil || runs(sp) != 0 || (name == "no pin" && refusal(err) != "apiary_public_key_missing") {
			t.Errorf("%s: %v, %d run directories", name, err, runs(sp))
		}
	}
	if n := c.hits.Load() - before; n != 0 {
		t.Errorf("%d requests reached the server", n)
	}
	other := accesskey.Pin{{Alg: "ed25519", PublicKey: mustGenerate().PublicKey().String()}}
	if sp, err := run(func(sp *session.Spec) { sp.Server.ApiaryPublicKey = other }); refusal(err) != "answer_unsigned" || runs(sp) != 0 {
		t.Errorf("a pin of another key: %v", err)
	}
	c.limit.Store(true)
	sp, err := run(func(*session.Spec) {})
	var r *session.Refusal
	if !errors.As(err, &r) || r.Code != "instance_limit" || r.Status != 409 || runs(sp) != 1 {
		t.Fatalf("an instance beyond the limit: %v", err)
	}
	entries, _ := os.ReadDir(sp.RunsDir)
	if evs, _ := os.ReadFile(filepath.Join(sp.RunsDir, entries[0].Name(), "events.jsonl")); strings.Count(string(evs), "\n") != 1 || !strings.Contains(string(evs), `"interval_seconds":1,`) {
		t.Errorf("the refused run's file:\n%s", evs)
	}
}

// TestHeartbeatsRunFromTheAcceptedPing pins the heartbeat with a server: the ping
// announces the interval, heartbeats start once the ping is accepted, so a slow start
// is covered too, and elapsed_seconds counts from the ping.
func TestHeartbeatsRunFromTheAcceptedPing(t *testing.T) {
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"observe"}}`, "sha256="+strings.Repeat("a", 64))
	c.slow.Store(2500)
	sp := spec(t, nil)
	sp.Forwarder = nil
	sp.Server, sp.Heartbeat = c.server(), time.Second
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	if evs[0]["type"] != "dev.qory.ping" || data(evs[0])["interval_seconds"] != 1.0 {
		t.Fatalf("first event %v", evs[0])
	}
	beats := 0
	for _, e := range evs[1:] {
		if e["type"] == "dev.qory.run.started" {
			break
		}
		if e["type"] != "dev.qory.run.heartbeat" {
			t.Errorf("before run.started: %v", e["type"])
		}
		beats++
	}
	if beats < 2 {
		t.Errorf("%d heartbeats before run.started, with a start of 2.5 s and an interval of 1 s", beats)
	}
	if last := evs[len(evs)-1]; last["type"] != "dev.qory.run.exited" {
		t.Errorf("last event %v", last["type"])
	}
}

// TestRunClosedStopsTheRuntime pins a signed 410 run_closed after the run started: the
// runtime is stopped as at its time limit, run.exited has the reason run_closed and
// the state failed, the result says so, and nothing after the closing answer reaches
// the server: the file sink holds run.exited, the server's copy does not.
func TestRunClosedStopsTheRuntime(t *testing.T) {
	c := newControl(t)
	sp := spec(t, nil)
	sp.Forwarder = nil
	sp.Server, sp.Heartbeat = c.server(), time.Second
	sp.Command = "sh"
	sp.Args = []string{"-c", "sleep 30"}
	sp.StopGrace = time.Second
	go func() {
		for c.store.Count() < 3 {
			time.Sleep(10 * time.Millisecond)
		}
		c.closed.Store(true)
	}()
	began := time.Now()
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(began); took > 15*time.Second {
		t.Errorf("the run took %s after the server closed it", took)
	}
	if !res.RunClosed || res.TimedOut || res.State != "failed" || res.Signal != "SIGTERM" {
		t.Errorf("result %+v", res)
	}
	evs := events(t, res)
	exited := ofType(evs, "dev.qory.run.exited")
	if len(exited) != 1 || data(exited[0])["reason"] != "run_closed" || data(exited[0])["state"] != "failed" || evs[len(evs)-1]["type"] != "dev.qory.run.exited" {
		t.Errorf("run.exited %v", exited)
	}
	b, _ := os.ReadFile(c.received)
	if strings.Contains(string(b), "dev.qory.run.exited") {
		t.Error("run.exited reached the server after it closed the run")
	}
	if again, err := session.Resend(context.Background(), resend(res.Dir, c.server())); err != nil || again.Sent != 0 {
		t.Errorf("a resend of a closed run: %+v, %v", again, err)
	}
}

// TestRunClosedBeforeTheStartIsRefused pins a signed 410 run_closed after the ping and
// before run.started: the start stops, the run is a refusal with the code run_closed,
// and the file sink, not the server, gets dev.qory.run.refused as the last event.
func TestRunClosedBeforeTheStartIsRefused(t *testing.T) {
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"observe"}}`, "sha256="+strings.Repeat("b", 64))
	c.closeOnFetch.Store(true)
	c.slow.Store(2500)
	sp := spec(t, nil)
	sp.Forwarder = nil
	sp.Server, sp.Heartbeat = c.server(), time.Second
	_, err := session.Run(context.Background(), sp)
	var r *session.Refusal
	if !errors.As(err, &r) || r.Code != "run_closed" || r.Status != 410 {
		t.Fatalf("a run closed before its start: %v", err)
	}
	entries, _ := os.ReadDir(sp.RunsDir)
	if len(entries) != 1 {
		t.Fatalf("%d run directories", len(entries))
	}
	evs := events(t, &session.Result{Dir: filepath.Join(sp.RunsDir, entries[0].Name())})
	last := evs[len(evs)-1]
	if last["type"] != "dev.qory.run.refused" || data(last)["code"] != "run_closed" || data(last)["status"] != 410.0 || len(ofType(evs, "dev.qory.run.started")) != 0 {
		t.Errorf("the record ends with %v", last)
	}
	b, _ := os.ReadFile(c.received)
	if strings.Contains(string(b), "dev.qory.run.refused") {
		t.Error("run.refused reached the server after it closed the run")
	}
}

// lineFunc is an events writer that hands each line to a function.
type lineFunc func([]byte)

func (f lineFunc) Write(b []byte) (int, error) { f(b); return len(b), nil }

// TestRunClosedBeforeTheRuntimeStartsEndsTheRun pins the race between the start and a
// close: a signed 410 run_closed that arrives after run.started and before the
// runtime starts ends the run as a closed one, run.exited with the reason run_closed
// and exit code -1, and a result with RunClosed, in place of an error that the
// runtime did not start.
func TestRunClosedBeforeTheRuntimeStartsEndsTheRun(t *testing.T) {
	c := newControl(t)
	sp := spec(t, nil)
	sp.Forwarder = nil
	sp.Server, sp.Heartbeat = c.server(), time.Second
	sp.Command = "sh"
	sp.Args = []string{"-c", "sleep 30"}
	once := sync.Once{}
	sp.Events = lineFunc(func(line []byte) {
		if !bytes.Contains(line, []byte(`"dev.qory.run.policy_applied"`)) {
			return
		}
		once.Do(func() {
			// Hold the start here, after run.started, until the server has closed the
			// run and the runner has read the answer.
			c.closed.Store(true)
			for c.closedAnswers.Load() == 0 {
				time.Sleep(10 * time.Millisecond)
			}
			time.Sleep(300 * time.Millisecond)
		})
	})
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatalf("a run closed before its runtime started: %v", err)
	}
	if !res.RunClosed || res.ExitCode != -1 || res.Signal != "" || res.State != "failed" {
		t.Errorf("result %+v", res)
	}
	evs := events(t, res)
	exited := ofType(evs, "dev.qory.run.exited")
	if len(exited) != 1 || data(exited[0])["reason"] != "run_closed" || data(exited[0])["exit_code"] != -1.0 {
		t.Errorf("run.exited %v", exited)
	}
}
