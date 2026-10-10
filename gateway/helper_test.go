package gateway_test

import (
	"bufio"
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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/server"
)

const (
	testKey      = "ak_f1xt0re000000000"
	testInstance = "i_test"
	testNode     = "nd_f1xt0re000000000"
)

// The keys of the tests: the access key the gateway signs with, and the control's own
// signing key, which the gateway pins; each fresh, so no published key is used.
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

// control is a server of the contract for the tests: the reference receiver in front
// of a store, whose configuration document names its own events endpoint and run
// endpoint, and which answers a run's registration and its reload with the run
// configuration the test gives it, which it may change during a run, or with
// {"version":1} without one.
type control struct {
	srv      *httptest.Server
	store    *receiver.File
	received string
	// refuse, when set, is the status every delivery gets instead of an answer,
	// unsigned; closed answers every delivery a signed 410 run_closed, a server's 410
	// with a code, and stop every registration, reload and new event a signed 410
	// without a code; closeOnFetch sets closed once the run configuration is asked for,
	// at the registration or again; limit answers every new registration a signed 409
	// instance_limit.
	refuse                            atomic.Int32
	closed, stop, closeOnFetch, limit atomic.Bool
	// deliveries counts every request to the events endpoint.
	deliveries atomic.Int32
	// goneAfter, when not zero, answers every request to the events endpoint past that
	// count of deliveries a signed 410 run_closed, as closed does.
	goneAfter atomic.Int32
	// goneOnFetch answers every registration and reload a signed 410 run_closed.
	goneOnFetch atomic.Bool
	// drop, when set, closes every delivery's connection unanswered.
	drop atomic.Bool
	// fetches counts every request to the run endpoint: registrations and reloads.
	fetches atomic.Int32
	// slowEvents and slowFetch, when not zero, are how long every delivery and every
	// request to the run endpoint wait before they are taken; one whose client goes
	// first is not taken.
	slowEvents, slowFetch atomic.Int64
	// intercept, when set, is asked first of every request, and answers it when it
	// returns true.
	intercept atomic.Pointer[func(http.ResponseWriter, *http.Request) bool]

	mu     sync.Mutex
	run    []byte
	digest string
	// labels are the labels of the last run the receiver decided on, and registrations
	// the body of every registration as it came, each try included.
	labels        map[string]string
	registrations [][]byte
}

// runsPath is the control's run endpoint.
const runsPath = receiver.DefaultRunPath

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
		Stop:   func(string) bool { return c.stop.Load() },
		Admit:  func(string, string) bool { return !c.limit.Load() },
		Configuration: func() ([]byte, string) {
			pin, _ := json.Marshal(testPin)
			doc := `{"version":1,"node_id":"` + testNode + `","apiary_public_key":` + string(pin) + `,"events":{"url":"` + c.srv.URL + `/v1/events","types":["*"]}`
			doc += `,"run":{"url":"` + c.srv.URL + runsPath + `"}}`
			return []byte(doc), "sha256=" + fmt.Sprint(len(doc))
		},
		RunConfiguration: func(run receiver.Run) ([]byte, string, *receiver.Refusal) {
			if c.goneOnFetch.Load() {
				return nil, "", &receiver.Refusal{Status: http.StatusGone, Code: "run_closed"}
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			c.labels = maps.Clone(run.Labels)
			if c.run == nil {
				return receiver.NoPolicy, "", nil
			}
			return c.run, c.digest, nil
		},
	}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f := c.intercept.Load(); f != nil && (*f)(w, r) {
			return
		}
		isRuns := r.URL.Path == runsPath || strings.HasPrefix(r.URL.Path, runsPath+"/")
		slow := c.slowEvents.Load()
		if isRuns {
			slow = c.slowFetch.Load()
		}
		if slow != 0 {
			// The body read first, so a client that goes is seen to.
			b, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(b))
			select {
			case <-time.After(time.Duration(slow)):
			case <-r.Context().Done():
				return
			}
		}
		if isRuns {
			c.fetches.Add(1)
			if r.Method == http.MethodPost {
				b, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(b))
				c.mu.Lock()
				c.registrations = append(c.registrations, b)
				c.mu.Unlock()
			}
			if c.closeOnFetch.Load() {
				c.closed.Store(true)
			}
		}
		if c.drop.Load() && r.URL.Path == "/v1/events" {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				conn.Close()
			}
			return
		}
		gone := false
		if r.URL.Path == "/v1/events" {
			n := c.deliveries.Add(1)
			gone = c.goneAfter.Load() != 0 && n > c.goneAfter.Load()
		}
		if code := c.refuse.Load(); code != 0 && r.URL.Path == "/v1/events" {
			w.WriteHeader(int(code))
			return
		}
		if gone || (c.closed.Load() && r.URL.Path == "/v1/events") {
			body := []byte(`{"error":"run_closed"}`)
			w.Header().Set(server.HeaderSignature, testSigner.SignAnswer(accesskey.Answer{Status: http.StatusGone, RequestSignature: r.Header.Get(server.HeaderSignature), Body: body}))
			w.WriteHeader(http.StatusGone)
			w.Write(body)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(c.srv.Close)
	t.Cleanup(func() { store.Close() })
	return c
}

// serve makes the control serve a run configuration with the policy, under a digest
// of the test's choosing: sha256= and 64 hex digits.
func (c *control) serve(policy string, digest byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.run, c.digest = []byte(`{"version":1,"security_policy":`+policy+`}`), "sha256="+strings.Repeat(string(digest), 64)
}

func (c *control) server() *gateway.Server {
	return &gateway.Server{Version: 1, URL: c.srv.URL, AccessKeyID: testKey, ApiaryPublicKey: testPin, AccessKey: testAccessKey, InstanceID: testInstance}
}

// lines are the events the control stored, decoded.
func (c *control) lines(t *testing.T) []recorded {
	t.Helper()
	return readLines(t, c.received)
}

// recorded is one event of a record, decoded.
type recorded struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Subject  string         `json:"subject"`
	Sequence string         `json:"sequence"`
	Data     map[string]any `json:"data"`
}

func readLines(t *testing.T, file string) []recorded {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []recorded
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 4<<20)
	for sc.Scan() {
		var r recorded
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		out = append(out, r)
	}
	return out
}

func types(lines []recorded) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = l.Type
	}
	return out
}

// harness is one gateway of a test, the session's client of its link, and what the
// gateway reported.
type harness struct {
	t    *testing.T
	g    *gateway.Gateway
	cfg  gateway.Config
	link *server.Link
	dir  string

	mu      sync.Mutex
	reports []string
	secrets []string
	digests []server.Digests
	// runSecrets are the run secrets of the runs opened, by run id, and links the link of
	// each run opened on the local link, which carries its secret, as a session's does.
	runSecrets map[string]string
	links      map[string]*server.Link
}

// start starts a gateway with cfg, its Dir a fresh one unless cfg names one, and a
// client of its link. At the test's end the gateway is closed, and no line it reported
// holds a secret.
func start(t *testing.T, cfg gateway.Config) *harness {
	t.Helper()
	h := &harness{t: t, dir: cfg.Dir}
	if h.dir == "" {
		h.dir = t.TempDir()
	}
	cfg.Dir = h.dir
	cfg.Report = func(line string) {
		h.mu.Lock()
		h.reports = append(h.reports, line)
		h.mu.Unlock()
		t.Log("reported: " + line)
	}
	h.cfg = cfg
	g, err := gateway.Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.g = g
	h.secrets = append(h.secrets, g.LocalLink().Secret)
	h.runSecrets, h.links = map[string]string{}, map[string]*server.Link{}
	l := h.newLink()
	h.link = l
	t.Cleanup(func() {
		l.Close()
		h.mu.Lock()
		for _, rl := range h.links {
			rl.Close()
		}
		h.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		g.Close(ctx)
		cancel()
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, line := range h.reports {
			for _, s := range h.secrets {
				if strings.Contains(line, s) {
					t.Errorf("a report holds a secret: %s", line)
				}
			}
		}
	})
	return h
}

// newLink is a client of the gateway's local link, as each session's run has one.
func (h *harness) newLink() *server.Link {
	h.t.Helper()
	l, err := server.NewLocalLink(h.g.LocalLink(), accesskey.UserAgent("test"), func(d server.Digests) {
		h.mu.Lock()
		h.digests = append(h.digests, d)
		h.mu.Unlock()
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return l
}

// keep notes the secrets of a run answer: none may reach a report, and the run's
// secret is what the harness's requests of the run carry.
func (h *harness) keep(a *server.LinkRunAnswer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.secrets = append(h.secrets, a.ProxySecret, a.RunSecret)
	h.runSecrets[a.RunID] = a.RunSecret
}

// runSecretOf is the run secret of a run the harness opened, empty for another.
func (h *harness) runSecretOf(runID string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.runSecrets[runID]
}

// linkOf is the link of a run the harness opened on the local link, which carries its
// run secret; the harness's own, which carries none, for another.
func (h *harness) linkOf(runID string) *server.Link {
	h.mu.Lock()
	defer h.mu.Unlock()
	if l := h.links[runID]; l != nil {
		return l
	}
	return h.link
}

// subjectOf is the subject of a batch's first event, empty for none.
func subjectOf(body []byte) string {
	var evs []struct {
		Subject string `json:"subject"`
	}
	if json.Unmarshal(body, &evs) != nil || len(evs) == 0 {
		return ""
	}
	return evs[0].Subject
}

// open opens a run on the link.
func (h *harness) open(req server.LinkRunRequest) *server.LinkRunAnswer {
	h.t.Helper()
	a, err := h.tryOpen(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return a
}

func (h *harness) tryOpen(req server.LinkRunRequest) (*server.LinkRunAnswer, error) {
	if req.RunID == "" {
		req.RunID = event.NewRunID()
	}
	l := h.newLink()
	a, err := l.OpenRun(context.Background(), server.LocalOrigin+"/v1/run-configuration", req)
	if err != nil {
		l.Close()
		return a, err
	}
	h.keep(a)
	h.mu.Lock()
	h.links[a.RunID] = l
	h.mu.Unlock()
	return a, err
}

// post posts one batch of the run's events, on the link of the run its first event
// names.
func (h *harness) post(evs ...map[string]any) server.Delivery {
	h.t.Helper()
	body, err := json.Marshal(evs)
	if err != nil {
		h.t.Fatal(err)
	}
	d, err := h.linkOf(subjectOf(body)).Deliver(context.Background(), server.LocalOrigin+"/v1/events", event.NewID(), body, "")
	if err != nil {
		h.t.Fatal(err)
	}
	return d
}

// close closes the gateway.
func (h *harness) close() gateway.Delivery {
	h.t.Helper()
	d, err := h.g.Close(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	return d
}

// record is the gateway's record of a run.
func (h *harness) record(runID string) []recorded {
	h.t.Helper()
	return readLines(h.t, filepath.Join(h.dir, "runs", runID, "events.jsonl"))
}

func (h *harness) reported(part string) bool {
	return len(h.reportsWith(part)) > 0
}

// reportsWith are the lines the gateway reported that hold part.
func (h *harness) reportsWith(part string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, l := range h.reports {
		if strings.Contains(l, part) {
			out = append(out, l)
		}
	}
	return out
}

// ev is one of the session's events of the run, as a link batch carries it.
func ev(runID, typ string, data map[string]any) map[string]any {
	return map[string]any{
		"specversion": "1.0", "id": event.NewID(), "source": event.Source(runID), "type": typ, "subject": runID,
		"time": time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00"), "dataschema": event.DataSchema(typ), "data": data,
	}
}

// started is the session's run.started of a run on the local link with the labels,
// its credential none.
func started(runID string, labels map[string]string) map[string]any {
	return startedWith(runID, labels, event.CredentialNone)
}

// issuerStarted is the session's run.started of a run on the one address with the
// labels, its credential an issuer's.
func issuerStarted(runID string, labels map[string]string) map[string]any {
	return startedWith(runID, labels, event.CredentialStarter)
}

func startedWith(runID string, labels map[string]string, credential string) map[string]any {
	data := map[string]any{"opened_by": "session", "credential": credential, "forager_version": "test", "runtime": "bare", "command": "true", "args": []string{}, "dir": "/work", "interactive": false}
	if len(labels) > 0 {
		data["labels"] = labels
	}
	return ev(runID, event.RunStarted, data)
}

// applied is the session's run.policy_applied from what the gateway decides, with the
// session's own members.
func applied(runID string, members json.RawMessage) map[string]any {
	var data map[string]any
	if err := json.Unmarshal(members, &data); err != nil {
		panic(err)
	}
	data["variables"] = []any{}
	data["harness_hosts"] = []string{"harness.example"}
	return ev(runID, event.PolicyApplied, data)
}

func logged(runID string) map[string]any {
	return ev(runID, event.RunLog, map[string]any{"stream": "stdout", "bytes": "aGkK"})
}

func heartbeat(runID string) map[string]any {
	return ev(runID, event.RunHeartbeat, map[string]any{"elapsed_seconds": 1, "interval_seconds": 30})
}

func exited(runID string) map[string]any {
	return ev(runID, event.RunExited, map[string]any{"state": "succeeded", "exit_code": 0, "duration_ms": 5})
}

// raw is a client of the link that sends what the session's client never would.
func raw(t *testing.T, l link.Local) *http.Client {
	t.Helper()
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "unix", l.Socket)
		if err != nil {
			return nil, err
		}
		if err := link.WriteLinkPreamble(c, l.Secret); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}}}
}

// refusalOf posts body to path on the link and returns the status and the members of
// the refusal it answers. A batch carries the run secret of the run its first event
// names, when the harness opened it.
func (h *harness) refusalOf(path, body string) (int, map[string]any) {
	h.t.Helper()
	contentType := server.LinkContentType
	var header http.Header
	if path == "/v1/events" {
		contentType = server.ContentType
		if rs := h.runSecretOf(subjectOf([]byte(body))); rs != "" {
			header = http.Header{server.HeaderRunSecret: {rs}}
		}
	}
	status, got := rawPostWith(h.t, raw(h.t, h.g.LocalLink()), path, contentType, body, header)
	var r map[string]any
	if err := json.Unmarshal([]byte(got), &r); err != nil {
		h.t.Fatalf("%d %q: %v", status, got, err)
	}
	return status, r
}

// openBody is a run request of the run id, without a wall.
func openBody(runID string) string { return `{"version":1,"run_id":"` + runID + `","wall":false}` }

// closedUnanswered dials the link's socket, writes open and fails the test unless the
// gateway closes the connection without an answer byte. The gateway may close it
// before the client has written everything: a write refused with EPIPE or ECONNRESET
// is that close, as is a read that ends in EOF or a reset before any byte.
func closedUnanswered(t *testing.T, socket, name, open string) {
	t.Helper()
	c, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, open); err != nil {
		if !closedByPeer(err) {
			t.Errorf("%s: the write: %v", name, err)
		}
		return
	}
	b, err := io.ReadAll(c)
	if len(b) != 0 {
		t.Errorf("%s: answered %q", name, b)
	}
	if err != nil && !closedByPeer(err) {
		t.Errorf("%s: the read: %v", name, err)
	}
}

// closedByPeer reports whether err is the peer's close: a broken pipe or a reset.
func closedByPeer(err error) bool {
	return errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)
}

// rawPost posts body to path on the link and returns the status and the body.
func rawPost(t *testing.T, c *http.Client, path, contentType, body string) (int, string) {
	t.Helper()
	return rawPostWith(t, c, path, contentType, body, nil)
}

// rawPostWith is rawPost with the headers given besides.
func rawPostWith(t *testing.T, c *http.Client, path, contentType, body string, header http.Header) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, server.LocalOrigin+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// relay is an HTTP client whose every connection goes to the gateway's proxy, opening
// with the relay's preamble and the run's proxy secret, as the wall's relay does.
func relay(addr, secret string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			if _, err := io.WriteString(c, link.Preamble(link.RelayPreamble, secret)); err != nil {
				c.Close()
				return nil, err
			}
			return c, nil
		},
		DisableKeepAlives: true,
	}}
}
