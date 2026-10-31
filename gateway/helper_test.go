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
	"slices"
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
	"github.com/qoryai/forager/sealed"
	"github.com/qoryai/forager/server"
)

const (
	testKey       = "ak_f1xt0re000000000"
	testInstance  = "i_test"
	testNode      = "nd_f1xt0re000000000"
	testWorkspace = "ws_f1xt0re000000000"
)

// The keys of the tests: the access key the gateway signs with, and the control's own
// signing key, which the gateway pins; each fresh, so no published key is used.
var (
	testAccessKey = mustGenerate()
	testSigner    = mustGenerate()
	testPin       = accesskey.Pin{{Alg: "ed25519", PublicKey: testSigner.PublicKey().String()}}
)

// envTool makes the test binary a tool when it is "serve": it listens where the gateway
// says and answers every request with its arguments and the request's path.
const envTool = "GATEWAY_TEST_TOOL"

func TestMain(m *testing.M) {
	if os.Getenv(envTool) != "serve" {
		os.Exit(m.Run())
	}
	ln, err := net.Listen("unix", os.Getenv(link.EnvToolListen))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Join(os.Args[1:], " ")+" "+r.URL.Path)
	}))
}

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
	// end, when set, is the end member of every 2xx to a delivery, the outcome the run's
	// starter gave, signed with the answer.
	end atomic.Pointer[server.ServerEnd]
	// attachRefusal, when set, answers every attach a signed refusal with its status
	// and code.
	attachRefusal atomic.Pointer[receiver.Refusal]

	mu sync.Mutex
	// node and workspaces are what the configuration document lists: the test node and
	// workspace unless asGateway made them a gateway key's, with no workspaces.
	node       string
	workspaces []string
	// runURL, when set, is the configuration document's run.url in place of the run
	// endpoint's.
	runURL string
	// attaches are the body of every attach as it came, each try included, and
	// attachLabels and attachAbout what an attach's answer gives back of the starter's
	// registration.
	attaches     [][]byte
	attachLabels map[string]string
	attachAbout  json.RawMessage
	run          []byte
	digest       string
	// labels are the labels of the last run the receiver decided on, and registrations
	// the body of every registration as it came, each try included.
	labels        map[string]string
	registrations [][]byte

	// attachInstances and deliveryInstances are the X-Qory-Instance-Id of every attach
	// and of every request to the events endpoint, in the order they came.
	attachInstances, deliveryInstances []string

	// accessKey is the key the control takes requests from, signer the key it signs
	// with, and pin the pin of signer.
	accessKey, signer *accesskey.Key
	pin               accesskey.Pin
	// secrets, when set, makes discovery list the secrets endpoint, whose answer seals
	// these values; secretsAnswer, when set, answers the request in its place; and
	// secretsRequests are the bodies of the secrets requests, as they came.
	secrets         map[string]string
	secretsAnswer   func(req server.SecretsRequest, sig string) (int, []byte)
	secretsRequests [][]byte
	// secretsURL, when set, is the secrets endpoint's URL discovery lists, in place of
	// the control's secretsPath; a query after the path still reaches answerSecrets.
	secretsURL string
	// attachedRuns are the runs whose attach the control answered.
	attachedRuns map[string]bool
}

// secretsPath is the control's secrets endpoint.
const secretsPath = "/v1/secrets"

// answerSecrets answers a secrets request as Qory Apiary does: a request signed by the
// control's access key gets the values sealed to it for the request's run, digest and
// credentials, signed; or secretsAnswer's answer.
func (c *control) answerSecrets(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	sig := r.Header.Get(server.HeaderSignature)
	if r.Method != http.MethodPost || !c.accessKey.PublicKey().VerifyRequest(accesskey.Request{AccessKeyID: r.Header.Get(server.HeaderAccessKeyID),
		InstanceID: r.Header.Get(server.HeaderInstanceID), Method: r.Method, Target: r.URL.RequestURI(), Body: body}, sig) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req server.SecretsRequest
	json.Unmarshal(body, &req)
	c.mu.Lock()
	c.secretsRequests = append(c.secretsRequests, body)
	values, answer := maps.Clone(c.secrets), c.secretsAnswer
	c.mu.Unlock()
	status, out := http.StatusOK, []byte(nil)
	if answer != nil {
		status, out = answer(req, sig)
	} else {
		out = c.seal(req, values, sealed.Expiry(time.Now()))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(server.HeaderSignature, c.signer.SignAnswer(accesskey.Answer{Status: status, RequestSignature: sig, Body: out}))
	w.WriteHeader(status)
	w.Write(out)
}

// seal is the secrets answer that seals values to the control's access key for the
// request, with exp.
func (c *control) seal(req server.SecretsRequest, values map[string]string, exp uint64) []byte {
	s := sealed.Sealing{AccessKeyID: testKey, PublicKey: c.accessKey.PublicKey(), RunID: req.RunID, RunConfiguration: req.RunConfiguration,
		Credentials: req.Credentials, Exp: exp}
	for _, name := range req.Credentials {
		s.Values = append(s.Values, sealed.NewValue(name, []byte(values[name])))
	}
	b, err := sealed.Seal(s, c.signer)
	if err != nil {
		panic(err)
	}
	return b
}

// runsPath is the control's run endpoint.
const runsPath = receiver.DefaultRunPath

func newControl(t *testing.T) *control {
	t.Helper()
	return newControlWith(t, testAccessKey, testSigner)
}

// newControlWith is a control whose access key is accessKey's and which signs with
// signer, the gateway's pin.
func newControlWith(t *testing.T, accessKey, signer *accesskey.Key) *control {
	t.Helper()
	received := filepath.Join(t.TempDir(), "received.jsonl")
	store, err := receiver.OpenFile(received)
	if err != nil {
		t.Fatal(err)
	}
	c := &control{store: store, received: received, node: testNode, workspaces: []string{testWorkspace}, accessKey: accessKey, signer: signer,
		pin: accesskey.Pin{{Alg: "ed25519", PublicKey: signer.PublicKey().String()}}}
	h := &receiver.Handler{
		Keys: func(k string) (receiver.AccessKey, bool) {
			return receiver.AccessKey{PublicKey: c.accessKey.PublicKey(), StoredSecrets: true}, k == testKey
		},
		Signer:        c.signer,
		Store:         store,
		Stop:          func(string) bool { return c.stop.Load() },
		Admit:         func(string, string) bool { return !c.limit.Load() },
		Configuration: c.configuration,
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
			// The receiver computes the digest of the bytes; c.digest is the digest of
			// the answers the control writes itself.
			return c.run, "", nil
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
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, runsPath+"/") && strings.HasSuffix(r.URL.Path, "/attach") {
			c.attach(w, r)
			return
		}
		if r.URL.Path == secretsPath {
			c.answerSecrets(w, r)
			return
		}
		if c.drop.Load() && r.URL.Path == "/v1/events" {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				conn.Close()
			}
			return
		}
		gone := false
		if r.URL.Path == "/v1/events" {
			c.mu.Lock()
			c.deliveryInstances = append(c.deliveryInstances, r.Header.Get(server.HeaderInstanceID))
			c.mu.Unlock()
			n := c.deliveries.Add(1)
			gone = c.goneAfter.Load() != 0 && n > c.goneAfter.Load()
		}
		if code := c.refuse.Load(); code != 0 && r.URL.Path == "/v1/events" {
			w.WriteHeader(int(code))
			return
		}
		if gone || (c.closed.Load() && r.URL.Path == "/v1/events") {
			body := []byte(`{"error":"run_closed"}`)
			w.Header().Set(server.HeaderSignature, c.signer.SignAnswer(accesskey.Answer{Status: http.StatusGone, RequestSignature: r.Header.Get(server.HeaderSignature), Body: body}))
			w.WriteHeader(http.StatusGone)
			w.Write(body)
			return
		}
		if e := c.end.Load(); e != nil && r.URL.Path == "/v1/events" {
			c.withEnd(w, r, h, *e)
			return
		}
		if id, ok := strings.CutPrefix(r.URL.Path, runsPath+"/"); ok && r.Method == http.MethodGet && c.wasAttached(id) {
			c.reloadAttached(w, r, h)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(c.srv.Close)
	t.Cleanup(func() { store.Close() })
	return c
}

// configuration is the control's configuration document and its digest.
func (c *control) configuration() ([]byte, string) {
	c.mu.Lock()
	node, workspaces, runURL := c.node, c.workspaces, c.runURL
	c.mu.Unlock()
	if runURL == "" {
		runURL = c.srv.URL + runsPath
	}
	pin, _ := json.Marshal(c.pin)
	doc := `{"version":1,"node_id":"` + node + `"`
	if workspaces != nil {
		ws, _ := json.Marshal(workspaces)
		doc += `,"workspaces":` + string(ws)
	}
	doc += `,"apiary_public_key":` + string(pin) + `,"events":{"url":"` + c.srv.URL + `/v1/events","types":["*"]}`
	doc += `,"run":{"url":"` + runURL + `"}`
	c.mu.Lock()
	if c.secrets != nil || c.secretsAnswer != nil {
		secretsURL := c.srv.URL + secretsPath
		if c.secretsURL != "" {
			secretsURL = c.secretsURL
		}
		doc += `,"secrets":{"url":"` + secretsURL + `"}`
	}
	c.mu.Unlock()
	doc += `}`
	return []byte(doc), "sha256=" + fmt.Sprint(len(doc))
}

// testGateway is the node id of the tests' gateway key.
const testGateway = "ng_f1xt0re000000000"

// asGateway makes the control's configuration document a gateway key's, testGateway,
// with no workspaces.
func (c *control) asGateway() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.node, c.workspaces = testGateway, nil
}

// attach answers an attach of the tests' access key, as Qory Apiary does: the run
// configuration the control serves, with the labels and about it gives back, its
// digest and the configuration's; or attachRefusal, signed. The run key is not read.
func (c *control) attach(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.attaches = append(c.attaches, b)
	c.attachInstances = append(c.attachInstances, r.Header.Get(server.HeaderInstanceID))
	doc, digest := c.run, c.digest
	labels, about := c.attachLabels, c.attachAbout
	c.mu.Unlock()
	if doc == nil {
		doc, digest = receiver.NoPolicy, "sha256="+strings.Repeat("0", 64)
	}
	_, conf := c.configuration()
	sig := r.Header.Get(server.HeaderSignature)
	if r.Header.Get(server.HeaderAccessKeyID) != testKey {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if ref := c.attachRefusal.Load(); ref != nil {
		body := []byte(`{"error":"` + ref.Code + `"}`)
		w.Header().Set(server.HeaderConfiguration, conf)
		w.Header().Set(server.HeaderSignature, c.signer.SignAnswer(accesskey.Answer{Status: ref.Status, RequestSignature: sig, Body: body, Configuration: conf}))
		w.WriteHeader(ref.Status)
		w.Write(body)
		return
	}
	var m map[string]json.RawMessage
	json.Unmarshal(doc, &m)
	if labels != nil {
		m["labels"], _ = json.Marshal(labels)
	}
	if about != nil {
		m["about"] = about
	}
	body, _ := json.Marshal(m)
	c.mu.Lock()
	if c.attachedRuns == nil {
		c.attachedRuns = map[string]bool{}
	}
	c.attachedRuns[strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, runsPath+"/"), "/attach")] = true
	c.mu.Unlock()
	w.Header().Set(server.HeaderConfiguration, conf)
	w.Header().Set(server.HeaderRunConfiguration, digest)
	w.Header().Set("ETag", `"`+digest+`"`)
	w.Header().Set(server.HeaderSignature, c.signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: sig, Body: body, Configuration: conf, RunConfiguration: digest}))
	w.Write(body)
}

// wasAttached reports whether the control answered an attach of the run.
func (c *control) wasAttached(runID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.attachedRuns[runID]
}

// reloadAttached answers a reload of an attached run as the receiver does, and, where
// the receiver has no registration of it yet because the control answered the attach,
// as Qory Apiary does: the run configuration it serves, its bytes as they are, signed.
func (c *control) reloadAttached(w http.ResponseWriter, r *http.Request, h http.Handler) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		maps.Copy(w.Header(), rec.Header())
		w.WriteHeader(rec.Code)
		w.Write(rec.Body.Bytes())
		return
	}
	c.mu.Lock()
	doc, digest := c.run, c.digest
	c.mu.Unlock()
	_, conf := c.configuration()
	sig := r.Header.Get(server.HeaderSignature)
	w.Header().Set(server.HeaderConfiguration, conf)
	w.Header().Set(server.HeaderRunConfiguration, digest)
	w.Header().Set("ETag", `"`+digest+`"`)
	w.Header().Set(server.HeaderSignature, c.signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: sig, Body: doc, Configuration: conf, RunConfiguration: digest}))
	w.Write(doc)
}

// attached are the bodies of the attaches the control was sent.
func (c *control) attached() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.attaches)
}

// instances are the X-Qory-Instance-Id of the attaches and of the deliveries the
// control was sent.
func (c *control) instances() (attaches, deliveries []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.attachInstances), slices.Clone(c.deliveryInstances)
}

// withEnd answers a delivery as the receiver does, and a 2xx with the end member e,
// signed again over its body.
func (c *control) withEnd(w http.ResponseWriter, r *http.Request, h http.Handler, e server.ServerEnd) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code/100 != 2 {
		maps.Copy(w.Header(), rec.Header())
		w.WriteHeader(rec.Code)
		w.Write(rec.Body.Bytes())
		return
	}
	end := map[string]string{"state": e.State}
	if e.Reason != "" {
		end["reason"] = e.Reason
	}
	body, _ := json.Marshal(map[string]any{"end": end})
	maps.Copy(w.Header(), rec.Header())
	w.Header().Set(server.HeaderSignature, c.signer.SignAnswer(accesskey.Answer{Status: rec.Code, RequestSignature: r.Header.Get(server.HeaderSignature), Body: body,
		Configuration: rec.Header().Get(server.HeaderConfiguration), RunConfiguration: rec.Header().Get(server.HeaderRunConfiguration)}))
	w.WriteHeader(rec.Code)
	w.Write(body)
}

// serve makes the control serve a run configuration with the policy. The answers the
// control writes itself, an attach's and an attached run's reload, carry a digest of
// the test's choosing: sha256= and 64 hex digits; the receiver's carry the digest of
// the document's bytes.
func (c *control) serve(policy string, digest byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.run, c.digest = []byte(`{"version":1,"security_policy":`+policy+`}`), "sha256="+strings.Repeat(string(digest), 64)
}

// serveDocument makes the control serve the run configuration document doc, under a
// digest as serve's.
func (c *control) serveDocument(doc string, digest byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.run, c.digest = []byte(doc), "sha256="+strings.Repeat(string(digest), 64)
}

func (c *control) server() *gateway.Server {
	return &gateway.Server{Version: 1, URL: c.srv.URL, AccessKeyID: testKey, ApiaryPublicKey: c.pin, AccessKey: c.accessKey, InstanceID: testInstance}
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
	// links are the link of each run opened on the local link, by run id, which names
	// its run on every batch, as a session's does.
	links map[string]*server.Link
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
	h.links = map[string]*server.Link{}
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

// keep notes the proxy secret and the stack proxy secret of a run answer: neither may
// reach a report.
func (h *harness) keep(a *server.LinkRunAnswer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.secrets = append(h.secrets, a.ProxySecret, a.StackProxySecret)
}

// opened reports whether the harness opened the run on the local link.
func (h *harness) opened(runID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.links[runID] != nil
}

// linkOf is the link of a run the harness opened on the local link, which names the
// run on its batches; the harness's own, which names none, for another.
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

// join joins a session to a run the harness opened on the local link, with the names
// it passes.
func (h *harness) join(runID string, passes ...string) (*server.LinkJoinAnswer, error) {
	return h.linkOf(runID).Join(context.Background(), server.LocalOrigin+"/v1/run-configuration", runID, server.LinkJoinRequest{Passes: passes, ModelKey: true})
}

// joined joins a session to the run and returns its number.
func (h *harness) joined(runID string, passes ...string) int {
	h.t.Helper()
	a, err := h.join(runID, passes...)
	if err != nil {
		h.t.Fatal(err)
	}
	return a.Session
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

// started is the session's run.started of a run with the labels.
func started(runID string, labels map[string]string) map[string]any {
	data := map[string]any{"opened_by": "run", "forager_version": "test"}
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

// sessionStarted is the session's dev.qory.session.started of the join numbered n.
func sessionStarted(runID string, n int) map[string]any {
	return ev(runID, event.SessionStarted, map[string]any{"session": n, "runtime": "bare", "command": "true", "args": []string{}, "dir": "/work", "interactive": false})
}

// sessionExited is the session's dev.qory.session.exited of the join numbered n, its
// runtime exited 0.
func sessionExited(runID string, n int) map[string]any {
	return ev(runID, event.SessionExited, map[string]any{"session": n, "state": "succeeded", "exit_code": 0, "duration_ms": 5})
}

func exited(runID string) map[string]any {
	return ev(runID, event.RunExited, map[string]any{"state": "succeeded", "exit_code": 0, "duration_ms": 5})
}

// raw is a client of the link that sends what the session's client never would.
func raw(t *testing.T, l link.Local) *http.Client {
	t.Helper()
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", l.Socket)
	}}}
}

// refusalOf posts body to path on the link and returns the status and the members of
// the refusal it answers. A batch carries X-Qory-Run-Id, the run its first event
// names, when the harness opened it.
func (h *harness) refusalOf(path, body string) (int, map[string]any) {
	h.t.Helper()
	contentType := server.LinkContentType
	var header http.Header
	if path == "/v1/events" {
		contentType = server.ContentType
		if id := subjectOf([]byte(body)); h.opened(id) {
			header = http.Header{server.HeaderRunID: {id}}
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
// before the client has written everything: a write refused with EPIPE, ECONNRESET or
// ENOTCONN (macOS returns ENOTCONN when the close comes first) is that close, as is a
// read that ends in EOF or one of those errors before any byte. Any answer byte fails.
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

// closedByPeer reports whether err is the peer's close: a broken pipe, a reset or a
// socket that is no longer connected.
func closedByPeer(err error) bool {
	return errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ENOTCONN)
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
			if _, err := io.WriteString(c, link.RelayLine(secret)); err != nil {
				c.Close()
				return nil, err
			}
			return c, nil
		},
		DisableKeepAlives: true,
	}}
}
