package sink_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/sink"
)

// TestFileSinkWritesBothRecords pins events.jsonl as one line per event and
// output.log as the log chunks' bytes, and that a run directory is never reused.
func TestFileSinkWritesBothRecords(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	f, err := sink.NewFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := event.NewEmitter(event.NewRunID(), nil)
	f.Write(e.Make(event.RunStarted, map[string]any{"runtime": "x"}))
	f.Write(e.Make(event.RunLog, map[string]any{"stream": "terminal", "bytes": base64.StdEncoding.EncodeToString([]byte("hi\n"))}))
	f.Write(e.Make(event.RunLog, map[string]any{"stream": "terminal", "bytes": base64.StdEncoding.EncodeToString([]byte("there"))}))
	if err := f.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	events, _ := os.ReadFile(filepath.Join(dir, sink.EventsFile))
	if n := strings.Count(string(events), "\n"); n != 3 || !strings.Contains(string(events), `"sequence":"0000000002"`) {
		t.Errorf("events.jsonl:\n%s", events)
	}
	out, _ := os.ReadFile(filepath.Join(dir, sink.OutputFile))
	if string(out) != "hi\nthere" {
		t.Errorf("output.log %q", out)
	}
	if _, err := sink.NewFile(dir); err == nil {
		t.Error("a run directory was reused")
	}
}

// TestWriterSinkWritesTheLineTheFileHolds pins that the writer sink and the file sink
// write the same bytes for the same event, and that closing it leaves the stream open.
func TestWriterSinkWritesTheLineTheFileHolds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	f, err := sink.NewFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	both := sink.Multi{f, sink.NewWriter(&out)}
	e := event.NewEmitter(event.NewRunID(), nil)
	both.Write(e.Make(event.RunStarted, map[string]any{"runtime": "x"}))
	both.Write(e.Make(event.RunExited, map[string]any{"state": "succeeded"}))
	if err := both.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	events, _ := os.ReadFile(filepath.Join(dir, sink.EventsFile))
	if out.String() != string(events) || strings.Count(out.String(), "\n") != 2 {
		t.Errorf("the writer got\n%s\nthe file\n%s", out.String(), events)
	}
}

// The keys of the tests: the access key the sink signs with and the receiver's own,
// each fresh.
var (
	accessKey = mustGenerate()
	signer    = mustGenerate()
)

func mustGenerate() *accesskey.Key {
	k, err := accesskey.Generate()
	if err != nil {
		panic(err)
	}
	return k
}

// station is a receiver in front of a store, with a failure mode the test flips: a
// status every request gets, unsigned, instead of the receiver's answer.
type station struct {
	srv   *httptest.Server
	store *receiver.File
	fail  atomic.Int32
	hits  atomic.Int32
	// runDigest is the run configuration digest the last delivery carried.
	runDigest atomic.Pointer[string]
}

func newStation(t *testing.T, stop, closed func(string) bool) *station {
	t.Helper()
	store, err := receiver.OpenFile(filepath.Join(t.TempDir(), "received.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	s := &station{store: store}
	h := &receiver.Handler{
		Keys: func(string) (receiver.AccessKey, bool) {
			return receiver.AccessKey{PublicKey: accessKey.PublicKey()}, true
		},
		Signer:        signer,
		Store:         store,
		Stop:          stop,
		Closed:        closed,
		Configuration: func() ([]byte, string) { return []byte("{}"), "sha256=configuration" },
	}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		d := r.Header.Get(server.HeaderRunConfiguration)
		s.runDigest.Store(&d)
		if code := s.fail.Load(); code != 0 {
			w.WriteHeader(int(code))
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(s.srv.Close)
	t.Cleanup(func() { store.Close() })
	return s
}

func client(s *station) *server.Client {
	pin := accesskey.Pin{{Alg: "ed25519", PublicKey: signer.PublicKey().String()}}
	return &server.Client{Config: &server.Config{Version: 1, URL: s.srv.URL, AccessKeyID: "ak_f1xt0re000000000", ApiaryPublicKey: pin}, Key: accessKey, InstanceID: "i_test", UserAgent: "qory-forager/test"}
}

// target is the station's events endpoint with a filter; none means every type.
func target(s *station, events ...string) sink.Target {
	if len(events) == 0 {
		events = []string{"*"}
	}
	return sink.Target{URL: s.srv.URL + receiver.DefaultEventsPath, Types: events}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestServerSinkDeliversBatchesTheReceiverStores pins the sink against the reference
// receiver: events arrive signed, in batches, and are stored once each; a filtered type
// is never sent; a batch cut by count is one delivery; the run configuration digest
// set on the sink goes with every delivery after it, and the answers' digests come
// back to the caller.
func TestServerSinkDeliversBatchesTheReceiverStores(t *testing.T) {
	s := newStation(t, nil, nil)
	var mu sync.Mutex
	var answers []server.Digests
	w := sink.NewServer(client(s), target(s, "dev.qory.run.started", "dev.qory.run.heartbeat"), t.TempDir(), nil, func(d server.Digests) {
		mu.Lock()
		answers = append(answers, d)
		mu.Unlock()
	}, nil)
	w.SetRunDigest("sha256=run")
	e := event.NewEmitter(event.NewRunID(), nil)
	w.Write(e.Make(event.RunStarted, map[string]any{"runtime": "x"}))
	w.Write(e.Make(event.RunLog, map[string]any{"stream": "terminal", "bytes": ""}))
	for i := 0; i < sink.BatchEvents+5; i++ {
		w.Write(e.Make(event.RunHeartbeat, map[string]any{"elapsed_seconds": i, "interval_seconds": 30}))
	}
	if err := w.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := s.store.Count(); got != sink.BatchEvents+6 {
		t.Errorf("stored %d events", got)
	}
	if hits := s.hits.Load(); hits < 2 || hits > 3 {
		t.Errorf("%d deliveries for %d events", hits, sink.BatchEvents+6)
	}
	if w.Undelivered() != 0 {
		t.Errorf("%d undelivered", w.Undelivered())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(answers) == 0 || answers[0].Configuration != "sha256=configuration" || answers[0].RunConfiguration != "" {
		t.Errorf("the answers' digests %+v", answers)
	}
	if d := s.runDigest.Load(); d == nil || *d != "sha256=run" {
		t.Errorf("the delivery carried the run configuration digest %v", d)
	}
}

// TestServerSinkRetriesUntilAcceptedAndSpoolsTheRest pins the retry and the spool: a
// receiver that fails then recovers gets the batch once it recovers, under the same
// delivery id; a receiver that stays down leaves the batch in undelivered/ with the
// count reported at close. Its answers are unsigned, so they are no answers, a 410
// among them, and are retried.
func TestServerSinkRetriesUntilAcceptedAndSpoolsTheRest(t *testing.T) {
	s := newStation(t, nil, nil)
	s.fail.Store(500)
	var notes []string
	dir := t.TempDir()
	w := sink.NewServer(client(s), target(s), dir, func(l string) { notes = append(notes, l) }, nil, nil)
	e := event.NewEmitter(event.NewRunID(), nil)
	w.Write(e.Make(event.RunStarted, map[string]any{"runtime": "x"}))
	waitFor(t, func() bool { return s.hits.Load() >= 1 })
	s.fail.Store(0)
	waitFor(t, func() bool { return s.store.Count() == 1 })

	s.fail.Store(410)
	w.Write(e.Make(event.RunExited, map[string]any{"state": "failed"}))
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if err := w.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if w.Undelivered() != 1 {
		t.Errorf("%d undelivered", w.Undelivered())
	}
	files, _ := filepath.Glob(filepath.Join(dir, sink.UndeliveredDir, "*.json"))
	if len(files) != 1 {
		t.Fatalf("spooled files %v", files)
	}
	b, _ := os.ReadFile(files[0])
	if !strings.Contains(string(b), `"dev.qory.run.exited"`) || !strings.HasPrefix(string(b), "[") {
		t.Errorf("spooled batch %s", b)
	}
	if len(notes) == 0 || !strings.Contains(notes[len(notes)-1], "1 events were not accepted") {
		t.Errorf("notes %v", notes)
	}
}

// TestReceiverStopEndsDeliveries pins a signed 410: the sink sends nothing more for
// the run and drops what follows without spooling it, and the run is not closed.
func TestReceiverStopEndsDeliveries(t *testing.T) {
	s := newStation(t, func(string) bool { return true }, nil)
	closed := false
	w := sink.NewServer(client(s), target(s), t.TempDir(), nil, nil, func() { closed = true })
	e := event.NewEmitter(event.NewRunID(), nil)
	w.Write(e.Make(event.RunStarted, map[string]any{"runtime": "x"}))
	waitFor(t, w.Stopped)
	w.Write(e.Make(event.RunExited, map[string]any{"state": "failed"}))
	w.Close(context.Background())
	if s.hits.Load() != 1 || w.Undelivered() != 0 || w.RunClosed() || closed {
		t.Errorf("%d deliveries, %d undelivered after stop, closed %v", s.hits.Load(), w.Undelivered(), closed)
	}
}

// TestRunClosedEndsDeliveriesAndTheRun pins a signed 410 run_closed: the sink calls
// its caller once, sends nothing more, and records the stop, so a resend sends nothing
// either.
func TestRunClosedEndsDeliveriesAndTheRun(t *testing.T) {
	s := newStation(t, nil, func(string) bool { return true })
	var calls atomic.Int32
	dir := t.TempDir()
	w := sink.NewServer(client(s), target(s), dir, nil, nil, func() { calls.Add(1) })
	e := event.NewEmitter(event.NewRunID(), nil)
	w.Write(e.Make(event.RunHeartbeat, map[string]any{"elapsed_seconds": 30, "interval_seconds": 30}))
	waitFor(t, w.RunClosed)
	w.Write(e.Make(event.RunExited, map[string]any{"state": "failed", "reason": "run_closed"}))
	w.Close(context.Background())
	if s.hits.Load() != 1 || calls.Load() != 1 || !w.Stopped() || w.Undelivered() != 0 {
		t.Errorf("%d deliveries, %d calls, stopped %v", s.hits.Load(), calls.Load(), w.Stopped())
	}
	if _, stopped, err := sink.Delivered(dir); err != nil || !stopped {
		t.Errorf("the record of accepted batches has no stop: %v", err)
	}
}

// TestRunClosedDropsTheBatchesQueuedBeforeIt pins that a signed 410 run_closed ends
// the deliveries at once: the batches already queued behind the closed one are
// dropped, not posted, and the caller hears of the close once.
func TestRunClosedDropsTheBatchesQueuedBeforeIt(t *testing.T) {
	s := newStation(t, nil, func(string) bool { return true })
	var calls atomic.Int32
	w := sink.NewServer(client(s), target(s), t.TempDir(), nil, nil, func() { calls.Add(1) })
	e := event.NewEmitter(event.NewRunID(), nil)
	for i := 0; i < 3*sink.BatchEvents+50; i++ {
		w.Write(e.Make(event.RunHeartbeat, map[string]any{"elapsed_seconds": i, "interval_seconds": 30}))
	}
	w.Close(context.Background())
	if s.hits.Load() != 1 || calls.Load() != 1 || !w.RunClosed() || w.Undelivered() != 0 {
		t.Errorf("%d deliveries, %d calls, closed %v, %d undelivered", s.hits.Load(), calls.Load(), w.RunClosed(), w.Undelivered())
	}
}

// TestAStopCarriesNoDigests pins that the digests of a signed 410 reach no caller: a
// run_closed answer that carries a new run configuration digest leads to no reload,
// and no request reaches the server after it.
func TestAStopCarriesNoDigests(t *testing.T) {
	s := newStation(t, nil, func(string) bool { return true })
	s.srv.Config.Handler = digestOn410(s.srv.Config.Handler)
	var digests atomic.Int32
	w := sink.NewServer(client(s), target(s), t.TempDir(), nil, func(server.Digests) { digests.Add(1) }, nil)
	e := event.NewEmitter(event.NewRunID(), nil)
	w.Write(e.Make(event.RunHeartbeat, map[string]any{"elapsed_seconds": 30, "interval_seconds": 30}))
	waitFor(t, w.RunClosed)
	hits := s.hits.Load()
	w.Write(e.Make(event.RunExited, map[string]any{"state": "failed", "reason": "run_closed"}))
	w.Close(context.Background())
	if digests.Load() != 0 || s.hits.Load() != hits || hits != 1 {
		t.Errorf("%d digests handed on, %d requests, %d after the close", digests.Load(), hits, s.hits.Load()-hits)
	}
}

// digestOn410 sets a run configuration digest on the receiver's answers, signed
// again over it, as a server whose 410 carries a changed digest.
func digestOn410(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(resigning{ResponseWriter: w, sig: r.Header.Get(server.HeaderSignature)}, r)
	})
}

type resigning struct {
	http.ResponseWriter
	sig string
}

func (r resigning) WriteHeader(status int) {
	r.Header().Set(server.HeaderRunConfiguration, "sha256="+strings.Repeat("e", 64))
	a := accesskey.Answer{Status: status, RequestSignature: r.sig, Body: []byte(`{"error":"run_closed"}`), Configuration: r.Header().Get(server.HeaderConfiguration), RunConfiguration: r.Header().Get(server.HeaderRunConfiguration)}
	r.Header().Set(server.HeaderSignature, signer.SignAnswer(a))
	r.ResponseWriter.WriteHeader(status)
}

// linkSecret is the link secret of the link sink's tests.
const linkSecret = "link-secret-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"

// linkGateway is a fake gateway's link whose events endpoint answers each batch with
// the status answer gives it, and keeps the bodies and when each arrived.
type linkGateway struct {
	mu     sync.Mutex
	bodies [][]byte
	at     []time.Time
	answer func(n int) (int, string)
}

func (g *linkGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	g.mu.Lock()
	g.bodies = append(g.bodies, b)
	g.at = append(g.at, time.Now())
	n := len(g.bodies)
	g.mu.Unlock()
	status, body := g.answer(n)
	w.Header().Set(server.HeaderRunConfiguration, "sha256="+strings.Repeat("b", 64))
	w.WriteHeader(status)
	io.WriteString(w, body)
}

func (g *linkGateway) hits() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.bodies)
}

// linkSink is a sink posting to the fake gateway's link with the link's short wait.
func linkSink(t *testing.T, g *linkGateway, c sink.Config) *sink.Server {
	t.Helper()
	gw := linktest.Start(t, linkSecret, g)
	k, err := server.NewLocalLink(gw.Local(), "qory-forager/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	c.To, c.Target, c.Wait, c.Link = k, sink.Target{URL: "http://localhost/v1/events", Types: []string{"*"}}, sink.LinkBatchWait, true
	return sink.New(c)
}

// TestTheLinkSinkPostsUnnumberedBatchesAndRetries pins the session's batches to its
// gateway: a batch waits the link's short wait, not the server's; its events are a
// link batch, with their ids and without sequence; an answer other than a 2xx is
// retried after the backoff with the same body; the digests of the answers reach the
// caller; and a sink with no run directory writes no record of its deliveries.
func TestTheLinkSinkPostsUnnumberedBatchesAndRetries(t *testing.T) {
	g := &linkGateway{answer: func(n int) (int, string) {
		if n == 1 {
			return http.StatusServiceUnavailable, ""
		}
		return http.StatusAccepted, ""
	}}
	var digests atomic.Int32
	cwd, _ := os.Getwd()
	w := linkSink(t, g, sink.Config{OnDigests: func(d server.Digests) {
		if d.RunConfiguration != "" {
			digests.Add(1)
		}
	}})
	e := event.NewEmitter(event.NewRunID(), nil)
	start := time.Now()
	ev := e.Make(event.RunHeartbeat, map[string]any{"elapsed_seconds": 30, "interval_seconds": 30})
	w.Write(ev)
	waitFor(t, func() bool { return g.hits() == 2 })
	w.Close(context.Background())
	g.mu.Lock()
	defer g.mu.Unlock()
	if first := g.at[0].Sub(start); first >= sink.BatchWait/2 {
		t.Errorf("the first batch went after %v, not the link's short wait", first)
	}
	if again := g.at[1].Sub(g.at[0]); again < sink.Backoff/2 {
		t.Errorf("the retry came after %v", again)
	}
	if !bytes.Equal(g.bodies[0], g.bodies[1]) || bytes.Contains(g.bodies[0], []byte(`"sequence"`)) || !bytes.Contains(g.bodies[0], []byte(ev.ID)) {
		t.Errorf("the batches %s and %s", g.bodies[0], g.bodies[1])
	}
	schema, err := contracts.Compile("link-batch.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := contracts.Decode("batch.json", g.bodies[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Errorf("the batch is no link batch: %v", err)
	}
	if digests.Load() != 2 || w.Undelivered() != 0 || w.Stopped() {
		t.Errorf("%d digests, %d undelivered, stopped %v", digests.Load(), w.Undelivered(), w.Stopped())
	}
	if _, err := os.Stat(filepath.Join(cwd, sink.DeliveredFile)); err == nil {
		t.Error("a sink with no run directory wrote the record of accepted batches")
	}
}

// TestTheGatewaysEndOfTheRunReachesTheCaller pins an answer on the link that ends the
// run, a 410 or a 400 invalid_request to a batch: the sink stops and tells the caller
// once with the end code, which the session records as its run.exited reason, and who
// ended the run; the words for the user are the caller's, so the sink reports nothing
// itself.
func TestTheGatewaysEndOfTheRunReachesTheCaller(t *testing.T) {
	for _, c := range []struct {
		status     int
		body, want string
	}{
		{http.StatusGone, `{"error":"credential_expired","from":"gateway"}`, "credential_expired gateway"},
		{http.StatusGone, `{"error":"run_closed","from":"apiary"}`, "run_closed apiary"},
		{http.StatusBadRequest, `{"error":"invalid_request"}`, "run_closed gateway"},
	} {
		g := &linkGateway{answer: func(int) (int, string) { return c.status, c.body }}
		var mu sync.Mutex
		var codes, notes []string
		var digests atomic.Int32
		w := linkSink(t, g, sink.Config{
			OnEnded:   func(code, from string) { mu.Lock(); codes = append(codes, code+" "+from); mu.Unlock() },
			Report:    func(l string) { mu.Lock(); notes = append(notes, l); mu.Unlock() },
			OnDigests: func(server.Digests) { digests.Add(1) },
		})
		e := event.NewEmitter(event.NewRunID(), nil)
		w.Write(e.Make(event.RunHeartbeat, map[string]any{"elapsed_seconds": 30, "interval_seconds": 30}))
		waitFor(t, w.RunClosed)
		w.Write(e.Make(event.RunExited, map[string]any{"state": "failed", "reason": "run_closed"}))
		w.Close(context.Background())
		mu.Lock()
		if g.hits() != 1 || !w.Stopped() || fmt.Sprint(codes) != "["+c.want+"]" || digests.Load() != 0 || w.Undelivered() != 0 {
			t.Errorf("%d %s: %d deliveries, stopped %v, codes %v, %d digests, %d undelivered", c.status, c.body, g.hits(), w.Stopped(), codes, digests.Load(), w.Undelivered())
		}
		if len(notes) != 0 {
			t.Errorf("%d %s: the sink reported the gateway's end itself: %v", c.status, c.body, notes)
		}
		mu.Unlock()
	}
}

// TestALinkSinkWithoutARunDirectoryCountsWhatItCouldNotDeliver pins a link sink with
// no run directory: what the gateway did not accept by the end is counted for the
// caller, written nowhere, and not reported by the sink.
func TestALinkSinkWithoutARunDirectoryCountsWhatItCouldNotDeliver(t *testing.T) {
	g := &linkGateway{answer: func(int) (int, string) { return http.StatusServiceUnavailable, "" }}
	var mu sync.Mutex
	var notes []string
	w := linkSink(t, g, sink.Config{Report: func(l string) { mu.Lock(); notes = append(notes, l); mu.Unlock() }})
	e := event.NewEmitter(event.NewRunID(), nil)
	w.Write(e.Make(event.RunHeartbeat, map[string]any{"elapsed_seconds": 30, "interval_seconds": 30}))
	waitFor(t, func() bool { return g.hits() >= 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	w.Close(ctx)
	mu.Lock()
	defer mu.Unlock()
	if w.Undelivered() != 1 || len(notes) != 0 {
		t.Errorf("%d undelivered, notes %q", w.Undelivered(), notes)
	}
}
