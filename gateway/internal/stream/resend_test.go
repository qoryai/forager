package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/sink"
)

// lostRun leaves the record of a run whose gateway was lost: the ping, run.started at
// a known time and a log two and a half seconds after it, and no run.exited.
func lostRun(t *testing.T) string {
	t.Helper()
	at := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	s := New(Config{Dir: t.TempDir(), Now: func() time.Time { return at }})
	runID := event.NewRunID()
	r, err := s.Open(runID)
	if err != nil {
		t.Fatal(err)
	}
	r.Ping(map[string]any{"forager_version": "dev", "events": []string{"*"}, "contract_version": 1, "interval_seconds": 30})
	started := sessionEvent(runID, event.RunStarted, map[string]any{})
	started.Time = "2026-10-09T10:00:00.000Z"
	log := sessionEvent(runID, event.RunLog, map[string]any{"stream": "stdout", "bytes": "aGkK"})
	log.Time = "2026-10-09T10:00:02.500Z"
	r.Accept([]event.Event{started, log})
	r.Close(context.Background())
	return r.Dir()
}

// TestResendSkipsAHeldRecord pins the lock: a record whose run is open here or in
// another gateway, or whose session lives, is ErrRunning and is left as it is.
func TestResendSkipsAHeldRecord(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	r, err := s.Open(event.NewRunID())
	if err != nil {
		t.Fatal(err)
	}
	r.Accept([]event.Event{sessionEvent(r.ID(), event.RunStarted, map[string]any{})})
	if _, err := Resend(context.Background(), ResendConfig{Dir: r.Dir()}); !errors.Is(err, ErrRunning) {
		t.Errorf("an open run: %v", err)
	}
	r.Close(context.Background())

	dir := lostRun(t)
	before, _ := os.ReadFile(filepath.Join(dir, sink.EventsFile))
	unlock, err := lock(dir, sessionLockFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Resend(context.Background(), ResendConfig{Dir: dir}); !errors.Is(err, ErrRunning) {
		t.Errorf("a living session: %v", err)
	}
	unlock()
	after, _ := os.ReadFile(filepath.Join(dir, sink.EventsFile))
	if string(before) != string(after) {
		t.Error("a held record was changed")
	}
}

// TestResendWritesGatewayLost pins the completion of a record: run.exited numbered on
// from the last event, failed, -1, gateway_lost, with the duration from run.started to
// the last event; a record that has one is left as it is, and a line cut short is cut
// off first.
func TestResendWritesGatewayLost(t *testing.T) {
	dir := lostRun(t)
	file := filepath.Join(dir, sink.EventsFile)
	f, _ := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"specversion":"1.0","id":"cut`)
	f.Close()
	res, err := Resend(context.Background(), ResendConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Closed || res.RunID != filepath.Base(dir) {
		t.Errorf("result %+v", res)
	}
	rec := readRecord(t, dir)
	contiguous(t, res.RunID, rec)
	last := rec[len(rec)-1]
	data, _ := last.Data.(map[string]any)
	if len(rec) != 4 || last.Type != event.RunExited || data["state"] != "failed" || data["exit_code"] != float64(-1) || data["reason"] != event.ReasonGatewayLost || data["duration_ms"] != float64(2500) {
		t.Errorf("the record ends %+v", last)
	}
	res, err = Resend(context.Background(), ResendConfig{Dir: dir})
	if err != nil || res.Closed {
		t.Errorf("again: %+v, %v", res, err)
	}
	if again := readRecord(t, dir); len(again) != 4 {
		t.Errorf("again: %v", types(again))
	}
}

// TestResendWritesGatewayLostOfARunAGatewayOpened pins the completion of the record of
// a run a gateway opened, with no process: gateway_lost with neither state nor
// exit_code, valid under run.exited.schema.json.
func TestResendWritesGatewayLostOfARunAGatewayOpened(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	r, _ := s.Open(event.NewRunID())
	r.Ping(map[string]any{})
	r.Emit(event.RunStarted, map[string]any{"opened_by": event.OpenedByGateway, "forager_version": "test"})
	r.Emit(event.RunHeartbeat, map[string]any{"elapsed_seconds": 1, "interval_seconds": 1})
	r.Close(context.Background())
	res, err := Resend(context.Background(), ResendConfig{Dir: r.Dir()})
	if err != nil || !res.Closed {
		t.Fatalf("%+v, %v", res, err)
	}
	rec := readRecord(t, r.Dir())
	last := rec[len(rec)-1]
	data, _ := last.Data.(map[string]any)
	if last.Type != event.RunExited || data["reason"] != event.ReasonGatewayLost || len(data) != 2 {
		t.Errorf("the record ends %+v", last)
	}
	schema, err := contracts.Compile("events/run.exited.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(data)
	doc, _ := contracts.Decode("exited.json", b)
	if err := schema.Validate(doc); err != nil {
		t.Error(err)
	}
}

// TestResendLeavesARunThatNeverStarted pins that a record without run.started gets no
// run.exited.
func TestResendLeavesARunThatNeverStarted(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	r, _ := s.Open(event.NewRunID())
	r.Ping(map[string]any{})
	r.Close(context.Background())
	res, err := Resend(context.Background(), ResendConfig{Dir: r.Dir()})
	if err != nil || res.Closed {
		t.Errorf("%+v, %v", res, err)
	}
}

// The keys of the receiver tests: the access key the sink signs with and the
// receiver's own.
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

// station is the reference receiver, which closes the runs closed says.
func station(t *testing.T, closed func(string) bool) (*httptest.Server, *receiver.File) {
	t.Helper()
	store, err := receiver.OpenFile(filepath.Join(t.TempDir(), "received.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	h := &receiver.Handler{
		Keys: func(string) (receiver.AccessKey, bool) {
			return receiver.AccessKey{PublicKey: accessKey.PublicKey()}, true
		},
		Signer:        signer,
		Store:         store,
		Closed:        closed,
		Configuration: func() ([]byte, string) { return []byte("{}"), "sha256=configuration" },
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	t.Cleanup(func() { store.Close() })
	return srv, store
}

// serverSink opens today's server sink toward the station, as the gateway would.
func serverSink(srv *httptest.Server) func(string) Sink {
	pin := accesskey.Pin{{Alg: "ed25519", PublicKey: signer.PublicKey().String()}}
	client := &server.Client{Config: &server.Config{Version: 1, URL: srv.URL, AccessKeyID: "ak_f1xt0re000000000", ApiaryPublicKey: pin}, Key: accessKey, InstanceID: "i_test", UserAgent: "qory-forager/test"}
	return func(dir string) Sink {
		return sink.NewServer(client, sink.Target{URL: srv.URL + receiver.DefaultEventsPath, Types: []string{"*"}}, dir, nil, nil, nil)
	}
}

// TestResendDeliversWhatIsOwed pins the delivery: gateway_lost first, then every event
// no accepted batch contained, through the server sink; the ping, accepted during the
// run, is not sent again, and a second resend sends nothing.
func TestResendDeliversWhatIsOwed(t *testing.T) {
	srv, store := station(t, nil)
	dir := lostRun(t)
	if err := os.WriteFile(filepath.Join(dir, sink.DeliveredFile), []byte("ping-delivery 0000000001\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(dir, sink.UndeliveredDir), 0o755)
	os.WriteFile(filepath.Join(dir, sink.UndeliveredDir, "old.json"), []byte("[]"), 0o644)
	res, err := Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Closed || res.Sent != 3 || res.Undelivered != 0 || res.Stopped || res.RunClosed {
		t.Errorf("result %+v", res)
	}
	if store.Count() != 3 {
		t.Errorf("the receiver stored %d events", store.Count())
	}
	if _, err := os.Stat(filepath.Join(dir, sink.UndeliveredDir, "old.json")); !os.IsNotExist(err) {
		t.Error("the old spool was kept")
	}
	res, err = Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv)})
	if err != nil || res.Sent != 0 || res.Undelivered != 0 || res.Closed {
		t.Errorf("again: %+v, %v", res, err)
	}
	if store.Count() != 3 {
		t.Errorf("again: the receiver stored %d events", store.Count())
	}
}

// TestResendHonoursTheFilterAndTheStop pins the server's filter, and that a server
// that said stop during the run is sent nothing.
func TestResendHonoursTheFilterAndTheStop(t *testing.T) {
	srv, store := station(t, nil)
	dir := lostRun(t)
	res, err := Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv), Wants: func(typ string) bool { return typ == event.RunExited }})
	if err != nil || res.Sent != 1 || store.Count() != 1 {
		t.Errorf("filtered: %+v, %v, stored %d", res, err, store.Count())
	}

	dir = lostRun(t)
	os.WriteFile(filepath.Join(dir, sink.DeliveredFile), []byte("stopped\n"), 0o644)
	var reports []string
	res, err = Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv), Report: func(l string) { reports = append(reports, l) }})
	if err != nil || !res.Stopped || res.Sent != 0 || !res.Closed {
		t.Errorf("stopped: %+v, %v", res, err)
	}
	if len(reports) != 1 || !strings.Contains(reports[0], "said stop") {
		t.Errorf("reports %q", reports)
	}
}

// TestResendReportsARunClosed pins that a server that closes the run when it is sent
// again says so in the result, and the events stay in the record directory.
func TestResendReportsARunClosed(t *testing.T) {
	srv, _ := station(t, func(string) bool { return true })
	dir := lostRun(t)
	res, err := Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv)})
	if err != nil || !res.RunClosed || res.Sent != 0 {
		t.Errorf("%+v, %v", res, err)
	}
	if rec := readRecord(t, dir); len(rec) != 4 {
		t.Errorf("the record: %v", types(rec))
	}
}

// tornRun leaves the record of a lost run whose ping the server accepted: the ping,
// run.started and three logs, and no run.exited. It returns the directory and the
// record's lines, each with its newline.
func tornRun(t *testing.T) (string, [][]byte) {
	t.Helper()
	s := New(Config{Dir: t.TempDir()})
	r, err := s.Open(event.NewRunID())
	if err != nil {
		t.Fatal(err)
	}
	r.Ping(map[string]any{})
	evs := []event.Event{sessionEvent(r.ID(), event.RunStarted, map[string]any{})}
	for range 3 {
		evs = append(evs, sessionEvent(r.ID(), event.RunLog, map[string]any{"stream": "stdout", "bytes": "aGkK"}))
	}
	r.Accept(evs)
	r.Close(context.Background())
	if err := os.WriteFile(filepath.Join(r.Dir(), sink.DeliveredFile), []byte("ping-delivery 0000000001\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(r.Dir(), sink.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	return r.Dir(), bytes.SplitAfter(b, []byte("\n"))[:5]
}

// exitedAfter checks that the record is before, then one line, run.exited with the
// sequence want, and returns that event.
func exitedAfter(t *testing.T, dir string, before []byte, want string) event.Event {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(dir, sink.EventsFile))
	rest, ok := bytes.CutPrefix(b, before)
	if !ok {
		t.Fatalf("the record was changed before its end:\n%s", b)
	}
	evs := parseLines(t, string(rest))
	if len(evs) != 1 || evs[0].Type != event.RunExited || evs[0].Sequence != want || !strings.HasSuffix(string(rest), "\n") {
		t.Fatalf("the record ends %q", rest)
	}
	return evs[0]
}

// TestResendReadsOnPastATornLine pins a line the gateway did not finish, in the middle
// of the record: the part of the event it holds is skipped, and so are a line that is
// no JSON and one with no sequence, but every whole event after them is read and sent,
// the one the next write put on the same line too; they stay in the file, which
// gateway_lost follows, numbered after the highest sequence.
func TestResendReadsOnPastATornLine(t *testing.T) {
	srv, store := station(t, nil)
	dir, lines := tornRun(t)
	id := func(line []byte) string {
		var ev event.Event
		json.Unmarshal(line, &ev)
		return ev.ID
	}
	torn := slices.Concat(lines[0], lines[1], lines[2][:len(lines[2])/2], lines[3],
		[]byte("not an event\n"), []byte(`{"type":"`+event.RunLog+`","id":"no-sequence"}`+"\n"), lines[4])
	if err := os.WriteFile(filepath.Join(dir, sink.EventsFile), torn, 0o644); err != nil {
		t.Fatal(err)
	}
	var told []int
	reportTorn = func(n int, _ string) string { told = append(told, n); return "torn" }
	defer func() { reportTorn = nil }()
	var reports []string
	res, err := Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv), Report: func(l string) { reports = append(reports, l) }})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Closed || res.Torn != 3 || res.Sent != 4 || res.Undelivered != 0 {
		t.Errorf("result %+v", res)
	}
	if !slices.Equal(told, []int{3}) || !slices.Contains(reports, "torn") {
		t.Errorf("told %v, reports %q", told, reports)
	}
	exited := exitedAfter(t, dir, torn, "0000000006")
	for _, want := range []string{id(lines[1]), id(lines[3]), id(lines[4]), exited.ID} {
		if !store.Seen(want) {
			t.Errorf("the receiver has no %s", want)
		}
	}
	if store.Count() != 4 {
		t.Errorf("the receiver stored %d events", store.Count())
	}
}

// TestResendEndsATornLastLine pins a last line the gateway did not finish: one that
// holds a whole event, only its newline missing, or bytes that are none and then a
// whole event, keeps it, and gets its newline before gateway_lost; one that holds no
// whole event is cut off. Nothing before it is changed.
func TestResendEndsATornLastLine(t *testing.T) {
	for name, tc := range map[string]struct {
		last   func(line []byte) []byte
		kept   bool
		torn   int
		exited string
	}{
		"a whole event without its newline":  {func(l []byte) []byte { return bytes.TrimSuffix(l, []byte("\n")) }, true, 1, "0000000006"},
		"part of an event, then a whole one": {func(l []byte) []byte { return slices.Concat(l[:len(l)/3], bytes.TrimSuffix(l, []byte("\n"))) }, true, 2, "0000000006"},
		"part of an event":                   {func(l []byte) []byte { return l[:len(l)/2] }, false, 2, "0000000005"},
	} {
		t.Run(name, func(t *testing.T) {
			dir, lines := tornRun(t)
			// A torn line in the middle too: the end is found past it.
			head := slices.Concat(lines[0], lines[1], lines[2][:len(lines[2])/2], []byte("\n"), lines[3])
			tail := tc.last(lines[4])
			if err := os.WriteFile(filepath.Join(dir, sink.EventsFile), slices.Concat(head, tail), 0o644); err != nil {
				t.Fatal(err)
			}
			res, err := Resend(context.Background(), ResendConfig{Dir: dir})
			if err != nil {
				t.Fatal(err)
			}
			if !res.Closed || res.Torn != tc.torn {
				t.Errorf("result %+v", res)
			}
			before := head
			if tc.kept {
				before = slices.Concat(head, tail, []byte("\n"))
			}
			exitedAfter(t, dir, before, tc.exited)
		})
	}
}
