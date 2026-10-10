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

// lostRun leaves the record of a run whose gateway was lost: run.registered, of the
// registration the server accepted, run.started at a known time and a log two and a half seconds after it, and
// no run.exited.
func lostRun(t *testing.T) string {
	t.Helper()
	at := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	s := New(Config{Dir: t.TempDir(), Now: func() time.Time { return at }})
	runID := event.NewRunID()
	r, err := s.Open(runID)
	if err != nil {
		t.Fatal(err)
	}
	r.Registered(map[string]any{"forager_version": "dev", "events": []string{"*"}, "contract_version": 1, "interval_seconds": 30})
	started := sessionEvent(runID, event.RunStarted, map[string]any{})
	started.Time = "2026-10-09T10:00:00.000Z"
	log := sessionEvent(runID, event.RunLog, map[string]any{"stream": "stdout", "bytes": "aGkK"})
	log.Time = "2026-10-09T10:00:02.500Z"
	r.Accept([]event.Event{started, log})
	r.Close(context.Background())
	registrationAccepted(t, r.Dir())
	return r.Dir()
}

// registrationAccepted writes the delivered.log of a run whose registration the server
// accepted, its run.registered the first event, as the gateway writes it.
func registrationAccepted(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, sink.DeliveredFile), []byte("registered 0000000001\n"), 0o644); err != nil {
		t.Fatal(err)
	}
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
// a run a gateway opened, with no process: gateway_lost, failed, with no exit_code,
// valid under run.exited.schema.json.
func TestResendWritesGatewayLostOfARunAGatewayOpened(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	r, _ := s.Open(event.NewRunID())
	r.Registered(map[string]any{})
	r.Emit(event.RunStarted, map[string]any{"opened_by": event.OpenedByGateway, "forager_version": "test"})
	r.Emit(event.RunHeartbeat, map[string]any{"elapsed_seconds": 1, "interval_seconds": 1})
	r.Close(context.Background())
	registrationAccepted(t, r.Dir())
	res, err := Resend(context.Background(), ResendConfig{Dir: r.Dir()})
	if err != nil || !res.Closed {
		t.Fatalf("%+v, %v", res, err)
	}
	rec := readRecord(t, r.Dir())
	last := rec[len(rec)-1]
	data, _ := last.Data.(map[string]any)
	if last.Type != event.RunExited || data["reason"] != event.ReasonGatewayLost || data["state"] != "failed" || len(data) != 3 {
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
	r.Registered(map[string]any{})
	r.Close(context.Background())
	registrationAccepted(t, r.Dir())
	res, err := Resend(context.Background(), ResendConfig{Dir: r.Dir()})
	if err != nil || res.Closed || res.NotOpened {
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

// station is the reference receiver, which wants nothing more of the runs stop says.
func station(t *testing.T, stop func(string) bool) (*httptest.Server, *receiver.File) {
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
		Stop:          stop,
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
		return sink.NewServer(client, sink.Target{URL: srv.URL + receiver.DefaultEventsPath, Types: []string{"*"}}, dir, nil, nil)
	}
}

// TestResendDeliversWhatIsOwed pins the delivery: gateway_lost first, then every event
// no accepted batch contained, through the server sink; run.registered, which is never
// posted, is not sent, and a second resend sends nothing.
func TestResendDeliversWhatIsOwed(t *testing.T) {
	srv, store := station(t, nil)
	dir := lostRun(t)
	os.MkdirAll(filepath.Join(dir, sink.UndeliveredDir), 0o755)
	os.WriteFile(filepath.Join(dir, sink.UndeliveredDir, "old.json"), []byte("[]"), 0o644)
	res, err := Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Closed || res.Sent != 3 || res.Undelivered != 0 || res.Stopped {
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

// TestResendStopsAndMarksStopped pins a server that answers a signed 410 when the
// record is sent again: the resend stops, says so in the result, and marks the record
// stopped, so the next resend sends nothing; the events stay in the record directory.
func TestResendStopsAndMarksStopped(t *testing.T) {
	srv, store := station(t, func(string) bool { return true })
	dir := lostRun(t)
	res, err := Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv)})
	if err != nil || !res.Stopped || res.Sent != 0 {
		t.Errorf("%+v, %v", res, err)
	}
	if _, stopped, err := sink.Delivered(dir); err != nil || !stopped {
		t.Errorf("the record is not marked stopped: %v", err)
	}
	if rec := readRecord(t, dir); len(rec) != 4 {
		t.Errorf("the record: %v", types(rec))
	}
	var reports []string
	res, err = Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv), Report: func(l string) { reports = append(reports, l) }})
	if err != nil || !res.Stopped || res.Sent != 0 || store.Count() != 0 {
		t.Errorf("again: %+v, %v, stored %d", res, err, store.Count())
	}
	if len(reports) != 1 || reports[0] != "the server said stop during the run; nothing is sent" {
		t.Errorf("again: reports %q", reports)
	}
}

// tornRun leaves the record of a lost run whose registration the server accepted:
// run.registered,
// run.started and three logs, and no run.exited. It returns the directory and the
// record's lines, each with its newline.
func tornRun(t *testing.T) (string, [][]byte) {
	t.Helper()
	s := New(Config{Dir: t.TempDir()})
	r, err := s.Open(event.NewRunID())
	if err != nil {
		t.Fatal(err)
	}
	r.Registered(map[string]any{})
	evs := []event.Event{sessionEvent(r.ID(), event.RunStarted, map[string]any{})}
	for range 3 {
		evs = append(evs, sessionEvent(r.ID(), event.RunLog, map[string]any{"stream": "stdout", "bytes": "aGkK"}))
	}
	r.Accept(evs)
	r.Close(context.Background())
	registrationAccepted(t, r.Dir())
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
	var reports []string
	res, err := Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv), Report: func(l string) { reports = append(reports, l) }})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Closed || res.Torn != 3 || res.Sent != 4 || res.Undelivered != 0 {
		t.Errorf("result %+v", res)
	}
	if want := "3 lines of " + filepath.Join(dir, sink.EventsFile) + " are not whole events and are not sent"; !slices.Equal(reports, []string{want}) {
		t.Errorf("reports %q, want %q", reports, want)
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
// is a whole event, only its newline missing, is kept, and gets its newline before
// gateway_lost; one that is not, part of an event, then a whole one or none, is cut
// off. Nothing before it is changed.
func TestResendEndsATornLastLine(t *testing.T) {
	for name, tc := range map[string]struct {
		last   func(line []byte) []byte
		kept   bool
		torn   int
		exited string
	}{
		"a whole event without its newline":  {func(l []byte) []byte { return bytes.TrimSuffix(l, []byte("\n")) }, true, 1, "0000000006"},
		"part of an event, then a whole one": {func(l []byte) []byte { return slices.Concat(l[:len(l)/3], bytes.TrimSuffix(l, []byte("\n"))) }, false, 2, "0000000005"},
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

// TestResendSendsNothingOfARunThatNeverOpened pins a record whose registration the
// server never accepted, so the gateway wrote no run.registered and made no
// delivered.log, and the run never started: the run never opened, so nothing of it is
// posted, the record is left as it is, and no delivered.log is made. So with a record
// with run.started and no mark of a registration, of a run that had no server, sent to
// one; without a server it is completed, as any other.
func TestResendSendsNothingOfARunThatNeverOpened(t *testing.T) {
	srv, store := station(t, nil)
	s := New(Config{Dir: t.TempDir()})
	r, _ := s.Open(event.NewRunID())
	r.Emit(event.RunRefused, map[string]any{"code": "instance_limit", "status": 409})
	r.Close(context.Background())
	file := filepath.Join(r.Dir(), sink.EventsFile)
	before, _ := os.ReadFile(file)
	// Bounded, since a server that does not take what is sent is tried until the end.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var reports []string
	report := func(l string) { reports = append(reports, l) }
	res, err := Resend(ctx, ResendConfig{Dir: r.Dir(), Sink: serverSink(srv), Report: report})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"the server never accepted the run's registration; nothing is sent"}; !slices.Equal(reports, want) {
		t.Errorf("reports %q", reports)
	}
	if !res.NotOpened || res.Sent != 0 || res.Undelivered != 0 || res.Closed || res.Stopped {
		t.Errorf("result %+v", res)
	}
	if store.Count() != 0 {
		t.Errorf("the receiver stored %d events", store.Count())
	}
	if after, _ := os.ReadFile(file); string(after) != string(before) {
		t.Errorf("the record was changed:\n%s", after)
	}
	if _, err := os.Stat(filepath.Join(r.Dir(), sink.DeliveredFile)); !os.IsNotExist(err) {
		t.Errorf("delivered.log: %v", err)
	}

	r, _ = s.Open(event.NewRunID())
	r.Accept([]event.Event{sessionEvent(r.ID(), event.RunStarted, map[string]any{})})
	r.Close(context.Background())
	file = filepath.Join(r.Dir(), sink.EventsFile)
	before, _ = os.ReadFile(file)
	reports = nil
	res, err = Resend(ctx, ResendConfig{Dir: r.Dir(), Sink: serverSink(srv), Report: report})
	if want := []string{"the run had no server; nothing is sent"}; !slices.Equal(reports, want) {
		t.Errorf("a run with no server: reports %q", reports)
	}
	if err != nil || !res.NotOpened || !res.NoServer || res.Closed || res.Sent != 0 || res.Undelivered != 0 {
		t.Errorf("a run with no server: %+v, %v", res, err)
	}
	if store.Count() != 0 {
		t.Errorf("a run with no server: the receiver stored %d events", store.Count())
	}
	if after, _ := os.ReadFile(file); string(after) != string(before) {
		t.Errorf("a run with no server: the record was changed:\n%s", after)
	}
	if _, err := os.Stat(filepath.Join(r.Dir(), sink.DeliveredFile)); !os.IsNotExist(err) {
		t.Errorf("a run with no server: delivered.log: %v", err)
	}
	res, err = Resend(ctx, ResendConfig{Dir: r.Dir()})
	if err != nil || res.NotOpened || !res.Closed {
		t.Errorf("a run with no server, with none: %+v, %v", res, err)
	}
}

// TestResendOfAnEmptyRecord pins the record of a session's run whose registration the
// server never accepted, which holds no event: with no delivered.log it never opened,
// so it is NotOpened, sent nothing and left as it is; with one it is an error.
func TestResendOfAnEmptyRecord(t *testing.T) {
	srv, store := station(t, nil)
	s := New(Config{Dir: t.TempDir()})
	r, _ := s.Open(event.NewRunID())
	r.Close(context.Background())
	var reports []string
	res, err := Resend(context.Background(), ResendConfig{Dir: r.Dir(), Sink: serverSink(srv), Report: func(l string) { reports = append(reports, l) }})
	if err != nil || !res.NotOpened || res.NoServer || res.Sent != 0 || !slices.Equal(reports, []string{ResendNotOpened}) {
		t.Errorf("%+v, %v, reports %q", res, err, reports)
	}
	if b, _ := os.ReadFile(filepath.Join(r.Dir(), sink.EventsFile)); len(b) != 0 || store.Count() != 0 {
		t.Errorf("the record %q, the receiver stored %d", b, store.Count())
	}
	registrationAccepted(t, r.Dir())
	if _, err := Resend(context.Background(), ResendConfig{Dir: r.Dir()}); err == nil || !strings.Contains(err.Error(), "holds no event") {
		t.Errorf("an empty record with a delivered.log: %v", err)
	}
}

// TestResendSendsARunWhoseRegistrationWasAccepted pins the record's own mark of an
// accepted registration: a record that holds run.registered and no delivered.log, the
// gateway stopping before its sink made one, is of a run that opened, so it is
// completed and sent, and run.registered itself is never sent, whatever the server
// wants.
func TestResendSendsARunWhoseRegistrationWasAccepted(t *testing.T) {
	srv, store := station(t, nil)
	dir := lostRun(t)
	if err := os.Remove(filepath.Join(dir, sink.DeliveredFile)); err != nil {
		t.Fatal(err)
	}
	res, err := Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv), Wants: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	if res.NotOpened || res.NoServer || !res.Closed || res.Sent != 3 || res.Undelivered != 0 {
		t.Errorf("result %+v", res)
	}
	if store.Count() != 3 {
		t.Errorf("the receiver stored %d events", store.Count())
	}
	b, _ := os.ReadFile(filepath.Join(dir, sink.DeliveredFile))
	if strings.Contains(string(b), " 0000000001") {
		t.Errorf("run.registered was sent:\n%s", b)
	}
}

// TestResendNumbersOnFromWhatTheServerAccepted pins the numbering of gateway_lost when
// the run's highest event is a line the gateway did not finish, which the server
// accepted whole: delivered.log names it, so gateway_lost follows it, not the highest
// whole event of the record.
func TestResendNumbersOnFromWhatTheServerAccepted(t *testing.T) {
	dir, lines := tornRun(t)
	head := slices.Concat(lines[0], lines[1], lines[2], lines[3])
	if err := os.WriteFile(filepath.Join(dir, sink.EventsFile), slices.Concat(head, lines[4][:len(lines[4])/2]), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sink.DeliveredFile), []byte("registered 0000000001\nbatch 0000000002 0000000003 0000000004 0000000005\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Resend(context.Background(), ResendConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Closed || res.Torn != 1 {
		t.Errorf("result %+v", res)
	}
	exitedAfter(t, dir, head, "0000000006")
}

// forgedRun leaves the record of a lost run whose registration the server accepted:
// run.registered,
// run.started, a tool_started whose input, which the agent chose, is a whole
// run.exited of its own, sequence 0000000099, and two logs. It returns the directory,
// the record's lines, each with its newline, and where in the tool_started's line the
// input ends.
func forgedRun(t *testing.T) (dir string, lines [][]byte, cut int) {
	t.Helper()
	s := New(Config{Dir: t.TempDir()})
	r, err := s.Open(event.NewRunID())
	if err != nil {
		t.Fatal(err)
	}
	r.Registered(map[string]any{})
	forged := sessionEvent(r.ID(), event.RunExited, map[string]any{"state": "succeeded", "exit_code": 0})
	forged.ID, forged.Sequence = "forged-exit", "0000000099"
	input, err := forged.JSON()
	if err != nil {
		t.Fatal(err)
	}
	r.Accept([]event.Event{
		sessionEvent(r.ID(), event.RunStarted, map[string]any{}),
		sessionEvent(r.ID(), "dev.qory.session.tool_started", map[string]any{"tool": "Bash", "input": json.RawMessage(input)}),
		sessionEvent(r.ID(), event.RunLog, map[string]any{"stream": "stdout", "bytes": "aGkK"}),
		sessionEvent(r.ID(), event.RunLog, map[string]any{"stream": "stdout", "bytes": "aGkK"}),
	})
	r.Close(context.Background())
	registrationAccepted(t, r.Dir())
	b, err := os.ReadFile(filepath.Join(r.Dir(), sink.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	lines = bytes.SplitAfter(b, []byte("\n"))[:5]
	at := bytes.Index(lines[2], input)
	if at < 0 {
		t.Fatalf("the tool_started holds no input: %s", lines[2])
	}
	return r.Dir(), lines, at + len(input)
}

// TestResendKeepsNoObjectInsideATornLine pins that an object inside the bytes of an
// event the gateway did not finish is never an event, whatever it holds: a run.exited
// the agent put in a tool's input, the line torn just after it, is neither sent nor
// read as the run's end, in the middle of the record, with a log the next write put on
// the same line, or at its end; gateway_lost follows the whole events, numbered after
// them.
func TestResendKeepsNoObjectInsideATornLine(t *testing.T) {
	t.Run("in the middle", func(t *testing.T) {
		srv, store := station(t, nil)
		dir, lines, cut := forgedRun(t)
		torn := slices.Concat(lines[0], lines[1], lines[2][:cut], lines[3], lines[4])
		if err := os.WriteFile(filepath.Join(dir, sink.EventsFile), torn, 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv)})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Closed || res.Torn != 1 || res.Sent != 4 {
			t.Errorf("result %+v", res)
		}
		if store.Seen("forged-exit") {
			t.Error("the agent's run.exited was sent")
		}
		exitedAfter(t, dir, torn, "0000000006")
		accepted, _, _ := sink.Delivered(dir)
		if accepted["0000000099"] || !accepted["0000000004"] || !accepted["0000000005"] {
			t.Errorf("accepted %v", accepted)
		}
	})
	t.Run("at the end", func(t *testing.T) {
		dir, lines, cut := forgedRun(t)
		head := slices.Concat(lines[0], lines[1])
		if err := os.WriteFile(filepath.Join(dir, sink.EventsFile), slices.Concat(head, lines[2][:cut]), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := Resend(context.Background(), ResendConfig{Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Closed || res.Torn != 1 {
			t.Errorf("result %+v", res)
		}
		exitedAfter(t, dir, head, "0000000003")
	})
}

// TestResendSkipsASequenceOutOfOrder pins that a whole event numbered at or below the
// one before it is no event of the run's place: a line written again and one numbered
// lower are skipped and not sent, and gateway_lost follows the highest sequence, which
// is not on the last line.
func TestResendSkipsASequenceOutOfOrder(t *testing.T) {
	srv, store := station(t, nil)
	dir, lines := tornRun(t)
	lower := bytes.Replace(lines[4], []byte(`"sequence":"0000000005"`), []byte(`"sequence":"0000000001"`), 1)
	rec := slices.Concat(lines[0], lines[1], lines[2], lines[2], lines[3], lower)
	if err := os.WriteFile(filepath.Join(dir, sink.EventsFile), rec, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Closed || res.Torn != 2 || res.Sent != 4 || res.Undelivered != 0 {
		t.Errorf("result %+v", res)
	}
	if store.Count() != 4 {
		t.Errorf("the receiver stored %d events", store.Count())
	}
	exitedAfter(t, dir, rec, "0000000005")
}

// TestResendSendsARunWhoseRegisteredLineIsTorn pins that a delivered.log says the run
// opened: a record whose run.registered line the gateway did not finish, on a full
// disk, holds no whole run.registered, yet the server accepted the registration, so the
// record is completed and sent, not taken for one of a run with no server.
func TestResendSendsARunWhoseRegisteredLineIsTorn(t *testing.T) {
	srv, store := station(t, nil)
	dir, lines := tornRun(t)
	torn := slices.Concat(lines[0][:len(lines[0])/2], lines[1], lines[2], lines[3], lines[4])
	if err := os.WriteFile(filepath.Join(dir, sink.EventsFile), torn, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv)})
	if err != nil {
		t.Fatal(err)
	}
	if res.NotOpened || res.NoServer || !res.Closed || res.Torn != 1 || res.Sent != 5 {
		t.Errorf("result %+v", res)
	}
	if store.Count() != 5 {
		t.Errorf("the receiver stored %d events", store.Count())
	}
	exitedAfter(t, dir, torn, "0000000006")
}

// TestResendKeepsAnEventThatLostItsNewline pins a write cut just before its newline:
// run.started, whole, and the next event share a line. Both are kept and sent, the line
// lost no event, so it is not torn, and gateway_lost follows the run.
func TestResendKeepsAnEventThatLostItsNewline(t *testing.T) {
	srv, store := station(t, nil)
	dir, lines := tornRun(t)
	rec := slices.Concat(lines[0], bytes.TrimSuffix(lines[1], []byte("\n")), lines[2], lines[3], lines[4])
	if err := os.WriteFile(filepath.Join(dir, sink.EventsFile), rec, 0o644); err != nil {
		t.Fatal(err)
	}
	var reports []string
	res, err := Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv), Report: func(l string) { reports = append(reports, l) }})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Closed || res.Torn != 0 || res.Sent != 5 || len(reports) != 0 {
		t.Errorf("result %+v, reports %q", res, reports)
	}
	if store.Count() != 5 {
		t.Errorf("the receiver stored %d events", store.Count())
	}
	exitedAfter(t, dir, rec, "0000000006")
}

// TestResendFindsTheEventThatEndsATornLineByItsStrings pins the reading back to the
// start of the event that ends a torn line: its strings hold braces with no pair,
// escaped quotes and runs of backslashes, one ending a string, and it is still kept
// whole.
func TestResendFindsTheEventThatEndsATornLineByItsStrings(t *testing.T) {
	dir, lines := tornRun(t)
	var glued event.Event
	if err := json.Unmarshal(lines[3], &glued); err != nil {
		t.Fatal(err)
	}
	// A brace with no pair, a string that ends with a backslash, and an escaped quote
	// before a brace, each in a string: read as anything but strings, they move where
	// the event seems to start.
	glued.Data = map[string]any{"stream": "stdout", "bytes": "aGkK", "a": `{`, "b": `x\`, "c": `"{`, "d": `}\\`}
	line, err := glued.JSON()
	if err != nil {
		t.Fatal(err)
	}
	rec := slices.Concat(lines[0], lines[1], lines[2][:len(lines[2])/2], line, []byte("\n"), lines[4])
	if err := os.WriteFile(filepath.Join(dir, sink.EventsFile), rec, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Resend(context.Background(), ResendConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Closed || res.Torn != 1 {
		t.Errorf("result %+v", res)
	}
	exitedAfter(t, dir, rec, "0000000006")
	got, err := record(filepath.Join(dir, sink.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.lines) != 5 || string(got.lines[2].line) != string(line) {
		t.Errorf("the events kept: %d, the glued one %s", len(got.lines), got.lines[2].line)
	}
}

// TestResendNeedsASequenceForTheTornBytes pins that the bytes of an event the gateway
// did not finish took a sequence: the event that ends their line, numbered right after
// the event before them, is no event of that place, and is neither kept nor sent.
func TestResendNeedsASequenceForTheTornBytes(t *testing.T) {
	srv, store := station(t, nil)
	dir, lines := tornRun(t)
	var skipped event.Event
	json.Unmarshal(lines[2], &skipped)
	rec := slices.Concat(lines[0], lines[1], lines[3][:len(lines[3])/2], lines[2], lines[3], lines[4])
	if err := os.WriteFile(filepath.Join(dir, sink.EventsFile), rec, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Resend(context.Background(), ResendConfig{Dir: dir, Sink: serverSink(srv)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Closed || res.Torn != 1 || res.Sent != 4 {
		t.Errorf("result %+v", res)
	}
	if store.Seen(skipped.ID) {
		t.Error("the event numbered right after the one before the torn bytes was sent")
	}
	exitedAfter(t, dir, rec, "0000000006")
}
