package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/sink"
)

// fakeSink is a control-plane sink that keeps what it is given.
type fakeSink struct {
	mu          sync.Mutex
	events      []*event.Event
	accepted    []string
	closed      bool
	deadline    time.Duration
	undelivered int
	runClosed   bool
}

func (f *fakeSink) Write(ev *event.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeSink) Accepted(id, seq string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accepted = append(f.accepted, id+" "+seq)
}

func (f *fakeSink) Resend(context.Context, []byte, string) bool { return true }

func (f *fakeSink) Close(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	if d, ok := ctx.Deadline(); ok {
		f.deadline = time.Until(d)
	}
	return nil
}

func (f *fakeSink) Undelivered() int { return f.undelivered }
func (f *fakeSink) RunClosed() bool  { return f.runClosed }

// syncBuffer is an io.Writer safe for the runs' goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// sessionEvent is an event of the session's as the link carries it: an id, no sequence.
func sessionEvent(runID, typ string, data any) event.Event {
	ev := event.NewEmitter(runID, nil).Unnumbered(typ, data)
	return *ev
}

// readRecord reads a run's events.jsonl.
func readRecord(t *testing.T, dir string) []event.Event {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, sink.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	return parseLines(t, string(b))
}

func parseLines(t *testing.T, s string) []event.Event {
	t.Helper()
	var out []event.Event
	for _, line := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		if line == "" {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

// types are the types of the events, in order.
func types(evs []event.Event) []string {
	var out []string
	for _, ev := range evs {
		out = append(out, strings.TrimPrefix(ev.Type, event.Prefix))
	}
	return out
}

// contiguous checks one sequence from 0000000001 without a gap, of the one run.
func contiguous(t *testing.T, runID string, evs []event.Event) {
	t.Helper()
	for i, ev := range evs {
		if want := fmt.Sprintf("%010d", i+1); ev.Sequence != want {
			t.Errorf("event %d (%s): sequence %q, want %s", i, ev.Type, ev.Sequence, want)
		}
		if ev.Subject != runID || ev.Source != event.Source(runID) {
			t.Errorf("event %d is of %s", i, ev.Subject)
		}
	}
}

// TestTheRunIsOneStreamFromThePing pins the numbering: the ping first, then the
// session's events and the gateway's own, one contiguous sequence; the record, the
// stream of events and the server each see that order; the server gets everything but
// the ping, which it accepted on its own, and the sink records the ping's delivery.
func TestTheRunIsOneStreamFromThePing(t *testing.T) {
	var out syncBuffer
	s := New(Config{Dir: t.TempDir(), Events: &out})
	runID := event.NewRunID()
	r, err := s.Open(runID)
	if err != nil {
		t.Fatal(err)
	}
	ping, err := r.Ping(map[string]any{"forager_version": "dev", "events": []string{"*"}, "contract_version": 1, "interval_seconds": 30})
	if err != nil || ping.Sequence != "0000000001" {
		t.Fatalf("ping %+v, %v", ping, err)
	}
	srv := &fakeSink{}
	if err := r.Deliver(srv, "delivery-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Ping(nil); err == nil {
		t.Error("a second ping was numbered")
	}
	n, err := r.Accept([]event.Event{
		sessionEvent(runID, event.RunStarted, map[string]any{"opened_by": "session"}),
		sessionEvent(runID, event.PolicyApplied, map[string]any{"mode": "observe"}),
		sessionEvent(runID, event.RunLog, map[string]any{"stream": "stdout", "bytes": "aGkK"}),
	})
	if err != nil || n != 3 {
		t.Fatalf("accepted %d, %v", n, err)
	}
	if err := r.Emit(event.RunEgress, map[string]any{"host": "example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Accept([]event.Event{sessionEvent(runID, event.RunExited, map[string]any{"state": "succeeded", "exit_code": 0})}); err != nil {
		t.Fatal(err)
	}
	if !r.Started() || !r.Ended() {
		t.Errorf("started %v ended %v", r.Started(), r.Ended())
	}
	if _, err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec := readRecord(t, r.Dir())
	contiguous(t, runID, rec)
	if got := strings.Join(types(rec), " "); got != "ping run.started run.policy_applied run.log run.egress run.exited" {
		t.Errorf("the record: %s", got)
	}
	b, _ := os.ReadFile(filepath.Join(r.Dir(), sink.EventsFile))
	if out.String() != string(b) {
		t.Errorf("the stream of events\n%s\nthe record\n%s", out.String(), b)
	}
	if len(srv.events) != 5 || srv.events[0].Type != event.RunStarted || srv.events[0].Sequence != "0000000002" {
		t.Errorf("the server got %d events", len(srv.events))
	}
	if len(srv.accepted) != 1 || srv.accepted[0] != "delivery-1 0000000001" || !srv.closed {
		t.Errorf("the sink: accepted %v, closed %v", srv.accepted, srv.closed)
	}
	if r.Dir() != filepath.Join(s.cfg.Dir, "runs", runID) {
		t.Errorf("the record directory %s", r.Dir())
	}
}

// TestARunWithNoServerHasNoPing pins the files-only run: run.started is the first
// event.
func TestARunWithNoServerHasNoPing(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	runID := event.NewRunID()
	r, err := s.Open(runID)
	if err != nil {
		t.Fatal(err)
	}
	r.Accept([]event.Event{sessionEvent(runID, event.RunStarted, map[string]any{})})
	r.Close(context.Background())
	rec := readRecord(t, r.Dir())
	contiguous(t, runID, rec)
	if len(rec) != 1 || rec[0].Type != event.RunStarted {
		t.Errorf("the record: %v", types(rec))
	}
}

// TestARepeatedIDIsNumberedOnce pins idempotent re-delivery: a batch sent again, and
// an id repeated inside a batch, are numbered once.
func TestARepeatedIDIsNumberedOnce(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	runID := event.NewRunID()
	r, _ := s.Open(runID)
	started := sessionEvent(runID, event.RunStarted, map[string]any{})
	log := sessionEvent(runID, event.RunLog, map[string]any{"stream": "stdout", "bytes": ""})
	batch := []event.Event{started, log, log}
	if n, err := r.Accept(batch); err != nil || n != 2 {
		t.Fatalf("first: %d, %v", n, err)
	}
	if n, err := r.Accept(batch); err != nil || n != 0 {
		t.Fatalf("again: %d, %v", n, err)
	}
	beat := sessionEvent(runID, event.RunHeartbeat, map[string]any{})
	if n, err := r.Accept([]event.Event{log, beat}); err != nil || n != 1 {
		t.Fatalf("overlapping: %d, %v", n, err)
	}
	r.Close(context.Background())
	rec := readRecord(t, r.Dir())
	contiguous(t, runID, rec)
	if got := strings.Join(types(rec), " "); got != "run.started run.log run.heartbeat" {
		t.Errorf("the record: %s", got)
	}
	if rec[1].ID != log.ID || rec[2].ID != beat.ID {
		t.Error("the session's ids were not kept")
	}
}

// TestABatchOfOthersIsRefusedWhole pins the checks: an event of another run, a ping,
// an event without an id; nothing of such a batch is numbered.
func TestABatchOfOthersIsRefusedWhole(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	runID := event.NewRunID()
	r, _ := s.Open(runID)
	defer r.Close(context.Background())
	good := sessionEvent(runID, event.RunStarted, map[string]any{})
	noID := sessionEvent(runID, event.RunLog, map[string]any{})
	noID.ID = ""
	for name, bad := range map[string]event.Event{
		"other run": sessionEvent(event.NewRunID(), event.RunLog, map[string]any{}),
		"ping":      sessionEvent(runID, event.Ping, map[string]any{}),
		"no id":     noID,
	} {
		if n, err := r.Accept([]event.Event{good, bad}); err == nil || n != 0 {
			t.Errorf("%s: accepted %d, %v", name, n, err)
		}
	}
	if r.Started() {
		t.Error("a refused batch was numbered")
	}
}

// TestEgressWaitsForRunStarted pins the gate: the gateway's run.egress before
// run.started is held, and follows run.started and the run.policy_applied right after
// it, in order; one after that is numbered at once. Heartbeats are not held.
func TestEgressWaitsForRunStarted(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	runID := event.NewRunID()
	r, _ := s.Open(runID)
	r.Ping(map[string]any{})
	r.Emit(event.RunEgress, map[string]any{"host": "one.example"})
	r.Accept([]event.Event{sessionEvent(runID, event.RunHeartbeat, map[string]any{})})
	r.Emit(event.RunEgress, map[string]any{"host": "two.example"})
	r.Accept([]event.Event{
		sessionEvent(runID, event.RunStarted, map[string]any{}),
		sessionEvent(runID, event.PolicyApplied, map[string]any{}),
		sessionEvent(runID, event.RunLog, map[string]any{}),
	})
	r.Emit(event.RunEgress, map[string]any{"host": "three.example"})
	r.Close(context.Background())
	rec := readRecord(t, r.Dir())
	contiguous(t, runID, rec)
	if got := strings.Join(types(rec), " "); got != "ping run.heartbeat run.started run.policy_applied run.egress run.egress run.log run.egress" {
		t.Errorf("the record: %s", got)
	}
	var hosts []string
	for _, ev := range rec {
		if ev.Type == event.RunEgress {
			hosts = append(hosts, ev.Data.(map[string]any)["host"].(string))
		}
	}
	if strings.Join(hosts, " ") != "one.example two.example three.example" {
		t.Errorf("the egress order %v", hosts)
	}
}

// TestHeldEgressFollowsAStartAloneInItsBatch pins the gate's edge: when run.started
// ends its batch, what was held follows it at once, before the next batch.
func TestHeldEgressFollowsAStartAloneInItsBatch(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	runID := event.NewRunID()
	r, _ := s.Open(runID)
	r.Emit(event.RunEgress, map[string]any{"host": "one.example"})
	r.Accept([]event.Event{sessionEvent(runID, event.RunStarted, map[string]any{})})
	r.Accept([]event.Event{sessionEvent(runID, event.PolicyApplied, map[string]any{})})
	r.Close(context.Background())
	rec := readRecord(t, r.Dir())
	contiguous(t, runID, rec)
	if got := strings.Join(types(rec), " "); got != "run.started run.egress run.policy_applied" {
		t.Errorf("the record: %s", got)
	}
}

// appliedDigest matches a run.policy_applied of that digest.
func appliedDigest(digest string) func(*event.Event) bool {
	return func(ev *event.Event) bool {
		data, _ := ev.Data.(map[string]any)
		return ev.Type == event.PolicyApplied && data["digest"] == digest
	}
}

// hostsAndTypes are the record's types, each run.egress with its host.
func hostsAndTypes(evs []event.Event) string {
	var out []string
	for _, ev := range evs {
		t := strings.TrimPrefix(ev.Type, event.Prefix)
		if ev.Type == event.RunEgress {
			t += ":" + ev.Data.(map[string]any)["host"].(string)
		}
		out = append(out, t)
	}
	return strings.Join(out, " ")
}

// TestWaitingEgressFollowsItsPolicyApplied pins the reload's order, today's session's:
// the run.egress made with EmitAfter follow the run.policy_applied they wait for, not
// another; one that comes releases those made before it that still wait; and when the
// session's final event comes first, they are numbered right before it.
func TestWaitingEgressFollowsItsPolicyApplied(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	runID := event.NewRunID()
	r, _ := s.Open(runID)
	r.Accept([]event.Event{
		sessionEvent(runID, event.RunStarted, map[string]any{}),
		sessionEvent(runID, event.PolicyApplied, map[string]any{"digest": "a"}),
	})
	r.EmitAfter(appliedDigest("b"), event.RunEgress, map[string]any{"host": "one.example"}, map[string]any{"host": "two.example"})
	r.Accept([]event.Event{
		sessionEvent(runID, event.RunLog, map[string]any{}),
		sessionEvent(runID, event.PolicyApplied, map[string]any{"digest": "a"}),
	})
	r.Emit(event.RunEgress, map[string]any{"host": "now.example"})
	r.Accept([]event.Event{
		sessionEvent(runID, event.PolicyApplied, map[string]any{"digest": "b"}),
		sessionEvent(runID, event.RunLog, map[string]any{}),
	})
	r.EmitAfter(appliedDigest("c"), event.RunEgress, map[string]any{"host": "three.example"})
	r.EmitAfter(appliedDigest("d"), event.RunEgress, map[string]any{"host": "four.example"})
	r.Accept([]event.Event{sessionEvent(runID, event.PolicyApplied, map[string]any{"digest": "d"})})
	r.EmitAfter(appliedDigest("e"), event.RunEgress, map[string]any{"host": "five.example"})
	r.Accept([]event.Event{
		sessionEvent(runID, event.RunLog, map[string]any{}),
		sessionEvent(runID, event.RunExited, map[string]any{}),
	})
	if err := r.EmitAfter(appliedDigest("f"), event.RunEgress, map[string]any{"host": "six.example"}); !errors.Is(err, ErrEnded) {
		t.Errorf("after the final event: %v", err)
	}
	r.Close(context.Background())
	rec := readRecord(t, r.Dir())
	contiguous(t, runID, rec)
	want := "run.started run.policy_applied run.log run.policy_applied run.egress:now.example " +
		"run.policy_applied run.egress:one.example run.egress:two.example run.log " +
		"run.policy_applied run.egress:three.example run.egress:four.example " +
		"run.log run.egress:five.example run.exited"
	if got := hostsAndTypes(rec); got != want {
		t.Errorf("the record:\n got %s\nwant %s", got, want)
	}
}

// TestWaitingEgressPrecedesTheGatewaysEnd pins the other ends: the gateway's own
// run.exited follows what still waits, and Close numbers what waits in a run that has
// no final event, one that never started too.
func TestWaitingEgressPrecedesTheGatewaysEnd(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	runID := event.NewRunID()
	r, _ := s.Open(runID)
	r.Accept([]event.Event{sessionEvent(runID, event.RunStarted, map[string]any{})})
	r.EmitAfter(appliedDigest("b"), event.RunEgress, map[string]any{"host": "one.example"})
	r.Emit(event.RunExited, map[string]any{"state": "failed"})
	r.Close(context.Background())
	rec := readRecord(t, r.Dir())
	contiguous(t, runID, rec)
	if got := hostsAndTypes(rec); got != "run.started run.egress:one.example run.exited" {
		t.Errorf("the record: %s", got)
	}

	runID = event.NewRunID()
	r, _ = s.Open(runID)
	r.Accept([]event.Event{sessionEvent(runID, event.RunStarted, map[string]any{})})
	r.EmitAfter(appliedDigest("b"), event.RunEgress, map[string]any{"host": "one.example"})
	r.Close(context.Background())
	rec = readRecord(t, r.Dir())
	contiguous(t, runID, rec)
	if got := hostsAndTypes(rec); got != "run.started run.egress:one.example" {
		t.Errorf("the record of a run with no final event: %s", got)
	}

	runID = event.NewRunID()
	r, _ = s.Open(runID)
	r.EmitAfter(appliedDigest("b"), event.RunEgress, map[string]any{"host": "one.example"})
	r.Close(context.Background())
	if got := hostsAndTypes(readRecord(t, r.Dir())); got != "run.egress:one.example" {
		t.Errorf("the record of a run that never started: %s", got)
	}
}

// TestEgressOfARunThatNeverStartedIsRecorded pins today's session's record of a run
// that never starts: each connection is in it, before the run's final event when one
// comes, else at the close, and nothing is reported.
func TestEgressOfARunThatNeverStartedIsRecorded(t *testing.T) {
	var reports []string
	s := New(Config{Dir: t.TempDir(), Report: func(l string) { reports = append(reports, l) }})
	runID := event.NewRunID()
	r, _ := s.Open(runID)
	r.Ping(map[string]any{})
	r.Emit(event.RunEgress, map[string]any{"host": "one.example"})
	r.Emit(event.RunEgress, map[string]any{"host": "two.example"})
	r.Close(context.Background())
	rec := readRecord(t, r.Dir())
	contiguous(t, runID, rec)
	if got := hostsAndTypes(rec); got != "ping run.egress:one.example run.egress:two.example" {
		t.Errorf("the record: %s", got)
	}
	runID = event.NewRunID()
	r, _ = s.Open(runID)
	r.Emit(event.RunEgress, map[string]any{"host": "one.example"})
	r.Accept([]event.Event{sessionEvent(runID, event.RunRefused, map[string]any{"code": "image_unknown"})})
	r.Close(context.Background())
	rec = readRecord(t, r.Dir())
	contiguous(t, runID, rec)
	if got := hostsAndTypes(rec); got != "run.egress:one.example run.refused" {
		t.Errorf("the record of a refused run: %s", got)
	}
	if len(reports) != 0 {
		t.Errorf("reports %q", reports)
	}
}

// TestNothingFollowsTheFinalEvent pins the end: after run.exited a new event is
// ErrEnded, from the session or the gateway, and a repeat of an old one is no error.
func TestNothingFollowsTheFinalEvent(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	runID := event.NewRunID()
	r, _ := s.Open(runID)
	exited := sessionEvent(runID, event.RunExited, map[string]any{})
	r.Accept([]event.Event{sessionEvent(runID, event.RunStarted, map[string]any{}), exited})
	if _, err := r.Accept([]event.Event{sessionEvent(runID, event.RunLog, map[string]any{})}); !errors.Is(err, ErrEnded) {
		t.Errorf("a new event after the end: %v", err)
	}
	if n, err := r.Accept([]event.Event{exited}); err != nil || n != 0 {
		t.Errorf("the final event again: %d, %v", n, err)
	}
	if err := r.Emit(event.RunEgress, map[string]any{}); !errors.Is(err, ErrEnded) {
		t.Errorf("an egress after the end: %v", err)
	}
	r.Close(context.Background())
	if _, err := r.Accept([]event.Event{sessionEvent(runID, event.RunLog, map[string]any{})}); !errors.Is(err, ErrClosed) {
		t.Errorf("after close: %v", err)
	}
	if rec := readRecord(t, r.Dir()); len(rec) != 2 {
		t.Errorf("the record: %v", types(rec))
	}
}

// TestCloseFlushesWithinTheWaitAndReleases pins the end of a run: the server's flush
// is bounded by the close wait, its result comes back, the lock is released, the run
// leaves the stream, and Close again is the same result.
func TestCloseFlushesWithinTheWaitAndReleases(t *testing.T) {
	s := New(Config{Dir: t.TempDir(), CloseWait: 2 * time.Second})
	runID := event.NewRunID()
	r, _ := s.Open(runID)
	srv := &fakeSink{undelivered: 3, runClosed: true}
	r.Ping(map[string]any{})
	r.Deliver(srv, "d")
	if s.Run(runID) != r {
		t.Error("the open run is not found")
	}
	if _, err := lock(r.Dir(), lockFile); !errors.Is(err, ErrRunning) {
		t.Errorf("the lock of an open run: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := r.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res != (Result{Undelivered: 3, RunClosed: true}) {
		t.Errorf("result %+v", res)
	}
	if !srv.closed || srv.deadline <= 0 || srv.deadline > 2*time.Second {
		t.Errorf("the flush had %v", srv.deadline)
	}
	if s.Run(runID) != nil {
		t.Error("a closed run is still open")
	}
	unlock, err := lock(r.Dir(), lockFile)
	if err != nil {
		t.Errorf("the lock after close: %v", err)
	} else {
		unlock()
	}
	if again, err := r.Close(context.Background()); err != nil || again != res {
		t.Errorf("close again: %+v, %v", again, err)
	}
}

// TestARunIsOpenedOnce pins the lock and the record: a run open in this stream is
// ErrOpen, one whose lock another holds is ErrRunning, and a record directory that
// holds an events.jsonl is not reused; a bad run id opens nothing.
func TestARunIsOpenedOnce(t *testing.T) {
	dir := t.TempDir()
	s := New(Config{Dir: dir})
	runID := event.NewRunID()
	r, err := s.Open(runID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(runID); !errors.Is(err, ErrOpen) {
		t.Errorf("open again: %v", err)
	}
	if _, err := New(Config{Dir: dir}).Open(runID); !errors.Is(err, ErrRunning) {
		t.Errorf("another gateway: %v", err)
	}
	r.Close(context.Background())
	if _, err := s.Open(runID); err == nil {
		t.Error("a record directory was reused")
	}
	if _, err := s.Open("../x"); err == nil {
		t.Error("a bad run id was opened")
	}
}

// TestRunDirPlacesTheRecord pins Config.RunDir.
func TestRunDirPlacesTheRecord(t *testing.T) {
	base := t.TempDir()
	s := New(Config{Dir: t.TempDir(), RunDir: func(id string) string { return filepath.Join(base, id) }})
	runID := event.NewRunID()
	r, err := s.Open(runID)
	if err != nil {
		t.Fatal(err)
	}
	r.Close(context.Background())
	if _, err := os.Stat(filepath.Join(base, runID, sink.EventsFile)); err != nil {
		t.Error(err)
	}
}

// TestConcurrentRunsAreIsolated pins that runs numbered at once, from several
// goroutines each, keep one contiguous stream each, with their own events alone, and
// that the shared stream of events gets whole lines.
func TestConcurrentRunsAreIsolated(t *testing.T) {
	var out syncBuffer
	s := New(Config{Dir: t.TempDir(), Events: &out})
	const runs, writers, each = 4, 4, 50
	var all []*Run
	for range runs {
		runID := event.NewRunID()
		r, err := s.Open(runID)
		if err != nil {
			t.Fatal(err)
		}
		r.Ping(map[string]any{})
		r.Deliver(&fakeSink{}, "d")
		r.Accept([]event.Event{sessionEvent(runID, event.RunStarted, map[string]any{})})
		all = append(all, r)
	}
	var wg sync.WaitGroup
	for _, r := range all {
		for w := range writers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range each {
					if w%2 == 0 {
						r.Emit(event.RunEgress, map[string]any{"n": i})
						continue
					}
					ev := sessionEvent(r.ID(), event.RunLog, map[string]any{"n": i})
					r.Accept([]event.Event{ev, ev})
				}
			}()
		}
	}
	wg.Wait()
	for _, r := range all {
		r.Close(context.Background())
		rec := readRecord(t, r.Dir())
		contiguous(t, r.ID(), rec)
		if len(rec) != 2+writers*each {
			t.Errorf("run %s: %d events", r.ID(), len(rec))
		}
	}
	if lines := parseLines(t, out.String()); len(lines) != runs*(2+writers*each) {
		t.Errorf("the stream of events has %d lines", len(lines))
	}
}

// TestTheRecordIsTodays pins the record format: the recorded runs of the contract's
// fixtures, fed through the stream as the gateway would, the ping and the egress its
// own and the rest from the session's link batches, give events.jsonl byte for byte.
func TestTheRecordIsTodays(t *testing.T) {
	root := filepath.Join("..", "..", "..", "contracts", "forager", "v1", "fixtures", "run")
	dirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	runs := 0
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		runs++
		t.Run(d.Name(), func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join(root, d.Name(), sink.EventsFile))
			if err != nil {
				t.Fatal(err)
			}
			var next struct{ id, time string }
			var out syncBuffer
			s := New(Config{Dir: t.TempDir(), Events: &out, Now: func() time.Time {
				tm, err := time.Parse(time.RFC3339Nano, next.time)
				if err != nil {
					t.Fatal(err)
				}
				return tm
			}})
			s.newID = func() string { return next.id }
			r, err := s.Open(d.Name())
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(strings.TrimSuffix(string(want), "\n"), "\n") {
				var head struct {
					ID   string          `json:"id"`
					Type string          `json:"type"`
					Time string          `json:"time"`
					Data json.RawMessage `json:"data"`
				}
				if err := json.Unmarshal([]byte(line), &head); err != nil {
					t.Fatal(err)
				}
				next.id, next.time = head.ID, head.Time
				switch head.Type {
				case event.Ping:
					if _, err := r.Ping(head.Data); err != nil {
						t.Fatal(err)
					}
				case event.RunEgress:
					if err := r.Emit(head.Type, head.Data); err != nil {
						t.Fatal(err)
					}
				default:
					// The link batch: the line without its sequence.
					var obj map[string]json.RawMessage
					json.Unmarshal([]byte(line), &obj)
					delete(obj, "sequence")
					body, _ := json.Marshal([]map[string]json.RawMessage{obj})
					evs, err := DecodeBatch(body)
					if err != nil {
						t.Fatal(err)
					}
					if n, err := r.Accept(evs); err != nil || n != 1 {
						t.Fatalf("%s: %d, %v", head.Type, n, err)
					}
				}
			}
			if _, err := r.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(filepath.Join(r.Dir(), sink.EventsFile))
			if !bytes.Equal(got, want) {
				t.Errorf("the record differs from the fixture\ngot\n%s\nwant\n%s", got, want)
			}
			if out.String() != string(want) {
				t.Error("the stream of events differs from the fixture")
			}
		})
	}
	if runs == 0 {
		t.Fatal("no recorded runs")
	}
}
