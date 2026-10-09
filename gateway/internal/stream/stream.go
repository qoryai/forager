// Package stream is the gateway's event stream of each run: the one numbering of the
// run's events, the session's and the gateway's own, and where the numbered stream goes.
//
// A [Run] numbers its stream with one contiguous sequence from 0000000001, as the
// contract's §The events requires. With a server the gateway's ping for the run is the
// first event. The session's events arrive on the link with their ids and without a
// sequence, and are numbered in the order they arrive, each id once: a batch the session
// sends again is not numbered twice. The gateway's own run.egress waits until
// run.started is numbered; in a run that never starts it comes before the run's final
// event, or at its close, since today's session records each connection when it is
// made and tells nothing of it. From the moment a reload puts a new policy in force,
// every run.egress waits for the session's run.policy_applied of that policy, the
// tunnels the reload closed first, then the connections decided after it, as today's
// session records them after the policy's event ([Run.Hold], [Run.Await]). Every numbered event goes, in sequence order, to the run's
// record, events.jsonl in the run's record directory as the session's file sink writes
// it today, to the control-plane sink when the run has one, and to [Config.Events].
//
// A run holds a lock in its record directory for as long as it is open, as the session
// holds its own; [Resend] completes and delivers the record of one run whose gateway is
// gone.
package stream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/sink"
)

// CloseWait is how long a run's sinks get to flush when it closes, as the session's
// after its runtime exits.
const CloseWait = 15 * time.Second

// Errors of a run.
var (
	// ErrRunning says a run directory's record is still held: by an open run of this
	// gateway or another's, or by the run's session.
	ErrRunning = errors.New("the run is still going")
	// ErrOpen says the run is open already.
	ErrOpen = errors.New("the run is open already")
	// ErrEnded says the run's final event is numbered: nothing new follows it.
	ErrEnded = errors.New("the run has ended")
	// ErrClosed says the run is closed.
	ErrClosed = errors.New("the run is closed")
)

// Sink is the control-plane sink of one run. [*sink.Server] is one.
type Sink interface {
	// Write queues an event; it never blocks on the server.
	Write(*event.Event) error
	// Accepted records a delivery the sink did not make itself, the ping.
	Accepted(id, seq string)
	// Resend queues a line the record already holds, waiting for room.
	Resend(ctx context.Context, line []byte, seq string) bool
	// Close delivers what is queued until the context ends and spools the rest.
	Close(ctx context.Context) error
	// Undelivered is the number of events the server did not accept.
	Undelivered() int
	// RunClosed says the server closed the run, a signed 410 run_closed.
	RunClosed() bool
}

var _ Sink = (*sink.Server)(nil)

// Config is the stream of every run of one gateway.
type Config struct {
	// Dir is the gateway's directory; a run's record directory is Dir/runs/<run id>
	// unless RunDir says otherwise.
	Dir string
	// RunDir, when not nil, is the record directory of a run.
	RunDir func(runID string) string
	// Events, when not nil, receives every numbered event of every run as the line
	// events.jsonl holds.
	Events io.Writer
	// Report receives one line per thing worth telling the user; nil means nothing is.
	// It is called with a run's lock held and must not block.
	Report func(string)
	// Now is the clock of the gateway's own events; nil means time.Now.
	Now func() time.Time
	// CloseWait bounds a run's flush when it closes; zero means [CloseWait].
	CloseWait time.Duration
}

// Stream holds the open runs of one gateway.
type Stream struct {
	cfg    Config
	events *sink.Writer
	// newID makes the ids of the gateway's own events; a test fixes them.
	newID func() string

	mu   sync.Mutex
	runs map[string]*Run
}

// New returns the stream of a gateway.
func New(cfg Config) *Stream {
	if cfg.Report == nil {
		cfg.Report = func(string) {}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.CloseWait == 0 {
		cfg.CloseWait = CloseWait
	}
	s := &Stream{cfg: cfg, runs: map[string]*Run{}}
	if cfg.Events != nil {
		s.events = sink.NewWriter(cfg.Events)
	}
	return s
}

// Dir is the record directory of a run.
func (s *Stream) Dir(runID string) string {
	if s.cfg.RunDir != nil {
		return s.cfg.RunDir(runID)
	}
	return filepath.Join(s.cfg.Dir, "runs", runID)
}

// Run is the open run of that id, or nil.
func (s *Stream) Run(runID string) *Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runs[runID]
}

// Open opens the stream of a run: it creates the run's record directory when needed,
// takes its lock, [ErrRunning] when another holds it, and creates events.jsonl, which
// must not exist yet, since a run id is never reused. Nothing is numbered yet.
func (s *Stream) Open(runID string) (*Run, error) {
	if err := checkRunID(runID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runs[runID] != nil {
		return nil, ErrOpen
	}
	dir := s.Dir(runID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	unlock, err := lock(dir, lockFile)
	if err != nil {
		return nil, err
	}
	rec, err := os.OpenFile(filepath.Join(dir, sink.EventsFile), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		unlock()
		return nil, err
	}
	newID := s.newID
	if newID == nil {
		newID = event.NewID
	}
	r := &Run{s: s, id: runID, dir: dir, emit: event.NewEmitter(runID, s.cfg.Now), newID: newID, record: rec, unlock: unlock, seen: map[string]bool{}, done: make(chan struct{})}
	s.runs[runID] = r
	return r, nil
}

// Result is what the end of a run's stream came to, toward the server.
type Result struct {
	// Undelivered is how many events the server did not accept; they are under the
	// record directory's undelivered/.
	Undelivered int
	// RunClosed says the server closed the run, a signed 410 run_closed.
	RunClosed bool
}

// Run is the stream of one run. It is safe for concurrent use: every event is numbered
// and written under one lock, so each sink sees the order of the sequence.
type Run struct {
	s     *Stream
	id    string
	dir   string
	emit  *event.Emitter
	newID func() string

	mu     sync.Mutex
	record *os.File
	unlock func()
	server Sink
	// ping is the sequence of the ping, when there is one.
	ping string
	// seen are the ids numbered so far.
	seen map[string]bool
	// started says run.started is numbered; ended that the final event is.
	started, ended bool
	// held are the gateway's run.egress events made before run.started, in order.
	held []*event.Event
	// release says run.started was just numbered and the held events follow it: after
	// a run.policy_applied numbered next, else before whatever is.
	release bool
	// waiting are the gateway's events that wait for an event of the session's, in the
	// order they were made.
	waiting []*Hold
	closed  bool
	// done is closed once Close has flushed, and result is then set.
	done   chan struct{}
	result Result
}

// ID is the run's id.
func (r *Run) ID() string { return r.id }

// Dir is the run's record directory.
func (r *Run) Dir() string { return r.dir }

// Ping numbers the gateway's ping for the run, which must be the run's first event,
// and writes it to the record and to [Config.Events]: the caller posts it to the server
// as a batch of one, then hands the run its sink with [Run.Deliver].
func (r *Run) Ping(data any) (*event.Event, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrClosed
	}
	if r.emit.Sequence() != 0 {
		return nil, errors.New("the ping is the run's first event, and events are numbered already")
	}
	ev := r.make(event.Ping, data)
	r.number(ev)
	r.ping = ev.Sequence
	return ev, nil
}

// Deliver hands the run its control-plane sink, once the server accepted the ping, and
// the run closes the sink. pingID, when not empty, is the delivery id the server
// accepted the ping under, which the sink records. Events numbered before it reach the
// record alone. A closed run is [ErrClosed], and the sink is the caller's to close.
func (r *Run) Deliver(s Sink, pingID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if r.server != nil {
		return errors.New("the run has its sink already")
	}
	r.server = s
	if pingID != "" && r.ping != "" {
		s.Accepted(pingID, r.ping)
	}
	return nil
}

// Started reports whether run.started is numbered.
func (r *Run) Started() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.started
}

// Ended reports whether the run's final event, run.exited or run.refused, is numbered.
func (r *Run) Ended() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ended
}

// Accept numbers the session's events in the order given, those of one link batch: an
// id numbered before is dropped, so a batch sent again is numbered once. Every event
// must be of this run, have an id and not be a ping; otherwise nothing of the batch is
// numbered. When the run's final event is numbered already, a batch with an event not
// numbered before is [ErrEnded], and nothing of it is numbered; within one batch, the
// events after its final event are not numbered, and the count of them is reported. It
// returns how many events it numbered.
func (r *Run) Accept(evs []event.Event) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, ErrClosed
	}
	fresh := make([]*event.Event, 0, len(evs))
	ids := map[string]bool{}
	for i := range evs {
		ev := evs[i]
		switch {
		case ev.ID == "":
			return 0, fmt.Errorf("event %d has no id", i)
		case ev.Subject != r.id || ev.Source != event.Source(r.id):
			return 0, fmt.Errorf("event %s is not of the run %s", ev.ID, r.id)
		case ev.Type == event.Ping:
			return 0, fmt.Errorf("event %s is a ping, which the gateway sends", ev.ID)
		}
		if r.seen[ev.ID] || ids[ev.ID] {
			continue
		}
		ids[ev.ID] = true
		ev.Sequence = ""
		fresh = append(fresh, &ev)
	}
	if len(fresh) == 0 {
		return 0, nil
	}
	if r.ended {
		return 0, ErrEnded
	}
	n := 0
	for _, ev := range fresh {
		if r.ended {
			// What follows the final event in the same batch has no place in the run.
			r.s.cfg.Report(fmt.Sprintf("run %s: %d events after its final event are not in its record", r.id, len(fresh)-n))
			break
		}
		r.number(ev)
		n++
	}
	r.flushHeld()
	return n, nil
}

// Emit numbers one of the gateway's own events: run.egress, or for a run with no
// session its run.started, run.policy_applied, heartbeats; and run.exited when the run
// ends at the gateway. A run.egress before run.started waits for it, and follows it;
// in a run that never starts it comes before the run's end. A run.egress while a
// [Hold] waits joins the newest one.
func (r *Run) Emit(typ string, data any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if r.ended {
		return ErrEnded
	}
	r.put(r.make(typ, data))
	return nil
}

// Hold is a group of the gateway's run.egress that waits for an event of the session's:
// from [Run.Hold] on, every run.egress the gateway emits joins the newest group, until
// [Run.Await] says which event releases it. A Hold belongs to its run.
type Hold struct {
	// match is the event that releases the group, nil until Await names it: until then
	// none does.
	match func(*event.Event) bool
	evs   []*event.Event
}

// Hold starts holding the gateway's run.egress, every one emitted from now on, in order,
// in a new group, the newest: the egress of a run whose policy a reload is about to
// change, which follows the session's run.policy_applied of the new policy, as today's
// session records it, the policy, its event and the connections after, in one step.
// Await says which event releases it. Nil when the run is closed or has ended.
func (r *Run) Hold() *Hold {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ended {
		return nil
	}
	h := &Hold{}
	r.waiting = append(r.waiting, h)
	return h
}

// Await names the event that releases h: the run.egress h holds is numbered right
// after the next numbered event match accepts, behind events of the type made from
// first, which go before what h holds: the tunnels the reload closed. An event match
// accepts releases the groups made before h that still wait too, in order, so a reload
// the session skipped does not hold its egress back. When the run's final event comes
// first they are numbered right before it, and [Run.Close] numbers what still waits. A
// run.egress released before run.started waits for it, as with [Run.Emit]. match is
// called with the lock held and must not call the run. A nil h, or one released
// already, holds nothing, and first is numbered as Emit numbers it.
func (r *Run) Await(h *Hold, match func(*event.Event) bool, typ string, first ...any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if r.ended {
		return ErrEnded
	}
	evs := make([]*event.Event, len(first))
	for i, d := range first {
		evs[i] = r.make(typ, d)
	}
	if h == nil || !slices.Contains(r.waiting, h) {
		for _, ev := range evs {
			r.put(ev)
		}
		return nil
	}
	h.match, h.evs = match, append(evs, h.evs...)
	return nil
}

// put numbers one of the gateway's own events in its place: a run.egress joins the
// newest group that waits, or waits for run.started; anything else is numbered at once.
// Called with the lock held.
func (r *Run) put(ev *event.Event) {
	switch {
	case ev.Type == event.RunEgress && len(r.waiting) > 0:
		w := r.waiting[len(r.waiting)-1]
		w.evs = append(w.evs, ev)
	case ev.Type == event.RunEgress && !r.started:
		r.held = append(r.held, ev)
	default:
		r.number(ev)
	}
}

// releaseWaiting numbers the first n groups of waiting events, in order: a run.egress
// before run.started is held for it. Called with the lock held.
func (r *Run) releaseWaiting(n int) {
	done := r.waiting[:n:n]
	r.waiting = r.waiting[n:]
	for _, w := range done {
		for _, ev := range w.evs {
			if ev.Type == event.RunEgress && !r.started {
				r.held = append(r.held, ev)
				continue
			}
			r.number(ev)
		}
	}
}

// make returns one of the gateway's own events, not numbered yet.
func (r *Run) make(typ string, data any) *event.Event {
	ev := r.emit.Unnumbered(typ, data)
	ev.ID = r.newID()
	return ev
}

// number gives the event its sequence and writes it everywhere, with the held egress
// in its place: after run.started and the run.policy_applied right after it; and the
// waiting events after the event they wait for, or before the final event, and in a
// run that never started what was held before its final event. Called with the lock
// held.
func (r *Run) number(ev *event.Event) {
	if r.release && ev.Type != event.PolicyApplied {
		r.flushHeld()
	}
	final := ev.Type == event.RunExited || ev.Type == event.RunRefused
	if final && len(r.waiting) > 0 {
		r.releaseWaiting(len(r.waiting))
	}
	if final {
		// A run that never started: what was held comes before its end.
		r.numberHeld()
	}
	r.emit.Number(ev)
	r.write(ev)
	r.seen[ev.ID] = true
	switch ev.Type {
	case event.RunStarted:
		r.started = true
		r.release = len(r.held) > 0
	case event.PolicyApplied:
		r.flushHeld()
	case event.RunExited, event.RunRefused:
		r.ended = true
	}
	if final {
		return
	}
	for i := len(r.waiting) - 1; i >= 0; i-- {
		if m := r.waiting[i].match; m != nil && m(ev) {
			r.releaseWaiting(i + 1)
			break
		}
	}
}

// flushHeld numbers the held egress, once run.started is. Called with the lock held.
func (r *Run) flushHeld() {
	if !r.release {
		return
	}
	r.numberHeld()
}

// numberHeld numbers the held egress, in order, whether or not run.started is. Called
// with the lock held.
func (r *Run) numberHeld() {
	r.release = false
	held := r.held
	r.held = nil
	for _, ev := range held {
		r.number(ev)
	}
}

// write writes a numbered event to the record, the server and the stream of events.
// Called with the lock held.
func (r *Run) write(ev *event.Event) {
	line, err := ev.JSON()
	if err != nil {
		r.s.cfg.Report(fmt.Sprintf("run %s: event %s: %v", r.id, ev.ID, err))
		return
	}
	if _, err := r.record.Write(append(line, '\n')); err != nil {
		r.s.cfg.Report(fmt.Sprintf("run %s: the record: %v", r.id, err))
	}
	if r.server != nil {
		if err := r.server.Write(ev); err != nil {
			r.s.cfg.Report(fmt.Sprintf("run %s: the server: %v", r.id, err))
		}
	}
	if r.s.events != nil {
		if err := r.s.events.Write(ev); err != nil {
			r.s.cfg.Report(fmt.Sprintf("run %s: the events: %v", r.id, err))
		}
	}
}

// Close ends the run's stream: the server gets up to [Config.CloseWait] to take what
// is queued, what it has not taken is spooled under undelivered/, the record is synced
// and closed and the lock released. The context's values pass to the flush, its
// cancellation does not, as the session's flush after its runtime exits. The events
// still waiting for an event of the session's are numbered first, and then a
// run.egress still held, of a run that never started and has no final event.
// The run is closed to new events at once, while it flushes; Close again waits for the
// first and returns its result.
func (r *Run) Close(ctx context.Context) (Result, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		<-r.done
		return r.result, nil
	}
	if len(r.waiting) > 0 && !r.ended {
		r.releaseWaiting(len(r.waiting))
	}
	r.waiting = nil
	if !r.ended {
		r.numberHeld()
	}
	r.held = nil
	r.closed = true
	srv, rec := r.server, r.record
	r.mu.Unlock()
	defer close(r.done)
	var errs []error
	if srv != nil {
		flush, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.s.cfg.CloseWait)
		errs = append(errs, srv.Close(flush))
		cancel()
		r.result = Result{Undelivered: srv.Undelivered(), RunClosed: srv.RunClosed()}
	}
	errs = append(errs, rec.Sync(), rec.Close())
	r.unlock()
	r.s.mu.Lock()
	delete(r.s.runs, r.id)
	r.s.mu.Unlock()
	return r.result, errors.Join(errs...)
}

// Discard closes the run's stream as [Run.Close] does, then removes what the stream
// wrote under the run's record directory, events.jsonl, the delivery state and its
// lock, and the directory itself when nothing else is left in it, so the run id opens
// again: a run that never opened.
func (r *Run) Discard(ctx context.Context) error {
	_, err := r.Close(ctx)
	errs := []error{err}
	for _, name := range []string{sink.EventsFile, sink.DeliveredFile, sink.UndeliveredDir, lockFile} {
		errs = append(errs, os.RemoveAll(filepath.Join(r.dir, name)))
	}
	// Left in place when it holds anything else, a session's own files on one machine.
	os.Remove(r.dir)
	return errors.Join(errs...)
}

// DecodeBatch reads a link batch, a JSON array of the session's events, keeping each
// event's data as the session encoded it, so the record holds the bytes it would have
// written itself. It checks the shape alone; the link checks the schema.
func DecodeBatch(body []byte) ([]event.Event, error) {
	var raw []struct {
		SpecVersion string          `json:"specversion"`
		ID          string          `json:"id"`
		Source      string          `json:"source"`
		Type        string          `json:"type"`
		Subject     string          `json:"subject"`
		Time        string          `json:"time"`
		DataSchema  string          `json:"dataschema"`
		Data        json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	out := make([]event.Event, len(raw))
	for i, e := range raw {
		out[i] = event.Event{SpecVersion: e.SpecVersion, ID: e.ID, Source: e.Source, Type: e.Type, Subject: e.Subject, Time: e.Time, DataSchema: e.DataSchema}
		if e.Data != nil {
			out[i].Data = e.Data
		}
	}
	return out, nil
}

// runIDShape is a run id: a UUID in the canonical lower-case form, since it names the
// run's record directory.
var runIDShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func checkRunID(id string) error {
	if !runIDShape.MatchString(id) {
		return fmt.Errorf("the run id %q is not a UUID in the canonical lower-case form", id)
	}
	return nil
}
