package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/sink"
)

// heldFile is the file in a run's record directory with the gateway's run.egress that
// waited for run.started when the run was suspended ([Run.Suspend]), one unnumbered
// event per line, in order. [Stream.Reopen] reads it back and removes it.
const heldFile = "held.jsonl"

// Suspend ends the run's stream at the gateway's stop without ending the run, so the
// gateway that starts again on the same directory reopens it ([Stream.Reopen]). The
// groups of [Run.Hold] that still wait are numbered, as [Run.Close] numbers them. A
// run.egress that waits for run.started is not numbered: it is written, unnumbered and
// in order, to held.jsonl in the run's record directory, mode 0600 and synced, and
// Reopen puts it back in its place. Then the run's sinks flush and its lock is released
// as Close does. No final event is numbered, and every file of the record stays. The run
// is closed to new events at once; Suspend or Close again waits for the first and
// returns its result.
func (r *Run) Suspend(ctx context.Context) (Result, error) {
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
	held := r.held
	r.held, r.release = nil, false
	r.closed = true
	srv, rec := r.server, r.record
	r.mu.Unlock()
	defer close(r.done)
	var errs []error
	if len(held) > 0 {
		errs = append(errs, writeHeld(r.dir, held))
	}
	return r.finish(ctx, srv, rec, errs)
}

// writeHeld writes the held events to the record directory's held.jsonl, one line
// each, mode 0600, and syncs the file and the directory.
func writeHeld(dir string, held []*event.Event) error {
	var b []byte
	for _, ev := range held {
		line, err := ev.JSON()
		if err != nil {
			return err
		}
		b = append(append(b, line...), '\n')
	}
	f, err := os.OpenFile(filepath.Join(dir, heldFile), os.O_CREATE|os.O_TRUNC|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return accesskey.ShownError(err)
	}
	_, werr := f.Write(b)
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
		return accesskey.ShownError(err)
	}
	return syncDirs(dir)
}

// Line is one whole event of a run's record, as events.jsonl has it.
type Line struct {
	ID, Type, Sequence, Time string
	// Data is the event's data as recorded.
	Data json.RawMessage
	// Bytes is the line without its newline.
	Bytes []byte
}

// Reopened is the stream of a suspended run, open again ([Stream.Reopen]).
type Reopened struct {
	Run *Run
	// Record is every whole event of the run's record, in sequence order: what the
	// gateway rebuilds the rest of the run from.
	Record []Line
	// Owed are the events of Record the server wants and did not accept, in order,
	// never the run's dev.qory.run.registered. The caller resends each through the
	// run's sink ([Sink.Resend]) right after [Run.Deliver], before anything new is
	// numbered.
	Owed []Line
}

// Reopen opens again the stream of a run suspended at a gateway's stop ([Run.Suspend]),
// in the run's record directory, and takes its lock. It returns an error, and changes
// nothing of the record, when the run is open here ([ErrOpen]), another holds the lock
// ([ErrRunning]), the record is not marked answered ([ErrNotAnswered]), it holds the
// run's final event, run.exited or run.refused of the session's or of the gateway's
// ([ErrEnded]), or delivered.log records the server's stop ([ErrStopped]); a record
// with no events.jsonl is an error that wraps [os.ErrNotExist].
//
// It reads events.jsonl as [Resend] does and makes a last line the gateway did not
// finish a line, as Resend does before it adds run.exited. The run numbers on after the
// higher of the highest whole event's sequence and the highest sequence delivered.log
// has. Every id in the record counts as numbered, so a batch the session sends again is
// numbered once, and run.started as numbered when the record has it. The run's
// dev.qory.run.registered keeps its sequence, which [Run.Deliver] marks only when
// delivered.log does not. The run.egress in held.jsonl waits for run.started again, or
// follows it as it did, and held.jsonl is removed; so is undelivered/, since what was
// spooled is owed again from events.jsonl. wants is the server's filter of event types;
// nil wants every type.
func (s *Stream) Reopen(runID string, wants func(typ string) bool) (*Reopened, error) {
	if err := checkRunID(runID); err != nil {
		return nil, err
	}
	if wants == nil {
		wants = func(string) bool { return true }
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runs[runID] != nil {
		return nil, ErrOpen
	}
	dir := s.Dir(runID)
	if _, err := os.Stat(filepath.Join(dir, sink.EventsFile)); err != nil {
		return nil, accesskey.ShownError(err)
	}
	unlock, err := lock(dir, lockFile)
	if err != nil {
		return nil, err
	}
	re, err := s.reopen(runID, dir, wants)
	if err != nil {
		unlock()
		return nil, err
	}
	re.Run.unlock = unlock
	s.runs[runID] = re.Run
	return re, nil
}

// reopen is [Stream.Reopen] once the lock is taken.
func (s *Stream) reopen(runID, dir string, wants func(string) bool) (*Reopened, error) {
	if _, err := os.Stat(filepath.Join(dir, answeredFile)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotAnswered
		}
		return nil, accesskey.ShownError(err)
	}
	file := filepath.Join(dir, sink.EventsFile)
	rec, err := record(file)
	if err != nil {
		return nil, accesskey.ShownError(err)
	}
	accepted, stopped, err := sink.Delivered(dir)
	if err != nil {
		return nil, err
	}
	if stopped {
		return nil, ErrStopped
	}
	newID := s.newID
	if newID == nil {
		newID = event.NewID
	}
	r := &Run{s: s, id: runID, dir: dir, newID: newID, seen: map[string]bool{}, done: make(chan struct{})}
	re := &Reopened{Run: r, Record: make([]Line, 0, len(rec.lines))}
	var top uint64
	for _, l := range rec.lines {
		switch l.Type {
		case event.RunExited, event.RunRefused:
			return nil, ErrEnded
		case event.RunStarted:
			r.started = true
		case event.RunRegistered:
			r.registered = l.Sequence
		}
		if l.ID != "" {
			r.seen[l.ID] = true
		}
		top = max(top, l.seq)
		line := Line{ID: l.ID, Type: l.Type, Sequence: l.Sequence, Time: l.Time, Data: l.Data, Bytes: l.line}
		re.Record = append(re.Record, line)
		if l.Type != event.RunRegistered && wants(l.Type) && !accepted[l.Sequence] {
			re.Owed = append(re.Owed, line)
		}
	}
	r.marked = r.registered != "" && accepted[r.registered]
	if r.held, err = s.readHeld(runID, dir); err != nil {
		return nil, err
	}
	r.release = r.started && len(r.held) > 0
	r.emit = event.NewEmitterAfter(runID, max(top, highest(accepted)), s.cfg.Now)
	if rec.torn > 0 {
		s.cfg.Report(fmt.Sprintf("run %s: "+ResendTorn, runID, rec.torn, accesskey.ShownValue(file, false)))
	}
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return nil, accesskey.ShownError(err)
	}
	first, err := mendTail(f, rec)
	if err == nil && len(first) > 0 {
		_, err = f.Write(first)
	}
	if err == nil {
		err = f.Sync()
	}
	for _, name := range []string{sink.UndeliveredDir, heldFile} {
		if err == nil {
			err = os.RemoveAll(filepath.Join(dir, name))
		}
	}
	if err != nil {
		f.Close()
		return nil, accesskey.ShownError(err)
	}
	r.record = f
	return re, nil
}

// readHeld reads the run.egress a suspend left in held.jsonl, in order; no file is
// none. A line that holds no whole event, a write the gateway did not finish, is
// skipped and reported.
func (s *Stream) readHeld(runID, dir string) ([]*event.Event, error) {
	b, err := os.ReadFile(filepath.Join(dir, heldFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, accesskey.ShownError(err)
	}
	var held []*event.Event
	torn := 0
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var u unnumbered
		if json.Unmarshal(line, &u) != nil || u.Type == "" || u.ID == "" {
			torn++
			continue
		}
		ev := u.event()
		held = append(held, &ev)
	}
	if torn > 0 {
		s.cfg.Report(fmt.Sprintf("run %s: %d lines of %s are not whole events and are not recorded", runID, torn, accesskey.ShownValue(filepath.Join(dir, heldFile), false)))
	}
	return held, nil
}
