package stream

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/sink"
)

// suspendedRun leaves the record of a run suspended at a gateway's stop: run.registered,
// the mark answered, run.started and two logs, the registration marked in delivered.log
// as the gateway's sink marks it. It returns the run id.
func suspendedRun(t *testing.T, s *Stream) string {
	t.Helper()
	runID := event.NewRunID()
	r, err := s.Open(runID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Registered(map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if err := r.MarkAnswered(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Accept([]event.Event{
		sessionEvent(runID, event.RunStarted, map[string]any{}),
		sessionEvent(runID, event.RunLog, map[string]any{"stream": "stdout", "bytes": "aGkK"}),
		sessionEvent(runID, event.RunLog, map[string]any{"stream": "stdout", "bytes": "aGkK"}),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Suspend(context.Background()); err != nil {
		t.Fatal(err)
	}
	registrationAccepted(t, r.Dir())
	return runID
}

// appendFile appends b to the file.
func appendFile(t *testing.T, file string, b string) {
	t.Helper()
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(b); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// TestReopenNumbersOnFromTheHigherSequence pins the sequence of a reopened run: it
// numbers on after the higher of the record's highest whole event and the highest
// sequence delivered.log has; run.registered is not numbered again, and the sink marks
// it only when delivered.log does not.
func TestReopenNumbersOnFromTheHigherSequence(t *testing.T) {
	for name, tc := range map[string]struct {
		delivered string
		next      string
		marks     []string
	}{
		"the record is higher":    {"registered 0000000001\nd1 0000000002\n", "0000000005", nil},
		"delivered.log is higher": {"registered 0000000001\nd1 0000000002 0000000003 0000000007\n", "0000000008", nil},
		"no registration marked":  {"", "0000000005", []string{"0000000001"}},
	} {
		t.Run(name, func(t *testing.T) {
			s := New(Config{Dir: t.TempDir()})
			runID := suspendedRun(t, s)
			if err := os.WriteFile(filepath.Join(s.Dir(runID), sink.DeliveredFile), []byte(tc.delivered), 0o644); err != nil {
				t.Fatal(err)
			}
			re, err := s.Reopen(runID, nil)
			if err != nil {
				t.Fatal(err)
			}
			if s.Run(runID) != re.Run {
				t.Error("the reopened run is not open in its stream")
			}
			f := &fakeSink{}
			if err := re.Run.Deliver(f); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(f.registered, tc.marks) {
				t.Errorf("the sink marks %q, want %q", f.registered, tc.marks)
			}
			if _, err := re.Run.Registered(map[string]any{}); err == nil {
				t.Error("run.registered numbered again")
			}
			if !re.Run.Started() {
				t.Error("run.started is not numbered")
			}
			if n, err := re.Run.Accept([]event.Event{sessionEvent(runID, event.RunLog, map[string]any{})}); n != 1 || err != nil {
				t.Fatalf("accept: %d %v", n, err)
			}
			if len(f.events) != 1 || f.events[0].Sequence != tc.next {
				t.Errorf("the sink has %+v, want one event of %s", f.events, tc.next)
			}
			if _, err := re.Run.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			rec := readRecord(t, s.Dir(runID))
			if got := rec[len(rec)-1].Sequence; got != tc.next || len(rec) != 5 {
				t.Errorf("the record ends with %s after %d events, want %s after 5", got, len(rec), tc.next)
			}
		})
	}
}

// TestReopenMendsATornLastLine pins a last line the gateway did not finish: a whole
// event without its newline gets it, part of an event is cut off; the next event starts
// its own line, numbered after the record's highest whole event.
func TestReopenMendsATornLastLine(t *testing.T) {
	for name, tc := range map[string]struct {
		cut  func(line []byte) []byte
		kept bool
		next string
	}{
		"a whole event without its newline": {func(l []byte) []byte { return bytes.TrimSuffix(l, []byte("\n")) }, true, "0000000005"},
		"part of an event":                  {func(l []byte) []byte { return l[:len(l)/2] }, false, "0000000004"},
	} {
		t.Run(name, func(t *testing.T) {
			var reports []string
			s := New(Config{Dir: t.TempDir(), Report: func(l string) { reports = append(reports, l) }})
			runID := suspendedRun(t, s)
			file := filepath.Join(s.Dir(runID), sink.EventsFile)
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			lines := bytes.SplitAfter(b, []byte("\n"))[:4]
			head := slices.Concat(lines[0], lines[1], lines[2])
			if err := os.WriteFile(file, slices.Concat(head, tc.cut(lines[3])), 0o644); err != nil {
				t.Fatal(err)
			}
			re, err := s.Reopen(runID, nil)
			if err != nil {
				t.Fatal(err)
			}
			if want := map[bool]int{true: 4, false: 3}[tc.kept]; len(re.Record) != want {
				t.Errorf("%d whole events, want %d", len(re.Record), want)
			}
			if tc.kept != (len(reports) == 0) {
				t.Errorf("reports %q", reports)
			}
			re.Run.Accept([]event.Event{sessionEvent(runID, event.RunLog, map[string]any{})})
			re.Run.Close(context.Background())
			after, _ := os.ReadFile(file)
			before := head
			if tc.kept {
				before = slices.Concat(head, lines[3])
			}
			rest, ok := bytes.CutPrefix(after, before)
			if !ok {
				t.Fatalf("the record was changed before its end:\n%s", after)
			}
			evs := parseLines(t, string(rest))
			if len(evs) != 1 || evs[0].Sequence != tc.next || !strings.HasSuffix(string(rest), "\n") {
				t.Errorf("the record ends %q, want one event of %s", rest, tc.next)
			}
		})
	}
}

// TestReopenSeesEveryID pins the ids of a reopened run: every id of the record counts
// as numbered, the session's and the gateway's, so a batch the session sends again is
// not numbered twice.
func TestReopenSeesEveryID(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	runID := event.NewRunID()
	r, _ := s.Open(runID)
	r.Registered(map[string]any{})
	r.MarkAnswered()
	batch := []event.Event{
		sessionEvent(runID, event.RunStarted, map[string]any{}),
		sessionEvent(runID, event.RunLog, map[string]any{}),
	}
	r.Accept(batch)
	r.Emit(event.RunEgress, egress("one.example"))
	r.Suspend(context.Background())
	registrationAccepted(t, r.Dir())
	re, err := s.Reopen(runID, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := readRecord(t, r.Dir())
	if len(re.Run.seen) != len(rec) {
		t.Errorf("%d ids seen, want %d", len(re.Run.seen), len(rec))
	}
	for _, ev := range rec {
		if !re.Run.seen[ev.ID] {
			t.Errorf("the id of %s is not seen", ev.Type)
		}
	}
	if n, err := re.Run.Accept(batch); n != 0 || err != nil {
		t.Errorf("a batch sent again: %d %v", n, err)
	}
	re.Run.Close(context.Background())
	if got := len(readRecord(t, r.Dir())); got != len(rec) {
		t.Errorf("the record has %d events, want %d", got, len(rec))
	}
}

// TestReopenLeavesARecordThatCannotGoOn pins the records that do not reopen: one with
// the run's final event, the session's or the gateway's; one the server said stop to;
// one another holds; one not marked answered; and a run open here. Each is an error and
// is left as it is.
func TestReopenLeavesARecordThatCannotGoOn(t *testing.T) {
	for name, tc := range map[string]struct {
		do   func(t *testing.T, s *Stream, runID string) func()
		want error
	}{
		"the session's run.exited": {func(t *testing.T, s *Stream, runID string) func() {
			appendFile(t, filepath.Join(s.Dir(runID), sink.EventsFile), `{"id":"x","type":"`+event.RunExited+`","sequence":"0000000005"}`+"\n")
			return nil
		}, ErrEnded},
		"the gateway's run.refused": {func(t *testing.T, s *Stream, runID string) func() {
			appendFile(t, filepath.Join(s.Dir(runID), sink.EventsFile), `{"id":"x","type":"`+event.RunRefused+`","sequence":"0000000005"}`+"\n")
			return nil
		}, ErrEnded},
		"stopped": {func(t *testing.T, s *Stream, runID string) func() {
			appendFile(t, filepath.Join(s.Dir(runID), sink.DeliveredFile), "stopped\n")
			return nil
		}, ErrStopped},
		"held by another": {func(t *testing.T, s *Stream, runID string) func() {
			unlock, err := lock(s.Dir(runID), lockFile)
			if err != nil {
				t.Fatal(err)
			}
			return unlock
		}, ErrRunning},
		"not answered": {func(t *testing.T, s *Stream, runID string) func() {
			os.Remove(filepath.Join(s.Dir(runID), answeredFile))
			return nil
		}, ErrNotAnswered},
		"open here": {func(t *testing.T, s *Stream, runID string) func() {
			if _, err := s.Reopen(runID, nil); err != nil {
				t.Fatal(err)
			}
			return nil
		}, ErrOpen},
	} {
		t.Run(name, func(t *testing.T) {
			s := New(Config{Dir: t.TempDir()})
			runID := suspendedRun(t, s)
			dir := s.Dir(runID)
			if err := os.MkdirAll(filepath.Join(dir, sink.UndeliveredDir), 0o755); err != nil {
				t.Fatal(err)
			}
			if done := tc.do(t, s, runID); done != nil {
				defer done()
			}
			before, _ := os.ReadFile(filepath.Join(dir, sink.EventsFile))
			if _, err := s.Reopen(runID, nil); !errors.Is(err, tc.want) {
				t.Fatalf("reopen: %v, want %v", err, tc.want)
			}
			if after, _ := os.ReadFile(filepath.Join(dir, sink.EventsFile)); !bytes.Equal(before, after) {
				t.Errorf("the record changed:\n%s", after)
			}
			if tc.want != ErrOpen {
				if _, err := os.Stat(filepath.Join(dir, sink.UndeliveredDir)); err != nil {
					t.Errorf("undelivered/ is gone: %v", err)
				}
				if s.Run(runID) != nil {
					t.Error("the run is open")
				}
			}
			if tc.want != ErrRunning && tc.want != ErrOpen {
				unlock, err := lock(dir, lockFile)
				if err != nil {
					t.Fatalf("the lock is held: %v", err)
				}
				unlock()
			}
		})
	}
	if _, err := New(Config{Dir: t.TempDir()}).Reopen(event.NewRunID(), nil); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no record: %v", err)
	}
}

// TestReopenOwesWhatTheServerDidNotAccept pins the owed lines: every event of the
// record that delivered.log has not accepted and the server wants, in order, never
// run.registered; undelivered/ is removed, since its batches are owed from the record.
func TestReopenOwesWhatTheServerDidNotAccept(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	runID := event.NewRunID()
	r, _ := s.Open(runID)
	r.Registered(map[string]any{})
	r.MarkAnswered()
	r.Accept([]event.Event{
		sessionEvent(runID, event.RunStarted, map[string]any{}),
		sessionEvent(runID, event.RunLog, map[string]any{}),
		sessionEvent(runID, event.RunHeartbeat, map[string]any{}),
		sessionEvent(runID, event.RunLog, map[string]any{}),
	})
	r.Emit(event.RunEgress, egress("one.example"))
	r.Suspend(context.Background())
	dir := r.Dir()
	// Accepted: run.started and the second log.
	if err := os.WriteFile(filepath.Join(dir, sink.DeliveredFile), []byte("registered 0000000001\nd1 0000000002 0000000005\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, sink.UndeliveredDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sink.UndeliveredDir, "d2.json"), []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
	re, err := s.Reopen(runID, func(typ string) bool { return typ != event.RunHeartbeat })
	if err != nil {
		t.Fatal(err)
	}
	defer re.Run.Close(context.Background())
	rec := readRecord(t, dir)
	var got []string
	for i, l := range re.Owed {
		got = append(got, l.Sequence+" "+strings.TrimPrefix(l.Type, event.Prefix))
		if l.ID == "" || !bytes.Contains(l.Bytes, []byte(l.ID)) || bytes.HasSuffix(l.Bytes, []byte("\n")) {
			t.Errorf("owed %d: %+v", i, l)
		}
	}
	if want := []string{"0000000003 run.log", "0000000006 run.egress"}; !slices.Equal(got, want) {
		t.Errorf("owed %q, want %q", got, want)
	}
	if len(re.Record) != len(rec) || re.Record[0].Type != event.RunRegistered {
		t.Errorf("the record has %d events, want %d from run.registered", len(re.Record), len(rec))
	}
	if _, err := os.Stat(filepath.Join(dir, sink.UndeliveredDir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("undelivered/ is left: %v", err)
	}
}

// TestSuspendKeepsTheRunAndItsHeldEgress pins Suspend: no final event, the record's
// files kept, the sinks flushed within the close wait and the lock released; the
// run.egress that waits for run.started goes unnumbered to held.jsonl, mode 0600, and a
// reopen numbers it after run.started, then removes the file; a Hold that waits is
// numbered as Close numbers it.
func TestSuspendKeepsTheRunAndItsHeldEgress(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	runID := event.NewRunID()
	r, _ := s.Open(runID)
	r.Registered(map[string]any{})
	r.MarkAnswered()
	f := &fakeSink{undelivered: 2}
	r.Deliver(f)
	r.Emit(event.RunEgress, egress("one.example"))
	r.Accept([]event.Event{sessionEvent(runID, event.RunHeartbeat, map[string]any{})})
	emitAfter(r, appliedDigest("b"), egress("closed.example"))
	r.Emit(event.RunEgress, egress("two.example"))
	res, err := r.Suspend(context.Background())
	if err != nil || res.Undelivered != 2 {
		t.Fatalf("suspend: %+v %v", res, err)
	}
	if again, err := r.Suspend(context.Background()); err != nil || again != res {
		t.Errorf("a second suspend: %+v %v", again, err)
	}
	if again, err := r.Close(context.Background()); err != nil || again != res {
		t.Errorf("a close after the suspend: %+v %v", again, err)
	}
	if !f.closed || f.deadline <= CloseWait-time.Second || f.deadline > CloseWait {
		t.Errorf("the sink: closed %v, deadline %v", f.closed, f.deadline)
	}
	if s.Run(runID) != nil {
		t.Error("the run is still open")
	}
	dir := r.Dir()
	if got := hostsAndTypes(readRecord(t, dir)); got != "run.registered run.heartbeat" {
		t.Errorf("the record after the suspend: %s", got)
	}
	for _, name := range []string{answeredFile, sink.EventsFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	fi, err := os.Stat(filepath.Join(dir, heldFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("held.jsonl: %v %v", fi, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, heldFile))
	held := parseLines(t, string(b))
	if got := hostsAndTypes(held); got != "run.egress:one.example run.egress:closed.example run.egress:two.example" {
		t.Errorf("held.jsonl: %s", got)
	}
	for _, ev := range held {
		if ev.Sequence != "" {
			t.Errorf("a held event is numbered %s", ev.Sequence)
		}
	}
	registrationAccepted(t, dir)
	re, err := s.Reopen(runID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, heldFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("held.jsonl is left: %v", err)
	}
	re.Run.Accept([]event.Event{
		sessionEvent(runID, event.RunStarted, map[string]any{}),
		sessionEvent(runID, event.RunLog, map[string]any{}),
	})
	re.Run.Close(context.Background())
	rec := readRecord(t, dir)
	contiguous(t, runID, rec)
	want := "run.registered run.heartbeat run.started run.egress:one.example run.egress:closed.example run.egress:two.example run.log"
	if got := hostsAndTypes(rec); got != want {
		t.Errorf("the record:\n got %s\nwant %s", got, want)
	}
	for i, ev := range held {
		if rec[3+i].ID != ev.ID {
			t.Errorf("held event %d has id %s, want %s", i, rec[3+i].ID, ev.ID)
		}
	}
}

// TestSuspendAfterStartNumbersTheWaitingEgress pins a started run: what a Hold keeps
// is numbered at the suspend, as at Close, and nothing goes to held.jsonl.
func TestSuspendAfterStartNumbersTheWaitingEgress(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	runID := event.NewRunID()
	r, _ := s.Open(runID)
	r.Accept([]event.Event{sessionEvent(runID, event.RunStarted, map[string]any{})})
	emitAfter(r, appliedDigest("b"), egress("closed.example"))
	r.Emit(event.RunEgress, egress("new.example"))
	if _, err := r.Suspend(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := hostsAndTypes(readRecord(t, r.Dir())); got != "run.started run.egress:closed.example run.egress:new.example" {
		t.Errorf("the record: %s", got)
	}
	if _, err := os.Stat(filepath.Join(r.Dir(), heldFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("held.jsonl: %v", err)
	}
}

// TestHeldEgressFollowsAGatewayStartAfterReopen pins a run.started the gateway numbered
// itself, whose held egress waits for the run.policy_applied that may follow it: the
// suspend keeps it so, and after the reopen it comes before the next event that is not
// a run.policy_applied, not at the close.
func TestHeldEgressFollowsAGatewayStartAfterReopen(t *testing.T) {
	s := New(Config{Dir: t.TempDir()})
	runID := event.NewRunID()
	r, _ := s.Open(runID)
	r.Registered(map[string]any{})
	r.MarkAnswered()
	r.Emit(event.RunEgress, egress("one.example"))
	r.Emit(event.RunStarted, map[string]any{})
	r.Suspend(context.Background())
	registrationAccepted(t, r.Dir())
	re, err := s.Reopen(runID, nil)
	if err != nil {
		t.Fatal(err)
	}
	re.Run.Accept([]event.Event{sessionEvent(runID, event.RunLog, map[string]any{})})
	re.Run.Close(context.Background())
	rec := readRecord(t, r.Dir())
	contiguous(t, runID, rec)
	if got := hostsAndTypes(rec); got != "run.registered run.started run.egress:one.example run.log" {
		t.Errorf("the record: %s", got)
	}
}

// TestReclaimAndDiscardRemoveTheKeptFiles pins the files the gateway keeps to reopen a
// run: Discard and Reclaim remove each of them, and nothing else beside the stream's.
func TestReclaimAndDiscardRemoveTheKeptFiles(t *testing.T) {
	write := func(t *testing.T, dir string) {
		t.Helper()
		for _, name := range keptFiles {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	s := New(Config{Dir: t.TempDir()})
	r, _ := s.Open(event.NewRunID())
	write(t, r.Dir())
	if err := r.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.Dir()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the discarded run's directory is left: %v", err)
	}

	runID := event.NewRunID()
	r, _ = s.Open(runID)
	r.Registered(map[string]any{})
	r.Close(context.Background())
	write(t, r.Dir())
	other := filepath.Join(r.Dir(), "other")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Reclaim(runID); !ok || err != nil {
		t.Fatalf("reclaim: %v %v", ok, err)
	}
	for _, name := range keptFiles {
		if _, err := os.Stat(filepath.Join(r.Dir(), name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is left: %v", name, err)
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("a file of another is gone: %v", err)
	}
	if want := []string{"request.json", "ca.pem", "ca.key", "given.jsonl", "joins.jsonl", "model-key-limit", "held.jsonl"}; !slices.Equal(keptFiles, want) {
		t.Errorf("the kept files %q, want %q", keptFiles, want)
	}
}
