package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/sink"
)

// ResendConfig is what sending one run's record again is given.
type ResendConfig struct {
	// Dir is the run's record directory; its name is the run id.
	Dir string
	// Sink, when not nil, opens the control-plane sink that posts the record, spooling
	// under the directory it is given: the caller has fetched the server's
	// configuration document first, as a run does. Nil completes the record and sends
	// nothing.
	Sink func(dir string) Sink
	// Wants is the server's filter, the configuration document's events; nil wants
	// every type.
	Wants func(typ string) bool
	// Report receives one line per thing worth telling the user; nil means nothing is.
	Report func(string)
	// Now is the clock of the run.exited Resend may add; nil means time.Now.
	Now func() time.Time
}

// ResendResult is what sending again came to.
type ResendResult struct {
	RunID string
	// Closed says the record had run.started and no run.exited and got one, with the
	// reason gateway_lost: the gateway was lost before the run's exit was recorded.
	Closed bool
	// Stopped says the server said stop during the run, a signed 410, so nothing was
	// sent.
	Stopped bool
	// RunClosed says the server closed the run now, a signed 410 run_closed: the
	// events stay in the record directory.
	RunClosed bool
	// Sent is how many events the server accepted now, and Undelivered how many it
	// still has not; those are under the record directory's undelivered/, as after a
	// run.
	Sent        int
	Undelivered int
	// Torn is how many lines of the record hold bytes that are no whole event: a write
	// the gateway did not finish. They are skipped and stay in the file, but for a last
	// line that holds no whole event, which is cut off when run.exited follows it.
	Torn int
}

// reportTorn is the report line of the lines of a record that hold bytes that are no
// whole event. Nil reports nothing: its wording waits for approval.
var reportTorn func(n int, file string) string

// Resend completes and delivers the record of one run whose gateway is gone, as the
// session's resend does today. A record still held, by an open run or by the run's
// session, is [ErrRunning], and is left as it is. A record with run.started and no
// run.exited gets one, numbered on from its last event, with the reason gateway_lost,
// and state failed and exit_code -1 for a session's run; a run a gateway opened, with
// no process, has neither. Then every event the server wants that no accepted batch
// contained is posted, in order and in the run's own batches, until the server accepts
// it or the context ends. A server that said stop during the run is sent nothing. A
// line of the record that holds bytes that are no whole event, a write the gateway did
// not finish, is skipped, and every event after it is read on (see [record]).
func Resend(ctx context.Context, cfg ResendConfig) (*ResendResult, error) {
	if cfg.Report == nil {
		cfg.Report = func(string) {}
	}
	if cfg.Wants == nil {
		cfg.Wants = func(string) bool { return true }
	}
	runID := filepath.Base(cfg.Dir)
	if err := checkRunID(runID); err != nil {
		return nil, err
	}
	file := filepath.Join(cfg.Dir, sink.EventsFile)
	if _, err := os.Stat(file); err != nil {
		return nil, err
	}
	unlock, err := lock(cfg.Dir, lockFile)
	if err != nil {
		return nil, err
	}
	defer unlock()
	unlockSession, err := lock(cfg.Dir, sessionLockFile)
	if err != nil {
		return nil, err
	}
	defer unlockSession()
	res := &ResendResult{RunID: runID}
	rec, err := record(file)
	if err != nil {
		return nil, err
	}
	if res.Torn = rec.torn; res.Torn > 0 && reportTorn != nil {
		cfg.Report(reportTorn(res.Torn, file))
	}
	if res.Closed, err = closeRecord(file, runID, rec, cfg.Now); err != nil {
		return nil, err
	}
	lines := rec.lines
	if cfg.Sink == nil {
		return res, nil
	}
	accepted, stopped, err := sink.Delivered(cfg.Dir)
	if err != nil {
		return nil, err
	}
	if stopped {
		cfg.Report("the server said stop during the run; nothing is sent")
		res.Stopped = true
		return res, nil
	}
	// What was spooled is in the events file as well, and is spooled again if the
	// server still does not take it.
	if err := os.RemoveAll(filepath.Join(cfg.Dir, sink.UndeliveredDir)); err != nil {
		return nil, err
	}
	var owed []recorded
	for _, l := range lines {
		if cfg.Wants(l.Type) && !accepted[l.Sequence] {
			owed = append(owed, l)
		}
	}
	posts := cfg.Sink(cfg.Dir)
	for _, l := range owed {
		if !posts.Resend(ctx, l.line, l.Sequence) {
			break
		}
	}
	posts.Close(ctx)
	res.RunClosed = posts.RunClosed()
	res.Undelivered = len(owed)
	if after, _, err := sink.Delivered(cfg.Dir); err == nil {
		for _, l := range owed {
			if after[l.Sequence] {
				res.Sent++
			}
		}
		res.Undelivered = len(owed) - res.Sent
	}
	return res, nil
}

// recorded is one event of events.jsonl and what Resend reads of it.
type recorded struct {
	Type     string `json:"type"`
	Sequence string `json:"sequence"`
	Time     string `json:"time"`
	// Data is what Resend reads of an event's data: run.started's opened_by.
	Data struct {
		OpenedBy string `json:"opened_by"`
	} `json:"data"`
	line []byte
	seq  uint64
}

// recordFile is what Resend reads of events.jsonl.
type recordFile struct {
	// lines are the whole events, in the file's order, which is the sequence's.
	lines []recorded
	// torn is how many lines hold bytes that are no whole event.
	torn int
	// size is the file's length, and whole its length up to and with its last newline:
	// past it is a last line the gateway did not finish, when there is one.
	size, whole int64
	// tailKept says that last line holds a whole event, which is kept.
	tailKept bool
}

// record reads the events file, and writes nothing. A whole event is a JSON object with
// a type and a sequence, a decimal number. A write the gateway did not finish, on a
// full disk, leaves part of a line, which is no event; the next write the gateway made
// goes on in the same line. So a line that is not one whole event is read for whole
// events after the bytes that are none, each '{' starting a try: those found are kept,
// the bytes that are none are skipped, and every line after it is read as any other. A
// blank line is skipped.
func record(file string) (*recordFile, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	rec := &recordFile{size: int64(len(b)), whole: int64(len(b))}
	for off := 0; off < len(b); {
		end := bytes.IndexByte(b[off:], '\n')
		last := end < 0
		if last {
			end = len(b)
			rec.whole = int64(off)
		} else {
			end += off
		}
		evs, torn := events(b[off:end])
		rec.lines = append(rec.lines, evs...)
		if torn {
			rec.torn++
		}
		if last {
			rec.tailKept = len(evs) > 0
		}
		off = end + 1
	}
	if len(rec.lines) == 0 {
		return nil, fmt.Errorf("%s holds no event", file)
	}
	return rec, nil
}

// events reads the whole events of one line of the record, and says whether the line
// holds bytes that are none.
func events(line []byte) (out []recorded, torn bool) {
	if len(bytes.TrimSpace(line)) == 0 {
		return nil, false
	}
	if l, ok := whole(line); ok {
		return []recorded{l}, false
	}
	for rest := line; len(rest) > 0; {
		dec := json.NewDecoder(bytes.NewReader(rest))
		var raw json.RawMessage
		if dec.Decode(&raw) == nil {
			if l, ok := whole(raw); ok {
				out = append(out, l)
				rest = bytes.TrimLeft(rest[dec.InputOffset():], " \t\r")
				continue
			}
		}
		torn = true
		i := bytes.IndexByte(rest[1:], '{')
		if i < 0 {
			break
		}
		rest = rest[i+1:]
	}
	return out, torn
}

// whole reads b as one whole event: a JSON object with a type and a sequence.
func whole(b []byte) (recorded, bool) {
	var l recorded
	if json.Unmarshal(b, &l) != nil || l.Type == "" {
		return recorded{}, false
	}
	seq, err := strconv.ParseUint(l.Sequence, 10, 64)
	if err != nil {
		return recorded{}, false
	}
	l.seq, l.line = seq, b
	return l, true
}

// closeRecord appends run.exited to the record of a started run that has none, numbered
// on from the highest sequence of its whole events, and reports whether it did. Its
// duration runs from run.started to that event. A last line the gateway did not finish
// is made a line first, so run.exited starts its own: one that holds a whole event gets
// its newline, and one that holds none is cut off the file, being no event. Nothing
// else of the file is changed.
func closeRecord(file, runID string, rec *recordFile, now func() time.Time) (bool, error) {
	var started time.Time
	begun, byGateway := false, false
	last := rec.lines[0]
	for _, l := range rec.lines {
		switch l.Type {
		case event.RunExited:
			return false, nil
		case event.RunStarted:
			begun = true
			byGateway = l.Data.OpenedBy == event.OpenedByGateway
			started, _ = time.Parse(time.RFC3339Nano, l.Time)
		}
		if l.seq > last.seq {
			last = l
		}
	}
	if !begun {
		// A run the server's ping refused, or one refused after it, never started, and
		// has no exit to record.
		return false, nil
	}
	var ran int64
	if end, err := time.Parse(time.RFC3339Nano, last.Time); err == nil && !started.IsZero() && end.After(started) {
		ran = end.Sub(started).Milliseconds()
	}
	data := map[string]any{"reason": event.ReasonGatewayLost, "duration_ms": ran}
	if !byGateway {
		// A session's run: no exit status was recorded. A run a gateway opened has no
		// process, and its run.exited neither.
		data["state"], data["exit_code"] = "failed", -1
	}
	ev := event.NewEmitterAfter(runID, last.seq, now).Make(event.RunExited, data)
	line, err := ev.JSON()
	if err != nil {
		return false, err
	}
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	write := append(line, '\n')
	if rec.size > rec.whole {
		if rec.tailKept {
			write = append([]byte{'\n'}, write...)
		} else if err := f.Truncate(rec.whole); err != nil {
			return false, err
		}
	}
	if _, err := f.Write(write); err != nil {
		return false, err
	}
	rec.lines = append(rec.lines, recorded{Type: ev.Type, Sequence: ev.Sequence, Time: ev.Time, line: line})
	return true, f.Sync()
}
