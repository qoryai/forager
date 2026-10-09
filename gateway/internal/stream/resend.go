package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	// NotOpened says the run never opened at the server, so nothing of it is sent, and
	// the record is left as it is: the record holds a ping and there is no
	// delivered.log, the server never having accepted the ping, or NoServer.
	NotOpened bool
	// NoServer says the record holds no ping and there is no delivered.log: the run had
	// no server, so it never opened at the one it is sent to. NotOpened is set too.
	NoServer bool
	// Torn is how many lines of the record hold bytes that are no whole event: a write
	// the gateway did not finish. They are skipped and stay in the file, but for a last
	// line that holds no whole event, which is cut off when run.exited follows it.
	Torn int
}

// reportTorn is the report line of the lines of a record that hold bytes that are no
// whole event. Nil reports nothing: its wording waits for approval.
var reportTorn func(n int, file string) string

// reportNotOpened is the report line of a record whose ping the server never accepted.
// Empty reports nothing: its wording waits for approval.
var reportNotOpened = ""

// reportNoServer is the report line of a record with no ping, of a run that had no
// server, sent to one. Empty reports nothing: its wording waits for approval.
var reportNoServer = ""

// Resend completes and delivers the record of one run whose gateway is gone, as the
// session's resend does today. A record still held, by an open run or by the run's
// session, is [ErrRunning], and is left as it is. A record with run.started and no
// run.exited gets one, numbered on from the higher of its highest whole event's sequence
// and the highest sequence delivered.log names, with the reason gateway_lost,
// and state failed and exit_code -1 for a session's run; a run a gateway opened, with
// no process, has neither. Then every event the server wants that no accepted batch
// contained is posted, in order and in the run's own batches, until the server accepts
// it or the context ends. A server that said stop during the run is sent nothing. A
// line of the record that holds bytes that are no whole event, a write the gateway did
// not finish, is skipped, and every event after it is read on (see [record]). A record
// that holds a ping and no delivered.log is of a run whose ping the server never
// accepted, which never opened: it is NotOpened, left as it is, and sent nothing. So is
// a record with no ping and no delivered.log, of a run that had no server, when it is
// sent to one; with no Sink it is completed, as any other.
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
	if res.NotOpened, res.NoServer, err = notOpened(cfg.Dir, rec); err != nil {
		return nil, err
	}
	if res.NoServer && cfg.Sink == nil {
		// Nothing is sent, and a run with no server is completed as any other.
		res.NotOpened, res.NoServer = false, false
	}
	if res.NotOpened {
		switch {
		case res.NoServer && reportNoServer != "":
			cfg.Report(reportNoServer)
		case !res.NoServer && reportNotOpened != "":
			cfg.Report(reportNotOpened)
		}
		return res, nil
	}
	accepted, stopped, err := sink.Delivered(cfg.Dir)
	if err != nil {
		return nil, err
	}
	if res.Closed, err = closeRecord(file, runID, rec, highest(accepted), cfg.Now); err != nil {
		return nil, err
	}
	lines := rec.lines
	if cfg.Sink == nil {
		return res, nil
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
	// lines are the whole events, in the file's order, each numbered after the one
	// before it: the sequence's order.
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
// a type and a sequence, a decimal number above the sequence of the whole event before
// it. The gateway numbers a run's events one after the other and writes each, a line,
// in that order, so a whole line of the record holds the next sequence, or a later one
// when a write before it left nothing at all. A write the gateway did not finish, on a
// full disk, leaves part of a line, which is no event and holds the next sequence; the
// next write the gateway finished goes on in the same line and ends it. So a line that
// is not one whole event holds at most one, the object that ends the line, which the
// gateway wrote whole: never an object inside the bytes before it, which may hold
// anything a session sent. It is kept when it decodes as one whole event from where it
// starts to the end of the line, and its sequence is at least two above the one before
// it, the bytes before it having taken one. A last line with no newline is kept only
// when the whole of it is one whole event, its newline alone lost. A blank line is
// skipped; every other line that is not kept, or holds bytes before what is, counts as
// torn.
func record(file string) (*recordFile, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	rec := &recordFile{size: int64(len(b)), whole: int64(len(b))}
	var prev uint64
	for off := 0; off < len(b); {
		end := bytes.IndexByte(b[off:], '\n')
		last := end < 0
		if last {
			end = len(b)
			rec.whole = int64(off)
		} else {
			end += off
		}
		l, kept, torn := readLine(b[off:end], last, prev)
		if kept {
			rec.lines = append(rec.lines, l)
			prev = l.seq
		}
		if torn {
			rec.torn++
		}
		if last {
			rec.tailKept = kept
		}
		off = end + 1
	}
	if len(rec.lines) == 0 {
		return nil, fmt.Errorf("%s holds no event", file)
	}
	return rec, nil
}

// readLine reads one line of the record, after the whole event of the sequence prev, as
// [record] says: the whole event it holds, if any, and whether it holds bytes that are
// none. final says the line has no newline.
func readLine(line []byte, final bool, prev uint64) (l recorded, kept, torn bool) {
	if len(bytes.TrimSpace(line)) == 0 {
		return recorded{}, false, false
	}
	if l, ok := whole(line); ok {
		if l.seq <= prev {
			return recorded{}, false, true
		}
		return l, true, false
	}
	if final {
		return recorded{}, false, true
	}
	start := lastObject(line)
	if start <= 0 {
		return recorded{}, false, true
	}
	l, ok := whole(line[start:])
	if !ok || l.seq < prev+2 {
		return recorded{}, false, true
	}
	return l, true, true
}

// lastObject is where the JSON object that ends the line starts, or -1: it reads back
// from the line's last '}', minding strings, to the '{' that opens it, each byte once.
// It does not check the JSON; [whole] does.
func lastObject(line []byte) int {
	i := len(bytes.TrimRight(line, " \t\r")) - 1
	if i < 0 || line[i] != '}' {
		return -1
	}
	depth, inString := 0, false
	for ; i >= 0; i-- {
		c := line[i]
		if inString {
			if c == '"' && !escaped(line, i) {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '}', ']':
			depth++
		case '{', '[':
			if depth--; depth == 0 {
				if c == '{' {
					return i
				}
				return -1
			}
		}
	}
	return -1
}

// escaped says the quote at i is escaped: an odd number of backslashes before it.
func escaped(line []byte, i int) bool {
	n := 0
	for j := i - 1; j >= 0 && line[j] == '\\'; j-- {
		n++
	}
	return n%2 == 1
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

// notOpened reports whether the record is of a run that never opened at a server, and
// whether that is since it had none. The gateway writes the ping to the record before
// it posts it, and only the sink creates delivered.log, with the ping's delivery its
// first line, once the server accepted the ping. So a delivered.log says the run
// opened, even without the ping's line, the gateway stopping before it wrote it, and
// even with no whole ping in the record, its line torn on a full disk. With no
// delivered.log, a record with a ping is of a run whose ping was never accepted, and
// one with no ping of a run that had no server.
func notOpened(dir string, rec *recordFile) (never, noServer bool, err error) {
	_, err = os.Stat(filepath.Join(dir, sink.DeliveredFile))
	if err == nil {
		return false, false, nil
	}
	if !os.IsNotExist(err) {
		return false, false, err
	}
	ping := slices.ContainsFunc(rec.lines, func(l recorded) bool { return l.Type == event.Ping })
	return true, !ping, nil
}

// highest is the highest of the sequences the server accepted, 0 for none. A line of
// delivered.log cut short holds a sequence lower than the one it was to hold.
func highest(accepted map[string]bool) uint64 {
	var top uint64
	for s := range accepted {
		if n, err := strconv.ParseUint(s, 10, 64); err == nil && n > top {
			top = n
		}
	}
	return top
}

// closeRecord appends run.exited to the record of a started run that has none, numbered
// on from the highest sequence of its whole events or of delivered, the highest the
// server accepted, and reports whether it did: an event whose line in the record the
// gateway did not finish may have reached the server whole. Its duration runs from
// run.started to the record's highest event. A last line the gateway did not finish
// is made a line first, so run.exited starts its own: one that holds a whole event gets
// its newline, and one that holds none is cut off the file, being no event. Nothing
// else of the file is changed.
func closeRecord(file, runID string, rec *recordFile, delivered uint64, now func() time.Time) (bool, error) {
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
	ev := event.NewEmitterAfter(runID, max(last.seq, delivered), now).Make(event.RunExited, data)
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
