package stream

import (
	"bufio"
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
}

// Resend completes and delivers the record of one run whose gateway is gone, as the
// session's resend does today. A record still held, by an open run or by the run's
// session, is [ErrRunning], and is left as it is. A record with run.started and no
// run.exited gets one, numbered on from its last event, with state failed, exit_code -1
// and the reason gateway_lost. Then every event the server wants that no accepted batch
// contained is posted, in order and in the run's own batches, until the server accepts
// it or the context ends. A server that said stop during the run is sent nothing.
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
	lines, err := record(file)
	if err != nil {
		return nil, err
	}
	if res.Closed, err = closeRecord(file, runID, &lines, cfg.Now); err != nil {
		return nil, err
	}
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

// recorded is one line of events.jsonl and what Resend reads of it.
type recorded struct {
	Type     string `json:"type"`
	Sequence string `json:"sequence"`
	Time     string `json:"time"`
	line     []byte
}

// record reads the events file. A last line the gateway died in the middle of is cut
// off the file: it is no event, and the next one must start a line.
func record(file string) ([]recorded, error) {
	f, err := os.OpenFile(file, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []recorded
	var good int64
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			break
		}
		var l recorded
		if json.Unmarshal(line, &l) != nil || l.Type == "" {
			break
		}
		good += int64(len(line))
		l.line = bytes.TrimSuffix(line, []byte("\n"))
		out = append(out, l)
	}
	if info, err := f.Stat(); err == nil && info.Size() > good {
		if err := f.Truncate(good); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s holds no event", file)
	}
	return out, nil
}

// closeRecord appends run.exited to the record of a started run that has none, numbered
// on from its last event, and reports whether it did. Its duration runs from
// run.started to the last event recorded.
func closeRecord(file, runID string, lines *[]recorded, now func() time.Time) (bool, error) {
	var started time.Time
	begun := false
	for _, l := range *lines {
		switch l.Type {
		case event.RunExited:
			return false, nil
		case event.RunStarted:
			begun = true
			started, _ = time.Parse(time.RFC3339Nano, l.Time)
		}
	}
	if !begun {
		// A run the server's ping refused, or one refused after it, never started, and
		// has no exit to record.
		return false, nil
	}
	last := (*lines)[len(*lines)-1]
	seq, err := strconv.ParseUint(last.Sequence, 10, 64)
	if err != nil {
		return false, fmt.Errorf("%s: the last event's sequence: %w", file, err)
	}
	var ran int64
	if end, err := time.Parse(time.RFC3339Nano, last.Time); err == nil && !started.IsZero() && end.After(started) {
		ran = end.Sub(started).Milliseconds()
	}
	ev := event.NewEmitterAfter(runID, seq, now).Make(event.RunExited, map[string]any{"state": "failed", "exit_code": -1, "reason": event.ReasonGatewayLost, "duration_ms": ran})
	line, err := ev.JSON()
	if err != nil {
		return false, err
	}
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return false, err
	}
	*lines = append(*lines, recorded{Type: ev.Type, Sequence: ev.Sequence, Time: ev.Time, line: line})
	return true, f.Sync()
}
