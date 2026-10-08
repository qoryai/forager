package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/qoryai/runner/accesskey"
	"github.com/qoryai/runner/event"
	"github.com/qoryai/runner/server"
	"github.com/qoryai/runner/sink"
	"github.com/qoryai/runner/wall"
)

// ResendSpec is what sending a run's record again is given.
type ResendSpec struct {
	// Dir is the run directory, the one [Result.Dir] named.
	Dir string
	// Server is where the events go: the server the run had, or another. Its
	// configuration document is fetched first, as for a run, and every answer is
	// verified under its pin.
	Server *Server
	// AccessKey, InstanceID and InstanceName sign and name the requests, as
	// [Spec.AccessKey], [Spec.InstanceID] and [Spec.InstanceName] do for a run.
	AccessKey                *accesskey.Key
	InstanceID, InstanceName string
	// Wall, when it is a [wall.Reaper], is asked to remove what the run's wall left.
	Wall wall.Wall
	// ForagerVersion is reported in the deliveries' user agent.
	ForagerVersion string
	// Report receives one line per thing worth telling the user; nil means nothing is.
	Report func(string)
}

// ResendResult is what sending again came to.
type ResendResult struct {
	RunID string
	// Closed says the record had no run.exited and got one, with the reason
	// gateway_lost: the runner died before the runtime's exit was recorded.
	Closed bool
	// Reaped is how many containers and networks the run's wall had left.
	Reaped int
	// Sent is how many events the receiver accepted now, and Undelivered how many it
	// still has not; those are under the run directory's undelivered, as after a run.
	Sent        int
	Undelivered int
}

// Resend completes and delivers the record of a run that is over, for a caller whose
// runner died or whose receiver was away: the step a job runs last, whatever happened
// before it. The events file is the record of truth and the run directory says which
// of its events the server accepted, so Resend sends the rest, the ones the server's
// configuration wants, in order and in the run's own batches, until they are accepted
// or the context ends. A record with run.started and without run.exited gets one
// first, with the reason gateway_lost, and what the run's wall left is removed. A run
// whose runner still lives is [ErrRunning]; a server that said stop during the run, or
// closed it, is sent nothing.
func Resend(ctx context.Context, spec ResendSpec) (*ResendResult, error) {
	if spec.Report == nil {
		spec.Report = func(string) {}
	}
	if spec.ForagerVersion == "" {
		spec.ForagerVersion = "dev"
	}
	runID := filepath.Base(spec.Dir)
	if err := CheckRunID(runID); err != nil {
		return nil, err
	}
	if spec.Server == nil {
		return nil, errors.New("no server to send the record to")
	}
	b, _ := json.Marshal(spec.Server)
	cfg, err := server.Read("server", b)
	if err != nil {
		return nil, err
	}
	client := &server.Client{Config: cfg, Key: spec.AccessKey, InstanceID: spec.InstanceID, InstanceName: spec.InstanceName, UserAgent: accesskey.UserAgent(spec.ForagerVersion)}
	conf, _, err := client.Discover(ctx)
	if err != nil {
		return nil, err
	}
	file := filepath.Join(spec.Dir, sink.EventsFile)
	if _, err := os.Stat(file); err != nil {
		return nil, err
	}
	unlock, err := lock(spec.Dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	res := &ResendResult{RunID: runID}
	if r, ok := spec.Wall.(wall.Reaper); ok {
		if res.Reaped, err = r.Reap(ctx, runID); err != nil {
			spec.Report("removing what the wall left: " + err.Error())
		}
	}
	lines, err := record(file)
	if err != nil {
		return nil, err
	}
	if res.Closed, err = closeRecord(file, runID, &lines); err != nil {
		return nil, err
	}
	accepted, stopped, err := sink.Delivered(spec.Dir)
	if err != nil {
		return nil, err
	}
	if stopped {
		spec.Report("the server said stop during the run; nothing is sent")
		return res, nil
	}
	// What was spooled is in the events file as well, and is spooled again if the
	// server still does not take it.
	if err := os.RemoveAll(filepath.Join(spec.Dir, sink.UndeliveredDir)); err != nil {
		return nil, err
	}
	var owed []recorded
	for _, l := range lines {
		if conf.Wants(l.Type) && !accepted[l.Sequence] {
			owed = append(owed, l)
		}
	}
	posts := sink.NewServer(client, sink.Target{URL: conf.Events.URL, Types: conf.Events.Types}, spec.Dir, spec.Report, nil, nil)
	for _, l := range owed {
		if !posts.Resend(ctx, l.line, l.Sequence) {
			break
		}
	}
	posts.Close(ctx)
	res.Undelivered = len(owed)
	if after, _, err := sink.Delivered(spec.Dir); err == nil {
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

// record reads the events file. A last line the runner died in the middle of is cut
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
// on from its last event, and reports whether it did.
func closeRecord(file, runID string, lines *[]recorded) (bool, error) {
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
	ev := event.NewEmitterAfter(runID, seq, nil).Make(event.RunExited, map[string]any{"state": "failed", "exit_code": -1, "reason": "gateway_lost", "duration_ms": ran})
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
