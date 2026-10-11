package session

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/sink"
)

// ResendSpec is what sending a run's record again through its separate gateway is
// given.
type ResendSpec struct {
	// Gateway is the separate gateway the run spoke to, by the run's run key, which the
	// caller passes from QORY_RUN_KEY: the resend reaches it as the run did. The run key
	// is never written to the run directory, which a walled agent sees, so the resend
	// has it from the caller alone.
	Gateway RemoteGateway
	// Dir is the run directory on the session's machine, the one that holds the
	// session's record, session.jsonl; its name is the run id.
	Dir string
	// ForagerVersion is Forager's version, in the requests' user agent; empty means
	// "dev".
	ForagerVersion string
	// Report receives one line per thing worth telling the user; nil means nothing is.
	Report func(string)
}

// ResendResult is what sending again came to: what gateway.Delivery says of a
// gateway's resend, but Completed, since the session completes no record.
type ResendResult struct {
	// Sent is how many events the gateway accepted now, and Undelivered how many it
	// still has not; those are in session.jsonl, and under the run directory's
	// undelivered/ as after a run, except when the gateway ended the run.
	Sent        int
	Undelivered int
	// RunClosed says the run had ended at the gateway: nothing more was sent, and the
	// events stay in the run directory. ClosedReason is the code of the gateway's 410,
	// as [Result.ClosedReason] holds it; batch_refused when the gateway refused a batch.
	RunClosed    bool
	ClosedReason string
	// State and Reason are how the run ended, where that is known, as [Result] has them,
	// once something was sent: when the gateway had ended the run, the state and the
	// reason its 410 says, as the session records them; otherwise, and after a 410
	// run_closed, the state and the reason of the run.exited the record holds. Both are
	// empty when neither says or nothing was owed, and Reason when the end has none.
	State  string
	Reason string
	// NotOpened says the record holds no delivered.log: the run never opened at the
	// gateway, so nothing of it is sent, and the record is left as it is. A record
	// that owes nothing has a delivered.log, and NotOpened false.
	NotOpened bool
}

// Resend sends the gateway what a run's session did not deliver to it, from the run
// directory on the session's machine. That directory holds, behind a separate gateway,
// the session's record, session.jsonl, and what the gateway accepted of it,
// delivered.log: every event of the record the link takes that no accepted batch
// contained is posted again, in order and in batches cut as the session cuts them,
// until the gateway accepts it or ctx ends, and what it still has not accepted is under
// undelivered/ again, unless the gateway ended the run. The events the session records
// in its own record alone are not sent: the run.exited of a run the gateway ended,
// which delivered.log's stopped says, and a run.refused of a code the session does not
// decide. A record that owes nothing is sent nothing, no request is made, and the
// result is the zero ResendResult. A
// record with no delivered.log is of a run that never opened at the gateway, a run
// refused at its run request say: it is NotOpened, left as it is, and sent nothing,
// with no request.
//
// The record is never completed: a session that was lost leaves its run's end to the
// gateway, which writes it itself. A record still held by its session is [ErrRunning].
// A record that owes something is sent with the run's run key, Gateway's RunKey: without
// one the resend returns "resend <dir>: the run key is needed to send to its gateway;
// set QORY_RUN_KEY", one it cannot read is "QORY_RUN_KEY is not a run key: " and the
// part that is wrong, and one of another run is refused, before any request. A
// directory that holds the run's stream, events.jsonl, is a gateway's record, which
// gateway.Resend sends; [BehindGateway] tells the two apart. A run the gateway has
// ended, or holds no more after its session was lost, answers with its 410: RunClosed,
// and the events stay in the directory. The gateway's 401 unauthorized, at the
// discovery or at a batch, is a [*Refusal] with its code and From gateway; what was not
// accepted is under undelivered/.
func Resend(ctx context.Context, spec ResendSpec) (ResendResult, error) {
	if spec.ForagerVersion == "" {
		spec.ForagerVersion = "dev"
	}
	if spec.Report == nil {
		spec.Report = func(string) {}
	}
	if err := CheckRunID(filepath.Base(spec.Dir)); err != nil {
		return ResendResult{}, err
	}
	if _, err := os.Lstat(filepath.Join(spec.Dir, sink.EventsFile)); err == nil {
		return ResendResult{}, &fs.PathError{Op: "open", Path: filepath.Join(spec.Dir, sink.EventsFile), Err: syscall.EEXIST}
	}
	file := filepath.Join(spec.Dir, sink.SessionFile)
	if _, err := os.Stat(file); err != nil {
		return ResendResult{}, err
	}
	unlock, err := lock(spec.Dir)
	if err != nil {
		return ResendResult{}, err
	}
	defer unlock()
	if _, err := os.Stat(filepath.Join(spec.Dir, sink.DeliveredFile)); errors.Is(err, fs.ErrNotExist) {
		// The link's sink never started: the run never opened at the gateway.
		return ResendResult{NotOpened: true}, nil
	} else if err != nil {
		return ResendResult{}, err
	}
	lines, err := sessionRecord(file)
	if err != nil {
		return ResendResult{}, err
	}
	accepted, stopped, err := sink.Delivered(spec.Dir)
	if err != nil {
		return ResendResult{}, err
	}
	owed := owedOf(lines, accepted, stopped)
	if len(owed) == 0 {
		return ResendResult{}, nil
	}
	// The record owes the gateway: the run key reaches it.
	if spec.Gateway.RunKey == "" {
		return ResendResult{}, fmt.Errorf("resend %s: the run key is needed to send to its gateway; set QORY_RUN_KEY", spec.Dir)
	}
	key, err := spec.Gateway.key()
	if err != nil {
		return ResendResult{}, err
	}
	if runID := filepath.Base(spec.Dir); key.RunID != runID {
		return ResendResult{}, fmt.Errorf("resend %s: QORY_RUN_KEY names the run %s, not this one", spec.Dir, key.RunID)
	}
	// How the run ended, as far as the record says.
	state, reason := exitOf(lines)
	k, err := spec.Gateway.link(spec.ForagerVersion, nil)
	if err != nil {
		return ResendResult{}, err
	}
	defer k.Close()
	disc, err := k.Discover(ctx)
	if err != nil {
		return ResendResult{}, err
	}
	target := sink.Target{URL: disc.Events.URL, Types: disc.Events.Types}
	owed = slices.DeleteFunc(owed, func(l recordedLine) bool { return !target.Wants(l.Type) })
	if len(owed) == 0 {
		return ResendResult{}, nil
	}
	// What was spooled is in session.jsonl as well, and is spooled again if the
	// gateway still does not take it.
	if err := os.RemoveAll(filepath.Join(spec.Dir, sink.UndeliveredDir)); err != nil {
		return ResendResult{}, err
	}
	sendCtx, stop := context.WithCancel(ctx)
	defer stop()
	to := &refusing{to: k, stop: stop}
	var closedEnd server.RunEnd
	posts := sink.New(sink.Config{
		To: to, Target: target, Spool: spec.Dir, Report: spec.Report,
		OnEnded: func(e server.RunEnd) { closedEnd = e },
		Wait:    sink.LinkBatchWait, Link: true,
	})
	for _, l := range owed {
		if !posts.Resend(sendCtx, l.line, l.Sequence) {
			break
		}
	}
	// The worker is done once Close returns, so what it set is read after.
	posts.Close(sendCtx)
	if r := to.refused(); r != nil {
		return ResendResult{}, r
	}
	res := ResendResult{RunClosed: posts.RunClosed(), Undelivered: len(owed), State: state, Reason: reason}
	if res.RunClosed {
		res.ClosedReason = closedEnd.Code
		// The gateway's end of the run is how it ended, as the session records it; a
		// run_closed says only that it had ended otherwise, which the record says.
		if closedEnd.State != "" || closedEnd.Code != event.ReasonRunClosed {
			res.State, res.Reason = recorded(closedEnd)
		}
	}
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

// refusing is the link's deliveries during a resend, which stop at the gateway's 401
// unauthorized: sending again cannot change it.
type refusing struct {
	to   sink.Deliverer
	stop context.CancelFunc

	mu  sync.Mutex
	ref *Refusal
}

// Deliver posts one batch through the link, and stops the resend at the gateway's 401
// unauthorized; after it, nothing more is sent, and each delivery is that refusal.
func (r *refusing) Deliver(ctx context.Context, eventsURL, deliveryID string, body []byte, runDigest string) (server.Delivery, error) {
	if ref := r.refused(); ref != nil {
		return server.Delivery{}, ref
	}
	d, err := r.to.Deliver(ctx, eventsURL, deliveryID, body, runDigest)
	if err == nil && unauthorized(d) {
		r.mu.Lock()
		if r.ref == nil {
			r.ref = d.Refusal
		}
		r.mu.Unlock()
		r.stop()
	}
	return d, err
}

// refused is the gateway's 401 unauthorized, nil for none.
func (r *refusing) refused() *Refusal {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ref
}

// unauthorized reports whether the gateway refused a batch with its 401 unauthorized.
func unauthorized(d server.Delivery) bool {
	return d.Refusal != nil && d.Refusal.From == accesskey.FromGateway && d.Status == http.StatusUnauthorized && d.Code == accesskey.CodeUnauthorized
}

// recordedLine is one line of session.jsonl and what Resend reads of it.
type recordedLine struct {
	Type     string `json:"type"`
	Sequence string `json:"sequence"`
	ID       string `json:"id"`
	Data     struct {
		State  string          `json:"state"`
		Reason string          `json:"reason"`
		Code   string          `json:"code"`
		Status json.RawMessage `json:"status"`
	} `json:"data"`
	line []byte
}

// posted reports whether the line is one the session may have posted on the link: not
// a run.refused of a code the session does not decide or with a status, which the
// session records in its own record alone, nor a run.exited whose reason is the code of
// a gateway's 410, one of [server.EndCodes], which only the session's own record of a
// 410 holds. Its own record of a 410 with a reason outside Forager's own, or none, reads
// as a posted one does: delivered.log's stopped tells it apart ([owedOf]).
func (l recordedLine) posted() bool {
	switch l.Type {
	case event.RunExited:
		return !slices.Contains(server.EndCodes, l.Data.Reason)
	case event.RunRefused:
		return refusal.Decides(l.Data.Code) && l.Data.Status == nil
	}
	return true
}

// exitOf is the state and the reason of the record's run.exited, empty when it holds
// none.
func exitOf(lines []recordedLine) (state, reason string) {
	for _, l := range slices.Backward(lines) {
		if l.Type == event.RunExited {
			return l.Data.State, l.Data.Reason
		}
	}
	return "", ""
}

// sessionRecord reads session.jsonl, up to a last line the session died in the middle
// of, which is no event; the file is not changed.
func sessionRecord(file string) ([]recordedLine, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []recordedLine
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			break
		}
		var l recordedLine
		if json.Unmarshal(line, &l) != nil || l.Type == "" || l.ID == "" {
			break
		}
		l.line = bytes.TrimSuffix(line, []byte("\n"))
		out = append(out, l)
	}
	return out, nil
}

// owes reports whether the session's record in dir holds an event the link takes,
// target's, that no batch the gateway accepted contained, as [Resend] reads it: one it
// would send. A record it cannot read owes.
func owes(dir string, target sink.Target) bool {
	lines, err := sessionRecord(filepath.Join(dir, sink.SessionFile))
	if err != nil {
		return true
	}
	accepted, stopped, err := sink.Delivered(dir)
	if err != nil {
		return true
	}
	return slices.ContainsFunc(owedOf(lines, accepted, stopped), func(l recordedLine) bool { return target.Wants(l.Type) })
}

// owedOf is what of the record the gateway is still owed, as delivered.log says: every
// line the session posts that no accepted batch contained, but a run.exited once
// delivered.log says stopped. The gateway's answer that ended the run, a 410 to a batch
// or to a reload, is the one word stopped, written before the session records its own
// run.exited in its record alone; the gateway, which ended that run, wrote its
// run.exited itself.
func owedOf(lines []recordedLine, accepted map[string]bool, stopped bool) []recordedLine {
	var owed []recordedLine
	for _, l := range lines {
		if !accepted[l.Sequence] && l.posted() && (!stopped || l.Type != event.RunExited) {
			owed = append(owed, l)
		}
	}
	return owed
}

// BehindGateway reports whether the run directory dir holds a record a session made
// behind a separate gateway, which [Resend] sends: the session's record, session.jsonl,
// without the run's stream, events.jsonl, which a gateway on the session's machine
// writes beside it and gateway.Resend sends. A directory without session.jsonl is
// false. It reads nothing but the two names; an error other than a name that does not
// exist is returned.
func BehindGateway(dir string) (bool, error) {
	if _, err := os.Lstat(filepath.Join(dir, sink.SessionFile)); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if _, err := os.Lstat(filepath.Join(dir, sink.EventsFile)); errors.Is(err, fs.ErrNotExist) {
		return true, nil
	} else if err != nil {
		return false, err
	}
	return false, nil
}
