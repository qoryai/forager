package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/server"
)

// reportGap is the least time between the starts of two model keys reports of a run.
const reportGap = time.Second

// reportBackoff are the waits before each new try of a report that got a 429, a 5xx or
// no answer; the last one repeats until the run ends.
var reportBackoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 60 * time.Second}

// maxReportKeys is the most entries a report has, model-keys-report.schema.json's: 6
// keys of 11 windows.
const maxReportKeys = 66

// keyReporter sends the state of a run's key group to the control plane, signed POST
// <run.url>/<run_id>/model-keys (the contract's §The server, The model keys): one report
// in flight at most, at most one a second, each with every window of the group and the
// number of the session open when it was made, and takes the newer states of the answer
// into the group. Each session's start and end make a report, a boundary report.
type keyReporter struct {
	runID string
	g     *modelkey.Group
	send  func(ctx context.Context, rep server.ModelKeysReport) ([]server.ModelKeyState, error)
	// reported writes a line to the gateway's log, and logLine one dev.qory.run.log line
	// to the run's record.
	reported, logLine func(string)
	// runURL is the control plane's run endpoint, for the line of a 404.
	runURL string
	wake   chan struct{}
	// gap and backoff, when set, replace reportGap and reportBackoff; tests set them.
	gap     time.Duration
	backoff []time.Duration

	// mu guards session, pending, made and stopped, so a report is made with the
	// session and the boundary reports as one state.
	mu sync.Mutex
	// session is the number of the open session, 0 when none is open.
	session int
	// pending are the boundary reports not yet sent or dropped, oldest first.
	pending []boundaryReport
	// made counts the boundary reports made, so no two boundary reports have the same
	// id.
	made uint64
	// stopped is true once run returned after a 404 or a 410: no boundary report is
	// kept from then on.
	stopped bool
}

// boundaryReport is the report made at a session's start or end: the session's number,
// the keys and the keys out of use after a 401 as they were then, and the group's change
// count they cover. Each try sends them with a new time.
type boundaryReport struct {
	// id is 1 for the first boundary report of the run, 2 for the next, and so on.
	id           uint64
	session      int
	keys         []server.ModelKeyState
	unauthorized []server.UnauthorizedKey
	covers       uint64
}

// newKeyReporter makes the reporter of the group g of the run runID, and has g wake it
// at each change.
func newKeyReporter(runID, runURL string, g *modelkey.Group, send func(context.Context, server.ModelKeysReport) ([]server.ModelKeyState, error), reported, logLine func(string)) *keyReporter {
	k := &keyReporter{runID: runID, runURL: runURL, g: g, send: send, reported: reported, logLine: logLine, wake: make(chan struct{}, 1), gap: reportGap, backoff: reportBackoff}
	g.OnChange(k.poke)
	return k
}

// poke wakes the reporter for a report, and drops the signal when one is already
// waiting; changes in flight join the next report.
func (k *keyReporter) poke() {
	select {
	case k.wake <- struct{}{}:
	default:
	}
}

// opened opens session n, from the gateway's 200 to its join, and makes its start
// report.
func (k *keyReporter) opened(n int) { k.boundary(n, n) }

// closed closes session n, as the gateway numbers its dev.qory.session.exited, and makes
// its end report.
func (k *keyReporter) closed(n int) { k.boundary(n, 0) }

// boundary makes the boundary report of session n, with every window the group has
// now, also when nothing changed, and then sets open as the open session.
func (k *keyReporter) boundary(n, open int) {
	k.mu.Lock()
	k.session = open
	if k.stopped {
		k.mu.Unlock()
		return
	}
	ws, covers := k.g.Snapshot()
	k.made++
	k.pending = append(k.pending, boundaryReport{id: k.made, session: n, keys: entries(ws), unauthorized: k.unauthorized(), covers: covers})
	k.mu.Unlock()
	k.poke()
}

// stop keeps no more boundary reports, and drops those that wait.
func (k *keyReporter) stop() {
	k.mu.Lock()
	k.stopped, k.pending = true, nil
	k.mu.Unlock()
}

// next is the report to send at now, the group's change count it covers, and its id:
// the oldest boundary report, with its session, keys, keys out of use after a 401 and
// id, else the group's newest state with the open session and the id 0.
func (k *keyReporter) next(now time.Time) (rep server.ModelKeysReport, covers, id uint64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	t := server.RegistrationTime(now)
	if len(k.pending) > 0 {
		b := k.pending[0]
		return server.ModelKeysReport{Time: t, Session: b.session, Keys: b.keys, Unauthorized: b.unauthorized}, b.covers, b.id
	}
	ws, covers := k.g.Snapshot()
	return server.ModelKeysReport{Time: t, Session: k.session, Keys: entries(ws), Unauthorized: k.unauthorized()}, covers, 0
}

// done ends the boundary report id, sent or dropped; the id 0 ends none.
func (k *keyReporter) done(id uint64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if id != 0 && len(k.pending) > 0 && k.pending[0].id == id {
		k.pending = k.pending[1:]
	}
}

// waiting reports whether a boundary report waits.
func (k *keyReporter) waiting() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.pending) > 0
}

// lastWait is how long the last reports of a run, sent once after the run ends, may
// take.
const lastWait = 10 * time.Second

// run sends reports until ctx ends, or the control plane returns 410 or 404: each
// boundary report, then one report per burst of changes. A report covers every change
// up to the group's change count it was made at ([modelkey.Group.Snapshot]). A wake for
// changes that the last report sent or dropped covers sends nothing: a change that came
// during the gap or a backoff before that report goes in no second report. A boundary
// report goes also when nothing changed, and keeps its session, its windows and its
// keys out of use after a 401 across tries; one that waits takes the place of the next
// try of a report of changes, which it covers. When ctx ends while a report waits, in the gap, in a backoff or in flight,
// the waiting boundary reports and the newest state go once more ([keyReporter.last]).
func (k *keyReporter) run(ctx context.Context) {
	var last time.Time
	// sent is the change count the last report sent or dropped covers.
	var sent uint64
	for {
		if !k.waiting() && k.g.Changes() == sent {
			select {
			case <-ctx.Done():
				k.last(ctx, last, sent)
				return
			case <-k.wake:
				continue
			}
		}
		if !sleep(ctx, k.gap-time.Since(last)) {
			k.last(ctx, last, sent)
			return
		}
		// current is the id of the report the tries are of; try counts its tries, so a
		// new report starts the backoff again.
		var current uint64
		for try := 0; ; try++ {
			last = time.Now()
			rep, covers, id := k.next(last)
			if id != current {
				current, try = id, 0
			}
			keys, err := k.send(ctx, rep)
			if ctx.Err() != nil {
				if err == nil {
					sent = max(sent, covers)
					k.done(id)
				}
				k.last(ctx, last, sent)
				return
			}
			var ae *server.ModelKeysAnswerError
			errors.As(err, &ae)
			switch {
			case err == nil:
				k.g.Merge(windows(keys))
				sent = max(sent, covers)
				k.done(id)
			case ae != nil && ae.Status == http.StatusNotFound:
				k.stop()
				k.logLine(fmt.Sprintf("Upgrade the control plane to share model key cooldowns between runs: %s returned 404 for model-keys", accesskey.ShownValue(k.runURL, false)))
				return
			case ae != nil && ae.Signed && ae.Status == http.StatusGone:
				k.stop()
				return
			case ae != nil && (ae.Status == http.StatusUnauthorized || ae.Signed && (ae.Status == http.StatusBadRequest || ae.Status == http.StatusRequestEntityTooLarge)),
				ae == nil && !retried(err):
				k.reported(fmt.Sprintf("run %s: If this repeats, check the control plane: the model keys report was dropped: %v", k.runID, accesskey.ShownError(err)))
				sent = max(sent, covers)
				k.done(id)
			default:
				// A 429, a 5xx, another answer that did not verify, or none: the same
				// boundary report, or the newest state, goes again.
				if !sleep(ctx, k.backoff[min(try, len(k.backoff)-1)]) {
					k.last(ctx, last, sent)
					return
				}
				continue
			}
			break
		}
	}
}

// unauthorized is the report's list of the keys out of use after a 401
// ([modelkey.Group.Unauthorized]), nil for none.
func (k *keyReporter) unauthorized() []server.UnauthorizedKey {
	var out []server.UnauthorizedKey
	for _, u := range k.g.Unauthorized() {
		out = append(out, server.UnauthorizedKey{Credential: u.Credential, At: rfc3339(u.At)})
	}
	return out
}

// last sends, once each after the run's end and within [lastWait], the boundary reports
// that wait and then the newest state, when a change came after sent, so the control
// plane gets the last change and a report that waited in a backoff. Each starts the gap
// after the one before, the first the gap after prev. Their answers are not merged: the
// run sets no more keys. It writes one line to the gateway's log with the count of the
// reports that were not sent or not accepted.
func (k *keyReporter) last(ctx context.Context, prev time.Time, sent uint64) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lastWait)
	defer cancel()
	lost := 0
	defer func() {
		if lost > 0 {
			k.reported(fmt.Sprintf("run %s: If this repeats, check the control plane: %d model keys reports after the run's end were not sent or not accepted within %v", k.runID, lost, lastWait))
		}
	}()
	for {
		k.mu.Lock()
		waiting := len(k.pending)
		// A change after the last waiting boundary report's snapshot needs one more report.
		covered := sent
		if waiting > 0 {
			covered = max(covered, k.pending[waiting-1].covers)
		}
		k.mu.Unlock()
		changed := k.g.Changes() > covered
		if waiting == 0 && !changed {
			return
		}
		if !sleep(ctx, k.gap-time.Since(prev)) {
			lost += waiting
			if changed {
				lost++
			}
			return
		}
		prev = time.Now()
		rep, covers, id := k.next(prev)
		if _, err := k.send(ctx, rep); err != nil {
			lost++
		}
		if id == 0 {
			return
		}
		sent = max(sent, covers)
		k.done(id)
	}
}

// retried reports whether err, a failure with no answer the table lists, is one a new
// try may get past: every one but a signed 200 that fails the schema.
func retried(err error) bool {
	var de *server.DocumentError
	return !errors.As(err, &de)
}

// sleep waits d, and reports false when ctx ends first.
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// entries are the windows ws as a report's keys: at most [maxReportKeys], and as
// many as fit [server.MaxModelKeysReport] with the report's other members, its
// unauthorized among them.
func entries(ws []modelkey.Window) []server.ModelKeyState {
	out := make([]server.ModelKeyState, 0, len(ws))
	for _, w := range ws {
		out = append(out, state(w))
	}
	if len(out) > maxReportKeys {
		out = out[:maxReportKeys]
	}
	// The run id, the time, the session and the members around them take at most 129
	// bytes, and unauthorized 677: 6 entries of a name of 64 characters and a time.
	for len(out) > 0 {
		b, _ := json.Marshal(out)
		if len(b)+806 <= server.MaxModelKeysReport {
			break
		}
		out = out[:len(out)-1]
	}
	return out
}

// rfc3339 is t in UTC with whole seconds, empty for the zero time.
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return server.RegistrationTime(t)
}

// state is a window as a report's entry.
func state(w modelkey.Window) server.ModelKeyState {
	s := server.ModelKeyState{Credential: w.Credential, Window: w.Window, Status: w.Status, ResetsAt: rfc3339(w.ResetsAt),
		Source: w.Source, ObservedAt: rfc3339(w.ObservedAt)}
	if w.HasUtilization {
		u := w.Utilization
		s.Utilization = &u
	}
	if w.Status == modelkey.StatusRejected {
		s.CooldownUntil = rfc3339(w.CooldownUntil)
	}
	return s
}

// windows are an answer's entries as windows; an entry whose times do not read is left
// out.
func windows(keys []server.ModelKeyState) []modelkey.Window {
	var out []modelkey.Window
	for _, s := range keys {
		w := modelkey.Window{Credential: s.Credential, Window: s.Window, Status: s.Status, Source: s.Source}
		var err error
		if w.ObservedAt, err = time.Parse(time.RFC3339, s.ObservedAt); err != nil {
			continue
		}
		if s.ResetsAt != "" {
			if w.ResetsAt, err = time.Parse(time.RFC3339, s.ResetsAt); err != nil {
				continue
			}
		}
		if s.CooldownUntil != "" {
			if w.CooldownUntil, err = time.Parse(time.RFC3339, s.CooldownUntil); err != nil {
				continue
			}
		}
		if s.Utilization != nil {
			w.Utilization, w.HasUtilization = *s.Utilization, true
		}
		out = append(out, w)
	}
	return out
}
