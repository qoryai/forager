package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
// in flight at most, at most one a second, each with every window of the group, and
// takes the newer states of the answer into the group.
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

// lastWait is how long the last report of a run, sent once after the run ends, may take.
const lastWait = 10 * time.Second

// run sends reports until ctx ends, or the control plane returns 410 or 404. When ctx
// ends while a change waits for its report, in the gap, in a backoff or in flight, the
// newest state goes once more ([keyReporter.last]).
func (k *keyReporter) run(ctx context.Context) {
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			select {
			case <-k.wake:
				k.last(ctx)
			default:
			}
			return
		case <-k.wake:
		}
		if !sleep(ctx, k.gap-time.Since(last)) {
			k.last(ctx)
			return
		}
		for try := 0; ; try++ {
			last = time.Now()
			keys, err := k.send(ctx, k.report())
			if ctx.Err() != nil {
				k.last(ctx)
				return
			}
			var ae *server.ModelKeysAnswerError
			errors.As(err, &ae)
			switch {
			case err == nil:
				k.g.Merge(windows(keys))
			case ae != nil && ae.Status == http.StatusNotFound:
				k.logLine(fmt.Sprintf("Upgrade the control plane to share model key cooldowns between runs: %s returned 404 for model-keys", accesskey.ShownValue(k.runURL, false)))
				return
			case ae != nil && ae.Signed && ae.Status == http.StatusGone:
				return
			case ae != nil && (ae.Status == http.StatusUnauthorized || ae.Signed && (ae.Status == http.StatusBadRequest || ae.Status == http.StatusRequestEntityTooLarge)),
				ae == nil && !retried(err):
				k.reported(fmt.Sprintf("run %s: If this repeats, check the control plane: the model keys report was dropped: %v", k.runID, accesskey.ShownError(err)))
			default:
				// A 429, a 5xx, another answer that did not verify, or none: the newest
				// state goes again.
				if !sleep(ctx, k.backoff[min(try, len(k.backoff)-1)]) {
					k.last(ctx)
					return
				}
				continue
			}
			break
		}
	}
}

// report is a report of the group's newest state, at the clock's time: its windows and
// the keys out of use after a 401 ([modelkey.Group.Unauthorized]).
func (k *keyReporter) report() server.ModelKeysReport {
	var out []server.UnauthorizedKey
	for _, u := range k.g.Unauthorized() {
		out = append(out, server.UnauthorizedKey{Credential: u.Credential, At: rfc3339(u.At)})
	}
	return server.ModelKeysReport{Time: server.RegistrationTime(time.Now()), Keys: k.entries(), Unauthorized: out}
}

// last sends the newest state once after the run's end, within [lastWait], so the
// control plane gets the last change and a report that waited in a backoff. Its answer
// is not merged: the run sets no more keys.
func (k *keyReporter) last(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lastWait)
	defer cancel()
	k.send(ctx, k.report())
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

// entries are the group's windows as a report's keys: at most [maxReportKeys], and as
// many as fit [server.MaxModelKeysReport] with the report's other members, its
// unauthorized among them.
func (k *keyReporter) entries() []server.ModelKeyState {
	ws := k.g.Windows()
	out := make([]server.ModelKeyState, 0, len(ws))
	for _, w := range ws {
		out = append(out, state(w))
	}
	if len(out) > maxReportKeys {
		out = out[:maxReportKeys]
	}
	// The run id, the time and the members around them take less than 200 bytes, and
	// unauthorized less than 600: 6 entries of a name of 64 characters and a time.
	for len(out) > 0 {
		b, _ := json.Marshal(out)
		if len(b)+800 <= server.MaxModelKeysReport {
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
