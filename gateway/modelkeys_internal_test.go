package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/server"
)

// fakeControl is the send of a key reporter: it records the time of each report and
// returns err, or a 200 with no key.
type fakeControl struct {
	mu    sync.Mutex
	times []time.Time
	err   error
	// cut is true for each report sent with a context that had ended.
	cut []bool
}

func (f *fakeControl) send(ctx context.Context, _ server.ModelKeysReport) ([]server.ModelKeyState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.times = append(f.times, time.Now())
	f.cut = append(f.cut, ctx.Err() != nil)
	return nil, f.err
}

func (f *fakeControl) sent() ([]time.Time, []bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.times...), append([]bool(nil), f.cut...)
}

// reporterOf is a reporter of a group of two keys that sends to f, with a gap of gap.
func reporterOf(f *fakeControl, gap time.Duration) (*keyReporter, *modelkey.Group) {
	g := modelkey.New([]modelkey.Key{{Name: "model", PauseFor: time.Hour}, {Name: "model-2", PauseFor: time.Hour}}, "model", nil)
	k := newKeyReporter("run", "https://control.example/v1/runs", g, f.send, func(string) {}, func(string) {})
	k.gap = gap
	return k, g
}

// TestABurstOfChangesSendsOneReportAGap pins the report rate: 200 changes within half a
// second send at most one report per gap, and the last change goes in a report.
func TestABurstOfChangesSendsOneReportAGap(t *testing.T) {
	f := &fakeControl{}
	k, g := reporterOf(f, 200*time.Millisecond)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { k.run(ctx); close(done) }()
	begin := time.Now()
	for i := range 200 {
		g.Answered("model", http.StatusOK, http.Header{"Anthropic-Ratelimit-Unified-5h-Status": {"allowed"}, "Anthropic-Ratelimit-Unified-5h-Utilization": {strconv.FormatFloat(float64(i%100)/100, 'f', 2, 64)}})
		time.Sleep(2500 * time.Microsecond)
	}
	time.Sleep(400 * time.Millisecond)
	cancel()
	<-done
	times, _ := f.sent()
	if limit := int(time.Since(begin)/(200*time.Millisecond)) + 1; len(times) == 0 || len(times) > limit {
		t.Errorf("%d reports in %v; want 1 to %d", len(times), time.Since(begin), limit)
	}
	for i := 1; i < len(times); i++ {
		if gap := times[i].Sub(times[i-1]); gap < 190*time.Millisecond {
			t.Errorf("reports %d and %d are %v apart; want at least the gap", i-1, i, gap)
		}
	}
}

// TestAReportedBurstIsNotSentAgain pins one report per burst of changes: changes that
// come during the gap after a report go in the next report alone, and after that
// report succeeds no report goes, at a later wake or at the run's end, while nothing
// changes.
func TestAReportedBurstIsNotSentAgain(t *testing.T) {
	f := &fakeControl{}
	k, g := reporterOf(f, 200*time.Millisecond)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { k.run(ctx); close(done) }()
	change := func(percent string) {
		g.Answered("model", http.StatusOK, http.Header{"Anthropic-Ratelimit-Unified-5h-Status": {"allowed"}, "Anthropic-Ratelimit-Unified-5h-Utilization": {percent}})
	}
	reports := func(n int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for times, _ := f.sent(); len(times) < n; times, _ = f.sent() {
			if time.Now().After(deadline) {
				t.Fatalf("%d reports; want %d", len(times), n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	change("0.10")
	reports(1)
	// Two changes within the gap after the first report: one report covers both.
	change("0.20")
	change("0.30")
	reports(2)
	// Two gaps on, nothing changed since the second report.
	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done
	if times, _ := f.sent(); len(times) != 2 {
		t.Errorf("%d reports; want 2, none after the burst's report", len(times))
	}
}

// TestAChangeDuringASendGoesInTheNextReport pins a change that comes while a report is
// in flight: it goes in one more report after the gap, and none follows that one.
func TestAChangeDuringASendGoesInTheNextReport(t *testing.T) {
	inFlight, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var reports []server.ModelKeysReport
	send := func(_ context.Context, rep server.ModelKeysReport) ([]server.ModelKeyState, error) {
		mu.Lock()
		reports = append(reports, rep)
		n := len(reports)
		mu.Unlock()
		if n == 1 {
			close(inFlight)
			<-release
		}
		return nil, nil
	}
	g := modelkey.New([]modelkey.Key{{Name: "model", PauseFor: time.Hour}}, "model", nil)
	k := newKeyReporter("run", "https://control.example/v1/runs", g, send, func(string) {}, func(string) {})
	k.gap = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { k.run(ctx); close(done) }()
	change := func(percent string) {
		g.Answered("model", http.StatusOK, http.Header{"Anthropic-Ratelimit-Unified-5h-Status": {"allowed"}, "Anthropic-Ratelimit-Unified-5h-Utilization": {percent}})
	}
	change("0.10")
	<-inFlight
	change("0.20")
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(reports)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 2 {
		t.Fatalf("%d reports; want 2", len(reports))
	}
	if keys := reports[1].Keys; len(keys) != 1 || keys[0].Utilization == nil || *keys[0].Utilization != 20 {
		t.Errorf("the second report's keys %+v; want the utilization 20", keys)
	}
}

// TestTheRunsEndSendsAWaitingReportOnce pins the last report: a report in a backoff
// when the run ends goes once more, with a context that has not ended; with no change
// waiting, the end sends nothing.
func TestTheRunsEndSendsAWaitingReportOnce(t *testing.T) {
	f := &fakeControl{err: errors.New("no answer")}
	k, g := reporterOf(f, 0)
	k.backoff = []time.Duration{time.Hour}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { k.run(ctx); close(done) }()
	g.Answered("model", http.StatusOK, http.Header{"Anthropic-Ratelimit-Unified-5h-Status": {"allowed"}})
	deadline := time.Now().Add(5 * time.Second)
	for times, _ := f.sent(); len(times) == 0 && time.Now().Before(deadline); times, _ = f.sent() {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if times, cut := f.sent(); len(times) != 2 || cut[1] {
		t.Errorf("%d reports, cut %v; want the first and one more after the end, not cut", len(times), cut)
	}

	idle := &fakeControl{}
	k, _ = reporterOf(idle, 0)
	ctx, cancel = context.WithCancel(t.Context())
	cancel()
	k.run(ctx)
	if times, _ := idle.sent(); len(times) != 0 {
		t.Errorf("%d reports at the end with no change; want none", len(times))
	}
}

// recorder is the send of a key reporter that records each report, and fails the tries
// fail returns true for with no answer.
type recorder struct {
	mu      sync.Mutex
	reports []server.ModelKeysReport
	at      []time.Time
	fail    func(n int, rep server.ModelKeysReport) bool
}

func (r *recorder) send(_ context.Context, rep server.ModelKeysReport) ([]server.ModelKeyState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, rep)
	r.at = append(r.at, time.Now())
	if r.fail != nil && r.fail(len(r.reports), rep) {
		return nil, errors.New("no answer")
	}
	return nil, nil
}

func (r *recorder) sent() []server.ModelKeysReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]server.ModelKeysReport(nil), r.reports...)
}

// wait waits until n reports are sent.
func (r *recorder) wait(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for len(r.sent()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d reports; want %d", len(r.sent()), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fiveHour is the utilization of the first entry for the five-hour window, -1 for none.
func fiveHour(rep server.ModelKeysReport) int {
	for _, s := range rep.Keys {
		if s.Window == "five_hour" && s.Utilization != nil {
			return *s.Utilization
		}
	}
	return -1
}

// startedReporter runs a reporter of one key that sends to r with a gap of gap, until
// the test's cleanup.
func startedReporter(t *testing.T, r *recorder, gap time.Duration) (*keyReporter, func(string), func()) {
	g := modelkey.New([]modelkey.Key{{Name: "model", PauseFor: time.Hour}}, "model", nil)
	k := newKeyReporter("run", "https://control.example/v1/runs", g, r.send, func(string) {}, func(string) {})
	k.gap = gap
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { k.run(ctx); close(done) }()
	stop := func() { cancel(); <-done }
	t.Cleanup(stop)
	change := func(fraction string) {
		g.Answered("model", http.StatusOK, http.Header{"Anthropic-Ratelimit-Unified-5h-Status": {"allowed"}, "Anthropic-Ratelimit-Unified-5h-Utilization": {fraction}})
	}
	return k, change, stop
}

// TestReportsHaveTheOpenSession pins the session of a report: none before the first
// session and after it; the session's number in its start report, which goes with no
// change, in each report made while it is open, and in its end report, which goes with
// no change too; and the gap between the starts of the reports.
func TestReportsHaveTheOpenSession(t *testing.T) {
	r := &recorder{}
	k, change, stop := startedReporter(t, r, 100*time.Millisecond)
	change("0.10")
	r.wait(t, 1)
	k.opened(1)
	r.wait(t, 2)
	change("0.20")
	r.wait(t, 3)
	k.closed(1)
	r.wait(t, 4)
	change("0.30")
	r.wait(t, 5)
	time.Sleep(300 * time.Millisecond)
	stop()
	reps := r.sent()
	want := []struct{ session, five int }{{0, 10}, {1, 10}, {1, 20}, {1, 20}, {0, 30}}
	if len(reps) != len(want) {
		t.Fatalf("%d reports %+v; want %d", len(reps), reps, len(want))
	}
	for i, w := range want {
		if reps[i].Session != w.session || fiveHour(reps[i]) != w.five {
			t.Errorf("report %d: session %d, utilization %d; want %d, %d", i, reps[i].Session, fiveHour(reps[i]), w.session, w.five)
		}
	}
	for i := 1; i < len(r.at); i++ {
		if gap := r.at[i].Sub(r.at[i-1]); gap < 95*time.Millisecond {
			t.Errorf("reports %d and %d are %v apart; want at least the gap", i-1, i, gap)
		}
	}
}

// TestABoundaryReportKeepsItsStateAcrossTries pins the tries of an end report: a try
// after the next session opened and the windows changed has the ended session's number
// and keys, with a new time, and the next session's start report follows it with the
// new keys; no report of changes goes between them or after.
func TestABoundaryReportKeepsItsStateAcrossTries(t *testing.T) {
	r := &recorder{}
	k, change, stop := startedReporter(t, r, 0)
	// Tries 1.1 seconds apart, so each try's time, in whole seconds, differs.
	k.backoff = []time.Duration{1100 * time.Millisecond}
	k.opened(1)
	r.wait(t, 1)
	change("0.10")
	r.wait(t, 2)
	r.mu.Lock()
	r.fail = func(n int, _ server.ModelKeysReport) bool { return n == 3 }
	r.mu.Unlock()
	k.closed(1)
	r.wait(t, 3)
	change("0.20")
	k.opened(2)
	r.wait(t, 5)
	time.Sleep(300 * time.Millisecond)
	stop()
	reps := r.sent()
	want := []struct{ session, five int }{{1, -1}, {1, 10}, {1, 10}, {1, 10}, {2, 20}}
	if len(reps) != len(want) {
		t.Fatalf("%d reports %+v; want %d", len(reps), reps, len(want))
	}
	for i, w := range want {
		if reps[i].Session != w.session || fiveHour(reps[i]) != w.five {
			t.Errorf("report %d: session %d, utilization %d; want %d, %d", i, reps[i].Session, fiveHour(reps[i]), w.session, w.five)
		}
	}
	if reps[2].Time == reps[3].Time {
		t.Errorf("the end report's two tries have the time %s; want a new time per try", reps[2].Time)
	}
}

// TestABoundaryReportTakesTheNextTry pins a report of changes in a backoff when a
// session opens: the next try is the start report, which covers the changes, and no
// report without a session follows it.
func TestABoundaryReportTakesTheNextTry(t *testing.T) {
	r := &recorder{fail: func(n int, _ server.ModelKeysReport) bool { return n == 1 }}
	k, change, stop := startedReporter(t, r, 0)
	k.backoff = []time.Duration{200 * time.Millisecond}
	change("0.10")
	r.wait(t, 1)
	k.opened(1)
	r.wait(t, 2)
	time.Sleep(300 * time.Millisecond)
	stop()
	reps := r.sent()
	if len(reps) != 2 || reps[0].Session != 0 || reps[1].Session != 1 || fiveHour(reps[1]) != 10 {
		t.Errorf("reports %+v; want the failed one without a session, then the start report of session 1 with utilization 10", reps)
	}
}

// TestTheRunsEndSendsAWaitingEndReport pins the end of a run within the gap after its
// session's end: the start and end reports that wait go once each, the gap apart, with
// the session's number, and nothing follows them.
func TestTheRunsEndSendsAWaitingEndReport(t *testing.T) {
	r := &recorder{}
	k, change, stop := startedReporter(t, r, 200*time.Millisecond)
	change("0.10")
	r.wait(t, 1)
	k.opened(1)
	k.closed(1)
	stop()
	reps := r.sent()
	if len(reps) != 3 || reps[1].Session != 1 || reps[2].Session != 1 || fiveHour(reps[2]) != 10 {
		t.Errorf("reports %+v; want one without a session, then the start and end reports of session 1", reps)
	}
	if gap := r.at[2].Sub(r.at[1]); gap < 195*time.Millisecond {
		t.Errorf("the start and end reports are %v apart; want at least the gap", gap)
	}
}

// TestNoReportAfterA404OrA410 pins the stop of the reports: after a 404, signed or not,
// or a signed 410, no report goes, and the starts and ends of later sessions keep no
// boundary report.
func TestNoReportAfterA404OrA410(t *testing.T) {
	for _, ae := range []*server.ModelKeysAnswerError{{Status: http.StatusNotFound}, {Status: http.StatusGone, Signed: true}} {
		r := &recorder{fail: func(int, server.ModelKeysReport) bool { return true }}
		g := modelkey.New([]modelkey.Key{{Name: "model", PauseFor: time.Hour}}, "model", nil)
		k := newKeyReporter("run", "https://control.example/v1/runs", g, func(ctx context.Context, rep server.ModelKeysReport) ([]server.ModelKeyState, error) {
			r.send(ctx, rep)
			return nil, ae
		}, func(string) {}, func(string) {})
		k.gap = 0
		done := make(chan struct{})
		go func() { k.run(t.Context()); close(done) }()
		k.opened(1)
		<-done
		for n := 1; n <= 50; n++ {
			k.closed(n)
			k.opened(n + 1)
		}
		k.mu.Lock()
		waiting := len(k.pending)
		k.mu.Unlock()
		if sent := len(r.sent()); sent != 1 || waiting != 0 {
			t.Errorf("after a %d: %d reports and %d waiting; want the one and none", ae.Status, sent, waiting)
		}
	}
}

// TestTheRunsEndLogsTheReportsThatDidNotGo pins the line of the reports after the run's
// end that the control plane did not accept: the start and end reports that wait go
// once each, and the gateway's log has one line with their count.
func TestTheRunsEndLogsTheReportsThatDidNotGo(t *testing.T) {
	r := &recorder{fail: func(int, server.ModelKeysReport) bool { return true }}
	g := modelkey.New([]modelkey.Key{{Name: "model", PauseFor: time.Hour}}, "model", nil)
	var mu sync.Mutex
	var lines []string
	k := newKeyReporter("run", "https://control.example/v1/runs", g, r.send, func(line string) { mu.Lock(); lines = append(lines, line); mu.Unlock() }, func(string) {})
	k.gap, k.backoff = 0, []time.Duration{time.Hour}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { k.run(ctx); close(done) }()
	k.opened(1)
	r.wait(t, 1)
	k.closed(1)
	cancel()
	<-done
	if reps := r.sent(); len(reps) != 3 || reps[1].Session != 1 || reps[2].Session != 1 {
		t.Errorf("reports %+v; want the start report, then the start and end reports once more", reps)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := "run run: If this repeats, check the control plane: 2 model keys reports after the run's end were not sent or not accepted within 10s"; len(lines) != 1 || lines[0] != want {
		t.Errorf("log %q; want %q", lines, want)
	}
}

// TestANewReportStartsTheBackoffAgain pins the backoff per report: a start report that
// takes the place of a report of changes in a backoff waits the first backoff after its
// first try, not the next one of the report it replaced.
func TestANewReportStartsTheBackoffAgain(t *testing.T) {
	r := &recorder{}
	k, change, _ := startedReporter(t, r, 0)
	k.backoff = []time.Duration{100 * time.Millisecond, time.Hour}
	r.mu.Lock()
	r.fail = func(n int, _ server.ModelKeysReport) bool {
		if n == 1 {
			// k.opened takes no lock of the recorder's.
			go k.opened(1)
		}
		return n <= 2
	}
	r.mu.Unlock()
	change("0.10")
	r.wait(t, 3)
	reps := r.sent()
	if reps[0].Session != 0 || reps[1].Session != 1 || reps[2].Session != 1 {
		t.Errorf("reports %+v; want one of changes, then the start report twice", reps)
	}
}

// TestASessionExitedAfterTheRunsEndMakesNoSecondEndReport pins one end report per
// session: a dev.qory.session.exited that a batch numbers after the run's end, which
// made the open join's end report, makes no second one; before the end it makes one.
func TestASessionExitedAfterTheRunsEndMakesNoSecondEndReport(t *testing.T) {
	for _, ended := range []bool{false, true} {
		g := modelkey.New([]modelkey.Key{{Name: "model", PauseFor: time.Hour}}, "model", nil)
		k := newKeyReporter("run", "https://control.example/v1/runs", g, (&recorder{}).send, func(string) {}, func(string) {})
		lr := &linkRun{id: "run", seen: map[string]bool{}, r: &run.Run{}, reporter: k, ended: ended,
			joins: []*join{{session: 1, accepted: true, started: true}}}
		lr.mu.Lock()
		lr.joined(event.Event{Type: event.SessionExited, Data: json.RawMessage(`{"session":1,"state":"succeeded","exit_code":0,"duration_ms":5}`)})
		lr.mu.Unlock()
		want := 1
		if ended {
			want = 0
		}
		if k.mu.Lock(); len(k.pending) != want {
			t.Errorf("run ended %v: %d end reports; want %d", ended, len(k.pending), want)
		}
		k.mu.Unlock()
	}
}
