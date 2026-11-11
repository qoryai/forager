package gateway

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/modelkey"
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
