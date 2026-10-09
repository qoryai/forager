package gateway

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestTheEndOfACheckIsTheSessionsRequest pins the end of a check of the run credential
// of a session's request that renews the run, a reload or a batch: the request counts
// as the session's at that moment, so a watch that comes after the check's end and
// before the request's touch finds the run heard from, though the starter took longer
// than the quiet time to answer; and the check is over however it ends, a panic of the
// ask among them.
func TestTheEndOfACheckIsTheSessionsRequest(t *testing.T) {
	var mu sync.Mutex
	var reports []string
	g := &Gateway{quiet: 200 * time.Millisecond, report: func(s string) {
		mu.Lock()
		defer mu.Unlock()
		reports = append(reports, s)
	}}
	lr := &linkRun{g: g, id: "run-1", ctx: context.Background(), cred: &runCred{active: func(context.Context, bool) error {
		time.Sleep(300 * time.Millisecond)
		return nil
	}}}
	lr.last = time.Now()
	if err := lr.checkActive(context.Background(), false, true); err != nil {
		t.Fatal(err)
	}
	// The watch comes between the check's end and the request's touch.
	lr.watch()
	lr.mu.Lock()
	timer, checks := lr.timer, lr.checks
	lr.mu.Unlock()
	if timer != nil {
		timer.Stop()
	}
	mu.Lock()
	if len(reports) != 0 {
		t.Errorf("the watch after the check reports %q", reports)
	}
	mu.Unlock()
	if checks != 0 {
		t.Errorf("%d checks after the check's end", checks)
	}

	lr.cred.active = func(context.Context, bool) error { panic("the ask") }
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the ask did not panic")
			}
		}()
		_ = lr.stillActive(context.Background())
	}()
	lr.mu.Lock()
	checks = lr.checks
	lr.mu.Unlock()
	if checks != 0 {
		t.Errorf("%d checks after an ask that panicked", checks)
	}
}
