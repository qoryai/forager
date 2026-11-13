package gateway

import (
	"slices"
	"sync"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/run"
)

// writeLog numbers a run's dev.qory.run.target_write: each write's started, then its
// end once, and at the run's end a cut for each write still open ([writeLog.cutOpen]).
// Its lock orders a write's end against the run's end, so no state of a write follows
// the cut, and every started has its end before dev.qory.run.exited.
type writeLog struct {
	emit func(data map[string]any)
	mu   sync.Mutex
	// open are the writes that started and have not ended, in the order they started.
	open []proxy.Write
	// closed is set by cutOpen: nothing is numbered after it.
	closed bool
}

// observe numbers one state of a write the run's proxy hands over: a started, or the
// end of a write that is open. An end of a write that is not open, one cutOpen ended,
// is dropped.
func (l *writeLog) observe(w proxy.Write) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	if w.State == event.WriteStarted {
		l.open = append(l.open, w)
		l.emit(run.TargetWrite(w))
		return
	}
	i := slices.IndexFunc(l.open, func(o proxy.Write) bool { return o.RequestID == w.RequestID })
	if i < 0 {
		return
	}
	l.open = slices.Delete(l.open, i, i+1)
	l.emit(run.TargetWrite(w))
}

// cutOpen numbers a cut for each write still open, in the order they started, and
// numbers nothing after. A nil log has none.
func (l *writeLog) cutOpen() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	for _, w := range l.open {
		w.State = event.WriteCut
		l.emit(run.TargetWrite(w))
	}
	l.open = nil
}
