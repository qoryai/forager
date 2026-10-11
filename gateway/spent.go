package gateway

import (
	"time"
)

// keepEnded is how long the gateway keeps what a run on the one address left once it
// ended and its record is flushed: its run key's later requests get the 410 of its end
// meanwhile, and a 410 run_closed after.
const keepEnded = 15 * time.Minute

// spentRun is what a run on the one address leaves once it has ended and its record is
// flushed: how a later request of the run is answered, until it lapses.
type spentRun struct {
	end   runEnd
	until time.Time
}

// retire lets go of a run on the one address that has ended and its record flushed: the
// gateway holds no more of it than its [spentRun], for [keepEnded]; what it came to
// joins the gateway's delivery. The spent runs past their time go too, so they do not
// grow with the runs a gateway has served. A gateway that is closing keeps every run
// for Close.
func (g *Gateway) retire(lr *linkRun) {
	end, _ := lr.gone()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closing {
		return
	}
	now := time.Now()
	for id, sp := range g.spent {
		if !now.Before(sp.until) {
			delete(g.spent, id)
		}
	}
	delete(g.runs, lr.id)
	g.spent[lr.id] = spentRun{end: end, until: now.Add(keepEnded)}
	g.delivery.Undelivered += lr.result.Undelivered
	g.closedRun(lr)
	if lr.err != nil {
		g.spentErrs = append(g.spentErrs, lr.err)
	}
}

// spentOf is the spent run of the run id, when it is still kept.
func (g *Gateway) spentOf(runID string) (spentRun, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	sp, ok := g.spent[runID]
	if ok && !time.Now().Before(sp.until) {
		delete(g.spent, runID)
		return spentRun{}, false
	}
	return sp, ok
}

// closedRun adds a run that ended at the gateway before its session ended it to the
// gateway's delivery, when it is the first: who closed it, and the state and the reason
// of the gateway's dev.qory.run.exited of it. Called with g.mu held, or at Close.
func (g *Gateway) closedRun(lr *linkRun) {
	if !lr.closed || g.delivery.RunClosed {
		return
	}
	end, _ := lr.gone()
	g.delivery.RunClosed, g.delivery.ClosedReason, g.delivery.State, g.delivery.Reason = true, end.code, end.state, end.reason
}
