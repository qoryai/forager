package gateway

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// keepEnded is how long the gateway keeps what a run on the one address left once it
// ended and its record is flushed: its run key's later requests get the 410 of its end
// meanwhile, and a 410 run_closed after.
const keepEnded = 15 * time.Minute

// keepLapsedErrs is how many errors of spent runs past their time the gateway keeps for
// Close, the first ones; it counts the others.
const keepLapsedErrs = 16

// spentRun is what a run on the one address leaves once it has ended and its record is
// flushed: how a later request of the run is answered, until it lapses, and the error
// its record's flush came to, for Close.
type spentRun struct {
	end   runEnd
	until time.Time
	err   error
}

// retire lets go of a run on the one address that has ended and its record flushed: the
// gateway holds no more of it than its [spentRun], for [keepEnded]; what it came to
// joins the gateway's delivery. The spent runs past their time go too, with their run
// ids among the used, so neither grows with the runs a gateway has served: a run id the
// gateway no longer keeps is refused by its record ([Gateway.lapse]). A gateway that is
// closing keeps every run for Close.
func (g *Gateway) retire(lr *linkRun) {
	end, _ := lr.gone()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closing {
		return
	}
	now := time.Now()
	g.lapse(now)
	delete(g.runs, lr.id)
	g.spent[lr.id] = spentRun{end: end, until: now.Add(keepEnded), err: lr.err}
	g.delivery.Undelivered += lr.result.Undelivered
	g.closedRun(lr)
}

// spentOf is the spent run of the run id, when it is still kept.
func (g *Gateway) spentOf(runID string) (spentRun, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lapse(time.Now())
	sp, ok := g.spent[runID]
	return sp, ok
}

// lapse lets go of the spent runs past their time as of now, and their run ids among
// the used. Their errors join the lapsed ones, in the order the runs were let go of:
// the first [keepLapsedErrs] are kept for Close, and the others counted. Called with
// g.mu held.
func (g *Gateway) lapse(now time.Time) {
	var lapsed []spentRun
	for id, sp := range g.spent {
		if !now.Before(sp.until) {
			delete(g.spent, id)
			delete(g.used, id)
			if sp.err != nil {
				lapsed = append(lapsed, sp)
			}
		}
	}
	slices.SortFunc(lapsed, func(a, b spentRun) int { return a.until.Compare(b.until) })
	for _, sp := range lapsed {
		if len(g.lapsedErrs) < keepLapsedErrs {
			g.lapsedErrs = append(g.lapsedErrs, sp.err)
		} else {
			g.lapsedMore++
		}
	}
}

// spentErrs are the errors the runs the gateway let go of came to, in the order it let
// go of them: the lapsed ones it kept, those of the spent runs it keeps, and a line for
// the lapsed ones it only counted. Called with g.mu held.
func (g *Gateway) spentErrs() []error {
	errs := slices.Clone(g.lapsedErrs)
	kept := make([]spentRun, 0, len(g.spent))
	for _, sp := range g.spent {
		if sp.err != nil {
			kept = append(kept, sp)
		}
	}
	slices.SortFunc(kept, func(a, b spentRun) int { return a.until.Compare(b.until) })
	for _, sp := range kept {
		errs = append(errs, sp.err)
	}
	switch {
	case g.lapsedMore == 1:
		errs = append(errs, errors.New("and 1 more run's record could not be closed"))
	case g.lapsedMore > 1:
		errs = append(errs, fmt.Errorf("and %d more runs' records could not be closed", g.lapsedMore))
	}
	return errs
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
