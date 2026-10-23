package e2e

import (
	"context"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/session"
)

// runSpec is one run with one session: the open's spec and the session's, whether the
// run fetches its image before the join, (*session.Run).FetchImage, and the setup
// commands it runs outside before the join, (*session.Run).Setup, in the session's
// working folder, with onSetup, when set, given Setup's error.
type runSpec struct {
	session.OpenSpec
	session.SessionSpec
	fetch   bool
	setup   []session.SetupCommand
	onSetup func(error)
	// opened, when set, is called with the run once it opens, before anything else.
	opened func(*session.Run)
}

// runOne opens a run, fetches its image when sp.fetch is set, runs its setup commands
// outside when sp.setup has any, joins one session and closes the run with the
// session's outcome, as qory does for a run of one session, and returns the session's
// result: the join's error, the fetch's, or the open's. After a setup that failed it
// joins all the same, so the suite sees the join refused.
func runOne(ctx context.Context, sp runSpec) (*session.Result, error) {
	r, err := session.Open(ctx, sp.OpenSpec)
	if err != nil {
		return nil, err
	}
	if sp.opened != nil {
		sp.opened(r)
	}
	if sp.fetch {
		if err := r.FetchImage(ctx); err != nil {
			r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1})
			return nil, err
		}
	}
	if len(sp.setup) > 0 {
		err := r.Setup(ctx, session.SetupSpec{Dir: sp.SessionSpec.Dir, Commands: sp.setup})
		if sp.onSetup != nil {
			sp.onSetup(err)
		}
	}
	res, err := r.Join(ctx, sp.SessionSpec)
	out := session.Outcome{State: event.StateFailed, ExitCode: -1}
	switch {
	case err != nil || res.RunClosed:
	case res.Reason == event.ReasonTimeout:
		out = session.Outcome{State: event.StateCancelled, Reason: event.ReasonTimeout, ExitCode: 124}
	case res.Reason == event.ReasonInterrupted:
		out = session.Outcome{State: event.StateCancelled, Reason: event.ReasonInterrupted, ExitCode: res.ExitCode}
	default:
		out = session.Outcome{State: res.State, ExitCode: res.ExitCode}
	}
	if _, cerr := r.Close(ctx, out); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}
