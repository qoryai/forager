package e2e

import (
	"context"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/session"
)

// runSpec is one run with one session: the open's spec and the session's.
type runSpec struct {
	session.OpenSpec
	session.SessionSpec
}

// runOne opens a run, joins one session and closes the run with the session's outcome,
// as qory does for a run of one session, and returns the session's result: the join's
// error, or the open's.
func runOne(ctx context.Context, sp runSpec) (*session.Result, error) {
	r, err := session.Open(ctx, sp.OpenSpec)
	if err != nil {
		return nil, err
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
