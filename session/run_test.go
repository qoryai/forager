package session_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/session"
)

// runSpec is one run with one session: the open's spec and the session's. Its fields
// are both specs' fields.
type runSpec struct {
	session.OpenSpec
	session.SessionSpec
}

// opened is the open's spec of sp as a test opens it: the run directories in .qory/runs
// of the session's Dir when sp has none, and the reports on the session's Stderr, after
// "qory run: ", when it has no Report.
func opened(sp runSpec) session.OpenSpec {
	o := sp.OpenSpec
	if o.RunsDir == "" {
		dir := sp.Dir
		if dir == "" {
			dir, _ = os.Getwd()
		}
		o.RunsDir = filepath.Join(dir, ".qory", "runs")
	}
	if o.Report == nil {
		var stderr io.Writer = os.Stderr
		if sp.Stderr != nil {
			stderr = sp.Stderr
		}
		o.Report = func(line string) { fmt.Fprintln(stderr, "qory run:", line) }
	}
	return o
}

// run opens a run, joins one session and closes the run with the outcome qory gives
// it, and returns the session's result: the join's error, or the open's.
func run(ctx context.Context, sp runSpec) (*session.Result, error) {
	res, _, err := runClosed(ctx, sp)
	return res, err
}

// runClosed is run with the close's result too.
func runClosed(ctx context.Context, sp runSpec) (*session.Result, *session.Closed, error) {
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		return nil, nil, err
	}
	res, err := r.Join(ctx, sp.SessionSpec)
	closed, cerr := r.Close(ctx, outcomeOf(res, err))
	if err != nil {
		return nil, closed, err
	}
	if cerr != nil {
		return res, nil, cerr
	}
	return res, closed, nil
}

// outcomeOf is the outcome qory closes a run of one session with: failed with -1 for a
// session that did not start; for one that did, the session's state and exit code,
// with timeout and 124 at the time limit and interrupted at a stop from where it was
// started.
func outcomeOf(res *session.Result, err error) session.Outcome {
	switch {
	case err != nil || res == nil || res.RunClosed:
		return session.Outcome{State: event.StateFailed, ExitCode: -1}
	case res.Reason == event.ReasonTimeout:
		return session.Outcome{State: event.StateCancelled, Reason: event.ReasonTimeout, ExitCode: 124}
	case res.Reason == event.ReasonInterrupted:
		return session.Outcome{State: event.StateCancelled, Reason: event.ReasonInterrupted, ExitCode: res.ExitCode}
	}
	return session.Outcome{State: res.State, ExitCode: res.ExitCode}
}
