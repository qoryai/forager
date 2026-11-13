package session

import (
	"context"
	"errors"
	"sync"

	"github.com/qoryai/forager/event"
)

// errModelKeyStop is the cause of the runtime's context ending after the gateway's
// answer to a batch had stop with one of [stopReasons].
var errModelKeyStop = errors.New("the gateway stopped the session for the run's model keys")

// stopReasons maps each reason of a stop in a batch's answer that stops the runtime to
// the state of the session's dev.qory.session.exited: paused for model_key_limit and
// model_key_switch, failed for model_key_unauthorized (contracts/forager/v1/README.md
// §The gateway's link, A stop in a batch's answer).
var stopReasons = map[string]string{
	event.ReasonModelKeyLimit:        event.StatePaused,
	event.ReasonModelKeySwitch:       event.StatePaused,
	event.ReasonModelKeyUnauthorized: event.StateFailed,
}

// stopReports is the line the run reports for a session stopped with each reason of
// [stopReasons].
var stopReports = map[string]string{
	event.ReasonModelKeyLimit:        "the runtime was stopped and the run pauses: every model key of the run is at its provider's limit or at its Use up to percentage, or the gateway could not send a refused request again with the next key (a request over 8 MiB, or a key whose credential does not cover the path)",
	event.ReasonModelKeySwitch:       "the runtime was stopped and the run pauses: the model provider returned 401 for the session's model key, and the run continues with another key of the run",
	event.ReasonModelKeyUnauthorized: "Renew or replace the run's model keys: the model provider returned 401 for every model key of the run, and no renewal of a key ended it. The runtime was stopped and the run fails",
}

// batchStop is the stop in the gateway's answer to a batch (contracts/forager/v1/README.md
// §The gateway's link, A stop in a batch's answer), for the session whose runtime runs.
// The sink's worker calls see; the session arms it as its runtime starts and reads it
// with end once the runtime exited. A stop while no runtime runs changes nothing.
type batchStop struct {
	mu     sync.Mutex
	stop   context.CancelCauseFunc
	reason string
}

// arm makes a stop end the runtime's context through stop, from now until end.
func (s *batchStop) arm(stop context.CancelCauseFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stop, s.reason = stop, ""
}

// see takes the reason of a stop in the answer to a batch: a reason of [stopReasons]
// stops the runtime that runs, as the run's time limit does, and the first such reason
// since arm is the one end returns. Any other reason is ignored, and so is a stop while
// no runtime runs.
func (s *batchStop) see(reason string) {
	if _, ok := stopReasons[reason]; !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stop == nil {
		return
	}
	if s.reason == "" {
		s.reason = reason
	}
	s.stop(errModelKeyStop)
}

// end returns the reason of the stop seen since arm, empty for none, and ignores every
// stop from now until the next arm.
func (s *batchStop) end() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	reason := s.reason
	s.stop, s.reason = nil, ""
	return reason
}
