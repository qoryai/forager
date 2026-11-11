package session

import (
	"context"
	"errors"
	"sync"

	"github.com/qoryai/forager/event"
)

// errModelKeyLimit is the cause of the runtime's context ending after the gateway's
// answer to a batch had stop with model_key_limit.
var errModelKeyLimit = errors.New("the gateway stopped the session at the model key limit")

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

// see takes the reason of a stop in the answer to a batch: model_key_limit stops the
// runtime that runs, as the run's time limit does. Any other reason is ignored, and so
// is a stop while no runtime runs.
func (s *batchStop) see(reason string) {
	if reason != event.ReasonModelKeyLimit {
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
	s.stop(errModelKeyLimit)
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
