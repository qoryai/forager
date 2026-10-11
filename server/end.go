package server

import (
	jsonv2 "encoding/json/v2"

	"github.com/qoryai/forager/event"
)

// ServerEnd is the end member of the server's signed 2xx to a batch,
// batch-answer.schema.json: the outcome the run's starter gave, its state, succeeded,
// failed or cancelled, and its reason, empty when the outcome has none.
type ServerEnd struct {
	State, Reason string
}

// endStates are the states an end member may carry, dev.qory.run.exited's.
var endStates = map[string]bool{"succeeded": true, "failed": true, "cancelled": true}

// ReadEnd reads the end member of the body of a signed 2xx to a batch, whose signature
// covers the body, so a caller reads it only once the answer verified. An empty body, a
// body that is not one JSON object, one without end, and an end whose state is not
// succeeded, failed or cancelled are no end: nil. A reason that is not a string, not a
// code of dev.qory.run.exited's pattern, or one of Forager's reserved codes is dropped
// alone, and the state kept. A member beside end is ignored.
func ReadEnd(body []byte) *ServerEnd {
	if len(body) == 0 {
		return nil
	}
	var doc struct {
		End *struct {
			State  string `json:"state"`
			Reason any    `json:"reason"`
		} `json:"end"`
	}
	if jsonv2.Unmarshal(body, &doc) != nil || doc.End == nil || !endStates[doc.End.State] {
		return nil
	}
	e := &ServerEnd{State: doc.End.State}
	if r, ok := doc.End.Reason.(string); ok && event.StarterReason(r) {
		e.Reason = r
	}
	return e
}
