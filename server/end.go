package server

import (
	jsonv2 "encoding/json/v2"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
)

// ServerEnd is the end member of the server's signed 2xx to a batch,
// batch-answer.schema.json: the outcome the run's starter gave, its state, succeeded,
// failed or cancelled, and its reason, empty when the outcome has none.
type ServerEnd struct {
	State, Reason string
}

// batchAnswerSchema is batch-answer.schema.json, compiled once.
var batchAnswerSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	return contracts.Compile("batch-answer.schema.json")
})

// ReadEnd reads the end member of the body of a signed 2xx to a batch, whose signature
// covers the body, so a caller reads it only once the answer verified. The body is read
// against batch-answer.schema.json first: an empty body, one that is not one JSON
// object with each member name once, one the schema refuses, an end with an unknown
// state, a reason that is no code or a member beside state and reason among them, and
// one without end are no end: nil. The server drops a reason that is no code at the
// outcome, so a valid end carries a code or none. A reason that is one of Forager's
// reserved codes is dropped alone, and the state kept. A member beside end is ignored.
func ReadEnd(body []byte) *ServerEnd {
	if len(body) == 0 {
		return nil
	}
	var doc struct {
		End *struct {
			State  string `json:"state"`
			Reason string `json:"reason"`
		} `json:"end"`
	}
	if jsonv2.Unmarshal(body, &doc) != nil || doc.End == nil {
		return nil
	}
	schema, err := batchAnswerSchema()
	if err != nil {
		return nil
	}
	v, err := contracts.Decode("batch-answer.json", body)
	if err != nil || schema.Validate(v) != nil {
		return nil
	}
	e := &ServerEnd{State: doc.End.State}
	if !event.Reserved(doc.End.Reason) {
		e.Reason = doc.End.Reason
	}
	return e
}
