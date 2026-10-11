package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Outcome is the run's starter's outcome, the body of run-outcome.schema.json: how the
// starter says the run ended. It sets the run's state at the server whenever it
// arrives, before or after the run's dev.qory.run.exited; the exit code and Forager's
// reason stay on record beside it. Each run gets one outcome: the same one repeated is
// accepted, and a different one is refused, outcome_given.
type Outcome struct {
	// State is succeeded, failed or cancelled. Empty leaves out both state and reason,
	// and the server reads the outcome as cancelled with the reason stopped, so the zero
	// Outcome needs no special case.
	State string `json:"state,omitempty"`
	// Reason is the starter's reason, a code: a lower-case letter, then lower-case
	// letters, digits and underscores, up to 64. The server drops one that is no code or
	// is one of Forager's reserved codes and keeps the outcome. A Reason without a State
	// is refused before anything is sent.
	Reason string `json:"reason,omitempty"`
	// Time is when the outcome was given, RFC 3339 in UTC with whole seconds. Empty,
	// PostOutcome sets it from the clock; a caller that tries again with the same Time
	// sends the same bytes, which the server answers with its stored answer.
	Time string `json:"time"`
}

// outcomeBody is an outcome's body: the version, then the outcome's members.
type outcomeBody struct {
	Version int `json:"version"`
	Outcome
}

// outcomeStates are the states an outcome may carry, dev.qory.run.exited's.
var outcomeStates = map[string]bool{"succeeded": true, "failed": true, "cancelled": true}

// body is the outcome's bytes. A Time left empty is the clock's now.
func (o Outcome) body() ([]byte, error) {
	if o.State != "" && !outcomeStates[o.State] {
		return nil, fmt.Errorf("the outcome: the state %q is not succeeded, failed or cancelled", o.State)
	}
	if o.State == "" && o.Reason != "" {
		return nil, errors.New("the outcome: a reason needs a state; with no state the outcome is cancelled with the reason stopped")
	}
	if o.Time == "" {
		o.Time = RegistrationTime(time.Now())
	}
	return json.Marshal(outcomeBody{Version: 1, Outcome: o})
}

// PostOutcome posts the run's starter's outcome o to <runURL>/<runID>/outcome, signed
// by the access key, which may be any active key of the node or node pool that
// registered the run, directly or through a gateway's relay with Via set. A State
// other than succeeded, failed and cancelled, and a Reason without a State, are refused
// before anything is sent; an empty State sends neither state nor reason, which the
// server reads as cancelled with the reason stopped. A Time left empty is the clock's
// now. The answer is a signed 200 with {"version": 1}. A 401 is unauthorized, an answer
// that does not verify answer_unsigned, and a signed refusal its code, each an
// [*accesskey.Refusal]: outcome_given for a different second outcome, and not_found for
// a run the node did not register or whose record is gone. A signed answer with no
// code is an [*AnswerError]. The error names outcome <runURL>/<runID> and the status.
func (c *Client) PostOutcome(ctx context.Context, runURL, runID string, o Outcome) error {
	if !runIDShape.MatchString(runID) {
		return errors.New("the outcome: the run id is not a UUID in the canonical lower-case form")
	}
	body, err := o.body()
	if err != nil {
		return err
	}
	what := "outcome " + runURL + "/" + runID
	a, err := c.send(ctx, http.MethodPost, runURL+"/"+runID+"/outcome", body, MaxRefusal, func(h http.Header) {
		h.Set("Content-Type", RegistrationContentType)
	})
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if a.status != http.StatusOK || !a.signed {
		return a.refusal(what)
	}
	var ans struct {
		Version int `json:"version"`
	}
	if err := readAnswer("run-outcome-answer.schema.json", a.body, &ans); err != nil {
		return &DocumentError{"outcome answer", runURL + "/" + runID + "/outcome", err}
	}
	return nil
}
