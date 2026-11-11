package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/qoryai/forager/accesskey"
)

// MaxModelKeysReport is the largest body of a model keys report: 66 entries with names
// of 64 characters take about 19 KiB.
const MaxModelKeysReport = 32 << 10

// ModelKeyState is the state of one limit window of one model key of a run's key group,
// an entry of model-keys-report.schema.json's keys and of model-keys-answer.schema.json's.
// Times are RFC 3339 in UTC; ResetsAt and CooldownUntil are empty when the state has
// none, and Utilization nil.
type ModelKeyState struct {
	Credential    string `json:"credential"`
	Window        string `json:"window"`
	Status        string `json:"status"`
	ResetsAt      string `json:"resets_at,omitempty"`
	Utilization   *int   `json:"utilization,omitempty"`
	CooldownUntil string `json:"cooldown_until,omitempty"`
	Source        string `json:"source"`
	ObservedAt    string `json:"observed_at"`
}

// ModelKeysReport is a model keys report: the time it is sent, RFC 3339 in UTC with
// whole seconds, empty for the clock's now, and every window the gateway has of the
// run's key group.
type ModelKeysReport struct {
	Time string
	Keys []ModelKeyState
}

// modelKeysBody is a report's bytes: the version, the run's id, the time and the keys.
type modelKeysBody struct {
	Version int             `json:"version"`
	RunID   string          `json:"run_id"`
	Time    string          `json:"time"`
	Keys    []ModelKeyState `json:"keys"`
}

// ModelKeysAnswerError is an answer to a model keys report other than a signed 200: its
// status and whether its signature verified under the pin.
type ModelKeysAnswerError struct {
	// What is the request, Status the answer's, and Signed is true when the signature verified.
	What   string
	Status int
	Signed bool
}

func (e *ModelKeysAnswerError) Error() string {
	signed := "unsigned"
	if e.Signed {
		signed = "signed"
	}
	return fmt.Sprintf("%s: %s status %d", e.What, signed, e.Status)
}

// PostModelKeys posts the state of a run's key group, rep, to
// <runURL>/<runID>/model-keys, signed by the access key, and returns the answer's
// keys: for each key of the group, the newest state per window from every gateway. A
// body over [MaxModelKeysReport] is refused before anything is sent. A transport failure
// is an error with no answer; any answer other than a signed 200 is a
// [*ModelKeysAnswerError]; a signed 200 that fails the schema is a [*DocumentError].
func (c *Client) PostModelKeys(ctx context.Context, runURL, runID string, rep ModelKeysReport) ([]ModelKeyState, error) {
	if !runIDShape.MatchString(runID) {
		return nil, errors.New("the model keys report: the run id is not a UUID in the canonical lower-case form")
	}
	t := rep.Time
	if t == "" {
		t = RegistrationTime(time.Now())
	}
	keys := rep.Keys
	if keys == nil {
		keys = []ModelKeyState{}
	}
	body, err := json.Marshal(modelKeysBody{Version: 1, RunID: runID, Time: t, Keys: keys})
	if err != nil {
		return nil, err
	}
	if len(body) > MaxModelKeysReport {
		return nil, fmt.Errorf("the model keys report: %d bytes, over the %d a report may have", len(body), MaxModelKeysReport)
	}
	what := "model-keys " + accesskey.ShownValue(runURL+"/"+runID, false)
	a, err := c.send(ctx, http.MethodPost, runURL+"/"+runID+"/model-keys", body, MaxRefusal, func(h http.Header) {
		h.Set("Content-Type", RegistrationContentType)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, accesskey.ShownError(err))
	}
	if a.status != http.StatusOK || !a.signed {
		return nil, &ModelKeysAnswerError{What: what, Status: a.status, Signed: a.signed}
	}
	var ans struct {
		Keys []ModelKeyState `json:"keys"`
	}
	if err := readAnswer("model-keys-answer.schema.json", a.body, &ans); err != nil {
		return nil, &DocumentError{"model keys answer", runURL + "/" + runID + "/model-keys", err}
	}
	return ans.Keys, nil
}
