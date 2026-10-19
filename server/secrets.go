package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/sealed"
)

// SecretsRequest is the body of the secrets request, secrets-request.schema.json: the
// run's id, the digest of the run configuration whose credentials it fetches, which
// Forager computed from the document's bytes, the names of those credentials in the
// document's order, and the sender's clock in Unix seconds.
type SecretsRequest struct {
	Version          int      `json:"version"`
	RunID            string   `json:"run_id"`
	RunConfiguration string   `json:"run_configuration"`
	Credentials      []string `json:"credentials"`
	Timestamp        int64    `json:"timestamp"`
}

// Body is the request's bytes. It refuses a run id or a digest outside its form, and a
// list that is not 1 to [sealed.MaxCredentials] names, each once.
func (r SecretsRequest) Body() ([]byte, error) {
	switch {
	case !runIDShape.MatchString(r.RunID):
		return nil, errors.New("the secrets request: the run id is not a UUID in the canonical lower-case form")
	case !digestShape.MatchString(r.RunConfiguration):
		return nil, errors.New("the secrets request: the digest is not sha256= and 64 hex digits")
	case len(r.Credentials) < 1 || len(r.Credentials) > sealed.MaxCredentials:
		return nil, fmt.Errorf("the secrets request lists %d credentials, and a request lists 1 to %d", len(r.Credentials), sealed.MaxCredentials)
	case r.Timestamp < 0:
		return nil, errors.New("the secrets request: the timestamp is before 1970")
	}
	for i, name := range r.Credentials {
		if slices.Contains(r.Credentials[:i], name) {
			return nil, errors.New("the secrets request lists a credential twice")
		}
	}
	return json.Marshal(r)
}

// Secrets posts a secrets request, body, the bytes of a [SecretsRequest], to
// secretsURL, discovery's secrets.url, signed by the access key, and returns the
// answer's body, read up to [sealed.MaxAnswer], for [sealed.Open] to check and open.
// The answer is a signed 200; a body over the bound counts as unsigned. A 401 is
// unauthorized, an answer that does not verify answer_unsigned, and a signed refusal
// its code, secrets_not_allowed and run_configuration_superseded among them, each an
// [*accesskey.Refusal]; a signed answer without a code is an [*AnswerError]. The error
// names the URL, secrets <secretsURL>, and the status.
func (c *Client) Secrets(ctx context.Context, secretsURL string, body []byte) ([]byte, error) {
	what := "secrets " + accesskey.ShownValue(secretsURL, false)
	a, err := c.send(ctx, http.MethodPost, secretsURL, body, sealed.MaxAnswer, func(h http.Header) {
		h.Set("Content-Type", RegistrationContentType)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if a.status != http.StatusOK || !a.signed {
		return nil, a.refusal(what)
	}
	return a.body, nil
}
