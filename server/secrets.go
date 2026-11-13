package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/sealed"
)

// SecretsRequest is the body of the secrets request, secrets-request.schema.json: the
// run's id, the digest of the run configuration whose credentials it fetches, which
// Forager computed from the document's bytes, the names of those credentials in the
// document's order, the model keys among them whose renewal follows a 401 of the model
// provider, in the same order, none for an empty list, and the sender's clock in Unix
// seconds.
type SecretsRequest struct {
	Version          int      `json:"version"`
	RunID            string   `json:"run_id"`
	RunConfiguration string   `json:"run_configuration"`
	Credentials      []string `json:"credentials"`
	Unauthorized     []string `json:"unauthorized,omitempty"`
	Timestamp        int64    `json:"timestamp"`
}

// Body is the request's bytes. It refuses a run id or a digest outside its form, a
// list that is not 1 to [sealed.MaxCredentials] names, each once, and an unauthorized
// list of more than [MaxUnauthorized] names, a name twice, a name that credentials does
// not list, or names out of the order of credentials.
func (r SecretsRequest) Body() ([]byte, error) {
	switch {
	case !runIDShape.MatchString(r.RunID):
		return nil, errors.New("report this bug in the gateway's secrets request to the Forager maintainers; the run id is not a UUID in the canonical lower-case form")
	case !digestShape.MatchString(r.RunConfiguration):
		return nil, errors.New("report this bug in the gateway's secrets request to the Forager maintainers; the digest is not sha256= and 64 hex digits")
	case len(r.Credentials) < 1 || len(r.Credentials) > sealed.MaxCredentials:
		return nil, fmt.Errorf("report this bug in the gateway's secrets request to the Forager maintainers; the request lists %d credentials, and a request lists 1 to %d", len(r.Credentials), sealed.MaxCredentials)
	case r.Timestamp < 0:
		return nil, errors.New("the secrets request: set this machine's clock to the right time; the timestamp is before 1970")
	}
	for i, name := range r.Credentials {
		if slices.Contains(r.Credentials[:i], name) {
			return nil, errors.New("report this bug in the gateway's secrets request to the Forager maintainers; the request lists a credential twice")
		}
	}
	if len(r.Unauthorized) > MaxUnauthorized {
		return nil, fmt.Errorf("report this bug in the gateway's secrets request to the Forager maintainers; the request lists %d unauthorized keys, and a request lists at most %d", len(r.Unauthorized), MaxUnauthorized)
	}
	last := -1
	for _, name := range r.Unauthorized {
		i := slices.Index(r.Credentials, name)
		if i <= last {
			return nil, errors.New("report this bug in the gateway's secrets request to the Forager maintainers; an unauthorized key is not in credentials, is listed twice, or is out of the order of credentials")
		}
		last = i
	}
	return json.Marshal(r)
}

// SecretsTimeout is how long the server has to answer a secrets request: Qory Apiary's
// refresh of a model key's value takes up to 15 seconds, and it may wait up to 10
// seconds for another refresh of the same key first. Other requests have [Timeout].
const SecretsTimeout = 30 * time.Second

// Secrets posts a secrets request, body, the bytes of a [SecretsRequest], to
// secretsURL, discovery's secrets.url, signed by the access key, and returns the
// answer's body, read up to [sealed.MaxAnswer], for [sealed.Open] to check and open.
// The server has [SecretsTimeout] to answer.
// The answer is a signed 200; a body over the bound counts as unsigned. A 401 is
// unauthorized, an answer that does not verify answer_unsigned, and a signed refusal
// its code, secrets_not_allowed and run_configuration_superseded among them, each an
// [*accesskey.Refusal]; a signed answer without a code is an [*AnswerError]. The error
// names the URL, secrets <secretsURL>, and the status.
func (c *Client) Secrets(ctx context.Context, secretsURL string, body []byte) ([]byte, error) {
	what := "secrets " + accesskey.ShownValue(secretsURL, false)
	a, err := c.sendWithin(ctx, SecretsTimeout, http.MethodPost, secretsURL, body, sealed.MaxAnswer, func(h http.Header) {
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
