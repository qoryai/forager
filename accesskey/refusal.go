package accesskey

import (
	jsonv2 "encoding/json/v2"
	"regexp"
	"strconv"
	"strings"
)

// The refusal codes this package and Forager's client decide or read. The contract's
// table of refusal codes lists every code and when each applies.
const (
	// CodeUnauthorized is a 401: the access key is unknown or revoked, or the request
	// does not verify. Every 401 is unsigned.
	CodeUnauthorized = "unauthorized"
	// CodeAnswerUnsigned is an answer other than a 401 without a valid signature under
	// the pin.
	CodeAnswerUnsigned = "answer_unsigned"
	// CodeApiaryPublicKeyMissing is a server and no pin, decided before any request.
	CodeApiaryPublicKeyMissing = "apiary_public_key_missing"
	// CodeKeyInvalid is the server's 409 at enrolment: signed to a key already enrolled,
	// a revoked one included, and unsigned to a key the checks refuse or a proof that
	// does not verify under it, which a machine reads as answer_unsigned.
	CodeKeyInvalid = "key_invalid"
	// CodeKeyLimit is the server's signed 409 at enrolment to a node that already holds
	// two keys.
	CodeKeyLimit = "key_limit"
	// CodeRateLimited is the server's signed 429 at enrolment, per code: too many
	// attempts with one code.
	CodeRateLimited = "rate_limited"
	// CodeInstanceLimit is the server's signed 409 to a ping from a new instance beyond
	// its node's limit.
	CodeInstanceLimit = "instance_limit"
	// CodeRunClosed is the server's signed 410 to an event of a run it has closed.
	CodeRunClosed = "run_closed"
)

// Refusal is an answer, or a decision, that means no run or no key, with its code: the
// server's, read from the body of a signed answer, or one Forager or this package
// decides. Status is the answer's HTTP status, or 0 when no answer is concerned.
type Refusal struct {
	Code   string
	Status int
	// Names are the names the server's body lists, when it lists any.
	Names []string
	// Detail says more about where the refusal came from, a URL say; it never contains
	// a secret.
	Detail string
	// From says who refused, as the gateway's link reports it: [FromApiary] for a code
	// read from the server's signed answer and for the server's 401 at run start,
	// unsigned as every 401 is; [FromGateway] for one a gateway decides. It is empty for
	// a refusal Forager decides, answer_unsigned or apiary_public_key_missing say, and
	// for a session's own. Error does not show it.
	From string
	// Text, when not empty, is what Error returns, in place of the text made of the
	// members: a refusal on the gateway's link carries the text the refusal's own Error
	// returned, which the session sets here, so the user reads what they read when the
	// session decided it.
	Text string
}

// The values of [Refusal.From].
const (
	// FromGateway is a refusal a gateway decides.
	FromGateway = "gateway"
	// FromApiary is a refusal of Qory Apiary's, the server's: a code read from its
	// signed answer, or its 401 at run start; a gateway passes it on with its code and
	// status.
	FromApiary = "apiary"
)

// Error is Text when it is set; else the Detail, the code, the status and the names.
func (r *Refusal) Error() string {
	if r.Text != "" {
		return r.Text
	}
	var b strings.Builder
	if r.Detail != "" {
		b.WriteString(r.Detail + ": ")
	}
	b.WriteString(r.Code)
	if r.Status != 0 {
		b.WriteString(" (status " + strconv.Itoa(r.Status) + ")")
	}
	if len(r.Names) > 0 {
		b.WriteString(": " + strings.Join(r.Names, ", "))
	}
	return b.String()
}

// codeShape is a refusal code's form.
var codeShape = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ReadRefusal reads the code of a coded refusal, {"error": "<code>", "names": [...]},
// from the body of an answer whose signature verified. It returns nil when the body
// contains no such code: a code is read from a signed answer alone, so a caller
// verifies the answer first. Its From is [FromApiary].
func ReadRefusal(status int, body []byte) *Refusal {
	var doc struct {
		Error string   `json:"error"`
		Names []string `json:"names"`
	}
	if jsonv2.Unmarshal(body, &doc) != nil || !codeShape.MatchString(doc.Error) {
		return nil
	}
	return &Refusal{Code: doc.Error, Status: status, Names: doc.Names, From: FromApiary}
}
