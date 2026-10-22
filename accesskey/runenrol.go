package accesskey

import (
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/qoryai/forager/internal/runkeywire"
)

// RunAnswer is the server's 201 to a run code, [CodePrefixRun]: the run's id, its run
// key and the server's keys. The code's redemption makes no access key.
//
// A RunAnswer shows its run id and never its run key: fmt prints it as String returns
// it, whatever the verb; slog writes run_id alone through LogValue; and encoding/json
// writes run_id alone through MarshalJSON, also inside an exported field, a slice or a
// map that a JSON handler writes. One case is open: fmt calls no method of a value it
// reaches through a struct field that is not exported, so it can print the run key of
// a RunAnswer, or of a *RunAnswer, in such a field, as %+v of struct{ a RunAnswer }
// does. Keep a RunAnswer out of unexported fields of a value you print.
type RunAnswer struct {
	Version int    `json:"version"`
	RunID   string `json:"run_id"`
	// RunKey is the run's run key, verified under Pin and for RunID. The machine keeps
	// it in memory and passes it to the session as session.RemoteGateway.RunKey, and
	// writes it to no file and no environment variable.
	RunKey string `json:"run_key"`
	// ApiaryPublicKey are the server's keys as it lists them, current then next.
	ApiaryPublicKey Pin `json:"apiary_public_key"`
	// Pin are the keys of ApiaryPublicKey whose fingerprints are in the code: the
	// keys the run key's signature verified under.
	Pin Pin `json:"-"`
}

// String returns "run" and the run's id. It and Format have value receivers, so a
// RunAnswer printed by value shows the same and no more.
func (a RunAnswer) String() string { return "run " + a.RunID }

// GoString returns what String returns.
func (a RunAnswer) GoString() string { return a.String() }

// Format writes what String returns, whatever the verb.
func (a RunAnswer) Format(f fmt.State, _ rune) { io.WriteString(f, a.String()) }

// LogValue returns a group with run_id alone, so slog writes no run key.
func (a RunAnswer) LogValue() slog.Value { return slog.GroupValue(slog.String("run_id", a.RunID)) }

// MarshalJSON writes {"run_id": RunID} alone, for a log or a dump that encodes a
// RunAnswer as JSON: no run key, version or keys. A RunAnswer is read from the wire,
// never written to it, so no writer needs the other members.
func (a RunAnswer) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RunID string `json:"run_id"`
	}{a.RunID})
}

// runIDShape is a run's id: a UUID in the canonical lower-case form.
var runIDShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// runKeyShape is a run answer's run_key as enrolment.schema.json allows it, at most
// runkeywire.MaxLength characters.
var runKeyShape = regexp.MustCompile(`^qrk_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

// fixRunCode starts every error of a run answer that the server signed: the code is
// used, and a retry by the same key gets the same members.
const fixRunCode = "use another run code: "

// VerifyRunAnswer reads the server's answer to a request with a run code, as
// [EnrolmentRequest.VerifyAnswer] reads an access key's: the same statuses, the same
// refusals and the same signature, under EnrolAnswerDomain with the request's proof as
// the third line and under the listed key whose fingerprint is the code's first.
// A verified 201 is the run's answer: the run's id, its run key and the server's keys.
// Its Pin is then the entries whose fingerprints are in the code, and the run key must
// verify under the key of Pin whose fingerprint is the signer of the run key's payload,
// as the gateway verifies it, with run_id equal to the answer's run_id. A
// verified 201 that enrols an access key is a [*KindError]. A request whose code is not
// a run code is an error, and nothing is read: [EnrolmentRequest.VerifyAnswer] reads
// its answer. No error contains the run key.
func (r *EnrolmentRequest) VerifyRunAnswer(a Answer, signature string) (*RunAnswer, error) {
	if err := r.forRun(); err != nil {
		return nil, err
	}
	verified, unsigned, err := r.created(&a, signature)
	if err != nil {
		return nil, err
	}
	var ans RunAnswer
	if err := jsonv2.Unmarshal(a.Body, &ans, jsonv2.RejectUnknownMembers(true)); err != nil || !verified(ans.ApiaryPublicKey) {
		var key EnrolmentAnswer
		if jsonv2.Unmarshal(a.Body, &key, jsonv2.RejectUnknownMembers(true)) == nil && verified(key.ApiaryPublicKey) {
			return nil, &KindError{Kind: key.NodeKind, AccessKeyID: key.AccessKeyID, NodeID: key.NodeID, codeKind: kindRun}
		}
		return nil, unsigned
	}
	if err := ans.check(); err != nil {
		return nil, err
	}
	if ans.Pin, err = r.pinOf(ans.ApiaryPublicKey); err != nil {
		return nil, fmt.Errorf(fixRunCode+"the enrolment answer: %w", err)
	}
	runID, err := checkRunKey(ans.RunKey, ans.Pin)
	if err != nil {
		return nil, fmt.Errorf(fixRunCode+"the enrolment answer's run key is not valid: %w", err)
	}
	if runID != ans.RunID {
		return nil, fmt.Errorf(fixRunCode+"the enrolment answer's run key is for run %s, and its run_id is %s", runID, ans.RunID)
	}
	return &ans, nil
}

// check refuses a run answer the schema refuses. No error contains the run key.
func (a *RunAnswer) check() error {
	if a.Version != 1 {
		return fmt.Errorf("update Forager to read the enrolment answer: its version is %d, and this Forager reads version 1", a.Version)
	}
	if !runIDShape.MatchString(a.RunID) {
		return fmt.Errorf(fixRunCode+"the enrolment answer's run_id %s is not a UUID in lower case", shown(a.RunID))
	}
	if a.RunKey == "" {
		return errors.New(fixRunCode + "the enrolment answer has no run_key")
	}
	if len(a.RunKey) > runkeywire.MaxLength || !runKeyShape.MatchString(a.RunKey) {
		return fmt.Errorf(fixRunCode+"the enrolment answer's run_key is not qrk_ and two parts of base64url joined by a dot, at most %d characters", runkeywire.MaxLength)
	}
	if n := len(a.ApiaryPublicKey); n < 1 || n > 2 {
		return fmt.Errorf(fixRunCode+"the enrolment answer's apiary_public_key lists %d keys; one or two belong", n)
	}
	if err := a.ApiaryPublicKey.Check(); err != nil {
		return fmt.Errorf(fixRunCode+"the enrolment answer: %w", err)
	}
	return nil
}

// checkRunKey verifies a run key as package runkey's Verify does, under the key of pin
// whose fingerprint is the payload's signer, reads its payload against
// run-key.schema.json, and returns its run_id. Package runkey imports this package, so
// both read the run key through internal/runkeywire.
func checkRunKey(runKey string, pin Pin) (string, error) {
	p, err := runkeywire.Signed(runKey, func(signer string, m, sig []byte) (bool, bool) {
		for _, k := range pin.Keys() {
			if k.Fingerprint() == signer {
				return true, k.Verify(m, sig)
			}
		}
		return false, false
	})
	if err != nil {
		return "", err
	}
	read, err := runkeywire.ReadPayload(p, func(s string) (PublicKey, bool) {
		pub, err := ParsePublicKey(s)
		return pub, err == nil && pub.Check() == nil
	})
	if err != nil {
		return "", err
	}
	return read.RunID, nil
}

// PostRun sends a request with a run code to the server's enrolment endpoint and
// returns its verified answer, as [EnrolmentRequest.VerifyRunAnswer] reads it, with
// serverURL, hc and userAgent as [EnrolmentRequest.Post] takes them. A request whose
// code is not a run code is an error, and nothing is sent.
func (r *EnrolmentRequest) PostRun(ctx context.Context, hc *http.Client, serverURL, userAgent string) (*RunAnswer, error) {
	if err := r.forRun(); err != nil {
		return nil, err
	}
	a, sig, err := r.direct(ctx, hc, serverURL, userAgent)
	if err != nil {
		return nil, err
	}
	return r.VerifyRunAnswer(a, sig)
}

// PostRunVia sends a request with a run code to the server's enrolment endpoint
// through the gateway at viaURL, as [EnrolmentRequest.PostVia] sends an access key's,
// and returns its verified answer, as [EnrolmentRequest.VerifyRunAnswer] reads it. hc
// is required, as for PostVia. A request whose code is not a run code is an error, and
// nothing is sent.
func (r *EnrolmentRequest) PostRunVia(ctx context.Context, hc *http.Client, serverURL, viaURL, userAgent string) (*RunAnswer, error) {
	if err := r.forRun(); err != nil {
		return nil, err
	}
	a, sig, err := r.via(ctx, hc, serverURL, viaURL, userAgent)
	if err != nil {
		return nil, err
	}
	return r.VerifyRunAnswer(a, sig)
}
