package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/qoryai/forager/accesskey"
)

// The limits of the host calls of the link, the next-session request, the pushed-commits
// request, the GET findings request and the POST findings request. Forager reads no body
// of them: it checks the size and the media type alone.
const (
	// MaxNextSessionRequest is the largest body of a next-session request, 4 KiB. The
	// body of next-session-request.schema.json of qoryai/integrations, a session number,
	// a state and a reason code of at most 64 characters, is under 150 bytes.
	MaxNextSessionRequest = 4 << 10
	// MaxNextSessionAnswer is the largest body of a next-session answer, 1 MiB, the run
	// documents' limit ([accesskey.MaxRunAnswer]): the answer contains the next
	// session's inputs, which the run documents hold to 768 KiB.
	MaxNextSessionAnswer = accesskey.MaxRunAnswer
	// MaxPushedCommitsRequest is the largest body of a pushed-commits request, 64 KiB,
	// the size Qory Apiary reads.
	MaxPushedCommitsRequest = 64 << 10
	// MaxPushedCommitsAnswer is the largest body of a pushed-commits answer, 64 KiB, as
	// any answer that is not a document: Qory Apiary returns 204 with no body.
	MaxPushedCommitsAnswer = MaxRefusal
	// MaxFindingsAnswer is the largest body of a GET findings answer, 16 MiB, the largest
	// answer of the run API other than a file.
	MaxFindingsAnswer = MaxRunAPIAnswer
	// MaxPostFindingsRequest is the largest body of a POST findings request, 8 MiB, the
	// size Qory Apiary reads.
	MaxPostFindingsRequest = 8 << 20
	// MaxPostFindingsAnswer is the largest body of a POST findings answer, 64 KiB, as any
	// answer that is not a document.
	MaxPostFindingsAnswer = MaxRefusal
)

// HostCallTime is the most time one host call has at Qory Apiary, from the gateway's
// send to the end of the answer: the run API's time for any request but a file.
const HostCallTime = 60 * time.Second

// hostCallWait is the most time the session waits for the answer to one host call behind
// a separate gateway: up to 60 seconds for the body to arrive, up to 120 seconds for a
// reopen of the run (heldRun in gateway/remote.go), and [HostCallTime], 4 minutes in all.
// No time is left for the answer's write. The wait can end as the answer arrives, so read
// the findings before you send a POST findings again.
const hostCallWait = 4 * time.Minute

// NextSession sends the next-session request of the run runID, a POST of body to
// <runURL>/<runID>/next-session with Content-Type: application/json, and returns the
// answer's body. The gateway forwards body unread to Qory Apiary, POST
// <run.url>/<run_id>/next-session, signed with the gateway's access key, and returns
// Qory Apiary's 200 unread, at most [MaxNextSessionAnswer] bytes.
//
// It returns an error for a run URL that is not on the link and a run id of another
// form, with nothing sent; for a transport failure or no answer within 4 minutes; and
// for every answer other than a 2xx: a 410 is the end of the run, [Ended]; a coded
// refusal is an [*accesskey.Refusal] whose From is apiary for Qory Apiary's code, which
// the gateway passes on with its status and, in RetryAfter, the wait of its
// Retry-After; From is gateway for the gateway's; any other answer is a
// [*StatusError], the gateway's 503 with no body while it closes or reopens the run
// among them. A 2xx body over
// [MaxNextSessionAnswer] is an error too.
func (k *Link) NextSession(ctx context.Context, runURL, runID string, body []byte) ([]byte, error) {
	return k.hostCall(ctx, "the next-session request", runURL, runID, http.MethodPost, "/next-session", body, MaxNextSessionAnswer)
}

// PushedCommits sends the pushed-commits request of the run runID, a POST of body to
// <runURL>/<runID>/pushed-commits with Content-Type: application/json, and returns the
// answer's body, empty for Qory Apiary's 204. The gateway forwards body unread to Qory
// Apiary, POST <run.url>/<run_id>/pushed-commits, signed with the gateway's access key,
// and returns its 2xx unread, at most [MaxPushedCommitsAnswer] bytes. It returns an
// error in the cases [Link.NextSession] lists.
func (k *Link) PushedCommits(ctx context.Context, runURL, runID string, body []byte) ([]byte, error) {
	return k.hostCall(ctx, "the pushed-commits request", runURL, runID, http.MethodPost, "/pushed-commits", body, MaxPushedCommitsAnswer)
}

// Findings sends the GET findings request of the run runID, a GET of
// <runURL>/<runID>/findings with no body, and returns the answer's body. The gateway
// sends it to Qory Apiary, GET <run.url>/<run_id>/findings, signed with the gateway's
// access key, and returns Qory Apiary's 200 unread, at most [MaxFindingsAnswer] bytes. It
// returns an error in the cases [Link.NextSession] lists.
func (k *Link) Findings(ctx context.Context, runURL, runID string) ([]byte, error) {
	return k.hostCall(ctx, "the GET findings request", runURL, runID, http.MethodGet, "/findings", nil, MaxFindingsAnswer)
}

// PostFindings sends the POST findings request of the run runID, a POST of body to
// <runURL>/<runID>/findings with Content-Type: application/json, and returns the
// answer's body. The gateway forwards body unread to Qory Apiary, POST
// <run.url>/<run_id>/findings, signed with the gateway's access key, and returns its 2xx
// unread, at most [MaxPostFindingsAnswer] bytes. It returns an error in the cases
// [Link.NextSession] lists, and, with nothing sent, for a body over
// [MaxPostFindingsRequest].
//
// Qory Apiary has no key for a repeated request: a second request with the same raises
// makes new findings. Read the findings with [Link.Findings] before you send one again.
func (k *Link) PostFindings(ctx context.Context, runURL, runID string, body []byte) ([]byte, error) {
	if len(body) > MaxPostFindingsRequest {
		// The signature of a separate gateway's answer covers one byte more at most, so an
		// answer to a longer body fails the link's check.
		return nil, fmt.Errorf("Send a POST findings body of at most %d bytes: this one is longer, so nothing was sent.", MaxPostFindingsRequest)
	}
	return k.hostCall(ctx, "the POST findings request", runURL, runID, http.MethodPost, "/findings", body, MaxPostFindingsAnswer)
}

// hostCall sends what, a host call, a GET with no body or a POST of body to
// <runURL>/<runID> and path, and returns the 2xx answer's body, at most most bytes.
func (k *Link) hostCall(ctx context.Context, what, runURL, runID, method, path string, body []byte, most int) ([]byte, error) {
	if err := k.onLink("the run URL", runURL); err != nil {
		return nil, fmt.Errorf("%s: %w", k.name, accesskey.ShownError(err))
	}
	if !runIDShape.MatchString(runID) {
		return nil, fmt.Errorf("Pass the run id as a UUID in the canonical lower-case form: this one has another form.\n%s", what)
	}
	var set func(http.Header)
	if method == http.MethodPost {
		set = func(h http.Header) { h.Set("Content-Type", LinkContentType) }
		if body == nil {
			body = []byte{}
		}
	}
	u := strings.TrimSuffix(runURL, "/") + "/" + runID + path
	what += " " + accesskey.ShownValue(k.at(u), false)
	a, err := k.send(ctx, waiting(k.http, hostCallWait), method, u, body, most, set)
	var ke *GatewayKeyError
	if errors.As(err, &ke) {
		return nil, ke
	} else if err != nil {
		return nil, fmt.Errorf("%s: %w", what, accesskey.ShownError(err))
	}
	k.hand(a)
	if a.status < 200 || a.status > 299 {
		return nil, a.refusal(what)
	}
	if a.body == nil {
		// send drops a body over most, and reads an empty one as an empty slice.
		return nil, fmt.Errorf("Check the gateway and the control plane: the answer is over the call's limit.\n%s: more than %d bytes", what, most)
	}
	return a.body, nil
}
