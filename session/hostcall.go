package session

import (
	"context"
	"errors"
	"fmt"
)

// ErrRunClosed is the error that the errors of [Run.NextSession], [Run.PushedCommits],
// [Run.Findings] and [Run.PostFindings] wrap once [Run.Close] began or the gateway closed
// the run; the call sent nothing.
// Test for it with [errors.Is]. A 410 from the gateway, for a run that ended there
// before or during the call, is not ErrRunClosed: [server.Ended] reports it.
var ErrRunClosed = errors.New("this run is closed")

// NextSession sends the run's next-session request with body, a JSON document of
// next-session-request.schema.json of qoryai/integrations, and returns the answer's
// body, a next-session-answer.schema.json document. Forager reads neither: the gateway
// forwards body to Qory Apiary, POST <run.url>/<run_id>/next-session, signed with its
// access key, and returns Qory Apiary's answer as it came. body is at most 4 KiB
// ([server.MaxNextSessionRequest]) and the answer at most 1 MiB.
//
// The request goes over the gateway's link, which no container reaches: call it from
// the host, at any time from [Open] to [Run.Close], from any goroutine, while a
// [Run.Join] runs too. It is sent once, and waits at most 4 minutes.
//
// It returns an error that wraps [ErrRunClosed], with nothing sent, once [Run.Close]
// began or the gateway closed the run, and an error with nothing sent for a run with no
// control plane. In an open run with no control plane, the error does not wrap
// [ErrRunClosed]. It returns an [*accesskey.Refusal] for a refusal: From is apiary for
// Qory Apiary's code, passed on with its status, such as 409 run_ended, with
// RetryAfter set from Qory Apiary's Retry-After of whole seconds, and gateway for
// the gateway's, such as 413 payload_too_large for a body over the limit or 502
// control_plane_unavailable when no valid answer came; a 410 is the end of the run at
// the gateway, which [server.Ended] reports. A 503 with no code, while the gateway
// closes or reopens the run, is a [*server.StatusError]: send the request again. A
// transport failure and no answer in time are errors too.
func (r *Run) NextSession(ctx context.Context, body []byte) ([]byte, error) {
	if err := r.hostCallAllowed("next-session"); err != nil {
		return nil, err
	}
	return r.link.NextSession(ctx, r.disc.Run.URL, r.id, body)
}

// PushedCommits sends the run's pushed-commits request with body, the JSON document
// Qory Apiary's run API takes at POST /v1/runs/<run_id>/pushed-commits, and returns the
// answer's body, empty for Qory Apiary's 204. Forager reads neither: the gateway
// forwards body to Qory Apiary, POST <run.url>/<run_id>/pushed-commits, signed with its
// access key. body is at most 64 KiB ([server.MaxPushedCommitsRequest]), and the
// answer at most 64 KiB.
//
// It goes over the gateway's link, as [Run.NextSession] does, and returns an error in
// the cases [Run.NextSession] lists: one that wraps [ErrRunClosed] once [Run.Close]
// began or the gateway closed the run.
func (r *Run) PushedCommits(ctx context.Context, body []byte) ([]byte, error) {
	if err := r.hostCallAllowed("pushed-commits"); err != nil {
		return nil, err
	}
	return r.link.PushedCommits(ctx, r.disc.Run.URL, r.id, body)
}

// Findings sends the run's GET findings request and returns the answer's body, the
// findings of the run's work item, as Qory Apiary returns them. Forager does not read it:
// the gateway sends Qory Apiary GET <run.url>/<run_id>/findings, signed with its access
// key. The answer is at most 16 MiB ([server.MaxFindingsAnswer]).
//
// It goes over the gateway's link, as [Run.NextSession] does, and returns an error in
// the cases [Run.NextSession] lists: one that wraps [ErrRunClosed] once [Run.Close]
// began or the gateway closed the run. A 429 rate_limited from the gateway is an answer
// past the gateway's memory budget: send the request again.
func (r *Run) Findings(ctx context.Context) ([]byte, error) {
	if err := r.hostCallAllowed("GET findings"); err != nil {
		return nil, err
	}
	return r.link.Findings(ctx, r.disc.Run.URL, r.id)
}

// PostFindings sends the run's POST findings request with body, the JSON document Qory
// Apiary's run API takes at POST /v1/runs/<run_id>/findings, and returns the answer's
// body. Forager reads neither: the gateway forwards body to Qory Apiary, POST
// <run.url>/<run_id>/findings, signed with its access key. body is at most 8 MiB
// ([server.MaxPostFindingsRequest]), and the answer at most 64 KiB.
//
// It goes over the gateway's link, as [Run.NextSession] does, and returns an error in
// the cases [Run.NextSession] lists, and for a 429 rate_limited from the gateway, a body
// past the gateway's memory budget.
//
// Qory Apiary has no key for a repeated request: a second request with the same raises
// makes new findings. Nothing was sent for an error that wraps [ErrRunClosed], for a run
// with no control plane, and for a refusal From the gateway with Status 400, 404, 413 or
// 429. Qory Apiary may have stored the findings of every other call that returned an
// error, a 503 with no code among them: read them with [Run.Findings] before you send
// the request again.
func (r *Run) PostFindings(ctx context.Context, body []byte) ([]byte, error) {
	if err := r.hostCallAllowed("POST findings"); err != nil {
		return nil, err
	}
	return r.link.PostFindings(ctx, r.disc.Run.URL, r.id, body)
}

// hostCallAllowed is the error of the host call name in a run that is closed or has no
// control plane, nil otherwise.
func (r *Run) hostCallAllowed(name string) error {
	// The *Run that Open returns with an error, when start failed, is closed too, and so
	// gets ErrRunClosed.
	switch {
	case r.runAPIClosed():
		return fmt.Errorf("Open another run to send the %s request: %w.", name, ErrRunClosed)
	case r.answer.RunAPI == "":
		return fmt.Errorf("Open the run with a control plane to send the %s request: this run has none.", name)
	}
	return nil
}
