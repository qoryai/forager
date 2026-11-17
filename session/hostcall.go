package session

import (
	"context"
	"fmt"
)

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
// It returns an error, with nothing sent, once [Run.Close] began or the gateway closed
// the run, and for a run with no control plane. It returns an [*accesskey.Refusal] for
// a refusal: From is apiary for Qory Apiary's code, passed on with its status, such as
// 409 run_ended, and gateway for the gateway's, such as 413 payload_too_large for a
// body over the limit or 502 control_plane_unavailable when no valid answer came; a 410
// is the end of the run at the gateway, which [server.Ended] reports. A transport
// failure and no answer in time are errors too.
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
// the cases [Run.NextSession] lists.
func (r *Run) PushedCommits(ctx context.Context, body []byte) ([]byte, error) {
	if err := r.hostCallAllowed("pushed-commits"); err != nil {
		return nil, err
	}
	return r.link.PushedCommits(ctx, r.disc.Run.URL, r.id, body)
}

// hostCallAllowed is the error of the host call name in a run that is closed or has no
// control plane, nil otherwise.
func (r *Run) hostCallAllowed(name string) error {
	switch {
	case r.runAPIClosed():
		return fmt.Errorf("Open another run to send the %s request: this run is closed.", name)
	case r.answer.RunAPI == "":
		return fmt.Errorf("Open the run through a gateway with a control plane to send the %s request: this run has none.", name)
	}
	return nil
}
