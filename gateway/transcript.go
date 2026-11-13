package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/server"
)

// transcriptPath ends the path of a transcript request under the run endpoint:
// <runs>/<run_id>/transcript.
const transcriptPath = "/transcript"

// transcriptTime is the most time a transcript request takes, the run API's for a file.
const transcriptTime = 10 * time.Minute

// transcriptRun is the run id of a transcript request's path under runs, and whether
// the path is one: <runs>/<run_id>/transcript.
func transcriptRun(path, runs string) (string, bool) {
	rest, ok := strings.CutPrefix(path, runs+"/")
	if !ok {
		return "", false
	}
	id, ok := strings.CutSuffix(rest, transcriptPath)
	return id, ok && id != "" && !strings.Contains(id, "/")
}

// isTranscript reports whether path is a transcript request's under runs.
func isTranscript(path, runs string) bool {
	_, ok := transcriptRun(path, runs)
	return ok
}

// transcript serves a session's transcript request of the run runID: the transcript
// of the paused run the run continues, which the gateway reads from the server, GET
// <run.url>/<run_id>/resume/transcript with its signed client, and streams with
// Content-Type: application/x-ndjson, at most 64 MiB. The bytes are verified at the
// end: a transcript whose bytes do not match the signed digest, or that is longer, ends
// with the connection closed and no clean end of body. A run whose run configuration
// has no resume, or a run with no control plane, is 404 not_found, the gateway's; a
// signed 404 of the server is 404 not_found, the server's; any other failure is 502
// transcript_unavailable. A run that ended at the gateway is 410. On the local link a
// run id of no run here is 400 invalid_request; on the one address the run id is the
// run key's, any other 400 run_key_invalid, and a run the gateway does not hold is
// reopened, or answered a 503 or a 410 ([Gateway.heldRun]).
func (g *Gateway) transcript(s *side, w http.ResponseWriter, r *http.Request, runID string) {
	var lr *linkRun
	if s.remote {
		if p, _ := runKeyOf(r.Context()); runID != p.key.RunID {
			ref := runKeyInvalid()
			refuse(w, ref.Status, ref.Code, nil, ref.From, ref.Error())
			return
		}
		if lr = g.heldRun(w, r, runID); lr == nil {
			return
		}
	} else if lr = g.localRun(runID); lr == nil {
		invalid(w)
		return
	}
	if end, ended := lr.gone(); ended {
		gone(w, end)
		return
	}
	lr.touch()
	if g.client == nil || lr.r == nil || lr.r.Resume() == nil {
		refuse(w, http.StatusNotFound, codeNotFound, nil, accesskey.FromGateway,
			"start the runtime without a resume: the run continues no paused run")
		return
	}
	conf, _ := g.config()
	ctx, cancel := context.WithTimeout(lr.ctx, transcriptTime)
	defer cancel()
	stop := context.AfterFunc(r.Context(), cancel)
	defer stop()
	f, err := g.client.ResumeTranscript(ctx, conf.Run.URL, runID)
	switch {
	case errors.Is(err, server.ErrTranscriptNotFound):
		refuse(w, http.StatusNotFound, codeNotFound, nil, accesskey.FromApiary,
			"start the runtime without a resume: the control plane has no transcript of the paused run")
		return
	case err != nil:
		g.report(fmt.Sprintf("run %s: If this repeats, check the control plane: the transcript of the paused run was not read: %v", runID, accesskey.ShownError(err)))
		refuse(w, http.StatusBadGateway, codeTranscriptUnavailable, nil, accesskey.FromGateway,
			"start the runtime without a resume: the gateway did not read the transcript of the paused run from the control plane")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, f); err != nil {
		// The bytes read are unverified, or the read failed: the session gets no clean
		// end of body.
		g.report(fmt.Sprintf("run %s: If this repeats, check the control plane: the transcript of the paused run was cut: %v", runID, accesskey.ShownError(err)))
		panic(http.ErrAbortHandler)
	}
}

// The codes of the transcript request's refusals: no transcript, and a failure to read
// one from the server.
const (
	codeNotFound              = "not_found"
	codeTranscriptUnavailable = "transcript_unavailable"
)
