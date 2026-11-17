package gateway

import (
	"context"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/server"
)

// hostCall is one of the link's two host calls: requests that only the run's host work
// sends, over the link, which no container reaches. The gateway forwards each to Qory
// Apiary unread.
type hostCall struct {
	// name is the request's name in texts; path ends its path on the link and at Qory
	// Apiary, under the run's id.
	name, path string
	// request and answer are the largest bodies of the request and of a 2xx answer.
	request, answer int
}

// The link's host calls.
var (
	nextSessionCall   = hostCall{name: "next-session", path: "/next-session", request: server.MaxNextSessionRequest, answer: server.MaxNextSessionAnswer}
	pushedCommitsCall = hostCall{name: "pushed-commits", path: "/pushed-commits", request: server.MaxPushedCommitsRequest, answer: server.MaxPushedCommitsAnswer}
)

// hostCallOf is the run id and the host call of a POST's path under runs,
// <runs>/<run_id>/next-session or <runs>/<run_id>/pushed-commits, and whether the path
// is one.
func hostCallOf(path, runs string) (string, *hostCall, bool) {
	rest, ok := strings.CutPrefix(path, runs+"/")
	if !ok {
		return "", nil, false
	}
	for _, c := range []*hostCall{&nextSessionCall, &pushedCommitsCall} {
		if id, ok := strings.CutSuffix(rest, c.path); ok && id != "" && !strings.Contains(id, "/") {
			return id, c, true
		}
	}
	return "", nil, false
}

// isHostCall reports whether path is a host call's under runs.
func isHostCall(path, runs string) bool {
	_, _, ok := hostCallOf(path, runs)
	return ok
}

// The codes of the host calls' refusals of the gateway: a body over the limit, and no
// valid answer from Qory Apiary.
const (
	codePayloadTooLarge         = "payload_too_large"
	codeControlPlaneUnavailable = "control_plane_unavailable"
)

// serveHostCall serves the host call c of the run runID: it forwards the request's body
// unread to Qory Apiary, POST <run.url>/<run_id> and c's path with its signed client,
// once, within [server.HostCallTime], and answers with what Qory Apiary returned.
//
//   - A 2xx passes with its status and body, at most c.answer bytes, a body with
//     Content-Type: application/json alone.
//   - A signed coded refusal of Qory Apiary's, 400 to 599 but 401 and 410, passes with
//     its status, code, names and message, from apiary.
//   - Every other answer, one that fails verification, and no answer are 502
//     control_plane_unavailable, the gateway's, with one line in its log. Qory
//     Apiary's 410 is among them: on the link a 410 ends the session's run, and only
//     the gateway ends a run there.
//
// The gateway's other refusals: on the local link a run id of no run here is 400
// invalid_request; on the one address the run id is the run key's, any other 400
// run_key_invalid, and a run the gateway does not hold is reopened, or answered a 503
// or a 410 ([Gateway.heldRun]). A run that ended at the gateway is 410, and a suspended
// run 503 with no body. A Content-Type other than application/json is 400
// invalid_request, a body over c.request bytes 413 payload_too_large, and a run with no
// control plane 404 not_found; Qory Apiary gets nothing for any of them.
func (g *Gateway) serveHostCall(s *side, w http.ResponseWriter, r *http.Request, runID string, c *hostCall) {
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
	if lr.isSuspended() {
		// The gateway stops: the caller sends the request again to the gateway that
		// starts again.
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	lr.touch()
	if !mediaType(r, server.LinkContentType) {
		invalid(w)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(c.request)+1))
	switch {
	case err != nil:
		invalid(w)
		return
	case len(body) > c.request:
		refuse(w, http.StatusRequestEntityTooLarge, codePayloadTooLarge, nil, accesskey.FromGateway,
			fmt.Sprintf("Send a %s body of at most %d bytes: this one is longer, so the gateway sent nothing.", c.name, c.request))
		return
	}
	if g.client == nil || lr.r == nil {
		refuse(w, http.StatusNotFound, codeNotFound, nil, accesskey.FromGateway,
			fmt.Sprintf("Open the run through a gateway with a control plane to send the %s request: this run has none.", c.name))
		return
	}
	conf, _ := g.config()
	ctx, cancel := context.WithTimeout(lr.ctx, server.HostCallTime)
	defer cancel()
	stop := context.AfterFunc(r.Context(), cancel)
	defer stop()
	a, err := g.client.RunAPI(ctx, conf.Run.URL, runID, http.MethodPost, c.path, body, false)
	if err != nil {
		if lr.isSuspended() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		g.hostCallFailed(w, runID, c, accesskey.ShownError(err).Error())
		return
	}
	switch {
	case a.Status >= 200 && a.Status <= 299:
		if len(a.Body) > c.answer {
			g.hostCallFailed(w, runID, c, fmt.Sprintf("the answer is %d bytes, over the %d the request takes", len(a.Body), c.answer))
			return
		}
		if len(a.Body) > 0 {
			if t, _, err := mime.ParseMediaType(a.Header.Get("Content-Type")); err != nil || t != "application/json" {
				g.hostCallFailed(w, runID, c, "the answer's Content-Type is not application/json")
				return
			}
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(a.Status)
		w.Write(a.Body)
	case a.Status >= 400 && a.Status <= 599 && a.Status != http.StatusUnauthorized && a.Status != http.StatusGone && accesskey.ReadRefusal(a.Status, a.Body) != nil:
		ref := accesskey.ReadRefusal(a.Status, a.Body)
		var doc struct {
			Message string `json:"message"`
		}
		jsonv2.Unmarshal(a.Body, &doc)
		answerRefusal(w, a.Status, linkRefusal{Error: ref.Code, Names: shownNames(ref.Names), Message: message(accesskey.ShownValue(doc.Message, false)), From: accesskey.FromApiary})
	default:
		g.hostCallFailed(w, runID, c, fmt.Sprintf("status %d with no code the link passes on", a.Status))
	}
}

// hostCallFailed writes one line of the failure why of the host call c of the run
// runID to the gateway's log, and answers 502 control_plane_unavailable.
func (g *Gateway) hostCallFailed(w http.ResponseWriter, runID string, c *hostCall, why string) {
	g.report(fmt.Sprintf("run %s: If this repeats, check the control plane: the %s request got no valid answer: %s", runID, c.name, why))
	refuse(w, http.StatusBadGateway, codeControlPlaneUnavailable, nil, accesskey.FromGateway,
		fmt.Sprintf("Send the %s request again: the gateway got no valid answer from the control plane.", c.name))
}

// shownNames are the names of a refusal of Qory Apiary's as the link lists them: each
// once, none empty, and a phrase in place of one that contains a secret; nil for none.
func shownNames(names []string) []string {
	var out []string
	for _, n := range accesskey.ShownNames(names) {
		if n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}
