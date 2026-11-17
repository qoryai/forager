package gateway

import (
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"

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

// hostCallTimeOf is the most time one host call has at Qory Apiary under c.
func (c Config) hostCallTimeOf() time.Duration {
	if c.hostCallTime > 0 {
		return c.hostCallTime
	}
	return server.HostCallTime
}

// serveHostCall serves the host call c of the run runID: it forwards the request's body
// unread to Qory Apiary, POST <run.url>/<run_id> and c's path with its signed client,
// once, within [server.HostCallTime], and writes what Qory Apiary returned.
//
//   - A 2xx passes with its status and body, a body with Content-Type:
//     application/json alone. The body of a 200 is at most c.answer bytes, and that of
//     any other 2xx at most [server.MaxRefusal]; the gateway reads no further.
//   - A signed coded refusal of Qory Apiary's, 400 to 599 but 410, passes with its
//     status, code, names and message, from apiary. A 401 is never signed, so it never
//     passes.
//   - Every other answer, one that fails verification, and no answer are 502
//     control_plane_unavailable, the gateway's, with one line in its log. Qory
//     Apiary's 410 is among them: on the link a 410 ends the session's run, and only
//     the gateway ends a run there.
//   - A run that ends or is suspended at the gateway while Qory Apiary has the request
//     is 410 or 503, as before the send, and a caller that hangs up gets nothing, with
//     no line in the log.
//
// The gateway's other refusals: those of [Gateway.linkRunOf], and a suspended run's 503
// with no body. A Content-Type other than application/json is 400 invalid_request, a
// body over c.request bytes 413 payload_too_large, and a run with no control plane 404
// not_found; Qory Apiary gets nothing for any of them.
func (g *Gateway) serveHostCall(s *side, w http.ResponseWriter, r *http.Request, runID string, c *hostCall) {
	// The body is read before the run is looked up, at most one byte over the limit: on
	// the one address a reopen of the run may take 120 seconds, longer than the one
	// address's time to read a request.
	body, readErr := io.ReadAll(io.LimitReader(r.Body, int64(c.request)+1))
	lr := g.linkRunOf(s, w, r, runID)
	if lr == nil {
		return
	}
	if lr.isSuspended() {
		// The gateway stops: the caller sends the request again to the gateway that
		// starts again.
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	lr.touch()
	switch {
	case !mediaType(r, server.LinkContentType):
		got := r.Header.Get("Content-Type")
		if got == "" {
			got = "(none)"
		}
		refuse(w, http.StatusBadRequest, server.CodeInvalidRequest, nil, accesskey.FromGateway,
			fmt.Sprintf("Send the %s request with Content-Type: application/json: the gateway sent nothing.\nContent-Type: %s", c.name, accesskey.ShownValue(got, false)))
		return
	case readErr != nil:
		refuse(w, http.StatusBadRequest, server.CodeInvalidRequest, nil, accesskey.FromGateway,
			fmt.Sprintf("Send the %s request again: the gateway did not read its body whole, and sent nothing.\n%v", c.name, accesskey.ShownError(readErr)))
		return
	case len(body) > c.request:
		refuse(w, http.StatusRequestEntityTooLarge, codePayloadTooLarge, nil, accesskey.FromGateway,
			fmt.Sprintf("Send a %s body of at most %d bytes: this one is longer, so the gateway sent nothing.", c.name, c.request))
		return
	}
	if g.client == nil || lr.r == nil {
		refuse(w, http.StatusNotFound, codeNotFound, nil, accesskey.FromGateway,
			fmt.Sprintf("Open the run with a control plane to send the %s request: this run has none.", c.name))
		return
	}
	conf, _ := g.config()
	ctx, cancel := lr.callContext(r, g.cfg.hostCallTimeOf())
	defer cancel()
	a, err := g.client.HostCall(ctx, conf.Run.URL, runID, c.path, body, c.answer)
	if err != nil {
		end, ended := lr.gone()
		switch {
		case lr.isSuspended():
			w.WriteHeader(http.StatusServiceUnavailable)
		case ended:
			gone(w, end)
		case r.Context().Err() != nil:
			// The caller hung up: nothing reaches it, and nothing failed at Qory Apiary.
			panic(http.ErrAbortHandler)
		case errors.Is(err, server.ErrRunAPITooLarge):
			g.hostCallFailed(w, runID, c, false, accesskey.ShownError(err).Error())
		default:
			g.hostCallFailed(w, runID, c, true, accesskey.ShownError(err).Error())
		}
		return
	}
	if a.Status >= 200 && a.Status <= 299 {
		if len(a.Body) > 0 {
			if t, _, err := mime.ParseMediaType(a.Header.Get("Content-Type")); err != nil || t != "application/json" {
				g.hostCallFailed(w, runID, c, false, "the answer's Content-Type is not application/json")
				return
			}
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(a.Status)
		w.Write(a.Body)
		return
	}
	var ref *accesskey.Refusal
	if a.Status >= 400 && a.Status <= 599 && a.Status != http.StatusGone {
		ref = accesskey.ReadRefusal(a.Status, a.Body)
	}
	switch {
	case ref != nil:
		var doc struct {
			Message string `json:"message"`
		}
		jsonv2.Unmarshal(a.Body, &doc)
		answerRefusal(w, a.Status, linkRefusal{Error: ref.Code, Names: shownNames(ref.Names), Message: message(accesskey.ShownValue(doc.Message, false)), From: accesskey.FromApiary})
	case a.Status == http.StatusGone:
		g.hostCallFailed(w, runID, c, false, "a signed 410, which only the gateway sends on the link")
	default:
		g.hostCallFailed(w, runID, c, true, fmt.Sprintf("status %d with no code the link passes on", a.Status))
	}
}

// hostCallFailed writes one line of the failure why of the host call c of the run
// runID to the gateway's log, and writes 502 control_plane_unavailable: with again, a
// text to send the request again, and without it, for an answer that comes back the
// same, a text to check the control plane.
func (g *Gateway) hostCallFailed(w http.ResponseWriter, runID string, c *hostCall, again bool, why string) {
	g.report(fmt.Sprintf("run %s: If this repeats, check the control plane: the %s request got no valid answer: %s", runID, c.name, why))
	text := fmt.Sprintf("Check the control plane: the gateway does not pass on its answer to the %s request.\n%s", c.name, why)
	if again {
		text = fmt.Sprintf("Send the %s request again: the gateway got no valid answer from the control plane.", c.name)
	}
	refuse(w, http.StatusBadGateway, codeControlPlaneUnavailable, nil, accesskey.FromGateway, text)
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
