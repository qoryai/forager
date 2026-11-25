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
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/server"
)

// hostCall is one of the link's host calls: requests that only the run's host work
// sends, over the link, which no container reaches. The gateway forwards each to Qory
// Apiary unread.
type hostCall struct {
	// name is the request's name in texts; method is its method, and path ends its path on
	// the link and at Qory Apiary, under the run's id.
	name, method, path string
	// request and answer are the largest bodies of the request, 0 for a GET, and of a 200
	// answer.
	request, answer int
	// readFirst is true for a request that Qory Apiary stores again when it is repeated: a
	// caller reads what is stored before it sends the request again.
	readFirst bool
	// single is true for a request that a run has at most one of in flight: its body or
	// its answer may be over 1 MiB.
	single bool
}

// runCall is a run's host call of one method and path in flight, by the run's id.
type runCall struct {
	runID string
	call  *hostCall
}

// The link's host calls.
var (
	nextSessionCall   = hostCall{name: "next-session", method: http.MethodPost, path: "/next-session", request: server.MaxNextSessionRequest, answer: server.MaxNextSessionAnswer}
	pushedCommitsCall = hostCall{name: "pushed-commits", method: http.MethodPost, path: "/pushed-commits", request: server.MaxPushedCommitsRequest, answer: server.MaxPushedCommitsAnswer}
	findingsCall      = hostCall{name: "GET findings", method: http.MethodGet, path: "/findings", answer: server.MaxFindingsAnswer, single: true}
	postFindingsCall  = hostCall{name: "POST findings", method: http.MethodPost, path: "/findings", request: server.MaxPostFindingsRequest, answer: server.MaxPostFindingsAnswer, readFirst: true, single: true}
)

// hostCallOf is the run id and the host call of a request's method and path under runs,
// POST <runs>/<run_id>/next-session, POST <runs>/<run_id>/pushed-commits, or GET or POST
// <runs>/<run_id>/findings, and whether the request is one.
func hostCallOf(method, path, runs string) (string, *hostCall, bool) {
	rest, ok := strings.CutPrefix(path, runs+"/")
	if !ok {
		return "", nil, false
	}
	for _, c := range []*hostCall{&nextSessionCall, &pushedCommitsCall, &findingsCall, &postFindingsCall} {
		if c.method != method {
			continue
		}
		if id, ok := strings.CutSuffix(rest, c.path); ok && id != "" && !strings.Contains(id, "/") {
			return id, c, true
		}
	}
	return "", nil, false
}

// isHostCall reports whether a request of method to path is a host call's under runs.
func isHostCall(method, path, runs string) bool {
	_, _, ok := hostCallOf(method, path, runs)
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
// unread to Qory Apiary, c's method to <run.url>/<run_id> and c's path with its signed
// client, once, within [server.HostCallTime], and writes what Qory Apiary returned. The
// body of a GET is not read, as a transcript request's.
//
//   - A 2xx passes with its status and body, a body with Content-Type:
//     application/json alone. The body of a 200 is at most c.answer bytes, and that of
//     any other 2xx at most [server.MaxRefusal]; the gateway reads no further.
//   - A signed coded refusal of Qory Apiary's, 400 to 599 but 410, passes with its
//     status, code, names and message, from apiary, and with retry_after when it has a
//     Retry-After of seconds. A 401 is never signed, so it never passes.
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
//
// A request's body and an answer count past their first 1 MiB in the gateway's memory
// budget ([proxy.RunAPILimits]): a body as it is read, before it is signed, until the call
// to Qory Apiary ends, and an answer once it is read and verified, to the end of its
// write, within [server.HostCallTime]. One past the budget is 429 rate_limited: Qory
// Apiary gets nothing of the body, and the gateway drops the answer.
//
// A run has at most one c in flight when c.single is true: a second one is 429
// rate_limited, and Qory Apiary gets nothing of it. For such a c, the run id and the end
// of the run are checked first ([Gateway.bodyRefusal]), then the place is taken, and then
// the body is read, on the local link within [server.HostCallTime], as on the one address
// within [edgeReadWait].
func (g *Gateway) serveHostCall(s *side, w http.ResponseWriter, r *http.Request, runID string, c *hostCall) {
	rc := http.NewResponseController(w)
	release := func() {}
	// drop reads and drops what is left of the body, up to one byte over the limit, before
	// the gateway writes a refusal, so a caller that still writes the body gets it.
	drop := func() { io.Copy(io.Discard, io.LimitReader(r.Body, int64(c.request)+1)) }
	// The local link's server sets no deadline for a body, and closes the connection after
	// a refusal that leaves 256 KiB or more of the body unread; the one address has both
	// ([Gateway.edgeHandler]). net/http clears the deadline once the body ends. A body of
	// no bytes gets none: net/http's background read, which ends the request's context when
	// the caller hangs up, then starts before the handler, and the deadline would end that
	// read, and with it the call, at the time of a host call.
	local := c.single && c.method == http.MethodPost && !s.remote
	if local && r.ContentLength != 0 {
		rc.SetReadDeadline(time.Now().Add(g.cfg.hostCallTimeOf()))
	}
	if c.single {
		refusal := g.bodyRefusal(s, r, runID)
		call := runCall{runID, c}
		if refusal == nil {
			if _, taken := g.inFlight.LoadOrStore(call, nil); taken {
				refusal = func(w http.ResponseWriter) {
					refuse(w, http.StatusTooManyRequests, accesskey.CodeRateLimited, nil, accesskey.FromGateway,
						fmt.Sprintf("Retry once the run's other %s request ends: a run has at most one in flight.\nThe gateway sent nothing.", c.name))
				}
			}
		}
		if refusal != nil {
			if local {
				drop()
			}
			refusal(w)
			return
		}
		defer g.inFlight.Delete(call)
	}
	// The body is read before the run is looked up, at most one byte over the limit: on
	// the one address a reopen of the run may take 120 seconds, longer than the one
	// address's time to read a request.
	var body []byte
	var readErr error
	if c.method == http.MethodPost {
		var charged io.Reader
		charged, release = g.runAPILimits.ChargeBody(io.LimitReader(r.Body, int64(c.request)+1))
		defer release()
		body, readErr = io.ReadAll(charged)
		if errors.Is(readErr, proxy.ErrRunAPIBudget) {
			body = nil
			release()
			drop()
		}
	}
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
	case c.method == http.MethodPost && !mediaType(r, server.LinkContentType):
		got := r.Header.Get("Content-Type")
		if got == "" {
			got = "(none)"
		}
		refuse(w, http.StatusBadRequest, server.CodeInvalidRequest, nil, accesskey.FromGateway,
			fmt.Sprintf("Send the %s request with Content-Type: application/json: the gateway sent nothing.\nContent-Type: %s", c.name, accesskey.ShownValue(got, false)))
		return
	case errors.Is(readErr, proxy.ErrRunAPIBudget):
		refuse(w, http.StatusTooManyRequests, accesskey.CodeRateLimited, nil, accesskey.FromGateway, proxy.RunAPIBudgetFull)
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
	a, err := g.client.HostCall(ctx, conf.Run.URL, runID, c.method, c.path, body, c.answer)
	release()
	if c.single {
		// A caller that stops reading the answer ends its write at the deadline, and so the
		// answer's count and the run's place. net/http reads a body that came with a GET
		// before it writes the answer's head, so that read has the deadline too. net/http
		// clears both before the connection's next request.
		deadline := time.Now().Add(g.cfg.hostCallTimeOf())
		rc.SetReadDeadline(deadline)
		rc.SetWriteDeadline(deadline)
	}
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
		}
		written, ok := g.runAPILimits.ChargeAnswer(len(a.Body))
		if !ok {
			refuse(w, http.StatusTooManyRequests, accesskey.CodeRateLimited, nil, accesskey.FromGateway, proxy.RunAPIAnswerFull)
			return
		}
		defer written()
		if len(a.Body) > 0 {
			w.Header().Set("Content-Type", "application/json")
			if c.method == http.MethodGet {
				// The one answer that counts: its write ends before the count does.
				defer rc.Flush()
			}
		}
		w.WriteHeader(a.Status)
		// shortcut: an answer that is read does not count until it is whole, at most one of
		// 16 MiB for each run, nor does the copy that a separate gateway signs, until it is
		// written; count both when a gateway's memory needs it.
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
		answerRefusal(w, a.Status, linkRefusal{Error: ref.Code, Names: shownNames(ref.Names), Message: message(accesskey.ShownValue(doc.Message, false)), From: accesskey.FromApiary, RetryAfter: seconds(server.ReadRetryAfter(a.Header))})
	case a.Status == http.StatusGone:
		g.hostCallFailed(w, runID, c, false, "a signed 410, which only the gateway sends on the link")
	default:
		g.hostCallFailed(w, runID, c, true, fmt.Sprintf("status %d with no code the link passes on", a.Status))
	}
}

// hostCallFailed writes one line of the failure why of the host call c of the run
// runID to the gateway's log, and writes 502 control_plane_unavailable: with again, a
// text to send the request again, for c.readFirst after a read of what is stored, and
// without it, for an answer that comes back the same, a text to check the control plane.
func (g *Gateway) hostCallFailed(w http.ResponseWriter, runID string, c *hostCall, again bool, why string) {
	g.report(fmt.Sprintf("run %s: If this repeats, check the control plane: the %s request got no valid answer: %s", runID, c.name, why))
	text := fmt.Sprintf("Check the control plane: the gateway does not pass on its answer to the %s request.\n%s", c.name, why)
	switch {
	case again && c.readFirst:
		text = fmt.Sprintf("Read the findings before you send the %s request again.\nThe gateway got no valid answer from the control plane.", c.name)
	case again:
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
