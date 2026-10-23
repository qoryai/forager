package gateway

import (
	"bytes"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/gateway/internal/stream"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
)

// The link's schemas, compiled once.
var (
	runRequestSchema = sync.OnceValues(func() (*jsonschema.Schema, error) { return contracts.Compile("link-run-request.schema.json") })
	batchSchema      = sync.OnceValues(func() (*jsonschema.Schema, error) { return contracts.Compile("link-batch.schema.json") })
)

// validate reports whether the schema accepts the JSON document b.
func validate(schema func() (*jsonschema.Schema, error), b []byte) bool {
	s, err := schema()
	if err != nil {
		return false
	}
	doc, err := contracts.Decode("link.json", b)
	if err != nil {
		return false
	}
	return s.Validate(doc) == nil
}

// readRunRequest reads a run request: one JSON object in UTF-8 with each member name
// once, which link-run-request.schema.json accepts.
func readRunRequest(body []byte) (*server.LinkRunRequest, bool) {
	var req server.LinkRunRequest
	if !validate(runRequestSchema, body) || jsonv2.Unmarshal(body, &req) != nil {
		return nil, false
	}
	return &req, true
}

// mediaType reports whether the request's Content-Type is want.
func mediaType(r *http.Request, want string) bool {
	t, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && t == want
}

// openRun answers a run request: 400 invalid_request for a body the schema refuses and
// for a narrowing, which the local link refuses; on the one address 400 run_key_invalid
// for a run id that is not the run key's, 400 invalid_request for labels or about, which
// are the starter's registration's, and 409 run_attached for a run the gateway holds,
// is opening or has a record of, and the server's run_key_expired again for a run key
// whose attach the server refused so, of a run it holds nothing of ([expired]); 409 run_id_used for a run id that already names a run here; the run's
// refusal when it does not open; else the run answer, on the one address once the run's
// record is marked answered, and a 500 internal of a run let go of when it cannot be.
func (g *Gateway) openRun(s *side, w http.ResponseWriter, r *http.Request) {
	deadline := g.openDeadline()
	if !mediaType(r, server.LinkContentType) {
		invalid(w)
		return
	}
	body, ok := readBody(r, server.MaxDocument)
	if !ok {
		invalid(w)
		return
	}
	req, ok := readRunRequest(body)
	if !ok || (req.Narrowing != nil && !s.remote) {
		invalid(w)
		return
	}
	how := opening{remote: s.remote, request: r.Context(), deadline: deadline}
	if s.remote {
		p, _ := runKeyOf(r.Context())
		if req.RunID != p.key.RunID {
			ref := runKeyInvalid()
			refuse(w, ref.Status, ref.Code, nil, ref.From, ref.Error())
			return
		}
		var members struct {
			Labels json.RawMessage `json:"labels"`
			About  json.RawMessage `json:"about"`
		}
		if json.Unmarshal(body, &members) != nil || members.Labels != nil || members.About != nil {
			invalid(w)
			return
		}
		how.runKey, how.key = p.raw, p.key
		if err := g.expired.refusal(p.raw, g.now()); err != nil && !g.knows(req.RunID) {
			// The server refused the run key's attach run_key_expired before, and the
			// gateway holds nothing of the run: the same refusal, and no attach.
			refuseOpen(w, err)
			return
		}
	}
	g.mu.Lock()
	if g.closing {
		g.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	g.opens.Add(1)
	g.mu.Unlock()
	defer g.opens.Done()
	if r.Context().Err() != nil {
		// The session gave up waiting for its answer: no run opens.
		return
	}
	g.mu.Lock()
	if g.used[req.RunID] {
		g.mu.Unlock()
		if s.remote {
			// A second session presents a run the gateway holds, or is opening.
			ref := g.attachRefused(codeRunAttached, http.StatusConflict, req.RunID)
			refuse(w, ref.Status, ref.Code, nil, ref.From, ref.Error())
			return
		}
		refuse(w, http.StatusConflict, refusal.RunIDUsed, nil, accesskey.FromGateway, gatewayText(refusal.RunIDUsed))
		return
	}
	g.used[req.RunID] = true
	g.mu.Unlock()
	lr, recorded, err := g.open(req, how)
	if err != nil {
		if r.Context().Err() != nil {
			// The session gave up waiting for its answer: the run did not open, and its
			// run id is free for a retry.
			g.mu.Lock()
			delete(g.used, req.RunID)
			g.mu.Unlock()
			return
		}
		if !recorded {
			if errors.Is(err, os.ErrExist) || errors.Is(err, stream.ErrRunning) || errors.Is(err, stream.ErrOpen) {
				// The run's record is there already: a run of another gateway's, or of
				// this machine's before; on the one address a run attached here before.
				if s.remote {
					ref := g.attachRefused(codeRunAttached, http.StatusConflict, req.RunID)
					refuse(w, ref.Status, ref.Code, nil, ref.From, ref.Error())
					return
				}
				refuse(w, http.StatusConflict, refusal.RunIDUsed, nil, accesskey.FromGateway, gatewayText(refusal.RunIDUsed))
				return
			}
			g.mu.Lock()
			delete(g.used, req.RunID)
			g.mu.Unlock()
			if s.remote {
				g.expired.keep(how.runKey, err, how.key.AttachBy.Add(server.Window), g.now())
			}
		}
		refuseOpen(w, err)
		return
	}
	if lr == nil {
		// No run and no error, which open never returns: nothing opened, and the run id
		// is free again.
		g.mu.Lock()
		delete(g.used, req.RunID)
		g.mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if s.remote && g.cfg.opened != nil {
		g.cfg.opened()
	}
	if r.Context().Err() != nil {
		// The session gave up as the run opened.
		g.discard(lr)
		return
	}
	g.mu.Lock()
	g.runs[lr.id] = lr
	g.mu.Unlock()
	lr.mu.Lock()
	answer, digest := lr.answer, lr.reloadDigest
	lr.mu.Unlock()
	if s.remote {
		// The record is marked answered before the answer goes, so a gateway that starts
		// again keeps it, and the run request that comes again is run_attached.
		if err := lr.st.MarkAnswered(); err != nil {
			g.discard(lr)
			refuseOpen(w, fmt.Errorf("run %s: marking its record answered: %w", req.RunID, accesskey.ShownError(err)))
			return
		}
		if g.cfg.marked != nil {
			g.cfg.marked(r.Context())
		}
	}
	g.answerHeaders(s, w, r, digest)
	w.Header().Set("Content-Type", server.LinkContentType)
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, answer.reveal())
	if r.Context().Err() != nil && !s.remote {
		// The answer is not sent whole before the handler returns: a session that has
		// gone now never has it.
		g.discard(lr)
		return
	}
	// On the one address the record is marked answered, and the answer may still go
	// once the handler returns: the run is kept as answered, and ends as any run whose
	// session sends nothing.
	lr.arm()
}

// discard lets go of a run that opened whose session gave up before it had the run
// answer, as if it never opened: it leaves the runs and ends with nothing more written
// of it, what its stream wrote is removed, and then its run id is free again, so a
// retry of it opens. A run that ended already is left to end as it does.
func (g *Gateway) discard(lr *linkRun) {
	if lr == nil {
		return
	}
	g.mu.Lock()
	lr.mu.Lock()
	ok := !lr.ended
	if ok {
		lr.discarded = true
		if g.runs[lr.id] == lr {
			delete(g.runs, lr.id)
		}
	}
	lr.mu.Unlock()
	g.mu.Unlock()
	if !ok {
		return
	}
	lr.end(sessionGone)
	<-lr.done
	g.mu.Lock()
	delete(g.used, lr.id)
	g.mu.Unlock()
}

// refuseOpen answers a run that did not open. A refusal passes on with its code and
// names, and who refused: the server's with its status, apiary, whatever its code; the
// gateway's own, gateway, a 403 for a refusal of the run's configuration Forager
// decides and for a run without a wall whose policy needs one, wall_required. Any
// other failure is a 500 internal. Each carries the error's text as its message, which
// the session returns as its error, the text today's session returned; the gateway
// itself tells the user nothing of it. A server's 410 is no refusal: it is a failure
// without a code, so no 410 crosses the link from here, signed or not.
func refuseOpen(w http.ResponseWriter, err error) {
	err = codeless(err)
	var wall *refusal.NeedsWall
	if errors.As(err, &wall) {
		refuse(w, http.StatusForbidden, refusal.WallRequired, shownWallNames(wall.Names), accesskey.FromGateway, err.Error())
		return
	}
	var ref *accesskey.Refusal
	if !errors.As(err, &ref) {
		refuse(w, http.StatusInternalServerError, codeInternal, nil, accesskey.FromGateway, accesskey.ShownError(err).Error())
		return
	}
	from := ref.From
	if from == "" {
		from = accesskey.FromGateway
	}
	status := ref.Status
	switch {
	case from != accesskey.FromApiary && refusal.Decides(ref.Code):
		status = http.StatusForbidden
	case status < 400 || status > 599:
		// A refusal of an answer that came without one, answer_unsigned to a 2xx say.
		status = http.StatusBadGateway
	}
	refuse(w, status, ref.Code, accesskey.ShownNames(ref.Names), from, err.Error())
}

// shownWallNames are a [refusal.NeedsWall]'s names as the link sends them: the image of
// image=<name> as [accesskey.ShownName] shows it, the other names as they are.
func shownWallNames(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		if image, ok := strings.CutPrefix(n, "image="); ok {
			n = "image=" + accesskey.ShownName(image, false)
		}
		out[i] = n
	}
	return out
}

// codeless turns a server's 410 to a request the gateway makes as a run opens, signed
// or not, whatever its code and whoever the refusal names, into the failure without a
// code a code-less 410 to that request is, with its text: a server's 410 ends no run
// and refuses none, so a code-less one is no [*server.AnswerError] either. Any other
// error is returned as it is.
func codeless(err error) error {
	var uncoded *server.AnswerError
	if errors.As(err, &uncoded) && uncoded.Status == http.StatusGone {
		return errors.New(accesskey.ShownError(uncoded).Error())
	}
	var ref *accesskey.Refusal
	if !errors.As(err, &ref) || ref.Status != http.StatusGone {
		return err
	}
	return fmt.Errorf("%s: status %d", ref.Detail, ref.Status)
}

// codeInternal is the code of a run that failed to open for a reason without one.
const codeInternal = "internal"

// maxMessage is the most characters a refusal's message holds.
const maxMessage = 8192

// message is an error's text as a refusal's message holds it: tab and newline kept,
// every other control character, C0, DEL and C1, and every format character, Cf, a
// space, at most maxMessage characters.
func message(text string) string {
	out := []rune(run.Spaced(text, '\t', '\n'))
	if len(out) > maxMessage {
		out = out[:maxMessage]
	}
	return string(out)
}

// answerHeaders sets the digests every answer for a run carries: the link's discovery's,
// the one the request's side answers, and the run's reload answer's, which a session
// fetches again when it changes.
func (g *Gateway) answerHeaders(s *side, w http.ResponseWriter, r *http.Request, runDigest string) {
	if _, digest, ok := g.discoveryOf(s, r); ok {
		w.Header().Set(server.HeaderConfiguration, digest)
	}
	w.Header().Set(server.HeaderRunConfiguration, runDigest)
}

// batchRun is the run id a batch names, the one value of its X-Qory-Run-Id; empty when
// it carries none or more than one.
func batchRun(r *http.Request) string {
	if values := r.Header.Values(server.HeaderRunID); len(values) == 1 {
		return values[0]
	}
	return ""
}

// localRun is the run of the local link a request names, nil for none: a run of the
// one address is not the local link's.
func (g *Gateway) localRun(runID string) *linkRun {
	g.mu.Lock()
	defer g.mu.Unlock()
	if lr := g.runs[runID]; lr != nil && !lr.remote {
		return lr
	}
	return nil
}

// reload answers a GET of a run's configuration by its run id: the reload answer as it
// stands, 410 for a run that ended at the gateway. On the local link a run id this
// gateway holds no run of is 400 invalid_request. On the one address the run id is
// the run key's, any other 400 run_key_invalid, and a run the gateway does not hold a
// 410 ([Gateway.heldRun]).
func (g *Gateway) reload(s *side, w http.ResponseWriter, r *http.Request, runID string) {
	var lr *linkRun
	if s.remote {
		if p, _ := runKeyOf(r.Context()); runID != p.key.RunID {
			ref := runKeyInvalid()
			refuse(w, ref.Status, ref.Code, nil, ref.From, ref.Error())
			return
		}
		if lr = g.heldRun(w, runID); lr == nil {
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
	lr.mu.Lock()
	body, digest := lr.reloadBody, lr.reloadDigest
	lr.mu.Unlock()
	g.answerHeaders(s, w, r, digest)
	w.Header().Set("ETag", `"`+digest+`"`)
	w.Header().Set("Content-Type", server.LinkContentType)
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// batch answers one link batch of its run: 202 when its events are numbered; 410 for
// a run that ended at the gateway; 400 invalid_request for one the link refuses, which
// ends the run, failed: its record says batch_refused, and the session's later requests
// are a 410 batch_refused. Every event's subject must be that run's. The run is found
// before the body is read: on the local link by its X-Qory-Run-Id, and a batch that names no run, or one of no run here, is 400
// invalid_request, which ends no run; on the one address by its run key,
// and a run the gateway does not hold is a 410 ([Gateway.heldRun]).
func (g *Gateway) batch(s *side, w http.ResponseWriter, r *http.Request) {
	if !mediaType(r, server.ContentType) {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	var lr *linkRun
	if s.remote {
		p, _ := runKeyOf(r.Context())
		if lr = g.heldRun(w, p.key.RunID); lr == nil {
			return
		}
	} else if lr = g.localRun(batchRun(r)); lr == nil {
		invalid(w)
		return
	}
	lr.batch.Lock()
	defer lr.batch.Unlock()
	if end, ended := lr.gone(); ended {
		gone(w, end)
		return
	}
	lr.touch()
	refused := func(why string) {
		g.report(fmt.Sprintf("run %s: the gateway refused a batch from the run's session, %s; the run ends: %s", lr.id, why, batchRefused.state))
		invalid(w)
		lr.end(batchRefused)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBatch+1))
	if err != nil {
		// The body did not arrive whole, its session gone say: no batch came, and no run
		// ends.
		invalid(w)
		return
	}
	if len(body) > maxBatch {
		refused("a batch over the size limit")
		return
	}
	evs, err := stream.DecodeBatch(body)
	if err != nil || len(evs) == 0 {
		refused("one link-batch.schema.json refuses")
		return
	}
	if why := lr.check(body, evs); why != "" {
		refused(why)
		return
	}
	shownStarted(evs)
	if _, err := lr.st.Accept(evs); err != nil {
		if end, ended := lr.gone(); ended {
			gone(w, end)
			return
		}
		refused(err.Error())
		return
	}
	final := lr.accepted(evs)
	lr.mu.Lock()
	digest := lr.reloadDigest
	lr.mu.Unlock()
	g.answerHeaders(s, w, r, digest)
	w.WriteHeader(http.StatusAccepted)
	if final {
		// The session's run.exited or run.refused: the run's gateway side ends.
		lr.end(ending{code: accesskey.CodeRunClosed, from: accesskey.FromGateway})
	}
}

// closeRule is why the link refuses a session's dev.qory.run.exited, its data, empty
// when it accepts it: the close's, with no reason or with timeout, interrupted,
// no_session or image_missing, the last two only for a run with no join the gateway
// numbered, and image_missing only failed with exit_code -1, the close after a fetch of
// the run's image that its registry did not have. The gateway writes the event of every
// other end itself. joined is true when the gateway numbered a join of the run.
func closeRule(data map[string]any, joined bool) string {
	given, hasReason := data["reason"]
	why, _ := given.(string)
	switch {
	case !hasReason, why == event.ReasonTimeout, why == event.ReasonInterrupted:
	case why == event.ReasonNoSession:
		if joined {
			return "a run.exited no_session of a run with a join"
		}
	case why == refusal.ImageMissing:
		code, _ := data["exit_code"].(float64)
		switch {
		case joined:
			return "a run.exited image_missing of a run with a join"
		case data["state"] != event.StateFailed || code != -1:
			return "a run.exited image_missing that is not failed with exit_code -1"
		}
	default:
		return "a run.exited with a reason the gateway decides"
	}
	return ""
}

// sessionOf is the session number of a dev.qory.session.started or
// dev.qory.session.exited, as its data decodes; 0 for none.
func sessionOf(data map[string]any) int {
	n, _ := data["session"].(float64)
	if n < 1 || n != float64(int(n)) {
		return 0
	}
	return int(n)
}

// otherOpen reports whether a join of joins other than session n is open: answered
// 200, with or without its dev.qory.session.started, and no dev.qory.session.exited.
func otherOpen(joins map[int]join, n int) bool {
	for m, j := range joins {
		if m != n && j.open() {
			return true
		}
	}
	return false
}

// gatewayName is a refusal's name of the form only a gateway's refusal carries.
var gatewayName = regexp.MustCompile(`^(labels|about\.details)\.[^=]*=`)

// check is why the link refuses a batch of the run's, the README's rules: empty when
// it accepts it. Each event the gateway numbered before, by its id, is the session's
// sending again and is not looked at twice. Called with lr.batch held.
func (lr *linkRun) check(body []byte, evs []event.Event) string {
	// First, before anything decodes it the lenient way: each member name once and
	// UTF-8 throughout, so what the gateway checks is what the record and the server
	// read, whichever copy of a name their decoder would keep.
	if jsonv2.Unmarshal(body, new(any)) != nil {
		return "a batch with a member name twice in one object, or not in UTF-8"
	}
	if !validate(batchSchema, body) {
		return "one link-batch.schema.json refuses"
	}
	lr.mu.Lock()
	seen, startedID, final := lr.seen, lr.startedID, lr.final
	given := lr.given
	// What the gateway holds of each join, as the batch's events change it, in order.
	joins := make(map[int]join, len(lr.joins))
	for _, j := range lr.joins {
		joins[j.session] = *j
	}
	lr.mu.Unlock()
	fresh := map[string]bool{}
	for _, ev := range evs {
		if ev.Subject != lr.id || ev.Source != event.Source(lr.id) {
			return "an event of another run"
		}
		if seen[ev.ID] || fresh[ev.ID] {
			continue
		}
		fresh[ev.ID] = true
		if final {
			return "an event after the run's final event"
		}
		var data map[string]any
		if raw, ok := ev.Data.(json.RawMessage); ok {
			if json.Unmarshal(raw, &data) != nil {
				return "an event whose data is no object"
			}
		}
		switch ev.Type {
		case event.RunRegistered, event.RunEgress:
			return "an event of a type the gateway writes"
		case event.RunStarted:
			if data["opened_by"] != event.OpenedByRun {
				return "a run.started not opened by the run"
			}
			if !sameLabels(data["labels"], lr.labels) {
				return "a run.started whose labels are not the run's"
			}
			if startedID != "" && startedID != ev.ID {
				return "a second run.started"
			}
			startedID = ev.ID
		case event.RunExited:
			if why := closeRule(data, len(joins) > 0); why != "" {
				return why
			}
			for _, j := range joins {
				if j.open() {
					return "a run.exited while a join is open"
				}
			}
			final = true
		case event.SessionStarted:
			n := sessionOf(data)
			j, ok := joins[n]
			switch {
			case !ok || !j.accepted:
				return "a session.started of no join the gateway accepted"
			case j.started:
				return "a second session.started of one session"
			case j.exited:
				return "a session.started after its session.exited"
			case otherOpen(joins, n):
				return "a session.started while another session runs"
			}
			j.started = true
			joins[n] = j
		case event.SessionExited:
			n := sessionOf(data)
			j, ok := joins[n]
			switch {
			case !ok:
				return "a session.exited of no join the gateway numbered"
			case j.exited:
				return "a second session.exited of one session"
			}
			j.exited = true
			joins[n] = j
		case event.RunRefused:
			if startedID != "" {
				return "a run.refused after run.started"
			}
			code, _ := data["code"].(string)
			if !refusal.Decides(code) {
				return "a run.refused with a code the session does not decide"
			}
			names, _ := data["names"].([]any)
			for _, n := range names {
				if s, _ := n.(string); gatewayName.MatchString(s) {
					return "a run.refused with a name only a gateway's refusal carries"
				}
			}
			final = true
		case event.PolicyApplied:
			own := decided(data)
			ok := false
			for _, a := range given {
				if reflect.DeepEqual(own, a) {
					ok = true
					break
				}
			}
			if !ok {
				return "a run.policy_applied that differs from what the gateway put in force"
			}
		}
	}
	return ""
}

// accepted records what a batch the stream numbered says of the run, and reports
// whether its final event was among it. Called with lr.batch held.
func (lr *linkRun) accepted(evs []event.Event) bool {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	final := false
	for _, ev := range evs {
		if lr.seen[ev.ID] {
			continue
		}
		lr.seen[ev.ID] = true
		switch ev.Type {
		case event.RunStarted:
			lr.startedID = ev.ID
			lr.startedAt, _ = time.Parse(time.RFC3339Nano, ev.Time)
		case event.SessionStarted, event.SessionExited:
			lr.joined(ev)
		case event.RunExited, event.RunRefused:
			lr.final, final = true, true
		}
	}
	return final
}

// joined records a dev.qory.session.started or dev.qory.session.exited the stream
// numbered on its join, which [linkRun.check] found. Called with lr.mu held.
func (lr *linkRun) joined(ev event.Event) {
	var data map[string]any
	if raw, ok := ev.Data.(json.RawMessage); !ok || json.Unmarshal(raw, &data) != nil {
		return
	}
	n := sessionOf(data)
	if n < 1 || n > len(lr.joins) {
		return
	}
	j := lr.joins[n-1]
	if ev.Type == event.SessionExited {
		j.exited = true
		if held := lr.r.Held(); j.accepted && j.model != "" && held != nil && held.Start != "" {
			// The session ended: the proxy sets the start key again.
			lr.px.SetModelKey(held.Start)
		}
		return
	}
	j.started = true
	j.startedAt, _ = time.Parse(time.RFC3339Nano, ev.Time)
}

// shownStarted phrases each dev.qory.run.started and dev.qory.session.started in evs, a
// batch [linkRun.check] accepted, as a session phrases one, so a session that sends a
// value as it is passes no value that contains qak_, qrk_, qecr_, qecn_, qecp_, qecg_ or
// qeci_ in any case through the gateway: the members of startedNames as
// [accesskey.ShownName] shows them, those of startedValues and each entry of startedLists
// as [accesskey.ShownValue] does, the labels as [server.ShownLabels] returns them and
// about as [server.ShownAbout] does. Data with no such value is left byte for byte.
func shownStarted(evs []event.Event) {
	for i, ev := range evs {
		if ev.Type != event.RunStarted && ev.Type != event.SessionStarted {
			continue
		}
		raw, ok := ev.Data.(json.RawMessage)
		if !ok {
			continue
		}
		var data map[string]json.RawMessage
		if json.Unmarshal(raw, &data) != nil {
			continue
		}
		changed := false
		set := func(member string, v any) {
			if b, err := unescaped(v); err == nil {
				data[member], changed = b, true
			}
		}
		for _, members := range []struct {
			names []string
			shown func(string, bool) string
		}{{startedNames, accesskey.ShownName}, {startedValues, accesskey.ShownValue}} {
			for _, m := range members.names {
				var v string
				if json.Unmarshal(data[m], &v) == nil && accesskey.ContainsSecret(v) {
					set(m, members.shown(v, false))
				}
			}
		}
		for _, m := range startedLists {
			var vs []string
			if json.Unmarshal(data[m], &vs) == nil && slices.ContainsFunc(vs, accesskey.ContainsSecret) {
				shown := make([]string, len(vs))
				for k, v := range vs {
					shown[k] = accesskey.ShownValue(v, false)
				}
				set(m, shown)
			}
		}
		var labels map[string]string
		if json.Unmarshal(data["labels"], &labels) == nil {
			if shown := server.ShownLabels(labels); !maps.Equal(shown, labels) {
				set("labels", shown)
			}
		}
		var about server.About
		if json.Unmarshal(data["about"], &about) == nil {
			if shown := server.ShownAbout(&about); !reflect.DeepEqual(*shown, about) {
				set("about", shown)
			}
		}
		if !changed {
			continue
		}
		if b, err := unescaped(data); err == nil {
			evs[i].Data = json.RawMessage(b)
		}
	}
}

// The members of dev.qory.run.started and dev.qory.session.started a session phrases: startedNames as names,
// startedValues as values, and each entry of startedLists as a value.
var (
	startedNames  = []string{"runtime", "host", "wall", "image", "image_name", "container_runtime"}
	startedValues = []string{"dir", "command", "runtime_version"}
	startedLists  = []string{"args", "setup_commands"}
)

// unescaped is v as JSON without HTML escaping, so the rest of an event's data keeps
// its characters.
func unescaped(v any) (json.RawMessage, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// sameLabels reports whether a run.started's labels, as its data decodes, are the
// run's: absent is none. They may be the run's as server.ShownLabels gives them, which
// the session sends; a session of before sends them as they are.
func sameLabels(v any, labels map[string]string) bool {
	got, _ := v.(map[string]any)
	if v != nil && got == nil {
		return false
	}
	return equalLabels(got, labels) || equalLabels(got, server.ShownLabels(labels))
}

// equalLabels reports whether got, a JSON object as it decodes, is labels.
func equalLabels(got map[string]any, labels map[string]string) bool {
	if len(got) != len(labels) {
		return false
	}
	for k, want := range labels {
		if s, ok := got[k].(string); !ok || s != want {
			return false
		}
	}
	return true
}
