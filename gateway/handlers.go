package gateway

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway/internal/stream"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/runcredential"
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
// for a narrowing, which the local link refuses; on the one address 401
// run_credential_refused for a run key the gateway refuses after the issuer's end,
// during its hold, or whose run credential the issuer no longer holds
// active; 409 run_id_used for a run id
// that already names a run here; on the one address 403
// target_differs_from_credential or differs_from_credential for labels or details
// that are not the run credential's; the run's refusal when it does not open; else the
// run answer.
func (g *Gateway) openRun(s *side, w http.ResponseWriter, r *http.Request) {
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
	var id *runIdentity
	if s.remote {
		got, ok := identityOf(r.Context())
		if !ok {
			refuseCredential(w)
			return
		}
		id = &got
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
	if id != nil {
		// The gateway tracks run keys and does not require them to be unique: each run
		// request opens a run of its own, but for a run key the gateway refuses after the
		// issuer's end.
		if g.blocked(keyOf(*id)) {
			g.presented(*id)
			refuseCredential(w)
			return
		}
		if !id.isActive(r.Context()) {
			refuseCredential(w)
			return
		}
	}
	if r.Context().Err() != nil {
		// The session gave up waiting for its answer: no run opens.
		return
	}
	// keyRefused reports, under the gateway's lock, whether the issuer ended a run of
	// the run key since it was asked.
	keyRefused := func() bool { return id != nil && g.blocked(keyOf(*id)) }
	var differs *accesskey.Refusal
	if id != nil {
		differs = runcredential.Compare(req.Labels, aboutDetails(req.About), id.Labels, id.Details)
	}
	g.mu.Lock()
	if keyRefused() {
		g.mu.Unlock()
		g.presented(*id)
		refuseCredential(w)
		return
	}
	if g.used[req.RunID] {
		g.mu.Unlock()
		refuse(w, http.StatusConflict, refusal.RunIDUsed, nil, accesskey.FromGateway, gatewayText(refusal.RunIDUsed))
		return
	}
	if differs != nil {
		g.mu.Unlock()
		refuse(w, http.StatusForbidden, differs.Code, differs.Names, accesskey.FromGateway, gatewayText(differs.Code))
		return
	}
	g.used[req.RunID] = true
	g.mu.Unlock()
	lr, recorded, err := g.open(req, opening{remote: s.remote, id: id, request: r.Context()})
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
				// this machine's before.
				refuse(w, http.StatusConflict, refusal.RunIDUsed, nil, accesskey.FromGateway, gatewayText(refusal.RunIDUsed))
				return
			}
			g.mu.Lock()
			delete(g.used, req.RunID)
			g.mu.Unlock()
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
	if id != nil && g.cfg.opened != nil {
		g.cfg.opened()
	}
	if r.Context().Err() != nil {
		// The session gave up as the run opened.
		g.discard(lr)
		return
	}
	g.mu.Lock()
	g.runs[lr.id] = lr
	g.indexSecret(lr)
	if keyRefused() {
		// The issuer ended a run of the run key while this one opened: it ends at once,
		// among the runs, so Close waits for its record.
		g.mu.Unlock()
		lr.end(endedAtIssuer)
		g.presented(*id)
		refuseCredential(w)
		return
	}
	g.mu.Unlock()
	lr.mu.Lock()
	answer, digest := lr.answer, lr.reloadDigest
	lr.mu.Unlock()
	g.answerHeaders(s, w, r, digest)
	w.Header().Set("Content-Type", server.LinkContentType)
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, answer.reveal())
	if r.Context().Err() != nil {
		// The answer is not sent whole before the handler returns: a session that has
		// gone now never has it.
		g.discard(lr)
		return
	}
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
			delete(g.bySecret, lr.runSecretSum)
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
// without a code, so no 410 from apiary crosses the link.
func refuseOpen(w http.ResponseWriter, err error) {
	err = codeless(err)
	var wall *refusal.NeedsWall
	if errors.As(err, &wall) {
		refuse(w, http.StatusForbidden, refusal.WallRequired, wall.Names, accesskey.FromGateway, err.Error())
		return
	}
	var ref *accesskey.Refusal
	if !errors.As(err, &ref) {
		refuse(w, http.StatusInternalServerError, codeInternal, nil, accesskey.FromGateway, err.Error())
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
	refuse(w, status, ref.Code, ref.Names, from, err.Error())
}

// codeless turns a server's signed 410 to a request the gateway makes as a run opens,
// whatever its code, into the failure without a code a code-less 410 to that request
// is, with its text: a server's 410 ends no run and refuses none. Any other error is
// returned as it is.
func codeless(err error) error {
	var ref *accesskey.Refusal
	if !errors.As(err, &ref) || ref.From != accesskey.FromApiary || ref.Status != http.StatusGone {
		return err
	}
	return fmt.Errorf("%s: status %d", ref.Detail, ref.Status)
}

// codeInternal is the code of a run that failed to open for a reason without one.
const codeInternal = "internal"

// maxMessage is the most characters a refusal's message holds.
const maxMessage = 8192

// message is an error's text as a refusal's message holds it: tab and newline kept,
// every other control character, C0, DEL and C1, a space, at most maxMessage
// characters.
func message(text string) string {
	out := []rune(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\t' && r != '\n' {
			return ' '
		}
		return r
	}, text))
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

// aboutDetails are the about.details a run request sends, as a JSON object decodes;
// nil for none.
func aboutDetails(about *server.About) map[string]any {
	if about == nil || len(about.Details) == 0 {
		return nil
	}
	var out map[string]any
	json.Unmarshal(about.Details, &out)
	return out
}

// indexSecret makes the session's run lr findable by its run secret. Called with g.mu
// held, as the run enters the runs.
func (g *Gateway) indexSecret(lr *linkRun) {
	if lr.runSecret == nil {
		return
	}
	if g.bySecret == nil {
		g.bySecret = map[[sha256.Size]byte]string{}
	}
	g.bySecret[lr.runSecretSum] = lr.id
}

// secretRun is the run id of the session's run whose run secret the request carries in
// X-Qory-Run-Secret, live, ended or let go of; empty when it carries none, more than one,
// or one of no run here. The secret's SHA-256 picks the one candidate, which is compared
// in constant time, in full for a run the gateway still holds. The secret is never
// logged or reported.
func (g *Gateway) secretRun(r *http.Request) string {
	values := r.Header.Values(server.HeaderRunSecret)
	if len(values) != 1 {
		return ""
	}
	presented := []byte(values[0])
	sum := sha256.Sum256(presented)
	g.mu.Lock()
	runID, ok := g.bySecret[sum]
	lr, sp := g.runs[runID], g.spent[runID]
	g.mu.Unlock()
	switch {
	case !ok:
		return ""
	case lr != nil:
		ok = subtle.ConstantTimeCompare([]byte(lr.runSecret.reveal()), presented) == 1
	default:
		ok = subtle.ConstantTimeCompare(sp.secretSum[:], sum[:]) == 1
	}
	if !ok {
		return ""
	}
	return runID
}

// pathRun is the run id of a reload's path, pathID, when the request carries that run's
// secret; empty otherwise, an empty pathID among them, which is no run's.
func (g *Gateway) pathRun(r *http.Request, pathID string) string {
	if runID := g.secretRun(r); runID != "" && runID == pathID {
		return runID
	}
	return ""
}

// localRun is the run of the local link a request names, nil for none: a run of the
// one address is not the local link's.
func (g *Gateway) localRun(runID string) *linkRun {
	g.mu.Lock()
	defer g.mu.Unlock()
	if lr := g.runs[runID]; lr != nil && lr.cred == nil {
		return lr
	}
	return nil
}

// credentialRun is the session's run of runID, the run whose run secret the request
// carries, live or ended, when the run credential a request on the one address carried
// is of its run key; nil when there is none to go on with, an empty runID among them:
// the 410 answered for a run of the run key that the gateway has let go of, and
// otherwise the 401 run_credential_refused, so no run is reached but the one of the run
// credential's run key whose secret the request carries.
func (g *Gateway) credentialRun(w http.ResponseWriter, r *http.Request, runID string) (*linkRun, runIdentity) {
	id, ok := identityOf(r.Context())
	if !ok {
		if late, ok := expiredOf(r.Context()); ok {
			g.endedRun(w, late, runID)
			return nil, late
		}
		refuseCredential(w)
		return nil, id
	}
	k := keyOf(id)
	g.mu.Lock()
	lr := g.runs[runID]
	g.mu.Unlock()
	if lr != nil && lr.cred != nil && !lr.client && lr.cred.key == k {
		return lr, id
	}
	if lr == nil {
		if sp, spent := g.spentOf(runID); spent && sp.key == k {
			g.presented(id)
			gone(w, sp.code, sp.from)
			return nil, id
		}
	}
	g.presented(id)
	refuseCredential(w)
	return nil, id
}

// endedRun answers a request whose run credential's exp has passed: the 410 of the
// session's run of the run id, the one whose run secret the request carries, of its run
// key, when it has ended, live or let go of, and otherwise 401 run_credential_refused.
// Nothing more is served for it.
func (g *Gateway) endedRun(w http.ResponseWriter, id runIdentity, runID string) {
	k := keyOf(id)
	g.keepAgainFor(k)
	g.mu.Lock()
	lr := g.runs[runID]
	g.mu.Unlock()
	switch {
	case lr != nil:
		if code, from, ended := lr.gone(); ended && lr.cred != nil && !lr.client && lr.cred.key == k {
			gone(w, code, from)
			return
		}
	default:
		if sp, spent := g.spentOf(runID); spent && sp.key == k {
			gone(w, sp.code, sp.from)
			return
		}
	}
	refuseCredential(w)
}

// admit decides a request of the run on the one address, after its run is found, by
// the run credential it carries: a run that ended is its 410, the run credential noted
// against its run key when the gateway refuses it; a run of a run key the gateway
// refuses after the issuer's end of another of its runs ends, run_ended_at_issuer, which
// is the 410, the run credential noted; a run credential with a later exp keeps the run
// going until then; and an issuer that no longer holds it active ends the run,
// run_ended_at_issuer, which is the 410. It reports whether the request goes on.
func (lr *linkRun) admit(w http.ResponseWriter, r *http.Request, id runIdentity) bool {
	if code, from, ended := lr.gone(); ended {
		lr.g.presented(id)
		gone(w, code, from)
		return false
	}
	if lr.g.blocked(keyOf(id)) {
		// The issuer ended a run of the run key: every request of a run of it is
		// refused, the run request, a reload, a batch, a client's proxy login and its
		// join, and a live run of it is served no more. The discovery is answered, and
		// opens nothing.
		lr.end(endedAtIssuer)
		lr.g.presented(id)
		code, from, _ := lr.gone()
		gone(w, code, from)
		return false
	}
	if ref := lr.differs(id); ref != nil {
		// A refreshed run credential is of the run's own target and details.
		refuse(w, http.StatusForbidden, ref.Code, ref.Names, accesskey.FromGateway, gatewayText(ref.Code))
		return false
	}
	lr.renew(id)
	if !lr.stillActive(r.Context()) {
		if code, from, ended := lr.gone(); ended {
			gone(w, code, from)
		} else {
			// The request went before the issuer answered.
			refuseCredential(w)
		}
		return false
	}
	return true
}

// reload answers a GET of a run's configuration by its run id, with the run's secret:
// the reload answer as it stands, 410 for a run that ended at the gateway; on the local
// link 400 invalid_request for a run id this gateway holds no run of, or a request
// without that run's secret, and on the one address 401 run_credential_refused for
// either, or a run id that is not the run credential's run.
func (g *Gateway) reload(s *side, w http.ResponseWriter, r *http.Request, runID string) {
	var lr *linkRun
	if s.remote {
		var id runIdentity
		if lr, id = g.credentialRun(w, r, g.pathRun(r, runID)); lr == nil {
			return
		}
		if !lr.admit(w, r, id) {
			return
		}
	} else {
		if lr = g.localRun(g.pathRun(r, runID)); lr == nil {
			invalid(w)
			return
		}
		if code, from, ended := lr.gone(); ended {
			gone(w, code, from)
			return
		}
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

// batch answers one link batch of the run whose secret it carries: 202 when its events
// are numbered; 410 for a run that ended at the gateway; 400 invalid_request for one
// the link refuses, which ends the run: its record says session_lost, and the session's
// later requests are a 410 batch_refused. The run is found before the body is read: a
// batch without a run's secret, or with one of no run here, is 400 invalid_request on
// the local link, and on the one address, as one whose run is not of the run
// credential's run key, 401 run_credential_refused; neither ends a run.
func (g *Gateway) batch(s *side, w http.ResponseWriter, r *http.Request) {
	if !mediaType(r, server.ContentType) {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	var lr *linkRun
	if s.remote {
		var id runIdentity
		if lr, id = g.credentialRun(w, r, g.secretRun(r)); lr == nil {
			return
		}
		lr.batch.Lock()
		defer lr.batch.Unlock()
		if !lr.admit(w, r, id) {
			return
		}
	} else {
		if lr = g.localRun(g.secretRun(r)); lr == nil {
			invalid(w)
			return
		}
		lr.batch.Lock()
		defer lr.batch.Unlock()
		if code, from, ended := lr.gone(); ended {
			gone(w, code, from)
			return
		}
	}
	lr.touch()
	refused := func(why string) {
		g.report(fmt.Sprintf("run %s: the gateway refused a batch of its session's, %s; the run ends, session_lost", lr.id, why))
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
	if _, err := lr.st.Accept(evs); err != nil {
		if code, from, ended := lr.gone(); ended {
			gone(w, code, from)
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
		case event.Ping, event.RunEgress:
			return "an event of a type the gateway writes"
		case event.RunStarted:
			if data["opened_by"] != event.OpenedBySession {
				return "a run.started not opened by the session"
			}
			if data["credential"] != lr.credential() {
				return "a run.started whose credential is not the run's"
			}
			if !sameLabels(data["labels"], lr.labels) {
				return "a run.started whose labels are not the run's"
			}
			if lr.cred != nil && !sameDetails(data["about"], lr.cred.details) {
				return "a run.started whose about.details differ from the run credential's"
			}
			if startedID != "" && startedID != ev.ID {
				return "a second run.started"
			}
			startedID = ev.ID
		case event.RunExited:
			if reason, ok := data["reason"]; ok && reason != event.ReasonTimeout {
				return "a run.exited with a reason the gateway decides"
			}
			final = true
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
		case event.RunExited, event.RunRefused:
			lr.final, final = true, true
		}
	}
	return final
}

// sameDetails reports whether a run.started's about, as its data decodes, holds each
// key of about.details the run credential decides with its value.
func sameDetails(about any, decided map[string]string) bool {
	if len(decided) == 0 {
		return true
	}
	a, _ := about.(map[string]any)
	details, _ := a["details"].(map[string]any)
	for k, want := range decided {
		if v, ok := details[k].(string); !ok || v != want {
			return false
		}
	}
	return true
}

// sameLabels reports whether a run.started's labels, as its data decodes, are the
// run's: absent is none.
func sameLabels(v any, labels map[string]string) bool {
	got, _ := v.(map[string]any)
	if v != nil && got == nil {
		return false
	}
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
