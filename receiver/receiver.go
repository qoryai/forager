// Package receiver is a server of the contract that is not the control plane: the
// receiving side this module's tests run Forager against, and a worked example of
// the contract's receiving rules, which any receiver may read and is tested against
// the same signed fixtures.
//
// A [Handler] serves the endpoints of the contract: discovery at the well-known path,
// the run endpoint, where a run registers with a POST and is reloaded by its id with a
// GET of the run endpoint, a slash and the run id, and the events endpoint, the last
// two where its fields say. It accepts the access keys its configuration holds, each a
// public key, and skips enrolment. It answers in the contract's order of refusals: a
// body over its limit, 413; a POST of another content type, application/json for a
// registration and application/cloudevents-batch+json for a batch, 415; a header the
// signature depends on sent twice, an unsigned 400 bad_request; then verification, the
// access key id's shape before any lookup and the Ed25519 signature over the request
// string, every failure alike an unsigned 401 with {"error":"unauthorized"} and nothing
// about the headers said or logged. Every answer after verification but a 401 is signed
// under the receiver's own key and bound to the request by its signature: an instance
// id absent or outside its pattern, 400 bad_request; another contract revision, 400
// unsupported_contract_version; a body the contract refuses, 400 invalid_request; a
// GET's timestamp or a registration's time outside the window, the unsigned 401; then
// each endpoint's own.
//
// The run endpoint keeps every registration it accepted by its run id, with the
// answer it gave, holding a SHA-256 of each body rather than the body: the same bytes
// under the same access key get that answer again, and the same run id under another
// access key, even with the same bytes, or other bytes, a signed 409 run_id_used. A run the receiver wants nothing more of is a
// signed 410, and a new instance it does not admit a signed 409 instance_limit. The
// [Handler.RunConfiguration] hook is handed each run's id, labels and about, and returns
// its run configuration or refuses the run; without it every run gets {"version":1}, no
// policy. A reload is answered only for a run the same access key registered, a signed
// 404 otherwise. A delivery it
// verified is deduplicated on each event's id, handed to a [Store], and answered 202
// with the digests in force; it reads nothing of an event's data. [File] is a store that
// appends events to one JSON lines file and remembers the ids it holds. It keeps one
// store and one table of runs for every access key alike, as a test needs; a server of
// many access keys scopes event ids per access key, so one key's events never
// deduplicate another's.
package receiver

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/server"
)

// MaxBody is the largest request body accepted, and the most the handler reads of a
// body before it has verified anything: 2 MiB, twice the mebibyte the contract cuts a
// batch at, so what an unauthenticated sender can make the receiver hold is small.
const MaxBody = 2 << 20

// The default paths of the events endpoint and the run endpoint.
const (
	DefaultEventsPath = "/v1/events"
	DefaultRunPath    = "/v1/runs"
)

// RegistrationType is the content type of a run's registration.
const RegistrationType = "application/json"

// NoPolicy is the run configuration of no policy, which a run gets when the handler
// has no RunConfiguration hook.
var NoPolicy = []byte(`{"version":1}`)

// unknownKey is the public key a request under an access key id the lookup does not
// hold is verified under: a fixed public key, of the zero seed, used only so such a
// request spends the time a known one does. The request is refused whatever the
// verification says.
var unknownKey = func() accesskey.PublicKey {
	k, err := accesskey.NewKey(make([]byte, accesskey.SeedSize))
	if err != nil {
		panic(err)
	}
	return k.PublicKey()
}()

// timestampShape is a decimal integer, and nothing else.
var timestampShape = regexp.MustCompile(`^[0-9]{1,19}$`)

// runIDShape is a run id in the canonical lower-case form.
var runIDShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// registrationSchema is run-registration.schema.json, compiled once.
var registrationSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	return contracts.Compile("run-registration.schema.json")
})

// Store keeps what a receiver accepted.
type Store interface {
	// Seen reports whether an event id was stored before.
	Seen(id string) bool
	// Append stores one event, given as its JSON line.
	Append(id string, line []byte) error
}

// AccessKey is one access key a receiver accepts: the public key its requests verify
// under, listed in the receiver's configuration. A public key
// [accesskey.PublicKey.Check] refuses verifies no request.
type AccessKey struct {
	PublicKey accesskey.PublicKey
}

// Run is a run as its registration named it, what the RunConfiguration hook decides
// on.
type Run struct {
	// AccessKeyID and InstanceID are the registration's, as its signed lines carry
	// them.
	AccessKeyID, InstanceID string
	// ID is the run id.
	ID string
	// Labels are the run's labels, empty when the registration sent none; a copy the
	// hook may keep.
	Labels map[string]string
	// About is what the run is about, as the registration sent it, nil when it sent
	// none. It is for display: it never selects or changes a security policy.
	About json.RawMessage
}

// Refusal is the hook's refusal of a run: a signed answer of Status, such as 409 or
// 410, with the Code in a coded refusal's body, or no body when the Code is empty.
type Refusal struct {
	Status int
	Code   string
}

// Handler is the receiving endpoint.
type Handler struct {
	// Keys looks an access key up by its id, once the id's shape is checked: its public
	// key, and whether the key is known and not revoked. Nil knows no key.
	Keys func(accessKeyID string) (AccessKey, bool)
	// Signer is the receiver's own signing key: every answer to a verified request is
	// signed under it, and Forager pins its public key. Nil answers every verified
	// request with an unsigned 500.
	Signer *accesskey.Key
	// Store keeps the events accepted.
	Store Store
	// Now is the receiver's clock; nil means the wall clock.
	Now func() time.Time
	// Window is how far a GET's timestamp, or a registration's time, may be from Now,
	// either way; zero means the contract's 300 seconds.
	Window time.Duration
	// Configuration answers discovery with the configuration document and the
	// receiver's digest of it. The document lists version, node_id, events, run, whose
	// url is the run endpoint, and apiary_public_key, the receiver's public key. Nil
	// means discovery is not served.
	Configuration func() (document []byte, digest string)
	// RunConfiguration decides the run configuration of a run: as it registers, as it
	// is reloaded by its id, and for the digest every answer to a delivery of the run
	// carries. It returns the document and the receiver's digest of it, an empty digest
	// meaning sha256= and the hex SHA-256 of the document, or a refusal. Which labels
	// name what the run works on is its to decide: the qory command labels a run in a
	// git checkout with forge and repository, and another caller labels its runs as it
	// likes. About never selects or changes a security policy. Nil gives every run
	// NoPolicy.
	RunConfiguration func(run Run) (document []byte, digest string, refusal *Refusal)
	// EventsPath and RunPath are where the events endpoint and the run endpoint are
	// served; empty means DefaultEventsPath and DefaultRunPath.
	EventsPath, RunPath string
	// Log receives one line per delivery, and may be nil. It never sees a header.
	Log func(string)
	// Stop, when set, is called per run id to learn whether the receiver wants nothing
	// more; true is a signed 410 without a code: to a registration, no run; to a reload
	// or a delivery, Forager sends no further batch and its run goes on. Nil means
	// never.
	Stop func(runID string) bool
	// Admit, when set, is called for every registration but one the receiver accepted
	// with the same bytes under the same access key, to learn whether the instance may
	// start a run; false is a signed 409 instance_limit, and the run does not start. It
	// is not called for a registration refused earlier in the order, a body the contract
	// refuses or a time outside the window, nor for one Stop refuses. Nil admits every
	// instance.
	Admit func(accessKeyID, instanceID string) bool

	// runs are the registrations accepted, by run id.
	mu   sync.Mutex
	runs map[string]*registration
}

// registration is a registration the receiver accepted: the SHA-256 of its bytes, the
// run they name, and the answer it gave.
type registration struct {
	sum      [sha256.Size]byte
	run      Run
	document []byte
	digest   string
}

// verified is a request that verified: its access key and the signature an answer is
// bound to.
type verified struct {
	key       AccessKey
	signature string
}

// The endpoints a request may be for.
const (
	toDiscovery = iota
	toRegistration
	toReload
	toEvents
)

// ServeHTTP routes one request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	events, run := h.EventsPath, h.RunPath
	if events == "" {
		events = DefaultEventsPath
	}
	if run == "" {
		run = DefaultRunPath
	}
	var to int
	var method, runID string
	switch rest, reload := strings.CutPrefix(r.URL.Path, run+"/"); {
	case r.URL.Path == server.WellKnown && h.Configuration != nil:
		to, method = toDiscovery, http.MethodGet
	case r.URL.Path == run:
		to, method = toRegistration, http.MethodPost
	case reload && runIDShape.MatchString(rest):
		to, method, runID = toReload, http.MethodGet, rest
	case r.URL.Path == events:
		to, method = toEvents, http.MethodPost
	default:
		http.NotFound(w, r)
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		http.Error(w, method+" is the method here", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		refuse(w, http.StatusRequestEntityTooLarge, "")
		return
	}
	if want := map[int]string{toRegistration: RegistrationType, toEvents: server.ContentType}[to]; want != "" {
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != want {
			refuse(w, http.StatusUnsupportedMediaType, "")
			return
		}
	}
	for _, name := range []string{server.HeaderAccessKeyID, server.HeaderInstanceID, server.HeaderSignature, server.HeaderTimestamp} {
		if len(r.Header.Values(name)) > 1 {
			refuse(w, http.StatusBadRequest, "bad_request")
			return
		}
	}
	v, ok := h.verify(r, body)
	if !ok {
		refuse(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.Signer == nil {
		refuse(w, http.StatusInternalServerError, "")
		return
	}
	switch {
	case accesskey.CheckInstanceID(r.Header.Get(server.HeaderInstanceID)) != nil:
		h.refuseSigned(w, v, http.StatusBadRequest, "bad_request")
	case r.Header.Get(server.HeaderContractVersion) != strconv.Itoa(server.Revision):
		h.refuseSigned(w, v, http.StatusBadRequest, "unsupported_contract_version")
	case to == toRegistration:
		h.register(w, r, v, body)
	case to == toEvents:
		h.deliver(w, v, body)
	case !h.fresh(r.Header.Get(server.HeaderTimestamp)):
		refuse(w, http.StatusUnauthorized, "unauthorized")
	case to == toDiscovery:
		doc, digest := h.Configuration()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(server.HeaderConfiguration, digest)
		h.answer(w, v, http.StatusOK, doc)
	default:
		h.reload(w, r, v, runID)
	}
}

// registrationBody is what the receiver reads of a registration's body, once the
// schema passed it.
type registrationBody struct {
	RunID  string            `json:"run_id"`
	Labels map[string]string `json:"labels"`
	About  json.RawMessage   `json:"about"`
	Time   string            `json:"time"`
}

// readRegistration reads a registration's body and refuses what the contract refuses:
// a body the schema refuses, interval_seconds over 300 among it, labels or an about
// outside the rules the schema cannot state: a label value over 256 bytes of UTF-8,
// which the schema's maxLength, counting characters, lets through, among them. A time that is no date is refused by the
// caller.
func readRegistration(body []byte) (*registrationBody, error) {
	schema, err := registrationSchema()
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(doc); err != nil {
		return nil, err
	}
	var reg registrationBody
	if err := json.Unmarshal(body, &reg); err != nil {
		return nil, err
	}
	if err := server.CheckLabels(reg.Labels); err != nil {
		return nil, err
	}
	if reg.About != nil {
		dec := json.NewDecoder(bytes.NewReader(reg.About))
		dec.DisallowUnknownFields()
		var a server.About
		if err := dec.Decode(&a); err != nil {
			return nil, err
		}
		if err := server.CheckAbout(&a); err != nil {
			return nil, err
		}
	}
	return &reg, nil
}

// register answers one verified registration, in the run endpoint's order: a body the
// contract refuses, 400 invalid_request; a time outside the window, the unsigned 401;
// a run id it accepted with the same bytes under the same access key, the same answer
// again; a run it wants nothing more of, 410; a new instance it does not admit, 409
// instance_limit; a run id it accepted under another access key, even with the same
// bytes, or with other bytes, 409 run_id_used; then the
// hook's refusal, or the run configuration, kept with the registration and answered
// 200.
func (h *Handler) register(w http.ResponseWriter, r *http.Request, v verified, body []byte) {
	reg, err := readRegistration(body)
	var at time.Time
	if err == nil {
		at, err = time.Parse(time.RFC3339, reg.Time)
	}
	if err != nil {
		h.refuseSigned(w, v, http.StatusBadRequest, "invalid_request")
		return
	}
	if !h.within(at.Unix()) {
		refuse(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	run := Run{AccessKeyID: r.Header.Get(server.HeaderAccessKeyID), InstanceID: r.Header.Get(server.HeaderInstanceID),
		ID: reg.RunID, Labels: reg.Labels, About: reg.About}
	if run.Labels == nil {
		run.Labels = map[string]string{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	sum := sha256.Sum256(body)
	prev := h.runs[run.ID]
	if prev != nil && prev.run.AccessKeyID == run.AccessKeyID && prev.sum == sum {
		h.answerRun(w, v, prev.document, prev.digest)
		return
	}
	if h.Stop != nil && h.Stop(run.ID) {
		h.answer(w, v, http.StatusGone, nil)
		return
	}
	if h.Admit != nil && !h.Admit(run.AccessKeyID, run.InstanceID) {
		h.refuseSigned(w, v, http.StatusConflict, "instance_limit")
		return
	}
	if prev != nil {
		h.refuseSigned(w, v, http.StatusConflict, "run_id_used")
		return
	}
	doc, digest, refusal := h.runConfiguration(run)
	if refusal != nil {
		h.refuseRun(w, v, refusal)
		return
	}
	if h.runs == nil {
		h.runs = map[string]*registration{}
	}
	h.runs[run.ID] = &registration{sum: sum, run: run, document: doc, digest: digest}
	h.answerRun(w, v, doc, digest)
}

// reload answers one verified reload of a run's configuration by its id: a run not
// registered under the request's access key, 404; a run it wants nothing more of, 410;
// the hook's refusal; otherwise the run configuration, 200.
func (h *Handler) reload(w http.ResponseWriter, r *http.Request, v verified, runID string) {
	h.mu.Lock()
	reg := h.runs[runID]
	h.mu.Unlock()
	if reg == nil || reg.run.AccessKeyID != r.Header.Get(server.HeaderAccessKeyID) {
		h.answer(w, v, http.StatusNotFound, nil)
		return
	}
	if h.Stop != nil && h.Stop(runID) {
		h.answer(w, v, http.StatusGone, nil)
		return
	}
	doc, digest, refusal := h.runConfiguration(reg.run)
	if refusal != nil {
		h.refuseRun(w, v, refusal)
		return
	}
	h.answerRun(w, v, doc, digest)
}

// runConfiguration asks the hook for a run's configuration, with a copy of its labels,
// and makes the digest of a document the hook gave none: NoPolicy without a hook.
func (h *Handler) runConfiguration(run Run) ([]byte, string, *Refusal) {
	doc, digest := NoPolicy, ""
	if h.RunConfiguration != nil {
		run.Labels = cloneLabels(run.Labels)
		var refusal *Refusal
		if doc, digest, refusal = h.RunConfiguration(run); refusal != nil {
			return nil, "", refusal
		}
	}
	if digest == "" {
		sum := sha256.Sum256(doc)
		digest = "sha256=" + hex.EncodeToString(sum[:])
	}
	return doc, digest, nil
}

func cloneLabels(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		out[k] = v
	}
	return out
}

// answerRun answers a run configuration: a signed 200, application/json, with
// X-Qory-Run-Configuration and the same digest quoted as the ETag.
func (h *Handler) answerRun(w http.ResponseWriter, v verified, doc []byte, digest string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(server.HeaderRunConfiguration, digest)
	w.Header().Set("ETag", strconv.Quote(digest))
	h.answer(w, v, http.StatusOK, doc)
}

// refuseRun answers the hook's refusal, signed: with its code, or no body without one.
func (h *Handler) refuseRun(w http.ResponseWriter, v verified, refusal *Refusal) {
	if refusal.Code == "" {
		h.answer(w, v, refusal.Status, nil)
		return
	}
	h.refuseSigned(w, v, refusal.Status, refusal.Code)
}

// refuse answers before verification, or with a 401, unsigned: with the code in a
// coded refusal's body when there is one.
func refuse(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if code != "" {
		io.WriteString(w, `{"error":"`+code+`"}`)
	}
}

// refuseSigned answers a verified request with a coded refusal, signed.
func (h *Handler) refuseSigned(w http.ResponseWriter, v verified, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	h.answer(w, v, status, []byte(`{"error":"`+code+`"}`))
}

// answer writes a signed answer: the signature under the receiver's key over the
// status, the request's signature, the body and the digest headers already set, and
// Cache-Control: no-store, no-transform, so no cache keeps it and no proxy re-codes it.
func (h *Handler) answer(w http.ResponseWriter, v verified, status int, body []byte) {
	a := accesskey.Answer{Status: status, RequestSignature: v.signature, Body: body,
		Configuration: w.Header().Get(server.HeaderConfiguration), RunConfiguration: w.Header().Get(server.HeaderRunConfiguration)}
	w.Header().Set("Cache-Control", "no-store, no-transform")
	w.Header().Set(server.HeaderSignature, h.Signer.SignAnswer(a))
	w.WriteHeader(status)
	w.Write(body)
}

// verify reports whether the request verifies: an access key id of the right shape,
// which is looked up only then, a key the lookup holds, and the Ed25519 signature over
// the request string under the key's public key. The request string's instance line is
// the header as sent, empty when it is absent; the target is the request-target as
// sent. A GET's timestamp and a registration's time are checked against the window
// later, in the contract's order of refusals.
func (h *Handler) verify(r *http.Request, body []byte) (verified, bool) {
	id, sig := r.Header.Get(server.HeaderAccessKeyID), r.Header.Get(server.HeaderSignature)
	if id == "" || sig == "" || accesskey.CheckID(id) != nil || h.Keys == nil {
		return verified{}, false
	}
	key, ok := h.Keys(id)
	if !ok {
		// An unknown access key costs what a known one does, so the time of a 401
		// says nothing of which access key ids exist.
		key = AccessKey{PublicKey: unknownKey}
	}
	target := r.RequestURI
	if target == "" {
		target = r.URL.RequestURI()
	}
	req := accesskey.Request{AccessKeyID: id, InstanceID: r.Header.Get(server.HeaderInstanceID), Method: r.Method, Target: target}
	if r.Method == http.MethodPost {
		req.Body = body
	} else {
		req.Timestamp = r.Header.Get(server.HeaderTimestamp)
	}
	if !key.PublicKey.VerifyRequest(req, sig) || !ok {
		return verified{}, false
	}
	return verified{key: key, signature: sig}, true
}

// fresh reports whether a GET's timestamp is a decimal integer within the window of
// the receiver's clock, either way.
func (h *Handler) fresh(ts string) bool {
	if !timestampShape.MatchString(ts) {
		return false
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	return h.within(n)
}

// within reports whether a moment, in Unix seconds, is within the window of the
// receiver's clock, either way.
func (h *Handler) within(n int64) bool {
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	window := h.Window
	if window == 0 {
		window = server.Window
	}
	d := now().Unix() - n
	return d <= int64(window/time.Second) && -d <= int64(window/time.Second)
}

// head is what the receiver reads of each event of a batch.
type head struct {
	ID      string `json:"id"`
	Subject string `json:"subject"`
	Type    string `json:"type"`
}

// deliver answers one verified delivery, in the events endpoint's order: a batch that
// is not one, 400 invalid_request; one whose events the store holds every one of, 202
// again; an event of a run it wants nothing more of, 410; otherwise each new event
// stored and 202.
func (h *Handler) deliver(w http.ResponseWriter, v verified, body []byte) {
	var batch []json.RawMessage
	if err := json.Unmarshal(body, &batch); err != nil || len(batch) == 0 {
		h.refuseSigned(w, v, http.StatusBadRequest, "invalid_request")
		return
	}
	heads := make([]head, len(batch))
	fresh := false
	for i, raw := range batch {
		if err := json.Unmarshal(raw, &heads[i]); err != nil || heads[i].ID == "" || heads[i].Subject == "" || heads[i].Type == "" {
			h.refuseSigned(w, v, http.StatusBadRequest, "invalid_request")
			return
		}
		if !h.Store.Seen(heads[i].ID) {
			fresh = true
		}
	}
	subject := heads[len(heads)-1].Subject
	if fresh && h.Stop != nil && h.Stop(subject) {
		h.digests(w, subject)
		h.answer(w, v, http.StatusGone, nil)
		return
	}
	stored, dup := 0, 0
	for i, raw := range batch {
		hd := heads[i]
		if h.Store.Seen(hd.ID) {
			dup++
			continue
		}
		if err := h.Store.Append(hd.ID, raw); err != nil {
			h.answer(w, v, http.StatusInternalServerError, nil)
			return
		}
		stored++
	}
	if h.Log != nil {
		h.Log("delivery for run " + subject + ": " + itoa(stored) + " stored, " + itoa(dup) + " duplicates")
	}
	h.digests(w, subject)
	h.answer(w, v, http.StatusAccepted, nil)
}

// digests sets on an answer the digests in force: the configuration's, and the run
// configuration's for the run as it registered, none when the receiver holds no
// registration of it or the hook refuses it now. The answer's signature covers both.
func (h *Handler) digests(w http.ResponseWriter, runID string) {
	if h.Configuration != nil {
		_, digest := h.Configuration()
		w.Header().Set(server.HeaderConfiguration, digest)
	}
	h.mu.Lock()
	reg := h.runs[runID]
	h.mu.Unlock()
	if reg == nil {
		return
	}
	if _, digest, refusal := h.runConfiguration(reg.run); refusal == nil {
		w.Header().Set(server.HeaderRunConfiguration, digest)
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// File is a store appending to one JSON lines file.
type File struct {
	mu   sync.Mutex
	f    *os.File
	seen map[string]bool
}

// OpenFile opens or creates the file and reads the ids it already holds, so a
// restarted receiver still deduplicates.
func OpenFile(path string) (*File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	s := bufio.NewScanner(f)
	s.Buffer(nil, MaxBody)
	for s.Scan() {
		var head struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(s.Bytes(), &head) == nil && head.ID != "" {
			seen[head.ID] = true
		}
	}
	if err := s.Err(); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, err
	}
	return &File{f: f, seen: seen}, nil
}

// Seen reports whether the id was stored.
func (s *File) Seen(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[id]
}

// Append writes the line and remembers the id.
func (s *File) Append(id string, line []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(append(append([]byte(nil), line...), '\n')); err != nil {
		return err
	}
	s.seen[id] = true
	return nil
}

// Count is how many events the store holds.
func (s *File) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// Close syncs and closes the file.
func (s *File) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return errors.Join(s.f.Sync(), s.f.Close())
}
