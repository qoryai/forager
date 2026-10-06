// Package receiver is a server of the contract that is not the control plane: the
// receiving side this module's tests run the runner against, and a worked example of
// the contract's receiving rules, which any receiver may read and is tested against
// the same signed fixtures.
//
// A [Handler] serves the three endpoints of the contract: discovery at the well-known
// path, the events endpoint, and the run configuration, the last two where its fields
// say. It accepts the access keys its configuration holds, each a public key, and
// skips enrolment. It answers in the contract's order of refusals: a body over its
// limit, 413; a delivery of another content type, 415; a header the signature depends
// on sent twice, an unsigned 400 bad_request; then verification, the access key id's
// shape before any lookup, the timestamp of a GET within the window, and the Ed25519
// signature over the request string, every failure alike an unsigned 401 with
// {"error":"unauthorized"} and nothing about the headers said or logged. Every answer
// after verification is signed under the receiver's own key and bound to the request
// by its signature: an instance id absent or outside its pattern, 400 bad_request; an
// access key that awaits approval, 409 key_pending; another contract revision, 400
// unsupported_contract_version; a body or query the contract refuses, 400
// invalid_request; then each endpoint's own. A delivery it verified is deduplicated on
// each event's id, handed to a [Store], and answered 202 with the digests in force.
// [File] is a store that appends events to one JSON lines file and remembers the ids
// it holds.
package receiver

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/runner/accesskey"
	"github.com/qoryai/runner/internal/server"
)

// MaxBody is the largest delivery accepted, and the most the handler reads of a body
// before it has verified anything: 2 MiB, twice the mebibyte the contract cuts a batch
// at, so what an unauthenticated sender can make the receiver hold is small.
const MaxBody = 2 << 20

// The default paths of the events endpoint and the run configuration.
const (
	DefaultEventsPath = "/v1/events"
	DefaultRunPath    = "/v1/run-configuration"
)

// timestampShape is a decimal integer, and nothing else.
var timestampShape = regexp.MustCompile(`^[0-9]{1,19}$`)

// Store keeps what a receiver accepted.
type Store interface {
	// Seen reports whether an event id was stored before.
	Seen(id string) bool
	// Append stores one event, given as its JSON line.
	Append(id string, line []byte) error
}

// AccessKey is one access key a receiver accepts: the public key its requests verify
// under, pasted into the receiver's configuration, and whether it awaits approval.
type AccessKey struct {
	PublicKey accesskey.PublicKey
	// Pending says the key awaits approval: its requests verify, and every endpoint
	// answers them with a signed 409 key_pending.
	Pending bool
}

// Handler is the receiving endpoint.
type Handler struct {
	// Keys looks an access key up by its id, once the id's shape is checked: its public
	// key, and whether the key is known and not revoked. Nil knows no key.
	Keys func(accessKeyID string) (AccessKey, bool)
	// Signer is the receiver's own signing key: every answer to a verified request is
	// signed under it, and a runner pins its public key. Nil answers every verified
	// request with an unsigned 500.
	Signer *accesskey.Key
	// Store keeps the events accepted.
	Store Store
	// Now is the receiver's clock; nil means the wall clock.
	Now func() time.Time
	// Window is how far a GET's timestamp may be from Now, either way; zero means
	// the contract's 300 seconds.
	Window time.Duration
	// Configuration answers discovery with the configuration document and the
	// receiver's digest of it. The document lists version, node_id, events and
	// apiary_public_key, the receiver's public key. Nil means discovery is not served.
	Configuration func() (document []byte, digest string)
	// RunConfiguration answers the run configuration for a run's labels, with the
	// receiver's digest of it; ok false means none for them, a 404. Which labels name
	// what the run works on is its to decide: the qory command labels a run in a git
	// checkout with forge and repository, and another caller labels its runs as it
	// likes. The map is every label the request or the run's run.started carried,
	// empty when there were none, and a copy the hook may keep. Nil means the run
	// configuration is not served.
	RunConfiguration func(labels map[string]string) (document []byte, digest string, ok bool)
	// EventsPath and RunPath are where the events endpoint and the run configuration
	// are served; empty means DefaultEventsPath and DefaultRunPath.
	EventsPath, RunPath string
	// Log receives one line per delivery, and may be nil. It never sees a header.
	Log func(string)
	// Stop, when set, is called per run id to learn whether the receiver wants nothing
	// more; true is a signed 410 without a code, after which the runner sends no
	// further batch and its run goes on. Nil means never.
	Stop func(runID string) bool
	// Closed, when set, is called per run id to learn whether the receiver has closed
	// the run; true is a signed 410 run_closed, which ends the run. Nil means never.
	Closed func(runID string) bool
	// Admit, when set, is called for a ping to learn whether the instance may start a
	// run; false is a signed 409 instance_limit, and the run does not start. Nil
	// admits every instance.
	Admit func(accessKeyID, instanceID string) bool

	// labels are the labels of each run whose run.started passed, so an answer to a
	// later delivery says which run configuration is in force for it.
	mu     sync.Mutex
	labels map[string]map[string]string
}

// verified is a request that verified: its access key and the signature an answer is
// bound to.
type verified struct {
	key       AccessKey
	signature string
}

// ServeHTTP routes one request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	events, run := h.EventsPath, h.RunPath
	if events == "" {
		events = DefaultEventsPath
	}
	if run == "" {
		run = DefaultRunPath
	}
	var method string
	switch {
	case r.URL.Path == server.WellKnown && h.Configuration != nil:
		method = http.MethodGet
	case r.URL.Path == run && h.RunConfiguration != nil:
		method = http.MethodGet
	case r.URL.Path == events:
		method = http.MethodPost
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
	if method == http.MethodPost {
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), server.ContentType) {
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
	case v.key.Pending:
		h.refuseSigned(w, v, http.StatusConflict, "key_pending")
	case r.Header.Get(server.HeaderContractVersion) != strconv.Itoa(server.Revision):
		h.refuseSigned(w, v, http.StatusBadRequest, "unsupported_contract_version")
	case r.URL.Path == server.WellKnown:
		doc, digest := h.Configuration()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(server.HeaderConfiguration, digest)
		h.answer(w, v, http.StatusOK, doc)
	case r.URL.Path == run:
		labels, err := queryLabels(r.URL.RawQuery)
		if err != nil {
			h.refuseSigned(w, v, http.StatusBadRequest, "invalid_request")
			return
		}
		doc, digest, ok := h.RunConfiguration(labels)
		if !ok {
			h.answer(w, v, http.StatusNotFound, nil)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(server.HeaderRunConfiguration, digest)
		w.Header().Set("ETag", strconv.Quote(digest))
		h.answer(w, v, http.StatusOK, doc)
	default:
		h.deliver(w, r, v, body)
	}
}

// queryLabels reads a run configuration request's query as the run's labels, every
// parameter one label, and refuses what is not: a query that does not parse, a key sent
// twice, and what the labels of a run may not be.
func queryLabels(raw string) (map[string]string, error) {
	q, err := url.ParseQuery(raw)
	if err != nil {
		return nil, err
	}
	labels := make(map[string]string, len(q))
	for k, vs := range q {
		if len(vs) != 1 {
			return nil, fmt.Errorf("the label %q is sent %d times", k, len(vs))
		}
		labels[k] = vs[0]
	}
	if err := server.CheckLabels(labels); err != nil {
		return nil, err
	}
	return labels, nil
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
// which the lookup is asked for only then, a key it knows, for a GET a timestamp
// within the window, and the Ed25519 signature over the request string under the key's
// public key. The request string's instance line is the header as sent, empty when it
// is absent; the target is the request-target as sent.
func (h *Handler) verify(r *http.Request, body []byte) (verified, bool) {
	id, sig := r.Header.Get(server.HeaderAccessKeyID), r.Header.Get(server.HeaderSignature)
	if id == "" || sig == "" || accesskey.CheckID(id) != nil || h.Keys == nil {
		return verified{}, false
	}
	key, ok := h.Keys(id)
	if !ok {
		return verified{}, false
	}
	target := r.RequestURI
	if target == "" {
		target = r.URL.RequestURI()
	}
	req := accesskey.Request{AccessKeyID: id, InstanceID: r.Header.Get(server.HeaderInstanceID), Method: r.Method, Target: target}
	if r.Method == http.MethodPost {
		req.Body = body
	} else {
		ts := r.Header.Get(server.HeaderTimestamp)
		if !h.fresh(ts) {
			return verified{}, false
		}
		req.Timestamp = ts
	}
	if !key.PublicKey.VerifyRequest(req, sig) {
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
	Data    struct {
		Labels map[string]string `json:"labels"`
	} `json:"data"`
}

// deliver answers one verified delivery, in the events endpoint's order: a batch that
// is not one, 400 invalid_request; one whose events the store holds every one of,
// 202 again; an event of a run the receiver closed, 410 run_closed; of a run it wants
// nothing more of, 410; a ping from an instance it does not admit, 409
// instance_limit; otherwise each new event stored and 202.
func (h *Handler) deliver(w http.ResponseWriter, r *http.Request, v verified, body []byte) {
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
	if fresh {
		if h.Closed != nil && h.Closed(subject) {
			h.digests(w, subject)
			h.refuseSigned(w, v, http.StatusGone, "run_closed")
			return
		}
		if h.Stop != nil && h.Stop(subject) {
			h.digests(w, subject)
			h.answer(w, v, http.StatusGone, nil)
			return
		}
		if len(heads) == 1 && heads[0].Type == "dev.qory.ping" && h.Admit != nil && !h.Admit(r.Header.Get(server.HeaderAccessKeyID), r.Header.Get(server.HeaderInstanceID)) {
			h.refuseSigned(w, v, http.StatusConflict, "instance_limit")
			return
		}
	}
	stored, dup := 0, 0
	for i, raw := range batch {
		hd := heads[i]
		if hd.Type == "dev.qory.run.started" {
			h.mu.Lock()
			if h.labels == nil {
				h.labels = map[string]map[string]string{}
			}
			h.labels[hd.Subject] = hd.Data.Labels
			h.mu.Unlock()
		}
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
// configuration's for the run's labels as its run.started said, none when the receiver
// has not seen it. The answer's signature covers both.
func (h *Handler) digests(w http.ResponseWriter, runID string) {
	if h.Configuration != nil {
		_, digest := h.Configuration()
		w.Header().Set(server.HeaderConfiguration, digest)
	}
	if h.RunConfiguration != nil {
		h.mu.Lock()
		labels := maps.Clone(h.labels[runID])
		h.mu.Unlock()
		if labels == nil {
			labels = map[string]string{}
		}
		if _, digest, ok := h.RunConfiguration(labels); ok {
			w.Header().Set(server.HeaderRunConfiguration, digest)
		}
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
