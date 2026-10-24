// Package receiver is a server of the contract that is not the control plane: the
// receiving side this module's tests run Forager against, and a worked example of
// the contract's receiving rules, which any receiver may read and is tested against
// the same signed fixtures.
//
// A [Handler] serves the endpoints of the contract: discovery at the well-known path,
// the run endpoint, where a run registers with a POST, is reloaded by its id with a GET
// of the run endpoint, a slash and the run id, is attached by its gateway with a POST
// of the run endpoint, the run id and /attach, and is given its starter's outcome with
// a POST of the run endpoint, the run id and /outcome, the events endpoint, and the
// secrets endpoint, the last three where its fields say. It accepts the access keys its
// configuration holds, each a public key, the node, node pool or gateway it belongs to
// and whether it is allowed stored secrets, and skips enrolment. It answers in the
// contract's order of refusals: a body over its limit, 413, 32 KiB for a secrets
// request; a POST of another content type, application/json for a registration, an
// attach, an outcome and a secrets request and application/cloudevents-batch+json for a
// batch, 415; a header the signature depends on sent twice, an unsigned 400
// bad_request; then verification, the access key id's shape before any lookup and the
// Ed25519 signature over the request string, every failure alike an unsigned 401 with
// {"error":"unauthorized"} and nothing about the headers said or logged. Every answer
// after verification but a 401 is signed under the receiver's own key and bound to the
// request by its signature: an instance id absent or outside its pattern, 400
// bad_request; another contract revision, 400 unsupported_contract_version; a body the
// contract refuses, 400 invalid_request; a GET's timestamp or a POST's time outside the
// window, the unsigned 401; then each endpoint's own.
//
// Discovery answers each access key with the key's node: Configuration's document, with
// node_id that of the key's record, workspaces a node's or node pool's one workspace,
// no workspaces for a gateway's key, and no secrets for a key not allowed stored
// secrets. The run endpoint resolves each registration's gateway from the record of the
// registering key's node or node pool, never from the body: Direct, Default, the
// workspace's default gateway, else its organisation's, or a named gateway, ng_. It
// keeps every registration it accepted by its run id, with the answer it gave, holding
// a SHA-256 of each body rather than the body: the same bytes under any active key of
// the same node get that answer again; a run the receiver wants nothing more of is a
// signed 410; a gateway's own key, a signed 409 gateway_key; a body whose shape does
// not match the node's resolved choice, node_is_direct or node_uses_gateway; a choice
// that resolves to no gateway, no_default_gateway, gateway_not_serving or
// gateway_without_key; a new instance it does not admit, instance_limit; and the same
// run id from another node, even with the same bytes, or other bytes, run_id_used. A
// direct run is answered its run configuration; a run through a gateway its run key,
// signed under the receiver's key, which the gateway it names attaches with. The
// [Handler.RunConfiguration] hook is handed each run's id, labels, about and placement,
// and returns its run configuration or refuses the run; without it every run gets
// {"version":1}, no policy. A run's reloads and batches are accepted from one node
// alone, under any of its active keys: the node that registered a direct run, or the
// gateway node that attached a run through a gateway, that run's reloads from the
// instance id its attach was signed with alone, and its batches from that instance too
// while the run is live; a reload from another is a signed 404, and a batch a signed
// 409 wrong_node or wrong_gateway. Once a run through a gateway is not live, its
// dev.qory.run.exited accepted or its heartbeats gone quiet, a batch from any instance
// of the attaching gateway node gets the answer the attaching instance would, and only
// the attaching instance's heartbeat makes the run live again; until then, the
// starter's outcome alone changes nothing of who may send. The starter's outcome is
// accepted from any active key of the registering node, once per run, and every 2xx to
// a batch of the run then carries it as the end member until the batch that carries the
// run's dev.qory.run.exited. A batch whose events are not all of one run is a signed
// 400 invalid_request. A delivery it verified is deduplicated on each event's id,
// handed to a [Store], and answered 202 with the digests in force; it reads nothing of
// an event's data but a heartbeat's time and the type. [File] is a store that appends
// events to one JSON lines file and remembers the ids it holds. It keeps one store and
// one table of runs for every access key alike, as a test needs; a server of many
// access keys scopes event ids per access key, so one key's events never deduplicate
// another's.
//
// The receiver computes every run configuration's digest from the bytes it serves:
// sha256= and the lower-case hex SHA-256. The secrets endpoint, served when
// [Handler.Secrets] is set, answers a run's secrets request, which only a key allowed
// stored secrets, [AccessKey.StoredSecrets], finds in its discovery: after the shared
// order, a body the contract refuses, 400 invalid_request, and a timestamp outside the
// window, the unsigned 401, a key not allowed is a signed 409 secrets_not_allowed; then
// the request is answered as a reload of the run is; a digest that is not that of the
// run configuration in force, or not one the run was answered with, is a signed 410
// run_configuration_superseded; and a credentials list that is not some of that run
// configuration's names, in its order, each once, a signed 409 credentials_differ: a
// renewal lists the names that are due. Otherwise the hook's values, with their
// expires_at and apply, are sealed to the requesting access key with [sealed.Seal], signed
// under the receiver's key and answered 200, and the receiver overwrites them with
// zeros. No value is logged or stored.
package receiver

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/sealed"
	"github.com/qoryai/forager/server"
)

// MaxBody is the largest request body accepted, and the most the handler reads of a
// body before it has verified anything: 2 MiB, twice the mebibyte the contract cuts a
// batch at, so what an unauthenticated sender can make the receiver hold is small.
const MaxBody = 2 << 20

// The default paths of the events endpoint, the run endpoint and the secrets endpoint.
const (
	DefaultEventsPath  = "/v1/events"
	DefaultRunPath     = "/v1/runs"
	DefaultSecretsPath = "/v1/secrets"
)

// MaxSecretsBody is the largest secrets request body accepted: 32 KiB, the contract's
// bound.
const MaxSecretsBody = 32 << 10

// RegistrationType is the content type of a run's registration, its attach, its
// outcome and a secrets request.
const RegistrationType = "application/json"

// NoPolicy is the run configuration of no policy, which a run gets when the handler
// has no RunConfiguration hook.
var NoPolicy = []byte(`{"version":1}`)

// The choices of a node or node pool, beside a named gateway, ng_: it reports
// directly, or through its workspace's default gateway, else its organisation's.
const (
	Direct  = "direct"
	Default = "default"
)

// The attach window of a registration through a gateway: AttachWindow when it asks for
// none, and AttachCeiling at most, a longer one clamped to it. The run key's attach_by
// states the window granted.
const (
	AttachWindow  = 600 * time.Second
	AttachCeiling = 3600 * time.Second
)

// heartbeatTolerance is how much later than its own time, corrected by the run's clock
// offset, a heartbeat counts as recent.
const heartbeatTolerance = 300 * time.Second

// gatewayPrefix starts a gateway's id.
const gatewayPrefix = "ng_"

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

// The schemas of the bodies the run endpoint reads, each compiled once.
var (
	registrationSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
		return contracts.Compile("run-registration.schema.json")
	})
	attachSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
		return contracts.Compile("run-attach.schema.json")
	})
	outcomeSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
		return contracts.Compile("run-outcome.schema.json")
	})
	secretsSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
		return contracts.Compile("secrets-request.schema.json")
	})
)

// Store keeps what a receiver accepted.
type Store interface {
	// Seen reports whether an event id was stored before.
	Seen(id string) bool
	// Append stores one event, given as its JSON line.
	Append(id string, line []byte) error
}

// AccessKey is one access key a receiver accepts: the public key its requests verify
// under, listed in the receiver's configuration, and what it belongs to. A public key
// [accesskey.PublicKey.Check] refuses verifies no request.
type AccessKey struct {
	PublicKey accesskey.PublicKey
	// Node is the id of what the access key belongs to: a node, nd_, or a node pool,
	// np_, whose record Nodes holds, or a gateway, ng_, whose record Gateways holds.
	// Every active key of one node is that node alike. Empty, the access key is a node
	// of its own, which reports directly.
	Node string
	// StoredSecrets is true for an access key allowed stored secrets: discovery lists
	// the secrets endpoint for it, and its secrets requests are served.
	StoredSecrets bool
}

// Node is the record of a node or node pool.
type Node struct {
	// Workspace is the workspace it belongs to, ws_.
	Workspace string
	// Gateway is its choice: Direct, or empty, for a node that reports directly;
	// Default for its workspace's default gateway, else its organisation's; or a named
	// gateway, ng_.
	Gateway string
}

// Workspace is the record of a workspace.
type Workspace struct {
	// Organisation is the organisation it belongs to.
	Organisation string
	// Default is the workspace's default gateway, ng_, empty for none.
	Default string
}

// Organisation is the record of an organisation.
type Organisation struct {
	// Default is the organisation's default gateway, ng_, empty for none.
	Default string
}

// Gateway is the record of a gateway.
type Gateway struct {
	// URL is where the edge reaches it, an https origin, which its run keys name.
	URL string
	// Workspace or Organisation is the level it lives at, one of them: it may serve
	// that workspace, or every workspace of that organisation, everything below it.
	Workspace, Organisation string
	// AccessKeys are the ids of its access keys, current then next. Those Keys holds
	// as this gateway's are its active keys, and a run key names the first two.
	AccessKeys []string
}

// Run is a run as its registration named it, what the RunConfiguration hook decides
// on.
type Run struct {
	// AccessKeyID and InstanceID are the registration's, as its signed lines carry
	// them.
	AccessKeyID, InstanceID string
	// ID is the run id.
	ID string
	// Labels are the run's labels, empty when the registration sent none, as
	// server.ShownLabels gives them; a copy the hook may keep.
	Labels map[string]string
	// About is what the run is about, as server.ShownAbout gives the registration's,
	// nil when it sent none. It is for display: it never selects or changes a security policy.
	About json.RawMessage
	// Node is the node or node pool that registered the run, as its access key names
	// it, empty for an access key with no node; Workspace is its workspace, empty when
	// Nodes holds no record of it; and Gateway is the gateway its choice resolved to at
	// the registration, ng_, empty for a run that reports directly. They are the run's
	// placement, from its registration, never from the gateway's attach.
	Node, Workspace, Gateway string
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
	// key, what it belongs to, and whether the key is known and not revoked. Nil knows
	// no key.
	Keys func(accessKeyID string) (AccessKey, bool)
	// Nodes, Workspaces, Organisations and Gateways are the records, by id, a
	// registration's gateway is resolved from and a gateway's discovery is answered
	// from. Nil holds none, and every run reports directly. The handler reads them as it
	// serves: change them only between requests.
	Nodes         map[string]Node
	Workspaces    map[string]Workspace
	Organisations map[string]Organisation
	Gateways      map[string]Gateway
	// Signer is the receiver's own signing key: every answer to a verified request is
	// signed under it, and so is every run key, and Forager pins its public key. Nil
	// answers every verified request with an unsigned 500.
	Signer *accesskey.Key
	// Store keeps the events accepted.
	Store Store
	// Now is the receiver's clock; nil means the wall clock.
	Now func() time.Time
	// Window is how far a GET's timestamp, or a POST's time, may be from Now, either
	// way; zero means the contract's 300 seconds.
	Window time.Duration
	// Configuration answers discovery with the configuration document and the
	// receiver's digest of it. The document lists version, node_id, workspaces, events,
	// run, whose url is the run endpoint, apiary_public_key, the receiver's public key,
	// and secrets, whose url is the secrets endpoint, when the receiver serves one. For
	// an access key whose node or gateway the records hold, node_id is replaced by the
	// key's, workspaces by a node's or node pool's one workspace, and a gateway's key
	// gets no workspaces; secrets is left out for an access key not allowed stored
	// secrets. The digest of a document changed so is sha256= and the hex SHA-256 of
	// the document served. Nil means discovery is not served.
	Configuration func() (document []byte, digest string)
	// RunConfiguration decides the run configuration of a run: as it registers, as it
	// is attached and reloaded by its id, as its gateway fetches its credentials'
	// values, and for the digest every answer to a delivery of the run carries. It
	// returns the document, or a refusal. The receiver computes the document's digest
	// itself, sha256= and the lower-case hex SHA-256 of the bytes it serves; the digest
	// the hook returns is empty or that digest, and any other is a signed 500 in place
	// of the answer. Which labels name what the run works on is its to decide: the qory
	// command labels a run in a git checkout with forge and repository, and another
	// caller labels its runs as it likes. About never selects or changes a security
	// policy. Nil gives every run NoPolicy.
	RunConfiguration func(run Run) (document []byte, digest string, refusal *Refusal)
	// Secrets returns the values of a run's credentials, for a secrets request the
	// receiver accepted: one value for each name of credentials, the names the request
	// lists of the credentials of the run configuration in force, in its order, every
	// one when the run starts and those due at a renewal, or a refusal, which is
	// answered as RunConfiguration's is. Each value's bytes are a copy, which the
	// receiver overwrites with zeros once it sealed them. A value outside the contract's
	// form, or a count other than the names', is a signed 500. Nil serves no secrets
	// endpoint: list secrets in Configuration's document only with the hook set.
	Secrets func(run Run, credentials []string) (values []Value, refusal *Refusal)
	// EventsPath, RunPath and SecretsPath are where the events endpoint, the run
	// endpoint and the secrets endpoint are served; empty means DefaultEventsPath,
	// DefaultRunPath and DefaultSecretsPath.
	EventsPath, RunPath, SecretsPath string
	// Log receives one line per delivery, and may be nil. It never sees a header.
	Log func(string)
	// Stop, when set, is called per run id to learn whether the receiver wants nothing
	// more; true is a signed 410 without a code: to a registration, no run; to an
	// attach, the run has ended; to a reload or a delivery, a delivery already accepted
	// included, Forager sends no further batch and its run goes on. Nil means never.
	Stop func(runID string) bool
	// Admit, when set, is called for every registration but one the receiver accepted
	// with the same bytes under a key of the same node, to learn whether the instance
	// may start a run; false is a signed 409 instance_limit, and the run does not start.
	// It is not called for a registration refused earlier in the order: a body the
	// contract refuses, a time outside the window, one Stop refuses, a gateway's key, a
	// shape that does not match the node's choice, a choice that resolves to no gateway
	// or a gateway with no active key. Nil admits every instance.
	Admit func(accessKeyID, instanceID string) bool

	// runs are the registrations accepted, by run id.
	mu   sync.Mutex
	runs map[string]*registration
}

// registration is a registration the receiver accepted: the SHA-256 of its bytes, the
// node that registered it, the run they name, the answer it gave, and what became of
// the run since.
type registration struct {
	sum [sha256.Size]byte
	// node is the node or node pool that registered the run, or its access key's id
	// for a key with no node.
	node string
	run  Run
	// document and digest are a direct run's answer, its run configuration; answer is
	// a run through a gateway's, with its run key, and attachBy the end of its attach
	// window.
	document []byte
	digest   string
	answer   []byte
	attachBy time.Time
	// since is when the run's liveness counts from, its registration or, through a
	// gateway, its attach, and interval the heartbeat interval announced there.
	since    time.Time
	interval time.Duration
	// attached is the gateway node that attached the run and instance the instance id
	// its attach was signed with, each empty before the attach, and attachAnswer and
	// attachDigest what it was answered.
	attached     string
	instance     string
	attachAnswer []byte
	attachDigest string
	// served are the digests of the run configurations the run was answered with: at
	// its registration, its attach and each reload. A secrets request is for one of
	// them.
	served map[string]bool
	// beats are the run's heartbeats accepted, through a gateway those the attaching
	// instance stored alone; exited says its dev.qory.run.exited arrived; outcome is its
	// starter's outcome, nil before one.
	beats   []beat
	exited  bool
	outcome *outcome
}

// beat is one heartbeat: its own time, and when it arrived.
type beat struct {
	time, arrival time.Time
}

// outcome is a run's starter's outcome as the receiver recorded it: the SHA-256 of the
// bytes that gave it, its state and its reason, empty when it has none.
type outcome struct {
	sum    [sha256.Size]byte
	state  string
	reason string
}

// serve records that the run was answered the run configuration of the digest.
func (reg *registration) serve(digest string) {
	if reg.served == nil {
		reg.served = map[string]bool{}
	}
	reg.served[digest] = true
}

// through reports whether the run goes through a gateway.
func (reg *registration) through() bool { return reg.run.Gateway != "" }

// sender is the node a run's reloads and batches are accepted from: the node that
// registered a direct run, or the gateway node that attached a run through a gateway,
// none before the attach.
func (reg *registration) sender() string {
	if reg.through() {
		return reg.attached
	}
	return reg.node
}

// live reports whether the run is live at now: until its dev.qory.run.exited arrives
// or it has no recent heartbeat, none within 3 × its interval, counted from its
// registration, or through a gateway from its attach, where the attaching instance's
// heartbeats alone count; before the attach, until its attach_by. A heartbeat is as
// recent as its own time, corrected by the run's clock offset, the smallest arrival
// time less time over its heartbeats, plus the tolerance, and never more recent than
// its arrival.
func (reg *registration) live(now time.Time) bool {
	if reg.exited {
		return false
	}
	if reg.through() && reg.attached == "" {
		return !now.After(reg.attachBy)
	}
	last := reg.since
	if len(reg.beats) > 0 {
		offset := reg.beats[0].arrival.Sub(reg.beats[0].time)
		for _, b := range reg.beats[1:] {
			offset = min(offset, b.arrival.Sub(b.time))
		}
		for _, b := range reg.beats {
			at := b.time.Add(offset + heartbeatTolerance)
			if at.After(b.arrival) {
				at = b.arrival
			}
			if at.After(last) {
				last = at
			}
		}
	}
	return !now.After(last.Add(3 * reg.interval))
}

// reloadable reports whether the run's reloads are accepted from a verified request:
// from its sender, under any of its active keys, and for a run through a gateway from
// the attaching instance alone.
func (reg *registration) reloadable(v verified) bool {
	return reg.sender() == v.node && (!reg.through() || reg.instance == v.instance)
}

// from reports whether the run's batches are accepted from a verified request at now:
// from its sender, under any of its active keys, and for a run through a gateway, while
// the run is live, from the attaching instance alone.
func (reg *registration) from(v verified, now time.Time) bool {
	if reg.sender() != v.node {
		return false
	}
	return !reg.through() || reg.instance == v.instance || !reg.live(now)
}

// serving reports whether the run's batches and reloads may still be served: always for
// a direct run, and for a run through a gateway while the gateway that attached it may
// serve the run's workspace, by the attach's test and never by the node's current
// choice. A run through a gateway not yet attached has no batches or reloads to refuse.
func (reg *registration) serving(h *Handler) bool {
	return !reg.through() || reg.attached == "" || h.serves(reg.attached, reg.run.Workspace)
}

// verified is a request that verified: its access key and id, the node it stands for,
// its signed instance id, and the signature an answer is bound to.
type verified struct {
	key AccessKey
	id  string
	// node is the access key's node, node pool or gateway, or its id for a key with
	// no node.
	node string
	// instance is the instance id the request was signed with, as its
	// X-Qory-Instance-Id contained it.
	instance  string
	signature string
}

// The endpoints a request may be for.
const (
	toDiscovery = iota
	toRegistration
	toReload
	toAttach
	toOutcome
	toEvents
	toSecrets
)

// ServeHTTP routes one request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	events, run, secrets := h.EventsPath, h.RunPath, h.SecretsPath
	if events == "" {
		events = DefaultEventsPath
	}
	if run == "" {
		run = DefaultRunPath
	}
	if secrets == "" {
		secrets = DefaultSecretsPath
	}
	var to int
	var method, runID string
	rest, under := strings.CutPrefix(r.URL.Path, run+"/")
	id, sub, _ := strings.Cut(rest, "/")
	switch {
	case r.URL.Path == server.WellKnown && h.Configuration != nil:
		to, method = toDiscovery, http.MethodGet
	case r.URL.Path == run:
		to, method = toRegistration, http.MethodPost
	case under && runIDShape.MatchString(rest):
		to, method, runID = toReload, http.MethodGet, rest
	case under && runIDShape.MatchString(id) && sub == "attach":
		to, method, runID = toAttach, http.MethodPost, id
	case under && runIDShape.MatchString(id) && sub == "outcome":
		to, method, runID = toOutcome, http.MethodPost, id
	case r.URL.Path == events:
		to, method = toEvents, http.MethodPost
	case r.URL.Path == secrets && h.Secrets != nil:
		to, method = toSecrets, http.MethodPost
	default:
		http.NotFound(w, r)
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		http.Error(w, method+" is the method here", http.StatusMethodNotAllowed)
		return
	}
	limit := MaxBody
	if to == toSecrets {
		limit = MaxSecretsBody
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil || len(body) > limit {
		refuse(w, http.StatusRequestEntityTooLarge, "")
		return
	}
	if want := map[int]string{toRegistration: RegistrationType, toAttach: RegistrationType, toOutcome: RegistrationType, toEvents: server.ContentType,
		toSecrets: RegistrationType}[to]; want != "" {
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
	case to == toAttach:
		h.attach(w, v, runID, body)
	case to == toOutcome:
		h.outcome(w, v, runID, body)
	case to == toEvents:
		h.deliver(w, v, body)
	case to == toSecrets:
		h.secrets(w, v, body)
	case !h.fresh(r.Header.Get(server.HeaderTimestamp)):
		refuse(w, http.StatusUnauthorized, "unauthorized")
	case to == toDiscovery:
		doc, digest := h.configuration(v)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(server.HeaderConfiguration, digest)
		h.answer(w, v, http.StatusOK, doc)
	default:
		h.reload(w, v, runID)
	}
}

// configuration is discovery's document for a verified access key, with the
// receiver's digest of it: Configuration's, and for a key whose node or node pool
// Nodes holds, or whose gateway Gateways holds, with node_id that id, workspaces the
// node's one workspace and no workspaces for a gateway; without secrets for a key not
// allowed stored secrets; the digest of a document changed so sha256= and the hex
// SHA-256 of the document served.
func (h *Handler) configuration(v verified) ([]byte, string) {
	doc, digest := h.Configuration()
	n, node := h.Nodes[v.key.Node]
	_, gateway := h.Gateways[v.key.Node]
	records := v.key.Node != "" && (node || gateway)
	var m map[string]json.RawMessage
	if json.Unmarshal(doc, &m) != nil {
		return doc, digest
	}
	_, listed := m["secrets"]
	hide := listed && !v.key.StoredSecrets
	if !records && !hide {
		return doc, digest
	}
	if hide {
		delete(m, "secrets")
	}
	if records {
		m["node_id"], _ = json.Marshal(v.key.Node)
		if node {
			m["workspaces"], _ = json.Marshal([]string{n.Workspace})
		} else {
			delete(m, "workspaces")
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return doc, digest
	}
	sum := sha256.Sum256(b)
	return b, "sha256=" + hex.EncodeToString(sum[:])
}

// setConfiguration sets on an answer the digest of the access key's discovery, when
// discovery is served.
func (h *Handler) setConfiguration(w http.ResponseWriter, v verified) {
	if h.Configuration != nil {
		_, digest := h.configuration(v)
		w.Header().Set(server.HeaderConfiguration, digest)
	}
}

// registrationBody is what the receiver reads of a registration's body, once the
// schema passed it.
type registrationBody struct {
	RunID           string            `json:"run_id"`
	Labels          map[string]string `json:"labels"`
	About           json.RawMessage   `json:"about"`
	IntervalSeconds int               `json:"interval_seconds"`
	AttachSeconds   int               `json:"attach_seconds"`
	Time            string            `json:"time"`
}

// throughGateway reports whether the body is of the gateway shape: without the direct
// shape's four members, which the schema holds together, interval_seconds among them.
func (reg *registrationBody) throughGateway() bool { return reg.IntervalSeconds == 0 }

// validate reads a body against a schema.
func validate(schema func() (*jsonschema.Schema, error), body []byte) error {
	s, err := schema()
	if err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		return err
	}
	return s.Validate(doc)
}

// readRegistration reads a registration's body and refuses what the contract refuses:
// a body the schema refuses, interval_seconds over 300 among it, a body of neither
// shape and an attach_seconds below 1, labels or an about outside the rules the schema
// cannot state: a label value over 256 bytes of UTF-8, which the schema's maxLength,
// counting characters, lets through, among them. A time that is no date is refused by
// the caller.
func readRegistration(body []byte) (*registrationBody, error) {
	if err := validate(registrationSchema, body); err != nil {
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
		// Kept as run.started sends it, so the attach's answer, and with it the gateway's
		// run.registered, contains no value that contains qak_, qrk_, qecr_, qecn_, qecp_, qecg_
		// or qeci_. An about without one is kept as the body has it.
		if shown := server.ShownAbout(&a); !reflect.DeepEqual(*shown, a) {
			reg.About = nil
			if !shown.Empty() {
				b, err := json.Marshal(shown)
				if err != nil {
					return nil, err
				}
				reg.About = b
			}
		}
	}
	// As run.started sends them, as about is.
	reg.Labels = server.ShownLabels(reg.Labels)
	return &reg, nil
}

// timely reads a POST's time, ts, once its body was read with the error err: a body
// the contract refuses, or a time that is no date, is a signed 400 invalid_request, and
// a time outside the window the unsigned 401. It reports whether the endpoint goes on.
func (h *Handler) timely(w http.ResponseWriter, v verified, err error, ts string) bool {
	var at time.Time
	if err == nil {
		at, err = time.Parse(time.RFC3339, ts)
	}
	if err != nil {
		h.refuseSigned(w, v, http.StatusBadRequest, "invalid_request")
		return false
	}
	if !h.within(at.Unix()) {
		refuse(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

// register answers one verified registration, in the run endpoint's order: a body the
// contract refuses, 400 invalid_request; a time outside the window, the unsigned 401;
// a run id it accepted with the same bytes under any active key of the same node, the
// same answer again; a run it wants nothing more of, 410; a gateway's own key, 409
// gateway_key; a body whose shape does not match the node's resolved choice, 409
// node_is_direct or node_uses_gateway; a choice that resolves to no gateway, 409
// no_default_gateway or gateway_not_serving; a gateway with no active key, 409
// gateway_without_key; a new instance it does not admit, 409 instance_limit; a run id
// it accepted from another node, even with the same bytes, or with other bytes, 409
// run_id_used; then the hook's refusal. A direct run is answered its run
// configuration, and a run through a gateway its run key; either answer is kept with
// the registration and answered 200.
func (h *Handler) register(w http.ResponseWriter, r *http.Request, v verified, body []byte) {
	reg, err := readRegistration(body)
	ts := ""
	if reg != nil {
		ts = reg.Time
	}
	if !h.timely(w, v, err, ts) {
		return
	}
	run := Run{AccessKeyID: v.id, InstanceID: r.Header.Get(server.HeaderInstanceID),
		ID: reg.RunID, Labels: reg.Labels, About: reg.About, Node: v.key.Node}
	if run.Labels == nil {
		run.Labels = map[string]string{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	sum := sha256.Sum256(body)
	prev := h.runs[run.ID]
	if prev != nil && prev.node == v.node && prev.sum == sum {
		if prev.through() {
			h.answerKey(w, v, prev.answer)
		} else {
			h.answerRun(w, v, prev.document, prev.digest)
		}
		return
	}
	if h.Stop != nil && h.Stop(run.ID) {
		h.answer(w, v, http.StatusGone, nil)
		return
	}
	if strings.HasPrefix(v.key.Node, gatewayPrefix) {
		h.refuseSigned(w, v, http.StatusConflict, "gateway_key")
		return
	}
	through, gateway, code := h.resolve(v.key.Node)
	switch {
	case !through && reg.throughGateway():
		code = "node_is_direct"
	case through && !reg.throughGateway():
		code = "node_uses_gateway"
	}
	if code != "" {
		h.refuseSigned(w, v, http.StatusConflict, code)
		return
	}
	var keys []accesskey.PublicKey
	if through {
		if keys = h.gatewayKeys(gateway); len(keys) == 0 {
			h.refuseSigned(w, v, http.StatusConflict, "gateway_without_key")
			return
		}
	}
	if h.Admit != nil && !h.Admit(run.AccessKeyID, run.InstanceID) {
		h.refuseSigned(w, v, http.StatusConflict, "instance_limit")
		return
	}
	if prev != nil {
		h.refuseSigned(w, v, http.StatusConflict, "run_id_used")
		return
	}
	if n, ok := h.Nodes[v.key.Node]; ok && v.key.Node != "" {
		run.Workspace = n.Workspace
	}
	run.Gateway = gateway
	doc, digest, refusal := h.runConfiguration(run)
	if refusal != nil {
		h.refuseRun(w, v, refusal)
		return
	}
	now := time.Unix(h.now().Unix(), 0).UTC()
	accepted := &registration{sum: sum, node: v.node, run: run, since: now, interval: time.Duration(reg.IntervalSeconds) * time.Second}
	if !through {
		accepted.document, accepted.digest = doc, digest
		accepted.serve(digest)
		h.keep(accepted)
		h.answerRun(w, v, doc, digest)
		return
	}
	window := AttachWindow
	if reg.AttachSeconds > 0 {
		window = min(time.Duration(reg.AttachSeconds)*time.Second, AttachCeiling)
	}
	accepted.attachBy = now.Add(window)
	key, err := runkey.Key{RunID: run.ID, Workspace: run.Workspace, NodeID: run.Node, Gateway: gateway,
		InstanceID: run.InstanceID, GatewayURL: h.Gateways[gateway].URL, GatewayKeys: keys,
		Issued: now, AttachBy: accepted.attachBy}.Sign(h.Signer)
	if err != nil {
		h.answer(w, v, http.StatusInternalServerError, nil)
		return
	}
	accepted.answer, err = json.Marshal(struct {
		Version int    `json:"version"`
		RunID   string `json:"run_id"`
		RunKey  string `json:"run_key"`
	}{1, run.ID, key})
	if err != nil {
		h.answer(w, v, http.StatusInternalServerError, nil)
		return
	}
	h.keep(accepted)
	h.answerKey(w, v, accepted.answer)
}

// keep keeps an accepted registration by its run id.
func (h *Handler) keep(reg *registration) {
	if h.runs == nil {
		h.runs = map[string]*registration{}
	}
	h.runs[reg.run.ID] = reg
}

// resolve resolves the choice of a node or node pool from its record: whether its runs
// go through a gateway, the gateway, and the code of a choice that resolves to none:
// no_default_gateway for Default when neither the workspace nor its organisation has a
// default gateway the records hold, and gateway_not_serving for a named gateway that
// may no longer serve the node's workspace. A key with no node, or one whose node
// Nodes does not hold, reports directly.
func (h *Handler) resolve(node string) (through bool, gateway, code string) {
	n, ok := h.Nodes[node]
	if node == "" || !ok || n.Gateway == "" || n.Gateway == Direct {
		return false, "", ""
	}
	if n.Gateway == Default {
		ws := h.Workspaces[n.Workspace]
		for _, g := range []string{ws.Default, h.Organisations[ws.Organisation].Default} {
			if _, ok := h.Gateways[g]; ok && g != "" {
				return true, g, ""
			}
		}
		return true, "", "no_default_gateway"
	}
	if !h.serves(n.Gateway, n.Workspace) {
		return true, "", "gateway_not_serving"
	}
	return true, n.Gateway, ""
}

// serves reports whether a gateway the records hold may serve a workspace: the one it
// lives at, or one of the organisation it lives at.
func (h *Handler) serves(gateway, workspace string) bool {
	g, ok := h.Gateways[gateway]
	if !ok || workspace == "" {
		return false
	}
	return g.Workspace == workspace || g.Organisation != "" && h.Workspaces[workspace].Organisation == g.Organisation
}

// gatewayKeys are a gateway's active keys, the first two, current then next: of its
// access keys, those Keys holds as the gateway's whose public key passes the key checks.
func (h *Handler) gatewayKeys(gateway string) []accesskey.PublicKey {
	var keys []accesskey.PublicKey
	if h.Keys == nil {
		return nil
	}
	for _, id := range h.Gateways[gateway].AccessKeys {
		k, ok := h.Keys(id)
		if ok && k.Node == gateway && k.PublicKey.Check() == nil && !slices.Contains(keys, k.PublicKey) && len(keys) < 2 {
			keys = append(keys, k.PublicKey)
		}
	}
	return keys
}

// attachBody is what the receiver reads of an attach's body, once the schema passed it.
type attachBody struct {
	RunKey          string `json:"run_key"`
	IntervalSeconds int    `json:"interval_seconds"`
	Time            string `json:"time"`
}

// attach answers one verified attach of the run runID, in its order after the shared
// one: a key that is not a gateway's, 409 not_a_gateway; a run key that does not verify
// under the receiver's key, or whose run id is not the path's, 400 run_key_invalid; the
// same gateway node, under any of its active keys and the instance id its attach was
// signed with, attaching the same live run again, the stored answer while the gateway
// may serve the run's workspace, else 409 workspace_not_served; a run that has
// ended, its dev.qory.run.exited arrived, an outcome given, lost after the attach, one
// it wants nothing more of, or whose registration it does not hold, 410; past the run
// key's attach_by and never attached, 409 run_key_expired; a run key that names another
// gateway, 409 wrong_gateway; a gateway that may not serve the run's workspace, 409
// workspace_not_served; a run another gateway node, or another instance of the same
// node, attached, 409 run_attached; then the hook's refusal, or the run configuration
// with the registration's labels and about, kept with the attaching node and instance
// and answered 200.
func (h *Handler) attach(w http.ResponseWriter, v verified, runID string, body []byte) {
	var a attachBody
	err := validate(attachSchema, body)
	if err == nil {
		err = json.Unmarshal(body, &a)
	}
	if !h.timely(w, v, err, a.Time) {
		return
	}
	if !strings.HasPrefix(v.key.Node, gatewayPrefix) {
		h.refuseSigned(w, v, http.StatusConflict, "not_a_gateway")
		return
	}
	k, err := runkey.Verify(a.RunKey, accesskey.Pin{{Alg: "ed25519", PublicKey: h.Signer.PublicKey().String()}})
	if err != nil || k.RunID != runID {
		h.refuseSigned(w, v, http.StatusBadRequest, "run_key_invalid")
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	reg := h.runs[runID]
	now := h.now()
	if reg == nil || !reg.through() {
		h.answer(w, v, http.StatusGone, nil)
		return
	}
	ended := reg.exited || reg.outcome != nil || (h.Stop != nil && h.Stop(runID)) || (reg.attached != "" && !reg.live(now))
	switch {
	case reg.attached == v.node && reg.instance == v.instance && !ended:
		if !h.serves(v.node, k.Workspace) {
			h.refuseSigned(w, v, http.StatusConflict, "workspace_not_served")
			return
		}
		h.answerAttach(w, v, reg.attachAnswer, reg.attachDigest)
		return
	case ended:
		h.answer(w, v, http.StatusGone, nil)
		return
	case reg.attached == "" && now.After(reg.attachBy):
		h.refuseSigned(w, v, http.StatusConflict, "run_key_expired")
		return
	case k.Gateway != v.node:
		h.refuseSigned(w, v, http.StatusConflict, "wrong_gateway")
		return
	case !h.serves(v.node, k.Workspace):
		h.refuseSigned(w, v, http.StatusConflict, "workspace_not_served")
		return
	case reg.attached != "":
		h.refuseSigned(w, v, http.StatusConflict, "run_attached")
		return
	}
	doc, digest, refusal := h.runConfiguration(reg.run)
	if refusal != nil {
		h.refuseRun(w, v, refusal)
		return
	}
	answer, err := withRegistration(doc, reg.run)
	if err != nil {
		h.answer(w, v, http.StatusInternalServerError, nil)
		return
	}
	reg.attached, reg.instance, reg.attachAnswer, reg.attachDigest = v.node, v.instance, answer, digest
	reg.serve(digest)
	reg.since, reg.interval = now, time.Duration(a.IntervalSeconds)*time.Second
	h.answerAttach(w, v, answer, digest)
}

// withRegistration is the attach's answer: the run configuration document doc, with
// the registration's labels and about, each left out when it had none.
func withRegistration(doc []byte, run Run) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(doc, &m); err != nil {
		return nil, err
	}
	delete(m, "labels")
	delete(m, "about")
	if len(run.Labels) > 0 {
		b, err := json.Marshal(run.Labels)
		if err != nil {
			return nil, err
		}
		m["labels"] = b
	}
	if run.About != nil {
		m["about"] = run.About
	}
	return json.Marshal(m)
}

// outcomeBody is what the receiver reads of an outcome's body, once the schema passed
// it.
type outcomeBody struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
	Time   string `json:"time"`
}

// outcome answers one verified outcome of the run runID, in its order after the shared
// one: the same bytes under any active key of the node that registered the run, the
// stored answer; a run the key's node did not register, or whose registration the
// receiver does not hold, a signed 404 not_found; a second outcome of the same state and
// reason, accepted again, and a different one, 409 outcome_given. With no state, the
// outcome is cancelled with the reason stopped; a reason that is no code, or one of
// Forager's reserved codes, is dropped and the outcome kept. It is accepted whenever
// it arrives, before or after the run's dev.qory.run.exited, and answered 200 with
// {"version":1}.
func (h *Handler) outcome(w http.ResponseWriter, v verified, runID string, body []byte) {
	var o outcomeBody
	err := validate(outcomeSchema, body)
	if err == nil {
		err = json.Unmarshal(body, &o)
	}
	if !h.timely(w, v, err, o.Time) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	reg := h.runs[runID]
	sum := sha256.Sum256(body)
	if reg == nil || reg.node != v.node {
		h.refuseSigned(w, v, http.StatusNotFound, "not_found")
		return
	}
	given := &outcome{sum: sum, state: o.State, reason: o.Reason}
	if given.state == "" {
		given.state, given.reason = event.StateCancelled, event.ReasonStopped
	} else if !event.StarterReason(given.reason) {
		given.reason = ""
	}
	if prev := reg.outcome; prev != nil && prev.sum != sum && (prev.state != given.state || prev.reason != given.reason) {
		h.refuseSigned(w, v, http.StatusConflict, "outcome_given")
		return
	}
	if reg.outcome == nil {
		reg.outcome = given
	}
	w.Header().Set("Content-Type", "application/json")
	h.setConfiguration(w, v)
	h.answer(w, v, http.StatusOK, []byte(`{"version":1}`))
}

// reload answers one verified reload of a run's configuration by its id: a run whose
// reloads the request may not send, from the node that registered a direct run or the
// gateway node that attached a run through a gateway, from the attaching instance
// alone, before and after the run's end, or a run not registered, 404; a run through a
// gateway that may no longer serve the run's workspace, decided as at the attach, 410
// workspace_not_served with no digest headers; a run it wants nothing more of, 410; the
// hook's refusal; otherwise the run configuration, 200.
func (h *Handler) reload(w http.ResponseWriter, v verified, runID string) {
	h.mu.Lock()
	reg := h.runs[runID]
	allowed := reg != nil && reg.reloadable(v)
	serving := allowed && reg.serving(h)
	h.mu.Unlock()
	if !allowed {
		h.answer(w, v, http.StatusNotFound, nil)
		return
	}
	if !serving {
		h.refuseSigned(w, v, http.StatusGone, "workspace_not_served")
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
	h.mu.Lock()
	reg.serve(digest)
	h.mu.Unlock()
	h.answerRun(w, v, doc, digest)
}

// Value is one value the Secrets hook returns: the bytes, when they stop working, zero
// when they do not, and where they are set, nil for the run configuration entry's
// items (sealed-plaintext.schema.json). A Value formats as a fixed phrase whatever the
// verb, and nothing of its bytes.
type Value struct {
	Value     []byte
	ExpiresAt time.Time
	Apply     []sealed.Apply
}

// String returns a fixed phrase, and nothing of the bytes.
func (v Value) String() string { return "a sealed value" }

// GoString returns what String returns.
func (v Value) GoString() string { return v.String() }

// Format writes what String returns, whatever the verb.
func (v Value) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, v.String()) }

// secretsBody is what the receiver reads of a secrets request's body, decoded with each
// member name once and no member the schema does not define, its timestamp kept as its
// raw number so its form is checked.
type secretsBody struct {
	Version          int            `json:"version"`
	RunID            string         `json:"run_id"`
	RunConfiguration string         `json:"run_configuration"`
	Credentials      []string       `json:"credentials"`
	Timestamp        jsontext.Value `json:"timestamp"`
}

// integerShape is a JSON integer with no sign, fraction or exponent, below 2^53 in
// digits.
var integerShape = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,15})$`)

// readSecrets reads a secrets request's body and refuses what the contract refuses: a
// member name twice, a member the schema does not define, invalid UTF-8, a body the
// schema refuses, and a timestamp that is not a JSON integer below 2^53 with no sign,
// fraction or exponent. It returns the body and its timestamp.
func readSecrets(body []byte) (*secretsBody, int64, error) {
	var req secretsBody
	if err := jsonv2.Unmarshal(body, &req, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, 0, err
	}
	if err := validate(secretsSchema, body); err != nil {
		return nil, 0, err
	}
	if !integerShape.Match(req.Timestamp) {
		return nil, 0, errors.New("the timestamp is not a JSON integer with no sign, fraction or exponent")
	}
	ts, err := strconv.ParseInt(string(req.Timestamp), 10, 64)
	if err != nil || ts > 1<<53-1 {
		return nil, 0, errors.New("the timestamp is not below 2^53")
	}
	return &req, ts, nil
}

// credentialNames are the names of a run configuration's credentials, in the
// document's order; none for a document without credentials, or one that does not
// decode.
func credentialNames(doc []byte) []string {
	var d struct {
		Credentials []struct {
			Name string `json:"name"`
		} `json:"credentials"`
	}
	if json.Unmarshal(doc, &d) != nil {
		return nil
	}
	names := make([]string, 0, len(d.Credentials))
	for _, c := range d.Credentials {
		names = append(names, c.Name)
	}
	return names
}

// inOrder reports whether requested are some of names, at least one, each once, in
// names' order.
func inOrder(names, requested []string) bool {
	if len(requested) == 0 {
		return false
	}
	i := 0
	for _, n := range requested {
		j := slices.Index(names[i:], n)
		if j < 0 {
			return false
		}
		i += j + 1
	}
	return true
}

// secrets answers one verified secrets request, in its order after the shared one: a
// body the contract refuses, 400 invalid_request; a timestamp more than the window
// from the receiver's clock, either way, the unsigned 401; an access key not allowed
// stored secrets, 409 secrets_not_allowed; then as a reload of the run would be
// answered: a run whose reloads the request may not send, or a run not registered,
// 404; a run through a gateway that may no longer serve the run's workspace, 410
// workspace_not_served; a run it wants nothing more of, 410; the hook's refusal of the
// run configuration; then a digest that is not the digest of the run configuration in
// force, or not one the run was answered with, 410 run_configuration_superseded; a
// credentials list that is not some of that run configuration's names, in its order,
// each once, 409 credentials_differ; the Secrets hook's refusal; values outside the contract's form, or
// a count other than the names', a signed 500. Otherwise each value is sealed to the
// access key the request verified under, signed under the receiver's key, with exp its
// clock plus sealed.Lifetime, and answered 200. The values are cleared once sealed, and
// none is logged or kept.
func (h *Handler) secrets(w http.ResponseWriter, v verified, body []byte) {
	req, ts, err := readSecrets(body)
	if err != nil {
		h.refuseSigned(w, v, http.StatusBadRequest, "invalid_request")
		return
	}
	if !h.within(ts) {
		refuse(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !v.key.StoredSecrets {
		h.refuseSigned(w, v, http.StatusConflict, "secrets_not_allowed")
		return
	}
	h.mu.Lock()
	reg := h.runs[req.RunID]
	allowed := reg != nil && reg.reloadable(v)
	serving := allowed && reg.serving(h)
	served := allowed && reg.served[req.RunConfiguration]
	h.mu.Unlock()
	if !allowed {
		h.answer(w, v, http.StatusNotFound, nil)
		return
	}
	if !serving {
		h.refuseSigned(w, v, http.StatusGone, "workspace_not_served")
		return
	}
	if h.Stop != nil && h.Stop(req.RunID) {
		h.answer(w, v, http.StatusGone, nil)
		return
	}
	doc, digest, refusal := h.runConfiguration(reg.run)
	if refusal != nil {
		h.refuseRun(w, v, refusal)
		return
	}
	if !served || req.RunConfiguration != digest {
		h.refuseSigned(w, v, http.StatusGone, "run_configuration_superseded")
		return
	}
	names := req.Credentials
	if !inOrder(credentialNames(doc), names) {
		h.refuseSigned(w, v, http.StatusConflict, "credentials_differ")
		return
	}
	run := reg.run
	run.Labels = cloneLabels(run.Labels)
	values, refusal := h.Secrets(run, slices.Clone(names))
	defer func() {
		for _, b := range values {
			clear(b.Value)
		}
	}()
	if refusal != nil {
		h.refuseRun(w, v, refusal)
		return
	}
	if len(values) != len(names) {
		h.answer(w, v, http.StatusInternalServerError, nil)
		return
	}
	s := sealed.Sealing{AccessKeyID: v.id, PublicKey: v.key.PublicKey, RunID: req.RunID, RunConfiguration: digest,
		Credentials: names, Exp: sealed.Expiry(h.now())}
	for i, name := range names {
		sv := sealed.NewValue(name, values[i].Value)
		sv.ExpiresAt, sv.Apply = values[i].ExpiresAt, values[i].Apply
		s.Values = append(s.Values, sv)
	}
	answer, err := sealed.Seal(s, h.Signer)
	if err != nil {
		h.answer(w, v, http.StatusInternalServerError, nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	h.answer(w, v, http.StatusOK, answer)
}

// runConfiguration asks the hook for a run's configuration, with a copy of its labels,
// NoPolicy without a hook, and computes its digest, sha256= and the lower-case hex
// SHA-256 of the document's bytes. A hook's digest other than empty or that one is a
// refusal of status 500 with no code: the receiver never serves a digest of another
// form.
func (h *Handler) runConfiguration(run Run) ([]byte, string, *Refusal) {
	doc, given := NoPolicy, ""
	if h.RunConfiguration != nil {
		run.Labels = cloneLabels(run.Labels)
		var refusal *Refusal
		if doc, given, refusal = h.RunConfiguration(run); refusal != nil {
			return nil, "", refusal
		}
	}
	sum := sha256.Sum256(doc)
	digest := "sha256=" + hex.EncodeToString(sum[:])
	if given != "" && given != digest {
		return nil, "", &Refusal{Status: http.StatusInternalServerError}
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

// answerKey answers a registration through a gateway: a signed 200, application/json,
// with the run's id and its run key, the digest of the access key's discovery and no
// X-Qory-Run-Configuration or ETag.
func (h *Handler) answerKey(w http.ResponseWriter, v verified, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	h.setConfiguration(w, v)
	h.answer(w, v, http.StatusOK, body)
}

// answerAttach answers an attach: the run configuration with the registration's labels
// and about, as answerRun answers a run configuration, with the digest of the access
// key's discovery.
func (h *Handler) answerAttach(w http.ResponseWriter, v verified, body []byte, digest string) {
	h.setConfiguration(w, v)
	h.answerRun(w, v, body, digest)
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
// sent. A GET's timestamp and a POST's time are checked against the window later, in
// the contract's order of refusals.
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
	node := key.Node
	if node == "" {
		node = id
	}
	return verified{key: key, id: id, node: node, instance: req.InstanceID, signature: sig}, true
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

// now is the receiver's clock.
func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// within reports whether a moment, in Unix seconds, is within the window of the
// receiver's clock, either way.
func (h *Handler) within(n int64) bool {
	window := h.Window
	if window == 0 {
		window = server.Window
	}
	d := h.now().Unix() - n
	return d <= int64(window/time.Second) && -d <= int64(window/time.Second)
}

// head is what the receiver reads of each event of a batch.
type head struct {
	ID      string `json:"id"`
	Subject string `json:"subject"`
	Type    string `json:"type"`
	Time    string `json:"time"`
}

// deliver answers one verified delivery, in the events endpoint's order: a batch that
// is not one, or whose events are not all of one run, 400 invalid_request; a batch of a
// run it holds the registration of from another node than the one its batches are
// accepted from, or, while a run through a gateway is live, from another instance than
// the attaching one, 409 wrong_gateway for a run through a gateway and wrong_node for a
// direct run; for a run through a gateway, once the gateway that attached it may no
// longer serve the run's workspace, decided as at the attach, 410 workspace_not_served
// with no digest headers; an event of a run it wants nothing more of, 410; each of the
// two before deduplication, a batch already accepted included, and with nothing stored;
// one whose events the store holds every one of, 202 again; otherwise each new event
// stored and 202. Once the run's starter gave its outcome, a 202 carries it as the end
// member, until the batch that carries the run's dev.qory.run.exited, whose answer and
// every one after it holds none.
func (h *Handler) deliver(w http.ResponseWriter, v verified, body []byte) {
	var batch []json.RawMessage
	if err := json.Unmarshal(body, &batch); err != nil || len(batch) == 0 {
		h.refuseSigned(w, v, http.StatusBadRequest, "invalid_request")
		return
	}
	heads := make([]head, len(batch))
	for i, raw := range batch {
		if err := json.Unmarshal(raw, &heads[i]); err != nil || heads[i].ID == "" || heads[i].Subject == "" || heads[i].Type == "" ||
			heads[i].Subject != heads[0].Subject {
			h.refuseSigned(w, v, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	subject := heads[0].Subject
	h.mu.Lock()
	defer h.mu.Unlock()
	reg := h.runs[subject]
	now := h.now()
	if reg != nil && !reg.from(v, now) {
		code := "wrong_node"
		if reg.through() {
			code = "wrong_gateway"
		}
		h.refuseSigned(w, v, http.StatusConflict, code)
		return
	}
	if reg != nil && !reg.serving(h) {
		h.refuseSigned(w, v, http.StatusGone, "workspace_not_served")
		return
	}
	if h.Stop != nil && h.Stop(subject) {
		h.digests(w, v, reg)
		h.answer(w, v, http.StatusGone, nil)
		return
	}
	stored, dup := 0, 0
	for i, raw := range batch {
		hd := heads[i]
		if reg != nil && hd.Type == event.RunExited {
			reg.exited = true
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
		if t, err := time.Parse(time.RFC3339Nano, hd.Time); err == nil && reg != nil && hd.Type == event.RunHeartbeat &&
			(!reg.through() || reg.instance == v.instance) {
			reg.beats = append(reg.beats, beat{time: t, arrival: now})
		}
	}
	if h.Log != nil {
		h.Log("delivery for run " + accesskey.ShownValue(subject, false) + ": " + itoa(stored) + " stored, " + itoa(dup) + " duplicates")
	}
	h.digests(w, v, reg)
	var answer []byte
	if reg != nil && reg.outcome != nil && !reg.exited {
		end := map[string]string{"state": reg.outcome.state}
		if reg.outcome.reason != "" {
			end["reason"] = reg.outcome.reason
		}
		answer, _ = json.Marshal(map[string]any{"end": end})
		w.Header().Set("Content-Type", "application/json")
	}
	h.answer(w, v, http.StatusAccepted, answer)
}

// digests sets on an answer the digests in force: the access key's discovery's, and
// the run configuration's for the run as it registered, none when the receiver holds no
// registration of it or the hook refuses it now. The answer's signature covers both.
func (h *Handler) digests(w http.ResponseWriter, v verified, reg *registration) {
	h.setConfiguration(w, v)
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

// OpenFile opens or creates the file and reads the ids it already contains, so a restarted
// receiver still deduplicates. An error whose text contains qak_, qrk_, qecr_, qecn_,
// qecp_, qecg_ or qeci_, such as one that quotes the path, prints as accesskey.ShownError
// prints it.
func OpenFile(path string) (*File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, accesskey.ShownError(err)
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
		return nil, accesskey.ShownError(err)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, accesskey.ShownError(err)
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
		return accesskey.ShownError(err)
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
	return accesskey.ShownError(errors.Join(s.f.Sync(), s.f.Close()))
}
