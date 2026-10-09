// Package event is the CloudEvents envelope Forager emits and the emitter that
// numbers events within a run.
//
// An [Event] is one event of the contract, contracts/forager/v1/event.schema.json, as Go
// sees it: the fixed attributes, the sequence extension and a data value that encodes to
// a JSON object. An [Emitter] belongs to one run and hands out ids, times and the
// contiguous sequence; every event of a run goes through it, so the order the sinks see
// is the order of the run. The type constants are the contract's type names.
package event

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Base is the contract's base URI; dataschema is Base plus the type's schema path.
const Base = "https://qory.dev/contracts/forager/v1"

// The event types of the contract. A type name is stable; a breaking change to its data
// is a new type.
const (
	Ping          = "dev.qory.ping"
	RunStarted    = "dev.qory.run.started"
	RunHeartbeat  = "dev.qory.run.heartbeat"
	RunLog        = "dev.qory.run.log"
	RunResized    = "dev.qory.run.resized"
	RunEgress     = "dev.qory.run.egress"
	PolicyApplied = "dev.qory.run.policy_applied"
	RunExited     = "dev.qory.run.exited"
	RunRefused    = "dev.qory.run.refused"
)

// What opened a run, the opened_by of dev.qory.run.started: a session around a runtime,
// or a gateway on a run credential, with no session and no process.
const (
	OpenedBySession = "session"
	OpenedByGateway = "gateway"
)

// Where a run's credential came from, the credential of dev.qory.run.started: an
// issuer gave the run its run credential, a session's run on a gateway's one address
// and every run a gateway opened; or none, a run on a gateway's local link. Nothing
// else of the issuer is reported.
const (
	CredentialIssuer = "issuer"
	CredentialNone   = "none"
)

// The reasons of dev.qory.run.exited, why a run ended other than by the runtime's own
// exit. The session writes timeout and run_closed, and in its own record the code of the
// gateway's 410, batch_refused among them; the resend of a record writes gateway_lost;
// the gateway writes the others.
const (
	ReasonTimeout           = "timeout"
	ReasonRunClosed         = "run_closed"
	ReasonGatewayLost       = "gateway_lost"
	ReasonSessionLost       = "session_lost"
	ReasonQuiet             = "quiet"
	ReasonCredentialExpired = "credential_expired"
	ReasonRunEndedAtIssuer  = "run_ended_at_issuer"
	// ReasonBatchRefused is the gateway's 410 to a session whose batch it refused, and
	// the reason of the session's own dev.qory.run.exited after it; the gateway's record
	// of the same end says session_lost.
	ReasonBatchRefused = "batch_refused"
)

// Prefix is what every type of the contract starts with; a descriptor's session types
// carry it too.
const Prefix = "dev.qory."

// Event is one CloudEvents 1.0 event in the JSON format, with the attributes the
// contract fixes. Data is any value that encodes to a JSON object.
type Event struct {
	SpecVersion string `json:"specversion"`
	ID          string `json:"id"`
	Source      string `json:"source"`
	Type        string `json:"type"`
	Subject     string `json:"subject"`
	Time        string `json:"time"`
	Sequence    string `json:"sequence"`
	DataSchema  string `json:"dataschema"`
	Data        any    `json:"data"`
}

// DataSchema is the dataschema of a type: the type without its prefix, as a schema path
// under events/ in the contract.
func DataSchema(typ string) string {
	return Base + "/events/" + strings.TrimPrefix(typ, Prefix) + ".schema.json"
}

// Source is the source attribute of a run: urn:qory:run: and the run id.
func Source(runID string) string {
	return "urn:qory:run:" + runID
}

// Emitter makes the events of one run. It is safe for concurrent use; the sequence is
// handed out under a lock in the order Make is called.
type Emitter struct {
	runID string
	now   func() time.Time
	mu    sync.Mutex
	seq   uint64
}

// NewEmitter returns an emitter for the run. now is the clock; nil means time.Now.
func NewEmitter(runID string, now func() time.Time) *Emitter {
	if now == nil {
		now = time.Now
	}
	return &Emitter{runID: runID, now: now}
}

// NewEmitterAfter returns an emitter that goes on after seq: whoever completes the
// record of a run its session left numbers on from the last event in the file.
func NewEmitterAfter(runID string, seq uint64, now func() time.Time) *Emitter {
	e := NewEmitter(runID, now)
	e.seq = seq
	return e
}

// RunID is the run the emitter numbers.
func (e *Emitter) RunID() string { return e.runID }

// Make returns the next event of the run with the given type and data: a fresh id, the
// clock's time in UTC with millisecond precision, and the next sequence, zero-padded to
// ten digits from 0000000001.
func (e *Emitter) Make(typ string, data any) *Event {
	ev := e.Unnumbered(typ, data)
	e.Number(ev)
	return ev
}

// Unnumbered returns an event of the run with the given type and data, a fresh id and
// the clock's time, as [Emitter.Make] does, but no sequence yet: an event that waits for
// its place in the run, which [Emitter.Number] gives it.
func (e *Emitter) Unnumbered(typ string, data any) *Event {
	return &Event{
		SpecVersion: "1.0",
		ID:          NewID(),
		Source:      Source(e.runID),
		Type:        typ,
		Subject:     e.runID,
		Time:        e.now().UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		DataSchema:  DataSchema(typ),
		Data:        data,
	}
}

// Number gives the event the run's next sequence, in the order Number and Make are
// called: an event made elsewhere, a session's that a gateway numbers into the run's
// stream, or one made by [Emitter.Unnumbered].
func (e *Emitter) Number(ev *Event) {
	e.mu.Lock()
	e.seq++
	seq := e.seq
	e.mu.Unlock()
	ev.Sequence = fmt.Sprintf("%010d", seq)
}

// Sequence is the number of events made so far.
func (e *Emitter) Sequence() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.seq
}

// JSON encodes the event as one line, without the trailing newline.
func (ev *Event) JSON() ([]byte, error) {
	return json.Marshal(ev)
}

// NewID returns a UUID version 4, in the canonical lower-case form.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return format(b)
}

// NewRunID returns a UUID version 7, RFC 9562: the current time in its first 48 bits,
// so run directories sort by start, then random bits.
func NewRunID() string {
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(b[:8], ms<<16)
	if _, err := rand.Read(b[6:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	return format(b)
}

func format(b [16]byte) string {
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
