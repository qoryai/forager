// Package runkeywire is the form of a run key and the reading of its payload, which
// package runkey and package accesskey both use: package runkey imports package
// accesskey, so accesskey checks the run key of a run code's enrolment answer through
// this package, and both packages read a run key by one definition. Package runkey
// documents the run key.
package runkeywire

import (
	"encoding/base64"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/qoryai/forager/contracts"
)

// Prefix starts every run key.
const Prefix = "qrk_"

// Domain is the first line of the message a run key's signature covers.
const Domain = "qory-run-key-ed25519-v1"

// MaxLength is the most characters a run key has, whole.
const MaxLength = 2048

// Version is the payload's version this package reads and writes.
const Version = 1

// Schema is the payload's schema, by its path under contracts/forager/v1.
const Schema = "run-key.schema.json"

// ErrInvalid is what every *Error matches with errors.Is.
var ErrInvalid = errors.New("not a valid run key")

// Error is why a string is not a valid run key: Reason is the part that is wrong, and
// never contains the run key or any part of its value. It matches [ErrInvalid].
type Error struct {
	Reason string
}

func (e *Error) Error() string { return e.Reason }

// Is reports whether target is [ErrInvalid].
func (e *Error) Is(target error) bool { return target == ErrInvalid }

// Invalid returns an [*Error] with the reason.
func Invalid(format string, a ...any) error { return &Error{Reason: fmt.Sprintf(format, a...)} }

// ServerKey is one entry of the payload's gateway_public_key.
type ServerKey struct {
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
}

// Payload is a run key's payload as run-key.schema.json defines it, its members in the
// order the payload writes them.
type Payload struct {
	Version          int         `json:"version"`
	Signer           string      `json:"signer"`
	RunID            string      `json:"run_id"`
	Workspace        string      `json:"workspace"`
	NodeID           string      `json:"node_id"`
	Gateway          string      `json:"gateway"`
	GatewayURL       string      `json:"gateway_url"`
	GatewayPublicKey []ServerKey `json:"gateway_public_key"`
	InstanceID       string      `json:"instance_id"`
	Issued           string      `json:"issued"`
	AttachBy         string      `json:"attach_by"`
}

// TimeLayout is the payload's times: RFC 3339 in UTC with whole seconds.
const TimeLayout = "2006-01-02T15:04:05Z"

// Read is a payload read: its members, the gateway's keys as the caller's parse
// returned them, and its two times.
type Read[K comparable] struct {
	Payload
	GatewayKeys      []K
	Issued, AttachBy time.Time
}

// Message is what a run key's signature covers: [Domain], a line feed, then the
// payload bytes.
func Message(p []byte) []byte {
	return append([]byte(Domain+"\n"), p...)
}

// Split checks a run key's form and returns its payload bytes and its signature: the
// prefix, at most [MaxLength] characters, and after the prefix the payload and the
// signature in base64url without padding, split on the last dot, the signature 64
// bytes. A character outside base64url and the dot, white space among them, is
// refused.
func Split(s string) ([]byte, []byte, error) {
	if len(s) > MaxLength {
		return nil, nil, Invalid("it is longer than %d characters", MaxLength)
	}
	rest, ok := strings.CutPrefix(s, Prefix)
	if !ok {
		return nil, nil, Invalid("it does not start with %s", Prefix)
	}
	for _, c := range []byte(rest) {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return nil, nil, Invalid("it holds a character outside base64url and the dot, such as white space")
		}
	}
	i := strings.LastIndexByte(rest, '.')
	if i < 0 {
		return nil, nil, Invalid("it has no dot between its payload and its signature")
	}
	strict := base64.RawURLEncoding.Strict()
	p, err := strict.DecodeString(rest[:i])
	if err != nil || len(p) == 0 {
		return nil, nil, Invalid("its payload is not base64url without padding")
	}
	sig, err := strict.DecodeString(rest[i+1:])
	if err != nil || len(sig) != 64 {
		return nil, nil, Invalid("its signature is not 64 bytes in base64url without padding")
	}
	return p, sig, nil
}

// Signed splits a run key, reads its payload's signer, and returns the payload bytes
// once verify reports that the signature over [Message] of them verifies. verify
// returns pinned false when the caller pins no key whose fingerprint is signer, and ok
// true when the signature verifies under that key. It reads nothing of the payload but
// its signer: the caller reads the payload with [ReadPayload] after.
func Signed(s string, verify func(signer string, message, sig []byte) (pinned, ok bool)) ([]byte, error) {
	p, sig, err := Split(s)
	if err != nil {
		return nil, err
	}
	var head struct {
		Signer string `json:"signer"`
	}
	if jsonv2.Unmarshal(p, &head) != nil {
		return nil, Invalid("its payload is not one JSON value in UTF-8 with each member name once")
	}
	if head.Signer == "" {
		return nil, Invalid("its payload names no signer")
	}
	pinned, ok := verify(head.Signer, Message(p), sig)
	if !pinned {
		return nil, Invalid("it is signed by a server key this side does not pin")
	}
	if !ok {
		return nil, Invalid("its signature does not verify")
	}
	return p, nil
}

// schema is run-key.schema.json, compiled once.
var schema = sync.OnceValues(func() (*jsonschema.Schema, error) { return contracts.Compile(Schema) })

// ReadPayload reads a payload's bytes: one JSON object in UTF-8 with each member name
// once, then against run-key.schema.json, then each of the gateway's keys with
// parseKey, which returns ok false for a key the key checks refuse, then the times. An
// error states where in the payload it is and which rule refused it, never a value.
func ReadPayload[K comparable](b []byte, parseKey func(string) (K, bool)) (Read[K], error) {
	var v any
	if err := jsonv2.Unmarshal(b, &v); err != nil {
		return Read[K]{}, Invalid("its payload is not one JSON value in UTF-8 with each member name once")
	}
	doc, err := contracts.Decode("run-key.json", b)
	if err != nil {
		return Read[K]{}, Invalid("its payload is not JSON")
	}
	s, err := schema()
	if err != nil {
		return Read[K]{}, err
	}
	if err := s.Validate(doc); err != nil {
		var ve *jsonschema.ValidationError
		if !errors.As(err, &ve) {
			return Read[K]{}, Invalid("its payload is refused by %s", Schema)
		}
		return Read[K]{}, Invalid("its payload is refused by %s at %s", Schema, strings.Join(leaves(ve), ", "))
	}
	var r Read[K]
	if err := jsonv2.Unmarshal(b, &r.Payload, jsonv2.RejectUnknownMembers(true)); err != nil {
		return Read[K]{}, Invalid("its payload does not decode as a run key's")
	}
	for i, g := range r.GatewayPublicKey {
		k, ok := parseKey(g.PublicKey)
		if !ok {
			return Read[K]{}, Invalid("its payload's /gateway_public_key/%d is not a key the key checks pass", i)
		}
		if slices.Contains(r.GatewayKeys, k) {
			return Read[K]{}, Invalid("its payload's /gateway_public_key lists a key twice")
		}
		r.GatewayKeys = append(r.GatewayKeys, k)
	}
	if r.Issued, err = time.Parse(TimeLayout, r.Payload.Issued); err != nil {
		return Read[K]{}, Invalid("its payload's /issued is not a time")
	}
	if r.AttachBy, err = time.Parse(TimeLayout, r.Payload.AttachBy); err != nil {
		return Read[K]{}, Invalid("its payload's /attach_by is not a time")
	}
	return r, nil
}

// leaves are the places the schema refused, each as the JSON pointer of the value and
// the keyword that refused it, sorted, each once.
func leaves(ve *jsonschema.ValidationError) []string {
	if len(ve.Causes) == 0 {
		var ptr jsontext.Pointer
		for _, t := range ve.InstanceLocation {
			ptr = ptr.AppendToken(t)
		}
		where := string(ptr)
		if where == "" {
			where = "/"
		}
		if ve.ErrorKind != nil {
			if kw := strings.Join(ve.ErrorKind.KeywordPath(), "/"); kw != "" {
				return []string{where + " (" + kw + ")"}
			}
		}
		return []string{where}
	}
	var out []string
	for _, c := range ve.Causes {
		out = append(out, leaves(c)...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
