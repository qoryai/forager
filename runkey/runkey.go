package runkey

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

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
)

// Prefix starts every run key, so secret scanners recognise one.
const Prefix = "qrk_"

// Domain is the first line of the message a run key's signature covers: the domain
// line, a line feed, then the payload bytes. No other message of the contract starts
// with it, so a run key's signature is never a signature of another kind.
const Domain = "qory-run-key-ed25519-v1"

// MaxLength is the most characters a run key has, whole: it bounds the relay's
// preamble and the Authorization header that carry it.
const MaxLength = 2048

// Version is the payload's version this package reads and writes.
const Version = 1

// Schema is the payload's schema, by its path under contracts/forager/v1.
const Schema = "run-key.schema.json"

// ErrInvalid is what every error of [Parse], [Verify] and [Key.Sign] matches with
// errors.Is: the string is not a run key, or not one this side accepts.
var ErrInvalid = errors.New("not a valid run key")

// Error is why a string is not a valid run key: Reason names the part that is wrong,
// "its signature does not verify" say, and never contains the run key or any part of
// its value. It matches [ErrInvalid].
type Error struct {
	Reason string
}

func (e *Error) Error() string { return e.Reason }

// Is reports whether target is [ErrInvalid].
func (e *Error) Is(target error) bool { return target == ErrInvalid }

// invalid returns an [*Error] with the reason.
func invalid(format string, a ...any) error { return &Error{Reason: fmt.Sprintf(format, a...)} }

// Key is a run key's payload, read: the run, its workspace, the node or node pool that
// registered it, the gateway its choice resolved to at that registration, with the
// gateway's URL and live keys, the registration's signed instance id, the server key
// that signed it, when Qory Apiary made it and the end of its attach window.
type Key struct {
	// RunID is the run's id, a UUID in the canonical lower-case form.
	RunID string
	// Workspace is the run's workspace, ws_.
	Workspace string
	// NodeID is the node, nd_, or node pool, np_, that registered the run.
	NodeID string
	// Gateway is the gateway the run attaches at, ng_.
	Gateway string
	// InstanceID is the registration's signed instance id.
	InstanceID string
	// GatewayURL is where the edge reaches the gateway: an https origin, the one
	// address the run key is ever sent to.
	GatewayURL string
	// GatewayKeys are the gateway's live keys, current then next, one or two: the pin
	// for the gateway's answers and for the channel binding.
	GatewayKeys []accesskey.PublicKey
	// Signer is the fingerprint of the server key that signed the run key.
	Signer string
	// Issued is when Qory Apiary made the run key, and AttachBy the end of its attach
	// window, each in UTC with whole seconds. A runner never checks either.
	Issued, AttachBy time.Time

	verified bool
}

// Verified reports whether the run key's signature was verified under a pinned server
// key: true for a [Key] of [Verify], false for one of [Parse], which grants nothing.
func (k Key) Verified() bool { return k.verified }

// payload is a run key's payload as run-key.schema.json defines it, its members in the
// order the payload writes them.
type payload struct {
	Version          int                   `json:"version"`
	Signer           string                `json:"signer"`
	RunID            string                `json:"run_id"`
	Workspace        string                `json:"workspace"`
	NodeID           string                `json:"node_id"`
	Gateway          string                `json:"gateway"`
	GatewayURL       string                `json:"gateway_url"`
	GatewayPublicKey []accesskey.ServerKey `json:"gateway_public_key"`
	InstanceID       string                `json:"instance_id"`
	Issued           string                `json:"issued"`
	AttachBy         string                `json:"attach_by"`
}

// timeLayout is the payload's times: RFC 3339 in UTC with whole seconds.
const timeLayout = "2006-01-02T15:04:05Z"

// Parse reads a run key without verifying it, as a runner does, which pins no server
// key: the prefix, the length, two parts of base64url without padding, a signature of
// 64 bytes and a payload run-key.schema.json accepts. The [Key] it returns reports
// false from [Key.Verified]: the parse grants nothing, and of it a runner takes only
// RunID, GatewayURL and GatewayKeys.
func Parse(s string) (Key, error) {
	p, _, err := split(s)
	if err != nil {
		return Key{}, err
	}
	return read(p)
}

// Verify reads a run key as the gateway and Qory Apiary do: it splits the run key,
// finds the key of pin whose fingerprint equals the payload's signer, verifies the
// signature over [Domain], a line feed and the payload bytes under it, and only then
// reads the payload against run-key.schema.json. A signer the pin does not hold, a
// signature that does not verify and a payload the schema refuses are each an error.
// It checks no time: Issued and AttachBy are the caller's to judge.
func Verify(s string, pin accesskey.Pin) (Key, error) {
	p, sig, err := split(s)
	if err != nil {
		return Key{}, err
	}
	var head struct {
		Signer string `json:"signer"`
	}
	if jsonv2.Unmarshal(p, &head) != nil {
		return Key{}, invalid("its payload is not one JSON value in UTF-8 with each member name once")
	}
	if head.Signer == "" {
		return Key{}, invalid("its payload names no signer")
	}
	var signer *accesskey.PublicKey
	for _, k := range pin.Keys() {
		if k.Fingerprint() == head.Signer {
			signer = &k
			break
		}
	}
	if signer == nil {
		return Key{}, invalid("it is signed by a server key this side does not pin")
	}
	if !signer.Verify(message(p), sig) {
		return Key{}, invalid("its signature does not verify")
	}
	k, err := read(p)
	if err != nil {
		return Key{}, err
	}
	k.verified = true
	return k, nil
}

// Sign returns the run key of k signed under the server signing key signer, as Qory
// Apiary makes one: the payload's bytes with k's members, its signer signer's
// fingerprint whatever k.Signer holds, and its times in UTC with whole seconds. A
// payload run-key.schema.json refuses, or a run key longer than [MaxLength], is an
// error, and no run key is made.
func (k Key) Sign(signer *accesskey.Key) (string, error) {
	if signer == nil {
		return "", invalid("it has no server key to sign it")
	}
	p := payload{
		Version: Version, Signer: signer.Fingerprint(), RunID: k.RunID, Workspace: k.Workspace,
		NodeID: k.NodeID, Gateway: k.Gateway, GatewayURL: k.GatewayURL, InstanceID: k.InstanceID,
		Issued: k.Issued.UTC().Format(timeLayout), AttachBy: k.AttachBy.UTC().Format(timeLayout),
	}
	for _, g := range k.GatewayKeys {
		p.GatewayPublicKey = append(p.GatewayPublicKey, accesskey.ServerKey{Alg: "ed25519", PublicKey: g.String()})
	}
	b, err := jsonv2.Marshal(p)
	if err != nil {
		return "", invalid("its payload does not encode")
	}
	if _, err := read(b); err != nil {
		return "", err
	}
	s := Prefix + base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(signer.Sign(message(b)))
	if len(s) > MaxLength {
		return "", invalid("it is longer than %d characters", MaxLength)
	}
	return s, nil
}

// message is what a run key's signature covers: [Domain], a line feed, then the payload
// bytes.
func message(p []byte) []byte {
	return append([]byte(Domain+"\n"), p...)
}

// split checks a run key's form and returns its payload bytes and its signature: the
// prefix, at most [MaxLength] characters, and after the prefix the payload and the
// signature in base64url without padding, split on the last dot, the signature 64
// bytes. A character outside base64url and the dot, white space among them, is
// refused.
func split(s string) ([]byte, []byte, error) {
	if len(s) > MaxLength {
		return nil, nil, invalid("it is longer than %d characters", MaxLength)
	}
	rest, ok := strings.CutPrefix(s, Prefix)
	if !ok {
		return nil, nil, invalid("it does not start with %s", Prefix)
	}
	for _, c := range []byte(rest) {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return nil, nil, invalid("it holds a character outside base64url and the dot, such as white space")
		}
	}
	i := strings.LastIndexByte(rest, '.')
	if i < 0 {
		return nil, nil, invalid("it has no dot between its payload and its signature")
	}
	strict := base64.RawURLEncoding.Strict()
	p, err := strict.DecodeString(rest[:i])
	if err != nil || len(p) == 0 {
		return nil, nil, invalid("its payload is not base64url without padding")
	}
	sig, err := strict.DecodeString(rest[i+1:])
	if err != nil || len(sig) != 64 {
		return nil, nil, invalid("its signature is not 64 bytes in base64url without padding")
	}
	return p, sig, nil
}

// schema is run-key.schema.json, compiled once.
var schema = sync.OnceValues(func() (*jsonschema.Schema, error) { return contracts.Compile(Schema) })

// read reads a payload's bytes: one JSON object in UTF-8 with each member name once,
// then against run-key.schema.json, then the gateway's keys against the key checks.
// An error names where in the payload it is and which rule refused it, never a value.
func read(b []byte) (Key, error) {
	var v any
	if err := jsonv2.Unmarshal(b, &v); err != nil {
		return Key{}, invalid("its payload is not one JSON value in UTF-8 with each member name once")
	}
	doc, err := contracts.Decode("run-key.json", b)
	if err != nil {
		return Key{}, invalid("its payload is not JSON")
	}
	s, err := schema()
	if err != nil {
		return Key{}, err
	}
	if err := s.Validate(doc); err != nil {
		var ve *jsonschema.ValidationError
		if !errors.As(err, &ve) {
			return Key{}, invalid("its payload is refused by %s", Schema)
		}
		return Key{}, invalid("its payload is refused by %s at %s", Schema, strings.Join(leaves(ve), ", "))
	}
	var p payload
	if err := jsonv2.Unmarshal(b, &p, jsonv2.RejectUnknownMembers(true)); err != nil {
		return Key{}, invalid("its payload does not decode as a run key's")
	}
	k := Key{
		RunID: p.RunID, Workspace: p.Workspace, NodeID: p.NodeID, Gateway: p.Gateway,
		InstanceID: p.InstanceID, GatewayURL: p.GatewayURL, Signer: p.Signer,
	}
	for i, g := range p.GatewayPublicKey {
		pub, err := accesskey.ParsePublicKey(g.PublicKey)
		if err != nil || pub.Check() != nil {
			return Key{}, invalid("its payload's /gateway_public_key/%d is not a key the key checks pass", i)
		}
		if slices.Contains(k.GatewayKeys, pub) {
			return Key{}, invalid("its payload's /gateway_public_key lists a key twice")
		}
		k.GatewayKeys = append(k.GatewayKeys, pub)
	}
	if k.Issued, err = time.Parse(timeLayout, p.Issued); err != nil {
		return Key{}, invalid("its payload's /issued is not a time")
	}
	if k.AttachBy, err = time.Parse(timeLayout, p.AttachBy); err != nil {
		return Key{}, invalid("its payload's /attach_by is not a time")
	}
	return k, nil
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
