package runkey

import (
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/internal/runkeywire"
)

// Prefix starts every run key, so secret scanners recognise one.
const Prefix = runkeywire.Prefix

// Domain is the first line of the message a run key's signature covers: the domain
// line, a line feed, then the payload bytes. No other message of the contract starts
// with it, so a run key's signature is never a signature of another kind.
const Domain = runkeywire.Domain

// MaxLength is the most characters a run key has, whole: it bounds the relay's
// preamble and the Authorization header that carry it.
const MaxLength = runkeywire.MaxLength

// Version is the payload's version this package reads and writes.
const Version = runkeywire.Version

// Schema is the payload's schema, by its path under contracts/forager/v1.
const Schema = runkeywire.Schema

// ErrInvalid is what every error of [Parse], [Verify] and [Key.Sign] matches with
// errors.Is: the string is not a run key, or not one this side accepts.
var ErrInvalid = runkeywire.ErrInvalid

// Error is why a string is not a valid run key: Reason states the part that is wrong,
// "its signature does not verify" say, and never contains the run key or any part of
// its value. It matches [ErrInvalid].
type Error = runkeywire.Error

// invalid returns an [*Error] with the reason.
func invalid(format string, a ...any) error { return runkeywire.Invalid(format, a...) }

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

// Parse reads a run key without verifying it, as a runner does, which pins no server
// key: the prefix, the length, two parts of base64url without padding, a signature of
// 64 bytes and a payload run-key.schema.json accepts. The [Key] it returns reports
// false from [Key.Verified]: the parse grants nothing, and of it a runner takes only
// RunID, GatewayURL and GatewayKeys.
func Parse(s string) (Key, error) {
	p, _, err := runkeywire.Split(s)
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
	p, err := runkeywire.Signed(s, func(signer string, m, sig []byte) (bool, bool) {
		for _, k := range pin.Keys() {
			if k.Fingerprint() == signer {
				return true, k.Verify(m, sig)
			}
		}
		return false, false
	})
	if err != nil {
		return Key{}, err
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
	p := runkeywire.Payload{
		Version: Version, Signer: signer.Fingerprint(), RunID: k.RunID, Workspace: k.Workspace,
		NodeID: k.NodeID, Gateway: k.Gateway, GatewayURL: k.GatewayURL, InstanceID: k.InstanceID,
		Issued: k.Issued.UTC().Format(runkeywire.TimeLayout), AttachBy: k.AttachBy.UTC().Format(runkeywire.TimeLayout),
	}
	for _, g := range k.GatewayKeys {
		p.GatewayPublicKey = append(p.GatewayPublicKey, runkeywire.ServerKey{Alg: "ed25519", PublicKey: g.String()})
	}
	b, err := jsonv2.Marshal(p)
	if err != nil {
		return "", invalid("its payload does not encode")
	}
	if _, err := read(b); err != nil {
		return "", err
	}
	s := Prefix + base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(signer.Sign(runkeywire.Message(b)))
	if len(s) > MaxLength {
		return "", invalid("it is longer than %d characters", MaxLength)
	}
	return s, nil
}

// read reads a payload's bytes as [runkeywire.ReadPayload] does, the gateway's keys
// under the key checks of package accesskey. An error states where in the payload it is
// and which rule refused it, never a value.
func read(b []byte) (Key, error) {
	r, err := runkeywire.ReadPayload(b, func(s string) (accesskey.PublicKey, bool) {
		pub, err := accesskey.ParsePublicKey(s)
		return pub, err == nil && pub.Check() == nil
	})
	if err != nil {
		return Key{}, err
	}
	return Key{
		RunID: r.RunID, Workspace: r.Workspace, NodeID: r.NodeID, Gateway: r.Gateway,
		InstanceID: r.InstanceID, GatewayURL: r.GatewayURL, Signer: r.Signer,
		GatewayKeys: r.GatewayKeys, Issued: r.Issued, AttachBy: r.AttachBy,
	}, nil
}
