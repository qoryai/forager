package link

import (
	"crypto/sha256"
	"encoding/hex"
)

// The wire of the link to a separate gateway (contracts/forager/v1/README.md §The
// gateway's link): every TLS 1.3 connection of a run's edge to the gateway's one address
// opens with the binding exchange, before anything else. The edge writes [BindWord] and
// a newline; the gateway derives the connection's exporter value, [BindingLabel], an
// empty context and [BindingSize] bytes (RFC 8446 §7.5), and writes [BoundWord], a
// space, the fingerprint of one of its keys, a space, and its Ed25519 signature under
// that key over [BindingMessage], base64url without padding, and a newline. The edge
// derives the same value and verifies the signature under the key the run key names by
// that fingerprint; only then does it send the run key, on HTTP/1.1 requests of the
// link or in the relay's preamble of a proxy connection.
const (
	// BindWord is the edge's first line on a connection to a separate gateway, without
	// its newline.
	BindWord = "QORY-BIND"
	// BoundWord begins the gateway's answer to [BindWord].
	BoundWord = "QORY-BOUND"
	// BindingLabel is the label of the TLS exporter both ends derive the connection's
	// binding value with, under an empty context.
	BindingLabel = "EXPERIMENTAL-qory-link-binding"
	// BindingSize is how many bytes of the exporter they derive.
	BindingSize = 32
	// BindingDomain is the first line of the message the gateway signs to prove it holds
	// a key the run key names, so that signature is never one of another kind.
	BindingDomain = "qory-link-binding-ed25519-v1"
	// MaxBoundLine is the longest line the edge reads as the gateway's answer to
	// [BindWord], its newline included.
	MaxBoundLine = 256
)

// The paths of a separate gateway's link. Every one of them begins with
// [RemotePathPrefix], so none is a path the gateway relays to Qory Apiary; the local
// link keeps the server's well-known path for its discovery.
const (
	RemotePathPrefix    = "/qory-link/"
	RemoteDiscoveryPath = RemotePathPrefix + "configuration"
)

// BindLine is the edge's first line on a connection to a separate gateway: [BindWord]
// and a newline.
const BindLine = BindWord + "\n"

// BindingMessage is what the gateway signs to prove it holds the key of fingerprint on
// the connection whose exporter value is ekm: [BindingDomain], a line feed, the lower-case
// hex of ekm, a line feed, and the fingerprint.
func BindingMessage(ekm []byte, fingerprint string) []byte {
	return []byte(BindingDomain + "\n" + hex.EncodeToString(ekm) + "\n" + fingerprint)
}

// BoundLine is the gateway's answer to [BindWord]: [BoundWord], a space, the
// fingerprint, a space, the signature in base64url without padding, and a newline.
func BoundLine(fingerprint, signature string) string {
	return BoundWord + " " + fingerprint + " " + signature + "\n"
}

// AnswerRequest is the third line of a separate gateway's answer signature, which binds
// the answer to the connection whose exporter value is ekm and to the request it
// answers, since the request has no signature of its own: the lower-case hex SHA-256 of
// the hex of ekm, the method, the request target as sent, the path and "?" and the query
// when it has one, and the body for a POST, empty for a GET, joined by line feeds.
func AnswerRequest(ekm []byte, method, target string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(hex.EncodeToString(ekm) + "\n" + method + "\n" + target + "\n"))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
