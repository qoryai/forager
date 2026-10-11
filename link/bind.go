package link

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/runkey"
)

// The binding of a connection to a separate gateway's one address, and the signature of
// its answers: every TLS 1.3 connection there opens with the edge's [BindWord] line,
// which the gateway answers with its [BoundWord] line, a signature under its key over
// the connection's TLS exporter value, before the edge sends the run key. Then the
// connection carries HTTP/1.1, the link, every request with the run key as its bearer
// value and every answer signed under the gateway's key, or the relay's preamble with
// the run key, [RelayPreamble], and the proxy's bytes.
const (
	// BindWord is the edge's line, this word and a newline, the first bytes of every
	// bound connection.
	BindWord = "QORY-BIND"
	// BoundWord begins the gateway's line: this word, a space, the fingerprint of the
	// key it signs under, a space, the signature in base64url without padding and a
	// newline.
	BoundWord = "QORY-BOUND"
	// BindingLabel is the label of the TLS exporter value both ends derive (RFC 8446
	// §7.5), with an empty context, [BindingLength] bytes.
	BindingLabel  = "EXPORTER-qory-link-binding"
	BindingLength = 32
	// BindingDomain is the first line of the message the gateway's [BoundWord] line
	// signs: the domain line, the lower-case hex of the exporter value and the
	// fingerprint, joined by a line feed.
	BindingDomain = "qory-link-binding-ed25519-v1"
	// AnswerDomain is the first line of the six lines the gateway's answers on a bound
	// connection are signed over, [Answer].
	AnswerDomain = "qory-link-answer-ed25519-v1"
	// RemoteDiscovery is the path of a separate gateway's discovery on its one address;
	// every path of the link there begins with RemotePrefix, so none is a path of the
	// server's the gateway relays.
	RemoteDiscovery = "/qory-link/configuration"
	RemotePrefix    = "/qory-link/"
)

// MaxBound is the longest [BoundWord] line, its newline included: the word, a
// fingerprint of 22 characters and a signature of 86, with their spaces.
const MaxBound = len(BoundWord) + 1 + 22 + 1 + 86 + 1

// MaxRelayRunKey is the longest relay preamble with a run key, its newline included:
// [RelayPreamble], a space, a run key of at most [runkey.MaxLength] characters and a
// newline.
const MaxRelayRunKey = len(RelayPreamble) + 1 + runkey.MaxLength + 1

// Binding is a TLS 1.3 connection's exporter value of [BindingLabel], with an empty
// context, [BindingLength] bytes: what both ends of a bound connection derive alike. A
// connection of another version has none.
func Binding(cs tls.ConnectionState) ([]byte, error) {
	if cs.Version != tls.VersionTLS13 {
		return nil, errors.New("the connection is not TLS 1.3, which a binding needs")
	}
	return cs.ExportKeyingMaterial(BindingLabel, nil, BindingLength)
}

// BindingMessage is what the gateway's [BoundWord] line signs: [BindingDomain], the
// lower-case hex of the exporter value ekm and the fingerprint of the key that signs,
// joined by a line feed, with none after the last.
func BindingMessage(ekm []byte, fingerprint string) []byte {
	return []byte(BindingDomain + "\n" + hex.EncodeToString(ekm) + "\n" + fingerprint)
}

// BoundLine is the gateway's [BoundWord] line for the exporter value ekm, signed under
// its key.
func BoundLine(key *accesskey.Key, ekm []byte) string {
	fp := key.Fingerprint()
	return BoundWord + " " + fp + " " + base64.RawURLEncoding.EncodeToString(key.Sign(BindingMessage(ekm, fp))) + "\n"
}

// ErrNotBound is what every error of [ReadBound] matches with errors.Is: the gateway
// did not prove it holds one of the keys the edge pins.
var ErrNotBound = errors.New("the gateway did not prove it holds a key it was named by")

// boundError is why a [BoundWord] line is refused; it matches [ErrNotBound].
type boundError struct{ why string }

func (e *boundError) Error() string { return e.why }

// Is matches [ErrNotBound].
func (e *boundError) Is(target error) bool { return target == ErrNotBound }

// ReadBound reads the gateway's [BoundWord] line from r, at most [MaxBound] bytes, and
// verifies its signature over the exporter value ekm under the key of keys whose
// fingerprint it names, which it returns. A line that does not come, is not one, names
// a key keys does not hold, or whose signature does not verify, is an error matching
// [ErrNotBound]. What follows the line stays in r.
func ReadBound(r *bufio.Reader, ekm []byte, keys []accesskey.PublicKey) (accesskey.PublicKey, error) {
	var line []byte
	for len(line) < MaxBound {
		c, err := r.ReadByte()
		if err != nil {
			return accesskey.PublicKey{}, &boundError{"no " + BoundWord + " line came"}
		}
		line = append(line, c)
		if c == '\n' {
			break
		}
	}
	rest, ok := bytes.CutPrefix(line, []byte(BoundWord+" "))
	rest, nl := bytes.CutSuffix(rest, []byte("\n"))
	fp, sig, two := strings.Cut(string(rest), " ")
	if !ok || !nl || !two {
		return accesskey.PublicKey{}, &boundError{"the gateway's first line is not a " + BoundWord + " line"}
	}
	for _, k := range keys {
		if k.Fingerprint() != fp {
			continue
		}
		b, err := base64.RawURLEncoding.Strict().DecodeString(sig)
		if err != nil || len(b) != 64 || !k.Verify(BindingMessage(ekm, fp), b) {
			return accesskey.PublicKey{}, &boundError{"the " + BoundWord + " signature does not verify"}
		}
		return k, nil
	}
	return accesskey.PublicKey{}, &boundError{"the " + BoundWord + " line names a key it was not named by"}
}

// AnswerRequest is the third line of a bound answer's six: the lower-case hex SHA-256
// of the lower-case hex of the connection's exporter value ekm, the request's method in
// upper case, its target exactly as sent, the path and then "?" and the query when the
// query is not empty, and its body for a POST, empty for a GET, joined by a line feed.
// It binds the answer to its connection and its request, which carries no signature of
// its own.
func AnswerRequest(ekm []byte, method, target string, body []byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n", hex.EncodeToString(ekm), strings.ToUpper(method), target)
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// Answer is one answer of a separate gateway on a bound connection, as its
// X-Qory-Signature-Ed25519 covers it: six lines joined by a line feed, with none after
// the last. [AnswerDomain]; the status, three decimal digits; Request, the request's
// line, [AnswerRequest]; the lower-case hex SHA-256 of the body; the answer's
// X-Qory-Configuration, or empty; and its X-Qory-Run-Configuration, or empty.
type Answer struct {
	Status           int
	Request          string
	Body             []byte
	Configuration    string
	RunConfiguration string
}

// Message is the six lines the answer's signature covers.
func (a Answer) Message() []byte {
	sum := sha256.Sum256(a.Body)
	return []byte(AnswerDomain + "\n" + fmt.Sprintf("%03d", a.Status) + "\n" + a.Request + "\n" +
		hex.EncodeToString(sum[:]) + "\n" + a.Configuration + "\n" + a.RunConfiguration)
}

// SignAnswer is the answer's X-Qory-Signature-Ed25519 under the gateway's key: 64
// bytes in base64url without padding.
func SignAnswer(key *accesskey.Key, a Answer) string {
	return base64.RawURLEncoding.EncodeToString(key.Sign(a.Message()))
}

// VerifyAnswer reports whether signature, as X-Qory-Signature-Ed25519 holds it, is
// the answer's under one of keys.
func VerifyAnswer(keys []accesskey.PublicKey, a Answer, signature string) bool {
	sig, err := base64.RawURLEncoding.Strict().DecodeString(signature)
	if err != nil || len(sig) != 64 {
		return false
	}
	m := a.Message()
	for _, k := range keys {
		if k.Verify(m, sig) {
			return true
		}
	}
	return false
}
