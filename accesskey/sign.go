package accesskey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The domain lines: the first line of every message an Ed25519 key signs, one per
// kind of message, so a signature of one kind is never a signature of another. An
// answer to an enrolment has its own, EnrolAnswerDomain: its third line is the
// request's proof, which anyone holding a live code can make up, so a signature over an
// enrolment answer never verifies as the answer to a signed request, whose third line
// is that request's signature.
const (
	RequestDomain     = "qory-request-ed25519-v1"
	AnswerDomain      = "qory-answer-ed25519-v1"
	EnrolDomain       = "qory-enrol-ed25519-v1"
	EnrolAnswerDomain = "qory-enrol-answer-ed25519-v1"
)

// The headers of a signed request and of a signed answer.
const (
	HeaderAccessKeyID  = "X-Qory-Access-Key-Id"
	HeaderInstanceID   = "X-Qory-Instance-Id"
	HeaderInstanceName = "X-Qory-Instance-Name"
	HeaderSignature    = "X-Qory-Signature-Ed25519"
	HeaderTimestamp    = "X-Qory-Timestamp"
	// The digests an answer contains, which its signature covers.
	HeaderConfiguration    = "X-Qory-Configuration"
	HeaderRunConfiguration = "X-Qory-Run-Configuration"
)

// Request is one request to the server, as its signature covers it. The request
// string starts with three lines, the domain line, the access key id and the instance
// id, exactly as the headers contain them; then the method in upper case and the
// request target exactly as sent, the path and then "?" and the query when the query
// is non-empty; then, for a GET, the timestamp as sent, and for a POST, the raw body.
// Lines are joined by a line feed, with none after the last.
type Request struct {
	AccessKeyID string
	// InstanceID is the instance id as X-Qory-Instance-Id contains it; empty is an
	// empty line.
	InstanceID string
	Method     string
	Target     string
	// Timestamp is X-Qory-Timestamp's value, on a GET.
	Timestamp string
	// Body is the raw body, on a POST.
	Body []byte
}

// ErrMethod is the error of a request whose method is neither GET nor POST, the two
// the contract signs.
var ErrMethod = errors.New("the contract signs a GET or a POST, and no other method")

// Message returns the request string the signature covers, or [ErrMethod] for a
// method other than GET and POST.
func (r Request) Message() ([]byte, error) {
	method := strings.ToUpper(r.Method)
	if method != http.MethodGet && method != http.MethodPost {
		return nil, ErrMethod
	}
	var b bytes.Buffer
	b.WriteString(RequestDomain + "\n" + r.AccessKeyID + "\n" + r.InstanceID + "\n" + method + "\n" + r.Target + "\n")
	if method == http.MethodPost {
		b.Write(r.Body)
	} else {
		b.WriteString(r.Timestamp)
	}
	return b.Bytes(), nil
}

// SignRequest returns X-Qory-Signature-Ed25519 for a request: its signature under the
// access key, 64 bytes in base64url, or [ErrMethod] for a method other than GET and
// POST.
func (k *Key) SignRequest(r Request) (string, error) {
	m, err := r.Message()
	if err != nil {
		return "", err
	}
	return encodeSignature(k.Sign(m)), nil
}

// VerifyRequest reports whether signature, as X-Qory-Signature-Ed25519 contains it,
// is the request's signature under the public key; a request of another method than
// GET and POST verifies under none.
func (p PublicKey) VerifyRequest(r Request, signature string) bool {
	m, err := r.Message()
	if err != nil {
		return false
	}
	sig, err := decode(signature, ed25519.SignatureSize)
	return err == nil && p.Verify(m, sig)
}

// Timestamp returns X-Qory-Timestamp for a moment: Unix seconds, UTC, a decimal
// integer.
func Timestamp(now time.Time) string { return strconv.FormatInt(now.Unix(), 10) }

// Answer is one answer of the server, as its signature covers it: six lines joined by
// a line feed, with none after the last. The domain line, AnswerDomain, or
// EnrolAnswerDomain for an answer to an enrolment; the status, three decimal digits;
// the request's X-Qory-Signature-Ed25519 exactly as sent, or for an enrolment the
// request's proof; the lower-case hex SHA-256 of the body as the server produced it,
// before any content coding; the answer's X-Qory-Configuration, or empty; and its
// X-Qory-Run-Configuration, or empty. The third line binds the answer to its request,
// and through the request's signature to the access key and the instance that sent it.
type Answer struct {
	// Enrolment marks an answer to an enrolment, whose message starts with
	// EnrolAnswerDomain. [EnrolmentRequest.VerifyAnswer] sets it; a server sets it to
	// sign an enrolment answer.
	Enrolment        bool
	Status           int
	RequestSignature string
	Body             []byte
	Configuration    string
	RunConfiguration string
}

// Message returns the six lines the answer's signature covers.
func (a Answer) Message() []byte {
	domain := AnswerDomain
	if a.Enrolment {
		domain = EnrolAnswerDomain
	}
	sum := sha256.Sum256(a.Body)
	return []byte(domain + "\n" + fmt.Sprintf("%03d", a.Status) + "\n" + a.RequestSignature + "\n" +
		hex.EncodeToString(sum[:]) + "\n" + a.Configuration + "\n" + a.RunConfiguration)
}

// SignAnswer returns X-Qory-Signature-Ed25519 for an answer: its signature under the
// server's signing key, 64 bytes in base64url.
func (k *Key) SignAnswer(a Answer) string { return encodeSignature(k.Sign(a.Message())) }

// ServerKey is one entry of a pin, and of the apiary_public_key list a server's
// discovery and enrolment answer contain: {"alg": "ed25519", "public_key": "<32
// bytes, base64url>"}.
type ServerKey struct {
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
}

// Pin is the machine's pin, apiary_public_key in the server document: the server's
// Ed25519 public keys the gateway verifies every answer under, a list so the server's key
// can rotate. The gateway takes keys from its pin alone, never from an answer.
type Pin []ServerKey

// ParsePin reads a pin written as JSON, the form QORY_APIARY_PUBLIC_KEY contains:
// [{"alg": "ed25519", "public_key": "<32 bytes, base64url>"}]. A member it does not
// define is refused, and so is a member twice. It then runs [Pin.Check]. A pin that
// contains an access key secret is [ErrSecretInDocument], whose message quotes
// nothing.
func ParsePin(b []byte) (Pin, error) {
	if ContainsSecret(string(b)) {
		return nil, ErrSecretInDocument
	}
	var doc any
	if err := jsonv2.Unmarshal(b, &doc); err != nil {
		return nil, errors.New("the pin is not a JSON list of {alg, public_key}")
	}
	if DocumentContainsSecret(doc) {
		return nil, ErrSecretInDocument
	}
	var p Pin
	if err := jsonv2.Unmarshal(b, &p, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("the pin is not a list of {alg, public_key}: %w", err)
	}
	if err := p.Check(); err != nil {
		return nil, err
	}
	return p, nil
}

// Check refuses a pin the gateway cannot verify under: an empty one, an entry whose alg
// is not ed25519, a key not in base64url of 32 bytes, a key twice, and a key
// [PublicKey.Check] refuses, since a key of small order verifies signatures nobody
// made.
func (p Pin) Check() error {
	if len(p) == 0 {
		return errors.New("the pin lists no key")
	}
	seen := map[PublicKey]bool{}
	for _, k := range p {
		if k.Alg != "ed25519" {
			return fmt.Errorf("the pin lists a key of alg %s; ed25519 is the one", shown(k.Alg))
		}
		pub, err := ParsePublicKey(k.PublicKey)
		if err != nil {
			return fmt.Errorf("the pin: %w", err)
		}
		if err := pub.Check(); err != nil {
			return fmt.Errorf("the pin's key %s: %w", shown(k.PublicKey), err)
		}
		if seen[pub] {
			return fmt.Errorf("the pin lists the key %s twice", shown(k.PublicKey))
		}
		seen[pub] = true
	}
	return nil
}

// Keys returns the pin's public keys, leaving out an entry that is not an ed25519 key
// [PublicKey.Check] passes.
func (p Pin) Keys() []PublicKey {
	var out []PublicKey
	for _, k := range p {
		if k.Alg != "ed25519" {
			continue
		}
		if pub, err := ParsePublicKey(k.PublicKey); err == nil && pub.Check() == nil {
			out = append(out, pub)
		}
	}
	return out
}

// Fixture reports whether the pin lists a published fixture key, [PublicKey.Fixture].
func (p Pin) Fixture() bool {
	for _, k := range p.Keys() {
		if k.Fixture() {
			return true
		}
	}
	return false
}

// Verify reports whether signature, 64 bytes in base64url, is the signature of
// message under one of the pin's keys.
func (p Pin) Verify(message []byte, signature string) bool {
	sig, err := decode(signature, ed25519.SignatureSize)
	if err != nil {
		return false
	}
	for _, k := range p.Keys() {
		if k.Verify(message, sig) {
			return true
		}
	}
	return false
}

// VerifyAnswer reports whether signature, as the answer's X-Qory-Signature-Ed25519
// contains it, is the answer's signature under one of the pin's keys.
func (p Pin) VerifyAnswer(a Answer, signature string) bool { return p.Verify(a.Message(), signature) }

// ErrSecretInDocument is the error of a document that contains an access key secret
// where none belongs: a fixed message, so the secret appears in no error.
var ErrSecretInDocument = errors.New("the document contains an access key secret, which belongs in access-key-secret or QORY_ACCESS_KEY_SECRET and nowhere else")

// encodeSignature writes a signature in base64url without padding.
func encodeSignature(sig []byte) string { return base64.RawURLEncoding.EncodeToString(sig) }
