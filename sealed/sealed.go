// Package sealed opens the answer to the contract's secrets request: the values of a
// run configuration's credentials, sealed with HPKE base mode to an access key and
// signed under the server's key (contracts/forager/v1, §The server, Secrets).
//
// [Open] checks and opens an answer in the contract's order: a suite other than
// [Suite] first, then the answer against secrets-answer.schema.json, decoded strictly;
// the signature under the pinned apiary_public_key; the access key id, the run id and
// the run configuration's digest against the caller's; exp against the caller's clock;
// the open, crypto/hpke with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM,
// with info and aad built from the caller's values alone; and the plaintext against
// sealed-plaintext.schema.json and against the request. Each refusal wraps one of the
// Err values of this package, so a caller distinguishes them with errors.Is. No error
// contains a value, and a credential's name in an error goes through
// [accesskey.ShownName].
//
// What opens is [Values]: each value by its credential's name, stored as bytes and
// never as a Go string, since a Go string cannot be overwritten. A Values formats as
// its count whatever the verb, and marshals as text to the same, so a log line, an
// event or an error that prints one contains no value; [Values.Clear] overwrites every
// byte. This package cannot clear the JSON decoder's buffers or the HPKE context's copy
// of the key.
//
// [Seal] is the server's side, for a receiver and the tests: it seals the values to an
// access key's public key with a fresh ephemeral key and signs the envelope.
package sealed

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
)

// Suite is the envelope's suite on the wire: RFC 9180 base mode with DHKEM(X25519,
// HKDF-SHA256), HKDF-SHA256 and AES-256-GCM.
const Suite = "x25519-sha256-aes256gcm"

// The identifiers of the suite's three parts, as RFC 9180 numbers them and as info
// contains them.
const (
	KEMID  = 0x0020
	KDFID  = 0x0001
	AEADID = 0x0002
)

// The domain strings of info and of the envelope's signed message.
const (
	InfoDomain     = "qory secrets v1"
	EnvelopeDomain = "qory envelope v1"
)

// The bounds of the contract.
const (
	// MaxAnswer is the largest secrets answer, 5 MiB.
	MaxAnswer = 5 << 20
	// MaxCredentials is how many credentials a request lists at most, and so how many
	// values a plaintext has.
	MaxCredentials = 8
	// MaxValueBytes is the largest value, in bytes of UTF-8.
	MaxValueBytes = 16384
	// Lifetime is how far after its clock the server sets exp, in seconds.
	Lifetime = 600
	// ExpiredAfter is how long after exp an envelope still opens, in seconds, and
	// AheadBy how far ahead of the clock exp may lie.
	ExpiredAfter = 300
	AheadBy      = 900
)

// The refusals of [Open]. Each error Open returns wraps exactly one of them.
var (
	// ErrRequest is a call whose access key, run id, digest or credentials are outside
	// the contract's forms, or a sealing outside them: no answer is read.
	ErrRequest = errors.New("the secrets request is not one the contract allows")
	// ErrAnswer is an answer that is not one secrets-answer.schema.json accepts,
	// decoded strictly: a member twice or unknown, an exp with a sign, fraction or
	// exponent, a binary value not in strict base64url, or the wrong length.
	ErrAnswer = errors.New("the secrets answer is not one secrets-answer.schema.json accepts")
	// ErrSuite is an envelope of a suite other than [Suite].
	ErrSuite = errors.New("the envelope's suite is not " + Suite)
	// ErrSignature is an envelope whose sig does not verify under the pin.
	ErrSignature = errors.New("the envelope's sig does not verify under the pinned apiary_public_key")
	// ErrAccessKey is an envelope sealed to another access key id.
	ErrAccessKey = errors.New("the envelope is sealed to another access key")
	// ErrRun is an envelope for another run id.
	ErrRun = errors.New("the envelope is for another run")
	// ErrDigest is an envelope, or a plaintext, for another run configuration digest.
	ErrDigest = errors.New("the envelope is for another run configuration")
	// ErrExpired is an exp more than [ExpiredAfter] seconds past.
	ErrExpired = errors.New("the envelope's exp is more than 300 seconds past")
	// ErrAhead is an exp more than [AheadBy] seconds ahead.
	ErrAhead = errors.New("the envelope's exp is more than 900 seconds ahead")
	// ErrOpen is an envelope that does not open with the access key, info and aad
	// built from the caller's values: a wrong aad, a wrong info, another recipient or
	// an altered ct.
	ErrOpen = errors.New("the envelope does not open with the access key")
	// ErrPlaintext is a plaintext that is not one sealed-plaintext.schema.json
	// accepts, or whose credentials or values are out of order.
	ErrPlaintext = errors.New("the plaintext is not one sealed-plaintext.schema.json accepts")
	// ErrCredentials is a plaintext whose credentials are not the set requested.
	ErrCredentials = errors.New("the plaintext lists other credentials than the request")
	// ErrNotRequested is a value for a credential the request did not ask for.
	ErrNotRequested = errors.New("the plaintext has a value for a credential the request did not ask for")
	// ErrMissing is a requested credential without a value.
	ErrMissing = errors.New("the plaintext has no value for a credential the request asked for")
	// ErrTwice is a credential with two values.
	ErrTwice = errors.New("the plaintext has two values for one credential")
	// ErrValue is a value that is not 1 to [MaxValueBytes] bytes of UTF-8 without a NUL.
	ErrValue = errors.New("a value is not 1 to 16384 bytes of UTF-8 without a NUL")
)

// refuse wraps one of the Err values with a detail. The detail contains identifiers alone
// and never a value.
func refuse(err error, format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{err}, a...)...)
}

// Values are the values an envelope opened to, by credential name, stored as bytes. A
// Values formats as its count whatever the verb, and marshals as text to the same. The
// map is stored through a pointer, so fmt printing a Values by reflection, as an
// unexported field of a struct, prints an address alone. The zero Values has none.
type Values struct {
	m *map[string][]byte
}

// Value returns the value of a credential and whether the envelope had one. The bytes
// are the stored ones, not a copy: the caller keeps no copy past its use, and
// [Values.Clear] overwrites them.
func (v Values) Value(credential string) ([]byte, bool) {
	if v.m == nil {
		return nil, false
	}
	b, ok := (*v.m)[credential]
	return b, ok
}

// Credentials returns the names of the credentials stored, sorted.
func (v Values) Credentials() []string {
	if v.m == nil {
		return nil
	}
	out := make([]string, 0, len(*v.m))
	for name := range *v.m {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// Len returns how many values are stored.
func (v Values) Len() int {
	if v.m == nil {
		return 0
	}
	return len(*v.m)
}

// Clear overwrites every value's bytes with zeros and drops them.
func (v Values) Clear() {
	if v.m == nil {
		return
	}
	for name, b := range *v.m {
		clear(b)
		delete(*v.m, name)
	}
}

// String returns how many values are stored, and nothing of them.
func (v Values) String() string {
	if n := v.Len(); n != 1 {
		return strconv.Itoa(n) + " sealed values"
	}
	return "1 sealed value"
}

// GoString returns what String returns.
func (v Values) GoString() string { return v.String() }

// Format writes what String returns, whatever the verb.
func (v Values) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, v.String()) }

// MarshalText returns what String returns, so a structured log or a JSON document of a
// Values shows its count.
func (v Values) MarshalText() ([]byte, error) { return []byte(v.String()), nil }
