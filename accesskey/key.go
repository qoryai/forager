package accesskey

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"filippo.io/edwards25519"
)

// SecretPrefix starts every access key secret, so secret scanners recognise one.
const SecretPrefix = "qak_"

// SeedSize is the size of an access key's seed, the whole of its secret.
const SeedSize = ed25519.SeedSize

// Key is an Ed25519 key, held from its seed: an access key, whose secret signs the
// runner's requests, or a server's signing key, whose public key a machine pins. It
// formats as its fingerprint alone, whatever the verb, and marshals as text to the
// same, so a log line that prints one shows which key it is and never its secret. The
// key material sits behind two pointers, so a Key printed by reflection, as a field
// fmt does not format through its methods, shows addresses alone.
type Key struct {
	m *material
}

// material is a Key's private key, itself behind a pointer: fmt prints a pointer below
// the top level as its address, so even a bad verb on a material shows no byte of it.
type material struct {
	priv *ed25519.PrivateKey
}

// Generate returns a new key from the system's random source.
func Generate() (*Key, error) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("the system's random source: %w", err)
	}
	return NewKey(seed)
}

// NewKey returns the key of a 32-byte seed.
func NewKey(seed []byte) (*Key, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("a seed is %d bytes, and this one is %d", SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Key{m: &material{priv: &priv}}, nil
}

// ParseSecret reads an access key secret: "qak_" and the seed in base64url without
// padding, decoded strictly. Surrounding white space, a line feed after a secret
// read from a file say, is the caller's to remove.
func ParseSecret(secret string) (*Key, error) {
	encoded, ok := strings.CutPrefix(secret, SecretPrefix)
	if !ok {
		return nil, errors.New("an access key secret starts with " + SecretPrefix)
	}
	seed, err := decode(encoded, SeedSize)
	if err != nil {
		return nil, fmt.Errorf("the access key secret: %w", err)
	}
	return NewKey(seed)
}

// Secret returns the access key secret: "qak_" and the seed in base64url without
// padding, 47 characters. It is the one string that holds the key; whoever holds it is
// the access key.
func (k *Key) Secret() string {
	return SecretPrefix + base64.RawURLEncoding.EncodeToString((*k.m.priv).Seed())
}

// PublicKey returns the key's Ed25519 public key.
func (k Key) PublicKey() PublicKey {
	var p PublicKey
	copy(p[:], (*k.m.priv).Public().(ed25519.PublicKey))
	return p
}

// Fingerprint returns the fingerprint of the key's public key.
func (k Key) Fingerprint() string { return k.PublicKey().Fingerprint() }

// X25519PrivateKey returns the X25519 private key of the access key: the first 32
// bytes of SHA-512 of the seed, clamped, the scalar Ed25519 signs with.
func (k *Key) X25519PrivateKey() []byte {
	h := sha512.Sum512((*k.m.priv).Seed())
	s := h[:32]
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return bytes.Clone(s)
}

// X25519 returns the X25519 private key of the access key as crypto/ecdh holds it,
// the key HPKE opens what the server seals to the access key with. Its public key is
// [PublicKey.X25519] of the key's public key.
func (k *Key) X25519() *ecdh.PrivateKey {
	priv, err := ecdh.X25519().NewPrivateKey(k.X25519PrivateKey())
	if err != nil {
		// Thirty-two bytes are always an X25519 private key.
		panic(err)
	}
	return priv
}

// Sign returns the Ed25519 signature of a message under the key. Every message the
// contract signs starts with a domain line of its own: [Request.Message],
// [Answer.Message] and [EnrolmentRequest.ProofMessage] build them.
func (k *Key) Sign(message []byte) []byte { return ed25519.Sign(*k.m.priv, message) }

// String returns "Ed25519 key" and the fingerprint of its public key. It and Format
// have value receivers, so a Key printed by value shows the same and no more.
func (k Key) String() string { return "Ed25519 key " + k.Fingerprint() }

// GoString returns what String returns.
func (k Key) GoString() string { return k.String() }

// Format writes what String returns, whatever the verb.
func (k Key) Format(f fmt.State, _ rune) { io.WriteString(f, k.String()) }

// MarshalText returns what String returns, so a structured log of a Key shows its
// fingerprint.
func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// PublicKey is a raw 32-byte Ed25519 public key, written in base64url without padding.
type PublicKey [ed25519.PublicKeySize]byte

// ParsePublicKey reads a public key in base64url without padding, decoded strictly.
// It checks the encoding alone; [PublicKey.Check] checks the point.
func ParsePublicKey(s string) (PublicKey, error) {
	var p PublicKey
	b, err := decode(s, len(p))
	if err != nil {
		return p, fmt.Errorf("the public key %s: %w", shown(s), err)
	}
	copy(p[:], b)
	return p, nil
}

// String returns the key in base64url without padding.
func (p PublicKey) String() string { return base64.RawURLEncoding.EncodeToString(p[:]) }

// Fingerprint returns base64url(SHA-256(raw public key)[:16]), 22 characters: what an
// operator compares between the machine and the server, and what an enrolment code
// carries of the server's key.
func (p PublicKey) Fingerprint() string {
	h := sha256.Sum256(p[:])
	return base64.RawURLEncoding.EncodeToString(h[:16])
}

// Verify reports whether sig is the Ed25519 signature of message under the key,
// verified cofactorless by RFC 8032 as crypto/ed25519 verifies: a non-canonical R and
// an S not below the group order fail. A key [PublicKey.Check] refuses verifies
// nothing, since a key of small order accepts signatures nobody made.
func (p PublicKey) Verify(message, sig []byte) bool {
	return len(sig) == ed25519.SignatureSize && p.Check() == nil && ed25519.Verify(p[:], message, sig)
}

// identityEncoding is the encoding of the identity point, y = 1.
var identityEncoding = [32]byte{1}

// orderMinusOne is ℓ − 1, ℓ being the order of the base point, little-endian: the
// largest canonical scalar, which with one more addition multiplies a point by ℓ.
var orderMinusOne = []byte{
	0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// ErrKeyInvalid is the error of a public key the key checks refuse.
var ErrKeyInvalid = errors.New("the public key cannot be used")

// Check runs the checks the contract requires of every public key the server is
// given, in order: a canonical encoding, a point on the curve, not of small order,
// of prime order, and y ≠ 1. A key that fails one is an error wrapping
// [ErrKeyInvalid] that names the check. A proof of possession proves nothing for a key
// of small order, and a key with a torsion component passes a proof about one time in
// eight, so a key is checked whatever proof comes with it. The published fixture keys
// pass these checks; [PublicKey.Fixture] names them.
func (p PublicKey) Check() error {
	pt, err := new(edwards25519.Point).SetBytes(p[:])
	if err != nil {
		return fmt.Errorf("%w: it is not a point on the curve", ErrKeyInvalid)
	}
	if !bytes.Equal(pt.Bytes(), p[:]) {
		return fmt.Errorf("%w: its encoding is not canonical", ErrKeyInvalid)
	}
	identity := edwards25519.NewIdentityPoint()
	if new(edwards25519.Point).MultByCofactor(pt).Equal(identity) == 1 {
		return fmt.Errorf("%w: it is a point of small order", ErrKeyInvalid)
	}
	s, err := edwards25519.NewScalar().SetCanonicalBytes(orderMinusOne)
	if err != nil {
		panic(err)
	}
	if new(edwards25519.Point).Add(new(edwards25519.Point).ScalarMult(s, pt), pt).Equal(identity) != 1 {
		return fmt.Errorf("%w: it is not of prime order", ErrKeyInvalid)
	}
	if p == identityEncoding {
		return fmt.Errorf("%w: its y-coordinate is 1", ErrKeyInvalid)
	}
	return nil
}

// X25519 returns the X25519 public key of an Ed25519 public key, the Montgomery
// u-coordinate u = (1 + y) / (1 − y) mod 2^255 − 19: the key the server seals to. It
// refuses a key [PublicKey.Check] refuses.
func (p PublicKey) X25519() ([]byte, error) {
	if err := p.Check(); err != nil {
		return nil, err
	}
	pt, err := new(edwards25519.Point).SetBytes(p[:])
	if err != nil {
		return nil, err
	}
	return pt.BytesMontgomery(), nil
}

// The published fixture keys of the contract: the fixture access key, a second fixture
// access key, and the fixture signing keys of the server, current and next. Their
// secrets are published, so a machine refuses each as its own key and as a pin.
var fixtureKeys = []string{
	"ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ",
	"dSnEVtk40rj-kPpsz5FtNGdwpkvLt7UyO2h6zeIM0Aw",
	"rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc",
	"C0eCPnEJXdWb54rCccV27zifh7ZFYasHz5pOvNAtIEE",
}

// Fixture reports whether the key is one of the contract's published fixture keys:
// a fixture access key, or the fixture signing key of the server, current or next.
// Their secrets are published, so qory refuses each as an access key and as a pin, and
// a server refuses each at enrolment and as its own key.
func (p PublicKey) Fixture() bool {
	for _, f := range fixtureKeys {
		if p.String() == f {
			return true
		}
	}
	return false
}

// shown is a value as an error quotes it: quoted, or, when it contains what starts an
// access key secret, a secret pasted where another value belongs say, a phrase in its
// place, so an error never contains a secret.
func shown(v string) string {
	if ContainsSecret(v) {
		return "(a value that contains an access key secret)"
	}
	return strconv.Quote(v)
}

// ContainsSecret reports whether a value contains what starts an access key secret,
// qak_ in any case. A reader of a document a secret does not belong in, such as the
// server document or a pin, refuses one that contains it with a fixed message, before
// a schema or a JSON decoder can quote the value in its error.
func ContainsSecret(v string) bool { return strings.Contains(strings.ToLower(v), SecretPrefix) }

// DocumentContainsSecret reports whether a decoded document, as JSON or YAML decodes
// to any, contains an access key secret in any string or member name. A reader checks
// it after decoding as well as the raw bytes before, since an escape, \u0071 in JSON
// or \x71 or a folded line in YAML, hides the secret from the bytes and not from the
// decoded value a schema error quotes.
func DocumentContainsSecret(doc any) bool {
	switch v := doc.(type) {
	case string:
		return ContainsSecret(v)
	case map[string]any:
		for k, e := range v {
			if ContainsSecret(k) || DocumentContainsSecret(e) {
				return true
			}
		}
	case map[any]any:
		for k, e := range v {
			if DocumentContainsSecret(k) || DocumentContainsSecret(e) {
				return true
			}
		}
	case []any:
		for _, e := range v {
			if DocumentContainsSecret(e) {
				return true
			}
		}
	}
	return false
}

// decode decodes base64url without padding strictly, to exactly n bytes: padding, a
// character of the standard alphabet, a line break and non-zero bits after the last
// full byte are refused.
func decode(s string, n int) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("not base64url without padding: it contains a line break")
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errors.New("not base64url without padding")
	}
	if len(b) != n {
		return nil, fmt.Errorf("%d bytes where %d belong", len(b), n)
	}
	return b, nil
}

// idShape is an access key id's form.
var idShape = regexp.MustCompile(`^ak_[0-9a-hjkmnp-tv-z]{16}$`)

// CheckID refuses an access key id that is not "ak_" and 16 lower-case Crockford
// base32 characters.
func CheckID(id string) error {
	if !idShape.MatchString(id) {
		return fmt.Errorf("the access key id %s is not ak_ and 16 lower-case Crockford base32 characters", shown(id))
	}
	return nil
}

// nodeShape is a node's or a node pool's id.
var nodeShape = regexp.MustCompile(`^n[dp]_[0-9a-hjkmnp-tv-z]{16}$`)

// CheckNodeID refuses a node id that is not "nd_", for a node, or "np_", for a node
// pool, and 16 lower-case Crockford base32 characters.
func CheckNodeID(id string) error {
	if !nodeShape.MatchString(id) {
		return fmt.Errorf("the node id %s is not nd_ or np_ and 16 lower-case Crockford base32 characters", shown(id))
	}
	return nil
}

// nameShape is the form of an instance id, an instance's display name and an access
// key's name.
var nameShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// CheckName refuses a name outside ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$: an access key's
// name at enrolment, and an instance's display name, X-Qory-Instance-Name. A name that
// contains an access key secret fits the pattern and is refused too, since the name
// travels in clear.
func CheckName(name string) error {
	if !nameShape.MatchString(name) || ContainsSecret(name) {
		return fmt.Errorf("the name %s is not 1 to 64 of A-Z, a-z, 0-9, dot, underscore and dash, starting with a letter or digit", shown(name))
	}
	return nil
}

// DefaultName returns the default display name for a host name: the host name, or its
// first label when the whole does not fit the name's pattern, or empty when neither
// does.
func DefaultName(host string) string {
	if CheckName(host) == nil {
		return host
	}
	if first, _, _ := strings.Cut(host, "."); CheckName(first) == nil {
		return first
	}
	return ""
}
