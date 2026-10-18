package accesskey

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"filippo.io/edwards25519"
	"gopkg.in/yaml.v3"
)

// SecretPrefix starts every access key secret, so secret scanners recognise one.
const SecretPrefix = "qak_"

// runKeyPrefix starts every run key, runkey.Prefix, which this package cannot import
// since package runkey imports it.
const runKeyPrefix = "qrk_"

// SeedSize is the size of an access key's seed, the whole of its secret.
const SeedSize = ed25519.SeedSize

// Key is an Ed25519 key, held from its seed: an access key, whose secret signs
// Forager's requests, or a server's signing key, whose public key a machine pins. It
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

// X25519 returns the X25519 private key of the access key as crypto/ecdh holds it.
// Its public key is [PublicKey.X25519] of the key's public key.
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
// u-coordinate u = (1 + y) / (1 − y) mod 2^255 − 19. It refuses a key
// [PublicKey.Check] refuses.
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
// access key, the fixture signing keys of the server, current and next, and the fixture
// gateway key. Their secrets are published, so a machine refuses each as its own key
// and as a pin.
var fixtureKeys = []string{
	"ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ",
	"dSnEVtk40rj-kPpsz5FtNGdwpkvLt7UyO2h6zeIM0Aw",
	"rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc",
	"C0eCPnEJXdWb54rCccV27zifh7ZFYasHz5pOvNAtIEE",
	"iC0Oo7KGTnpYfz5pjOpEWZmDEuZV4F-l6LURnYuqyM0",
}

// Fixture reports whether the key is one of the contract's published fixture keys:
// a fixture access key, the fixture gateway key, or the fixture signing key of the
// server, current or next.
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
// access key secret or a run key, a secret pasted where another value belongs say, a
// phrase in its place, so an error never contains a secret.
func shown(v string) string {
	switch {
	case containsAccessKeySecret(v):
		return "(a value that contains an access key secret)"
	case containsRunKey(v):
		return "(a value that contains a run key)"
	}
	return strconv.Quote(v)
}

// ContainsSecret reports whether a value contains what starts an access key secret,
// qak_, or a run key, qrk_, in any case. A reader of a document a secret does not
// belong in, such as the server document or a pin, refuses one that contains it with a
// fixed message, before a schema or a JSON decoder can quote the value in its error.
func ContainsSecret(v string) bool { return containsAccessKeySecret(v) || containsRunKey(v) }

// containsAccessKeySecret reports whether a value contains qak_ in any case.
func containsAccessKeySecret(v string) bool {
	return strings.Contains(strings.ToLower(v), SecretPrefix)
}

// containsRunKey reports whether a value contains qrk_ in any case.
func containsRunKey(v string) bool { return strings.Contains(strings.ToLower(v), runKeyPrefix) }

// DocumentContainsSecret reports whether a decoded document, as JSON or YAML decodes
// to any, contains an access key secret or a run key in any string or member name. A
// reader checks it after decoding as well as the raw bytes before, since an escape,
// \u0071 in JSON or \x71 or a folded line in YAML, hides the secret from the bytes and
// not from the decoded value a schema error quotes.
func DocumentContainsSecret(doc any) bool { return documentHas(doc, ContainsSecret) }

// SecretInDocument is the error of a value or a decoded document that contains a
// secret, as [DocumentContainsSecret] reports one: [ErrSecretInDocument] for an access
// key secret, [ErrRunKeyInDocument] for a run key and no access key secret, and nil for
// neither. A string is checked as it is, so a reader passes it the raw bytes before
// decoding and the decoded document after.
func SecretInDocument(doc any) error {
	switch {
	case documentHas(doc, containsAccessKeySecret):
		return ErrSecretInDocument
	case documentHas(doc, containsRunKey):
		return ErrRunKeyInDocument
	}
	return nil
}

// documentHas reports whether has holds for any string or member name of a decoded
// document.
func documentHas(doc any, has func(string) bool) bool {
	switch v := doc.(type) {
	case string:
		return has(v)
	case map[string]any:
		for k, e := range v {
			if has(k) || documentHas(e, has) {
				return true
			}
		}
	case map[any]any:
		for k, e := range v {
			if documentHas(k, has) || documentHas(e, has) {
				return true
			}
		}
	case []any:
		for _, e := range v {
			if documentHas(e, has) {
				return true
			}
		}
	}
	return false
}

// SecretInPinDocument is [SecretInDocument] of a document that holds a pin, with the
// pin's keys left out. member is the top-level member that holds the pin,
// apiary_public_key in the server document, or empty for a document that is the pin.
// An entry's public_key is left out when it is one string that [ParsePublicKey] reads
// and [PublicKey.Check] passes, so a key whose base64url contains qak_ or qrk_ by
// chance is not refused. The entry's alg, its other members and the rest of the
// document are checked as SecretInDocument checks them.
//
// A string is the raw bytes, read as JSON when they are one JSON value and as YAML
// otherwise. A key is left out only where the pin writes it, as a JSON string or a
// plain or quoted YAML scalar, so the same text elsewhere, in another member or a YAML
// comment say, is checked. No key is left out when member appears twice, and an
// entry's key is not when its public_key appears twice. In YAML, a key is not left out
// when it is written with an anchor, an alias or a tag, or when the mapping that holds
// it, or the document, has a merge key or a key that is not a scalar. A decoded
// document has the decoded value left out.
func SecretInPinDocument(doc any, member string) error {
	if raw, ok := doc.(string); ok {
		return SecretInDocument(outsidePinKeys(raw, member))
	}
	return SecretInDocument(withoutPinKeys(doc, member))
}

// SecretInPinEntry is [SecretInDocument] of one entry of a pin, its alg and its public
// key, with the public key left out when [SecretInPinDocument] leaves it out.
func SecretInPinEntry(alg, publicKey string) error {
	if pinKey(publicKey) {
		return SecretInDocument(alg)
	}
	return SecretInDocument([]any{alg, publicKey})
}

// pinKey reports whether v is a key a pin may list: [ParsePublicKey] reads it and
// [PublicKey.Check] passes it.
func pinKey(v string) bool {
	p, err := ParsePublicKey(v)
	return err == nil && p.Check() == nil
}

// withoutPinKeys is a decoded document with each public_key of its pin that pinKey
// accepts set to nil, in copies, so the document passed in is unchanged.
func withoutPinKeys(doc any, member string) any {
	if member == "" {
		return withoutKeys(doc)
	}
	m, ok := doc.(map[string]any)
	if !ok {
		return doc
	}
	pin, ok := m[member]
	if !ok {
		return doc
	}
	out := maps.Clone(m)
	out[member] = withoutKeys(pin)
	return out
}

// withoutKeys is withoutPinKeys of a decoded pin, a list of entries.
func withoutKeys(pin any) any {
	list, ok := pin.([]any)
	if !ok {
		return pin
	}
	out := slices.Clone(list)
	for i, e := range list {
		entry, _ := e.(map[string]any)
		if k, ok := entry["public_key"].(string); ok && pinKey(k) {
			c := maps.Clone(entry)
			c["public_key"] = nil
			out[i] = c
		}
	}
	return out
}

// span is the bytes from and up to, not including, to.
type span struct{ from, to int }

// outsidePinKeys is the raw bytes of a document as parts, split where its pin writes a
// key withoutPinKeys leaves out, those bytes left out. Such a span starts and ends with
// a quote, or is a plain YAML scalar, which a separator bounds; neither qak_ nor qrk_
// contains a quote or a separator, so no match runs across the edge of a span.
func outsidePinKeys(raw, member string) []any {
	b := []byte(raw)
	spans, ok := jsonPinKeys(b, member)
	if !ok {
		spans = yamlPinKeys(b, member)
	}
	var parts []any
	at := 0
	for _, s := range spans {
		if s.from < at {
			return []any{raw}
		}
		parts = append(parts, raw[at:s.from])
		at = s.to
	}
	return append(parts, raw[at:])
}

// jsonPinKeys returns where the bytes write each key withoutPinKeys leaves out, and
// false when the bytes are not one JSON value.
func jsonPinKeys(b []byte, member string) ([]span, bool) {
	j := jsonPin{b: b, d: jsontext.NewDecoder(bytes.NewReader(b), jsontext.AllowDuplicateNames(true))}
	var spans []span
	var err error
	if member == "" {
		spans, err = j.entries()
	} else {
		spans, err = j.member(member)
	}
	if err != nil {
		return nil, false
	}
	if _, err := j.d.ReadToken(); err != io.EOF {
		return nil, false
	}
	return spans, true
}

// jsonPin reads the bytes b of a JSON document with d.
type jsonPin struct {
	b []byte
	d *jsontext.Decoder
}

// member reads one value, and returns the spans of the pin in its member name when it
// is an object that holds that member once.
func (j jsonPin) member(name string) ([]span, error) {
	if j.d.PeekKind() != '{' {
		return nil, j.d.SkipValue()
	}
	if _, err := j.d.ReadToken(); err != nil {
		return nil, err
	}
	var spans []span
	n := 0
	for j.d.PeekKind() != '}' {
		k, err := j.d.ReadToken()
		if err != nil {
			return nil, err
		}
		if k.String() != name {
			if err := j.d.SkipValue(); err != nil {
				return nil, err
			}
			continue
		}
		n++
		if spans, err = j.entries(); err != nil {
			return nil, err
		}
	}
	if _, err := j.d.ReadToken(); err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, nil
	}
	return spans, nil
}

// entries reads one value, and returns the spans of the keys of its entries when it is
// a list.
func (j jsonPin) entries() ([]span, error) {
	if j.d.PeekKind() != '[' {
		return nil, j.d.SkipValue()
	}
	if _, err := j.d.ReadToken(); err != nil {
		return nil, err
	}
	var spans []span
	for j.d.PeekKind() != ']' {
		if j.d.PeekKind() != '{' {
			if err := j.d.SkipValue(); err != nil {
				return nil, err
			}
			continue
		}
		s, err := j.entry()
		if err != nil {
			return nil, err
		}
		spans = append(spans, s...)
	}
	_, err := j.d.ReadToken()
	return spans, err
}

// entry reads one object, and returns the span of its public_key when the object
// holds that member once and its value is a string pinKey accepts.
func (j jsonPin) entry() ([]span, error) {
	if _, err := j.d.ReadToken(); err != nil {
		return nil, err
	}
	var key []span
	n := 0
	for j.d.PeekKind() != '}' {
		k, err := j.d.ReadToken()
		if err != nil {
			return nil, err
		}
		if k.String() != "public_key" {
			if err := j.d.SkipValue(); err != nil {
				return nil, err
			}
			continue
		}
		n++
		v, err := j.d.ReadValue()
		if err != nil {
			return nil, err
		}
		key = nil
		to := int(j.d.InputOffset())
		from := to - len(v)
		var s string
		if v.Kind() == '"' && from >= 0 && bytes.Equal(j.b[from:to], v) && jsonv2.Unmarshal(v, &s) == nil && pinKey(s) {
			key = []span{{from, to}}
		}
	}
	if _, err := j.d.ReadToken(); err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, nil
	}
	return key, nil
}

// yamlPinKeys returns where the bytes, as YAML, write each key withoutPinKeys leaves
// out: none when they are not YAML, or where yamlMember finds no member.
func yamlPinKeys(b []byte, member string) []span {
	var doc yaml.Node
	if yaml.Unmarshal(b, &doc) != nil || len(doc.Content) != 1 {
		return nil
	}
	pin := doc.Content[0]
	if member != "" {
		pin = yamlMember(pin, member)
	}
	if pin == nil || pin.Kind != yaml.SequenceNode {
		return nil
	}
	var spans []span
	for _, e := range pin.Content {
		v := yamlMember(e, "public_key")
		if v == nil || v.Kind != yaml.ScalarNode || v.ShortTag() != "!!str" || !pinKey(v.Value) {
			continue
		}
		if s, ok := yamlScalar(b, v); ok {
			spans = append(spans, s)
		}
	}
	return spans
}

// yamlMember returns the value of a mapping's member name, or nil when the node is no
// mapping, holds the member other than once, or has a merge key or a key that is not a
// scalar.
func yamlMember(m *yaml.Node, name string) *yaml.Node {
	if m.Kind != yaml.MappingNode {
		return nil
	}
	var v *yaml.Node
	n := 0
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind != yaml.ScalarNode || k.ShortTag() == "!!merge" {
			return nil
		}
		if k.Value == name {
			n++
			v = m.Content[i+1]
		}
	}
	if n != 1 {
		return nil
	}
	return v
}

// yamlScalar returns the span of a scalar where the node's line and column put it,
// plain, single-quoted or double-quoted, and false unless those bytes, read as YAML
// alone, are the node's value. An anchor or a tag puts the column on itself, so a
// scalar written with one has no span.
func yamlScalar(b []byte, v *yaml.Node) (span, bool) {
	from, ok := yamlOffset(b, v.Line, v.Column)
	if !ok {
		return span{}, false
	}
	to := -1
	switch v.Style {
	case 0:
		to = from + len(v.Value)
	case yaml.SingleQuotedStyle:
		to = from + len(v.Value) + 2
	case yaml.DoubleQuotedStyle:
		for i := from + 1; i < len(b); i++ {
			if b[i] == '\\' {
				i++
				continue
			}
			if b[i] == '"' {
				to = i + 1
				break
			}
		}
	}
	if to < from || to > len(b) {
		return span{}, false
	}
	var s string
	if yaml.Unmarshal(b[from:to], &s) != nil || s != v.Value {
		return span{}, false
	}
	return span{from, to}, true
}

// bom is the UTF-8 byte order mark, which yaml.v3 skips.
const bom = "\xef\xbb\xbf"

// yamlOffset returns the byte offset of a line and a column as yaml.v3 counts them:
// from 1, in characters, after a UTF-8 byte order mark. It is false when the bytes have
// no such place.
func yamlOffset(b []byte, line, column int) (int, bool) {
	at := 0
	if bytes.HasPrefix(b, []byte(bom)) {
		at = len(bom)
	}
	for ; line > 1; line-- {
		i := bytes.IndexAny(b[at:], "\r\n\u0085\u2028\u2029")
		if i < 0 {
			return 0, false
		}
		at += i
		_, n := utf8.DecodeRune(b[at:])
		if bytes.HasPrefix(b[at:], []byte("\r\n")) {
			n = 2
		}
		at += n
	}
	for ; column > 1; column-- {
		if at >= len(b) {
			return 0, false
		}
		_, n := utf8.DecodeRune(b[at:])
		at += n
	}
	return at, true
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

// nodeShape is a node's, a node pool's, a gateway's or an adapter's id.
var nodeShape = regexp.MustCompile(`^n[dpga]_[0-9a-hjkmnp-tv-z]{16}$`)

// CheckNodeID refuses a node id that is not "nd_", for a node, "np_", for a node pool,
// "ng_", for a gateway, or "na_", for an adapter, and 16 lower-case Crockford base32
// characters.
func CheckNodeID(id string) error {
	if !nodeShape.MatchString(id) {
		return fmt.Errorf("the node id %s is not nd_, np_, ng_ or na_ and 16 lower-case Crockford base32 characters", shown(id))
	}
	return nil
}

// nameShape is the form of an instance id, an instance's display name and an access
// key's name.
var nameShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// CheckName refuses a name outside ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$: an access key's
// name at enrolment, and an instance's display name, X-Qory-Instance-Name. A name that
// contains an access key secret or a run key fits the pattern and is refused too, since
// the name travels in clear.
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
