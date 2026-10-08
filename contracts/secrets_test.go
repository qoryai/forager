package contracts_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/qoryai/runner/contracts"
)

// The fixtures of the access key: enrolment's schema, and the known answers this
// contract publishes, recomputed here with Go's standard library alone.

// b64 decodes a binary value of the contract: base64url without padding, decoded
// strictly, so padding, a character of the standard alphabet or non-zero bits after the
// last full byte fail the test.
func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return b
}

// read reads one file of the contract, by its path under forager/v1.
func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(contracts.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// load reads one JSON file of the contract into v.
func load(t *testing.T, name string, v any) {
	t.Helper()
	if err := json.Unmarshal(read(t, name), v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func hexSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func fingerprint(pub []byte) string {
	h := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(h[:16])
}

// counting returns n bytes counting up from first, so counting(1, 32) is bytes 1 to 32.
func counting(first, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(first + i)
	}
	return b
}

type keyPair struct {
	Note        string `json:"note"`
	Seed        string `json:"seed"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

type fixtureKeys struct {
	AccessKey struct {
		Note             string `json:"note"`
		Secret           string `json:"secret"`
		AccessKeyID      string `json:"access_key_id"`
		InstanceID       string `json:"instance_id"`
		PublicKey        string `json:"public_key"`
		Fingerprint      string `json:"fingerprint"`
		X25519PrivateKey string `json:"x25519_private_key"`
		X25519PublicKey  string `json:"x25519_public_key"`
	} `json:"access_key"`
	SigningKey     keyPair `json:"signing_key"`
	NextSigningKey keyPair `json:"next_signing_key"`
}

func loadKeys(t *testing.T) fixtureKeys {
	t.Helper()
	var k fixtureKeys
	load(t, "fixtures/known-answers/keys.json", &k)
	return k
}

// accessKey returns the fixture access key's Ed25519 private key from its secret.
func (k fixtureKeys) accessKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	secret, ok := strings.CutPrefix(k.AccessKey.Secret, "qak_")
	if !ok || len(k.AccessKey.Secret) != 47 {
		t.Fatalf("access key secret %q: want qak_ and 43 characters", k.AccessKey.Secret)
	}
	return ed25519.NewKeyFromSeed(b64(t, secret))
}

// TestSecretsFixturesValidate pins that every fixture of enrolment and of the known
// answers passes its schema: discovery, and the enrolment request, answer and signed
// refusals each against the part of enrolment.schema.json it is.
func TestSecretsFixturesValidate(t *testing.T) {
	c, err := contracts.Compiler()
	if err != nil {
		t.Fatal(err)
	}
	schema := func(ref string) func(any) error {
		s, err := c.Compile(contracts.Base + "/" + ref)
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		return s.Validate
	}
	want := map[string][]string{
		"fixtures/known-answers/discovery.json":                {"configuration.schema.json"},
		"fixtures/enrolment/request.json":                      {"enrolment.schema.json", "enrolment.schema.json#/$defs/request"},
		"fixtures/enrolment/request-two-fingerprints.json":     {"enrolment.schema.json", "enrolment.schema.json#/$defs/request"},
		"fixtures/enrolment/answer.json":                       {"enrolment.schema.json", "enrolment.schema.json#/$defs/answer"},
		"fixtures/enrolment/refusal-key-limit.json":            {"enrolment.schema.json", "enrolment.schema.json#/$defs/refusal"},
		"fixtures/enrolment/refusal-key-invalid.json":          {"enrolment.schema.json", "enrolment.schema.json#/$defs/refusal"},
		"fixtures/enrolment/refusal-key-limit-rotation.json":   {"enrolment.schema.json", "enrolment.schema.json#/$defs/refusal"},
		"fixtures/enrolment/refusal-key-invalid-rotation.json": {"enrolment.schema.json", "enrolment.schema.json#/$defs/refusal"},
		"fixtures/enrolment/refusal-rate-limited.json":         {"enrolment.schema.json", "enrolment.schema.json#/$defs/refusal"},
	}
	data := map[string]bool{
		"fixtures/known-answers/keys.json":        true,
		"fixtures/known-answers/signatures.json":  true,
		"fixtures/known-answers/small-order.json": true,
	}
	for _, dir := range []string{"fixtures/enrolment", "fixtures/known-answers"} {
		for _, f := range files(t, dir) {
			if _, ok := want[f]; !ok && !data[f] {
				t.Errorf("%s: a fixture no test validates", f)
			}
		}
	}
	for f, refs := range want {
		doc, err := contracts.Document(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, ref := range refs {
			if err := schema(ref)(doc); err != nil {
				t.Errorf("%s against %s: %v", f, ref, err)
			}
		}
	}
	// The halves of enrolment.schema.json are distinct: a request is no answer.
	request, _ := contracts.Document("fixtures/enrolment/request.json")
	if schema("enrolment.schema.json#/$defs/answer")(request) == nil {
		t.Error("the enrolment request passes as an answer")
	}
}

// TestFixtureAccessKey pins the fixture access key and the fixture signing keys: each
// public key and fingerprint from its seed, the X25519 private key as the clamped first
// 32 bytes of SHA-512(seed), and the X25519 public key two ways, from the private key
// with crypto/ecdh, and as the Montgomery u-coordinate of the Ed25519 public key.
func TestFixtureAccessKey(t *testing.T) {
	k := loadKeys(t)
	a := k.AccessKey
	priv := k.accessKey(t)
	if seed := priv.Seed(); !bytes.Equal(seed, counting(1, 32)) {
		t.Errorf("access key seed %x; want bytes 1 to 32", seed)
	}
	pub := []byte(priv.Public().(ed25519.PublicKey))
	if !bytes.Equal(pub, b64(t, a.PublicKey)) {
		t.Errorf("Ed25519 public key %s; want %s", base64.RawURLEncoding.EncodeToString(pub), a.PublicKey)
	}
	if fp := fingerprint(pub); fp != a.Fingerprint {
		t.Errorf("access key fingerprint %s; want %s", fp, a.Fingerprint)
	}
	if !regexp.MustCompile(`^ak_[0-9a-hjkmnp-tv-z]{16}$`).MatchString(a.AccessKeyID) {
		t.Errorf("access key id %q outside its pattern", a.AccessKeyID)
	}
	if want := "i_" + base64.RawURLEncoding.EncodeToString(counting(129, 16)); a.InstanceID != want ||
		!regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`).MatchString(a.InstanceID) {
		t.Errorf("instance id %q; want %q, i_ and bytes 129 to 144", a.InstanceID, want)
	}

	h := sha512.Sum512(priv.Seed())
	clamped := slices.Clone(h[:32])
	clamped[0] &= 248
	clamped[31] &= 127
	clamped[31] |= 64
	if !bytes.Equal(clamped, b64(t, a.X25519PrivateKey)) {
		t.Errorf("X25519 private key %s; want %s", base64.RawURLEncoding.EncodeToString(clamped), a.X25519PrivateKey)
	}
	want := b64(t, a.X25519PublicKey)
	for name, scalar := range map[string][]byte{"clamped": clamped, "unclamped": h[:32]} {
		x, err := ecdh.X25519().NewPrivateKey(scalar)
		if err != nil {
			t.Fatal(err)
		}
		if got := x.PublicKey().Bytes(); !bytes.Equal(got, want) {
			t.Errorf("X25519 public key of the %s scalar %x; want %x", name, got, want)
		}
	}
	if got := montgomery(t, pub); !bytes.Equal(got, want) {
		t.Errorf("u-coordinate of the Ed25519 public key %x; want %x", got, want)
	}

	for name, s := range map[string]struct {
		key   keyPair
		first int
	}{"signing key": {k.SigningKey, 65}, "next signing key": {k.NextSigningKey, 161}} {
		seed := b64(t, s.key.Seed)
		if !bytes.Equal(seed, counting(s.first, 32)) {
			t.Errorf("%s seed %x; want bytes %d to %d", name, seed, s.first, s.first+31)
		}
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		if !bytes.Equal(pub, b64(t, s.key.PublicKey)) {
			t.Errorf("%s public key %s; want %s", name, base64.RawURLEncoding.EncodeToString(pub), s.key.PublicKey)
		}
		if fp := fingerprint(pub); fp != s.key.Fingerprint {
			t.Errorf("%s fingerprint %s; want %s", name, fp, s.key.Fingerprint)
		}
	}
}

type signedVector struct {
	Note       string   `json:"note"`
	Body       *string  `json:"body"`
	BodyLength *int     `json:"body_length"`
	Lines      []string `json:"lines"`
	Length     int      `json:"length"`
	Signature  string   `json:"signature"`
}

type signatureVectors struct {
	Requests  []signedVector `json:"requests"`
	Enrolment []signedVector `json:"enrolment"`
	Answers   []signedVector `json:"answers"`
}

// message joins a vector's lines by a line feed, with none after the last, and checks
// its length.
func (v signedVector) message(t *testing.T) []byte {
	t.Helper()
	m := []byte(strings.Join(v.Lines, "\n"))
	if len(m) != v.Length {
		t.Errorf("%s: the message is %d bytes; want %d", v.Note, len(m), v.Length)
	}
	return m
}

// body returns the bytes of the file a vector lists, or none for an empty name.
func (v signedVector) body(t *testing.T) []byte {
	t.Helper()
	if v.Body == nil {
		t.Fatalf("%s: no body", v.Note)
	}
	if *v.Body == "" {
		return nil
	}
	name, ok := strings.CutPrefix(*v.Body, "fixtures/")
	if !ok {
		t.Fatalf("%s: body %q outside fixtures/", v.Note, *v.Body)
	}
	return read(t, "fixtures/"+name)
}

// signs checks that sig is the signature under priv of m: it verifies under the public
// key, and Ed25519 being deterministic, signing again returns the same bytes.
func signs(t *testing.T, what string, priv ed25519.PrivateKey, m []byte, sig string) {
	t.Helper()
	s := b64(t, sig)
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), m, s) {
		t.Errorf("%s: the signature does not verify", what)
	}
	if again := ed25519.Sign(priv, m); !bytes.Equal(again, s) {
		t.Errorf("%s: signature %s; want %s", what, sig, base64.RawURLEncoding.EncodeToString(again))
	}
}

// TestRequestSignatures pins the request strings and their known answers under the
// fixture access key: a GET's six lines with the timestamp, and the same with a query.
func TestRequestSignatures(t *testing.T) {
	k := loadKeys(t)
	priv := k.accessKey(t)
	var v signatureVectors
	load(t, "fixtures/known-answers/signatures.json", &v)
	if len(v.Requests) != 2 {
		t.Fatalf("%d request vectors; want 2", len(v.Requests))
	}
	for _, r := range v.Requests {
		if len(r.Lines) != 6 || r.Lines[0] != "qory-request-ed25519-v1" ||
			r.Lines[1] != k.AccessKey.AccessKeyID || r.Lines[2] != k.AccessKey.InstanceID {
			t.Errorf("%s: lines %q; want the domain line, the access key id and the instance id, then three", r.Note, r.Lines)
			continue
		}
		if r.Lines[3] != "GET" {
			t.Errorf("%s: method %q", r.Note, r.Lines[3])
		}
		if _, err := strconv.ParseUint(r.Lines[5], 10, 64); err != nil {
			t.Errorf("%s: timestamp line %q", r.Note, r.Lines[5])
		}
		signs(t, r.Note, priv, r.message(t), r.Signature)
	}
}

// TestEnrolmentProofs pins the enrolment proof's five lines, built from the request's
// body, and the proof the body carries, under the fixture access key, for a code with
// the signing key's fingerprint and for one made during a rotation with both.
func TestEnrolmentProofs(t *testing.T) {
	k := loadKeys(t)
	priv := k.accessKey(t)
	var v signatureVectors
	load(t, "fixtures/known-answers/signatures.json", &v)
	if len(v.Enrolment) != 2 {
		t.Fatalf("%d enrolment vectors; want 2", len(v.Enrolment))
	}
	fingerprints := []string{k.SigningKey.Fingerprint, k.NextSigningKey.Fingerprint}
	for i, e := range v.Enrolment {
		var body struct {
			Code      string `json:"code"`
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
			Timestamp int64  `json:"timestamp"`
			Proof     string `json:"proof"`
		}
		if err := json.Unmarshal(e.body(t), &body); err != nil {
			t.Fatal(err)
		}
		want := []string{"qory-enrol-ed25519-v1", body.Code, body.PublicKey, body.Name, strconv.FormatInt(body.Timestamp, 10)}
		if !slices.Equal(e.Lines, want) {
			t.Errorf("%s: lines %q; want %q from the body", e.Note, e.Lines, want)
		}
		if body.PublicKey != k.AccessKey.PublicKey {
			t.Errorf("%s: public key %s; want the fixture access key's", e.Note, body.PublicKey)
		}
		parts := strings.Split(body.Code, ".")
		if !slices.Equal(parts[1:], fingerprints[:i+1]) {
			t.Errorf("%s: the code's fingerprints %q; want %q", e.Note, parts[1:], fingerprints[:i+1])
		}
		signs(t, e.Note, priv, e.message(t), body.Proof)
	}
}

// TestAnswerSignatures pins the six lines of a signed answer and their known answers
// under the fixture signing key: 200 with the discovery body and 404 with an empty
// body, under qory-answer-ed25519-v1; 201 to the enrolment request, whose line 3 is the
// request's proof, the signed 409s key_limit and key_invalid at enrolment, with one key
// and, during a rotation, to the request with two fingerprints, with two keys, current
// first, and the signed 429 rate_limited per code with one key, under
// qory-enrol-answer-ed25519-v1. A signature under one domain line does not verify under
// the other.
func TestAnswerSignatures(t *testing.T) {
	k := loadKeys(t)
	signing := ed25519.NewKeyFromSeed(b64(t, k.SigningKey.Seed))
	var v signatureVectors
	load(t, "fixtures/known-answers/signatures.json", &v)
	if len(v.Answers) != 8 {
		t.Fatalf("%d answer vectors; want 8", len(v.Answers))
	}
	var proof, rotation struct {
		Proof string `json:"proof"`
	}
	load(t, "fixtures/enrolment/request.json", &proof)
	load(t, "fixtures/enrolment/request-two-fingerprints.json", &rotation)
	for _, a := range v.Answers {
		domain := "qory-answer-ed25519-v1"
		if a.Lines[1] == "201" || a.Lines[1] == "409" || a.Lines[1] == "429" {
			domain = "qory-enrol-answer-ed25519-v1"
		}
		if len(a.Lines) != 6 || a.Lines[0] != domain {
			t.Errorf("%s: lines %q; want six, the first the domain line %s", a.Note, a.Lines, domain)
			continue
		}
		body := a.body(t)
		if a.BodyLength == nil || len(body) != *a.BodyLength {
			t.Errorf("%s: body of %d bytes; want %v", a.Note, len(body), a.BodyLength)
		}
		if a.Lines[3] != hexSHA256(body) {
			t.Errorf("%s: line 4 %s; want the body's SHA-256 %s", a.Note, a.Lines[3], hexSHA256(body))
		}
		switch a.Lines[1] {
		case "200":
			if a.Lines[2] != v.Requests[0].Signature || a.Lines[4] != "sha256="+hexSHA256(body) || a.Lines[5] != "" {
				t.Errorf("%s: lines %q; want the GET's signature, the discovery digest and no run-configuration digest", a.Note, a.Lines)
			}
			var d struct {
				APIaryPublicKey []struct {
					PublicKey string `json:"public_key"`
				} `json:"apiary_public_key"`
			}
			if err := json.Unmarshal(body, &d); err != nil || len(d.APIaryPublicKey) != 1 || d.APIaryPublicKey[0].PublicKey != k.SigningKey.PublicKey {
				t.Errorf("%s: discovery lists %v; want the fixture signing key", a.Note, d.APIaryPublicKey)
			}
		case "404":
			if a.Lines[2] != v.Requests[0].Signature || a.Lines[4] != "" || a.Lines[5] != "" {
				t.Errorf("%s: lines %q; want the GET's signature and no digest", a.Note, a.Lines)
			}
		case "201":
			if a.Lines[2] != proof.Proof || a.Lines[4] != "" || a.Lines[5] != "" {
				t.Errorf("%s: lines %q; want the enrolment proof and no digest", a.Note, a.Lines)
			}
			var e struct {
				AccessKeyID     string `json:"access_key_id"`
				APIaryPublicKey []struct {
					PublicKey string `json:"public_key"`
				} `json:"apiary_public_key"`
			}
			if err := json.Unmarshal(body, &e); err != nil || e.AccessKeyID != k.AccessKey.AccessKeyID ||
				len(e.APIaryPublicKey) != 1 || e.APIaryPublicKey[0].PublicKey != k.SigningKey.PublicKey {
				t.Errorf("%s: the answer contains %s and %v; want the fixture access key and signing key", a.Note, e.AccessKeyID, e.APIaryPublicKey)
			}
		case "409", "429":
			two := a.Body != nil && strings.HasSuffix(*a.Body, "-rotation.json")
			want := proof.Proof
			if two {
				want = rotation.Proof
			}
			if a.Lines[2] != want || a.Lines[4] != "" || a.Lines[5] != "" {
				t.Errorf("%s: lines %q; want the enrolment proof and no digest", a.Note, a.Lines)
			}
			var r struct {
				Error           string `json:"error"`
				APIaryPublicKey []struct {
					PublicKey string `json:"public_key"`
				} `json:"apiary_public_key"`
			}
			keys := []string{k.SigningKey.PublicKey}
			if two {
				keys = append(keys, k.NextSigningKey.PublicKey)
			}
			codes := map[string][]string{
				"409": {"key_limit", "key_invalid"},
				"429": {"rate_limited"},
			}[a.Lines[1]]
			err := json.Unmarshal(body, &r)
			if err != nil || !slices.Contains(codes, r.Error) ||
				len(r.APIaryPublicKey) != len(keys) {
				t.Errorf("%s: the refusal contains %s and %v", a.Note, r.Error, r.APIaryPublicKey)
				continue
			}
			for i, key := range keys {
				if r.APIaryPublicKey[i].PublicKey != key {
					t.Errorf("%s: key %d is %s; want %s", a.Note, i, r.APIaryPublicKey[i].PublicKey, key)
				}
			}
		default:
			t.Errorf("%s: status %q", a.Note, a.Lines[1])
		}
		signs(t, a.Note, signing, a.message(t), a.Signature)
		other := slices.Clone(a.Lines)
		other[0] = map[string]string{"qory-answer-ed25519-v1": "qory-enrol-answer-ed25519-v1", "qory-enrol-answer-ed25519-v1": "qory-answer-ed25519-v1"}[domain]
		if ed25519.Verify(signing.Public().(ed25519.PublicKey), []byte(strings.Join(other, "\n")), b64(t, a.Signature)) {
			t.Errorf("%s: the signature verifies under %s", a.Note, other[0])
		}
	}
}

// Edwards25519 in math/big, for the checks crypto/ed25519 keeps to itself: decoding a
// public key strictly or leniently, the order of a point, and the u-coordinate.

var (
	fieldP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	curveD = func() *big.Int {
		d := new(big.Int).ModInverse(big.NewInt(121666), fieldP)
		d.Mul(d, big.NewInt(-121665))
		return d.Mod(d, fieldP)
	}()
	groupL = func() *big.Int {
		l, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
		return l.Add(l, new(big.Int).Lsh(big.NewInt(1), 252))
	}()
)

type point struct{ x, y *big.Int }

func identity() point { return point{big.NewInt(0), big.NewInt(1)} }

func (a point) equal(b point) bool { return a.x.Cmp(b.x) == 0 && a.y.Cmp(b.y) == 0 }

func mod(x *big.Int) *big.Int { return x.Mod(x, fieldP) }

// add is the complete addition law of the twisted Edwards curve -x² + y² = 1 + d·x²·y².
func (a point) add(b point) point {
	t := mod(new(big.Int).Mul(curveD, mod(new(big.Int).Mul(mod(new(big.Int).Mul(a.x, b.x)), mod(new(big.Int).Mul(a.y, b.y))))))
	x := mod(new(big.Int).Add(new(big.Int).Mul(a.x, b.y), new(big.Int).Mul(a.y, b.x)))
	y := mod(new(big.Int).Add(new(big.Int).Mul(a.y, b.y), new(big.Int).Mul(a.x, b.x)))
	x.Mul(x, new(big.Int).ModInverse(mod(new(big.Int).Add(big.NewInt(1), t)), fieldP))
	y.Mul(y, new(big.Int).ModInverse(mod(new(big.Int).Sub(big.NewInt(1), t)), fieldP))
	return point{mod(x), mod(y)}
}

func (a point) mul(k *big.Int) point {
	r := identity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = r.add(r)
		if k.Bit(i) == 1 {
			r = r.add(a)
		}
	}
	return r
}

func littleEndian(b []byte) *big.Int {
	r := slices.Clone(b)
	slices.Reverse(r)
	return new(big.Int).SetBytes(r)
}

func (a point) encode() []byte {
	b := make([]byte, 32)
	a.y.FillBytes(b)
	slices.Reverse(b)
	b[31] |= byte(a.x.Bit(0)) << 7
	return b
}

// decode reads a 32-byte encoding. Strictly, as RFC 8032 decodes, y must be below p and
// x = 0 must come with the sign bit clear; leniently, y is taken mod p and the sign bit
// of x = 0 is ignored, as some decoders do. ok is false for an encoding off the curve,
// or one the strict reading refuses.
func decode(b []byte, strict bool) (point, bool) {
	if len(b) != 32 {
		return point{}, false
	}
	sign := uint(b[31] >> 7)
	yb := slices.Clone(b)
	yb[31] &= 0x7f
	y := littleEndian(yb)
	if y.Cmp(fieldP) >= 0 {
		if strict {
			return point{}, false
		}
		y = mod(y)
	}
	y2 := mod(new(big.Int).Mul(y, y))
	u := mod(new(big.Int).Sub(y2, big.NewInt(1)))
	v := mod(new(big.Int).Add(new(big.Int).Mul(curveD, y2), big.NewInt(1)))
	x2 := mod(new(big.Int).Mul(u, new(big.Int).ModInverse(v, fieldP)))
	x := new(big.Int).ModSqrt(x2, fieldP)
	if x == nil {
		return point{}, false
	}
	if x.Sign() == 0 && sign == 1 {
		if strict {
			return point{}, false
		}
		return point{x, y}, true
	}
	if x.Bit(0) != sign {
		x.Sub(fieldP, x)
	}
	return point{x, y}, true
}

// order is the order of a point of small order, 1, 2, 4 or 8, or 0 for any other point.
func (a point) order() int {
	for _, n := range []int{1, 2, 4, 8} {
		if a.mul(big.NewInt(int64(n))).equal(identity()) {
			return n
		}
	}
	return 0
}

// montgomery returns the u-coordinate of an Ed25519 public key, u = (1 + y) / (1 − y)
// mod p, little-endian.
func montgomery(t *testing.T, pub []byte) []byte {
	t.Helper()
	a, ok := decode(pub, true)
	if !ok {
		t.Fatalf("%x is no canonical point", pub)
	}
	u := mod(new(big.Int).Add(big.NewInt(1), a.y))
	u.Mul(u, new(big.Int).ModInverse(mod(new(big.Int).Sub(big.NewInt(1), a.y)), fieldP))
	b := make([]byte, 32)
	mod(u).FillBytes(b)
	slices.Reverse(b)
	return b
}

// TestSmallOrderList pins the public keys enrolment refuses. The eight canonical
// encodings of the points of small order decode strictly to points of the order they
// are listed with; the six non-canonical encodings fail the strict decoding and decode
// leniently to one of those points. The fixture access key passes all five checks:
// canonical, on the curve, not of small order, of prime order, and y ≠ 1. The torsion
// key is the fixture access key plus the first order-8 point and fails only prime
// order. The arithmetic is checked first against crypto/ed25519: the base point times
// the access key's scalar is its public key.
func TestSmallOrderList(t *testing.T) {
	k := loadKeys(t)
	priv := k.accessKey(t)
	h := sha512.Sum512(priv.Seed())
	scalar := slices.Clone(h[:32])
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64
	base, ok := decode(b64(t, "WGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY"), true)
	if !ok {
		t.Fatal("the base point does not decode")
	}
	pub := b64(t, k.AccessKey.PublicKey)
	if got := base.mul(littleEndian(scalar)).encode(); !bytes.Equal(got, pub) {
		t.Fatalf("[s]B is %x; want the access key's public key %x", got, pub)
	}

	var list struct {
		SmallOrder []struct {
			Point    string `json:"point"`
			Order    int    `json:"order"`
			Encoding string `json:"encoding"`
		} `json:"small_order"`
		NonCanonical []struct {
			Point    string `json:"point"`
			Encoding string `json:"encoding"`
		} `json:"non_canonical"`
		Torsion struct {
			Encoding string `json:"encoding"`
		} `json:"torsion"`
	}
	load(t, "fixtures/known-answers/small-order.json", &list)
	if len(list.SmallOrder) != 8 || len(list.NonCanonical) != 6 {
		t.Fatalf("%d small-order and %d non-canonical encodings; want 8 and 6", len(list.SmallOrder), len(list.NonCanonical))
	}
	small := map[string]bool{}
	for _, e := range list.SmallOrder {
		b := b64(t, e.Encoding)
		p, ok := decode(b, true)
		if !ok {
			t.Errorf("%s %s: does not decode strictly", e.Point, e.Encoding)
			continue
		}
		if !bytes.Equal(p.encode(), b) {
			t.Errorf("%s %s: re-encodes to %x", e.Point, e.Encoding, p.encode())
		}
		if n := p.order(); n != e.Order {
			t.Errorf("%s %s: order %d; want %d", e.Point, e.Encoding, n, e.Order)
		}
		small[string(b)] = true
	}
	if len(small) != 8 {
		t.Errorf("%d distinct small-order encodings; want 8", len(small))
	}
	nonCanonical := map[string]bool{}
	for _, e := range list.NonCanonical {
		b := b64(t, e.Encoding)
		if nonCanonical[string(b)] || small[string(b)] {
			t.Errorf("%s %s: listed twice", e.Point, e.Encoding)
		}
		nonCanonical[string(b)] = true
		if _, ok := decode(b, true); ok {
			t.Errorf("%s %s: decodes strictly; want a refusal", e.Point, e.Encoding)
		}
		p, ok := decode(b, false)
		if !ok || !small[string(p.encode())] {
			t.Errorf("%s %s: does not decode leniently to a point of small order", e.Point, e.Encoding)
		}
	}

	a, ok := decode(pub, true)
	if !ok || a.order() != 0 || !a.mul(groupL).equal(identity()) || a.y.Cmp(big.NewInt(1)) == 0 {
		t.Error("the fixture access key fails one of the five checks")
	}
	torsion := b64(t, list.Torsion.Encoding)
	tp, ok := decode(torsion, true)
	if !ok || !bytes.Equal(tp.encode(), torsion) {
		t.Fatalf("the torsion key %s is no canonical point", list.Torsion.Encoding)
	}
	if tp.order() != 0 {
		t.Error("the torsion key is of small order; want only prime order to fail")
	}
	if tp.mul(groupL).equal(identity()) {
		t.Error("the torsion key is of prime order; want [l]T not the identity")
	}
	eight, _ := decode(b64(t, list.SmallOrder[4].Encoding), true)
	if got := a.add(eight).encode(); !bytes.Equal(got, torsion) {
		t.Errorf("the fixture access key plus the first order-8 point is %x; want the torsion key %x", got, torsion)
	}
}

// globMatch matches a deny list entry against a whole name, ignoring case: * matches any
// run of characters, the empty run included.
func globMatch(entry, name string) bool {
	parts := strings.Split(strings.ToUpper(entry), "*")
	name = strings.ToUpper(name)
	if len(parts) == 1 {
		return parts[0] == name
	}
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	name = name[len(parts[0]):]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(name, p)
		if i < 0 {
			return false
		}
		name = name[i+len(p):]
	}
	return strings.HasSuffix(name, parts[len(parts)-1])
}

// TestDeniedVariables pins denied-variables.json: version 1, names and patterns in the
// entry grammar, and the built-in list's rows, each left out in upper and lower case,
// while names beside them stay.
func TestDeniedVariables(t *testing.T) {
	var d struct {
		Version  int      `json:"version"`
		Names    []string `json:"names"`
		Patterns []string `json:"patterns"`
	}
	load(t, "denied-variables.json", &d)
	if d.Version != 1 {
		t.Errorf("version %d; want 1", d.Version)
	}
	entry := regexp.MustCompile(`^[A-Za-z0-9_*]{1,128}$`)
	for _, list := range []struct {
		name    string
		entries []string
		star    bool
	}{{"names", d.Names, false}, {"patterns", d.Patterns, true}} {
		if len(list.entries) == 0 || !slices.IsSorted(list.entries) || len(slices.Compact(slices.Clone(list.entries))) != len(list.entries) {
			t.Errorf("%s %q; want a sorted list without repeats", list.name, list.entries)
		}
		for _, e := range list.entries {
			if !entry.MatchString(e) || strings.Trim(e, "*") == "" || strings.Contains(e, "*") != list.star {
				t.Errorf("%s: %q outside the entry grammar", list.name, e)
			}
		}
	}
	denied := func(name string) bool {
		for _, e := range append(slices.Clone(d.Names), d.Patterns...) {
			if globMatch(e, name) {
				return true
			}
		}
		return false
	}
	for _, name := range []string{
		"QORY_ACCESS_KEY_SECRET", "QORY_ACCESS_KEY_ID", "QORY_RUN_ID", "QORY_",
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY",
		"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "AWS_CA_BUNDLE", "GIT_SSL_CAINFO",
		"SSL_CERT_DIR", "GIT_SSL_CAPATH",
		"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "DOCKER_CONFIG",
		"PATH",
	} {
		for _, n := range []string{name, strings.ToLower(name)} {
			if !denied(n) {
				t.Errorf("%s is not on the deny list", n)
			}
		}
	}
	for _, name := range []string{"NODE_ENV", "APP_REGION", "PATHEXT", "MY_PATH", "PROXY", "HTTP_PROXY_URL", "QORY", "DOCKER_BUILDKIT", "ANTHROPIC_BASE_URL"} {
		if denied(name) {
			t.Errorf("%s is on the deny list; want it left to the server", name)
		}
	}
}

// TestRunRefusedCodes pins the codes of dev.qory.run.refused: the server's, the
// runner's and qory's.
func TestRunRefusedCodes(t *testing.T) {
	var s struct {
		Properties struct {
			Code struct {
				Enum []string `json:"enum"`
			} `json:"code"`
		} `json:"properties"`
	}
	load(t, "events/run.refused.schema.json", &s)
	want := []string{
		"answer_unsigned", "apiary_public_key_missing", "bad_request", "engine_unreachable",
		"image_unknown", "instance_limit", "invalid_request", "key_invalid", "key_limit",
		"labels_changed", "mount_contains_forager_files", "mount_mode_conflict",
		"mount_shared_with_run", "mount_through_link", "placeholder_conflict", "rate_limited",
		"run_closed", "run_configuration_invalid", "run_configuration_superseded",
		"secrets_not_allowed", "server_needs_wall", "tool_unknown", "unauthorized",
		"unavailable", "unsupported_contract_version", "variable_reserved",
	}
	if len(want) != 26 {
		t.Fatalf("%d codes in the test's list; want 26", len(want))
	}
	if got := slices.Sorted(slices.Values(s.Properties.Code.Enum)); !slices.Equal(got, want) {
		t.Errorf("run.refused codes %q; want %q", got, want)
	}
}
