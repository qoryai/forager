package contracts_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"path"
	"slices"
	"strconv"
	"testing"

	"github.com/qoryai/forager/contracts"
)

// The sealed fixture of the secrets request, fixtures/sealed: the run configuration,
// the request, the envelope that answers it and what the envelope opens to, and the
// envelopes that are refused, each recomputed here with Go's standard library alone.

// The suite of the envelope, as the contract writes it and as RFC 9180 numbers it.
const (
	sealedSuite        = "x25519-sha256-aes256gcm"
	kemID, kdfID, aeID = 0x0020, 0x0001, 0x0002
)

// lp16 is a u16 big-endian length, then the bytes, as info and aad write each value;
// lp32 the same with a u32, as the envelope's signed message writes each value.
func lp16(b []byte, s string) []byte {
	return append(binary.BigEndian.AppendUint16(b, uint16(len(s))), s...)
}

func lp32(b, v []byte) []byte {
	return append(binary.BigEndian.AppendUint32(b, uint32(len(v))), v...)
}

// sealedInfo is HPKE's info: "qory secrets v1", a zero byte, the suite's three ids as
// u16 big-endian, and lp16 of the access key id.
func sealedInfo(accessKeyID string) []byte {
	b := append([]byte("qory secrets v1"), 0)
	for _, id := range []uint16{kemID, kdfID, aeID} {
		b = binary.BigEndian.AppendUint16(b, id)
	}
	return lp16(b, accessKeyID)
}

// sealedAAD is the open's associated data: lp16 of the run id, the access key id, the
// run configuration's digest and exp in canonical decimal.
func sealedAAD(runID, accessKeyID, digest string, exp uint64) []byte {
	var b []byte
	for _, s := range []string{runID, accessKeyID, digest, strconv.FormatUint(exp, 10)} {
		b = lp16(b, s)
	}
	return b
}

// envelopeMessage is what an envelope's sig covers: lp32 of "qory envelope v1", the
// suite, the access key id, the run id, the digest, exp in canonical decimal, enc and
// ct, the last two raw.
func envelopeMessage(e sealedEnvelope, enc, ct []byte) []byte {
	var m []byte
	for _, s := range []string{"qory envelope v1", e.Suite, e.AccessKeyID, e.RunID, e.RunConfiguration, strconv.FormatUint(e.Exp, 10)} {
		m = lp32(m, []byte(s))
	}
	return lp32(lp32(m, enc), ct)
}

// rfc9180Seal is RFC 9180's base mode for DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
// AES-256-GCM, written out with a given ephemeral key, which crypto/hpke does not take:
// it returns enc and the ciphertext with its tag.
func rfc9180Seal(t *testing.T, ephemeral, pkR, info, aad, pt []byte) (enc, ct []byte) {
	t.Helper()
	skE, err := ecdh.X25519().NewPrivateKey(ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ecdh.X25519().NewPublicKey(pkR)
	if err != nil {
		t.Fatal(err)
	}
	dh, err := skE.ECDH(pub)
	if err != nil {
		t.Fatal(err)
	}
	enc = skE.PublicKey().Bytes()
	u16 := func(n int) []byte { return binary.BigEndian.AppendUint16(nil, uint16(n)) }
	extract := func(suiteID, salt []byte, label string, ikm []byte) []byte {
		b, err := hkdf.Extract(sha256.New, slices.Concat([]byte("HPKE-v1"), suiteID, []byte(label), ikm), salt)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	expand := func(suiteID, prk []byte, label string, info []byte, n int) []byte {
		b, err := hkdf.Expand(sha256.New, prk, string(slices.Concat(u16(n), []byte("HPKE-v1"), suiteID, []byte(label), info)), n)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	kem := slices.Concat([]byte("KEM"), u16(kemID))
	shared := expand(kem, extract(kem, nil, "eae_prk", dh), "shared_secret", slices.Concat(enc, pkR), 32)
	suiteID := slices.Concat([]byte("HPKE"), u16(kemID), u16(kdfID), u16(aeID))
	ctx := slices.Concat([]byte{0}, extract(suiteID, nil, "psk_id_hash", nil), extract(suiteID, nil, "info_hash", info))
	secret := extract(suiteID, shared, "secret", nil)
	block, err := aes.NewCipher(expand(suiteID, secret, "key", ctx, 32))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return enc, gcm.Seal(nil, expand(suiteID, secret, "base_nonce", ctx, 12), pt, aad)
}

// hpkeOpen opens ct with crypto/hpke: NewRecipient with info, then Open on the context
// with aad, since the single-shot Open takes no aad.
func hpkeOpen(t *testing.T, skR, enc, info, aad, ct []byte) ([]byte, error) {
	t.Helper()
	priv, err := hpke.DHKEM(ecdh.X25519()).NewPrivateKey(skR)
	if err != nil {
		t.Fatal(err)
	}
	r, err := hpke.NewRecipient(enc, priv, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, err
	}
	return r.Open(aad, ct)
}

type sealedEnvelope struct {
	Suite            string `json:"suite"`
	AccessKeyID      string `json:"access_key_id"`
	RunID            string `json:"run_id"`
	RunConfiguration string `json:"run_configuration"`
	Exp              uint64 `json:"exp"`
	Enc              string `json:"enc"`
	CT               string `json:"ct"`
	Sig              string `json:"sig"`
}

type sealedAnswer struct {
	Version int            `json:"version"`
	Sealed  sealedEnvelope `json:"sealed"`
}

type sealedRequest struct {
	RunID            string   `json:"run_id"`
	RunConfiguration string   `json:"run_configuration"`
	Credentials      []string `json:"credentials"`
	Timestamp        uint64   `json:"timestamp"`
}

type sealedPlaintext struct {
	RunConfiguration string   `json:"run_configuration"`
	Credentials      []string `json:"credentials"`
	Values           []struct {
		Credential string `json:"credential"`
		Value      string `json:"value"`
	} `json:"values"`
}

type sealedCase struct {
	File      string `json:"file"`
	Note      string `json:"note"`
	Refused   string `json:"refused"`
	Plaintext string `json:"plaintext"`
	Info      string `json:"info"`
	AAD       string `json:"aad"`
}

type sealedVectors struct {
	Now                    uint64       `json:"now"`
	EphemeralPrivateKey    string       `json:"ephemeral_private_key"`
	Info                   string       `json:"info"`
	InfoLength             int          `json:"info_length"`
	AAD                    string       `json:"aad"`
	AADLength              int          `json:"aad_length"`
	RunConfigurationLength int          `json:"run_configuration_length"`
	SecretsRequestLength   int          `json:"secrets_request_length"`
	SecretsRequestSHA256   string       `json:"secrets_request_sha256"`
	PlaintextLength        int          `json:"plaintext_length"`
	CTLength               int          `json:"ct_length"`
	CTSHA256               string       `json:"ct_sha256"`
	SignedLength           int          `json:"signed_length"`
	SignedSHA256           string       `json:"signed_sha256"`
	Invalid                []sealedCase `json:"invalid"`
}

// TestSealedFixturesValidate pins that every file of fixtures/sealed passes its schema:
// the run configuration, the request, the answer and the three plaintexts; and that of
// the refused envelopes of fixtures/sealed/invalid, every one passes the answer's
// schema but the one of an unknown suite, which the schema refuses. A file no test
// reads fails the test.
func TestSealedFixturesValidate(t *testing.T) {
	s := compile(t, "run-configuration.schema.json", "secrets-request.schema.json", "secrets-answer.schema.json",
		"sealed-plaintext.schema.json")
	want := map[string]string{
		"fixtures/sealed/run-configuration.json":       "run-configuration.schema.json",
		"fixtures/sealed/secrets-request.json":         "secrets-request.schema.json",
		"fixtures/sealed/secrets-answer.json":          "secrets-answer.schema.json",
		"fixtures/sealed/sealed-plaintext.json":        "sealed-plaintext.schema.json",
		"fixtures/sealed/plaintext-other-digest.json":  "sealed-plaintext.schema.json",
		"fixtures/sealed/plaintext-not-requested.json": "sealed-plaintext.schema.json",
	}
	for _, f := range files(t, "fixtures/sealed") {
		if _, ok := want[f]; !ok && f != "fixtures/sealed/vectors.json" {
			t.Errorf("%s: a fixture no test validates", f)
		}
	}
	for f, schema := range want {
		doc, err := contracts.Document(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := s[schema].Validate(doc); err != nil {
			t.Errorf("%s against %s: %v", f, schema, err)
		}
	}
	for _, f := range files(t, "fixtures/sealed/invalid") {
		doc, err := contracts.Document(f)
		if err != nil {
			t.Fatal(err)
		}
		err = s["secrets-answer.schema.json"].Validate(doc)
		if suite := path.Base(f) == "unknown-suite.json"; suite != (err != nil) {
			t.Errorf("%s against secrets-answer.schema.json: %v; want refused %t", f, err, suite)
		}
	}
}

// sealedFixture is what every test of the sealed fixture reads: the vectors, the run
// configuration, the request, the answer, the plaintext, and the fixture keys.
type sealedFixture struct {
	vec       sealedVectors
	doc       []byte
	digest    string
	request   sealedRequest
	answer    sealedAnswer
	plaintext []byte
	keys      fixtureKeys
}

func loadSealed(t *testing.T) sealedFixture {
	t.Helper()
	var f sealedFixture
	load(t, "fixtures/sealed/vectors.json", &f.vec)
	f.doc = read(t, "fixtures/sealed/run-configuration.json")
	f.digest = "sha256=" + hexSHA256(f.doc)
	load(t, "fixtures/sealed/secrets-request.json", &f.request)
	load(t, "fixtures/sealed/secrets-answer.json", &f.answer)
	f.plaintext = read(t, "fixtures/sealed/sealed-plaintext.json")
	f.keys = loadKeys(t)
	return f
}

// TestSealedFixture pins the sealed fixture end to end: the run configuration's digest,
// sha256= and the hex SHA-256 of its bytes; the request that lists it and the names of
// the run configuration's credentials, in their order; info and aad built from the
// envelope's identifiers; enc and ct, sealed again with the fixed ephemeral key by RFC
// 9180 written out here; the envelope's signature under the fixture signing key; and
// the open with crypto/hpke, which yields the published plaintext, and fails with an
// altered aad. The plaintext lists the request's credentials, sorted, and one value for
// each, sorted by credential.
func TestSealedFixture(t *testing.T) {
	f := loadSealed(t)
	vec, s := f.vec, f.answer.Sealed
	if len(f.doc) != vec.RunConfigurationLength {
		t.Errorf("run configuration of %d bytes; want %d", len(f.doc), vec.RunConfigurationLength)
	}
	reqBytes := read(t, "fixtures/sealed/secrets-request.json")
	if len(reqBytes) != vec.SecretsRequestLength || hexSHA256(reqBytes) != vec.SecretsRequestSHA256 {
		t.Errorf("secrets request of %d bytes, SHA-256 %s; want %d and %s", len(reqBytes), hexSHA256(reqBytes),
			vec.SecretsRequestLength, vec.SecretsRequestSHA256)
	}
	if f.request.RunConfiguration != f.digest || s.RunConfiguration != f.digest {
		t.Errorf("digests %s and %s; want the run configuration's %s", f.request.RunConfiguration, s.RunConfiguration, f.digest)
	}
	var rc struct {
		Credentials []struct {
			Name string `json:"name"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(f.doc, &rc); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range rc.Credentials {
		names = append(names, c.Name)
	}
	if !slices.Equal(f.request.Credentials, names) {
		t.Errorf("the request lists %q; want the run configuration's %q, in its order", f.request.Credentials, names)
	}
	if s.RunID != f.request.RunID || s.AccessKeyID != f.keys.AccessKey.AccessKeyID || s.Suite != sealedSuite {
		t.Errorf("envelope of %s for %s in %s; want the request's run, the fixture access key and the suite", s.RunID, s.AccessKeyID, s.Suite)
	}
	if s.Exp != f.request.Timestamp+600 || f.request.Timestamp != vec.Now {
		t.Errorf("exp %d and timestamp %d; want the vectors' now, %d, and exp 600 seconds after it", s.Exp, f.request.Timestamp, vec.Now)
	}

	info := sealedInfo(s.AccessKeyID)
	if len(info) != vec.InfoLength || hex.EncodeToString(info) != vec.Info {
		t.Errorf("info %x, %d bytes; want %s, %d", info, len(info), vec.Info, vec.InfoLength)
	}
	kem, kdf, aead := hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.AES256GCM()
	if kem.ID() != kemID || kdf.ID() != kdfID || aead.ID() != aeID {
		t.Errorf("suite %#04x %#04x %#04x; want 0x0020 0x0001 0x0002", kem.ID(), kdf.ID(), aead.ID())
	}
	aad := sealedAAD(s.RunID, s.AccessKeyID, s.RunConfiguration, s.Exp)
	if len(aad) != vec.AADLength || hex.EncodeToString(aad) != vec.AAD {
		t.Errorf("aad %x, %d bytes; want %s, %d", aad, len(aad), vec.AAD, vec.AADLength)
	}

	ephemeral := b64(t, vec.EphemeralPrivateKey)
	if !bytes.Equal(ephemeral, counting(33, 32)) {
		t.Errorf("ephemeral private key %x; want bytes 33 to 64", ephemeral)
	}
	enc, ct := b64(t, s.Enc), b64(t, s.CT)
	if len(ct) != vec.CTLength || hexSHA256(ct) != vec.CTSHA256 {
		t.Errorf("ct of %d bytes, SHA-256 %s; want %d, %s", len(ct), hexSHA256(ct), vec.CTLength, vec.CTSHA256)
	}
	pkR := b64(t, f.keys.AccessKey.X25519PublicKey)
	wantEnc, wantCT := rfc9180Seal(t, ephemeral, pkR, info, aad, f.plaintext)
	if !bytes.Equal(enc, wantEnc) || !bytes.Equal(ct, wantCT) {
		t.Errorf("enc %x and ct %x; want, sealed again, %x and %x", enc, ct, wantEnc, wantCT)
	}

	signed := envelopeMessage(s, enc, ct)
	if len(signed) != vec.SignedLength || hexSHA256(signed) != vec.SignedSHA256 {
		t.Errorf("signed message of %d bytes, SHA-256 %s; want %d, %s", len(signed), hexSHA256(signed), vec.SignedLength, vec.SignedSHA256)
	}
	signs(t, "envelope sig", ed25519.NewKeyFromSeed(b64(t, f.keys.SigningKey.Seed)), signed, s.Sig)

	skR := b64(t, f.keys.AccessKey.X25519PrivateKey)
	pt, err := hpkeOpen(t, skR, enc, info, aad, ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(pt, f.plaintext) || len(pt) != vec.PlaintextLength {
		t.Errorf("plaintext of %d bytes %q; want %d bytes %q", len(pt), pt, vec.PlaintextLength, f.plaintext)
	}
	altered := slices.Clone(aad)
	altered[len(altered)-1] ^= 1
	if _, err := hpkeOpen(t, skR, enc, info, altered, ct); err == nil {
		t.Error("the envelope opens with an altered aad")
	}

	var p sealedPlaintext
	if err := json.Unmarshal(pt, &p); err != nil {
		t.Fatal(err)
	}
	sorted := slices.Sorted(slices.Values(f.request.Credentials))
	if p.RunConfiguration != f.digest || !slices.Equal(p.Credentials, sorted) {
		t.Errorf("plaintext for %s and %q; want %s and %q, sorted", p.RunConfiguration, p.Credentials, f.digest, sorted)
	}
	var valued []string
	for _, v := range p.Values {
		valued = append(valued, v.Credential)
	}
	if !slices.Equal(valued, sorted) {
		t.Errorf("plaintext values for %q; want one for each of %q, sorted", valued, sorted)
	}
}

// refusedAt runs the checks whoever opens an envelope makes, in their order, with the
// request's run id, digest and credentials and the access key's id, at now, and
// returns the name of the first one that refuses it, or "" when none does: suite,
// signature, run_id, run_configuration, expired (exp more than 300 seconds past),
// ahead (exp more than 900 seconds ahead), open (with info and aad built from the
// caller's values), values (the plaintext's credentials and values against the
// request).
func refusedAt(t *testing.T, f sealedFixture, e sealedEnvelope, now uint64) string {
	t.Helper()
	enc, ct := b64(t, e.Enc), b64(t, e.CT)
	signer := ed25519.NewKeyFromSeed(b64(t, f.keys.SigningKey.Seed)).Public().(ed25519.PublicKey)
	keyID := f.keys.AccessKey.AccessKeyID
	switch {
	case e.Suite != sealedSuite:
		return "suite"
	case !ed25519.Verify(signer, envelopeMessage(e, enc, ct), b64(t, e.Sig)):
		return "signature"
	case e.AccessKeyID != keyID:
		return "access_key_id"
	case e.RunID != f.request.RunID:
		return "run_id"
	case e.RunConfiguration != f.digest:
		return "run_configuration"
	case now > e.Exp+300:
		return "expired"
	case e.Exp > now+900:
		return "ahead"
	}
	pt, err := hpkeOpen(t, b64(t, f.keys.AccessKey.X25519PrivateKey), enc, sealedInfo(keyID), sealedAAD(f.request.RunID, keyID, f.digest, e.Exp), ct)
	if err != nil {
		return "open"
	}
	var p sealedPlaintext
	if err := json.Unmarshal(pt, &p); err != nil {
		t.Fatalf("a plaintext that is not JSON: %v", err)
	}
	sorted := slices.Sorted(slices.Values(f.request.Credentials))
	var valued []string
	for _, v := range p.Values {
		valued = append(valued, v.Credential)
	}
	if p.RunConfiguration != f.digest || !slices.Equal(p.Credentials, sorted) || !slices.Equal(valued, sorted) {
		return "values"
	}
	return ""
}

// TestSealedInvalidVectors pins every refused envelope of fixtures/sealed/invalid: each
// is sealed again from the plaintext, the info and the aad its case lists, with the
// fixed ephemeral key, and its enc and ct are the file's; a sig is the fixture signing
// key's over the envelope's members, the bad signature's case apart; and the checks of
// whoever opens it, in order, refuse it at the step its case names and at no step before. The
// accepted answer passes every check, and the cases cover every step but the access
// key's, which the run id's and the digest's stand for.
func TestSealedInvalidVectors(t *testing.T) {
	f := loadSealed(t)
	if got := refusedAt(t, f, f.answer.Sealed, f.vec.Now); got != "" {
		t.Errorf("secrets-answer.json is refused at %s", got)
	}
	ephemeral := b64(t, f.vec.EphemeralPrivateKey)
	pkR := b64(t, f.keys.AccessKey.X25519PublicKey)
	signer := ed25519.NewKeyFromSeed(b64(t, f.keys.SigningKey.Seed))
	listed := map[string]bool{}
	steps := map[string]bool{}
	for _, c := range f.vec.Invalid {
		listed[c.File] = true
		steps[c.Refused] = true
		var a sealedAnswer
		load(t, c.File, &a)
		e := a.Sealed
		info, err := hex.DecodeString(c.Info)
		if err != nil {
			t.Fatal(err)
		}
		aad, err := hex.DecodeString(c.AAD)
		if err != nil {
			t.Fatal(err)
		}
		pt := read(t, c.Plaintext)
		enc, ct := rfc9180Seal(t, ephemeral, pkR, info, aad, pt)
		if !bytes.Equal(b64(t, e.Enc), enc) || !bytes.Equal(b64(t, e.CT), ct) {
			t.Errorf("%s: enc and ct are not the case's plaintext sealed with its info and aad", c.File)
		}
		if opened, err := hpkeOpen(t, b64(t, f.keys.AccessKey.X25519PrivateKey), enc, info, aad, ct); err != nil || !bytes.Equal(opened, pt) {
			t.Errorf("%s: the envelope does not open with the info and aad of the case: %v", c.File, err)
		}
		if c.Refused != "signature" {
			signs(t, c.File, signer, envelopeMessage(e, enc, ct), e.Sig)
		}
		if got := refusedAt(t, f, e, f.vec.Now); got != c.Refused {
			t.Errorf("%s: refused at %q; want %q", c.File, got, c.Refused)
		}
	}
	for _, file := range files(t, "fixtures/sealed/invalid") {
		if !listed[file] {
			t.Errorf("%s: no case of vectors.json lists it", file)
		}
	}
	for _, step := range []string{"suite", "signature", "run_id", "run_configuration", "expired", "ahead", "open", "values"} {
		if !steps[step] {
			t.Errorf("no case is refused at %s", step)
		}
	}
	// The edges of exp are inclusive: 300 seconds past and 900 ahead still open.
	for _, now := range []uint64{f.answer.Sealed.Exp + 300, f.answer.Sealed.Exp - 900} {
		if got := refusedAt(t, f, f.answer.Sealed, now); got != "" {
			t.Errorf("at %d, exp %d: refused at %s", now, f.answer.Sealed.Exp, got)
		}
	}
}
