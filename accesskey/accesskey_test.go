package accesskey_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filippo.io/edwards25519"

	"github.com/qoryai/runner/accesskey"
	"github.com/qoryai/runner/contracts"
)

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

type fixtureKeys struct {
	AccessKey struct {
		Secret           string `json:"secret"`
		AccessKeyID      string `json:"access_key_id"`
		InstanceID       string `json:"instance_id"`
		PublicKey        string `json:"public_key"`
		Fingerprint      string `json:"fingerprint"`
		X25519PrivateKey string `json:"x25519_private_key"`
		X25519PublicKey  string `json:"x25519_public_key"`
	} `json:"access_key"`
	SigningKey     signingKey `json:"signing_key"`
	NextSigningKey signingKey `json:"next_signing_key"`
}

type signingKey struct {
	Seed        string `json:"seed"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

func keys(t *testing.T) fixtureKeys {
	t.Helper()
	var k fixtureKeys
	load(t, "fixtures/known-answers/keys.json", &k)
	return k
}

// accessKey is the fixture access key, read from its secret.
func (k fixtureKeys) accessKey(t *testing.T) *accesskey.Key {
	t.Helper()
	key, err := accesskey.ParseSecret(k.AccessKey.Secret)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// signing is a fixture signing key of the server, from its seed.
func (s signingKey) key(t *testing.T) *accesskey.Key {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString(s.Seed)
	if err != nil {
		t.Fatal(err)
	}
	key, err := accesskey.NewKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func (s signingKey) pin() accesskey.Pin {
	return accesskey.Pin{{Alg: "ed25519", PublicKey: s.PublicKey}}
}

// TestFixtureAccessKey reproduces the fixture access key from its secret: the secret
// read and written again, the public key, its fingerprint, the X25519 private key and
// the X25519 public key both from the private key and as the u-coordinate of the
// Ed25519 public key; and the fixture signing keys from their seeds.
func TestFixtureAccessKey(t *testing.T) {
	k := keys(t)
	key := k.accessKey(t)
	a := k.AccessKey
	if key.Secret() != a.Secret {
		t.Errorf("Secret = %s, want the one it was read from", key.Secret())
	}
	if got := key.PublicKey().String(); got != a.PublicKey {
		t.Errorf("public key %s, want %s", got, a.PublicKey)
	}
	if got := key.Fingerprint(); got != a.Fingerprint {
		t.Errorf("fingerprint %s, want %s", got, a.Fingerprint)
	}
	if got := base64.RawURLEncoding.EncodeToString(key.X25519PrivateKey()); got != a.X25519PrivateKey {
		t.Errorf("X25519 private key %s, want %s", got, a.X25519PrivateKey)
	}
	if got := base64.RawURLEncoding.EncodeToString(key.X25519().Bytes()); got != a.X25519PrivateKey {
		t.Errorf("X25519().Bytes() %s, want %s", got, a.X25519PrivateKey)
	}
	if got := base64.RawURLEncoding.EncodeToString(key.X25519().PublicKey().Bytes()); got != a.X25519PublicKey {
		t.Errorf("X25519 public key from the private key %s, want %s", got, a.X25519PublicKey)
	}
	u, err := key.PublicKey().X25519()
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.RawURLEncoding.EncodeToString(u); got != a.X25519PublicKey {
		t.Errorf("X25519 public key as the u-coordinate %s, want %s", got, a.X25519PublicKey)
	}
	if err := accesskey.CheckID(a.AccessKeyID); err != nil {
		t.Error(err)
	}
	if err := accesskey.CheckInstanceID(a.InstanceID); err != nil {
		t.Error(err)
	}
	if !key.PublicKey().Fixture() {
		t.Error("the fixture access key is not reported as a fixture")
	}
	// A second fixture access key, the seed being bytes 193 to 224, has its secret
	// published too and is refused alike.
	second, err := accesskey.ParseSecret("qak_wcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3-A")
	if err != nil {
		t.Fatal(err)
	}
	if !second.PublicKey().Fixture() {
		t.Errorf("the second fixture access key %s is not reported as a fixture", second.PublicKey())
	}
	for _, s := range []signingKey{k.SigningKey, k.NextSigningKey} {
		sk := s.key(t)
		if got := sk.PublicKey().String(); got != s.PublicKey || sk.Fingerprint() != s.Fingerprint {
			t.Errorf("signing key %s, fingerprint %s; want %s, %s", got, sk.Fingerprint(), s.PublicKey, s.Fingerprint)
		}
		if !sk.PublicKey().Fixture() || !s.pin().Fixture() {
			t.Errorf("the fixture signing key %s is not reported as a fixture", s.PublicKey)
		}
	}
	other, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if other.PublicKey().Fixture() {
		t.Error("a generated key is reported as a fixture")
	}
}

// TestKeyFormatsAsItsFingerprint pins that a key printed with any verb shows its
// fingerprint and never its secret: by pointer and by value, inside slices, maps and
// structs, in unexported fields, under a bad verb, and through slog's text and JSON
// handlers.
func TestKeyFormatsAsItsFingerprint(t *testing.T) {
	key := keys(t).accessKey(t)
	secret := strings.TrimPrefix(key.Secret(), accesskey.SecretPrefix)
	seed, _ := base64.RawURLEncoding.DecodeString(secret)
	seedHex := hex.EncodeToString(seed)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		type hidden struct {
			k  accesskey.Key
			kp *accesskey.Key
		}
		for _, v := range []any{key, *key, []*accesskey.Key{key}, struct{ K *accesskey.Key }{key}, struct{ K accesskey.Key }{*key}, hidden{*key, key}, []hidden{{*key, key}}, map[string]any{"k": hidden{*key, key}}} {
			got := fmt.Sprintf(verb, v)
			if strings.Contains(got, secret) || strings.Contains(got, seedHex) || strings.Contains(got, "[1 2 3 4 5") {
				t.Errorf("%s of %T: %q", verb, v, got)
			}
		}
		if got := fmt.Sprintf(verb, key); !strings.Contains(got, key.Fingerprint()) {
			t.Errorf("%s: %q", verb, got)
		}
	}
	for _, verb := range []string{"%z", "%!", "%[2]v", "%d %d"} {
		if got := fmt.Sprintf(verb, key); strings.Contains(got, secret) || strings.Contains(got, seedHex) {
			t.Errorf("a bad verb %s: %q", verb, got)
		}
	}
	var text, js bytes.Buffer
	for _, h := range []slog.Handler{slog.NewTextHandler(&text, nil), slog.NewJSONHandler(&js, nil)} {
		slog.New(h).Info("run", "key", key, "value", *key, "hidden", struct{ k accesskey.Key }{*key})
	}
	for name, out := range map[string]string{"text": text.String(), "JSON": js.String()} {
		if strings.Contains(out, secret) || strings.Contains(out, seedHex) || !strings.Contains(out, key.Fingerprint()) {
			t.Errorf("slog's %s handler: %s", name, out)
		}
	}
}

// TestParseSecretIsStrict pins that a secret is qak_ and the seed in base64url without
// padding, decoded strictly, and that an error never contains the secret.
func TestParseSecretIsStrict(t *testing.T) {
	good := keys(t).AccessKey.Secret
	encoded := strings.TrimPrefix(good, accesskey.SecretPrefix)
	for name, s := range map[string]string{
		"no prefix":         encoded,
		"another prefix":    "qok_" + encoded,
		"padding":           good + "=",
		"standard alphabet": accesskey.SecretPrefix + strings.ReplaceAll(strings.ReplaceAll(encoded, "-", "+"), "_", "/") + "+",
		"spare bits":        good[:len(good)-1] + "B",
		"short":             good[:len(good)-2],
		"line feed":         good[:20] + "\n" + good[20:],
		"long":              good + "AAAA",
	} {
		_, err := accesskey.ParseSecret(s)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), encoded[:10]) {
			t.Errorf("%s: the error contains the secret: %v", name, err)
		}
	}
	for name, s := range map[string]string{
		"padding":    keys(t).AccessKey.PublicKey + "=",
		"plus":       "+" + keys(t).AccessKey.PublicKey[1:],
		"spare bits": keys(t).AccessKey.PublicKey[:42] + "B",
	} {
		if _, err := accesskey.ParsePublicKey(s); err == nil {
			t.Errorf("public key with %s: accepted", name)
		}
	}
}

// TestGenerateMakesDistinctKeysThatRoundTrip pins that two generated keys differ and
// that each reads back from its secret.
func TestGenerateMakesDistinctKeysThatRoundTrip(t *testing.T) {
	a, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if a.Secret() == b.Secret() {
		t.Fatal("two generated keys are the same")
	}
	if len(a.Secret()) != 47 {
		t.Errorf("a secret is %d characters; want 47", len(a.Secret()))
	}
	again, err := accesskey.ParseSecret(a.Secret())
	if err != nil || again.PublicKey() != a.PublicKey() {
		t.Errorf("a secret does not read back to its key: %v", err)
	}
	if err := a.PublicKey().Check(); err != nil {
		t.Errorf("a generated key fails the key checks: %v", err)
	}
}

type signedVector struct {
	Note       string   `json:"note"`
	Body       string   `json:"body"`
	BodyLength int      `json:"body_length"`
	Lines      []string `json:"lines"`
	Length     int      `json:"length"`
	Signature  string   `json:"signature"`
}

type signatureVectors struct {
	Requests  []signedVector `json:"requests"`
	Enrolment []signedVector `json:"enrolment"`
	Answers   []signedVector `json:"answers"`
}

func vectors(t *testing.T) signatureVectors {
	t.Helper()
	var v signatureVectors
	load(t, "fixtures/known-answers/signatures.json", &v)
	return v
}

// body returns the bytes of the file a vector lists, with a JSON file's surrounding
// white space removed, or none for an empty name.
func (v signedVector) body(t *testing.T) []byte {
	t.Helper()
	if v.Body == "" {
		return nil
	}
	return bytes.TrimSpace(read(t, v.Body))
}

// TestRequestKnownAnswers signs the published GET strings under the fixture access key
// and instance id, and checks each string, its length and its signature against the
// known answer. A signature does not verify for another target, nor for a request
// whose access key id or instance id line differs.
func TestRequestKnownAnswers(t *testing.T) {
	k := keys(t)
	key := k.accessKey(t)
	for _, v := range vectors(t).Requests {
		r := accesskey.Request{AccessKeyID: k.AccessKey.AccessKeyID, InstanceID: k.AccessKey.InstanceID, Method: v.Lines[3], Target: v.Lines[4]}
		if r.Method == http.MethodPost {
			r.Body = []byte(v.Lines[5])
			if file := v.body(t); !bytes.Equal(file, r.Body) {
				t.Errorf("%s: the body's last line is not the file %s", v.Note, v.Body)
			}
		} else {
			r.Timestamp = v.Lines[5]
		}
		m, err := r.Message()
		if err != nil {
			t.Fatal(err)
		}
		if string(m) != strings.Join(v.Lines, "\n") || len(m) != v.Length {
			t.Errorf("%s: message of %d bytes:\n%s", v.Note, len(m), m)
		}
		if got, _ := key.SignRequest(r); got != v.Signature {
			t.Errorf("%s: signature %s, want %s", v.Note, got, v.Signature)
		}
		pub := key.PublicKey()
		if !pub.VerifyRequest(r, v.Signature) {
			t.Errorf("%s: the known answer does not verify", v.Note)
		}
		for name, changed := range map[string]func(accesskey.Request) accesskey.Request{
			"another target":      func(r accesskey.Request) accesskey.Request { r.Target = "/v1/events"; return r },
			"another access key":  func(r accesskey.Request) accesskey.Request { r.AccessKeyID = "ak_0000000000000000"; return r },
			"another instance id": func(r accesskey.Request) accesskey.Request { r.InstanceID = "i_other"; return r },
			"no instance id":      func(r accesskey.Request) accesskey.Request { r.InstanceID = ""; return r },
		} {
			if pub.VerifyRequest(changed(r), v.Signature) {
				t.Errorf("%s: verifies with %s", v.Note, name)
			}
		}
	}
}

// TestAnswerKnownAnswers verifies the published answers under the fixture signing key,
// as Forager pinning it does: 200 with the discovery body and its digest, 404 with an
// empty body, and the enrolment answers, under their own domain line, whose third line
// is the proof. Each is also signed again to the same bytes, and an answer with another
// status, another body, another digest, another request's signature or the other
// domain line does not verify: an enrolment answer's signature is never one of an
// answer to a signed request, nor the reverse.
func TestAnswerKnownAnswers(t *testing.T) {
	k := keys(t)
	signer := k.SigningKey.key(t)
	pin := k.SigningKey.pin()
	for _, v := range vectors(t).Answers {
		body := v.body(t)
		if len(body) != v.BodyLength {
			t.Errorf("%s: body of %d bytes, want %d", v.Note, len(body), v.BodyLength)
		}
		var status int
		fmt.Sscanf(v.Lines[1], "%d", &status)
		enrolment := v.Lines[1] == "201" || v.Lines[1] == "409" || v.Lines[1] == "429"
		if want := map[bool]string{false: accesskey.AnswerDomain, true: accesskey.EnrolAnswerDomain}[enrolment]; v.Lines[0] != want {
			t.Errorf("%s: domain line %s, want %s", v.Note, v.Lines[0], want)
		}
		a := accesskey.Answer{Enrolment: enrolment, Status: status, RequestSignature: v.Lines[2], Body: body, Configuration: v.Lines[4], RunConfiguration: v.Lines[5]}
		m := a.Message()
		if string(m) != strings.Join(v.Lines, "\n") || len(m) != v.Length {
			t.Errorf("%s: message of %d bytes:\n%s", v.Note, len(m), m)
		}
		if !pin.VerifyAnswer(a, v.Signature) {
			t.Errorf("%s: does not verify under the pin", v.Note)
		}
		if got := signer.SignAnswer(a); got != v.Signature {
			t.Errorf("%s: signed again %s, want %s", v.Note, got, v.Signature)
		}
		if k.NextSigningKey.pin().VerifyAnswer(a, v.Signature) {
			t.Errorf("%s: verifies under another pin", v.Note)
		}
		for name, changed := range map[string]func(accesskey.Answer) accesskey.Answer{
			"another status":    func(a accesskey.Answer) accesskey.Answer { a.Status = 500; return a },
			"another body":      func(a accesskey.Answer) accesskey.Answer { a.Body = append(bytes.Clone(a.Body), ' '); return a },
			"another digest":    func(a accesskey.Answer) accesskey.Answer { a.Configuration = "sha256=00"; return a },
			"a run digest":      func(a accesskey.Answer) accesskey.Answer { a.RunConfiguration = "sha256=00"; return a },
			"another request":   func(a accesskey.Answer) accesskey.Answer { a.RequestSignature = v.Signature; return a },
			"no request at all": func(a accesskey.Answer) accesskey.Answer { a.RequestSignature = ""; return a },
			"the other domain":  func(a accesskey.Answer) accesskey.Answer { a.Enrolment = !a.Enrolment; return a },
		} {
			if pin.VerifyAnswer(changed(a), v.Signature) {
				t.Errorf("%s: verifies with %s", v.Note, name)
			}
		}
	}
	// A pin lists both keys during a rotation; either verifies.
	both := append(k.NextSigningKey.pin(), pin...)
	a := vectors(t).Answers[0]
	if !both.VerifyAnswer(accesskey.Answer{Status: 200, RequestSignature: a.Lines[2], Body: a.body(t), Configuration: a.Lines[4]}, a.Signature) {
		t.Error("a pin of two keys does not verify an answer under the second")
	}
}

// TestEnrolmentKnownAnswers builds the published enrolment requests from the fixture
// access key, the code, the name and the timestamp, and checks each body and proof;
// then verifies the published answer as qory does, under the key the code's first
// fingerprint selects, and pins only the keys the code carries.
func TestEnrolmentKnownAnswers(t *testing.T) {
	k := keys(t)
	key := k.accessKey(t)
	for _, v := range vectors(t).Enrolment {
		var want accesskey.EnrolmentRequest
		if err := json.Unmarshal(v.body(t), &want); err != nil {
			t.Fatal(err)
		}
		r, err := accesskey.NewEnrolmentRequest(key, v.Lines[1], v.Lines[3], time.Unix(1700000000, 0))
		if err != nil {
			t.Fatal(err)
		}
		m := r.ProofMessage()
		if string(m) != strings.Join(v.Lines, "\n") || len(m) != v.Length {
			t.Errorf("%s: proof message of %d bytes:\n%s", v.Note, len(m), m)
		}
		if *r != want {
			t.Errorf("%s: request\n%+v\nwant\n%+v", v.Note, *r, want)
		}
		if !r.VerifyProof() {
			t.Errorf("%s: the proof does not verify", v.Note)
		}
		changed := *r
		changed.Name = "build-02"
		if changed.VerifyProof() {
			t.Errorf("%s: the proof verifies for another name", v.Note)
		}
	}
	// The answer to the first request.
	r, err := accesskey.NewEnrolmentRequest(key, vectors(t).Enrolment[0].Lines[1], "build-01", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	ans := vectors(t).Answers[2]
	answer := accesskey.Answer{Status: http.StatusCreated, Body: ans.body(t)}
	got, err := r.VerifyAnswer(answer, ans.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessKeyID != "ak_f1xt0re000000000" || got.NodeID != "nd_f1xt0re000000000" || got.NodeKind != "node" || got.StoredSecrets {
		t.Errorf("answer %+v", got)
	}
	if len(got.Pin) != 1 || got.Pin[0].PublicKey != k.SigningKey.PublicKey {
		t.Errorf("pin %+v; want the fixture signing key alone", got.Pin)
	}
	// Signed by another key than the one the code names: refused.
	other := k.NextSigningKey.key(t)
	if _, err := r.VerifyAnswer(answer, other.SignAnswer(accesskey.Answer{Enrolment: true, Status: 201, RequestSignature: r.Proof, Body: answer.Body})); code(err) != accesskey.CodeAnswerUnsigned {
		t.Errorf("an answer signed by a key the code does not name: %v", err)
	}
}

// code returns the code of a refusal, or the error's text.
func code(err error) string {
	var r *accesskey.Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	if err == nil {
		return "nil"
	}
	return err.Error()
}

// TestEnrolmentAnswerPinsOnlyTheCodesKeys pins that, during a rotation, an answer that
// lists two keys is pinned as far as the code carries them: a code with one
// fingerprint pins one key, a code with both pins both.
func TestEnrolmentAnswerPinsOnlyTheCodesKeys(t *testing.T) {
	k := keys(t)
	key := k.accessKey(t)
	signer := k.SigningKey.key(t)
	body := []byte(`{"version":1,"access_key_id":"ak_f1xt0re000000000","node_id":"np_f1xt0re000000000","node_kind":"pool","stored_secrets":true,"apiary_public_key":[{"alg":"ed25519","public_key":"` + k.SigningKey.PublicKey + `"},{"alg":"ed25519","public_key":"` + k.NextSigningKey.PublicKey + `"}]}`)
	for _, c := range []struct {
		code string
		pins int
	}{
		{"qec_F1XT0RE0000000000000000000." + k.SigningKey.Fingerprint, 1},
		{"qec_F1XT0RE0000000000000000000." + k.SigningKey.Fingerprint + "." + k.NextSigningKey.Fingerprint, 2},
	} {
		r, err := accesskey.NewEnrolmentRequest(key, c.code, "build-01", time.Unix(1700000000, 0))
		if err != nil {
			t.Fatal(err)
		}
		a := accesskey.Answer{Enrolment: true, Status: 201, RequestSignature: r.Proof, Body: body}
		got, err := r.VerifyAnswer(a, signer.SignAnswer(a))
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Pin) != c.pins || got.NodeKind != "pool" || !got.StoredSecrets {
			t.Errorf("%s: pinned %d keys, %+v", c.code, len(got.Pin), got)
		}
	}
}

// TestADegenerateProofUnderASmallOrderKeyFails pins that a proof verifies only under a
// key the checks pass. Under the identity point as the public key, R = [S]B makes a
// "proof" that plain Ed25519 verification accepts for any message, though no key made
// it; VerifyProof refuses it, as a server checks the key before it verifies the proof.
func TestADegenerateProofUnderASmallOrderKeyFails(t *testing.T) {
	identity := edwards25519.NewIdentityPoint().Bytes()
	var one [32]byte
	one[0] = 1
	s, err := edwards25519.NewScalar().SetCanonicalBytes(one[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(new(edwards25519.Point).ScalarBaseMult(s).Bytes(), s.Bytes()...)
	r := accesskey.EnrolmentRequest{
		Version:   1,
		Code:      vectors(t).Enrolment[0].Lines[1],
		Name:      "build-01",
		PublicKey: base64.RawURLEncoding.EncodeToString(identity),
		Timestamp: 1700000000,
		Proof:     base64.RawURLEncoding.EncodeToString(sig),
	}
	if !ed25519.Verify(identity, r.ProofMessage(), sig) {
		t.Fatal("plain Ed25519 verification refuses the degenerate proof, " +
			"so the test proves nothing")
	}
	if r.VerifyProof() {
		t.Error("a degenerate proof under the identity point verifies")
	}
}

// TestEnrolmentAnswersHaveTheirOwnDomain pins the domain line that keeps an enrolment
// answer apart from every other answer. Anyone holding a live code chooses the proof
// that is an enrolment answer's third line, so a server's signed 409 key_invalid to a
// proof equal to a node's request signature must not verify as the answer to that
// node's request; and an answer signed under the other answers' domain line with the
// proof as its third line must not verify as an enrolment answer.
func TestEnrolmentAnswersHaveTheirOwnDomain(t *testing.T) {
	k := keys(t)
	signer := k.SigningKey.key(t)
	pin := k.SigningKey.pin()
	r, err := accesskey.NewEnrolmentRequest(k.accessKey(t), vectors(t).Enrolment[0].Lines[1], "build-01", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"error":"key_invalid","apiary_public_key":[{"alg":"ed25519","public_key":"` + k.SigningKey.PublicKey + `"}]}`)
	// Suppose a server signed a refusal to an enrolment whose proof is a node's request
	// signature. The published signature of the GET of discovery serves as that proof.
	nodeRequest := vectors(t).Requests[0].Signature
	enrolment := accesskey.Answer{Enrolment: true, Status: http.StatusConflict, RequestSignature: nodeRequest, Body: body}
	if pin.VerifyAnswer(accesskey.Answer{Status: http.StatusConflict, RequestSignature: nodeRequest, Body: body}, signer.SignAnswer(enrolment)) {
		t.Error("an enrolment answer verifies as the answer to a signed request")
	}
	if !pin.VerifyAnswer(enrolment, signer.SignAnswer(enrolment)) {
		t.Error("an enrolment answer does not verify as one")
	}
	// An answer under the other answers' domain line, its third line the proof.
	plain := accesskey.Answer{Status: http.StatusConflict, RequestSignature: r.Proof, Body: body}
	if _, err := r.VerifyAnswer(plain, signer.SignAnswer(plain)); code(err) != accesskey.CodeAnswerUnsigned {
		t.Errorf("a 409 signed under %s: %v", accesskey.AnswerDomain, err)
	}
	if _, err := r.VerifyAnswer(plain, signer.SignAnswer(accesskey.Answer{Enrolment: true, Status: http.StatusConflict, RequestSignature: r.Proof, Body: body})); code(err) != accesskey.CodeKeyInvalid {
		t.Errorf("a 409 signed under %s: %v", accesskey.EnrolAnswerDomain, err)
	}
	created := accesskey.Answer{Status: http.StatusCreated, RequestSignature: r.Proof, Body: bytes.TrimSpace(read(t, "fixtures/enrolment/answer.json"))}
	if _, err := r.VerifyAnswer(created, signer.SignAnswer(created)); code(err) != accesskey.CodeAnswerUnsigned {
		t.Errorf("a 201 signed under %s: %v", accesskey.AnswerDomain, err)
	}
}

// TestNormaliseCode pins the normalised form of an enrolment code: a code typed in
// lower case or in groups normalises to the published one, I and L read as 1 and O as
// 0, the fingerprints as issued; U, another character, a wrong length and a third
// fingerprint are refused.
func TestNormaliseCode(t *testing.T) {
	const want = "qec_F1XT0RE0000000000000000000.uoES-kuj1vk0sq0qoGlmAg"
	for _, in := range []string{
		want,
		"qec_f1xt0re0000000000000000000.uoES-kuj1vk0sq0qoGlmAg",
		"qec_F1XT-0RE0-0000-0000-0000-0000-00.uoES-kuj1vk0sq0qoGlmAg",
		"QEC_fixtore0000000000000000000.uoES-kuj1vk0sq0qoGlmAg",
		"qec_FLXT0RE000000000000000000o.uoES-kuj1vk0sq0qoGlmAg",
	} {
		got, err := accesskey.NormaliseCode(in)
		if err != nil || got != want {
			t.Errorf("%s: %s, %v; want %s", in, got, err, want)
		}
	}
	for _, in := range []string{
		"qec_F1XT0RE000000000000000000U.uoES-kuj1vk0sq0qoGlmAg",
		"qec_F1XT0RE00000000000000000*0.uoES-kuj1vk0sq0qoGlmAg",
		"qec_F1XT0RE000000000000000000.uoES-kuj1vk0sq0qoGlmAg",
		"qec_F1XT0RE0000000000000000000",
		"qec_F1XT0RE0000000000000000000.uoES-kuj1vk0sq0qoGlmAg.52vzzF--Ic7qH_eZWi5K2A.52vzzF--Ic7qH_eZWi5K2A",
		"qec_F1XT0RE0000000000000000000.uoES+kuj1vk0sq0qoGlmAg",
		"qak_F1XT0RE0000000000000000000.uoES-kuj1vk0sq0qoGlmAg",
	} {
		if got, err := accesskey.NormaliseCode(in); err == nil {
			t.Errorf("%s: accepted as %s", in, got)
		}
	}
	two := "qec_F1XT0RE0000000000000000000.uoES-kuj1vk0sq0qoGlmAg.52vzzF--Ic7qH_eZWi5K2A"
	if got := accesskey.CodeFingerprints(two); len(got) != 2 || got[1] != "52vzzF--Ic7qH_eZWi5K2A" {
		t.Errorf("fingerprints %v", got)
	}
}

// TestPinCheckCode pins that a machine with a pin refuses a code whose fingerprints
// name none of its keys, and that a machine without one accepts every code.
func TestPinCheckCode(t *testing.T) {
	k := keys(t)
	code := "qec_F1XT0RE0000000000000000000." + k.SigningKey.Fingerprint
	if err := k.SigningKey.pin().CheckCode(code); err != nil {
		t.Error(err)
	}
	if err := (accesskey.Pin{}).CheckCode(code); err != nil {
		t.Error(err)
	}
	if err := k.NextSigningKey.pin().CheckCode(code); err == nil {
		t.Error("a code for another server's key is accepted")
	}
}

// TestKeyChecks pins the five checks of a public key against the published list: the
// eight points of small order and the six non-canonical encodings are refused, the
// torsion key is refused as not of prime order, and the fixture access key passes, as
// do generated keys. A pin with any refused key is refused.
func TestKeyChecks(t *testing.T) {
	var list struct {
		SmallOrder   []struct{ Encoding string } `json:"small_order"`
		NonCanonical []struct{ Encoding string } `json:"non_canonical"`
		Torsion      struct{ Encoding string }   `json:"torsion"`
	}
	load(t, "fixtures/known-answers/small-order.json", &list)
	check := func(enc string) error {
		p, err := accesskey.ParsePublicKey(enc)
		if err != nil {
			t.Fatalf("%s: %v", enc, err)
		}
		return p.Check()
	}
	refused := func(enc, why string) {
		err := check(enc)
		if !errors.Is(err, accesskey.ErrKeyInvalid) || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: %v; want refused as %s", enc, err, why)
		}
		if _, err := accesskey.ParsePin([]byte(`[{"alg":"ed25519","public_key":"` + enc + `"}]`)); err == nil {
			t.Errorf("%s: accepted in a pin", enc)
		}
	}
	for _, p := range list.SmallOrder {
		refused(p.Encoding, "small order")
	}
	for _, p := range list.NonCanonical {
		refused(p.Encoding, "not canonical")
	}
	refused(list.Torsion.Encoding, "prime order")
	if err := check(keys(t).AccessKey.PublicKey); err != nil {
		t.Errorf("the fixture access key: %v", err)
	}
	if len(list.SmallOrder) != 8 || len(list.NonCanonical) != 6 {
		t.Errorf("%d small-order and %d non-canonical encodings; want 8 and 6", len(list.SmallOrder), len(list.NonCanonical))
	}
	if _, err := (accesskey.PublicKey{1}).X25519(); err == nil {
		t.Error("the identity converts to an X25519 key")
	}
}

// TestParsePin pins the pin's JSON form, the one QORY_APIARY_PUBLIC_KEY contains.
func TestParsePin(t *testing.T) {
	k := keys(t)
	good := `[{"alg":"ed25519","public_key":"` + k.SigningKey.PublicKey + `"}]`
	if p, err := accesskey.ParsePin([]byte(good)); err != nil || len(p) != 1 {
		t.Errorf("%s: %v", good, err)
	}
	for _, bad := range []string{
		`[]`,
		`{}`,
		`[{"alg":"rsa","public_key":"` + k.SigningKey.PublicKey + `"}]`,
		`[{"alg":"ed25519","public_key":"` + k.SigningKey.PublicKey + `","extra":1}]`,
		`[{"alg":"ed25519","public_key":"` + k.SigningKey.PublicKey + `","public_key":"` + k.NextSigningKey.PublicKey + `"}]`,
		`[{"alg":"ed25519","public_key":"` + k.SigningKey.PublicKey + `"},{"alg":"ed25519","public_key":"` + k.SigningKey.PublicKey + `"}]`,
		`[{"alg":"ed25519","public_key":"` + k.SigningKey.PublicKey + `="}]`,
	} {
		if _, err := accesskey.ParsePin([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

// TestInstanceID pins the instance id and its file: a new id is i_ and 24 characters
// and passes the pattern; the file is the id and the keyed hash of the machine's
// identity; a file read on the same machine yields its id, and one copied to another
// machine, or holding an id outside the pattern, yields none.
func TestInstanceID(t *testing.T) {
	id, err := accesskey.NewInstanceID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 24 || !strings.HasPrefix(id, "i_") || accesskey.CheckInstanceID(id) != nil {
		t.Errorf("instance id %q", id)
	}
	if again, _ := accesskey.NewInstanceID(); again == id {
		t.Error("two instance ids are the same")
	}
	machine := []byte("0123456789abcdef0123456789abcdef\n")
	file := accesskey.InstanceFile(id, machine)
	if got, ok := accesskey.ReadInstanceFile(file, machine); !ok || got != id {
		t.Errorf("read back %q, %v", got, ok)
	}
	if _, ok := accesskey.ReadInstanceFile(file, []byte("fedcba9876543210fedcba9876543210")); ok {
		t.Error("a file copied to another machine yields its id")
	}
	if _, ok := accesskey.ReadInstanceFile(accesskey.InstanceFile("-bad", machine), machine); ok {
		t.Error("an id outside the pattern is read")
	}
	if _, ok := accesskey.ReadInstanceFile([]byte(id+"\n"), machine); ok {
		t.Error("a file without the hash is read")
	}
	mac := accesskey.MachineHash(machine)
	if len(mac) != 64 || mac != accesskey.MachineHash([]byte("0123456789abcdef0123456789abcdef")) {
		t.Errorf("the machine's hash %q depends on the trailing line feed", mac)
	}
	sum := sha256.Sum256(machine)
	if mac == hex.EncodeToString(sum[:]) {
		t.Error("the machine's hash is not keyed")
	}
	for _, bad := range []string{"", "-x", ".x", "x y", strings.Repeat("a", 65), "é"} {
		if accesskey.CheckInstanceID(bad) == nil {
			t.Errorf("instance id %q accepted", bad)
		}
	}
	if got := accesskey.DefaultName("build-01.ci.example"); got != "build-01.ci.example" {
		t.Errorf("DefaultName = %q", got)
	}
	if got := accesskey.DefaultName("build_01!.ci.example"); got != "" {
		t.Errorf("DefaultName of a name that fits nowhere = %q", got)
	}
	if got := accesskey.DefaultName(strings.Repeat("a", 60) + ".example.internal"); got != strings.Repeat("a", 60) {
		t.Errorf("DefaultName of a long host = %q", got)
	}
}

// TestPostEnrols posts an enrolment to a fake server signing under the fixture
// signing key: a 201 verifies and pins; a 401 is unauthorized; a signed 409, key_limit
// or key_invalid, and a signed 429, rate_limited, is its code, verified under the key
// its body lists, and one that lists no key is answer_unsigned; a signed 409 or 429
// with another status's code is an error; a signed 201 the schema refuses is an error;
// an unsigned answer, a 429 included, is answer_unsigned with its status.
func TestPostEnrols(t *testing.T) {
	k := keys(t)
	signer := k.SigningKey.key(t)
	status, body := http.StatusCreated, bytes.TrimSpace(read(t, "fixtures/enrolment/answer.json"))
	sign := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != accesskey.EnrolmentPath || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("X-Qory-Contract-Version") != "1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		b, _ := io.ReadAll(r.Body)
		var req accesskey.EnrolmentRequest
		if json.Unmarshal(b, &req) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// A key the checks refuse or a proof that does not verify under it: unsigned.
		if !req.VerifyProof() {
			w.WriteHeader(http.StatusConflict)
			io.WriteString(w, `{"error":"key_invalid"}`)
			return
		}
		if sign && status != http.StatusUnauthorized {
			w.Header().Set(accesskey.HeaderSignature, signer.SignAnswer(accesskey.Answer{Enrolment: true, Status: status, RequestSignature: req.Proof, Body: body}))
		}
		w.WriteHeader(status)
		w.Write(body)
	}))
	defer srv.Close()
	key, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	r, err := accesskey.NewEnrolmentRequest(key, "qec_F1XT0RE0000000000000000000."+k.SigningKey.Fingerprint, "build-01", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	got, err := r.Post(ctx, nil, srv.URL, "qory/test")
	if err != nil || got.AccessKeyID != "ak_f1xt0re000000000" || len(got.Pin) != 1 {
		t.Fatalf("201: %+v, %v", got, err)
	}
	status, body = http.StatusUnauthorized, []byte(`{"error":"unauthorized"}`)
	if _, err := r.Post(ctx, nil, srv.URL, "qory/test"); code(err) != accesskey.CodeUnauthorized {
		t.Errorf("401: %v", err)
	}
	keys := `"apiary_public_key":[{"alg":"ed25519","public_key":"` + k.SigningKey.PublicKey + `"}]`
	status, body = http.StatusConflict, []byte(`{"error":"key_limit",`+keys+`}`)
	if _, err := r.Post(ctx, nil, srv.URL, "qory/test"); code(err) != accesskey.CodeKeyLimit {
		t.Errorf("signed 409 key_limit: %v", err)
	}
	body = []byte(`{"error":"key_invalid",` + keys + `}`)
	if _, err := r.Post(ctx, nil, srv.URL, "qory/test"); code(err) != accesskey.CodeKeyInvalid {
		t.Errorf("signed 409 key_invalid: %v", err)
	}
	body = []byte(`{"error":"key_limit"}`)
	if _, err := r.Post(ctx, nil, srv.URL, "qory/test"); code(err) != accesskey.CodeAnswerUnsigned {
		t.Errorf("a signed 409 that lists no key: %v", err)
	}
	status, body = http.StatusTooManyRequests, []byte(`{"error":"rate_limited",`+keys+`}`)
	var limited *accesskey.Refusal
	_, err = r.Post(ctx, nil, srv.URL, "qory/test")
	if !errors.As(err, &limited) || limited.Code != accesskey.CodeRateLimited ||
		limited.Status != http.StatusTooManyRequests {
		t.Errorf("signed 429 rate_limited: %v", err)
	}
	body = []byte(`{"error":"rate_limited"}`)
	_, err = r.Post(ctx, nil, srv.URL, "qory/test")
	if code(err) != accesskey.CodeAnswerUnsigned {
		t.Errorf("a signed 429 that lists no key: %v", err)
	}
	// A signed refusal whose code its status does not carry is an error, no refusal.
	for s, b := range map[int]string{
		http.StatusTooManyRequests: `{"error":"key_limit",` + keys + `}`,
		http.StatusConflict:        `{"error":"rate_limited",` + keys + `}`,
	} {
		status, body = s, []byte(b)
		var ref *accesskey.Refusal
		_, err := r.Post(ctx, nil, srv.URL, "qory/test")
		if err == nil || errors.As(err, &ref) {
			t.Errorf("a signed %d %s: %v", s, b, err)
		}
	}
	status = http.StatusConflict
	// The server refuses a key the checks refuse or a proof that does not verify under
	// it with an unsigned 409 key_invalid, before it signs anything: answer_unsigned,
	// with its status.
	sign = false
	for _, b := range []string{`{"error":"key_invalid"}`, `{"error":"key_invalid",` + keys + `}`} {
		body = []byte(b)
		var ref *accesskey.Refusal
		if _, err := r.Post(ctx, nil, srv.URL, "qory/test"); !errors.As(err, &ref) || ref.Code != accesskey.CodeAnswerUnsigned || ref.Status != http.StatusConflict {
			t.Errorf("an unsigned 409 %s: %v", b, err)
		}
	}
	// A 429 per source address goes out unsigned: answer_unsigned, with its status.
	status = http.StatusTooManyRequests
	limit := `{"error":"rate_limited"`
	for _, b := range []string{limit + `}`, limit + `,` + keys + `}`} {
		body = []byte(b)
		var ref *accesskey.Refusal
		_, err := r.Post(ctx, nil, srv.URL, "qory/test")
		if !errors.As(err, &ref) || ref.Code != accesskey.CodeAnswerUnsigned ||
			ref.Status != http.StatusTooManyRequests {
			t.Errorf("an unsigned 429 %s: %v", b, err)
		}
	}
	sign = true
	status = http.StatusCreated
	for name, b := range map[string]string{
		"a node_kind against its id": `{"version":1,"access_key_id":"ak_f1xt0re000000000","node_id":"nd_f1xt0re000000000","node_kind":"pool","stored_secrets":false,"apiary_public_key":[{"alg":"ed25519","public_key":"` + k.SigningKey.PublicKey + `"}]}`,
		"three keys":                 `{"version":1,"access_key_id":"ak_f1xt0re000000000","node_id":"nd_f1xt0re000000000","node_kind":"node","stored_secrets":false,"apiary_public_key":[{"alg":"ed25519","public_key":"` + k.SigningKey.PublicKey + `"},{"alg":"ed25519","public_key":"` + k.NextSigningKey.PublicKey + `"},{"alg":"ed25519","public_key":"` + k.AccessKey.PublicKey + `"}]}`,
		"an unknown member":          `{"version":1,"access_key_id":"ak_f1xt0re000000000","node_id":"nd_f1xt0re000000000","node_kind":"node","stored_secrets":false,"extra":1,"apiary_public_key":[{"alg":"ed25519","public_key":"` + k.SigningKey.PublicKey + `"}]}`,
	} {
		body = []byte(b)
		if got, err := r.Post(ctx, nil, srv.URL, "qory/test"); err == nil {
			t.Errorf("a 201 with %s: accepted as %+v", name, got)
		}
	}
	sign = false
	status, body = http.StatusCreated, bytes.TrimSpace(read(t, "fixtures/enrolment/answer.json"))
	if _, err := r.Post(ctx, nil, srv.URL, "qory/test"); code(err) != accesskey.CodeAnswerUnsigned {
		t.Errorf("unsigned 201: %v", err)
	}
	if _, err := r.Post(ctx, nil, "http://qory.example", "qory/test"); err == nil {
		t.Error("plain http to another host than loopback is accepted")
	}
}

// TestErrorsNeverQuoteASecret pins that a secret pasted where another value belongs,
// a public key, an access key id, an instance id, a name, a pin or a server URL, is
// named in the error and never quoted.
func TestErrorsNeverQuoteASecret(t *testing.T) {
	secret := keys(t).AccessKey.Secret
	_, e1 := accesskey.ParsePublicKey(secret)
	_, e2 := accesskey.ParsePin([]byte(`[{"alg":"ed25519","public_key":"` + secret + `"}]`))
	_, e3 := accesskey.NormaliseCode("qec_F1XT0RE0000000000000000000." + secret)
	r, _ := accesskey.NewEnrolmentRequest(keys(t).accessKey(t), "qec_F1XT0RE0000000000000000000."+keys(t).SigningKey.Fingerprint, "build-01", time.Now())
	_, e4 := r.Post(context.Background(), nil, "https://"+secret, "test")
	for i, err := range []error{e1, e2, e3, e4, accesskey.CheckID(secret), accesskey.CheckInstanceID(secret), accesskey.CheckName(secret), accesskey.CheckNodeID(strings.ToUpper(secret))} {
		if err == nil || strings.Contains(err.Error(), secret[4:]) || strings.Contains(strings.ToLower(err.Error()), strings.ToLower(secret[4:])) {
			t.Errorf("%d: %v", i, err)
		}
	}
}

// TestRefusedKeysVerifyNothing pins that a key the key checks refuse verifies no
// signature, as a key and in a pin: the forged signature R = identity, S = 0, which
// crypto/ed25519 accepts under the identity key for any message, and the same
// signature under every other refused key, fail. A pin of such keys verifies nothing.
func TestRefusedKeysVerifyNothing(t *testing.T) {
	var list struct {
		SmallOrder   []struct{ Encoding string } `json:"small_order"`
		NonCanonical []struct{ Encoding string } `json:"non_canonical"`
		Torsion      struct{ Encoding string }   `json:"torsion"`
	}
	load(t, "fixtures/known-answers/small-order.json", &list)
	forged := make([]byte, 64)
	forged[0] = 1
	identity, _ := accesskey.ParsePublicKey(list.SmallOrder[0].Encoding)
	if !ed25519.Verify(identity[:], []byte("any message"), forged) {
		t.Fatal("crypto/ed25519 refuses the forged signature under the identity key; the test proves nothing")
	}
	encodings := []string{list.Torsion.Encoding}
	for _, p := range list.SmallOrder {
		encodings = append(encodings, p.Encoding)
	}
	for _, p := range list.NonCanonical {
		encodings = append(encodings, p.Encoding)
	}
	for _, enc := range encodings {
		pub, err := accesskey.ParsePublicKey(enc)
		if err != nil {
			t.Fatal(err)
		}
		pin := accesskey.Pin{{Alg: "ed25519", PublicKey: enc}}
		for _, m := range []string{"any message", "another", ""} {
			if pub.Verify([]byte(m), forged) || pin.Verify([]byte(m), base64.RawURLEncoding.EncodeToString(forged)) {
				t.Errorf("%s verifies a forged signature over %q", enc, m)
			}
		}
		if pub.VerifyRequest(accesskey.Request{AccessKeyID: "ak_f1xt0re000000000", Method: "GET", Target: "/", Timestamp: "1"}, base64.RawURLEncoding.EncodeToString(forged)) {
			t.Errorf("%s verifies a forged request", enc)
		}
		if len(pin.Keys()) != 0 {
			t.Errorf("%s is among a pin's keys", enc)
		}
	}
}

// TestEnrolmentRefusalKnownAnswers verifies the published signed refusals as a machine
// without a pin does: each 409, key_limit and key_invalid, with one key and during a
// rotation with two, and the 429 rate_limited, is its code with its status, verified
// under the key its code's first fingerprint names; the same refusal tampered, signed by
// the next key, bound to another proof, or listing only a key the code does not name,
// is answer_unsigned.
func TestEnrolmentRefusalKnownAnswers(t *testing.T) {
	k := keys(t)
	key := k.accessKey(t)
	one, err := accesskey.NewEnrolmentRequest(key, vectors(t).Enrolment[0].Lines[1], "build-01", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	two, err := accesskey.NewEnrolmentRequest(key, vectors(t).Enrolment[1].Lines[1], "build-01", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, v := range vectors(t).Answers {
		if v.Lines[1] != "409" && v.Lines[1] != "429" {
			continue
		}
		n++
		r := one
		if strings.HasSuffix(v.Body, "-rotation.json") {
			r = two
		}
		body := v.body(t)
		var status int
		fmt.Sscanf(v.Lines[1], "%d", &status)
		a := accesskey.Answer{Status: status, Body: body}
		var want struct {
			Error string `json:"error"`
		}
		json.Unmarshal(body, &want)
		var ref *accesskey.Refusal
		_, err := r.VerifyAnswer(a, v.Signature)
		if !errors.As(err, &ref) || ref.Code != want.Error || ref.Status != status {
			t.Errorf("%s: %v", v.Note, err)
		}
		tampered := a
		tampered.Body = bytes.Replace(body, []byte(want.Error), []byte("key_limit"), 1)
		if want.Error == "key_limit" {
			tampered.Body = bytes.Replace(body, []byte("key_limit"), []byte("key_invalid"), 1)
		}
		other := two
		if r == two {
			other = one
		}
		next := k.NextSigningKey.key(t)
		for name, check := range map[string]func() error{
			"tampered":      func() error { _, err := r.VerifyAnswer(tampered, v.Signature); return err },
			"another proof": func() error { _, err := other.VerifyAnswer(a, v.Signature); return err },
			"signed by the next": func() error {
				signed := accesskey.Answer{Enrolment: true, Status: status,
					RequestSignature: r.Proof, Body: body}
				_, err := r.VerifyAnswer(a, next.SignAnswer(signed))
				return err
			},
			"another key listed": func() error {
				b := []byte(`{"error":"key_limit","apiary_public_key":[{"alg":"ed25519","public_key":"` + k.NextSigningKey.PublicKey + `"}]}`)
				_, err := one.VerifyAnswer(accesskey.Answer{Status: 409, Body: b}, next.SignAnswer(accesskey.Answer{Enrolment: true, Status: 409, RequestSignature: one.Proof, Body: b}))
				return err
			},
		} {
			if code(check()) != accesskey.CodeAnswerUnsigned {
				t.Errorf("%s, %s: %v", v.Note, name, check())
			}
		}
	}
	if n != 5 {
		t.Errorf("%d signed refusals; want 5", n)
	}
}

// TestOnlyAGETOrAPOSTIsSigned pins that a request of another method has no request
// string: it is not signed, and no signature verifies for it.
func TestOnlyAGETOrAPOSTIsSigned(t *testing.T) {
	key := keys(t).accessKey(t)
	for _, method := range []string{"PUT", "DELETE", "HEAD", "", "get"} {
		r := accesskey.Request{AccessKeyID: "ak_f1xt0re000000000", InstanceID: "i_x", Method: method, Target: "/"}
		sig, err := key.SignRequest(r)
		if method == "get" {
			if err != nil {
				t.Errorf("a GET in lower case: %v", err)
			}
			continue
		}
		if !errors.Is(err, accesskey.ErrMethod) || sig != "" {
			t.Errorf("%q: %q, %v", method, sig, err)
		}
		get, _ := key.SignRequest(accesskey.Request{AccessKeyID: "ak_f1xt0re000000000", InstanceID: "i_x", Method: "GET", Target: "/"})
		if key.PublicKey().VerifyRequest(r, get) {
			t.Errorf("%q verifies", method)
		}
	}
	for _, origin := range []string{"http://localhost:8787", "http://127.0.0.1:8787", "http://[::1]:8787"} {
		r, _ := accesskey.NewEnrolmentRequest(key, "qec_F1XT0RE0000000000000000000."+keys(t).SigningKey.Fingerprint, "build-01", time.Now())
		if _, err := r.Post(context.Background(), nil, origin, "test"); err != nil && strings.Contains(err.Error(), "neither https") {
			t.Errorf("%s is refused as an origin", origin)
		}
	}
	r, _ := accesskey.NewEnrolmentRequest(key, "qec_F1XT0RE0000000000000000000."+keys(t).SigningKey.Fingerprint, "build-01", time.Now())
	if _, err := r.Post(context.Background(), nil, "http://127.0.0.2:8787", "test"); err == nil || !strings.Contains(err.Error(), "neither https") {
		t.Errorf("http to 127.0.0.2, which server.schema.json refuses: %v", err)
	}
}
