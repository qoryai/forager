package sealed

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
)

// errs are the refusals of the package; each error Open returns wraps one of them.
var errs = []error{ErrRequest, ErrAnswer, ErrSuite, ErrSignature, ErrAccessKey, ErrRun, ErrDigest, ErrExpired,
	ErrAhead, ErrOpen, ErrPlaintext, ErrCredentials, ErrNotRequested, ErrMissing, ErrTwice, ErrValue}

// fixture is the contract's sealed fixture: the fixture access key, the pin of the
// fixture signing key, the signer, the request, the answer, its plaintext and vectors.
type fixture struct {
	key       AccessKey
	pin       accesskey.Pin
	signer    *accesskey.Key
	runID     string
	digest    string
	requested []string
	answer    []byte
	plaintext []byte
	now       time.Time
	ephemeral []byte
	info, aad string
	cases     []struct {
		File, Refused, Plaintext string
	}
}

func read(t testing.TB, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(contracts.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func load(t testing.TB) fixture {
	t.Helper()
	var keys struct {
		AccessKey struct {
			Secret      string `json:"secret"`
			AccessKeyID string `json:"access_key_id"`
		} `json:"access_key"`
		SigningKey struct {
			Seed      string `json:"seed"`
			PublicKey string `json:"public_key"`
		} `json:"signing_key"`
	}
	var request struct {
		RunID            string   `json:"run_id"`
		RunConfiguration string   `json:"run_configuration"`
		Credentials      []string `json:"credentials"`
	}
	var vectors struct {
		Now       int64  `json:"now"`
		Ephemeral string `json:"ephemeral_private_key"`
		Info      string `json:"info"`
		AAD       string `json:"aad"`
		Invalid   []struct {
			File      string `json:"file"`
			Refused   string `json:"refused"`
			Plaintext string `json:"plaintext"`
		} `json:"invalid"`
	}
	for name, v := range map[string]any{"fixtures/known-answers/keys.json": &keys, "fixtures/sealed/secrets-request.json": &request, "fixtures/sealed/vectors.json": &vectors} {
		if err := json.Unmarshal(read(t, name), v); err != nil {
			t.Fatal(name, err)
		}
	}
	key, err := accesskey.ParseSecret(keys.AccessKey.Secret)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base64.RawURLEncoding.DecodeString(keys.SigningKey.Seed)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := accesskey.NewKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := base64.RawURLEncoding.DecodeString(vectors.Ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{
		key: AccessKey{ID: keys.AccessKey.AccessKeyID, Key: key}, pin: accesskey.Pin{{Alg: "ed25519", PublicKey: keys.SigningKey.PublicKey}},
		signer: signer, runID: request.RunID, digest: request.RunConfiguration, requested: request.Credentials,
		answer: read(t, "fixtures/sealed/secrets-answer.json"), plaintext: read(t, "fixtures/sealed/sealed-plaintext.json"),
		now: time.Unix(vectors.Now, 0), ephemeral: ephemeral, info: vectors.Info, aad: vectors.AAD,
	}
	for _, c := range vectors.Invalid {
		f.cases = append(f.cases, struct{ File, Refused, Plaintext string }{c.File, c.Refused, c.Plaintext})
	}
	return f
}

// values are the values of a plaintext, decoded with the standard library, by
// credential.
func values(t testing.TB, pt []byte) map[string]string {
	t.Helper()
	var d struct {
		Values []struct{ Credential, Value string } `json:"values"`
	}
	if err := json.Unmarshal(pt, &d); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, v := range d.Values {
		out[v.Credential] = v.Value
	}
	return out
}

// fixedSender is RFC 9180's base mode written out, with the fixture's fixed ephemeral
// key, so a sealing is compared byte for byte with the published answer.
func fixedSender(t testing.TB, ephemeral []byte) sender {
	return func(pkR, info, aad, pt []byte) ([]byte, []byte, error) {
		skE, err := ecdh.X25519().NewPrivateKey(ephemeral)
		if err != nil {
			return nil, nil, err
		}
		pub, err := ecdh.X25519().NewPublicKey(pkR)
		if err != nil {
			return nil, nil, err
		}
		dh, err := skE.ECDH(pub)
		if err != nil {
			return nil, nil, err
		}
		enc := skE.PublicKey().Bytes()
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
		kem := slices.Concat([]byte("KEM"), u16(KEMID))
		shared := expand(kem, extract(kem, nil, "eae_prk", dh), "shared_secret", slices.Concat(enc, pkR), 32)
		suiteID := slices.Concat([]byte("HPKE"), u16(KEMID), u16(KDFID), u16(AEADID))
		ctx := slices.Concat([]byte{0}, extract(suiteID, nil, "psk_id_hash", nil), extract(suiteID, nil, "info_hash", info))
		secret := extract(suiteID, shared, "secret", nil)
		block, err := aes.NewCipher(expand(suiteID, secret, "key", ctx, 32))
		if err != nil {
			return nil, nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, nil, err
		}
		return enc, gcm.Seal(nil, expand(suiteID, secret, "base_nonce", ctx, 12), pt, aad), nil
	}
}

// only reports whether err wraps want and no other refusal of the package.
func only(err, want error) bool {
	for _, e := range errs {
		if errors.Is(err, e) != (e == want) {
			return false
		}
	}
	return true
}

// TestTheFixtureOpens pins that the published answer opens to the published
// plaintext's values, and that info and aad are the vectors' bytes.
func TestTheFixtureOpens(t *testing.T) {
	f := load(t)
	if got := hex.EncodeToString(Info(f.key.ID)); got != f.info {
		t.Errorf("info %s; want %s", got, f.info)
	}
	if got := hex.EncodeToString(AAD(f.runID, f.key.ID, f.digest, 1700000600)); got != f.aad {
		t.Errorf("aad %s; want %s", got, f.aad)
	}
	v, err := Open(f.answer, f.key, f.pin, f.runID, f.digest, f.requested, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Clear()
	want := values(t, f.plaintext)
	if v.Len() != len(want) || !slices.Equal(v.Credentials(), []string{"forge", "model"}) {
		t.Fatalf("opened %d values for %v", v.Len(), v.Credentials())
	}
	for name, value := range want {
		if b, ok := v.Value(name); !ok || string(b) != value {
			t.Errorf("the value of %s is not the plaintext's", name)
		}
	}
}

// TestSealIsTheFixture pins that Seal, with the fixture's fixed ephemeral key and the
// fixture signing key, writes the published answer, compacted, byte for byte, and that
// its plaintext is the published plaintext.
func TestSealIsTheFixture(t *testing.T) {
	f := load(t)
	s := Sealing{AccessKeyID: f.key.ID, PublicKey: f.key.Key.PublicKey(), RunID: f.runID, RunConfiguration: f.digest,
		Credentials: f.requested, Exp: Expiry(f.now)}
	for name, value := range values(t, f.plaintext) {
		s.Values = append(s.Values, Value{Credential: name, Value: []byte(value)})
	}
	pt, err := s.Plaintext()
	if err != nil || !bytes.Equal(pt, f.plaintext) {
		t.Fatalf("plaintext %s, %v; want the fixture's", pt, err)
	}
	got, err := seal(s, f.signer, fixedSender(t, f.ephemeral))
	if err != nil {
		t.Fatal(err)
	}
	want := jsontext.Value(bytes.Clone(f.answer))
	if err := want.Compact(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("sealed\n%s\nwant\n%s", got, want)
	}
}

// TestTheInvalidVectorsAreRefused pins that each refused envelope of the fixture is
// refused at its step, with its error alone, and with no value in the error. A wrong
// aad and a wrong info are both ErrOpen: the open fails the same way for either.
func TestTheInvalidVectorsAreRefused(t *testing.T) {
	f := load(t)
	steps := map[string]error{"open": ErrOpen, "signature": ErrSignature, "expired": ErrExpired, "ahead": ErrAhead,
		"run_configuration": ErrDigest, "run_id": ErrRun, "suite": ErrSuite, "values": ErrNotRequested}
	seen := map[string]bool{}
	for _, c := range f.cases {
		want := steps[c.Refused]
		if want == nil {
			t.Fatalf("%s: the step %s has no error", c.File, c.Refused)
		}
		seen[c.Refused] = true
		v, err := Open(read(t, c.File), f.key, f.pin, f.runID, f.digest, f.requested, f.now)
		if v.Len() != 0 || !only(err, want) {
			t.Errorf("%s: %d values, %v; want %v alone", c.File, v.Len(), err, want)
		}
		for _, value := range values(t, read(t, c.Plaintext)) {
			if err != nil && strings.Contains(err.Error(), value) {
				t.Errorf("%s: the error contains a value: %v", c.File, err)
			}
		}
	}
	if len(seen) != len(steps) {
		t.Errorf("the vectors cover %v; want every step of %v", seen, steps)
	}
	for _, name := range []string{"secrets-answer-ct-length.json", "secrets-answer-ct-short.json"} {
		if _, err := Open(read(t, "fixtures/invalid/"+name), f.key, f.pin, f.runID, f.digest, f.requested, f.now); !only(err, ErrAnswer) {
			t.Errorf("%s: %v; want ErrAnswer", name, err)
		}
	}
}

// member returns the answer with one member of sealed set to raw JSON, or removed
// when raw is empty.
func member(t *testing.T, answer []byte, name, raw string) []byte {
	t.Helper()
	var d struct {
		Version jsontext.Value            `json:"version"`
		Sealed  map[string]jsontext.Value `json:"sealed"`
	}
	if err := jsonv2.Unmarshal(answer, &d); err != nil {
		t.Fatal(err)
	}
	if raw == "" {
		delete(d.Sealed, name)
	} else {
		d.Sealed[name] = jsontext.Value(raw)
	}
	b, err := jsonv2.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestOpenRefusesAnAnswerOutsideItsForm pins ErrAnswer for an answer read strictly: a
// member twice, a member the schema does not define, an exp with a fraction, an
// exponent or a sign, a binary value padded, in the standard alphabet or with non-zero
// trailing bits, an enc of 31 bytes, a missing member, trailing data, and more than
// 5 MiB; and ErrRequest for a call outside its forms, before the answer is read.
func TestOpenRefusesAnAnswerOutsideItsForm(t *testing.T) {
	f := load(t)
	var e struct {
		Sealed struct{ Enc, CT, Sig string } `json:"sealed"`
	}
	if err := json.Unmarshal(f.answer, &e); err != nil {
		t.Fatal(err)
	}
	enc := e.Sealed.Enc
	// enc is 32 bytes in 43 characters, whose last two bits are zero: setting the
	// lowest bit of the last character's 6 makes them non-zero.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	trailing := enc[:len(enc)-1] + string(alphabet[strings.IndexByte(alphabet, enc[len(enc)-1])|1])
	standard, which := "", ""
	for _, m := range []struct{ name, v string }{{"ct", e.Sealed.CT}, {"sig", e.Sealed.Sig}, {"enc", enc}} {
		if strings.ContainsAny(m.v, "-_") {
			standard, which = strings.NewReplacer("-", "+", "_", "/").Replace(m.v), m.name
			break
		}
	}
	if which == "" {
		t.Fatal("no binary member of the fixture contains - or _")
	}
	for name, answer := range map[string][]byte{
		"a member twice":        bytes.Replace(f.answer, []byte(`"version": 1,`), []byte(`"version": 1, "version": 1,`), 1),
		"an unknown member":     member(t, f.answer, "labels", `{}`),
		"exp 1700000600.0":      member(t, f.answer, "exp", `1700000600.0`),
		"exp 17000006e2":        member(t, f.answer, "exp", `17000006e2`),
		"exp -1":                member(t, f.answer, "exp", `-1`),
		"enc padded":            member(t, f.answer, "enc", `"`+enc+`="`),
		"the standard alphabet": member(t, f.answer, which, `"`+standard+`"`),
		"enc trailing bits":     member(t, f.answer, "enc", `"`+trailing+`"`),
		"enc of 31 bytes":       member(t, f.answer, "enc", `"`+base64.RawURLEncoding.EncodeToString(make([]byte, 31))+`"`),
		"no sig":                member(t, f.answer, "sig", ""),
		"trailing data":         append(bytes.Clone(f.answer), '{', '}'),
		"more than 5 MiB":       append(bytes.Clone(f.answer), bytes.Repeat([]byte(" "), MaxAnswer)...),
		"not JSON":              []byte("not JSON"),
		"version 2":             bytes.Replace(f.answer, []byte(`"version": 1`), []byte(`"version": 2`), 1),
		"suite missing":         member(t, f.answer, "suite", ""),
		"access key id upper":   member(t, f.answer, "access_key_id", `"AK_F1XT0RE000000000"`),
		"run_configuration md":  member(t, f.answer, "run_configuration", `"md5=0"`),
	} {
		if _, err := Open(answer, f.key, f.pin, f.runID, f.digest, f.requested, f.now); !only(err, ErrAnswer) {
			t.Errorf("%s: %v; want ErrAnswer", name, err)
		}
	}
	for name, call := range map[string]func() error{
		"no key": func() error {
			_, err := Open(f.answer, AccessKey{ID: f.key.ID}, f.pin, f.runID, f.digest, f.requested, f.now)
			return err
		},
		"an id outside the form": func() error {
			_, err := Open(f.answer, AccessKey{ID: "ak_x", Key: f.key.Key}, f.pin, f.runID, f.digest, f.requested, f.now)
			return err
		},
		"a run id outside": func() error { _, err := Open(f.answer, f.key, f.pin, "run", f.digest, f.requested, f.now); return err },
		"a digest outside": func() error {
			_, err := Open(f.answer, f.key, f.pin, f.runID, "sha256=", f.requested, f.now)
			return err
		},
		"no credential": func() error { _, err := Open(f.answer, f.key, f.pin, f.runID, f.digest, nil, f.now); return err },
		"a credential twice": func() error {
			_, err := Open(f.answer, f.key, f.pin, f.runID, f.digest, []string{"model", "model"}, f.now)
			return err
		},
		"nine credentials": func() error {
			_, err := Open(f.answer, f.key, f.pin, f.runID, f.digest, []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}, f.now)
			return err
		},
	} {
		if err := call(); !only(err, ErrRequest) {
			t.Errorf("%s: %v; want ErrRequest", name, err)
		}
	}
}

// TestOpenChecksTheEnvelopeAgainstTheCall pins the checks of an envelope that verifies:
// another access key, run and digest each with its error, a pin of another key
// ErrSignature, and the window of exp, open at 300 seconds past and 900 ahead and
// refused one second beyond each.
func TestOpenChecksTheEnvelopeAgainstTheCall(t *testing.T) {
	f := load(t)
	other, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	open := func(key AccessKey, pin accesskey.Pin, runID, digest string, now time.Time) error {
		v, err := Open(f.answer, key, pin, runID, digest, f.requested, now)
		v.Clear()
		return err
	}
	otherPin := accesskey.Pin{{Alg: "ed25519", PublicKey: other.PublicKey().String()}}
	for name, tc := range map[string]struct {
		err  error
		want error
	}{
		"another access key": {open(AccessKey{ID: "ak_f1xt0re00000000g", Key: f.key.Key}, f.pin, f.runID, f.digest, f.now), ErrAccessKey},
		"another run":        {open(f.key, f.pin, "01928f4e-7c3a-7d2e-9b1a-3f5e6d7c8b9b", f.digest, f.now), ErrRun},
		"another digest":     {open(f.key, f.pin, f.runID, "sha256="+strings.Repeat("0", 64), f.now), ErrDigest},
		"another pin":        {open(f.key, otherPin, f.runID, f.digest, f.now), ErrSignature},
		"another key's open": {open(AccessKey{ID: f.key.ID, Key: other}, f.pin, f.runID, f.digest, f.now), ErrOpen},
		"301 s past exp":     {open(f.key, f.pin, f.runID, f.digest, time.Unix(1700000600+301, 0)), ErrExpired},
		"901 s ahead":        {open(f.key, f.pin, f.runID, f.digest, time.Unix(1700000600-901, 0)), ErrAhead},
	} {
		if !only(tc.err, tc.want) {
			t.Errorf("%s: %v; want %v alone", name, tc.err, tc.want)
		}
	}
	for _, now := range []int64{1700000600 + 300, 1700000600 - 900} {
		if err := open(f.key, f.pin, f.runID, f.digest, time.Unix(now, 0)); err != nil {
			t.Errorf("at %d: %v; want it opened", now, err)
		}
	}
}

// TestSealThenOpen pins a round trip with a generated access key and signing key, a
// value with every byte from 1 to 255 that is UTF-8, and a value of 16384 bytes; that
// two sealings use two ephemeral keys; and what Plaintext refuses of a sealing.
func TestSealThenOpen(t *testing.T) {
	key, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	id, runID, digest := "ak_0123456789abcdef", "01928f4e-7c3a-7d2e-9b1a-3f5e6d7c8b9a", "sha256="+strings.Repeat("ab", 32)
	var odd []byte
	for r := rune(1); r < 0x800; r++ {
		odd = fmt.Appendf(odd, "%c", r)
	}
	big := bytes.Repeat([]byte("é"), MaxValueBytes/2)
	now := time.Unix(1800000000, 0)
	s := Sealing{AccessKeyID: id, PublicKey: key.PublicKey(), RunID: runID, RunConfiguration: digest,
		Credentials: []string{"model", "forge", "a.b_c-d"}, Exp: Expiry(now),
		Values: []Value{{"model", []byte("generated-model-value")}, {"forge", odd}, {"a.b_c-d", big}}}
	pin := accesskey.Pin{{Alg: "ed25519", PublicKey: signer.PublicKey().String()}}
	answer, err := Seal(s, signer)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Seal(s, signer)
	if err != nil || bytes.Equal(answer, again) {
		t.Errorf("two sealings: equal %v, %v; want two ephemeral keys", bytes.Equal(answer, again), err)
	}
	v, err := Open(answer, AccessKey{ID: id, Key: key}, pin, runID, digest, []string{"forge", "a.b_c-d", "model"}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range s.Values {
		if b, ok := v.Value(want.Credential); !ok || !bytes.Equal(b, want.Value) {
			t.Errorf("the value of %s did not round-trip", want.Credential)
		}
	}
	v.Clear()
	for name, bad := range map[string]struct {
		s    Sealing
		want error
	}{
		"a value missing": {func() Sealing { c := s; c.Values = s.Values[:2]; return c }(), ErrRequest},
		"a value twice":   {func() Sealing { c := s; c.Values = []Value{s.Values[0], s.Values[0], s.Values[1]}; return c }(), ErrRequest},
		"an empty value":  {func() Sealing { c := s; c.Values = []Value{{"model", nil}, s.Values[1], s.Values[2]}; return c }(), ErrValue},
		"a NUL": {func() Sealing {
			c := s
			c.Values = []Value{{"model", []byte("a\x00b")}, s.Values[1], s.Values[2]}
			return c
		}(), ErrValue},
		"invalid UTF-8": {func() Sealing {
			c := s
			c.Values = []Value{{"model", []byte("a\xffb")}, s.Values[1], s.Values[2]}
			return c
		}(), ErrValue},
		"16385 bytes": {func() Sealing {
			c := s
			c.Values = []Value{{"model", append(bytes.Clone(big), 'x')}, s.Values[1], s.Values[2]}
			return c
		}(), ErrValue},
		"a name upper":     {func() Sealing { c := s; c.Credentials = []string{"Model", "forge", "a.b_c-d"}; return c }(), ErrRequest},
		"a run id outside": {func() Sealing { c := s; c.RunID = "run"; return c }(), ErrRequest},
	} {
		if _, err := Seal(bad.s, signer); !errors.Is(err, bad.want) {
			t.Errorf("%s: %v; want %v", name, err, bad.want)
		}
	}
}

// TestValuesShowNoValue pins that a Values prints, marshals and formats as its count
// alone, with every verb, inside a struct, a pointer and a slice, and that Clear
// overwrites the bytes Value returned.
func TestValuesShowNoValue(t *testing.T) {
	f := load(t)
	v, err := Open(f.answer, f.key, f.pin, f.runID, f.digest, f.requested, f.now)
	if err != nil {
		t.Fatal(err)
	}
	secrets := values(t, f.plaintext)
	holder := struct {
		Values Values
		Ptr    *Values
	}{v, &v}
	var out []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T"} {
		out = append(out, fmt.Sprintf(verb, v), fmt.Sprintf(verb, holder), fmt.Sprintf(verb, []Values{v}), fmt.Sprintf(verb, &v))
	}
	out = append(out, fmt.Sprint(v), fmt.Sprintln(v), v.String(), v.GoString())
	for _, marshal := range []func(any) ([]byte, error){json.Marshal, func(a any) ([]byte, error) { return jsonv2.Marshal(a) }} {
		for _, a := range []any{v, holder} {
			b, err := marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, string(b))
		}
	}
	if b, err := v.MarshalText(); err != nil || string(b) != "2 sealed values" {
		t.Errorf("MarshalText %q, %v", b, err)
	}
	for _, s := range out {
		for _, value := range secrets {
			if strings.Contains(s, value) || strings.Contains(s, hex.EncodeToString([]byte(value))) || strings.Contains(strings.ToLower(s), hex.EncodeToString([]byte(value))) {
				t.Errorf("%q shows a value", s)
			}
		}
	}
	held, _ := v.Value("model")
	v.Clear()
	if v.Len() != 0 || !bytes.Equal(held, make([]byte, len(held))) || len(held) == 0 {
		t.Errorf("after Clear: %d values, the bytes %x", v.Len(), held)
	}
	if _, ok := v.Value("model"); ok {
		t.Error("a value after Clear")
	}
	var zero Values
	zero.Clear()
	if zero.Len() != 0 || zero.String() != "0 sealed values" || zero.Credentials() != nil {
		t.Errorf("the zero Values: %v", zero)
	}
}

// TestPlaintextRefusals pins what Plaintext refuses, each with its error and with no
// value in the error.
func TestPlaintextRefusals(t *testing.T) {
	const marker = "marker-value-no-error-quotes"
	d := "sha256=" + strings.Repeat("0", 64)
	doc := func(credentials, values string) []byte {
		return []byte(`{"version":1,"run_configuration":"` + d + `","credentials":` + credentials + `,"values":` + values + `}`)
	}
	val := func(c string) string { return `{"credential":"` + c + `","value":"` + marker + `"}` }
	for name, tc := range map[string]struct {
		pt   []byte
		want error
	}{
		"a value twice":        {doc(`["a","b"]`, `[`+val("a")+`,`+val("a")+`,`+val("b")+`]`), ErrTwice},
		"another digest":       {[]byte(strings.Replace(string(doc(`["a","b"]`, `[`+val("a")+`,`+val("b")+`]`)), d, "sha256="+strings.Repeat("1", 64), 1)), ErrDigest},
		"other credentials":    {doc(`["a","c"]`, `[`+val("a")+`,`+val("c")+`]`), ErrCredentials},
		"credentials unsorted": {doc(`["b","a"]`, `[`+val("a")+`,`+val("b")+`]`), ErrPlaintext},
		"values unsorted":      {doc(`["a","b"]`, `[`+val("b")+`,`+val("a")+`]`), ErrPlaintext},
		"not requested":        {doc(`["a","b"]`, `[`+val("a")+`,`+val("b")+`,`+val("c")+`]`), ErrNotRequested},
		"missing":              {doc(`["a","b"]`, `[`+val("a")+`]`), ErrMissing},
		"a NUL":                {doc(`["a","b"]`, `[`+val("a")+`,{"credential":"b","value":"`+marker+`\u0000"}]`), ErrValue},
		"empty":                {doc(`["a","b"]`, `[`+val("a")+`,{"credential":"b","value":""}]`), ErrValue},
		"16385 bytes":          {doc(`["a","b"]`, `[`+val("a")+`,{"credential":"b","value":"`+marker+strings.Repeat("x", MaxValueBytes)+`"}]`), ErrValue},
		"a number":             {doc(`["a","b"]`, `[`+val("a")+`,{"credential":"b","value":7}]`), ErrPlaintext},
		"a secret id":          {doc(`["a","b"]`, `[`+val("a")+`,{"secret":"b","value":"`+marker+`"}]`), ErrPlaintext},
		"invalid UTF-8":        {doc(`["a","b"]`, `[`+val("a")+`,{"credential":"b","value":"`+marker+"\xff"+`"}]`), ErrPlaintext},
		"a member twice":       {doc(`["a","b"]`, `[`+val("a")+`,{"credential":"b","value":"`+marker+`","value":"`+marker+`"}]`), ErrPlaintext},
		"version 1.0":          {[]byte(strings.Replace(string(doc(`["a","b"]`, `[`+val("a")+`,`+val("b")+`]`)), `"version":1`, `"version":1.0`, 1)), ErrPlaintext},
	} {
		v, err := Plaintext(tc.pt, d, []string{"b", "a"})
		if v.Len() != 0 || !only(err, tc.want) {
			t.Errorf("%s: %d values, %v; want %v alone", name, v.Len(), err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), marker) {
			t.Errorf("%s: the error contains the value: %v", name, err)
		}
	}
}

// FuzzOpen pins that Open never panics on any answer, refuses each with exactly one of
// the package's errors, and that an error contains none of the fixture's values.
func FuzzOpen(f *testing.F) {
	fx := load(f)
	f.Add(fx.answer)
	for _, c := range fx.cases {
		f.Add(read(f, c.File))
	}
	secrets := values(f, fx.plaintext)
	f.Fuzz(func(t *testing.T, answer []byte) {
		v, err := Open(answer, fx.key, fx.pin, fx.runID, fx.digest, fx.requested, fx.now)
		defer v.Clear()
		if err == nil {
			return
		}
		n := 0
		for _, e := range errs {
			if errors.Is(err, e) {
				n++
			}
		}
		if n != 1 || v.Len() != 0 {
			t.Fatalf("%v wraps %d refusals with %d values", err, n, v.Len())
		}
		for _, value := range secrets {
			if strings.Contains(err.Error(), value) {
				t.Fatalf("the error contains a value: %v", err)
			}
		}
	})
}

// FuzzPlaintext pins that readPlaintext and sealed-plaintext.schema.json agree: what
// readPlaintext accepts the schema accepts, and what the schema accepts readPlaintext
// accepts, except a value of more than 16384 bytes, which the schema's count of
// characters lets through, a version written other than 1, and a document a strict
// decoder refuses, a member twice or invalid UTF-8 say.
func FuzzPlaintext(f *testing.F) {
	schema, err := contracts.Compile("sealed-plaintext.schema.json")
	if err != nil {
		f.Fatal(err)
	}
	for _, name := range []string{"fixtures/sealed/sealed-plaintext.json", "fixtures/sealed/plaintext-other-digest.json",
		"fixtures/sealed/plaintext-not-requested.json", "fixtures/invalid/sealed-plaintext-secret-id.json", "fixtures/invalid/sealed-plaintext-value-nul.json"} {
		f.Add(read(f, name))
	}
	f.Fuzz(func(t *testing.T, pt []byte) {
		_, _, _, values, err := readPlaintext(pt)
		clearAll(values)
		doc, derr := contracts.Decode("plaintext.json", pt)
		schemaOK := derr == nil && schema.Validate(doc) == nil
		if err == nil && !schemaOK {
			t.Fatalf("readPlaintext accepts what the schema refuses: %q", pt)
		}
		if err != nil && schemaOK && !errors.Is(err, ErrValue) {
			var v struct {
				Version jsontext.Value `json:"version"`
			}
			if jsontext.Value(pt).IsValid() && jsonv2.Unmarshal(pt, &v) == nil && string(v.Version) == "1" {
				t.Fatalf("the schema accepts what readPlaintext refuses with %v: %q", err, pt)
			}
		}
	})
}
