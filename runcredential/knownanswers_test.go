package runcredential

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"encoding/pem"
	"errors"
	"io/fs"
	"maps"
	"math/big"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/runcredential/internal/knownanswers"
)

// TestKnownAnswersAreCurrent pins that the known answers in the contract are what
// package knownanswers writes from the published seed: go generate ./runcredential
// writes them again.
func TestKnownAnswersAreCurrent(t *testing.T) {
	want, err := knownanswers.Files()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(contracts.FS, knownAnswers)
	if err != nil {
		t.Fatal(err)
	}
	var have []string
	for _, e := range entries {
		have = append(have, e.Name())
	}
	if names := slices.Sorted(maps.Keys(want)); !slices.Equal(have, names) {
		t.Fatalf("%s holds %v; want %v (go generate ./runcredential)", knownAnswers, have, names)
	}
	for name, b := range want {
		if got := knownFile(t, name); !bytes.Equal(got, b) {
			t.Errorf("%s differs from what the seed makes (go generate ./runcredential)", name)
		}
	}
	src, err := knownanswers.FixtureKeysSource()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile("fixturekeys.go"); err != nil || !bytes.Equal(got, src) {
		t.Errorf("fixturekeys.go differs from what the seed makes (go generate ./runcredential): %v", err)
	}
	var keys struct {
		Seed string `json:"seed"`
	}
	if err := json.Unmarshal(knownFile(t, "keys.json"), &keys); err != nil {
		t.Fatal(err)
	}
	seed, err := base64.RawURLEncoding.Strict().DecodeString(keys.Seed)
	if err != nil || !bytes.Equal(seed, knownanswers.Seed()) {
		t.Errorf("keys.json publishes the seed %q; want bytes 193 to 224", keys.Seed)
	}
	for n, b := range seed {
		if int(b) != 193+n {
			t.Errorf("seed byte %d is %d; want %d", n, b, 193+n)
		}
	}
}

// TestFixtureKeysAreTheKnownAnswers pins that the keys Key.PublicKey refuses as fixture
// keys are exactly the public keys of the known answers, rs256.pem, es256.pem and
// eddsa.pem, each once.
func TestFixtureKeysAreTheKnownAnswers(t *testing.T) {
	var files []string
	for _, name := range []string{"rs256.pem", "es256.pem", "eddsa.pem"} {
		block, _ := pem.Decode(knownFile(t, name))
		if block == nil {
			t.Fatalf("%s holds no PEM block", name)
		}
		files = append(files, base64.StdEncoding.EncodeToString(block.Bytes))
	}
	if !slices.Equal(fixtureKeys, files) {
		t.Errorf("fixtureKeys differ from rs256.pem, es256.pem and eddsa.pem (go generate ./runcredential)")
	}
	if len(slices.Compact(slices.Sorted(slices.Values(fixtureKeys)))) != 3 {
		t.Errorf("fixtureKeys hold %d keys; want three different ones", len(fixtureKeys))
	}
	for _, name := range []string{"rs256.pem", "es256.pem", "eddsa.pem"} {
		pub, err := parsePublicKey(map[string]string{"rs256.pem": RS256, "es256.pem": ES256, "eddsa.pem": EdDSA}[name], knownFile(t, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !fixtureKey(pub) {
			t.Errorf("%s is not reported as a fixture key", name)
		}
	}
	other, err := madeKeys()
	if err != nil {
		t.Fatal(err)
	}
	if pub, err := parsePublicKey(ES256, other["es256.pem"]); err != nil || fixtureKey(pub) {
		t.Errorf("a key made by the tests is reported as a fixture key: %v", err)
	}
}

// knownAnswer is one run credential of credentials.json.
type knownAnswer struct {
	Name          string            `json:"name"`
	Configuration string            `json:"configuration"`
	Credential    string            `json:"credential"`
	Outcome       string            `json:"outcome"`
	RefusedAt     string            `json:"refused_at"`
	Labels        map[string]string `json:"labels"`
	Details       map[string]string `json:"details"`
}

// decodeSegment decodes one base64url segment of a JWS into a JSON object through
// encoding/json/v2, which refuses a member name twice; false when it is not one.
func decodeSegment(s string) (map[string]any, bool) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) == 0 || b[0] != '{' {
		return nil, false
	}
	var m map[string]any
	if err := jsonv2.Unmarshal(b, &m); err != nil {
		return nil, false
	}
	return m, true
}

// strictPart is a part of a JWS compact serialisation, of the base64url alphabet alone.
var strictPart = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

// strictParts are the three parts of a JWS compact serialisation, each of the
// base64url alphabet alone, the header and the payload not empty, or nil: this test's
// own reading of the serialisation.
func strictParts(cred string) []string {
	parts := strings.Split(cred, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return nil
	}
	for _, p := range parts {
		if !strictPart.MatchString(p) {
			return nil
		}
		if _, err := base64.RawURLEncoding.Strict().DecodeString(p); err != nil {
			return nil
		}
	}
	return parts
}

// verify is this test's own check of a known answer's signature, so the fixtures are
// known to be what they say; the gateway's verifier is not this package's.
func verify(t *testing.T, pub crypto.PublicKey, alg, input string, sig []byte) bool {
	t.Helper()
	h := sha256.Sum256([]byte(input))
	switch alg {
	case RS256:
		return rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, h[:], sig) == nil
	case ES256:
		if len(sig) != 64 {
			return false
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(pub.(*ecdsa.PublicKey), h[:], r, s)
	case EdDSA:
		return ed25519.Verify(pub.(ed25519.PublicKey), []byte(input), sig)
	}
	return false
}

// knownConfigurations are the fixture issuer's two configurations of the known
// answers, by file name, read through the path that accepts the published fixture keys.
func knownConfigurations(t *testing.T) (map[string]Issuer, ReadFile) {
	t.Helper()
	read := func(name string) ([]byte, error) { return fs.ReadFile(contracts.FS, path.Join(knownAnswers, name)) }
	configs := map[string]Issuer{}
	for _, name := range []string{"one-key.json", "two-keys.json"} {
		l, err := Parse(name, knownFile(t, name))
		if err != nil {
			t.Fatal(err)
		}
		// The published fixture keys are refused outside the known answers; the known
		// answers reach the parser through the path that skips that check alone.
		if err := l.Check(read); err == nil || !strings.Contains(err.Error(), "a published fixture key") {
			t.Fatalf("%s: Check: %v; want the fixture key refused", name, err)
		}
		if _, err := NewVerifier(l, read); err == nil || !strings.Contains(err.Error(), "a published fixture key") {
			t.Fatalf("%s: NewVerifier: %v; want the fixture key refused", name, err)
		}
		if err := l.check(read, true); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		configs[name] = l[0]
	}
	return configs, read
}

// knownIndex is credentials.json.
func knownIndex(t *testing.T) (time.Time, []knownAnswer) {
	t.Helper()
	var index struct {
		Now         int64         `json:"now"`
		Credentials []knownAnswer `json:"credentials"`
	}
	if err := json.Unmarshal(knownFile(t, "credentials.json"), &index); err != nil {
		t.Fatal(err)
	}
	if index.Now != knownanswers.Now || len(index.Credentials) < 40 {
		t.Fatalf("credentials.json: now %d, %d credentials", index.Now, len(index.Credentials))
	}
	return time.Unix(index.Now, 0), index.Credentials
}

// TestVerifyKnownAnswers holds Verifier.Verify to every run credential of the known
// answers, at their now: an accepted one is verified, with its issuer, run key, exp,
// labels and details; a refused one is ErrRefused, refused at the step listed, with
// ErrRefused's text alone, which holds no part of the run credential.
func TestVerifyKnownAnswers(t *testing.T) {
	configs, read := knownConfigurations(t)
	at, cases := knownIndex(t)
	verifiers := map[string]*Verifier{}
	for name, i := range configs {
		v, err := newVerifier(Issuers{i}, read, true)
		if err != nil {
			t.Fatal(err)
		}
		verifiers[name] = v
	}
	seen := map[string]bool{}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			seen[c.RefusedAt] = true
			got, err := verifiers[c.Configuration].Verify(c.Credential, at)
			if c.Outcome == "accepted" {
				if err != nil {
					t.Fatalf("Verify: %v (%s at %s)", err, reason(t, err), stepOf(err))
				}
				if got.Issuer != knownanswers.Issuer || got.RunKey != "rk-0001" || !got.Expires.Equal(time.Unix(expOf(t, c.Credential), 0)) {
					t.Errorf("Verify = %s, %s, %v", got.Issuer, got.RunKey, got.Expires)
				}
				if !maps.Equal(got.Labels, c.Labels) {
					t.Errorf("Labels = %v; want %v", got.Labels, c.Labels)
				}
				if !maps.Equal(got.Details, c.Details) {
					t.Errorf("Details = %v; want %v", got.Details, c.Details)
				}
				if got.Claims["sub"] != "rk-0001" {
					t.Errorf("Claims = %v", got.Claims)
				}
				return
			}
			if got != nil || !errors.Is(err, ErrRefused) {
				t.Fatalf("Verify = %v, %v; want ErrRefused", got, err)
			}
			if s := stepOf(err); s != c.RefusedAt {
				t.Errorf("refused at %q (%s); want %q", s, reason(t, err), c.RefusedAt)
			}
			holdsNoPart(t, err, c.Credential)
		})
	}
	for _, s := range append(slices.Clone(steps), "") {
		if !seen[s] {
			t.Errorf("no known answer refused at %q", s)
		}
	}
}

// stepOf is the step of a refusal of the run credential.
func stepOf(err error) string {
	var r *refused
	if errors.As(err, &r) {
		return r.step
	}
	return ""
}

// expOf is the claim exp of a run credential, read without a check.
func expOf(t *testing.T, cred string) int64 {
	t.Helper()
	claims, ok := decodeSegment(strings.Split(cred, ".")[1])
	if !ok {
		t.Fatal("no payload")
	}
	return int64(claims["exp"].(float64))
}

// holdsNoPart fails the test when err's text is not ErrRefused's, or holds any part of
// the run credential, or any eight bytes of one.
func holdsNoPart(t *testing.T, err error, cred string) {
	t.Helper()
	if err.Error() != ErrRefused.Error() {
		t.Errorf("the error is %q; want ErrRefused's text alone", err)
	}
	for _, p := range strings.FieldsFunc(cred, func(r rune) bool { return r == '.' || r == ' ' || r == '\n' }) {
		for n := 0; n+8 <= len(p); n += 8 {
			if strings.Contains(err.Error(), p[n:n+8]) {
				t.Errorf("the error holds a part of the run credential: %q", err)
			}
		}
	}
}

// TestKnownAnswers holds the serialisation, the header step, the claim checks, the
// scope and the mapping, Labels and Details, each on its own, to every run credential of
// the known answers, at their now: a run credential refused at a step fails that step
// and passes every earlier one; an accepted one passes every step and maps to the
// labels and details listed. The signature step is this test's own check, independent
// of Verify's: a credential refused at signature passes every other step.
func TestKnownAnswers(t *testing.T) {
	configs, read := knownConfigurations(t)
	at, cases := knownIndex(t)
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			i, ok := configs[c.Configuration]
			if !ok {
				t.Fatalf("no configuration %q", c.Configuration)
			}
			if (c.Outcome == "accepted") != (c.RefusedAt == "") || !(c.Outcome == "accepted" || slices.Contains(steps, c.RefusedAt)) {
				t.Fatalf("outcome %q refused at %q", c.Outcome, c.RefusedAt)
			}
			// reached reports whether the run credential passes a step: every step before
			// the one that refuses it, and every step but the signature when that is the
			// one.
			reached := func(step string) bool {
				switch c.RefusedAt {
				case "":
					return true
				case "signature":
					return step != "signature"
				}
				return slices.Index(steps, step) < slices.Index(steps, c.RefusedAt)
			}
			parts := strictParts(c.Credential)
			if (parts != nil) != reached("serialisation") {
				t.Fatalf("the serialisation is strict: %v; want %v", parts != nil, reached("serialisation"))
			}
			if parts == nil {
				return
			}
			header, ok := decodeSegment(parts[0])
			if !ok {
				if c.RefusedAt != "header" {
					t.Fatalf("the header is not one JSON object with each member name once; refused at %q", c.RefusedAt)
				}
				return
			}
			n, err := i.SelectKey(header)
			if reached("header") != (err == nil) {
				t.Fatalf("SelectKey: %v; want it to pass: %v", err, reached("header"))
			}
			if c.RefusedAt == "header" {
				return
			}
			pub, err := i.Keys[n].publicKey(read, true)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
			if err != nil {
				t.Fatal(err)
			}
			if good := verify(t, pub, i.Keys[n].Alg, parts[0]+"."+parts[1], sig); good != reached("signature") {
				t.Errorf("the signature verifies: %v; want %v", good, reached("signature"))
			}
			claims, ok := decodeSegment(parts[1])
			if !ok {
				if c.RefusedAt != "claims" {
					t.Fatalf("the payload is not one JSON object with each member name once; refused at %q", c.RefusedAt)
				}
				return
			}
			err = i.CheckClaims(claims, at)
			if reached("claims") != (err == nil) {
				t.Fatalf("CheckClaims: %v; want it to pass: %v", err, reached("claims"))
			}
			if c.RefusedAt == "claims" {
				return
			}
			if i.Allowed(claims) != reached("scope") {
				t.Fatalf("Allowed: %v; want %v", i.Allowed(claims), reached("scope"))
			}
			if c.RefusedAt == "scope" {
				return
			}
			labels, lerr := i.Labels(claims)
			details, derr := i.Details(claims)
			if mapped := lerr == nil && derr == nil; mapped != reached("mapping") {
				t.Fatalf("Labels: %v, Details: %v; want them to pass: %v", lerr, derr, reached("mapping"))
			}
			if c.RefusedAt != "" {
				return
			}
			if !maps.Equal(labels, c.Labels) {
				t.Errorf("Labels = %v; want %v", labels, c.Labels)
			}
			if !maps.Equal(details, c.Details) {
				t.Errorf("Details = %v; want %v", details, c.Details)
			}
		})
	}
}
