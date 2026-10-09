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
	"io/fs"
	"maps"
	"math/big"
	"path"
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

// decodeSegment decodes one base64url segment of a JWS into a JSON object, numbers as
// json.Number.
func decodeSegment(t *testing.T, s string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		t.Fatalf("segment %q: %v", s, err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
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

// TestKnownAnswers holds the header step, the claim checks, the scope and the mapping
// to every run credential of the known answers, at their now: a run credential refused
// at a step fails that step and passes every earlier one; an accepted one passes every
// step and maps to the labels and details listed. The signature step is this test's
// own check, left to the gateway's verifier: a credential refused at signature passes
// every other step.
func TestKnownAnswers(t *testing.T) {
	var index struct {
		Now         int64         `json:"now"`
		Credentials []knownAnswer `json:"credentials"`
	}
	if err := json.Unmarshal(knownFile(t, "credentials.json"), &index); err != nil {
		t.Fatal(err)
	}
	if index.Now != knownanswers.Now || len(index.Credentials) < 20 {
		t.Fatalf("credentials.json: now %d, %d credentials", index.Now, len(index.Credentials))
	}
	at := time.Unix(index.Now, 0)
	read := func(name string) ([]byte, error) { return fs.ReadFile(contracts.FS, path.Join(knownAnswers, name)) }
	configs := map[string]Issuer{}
	for _, name := range []string{"one-key.json", "two-keys.json"} {
		l, err := Parse(name, knownFile(t, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Check(read); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		configs[name] = l[0]
	}
	steps := []string{"header", "signature", "claims", "scope"}
	seen := map[string]bool{}
	for _, c := range index.Credentials {
		t.Run(c.Name, func(t *testing.T) {
			i, ok := configs[c.Configuration]
			if !ok {
				t.Fatalf("no configuration %q", c.Configuration)
			}
			if (c.Outcome == "accepted") != (c.RefusedAt == "") || !(c.Outcome == "accepted" || slices.Contains(steps, c.RefusedAt)) {
				t.Fatalf("outcome %q refused at %q", c.Outcome, c.RefusedAt)
			}
			seen[c.RefusedAt] = true
			parts := strings.Split(c.Credential, ".")
			if len(parts) != 3 {
				t.Fatalf("%d segments", len(parts))
			}
			header, claims := decodeSegment(t, parts[0]), decodeSegment(t, parts[1])
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
			n, err := i.SelectKey(header)
			if reached("header") != (err == nil) {
				t.Fatalf("SelectKey: %v; want it to pass: %v", err, reached("header"))
			}
			if c.RefusedAt == "header" {
				return
			}
			pub, err := i.Keys[n].PublicKey(read)
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
			labels, err := i.Labels(claims)
			if c.RefusedAt != "" {
				if c.RefusedAt == "signature" && err != nil {
					t.Errorf("Labels refuses the credential refused at signature: %v", err)
				}
				return
			}
			if err != nil || !maps.Equal(labels, c.Labels) {
				t.Errorf("Labels = %v, %v; want %v", labels, err, c.Labels)
			}
			details, err := i.Details(claims)
			if err != nil || !maps.Equal(details, c.Details) {
				t.Errorf("Details = %v, %v; want %v", details, err, c.Details)
			}
		})
	}
	for _, s := range append(steps, "") {
		if !seen[s] {
			t.Errorf("no known answer refused at %q", s)
		}
	}
}
