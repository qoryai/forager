package runcredential

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// signingKeys are private keys made for this run of the tests, and the PEM files of
// their public keys.
type signingKeys struct {
	rsa   *rsa.PrivateKey
	ecdsa *ecdsa.PrivateKey
	ed    ed25519.PrivateKey
	files map[string][]byte
}

var makeSigningKeys = sync.OnceValues(func() (*signingKeys, error) {
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	e, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	k := &signingKeys{rsa: r, ecdsa: e, ed: ed, files: map[string][]byte{}}
	for name, pub := range map[string]any{"rs256.pem": &r.PublicKey, "es256.pem": &e.PublicKey, "eddsa.pem": ed.Public(), "rsa1024.pem": &small.PublicKey} {
		b, err := pemPublic(pub)
		if err != nil {
			return nil, err
		}
		k.files[name] = b
	}
	return k, nil
})

// pemPublic is the PEM of a public key, PUBLIC KEY.
func pemPublic(pub any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pemOf("PUBLIC KEY", der), nil
}

func keysForSigning(t *testing.T) *signingKeys {
	t.Helper()
	k, err := makeSigningKeys()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// jws is the compact serialisation of the header and claims, signed by alg under the
// tests' keys.
func (k *signingKeys) jws(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	h := sha256.Sum256([]byte(input))
	var sig []byte
	switch header["alg"] {
	case RS256:
		s, err := rsa.SignPKCS1v15(nil, k.rsa, crypto.SHA256, h[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = s
	case ES256:
		r, s, err := ecdsa.Sign(rand.Reader, k.ecdsa, h[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case EdDSA:
		sig = ed25519.Sign(k.ed, []byte(input))
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// verifierOf is a verifier under the issuers, over the tests' keys.
func verifierOf(t *testing.T, k *signingKeys, issuers ...Issuer) *Verifier {
	t.Helper()
	v, err := NewVerifier(issuers, files(k.files))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// refusedAt fails the test unless err is ErrRefused at step, with ErrRefused's text
// alone and no part of cred.
func refusedAt(t *testing.T, got *Verified, err error, step, cred string) {
	t.Helper()
	if got != nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("Verify = %v, %v; want ErrRefused", got, err)
	}
	if s := stepOf(err); s != step {
		t.Errorf("refused at %q (%s); want %q", s, reason(t, err), step)
	}
	holdsNoPart(t, err, cred)
}

func TestVerifyAcceptsEachAlgorithm(t *testing.T) {
	k := keysForSigning(t)
	i := issuer()
	i.Algorithms = []string{RS256, ES256, EdDSA}
	i.Keys = []Key{{KID: "k1", Alg: RS256, PublicKeyFile: "rs256.pem"}, {KID: "k2", Alg: ES256, PublicKeyFile: "es256.pem"}, {KID: "k3", Alg: EdDSA, PublicKeyFile: "eddsa.pem"}}
	v := verifierOf(t, k, i)
	for kid, alg := range map[string]string{"k1": RS256, "k2": ES256, "k3": EdDSA} {
		cred := k.jws(t, map[string]any{"alg": alg, "kid": kid, "typ": "JWT"}, validClaims())
		got, err := v.Verify(cred, now)
		if err != nil {
			t.Fatalf("%s: %v (%s)", alg, err, reason(t, err))
		}
		if got.Issuer != exampleIssuer || got.RunKey != "rk-0001" || !got.Expires.Equal(now.Add(600*time.Second)) ||
			got.Labels[LabelRepository] != "example-namespace/project" || got.Details["requester"] != "example-requester" {
			t.Errorf("%s: Verify = %+v", alg, got)
		}
	}
}

func TestVerifyRefuses(t *testing.T) {
	k := keysForSigning(t)
	v := verifierOf(t, k, issuer())
	hRS := map[string]any{"alg": RS256, "typ": "JWT"}
	good := k.jws(t, hRS, validClaims())
	parts := strings.Split(good, ".")
	enc := base64.RawURLEncoding.EncodeToString
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	with := func(change func(map[string]any)) map[string]any {
		c := validClaims()
		change(c)
		return c
	}
	for _, c := range []struct {
		name, cred, step string
	}{
		{"empty", "", "serialisation"},
		{"too long", good + strings.Repeat("A", MaxCredentialBytes), "serialisation"},
		{"one part", parts[0], "serialisation"},
		{"an empty header", "." + parts[1] + "." + parts[2], "serialisation"},
		{"an empty payload", parts[0] + ".." + parts[2], "serialisation"},
		{"a tab", parts[0] + "\t." + parts[1] + "." + parts[2], "serialisation"},
		{"a carriage return", parts[0] + "." + parts[1][:5] + "\r" + parts[1][5:] + "." + parts[2], "serialisation"},
		{"standard base64", parts[0] + "." + parts[1] + "." + strings.NewReplacer("-", "+", "_", "/").Replace(parts[2]) + "+", "serialisation"},
		{"bits beyond the last byte", bitsBeyond(enc([]byte(`{"alg":"RS256"} `))) + "." + parts[1] + "." + parts[2], "serialisation"},
		{"a header that is an array", enc([]byte(`["alg"]`)) + "." + parts[1] + "." + parts[2], "header"},
		{"a header that is null", enc([]byte(`null`)) + "." + parts[1] + "." + parts[2], "header"},
		{"a header not UTF-8", enc([]byte("{\"alg\":\"RS256\",\"x\":\"\xff\"}")) + "." + parts[1] + "." + parts[2], "header"},
		{"a header with no alg", k.jws(t, map[string]any{"typ": "JWT"}, validClaims()), "header"},
		{"a typ that is a number", k.jws(t, map[string]any{"alg": RS256, "typ": 1}, validClaims()), "header"},
		{"a kid that is a number", k.jws(t, map[string]any{"alg": RS256, "kid": 1}, validClaims()), "header"},
		{"HS256", enc([]byte(`{"alg":"HS256"}`)) + "." + parts[1] + "." + parts[2], "header"},
		{"crit empty", k.jws(t, map[string]any{"alg": RS256, "crit": []string{}}, validClaims()), "header"},
		{"a signature of another length", parts[0] + "." + parts[1] + "." + enc(sig[:len(sig)-1]), "signature"},
		{"another payload", parts[0] + "." + enc([]byte(`{"sub":"rk-0002"}`)) + "." + parts[2], "signature"},
		{"a payload that is an array", signedRaw(t, k, `{"alg":"RS256"}`, `["sub"]`), "claims"},
		{"a payload not UTF-8", signedRaw(t, k, `{"alg":"RS256"}`, "{\"sub\":\"\xff\"}"), "claims"},
		{"exp a string", k.jws(t, hRS, with(func(c map[string]any) { c["exp"] = "1700000600" })), "claims"},
		{"aud of another type", k.jws(t, hRS, with(func(c map[string]any) { c["aud"] = 7 })), "claims"},
		{"an empty sub", k.jws(t, hRS, with(func(c map[string]any) { c["sub"] = "" })), "claims"},
		{"nbf ahead", k.jws(t, hRS, with(func(c map[string]any) { c["nbf"] = float64(now.Unix() + 600) })), "claims"},
		{"no namespace", k.jws(t, hRS, with(func(c map[string]any) { delete(c, "namespace") })), "scope"},
		{"no project", k.jws(t, hRS, with(func(c map[string]any) { delete(c, "project") })), "mapping"},
		{"a project with the join", k.jws(t, hRS, with(func(c map[string]any) { c["project"] = "a/b" })), "mapping"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := v.Verify(c.cred, now)
			refusedAt(t, got, err, c.step, c.cred)
		})
	}
	if _, err := v.Verify(good, now); err != nil {
		t.Fatalf("the good run credential: %v", err)
	}
	var none *Verifier
	if got, err := none.Verify(good, now); got != nil || !errors.Is(err, ErrRefused) {
		t.Errorf("a nil verifier: %v, %v", got, err)
	}
}

// bitsBeyond is base64url s, whose last character holds bits beyond the last byte,
// with the lowest of them set: the same bytes to a lenient decoder.
func bitsBeyond(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, s[len(s)-1])
	return s[:len(s)-1] + string(alphabet[last+1])
}

// signedRaw is the JWS of the JSON text of a header and a payload under the tests' RSA
// key.
func signedRaw(t *testing.T, k *signingKeys, header, payload string) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	h := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(nil, k.rsa, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestVerifyRefusesAnECDSASignatureOutsideTheOrder pins the checks of R and S, each in
// [1, n-1], and that the high S of a signature, n - S, is the other valid signature
// ECDSA allows.
func TestVerifyRefusesAnECDSASignatureOutsideTheOrder(t *testing.T) {
	k := keysForSigning(t)
	i := issuer()
	i.Algorithms = []string{ES256}
	i.Keys = []Key{{Alg: ES256, PublicKeyFile: "es256.pem"}}
	v := verifierOf(t, k, i)
	cred := k.jws(t, map[string]any{"alg": ES256}, validClaims())
	parts := strings.Split(cred, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	n := elliptic.P256().Params().N
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	with := func(r, s *big.Int) string {
		b := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		return parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(b)
	}
	for name, c := range map[string]string{
		"r = n": with(n, s),
		"s = 0": with(r, big.NewInt(0)),
		"s = n": with(r, n),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := v.Verify(c, now)
			refusedAt(t, got, err, "signature", c)
		})
	}
	if _, err := v.Verify(with(r, new(big.Int).Sub(n, s)), now); err != nil {
		t.Errorf("the signature with n - S: %v", err)
	}
}

func TestNewVerifierRefusesAnRSAKeyOf1024Bits(t *testing.T) {
	k := keysForSigning(t)
	i := issuer()
	i.Keys[0].PublicKeyFile = "rsa1024.pem"
	if _, err := NewVerifier(Issuers{i}, files(k.files)); err == nil || !strings.Contains(err.Error(), "1024 bits") {
		t.Errorf("NewVerifier: %v; want the 1024-bit key refused", err)
	}
	if _, err := NewVerifier(nil, files(k.files)); err == nil {
		t.Error("NewVerifier accepts no issuer")
	}
}

func TestTheLeewayIsCapped(t *testing.T) {
	k := keysForSigning(t)
	for _, c := range []struct {
		leeway time.Duration
		ok     bool
	}{{0, true}, {MaxLeeway, true}, {MaxLeeway + time.Second, false}, {time.Hour, false}} {
		i := issuer()
		i.Leeway = d(c.leeway)
		err := i.Check(files(k.files))
		if (err == nil) != c.ok {
			t.Errorf("a leeway of %v: Check: %v", c.leeway, err)
		}
		if err != nil && !strings.Contains(err.Error(), "above 5m0s") {
			t.Errorf("a leeway of %v: %v", c.leeway, err)
		}
		// An Issuer built in Go without Check is held to the cap too.
		if err := i.CheckClaims(validClaims(), now); (err == nil) != c.ok {
			t.Errorf("a leeway of %v: CheckClaims: %v", c.leeway, err)
		}
	}
	// The schema writes a duration as a string, and leaves the cap to Check.
	l, err := Parse("l.yaml", []byte(`- {issuer: "https://issuer.example", audience: qory-gateway, algorithms: [RS256],
   keys: [{alg: RS256, public_key_file: rs256.pem}], leeway: 6m,
   labels: {forge: {value: example-forge}, repository: {claim: project}, run_key: {claim: sub}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Check(files(k.files)); err == nil || !strings.Contains(err.Error(), "the leeway 6m0s is above 5m0s") {
		t.Errorf("a leeway of 6m in a document: Check: %v", err)
	}
	if _, err := NewVerifier(l, files(k.files)); err == nil {
		t.Error("NewVerifier accepts a leeway of 6m")
	}
	// Within the cap, the leeway is honoured: exp passed 4 minutes ago is accepted under
	// a leeway of 5 minutes, and refused under the default.
	i := issuer()
	i.Leeway = d(MaxLeeway)
	c := validClaims()
	c["iat"], c["exp"] = float64(now.Unix()-600), float64(now.Unix()-240)
	if err := i.CheckClaims(c, now); err != nil {
		t.Errorf("exp within a leeway of 5 minutes: %v", err)
	}
	if err := issuer().CheckClaims(c, now); err == nil {
		t.Error("exp 4 minutes ago is accepted under the default leeway")
	}
}

// TestVerifyChoosesTheIssuerWhoseKeyVerified pins that the issuer is the one whose
// pinned key verified the signature, and that its issuer equals iss: a run credential
// signed under one issuer's key and naming another issuer is refused, even when that
// other issuer is configured.
func TestVerifyChoosesTheIssuerWhoseKeyVerified(t *testing.T) {
	k := keysForSigning(t)
	a := issuer()
	b := issuer()
	b.Issuer = "https://issuer-b.example"
	b.Algorithms = []string{ES256}
	b.Keys = []Key{{Alg: ES256, PublicKeyFile: "es256.pem"}}
	v := verifierOf(t, k, a, b)
	claimsB := validClaims()
	claimsB["iss"] = b.Issuer
	got, err := v.Verify(k.jws(t, map[string]any{"alg": ES256}, claimsB), now)
	if err != nil || got.Issuer != b.Issuer {
		t.Fatalf("issuer b's run credential: %v, %v", got, err)
	}
	// Signed under a's key, naming b.
	cred := k.jws(t, map[string]any{"alg": RS256}, claimsB)
	got, err = v.Verify(cred, now)
	refusedAt(t, got, err, "claims", cred)
	// Signed under b's key, naming a.
	cred = k.jws(t, map[string]any{"alg": ES256}, validClaims())
	got, err = v.Verify(cred, now)
	refusedAt(t, got, err, "claims", cred)

	// Two issuers that pin the same key: iss picks among them.
	c := issuer()
	c.Issuer = "https://issuer-c.example"
	v = verifierOf(t, k, a, c)
	claimsC := validClaims()
	claimsC["iss"] = c.Issuer
	if got, err := v.Verify(k.jws(t, map[string]any{"alg": RS256}, claimsC), now); err != nil || got.Issuer != c.Issuer {
		t.Errorf("issuer c's run credential under the key a pins too: %v, %v", got, err)
	}
	if got, err := v.Verify(k.jws(t, map[string]any{"alg": RS256}, validClaims()), now); err != nil || got.Issuer != a.Issuer {
		t.Errorf("issuer a's run credential: %v, %v", got, err)
	}
}

// TestVerifierKeepsItsOwnCopy pins that a change to the issuers after NewVerifier
// changes nothing the verifier accepts or refuses.
func TestVerifierKeepsItsOwnCopy(t *testing.T) {
	k := keysForSigning(t)
	l := Issuers{issuer()}
	v := verifierOf(t, k, l...)
	l[0].Allow.Values[0] = "other-namespace"
	l[0].Algorithms[0] = "none"
	l[0].Audience = "another-service"
	if _, err := v.Verify(k.jws(t, map[string]any{"alg": RS256}, validClaims()), now); err != nil {
		t.Errorf("Verify after the issuers changed: %v (%s)", err, reason(t, err))
	}
}

// TestVerifyReadsNoClaimBeforeTheSignature pins that a run credential with a bad
// signature is refused at the signature whatever its payload holds, a payload that is
// not JSON included.
func TestVerifyReadsNoClaimBeforeTheSignature(t *testing.T) {
	k := keysForSigning(t)
	v := verifierOf(t, k, issuer())
	parts := strings.Split(k.jws(t, map[string]any{"alg": RS256}, validClaims()), ".")
	for _, payload := range []string{"not JSON", `{"exp":"x","exp":"y"}`, `{"iss":"https://other.example"}`} {
		cred := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + parts[2]
		got, err := v.Verify(cred, now)
		refusedAt(t, got, err, "signature", cred)
	}
}
