package runcredential

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// MaxCredentialBytes is the longest run credential the gateway reads, in bytes: far
// above any JWT of the claims the mapping reads, under an RSA key of 4096 bits, and
// short enough that no request makes the gateway decode much.
const MaxCredentialBytes = 16384

// Verifier verifies run credentials under the issuers a gateway accepts, their keys
// read and parsed once. It is safe for concurrent use.
type Verifier struct {
	issuers []verifierIssuer
}

// verifierIssuer is one issuer of a [Verifier], with its pinned keys parsed, in the
// order of its keys.
type verifierIssuer struct {
	issuer Issuer
	keys   []crypto.PublicKey
}

// Verified is a run credential [Verifier.Verify] accepted: what its signed claims
// say, and what the mapping made of them.
type Verified struct {
	// Issuer is the issuer whose pinned key verified the signature, the claim iss.
	Issuer string
	// RunKey is the run key, the claim sub.
	RunKey string
	// Expires is the claim exp. The run credential is refused from Expires plus the
	// issuer's leeway on.
	Expires time.Time
	// Claims are the signed claims, decoded with every number a float64. They hold every
	// claim value the run credential carries, personal data among them: never log or
	// record them, or pass them beyond the gateway; Labels and Details are what a run
	// carries.
	Claims map[string]any
	// Labels are the run's labels, forge, repository and run_key ([Issuer.Labels]).
	Labels map[string]string
	// Details are the keys of about.details the run credential decides
	// ([Issuer.Details]); nil when it decides none.
	Details map[string]string
}

// NewVerifier checks the issuers as [Issuers.Check] does, reading each key's
// public_key_file with read, and returns a verifier under their keys. It keeps its own
// copy of the issuers, so a change to them afterwards changes nothing it verifies.
func NewVerifier(issuers Issuers, read ReadFile) (*Verifier, error) {
	return newVerifier(issuers, read, false)
}

// newVerifier is [NewVerifier]; fixtures accepts the published fixture keys, which the
// known-answer tests alone do.
func newVerifier(issuers Issuers, read ReadFile, fixtures bool) (*Verifier, error) {
	if err := issuers.check(read, fixtures); err != nil {
		return nil, err
	}
	v := &Verifier{}
	for n, i := range issuers {
		c, err := cloneIssuer(i)
		if err != nil {
			return nil, fmt.Errorf("run_credentials[%d]: %w", n, err)
		}
		vi := verifierIssuer{issuer: c}
		for k, key := range c.Keys {
			pub, err := key.publicKey(read, fixtures)
			if err != nil {
				return nil, fmt.Errorf("run_credentials[%d]: the starter %s: keys[%d]: %w", n, c.Issuer, k, err)
			}
			vi.keys = append(vi.keys, pub)
		}
		v.issuers = append(v.issuers, vi)
	}
	return v, nil
}

// cloneIssuer is a copy of an issuer that shares no slice, map or pointer with it.
func cloneIssuer(i Issuer) (Issuer, error) {
	b, err := json.Marshal(i)
	if err != nil {
		return Issuer{}, err
	}
	var c Issuer
	if err := json.Unmarshal(b, &c); err != nil {
		return Issuer{}, err
	}
	return c, nil
}

// steps are the steps of the verification in order, as a refusal names them.
var steps = []string{"serialisation", "header", "signature", "claims", "scope", "mapping"}

// Verify verifies a run credential, raw, the JWS compact serialisation (RFC 7515
// §7.1) of a JWT (RFC 7519), at now, and returns what it says. In order:
//
//  1. The serialisation: at most [MaxCredentialBytes] bytes; exactly three parts
//     separated by dots, each base64url without padding, white space or any byte
//     outside its alphabet, and with no bits set beyond its last byte; the header and
//     the payload are not empty.
//  2. The header: one JSON object in UTF-8 with no member name twice, then
//     [Issuer.SelectKey] for each issuer, which selects a pinned key by alg and kid
//     and refuses crit and a typ other than JWT. No claim is read yet.
//  3. The signature, under each key selected, over the exact bytes received before the
//     last dot: RS256 by RSASSA-PKCS1-v1_5 with SHA-256; ES256, exactly 64 bytes, R and
//     S each in [1, n-1], by ECDSA with SHA-256 on P-256; EdDSA by Ed25519.
//  4. The claims: the payload is one JSON object in UTF-8 with no member name twice;
//     among the issuers whose key verified the signature, the one whose issuer equals
//     iss is the run credential's, and [Issuer.CheckClaims] checks the claims under it.
//  5. The scope, [Issuer.Allowed].
//  6. The mapping, [Issuer.Labels] and [Issuer.Details].
//
// Every failure is [ErrRefused], whose text names no claim value and never contains the
// run credential; nothing else of a failure leaves this package.
func (v *Verifier) Verify(raw string, now time.Time) (*Verified, error) {
	return v.verify(raw, now, false)
}

// VerifyExpired verifies a run credential that [Verifier.Verify] refuses at now only
// because its exp has passed, and by less than [MaxLeeway]: every step of Verify, the
// time checks of [Issuer.CheckClaims] made as just before exp. It refuses, as
// [ErrRefused], every other run credential, one that Verify accepts at now among them.
// A gateway uses it only to answer a request of a run that has ended with that end,
// never to serve one.
func (v *Verifier) VerifyExpired(raw string, now time.Time) (*Verified, error) {
	return v.verify(raw, now, true)
}

// verify is [Verifier.Verify], or with expired [Verifier.VerifyExpired].
func (v *Verifier) verify(raw string, now time.Time, expired bool) (*Verified, error) {
	if v == nil || len(v.issuers) == 0 {
		return nil, refuseAt("header", "no starter")
	}
	header, payload, input, sig, err := split(raw)
	if err != nil {
		return nil, err
	}
	var h map[string]any
	if err := decodeObject(header, &h); err != nil {
		return nil, refuseAt("header", "the header is not one JSON object with each member name once")
	}
	// The furthest refusal across the issuers is the one returned, so a run
	// credential of one issuer is refused at the step that refuses it there, not at
	// another issuer's header step.
	var best error
	bestStep := -1
	keep := func(err error) {
		var r *refused
		if errors.As(err, &r) {
			if n := stepIndex(r.step); n > bestStep {
				best, bestStep = err, n
			}
		}
	}
	var claims map[string]any
	var verified []*verifierIssuer
	for n := range v.issuers {
		vi := &v.issuers[n]
		k, err := vi.issuer.SelectKey(h)
		if err != nil {
			keep(at("header", err))
			continue
		}
		if !verifySignature(vi.issuer.Keys[k].Alg, vi.keys[k], input, sig) {
			keep(refuseAt("signature", "the signature does not verify"))
			continue
		}
		verified = append(verified, vi)
	}
	if len(verified) == 0 {
		if best == nil {
			best = refuseAt("header", "no starter's key was selected")
		}
		return nil, best
	}
	// The signature verified: the payload is now the issuer's, and is read.
	if err := decodeObject(payload, &claims); err != nil {
		return nil, refuseAt("claims", "the payload is not one JSON object with each member name once")
	}
	iss, _ := claims["iss"].(string)
	var vi *verifierIssuer
	for _, c := range verified {
		if c.issuer.Issuer == iss {
			vi = c
			break
		}
	}
	if vi == nil {
		return nil, refuseAt("claims", "iss is not that of the starter whose key verified the signature")
	}
	i := &vi.issuer
	checkAt := now
	if expired {
		exp, ok, err := numericDate(claims, "exp")
		if err != nil || !ok {
			return nil, refuseAt("claims", "exp is missing or not a NumericDate")
		}
		switch {
		case now.Before(exp.Add(i.LeewayOrDefault())):
			return nil, refuseAt("claims", "exp has not passed")
		case !now.Before(exp.Add(MaxLeeway)):
			return nil, refuseAt("claims", "exp passed too long ago")
		}
		checkAt = exp.Add(-time.Nanosecond)
	}
	if err := i.CheckClaims(claims, checkAt); err != nil {
		return nil, at("claims", err)
	}
	if !i.Allowed(claims) {
		return nil, refuseAt("scope", "the claim allow names holds no value it lists")
	}
	labels, err := i.Labels(claims)
	if err != nil {
		return nil, at("mapping", err)
	}
	details, err := i.Details(claims)
	if err != nil {
		return nil, at("mapping", err)
	}
	exp, _, _ := numericDate(claims, "exp")
	return &Verified{
		Issuer:  i.Issuer,
		RunKey:  labels[LabelRunKey],
		Expires: exp,
		Claims:  claims,
		Labels:  labels,
		Details: details,
	}, nil
}

// stepIndex is the index of a step in [steps], -1 for none.
func stepIndex(step string) int {
	for n, s := range steps {
		if s == step {
			return n
		}
	}
	return -1
}

// b64 is base64url without padding, refusing bits set beyond the last byte.
var b64 = base64.RawURLEncoding.Strict()

// split splits a run credential into its decoded header and payload, the signing
// input as received, and the decoded signature, refusing every serialisation but the
// one strict form.
func split(raw string) (header, payload []byte, input string, sig []byte, err error) {
	bad := func(reason string) ([]byte, []byte, string, []byte, error) {
		return nil, nil, "", nil, refuseAt("serialisation", reason)
	}
	if len(raw) == 0 || len(raw) > MaxCredentialBytes {
		return bad("empty or longer than MaxCredentialBytes")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return bad("not three parts")
	}
	decoded := make([][]byte, 3)
	for n, p := range parts {
		// The signature alone may be empty, as an unsecured JWS's is (RFC 7515 §7.1),
		// so alg none is refused at the header, by its alg.
		if (p == "" && n < 2) || !base64url(p) {
			return bad("the header or payload is empty, or a part is not base64url without padding")
		}
		d, err := b64.DecodeString(p)
		if err != nil {
			return bad("a part does not decode")
		}
		decoded[n] = d
	}
	return decoded[0], decoded[1], parts[0] + "." + parts[1], decoded[2], nil
}

// base64url reports whether every byte of s is of the base64url alphabet (RFC 4648 §5):
// no padding and no white space, which Go's decoder would otherwise skip.
func base64url(s string) bool {
	for n := 0; n < len(s); n++ {
		c := s[n]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// decodeObject decodes one JSON object through encoding/json/v2, which refuses a
// member name that appears twice and invalid UTF-8, into out.
func decodeObject(b []byte, out *map[string]any) error {
	if len(b) == 0 || b[0] != '{' {
		return errNotObject
	}
	var m map[string]any
	if err := jsonv2.Unmarshal(b, &m); err != nil {
		return err
	}
	if m == nil {
		return errNotObject
	}
	*out = m
	return nil
}

// errNotObject is a part that is not a JSON object.
var errNotObject = errors.New("not a JSON object")

// p256Order is the order n of P-256's base point.
var p256Order, _ = new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

// verifySignature verifies sig over input under pub, by alg.
func verifySignature(alg string, pub crypto.PublicKey, input string, sig []byte) bool {
	switch alg {
	case RS256:
		k, ok := pub.(*rsa.PublicKey)
		if !ok || k.N.BitLen() < MinRSABits || len(sig) != k.Size() {
			return false
		}
		h := sha256.Sum256([]byte(input))
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil
	case ES256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() || len(sig) != 64 {
			return false
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !inOrder(r) || !inOrder(s) {
			return false
		}
		h := sha256.Sum256([]byte(input))
		return ecdsa.Verify(k, h[:], r, s)
	case EdDSA:
		k, ok := pub.(ed25519.PublicKey)
		if !ok || len(k) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
			return false
		}
		return ed25519.Verify(k, []byte(input), sig)
	}
	return false
}

// inOrder reports whether v is in [1, n-1], n the order of P-256.
func inOrder(v *big.Int) bool { return v.Sign() > 0 && v.Cmp(p256Order) < 0 }
