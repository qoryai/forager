// Package runcredential is the run credential of the contract, contracts/forager/v1: the
// configuration of the issuers a gateway accepts, its checks, the checks of a run
// credential's claims, and the mapping of its claims to a run's labels and
// about.details.
//
// A run credential is a JWT (RFC 7519) signed as a JWS (RFC 7515) with an asymmetric
// key, which an issuer gives one run. A gateway verifies it in four steps: the header
// selects a pinned key ([Issuer.SelectKey]), the signature is verified under it, the
// claims are checked ([Issuer.CheckClaims]), and the scope is checked ([Issuer.Allowed]).
// The labels and the details are then made from the claims ([Issuer.Labels],
// [Issuer.Details]), and what a session sends beside the run credential is compared
// with them ([Compare]).
//
// The signature step is the gateway's: every function of this package that reads
// claims takes claims a verifier has already verified, and reads nothing else of the
// request. Every failure of a run credential is one opaque error, [ErrRefused], which
// a gateway answers with [Refused]: the error names no claim value and never contains
// the run credential.
package runcredential

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/server"
)

// The algorithms a run credential may be signed with (RFC 7518 §3.3 and §3.4, RFC 8037
// §3.1). none and every HMAC algorithm are not among them: a gateway holds public keys
// alone, so no run credential is checked as HMAC under one.
const (
	// RS256 is RSASSA-PKCS1-v1_5 with SHA-256, under an RSA key of at least 2048 bits.
	RS256 = "RS256"
	// ES256 is ECDSA with SHA-256 under a P-256 key, the signature R and S, 32 bytes each.
	ES256 = "ES256"
	// EdDSA is EdDSA under an Ed25519 key. Ed448 is not accepted.
	EdDSA = "EdDSA"
)

// supported reports whether alg is one of the algorithms a run credential may be
// signed with.
func supported(alg string) bool { return alg == RS256 || alg == ES256 || alg == EdDSA }

// DefaultLeeway is the clock skew allowed in the time checks when an issuer sets none.
const DefaultLeeway = 60 * time.Second

// MinRSABits is the smallest RSA modulus a pinned RS256 key may have, in bits.
const MinRSABits = 2048

// The label keys the mapping sets: every run's labels are these three, made from the
// run credential alone.
const (
	// LabelForge is the forge of the run's target.
	LabelForge = "forge"
	// LabelRepository is the repository of the run's target.
	LabelRepository = "repository"
	// LabelRunKey is the run key, the claim sub.
	LabelRunKey = "run_key"
)

// Issuers is the list under gateway.run_credentials of the operator's forager.yaml,
// the document run-credentials.schema.json defines.
type Issuers []Issuer

// Issuer is one issuer of run credentials: who it is, the audience it mints them for,
// its pinned keys, the claim checks and the mapping of its claims.
type Issuer struct {
	// Issuer is the https URL the claim iss equals.
	Issuer string `json:"issuer"`
	// Audience is the gateway's own audience, which the claim aud contains.
	Audience string `json:"audience"`
	// Algorithms are the algorithms the issuer signs with.
	Algorithms []string `json:"algorithms"`
	// Keys are the issuer's pinned public keys.
	Keys []Key `json:"keys"`
	// Leeway is the clock skew the time checks allow; nil is [DefaultLeeway].
	Leeway *Duration `json:"leeway,omitempty"`
	// MaxLifetime bounds exp minus iat when it is set.
	MaxLifetime *Duration `json:"max_lifetime,omitempty"`
	// Allow is the scope, nil when the issuer sets none.
	Allow *Allow `json:"allow,omitempty"`
	// LabelMapping is the mapping of claims to the run's labels, labels in the
	// document.
	LabelMapping LabelMapping `json:"labels"`
	// DetailMapping is the mapping of claims to keys of about.details, by key, details
	// in the document.
	DetailMapping map[string]Claim `json:"details,omitempty"`
	// Introspection is the issuer's RFC 7662 endpoint, nil when it offers none.
	Introspection *Introspection `json:"introspection,omitempty"`
}

// Key is one pinned public key of an issuer.
type Key struct {
	// KID is the key id a run credential's kid header names, empty when the issuer pins
	// one key without one.
	KID string `json:"kid,omitempty"`
	// Alg is the algorithm the key signs with, one of [RS256], [ES256] and [EdDSA].
	Alg string `json:"alg"`
	// PublicKeyFile is the file of the key, one PEM block of type PUBLIC KEY.
	PublicKeyFile string `json:"public_key_file"`
}

// Allow is the scope: the claim must be a string, one of the values.
type Allow struct {
	Claim  string   `json:"claim"`
	Values []string `json:"values"`
}

// LabelMapping is the mapping of claims to the run's three labels.
type LabelMapping struct {
	// Forge is a constant or a claim.
	Forge Source `json:"forge"`
	// Repository is the claims that name the target joined with a separator, one
	// claim, or a constant.
	Repository Source `json:"repository"`
	// RunKey is always the claim sub.
	RunKey Claim `json:"run_key"`
}

// Source is where a label's value comes from: exactly one of Value, Claim and Claims,
// with Join beside Claims.
type Source struct {
	// Value is a constant.
	Value string `json:"value,omitempty"`
	// Claim is one claim, a string.
	Claim string `json:"claim,omitempty"`
	// Claims are claims, each a string, joined in order with Join.
	Claims []string `json:"claims,omitempty"`
	// Join is the separator between the values of Claims.
	Join string `json:"join,omitempty"`
}

// Claim names one claim, a string.
type Claim struct {
	Claim string `json:"claim"`
}

// Introspection is an issuer's OAuth 2.0 token introspection endpoint (RFC 7662).
type Introspection struct {
	// URL is the endpoint, https.
	URL string `json:"url"`
	// ClientID is the client the gateway authenticates as.
	ClientID string `json:"client_id"`
	// ClientSecretFile is the file of the client's secret.
	ClientSecretFile string `json:"client_secret_file"`
	// Cache is how long an answer holds; nil is the run's heartbeat interval.
	Cache *Duration `json:"cache,omitempty"`
}

// Duration is a duration as the configuration writes it: a Go duration string such as
// 60s or 1h30m.
type Duration time.Duration

// UnmarshalJSON reads a duration string.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// MarshalJSON writes the duration as Go writes it.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// LeewayOrDefault is the issuer's leeway, or [DefaultLeeway] when it sets none.
func (i Issuer) LeewayOrDefault() time.Duration {
	if i.Leeway == nil {
		return DefaultLeeway
	}
	return time.Duration(*i.Leeway)
}

// CacheOr is how long an introspection answer holds: the configured cache, or
// heartbeat, the run's heartbeat interval, when it sets none.
func (in Introspection) CacheOr(heartbeat time.Duration) time.Duration {
	if in.Cache == nil {
		return heartbeat
	}
	return time.Duration(*in.Cache)
}

// Parse validates the bytes of a run credentials document, the list under
// gateway.run_credentials, against run-credentials.schema.json and decodes it. name
// chooses YAML or JSON by its extension, JSON when it has none. A member the schema
// does not define is refused. Parse reads no file: [Issuers.Check] does.
func Parse(name string, b []byte) (Issuers, error) {
	if !strings.Contains(name, ".") {
		name += ".json"
	}
	doc, err := contracts.Decode(name, b)
	if err != nil {
		return nil, err
	}
	schema, err := contracts.Compile("run-credentials.schema.json")
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(doc); err != nil {
		return nil, fmt.Errorf("run credentials %s: %w", name, err)
	}
	j, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var out Issuers
	if err := json.Unmarshal(j, &out); err != nil {
		return nil, fmt.Errorf("run credentials %s: %w", name, err)
	}
	return out, nil
}

// ReadFile reads a file by its name, as os.ReadFile does.
type ReadFile func(name string) ([]byte, error)

// Check checks every issuer as [Issuer.Check] does, and that no two have the same
// issuer. An empty list is refused: a gateway without issuers serves no other machine.
func (l Issuers) Check(read ReadFile) error { return l.check(read, false) }

// check is [Issuers.Check]; fixtures accepts the published fixture keys, which the
// known-answer tests alone do.
func (l Issuers) check(read ReadFile, fixtures bool) error {
	if len(l) == 0 {
		return fmt.Errorf("run credentials: no issuer")
	}
	seen := map[string]bool{}
	for n, i := range l {
		if seen[i.Issuer] {
			return fmt.Errorf("run credentials: the issuer %s appears twice", i.Issuer)
		}
		seen[i.Issuer] = true
		if err := i.check(read, fixtures); err != nil {
			return fmt.Errorf("run credentials[%d]: %w", n, err)
		}
	}
	return nil
}

// Check checks an issuer beyond what the schema states, and the rules the schema
// states that guard the run credential, so an Issuer built in Go is held to them too:
//
//   - the issuer is an https URL with a host and no user, query or fragment, and the
//     audience is not empty;
//   - every algorithm is RS256, ES256 or EdDSA, each once;
//   - every key's alg is among the algorithms; with more than one key every key has a
//     kid, and no two have the same;
//   - each key's public_key_file, read with read, is one PEM block of type PUBLIC KEY of
//     the key type its alg needs, and none of the published fixture keys (see
//     [Key.PublicKey]);
//   - the leeway is not negative, and max_lifetime and the introspection cache are
//     positive when they are set;
//   - the scope, the labels and the details are well formed: forge is a constant or a
//     claim, repository a constant, a claim, or claims with a join, run_key the claim
//     sub, a constant a label value of 1 to 256 bytes of UTF-8 with no control
//     character, a join UTF-8 with no control character, and a details key 1 to 64
//     bytes with no control character and no =, since a refusal names a key as
//     about.details.<key>=<value>;
//   - the introspection endpoint is https, with a client id and a secret's file. The
//     secret is not read here.
//
// The error names the issuer, the member and a file's name, never what a file holds.
func (i Issuer) Check(read ReadFile) error { return i.check(read, false) }

// check is [Issuer.Check]; fixtures accepts the published fixture keys, which the
// known-answer tests alone do.
func (i Issuer) check(read ReadFile, fixtures bool) error {
	if err := checkHTTPS(i.Issuer); err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if i.Audience == "" {
		return fmt.Errorf("issuer %s: no audience", i.Issuer)
	}
	if len(i.Algorithms) == 0 {
		return fmt.Errorf("issuer %s: no algorithm", i.Issuer)
	}
	algs := map[string]bool{}
	for _, a := range i.Algorithms {
		if !supported(a) {
			return fmt.Errorf("issuer %s: the algorithm %q is not RS256, ES256 or EdDSA", i.Issuer, a)
		}
		if algs[a] {
			return fmt.Errorf("issuer %s: the algorithm %s appears twice", i.Issuer, a)
		}
		algs[a] = true
	}
	if len(i.Keys) == 0 {
		return fmt.Errorf("issuer %s: no key", i.Issuer)
	}
	kids := map[string]bool{}
	for n, k := range i.Keys {
		if !algs[k.Alg] {
			return fmt.Errorf("issuer %s: keys[%d]: the alg %q is not among the issuer's algorithms", i.Issuer, n, k.Alg)
		}
		if len(i.Keys) > 1 && k.KID == "" {
			return fmt.Errorf("issuer %s: keys[%d]: no kid, and the issuer pins more than one key", i.Issuer, n)
		}
		if k.KID != "" {
			if kids[k.KID] {
				return fmt.Errorf("issuer %s: keys[%d]: the kid %q appears twice", i.Issuer, n, k.KID)
			}
			kids[k.KID] = true
		}
		if _, err := k.publicKey(read, fixtures); err != nil {
			return fmt.Errorf("issuer %s: keys[%d]: %w", i.Issuer, n, err)
		}
	}
	if i.Leeway != nil && *i.Leeway < 0 {
		return fmt.Errorf("issuer %s: the leeway is negative", i.Issuer)
	}
	if i.MaxLifetime != nil && *i.MaxLifetime <= 0 {
		return fmt.Errorf("issuer %s: max_lifetime is not positive", i.Issuer)
	}
	if a := i.Allow; a != nil {
		if a.Claim == "" || len(a.Values) == 0 {
			return fmt.Errorf("issuer %s: allow names no claim or no value", i.Issuer)
		}
		for _, v := range a.Values {
			if v == "" {
				return fmt.Errorf("issuer %s: allow lists an empty value", i.Issuer)
			}
		}
	}
	if err := i.LabelMapping.check(); err != nil {
		return fmt.Errorf("issuer %s: labels: %w", i.Issuer, err)
	}
	for key, c := range i.DetailMapping {
		if !detailsKey(key) {
			return fmt.Errorf("issuer %s: the details key %q is not 1 to 64 bytes without a control character or =", i.Issuer, key)
		}
		if c.Claim == "" {
			return fmt.Errorf("issuer %s: details.%s names no claim", i.Issuer, key)
		}
	}
	if in := i.Introspection; in != nil {
		if err := checkHTTPS(in.URL); err != nil {
			return fmt.Errorf("issuer %s: introspection: %w", i.Issuer, err)
		}
		if in.ClientID == "" || in.ClientSecretFile == "" {
			return fmt.Errorf("issuer %s: introspection: no client id or no client secret file", i.Issuer)
		}
		if in.Cache != nil && *in.Cache <= 0 {
			return fmt.Errorf("issuer %s: introspection: the cache is not positive", i.Issuer)
		}
	}
	return nil
}

// check checks the mapping of claims to labels.
func (l LabelMapping) check() error {
	if err := l.Forge.check(false); err != nil {
		return fmt.Errorf("forge: %w", err)
	}
	if err := l.Repository.check(true); err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	if l.RunKey.Claim != "sub" {
		return fmt.Errorf("run_key: the claim is %q; the run key is always sub", l.RunKey.Claim)
	}
	return nil
}

// check checks a label's source: exactly one of a constant, a claim and, when claims
// is true, claims with a join.
func (s Source) check(claims bool) error {
	n := 0
	if s.Value != "" {
		n++
		if err := server.CheckLabels(map[string]string{"value": s.Value}); err != nil {
			return fmt.Errorf("the value is longer than 256 bytes or not UTF-8")
		}
		if !plain(s.Value) {
			return fmt.Errorf("the value holds a control character")
		}
	}
	if s.Claim != "" {
		n++
	}
	if len(s.Claims) > 0 {
		if !claims {
			return fmt.Errorf("claims are not allowed here; give a value or a claim")
		}
		n++
		for _, c := range s.Claims {
			if c == "" {
				return fmt.Errorf("claims lists an empty name")
			}
		}
		if s.Join == "" {
			return fmt.Errorf("claims without a join")
		}
		if !plain(s.Join) {
			return fmt.Errorf("the join is not UTF-8 or holds a control character")
		}
	} else if s.Join != "" {
		return fmt.Errorf("a join without claims")
	}
	if n != 1 && claims {
		return fmt.Errorf("give exactly one of a value, a claim and claims")
	}
	if n != 1 {
		return fmt.Errorf("give exactly one of a value and a claim")
	}
	return nil
}

// checkHTTPS checks an https URL with a host and no user, query or fragment.
func checkHTTPS(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") {
		return fmt.Errorf("%q is not an https URL with a host and no user, query or fragment", s)
	}
	return nil
}

// detailsKey reports whether key follows the grammar of an about.details key, 1 to 64
// bytes of UTF-8 with no control character, and holds no =: a refusal names a key as
// about.details.<key>=<value>, and a key with = would make that name ambiguous.
func detailsKey(key string) bool {
	return key != "" && len(key) <= 64 && plain(key) && !strings.Contains(key, "=")
}

// plain reports whether s is UTF-8 with no control character as the contract counts
// them: U+0000 to U+001F, U+007F to U+009F, U+2028 and U+2029.
func plain(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r <= 0x1f || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 {
			return false
		}
	}
	return true
}
