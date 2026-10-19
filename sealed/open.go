package sealed

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
)

// AccessKey is the access key an envelope is sealed to: its id, ak_ and 16 lower-case
// Crockford base32 characters, and the key, read from its secret.
type AccessKey struct {
	ID  string
	Key *accesskey.Key
}

// Envelope is the sealed member of a secrets answer, decoded: the identifiers as the
// server wrote them, and enc, ct and sig as bytes.
type Envelope struct {
	Suite            string
	AccessKeyID      string
	RunID            string
	RunConfiguration string
	Exp              uint64
	// Enc is the sender's ephemeral X25519 public key, 32 bytes.
	Enc []byte
	// CT is the ciphertext of the plaintext followed by the 16-byte tag.
	CT []byte
	// Sig is the Ed25519 signature under the server's key over [Envelope.Message].
	Sig []byte
}

// Message returns what the envelope's sig covers: lp32 of "qory envelope v1", the
// suite, the access key id, the run id, the run configuration's digest, exp in
// canonical decimal, enc and ct, the last two raw; lp32 is a u32 big-endian length,
// then the bytes.
func (e *Envelope) Message() []byte {
	var m []byte
	for _, s := range []string{EnvelopeDomain, e.Suite, e.AccessKeyID, e.RunID, e.RunConfiguration, strconv.FormatUint(e.Exp, 10)} {
		m = lp32(m, []byte(s))
	}
	return lp32(lp32(m, e.Enc), e.CT)
}

// Info returns HPKE's info for an access key: "qory secrets v1", a zero byte, the
// suite's three identifiers as u16 big-endian, and lp(access key id); lp is a u16
// big-endian length, then the bytes.
func Info(accessKeyID string) []byte {
	b := append([]byte(InfoDomain), 0)
	for _, id := range []uint16{KEMID, KDFID, AEADID} {
		b = binary.BigEndian.AppendUint16(b, id)
	}
	return lp(b, accessKeyID)
}

// AAD returns the associated data of the open: lp(run id), lp(access key id),
// lp(run configuration digest) and lp(exp in canonical decimal).
func AAD(runID, accessKeyID, digest string, exp uint64) []byte {
	var b []byte
	for _, s := range []string{runID, accessKeyID, digest, strconv.FormatUint(exp, 10)} {
		b = lp(b, s)
	}
	return b
}

// lp is a u16 big-endian length, then the bytes. Every value it is given is bounded by
// a pattern of the contract far below 65536 bytes.
func lp(b []byte, s string) []byte {
	return append(binary.BigEndian.AppendUint16(b, uint16(len(s))), s...)
}

// lp32 is a u32 big-endian length, then the bytes.
func lp32(b, v []byte) []byte {
	return append(binary.BigEndian.AppendUint32(b, uint32(len(v))), v...)
}

// The forms of the identifiers, as the contract's schemas give them.
var (
	runIDShape   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestShape  = regexp.MustCompile(`^sha256=[0-9a-f]{64}$`)
	nameShape    = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	integerShape = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,15})$`)
)

// maxInteger is 2^53 − 1, the largest integer the schemas allow.
const maxInteger = 1<<53 - 1

// unsigned reads a JSON number that is an integer below 2^53 with no sign, fraction or
// exponent.
func unsigned(v jsontext.Value) (uint64, bool) {
	if !integerShape.Match(v) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(v), 10, 64)
	return n, err == nil && n <= maxInteger
}

// decode decodes base64url without padding strictly: padding, a character of the
// standard alphabet, a line break and non-zero bits after the last full byte are
// refused.
func decode(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, base64.CorruptInputError(0)
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// answerSchema is secrets-answer.schema.json, compiled once.
var answerSchema = sync.OnceValues(func() (*jsonschema.Schema, error) { return contracts.Compile("secrets-answer.schema.json") })

// answerDocument is a secrets answer as it is decoded, exp kept as its raw number so
// its form is checked.
type answerDocument struct {
	Version jsontext.Value `json:"version"`
	Sealed  struct {
		Suite            string         `json:"suite"`
		AccessKeyID      string         `json:"access_key_id"`
		RunID            string         `json:"run_id"`
		RunConfiguration string         `json:"run_configuration"`
		Exp              jsontext.Value `json:"exp"`
		Enc              string         `json:"enc"`
		CT               string         `json:"ct"`
		Sig              string         `json:"sig"`
	} `json:"sealed"`
}

// readEnvelope reads a secrets answer: one JSON document with each member name once
// and no member the schema does not define; a suite other than [Suite] is [ErrSuite],
// before the schema; then the schema; exp a JSON integer with no sign, fraction or
// exponent; and enc, ct and sig base64url without padding, decoded strictly, of 32, at
// least 16 and 64 bytes. Anything else is [ErrAnswer], whose text quotes nothing of the
// answer.
func readEnvelope(answer []byte) (*Envelope, error) {
	var d answerDocument
	if len(answer) > MaxAnswer || jsonv2.Unmarshal(answer, &d, jsonv2.RejectUnknownMembers(true)) != nil {
		return nil, ErrAnswer
	}
	s := d.Sealed
	if string(d.Version) == "1" && s.Suite != "" && s.Suite != Suite {
		return nil, ErrSuite
	}
	schema, err := answerSchema()
	if err != nil {
		return nil, refuse(ErrAnswer, "secrets-answer.schema.json does not compile: %v", err)
	}
	doc, err := contracts.Decode("secrets-answer.json", answer)
	if err != nil || schema.Validate(doc) != nil {
		return nil, ErrAnswer
	}
	exp, ok := unsigned(s.Exp)
	if !ok {
		return nil, ErrAnswer
	}
	enc, err1 := decode(s.Enc)
	ct, err2 := decode(s.CT)
	sig, err3 := decode(s.Sig)
	if err1 != nil || err2 != nil || err3 != nil || len(enc) != 32 || len(ct) < 16 || len(sig) != 64 {
		return nil, ErrAnswer
	}
	return &Envelope{Suite: s.Suite, AccessKeyID: s.AccessKeyID, RunID: s.RunID, RunConfiguration: s.RunConfiguration,
		Exp: exp, Enc: enc, CT: ct, Sig: sig}, nil
}

// checkRequest refuses a call whose access key, run id, digest or credentials are
// outside the contract's forms, with [ErrRequest].
func checkRequest(key AccessKey, runID, digest string, requested []string) error {
	if accesskey.CheckID(key.ID) != nil || key.Key == nil {
		return refuse(ErrRequest, "it needs an access key id of the form ak_ and 16 characters, and the access key")
	}
	if !runIDShape.MatchString(runID) || !digestShape.MatchString(digest) {
		return refuse(ErrRequest, "the run id or the digest is outside its form")
	}
	if len(requested) < 1 || len(requested) > MaxCredentials {
		return refuse(ErrRequest, "it lists %d credentials, and a request lists 1 to %d", len(requested), MaxCredentials)
	}
	for i, name := range requested {
		if !nameShape.MatchString(name) || slices.Contains(requested[:i], name) {
			return refuse(ErrRequest, "the credential %s is outside the grammar or listed twice", accesskey.ShownName(name, true))
		}
	}
	return nil
}

// Open checks and opens a secrets answer for the request the caller sent: the run id,
// the run configuration's digest, which the caller computed from the bytes it
// received, and the requested credentials. It checks, in order: the call's forms,
// [ErrRequest]; the answer's form, [ErrAnswer], a suite other than [Suite] being
// [ErrSuite] before the schema; sig under the pin, [ErrSignature]; the access key id,
// [ErrAccessKey], the run id, [ErrRun], and the digest, [ErrDigest], against the
// caller's; exp against now, [ErrExpired] more than [ExpiredAfter] seconds past and
// [ErrAhead] more than [AheadBy] seconds ahead, both bounds inclusive of the window;
// the open with info and aad from the caller's values, [ErrOpen]; then the plaintext,
// as [Plaintext] checks it. Open writes the values nowhere; on an error it returns
// none.
func Open(answer []byte, key AccessKey, pin accesskey.Pin, runID, digest string, requested []string, now time.Time) (Values, error) {
	if err := checkRequest(key, runID, digest, requested); err != nil {
		return Values{}, err
	}
	e, err := readEnvelope(answer)
	if err != nil {
		return Values{}, err
	}
	if !pin.Verify(e.Message(), base64.RawURLEncoding.EncodeToString(e.Sig)) {
		return Values{}, ErrSignature
	}
	switch {
	case e.AccessKeyID != key.ID:
		return Values{}, refuse(ErrAccessKey, "sealed to %s, and the access key is %s", e.AccessKeyID, key.ID)
	case e.RunID != runID:
		return Values{}, refuse(ErrRun, "for %s, and the run is %s", e.RunID, runID)
	case e.RunConfiguration != digest:
		return Values{}, refuse(ErrDigest, "for %s, and the run configuration is %s", e.RunConfiguration, digest)
	}
	exp, t := int64(e.Exp), now.Unix()
	switch {
	case t > exp+ExpiredAfter:
		return Values{}, refuse(ErrExpired, "exp %d, the clock %d", exp, t)
	case exp > t+AheadBy:
		return Values{}, refuse(ErrAhead, "exp %d, the clock %d", exp, t)
	}
	pt, err := open(key.Key, e.Enc, e.CT, Info(key.ID), AAD(runID, key.ID, digest, e.Exp))
	if err != nil {
		return Values{}, ErrOpen
	}
	defer clear(pt)
	return Plaintext(pt, digest, requested)
}

// suite returns the suite's three parts as crypto/hpke defines them.
func suite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.AES256GCM()
}

// open opens ct with the access key's X25519 key: NewRecipient with info, then Open on
// the context with aad, since the single-shot Open takes no aad.
func open(key *accesskey.Key, enc, ct, info, aad []byte) ([]byte, error) {
	kem, kdf, aead := suite()
	scalar := key.X25519PrivateKey()
	defer clear(scalar)
	priv, err := kem.NewPrivateKey(scalar)
	if err != nil {
		return nil, err
	}
	r, err := hpke.NewRecipient(enc, priv, kdf, aead, info)
	if err != nil {
		return nil, err
	}
	return r.Open(aad, ct)
}
