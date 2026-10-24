package sealed

import (
	"bytes"
	"cmp"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/qoryai/forager/accesskey"
)

// Value is one value as the server seals it: the credential's name, the value, and
// optionally when it expires and where it is set. The value is returned by a func, so a
// Value printed by reflection, as an unexported field of a struct, prints the func's
// address and no byte of it; a Value formats as its credential's name alone whatever
// the verb. Make one with [NewValue].
type Value struct {
	Credential string
	// ExpiresAt is when the value stops working, written as RFC 3339 in UTC; zero
	// writes no expires_at.
	ExpiresAt time.Time
	// Apply is where and how the value is set; nil writes no apply.
	Apply []Apply
	value func() []byte
}

// NewValue returns the Value of a credential. It keeps value, not a copy: the caller
// clears value after [Seal] returns.
func NewValue(credential string, value []byte) Value {
	return Value{Credential: credential, value: func() []byte { return value }}
}

// bytes returns the value, or nil for a Value not made by NewValue.
func (v Value) bytes() []byte {
	if v.value == nil {
		return nil
	}
	return v.value()
}

// String returns the credential's name and nothing of the value.
func (v Value) String() string {
	return "the sealed value of " + accesskey.ShownName(v.Credential, true)
}

// GoString returns what String returns.
func (v Value) GoString() string { return v.String() }

// Format writes what String returns, whatever the verb.
func (v Value) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, v.String()) }

// Sealing is what the server seals for one secrets request: to the access key the
// request verified under, for the run and the digest of its run configuration, the
// request's credentials and a value for each, with exp. A Sealing formats as its count
// of values and its run whatever the verb; printed by reflection, its Values print as
// each Value does.
type Sealing struct {
	AccessKeyID string
	// PublicKey is the access key's Ed25519 public key, whose X25519 u-coordinate the
	// values are sealed to.
	PublicKey        accesskey.PublicKey
	RunID            string
	RunConfiguration string
	// Credentials is the request's list, in any order.
	Credentials []string
	Values      []Value
	Exp         uint64
}

// String returns how many values the sealing has and for which run, and nothing of
// the values.
func (s Sealing) String() string {
	return fmt.Sprintf("a sealing of %d values for the run %s", len(s.Values), accesskey.ShownName(s.RunID, true))
}

// GoString returns what String returns.
func (s Sealing) GoString() string { return s.String() }

// Format writes what String returns, whatever the verb.
func (s Sealing) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

// Expiry returns exp for an envelope sealed at the server's clock now, in Unix
// seconds: now plus [Lifetime].
func Expiry(now time.Time) uint64 { return uint64(now.Unix()) + Lifetime }

// plaintextSize is an upper bound of the plaintext's length: JSON escapes a byte in at
// most 6 bytes, \u001f say, and every identifier and the digest are ASCII.
func plaintextSize(digest string, credentials []string, values []Value, metas [][]byte) int {
	n := len(`{"version":1,"run_configuration":"","credentials":[],"values":[]}`) + len(digest)
	for _, c := range credentials {
		n += len(c) + 3
	}
	for i, v := range values {
		n += len(`{"credential":"","value":""},`) + len(v.Credential) + 6*len(v.bytes()) + len(metas[i])
	}
	return n
}

// metaJSON is what the plaintext writes of a value after the value: expires_at, then
// apply with each item's hosts, scheme, username, header and paths, the last three only
// when set. It holds no secret. It refuses, with [ErrRequest], an apply that
// sealed-plaintext.schema.json refuses, as [readMeta] reads it.
func metaJSON(v Value) ([]byte, error) {
	var expires, apply []byte
	if !v.ExpiresAt.IsZero() {
		expires, _ = jsontext.AppendQuote(nil, v.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if v.Apply != nil {
		list := func(b []byte, name string, items []string) []byte {
			b = append(b, `"`+name+`":[`...)
			for i, s := range items {
				if i > 0 {
					b = append(b, ',')
				}
				b, _ = jsontext.AppendQuote(b, s)
			}
			return append(b, ']')
		}
		apply = []byte{'['}
		for i, a := range v.Apply {
			if i > 0 {
				apply = append(apply, ',')
			}
			apply = list(append(apply, '{'), "hosts", a.Hosts)
			apply = append(apply, `,"scheme":`...)
			apply, _ = jsontext.AppendQuote(apply, a.Scheme)
			if a.Username != "" {
				apply = append(apply, `,"username":`...)
				apply, _ = jsontext.AppendQuote(apply, a.Username)
			}
			if a.Header != "" {
				apply = append(apply, `,"header":`...)
				apply, _ = jsontext.AppendQuote(apply, a.Header)
			}
			if a.Paths != nil {
				apply = list(append(apply, ','), "paths", a.Paths)
			}
			apply = append(apply, '}')
		}
		apply = append(apply, ']')
	}
	if _, ok := readMeta(v.Credential, expires, apply); !ok {
		return nil, refuse(ErrRequest, "the expires_at or the apply of the credential %s is outside sealed-plaintext.schema.json", accesskey.ShownName(v.Credential, true))
	}
	var b []byte
	if expires != nil {
		b = append(append(b, `,"expires_at":`...), expires...)
	}
	if apply != nil {
		b = append(append(b, `,"apply":`...), apply...)
	}
	return b, nil
}

// Plaintext returns what the envelope seals: compact JSON of version,
// run_configuration, the credentials sorted, and the values sorted by credential, each
// written credential and then value. It refuses, with [ErrRequest], a sealing whose
// identifiers are outside their forms, whose credentials are not 1 to
// [MaxCredentials] names each once, or whose values are not one for each credential;
// and, with [ErrValue], a value that is not 1 to [MaxValueBytes] bytes of UTF-8 without
// a NUL. Its buffer is allocated once at [plaintextSize], so append writes the values
// into no other buffer. The caller clears what it returns.
func (s Sealing) Plaintext() ([]byte, error) {
	if accesskey.CheckID(s.AccessKeyID) != nil || !runIDShape.MatchString(s.RunID) || !digestShape.MatchString(s.RunConfiguration) || s.Exp > maxInteger {
		return nil, refuse(ErrRequest, "the access key id, the run id, the digest or exp is outside its form")
	}
	if len(s.Credentials) < 1 || len(s.Credentials) > MaxCredentials || len(s.Values) != len(s.Credentials) {
		return nil, refuse(ErrRequest, "it lists %d credentials and %d values, and a sealing has 1 to %d credentials and one value for each", len(s.Credentials), len(s.Values), MaxCredentials)
	}
	credentials := slices.Sorted(slices.Values(s.Credentials))
	values := slices.Clone(s.Values)
	slices.SortFunc(values, func(a, b Value) int { return cmp.Compare(a.Credential, b.Credential) })
	for i, name := range credentials {
		if !nameShape.MatchString(name) || (i > 0 && credentials[i-1] == name) {
			return nil, refuse(ErrRequest, "the credential %s is outside the grammar or listed twice", accesskey.ShownName(name, true))
		}
		if values[i].Credential != name {
			return nil, refuse(ErrRequest, "the values are not one for each credential")
		}
		if v := values[i].bytes(); len(v) == 0 || len(v) > MaxValueBytes || bytes.IndexByte(v, 0) >= 0 {
			return nil, refuse(ErrValue, "the value of the credential %s", accesskey.ShownName(name, true))
		}
	}
	metas := make([][]byte, len(values))
	for i, v := range values {
		m, err := metaJSON(v)
		if err != nil {
			return nil, err
		}
		metas[i] = m
	}
	size := plaintextSize(s.RunConfiguration, credentials, values, metas)
	b := make([]byte, 0, size)
	b = append(b, `{"version":1,"run_configuration":`...)
	b, _ = jsontext.AppendQuote(b, s.RunConfiguration)
	b = append(b, `,"credentials":[`...)
	for i, name := range credentials {
		if i > 0 {
			b = append(b, ',')
		}
		b, _ = jsontext.AppendQuote(b, name)
	}
	b = append(b, `],"values":[`...)
	for i, v := range values {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"credential":`...)
		b, _ = jsontext.AppendQuote(b, v.Credential)
		b = append(b, `,"value":`...)
		var err error
		if b, err = jsontext.AppendQuote(b, v.bytes()); err != nil {
			clear(b[:cap(b)])
			return nil, refuse(ErrValue, "the value of the credential %s", accesskey.ShownName(v.Credential, true))
		}
		b = append(append(b, metas[i]...), '}')
	}
	b = append(b, "]}"...)
	if cap(b) != size {
		// Unreachable while plaintextSize bounds the length: append moved the buffer,
		// and the old one, which this package cannot reach, has the values.
		clear(b[:cap(b)])
		return nil, errors.New("report this bug in package sealed to the Forager maintainers: the plaintext is longer than its buffer")
	}
	return b, nil
}

// sender seals pt to the recipient's X25519 public key with info and aad, returning
// enc and the ciphertext with its tag. [hpkeSender] is the one [Seal] uses; the
// package's known-answer test passes one with the published fixed ephemeral key.
type sender func(pkR, info, aad, pt []byte) (enc, ct []byte, err error)

// hpkeSender is crypto/hpke's NewSender, with a fresh ephemeral key from the system's
// random source, and then Seal on the context with aad.
func hpkeSender(pkR, info, aad, pt []byte) ([]byte, []byte, error) {
	kem, kdf, aead := suite()
	pub, err := kem.NewPublicKey(pkR)
	if err != nil {
		return nil, nil, err
	}
	enc, s, err := hpke.NewSender(pub, kdf, aead, info)
	if err != nil {
		return nil, nil, err
	}
	ct, err := s.Seal(aad, pt)
	return enc, ct, err
}

// Seal returns the body of a secrets answer: the sealing's plaintext sealed to the
// access key's X25519 public key with a fresh ephemeral key, info and aad from the
// sealing's values, and the envelope signed under the server's key. It refuses a
// sealing [Sealing.Plaintext] refuses, and a public key [accesskey.PublicKey.X25519]
// refuses.
func Seal(s Sealing, signer *accesskey.Key) ([]byte, error) { return seal(s, signer, hpkeSender) }

func seal(s Sealing, signer *accesskey.Key, send sender) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("pass the server's signing key to Seal; sealing needs it")
	}
	u, err := s.PublicKey.X25519()
	if err != nil {
		return nil, err
	}
	pt, err := s.Plaintext()
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	enc, ct, err := send(u, Info(s.AccessKeyID), AAD(s.RunID, s.AccessKeyID, s.RunConfiguration, s.Exp), pt)
	if err != nil {
		return nil, err
	}
	e := Envelope{Suite: Suite, AccessKeyID: s.AccessKeyID, RunID: s.RunID, RunConfiguration: s.RunConfiguration, Exp: s.Exp, Enc: enc, CT: ct}
	b64 := base64.RawURLEncoding.EncodeToString
	b := []byte(`{"version":1,"sealed":{`)
	for i, m := range []struct{ name, value string }{
		{"suite", Suite}, {"access_key_id", s.AccessKeyID}, {"run_id", s.RunID}, {"run_configuration", s.RunConfiguration},
	} {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, `"`+m.name+`":`...)
		b, _ = jsontext.AppendQuote(b, m.value)
	}
	b = append(b, `,"exp":`+strconv.FormatUint(s.Exp, 10)...)
	b = append(b, `,"enc":"`+b64(enc)+`","ct":"`+b64(ct)+`","sig":"`+b64(signer.Sign(e.Message()))+`"}}`...)
	return b, nil
}
