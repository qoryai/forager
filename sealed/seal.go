package sealed

import (
	"bytes"
	"cmp"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/qoryai/forager/accesskey"
)

// Value is one value as the server seals it: the credential's name and the value.
type Value struct {
	Credential string
	Value      []byte
}

// Sealing is what the server seals for one secrets request: to the access key the
// request verified under, for the run and the digest of its run configuration, the
// request's credentials and a value for each, with exp.
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

// Expiry returns exp for an envelope sealed at the server's clock now, in Unix
// seconds: now plus [Lifetime].
func Expiry(now time.Time) uint64 { return uint64(now.Unix()) + Lifetime }

// Plaintext returns what the envelope seals: compact JSON of version,
// run_configuration, the credentials sorted, and the values sorted by credential, each
// written credential and then value. It refuses, with [ErrRequest], a sealing whose
// identifiers are outside their forms, whose credentials are not 1 to
// [MaxCredentials] names each once, or whose values are not one for each credential;
// and, with [ErrValue], a value that is not 1 to [MaxValueBytes] bytes of UTF-8 without
// a NUL. The caller clears what it returns.
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
		if v := values[i].Value; len(v) == 0 || len(v) > MaxValueBytes || bytes.IndexByte(v, 0) >= 0 {
			return nil, refuse(ErrValue, "the value of the credential %s", accesskey.ShownName(name, true))
		}
	}
	b := []byte(`{"version":1,"run_configuration":`)
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
		if b, err = jsontext.AppendQuote(b, v.Value); err != nil {
			clear(b)
			return nil, refuse(ErrValue, "the value of the credential %s", accesskey.ShownName(v.Credential, true))
		}
		b = append(b, '}')
	}
	return append(b, "]}"...), nil
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
		return nil, errors.New("sealing needs the server's signing key")
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
