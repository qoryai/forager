package sealed

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"slices"
	"strings"

	"github.com/qoryai/forager/accesskey"
)

// plainDocument is the plaintext as it is decoded. Each value stays the raw JSON string
// until it is unquoted into bytes of this package, so no value becomes a Go string.
type plainDocument struct {
	Version          jsontext.Value `json:"version"`
	RunConfiguration *string        `json:"run_configuration"`
	Credentials      *[]string      `json:"credentials"`
	Values           *[]plainValue  `json:"values"`
}

type plainValue struct {
	Credential *string        `json:"credential"`
	Value      jsontext.Value `json:"value"`
}

// readPlaintext reads a plaintext and checks it against sealed-plaintext.schema.json:
// one JSON object with each member name once and no member the schema does not define,
// version 1, the digest, 1 to [MaxCredentials] credentials, each once and in the
// grammar, and 1 to [MaxCredentials] values, each a credential in the grammar and a
// string. Anything else is [ErrPlaintext]. A value that is not 1 to [MaxValueBytes]
// bytes or contains a NUL is [ErrValue]. The schema's rules are checked here and not by
// the validator, which would decode every value into a Go string. It returns the
// digest, the credentials, and each value's credential and bytes in the plaintext's
// order; on an error it has cleared every value it read.
func readPlaintext(pt []byte) (digest string, credentials, names []string, values [][]byte, err error) {
	var d plainDocument
	if jsonv2.Unmarshal(pt, &d, jsonv2.RejectUnknownMembers(true)) != nil {
		clearDocument(&d)
		return "", nil, nil, nil, ErrPlaintext
	}
	defer clearDocument(&d)
	if string(d.Version) != "1" || d.RunConfiguration == nil || d.Credentials == nil || d.Values == nil {
		return "", nil, nil, nil, ErrPlaintext
	}
	credentials, raw := *d.Credentials, *d.Values
	if !digestShape.MatchString(*d.RunConfiguration) || len(credentials) < 1 || len(credentials) > MaxCredentials ||
		len(raw) < 1 || len(raw) > MaxCredentials {
		return "", nil, nil, nil, ErrPlaintext
	}
	for i, c := range credentials {
		if !nameShape.MatchString(c) || slices.Contains(credentials[:i], c) {
			return "", nil, nil, nil, ErrPlaintext
		}
	}
	for _, v := range raw {
		if v.Credential == nil || !nameShape.MatchString(*v.Credential) || v.Value.Kind() != '"' {
			return "", nil, nil, nil, ErrPlaintext
		}
	}
	values = make([][]byte, 0, len(raw))
	for _, v := range raw {
		// The unquoted value is shorter than its raw JSON, so AppendUnquote writes into
		// this buffer and allocates no other copy of the value.
		b, err := jsontext.AppendUnquote(make([]byte, 0, len(v.Value)), v.Value)
		if err != nil || len(b) == 0 || len(b) > MaxValueBytes || bytes.IndexByte(b, 0) >= 0 {
			clear(b)
			clearAll(values)
			if err != nil {
				return "", nil, nil, nil, ErrPlaintext
			}
			return "", nil, nil, nil, refuse(ErrValue, "the value of the credential %s", accesskey.ShownName(*v.Credential, true))
		}
		values = append(values, b)
		names = append(names, *v.Credential)
	}
	return *d.RunConfiguration, credentials, names, values, nil
}

// clearDocument overwrites the raw JSON of every value the decoder read.
func clearDocument(d *plainDocument) {
	if d.Values == nil {
		return
	}
	for _, v := range *d.Values {
		clear(v.Value)
	}
}

// clearAll overwrites each of values.
func clearAll(values [][]byte) {
	for _, b := range values {
		clear(b)
	}
}

// Plaintext reads what an envelope opened to, checked against
// sealed-plaintext.schema.json as [readPlaintext] checks it, and checks it against the
// request: a credential with two values is [ErrTwice]; a digest other than digest
// [ErrDigest]; credentials other than the set requested [ErrCredentials]; credentials,
// or values, not sorted by name [ErrPlaintext]; a value for a credential the request
// did not ask for [ErrNotRequested]; and a requested credential without a value
// [ErrMissing]. A digest outside its form or a request outside its forms is
// [ErrRequest], before pt is read. It does not check the rule for a value set in a
// header, no control character other than tab and no leading or trailing space or tab:
// Plaintext is not given which values are set in a header, so that check is the
// caller's. It returns the values by credential; on an error it has cleared every value
// it read. The caller clears pt.
func Plaintext(pt []byte, digest string, requested []string) (Values, error) {
	if !digestShape.MatchString(digest) || len(requested) < 1 || len(requested) > MaxCredentials {
		return Values{}, refuse(ErrRequest, "the digest is outside its form, or the request lists %d credentials and not 1 to %d", len(requested), MaxCredentials)
	}
	for i, name := range requested {
		if !nameShape.MatchString(name) || slices.Contains(requested[:i], name) {
			return Values{}, refuse(ErrRequest, "the credential %s is outside the grammar or listed twice", accesskey.ShownName(name, true))
		}
	}
	got, credentials, names, values, err := readPlaintext(pt)
	if err != nil {
		return Values{}, err
	}
	fail := func(err error) (Values, error) {
		clearAll(values)
		return Values{}, err
	}
	for i, name := range names {
		if slices.Contains(names[:i], name) {
			return fail(refuse(ErrTwice, "the credential %s", accesskey.ShownName(name, true)))
		}
	}
	if got != digest {
		return fail(refuse(ErrDigest, "the plaintext is for %s, and the run configuration is %s", got, digest))
	}
	want := slices.Sorted(slices.Values(requested))
	if !slices.Equal(slices.Sorted(slices.Values(credentials)), want) {
		return fail(refuse(ErrCredentials, "the plaintext lists %s, and the request %s", shownNames(credentials), shownNames(want)))
	}
	if !slices.IsSorted(credentials) || !slices.IsSorted(names) {
		return fail(refuse(ErrPlaintext, "the credentials or the values are not sorted by name"))
	}
	for _, name := range names {
		if !slices.Contains(want, name) {
			return fail(refuse(ErrNotRequested, "the credential %s", accesskey.ShownName(name, true)))
		}
	}
	for _, name := range want {
		if !slices.Contains(names, name) {
			return fail(refuse(ErrMissing, "the credential %s", accesskey.ShownName(name, true)))
		}
	}
	m := make(map[string][]byte, len(names))
	for i, name := range names {
		m[name] = values[i]
	}
	return Values{m: func() map[string][]byte { return m }}, nil
}

// shownNames is a list of credential names as an error prints it.
func shownNames(names []string) string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = accesskey.ShownName(n, true)
	}
	return strings.Join(out, ", ")
}
