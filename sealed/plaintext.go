package sealed

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
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
	ExpiresAt  jsontext.Value `json:"expires_at"`
	Apply      jsontext.Value `json:"apply"`
}

// plainApply is one item of a value's apply as it is decoded: a member the schema does
// not define, token among them, is refused.
type plainApply struct {
	Hosts    []string `json:"hosts"`
	Scheme   string   `json:"scheme"`
	Username string   `json:"username"`
	Header   string   `json:"header"`
	Paths    []string `json:"paths"`
}

// meta is what a value has beside its bytes: when it expires, zero when it does not,
// and where it is set, nil when the plaintext gives no apply.
type meta struct {
	expires time.Time
	apply   []Apply
}

// plaintextSchema is sealed-plaintext.schema.json, compiled once.
var plaintextSchema = sync.OnceValues(func() (*jsonschema.Schema, error) { return contracts.Compile("sealed-plaintext.schema.json") })

// readMeta reads a value's expires_at and apply, raw as the plaintext has them. They
// hold no secret, so the schema checks them: a plaintext of one credential, this
// value's members beside a stand-in value, keeps the validator from every value's
// bytes. An apply that does not decode into its items, a member twice or unknown, is
// refused before the schema.
func readMeta(credential string, expiresAt, apply jsontext.Value) (meta, bool) {
	var m meta
	if expiresAt == nil && apply == nil {
		return m, true
	}
	var items []plainApply
	if apply != nil && jsonv2.Unmarshal(apply, &items, jsonv2.RejectUnknownMembers(true)) != nil {
		return m, false
	}
	doc := []byte(`{"version":1,"run_configuration":"sha256=0000000000000000000000000000000000000000000000000000000000000000","credentials":[`)
	doc, _ = jsontext.AppendQuote(doc, credential)
	doc = append(doc, `],"values":[{"credential":`...)
	doc, _ = jsontext.AppendQuote(doc, credential)
	doc = append(doc, `,"value":"stand-in"`...)
	if expiresAt != nil {
		doc = append(append(doc, `,"expires_at":`...), expiresAt...)
	}
	if apply != nil {
		doc = append(append(doc, `,"apply":`...), apply...)
	}
	doc = append(doc, "}]}"...)
	schema, err := plaintextSchema()
	if err != nil {
		return m, false
	}
	decoded, err := contracts.Decode("plaintext.json", doc)
	if err != nil || schema.Validate(decoded) != nil {
		return m, false
	}
	if expiresAt != nil {
		var text string
		if jsonv2.Unmarshal(expiresAt, &text) != nil {
			return m, false
		}
		t, ok := parseTime(text)
		if !ok {
			return m, false
		}
		m.expires = t
	}
	if apply != nil {
		m.apply = make([]Apply, len(items))
		for i, a := range items {
			m.apply[i] = Apply(a)
		}
	}
	return m, true
}

// parseTime reads an RFC 3339 date-time the schema's format accepts: t and z in either
// case, a fraction of any length, and a leap second, read as the second before it.
func parseTime(text string) (time.Time, bool) {
	b := []byte(text)
	if len(b) > 10 {
		b[10] = 'T'
	}
	if n := len(b); n > 0 && b[n-1] == 'z' {
		b[n-1] = 'Z'
	}
	if len(b) > 19 && string(b[17:19]) == "60" {
		b[17], b[18] = '5', '9'
	}
	t, err := time.Parse(time.RFC3339Nano, string(b))
	return t, err == nil
}

// readPlaintext reads a plaintext and checks it against sealed-plaintext.schema.json:
// one JSON object with each member name once and no member the schema does not define,
// version 1, the digest, 1 to [MaxCredentials] credentials, each once and in the
// grammar, and 1 to [MaxCredentials] values, each a credential in the grammar and a
// string, with an optional expires_at and apply as [readMeta] reads them. Anything else
// is [ErrPlaintext]. A value that is not 1 to [MaxValueBytes] bytes or contains a NUL is
// [ErrValue]. The schema's rules for the values are checked here and not by the
// validator, which would decode every value into a Go string. It returns the digest,
// the credentials, and each value's credential, bytes and meta in the plaintext's
// order; on an error it has cleared every value it read.
func readPlaintext(pt []byte) (digest string, credentials, names []string, values [][]byte, metas []meta, err error) {
	var d plainDocument
	if jsonv2.Unmarshal(pt, &d, jsonv2.RejectUnknownMembers(true)) != nil {
		clearDocument(&d)
		return "", nil, nil, nil, nil, ErrPlaintext
	}
	defer clearDocument(&d)
	if string(d.Version) != "1" || d.RunConfiguration == nil || d.Credentials == nil || d.Values == nil {
		return "", nil, nil, nil, nil, ErrPlaintext
	}
	credentials, raw := *d.Credentials, *d.Values
	if !digestShape.MatchString(*d.RunConfiguration) || len(credentials) < 1 || len(credentials) > MaxCredentials ||
		len(raw) < 1 || len(raw) > MaxCredentials {
		return "", nil, nil, nil, nil, ErrPlaintext
	}
	for i, c := range credentials {
		if !nameShape.MatchString(c) || slices.Contains(credentials[:i], c) {
			return "", nil, nil, nil, nil, ErrPlaintext
		}
	}
	for _, v := range raw {
		if v.Credential == nil || !nameShape.MatchString(*v.Credential) || v.Value.Kind() != '"' {
			return "", nil, nil, nil, nil, ErrPlaintext
		}
		m, ok := readMeta(*v.Credential, v.ExpiresAt, v.Apply)
		if !ok {
			return "", nil, nil, nil, nil, ErrPlaintext
		}
		metas = append(metas, m)
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
				return "", nil, nil, nil, nil, ErrPlaintext
			}
			return "", nil, nil, nil, nil, refuse(ErrValue, "the value of the credential %s", accesskey.ShownName(*v.Credential, true))
		}
		values = append(values, b)
		names = append(names, *v.Credential)
	}
	return *d.RunConfiguration, credentials, names, values, metas, nil
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
	got, credentials, names, values, metas, err := readPlaintext(pt)
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
	s := &store{values: make(map[string][]byte, len(names)), metas: make(map[string]meta, len(names))}
	for i, name := range names {
		s.values[name], s.metas[name] = values[i], metas[i]
	}
	return Values{m: func() *store { return s }}, nil
}

// shownNames is a list of credential names as an error prints it.
func shownNames(names []string) string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = accesskey.ShownName(n, true)
	}
	return strings.Join(out, ", ")
}
