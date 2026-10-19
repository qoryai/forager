package proxy

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
)

// errUnaskedSwitch is the answer to a 101 from a host whose request went without its
// Upgrade, on the plain path and on a host that gets a credential.
var errUnaskedSwitch = errors.New("the host answered 101 Switching Protocols to a request that asked for no upgrade")

// masker replaces a credential's value in what a host answers, in each form the value
// is looked for in, with the placeholder in the same form. Every find is a copy of the
// value or of a form of it, overwritten by clear.
type masker struct {
	pairs []maskPair
	// longest is the length of the longest find.
	longest int
	// fold is the masker of header names, which a server may write in another case:
	// its finds and puts are in lower case. It is made on first use.
	fold *masker
}

// maskPair is one form of the value and the placeholder in the same form.
type maskPair struct{ find, put []byte }

// masker is the masker of the value v that the proxy sets for the credential, or nil
// when v is empty. The forms are v itself and, for basic, the base64 of the username
// and v that the header has, with and without its padding, in the standard and the URL
// alphabet. Each of these is looked for as well percent-encoded and JSON-escaped, where
// that changes it. v stays the caller's to clear.
func (c *Credential) masker(v []byte) *masker {
	if len(v) == 0 {
		return nil
	}
	m := &masker{}
	m.add(v, []byte(link.Placeholder))
	if c.Scheme == "basic" {
		pair := make([]byte, 0, len(c.Username)+1+len(v))
		pair = append(append(append(pair, c.Username...), ':'), v...)
		defer clear(pair)
		stand := []byte(c.Username + ":" + link.Placeholder)
		// A padded form comes first: at the same place the longest find wins, so a copy
		// with its padding gets the placeholder's.
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			find := make([]byte, enc.EncodedLen(len(pair)))
			enc.Encode(find, pair)
			put := make([]byte, enc.EncodedLen(len(stand)))
			enc.Encode(put, stand)
			m.add(find, put)
			clear(find)
		}
	}
	return m
}

// add adds find and put in each form, once: as they are, percent-encoded, and
// JSON-escaped with and without the escapes of <, > and &, and with / escaped. find
// stays the caller's to clear; add keeps copies.
func (m *masker) add(find, put []byte) {
	forms := []func([]byte) []byte{
		func(b []byte) []byte { return bytes.Clone(b) },
		percent,
		func(b []byte) []byte { return jsonEscaped(b, true, false) },
		func(b []byte) []byte { return jsonEscaped(b, false, false) },
		func(b []byte) []byte { return jsonEscaped(b, false, true) },
	}
	for _, form := range forms {
		f := form(find)
		known := false
		for _, p := range m.pairs {
			if bytes.Equal(p.find, f) {
				known = true
				break
			}
		}
		if known {
			clear(f)
			continue
		}
		m.pairs = append(m.pairs, maskPair{find: f, put: form(put)})
		m.longest = max(m.longest, len(f))
	}
}

// unreserved reports whether percent-encoding leaves the byte as it is.
func unreserved(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

// percent is b with every byte but the unreserved ones as % and two upper-case hex
// digits.
func percent(b []byte) []byte {
	const hex = "0123456789ABCDEF"
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if unreserved(c) {
			out = append(out, c)
			continue
		}
		out = append(out, '%', hex[c>>4], hex[c&15])
	}
	return out
}

// jsonEscaped is b as it is inside a JSON string: " and \ escaped, and the control
// characters; html escapes <, > and & as encoding/json does, slash escapes / as some
// encoders do.
func jsonEscaped(b []byte, html, slash bool) []byte {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch {
		case c == '"' || c == '\\':
			out = append(out, '\\', c)
		case c == '/' && slash:
			out = append(out, '\\', '/')
		case c == '\n':
			out = append(out, '\\', 'n')
		case c == '\r':
			out = append(out, '\\', 'r')
		case c == '\t':
			out = append(out, '\\', 't')
		case c < 0x20 || html && (c == '<' || c == '>' || c == '&'):
			out = append(out, '\\', 'u', '0', '0', hex[c>>4], hex[c&15])
		default:
			out = append(out, c)
		}
	}
	return out
}

// next is the index in b of the first find, the longest of those that start there, or
// -1 when b contains none.
func (m *masker) next(b []byte) (int, *maskPair) {
	at, which := -1, -1
	for i := range m.pairs {
		j := bytes.Index(b, m.pairs[i].find)
		if j < 0 {
			continue
		}
		if at < 0 || j < at || j == at && len(m.pairs[i].find) > len(m.pairs[which].find) {
			at, which = j, i
		}
	}
	if at < 0 {
		return -1, nil
	}
	return at, &m.pairs[which]
}

// scan appends b to dst with every find replaced. Unless final, it keeps back the end
// of b that a find could start in and the next bytes complete: at most longest-1
// bytes, and none when no find starts with that end. rest is where the bytes kept back
// start in b.
func (m *masker) scan(dst, b []byte, final bool) (out []byte, rest int) {
	i := 0
	for {
		at, p := m.next(b[i:])
		if at < 0 {
			break
		}
		dst = append(append(dst, b[i:i+at]...), p.put...)
		i += at + len(p.find)
	}
	hold := len(b)
	if !final {
		for s := max(i, len(b)-(m.longest-1)); s < len(b); s++ {
			if m.starts(b[s:]) {
				hold = s
				break
			}
		}
	}
	return append(dst, b[i:hold]...), hold
}

// starts reports whether a find starts with b.
func (m *masker) starts(b []byte) bool {
	for _, p := range m.pairs {
		if bytes.HasPrefix(p.find, b) {
			return true
		}
	}
	return false
}

// replace is s with every find replaced.
func (m *masker) replace(s string) string {
	b := []byte(s)
	if at, _ := m.next(b); at < 0 {
		return s
	}
	out, _ := m.scan(nil, b, true)
	clear(b)
	return string(out)
}

// header replaces every find in the values of h, and in its names in any case.
func (m *masker) header(h http.Header) {
	if m.fold == nil {
		m.fold = &masker{longest: m.longest}
		for _, p := range m.pairs {
			m.fold.pairs = append(m.fold.pairs, maskPair{find: bytes.ToLower(p.find), put: bytes.ToLower(p.put)})
		}
	}
	for name, values := range h {
		for i, v := range values {
			values[i] = m.replace(v)
		}
		lower := strings.ToLower(name)
		if masked := m.fold.replace(lower); masked != lower {
			delete(h, name)
			key := http.CanonicalHeaderKey(masked)
			h[key] = append(h[key], values...)
		}
	}
}

// clear overwrites every find.
func (m *masker) clear() {
	for _, p := range m.pairs {
		clear(p.find)
	}
	if m.fold != nil {
		m.fold.clear()
	}
}

// masking is the writer of an answer from a host that gets a credential: it replaces
// the value in the headers when they are written, those of a 1xx and the trailer
// included, and in the body as it streams, keeping back the end of each write that a
// find could start in. The body's length can change, so the Content-Length goes; the
// connection cannot be taken over, so an upgrade is never served through it.
type masking struct {
	w    http.ResponseWriter
	m    *masker
	tail []byte
	// final says the status of the answer, past every 1xx, is written.
	final bool
}

// Header is the headers of the writer it wraps.
func (mw *masking) Header() http.Header { return mw.w.Header() }

// WriteHeader writes the status and the headers with every find replaced.
func (mw *masking) WriteHeader(code int) {
	mw.m.header(mw.w.Header())
	if code >= 200 && !mw.final {
		mw.final = true
		mw.w.Header().Del("Content-Length")
	}
	mw.w.WriteHeader(code)
}

// Write writes b with every find replaced, keeping back the end a find could start in.
func (mw *masking) Write(b []byte) (int, error) {
	if !mw.final {
		mw.WriteHeader(http.StatusOK)
	}
	buf := append(mw.tail, b...)
	out, rest := mw.m.scan(nil, buf, false)
	mw.tail = append([]byte(nil), buf[rest:]...)
	clear(buf)
	defer clear(out)
	if len(out) == 0 {
		return len(b), nil
	}
	if _, err := mw.w.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Flush flushes what is written, apart from the bytes kept back.
func (mw *masking) Flush() {
	http.NewResponseController(mw.w).Flush()
}

// finish writes the bytes kept back, which hold no find, and replaces every find in
// the trailer, which the server writes once the handler returns.
func (mw *masking) finish() {
	if len(mw.tail) > 0 {
		_, _ = mw.w.Write(mw.tail)
		clear(mw.tail)
		mw.tail = nil
	}
	mw.m.header(mw.w.Header())
}

// encoded is the content coding of an answer with a body, empty when it has none or is
// identity.
func encoded(resp *http.Response) string {
	if resp.Request != nil && resp.Request.Method == http.MethodHead || resp.StatusCode < 200 || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified || resp.ContentLength == 0 {
		return ""
	}
	coding := strings.TrimSpace(strings.Join(resp.Header.Values("Content-Encoding"), ","))
	if coding == "" || strings.EqualFold(coding, "identity") {
		return ""
	}
	return coding
}

// withheld puts, in place of a compressed answer from a host that gets a credential, a
// 502 that says why; the value could be inside the compressed body unseen.
func withheld(resp *http.Response, coding, method, host, path string) {
	resp.Body.Close()
	body := fmt.Sprintf("qory: remove this host's credential from the policy, or serve the host through a tool.\n"+
		"qory: the gateway did not pass on the answer to %s %s%s: it has Content-Encoding %s although the request had Accept-Encoding: identity, and the gateway replaces the credential only in an uncompressed answer\n",
		accesskey.ShownValue(method, false), host, accesskey.ShownValue(path, false), accesskey.ShownValue(coding, true))
	resp.StatusCode, resp.Status = http.StatusBadGateway, "502 Bad Gateway"
	resp.Header = http.Header{"Content-Type": {"text/plain; charset=utf-8"}}
	resp.Trailer = nil
	resp.ContentLength = int64(len(body))
	resp.Body = io.NopCloser(strings.NewReader(body))
}
