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
	// fold is the masker of headers in any case, since a server or the proxy may write
	// a header's name or value in another case: its finds and puts are in lower case.
	// It is made on first use.
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
	// A model key is masked with the placeholder of its name, every other credential
	// with the shared one.
	placeholder := link.Placeholder
	if c.Placeholder != "" {
		placeholder = c.Placeholder
	}
	m := &masker{}
	m.add(v, []byte(placeholder))
	if c.Scheme == "basic" {
		pair := make([]byte, 0, len(c.Username)+1+len(v))
		pair = append(append(append(pair, c.Username...), ':'), v...)
		defer clear(pair)
		stand := []byte(c.Username + ":" + placeholder)
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

// index is the index in b of f at or after from, or -1 when there is none.
func index(b []byte, from int, f []byte) int {
	if j := bytes.Index(b[from:], f); j >= 0 {
		return from + j
	}
	return -1
}

// scan appends b to dst with every find replaced. Unless final, it keeps back the end
// of b that a find could start in and the next bytes complete: at most longest-1
// bytes, and none when no find starts with that end. rest is where the bytes kept back
// start in b.
func (m *masker) scan(dst, b []byte, final bool) (out []byte, rest int) {
	return m.scanIn(dst, b, b, final)
}

// scanIn is scan that looks for the finds in in, which has the length of b and its
// bytes at the same places, such as b in lower case, and copies the rest from b. Of
// the finds at one place the longest wins. Each find's next place is kept and looked
// for again only once the replacing has passed it, so the time is linear in b for a
// fixed set of finds, however often b contains them.
func (m *masker) scanIn(dst, b, in []byte, final bool) (out []byte, rest int) {
	at := make([]int, len(m.pairs))
	for k := range m.pairs {
		at[k] = index(in, 0, m.pairs[k].find)
	}
	i := 0
	for {
		which := -1
		for k := range m.pairs {
			if at[k] >= 0 && at[k] < i {
				at[k] = index(in, i, m.pairs[k].find)
			}
			if at[k] < 0 {
				continue
			}
			if which < 0 || at[k] < at[which] || at[k] == at[which] && len(m.pairs[k].find) > len(m.pairs[which].find) {
				which = k
			}
		}
		if which < 0 {
			break
		}
		p := &m.pairs[which]
		dst = append(append(dst, b[i:at[which]]...), p.put...)
		i = at[which] + len(p.find)
	}
	hold := len(b)
	if !final {
		for s := max(i, len(b)-(m.longest-1)); s < len(b); s++ {
			if m.starts(in[s:]) {
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

// contains reports whether b contains a find.
func (m *masker) contains(b []byte) bool {
	for _, p := range m.pairs {
		if bytes.Contains(b, p.find) {
			return true
		}
	}
	return false
}

// replace is s with every find replaced.
func (m *masker) replace(s string) string {
	b := []byte(s)
	defer clear(b)
	if !m.contains(b) {
		return s
	}
	out, _ := m.scan(nil, b, true)
	return string(out)
}

// lowerASCII is b with the ASCII letters in lower case, every other byte as it is, so
// each byte stays at its place.
func lowerASCII(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// replaceFold is s with every find of the folded masker replaced in any case of its
// ASCII letters; what is not replaced keeps its case.
func (m *masker) replaceFold(s string) string {
	b := []byte(s)
	defer clear(b)
	in := lowerASCII(b)
	defer clear(in)
	if !m.contains(in) {
		return s
	}
	out, _ := m.scanIn(nil, b, in, true)
	return string(out)
}

// header replaces every find in the names and the values of h: in the case it has,
// then in any case, since a server or the proxy may write a name, such as one the
// Trailer header lists, in another case.
func (m *masker) header(h http.Header) {
	if m.fold == nil {
		m.fold = &masker{longest: m.longest}
		for _, p := range m.pairs {
			m.fold.pairs = append(m.fold.pairs, maskPair{find: lowerASCII(p.find), put: lowerASCII(p.put)})
		}
	}
	for name, values := range h {
		for i, v := range values {
			values[i] = m.fold.replaceFold(m.replace(v))
		}
		if masked := m.fold.replaceFold(name); masked != name {
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
	defer clear(buf)
	out, rest := mw.m.scan(nil, buf, false)
	defer clear(out)
	mw.tail = append([]byte(nil), buf[rest:]...)
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

// discard overwrites the bytes kept back, which the handler defers so that a copy that
// ends early, with the server's panic, keeps no part of the value.
func (mw *masking) discard() {
	clear(mw.tail)
	mw.tail = nil
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

// serveMasked serves r with h through a masking writer of m, then clears the bytes kept
// back and every find, also when h ends with a panic, as the reverse proxy does when a
// copy fails part way.
func serveMasked(h http.Handler, w http.ResponseWriter, r *http.Request, m *masker) {
	defer m.clear()
	mw := &masking{w: w, m: m}
	defer mw.discard()
	h.ServeHTTP(mw, r)
	mw.finish()
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
