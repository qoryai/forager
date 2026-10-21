// Package mask replaces secret values in bytes and strings with a fixed text in the same
// form. The gateway's proxy masks a credential's value in what a host answers; the
// session masks the passwords of a run's forwarders in the runtime's output and in the
// records it maps to events.
//
// A [Masker] is a set of finds, each with what replaces it. [Writer] masks a stream
// that arrives in writes, keeping back the end of each write that a find could start
// in, so a value split across two writes is replaced whole.
package mask

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"sync"
)

// ProxyPassword is what replaces the password of a forwarder's proxy URL.
const ProxyPassword = "qory-proxy-password"

// Masker replaces each find with its put: a value, in each form the value is looked
// for in, with the placeholder in the same form. Every find is a copy of the value or
// of a form of it, overwritten by Clear. The zero Masker has no find; [Masker.Add] adds
// one. A nil Masker replaces nothing. Once its finds are added, a Masker is safe for
// concurrent use, apart from Header and Clear.
type Masker struct {
	pairs []pair
	// longest is the length of the longest find.
	longest int
	// fold is the masker of headers in any case, since a server or the proxy may write
	// a header's name or value in another case: its finds and puts are in lower case.
	// It is made on first use.
	fold *Masker
}

// pair is one form of the value and the placeholder in the same form.
type pair struct{ find, put []byte }

// Proxy is the masker of the passwords of proxy URLs with the user name user, each
// replaced with ProxyPassword: each password as it is, and the base64 of
// user:password that Proxy-Authorization: Basic has, with and without its padding, in
// the standard and the URL alphabet, replaced with the same form of
// user:ProxyPassword. An empty password is left out; with none, Proxy is nil.
func Proxy(user string, passwords ...string) *Masker {
	m := &Masker{}
	stand := []byte(user + ":" + ProxyPassword)
	for _, p := range passwords {
		if p == "" {
			continue
		}
		m.addForm([]byte(p), []byte(ProxyPassword), same)
		pair := []byte(user + ":" + p)
		// A padded form comes first: at the same place the longest find wins, so a copy
		// with its padding gets the placeholder's.
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			find := make([]byte, enc.EncodedLen(len(pair)))
			enc.Encode(find, pair)
			put := make([]byte, enc.EncodedLen(len(stand)))
			enc.Encode(put, stand)
			m.addForm(find, put, same)
			clear(find)
		}
		clear(pair)
	}
	if len(m.pairs) == 0 {
		return nil
	}
	return m
}

// same is b as it is, a copy.
func same(b []byte) []byte { return bytes.Clone(b) }

// Add adds find and put in each form, once: as they are, percent-encoded, and
// JSON-escaped with and without the escapes of <, > and &, and with / escaped. find
// stays the caller's to clear; Add keeps copies.
func (m *Masker) Add(find, put []byte) {
	forms := []func([]byte) []byte{
		same,
		percent,
		func(b []byte) []byte { return jsonEscaped(b, true, false) },
		func(b []byte) []byte { return jsonEscaped(b, false, false) },
		func(b []byte) []byte { return jsonEscaped(b, false, true) },
	}
	for _, form := range forms {
		m.addForm(find, put, form)
	}
}

// addForm adds find and put in the form, unless the masker has that find already.
func (m *Masker) addForm(find, put []byte, form func([]byte) []byte) {
	f := form(find)
	for _, p := range m.pairs {
		if bytes.Equal(p.find, f) {
			clear(f)
			return
		}
	}
	m.pairs = append(m.pairs, pair{find: f, put: form(put)})
	m.longest = max(m.longest, len(f))
}

// Finds is the masker's finds, in the order they were added. The slices are the
// masker's, which Clear overwrites; the caller does not change them.
func (m *Masker) Finds() [][]byte {
	if m == nil {
		return nil
	}
	out := make([][]byte, len(m.pairs))
	for i, p := range m.pairs {
		out[i] = p.find
	}
	return out
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

// Scan appends b to dst with every find replaced. Unless final, it keeps back the end
// of b that a find could start in and the next bytes complete: at most longest-1
// bytes, and none when no find starts with that end. rest is where the bytes kept back
// start in b.
func (m *Masker) Scan(dst, b []byte, final bool) (out []byte, rest int) {
	return m.scanIn(dst, b, b, final)
}

// scanIn is Scan that looks for the finds in in, which has the length of b and its
// bytes at the same places, such as b in lower case, and copies the rest from b. Of
// the finds at one place the longest wins. Each find's next place is kept and looked
// for again only once the replacing has passed it, so the time is linear in b for a
// fixed set of finds, however often b contains them.
func (m *Masker) scanIn(dst, b, in []byte, final bool) (out []byte, rest int) {
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
func (m *Masker) starts(b []byte) bool {
	for _, p := range m.pairs {
		if bytes.HasPrefix(p.find, b) {
			return true
		}
	}
	return false
}

// contains reports whether b contains a find.
func (m *Masker) contains(b []byte) bool {
	for _, p := range m.pairs {
		if bytes.Contains(b, p.find) {
			return true
		}
	}
	return false
}

// Replace is s with every find replaced; a nil masker returns s.
func (m *Masker) Replace(s string) string {
	if m == nil {
		return s
	}
	b := []byte(s)
	defer clear(b)
	if !m.contains(b) {
		return s
	}
	out, _ := m.Scan(nil, b, true)
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
func (m *Masker) replaceFold(s string) string {
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

// Header replaces every find in the names and the values of h: in the case it has,
// then in any case, since a server or the proxy may write a name, such as one the
// Trailer header lists, in another case.
func (m *Masker) Header(h http.Header) {
	if m.fold == nil {
		m.fold = &Masker{longest: m.longest}
		for _, p := range m.pairs {
			m.fold.pairs = append(m.fold.pairs, pair{find: lowerASCII(p.find), put: lowerASCII(p.put)})
		}
	}
	for name, values := range h {
		for i, v := range values {
			values[i] = m.fold.replaceFold(m.Replace(v))
		}
		if masked := m.fold.replaceFold(name); masked != name {
			delete(h, name)
			key := http.CanonicalHeaderKey(masked)
			h[key] = append(h[key], values...)
		}
	}
}

// Clear overwrites every find.
func (m *Masker) Clear() {
	for _, p := range m.pairs {
		clear(p.find)
	}
	if m.fold != nil {
		m.fold.Clear()
	}
}

// Writer writes to the writer it wraps what is written to it, with every find of its
// masker replaced. It keeps back the end of each write that a find could start in, at
// most the longest find's length less one byte, and writes it with the next write or
// on Flush. It is safe for concurrent writes.
type Writer struct {
	w    io.Writer
	m    *Masker
	mu   sync.Mutex
	tail []byte
}

// NewWriter returns a writer that writes to w with every find of m replaced. With a nil
// m it writes to w what it is given, and keeps nothing back.
func NewWriter(w io.Writer, m *Masker) *Writer {
	return &Writer{w: w, m: m}
}

// Write writes b with every find replaced, keeping back the end a find could start in.
func (mw *Writer) Write(b []byte) (int, error) {
	if mw.m == nil {
		return mw.w.Write(b)
	}
	mw.mu.Lock()
	defer mw.mu.Unlock()
	buf := append(mw.tail, b...)
	defer clear(buf)
	out, rest := mw.m.Scan(nil, buf, false)
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

// Flush writes the bytes kept back, which contain no find: the stream is over.
func (mw *Writer) Flush() error {
	mw.mu.Lock()
	defer mw.mu.Unlock()
	if len(mw.tail) == 0 {
		return nil
	}
	_, err := mw.w.Write(mw.tail)
	clear(mw.tail)
	mw.tail = nil
	return err
}
