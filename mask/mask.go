// Package mask replaces secret values in bytes and strings with a fixed text in the same
// form. The gateway's proxy masks a credential's value in what a host answers; the
// session masks the passwords of a run's forwarders, the values its caller gives and
// the server's variables in the runtime's output and in the records it maps to events.
//
// A [Masker] is a set of finds, each with what replaces it. [Writer] masks a stream
// that arrives in writes, keeping back the end of each write that a find could start
// in, so a value split across two writes is replaced whole.
package mask

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// ProxyPassword is what replaces the password of a forwarder's proxy URL.
const ProxyPassword = "qory-proxy-password"

// Secret is what replaces a value [Masker.AddSecret] adds, in every form of the value.
const Secret = "***"

// The bounds of [Masker.AddSecret].
const (
	// MaxSecrets is how many different values AddSecret adds to one masker.
	MaxSecrets = 1024
	// MaxSecretSize is how many bytes one value of AddSecret may have.
	MaxSecretSize = 4096
)

// Masker replaces each find with its put: a value, in each form the value is looked
// for in, with the placeholder in the same form. Every find is a copy of the value or
// of a form of it, overwritten by Clear. The zero Masker has no find; [Masker.Add] adds
// one. A nil Masker replaces nothing. A Masker is safe for concurrent use: a find added
// while another goroutine masks applies from the next call that masks.
type Masker struct {
	mu    sync.RWMutex
	pairs []pair
	// longest is the length of the longest find.
	longest int
	// fold is the masker of headers in any case, since a server or the proxy may write
	// a header's name or value in another case: its finds and puts are in lower case.
	// It is made on first use.
	fold *Masker
	// cleared counts the calls of Clear, so a Writer drops the bytes it kept back
	// before one.
	cleared uint64
	// secrets counts the different values AddSecret added since the last Clear.
	secrets int
	// shapes are the shapes the masker replaces, from New, and shapeLongest the
	// longest find one of them can have; Clear leaves them.
	shapes       []shape
	shapeLongest int
}

// New returns a masker for a run that replaces every match of [Shapes] with Secret
// and no value yet: the caller adds the run's secrets with [Masker.AddSecret] and wraps
// its writers with [NewWriter] on it.
func New() *Masker {
	m := &Masker{}
	m.shapes, m.shapeLongest = compile(Shapes())
	return m
}

// window is how many bytes from the end of a scan a find could start in and go on past
// it, plus one: the longest find of a value or of a shape.
func (m *Masker) window() int { return max(m.longest, m.shapeLongest) }

// pair is one form of the value and the placeholder in the same form.
type pair struct{ find, put []byte }

// Proxy is the masker of the passwords of proxy URLs with the user name user, each
// replaced with ProxyPassword in the forms [Masker.AddProxy] adds: each password as it
// is and as a URL escapes it, and the base64 of user:password that
// Proxy-Authorization: Basic has, with and without its padding, in the standard and the
// URL alphabet, replaced with the same form of user:ProxyPassword. An empty password is
// left out; with none, Proxy is nil.
func Proxy(user string, passwords ...string) *Masker {
	m := &Masker{}
	for _, p := range passwords {
		m.AddProxy(user, p)
	}
	if len(m.pairs) == 0 {
		return nil
	}
	return m
}

// AddProxy adds the password of a proxy URL with the user name user, in the forms
// [Proxy] replaces: the password as it is; percent-encoded as a URL prints it, in the
// userinfo of url.UserPassword, by url.QueryEscape, by url.PathEscape and with every
// byte but the unreserved ones encoded; and the base64 of user:password. Each is
// replaced with the same form of ProxyPassword, which no encoding changes. An empty
// password adds nothing. A run keeps one Masker and adds each forwarder's password as
// the forwarder is made, before the forwarder starts, so the password is masked from
// its first use.
func (m *Masker) AddProxy(user, password string) {
	if password == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	stand := []byte(user + ":" + ProxyPassword)
	m.addForm([]byte(password), []byte(ProxyPassword), same)
	// A password may have any printable byte but a space, so a URL may print it
	// escaped. addPair keeps one find of the forms that are the same.
	userinfo := strings.TrimPrefix(url.UserPassword(user, password).String(), url.User(user).String()+":")
	for _, escaped := range []string{userinfo, url.QueryEscape(password), url.PathEscape(password), string(percent([]byte(password)))} {
		m.addPair([]byte(escaped), []byte(ProxyPassword))
	}
	pair := []byte(user + ":" + password)
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

// Empty reports whether the masker replaces nothing: a nil one, or one with no shape
// that no value was added to or that Clear cleared.
func (m *Masker) Empty() bool {
	if m == nil {
		return true
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.pairs) == 0 && len(m.shapes) == 0
}

// same is b as it is, a copy.
func same(b []byte) []byte { return bytes.Clone(b) }

// forms are the forms [Masker.Add] looks for a value in: as it is, percent-encoded,
// and JSON-escaped with and without the escapes of <, > and &, and with / escaped.
var forms = []func([]byte) []byte{
	same,
	percent,
	func(b []byte) []byte { return jsonEscaped(b, true, false) },
	func(b []byte) []byte { return jsonEscaped(b, false, false) },
	func(b []byte) []byte { return jsonEscaped(b, false, true) },
}

// Add adds find and put in each form, once: as they are, percent-encoded, and
// JSON-escaped with and without the escapes of <, > and &, and with / escaped. find
// stays the caller's to clear; Add keeps copies.
func (m *Masker) Add(find, put []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, form := range forms {
		m.addForm(find, put, form)
	}
}

// AddSecret adds value in each form Add looks for it in, each replaced with Secret as
// it is: Secret has no character JSON escapes, and * is a character a URL may have
// unencoded, so *** also stands in a percent-encoded text, such as a query value. A
// form the masker has a find for already keeps that find's put, so a proxy password
// keeps ProxyPassword. An empty value adds nothing. AddSecret returns an error, and
// adds nothing, for a value of more than MaxSecretSize bytes, and for a value the
// masker does not have yet once it has MaxSecrets different values; a value it has
// already does not count again. The error contains no value. value stays the caller's
// to clear; AddSecret keeps copies.
func (m *Masker) AddSecret(value []byte) error {
	if len(value) == 0 {
		return nil
	}
	if len(value) > MaxSecretSize {
		return fmt.Errorf("add a value of at most %d bytes to the masker: this value has %d bytes, and it is not masked", MaxSecretSize, len(value))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.has(value) {
		if m.secrets >= MaxSecrets {
			return fmt.Errorf("add at most %d values to the masker: it has %d already, and this value is not masked", MaxSecrets, m.secrets)
		}
		m.secrets++
	}
	for _, form := range forms {
		m.addPair(form(value), []byte(Secret))
	}
	return nil
}

// has reports whether the masker has value as it is among its finds. Called with the
// lock held.
func (m *Masker) has(value []byte) bool {
	for _, p := range m.pairs {
		if bytes.Equal(p.find, value) {
			return true
		}
	}
	return false
}

// addForm adds find and put in the form, unless the masker has that find already.
// Called with the lock held.
func (m *Masker) addForm(find, put []byte, form func([]byte) []byte) {
	m.addPair(form(find), form(put))
}

// addPair adds the find f, which it keeps, and its put, unless the masker has that find
// already: then it clears f. The masker of headers in any case is made again on its
// next use. Called with the lock held.
func (m *Masker) addPair(f, put []byte) {
	for _, p := range m.pairs {
		if bytes.Equal(p.find, f) {
			clear(f)
			return
		}
	}
	m.pairs = append(m.pairs, pair{find: f, put: put})
	m.longest = max(m.longest, len(f))
	if m.fold != nil {
		m.fold.Clear()
		m.fold = nil
	}
}

// Finds is the masker's finds, in the order they were added. The slices are the
// masker's, which Clear overwrites; the caller does not change them.
func (m *Masker) Finds() [][]byte {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
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

// Scan appends b to dst with every find replaced. Finds that overlap are replaced as
// one: the bytes from the first one's start to the furthest end get the put of the
// find that starts first, the longest of those. covered is how many bytes at the start
// of b a put written before already stands for, the kept of the call before: Scan
// widens that put's range over them and what follows, and copies none of them out.
//
// Unless final, it keeps back the end of b that a find could start in and the next
// bytes complete, at most longest-1 bytes: none when no find starts with that end; the
// bytes from the start of a find that could go on past the end of b and starts before
// a replaced range or at its start, such as a longer value that contains a shorter one
// or starts with it; or, of a replaced range that a find which starts inside it could
// extend past the end of b, the bytes from that find's start, after the range's put.
// rest is where the bytes kept back start in b, and kept how many of them that put
// stands for, which the caller passes as covered with the next bytes. A stream scanned
// this way, with the bytes kept back scanned with final at its end, is the scan of the
// whole stream in one call, byte for byte, however the writes split it.
func (m *Masker) Scan(dst, b []byte, covered int, final bool) (out []byte, rest, kept int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.scanIn(dst, b, b, covered, final)
}

// scanIn is Scan that looks for the finds in in, which has the length of b and its
// bytes at the same places, such as b in lower case, and copies the rest from b. Of
// the finds at one place the longest wins, and finds that overlap it widen its range.
// Each find's next place is kept and looked for again only once the replacing has
// passed it, and widen looks for each find only forward, so the time is linear in b for
// a fixed set of finds, however often b contains them and however they overlap. Called
// with the lock held.
func (m *Masker) scanIn(dst, b, in []byte, covered int, final bool) (out []byte, rest, kept int) {
	covered = min(max(covered, 0), len(b))
	i := 0
	if covered > 0 {
		// The covered bytes go on with a range whose put is written already: every
		// find that starts in them is part of that range.
		end := m.widen(in, 0, covered, final)
		if from := m.goesOn(in, 0, end); !final && from >= 0 {
			return dst, from, end - from
		}
		i = end
	}
	at := make([]int, len(m.pairs))
	for k := range m.pairs {
		at[k] = index(in, i, m.pairs[k].find)
	}
	// sat and slen are each shape's next find, its start and its length.
	sat, slen := make([]int, len(m.shapes)), make([]int, len(m.shapes))
	for k := range m.shapes {
		sat[k], slen[k] = m.shapes[k].next(in, i, final)
	}
	secret := []byte(Secret)
	for {
		start, n, put := -1, 0, []byte(nil)
		for k := range m.pairs {
			if at[k] >= 0 && at[k] < i {
				at[k] = index(in, i, m.pairs[k].find)
			}
			if at[k] < 0 {
				continue
			}
			if start < 0 || at[k] < start || at[k] == start && len(m.pairs[k].find) > n {
				start, n, put = at[k], len(m.pairs[k].find), m.pairs[k].put
			}
		}
		for k := range m.shapes {
			if sat[k] >= 0 && sat[k] < i {
				sat[k], slen[k] = m.shapes[k].next(in, i, final)
			}
			if sat[k] < 0 {
				continue
			}
			if start < 0 || sat[k] < start || sat[k] == start && slen[k] > n {
				start, n, put = sat[k], slen[k], secret
			}
		}
		if start < 0 {
			break
		}
		end := m.widen(in, start, start+n, final)
		if from := m.goesOn(in, i, end); !final && from >= 0 {
			// A find that could start before the range or at its start and go on
			// past the end of b, such as a longer value that contains this one or
			// starts with it, keeps back the bytes from its place, and the range
			// with them: the longer find wins if the next bytes complete it.
			if from <= start {
				return append(dst, b[i:from]...), from, 0
			}
			// A find that starts inside the range and could go on past the end of b
			// extends the range: the put is written now, and the bytes from that
			// find's place are kept back as covered.
			return append(append(dst, b[i:start]...), put...), from, end - from
		}
		dst = append(append(dst, b[i:start]...), put...)
		i = end
	}
	hold := len(b)
	if !final {
		for s := max(i, len(b)-(m.window()-1)); s < len(b); s++ {
			if m.starts(in[s:]) {
				hold = s
				break
			}
		}
	}
	return append(dst, b[i:hold]...), hold, 0
}

// widen is the end of the range from start to end once every find that starts inside
// the range, at start or after it, extends it to its end, until no find extends it: a
// value's, or a shape's that no byte after in can change, or that ends with in when
// final. Each find has a place from which it is looked for next, which only moves
// forward, and it is looked for only in the bytes a find starting inside the range can
// cover: each pass over the finds goes on from where the last one stopped, so finds that
// overlap in turn, such as a value and its percent-encoded form, cost time linear in
// the range.
func (m *Masker) widen(in []byte, start, end int, final bool) int {
	next := make([]int, len(m.pairs))
	for k := range next {
		next[k] = start
	}
	snext := make([]int, len(m.shapes))
	for k := range snext {
		snext[k] = start
	}
	for grown := true; grown; {
		grown = false
		for k, p := range m.pairs {
			n := len(p.find)
			for {
				limit := min(len(in), end+n-1)
				if next[k]+n > limit {
					break
				}
				j := bytes.Index(in[next[k]:limit], p.find)
				if j < 0 {
					next[k] = limit - n + 1
					break
				}
				j += next[k]
				next[k] = j + 1
				if j+n > end {
					end, grown = j+n, true
				}
			}
		}
		for k := range m.shapes {
			sh := &m.shapes[k]
			n := len(sh.prefix)
			for {
				limit := min(len(in), end+n-1)
				if snext[k]+n > limit {
					break
				}
				j := sh.index(in[snext[k]:limit])
				if j < 0 {
					snext[k] = limit - n + 1
					break
				}
				j += snext[k]
				snext[k] = j + 1
				if f, open := sh.at(in[j:]); f > 0 && (final || !open) && j+f > end {
					end, grown = j+f, true
				}
			}
		}
	}
	return end
}

// goesOn is the first place from start, before end, where a find could start and go
// on past the end of in: the bytes from that place to the end of in are the start of a
// value's find, and shorter than it, or a shape's find there could change with more
// bytes. It is -1 when there is none. The place is at most window()-1 bytes before
// the end of in.
func (m *Masker) goesOn(in []byte, start, end int) int {
	for s := max(start, len(in)-(m.window()-1)); s < end && s < len(in); s++ {
		for _, p := range m.pairs {
			if len(in)-s < len(p.find) && bytes.HasPrefix(p.find, in[s:]) {
				return s
			}
		}
		if m.shapeOpen(in[s:]) {
			return s
		}
	}
	return -1
}

// shapeOpen reports whether a shape's find at the start of b could change with bytes
// after b.
func (m *Masker) shapeOpen(b []byte) bool {
	for k := range m.shapes {
		if _, open := m.shapes[k].at(b); open {
			return true
		}
	}
	return false
}

// starts reports whether a value's find starts with b, or a shape's find at the start
// of b could change with bytes after b.
func (m *Masker) starts(b []byte) bool {
	for _, p := range m.pairs {
		if bytes.HasPrefix(p.find, b) {
			return true
		}
	}
	return m.shapeOpen(b)
}

// contains reports whether b contains a value's find or a shape's prefix.
func (m *Masker) contains(b []byte) bool {
	for _, p := range m.pairs {
		if bytes.Contains(b, p.find) {
			return true
		}
	}
	for k := range m.shapes {
		if m.shapes[k].index(b) >= 0 {
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
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.replace(s)
}

// replace is Replace with the lock held.
func (m *Masker) replace(s string) string {
	b := []byte(s)
	defer clear(b)
	if !m.contains(b) {
		return s
	}
	out, _, _ := m.scanIn(nil, b, b, 0, true)
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
// ASCII letters; what is not replaced keeps its case. The folded masker is reached
// only under the lock of the masker that made it.
func (m *Masker) replaceFold(s string) string {
	b := []byte(s)
	defer clear(b)
	in := lowerASCII(b)
	defer clear(in)
	if !m.contains(in) {
		return s
	}
	out, _, _ := m.scanIn(nil, b, in, 0, true)
	return string(out)
}

// Header replaces every find in the names and the values of h: in the case it has,
// then in any case, since a server or the proxy may write a name, such as one the
// Trailer header lists, in another case.
func (m *Masker) Header(h http.Header) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fold == nil {
		m.fold = &Masker{longest: m.longest}
		for _, p := range m.pairs {
			m.fold.pairs = append(m.fold.pairs, pair{find: lowerASCII(p.find), put: lowerASCII(p.put)})
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

// Clear overwrites every value's find and removes it, so the masker replaces no value
// after it; its shapes stay. A Writer drops the bytes it kept back before Clear,
// unwritten.
func (m *Masker) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleared++
	for _, p := range m.pairs {
		clear(p.find)
	}
	m.pairs, m.longest, m.secrets = nil, 0, 0
	if m.fold != nil {
		m.fold.Clear()
		m.fold = nil
	}
}

// Writer writes to the writer it wraps what is written to it, with every find of its
// masker replaced. It keeps back the end of each write that a find could start in, at
// most the longest find's length less one byte, as [Masker.Scan] does, and writes it
// with the next write or on Flush. While the finds stay the same, what it writes is
// what [Masker.Replace] makes of all the writes together. Once the masker is cleared,
// it drops the bytes it kept back before: the finds that could complete them are gone.
// It is safe for concurrent writes.
type Writer struct {
	w    io.Writer
	m    *Masker
	mu   sync.Mutex
	tail []byte
	// covered is how many bytes at the start of tail a put written already stands for.
	covered int
	// cleared is the masker's count of Clear calls when tail was kept back.
	cleared uint64
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
	out := mw.scan(b, false)
	defer clear(out)
	if len(out) == 0 {
		return len(b), nil
	}
	if _, err := mw.w.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Flush writes the bytes kept back, with every find replaced, such as one the masker
// got after the write that kept them back: the stream is over.
func (mw *Writer) Flush() error {
	if mw.m == nil {
		return nil
	}
	mw.mu.Lock()
	defer mw.mu.Unlock()
	if len(mw.tail) == 0 {
		return nil
	}
	out := mw.scan(nil, true)
	defer clear(out)
	if len(out) == 0 {
		return nil
	}
	_, err := mw.w.Write(out)
	return err
}

// scan is the bytes kept back and b with every find replaced, and keeps back again the
// end a find could start in, unless final. It drops the bytes kept back before a Clear
// of the masker, under the masker's lock, so no Clear comes between that check and the
// scan. Called with mw.mu held.
func (mw *Writer) scan(b []byte, final bool) []byte {
	m := mw.m
	m.mu.RLock()
	defer m.mu.RUnlock()
	if mw.cleared != m.cleared {
		clear(mw.tail)
		mw.tail, mw.covered, mw.cleared = nil, 0, m.cleared
	}
	buf := make([]byte, 0, len(mw.tail)+len(b))
	buf = append(append(buf, mw.tail...), b...)
	defer clear(buf)
	clear(mw.tail)
	out, rest, kept := m.scanIn(nil, buf, buf, mw.covered, final)
	mw.tail, mw.covered = nil, 0
	if rest < len(buf) {
		mw.tail, mw.covered = append([]byte(nil), buf[rest:]...), kept
	}
	return out
}
