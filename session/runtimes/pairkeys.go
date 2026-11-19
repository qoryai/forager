package runtimes

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// PairKeys is the keys that a key=value pair sets, read as Codex reads a --config pair:
// the key before the first =, with the spaces around it removed, and the value in TOML
// as the value of a key in a document (codex-rs utils/cli/src/config_override.rs:55-82
// and :97-104 in 0.169.0). For a value that is an inline table, such as
// features={hooks=false} or features={"hooks"={enabled=false}}, they are the key of
// each value in the table below the pair's key, features.hooks and
// features.hooks.enabled, in the order of the table, through nested tables and dotted
// keys; an empty table is the key it is at. For any other value, and for a table that
// does not parse, it is the pair's key alone. After the table, the value may have
// spaces, tabs and a comment, and nothing else: a value with another line after the
// table, which Codex reads as more of the document, is read as no table. A quoted key
// has its escapes of TOML 1.1 decoded, and is joined to the pair's key with a dot, so
// a quoted key with a dot in it reads as two parts. A local date and a time with a
// space between them, such as 1979-05-27 07:32:00Z, is one value.
func PairKeys(pair string) []string {
	key, value, _ := strings.Cut(pair, "=")
	key = strings.TrimSpace(key)
	p := &inlineTable{s: strings.TrimSpace(value)}
	if !strings.HasPrefix(p.s, "{") {
		return []string{key}
	}
	var keys []string
	if !p.table(key, &keys) || !p.end() {
		return []string{key}
	}
	return keys
}

// end reports whether s has nothing from i on but spaces, tabs and a comment.
func (p *inlineTable) end() bool {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
	if p.next('#') {
		return !strings.ContainsAny(p.s[p.i:], "\n\r")
	}
	return p.i == len(p.s)
}

// inlineTable reads the keys of a TOML inline table in s from i on. It reads more than
// TOML 1.0 takes, such as newlines and a comma before the }, since a value that Codex
// does not parse sets no key of the table.
type inlineTable struct {
	s string
	i int
}

// space skips spaces, tabs, newlines and comments.
func (p *inlineTable) space() {
	for p.i < len(p.s) {
		switch c := p.s[p.i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			p.i++
		case c == '#':
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
		default:
			return
		}
	}
}

// next reports whether s at i starts with c, and skips it when it does.
func (p *inlineTable) next(c byte) bool {
	if p.i < len(p.s) && p.s[p.i] == c {
		p.i++
		return true
	}
	return false
}

// table reads the table at i, which starts with {, and adds to keys the key of each of
// its values below prefix. It reports whether the table parsed.
func (p *inlineTable) table(prefix string, keys *[]string) bool {
	if !p.next('{') {
		return false
	}
	empty := true
	for {
		p.space()
		if p.next('}') {
			if empty {
				*keys = append(*keys, prefix)
			}
			return true
		}
		key, ok := p.dottedKey()
		if !ok {
			return false
		}
		p.space()
		if !p.next('=') {
			return false
		}
		p.space()
		full := prefix + "." + key
		if p.i < len(p.s) && p.s[p.i] == '{' {
			if !p.table(full, keys) {
				return false
			}
		} else {
			if !p.value() {
				return false
			}
			*keys = append(*keys, full)
		}
		empty = false
		p.space()
		if !p.next(',') {
			p.space()
			if p.i >= len(p.s) || p.s[p.i] != '}' {
				return false
			}
		}
	}
}

// dottedKey reads a key of one or more parts with dots between them, spaces around
// each dot allowed, and returns the parts joined with dots.
func (p *inlineTable) dottedKey() (string, bool) {
	var parts []string
	for {
		part, ok := p.simpleKey()
		if !ok {
			return "", false
		}
		parts = append(parts, part)
		at := p.i
		p.space()
		if !p.next('.') {
			p.i = at
			return strings.Join(parts, "."), true
		}
		p.space()
	}
}

// simpleKey reads a bare key, a basic string or a literal string of one line, and
// returns the key's text without its quotes, a basic string's escapes decoded.
func (p *inlineTable) simpleKey() (string, bool) {
	if p.i >= len(p.s) {
		return "", false
	}
	switch q := p.s[p.i]; q {
	case '"', '\'':
		if strings.HasPrefix(p.s[p.i:], strings.Repeat(string(q), 3)) {
			return "", false
		}
		start := p.i + 1
		if !p.str() {
			return "", false
		}
		if q == '\'' {
			return p.s[start : p.i-1], true
		}
		return unescape(p.s[start : p.i-1])
	}
	start := p.i
	for p.i < len(p.s) {
		c := p.s[p.i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			break
		}
		p.i++
	}
	return p.s[start:p.i], p.i > start
}

// str skips a basic or literal string at i, of one line or of several.
func (p *inlineTable) str() bool {
	q := p.s[p.i]
	if strings.HasPrefix(p.s[p.i:], strings.Repeat(string(q), 3)) {
		end := strings.Index(p.s[p.i+3:], strings.Repeat(string(q), 3))
		if end < 0 {
			return false
		}
		p.i += 3 + end + 3
		// A multi-line string may end with up to two more quotes.
		for range 2 {
			p.next(q)
		}
		return true
	}
	for p.i++; p.i < len(p.s); p.i++ {
		switch p.s[p.i] {
		case '\\':
			if q == '"' {
				p.i++
			}
		case '\n':
			return false
		case q:
			p.i++
			return true
		}
	}
	return false
}

// value skips a value that is no inline table: a string, an array, whose inline
// tables it skips too, or another value up to the next comma, }, ], space or comment.
func (p *inlineTable) value() bool {
	if p.i >= len(p.s) {
		return false
	}
	switch p.s[p.i] {
	case '"', '\'':
		return p.str()
	case '[':
		p.i++
		for {
			p.space()
			if p.next(']') {
				return true
			}
			if p.i < len(p.s) && p.s[p.i] == '{' {
				var ignored []string
				if !p.table("", &ignored) {
					return false
				}
			} else if !p.value() {
				return false
			}
			p.space()
			if !p.next(',') {
				p.space()
				if !p.next(']') {
					return false
				}
				return true
			}
		}
	}
	start := p.i
	p.bare()
	// A local date, then a space and a digit, is a date and a time: 1979-05-27 07:32:00.
	if isDate(p.s[start:p.i]) && p.i+1 < len(p.s) && p.s[p.i] == ' ' && isDigit(p.s[p.i+1]) {
		p.i++
		p.bare()
	}
	return p.i > start
}

// bare skips a value that is no string, array or table, up to the next comma, }, ],
// space or comment.
func (p *inlineTable) bare() {
	for p.i < len(p.s) && !strings.ContainsRune(",}] \t\r\n#", rune(p.s[p.i])) {
		p.i++
	}
}

// isDigit reports whether c is an ASCII digit.
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// isDate reports whether v is a local date of TOML, such as 1979-05-27.
func isDate(v string) bool {
	if len(v) != 10 || v[4] != '-' || v[7] != '-' {
		return false
	}
	for i := range len(v) {
		if i != 4 && i != 7 && !isDigit(v[i]) {
			return false
		}
	}
	return true
}

// shortEscapes are the escapes of TOML 1.1 of one letter, and hexEscapes the count of
// hexadecimal digits after \x, \u and \U.
var (
	shortEscapes = map[byte]byte{'b': '\b', 't': '\t', 'n': '\n', 'f': '\f', 'r': '\r', 'e': 0x1b, '"': '"', '\\': '\\'}
	hexEscapes   = map[byte]int{'x': 2, 'u': 4, 'U': 8}
)

// unescape is the text of a basic string of one line between its quotes, with the
// escapes of TOML 1.1 decoded: \b, \t, \n, \f, \r, \e, \", \\, \xHH, \uHHHH and
// \UHHHHHHHH. It reports false for another escape and for a code point that is no
// Unicode scalar value.
func unescape(s string) (string, bool) {
	if !strings.Contains(s, "\\") {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i++; i >= len(s) {
			return "", false
		}
		if c, ok := shortEscapes[s[i]]; ok {
			b.WriteByte(c)
			continue
		}
		digits := hexEscapes[s[i]]
		if digits == 0 || i+digits >= len(s) {
			return "", false
		}
		n, err := strconv.ParseUint(s[i+1:i+1+digits], 16, 32)
		if err != nil || !utf8.ValidRune(rune(n)) {
			return "", false
		}
		b.WriteRune(rune(n))
		i += digits
	}
	return b.String(), true
}
