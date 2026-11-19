package runtimes

import "strings"

// PairKeys is the keys that a key=value pair sets, read as Codex reads a --config pair:
// the key before the first =, with the spaces around it removed, and the value in TOML
// (codex-rs utils/cli/src/config_override.rs:55-82 in 0.169.0). For a value that is an
// inline table, such as features={hooks=false} or features={"hooks"={enabled=false}},
// they are the key of each value in the table below the pair's key, features.hooks and
// features.hooks.enabled, in the order of the table, through nested tables and dotted
// keys; an empty table is the key it is at. For any other value, and for a table that
// does not parse, it is the pair's key alone. A key of the table is joined to the
// pair's key with a dot as it is, so a quoted key with a dot in it reads as two parts.
func PairKeys(pair string) []string {
	key, value, _ := strings.Cut(pair, "=")
	key = strings.TrimSpace(key)
	p := &inlineTable{s: strings.TrimSpace(value)}
	if !strings.HasPrefix(p.s, "{") {
		return []string{key}
	}
	var keys []string
	if !p.table(key, &keys) {
		return []string{key}
	}
	return keys
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

// simpleKey reads a bare key, a basic string or a literal string, and returns the
// key's text without its quotes. A basic string's escapes stay as they are written.
func (p *inlineTable) simpleKey() (string, bool) {
	if p.i >= len(p.s) {
		return "", false
	}
	switch p.s[p.i] {
	case '"', '\'':
		start := p.i + 1
		if !p.str() {
			return "", false
		}
		return p.s[start : p.i-1], true
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
	for p.i < len(p.s) && !strings.ContainsRune(",}] \t\r\n#", rune(p.s[p.i])) {
		p.i++
	}
	return p.i > start
}
