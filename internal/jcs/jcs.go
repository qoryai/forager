// Package jcs is the JSON Canonicalization Scheme of RFC 8785: one serialisation of a
// JSON value, the same bytes for the same data however it was written, so a digest of
// it is the digest of the data.
//
// [Canonical] reads one JSON value and writes it with no whitespace, the members of
// every object sorted by their names as UTF-16 code units, every string with the
// escapes of ECMAScript's JSON.stringify and no others, and every number as
// ECMAScript's Number.prototype.toString writes the IEEE 754 double it reads as. The
// input is I-JSON (RFC 7493): a document with invalid UTF-8, a lone surrogate, a
// member name twice in one object or a number beyond the double's range is refused.
package jcs

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Canonical returns the RFC 8785 serialisation of the one JSON value in b.
func Canonical(b []byte) ([]byte, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(b))
	var out bytes.Buffer
	if err := value(dec, &out); err != nil {
		return nil, err
	}
	if _, err := dec.ReadToken(); err == nil {
		return nil, errors.New("jcs: more than one JSON value")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("jcs: %w", err)
	}
	return out.Bytes(), nil
}

// value writes the next value of dec in canonical form.
func value(dec *jsontext.Decoder, out *bytes.Buffer) error {
	tok, err := dec.ReadToken()
	if err != nil {
		return fmt.Errorf("jcs: %w", err)
	}
	switch tok.Kind() {
	case 'n':
		out.WriteString("null")
	case 't':
		out.WriteString("true")
	case 'f':
		out.WriteString("false")
	case '"':
		writeString(out, tok.String())
	case '0':
		s, err := Number(tok.String())
		if err != nil {
			return err
		}
		out.WriteString(s)
	case '[':
		out.WriteByte('[')
		for first := true; dec.PeekKind() != ']'; first = false {
			if !first {
				out.WriteByte(',')
			}
			if err := value(dec, out); err != nil {
				return err
			}
		}
		if _, err := dec.ReadToken(); err != nil {
			return fmt.Errorf("jcs: %w", err)
		}
		out.WriteByte(']')
	case '{':
		type member struct {
			name  string
			units []uint16
			value []byte
		}
		var members []member
		for dec.PeekKind() != '}' {
			name, err := dec.ReadToken()
			if err != nil {
				return fmt.Errorf("jcs: %w", err)
			}
			// What ReadToken returns is the decoder's until its next call.
			n := name.String()
			var v bytes.Buffer
			if err := value(dec, &v); err != nil {
				return err
			}
			members = append(members, member{n, utf16.Encode([]rune(n)), v.Bytes()})
		}
		if _, err := dec.ReadToken(); err != nil {
			return fmt.Errorf("jcs: %w", err)
		}
		slices.SortFunc(members, func(a, b member) int { return slices.Compare(a.units, b.units) })
		out.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				out.WriteByte(',')
			}
			writeString(out, m.name)
			out.WriteByte(':')
			out.Write(m.value)
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("jcs: unexpected %v", tok.Kind())
	}
	return nil
}

// writeString writes s as JSON.stringify quotes it: the quotation mark and the reverse
// solidus escaped, the five control characters with a short escape written so, every
// other control character as \u and four lower-case hex digits, and everything else as
// it is.
func writeString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

// Number returns a JSON number literal as RFC 8785 writes it: the IEEE 754 double the
// literal reads as, in the shortest form that reads back as the same double, laid out
// by ECMAScript's Number.prototype.toString. Zero, negative zero included, is "0". A
// literal beyond the double's range is refused, as NaN and the infinities have no
// literal.
func Number(literal string) (string, error) {
	f, err := strconv.ParseFloat(literal, 64)
	if err != nil {
		return "", fmt.Errorf("jcs: the number %s is not an IEEE 754 double", literal)
	}
	return format(f)
}

// format lays out a double as ECMAScript does, from its shortest decimal digits d of
// length k and the exponent n with the value d × 10^(n-k).
func format(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("jcs: NaN and the infinities are not JSON numbers")
	}
	if f == 0 {
		return "0", nil
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	mantissa, exponent, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	e, err := strconv.Atoi(exponent)
	if err != nil {
		return "", err
	}
	k, n := len(digits), e+1
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k), nil
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:], nil
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits, nil
	}
	exp := "e+"
	if n-1 < 0 {
		exp = "e-"
	}
	exp += strconv.Itoa(abs(n - 1))
	if k == 1 {
		return sign + digits + exp, nil
	}
	return sign + digits[:1] + "." + digits[1:] + exp, nil
}

func abs(i int) int {
	if i < 0 {
		return -i
	}
	return i
}
