package jcs_test

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/qoryai/runner/internal/jcs"
)

// u is a JSON \u escape of four hex digits, spelt out so no tool on the way reads it
// as the character it stands for.
func u(digits string) string { return string([]byte{92, 'u'}) + digits }

// TestTheRFCExample is the sample of RFC 8785 section 3.2.2: numbers, a string with
// escapes and the literals, in one object.
func TestTheRFCExample(t *testing.T) {
	in := `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "` + u("20ac") + `$` + u("000F") + u("000a") + `A'` + u("0042") + u("0022") + u("005c") + `\\\"\/",
  "literals": [null, true, false]
}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"` +
		string(rune(0x20ac)) + `$` + u("000f") + `\nA'B\"\\\\\"/"}`
	got, err := jcs.Canonical([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// TestTheRFCSortingExample is the sample of RFC 8785 section 3.2.3: member names sorted
// by their UTF-16 code units, so a name outside the Basic Multilingual Plane, a
// surrogate pair, sorts before U+FB33.
func TestTheRFCSortingExample(t *testing.T) {
	in := `{
  "` + u("20ac") + `": "Euro Sign",
  "\r": "Carriage Return",
  "` + u("fb33") + `": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "` + u("d83d") + u("de00") + `": "Emoji: Grinning Face",
  "` + u("0080") + `": "Control",
  "` + u("00f6") + `": "Latin Small Letter O With Diaeresis"
}`
	member := func(name rune, v string) string { return `"` + string(name) + `":"` + v + `"` }
	want := `{"\r":"Carriage Return","1":"One",` +
		member(0x80, "Control") + "," +
		member(0xf6, "Latin Small Letter O With Diaeresis") + "," +
		member(0x20ac, "Euro Sign") + "," +
		member(0x1f600, "Emoji: Grinning Face") + "," +
		member(0xfb33, "Hebrew Letter Dalet With Dagesh") + "}"
	got, err := jcs.Canonical([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// TestTheRFCNumbers are the IEEE 754 values of RFC 8785 appendix B with the text the
// scheme writes for each.
func TestTheRFCNumbers(t *testing.T) {
	for _, tc := range []struct{ bits, want string }{
		{"0000000000000000", "0"},
		{"8000000000000000", "0"},
		{"0000000000000001", "5e-324"},
		{"8000000000000001", "-5e-324"},
		{"7fefffffffffffff", "1.7976931348623157e+308"},
		{"ffefffffffffffff", "-1.7976931348623157e+308"},
		{"4340000000000000", "9007199254740992"},
		{"c340000000000000", "-9007199254740992"},
		{"4430000000000000", "295147905179352830000"},
		{"44b52d02c7e14af5", "9.999999999999997e+22"},
		{"44b52d02c7e14af6", "1e+23"},
		{"44b52d02c7e14af7", "1.0000000000000001e+23"},
		{"444b1ae4d6e2ef4e", "999999999999999700000"},
		{"444b1ae4d6e2ef4f", "999999999999999900000"},
		{"444b1ae4d6e2ef50", "1e+21"},
		{"3eb0c6f7a0b5ed8c", "9.999999999999997e-7"},
		{"3eb0c6f7a0b5ed8d", "0.000001"},
		{"41b3de4355555553", "333333333.3333332"},
		{"41b3de4355555554", "333333333.33333325"},
		{"41b3de4355555555", "333333333.3333333"},
		{"41b3de4355555556", "333333333.3333334"},
		{"41b3de4355555557", "333333333.33333343"},
		{"becbf647612f3696", "-0.0000033333333333333333"},
		{"43143ff3c1cb0959", "1424953923781206.2"},
	} {
		b, err := hex.DecodeString(tc.bits)
		if err != nil {
			t.Fatal(err)
		}
		f := math.Float64frombits(binary.BigEndian.Uint64(b))
		// The double as Go writes it with every digit it needs to read back, so the
		// literal the scheme reads is this double and no neighbour.
		literal := strconv.FormatFloat(f, 'g', 17, 64)
		got, err := jcs.Number(literal)
		if err != nil {
			t.Errorf("%s: %v", tc.bits, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s (%s): got %s, want %s", tc.bits, literal, got, tc.want)
		}
		doc, err := jcs.Canonical([]byte("[" + literal + "]"))
		if err != nil || string(doc) != "["+tc.want+"]" {
			t.Errorf("%s in an array: %s %v", tc.bits, doc, err)
		}
	}
}

// TestWhatTheSchemeRefuses pins the input that is not I-JSON: a name twice in one
// object, invalid UTF-8, a lone surrogate, a number beyond the double's range, two
// values, and no value.
func TestWhatTheSchemeRefuses(t *testing.T) {
	for _, in := range []string{
		`{"a":1,"a":2}`,
		"{\"a\":\"\xff\"}",
		`["` + u("d800") + `"]`,
		`[1e400]`,
		`{} {}`,
		``,
		`{"a":}`,
	} {
		if got, err := jcs.Canonical([]byte(in)); err == nil {
			t.Errorf("%q was canonicalised to %s", in, got)
		}
	}
}

// TestNumberTakesJSONNumbersAlone pins that Number refuses what strconv reads and JSON
// does not spell as a number.
func TestNumberTakesJSONNumbersAlone(t *testing.T) {
	for _, in := range []string{"Inf", "-Inf", "NaN", "0x1p4", "+1", "1.", ".5", "01", "1e", " 1", "1_000", `"1"`, "true"} {
		if got, err := jcs.Number(in); err == nil {
			t.Errorf("%q was written as %s", in, got)
		}
	}
	for in, want := range map[string]string{"-0": "0", "1E2": "100", "0.5": "0.5", "-1.5e-7": "-1.5e-7"} {
		if got, err := jcs.Number(in); err != nil || got != want {
			t.Errorf("%s: %s %v, want %s", in, got, err, want)
		}
	}
}

// TestStringsAreEscapedAsJSONStringifyEscapesThem pins the escapes: the short forms of
// the five control characters, \u with lower-case hex for the others, and every other
// character, DEL, U+2028 and the HTML characters included, as it is.
func TestStringsAreEscapedAsJSONStringifyEscapesThem(t *testing.T) {
	in := `["` + u("0000") + u("001F") + `\b\f\n\r\t` + u("007f") + u("2028") + `<>&"]`
	want := `["` + u("0000") + u("001f") + `\b\f\n\r\t` + "\x7f" + string(rune(0x2028)) + `<>&"]`
	got, err := jcs.Canonical([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// TestCanonicalAgreesWithTheStandardLibrary checks documents of several shapes against
// encoding/json/jsontext's own RFC 8785 serialisation, which is written independently.
func TestCanonicalAgreesWithTheStandardLibrary(t *testing.T) {
	for _, in := range []string{
		`{"version":1,"egress":{"mode":"enforce","allow":["api.example","*.example.org"],"paths":{"api.example":["/v1/*","/"]}},"tools":[]}`,
		`{"b":[1,2.5,-0,1e21,1e-7,123456789012345680000,0.1,100],"a":{"z":null,"y":true,"x":false}}`,
		`{"` + u("00e9") + `":"` + u("00e9") + `","e":"plain","E":"upper","":"empty"}`,
		`[[],{},"",0,-1.5e-10,12345.678]`,
		`"` + u("d83d") + u("de00") + ` and \t"`,
		strings.Repeat("[", 50) + strings.Repeat("]", 50),
	} {
		got, err := jcs.Canonical([]byte(in))
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		v := jsontext.Value(in)
		if err := v.Canonicalize(); err != nil {
			t.Fatal(err)
		}
		if string(got) != string(v) {
			t.Errorf("%s:\ngot  %s\nwant %s", in, got, v)
		}
	}
}
