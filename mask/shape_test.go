package mask_test

import (
	"bytes"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/mask"
)

// fakeShaped are fake keys of each shape of mask.Shapes, at the shape's least length:
// none is a real key.
var fakeShaped = []string{
	"sk-ant-" + strings.Repeat("x", 16),
	"ghp_" + strings.Repeat("x", 36),
	"ghs_" + strings.Repeat("x", 36),
	"gho_" + strings.Repeat("x", 36),
	"ghu_" + strings.Repeat("x", 36),
	"ghr_" + strings.Repeat("x", 36),
	"github_pat_" + strings.Repeat("x", 16),
	"AKIA" + strings.Repeat("X", 16),
	"ASIA" + strings.Repeat("X", 16),
	"Bearer " + strings.Repeat("x", 16),
}

// TestNewMasksEveryShape pins mask.Shapes in a masker from New: each fake key at its
// least length is a bare ***, its prefix included, inside text and at its ends; one
// character fewer is left as it is; a token ends at the first character outside its
// alphabet; and a token of more than the shape's Max characters, 4096 for a bearer
// token and 256 for the others, has its characters after Max left as they are. The
// bearer token's prefix matches in any case, followed by 1 to 16 spaces or tabs. A
// masker that New did not make replaces no shape.
func TestNewMasksEveryShape(t *testing.T) {
	m := mask.New()
	for _, key := range fakeShaped {
		if got := m.Replace("key=" + key + " end"); got != "key=*** end" {
			t.Errorf("%q: Replace %q", key, got)
		}
		if got := m.Replace(key); got != "***" {
			t.Errorf("%q alone: Replace %q", key, got)
		}
		short := key[:len(key)-1]
		if got := m.Replace("key=" + short + " end"); got != "key="+short+" end" {
			t.Errorf("%q, one character short: Replace %q", short, got)
		}
		if got := (&mask.Masker{}).Replace(key); got != key {
			t.Errorf("%q in a zero masker: Replace %q", key, got)
		}
	}
	for text, want := range map[string]string{
		"ghp_" + strings.Repeat("a", 36) + "-tail":                   "***-tail",
		"AKIA" + strings.Repeat("A", 16) + "lower":                   "***lower",
		"Authorization: Bearer abc.DEF_ghi~jkl+mno/pq=rs-tu":         "Authorization: ***",
		"Bearer " + strings.Repeat("t", mask.MaxSecretSize+3):        "***ttt",
		"Bearer " + jwt(905):                                         "***",
		"AKIA" + strings.Repeat("X", 259):                            "***XXX",
		"ASIA" + strings.Repeat("X", 259):                            "***XXX",
		"ghr_" + strings.Repeat("r", 72) + " end":                    "*** end",
		"ghp_" + strings.Repeat("a", 262):                            "***aaaaaa",
		"authorization: BEARER\t" + strings.Repeat("x", 16):          "authorization: ***",
		"bearer  \t " + strings.Repeat("x", 16) + " end":             "*** end",
		"Bearer" + strings.Repeat(" ", 17) + strings.Repeat("x", 16): "Bearer" + strings.Repeat(" ", 17) + strings.Repeat("x", 16),
		"Bearer" + strings.Repeat("x", 16):                           "Bearer" + strings.Repeat("x", 16),
		"sk-ant-api03-" + strings.Repeat("k", 20) + `"}`:             `***"}`,
	} {
		if got := m.Replace(text); got != want {
			t.Errorf("Replace(%q) = %q, want %q", text, got, want)
		}
	}
}

// jwt is a fake JSON web token of n characters: three base64url parts joined by dots.
func jwt(n int) string {
	b := []byte(strings.Repeat("eyJhbGciOiJIUzI1NiJ9", n/20+1)[:n])
	b[n/3], b[2*n/3] = '.', '.'
	return string(b)
}

// TestTheWriterAgreesWithReplaceOnALongToken pins a bearer token of more than 4096
// characters split into two writes at every byte: the writer's output is Replace's,
// *** and then the characters past the 4096th.
func TestTheWriterAgreesWithReplaceOnALongToken(t *testing.T) {
	m := mask.New()
	text := "Authorization: Bearer " + strings.Repeat("t", mask.MaxSecretSize+3) + "\n"
	want := m.Replace(text)
	if want != "Authorization: ***ttt\n" {
		t.Fatalf("Replace = %q", want)
	}
	for k := 0; k <= len(text); k++ {
		if got := writeSplit(m, text, []int{k}); got != want {
			t.Fatalf("split at %d: the writer wrote %q, Replace %q", k, got, want)
		}
	}
}

// TestAKeyRepeatedInWritesOfOneByteIsFast pins the cost of the shapes whose prefix can
// occur inside their token, AKIA and ASIA: 200 KB of each prefix repeated, in writes of
// 1 byte, masks in less than 5 seconds, 150 under the race detector, and as one
// Replace; each took about 1.4 seconds on an arm64 laptop with 9 shapes. With a cap of 4096 for AKIA it took about 830 µs per byte, 166 seconds.
func TestAKeyRepeatedInWritesOfOneByteIsFast(t *testing.T) {
	m := mask.New()
	for _, prefix := range []string{"AKIA", "ASIA"} {
		text := strings.Repeat(prefix, 50_000)
		var out bytes.Buffer
		w := mask.NewWriter(&out, m)
		began := time.Now()
		for i := range len(text) {
			w.Write([]byte{text[i]})
		}
		w.Flush()
		took := time.Since(began)
		t.Logf("%s: %d bytes in writes of 1 byte: %s, %s per byte", prefix, len(text), took, took/time.Duration(len(text)))
		if limit := slower * 5 * time.Second; took > limit {
			t.Errorf("%s: %d bytes in writes of 1 byte took %s, want less than %s", prefix, len(text), took, limit)
		}
		if want := m.Replace(text); out.String() != want {
			t.Errorf("%s: the writer wrote %d bytes, Replace %d", prefix, out.Len(), len(want))
		}
	}
}

// shapedText is a random text of pieces that make shapes' finds and nearly make them:
// prefixes and their starts, tokens of 0 to 300 characters of an alphabet that mixes
// the shapes' alphabets, and values the masker has.
func shapedText(r *rand.Rand, values []string) string {
	pieces := []string{"sk-ant-", "ghp_", "ghs_", "gho_", "ghu_", "ghr_", "github_pat_", "AKIA", "ASIA", "AS", "Bearer ", "bearer\t", "BEARER  ", "beare", " \t", "gh", "github_", "Bear", "sk-an", "AK", " ", "*", "\n", "%2F", "/"}
	var b strings.Builder
	for range 1 + r.IntN(8) {
		switch r.IntN(4) {
		case 0, 1:
			b.WriteString(pieces[r.IntN(len(pieces))])
		case 2:
			n := r.IntN(301)
			alphabet := []string{"xX9", "X9", "x_-", "x.=~", "X"}[r.IntN(5)]
			for range n {
				b.WriteByte(alphabet[r.IntN(len(alphabet))])
			}
		default:
			if len(values) > 0 {
				b.WriteString(values[r.IntN(len(values))])
			}
		}
	}
	return b.String()
}

// writeSplit writes text to a writer on m in the writes splits has, then flushes it,
// and returns what the writer wrote.
func writeSplit(m *mask.Masker, text string, splits []int) string {
	var out bytes.Buffer
	w := mask.NewWriter(&out, m)
	rest := text
	for _, n := range splits {
		w.Write([]byte(rest[:n]))
		rest = rest[n:]
	}
	w.Write([]byte(rest))
	w.Flush()
	return out.String()
}

// TestTheWriterAgreesWithReplaceOnShapes is TestTheWriterAgreesWithReplace on texts
// with shapes' finds, in a masker from New with values that overlap tokens and a
// proxy password, whose put differs: the writer's output, split into two writes at
// every byte, in writes of one byte, and in random writes, is Replace's output, one
// scan of the whole text, byte for byte.
func TestTheWriterAgreesWithReplaceOnShapes(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	candidates := []string{"xxxxXXXX", "x-y", "ghp_xx", "X9X9", "Bearer x", "AKIAX", "xxx", "rer xx", "x*x"}
	for range 300 {
		m := mask.New()
		var values []string
		for range r.IntN(3) {
			v := candidates[r.IntN(len(candidates))]
			values = append(values, v)
			m.AddSecret([]byte(v))
		}
		if r.IntN(4) == 0 {
			m.AddProxy("qory", "xx9xx")
			values = append(values, "xx9xx")
		}
		text := shapedText(r, values)
		want := m.Replace(text)
		for k := 0; k <= len(text); k++ {
			if got := writeSplit(m, text, []int{k}); got != want {
				t.Fatalf("values %q, text %q split at %d: the writer wrote %q, Replace %q", values, text, k, got, want)
			}
		}
		ones := make([]int, len(text))
		for i := range ones {
			ones[i] = 1
		}
		if got := writeSplit(m, text, ones); got != want {
			t.Fatalf("values %q, text %q in writes of 1 byte: the writer wrote %q, Replace %q", values, text, got, want)
		}
		var splits []int
		for rest := len(text); rest > 0; {
			n := 1 + r.IntN(min(rest, 40))
			splits = append(splits, n)
			rest -= n
		}
		if got := writeSplit(m, text, splits); got != want {
			t.Fatalf("values %q, text %q in writes of %v: the writer wrote %q, Replace %q", values, text, splits, got, want)
		}
	}
}

// TestMaskingTwiceIsMaskingOnce pins that a masker from New makes nothing more of its
// own output: on random texts with shapes' finds and values, one of them with a * inside
// it, Replace of Replace's output is Replace's output.
func TestMaskingTwiceIsMaskingOnce(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	candidates := []string{"xxxxXXXX", "x-y", "ghp_xx", "fake*value", "fa**ke-value", "Bearer x"}
	for range 3000 {
		m := mask.New()
		var values []string
		for range r.IntN(3) {
			v := candidates[r.IntN(len(candidates))]
			values = append(values, v)
			m.AddSecret([]byte(v))
		}
		text := shapedText(r, values)
		once := m.Replace(text)
		if twice := m.Replace(once); twice != once {
			t.Fatalf("values %q, text %q: once %q, twice %q", values, text, once, twice)
		}
	}
}

// TestALongerShapeAtTheSameStartKeepsItsPut pins a write that ends inside a shape's
// find that starts where a shorter find with another put does: a proxy password that is
// an AWS key id at its least length, followed by more of the key's alphabet. At every
// split, the writer writes the shape's ***, as one scan of the whole text does.
func TestALongerShapeAtTheSameStartKeepsItsPut(t *testing.T) {
	m := mask.New()
	password := "AKIA" + strings.Repeat("X", 16)
	m.AddProxy("qory", password)
	text := password + "XYZ end"
	for k := 0; k <= len(text); k++ {
		if got := writeSplit(m, text, []int{k}); got != "*** end" {
			t.Errorf("split at %d: the writer wrote %q, want %q", k, got, "*** end")
		}
	}
}
