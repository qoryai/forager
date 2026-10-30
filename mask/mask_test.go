package mask_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/mask"
)

// fakePassword stands in for a forwarder's password; it is no real one.
const fakePassword = "fakeproxypasswordforthisexampleonly01234567"

// TestProxyMasksThePasswordAndItsBasicForm pins the forms of a proxy URL's password:
// the password, and the base64 of qory and the password in the standard and the URL
// alphabet, each with qory-proxy-password in the same form.
func TestProxyMasksThePasswordAndItsBasicForm(t *testing.T) {
	m := mask.Proxy("qory", fakePassword)
	in := "HTTP_PROXY=http://qory:" + fakePassword + "@127.0.0.1:41853\n" +
		"Proxy-Authorization: Basic cW9yeTpmYWtlcHJveHlwYXNzd29yZGZvcnRoaXNleGFtcGxlb25seTAxMjM0NTY3\n"
	want := "HTTP_PROXY=http://qory:qory-proxy-password@127.0.0.1:41853\n" +
		"Proxy-Authorization: Basic cW9yeTpxb3J5LXByb3h5LXBhc3N3b3Jk\n"
	if got := m.Replace(in); got != want {
		t.Errorf("Replace:\n%s\nwant:\n%s", got, want)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		pw := "x+/" + fakePassword[3:]
		f := enc.EncodeToString([]byte("qory:" + pw))
		if got, put := mask.Proxy("qory", pw).Replace(f), enc.EncodeToString([]byte("qory:"+mask.ProxyPassword)); got != put {
			t.Errorf("%q: %q, want %q", f, got, put)
		}
	}
	var finds []string
	for _, f := range m.Finds() {
		finds = append(finds, string(f))
	}
	if want := []string{fakePassword, "cW9yeTpmYWtlcHJveHlwYXNzd29yZGZvcnRoaXNleGFtcGxlb25seTAxMjM0NTY3"}; !slices.Equal(finds, want) {
		t.Errorf("the finds %q, want %q", finds, want)
	}
	if mask.Proxy("qory") != nil || mask.Proxy("qory", "") != nil {
		t.Error("no password has a masker")
	}
	var none *mask.Masker
	if none.Replace(fakePassword) != fakePassword {
		t.Error("a nil masker replaced the value")
	}
}

// TestTheWriterMasksAPasswordAtEverySplit writes the password twice in two writes,
// split at every place, and a stream that ends in the start of the password: every
// copy is replaced, and what is kept back is at most 63 bytes.
func TestTheWriterMasksAPasswordAtEverySplit(t *testing.T) {
	m := mask.Proxy("qory", fakePassword)
	body := "a " + fakePassword + fakePassword + " b " + fakePassword[:5]
	want := "a " + mask.ProxyPassword + mask.ProxyPassword + " b " + fakePassword[:5]
	for i := 0; i <= len(body); i++ {
		var out bytes.Buffer
		w := mask.NewWriter(&out, m)
		w.Write([]byte(body[:i]))
		if held := i - out.Len(); held > 63 && !strings.Contains(body[:i], fakePassword) {
			t.Errorf("split at %d: %d bytes kept back", i, held)
		}
		w.Write([]byte(body[i:]))
		w.Flush()
		if out.String() != want {
			t.Errorf("split at %d: %q", i, out.String())
		}
	}
	var out bytes.Buffer
	w := mask.NewWriter(&out, nil)
	w.Write([]byte(fakePassword[:5]))
	if out.String() != fakePassword[:5] {
		t.Errorf("a writer with no masker kept back %q", out.String())
	}
}

// TestClearOverwritesEveryFind pins Clear: every find is zero bytes after it.
func TestClearOverwritesEveryFind(t *testing.T) {
	m := mask.Proxy("qory", fakePassword)
	finds := m.Finds()
	m.Clear()
	for _, f := range finds {
		if !bytes.Equal(f, make([]byte, len(f))) {
			t.Errorf("a find after Clear: %q", f)
		}
	}
}

// TestAProxyPasswordIsMaskedAsAURLPrintsIt pins a proxy password with the bytes a URL
// escapes, @ / : % ? and #: as it is, in a proxy URL's userinfo, by url.QueryEscape, by
// url.PathEscape and percent-encoded, each form is the placeholder, in Replace and in a
// writer's lines.
func TestAProxyPasswordIsMaskedAsAURLPrintsIt(t *testing.T) {
	const password = "fake@pass/word:50%?x#y-0123"
	m := mask.Proxy("qory", password)
	proxyURL := (&url.URL{Scheme: "http", User: url.UserPassword("qory", password), Host: "127.0.0.1:2375"}).String()
	for _, text := range []string{
		"proxyconnect tcp: " + proxyURL + ": refused",
		"password=" + url.QueryEscape(password),
		"/p/" + url.PathEscape(password) + "/",
		"raw " + password,
	} {
		if !strings.Contains(text, "fake") {
			t.Fatalf("%q has no password", text)
		}
		got := m.Replace(text)
		if strings.Contains(got, "fake") || !strings.Contains(got, mask.ProxyPassword) {
			t.Errorf("Replace(%q) = %q", text, got)
		}
		var out bytes.Buffer
		w := mask.NewWriter(&out, m)
		for i := range len(text) {
			w.Write([]byte{text[i]})
		}
		w.Flush()
		if out.String() != got {
			t.Errorf("the writer wrote %q, Replace %q", out.String(), got)
		}
	}
	if got, want := m.Replace("proxyconnect tcp: "+proxyURL+": refused"), "proxyconnect tcp: http://qory:qory-proxy-password@127.0.0.1:2375: refused"; got != want {
		t.Errorf("Replace = %q, want %q", got, want)
	}
}

// TestAddProxyMasksEachPasswordAdded pins a run's one masker: an empty one masks
// nothing, and each password added, with its basic form, is replaced, the first one
// still after the second is added; an empty password adds nothing.
func TestAddProxyMasksEachPasswordAdded(t *testing.T) {
	m := &mask.Masker{}
	if !m.Empty() || !(*mask.Masker)(nil).Empty() {
		t.Error("a masker with nothing added is not empty")
	}
	m.AddProxy("qory", "")
	if !m.Empty() {
		t.Error("an empty password added a find")
	}
	second := strings.ToUpper(fakePassword)
	m.AddProxy("qory", fakePassword)
	m.AddProxy("qory", second)
	basic := base64.StdEncoding.EncodeToString([]byte("qory:" + fakePassword))
	got := m.Replace("http://qory:" + fakePassword + "@x http://qory:" + second + "@y " + basic)
	want := "http://qory:" + mask.ProxyPassword + "@x http://qory:" + mask.ProxyPassword + "@y " + base64.StdEncoding.EncodeToString([]byte("qory:"+mask.ProxyPassword))
	if m.Empty() || got != want {
		t.Errorf("Replace %q, want %q", got, want)
	}
}

// TestAddSecretPutsTheSecretInEveryForm pins AddSecret: the value as it is,
// percent-encoded and JSON-escaped is *** each, a proxy password added first keeps
// qory-proxy-password, and an empty value adds nothing.
func TestAddSecretPutsTheSecretInEveryForm(t *testing.T) {
	m := &mask.Masker{}
	m.AddSecret(nil)
	if !m.Empty() {
		t.Fatal("an empty value added a find")
	}
	m.AddProxy("qory", fakePassword)
	m.AddSecret([]byte(fakePassword))
	m.AddSecret([]byte(`fake/secret"<1>`))
	in := `a fake/secret"<1> b fake%2Fsecret%22%3C1%3E c "fake/secret\"<1>" d "fake\/secret\"<1>" e ` + fakePassword
	want := `a *** b *** c "***" d "***" e qory-proxy-password`
	if got := m.Replace(in); got != want {
		t.Errorf("Replace:\n%s\nwant:\n%s", got, want)
	}
}

// TestClearRemovesEveryFind pins a masker after Clear: it replaces nothing, a run of
// zero bytes as long as a find among it.
func TestClearRemovesEveryFind(t *testing.T) {
	m := &mask.Masker{}
	m.AddSecret([]byte("fake-secret"))
	m.Clear()
	zeros := string(make([]byte, len("fake-secret")))
	if !m.Empty() || m.Replace(zeros) != zeros {
		t.Error("a masker after Clear still replaces")
	}
}

// TestAMaskerAddsWhileItMasks pins a masker that gets a value while writers mask with
// it, which the race detector checks: from the add on, the value is ***.
func TestAMaskerAddsWhileItMasks(t *testing.T) {
	m := &mask.Masker{}
	m.AddProxy("qory", fakePassword)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var out bytes.Buffer
		w := mask.NewWriter(&out, m)
		for range 200 {
			w.Write([]byte("line fake-added-secret " + fakePassword + "\n"))
			m.Replace("fake-added-secret")
		}
		w.Flush()
	}()
	m.AddSecret([]byte("fake-added-secret"))
	<-done
	if got := m.Replace("fake-added-secret"); got != "***" {
		t.Errorf("Replace after the add: %q", got)
	}
}

// TestOverlappingFindsAreReplacedAsOne pins two values that overlap: the bytes from the
// first one's start to the second one's end are one ***, in a string and in a stream
// split inside the overlap; a chain of a short value repeated is replaced whole.
func TestOverlappingFindsAreReplacedAsOne(t *testing.T) {
	m := &mask.Masker{}
	m.AddSecret([]byte("prefixSEC"))
	m.AddSecret([]byte("SECRET"))
	if got, want := m.Replace("a prefixSECRET b SECRET c prefixSEC d"), "a *** b *** c *** d"; got != want {
		t.Errorf("Replace %q, want %q", got, want)
	}
	for split := 1; split < len("x prefixSECRET y"); split++ {
		in := "x prefixSECRET y"
		var out bytes.Buffer
		w := mask.NewWriter(&out, m)
		w.Write([]byte(in[:split]))
		w.Write([]byte(in[split:]))
		w.Flush()
		if out.String() != "x *** y" {
			t.Errorf("split at %d: %q", split, out.String())
		}
	}
	short := &mask.Masker{}
	short.AddSecret([]byte("aa"))
	if got := short.Replace("x aaaaa y"); got != "x *** y" {
		t.Errorf("a chain of aa: %q", got)
	}
}

// TestFlushMasksAFindAddedAfterTheWrite pins a value added while the writer keeps back
// its start: Flush replaces it.
func TestFlushMasksAFindAddedAfterTheWrite(t *testing.T) {
	m := &mask.Masker{}
	m.AddSecret([]byte("fake-secret-long"))
	var out bytes.Buffer
	w := mask.NewWriter(&out, m)
	w.Write([]byte("x fake-secret"))
	m.AddSecret([]byte("fake-secret"))
	w.Flush()
	if out.String() != "x ***" {
		t.Errorf("after Flush %q, want %q", out.String(), "x ***")
	}
}

// TestOverlappingFindsInTurnAreLinear masks 1 MiB of a chain of two values that
// overlap in turn, and 1 MiB of a value and its percent-encoded form that overlap in
// turn, whole and in writes of 32 KiB. When each widening of the range searched every
// find again from the range's start, such a chain took minutes.
func TestOverlappingFindsInTurnAreLinear(t *testing.T) {
	two := &mask.Masker{}
	two.AddSecret([]byte("k123"))
	two.AddSecret([]byte("3xyk"))
	percent := &mask.Masker{}
	percent.AddSecret([]byte("a/a"))
	for name, c := range map[string]struct {
		m    *mask.Masker
		body []byte
	}{
		"k123 and 3xyk": {two, bytes.Repeat([]byte("k123xy"), (1<<20)/6)},
		"a/a and a%2Fa": {percent, bytes.Repeat([]byte("a/a%2F"), (1<<20)/6)},
	} {
		start := time.Now()
		if got := c.m.Replace(string(c.body)); !strings.HasPrefix(got, "***") || strings.Contains(got, "k123") || strings.Contains(got, "a/a") {
			t.Errorf("%s: Replace left %q", name, got[:min(len(got), 40)])
		}
		var out bytes.Buffer
		w := mask.NewWriter(&out, c.m)
		for b := c.body; len(b) > 0; b = b[min(len(b), 32<<10):] {
			w.Write(b[:min(len(b), 32<<10)])
		}
		w.Flush()
		if took := time.Since(start); took > 2*time.Second {
			t.Errorf("%s: masking 1 MiB twice took %v", name, took)
		}
	}
}

// TestAValueSplitAfterALongChainIsMasked pins a chain of overlapping finds of 70 KiB
// that ends in the start of another value, which the next write completes: one ***
// stands for the chain and the value, so no byte of the value reaches the writer.
func TestAValueSplitAfterALongChainIsMasked(t *testing.T) {
	m := &mask.Masker{}
	m.AddSecret([]byte("xxxxxxxx"))
	m.AddSecret([]byte("xxSECRETVALUE0123"))
	var out bytes.Buffer
	w := mask.NewWriter(&out, m)
	w.Write(append(bytes.Repeat([]byte("x"), 70<<10), "SECRETVA"...))
	w.Write([]byte("LUE0123 end"))
	w.Flush()
	if got := out.String(); strings.Contains(got, "SECRET") || strings.Contains(got, "VALUE") || got != "*** end" {
		t.Errorf("the writer wrote %q", got)
	}
}

// TestAValueThatContainsAnotherIsMaskedAtEverySplit pins two values where the longer
// contains the shorter, in each of the four forms that differ for these values among
// the five Add looks for, since the JSON escape without the escapes of <, > and & is
// the value as it is: a write split at every place of the longer value's form gives
// the put in that form and no byte of either value. Before, a split after the shorter
// value replaced it and let the rest of the longer one through.
func TestAValueThatContainsAnotherIsMaskedAtEverySplit(t *testing.T) {
	m := &mask.Masker{}
	m.Add([]byte("Ab/c<9"), []byte("***"))
	m.Add([]byte("ZZAb/c<9YY"), []byte("***"))
	for _, c := range []struct{ long, put string }{
		{"ZZAb/c<9YY", "***"},
		{"ZZAb%2Fc%3C9YY", "%2A%2A%2A"},
		{"ZZAb/c" + `\` + "u003c9YY", "***"},
		{`ZZAb\/c<9YY`, "***"},
	} {
		in := "x " + c.long + " y"
		for split := 1; split < len(in); split++ {
			var out bytes.Buffer
			w := mask.NewWriter(&out, m)
			w.Write([]byte(in[:split]))
			w.Write([]byte(in[split:]))
			w.Flush()
			if want := "x " + c.put + " y"; out.String() != want {
				t.Errorf("%s split at %d: %q, want %q", c.long, split, out.String(), want)
			}
		}
	}
}

// TestALongChainKeepsNoReplacedByte pins long chains of overlapping finds whose last
// bytes the writer keeps back: when no find completes from them, in the next write or
// at Flush, none of them goes out, and one *** stands for the chain, also in writes of
// 1 byte, whose time stays linear.
func TestALongChainKeepsNoReplacedByte(t *testing.T) {
	one := &mask.Masker{}
	one.AddSecret([]byte("ab12XYab12"))
	two := &mask.Masker{}
	two.AddSecret([]byte("k123"))
	two.AddSecret([]byte("3xyk"))
	xs := &mask.Masker{}
	xs.AddSecret([]byte("xxxxxxxx"))
	xs.AddSecret([]byte("xxSECRETVALUE0123"))
	for _, c := range []struct {
		name   string
		m      *mask.Masker
		writes []string
		want   string
	}{
		{"ab12XYab12, then Flush", one, []string{strings.Repeat("ab12XY", 12000) + "ab12"}, "***"},
		{"k123 and 3xyk, then zz end", two, []string{strings.Repeat("k123xy", 12000) + "k123", "zz end"}, "***zz end"},
		{"x and SECRETVA, then Q end", xs, []string{strings.Repeat("x", 70<<10) + "SECRETVA", "Q end"}, "***SECRETVAQ end"},
		{"x, then Flush", xs, []string{strings.Repeat("x", 70<<10)}, "***"},
		{"256 KiB of x in 4 KiB writes", xs, slices.Repeat([]string{strings.Repeat("x", 4<<10)}, 64), "***"},
		{"256 KiB of x in 1-byte writes", xs, slices.Repeat([]string{"x"}, 256<<10), "***"},
	} {
		var out bytes.Buffer
		w := mask.NewWriter(&out, c.m)
		start := time.Now()
		for _, b := range c.writes {
			w.Write([]byte(b))
		}
		w.Flush()
		if took := time.Since(start); took > 2*time.Second {
			t.Errorf("%s: the writes took %v", c.name, took)
		}
		if out.String() != c.want {
			got := out.String()
			t.Errorf("%s: the writer wrote %q, want %q", c.name, got[:min(len(got), 60)], c.want)
		}
	}
}

// TestTheWriterAgreesWithReplace compares the writer with Replace on random texts of a
// small alphabet, with values of 2 to 6 bytes that overlap, contain each other or start
// with each other, split into random writes and flushed, many of 1 or 2 bytes: the
// writer's output is Replace's output, byte for byte. The values get *** each, or a
// put of their own index, so the output shows which value won a place.
func TestTheWriterAgreesWithReplace(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	word := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = "ab"[r.IntN(2)]
		}
		return string(b)
	}
	for _, puts := range []string{"***", "an index"} {
		for range 20000 {
			m := &mask.Masker{}
			var values []string
			for k := range 1 + r.IntN(3) {
				v := word(2 + r.IntN(5))
				values = append(values, v)
				if puts == "***" {
					m.AddSecret([]byte(v))
				} else {
					m.Add([]byte(v), []byte{'<', '0' + byte(k), '>'})
				}
			}
			text := "<" + word(r.IntN(40)) + ">"
			var out bytes.Buffer
			w := mask.NewWriter(&out, m)
			var splits []int
			for rest := text; len(rest) > 0; {
				// Writes of 1 or 2 bytes come as often as longer ones.
				n := 1 + r.IntN(min(len(rest), []int{2, len(rest)}[r.IntN(2)]))
				splits = append(splits, n)
				w.Write([]byte(rest[:n]))
				rest = rest[n:]
			}
			w.Flush()
			if got, want := out.String(), m.Replace(text); got != want {
				t.Fatalf("puts %s, values %q, text %q in writes of %v: the writer wrote %q, Replace %q", puts, values, text, splits, got, want)
			}
		}
	}
}

// TestALongerValueAtTheSamePlaceWinsAtEverySplit pins two values where the longer
// starts with the shorter, each with a put of its own: a write that ends inside the
// longer value, after the shorter, gives the longer value's put once the next write
// completes it. So do the base64 forms of a basic credential, the padded form added
// first: a split inside the padding keeps the put's padding. Before, the write that
// ended there got the shorter put.
func TestALongerValueAtTheSamePlaceWinsAtEverySplit(t *testing.T) {
	prefix := &mask.Masker{}
	prefix.Add([]byte("abcdef12"), []byte("SHORT"))
	prefix.Add([]byte("abcdef12345"), []byte("LONG"))
	basic := &mask.Masker{}
	pair, stand := []byte("user:fake-secre1"), []byte("user:placeholder")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		basic.Add([]byte(enc.EncodeToString(pair)), []byte(enc.EncodeToString(stand)))
	}
	padded, put := base64.StdEncoding.EncodeToString(pair), base64.StdEncoding.EncodeToString(stand)
	if !strings.HasSuffix(padded, "==") || !strings.HasSuffix(put, "==") {
		t.Fatalf("the padded forms %q and %q end without ==", padded, put)
	}
	for _, c := range []struct {
		name string
		m    *mask.Masker
		in   string
		want string
	}{
		{"abcdef12345", prefix, "x abcdef12345 y", "x LONG y"},
		{"the padded base64", basic, "Basic " + padded + " y", "Basic " + put + " y"},
	} {
		if got := c.m.Replace(c.in); got != c.want {
			t.Fatalf("%s: Replace gives %q, want %q", c.name, got, c.want)
		}
		for split := 1; split < len(c.in); split++ {
			var out bytes.Buffer
			w := mask.NewWriter(&out, c.m)
			w.Write([]byte(c.in[:split]))
			w.Write([]byte(c.in[split:]))
			w.Flush()
			if out.String() != c.want {
				t.Errorf("%s split at %d: %q, want %q", c.name, split, out.String(), c.want)
			}
		}
	}
}

// TestAWriterDropsWhatItKeptBackBeforeClear pins a writer whose masker is cleared while
// it keeps back the start of a value: Flush and the next write drop those bytes, so the
// writes before and after the Clear never join into the value unmasked.
func TestAWriterDropsWhatItKeptBackBeforeClear(t *testing.T) {
	for name, after := range map[string]func(w *mask.Writer){
		"Flush":         func(w *mask.Writer) { w.Flush() },
		"a write of 23": func(w *mask.Writer) { w.Write([]byte("23 end")); w.Flush() },
	} {
		m := &mask.Masker{}
		m.AddSecret([]byte("fake-value-0123"))
		var out bytes.Buffer
		w := mask.NewWriter(&out, m)
		w.Write([]byte("start fake-value-01"))
		m.Clear()
		after(w)
		if got := out.String(); strings.Contains(got, "fake-value") {
			t.Errorf("%s after Clear: the writer wrote %q", name, got)
		}
	}
}

// TestAddSecretRefusesPastTheCaps pins the bounds of AddSecret: a value of 4096 bytes
// is added and one of 4097 is not; of 1025 different values the last is refused, a
// value the masker has already is added again without counting, and Clear starts the
// count over. Each error starts with the fix and contains no value.
func TestAddSecretRefusesPastTheCaps(t *testing.T) {
	m := mask.New()
	if err := m.AddSecret([]byte(strings.Repeat("v", mask.MaxSecretSize))); err != nil {
		t.Fatalf("a value at the size cap: %v", err)
	}
	long := "fake-long-" + strings.Repeat("w", mask.MaxSecretSize)
	err := m.AddSecret([]byte(long))
	if want := "add a value of at most 4096 bytes to the masker: this value has 4106 bytes, and it is not masked"; err == nil || err.Error() != want {
		t.Errorf("a value past the size cap: %v, want %q", err, want)
	}
	for i := range mask.MaxSecrets - 1 {
		if err := m.AddSecret(fmt.Appendf(nil, "fake-value-%04d", i)); err != nil {
			t.Fatalf("value %d: %v", i, err)
		}
	}
	err = m.AddSecret([]byte("fake-value-over"))
	if want := "add at most 1024 values to the masker: it has 1024 already, and this value is not masked"; err == nil || err.Error() != want {
		t.Errorf("a value past the count: %v, want %q", err, want)
	}
	if err := m.AddSecret([]byte("fake-value-0000")); err != nil {
		t.Errorf("a value the masker has: %v", err)
	}
	if got := m.Replace("fake-value-0001 fake-value-over " + long[:20]); got != "*** fake-value-over "+long[:20] {
		t.Errorf("Replace: %q", got)
	}
	m.Clear()
	if err := m.AddSecret([]byte("fake-value-over")); err != nil {
		t.Errorf("a value after Clear: %v", err)
	}
}
