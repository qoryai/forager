package mask_test

import (
	"bytes"
	"encoding/base64"
	"slices"
	"strings"
	"testing"

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
