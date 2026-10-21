package proxy

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/mask"
)

// errUnaskedSwitch is the answer to a 101 from a host whose request went without its
// Upgrade, on the plain path and on a host that gets a credential.
var errUnaskedSwitch = errors.New("the host answered 101 Switching Protocols to a request that asked for no upgrade")

// masker replaces a credential's value in what a host answers, in each form the value
// is looked for in, with the placeholder in the same form: a [mask.Masker].
type masker = mask.Masker

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
	m.Add(v, []byte(placeholder))
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
			m.Add(find, put)
			clear(find)
		}
	}
	return m
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
	mw.m.Header(mw.w.Header())
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
	mw.m.Header(mw.w.Header())
}

// serveMasked serves r with h through a masking writer of m, then clears the bytes kept
// back and every find, also when h ends with a panic, as the reverse proxy does when a
// copy fails part way.
func serveMasked(h http.Handler, w http.ResponseWriter, r *http.Request, m *masker) {
	defer m.Clear()
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
