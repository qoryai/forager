package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/modelkey"
)

// maxErrorBody is the most of a limit refusal's body the proxy reads for its error type
// before it passes the refusal on or sends the request again.
const maxErrorBody = 64 << 10

// keyGroup is the run's key group as the proxy sets it, and where it writes its log of
// limit answers.
type keyGroup struct {
	g   *modelkey.Group
	log func(string)
}

// SetKeyGroup gives p the run's key group: of the model keys whose names g has, which
// share one placeholder, the proxy sets the group's active key on each request with the
// placeholder, and sends a request again with the next key after a limit refusal. log
// gets one line of each limit answer: its status, its header names and its error type,
// never a value. The gateway calls it once, after [New] and before the run's first
// connection.
func (p *Proxy) SetKeyGroup(g *modelkey.Group, log func(string)) {
	if log == nil {
		log = func(string) {}
	}
	p.keys.Store(&keyGroup{g: g, log: log})
}

// group is the run's key group when name is one of its keys, nil otherwise.
func (p *Proxy) group(name string) *keyGroup {
	k := p.keys.Load()
	if k == nil || !k.g.Has(name) {
		return nil
	}
	return k
}

// limitPassed answers a request with the key group's placeholder after the proxy passed
// a limit refusal to the session: a 429 the provider never sees, until the session's
// join ends. d is recorded refused, with no credential.
func (p *Proxy) limitPassed(w http.ResponseWriter, d Decision) {
	d.Outcome, d.Credential, d.Status = Refused, "", 0
	p.observe(d)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprint(w, "qory: start the run again once a model key's cooldown ends: every key of the run's key group is at its provider's limit, and the gateway sends no more model requests in this session.\n")
}

// resendKey marks the context of a request with a key of the group, with its [resend].
type resendKey struct{}

// resend is one request with a key of the group: the keys of its host, the key it goes
// with, and a copy of its body, kept until the answer's status arrives.
type resend struct {
	k     *keyGroup
	creds []*Credential
	// name is the key the request goes with, the one the proxy set last.
	name string
	// body is the copy of the request's body, nil once dropped or when the body was over
	// [modelkey.MaxCopy].
	body   []byte
	copied bool
	// pending is the request's decision, whose credential follows the key.
	pending *pending
}

// copyBody reads r's body up to [modelkey.MaxCopy] and gives r a body of the same
// bytes: the copy, or the bytes read and then the rest when the body is larger. It
// returns the copy, nil for a larger body or one whose read failed.
func copyBody(r *http.Request) ([]byte, bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return []byte{}, true
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, modelkey.MaxCopy+1))
	if err != nil || len(b) > modelkey.MaxCopy {
		r.Body = readCloser{io.MultiReader(bytes.NewReader(b), r.Body), r.Body}
		return nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return b, true
}

// readCloser reads from Reader and closes Closer.
type readCloser struct {
	io.Reader
	io.Closer
}

// resendOf is the request's [resend], nil for a request with no key of the group.
func resendOf(r *http.Request) *resend {
	rs, _ := r.Context().Value(resendKey{}).(*resend)
	return rs
}

// cred is the credential of the key name among rs's, nil for none.
func (rs *resend) cred(name string) *Credential {
	for _, c := range rs.creds {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// drop forgets the copy of the body.
func (rs *resend) drop() { rs.body, rs.copied = nil, false }

// roundTrip sends out by rt, and, while the provider answers it with a limit refusal and
// a key of the group is left out of cooldown, sends it again from the copy of its body
// with the next key. Every answer's headers go to the group. The refusal reaches the
// caller when no key is left, or with no copy, and the group then holds the stop.
func (rs *resend) roundTrip(rt http.RoundTripper, out *http.Request) (*http.Response, error) {
	g := rs.k.g
	for tries := 0; ; tries++ {
		resp, err := rt.RoundTrip(out)
		if err != nil {
			rs.drop()
			return nil, err
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			rs.drop()
			g.Answered(rs.name, resp.Header)
			if resp.StatusCode == http.StatusOK && eventStream(resp.Header) {
				resp.Body = &streamWatch{ReadCloser: resp.Body, rs: rs, header: resp.Header.Clone()}
			}
			return resp, nil
		}
		head, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		kind, code := modelkey.ErrorOf(head)
		rs.k.log(modelkey.Shown(accesskey.ShownName(rs.name, true), resp.StatusCode, resp.Header, kind))
		next, ok := g.Refused(rs.name, resp.Header, code)
		c := rs.cred(next)
		var name, value string
		if ok && c != nil {
			v := c.secret()
			var set bool
			name, value, set = c.header(v)
			clear(v)
			ok = set
		}
		// Each try cools a key, so the group runs out of keys within its size; the bound
		// holds a provider that names a reset already past.
		if !ok || c == nil || !rs.copied || tries >= len(rs.creds) {
			rs.drop()
			g.Pass()
			resp.Body = readCloser{io.MultiReader(bytes.NewReader(head), resp.Body), resp.Body}
			return resp, nil
		}
		resp.Body.Close()
		again := out.Clone(out.Context())
		again.Body = io.NopCloser(bytes.NewReader(rs.body))
		again.ContentLength = int64(len(rs.body))
		body := rs.body
		again.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		again.Header.Set(name, value)
		rs.name = next
		if rs.pending != nil {
			rs.pending.d.Credential = next
		}
		out = again
	}
}

// eventStream reports whether an answer's Content-Type is text/event-stream.
func eventStream(h http.Header) bool {
	t, _, err := mime.ParseMediaType(h.Get("Content-Type"))
	return err == nil && t == "text/event-stream"
}

// maxLine is the most of one line of a stream the proxy reads for an error event; a
// longer line is passed on unread, as every byte is.
const maxLine = 4096

// streamWatch passes a streamed answer on as it came, and reads each line of it for an
// error event of the type rate_limit_error: the key it went with then goes into
// cooldown, and the next key becomes active.
type streamWatch struct {
	io.ReadCloser
	rs     *resend
	header http.Header
	once   sync.Once
	line   []byte
	long   bool
	// errorEvent says the event's lines so far contain event: error.
	errorEvent bool
}

// Read reads the stream on, and reads its lines.
func (s *streamWatch) Read(p []byte) (int, error) {
	n, err := s.ReadCloser.Read(p)
	for _, b := range p[:n] {
		if b != '\n' {
			if len(s.line) < maxLine {
				s.line = append(s.line, b)
			} else {
				s.long = true
			}
			continue
		}
		if !s.long {
			s.read(strings.TrimSuffix(string(s.line), "\r"))
		}
		s.line, s.long = s.line[:0], false
	}
	return n, err
}

// read reads one whole line of the stream.
func (s *streamWatch) read(line string) {
	switch {
	case line == "":
		s.errorEvent = false
	case strings.HasPrefix(line, "event:"):
		s.errorEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:")) == "error"
	case strings.HasPrefix(line, "data:"):
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		isError := s.errorEvent || strings.HasPrefix(data, `{"type":"error"`)
		if isError && strings.Contains(data, `"`+modelkey.RateLimitError+`"`) {
			s.once.Do(func() {
				s.rs.k.log(modelkey.Shown(accesskey.ShownName(s.rs.name, true), http.StatusOK, s.header, modelkey.RateLimitError))
				s.rs.k.g.Streamed(s.rs.name, s.header)
			})
		}
	}
}

// withResend attaches a [resend] to the context of a request c is set on, a key of the
// run's key group, and copies the request's body. creds are the host's credentials.
func (p *Proxy) withResend(ctx context.Context, r *http.Request, k *keyGroup, c *Credential, creds []*Credential) context.Context {
	rs := &resend{k: k, name: c.Name}
	for _, h := range creds {
		if k.g.Has(h.Name) {
			rs.creds = append(rs.creds, h)
		}
	}
	rs.body, rs.copied = copyBody(r)
	rs.pending, _ = ctx.Value(pendingKey{}).(*pending)
	return context.WithValue(ctx, resendKey{}, rs)
}
