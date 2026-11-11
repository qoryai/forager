package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/policy"
)

// maxErrorBody is the most of a limit refusal's body the proxy reads for its error type
// before it passes the refusal on or sends the request again.
const maxErrorBody = 64 << 10

// keyGroup is the run's key group as the proxy sets it, the path of its model API's
// messages, and where it writes its log of limit answers.
type keyGroup struct {
	g *modelkey.Group
	// messages is the clean path of the messages request of the model API under the
	// endpoint, whose streamed answers the proxy reads for a rate_limit_error event;
	// empty for a format with none.
	messages string
	log      func(string)
}

// SetKeyGroup gives p the run's key group: of the model keys whose names g has, which
// share one placeholder, the proxy sets the group's active key on each request with the
// placeholder, and sends a request again with the next key after a limit refusal.
// messages is the clean path of the model API's messages request, [modelkey.MessagesPath]:
// the proxy reads the streamed 200 of a POST to it with the placeholder for a
// rate_limit_error event, and no other answer. log gets one line of each limit answer:
// its status, its header names and its error type, never a value. The gateway calls it
// once, after [New] and before the run's first connection.
func (p *Proxy) SetKeyGroup(g *modelkey.Group, messages string, log func(string)) {
	if log == nil {
		log = func(string) {}
	}
	p.keys.Store(&keyGroup{g: g, messages: messages, log: log})
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
// a limit refusal to the session, or while every key of the group is in cooldown: a 429
// the provider never sees, until the session's join ends. d is recorded refused, with
// no credential.
func (p *Proxy) limitPassed(w http.ResponseWriter, d Decision) {
	d.Outcome, d.Credential, d.Status = Refused, "", 0
	p.observe(d)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprint(w, "qory: start the run again once a model key's cooldown ends: every key of the run's key group is at its provider's limit, and the gateway sends no more model requests in this session.\n")
}

// resendKey marks the context of a request with a key of the group, with its [resend].
type resendKey struct{}

// errDropped is the error of a body read again after the proxy dropped its copy.
var errDropped = errors.New("the proxy dropped the copy of the request body once the answer's status arrived")

// resend is one request with a key of the group: the keys of its host, the key it goes
// with, and a copy of its body, from the request until the answer's status arrives.
type resend struct {
	k     *keyGroup
	creds []*Credential
	// first is the credential the proxy set first; a resend sets a key with its scheme,
	// username and header alone.
	first *Credential
	// clean is the request's clean path, which the paths of the next key's credential
	// must match, as [terminator.credentialFor] decides.
	clean string
	// name is the key the request goes with, the one the proxy set last.
	name string
	// scan is true for a POST to the messages path of the model API: the proxy reads
	// its streamed 200 for a rate_limit_error event.
	scan bool
	// pending is the request's decision, whose credential follows the key.
	pending *pending

	mu sync.Mutex
	// body is the copy of the request's body, or of its first [modelkey.MaxCopy] + 1
	// bytes when the body is larger; nil once dropped. Every reader of the request's
	// body reads it through rs, so a drop leaves no reference to the bytes.
	body []byte
	// copied is true when body is the whole body.
	copied bool
}

// copyBody reads r's body up to [modelkey.MaxCopy] + 1 bytes into rs, and gives r a body
// of the same bytes: the copy, or the bytes read and then the rest when the body is
// larger or its read failed, in which case rs has no copy to send again.
func (rs *resend) copyBody(r *http.Request) {
	if r.Body == nil || r.Body == http.NoBody {
		rs.body, rs.copied = []byte{}, true
		return
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, modelkey.MaxCopy+1))
	rs.body = b
	if err != nil || len(b) > modelkey.MaxCopy {
		r.Body = readCloser{io.MultiReader(&copyReader{rs: rs}, r.Body), r.Body}
		return
	}
	rs.copied = true
	r.Body = readCloser{&copyReader{rs: rs}, r.Body}
}

// readCloser reads from Reader and closes Closer.
type readCloser struct {
	io.Reader
	io.Closer
}

// copyReader reads rs's copy of the body from its start, under rs.mu: it reads nothing
// more once rs drops the copy.
type copyReader struct {
	rs  *resend
	off int
}

// Read reads the copy on.
func (c *copyReader) Read(p []byte) (int, error) {
	c.rs.mu.Lock()
	defer c.rs.mu.Unlock()
	if c.off >= len(c.rs.body) {
		return 0, io.EOF
	}
	n := copy(p, c.rs.body[c.off:])
	c.off += n
	return n, nil
}

// again is a new body of the copy, for a resend and its GetBody; errDropped once the
// copy is dropped.
func (rs *resend) again() (io.ReadCloser, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.body == nil {
		return nil, errDropped
	}
	return io.NopCloser(&copyReader{rs: rs}), nil
}

// resendOf is the request's [resend], nil for a request with no key of the group.
func resendOf(r *http.Request) *resend {
	rs, _ := r.Context().Value(resendKey{}).(*resend)
	return rs
}

// cred is the credential of the key name among rs's that the proxy sets on the request:
// the first one with the first credential's scheme, username and header, whose paths
// cover every path or match rs's path. Nil for none.
func (rs *resend) cred(name string) *Credential {
	for _, c := range rs.creds {
		if c.Name != name || c.Scheme != rs.first.Scheme || c.Username != rs.first.Username || !strings.EqualFold(c.Header, rs.first.Header) {
			continue
		}
		if c.Paths == nil {
			return c
		}
		if _, ok := policy.MatchPath(c.Paths, rs.clean); ok {
			return c
		}
	}
	return nil
}

// drop forgets the copy of the body: every reader of it reads nothing more.
func (rs *resend) drop() {
	rs.mu.Lock()
	rs.body, rs.copied = nil, false
	rs.mu.Unlock()
}

// roundTrip sends out by rt, and, while the provider answers it with a limit refusal and
// a key of the group is left out of cooldown, sends it again from the copy of its body
// with the next key. Every answer's headers go to the group, and the copy is dropped
// once an answer's status arrives that the proxy passes on. The refusal reaches the
// caller when no key is left, with no copy, or when the next key's credential does not
// cover the request ([resend.cred]); the group then holds the stop.
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
			if rs.scan && resp.StatusCode == http.StatusOK && eventStream(resp.Header) {
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
		// stops the loop when a provider sends a reset that has passed.
		if !ok || c == nil || !rs.copied || tries >= len(rs.creds) {
			rs.drop()
			g.Pass()
			resp.Body = readCloser{io.MultiReader(bytes.NewReader(head), resp.Body), resp.Body}
			return resp, nil
		}
		resp.Body.Close()
		again := out.Clone(out.Context())
		// The copy stays until the drop: a body made before it reads the copy, and one
		// asked for after it fails.
		again.Body, _ = rs.again()
		again.ContentLength = int64(len(rs.body))
		again.GetBody = rs.again
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

// maxLine is the most of one line, and of one event's data, of a stream the proxy reads
// for an error event; a longer line is passed on unread, as every byte is, and its event
// is not read.
const maxLine = 4096

// streamWatch passes a streamed answer on as it came, and reads each event of it, by
// the lines of server-sent events: an event whose event field is error, and whose data
// is an error of the type rate_limit_error, puts the key it went with into cooldown,
// and the next key becomes active.
type streamWatch struct {
	io.ReadCloser
	rs     *resend
	header http.Header
	once   sync.Once
	line   []byte
	long   bool
	// event is the event field of the event so far, and data its data lines, joined by
	// a newline; over is true when a line or the data passed [maxLine].
	event string
	data  []byte
	over  bool
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
		if s.long {
			s.over = true
		} else {
			s.read(strings.TrimSuffix(string(s.line), "\r"))
		}
		s.line, s.long = s.line[:0], false
	}
	return n, err
}

// read reads one whole line of the stream. An empty line ends the event.
func (s *streamWatch) read(line string) {
	if line == "" {
		s.dispatch()
		s.event, s.data, s.over = "", s.data[:0], false
		return
	}
	field, value, _ := strings.Cut(line, ":")
	value = strings.TrimPrefix(value, " ")
	switch field {
	case "event":
		s.event = value
	case "data":
		if len(s.data) > 0 {
			s.data = append(s.data, '\n')
		}
		if len(s.data)+len(value) > maxLine {
			s.over = true
			return
		}
		s.data = append(s.data, value...)
	}
}

// dispatch reads the event that ended: an error event of the type rate_limit_error
// cools the key, once per stream.
func (s *streamWatch) dispatch() {
	if s.event != "error" || s.over {
		return
	}
	if kind, _ := modelkey.ErrorOf(s.data); kind != modelkey.RateLimitError {
		return
	}
	s.once.Do(func() {
		s.rs.k.log(modelkey.Shown(accesskey.ShownName(s.rs.name, true), http.StatusOK, s.header, modelkey.RateLimitError))
		s.rs.k.g.Streamed(s.rs.name, s.header)
	})
}

// withResend attaches a [resend] to the context of a request c is set on, a key of the
// run's key group, and copies the request's body. creds are the host's credentials,
// clean is the request's clean path, and scan is true for a POST to the model API's
// messages path.
func (p *Proxy) withResend(ctx context.Context, r *http.Request, k *keyGroup, c *Credential, creds []*Credential, clean string, scan bool) context.Context {
	rs := &resend{k: k, first: c, name: c.Name, clean: clean, scan: scan}
	for _, h := range creds {
		if k.g.Has(h.Name) {
			rs.creds = append(rs.creds, h)
		}
	}
	rs.copyBody(r)
	rs.pending, _ = ctx.Value(pendingKey{}).(*pending)
	return context.WithValue(ctx, resendKey{}, rs)
}
