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

// keyGroup is the run's key group as the proxy sets it, the format and the stream path
// of its model API, and where it writes its log of limit answers.
type keyGroup struct {
	g *modelkey.Group
	// format is the API format of the group's keys; empty counts as a format whose
	// requests the proxy sends again ([modelkey.Resends]) and whose stream it does not
	// read.
	format string
	// messages is the clean path of the request of the model API under the endpoint
	// whose streamed answers the proxy reads for a limit event, [modelkey.StreamPath];
	// empty for a format with none.
	messages string
	log      func(string)
}

// SetKeyGroup sets p's key group to g, the run's: of the model keys whose names g has,
// which share one placeholder, the proxy sets the group's active key on each request with the
// placeholder. After a limit refusal it sends a request again with the next key, for a
// format other than openai-responses ([modelkey.Resends]). format is the keys' API
// format, and stream the clean path of the model API's request whose streamed answers
// the proxy reads, [modelkey.StreamPath]: the proxy reads the streamed 200 of a POST to
// it with the placeholder for a limit event ([modelkey.StreamLimit]), and no other
// answer. log gets one line of each limit answer: its status, its header names, its
// error type and code, never a value. The gateway calls it once, after [New] and
// before the run's first connection.
func (p *Proxy) SetKeyGroup(g *modelkey.Group, format, stream string, log func(string)) {
	if log == nil {
		log = func(string) {}
	}
	p.keys.Store(&keyGroup{g: g, format: format, messages: stream, log: log})
}

// group is the run's key group when name is one of its keys, nil otherwise.
func (p *Proxy) group(name string) *keyGroup {
	k := p.keys.Load()
	if k == nil || !k.g.Has(name) {
		return nil
	}
	return k
}

// limitPassed returns a 429 to a request with the key group's placeholder after the
// proxy passed a limit refusal to the session, or while every key of the group is in
// cooldown: a 429 the provider never gets, until the session's join ends. d is recorded
// refused, with no credential.
func (p *Proxy) limitPassed(w http.ResponseWriter, d Decision) {
	d.Outcome, d.Credential, d.Status = Refused, "", 0
	p.observe(d)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprint(w, "qory: the run pauses: every model key of the run's key group is at its provider's limit or at its Use up to percentage, or the gateway could not send a refused request again with the next key (a request over 8 MiB, a key whose credential does not cover the path, or an openai-responses request, whose session keeps one key), and the gateway sends no more model requests in this session.\n")
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
	// must match, as [terminator.credentialFor] checks.
	clean string
	// name is the key the request goes with, the one the proxy set last.
	name string
	// scan is true for a POST to the stream path of the model API: the proxy reads its
	// streamed 200 for a limit event.
	scan bool
	// pending is the request's decision, whose credential follows the key.
	pending *pending

	mu sync.Mutex
	// body is the copy of the request's body, or of its first [modelkey.MaxCopy] + 1
	// bytes when the body is larger; nil once dropped. A drop removes the resend's
	// reference alone: each body of the copy keeps one until the transport reads it to
	// its end or closes it ([copyReader]).
	body []byte
	// copied is true when body is the whole body.
	copied bool
}

// copyBody reads r's body up to [modelkey.MaxCopy] + 1 bytes into rs, and sets r's body
// to one of the same bytes: the copy, or the bytes read and then the rest when the body is
// larger or its read failed, in which case rs has no copy to send again.
func (rs *resend) copyBody(r *http.Request) {
	if r.Body == nil || r.Body == http.NoBody {
		rs.body, rs.copied = []byte{}, true
		return
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, modelkey.MaxCopy+1))
	rs.body = b
	rs.copied = err == nil && len(b) <= modelkey.MaxCopy
	rest := r.Body
	if rs.copied {
		// The body ended within the copy: the rest is read no more, and only closed.
		rest = readCloser{http.NoBody, r.Body}
	}
	r.Body = &copyReader{b: b, rest: rest}
}

// readCloser reads from Reader and closes Closer.
type readCloser struct {
	io.Reader
	io.Closer
}

// errClosedBody is the error of a read of a body after its Close.
var errClosedBody = errors.New("read of a request body after its Close")

// copyReader is one body of the copy: its bytes from their start, then rest. It keeps
// the bytes after a drop, so a transport that still writes the body when the status
// arrives sends it whole. It sets b to nil once the bytes are read to their end or the
// body is closed, which releases them.
type copyReader struct {
	mu sync.Mutex
	// b is the copy; nil once read to its end or closed.
	b      []byte
	off    int
	closed bool
	// rest is the rest of the request's body, read after b; nil for a resend's body.
	rest io.ReadCloser
}

// Read reads the copy on, then the rest. An empty p reads nothing and returns no error.
func (c *copyReader) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, errClosedBody
	}
	if len(p) == 0 {
		c.mu.Unlock()
		return 0, nil
	}
	if c.b != nil {
		n := copy(p, c.b[c.off:])
		c.off += n
		if c.off >= len(c.b) {
			c.b = nil
		}
		if n > 0 {
			c.mu.Unlock()
			return n, nil
		}
	}
	rest := c.rest
	c.mu.Unlock()
	if rest == nil {
		return 0, io.EOF
	}
	return rest.Read(p)
}

// Close sets b to nil, which releases the copy, and closes the rest.
func (c *copyReader) Close() error {
	c.mu.Lock()
	c.b, c.closed = nil, true
	rest := c.rest
	c.mu.Unlock()
	if rest != nil {
		return rest.Close()
	}
	return nil
}

// held reports whether c still has bytes of the copy.
func (c *copyReader) held() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b != nil
}

// again is a new body of the copy, for a resend and its GetBody; errDropped once the
// copy is dropped.
func (rs *resend) again() (io.ReadCloser, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.body == nil {
		return nil, errDropped
	}
	return &copyReader{b: rs.body}, nil
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

// drop forgets the resend's copy of the body: a resend or a GetBody after it fails, and
// a body of the copy that the transport still writes keeps its bytes until it ends.
func (rs *resend) drop() {
	rs.mu.Lock()
	rs.body, rs.copied = nil, false
	rs.mu.Unlock()
}

// roundTrip sends out by rt, and, while the provider returns a limit refusal for it and
// a key of the group is left out of cooldown, sends it again from the copy of its body
// with the next key. Every answer's headers go to the group, and the copy is dropped
// once an answer's status arrives that the proxy passes on. The refusal reaches the
// caller when no key is left, with no copy, when the next key's credential does not
// cover the request ([resend.cred]), or for a format whose requests the proxy does not
// send again ([modelkey.Resends]), whose first refusal puts the key in cooldown and
// goes to the caller; the group is then stopped ([modelkey.Group.Pass]).
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
			g.Answered(rs.name, resp.StatusCode, resp.Header)
			if rs.scan && resp.StatusCode == http.StatusOK && eventStream(resp.Header) {
				resp.Body = &streamWatch{ReadCloser: resp.Body, rs: rs, format: rs.k.format, header: resp.Header.Clone()}
			}
			return resp, nil
		}
		head, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		kind, code := modelkey.ErrorOf(head)
		rs.k.log(g.Shown(accesskey.ShownName(rs.name, true), resp.StatusCode, resp.Header, kind, code))
		resends := modelkey.Resends(rs.k.format)
		// For a format that keeps one key per session, Refused reports false.
		next, ok := g.Refused(rs.name, resp.Header, code)
		// Each try cools a key, so the group runs out of keys within its size; the bound
		// stops the loop when a provider sends a reset that has passed.
		var c *Credential
		if ok && resends && rs.copied && tries < len(rs.creds) {
			c = rs.cred(next)
		}
		var name, value, account string
		if c != nil {
			v := c.secret()
			var set, accountOK bool
			name, value, set = c.header(v)
			account, accountOK = c.account(v)
			clear(v)
			if !set || !accountOK {
				c = nil
			}
		}
		if c == nil {
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
		// The key before this one set the account header to its account id. The keys
		// of a group share the header's name, case ignored, so it goes first, and the
		// next key sets it to the next key's account id.
		if rs.first.AccountHeader != "" {
			dropHeader(again.Header, rs.first.AccountHeader)
		}
		again.Header.Set(name, value)
		if c.AccountHeader != "" {
			again.Header.Set(c.AccountHeader, account)
		}
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
// is not read. An openai-responses stream has [maxFailedData] in its place.
const maxLine = 4096

// maxFailedData is the limit of a response.failed event's data, and of each of its
// lines: the event can repeat the request's instructions and tools, which pass 4096
// bytes. Its data line can come before its event field, or have none, so the limit
// holds for every line and every event's data of an openai-responses stream.
const maxFailedData = 1 << 20

// streamWatch passes a streamed answer on as it came, and reads each event of it, by
// the lines of server-sent events: a limit event of the format ([modelkey.StreamLimit])
// puts the key it went with into cooldown, and the next key becomes active. For a
// format whose requests the proxy does not send again ([modelkey.Resends]), the key
// stays active and the group is stopped too ([modelkey.Group.Pass]): the runtime's
// next request, a retry among them, gets the proxy's 429.
type streamWatch struct {
	io.ReadCloser
	rs     *resend
	format string
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
			if len(s.line) < s.limit() {
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
		if s.over {
			// The event is passed on unread: its data grows no more.
			return
		}
		sep := 0
		if len(s.data) > 0 {
			sep = 1
		}
		if len(s.data)+sep+len(value) > s.limit() {
			s.over = true
			return
		}
		if sep == 1 {
			s.data = append(s.data, '\n')
		}
		s.data = append(s.data, value...)
	}
}

// limit is the most of a line and of an event's data: [maxFailedData] for an
// openai-responses stream, else [maxLine].
func (s *streamWatch) limit() int {
	if s.format == modelkey.FormatOpenAIResponses {
		return maxFailedData
	}
	return maxLine
}

// dispatch reads the event that ended: a limit event cools the key, once per stream.
func (s *streamWatch) dispatch() {
	if s.over {
		return
	}
	kind, code, ok := modelkey.StreamLimit(s.format, s.event, s.data)
	if !ok {
		return
	}
	s.once.Do(func() {
		s.rs.k.log(s.rs.k.g.Shown(accesskey.ShownName(s.rs.name, true), http.StatusOK, s.header, kind, code))
		s.rs.k.g.Streamed(s.rs.name, s.header, code)
		if !modelkey.Resends(s.format) {
			s.rs.k.g.Pass()
		}
	})
}

// withResend attaches a [resend] to the context of a request c is set on, a key of the
// run's key group, and copies the request's body when the group's format is one whose
// requests the proxy sends again ([modelkey.Resends]). creds are the host's
// credentials, clean is the request's clean path, and scan is true for a POST to the
// model API's stream path.
func (p *Proxy) withResend(ctx context.Context, r *http.Request, k *keyGroup, c *Credential, creds []*Credential, clean string, scan bool) context.Context {
	rs := &resend{k: k, first: c, name: c.Name, clean: clean, scan: scan}
	for _, h := range creds {
		if k.g.Has(h.Name) {
			rs.creds = append(rs.creds, h)
		}
	}
	if modelkey.Resends(k.format) {
		rs.copyBody(r)
	}
	rs.pending, _ = ctx.Value(pendingKey{}).(*pending)
	return context.WithValue(ctx, resendKey{}, rs)
}
