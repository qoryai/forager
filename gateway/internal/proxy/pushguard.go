package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/qoryai/forager/accesskey"
)

// PushRefRule is the rule a denial names of a git push the branch guard refuses: a
// push to a host of a credential whose ref commands name a ref other than the
// credential's PushRef, a push through a credential with no PushRef, and a request
// that names receive-pack in any other form than git's push over HTTP. A refusal of the
// proxy's, in either mode, with a 403, before anything reaches the host.
const PushRefRule = "wall:push-ref"

// MaxPushCommands is the most bytes of a push's request the guard reads for its ref
// commands, the shallow lines, the commands and their flush: a section that does not
// end within it is refused.
const MaxPushCommands = 64 << 10

// PushCommandsWait is how long the guard waits for a push's ref commands to arrive
// whole: a section that has not ended by then is refused.
var PushCommandsWait = 10 * time.Second

// pushRefusal is why the guard refuses a push, and the text of its 403.
type pushRefusal struct{ text string }

func (e *pushRefusal) Error() string { return e.text }

// pushLike reports whether r names receive-pack, in any case, in its path or its
// Content-Type: what the guard reads, or refuses, on a host of a credential.
func pushLike(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.URL.EscapedPath()), "receive-pack") ||
		strings.Contains(strings.ToLower(r.URL.Path), "receive-pack") ||
		strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "receive-pack")
}

// guardPush is the branch guard for r, a request to host whose path clean the proxy
// decided, with c the credential the proxy sets on it, nil for none: nil when r is no
// push or a push that changes c.PushRef alone, whose body then goes on as it came,
// and the refusal otherwise. A push is any request [pushLike] reports. Only POST
// .../git-receive-pack with Content-Type application/x-git-receive-pack-request and no
// content coding is read; any other form is refused, and so is a push through a
// credential with no PushRef. The guard reads the request's shallow lines and its ref
// commands up to their flush before anything is sent: each command must create,
// update or delete PushRef. A signed push, a line of another form, and a section over
// [MaxPushCommands] or slower than [PushCommandsWait] are refused, and so is a
// capability outside [pushCapabilities], push-options among them: a push option asks
// some hosts to act on a branch other than PushRef, such as a merge into main. After
// the flush the body ends, or a pack follows: anything else is refused. A body of a
// flush alone, git's probe before a large push, names no ref and goes on; a flush
// followed by more bytes is refused.
func guardPush(w http.ResponseWriter, r *http.Request, host, clean string, c *Credential) error {
	if !pushLike(r) {
		return nil
	}
	where := host + accesskey.ShownValue(clean, false)
	if _, ok := pushPath(r); !ok || r.Method != http.MethodPost || !pushContentType(r.Header.Get("Content-Type")) || !identity(r.Header.Values("Content-Encoding")) {
		return &pushRefusal{fmt.Sprintf("qory: push with git over HTTPS: the gateway refuses any other request to %s that names receive-pack\n", where)}
	}
	if c == nil || c.PushRef == "" {
		return &pushRefusal{fmt.Sprintf("qory: push through qory's push step: the run's credential for %s allows no push\n", host)}
	}
	rc := http.NewResponseController(w)
	// A connection whose deadline cannot be set is read with no limit in time, as
	// every other body.
	if rc.SetReadDeadline(time.Now().Add(PushCommandsWait)) == nil {
		defer rc.SetReadDeadline(time.Time{})
	}
	read, err := readCommands(r.Body, c.PushRef)
	var refused *pushRefusal
	switch {
	case errors.As(err, &refused):
		return &pushRefusal{strings.ReplaceAll(refused.text, "@WHERE@", where)}
	case err != nil:
		return &pushRefusal{fmt.Sprintf("qory: send the push's ref commands within %d KiB and %s: the gateway refuses the push to %s\n", MaxPushCommands>>10, PushCommandsWait, where)}
	}
	r.Body = &replayed{Reader: io.MultiReader(bytes.NewReader(read), r.Body), Closer: r.Body}
	return nil
}

// replayed is a request's body with the bytes the guard read put back in front.
type replayed struct {
	io.Reader
	io.Closer
}

// pushContentType reports whether a Content-Type is git's for a push's request, its
// parameters and case aside.
func pushContentType(v string) bool {
	media, _, _ := strings.Cut(v, ";")
	return strings.EqualFold(strings.TrimSpace(media), "application/x-git-receive-pack-request")
}

// identity reports whether Content-Encoding values name no coding but identity.
func identity(values []string) bool {
	for _, v := range values {
		for _, c := range strings.Split(v, ",") {
			if c = strings.TrimSpace(c); c != "" && !strings.EqualFold(c, "identity") {
				return false
			}
		}
	}
	return true
}

// readCommands reads body up to the flush that ends a push's commands, and the first
// bytes after it, and returns every byte it read: nil error when each command names
// ref, asks for no capability outside [pushCapabilities], and the flush is followed by
// the body's end or, after one command or more, by a pack. A [*pushRefusal] has
// @WHERE@ in place of the push's host and path; any other error is a body that ended,
// failed or grew past [MaxPushCommands] before the flush.
func readCommands(body io.Reader, ref string) ([]byte, error) {
	s := &commandLines{ref: ref}
	var rd pktReader
	buf := make([]byte, 0, 4096)
	piece := make([]byte, 4096)
	for {
		n, err := body.Read(piece[:min(len(piece), MaxPushCommands-len(buf))])
		if n > 0 {
			buf = append(buf, piece[:n]...)
			if !rd.feed(piece[:n], s) {
				if s.done {
					return afterFlush(body, buf, s.commands)
				}
				if s.refused == nil {
					s.refused = &pushRefusal{"qory: send the push's ref commands as git does: the gateway cannot read them, so it refuses the push to @WHERE@\n"}
				}
				return nil, s.refused
			}
		}
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if len(buf) >= MaxPushCommands {
			return nil, errors.New("the push's commands are longer than the guard reads")
		}
	}
}

// packSignature begins a pack, the part of a push's body after its commands' flush.
const packSignature = "PACK"

// afterFlush reads what follows the commands' flush in buf, the bytes read so far,
// from body as far as it needs, and returns every byte read: nil error when the body
// ends at the flush, or when commands is one or more and a pack follows. Anything
// else after the flush, such as push options or more commands after git's probe, is
// a [*pushRefusal].
func afterFlush(body io.Reader, buf []byte, commands int) ([]byte, error) {
	rest := len(buf) - flushEnd(buf)
	// One byte past the signature tells a body that ends from one that goes on.
	want := len(packSignature)
	if commands == 0 {
		want = 1
	}
	piece := make([]byte, want)
	for rest < want {
		n, err := body.Read(piece[:want-rest])
		buf, rest = append(buf, piece[:n]...), rest+n
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	tail := buf[len(buf)-rest:]
	switch {
	case rest == 0:
		return buf, nil
	case commands > 0 && rest >= len(packSignature) && string(tail[:len(packSignature)]) == packSignature:
		return buf, nil
	}
	return nil, &pushRefusal{"qory: push with git over HTTPS: the gateway refuses a push to @WHERE@ whose body goes on after its ref commands with anything but a pack\n"}
}

// flushEnd is the offset in buf just past the first flush, which buf contains: buf
// is pkt-lines that [pktReader] read up to that flush.
func flushEnd(buf []byte) int {
	at := 0
	for {
		n, _ := pktLength([4]byte(buf[at : at+4]))
		if n == 0 {
			return at + 4
		}
		at += n
	}
}

// pushCapabilities are the capabilities a push's first command may ask for, by name,
// a value after = aside: those git and JGit send for a push over HTTP. push-options
// and push-cert are not among them.
var pushCapabilities = []string{"report-status", "report-status-v2", "side-band", "side-band-64k", "quiet", "atomic", "ofs-delta", "delete-refs", "agent", "object-format", "session-id"}

// commandLines is a [pktSink] for the start of a push's request: shallow lines, then
// ref commands, the first with its capabilities after a NUL, then a flush. Each
// command must name ref, and each capability be one of [pushCapabilities]; done is
// set at the flush.
type commandLines struct {
	ref      string
	line     []byte
	commands int
	done     bool
	refused  *pushRefusal
}

func (s *commandLines) start(n int) bool {
	s.line = s.line[:0]
	return n > 0
}

func (s *commandLines) data(b []byte) bool {
	s.line = append(s.line, b...)
	return true
}

func (s *commandLines) end() bool {
	line := strings.TrimSuffix(string(s.line), "\n")
	if s.commands == 0 {
		if hex, ok := strings.CutPrefix(line, "shallow "); ok {
			return objectID(hex)
		}
		if strings.HasPrefix(line, "push-cert") {
			s.refused = &pushRefusal{"qory: push without --signed: the gateway refuses a signed push to @WHERE@, whose ref commands it does not read\n"}
			return false
		}
		var capabilities string
		line, capabilities, _ = strings.Cut(line, "\x00")
		for _, c := range strings.Split(capabilities, " ") {
			if name, _, _ := strings.Cut(c, "="); c != "" && !slices.Contains(pushCapabilities, name) {
				s.refused = &pushRefusal{fmt.Sprintf("qory: push with git over HTTPS, without --push-option: the gateway refuses the capability %s in a push to @WHERE@\n", shownRef(c))}
				return false
			}
		}
	}
	fields := strings.Split(line, " ")
	if len(fields) != 3 || !objectID(fields[0]) || !objectID(fields[1]) || fields[2] == "" {
		return false
	}
	s.commands++
	if fields[2] != s.ref {
		s.refused = &pushRefusal{fmt.Sprintf("qory: push only %s to @WHERE@: the gateway refuses a push that creates, updates or deletes %s\n", s.ref, shownRef(fields[2]))}
		return false
	}
	return true
}

func (s *commandLines) flush() bool {
	s.done = true
	return false
}

// objectID reports whether s is an object id as a push names it: 40 or 64 lower-case
// hexadecimal digits.
func objectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// shownRef is a ref or a capability a push named, as a refusal shows it: at most 256
// bytes, quoted in ASCII, and a phrase in place of one that contains an access key's
// secret.
func shownRef(ref string) string {
	if accesskey.ContainsSecret(ref) {
		return accesskey.ShownValue(ref, false)
	}
	if len(ref) > 256 {
		ref = ref[:256]
	}
	return strconv.QuoteToASCII(ref)
}

// refusePush answers a push the guard refused: req, the request's decision, is
// recorded denied with [PushRefRule], and the session gets a 403 with the refusal's
// text.
func (p *Proxy) refusePush(w http.ResponseWriter, req Decision, err error) {
	req.Allowed, req.PathRule, req.Outcome = false, PushRefRule, Refused
	p.observe(req)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusForbidden)
	io.WriteString(w, err.Error())
}
