package proxy

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/policy"
)

// Write is one state of one write the session sent through the proxy to a place in
// another system: a request the proxy reads that counts as a git push over HTTP.
// State is one of event.WriteStarted, event.WriteChanged, event.WriteRefused and
// event.WriteCut; each write is handed over twice, started and then its end.
type Write struct {
	// System is the request's host as decided, without its port; Path the repository's
	// path in it, as qory's labels of a checkout have them.
	System, Path string
	// RequestID is the request's id, that of its [Decision].
	RequestID string
	State     string
}

// MaxReport is the most bytes of a push's answer the proxy reads for its report
// status. An answer whose report is not complete within it ends the write cut.
const MaxReport = 4 << 20

// receivePack is the end of the path of a git push over HTTP.
const receivePack = "/git-receive-pack"

// ObserveWrites hands every state of every git push the proxy reads to observe, on
// the goroutine of the request: started before the request is sent, then its end
// once. Without it no request counts as a write.
func (p *Proxy) ObserveWrites(observe func(Write)) { p.writes.Store(&observe) }

// pushPath is the path of the repository a request pushes to, and whether it is a
// git push over HTTP: a POST whose path ends in /git-receive-pack, without that end,
// its leading and trailing slash and a .git at its end, as qory's labels take a
// repository from an origin remote. The path is the request's path as
// [policy.CleanPath] reads it, decoded; one CleanPath refuses, with an encoded slash or
// a dot segment say, is the path as sent, undecoded, as the request's [Decision] has it.
func pushPath(r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		return "", false
	}
	sent := r.URL.EscapedPath()
	clean, ok := policy.CleanPath(sent)
	if ok {
		// CleanPath refuses %2f, %25 and %2e, so the decoded path has no slash, dot
		// segment or escape the sent one did not.
		if decoded, err := url.PathUnescape(clean); err == nil {
			clean = decoded
		}
	} else {
		clean = sent
	}
	rest, ok := strings.CutSuffix(clean, receivePack)
	if !ok {
		return "", false
	}
	path := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(rest, "/"), "/"), ".git")
	return path, path != ""
}

// gitWrite is one git push the proxy reads, from its start to its end. A nil one is
// a request that is no push, and every method of it does nothing.
type gitWrite struct {
	observe func(Write)
	w       Write
	once    sync.Once
}

// beginWrite starts the write of r to host, the request of the decision with the id
// requestID, and hands over its started: nil when r is no git push or no one observes
// writes.
func (p *Proxy) beginWrite(r *http.Request, host, requestID string) *gitWrite {
	observe := p.writes.Load()
	if observe == nil {
		return nil
	}
	path, ok := pushPath(r)
	if !ok {
		return nil
	}
	g := &gitWrite{observe: *observe, w: Write{System: host, Path: path, RequestID: requestID}}
	w := g.w
	w.State = event.WriteStarted
	g.observe(w)
	return g
}

// end hands over the write's end as state, once: the first end wins.
func (g *gitWrite) end(state string) {
	if g == nil {
		return
	}
	g.once.Do(func() {
		w := g.w
		w.State = state
		g.observe(w)
	})
}

// cut ends the write as cut, when nothing ended it before: deferred by the request's
// handler, so a transport failure and a panic end it too.
func (g *gitWrite) cut() { g.end(event.WriteCut) }

// answer reads the answer to the push, resp: a 4xx is refused, any other status but
// 200 and an answer with a content coding cut, and a 200's body is read for its report
// status as it passes ([reportBody]). resp.Body is replaced; the bytes it returns are
// the same.
func (g *gitWrite) answer(resp *http.Response) {
	if g == nil {
		return
	}
	switch {
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		g.end(event.WriteRefused)
		return
	case resp.StatusCode != http.StatusOK:
		g.end(event.WriteCut)
		return
	}
	if coding := strings.TrimSpace(strings.Join(resp.Header.Values("Content-Encoding"), ",")); coding != "" && !strings.EqualFold(coding, "identity") {
		g.end(event.WriteCut)
		return
	}
	resp.Body = &reportBody{ReadCloser: resp.Body, w: g}
}

// writeKey is the context key of a request's git write.
type writeKey struct{}

// withWrite is ctx with the git write g, when there is one.
func withWrite(ctx context.Context, g *gitWrite) context.Context {
	if g == nil {
		return ctx
	}
	return context.WithValue(ctx, writeKey{}, g)
}

// writeOf is the git write of the request r, nil when it is none.
func writeOf(r *http.Request) *gitWrite {
	g, _ := r.Context().Value(writeKey{}).(*gitWrite)
	return g
}

// reportBody is the body of a push's 200: what it reads passes on unchanged, and a
// copy goes through a [report] as it passes, up to [MaxReport] bytes. The report's
// end ends the write; so does the body's end, an error or Close before it, as cut.
type reportBody struct {
	io.ReadCloser
	w    *gitWrite
	rep  report
	read int
	done bool
}

// Read reads the answer on, and a copy of what it reads into the report.
func (b *reportBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 && !b.done {
		b.see(p[:n])
	}
	if err != nil && !b.done {
		b.done = true
		b.w.end(event.WriteCut)
	}
	return n, err
}

// see reads one chunk of the answer into the report, and ends the write once the
// report has a result, the answer is no report, or the cap is reached.
func (b *reportBody) see(p []byte) {
	if len(p) > MaxReport-b.read {
		p = p[:MaxReport-b.read]
	}
	b.read += len(p)
	state := b.rep.feed(p)
	if state == "" && b.read >= MaxReport {
		state = event.WriteCut
	}
	if state != "" {
		b.done = true
		b.w.end(state)
	}
}

// Close ends the write cut, unless the report ended it, and closes the answer.
func (b *reportBody) Close() error {
	b.w.end(event.WriteCut)
	return b.ReadCloser.Close()
}

// maxPkt is the longest pkt-line, its four digits of length included.
const maxPkt = 65520

// linePrefix is how many first bytes of a report line the report keeps: enough for
// "unpack ok\n" and one byte more.
const linePrefix = 16

// pktSink receives the pkt-lines a [pktReader] reads: each line's start with its
// payload's length, its payload in pieces, and its end; and each flush. A false return
// makes the reader stop.
type pktSink interface {
	start(n int) bool
	data(b []byte) bool
	end() bool
	flush() bool
}

// pktReader reads pkt-lines from bytes that arrive in pieces of any size: four hex
// digits of length, the four included, then the payload; 0000 is a flush. It keeps the
// length's digits and a count, never a payload.
type pktReader struct {
	hdr  [4]byte
	hn   int
	left int
	open bool
}

// feed reads b into s, and reports false when b is no pkt-line or s stops.
func (p *pktReader) feed(b []byte, s pktSink) bool {
	for len(b) > 0 {
		if !p.open {
			k := copy(p.hdr[p.hn:], b)
			p.hn += k
			b = b[k:]
			if p.hn < len(p.hdr) {
				return true
			}
			p.hn = 0
			n, ok := pktLength(p.hdr)
			switch {
			case !ok:
				return false
			case n == 0:
				if !s.flush() {
					return false
				}
				continue
			}
			if !s.start(n - 4) {
				return false
			}
			if n == 4 {
				if !s.end() {
					return false
				}
				continue
			}
			p.open, p.left = true, n-4
			continue
		}
		k := min(p.left, len(b))
		if !s.data(b[:k]) {
			return false
		}
		b, p.left = b[k:], p.left-k
		if p.left == 0 {
			p.open = false
			if !s.end() {
				return false
			}
		}
	}
	return true
}

// pktLength is the length four hex digits are, and whether it is one a push's answer
// has: 0, the flush, or 4 to [maxPkt].
func pktLength(h [4]byte) (int, bool) {
	n := 0
	for _, c := range h {
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			return 0, false
		}
		n = n<<4 | int(v)
	}
	return n, n == 0 || n >= 4 && n <= maxPkt
}

// report reads the answer of a git push for its report status: the pkt-lines of the
// answer, or with side-band the pkt-lines inside band 1 of them. Its result is a
// write's end state, empty until it has one.
type report struct {
	outer pktReader
	// mode is 0 until the first payload byte shows whether the answer has side-band,
	// then sideBand or plain.
	mode int
	// band is the band of the outer pkt-line read now, with side-band; first is set while its
	// band byte comes next.
	band  byte
	first bool
	// n is the payload length of the outer pkt-line read now.
	n     int
	inner pktReader
	lines reportLines
	// stop is set once the answer is no report.
	stop bool
}

const (
	sideBand = 1 + iota
	plain
)

// The bands of side-band: the report, progress, a fatal error.
const (
	bandReport   = 1
	bandProgress = 2
	bandError    = 3
)

// feed reads one chunk of the answer, and returns the write's end state once there is
// one: the report's result, or cut for an answer that is no report.
func (r *report) feed(b []byte) string {
	if r.stop {
		return event.WriteCut
	}
	if !r.outer.feed(b, (*outerLines)(r)) {
		r.stop = true
		if r.lines.result != "" {
			return r.lines.result
		}
		return event.WriteCut
	}
	return r.lines.result
}

// outerLines is a report receiving the pkt-lines of the answer itself.
type outerLines report

func (o *outerLines) start(n int) bool {
	if o.mode == plain {
		return o.lines.start(n)
	}
	o.first, o.n = true, n
	return true
}

func (o *outerLines) data(b []byte) bool {
	if o.mode == 0 {
		o.mode = plain
		if b[0] == bandReport || b[0] == bandProgress || b[0] == bandError {
			o.mode = sideBand
		} else if !o.lines.start(o.n) {
			// The first line's start went by before its first byte showed the mode.
			return false
		}
	}
	if o.mode == plain {
		return o.lines.data(b)
	}
	if o.first {
		o.first, o.band, b = false, b[0], b[1:]
	}
	switch o.band {
	case bandReport:
		return o.inner.feed(b, &o.lines)
	case bandProgress:
		return true
	}
	// A fatal error, or a band side-band does not have: no report follows.
	return false
}

func (o *outerLines) end() bool {
	switch o.mode {
	case plain:
		return o.lines.end()
	case sideBand:
		// A pkt-line of side-band with no band byte.
		return !o.first
	}
	// An empty first line.
	return false
}

func (o *outerLines) flush() bool {
	if o.mode == plain {
		return o.lines.flush()
	}
	// The answer ends: a report not complete by now is no report.
	return false
}

// reportLines reads the lines of a report status: unpack ok or unpack <error>, then
// ok <ref> or ng <ref> <reason> per ref, with option lines under report-status-v2,
// then a flush. It keeps each line's first [linePrefix] bytes and its length.
type reportLines struct {
	prefix [linePrefix]byte
	pn, n  int
	// unpacked is set once the first line is read; oks and ngs count the refs.
	unpacked bool
	oks, ngs int
	result   string
}

func (l *reportLines) start(n int) bool {
	if l.result != "" {
		return false
	}
	l.pn, l.n = 0, n
	return true
}

func (l *reportLines) data(b []byte) bool {
	l.pn += copy(l.prefix[l.pn:], b)
	return true
}

func (l *reportLines) end() bool {
	line := string(l.prefix[:l.pn])
	if l.n <= linePrefix {
		line = strings.TrimSuffix(line, "\n")
	}
	if !l.unpacked {
		l.unpacked = true
		switch {
		case line == "unpack ok":
			return true
		case strings.HasPrefix(line, "unpack "):
			l.result = event.WriteRefused
		}
		// An unpack error ends the report; anything else is no report.
		return false
	}
	switch {
	case strings.HasPrefix(line, "ok "):
		l.oks++
	case strings.HasPrefix(line, "ng "):
		l.ngs++
	case strings.HasPrefix(line, "option "):
	default:
		return false
	}
	return true
}

func (l *reportLines) flush() bool {
	switch {
	case !l.unpacked:
	case l.oks > 0:
		l.result = event.WriteChanged
	case l.ngs > 0:
		l.result = event.WriteRefused
	}
	// The report ends here, with a result or as no report.
	return false
}
