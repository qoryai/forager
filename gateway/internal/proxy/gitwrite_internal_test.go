package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/policy"
)

// pkt is s as one pkt-line.
func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

// band is s as one pkt-line of side-band on band b.
func band(b byte, s string) string { return pkt(string([]byte{b}) + s) }

// flush is the flush pkt-line.
const flush = "0000"

// inside is a report status in side-band: the report's pkt-lines inside one band-1
// pkt-line, then the answer's flush.
func inside(report string) string { return band(bandReport, report) + flush }

// lines are report lines as pkt-lines, each with its newline, then a flush.
func lines(ls ...string) string {
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(pkt(l + "\n"))
	}
	return b.String() + flush
}

// writes are the writes a proxy handed over.
type writes struct {
	mu   sync.Mutex
	seen []Write
}

func (w *writes) observe(x Write) {
	w.mu.Lock()
	w.seen = append(w.seen, x)
	w.mu.Unlock()
}

func (w *writes) all() []Write {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.seen)
}

// states are the writes' states, in order.
func (w *writes) states() []string {
	var out []string
	for _, x := range w.all() {
		out = append(out, x.State)
	}
	return out
}

// splits are the ways an answer arrives: whole, a byte a read, and three bytes a read.
var splits = map[string]func(io.Reader) io.Reader{
	"whole":    func(r io.Reader) io.Reader { return r },
	"one byte": iotest.OneByteReader,
	"3 bytes":  func(r io.Reader) io.Reader { return &chunks{r: r, n: 3} },
}

// chunks reads at most n bytes a read.
type chunks struct {
	r io.Reader
	n int
}

func (c *chunks) Read(p []byte) (int, error) { return c.r.Read(p[:min(len(p), c.n)]) }

// readAnswer reads answer through a push's reportBody as split returns it, and returns
// the bytes read and the write's end state.
func readAnswer(t *testing.T, answer string, split func(io.Reader) io.Reader) (string, string) {
	t.Helper()
	w := &writes{}
	g := &gitWrite{observe: w.observe, w: Write{System: "git.example", Path: "example-org/app", RequestID: "id"}}
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(split(strings.NewReader(answer)))}
	g.answer(resp)
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	states := w.states()
	if len(states) != 1 {
		t.Fatalf("the write ended %d times: %v", len(states), states)
	}
	return string(got), states[0]
}

// TestTheReportStatusEndsTheWrite pins how a push's answer ends its write, whole, a
// byte a read and three bytes a read: the bytes read are the answer's, unchanged, and
// the end state is the report's. changed with unpack ok and at least one ref ok;
// refused with an unpack error or every ref ng; cut for an answer the report does not
// end: a fatal error, a line of another form, no ref, a bad length, an end before the
// flush.
func TestTheReportStatusEndsTheWrite(t *testing.T) {
	ok, ng := "ok refs/heads/main", "ng refs/heads/main pre-receive hook declined"
	okLines := lines("unpack ok", ok)
	ngLines := lines("unpack ok", ng)
	mixed := lines("unpack ok", ok, "ng refs/heads/dev non-fast-forward", "ok refs/tags/v1")
	allNG := lines("unpack ok", ng, "ng refs/heads/dev non-fast-forward")
	cases := map[string]struct {
		answer, want string
	}{
		"plain, every ref ok":                             {okLines, event.WriteChanged},
		"plain, a ref ng":                                 {ngLines, event.WriteRefused},
		"plain, mixed":                                    {mixed, event.WriteChanged},
		"plain, every ref ng":                             {allNG, event.WriteRefused},
		"plain, an unpack error":                          {lines("unpack index-pack abnormal exit", "ng refs/heads/main unpacker error"), event.WriteRefused},
		"plain, report-status-v2":                         {lines("unpack ok", ok, "option refname refs/heads/main", "option old-oid 0000", "option new-oid 1111"), event.WriteChanged},
		"plain, no newlines":                              {pkt("unpack ok") + pkt(ok) + flush, event.WriteChanged},
		"side-band, every ref ok":                         {inside(okLines), event.WriteChanged},
		"side-band, a refused ref":                        {inside(ngLines), event.WriteRefused},
		"side-band, mixed":                                {inside(mixed), event.WriteChanged},
		"side-band, every ref ng":                         {inside(allNG), event.WriteRefused},
		"side-band, an unpack error":                      {inside(lines("unpack error: out of space", "ng refs/heads/main unpacker error")), event.WriteRefused},
		"side-band, progress":                             {band(bandProgress, "Resolving deltas: 100% (3/3)\r") + band(bandProgress, pkt(ng+"\n")) + inside(okLines), event.WriteChanged},
		"side-band, a fatal error":                        {band(bandProgress, "remote: working\n") + band(bandError, "fatal: the remote end hung up\n") + flush, event.WriteCut},
		"side-band, a fatal error first":                  {band(bandError, "fatal: the remote end hung up\n") + inside(okLines), event.WriteCut},
		"side-band, an unknown band":                      {band(4, "x") + inside(okLines), event.WriteCut},
		"side-band, an empty pkt-line":                    {"0004" + inside(okLines), event.WriteCut},
		"side-band, an empty pkt-line after progress":     {band(bandProgress, "p") + "0004" + inside(okLines), event.WriteCut},
		"side-band, the answer's flush inside the report": {band(bandReport, pkt("unpack ok\n")) + flush + band(bandReport, pkt(ok+"\n")+flush) + flush, event.WriteCut},
		"side-band, a ref ng split":                       {splitBands(ngLines, 3, 7, 16, 30) + flush, event.WriteRefused},
		"side-band, every ref ok split":                   {splitBands(okLines, 1, 5, 6, 20) + flush, event.WriteChanged},
		"side-band, no flush":                             {band(bandReport, pkt("unpack ok\n")+pkt(ok+"\n")), event.WriteCut},
		"side-band, the answer's flush":                   {band(bandReport, pkt("unpack ok\n")+pkt(ok+"\n")) + flush, event.WriteCut},
		"side-band, an inner bad length":                  {inside(pkt("unpack ok\n") + "zz10"), event.WriteCut},
		"an ERR line":                                     {lines("ERR access denied"), event.WriteCut},
		"no ref":                                          {lines("unpack ok"), event.WriteCut},
		"a line of another form":                          {lines("unpack ok", "what refs/heads/main"), event.WriteCut},
		"no unpack line":                                  {lines(ok), event.WriteCut},
		"a length that is not hex":                        {"zzzz" + okLines, event.WriteCut},
		"a delimiter":                                     {"0001" + okLines, event.WriteCut},
		"a length of 3":                                   {"0003" + okLines, event.WriteCut},
		"a length over 65520":                             {"fff1" + okLines, event.WriteCut},
		"a pkt-line cut short":                            {"fff0unpack ok\n", event.WriteCut},
		"a length cut short":                              {"00", event.WriteCut},
		"an empty answer":                                 {"", event.WriteCut},
		"a report cut before its flush":                   {pkt("unpack ok\n") + pkt(ok+"\n"), event.WriteCut},
		"bytes after the report":                          {okLines + "garbage", event.WriteChanged},
	}
	for name, c := range cases {
		for how, split := range splits {
			t.Run(name+", "+how, func(t *testing.T) {
				got, state := readAnswer(t, c.answer, split)
				if got != c.answer {
					t.Errorf("the session read %q; want the answer %q", got, c.answer)
				}
				if state != c.want {
					t.Errorf("the write ended %s; want %s", state, c.want)
				}
			})
		}
	}
}

// splitBands is report in band-1 pkt-lines cut at the offsets at, so its pkt-lines
// cross the side-band's.
func splitBands(report string, at ...int) string {
	var b strings.Builder
	last := 0
	for _, i := range append(at, len(report)) {
		b.WriteString(band(bandReport, report[last:i]))
		last = i
	}
	return b.String()
}

// TestTheReportCapEndsTheWriteCut pins MaxReport: a report whose flush ends on the
// cap's last byte ends the write by its result, and one a byte later ends it cut. Every byte
// still reaches the session.
func TestTheReportCapEndsTheWriteCut(t *testing.T) {
	if MaxReport != 4<<20 {
		t.Fatalf("MaxReport is %d; the README states 4 MiB", MaxReport)
	}
	report := inside(lines("unpack ok", "ok refs/heads/main"))
	// The report's flush, inside band 1, ends it before the answer's flush.
	decided := len(report) - len(flush)
	for name, c := range map[string]struct {
		answer, want string
	}{
		"at the cap":   {progress(MaxReport-decided) + report, event.WriteChanged},
		"past the cap": {progress(MaxReport-decided+1) + report, event.WriteCut},
	} {
		t.Run(name, func(t *testing.T) {
			got, state := readAnswer(t, c.answer, splits["whole"])
			if got != c.answer {
				t.Error("the session read other bytes than the answer's")
			}
			if state != c.want {
				t.Errorf("the write ended %s; want %s", state, c.want)
			}
		})
	}
}

// progress is band-2 pkt-lines of n bytes in all, n at least 6.
func progress(n int) string {
	var b strings.Builder
	for n > 0 {
		k := min(n, maxPkt)
		if n-k > 0 && n-k < 6 {
			k -= 6
		}
		// A pkt-line's length and band byte are 5 bytes.
		b.WriteString(band(bandProgress, strings.Repeat("p", k-5)))
		n -= k
	}
	return b.String()
}

// TestAnyAnswerEndsTheWriteOnce pins the reader on answers of random bytes and random
// pkt-lines: it does not panic, the session reads the bytes unchanged, and the write
// ends once, in one of the three end states.
func TestAnyAnswerEndsTheWriteOnce(t *testing.T) {
	rng := rand.New(rand.NewPCG(577, 1))
	parts := []string{flush, "0001", "0004", "ffff", "zzzz", pkt("unpack ok\n"), pkt("ok refs/heads/main\n"), pkt("ng refs/heads/x y\n"),
		band(bandReport, pkt("unpack ok\n")), band(bandReport, "00"), band(bandProgress, "p"), band(bandError, "e"), "\x01", "\xff"}
	for i := range 3000 {
		var b strings.Builder
		if i%2 == 0 {
			for range rng.IntN(12) {
				b.WriteString(parts[rng.IntN(len(parts))])
			}
		} else {
			for range rng.IntN(64) {
				b.WriteByte(byte(rng.IntN(256)))
			}
		}
		answer := b.String()
		got, state := readAnswer(t, answer, splits["3 bytes"])
		if got != answer {
			t.Fatalf("answer %q: the session read %q", answer, got)
		}
		if state != event.WriteChanged && state != event.WriteRefused && state != event.WriteCut {
			t.Fatalf("answer %q: the write ended %q", answer, state)
		}
	}
}

// TestAReadErrorEndsTheWriteCut pins a push's body whose read fails before the
// report's end: the session gets the error, and the write ends cut at the error, before
// Close; a read that fails after the report's end leaves the report's result.
func TestAReadErrorEndsTheWriteCut(t *testing.T) {
	report := lines("unpack ok", "ok refs/heads/main")
	for _, c := range []struct {
		before, want string
	}{
		{report[:12], event.WriteCut},
		{report, event.WriteChanged},
	} {
		w := &writes{}
		g := &gitWrite{observe: w.observe, w: Write{RequestID: "id"}}
		reset := errors.New("connection reset by the host")
		resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(io.MultiReader(strings.NewReader(c.before), iotest.ErrReader(reset)))}
		g.answer(resp)
		got, err := io.ReadAll(resp.Body)
		if !errors.Is(err, reset) || string(got) != c.before {
			t.Errorf("the session read %q, %v; want %q and the error", got, err, c.before)
		}
		// The read's error ends the write, before Close.
		if states := w.states(); !slices.Equal(states, []string{c.want}) {
			t.Errorf("after %d bytes: the write's states %v; want %s", len(c.before), states, c.want)
		}
		resp.Body.Close()
	}
}

// TestAnAnswerClosedEarlyEndsTheWriteCut pins a push's body that the session stops
// reading before the report's end: Close ends the write cut, once.
func TestAnAnswerClosedEarlyEndsTheWriteCut(t *testing.T) {
	w := &writes{}
	g := &gitWrite{observe: w.observe, w: Write{RequestID: "id"}}
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(lines("unpack ok", "ok refs/heads/main")))}
	g.answer(resp)
	io.ReadFull(resp.Body, make([]byte, 5))
	resp.Body.Close()
	resp.Body.Close()
	if got := w.states(); !slices.Equal(got, []string{event.WriteCut}) {
		t.Errorf("the write's states %v; want cut", got)
	}
}

// TestTheAnswersStatusEndsTheWrite pins a push's answer by its status and coding: a
// 4xx is refused, a 5xx and another status but 200 cut, a 200 with a content coding
// cut, each before its body is read.
func TestTheAnswersStatusEndsTheWrite(t *testing.T) {
	for _, c := range []struct {
		status int
		coding string
		want   string
	}{
		{http.StatusForbidden, "", event.WriteRefused},
		{http.StatusNotFound, "", event.WriteRefused},
		{http.StatusRequestEntityTooLarge, "", event.WriteRefused},
		{http.StatusInternalServerError, "", event.WriteCut},
		{http.StatusServiceUnavailable, "", event.WriteCut},
		{http.StatusFound, "", event.WriteCut},
		{http.StatusOK, "gzip", event.WriteCut},
		{http.StatusOK, "identity", event.WriteChanged},
	} {
		w := &writes{}
		g := &gitWrite{observe: w.observe, w: Write{RequestID: "id"}}
		resp := &http.Response{StatusCode: c.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(lines("unpack ok", "ok refs/heads/main")))}
		if c.coding != "" {
			resp.Header.Set("Content-Encoding", c.coding)
		}
		g.answer(resp)
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if got := w.states(); !slices.Equal(got, []string{c.want}) {
			t.Errorf("%d %q: the write's states %v; want %s", c.status, c.coding, got, c.want)
		}
	}
}

// TestAPushIsRecognisedByItsMethodAndPath pins pushPath: a POST whose path ends in
// /git-receive-pack, with the repository's path as qory's labels take it from an
// origin remote, a trailing slash trimmed; a path policy.CleanPath refuses, with a dot
// segment or an encoded dot or slash, as sent, undecoded; a fetch, an advertisement and
// another method are no push.
func TestAPushIsRecognisedByItsMethodAndPath(t *testing.T) {
	for _, c := range []struct {
		method, target, want string
		push                 bool
	}{
		{http.MethodPost, "https://git.example/example-org/app.git/git-receive-pack", "example-org/app", true},
		{http.MethodPost, "https://git.example/example-org/app/git-receive-pack", "example-org/app", true},
		{http.MethodPost, "https://git.example/group/sub/app.git/git-receive-pack", "group/sub/app", true},
		{http.MethodPost, "https://git.example/example-org/my%20app.git/git-receive-pack", "example-org/my app", true},
		{http.MethodPost, "https://git.example/git-receive-pack", "", false},
		{http.MethodPost, "https://git.example/example-org/app.git/git-upload-pack", "", false},
		{http.MethodGet, "https://git.example/example-org/app.git/info/refs?service=git-receive-pack", "", false},
		{http.MethodGet, "https://git.example/example-org/app.git/git-receive-pack", "", false},
		{http.MethodPost, "https://git.example/example-org/app.git/git-receive-pack/x", "", false},
		{http.MethodPost, "https://git.example/example-org/app//git-receive-pack", "example-org/app", true},
		{http.MethodPost, "https://git.example/example-org/app.git/git-receive-pack/", "", false},
		{http.MethodPost, "https://git.example/org/x/../app.git/git-receive-pack", "org/x/../app", true},
		{http.MethodPost, "https://git.example/org/x/%2e%2e/app.git/git-receive-pack", "org/x/%2e%2e/app", true},
		{http.MethodPost, "https://git.example/org%2fx/app.git/git-receive-pack", "org%2fx/app", true},
	} {
		r := httptest.NewRequest(c.method, c.target, nil)
		got, push := pushPath(r)
		if got != c.want || push != c.push {
			t.Errorf("%s %s: %q %v; want %q %v", c.method, c.target, got, push, c.want, c.push)
		}
	}
}

// gitOrigin is a git host behind a terminating proxy: returns by path, git's answer
// to a push sent in pieces with a flush between them.
type gitOrigin struct {
	p      *Proxy
	client *http.Client
	writes *writes
	dec    *decisions
	// pushed is the answer to a push, cut into the pieces the origin flushes.
	mu     sync.Mutex
	status int
	pieces []string
	abort  bool
}

func (o *gitOrigin) answer(status int, abort bool, pieces ...string) {
	o.mu.Lock()
	o.status, o.pieces, o.abort = status, pieces, abort
	o.mu.Unlock()
}

func (o *gitOrigin) serve(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)
	switch {
	case strings.HasSuffix(r.URL.Path, "/git-upload-pack"):
		w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
		io.WriteString(w, lines("NAK"))
		return
	case !strings.HasSuffix(r.URL.Path, "/git-receive-pack"):
		io.WriteString(w, "plain")
		return
	}
	o.mu.Lock()
	status, pieces, abort := o.status, o.pieces, o.abort
	o.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
	w.WriteHeader(status)
	for _, piece := range pieces {
		io.WriteString(w, piece)
		w.(http.Flusher).Flush()
		time.Sleep(5 * time.Millisecond)
	}
	if abort {
		panic(http.ErrAbortHandler)
	}
}

// newGitOrigin starts a git origin for git.example and a proxy that terminates it.
func newGitOrigin(t *testing.T) *gitOrigin {
	t.Helper()
	up, err := NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	o := &gitOrigin{writes: &writes{}, dec: &decisions{}, status: http.StatusOK}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(o.serve))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return up.leaf(hello.ServerName) }}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	plain := httptest.NewServer(http.HandlerFunc(o.serve))
	plain.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(plain.Close)

	p, err := Listen("", policy.Observe, nil, nil, o.dec.observe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	p.dial = (&dials{secure: origin.Listener.Addr().String(), plain: plain.Listener.Addr().String()}).dial
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(up.PEM())
	p.TrustUpstream(roots)
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	p.Terminate(ca, nil, map[string][]string{"git.example": {"/*"}}, nil)
	p.ObserveWrites(o.writes.observe)
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	proxyURL, _ := url.Parse(p.URL())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}
	t.Cleanup(tr.CloseIdleConnections)
	o.p, o.client = p, &http.Client{Transport: tr, Timeout: 10 * time.Second}
	return o
}

// do sends method to target through the proxy and returns the body the session read.
func (o *gitOrigin) do(t *testing.T, method, target string) (int, string, error) {
	t.Helper()
	resp, err := o.client.Do(must2(http.NewRequest(method, target, strings.NewReader("0000"))))
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), err
}

func must2(r *http.Request, err error) *http.Request {
	if err != nil {
		panic(err)
	}
	return r
}

// TestThePushesTheProxyReadsAreWrites pins the proxy's writes end to end, on a host it
// terminates and in a plain request: a push is started and then ended by its answer,
// with the system, the repository's path and the request id of the request's
// decision; the session reads git's answer unchanged, side-band, pieces and all; a
// fetch, an advertisement and another request to the same host are no write; and a 4xx
// is refused, a 5xx cut, and an answer the host cuts short cut.
func TestThePushesTheProxyReadsAreWrites(t *testing.T) {
	refused := inside(lines("unpack ok", "ng refs/heads/main pre-receive hook declined"))
	changed := band(bandProgress, "Resolving deltas: 100% (2/2)\n") + inside(lines("unpack ok", "ok refs/heads/main"))
	for _, scheme := range []string{"https", "http"} {
		push := scheme + "://git.example/example-org/app.git/git-receive-pack"
		for name, c := range map[string]struct {
			status int
			pieces []string
			abort  bool
			want   string
		}{
			"a refused ref in side-band-64k, in pieces": {http.StatusOK, []string{refused[:9], refused[9:30], refused[30:]}, false, event.WriteRefused},
			"progress, then every ref ok":               {http.StatusOK, []string{changed}, false, event.WriteChanged},
			"a 403":                                     {http.StatusForbidden, []string{"denied"}, false, event.WriteRefused},
			"a 503":                                     {http.StatusServiceUnavailable, []string{"down"}, false, event.WriteCut},
			"an answer the host cuts short":             {http.StatusOK, []string{band(bandProgress, "working\n")}, true, event.WriteCut},
		} {
			t.Run(scheme+", "+name, func(t *testing.T) {
				o := newGitOrigin(t)
				o.answer(c.status, c.abort, c.pieces...)
				status, body, err := o.do(t, http.MethodPost, push)
				if c.abort {
					// A plain request's answer ends as the copy fails, so only the
					// terminated one shows the session the cut.
					if err == nil && scheme == "https" {
						t.Error("the session read the cut answer whole")
					}
				} else if err != nil || status != c.status || body != strings.Join(c.pieces, "") {
					t.Errorf("the session got %d %q %v; want %d and the host's bytes", status, body, err, c.status)
				}
				var got []Write
				deadline := time.Now().Add(5 * time.Second)
				for len(got) < 2 && time.Now().Before(deadline) {
					time.Sleep(5 * time.Millisecond)
					got = o.writes.all()
				}
				if len(got) != 2 {
					t.Fatalf("the writes %+v; want started and its end", got)
				}
				id := o.dec.at(-1).RequestID
				want := []Write{{System: "git.example", Path: "example-org/app", RequestID: id, State: event.WriteStarted}, {System: "git.example", Path: "example-org/app", RequestID: id, State: c.want}}
				if id == "" || !slices.Equal(got, want) {
					t.Errorf("the writes %+v; want %+v", got, want)
				}
			})
		}
		t.Run(scheme+", no push", func(t *testing.T) {
			o := newGitOrigin(t)
			for _, r := range []struct{ method, target string }{
				{http.MethodPost, scheme + "://git.example/example-org/app.git/git-upload-pack"},
				{http.MethodGet, scheme + "://git.example/example-org/app.git/info/refs?service=git-receive-pack"},
				{http.MethodGet, scheme + "://git.example/example-org/app"},
				{http.MethodPost, scheme + "://git.example/api/v1/issues"},
			} {
				if _, _, err := o.do(t, r.method, r.target); err != nil {
					t.Fatal(err)
				}
			}
			if got := o.writes.all(); len(got) != 0 {
				t.Errorf("the writes %+v; want none", got)
			}
			if n := o.dec.count(); n < 4 {
				t.Errorf("%d decisions; want each request recorded", n)
			}
		})
	}
}

// TestATransportFailureEndsAPushCut pins a push whose dial fails: started, then cut.
func TestATransportFailureEndsAPushCut(t *testing.T) {
	o := newGitOrigin(t)
	o.p.dial = (&dials{secure: "127.0.0.1:1", plain: "127.0.0.1:1"}).dial
	for _, scheme := range []string{"https", "http"} {
		before := len(o.writes.all())
		o.do(t, http.MethodPost, scheme+"://git.example/example-org/app.git/git-receive-pack")
		got := o.writes.all()[before:]
		if states := []string{}; len(got) == 2 {
			states = append(states, got[0].State, got[1].State)
			if !slices.Equal(states, []string{event.WriteStarted, event.WriteCut}) {
				t.Errorf("%s: the states %v; want started, cut", scheme, states)
			}
		} else {
			t.Errorf("%s: the writes %+v; want started and cut", scheme, got)
		}
	}
}

// TestAProxyWithNoObserverRecognisesNoWrite pins ObserveWrites as the switch: a proxy
// without it reads no answer and passes a push on as any request.
func TestAProxyWithNoObserverRecognisesNoWrite(t *testing.T) {
	p, err := New(policy.Observe, nil, nil, func(Decision) {})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	r := httptest.NewRequest(http.MethodPost, "https://git.example/example-org/app.git/git-receive-pack", nil)
	if g := p.beginWrite(r, "git.example", "id"); g != nil {
		t.Error("a write without an observer")
	}
	var nothing *gitWrite
	nothing.answer(&http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(nil))})
	nothing.cut()
}
