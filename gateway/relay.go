package gateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// The relay's limits: requests a minute from one source, an IPv4 address or an IPv6
// /64 ([sourceKey]), and the burst of them; the most of a request's body it takes for
// each endpoint; the most of an answer it passes back; and how long it waits for the
// server.
const (
	relayPerMinute = 60
	relayBurst     = 20
	relayEnrolment = 16 << 10
	relayRegister  = 64 << 10
	relayOutcome   = 4 << 10
	relayMaxAnswer = 1 << 20
	enrolmentPath  = "/.well-known/qory-enrolment"
)

// relayRefill is how long a source's bucket takes to fill from empty: one idle as long
// is full, and the relay lets go of it, every relayRefill.
const relayRefill = time.Minute * relayBurst / relayPerMinute

// relaySources is the most sources the relay follows at once: a new one past it is
// 429 until buckets are let go of.
const relaySources = 1 << 16

// relayInFlight is the most requests the relay has with the server at once: one more is
// 503.
const relayInFlight = 64

// The relay's bounds on a request: how long it may take to arrive whole, its body
// included; how long its answer may take from then on, the server's wait among it; and
// the most its request line and fields may hold.
const (
	relayReadWait  = 30 * time.Second
	relayWriteWait = 30 * time.Second
	relayMaxHeader = 16 << 10
)

// sourceFields are the fields that name a request's source to the server, which the
// relay never passes on: the server sees the gateway as the source.
var sourceFields = []string{"X-Forwarded-For", "Forwarded", "X-Real-Ip"}

// relayWait is how long the relay waits for the server's answer.
const relayWait = 10 * time.Second

// outcomePath is the path of a run's outcome under the run endpoint's: a slash, the
// run's id and /outcome.
var outcomePath = regexp.MustCompile(`^/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/outcome$`)

// hopHeaders are the fields of one connection, never relayed (RFC 9110 §7.6.1).
var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// dropHop removes from h the fields of one connection: those its Connection names, and
// [hopHeaders].
func dropHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = textproto.TrimString(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// relay is the gateway's relay of the server's four endpoints, on connections of the
// one address that open with no binding: a keyed machine's or a starter's enrolment,
// discovery, registration and outcome, each signed by the holder's own key. It
// forwards each request to the server's origin with its target in origin form, the path
// it matched, and the query of a discovery, as the holder sent them, and passes the
// answer back byte for byte, so the request's signature and the answer's are the
// server's. It relays nothing else, the attach above all, and serves none of them
// itself.
type relay struct {
	g      *Gateway
	origin *url.URL
	client *http.Client
	wait   time.Duration
	http   *http.Server
	queue  *connQueue

	// slots holds one value for each request with the server, at most [relayInFlight].
	slots chan struct{}
	done  chan struct{}

	mu      sync.Mutex
	sources map[string]*bucket
}

// bucket is the requests one source address may still make: left, refilled at
// [relayPerMinute] a minute up to [relayBurst], as of at.
type bucket struct {
	left float64
	at   time.Time
}

// newRelay is the relay to the server of the gateway's server document.
func (g *Gateway) newRelay(addr net.Addr) *relay {
	origin, _ := url.Parse(strings.TrimSuffix(g.cfg.Server.URL, "/"))
	t := http.DefaultTransport.(*http.Transport).Clone()
	// The answer passes back as the server encoded it, and the holder decodes it.
	t.DisableCompression = true
	wait := relayWait
	if g.cfg.relayWait != 0 {
		wait = g.cfg.relayWait
	}
	inFlight := relayInFlight
	if g.cfg.relayInFlight != 0 {
		inFlight = g.cfg.relayInFlight
	}
	rl := &relay{g: g, origin: origin, queue: newConnQueue(addr), sources: map[string]*bucket{}, wait: wait,
		slots: make(chan struct{}, inFlight), done: make(chan struct{}),
		client: &http.Client{Transport: t, Timeout: wait, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	// OPTIONS * goes to the handler too, which counts it and answers it 404.
	rl.http = &http.Server{Handler: rl, ReadHeaderTimeout: link.PreambleWait, ReadTimeout: relayReadWait, WriteTimeout: relayWriteWait,
		MaxHeaderBytes: relayMaxHeader, IdleTimeout: serviceIdle, DisableGeneralOptionsHandler: true, ErrorLog: quietLog()}
	go rl.http.Serve(rl.queue)
	go rl.pruneEvery(relayRefill)
	return rl
}

// pruneEvery lets go of the full buckets every d, until the relay closes.
func (rl *relay) pruneEvery(d time.Duration) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case now := <-t.C:
			rl.prune(now)
		case <-rl.done:
			return
		}
	}
}

// prune lets go of every bucket idle for [relayRefill] or more as of now: full again,
// it is the one a new source gets.
func (rl *relay) prune(now time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for s, b := range rl.sources {
		if now.Sub(b.at) >= relayRefill {
			delete(rl.sources, s)
		}
	}
}

// allow takes one request of the source from its bucket, and reports whether there was
// one. A source new to the relay while it follows [relaySources] has none.
func (rl *relay) allow(source string, now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b := rl.sources[source]
	if b == nil {
		if len(rl.sources) >= relaySources {
			return false
		}
		b = &bucket{left: relayBurst, at: now}
		rl.sources[source] = b
	}
	b.left = min(relayBurst, b.left+now.Sub(b.at).Minutes()*relayPerMinute)
	b.at = now
	if b.left < 1 {
		return false
	}
	b.left--
	return true
}

// limit is the most of a request's body the relay takes for its method and path, and
// whether it relays it at all: the enrolment, the discovery, a registration at the run
// endpoint's path and a run's outcome under it.
func (rl *relay) limit(method, path string) (int, int) {
	conf, _ := rl.g.config()
	runPath := ""
	if u, err := url.Parse(conf.Run.URL); err == nil {
		runPath = u.Path
	}
	var want string
	var max int
	switch {
	case path == enrolmentPath:
		want, max = http.MethodPost, relayEnrolment
	case path == server.WellKnown:
		want, max = http.MethodGet, 0
	case runPath != "" && path == runPath:
		want, max = http.MethodPost, relayRegister
	case runPath != "" && strings.HasPrefix(path, runPath) && outcomePath.MatchString(strings.TrimPrefix(path, runPath)):
		want, max = http.MethodPost, relayOutcome
	default:
		return 0, http.StatusNotFound
	}
	if method != want {
		return 0, http.StatusMethodNotAllowed
	}
	return max, 0
}

// ServeHTTP relays one request, in order: past its source's rate, or a source new to a
// relay that follows [relaySources], 429; a method or a target the relay does not
// relay, 405 or 404, an escaped path and a query on a POST among the latter; a body over
// its endpoint's bound, 413; [relayInFlight] requests with the server already, 503; the
// server unreached, 502, or not answering within [relayWait], 504; an answer over
// [relayMaxAnswer], 502. Each of these is the relay's own answer, with no body.
// Otherwise the server's answer, its status, its fields but those of one connection,
// and its body as it came.
func (rl *relay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The connection's own address, never a field the request carries.
	if !rl.allow(addressSource(r.RemoteAddr), time.Now()) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	max, status := rl.limit(r.Method, r.URL.Path)
	if status == 0 && (r.URL.RawPath != "" || r.Method == http.MethodPost && (r.URL.RawQuery != "" || r.URL.ForceQuery)) {
		// A path with an escaped byte is not the one matched, and no POST the relay
		// passes on has a query.
		status = http.StatusNotFound
	}
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	var body []byte
	var err error
	if r.Method == http.MethodPost {
		if body, err = io.ReadAll(io.LimitReader(r.Body, int64(max)+1)); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(body) > max {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
	}
	select {
	case rl.slots <- struct{}{}:
		defer func() { <-rl.slots }()
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	target := r.URL.EscapedPath()
	if r.Method == http.MethodGet && (r.URL.RawQuery != "" || r.URL.ForceQuery) {
		target += "?" + r.URL.RawQuery
	}
	ctx, cancel := context.WithTimeout(r.Context(), rl.wait)
	defer cancel()
	out, err := http.NewRequestWithContext(ctx, r.Method, rl.origin.Scheme+"://"+rl.origin.Host+target, bytes.NewReader(body))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if body == nil {
		out.Body, out.ContentLength = nil, 0
	}
	out.Header = r.Header.Clone()
	dropHop(out.Header)
	for _, k := range sourceFields {
		out.Header.Del(k)
	}
	resp, err := rl.client.Do(out)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, relayMaxAnswer+1))
	if err != nil || len(answer) > relayMaxAnswer {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	h := w.Header()
	answerHeader := resp.Header.Clone()
	dropHop(answerHeader)
	for k, v := range answerHeader {
		h[k] = v
	}
	h.Set("Content-Length", strconv.Itoa(len(answer)))
	w.WriteHeader(resp.StatusCode)
	w.Write(answer)
}

// close shuts the relay's server within ctx.
func (rl *relay) close(ctx context.Context) {
	if err := rl.http.Shutdown(ctx); err != nil {
		rl.http.Close()
	}
	rl.queue.Close()
	close(rl.done)
}
