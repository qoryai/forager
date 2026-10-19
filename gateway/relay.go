package gateway

import (
	"bytes"
	"container/list"
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

	"github.com/qoryai/forager/gateway/internal/routine"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// The relay's limits: requests a minute from one source, an IPv4 address or an IPv6
// /64 ([addressSource]), and the burst of them; requests a minute from one IPv6 /48, and
// the burst of them; the most of a request's body it takes for each endpoint; the most
// of an answer it passes back; and how long it waits for the server.
const (
	relayPerMinute      = 60
	relayBurst          = 20
	relayBlockPerMinute = 240
	relayBlockBurst     = 80
	relayEnrolment      = 16 << 10
	relayRegister       = 64 << 10
	relayOutcome        = 4 << 10
	relayMaxAnswer      = 1 << 20
	enrolmentPath       = "/.well-known/qory-enrolment"
)

// relayRefill is how long a source's bucket takes to fill from empty, and a /48's as
// long: one idle as long is full, and the relay lets go of it, every relayRefill.
const relayRefill = time.Minute * relayBurst / relayPerMinute

// relaySources is the most sources the relay follows at once: a new one past it lets go
// of the one idle longest.
const relaySources = 1 << 16

// relayBlockSources is the most sources of one IPv6 /48 the relay follows at once: a new
// one past it lets go of the one of that /48 idle longest.
const relayBlockSources = 256

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
	sources map[string]*relaySource
	blocks  map[string]*relayBlock
	// idle holds every source followed, the one idle longest first.
	idle list.List
}

// bucket is the requests a source, or a /48, may still make: left, as of at.
type bucket struct {
	left float64
	at   time.Time
}

// refill is b as of now, refilled at perMinute a minute up to burst.
func (b *bucket) refill(perMinute, burst float64, now time.Time) {
	b.left = min(burst, b.left+now.Sub(b.at).Minutes()*perMinute)
	b.at = now
}

// relaySource is a source the relay follows: its bucket, refilled at [relayPerMinute]
// a minute up to [relayBurst]; its /48's, nil for an IPv4 address; and its places
// among the sources followed and among its /48's.
type relaySource struct {
	bucket
	key           string
	block         *relayBlock
	idle, inBlock *list.Element
}

// relayBlock is an IPv6 /48 the relay follows while it follows a source of it: its
// bucket, refilled at [relayBlockPerMinute] a minute up to [relayBlockBurst], and its
// sources followed, the one idle longest first.
type relayBlock struct {
	bucket
	key     string
	sources list.List
}

// newRelay is the relay to the server of the gateway's server document.
func (g *Gateway) newRelay(addr net.Addr) *relay {
	origin, _ := url.Parse(strings.TrimSuffix(g.cfg.Server.URL, "/"))
	t := defaultTransport()
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
	rl := &relay{g: g, origin: origin, queue: newConnQueue(addr), sources: map[string]*relaySource{}, blocks: map[string]*relayBlock{}, wait: wait,
		slots: make(chan struct{}, inFlight), done: make(chan struct{}),
		client: &http.Client{Transport: t, Timeout: wait, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	// OPTIONS * goes to the handler too, which counts it and answers it 404.
	rl.http = &http.Server{Handler: routine.Handler(g.report, rl), ReadHeaderTimeout: link.PreambleWait, ReadTimeout: relayReadWait, WriteTimeout: relayWriteWait,
		MaxHeaderBytes: relayMaxHeader, IdleTimeout: serviceIdle, DisableGeneralOptionsHandler: true, ErrorLog: quietLog()}
	routine.Go(g.report, func() { rl.http.Serve(rl.queue) })
	routine.Go(g.report, func() { rl.pruneEvery(relayRefill) })
	return rl
}

// defaultTransport is Go's default transport, cloned, or a new one of its settings when a program replaced it.
func defaultTransport() *http.Transport {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		return t.Clone()
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
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

// prune lets go of every source idle for [relayRefill] or more as of now, and of a /48
// with none of its sources left: full again, its bucket is the one a new source gets.
func (rl *relay) prune(now time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for e := rl.idle.Front(); e != nil; e = rl.idle.Front() {
		src := e.Value.(*relaySource)
		if now.Sub(src.at) < relayRefill {
			return
		}
		rl.forget(src)
	}
}

// allow takes one request of the source s from its bucket and from its /48's, and
// reports whether both had one. A source new to the relay while it follows
// [relaySources] lets go of the one idle longest, and one new to a /48 of which it
// follows [relayBlockSources] lets go of the one of that /48 idle longest.
func (rl *relay) allow(s connSource, now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	src := rl.sources[s.key]
	if src == nil {
		src = rl.follow(s, now)
	}
	rl.idle.MoveToBack(src.idle)
	src.refill(relayPerMinute, relayBurst, now)
	blk := src.block
	if blk != nil {
		blk.sources.MoveToBack(src.inBlock)
		blk.refill(relayBlockPerMinute, relayBlockBurst, now)
	}
	if src.left < 1 || blk != nil && blk.left < 1 {
		return false
	}
	src.left--
	if blk != nil {
		blk.left--
	}
	return true
}

// follow is the source s, new to the relay, followed from now with full buckets, its
// /48's kept when the relay follows it.
func (rl *relay) follow(s connSource, now time.Time) *relaySource {
	if len(rl.sources) >= relaySources {
		rl.forget(rl.idle.Front().Value.(*relaySource))
	}
	src := &relaySource{bucket: bucket{left: relayBurst, at: now}, key: s.key}
	if s.block != "" {
		blk := rl.blocks[s.block]
		if blk == nil {
			blk = &relayBlock{bucket: bucket{left: relayBlockBurst, at: now}, key: s.block}
			rl.blocks[s.block] = blk
		} else if blk.sources.Len() >= relayBlockSources {
			rl.forget(blk.sources.Front().Value.(*relaySource))
		}
		src.block = blk
		src.inBlock = blk.sources.PushBack(src)
	}
	src.idle = rl.idle.PushBack(src)
	rl.sources[s.key] = src
	return src
}

// forget lets go of src, and of its /48 once none of its sources is left.
func (rl *relay) forget(src *relaySource) {
	delete(rl.sources, src.key)
	rl.idle.Remove(src.idle)
	if blk := src.block; blk != nil {
		blk.sources.Remove(src.inBlock)
		if blk.sources.Len() == 0 {
			delete(rl.blocks, blk.key)
		}
	}
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

// ServeHTTP relays one request, in order: past its source's rate, or its IPv6 /48's,
// 429; a method or a target the relay does not relay, 405 or 404, an escaped path and a
// query on a POST among the latter; a body over its endpoint's bound, 413;
// [relayInFlight] requests with the server already, 503; the server unreached, 502, or
// not answering within [relayWait], 504; an answer over [relayMaxAnswer], 502. Each of
// these is the relay's own answer, with no body.
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
