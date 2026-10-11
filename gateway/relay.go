package gateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// The relay's limits: requests a minute from one source address, and the burst of them;
// the most of a request's body it takes for each endpoint; the most of an answer it
// passes back; and how long it waits for the server.
const (
	relayPerMinute   = 60
	relayBurst       = 20
	relayEnrolment   = 16 << 10
	relayRegister    = 64 << 10
	relayOutcome     = 4 << 10
	relayMaxAnswer   = 1 << 20
	enrolmentPath    = "/.well-known/qory-enrolment"
	relayIdleSources = 10 * time.Minute
)

// relayWait is how long the relay waits for the server's answer.
const relayWait = 10 * time.Second

// outcomePath is the path of a run's outcome under the run endpoint's: a slash, the
// run's id and /outcome.
var outcomePath = regexp.MustCompile(`^/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/outcome$`)

// hopHeaders are the fields of one connection, never relayed (RFC 9110 §7.6.1).
var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// relay is the gateway's relay of the server's four endpoints, on connections of the
// one address that open with no binding: a keyed machine's or a starter's enrolment,
// discovery, registration and outcome, each signed by the holder's own key. It
// forwards each request to the server's origin with its target, the path and the query,
// unchanged, and passes the answer back byte for byte, so the request's signature and
// the answer's are the server's. It relays nothing else, the attach above all, and
// serves none of them itself.
type relay struct {
	g      *Gateway
	origin *url.URL
	client *http.Client
	wait   time.Duration
	http   *http.Server
	queue  *connQueue

	mu      sync.Mutex
	sources map[string]*bucket
}

// bucket is the requests one source address may still make: left, refilled at
// [relayPerMinute] a minute up to [relayBurst], as of at.
type bucket struct {
	left float64
	at     time.Time
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
	rl := &relay{g: g, origin: origin, queue: newConnQueue(addr), sources: map[string]*bucket{}, wait: wait,
		client: &http.Client{Transport: t, Timeout: wait, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	rl.http = &http.Server{Handler: rl, ReadHeaderTimeout: link.PreambleWait, IdleTimeout: serviceIdle, ErrorLog: quietLog()}
	go rl.http.Serve(rl.queue)
	return rl
}

// allow takes one request of the source address from its bucket, and reports whether
// there was one. Buckets full again are let go of now and then, so they do not grow
// with the addresses the relay has seen.
func (rl *relay) allow(source string, now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b := rl.sources[source]
	if b == nil {
		if len(rl.sources) > 1024 {
			for s, o := range rl.sources {
				if now.Sub(o.at) > relayIdleSources {
					delete(rl.sources, s)
				}
			}
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

// ServeHTTP relays one request, in order: past its source address's rate, 429; a
// method or a path the relay does not relay, 405 or 404; a body over its endpoint's
// bound, 413; the server unreached, 502, or not answering within [relayWait], 504; an
// answer over [relayMaxAnswer], 502. Each of these is the relay's own answer, with no
// body. Otherwise the server's answer, its status, its fields but those of one
// connection, and its body as it came.
func (rl *relay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	source, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		source = r.RemoteAddr
	}
	if !rl.allow(source, time.Now()) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	max, status := rl.limit(r.Method, r.URL.Path)
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	var body []byte
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
	ctx, cancel := context.WithTimeout(r.Context(), rl.wait)
	defer cancel()
	out, err := http.NewRequestWithContext(ctx, r.Method, rl.origin.Scheme+"://"+rl.origin.Host+r.RequestURI, bytes.NewReader(body))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if body == nil {
		out.Body, out.ContentLength = nil, 0
	}
	out.Header = r.Header.Clone()
	for _, h := range hopHeaders {
		out.Header.Del(h)
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
	for k, v := range resp.Header {
		h[k] = v
	}
	for _, k := range hopHeaders {
		h.Del(k)
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
}
