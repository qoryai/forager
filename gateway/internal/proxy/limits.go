package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// The rules a refusal by one of the run's limits names in its decision: not an allow or
// deny entry, the proxy's refusal, in either mode.
const (
	// ConnectionLimit is the rule of a connection refused because the run has
	// [Limits.Connections] open.
	ConnectionLimit = "wall:connection-limit"
	// RateLimit is the rule of a request refused because it waited [RateWait] for a
	// token of the run's rate limit and got none.
	RateLimit = "wall:rate-limit"
)

// RateWait is how long a request waits for a token of the run's rate limit before the
// proxy refuses it.
const RateWait = 5 * time.Second

// recordEvery is the interval in which at most one refusal per limit is recorded, so
// a run at its limit adds at most one event a second per limit to the record.
const recordEvery = time.Second

// Limits are one run's limits on its proxy. A field of zero or less sets no such limit.
type Limits struct {
	// Connections is the most connections the run has open at once: CONNECT tunnels,
	// blind or terminated, and plain requests in flight. The next one is refused with
	// 429 at once.
	Connections int
	// RequestsPerSecond and Burst are the run's token bucket: it holds Burst tokens at
	// most and gains RequestsPerSecond tokens a second. Every request takes one token: a
	// CONNECT, a plain request, and a request inside a terminated tunnel, before the
	// policy decides it. A request waits up to [RateWait] for a token, then is refused
	// with 429. While Connections requests wait, the next that needs a token is refused
	// with 429 at once.
	RequestsPerSecond, Burst int
}

// errRate says a request waited [RateWait] and got no token.
var errRate = errors.New("the run's rate limit refused the request")

// errCrowded says a request needed to wait for a token while as many of the run's
// requests as [Limits.Connections] already waited, and was refused at once.
var errCrowded = errors.New("the run's rate limit refused the request: too many wait")

// limiter holds one run's counters: the connections open, the tokens of the bucket,
// and when each limit's last refusal was recorded.
type limiter struct {
	l Limits
	// now is the clock and wait the timer the limiter reads; tests set others.
	now  func() time.Time
	wait func(ctx context.Context, d time.Duration) bool

	mu   sync.Mutex
	open int
	// waiting counts the requests that wait for a token, or wait out [RateWait] before
	// their refusal.
	waiting int
	// tokens is below zero while requests wait: each waiting request took one ahead.
	tokens float64
	at     time.Time
	// recorded is when the last refusal of each rule was recorded.
	recorded map[string]time.Time
}

// newLimiter makes the counters of a run with limits l, its bucket full.
func newLimiter(l Limits, now func() time.Time, wait func(context.Context, time.Duration) bool) *limiter {
	return &limiter{l: l, now: now, wait: wait, tokens: float64(max(l.Burst, 1)), at: now(), recorded: map[string]time.Time{}}
}

// sleep waits d, and returns false when ctx ends first.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// SetLimits sets the run's limits on p, with new counters. The gateway calls it once,
// after [New] and before the run's first connection.
func (p *Proxy) SetLimits(l Limits) {
	p.limits.Store(newLimiter(l, time.Now, sleep))
}

// Limits are the run's limits [Proxy.SetLimits] set, zero when it set none.
func (p *Proxy) Limits() Limits {
	if lm := p.limits.Load(); lm != nil {
		return lm.l
	}
	return Limits{}
}

// take takes one token of the run's bucket for a request: nil at once while the bucket
// holds one, nil after a wait for the next while that wait is [RateWait] at most, and
// [errRate] after a wait of [RateWait] otherwise. When ctx ends, or the proxy closes,
// during the wait, it panics with [http.ErrAbortHandler], so the server closes the
// connection with no answer: the request is not served, and gets no 200 with an empty
// body.
func (p *Proxy) take(ctx context.Context) error {
	lm := p.limits.Load()
	if lm == nil || lm.l.RequestsPerSecond <= 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(p.stopped, cancel)()
	rate := float64(lm.l.RequestsPerSecond)
	lm.mu.Lock()
	lm.refill()
	// A run has at most as many requests waiting as it may have connections open, so
	// that it cannot pile up waiting requests on the gateway.
	if lm.tokens < 1 && lm.waiting >= max(lm.l.Connections, 1) {
		lm.mu.Unlock()
		return errCrowded
	}
	lm.tokens--
	var wait time.Duration
	if lm.tokens < 0 {
		wait = time.Duration(-lm.tokens / rate * float64(time.Second))
	}
	refused := wait > RateWait
	if refused {
		lm.tokens++
		wait = RateWait
	}
	if wait > 0 {
		lm.waiting++
	}
	lm.mu.Unlock()
	if wait > 0 {
		defer func() {
			lm.mu.Lock()
			lm.waiting--
			lm.mu.Unlock()
		}()
	}
	if wait > 0 && !lm.wait(ctx, wait) {
		if !refused {
			// The token goes back for the next request.
			lm.mu.Lock()
			lm.refill()
			lm.tokens = min(lm.tokens+1, float64(max(lm.l.Burst, 1)))
			lm.mu.Unlock()
		}
		panic(http.ErrAbortHandler)
	}
	if ctx.Err() != nil {
		// The connection closed, or the proxy, as the wait ended.
		panic(http.ErrAbortHandler)
	}
	if refused {
		return errRate
	}
	return nil
}

// refill adds the tokens the bucket gained since it was last read. lm.mu is held.
func (lm *limiter) refill() {
	now := lm.now()
	if d := now.Sub(lm.at); d > 0 {
		lm.tokens = min(lm.tokens+d.Seconds()*float64(lm.l.RequestsPerSecond), float64(max(lm.l.Burst, 1)))
		lm.at = now
	}
}

// hold counts one more connection open, and returns false, counting nothing, when the
// run has [Limits.Connections] open. Each true is followed by one release.
func (p *Proxy) hold() bool {
	lm := p.limits.Load()
	if lm == nil || lm.l.Connections <= 0 {
		return true
	}
	lm.mu.Lock()
	defer lm.mu.Unlock()
	if lm.open >= lm.l.Connections {
		return false
	}
	lm.open++
	return true
}

// release counts one connection fewer open, one [Proxy.hold] counted.
func (p *Proxy) release() {
	lm := p.limits.Load()
	if lm == nil || lm.l.Connections <= 0 {
		return
	}
	lm.mu.Lock()
	lm.open--
	lm.mu.Unlock()
}

// recordable says whether a refusal by rule is recorded now: the first, and then one
// at most every [recordEvery].
func (lm *limiter) recordable(rule string) bool {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	now := lm.now()
	if last, ok := lm.recorded[rule]; ok && now.Sub(last) < recordEvery && now.Sub(last) >= 0 {
		return false
	}
	lm.recorded[rule] = now
	return true
}

// limited answers a request one of the run's limits refused, rule [ConnectionLimit] or
// [RateLimit]: 429 with Retry-After: 1 and one line that says when to retry and which
// limit refused it. The refusal is d, denied and refused with rule, recorded when
// [limiter.recordable] allows.
func (p *Proxy) limited(w http.ResponseWriter, d Decision, rule string, why error) {
	lm := p.limits.Load()
	d.Allowed, d.Rule, d.Outcome, d.Status, d.Credential, d.Tool = false, rule, Refused, 0, "", ""
	if lm.recordable(rule) {
		p.observe(d)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Retry-After", "1")
	w.WriteHeader(http.StatusTooManyRequests)
	if rule == ConnectionLimit {
		fmt.Fprintf(w, "qory: retry once one of this run's connections closes. The run has %d connections open through the gateway, the most gateway.run_limits.connections allows.\n", lm.l.Connections)
		return
	}
	if errors.Is(why, errCrowded) {
		n, verb := max(lm.l.Connections, 1), "were"
		if n == 1 {
			verb = "was"
		}
		fmt.Fprintf(w, "qory: retry in 1 second. This run's requests came faster than %d a second, the most gateway.run_limits.requests_per_second allows, and %d of its requests %s already waiting.\n", lm.l.RequestsPerSecond, n, verb)
		return
	}
	fmt.Fprintf(w, "qory: retry in 1 second. This run's requests came faster than %d a second, the most gateway.run_limits.requests_per_second allows, and this request waited %d seconds.\n", lm.l.RequestsPerSecond, int(RateWait/time.Second))
}
