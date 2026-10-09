package gateway

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/runcredential"
	"github.com/qoryai/forager/server"
)

// clientLogin is the gateway's [proxyLogin]: the runs of clients with no session,
// which the client's run credential opens, as its proxy login's password, and every
// connection presenting one for the same run key belongs to (contracts/forager/v1
// README.md §Run credentials).
type clientLogin struct{ g *Gateway }

// login decides a proxy login of a client with no session. The password of Basic is
// the run credential, the user name ignored, verified as every run credential is. The
// gateway tracks run keys and does not require them to be unique; each period of
// activity is a run. While a run of the run key is open, every connection of it joins
// that run, its run credential extending the run to its exp; otherwise the connection
// opens a new run, of a new run id and the same run_key label, after the issuer, when it
// has introspection, holds the run credential active. A run that ended is never opened
// again. A client has at most one open run per run key, and never joins a session's
// run, which only its proxy secret reaches: a run key with sessions' runs open opens or
// joins its client's run beside them. Every failure of the run credential is refused,
// 407, and so is a run key the gateway refuses after the issuer's end, until the latest
// exp presented. A run refused with a code is [errUnserved], and one that fails to open
// without a code [errNotOpened].
func (c clientLogin) login(ctx context.Context, authorization string, _ *http.Request) (*proxy.Proxy, func(net.Conn) net.Conn, error) {
	g := c.g
	password, ok := basicPassword(authorization)
	if !ok || password == "" {
		return nil, nil, runcredential.ErrRefused
	}
	id, err := g.auth.authenticate(ctx, password)
	if err != nil {
		return nil, nil, runcredential.ErrRefused
	}
	k := keyOf(id)
	var opened chan struct{}
	for opened == nil {
		g.mu.Lock()
		if g.closing {
			g.mu.Unlock()
			return nil, nil, errUnserved
		}
		if lr := g.clientRuns[k]; lr != nil {
			if _, _, ended := lr.gone(); !ended {
				g.mu.Unlock()
				px, track, err := lr.join(ctx, id)
				if errors.Is(err, errRunEnded) {
					// It ended as this connection joined: the next look opens anew.
					continue
				}
				return px, track, err
			}
			delete(g.clientRuns, k)
		}
		if wait := g.opening[k]; wait != nil {
			// The run key's first connection is opening its run: this one joins it.
			g.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, nil, errUnserved
			}
		}
		if g.blocked(k) {
			g.mu.Unlock()
			g.presented(id)
			return nil, nil, runcredential.ErrRefused
		}
		opened = make(chan struct{})
		g.opening[k] = opened
		g.opens.Add(1)
		g.mu.Unlock()
	}
	defer func() {
		g.mu.Lock()
		delete(g.opening, k)
		g.mu.Unlock()
		close(opened)
		g.opens.Done()
	}()
	if !id.isActive(ctx) {
		return nil, nil, runcredential.ErrRefused
	}
	// The issuer may have ended a run of the run key while it was asked.
	g.mu.Lock()
	blocked := g.blocked(k)
	g.mu.Unlock()
	if blocked {
		g.presented(id)
		return nil, nil, runcredential.ErrRefused
	}
	lr, err := g.openClient(id)
	if errors.Is(err, errKeyRefused) {
		g.presented(id)
		return nil, nil, runcredential.ErrRefused
	}
	if err != nil {
		g.report(fmt.Sprintf("a run of a client with no session did not open: %v", err))
		if ref := (*accesskey.Refusal)(nil); errors.As(err, &ref) && ref.Code != "" {
			return nil, nil, errUnserved
		}
		return nil, nil, errNotOpened
	}
	return lr.px, lr.track, nil
}

// openClient opens the run of a client with no session: the gateway's own run id, the
// run credential's labels and details, and no wall but the guard of the one address,
// its proxy reading inside HTTPS with the gateway's own authority for the credentials,
// the tools and the path rules its policy selects. The run is its run key's client's
// run from then on; a run key the issuer ended while the run opened ends it,
// run_ended_at_issuer, and is [errKeyRefused].
func (g *Gateway) openClient(id runIdentity) (*linkRun, error) {
	req := &server.LinkRunRequest{Version: 1, RunID: event.NewRunID(), Wall: true}
	g.mu.Lock()
	g.used[req.RunID] = true
	g.mu.Unlock()
	lr, _, err := g.open(req, opening{remote: true, id: &id, client: true})
	if err != nil {
		return nil, err
	}
	k := keyOf(id)
	g.mu.Lock()
	if g.blocked(k) {
		g.mu.Unlock()
		lr.end(endedAtIssuer)
		return nil, errKeyRefused
	}
	g.runs[lr.id] = lr
	g.clientRuns[k] = lr
	g.mu.Unlock()
	lr.arm()
	return lr, nil
}

// errKeyRefused is a run that opened for a run key the gateway refuses since: ended at
// once, run_ended_at_issuer.
var errKeyRefused = errors.New("the gateway refuses the run key")

// join is a later connection of the run's run key: the run takes it, once its run
// credential extends the run and the issuer, when asked, holds it active; an issuer
// that does not ends the run, and the connection is refused, 407, as is one of a run key
// the gateway refuses. A run that has ended takes none, [errRunEnded].
func (lr *linkRun) join(ctx context.Context, id runIdentity) (*proxy.Proxy, func(net.Conn) net.Conn, error) {
	if lr.g.blocked(keyOf(id)) {
		lr.g.presented(id)
		return nil, nil, runcredential.ErrRefused
	}
	if _, _, ended := lr.gone(); ended {
		return nil, nil, errRunEnded
	}
	lr.renew(id)
	if !lr.stillActive(ctx) {
		lr.g.presented(id)
		return nil, nil, runcredential.ErrRefused
	}
	return lr.px, lr.track, nil
}

// errRunEnded is a run a connection would join that has ended.
var errRunEnded = errors.New("the run has ended")

// track counts a connection of a run with no session for as long as it is open, so the
// run is quiet only once it has none.
func (lr *linkRun) track(c net.Conn) net.Conn {
	lr.mu.Lock()
	lr.conns++
	lr.lastConn = time.Now()
	lr.mu.Unlock()
	return &trackedConn{Conn: c, closed: lr.untrack}
}

// untrack is a connection of the run's that closed.
func (lr *linkRun) untrack() {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	lr.conns--
	lr.lastConn = time.Now()
	if lr.conns == 0 && !lr.ended {
		if lr.quiet != nil {
			lr.quiet.Stop()
		}
		lr.quiet = time.AfterFunc(lr.g.runsQuiet, lr.watchQuiet)
	}
}

// watchQuiet ends a run with no session that has had no connection for the gateway's
// quiet time, quiet, and otherwise looks again when that time would be up.
func (lr *linkRun) watchQuiet() {
	lr.mu.Lock()
	if lr.ended || lr.conns > 0 {
		// A connection is open: the last to close looks again.
		lr.mu.Unlock()
		return
	}
	if idle := time.Since(lr.lastConn); idle < lr.g.runsQuiet {
		lr.quiet = time.AfterFunc(lr.g.runsQuiet-idle, lr.watchQuiet)
		lr.mu.Unlock()
		return
	}
	lr.mu.Unlock()
	lr.g.report(fmt.Sprintf("run %s: it had no connection for %s; the run ends, quiet", lr.id, lr.g.runsQuiet))
	e := ending{reason: event.ReasonQuiet, code: event.ReasonQuiet, from: accesskey.FromGateway, closed: true, quietSeconds: quietSeconds(lr.g.runsQuiet)}
	lr.end(e)
}

// quietSeconds is the quiet period as run.exited's quiet_seconds holds it: whole
// seconds, rounded up, at least one.
func quietSeconds(d time.Duration) int {
	return max(1, int(math.Ceil(d.Seconds())))
}

// keep is a run with no session while it lives: its heartbeats, the gateway's own,
// every interval, the seconds counted from its ping, or from its run.started without a
// server; and, for an issuer with introspection, the issuer asked again at most every
// cache while the run has connections, or had one since it last asked.
func (lr *linkRun) keep() {
	beat := time.NewTicker(time.Duration(lr.g.interval) * time.Second)
	defer beat.Stop()
	lr.mu.Lock()
	since := lr.startedAt
	if !lr.pingAt.IsZero() {
		since = lr.pingAt
	}
	cache := lr.cred.cache
	lr.mu.Unlock()
	var ask <-chan time.Time
	if cache > 0 {
		t := time.NewTicker(cache)
		defer t.Stop()
		ask = t.C
	}
	for {
		select {
		case <-lr.ctx.Done():
			return
		case <-beat.C:
			lr.st.Emit(event.RunHeartbeat, map[string]any{"elapsed_seconds": int(time.Since(since) / time.Second), "interval_seconds": lr.g.interval})
		case <-ask:
			lr.mu.Lock()
			busy := lr.conns > 0 || lr.lastConn.After(lr.asked)
			lr.mu.Unlock()
			if busy && !lr.stillActive(lr.ctx) {
				return
			}
		}
	}
}

// trackedConn is a connection of a run with no session, which tells the run once when
// it closes.
type trackedConn struct {
	net.Conn
	once   sync.Once
	closed func()
}

// Close closes the connection, and tells the run the first time.
func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.closed)
	return err
}
