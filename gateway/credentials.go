package gateway

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/runcredential"
)

// activeChecker is an issuer's introspection endpoint (RFC 7662) as the gateway asks
// it: [*runcredential.Introspector], which keeps each answer the endpoint gives for its
// cache.
type activeChecker interface {
	Active(ctx context.Context, credential string, now time.Time) (bool, error)
	Cache() time.Duration
}

// credentialVerifier is the gateway's [runAuth]: a run credential verified under the
// issuers of [Config.RunCredentials], their keys pinned, and the issuer's
// introspection endpoint, when it has one, to ask whether it is still active.
type credentialVerifier struct {
	v *runcredential.Verifier
	// intro are the issuers' introspection endpoints, by issuer.
	intro map[string]activeChecker
}

// newCredentialVerifier is the verifier of the config's issuers, each key read from
// its file, each introspection client's secret too; heartbeat is the cache of an
// issuer's introspection that sets none. The error names a file, never what it holds.
func newCredentialVerifier(cfg *Config, heartbeat time.Duration) (*credentialVerifier, error) {
	v, err := runcredential.NewVerifier(cfg.RunCredentials, os.ReadFile)
	if err != nil {
		return nil, err
	}
	cv := &credentialVerifier{v: v, intro: map[string]activeChecker{}}
	for _, i := range cfg.RunCredentials {
		if i.Introspection == nil {
			continue
		}
		if cfg.introspector != nil {
			cv.intro[i.Issuer] = cfg.introspector(i)
			continue
		}
		in, err := runcredential.NewIntrospector(*i.Introspection, os.ReadFile, heartbeat)
		if err != nil {
			return nil, fmt.Errorf("run credentials: issuer %s: %w", i.Issuer, err)
		}
		cv.intro[i.Issuer] = in
	}
	return cv, nil
}

// authenticate verifies the run credential now, and makes the run it is for from what
// the verifier's mapping made of its claims, the labels and the details alone: the
// claims themselves go no further. The issuer's introspection is not asked here, only
// after the verification, by the caller, when it decides the run ([runIdentity.active]).
func (c *credentialVerifier) authenticate(_ context.Context, credential string) (runIdentity, error) {
	ver, err := c.v.Verify(credential, time.Now())
	if err != nil {
		return runIdentity{}, runcredential.ErrRefused
	}
	id := runIdentity{Issuer: ver.Issuer, RunKey: ver.RunKey, Labels: ver.Labels, Details: ver.Details, Expires: ver.Expires}
	if a := c.intro[ver.Issuer]; a != nil {
		id.active = func(ctx context.Context) bool {
			// Any answer but active, and a failure to ask, is not active: the check
			// fails closed.
			ok, _ := a.Active(ctx, credential, time.Now())
			return ok
		}
		id.cache = a.Cache()
	}
	return id, nil
}

// runKeyID is a run key of an issuer, the run_key label of the runs of its run
// credentials.
type runKeyID struct{ issuer, runKey string }

// keyOf is the run key of a run credential's run.
func keyOf(id runIdentity) runKeyID { return runKeyID{id.Issuer, id.RunKey} }

// isActive reports whether the issuer still holds the run credential active: true for
// an issuer without introspection.
func (id runIdentity) isActive(ctx context.Context) bool {
	return id.active == nil || id.active(ctx)
}

// The gateway tracks run keys and does not require them to be unique; each period of
// activity is a run. It refuses a run key only after the issuer's end of a run of it:
// after run_ended_at_issuer, the gateway refuses the run key until the latest exp
// presented for it. Those run keys are kept in the gateway's directory, so a restart
// refuses them too.

// blocked reports whether the gateway refuses the run key, after the issuer's end.
func (g *Gateway) blocked(k runKeyID) bool {
	return g.ended != nil && g.ended.Has(k.issuer, k.runKey, g.now())
}

// now is the gateway's time of the refused run keys: the clock a test sets, else the
// system's.
func (g *Gateway) now() time.Time {
	if g.cfg.clock != nil {
		return g.cfg.clock()
	}
	return time.Now()
}

// blocks reports whether an ending is the one after which the gateway refuses the run
// key: the issuer's end.
func (e ending) blocks() bool { return e.code == event.ReasonRunEndedAtIssuer }

// holdKey keeps a run key among the refused run keys, in the gateway's directory,
// until exp, so that neither this gateway nor another started on its directory, after
// a crash as after a stop, opens a run of it before then.
func (g *Gateway) holdKey(k runKeyID, exp time.Time) error {
	if g.ended == nil {
		return nil
	}
	g.mu.Lock()
	held := !exp.After(g.endedUntil[k])
	g.mu.Unlock()
	if held {
		return nil
	}
	if err := g.ended.Add(k.issuer, k.runKey, exp); err != nil {
		return err
	}
	g.mu.Lock()
	if exp.After(g.endedUntil[k]) {
		g.endedUntil[k] = exp
	}
	g.mu.Unlock()
	return nil
}

// endKey is [Gateway.holdKey], a failure reported, the run key's issuer and nothing of
// the run credential. The gateway refuses the run key in this process either way.
func (g *Gateway) endKey(k runKeyID, exp time.Time) {
	if err := g.holdKey(k, exp); err != nil {
		g.report(fmt.Sprintf("keeping the run key of a run of the issuer %s: %v", k.issuer, err))
	}
}

// keptTo reports whether the refused run keys keep k at least to exp, as this process
// wrote them.
func (g *Gateway) keptTo(k runKeyID, exp time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !exp.After(g.endedUntil[k])
}

// spentRun is what a run on the one address leaves once it has ended and its record is
// flushed: how a later request of the run is answered, until a run credential of it can
// no longer be accepted.
type spentRun struct {
	key        runKeyID
	code, from string
	started    bool
	until      time.Time
}

// retire lets go of a run on the one address that has ended, its record flushed and,
// after the issuer's end, its run key kept to exp: the
// gateway holds no more of it than its [spentRun], until exp plus
// [runcredential.MaxLeeway], the latest a run credential of that exp is accepted; what
// it came to joins the gateway's delivery. The spent runs and the refused run keys kept
// past that time go too, so neither grows with the runs a gateway has served. A gateway
// that is closing keeps every run for Close.
func (g *Gateway) retire(lr *linkRun, k runKeyID, exp time.Time) {
	code, from, _ := lr.gone()
	started := lr.st.Started()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closing {
		return
	}
	keep := runcredential.MaxLeeway
	if g.cfg.keepSpent != 0 {
		keep = g.cfg.keepSpent
	}
	now := time.Now()
	for id, sp := range g.spent {
		if !now.Before(sp.until) {
			delete(g.spent, id)
		}
	}
	for ek, until := range g.endedUntil {
		if !now.Before(until.Add(keep)) {
			delete(g.endedUntil, ek)
		}
	}
	if g.clientRuns[k] == lr {
		delete(g.clientRuns, k)
	}
	delete(g.runs, lr.id)
	g.spent[lr.id] = spentRun{key: k, code: code, from: from, started: started, until: exp.Add(keep)}
	g.delivery.Undelivered += lr.result.Undelivered
	if lr.closed && !g.delivery.RunClosed {
		g.delivery.RunClosed, g.delivery.ClosedBy, g.delivery.Reason = true, lr.endFrom, lr.endCode
	}
	if lr.err != nil {
		g.spentErrs = append(g.spentErrs, lr.err)
	}
}

// spentOf is the spent run of the run id, when it is still kept.
func (g *Gateway) spentOf(runID string) (spentRun, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	sp, ok := g.spent[runID]
	if ok && !time.Now().Before(sp.until) {
		delete(g.spent, runID)
		return spentRun{}, false
	}
	return sp, ok
}

// presented notes a run credential presented for a run key the gateway refuses: it is
// refused, and extends the refusal to its own exp, so the refusal lapses only after the
// latest exp presented. A run key the gateway does not refuse is left as it is.
func (g *Gateway) presented(id runIdentity) {
	if k := keyOf(id); g.blocked(k) {
		g.endKey(k, id.Expires)
	}
}
