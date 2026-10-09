package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
		id.active = func(ctx context.Context) error {
			// Any answer but active, and a failure to ask, is not active: the check
			// fails closed.
			ok, err := a.Active(ctx, credential, time.Now())
			if err != nil {
				return err
			}
			if !ok {
				return errInactive
			}
			return nil
		}
		id.cache = a.Cache()
	}
	return id, nil
}

// authenticateExpired verifies a run credential whose exp has passed, as
// [runcredential.Verifier.VerifyExpired] does: the run it was for, which the gateway
// only answers with its end, and never serves.
func (c *credentialVerifier) authenticateExpired(credential string) (runIdentity, error) {
	ver, err := c.v.VerifyExpired(credential, time.Now())
	if err != nil {
		return runIdentity{}, runcredential.ErrRefused
	}
	return runIdentity{Issuer: ver.Issuer, RunKey: ver.RunKey, Labels: ver.Labels, Details: ver.Details, Expires: ver.Expires}, nil
}

// runKeyID is a run key of an issuer, the run_key label of the runs of its run
// credentials.
type runKeyID struct{ issuer, runKey string }

// keyOf is the run key of a run credential's run.
func keyOf(id runIdentity) runKeyID { return runKeyID{id.Issuer, id.RunKey} }

// errInactive is the issuer's answer that it no longer holds the run credential active.
var errInactive = errors.New("the issuer no longer holds the run credential active")

// checkActive asks whether the issuer still holds the run credential active: nil when
// it does, and for an issuer without introspection; errInactive when it answered that
// it does not; [runcredential.ErrIssuerUnreachable] or an error that is
// [runcredential.ErrAnswerInvalid] when it gave no answer, or none that is valid; or
// ctx's error.
func (id runIdentity) checkActive(ctx context.Context) error {
	if id.active == nil {
		return nil
	}
	return id.active(ctx)
}

// The gateway tracks run keys and does not require them to be unique; each period of
// activity is a run. It refuses a run key only after the issuer's end of a run of it:
// after run_ended_at_issuer, the gateway refuses the run key until the latest exp of
// the run credentials of the run key it still holds, and of any presented during the
// hold. Those run keys are kept in the gateway's directory, so a restart
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

// keepRetry is how often the gateway writes the refused run keys again while a write
// of them has failed.
const keepRetry = 5 * time.Second

// holdKey keeps a run key among the refused run keys, in the gateway's directory,
// until exp, so that neither this gateway nor another started on its directory, after
// a crash as after a stop, opens a run of it before then. The gateway refuses the run
// key in this process whether or not the write succeeds. A run key whose write failed
// is written again by each later hold of it, and every [keepRetry] until a write
// succeeds, which holds every run key refused in memory, and is reported; a gateway that
// is closing leaves the last try to Close, which reports the run keys still not written. first reports a failure for a run key whose write had
// not failed since the last that succeeded.
func (g *Gateway) holdKey(k runKeyID, exp time.Time) (first bool, err error) {
	if g.ended == nil {
		return false, nil
	}
	g.keeping.Lock()
	defer g.keeping.Unlock()
	g.mu.Lock()
	_, unkept := g.unkept[k]
	held := !unkept && !exp.After(g.endedUntil[k])
	g.mu.Unlock()
	if held {
		return false, nil
	}
	err = g.ended.Add(k.issuer, k.runKey, exp)
	g.mu.Lock()
	if err != nil {
		defer g.mu.Unlock()
		if exp.After(g.unkept[k]) {
			g.unkept[k] = exp
		}
		if g.keepTimer == nil && !g.closing {
			every := keepRetry
			if g.cfg.keepRetry != 0 {
				every = g.cfg.keepRetry
			}
			g.keepTimer = time.AfterFunc(every, g.keepAgain)
		}
		return !unkept, err
	}
	if exp.After(g.endedUntil[k]) {
		g.endedUntil[k] = exp
	}
	// The file now holds every run key refused in memory, those whose write failed
	// among them: when there were any, the write recovered.
	recovered := len(g.unkept) > 0
	for uk, until := range g.unkept {
		if until.After(g.endedUntil[uk]) {
			g.endedUntil[uk] = until
		}
		delete(g.unkept, uk)
	}
	if g.keepTimer != nil {
		g.keepTimer.Stop()
		g.keepTimer = nil
	}
	g.mu.Unlock()
	if recovered {
		g.report(fmt.Sprintf("the run keys the issuer ended are written to %s again", g.endedPath()))
	}
	return false, nil
}

// endedPath is the file of the refused run keys, in the gateway's directory.
func (g *Gateway) endedPath() string { return filepath.Join(g.cfg.Dir, runcredential.EndedFile) }

// unkeptKey is a run key whose write failed and that the gateway still refuses, and the
// exp it is to be kept to; ok is false when there is none. Those the gateway no longer
// refuses need no write, and are dropped. Under the gateway's lock.
func (g *Gateway) unkeptKey() (k runKeyID, exp time.Time, ok bool) {
	for uk, until := range g.unkept {
		if !g.blocked(uk) {
			delete(g.unkept, uk)
			continue
		}
		k, exp, ok = uk, until, true
	}
	return k, exp, ok
}

// keepAgain writes the refused run keys again, every [keepRetry] while a write of them
// has failed. The failure is not reported again.
func (g *Gateway) keepAgain() {
	g.mu.Lock()
	g.keepTimer = nil
	k, exp, ok := g.unkeptKey()
	closing := g.closing
	g.mu.Unlock()
	if ok && !closing {
		g.holdKey(k, exp)
	}
}

// keepAgainFor writes the refused run keys again when the write of the run key's had
// failed: a request of it that is refused. The failure is not reported again.
func (g *Gateway) keepAgainFor(k runKeyID) {
	g.mu.Lock()
	exp, ok := g.unkept[k]
	g.mu.Unlock()
	if ok {
		g.holdKey(k, exp)
	}
}

// keepOnClose stops the retries and writes the refused run keys once more, for a
// gateway that is closing, when a write of them has failed. It returns how many run
// keys refused in memory a restart would not refuse: those the file does not hold, or
// no longer at now. A run key the file holds, whose later extension alone failed to
// write, a restart still refuses, until the exp written last, and is not counted.
func (g *Gateway) keepOnClose() int {
	g.mu.Lock()
	if g.keepTimer != nil {
		g.keepTimer.Stop()
		g.keepTimer = nil
	}
	k, exp, ok := g.unkeptKey()
	g.mu.Unlock()
	if ok {
		g.holdKey(k, exp)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.unkeptKey()
	n := 0
	for k := range g.unkept {
		if !g.ended.Written(k.issuer, k.runKey, g.now()) {
			n++
		}
	}
	return n
}

// heldTo is the latest of exp and the exps of the run credentials of the run key the
// gateway still holds: those of its runs, live and ended, that it has not let go of.
// What a run it let go of was presented, it no longer remembers. Not under the lock of
// any run.
func (g *Gateway) heldTo(k runKeyID, exp time.Time) time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, lr := range g.runs {
		if lr.cred == nil || lr.cred.key != k {
			continue
		}
		lr.mu.Lock()
		if lr.cred.expires.After(exp) {
			exp = lr.cred.expires
		}
		lr.mu.Unlock()
	}
	return exp
}

// endKey is [Gateway.holdKey], a run key's first failure reported, the run key's issuer
// and nothing of the run credential; its retries are not. The gateway refuses the run
// key in this process either way.
func (g *Gateway) endKey(k runKeyID, exp time.Time) {
	if first, err := g.holdKey(k, exp); first {
		g.report(fmt.Sprintf("keeping the run key of a run of the issuer %s: %v", k.issuer, err))
	}
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

// retire lets go of a run on the one address that has ended and its record flushed: the
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
// latest exp held or presented. A run key the gateway does not refuse is left as it is.
func (g *Gateway) presented(id runIdentity) {
	if k := keyOf(id); g.blocked(k) {
		g.endKey(k, id.Expires)
	}
}
