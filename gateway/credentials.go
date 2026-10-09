package gateway

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/qoryai/forager/runcredential"
)

// activeChecker is an issuer's introspection endpoint (RFC 7662) as the gateway asks
// it: [*runcredential.Introspector], which keeps each answer for its cache.
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

// runKeyID is a run key of an issuer: what opens one run at a gateway.
type runKeyID struct{ issuer, runKey string }

// keyOf is the run key of a run credential's run.
func keyOf(id runIdentity) runKeyID { return runKeyID{id.Issuer, id.RunKey} }

// isActive reports whether the issuer still holds the run credential active: true for
// an issuer without introspection.
func (id runIdentity) isActive(ctx context.Context) bool {
	return id.active == nil || id.active(ctx)
}

// keyTaken reports whether a run key already has a run at this gateway, live or ended,
// or one is opening, or the ended run keys hold it. Called with g.mu held.
func (g *Gateway) keyTaken(k runKeyID) bool {
	if _, ok := g.keys[k]; ok {
		return true
	}
	if _, ok := g.opening[k]; ok {
		return true
	}
	return g.ended != nil && g.ended.Has(k.issuer, k.runKey, time.Now())
}

// holdKey keeps a run key among the ended run keys, in the gateway's directory, until
// exp, so that neither this gateway nor another started on its directory, after a crash
// as after a stop, opens it again: written when its run opens, before the session hears
// the answer or the client's first byte is relayed, and again for each later exp. The
// live run itself is found first ([Gateway.keyTaken]), so it goes on.
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
// the run credential.
func (g *Gateway) endKey(k runKeyID, exp time.Time) {
	if err := g.holdKey(k, exp); err != nil {
		g.report(fmt.Sprintf("keeping the run key of a run of the issuer %s: %v", k.issuer, err))
	}
}

// presented notes a run credential presented for a run key: when its run has ended,
// one whose exp is later than the one the ended run keys keep it to is kept to it, so
// a refreshed run credential never reopens the run key once the earlier entry lapses.
// A run key whose run is live, or opening, or has none, is left as it is.
func (g *Gateway) presented(id runIdentity) {
	k := keyOf(id)
	g.mu.Lock()
	lr := g.keys[k]
	g.mu.Unlock()
	switch {
	case lr != nil:
		if _, _, ended := lr.gone(); !ended {
			return
		}
	case g.ended == nil || !g.ended.Has(k.issuer, k.runKey, time.Now()):
		return
	}
	g.endKey(k, id.Expires)
}
