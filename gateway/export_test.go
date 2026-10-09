package gateway

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"time"

	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/runcredential"
)

// SetQuiet makes a run whose session sends nothing for d end, in place of three
// heartbeat intervals.
func SetQuiet(c *Config, d time.Duration) { c.quiet = d }

// SetLinkUID makes the link serve the user uid in place of this process's.
func SetLinkUID(c *Config, uid int) { c.uid = &uid }

// RefuseOpen answers a run that did not open with err.
func RefuseOpen(w http.ResponseWriter, err error) { refuseOpen(w, err) }

// MessageOf is err's text as a refusal's message holds it.
func MessageOf(err error) string { return message(err.Error()) }

// SetCloseWait bounds each run's flush when it closes by d.
func SetCloseWait(c *Config, d time.Duration) { c.closeWait = d }

// RunIdentity is the run a run credential is for, as a test's verifier answers it.
type RunIdentity = runIdentity

// authFunc is a test's run credential verifier.
type authFunc func(credential string) (RunIdentity, error)

func (f authFunc) authenticate(_ context.Context, credential string) (runIdentity, error) {
	return f(credential)
}

// loginFunc is a test's proxy login.
type loginFunc func(authorization string, first *http.Request) (*proxy.Proxy, error)

func (f loginFunc) login(_ context.Context, authorization string, first *http.Request) (*proxy.Proxy, func(net.Conn) net.Conn, error) {
	px, err := f(authorization, first)
	return px, nil, err
}

// SetRunAuth makes f decide the run credential of every request of the contract on the
// gateway's one address.
func SetRunAuth(c *Config, f func(credential string) (RunIdentity, error)) { c.runAuth = authFunc(f) }

// SetProxyLogin makes f decide the proxy login of a client with no session.
func SetProxyLogin(c *Config, f func(authorization string, first *http.Request) (*proxy.Proxy, error)) {
	c.proxyLogin = loginFunc(f)
}

// Authority is the certificate of the gateway's own certificate authority, PEM; nil
// without one.
func Authority(g *Gateway) []byte {
	if g.authority == nil {
		return nil
	}
	return g.authority.PEM()
}

// AuthorityPath is where the gateway's own certificate authority is kept in dir.
func AuthorityPath(dir string) string { return authorityPath(dir) }

// BasicPassword is the password of a Proxy-Authorization value of the Basic scheme.
func BasicPassword(value string) (string, bool) { return basicPassword(value) }

// Bearer is the credential of a request's Authorization values.
func Bearer(values []string) (string, bool) { return bearer(values) }

// PrintedCopy is a copy of the Gateway, *g, printed with format: its fields, since its
// print methods are on the pointer.
func PrintedCopy(g *Gateway, format string) string {
	return fmt.Sprintf(format, reflect.ValueOf(g).Elem())
}

// PrintedSecret is the gateway's link secret, as its own type holds it, printed with
// format.
func PrintedSecret(g *Gateway, format string) string { return fmt.Sprintf(format, g.secret) }

// introspectionFunc is a test's introspection endpoint of an issuer.
type introspectionFunc struct {
	issuer string
	active func(issuer, credential string) bool
	cache  time.Duration
}

// Active asks active, and as runcredential's client does, a caller whose context ends
// first gets no answer, an error, while the ask goes on.
func (f introspectionFunc) Active(ctx context.Context, credential string, _ time.Time) (bool, error) {
	answer := make(chan bool, 1)
	go func() { answer <- f.active(f.issuer, credential) }()
	select {
	case ok := <-answer:
		return ok, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (f introspectionFunc) Cache() time.Duration { return f.cache }

// SetIntrospector makes active answer the introspection endpoint of every issuer that
// has one, each answer kept for cache, in place of runcredential's client of it.
func SetIntrospector(c *Config, active func(issuer, credential string) bool, cache time.Duration) {
	c.introspector = func(i runcredential.Issuer) activeChecker {
		return introspectionFunc{issuer: i.Issuer, active: active, cache: cache}
	}
}

// SetKeepSpent sets how long past its exp the gateway keeps what an ended run of the
// one address left, in place of runcredential.MaxLeeway.
func SetKeepSpent(c *Config, d time.Duration) { c.keepSpent = d }

// Held counts what g holds of its runs: the runs, the runs on the one address by run
// key, what the ended ones it let go of left, and the refused run keys it kept to an
// exp.
func Held(g *Gateway) (runs, keys, spent, kept int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.runs), len(g.clientRuns), len(g.spent), len(g.endedUntil)
}

// SecretsIndexed counts the run secrets g knows a run by: its live runs', its ended
// ones', and those its spent runs left until they lapse.
func SecretsIndexed(g *Gateway) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.bySecret)
}

// SetOpened sets what is called once a run on the one address opened, before the
// gateway looks again whether it refuses the run's run key.
func SetOpened(c *Config, f func()) { c.opened = f }

// SetKeepRetry sets how often the gateway writes the refused run keys again while a
// write of them has failed.
func SetKeepRetry(c *Config, d time.Duration) { c.keepRetry = d }

// SetClock sets the time g refuses a run key by, in place of the system's.
func SetClock(c *Config, now func() time.Time) { c.clock = now }

// SetOpenTries sets the waits between the tries of Qory Apiary's ping and run
// configuration as a run opens, and how long after the run request or the login a try
// may start again, in place of openWaits and openWindow.
func SetOpenTries(c *Config, waits []time.Duration, window time.Duration) {
	c.openWaits, c.openWindow = waits, window
}

// OpenTries are the gateway's own waits between the tries of Qory Apiary as a run
// opens, and its window.
func OpenTries() ([]time.Duration, time.Duration) { return openWaits, openWindow }

// introspectionAnswer is a test's introspection endpoint of an issuer that answers
// with an error too.
type introspectionAnswer struct {
	issuer string
	answer func(issuer, credential string) (bool, error)
	cache  time.Duration
}

func (f introspectionAnswer) Active(ctx context.Context, credential string, _ time.Time) (bool, error) {
	type result struct {
		ok  bool
		err error
	}
	answer := make(chan result, 1)
	go func() {
		ok, err := f.answer(f.issuer, credential)
		answer <- result{ok, err}
	}()
	select {
	case r := <-answer:
		return r.ok, r.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (f introspectionAnswer) Cache() time.Duration { return f.cache }

// SetIntrospection makes answer answer the introspection endpoint of every issuer that
// has one, its error as runcredential's client gives one, each answer kept for cache.
func SetIntrospection(c *Config, answer func(issuer, credential string) (bool, error), cache time.Duration) {
	c.introspector = func(i runcredential.Issuer) activeChecker {
		return introspectionAnswer{issuer: i.Issuer, answer: answer, cache: cache}
	}
}
