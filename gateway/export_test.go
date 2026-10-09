package gateway

import (
	"context"
	"net/http"
	"time"

	"github.com/qoryai/forager/gateway/internal/proxy"
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

func (f loginFunc) login(_ context.Context, authorization string, first *http.Request) (*proxy.Proxy, error) {
	return f(authorization, first)
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
