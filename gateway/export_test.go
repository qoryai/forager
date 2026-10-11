package gateway

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/qoryai/forager/server"
)

// RegistrationAt is the bytes g sends for the registration reg at now: those it kept
// for the run id, or new ones.
func RegistrationAt(g *Gateway, reg server.Registration, now time.Time) ([]byte, error) {
	return g.registrationAt(reg, now)
}

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

// RunIdentity is the run a bearer value is for, as a test's verifier answers it.
type RunIdentity = runIdentity

// authFunc is a test's verifier of a request's bearer value.
type authFunc func(value string) (RunIdentity, error)

func (f authFunc) authenticate(_ context.Context, value string) (runIdentity, error) {
	return f(value)
}

// SetRunAuth makes f decide the bearer value of every request of the contract on the
// gateway's one address, in place of refusing every one.
func SetRunAuth(c *Config, f func(value string) (RunIdentity, error)) { c.runAuth = authFunc(f) }

// BasicPassword is the password of a Proxy-Authorization value of the Basic scheme.
func BasicPassword(value string) (string, bool) { return basicPassword(value) }

// Bearer is the bearer value of a request's Authorization values.
func Bearer(values []string) (string, bool) { return bearer(values) }

// PrintedCopy is a copy of the Gateway, *g, printed with format: its fields, since its
// print methods are on the pointer.
func PrintedCopy(g *Gateway, format string) string {
	return fmt.Sprintf(format, reflect.ValueOf(g).Elem())
}

// PrintedSecret is the gateway's link secret, as its own type holds it, printed with
// format.
func PrintedSecret(g *Gateway, format string) string { return fmt.Sprintf(format, g.secret) }

// Held counts what g holds of its runs: the runs, and what the ended ones it let go of
// left.
func Held(g *Gateway) (runs, spent int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.runs), len(g.spent)
}

// SecretsIndexed counts the run secrets g knows a run by: its live runs', its ended
// ones', and those its spent runs left until they lapse.
func SecretsIndexed(g *Gateway) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.bySecret)
}

// SetOpened sets what is called once a run on the one address opened.
func SetOpened(c *Config, f func()) { c.opened = f }

// SetOpenTries sets the waits between the tries of the run's registration with Qory
// Apiary as a run opens, and how long after the run request or the login a try
// may start again, in place of openWaits and openWindow.
func SetOpenTries(c *Config, waits []time.Duration, window time.Duration) {
	c.openWaits, c.openWindow = waits, window
}

// OpenTries are the gateway's own waits between the tries of Qory Apiary as a run
// opens, and its window.
func OpenTries() ([]time.Duration, time.Duration) { return openWaits, openWindow }

// EndWords is how a line says a run ended with the state and the reason.
func EndWords(state, reason string) string {
	return endWords(runEnd{state: state, reason: reason})
}
