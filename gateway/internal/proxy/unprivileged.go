package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/qoryai/forager/accesskey"
)

// UnprivilegedRule is the rule of a request that came on an unprivileged connection,
// one opened with link.UnprivilegedPreamble, and went to a tool's host: the proxy sends
// no such request to the tool, in either mode.
const UnprivilegedRule = "wall:unprivileged"

// unprivileged is a connection that opened with link.UnprivilegedPreamble: from a step
// container or a setup container started with Unprivileged. The proxy's server finds it
// by its type, [unprivilegedContext].
type unprivileged struct{ net.Conn }

// unprivilegedKey marks the context of a request that came on an [unprivileged]
// connection.
type unprivilegedKey struct{}

// unprivilegedContext is the server's ConnContext: ctx marked for a connection that is
// [unprivileged], and ctx as it is for any other.
func unprivilegedContext(ctx context.Context, c net.Conn) context.Context {
	if _, ok := c.(*unprivileged); ok {
		return context.WithValue(ctx, unprivilegedKey{}, true)
	}
	return ctx
}

// isUnprivileged reports whether ctx is of a request that came on an unprivileged
// connection.
func isUnprivileged(ctx context.Context) bool {
	marked, _ := ctx.Value(unprivilegedKey{}).(bool)
	return marked
}

// ServeUnprivileged hands c to a proxy [New] made as [Proxy.ServeConn] does, as a
// connection that opened with link.UnprivilegedPreamble: the run's allow list and the
// record apply to its requests, the proxy sets no credential on them, sends none of them
// to a tool and answers each run API request with 403.
func (p *Proxy) ServeUnprivileged(c net.Conn) { p.ServeConn(&unprivileged{Conn: c}) }

// refuseTool records d, a request on an unprivileged connection to a tool's host, as
// refused with [UnprivilegedRule], and answers it with 403.
func (p *Proxy) refuseTool(w http.ResponseWriter, d Decision) {
	d.Allowed, d.PathRule, d.Outcome = false, UnprivilegedRule, Refused
	p.observe(d)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "qory: run this from the session: steps and unprivileged setup containers reach no tool.\n"+
		"qory: %s %s%s denied by the gateway\n", accesskey.ShownValue(d.RequestMethod, false), d.Host, accesskey.ShownValue(d.Path, false))
}
