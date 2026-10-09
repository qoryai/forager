package session

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"

	"github.com/qoryai/forager/link"
)

// Gateway is the gateway a run speaks to: the one that holds the run's proxy, its
// policy, its credentials and its tools, and is the node toward the server. The session
// is its client, over its link (contracts/forager/v1/README.md §The gateway's link).
// [LocalGateway] makes one on this machine. The zero Gateway is none, and no run.
//
// A Gateway never prints the link secret: fmt and log/slog show it by its socket.
type Gateway struct {
	local link.Local
	set   bool
}

// LocalGateway is the gateway on this machine, by its local link as the gateway hands
// it out: the socket, the link secret, which stays in this process's memory and is
// never set in an environment or written to a file, the gateway's own files, which a
// walled run must not mount, and the names it sets for a run.
func LocalGateway(l link.Local) Gateway {
	l.Files, l.Reserved = slices.Clone(l.Files), slices.Clone(l.Reserved)
	return Gateway{local: l, set: true}
}

// files are the gateway's own files, which a walled run must not mount.
func (g Gateway) files() []string { return g.local.Files }

// errNoGateway is a spec without a gateway.
var errNoGateway = errors.New("the run has no gateway: a session speaks only to a gateway, session.LocalGateway")

// String names the gateway by its link's socket, never its secret.
func (g Gateway) String() string {
	if !g.set {
		return "session.Gateway{}"
	}
	return "session.Gateway{" + g.local.Socket + "}"
}

// Format prints g as String does, under every verb and flag.
func (g Gateway) Format(f fmt.State, _ rune) { io.WriteString(f, g.String()) }

// GoString is g as %#v prints it, never its secret.
func (g Gateway) GoString() string { return g.String() }

// LogValue is g as log/slog logs it, never its secret.
func (g Gateway) LogValue() slog.Value { return slog.StringValue(g.String()) }
