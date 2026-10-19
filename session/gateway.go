package session

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/server"
)

// Gateway is the gateway a run speaks to: the one that holds the run's proxy, its
// policy, its credentials and its tools, and is the node toward the server. The session
// is its client, over its link (contracts/forager/v1/README.md §The gateway's link).
// [LocalGateway] makes one on this machine; a [RemoteGateway] is a separate gateway, on
// a machine of its own. A nil Gateway is none, and no run.
//
// A Gateway never prints the run key: fmt and log/slog show it by its socket or its
// URL.
type Gateway interface {
	fmt.Stringer
	fmt.GoStringer
	// gateway seals the interface: LocalGateway and RemoteGateway are its kinds.
	gateway()
}

// localGateway is the gateway on this machine, by its local link.
type localGateway struct {
	local link.Local
}

// LocalGateway is the gateway on this machine, by its local link as the gateway hands
// it out: the socket, or the way to it in this process's memory, the gateway's own
// files, which a walled run must not mount, and the names it sets for a run.
func LocalGateway(l link.Local) Gateway {
	l.Files, l.Reserved = slices.Clone(l.Files), slices.Clone(l.Reserved)
	return localGateway{local: l}
}

func (localGateway) gateway() {}

// String names the gateway by its link's socket.
func (g localGateway) String() string {
	return "session.Gateway{" + accesskey.ShownValue(g.local.Socket, false) + "}"
}

// Format prints g as String does, under every verb and flag.
func (g localGateway) Format(f fmt.State, _ rune) { io.WriteString(f, g.String()) }

// GoString is g as %#v prints it.
func (g localGateway) GoString() string { return g.String() }

// LogValue is g as log/slog logs it.
func (g localGateway) LogValue() slog.Value { return slog.StringValue(g.String()) }

// RemoteGateway is a separate gateway, on a machine of its own, which the run reaches
// over TLS 1.3 on the gateway's one address (contracts/forager/v1/README.md §The
// gateway's link), as the run key names it. The session reads the run key as a runner
// does, unverified, [runkey.Parse], and takes of it the run's id, the gateway's URL,
// the one address the run key is ever sent to, and the gateway's keys. It checks the
// certificate chain of the gateway for the host name of that URL against the system's
// roots, and every connection is bound to a key the run key names before the run key
// is sent; every answer of the gateway must be signed under one. It holds no access key:
// the gateway's signs toward the server.
//
// The session reads no environment: the caller passes the run key, from [EnvRunKey].
// It is never written to a file, set in an agent's environment or printed: fmt and
// log/slog show a RemoteGateway by its gateway's URL alone, and EnvRunKey is taken out
// of every agent's environment, the one it inherits among them.
type RemoteGateway struct {
	// RunKey is the run key Qory Apiary answered the run's registration with: qrk_,
	// its payload and its signature.
	RunKey string
}

func (RemoteGateway) gateway() {}

// EnvRunKey is the variable a runner passes a run's run key in. The session never reads
// it, and no program it starts on the machine receives it: no agent, whatever
// environment the agent has, and no command of its wall's, the docker CLI among them.
const EnvRunKey = accesskey.EnvRunKey

// key reads the run key, as a runner does: an unreadable one is an error that names the
// part that is wrong, never the run key.
func (g *RemoteGateway) key() (runkey.Key, error) {
	k, err := runkey.Parse(g.RunKey)
	if err != nil {
		reason := err.Error()
		if re := (*runkey.Error)(nil); errors.As(err, &re) {
			reason = re.Reason
		}
		return runkey.Key{}, errors.New("QORY_RUN_KEY is not a run key: " + reason)
	}
	return k, nil
}

// remoteTrust is how the session checks the certificate chain of the separate gateway
// at a URL: the system's roots, the zero RemoteTLS. A test sets another.
var remoteTrust = func(string) server.RemoteTLS { return server.RemoteTLS{} }

// link is the client of the gateway's link a run and a resend speak to it through:
// TLS 1.3 to its one address, bound to a key the run key names. version is Forager's,
// in the User-Agent; digests is as [server.NewRemoteLink] takes it.
func (g *RemoteGateway) link(version string, digests func(server.Digests)) (*server.Link, error) {
	k, err := g.key()
	if err != nil {
		return nil, err
	}
	return server.NewRemoteLink(g.RunKey, remoteTrust(k.GatewayURL), accesskey.UserAgent(version), digests)
}

// String names the gateway by the URL its run key names, never the run key: "(no run
// key)" for none, and "(not a run key)" for one the session cannot read.
func (g RemoteGateway) String() string {
	shown := "(no run key)"
	if g.RunKey != "" {
		shown = "(not a run key)"
		if k, err := runkey.Parse(g.RunKey); err == nil {
			shown = accesskey.ShownValue(k.GatewayURL, false)
		}
	}
	return "session.RemoteGateway{" + shown + "}"
}

// Format prints g as String does, under every verb and flag.
func (g RemoteGateway) Format(f fmt.State, _ rune) { io.WriteString(f, g.String()) }

// GoString is g as %#v prints it.
func (g RemoteGateway) GoString() string { return g.String() }

// LogValue is g as log/slog logs it.
func (g RemoteGateway) LogValue() slog.Value { return slog.StringValue(g.String()) }

// gatewayOf is the spec's gateway by its kind: the local link's, or a separate
// gateway's. A spec with neither is refused.
func gatewayOf(g Gateway) (*localGateway, *RemoteGateway, error) {
	switch g := g.(type) {
	case localGateway:
		return &g, nil, nil
	case RemoteGateway:
		return nil, &g, nil
	case *RemoteGateway:
		if g != nil {
			return gatewayOf(*g)
		}
	}
	return nil, nil, errNoGateway
}

// gatewayFiles are the gateway's own files on this machine, which a walled run must not
// mount, each with what it is: the local gateway's. A separate gateway has none here.
func gatewayFiles(g Gateway) []link.File {
	if l, ok := g.(localGateway); ok {
		return l.local.Files
	}
	return nil
}

// reservedOf are the names of the variables the machine's credentials are read from on
// this machine: the local gateway's. A separate gateway reads none here.
func reservedOf(g Gateway) []string {
	if l, ok := g.(localGateway); ok {
		return l.local.Reserved
	}
	return nil
}

// errNoGateway is a spec without a gateway.
var errNoGateway = errors.New("the run has no gateway: a session speaks only to a gateway, session.LocalGateway or session.RemoteGateway")
