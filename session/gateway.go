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
// another machine. A nil Gateway is none, and no run.
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

// RemoteGateway is a separate gateway, on another machine, which the run reaches over
// TLS 1.3 on the gateway's one address (contracts/forager/v1/README.md §The gateway's
// link), as the run key names it. The session reads the run key as a runner does,
// unverified, [runkey.Parse], and takes of it the run's id, the gateway's URL, the one
// address the run key is ever sent to, and the gateway's keys. It checks the certificate
// chain of the gateway for the host name of that URL with the trust in TLS, and every
// connection is bound to a key the run key names before the run key is sent; every
// answer of the gateway must be signed under one. It has no access key: the gateway's
// signs toward the server.
//
// The session reads no environment: the caller passes the run key, from [EnvRunKey].
// It is never written to a file, set in an agent's environment or printed: fmt and
// log/slog show a RemoteGateway by its gateway's URL alone, and EnvRunKey is taken out
// of every agent's environment, the one it inherits among them.
type RemoteGateway struct {
	// RunKey is the run key Qory Apiary answered the run's registration with: qrk_,
	// its payload and its signature.
	RunKey string
	// TLS is how the session trusts the certificate of the run key's gateway, on the
	// run's link and on a resend's, as for [server.Via]: with the zero RemoteTLS the
	// session checks the chain against the system's roots; with CAFile, against the
	// authorities of that PEM file in their place; with CertificateSHA256, it also
	// accepts only a certificate with that public key. A CA file Forager cannot read,
	// or a pin of another form, stops the run, and a resend that sends events, before
	// any connection, with an error that starts with the fix.
	TLS server.RemoteTLS
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

// link is the client of the gateway's link a run and a resend speak to it through:
// TLS 1.3 to its one address with g.TLS, bound to a key the run key names. version is
// Forager's, in the User-Agent; digests is as [server.NewRemoteLink] takes it.
func (g *RemoteGateway) link(version string, digests func(server.Digests)) (*server.Link, error) {
	if _, err := g.key(); err != nil {
		return nil, err
	}
	if err := g.checkTLS(); err != nil {
		return nil, err
	}
	return server.NewRemoteLink(g.RunKey, g.TLS, accesskey.UserAgent(version), digests)
}

// checkTLS refuses a TLS the link cannot use, with an error that starts with the fix:
// a CA file that cannot be read or has no PEM certificate, and a pin of another form.
// [server.RemoteTLS.Check] checks each; of its error, the text after the fix is the
// cause the fix does not state: the read error, or that the file has no PEM
// certificate.
func (g *RemoteGateway) checkTLS() error {
	if f := g.TLS.CAFile; f != "" {
		if err := (server.RemoteTLS{CAFile: f}).Check(); err != nil {
			if cause := errors.Unwrap(err); cause != nil {
				err = cause
			}
			return fmt.Errorf("set the gateway's CA file to a PEM file of its certificate authorities that Forager can read: %w", err)
		}
	}
	if p := g.TLS.CertificateSHA256; p != "" {
		if (server.RemoteTLS{CertificateSHA256: p}).Check() != nil {
			return errors.New("set the gateway's certificate pin to the SHA-256 of its public key: 44 characters of standard base64 ending in =")
		}
	}
	return nil
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
