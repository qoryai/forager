package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"slices"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// Gateway is the gateway a run speaks to: the one that holds the run's proxy, its
// policy, its credentials and its tools, and is the node toward the server. The session
// is its client, over its link (contracts/forager/v1/README.md §The gateway's link).
// [LocalGateway] makes one on this machine; a [RemoteGateway] is a separate gateway, on
// a machine of its own. A nil Gateway is none, and no run.
//
// A Gateway never prints the link secret or the run credential: fmt and log/slog show
// it by its socket or its URL.
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
// it out: the socket, the link secret, which stays in this process's memory and is
// never set in an environment or written to a file, the gateway's own files, which a
// walled run must not mount, and the names it sets for a run.
func LocalGateway(l link.Local) Gateway {
	l.Files, l.Reserved = slices.Clone(l.Files), slices.Clone(l.Reserved)
	return localGateway{local: l}
}

func (localGateway) gateway() {}

// String names the gateway by its link's socket, never its secret.
func (g localGateway) String() string { return "session.Gateway{" + g.local.Socket + "}" }

// Format prints g as String does, under every verb and flag.
func (g localGateway) Format(f fmt.State, _ rune) { io.WriteString(f, g.String()) }

// GoString is g as %#v prints it, never its secret.
func (g localGateway) GoString() string { return g.String() }

// LogValue is g as log/slog logs it, never its secret.
func (g localGateway) LogValue() slog.Value { return slog.StringValue(g.String()) }

// RemoteGateway is a separate gateway, on a machine of its own, which the run reaches
// over TLS 1.3 on the gateway's one address (contracts/forager/v1/README.md §The
// gateway's link). The session verifies the gateway's certificate chain for the host
// name of URL, against the system's roots or CAFile's authorities, and its public key
// against CertificateSHA256 when it is set; it presents the run credential on every
// request, Authorization: Bearer. The run's labels are the run credential's: the
// session's Labels, its forge and repository among them, must match it, or the gateway
// refuses the run. It holds no access key: the gateway's signs toward the server.
//
// A RemoteGateway never prints the run credential: Credential is a function, and fmt
// and log/slog show the gateway by its URL, its CAFile and its pin alone.
type RemoteGateway struct {
	// URL is the gateway's, https and a host with an optional port, and no user
	// information, path, query or fragment: https://gateway.example:8443.
	URL string
	// CAFile is a PEM file of the authorities the gateway's certificate chains to, which
	// replace the system's roots for this gateway; empty means the system's roots.
	CAFile string
	// CertificateSHA256 is the SHA-256 of the gateway certificate's public key, its DER
	// SubjectPublicKeyInfo, in standard base64 with padding, 44 characters ending in =;
	// empty means no pin.
	CertificateSHA256 string
	// Credential returns the run's current run credential. It is asked again before
	// every request, so a run credential its starter refreshes, in a file say, is sent
	// from then on. Its error is returned as the request's, and must not hold the run
	// credential. A RemoteGateway without one is no run.
	Credential func(ctx context.Context) (string, error)
}

func (RemoteGateway) gateway() {}

// link is the client of the gateway's link a run and a resend speak to it through:
// TLS 1.3 to its one address, verified as the gateway says, and the run credential on
// every request, set by the link alone. version is Forager's, in the User-Agent; digests
// is as [server.NewRemoteLink] takes it.
func (g *RemoteGateway) link(version string, digests func(server.Digests)) (*server.Link, error) {
	return server.NewRemoteLink(g.URL, server.RemoteTLS{CAFile: g.CAFile, CertificateSHA256: g.CertificateSHA256},
		g.Credential, accesskey.UserAgent(version), digests)
}

// String names the gateway by its URL's origin, without user information, a path, a
// query or a fragment, its CAFile and its pin; never the run credential.
func (g RemoteGateway) String() string {
	shown := "(no URL)"
	if g.URL != "" {
		// The origin alone: user information, a path, a query or a fragment, which
		// the gateway's URL never has, could hold what is not to be printed.
		if u, err := url.Parse(g.URL); err == nil && u.Scheme != "" && u.Host != "" {
			shown = u.Scheme + "://" + u.Host
		} else {
			shown = "(not a URL)"
		}
	}
	s := "session.RemoteGateway{" + shown
	if g.CAFile != "" {
		s += " ca_file=" + g.CAFile
	}
	if g.CertificateSHA256 != "" {
		s += " certificate_sha256=" + g.CertificateSHA256
	}
	return s + "}"
}

// Format prints g as String does, under every verb and flag.
func (g RemoteGateway) Format(f fmt.State, _ rune) { io.WriteString(f, g.String()) }

// GoString is g as %#v prints it, never the run credential.
func (g RemoteGateway) GoString() string { return g.String() }

// LogValue is g as log/slog logs it, never the run credential.
func (g RemoteGateway) LogValue() slog.Value { return slog.StringValue(g.String()) }

// gatewayOf is the spec's gateway by its kind: the local link's, or a separate
// gateway's. A spec with neither is refused.
func gatewayOf(g Gateway) (*localGateway, *RemoteGateway, error) {
	switch g := g.(type) {
	case localGateway:
		return &g, nil, nil
	case RemoteGateway:
		if g.Credential == nil {
			return nil, nil, errNoCredential
		}
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

// errNoCredential is a separate gateway without a run credential.
var errNoCredential = errors.New("the separate gateway has no run credential: a run behind one opens only with a run credential")
