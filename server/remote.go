package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/qoryai/forager/link"
)

// RemoteTLS is how the session trusts a separate gateway's certificate
// (contracts/forager/v1/README.md §The gateway's link): the full chain, for the host
// name of the gateway's URL, against the system's roots, or, when CAFile is set,
// against the authorities of that file alone; and, when CertificateSHA256 is set, the
// pin of the certificate's public key besides.
type RemoteTLS struct {
	// CAFile is a PEM file of the authorities the gateway's certificate chains to. Set,
	// it replaces the system's roots for this link; empty means the system's roots.
	CAFile string
	// CertificateSHA256 is the SHA-256 of the gateway certificate's public key, its DER
	// SubjectPublicKeyInfo, in standard base64 with padding: 44 characters ending in
	// "=". Set, only a certificate with that key is accepted, and its chain is still
	// checked. Empty means no pin.
	CertificateSHA256 string
}

// pinShape is a pin's form: 32 bytes in standard base64 with padding.
var pinShape = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

// config is the TLS of the link to the gateway at host: TLS 1.3 alone, the roots, the
// host name and the pin.
func (r RemoteTLS) config(host string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ServerName: host,
		NextProtos: []string{"http/1.1"},
	}
	if r.CAFile != "" {
		b, err := os.ReadFile(r.CAFile)
		if err != nil {
			return nil, fmt.Errorf("the gateway's certificate authorities: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("the gateway's certificate authorities %s hold no PEM certificate", r.CAFile)
		}
		cfg.RootCAs = pool
	}
	if r.CertificateSHA256 != "" {
		if !pinShape.MatchString(r.CertificateSHA256) {
			return nil, errors.New("the gateway's certificate pin is not the SHA-256 of a public key in standard base64 with padding, 44 characters ending in =")
		}
		pin, err := base64.StdEncoding.Strict().DecodeString(r.CertificateSHA256)
		if err != nil || len(pin) != sha256.Size {
			return nil, errors.New("the gateway's certificate pin is not the SHA-256 of a public key in standard base64 with padding, 44 characters ending in =")
		}
		// The chain and the host name are verified first, as without a pin; the pin
		// then holds the certificate to its one key.
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the gateway presented no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return errors.New("the gateway's certificate does not have the public key its pin names")
			}
			return nil
		}
	}
	return cfg, nil
}

// bearerToken is a run credential's form in Authorization: Bearer, b64token of RFC 6750
// §2.1.
var bearerToken = regexp.MustCompile(`^[A-Za-z0-9\-._~+/]+=*$`)

// errCredentialShape refuses a run credential that is not a Bearer token; it never
// names the credential.
var errCredentialShape = errors.New("the run credential is not in the syntax of a Bearer token (RFC 6750 §2.1)")

// NewRemoteLink returns the client of a separate gateway's link at gatewayURL, an
// https URL with a host and, optionally, a port, and no user information, path, query
// or fragment. Every connection is TLS 1.3 alone, verified as trust says
// ([RemoteTLS]); no proxy of the environment is used, and no redirect is followed.
// Every request carries Authorization: Bearer and the run credential credential
// returns, which is asked for again before each request, so a run credential its starter
// refreshes is sent from then on. A credential that fails, or that is not a Bearer
// token, sends nothing. The run credential is never printed, logged or contained in an
// error the link returns; the error credential returns is passed on, and must not hold
// it.
//
// userAgent and digests are as for [NewLocalLink]. The link's discovery must list
// URLs of gatewayURL's origin alone, and name as its proxy the gateway's one address,
// the host and port of gatewayURL, which [Link.DialProxy] reaches.
func NewRemoteLink(gatewayURL string, trust RemoteTLS, credential func(context.Context) (string, error), userAgent string, digests func(Digests)) (*Link, error) {
	u, err := url.Parse(gatewayURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.Opaque != "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("the gateway's URL is not an https URL of a host and an optional port, with no user information, path, query or fragment")
	}
	if credential == nil {
		return nil, errors.New("the gateway's link has no run credential")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	cfg, err := trust.config(u.Hostname())
	if err != nil {
		return nil, err
	}
	origin := "https://" + u.Host
	k := &Link{
		userAgent: userAgent, origin: origin, name: "the gateway at " + origin, digests: digests,
		credential: credential, address: net.JoinHostPort(u.Hostname(), port), tls: cfg, runSecret: new(atomic.Pointer[string]),
	}
	k.http = &http.Client{
		Timeout: Timeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: dialTimeout}).DialContext,
			TLSClientConfig:     cfg,
			TLSHandshakeTimeout: dialTimeout,
			DisableCompression:  true,
			MaxIdleConns:        4,
			IdleConnTimeout:     90 * time.Second,
		},
		// A 3xx is a status like any other: the run credential goes to the gateway alone.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return k, nil
}

// dialTimeout is how long a connection to a separate gateway has to open, its TLS
// handshake included.
const dialTimeout = 10 * time.Second

// authorize sets the request's authentication, the one place it is set: behind a
// separate gateway its Authorization, the run credential asked for now; and on either
// link, once the run is open, X-Qory-Run-Secret, the run's secret.
func (k *Link) authorize(ctx context.Context, h http.Header) error {
	if k.credential != nil {
		c, err := k.credential(ctx)
		if err != nil {
			return fmt.Errorf("the run credential: %w", err)
		}
		if !bearerToken.MatchString(c) {
			return errCredentialShape
		}
		h.Set("Authorization", link.BearerScheme+" "+c)
	}
	if s := k.runSecret.Load(); s != nil {
		h.Set(HeaderRunSecret, *s)
	}
	return nil
}

// DialProxy opens one connection to a separate gateway's proxy, its one address, over
// TLS 1.3 with the link's trust, the handshake done: what the run's agent traffic goes
// through behind a separate gateway. Nothing is written on it. The local link has no
// such way: its proxy is on loopback, reached as it is.
func (k *Link) DialProxy(ctx context.Context) (net.Conn, error) {
	if k.tls == nil {
		return nil, errors.New("the gateway's local link has no proxy over TLS")
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: dialTimeout}, Config: k.tls}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", k.address)
	if err != nil {
		return nil, fmt.Errorf("the gateway's proxy %s: %w", k.address, err)
	}
	return c, nil
}

// ProxyAddress is a separate gateway's one address, host:port, which its discovery
// names as its proxy; empty on the local link.
func (k *Link) ProxyAddress() string { return k.address }

// oneAddress refuses a discovery's proxy address that is not a separate gateway's one
// address.
func (k *Link) oneAddress(addr string) error {
	if k.address == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	want, wantPort, _ := net.SplitHostPort(k.address)
	if err != nil || !strings.EqualFold(host, want) || port != wantPort {
		return errors.New("proxy.address is not the gateway's one address, the host and port of its URL")
	}
	return nil
}
