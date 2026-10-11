package server

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/runkey"
)

// RemoteTLS is how a gateway's certificate is trusted: the full chain, for the host name
// of the gateway's URL, against the system's roots, or, when CAFile is set, against the
// authorities of that file alone; and, when CertificateSHA256 is set, the pin of the
// certificate's public key besides. [Via] carries it toward a gateway that relays to the
// server, and [NewRemoteLink] checks the chain of a separate gateway's certificate with
// it, the zero RemoteTLS on a run's edge.
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

// NewRemoteLink returns the client of the link to the separate gateway runKey names,
// the run key Qory Apiary answered the run's registration with: its gateway_url is the
// one address the run key is ever sent to, and its gateway_public_key the keys the
// gateway must prove it holds. The run key is read as a runner reads one,
// [runkey.Parse], unverified: an error of the parse is a [*runkey.Error], which names
// the part that is wrong and never the run key.
//
// Every connection is TLS 1.3 alone, its chain checked as trust says ([RemoteTLS]): the
// zero RemoteTLS checks it against the system's roots for the host name of the
// gateway's URL. It then opens with the binding exchange (contracts/forager/v1/README.md
// §The gateway's link): the gateway proves, over the connection's exporter value, that
// it holds a key the run key names, or the connection is closed and the run key never
// sent, a [*GatewayKeyError]. Every request of the link carries the run key,
// Authorization: Bearer, every answer must be signed under a key the run key names for
// that connection and request, and a proxy connection, [Link.DialProxy], opens with the
// relay's preamble and the run key. No proxy of the environment is used, HTTP/2 is not
// offered, and no redirect is followed.
//
// userAgent and digests are as for [NewLocalLink]. The link's discovery must list URLs
// of the gateway's origin under [link.RemotePathPrefix] alone, and name as its proxy
// the gateway's one address, the host and port of its URL.
func NewRemoteLink(runKey string, trust RemoteTLS, userAgent string, digests func(Digests)) (*Link, error) {
	key, err := runkey.Parse(runKey)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(key.GatewayURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.Opaque != "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("the gateway's URL is not an https URL of a host and an optional port, with no user information, path, query or fragment")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	cfg, err := trust.config(u.Hostname())
	if err != nil {
		return nil, err
	}
	g := &remoteGateway{
		url: "https://" + u.Host, address: net.JoinHostPort(u.Hostname(), port), tls: cfg,
		keys: slices.Clone(key.GatewayKeys), runKey: runKey,
	}
	k := &Link{
		userAgent: userAgent, origin: g.url, name: "the gateway at " + g.url, digests: digests,
		runID: new(atomic.Pointer[string]), remote: g,
	}
	k.http = &http.Client{
		Timeout: Timeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return g.dial(ctx)
			},
			ForceAttemptHTTP2:  false,
			DisableCompression: true,
			MaxIdleConns:       4,
			IdleConnTimeout:    90 * time.Second,
		},
		// A 3xx is a status like any other: nothing of the run goes elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return k, nil
}

// remoteGateway is a separate gateway, as the run key names it: its origin, its one
// address, the TLS every connection to it is made with, the keys it must prove it
// holds, and the run key, which every request carries once the connection is bound.
type remoteGateway struct {
	url     string
	address string
	tls     *tls.Config
	keys    []accesskey.PublicKey
	runKey  string
}

// GatewayKeyError is a separate gateway that failed the run key's pin: on a connection,
// it did not prove it holds a key the run key names, Unproven, its answer to the
// binding being missing, of another form, of a fingerprint the run key does not name
// or with a signature that does not verify; or it answered a request under a key the
// run key does not name, or with no signature. Before the run starts the run does not
// start with its text; once it runs, it is no answer, and nothing of it is applied.
type GatewayKeyError struct {
	// URL is the gateway's, as the run key names it.
	URL string
	// Unproven says the binding failed; false is an answer under another key.
	Unproven bool
}

func (e *GatewayKeyError) Error() string {
	if e.Unproven {
		return "the gateway at " + e.URL + " could not prove it holds a key the run key names"
	}
	return "the gateway at " + e.URL + " answered under a key the run key does not name"
}

// dialTimeout is how long a connection to a separate gateway has to open, its TLS
// handshake and its binding included.
const dialTimeout = 10 * time.Second

// boundConn is a connection to a separate gateway past its binding: its exporter value,
// which the gateway's answers on it are signed over, and the reader the binding's answer
// was read with, which may hold the first bytes after it.
type boundConn struct {
	*tls.Conn
	r   *bufio.Reader
	ekm []byte
}

func (c *boundConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// dial opens one connection to the gateway: TLS 1.3 with the link's trust, then the
// binding exchange, within [dialTimeout]. A gateway that does not prove it holds a key
// the run key names is a [*GatewayKeyError] Unproven, and the connection is closed
// before the run key is sent; a connection that does not open is the transport's error.
func (g *remoteGateway) dial(ctx context.Context) (*boundConn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	d := &tls.Dialer{NetDialer: &net.Dialer{}, Config: g.tls}
	c, err := d.DialContext(ctx, "tcp", g.address)
	if err != nil {
		return nil, err
	}
	tc := c.(*tls.Conn)
	cs := tc.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial(link.BindingLabel, []byte{}, link.BindingSize)
	if err != nil {
		tc.Close()
		return nil, &GatewayKeyError{URL: g.url, Unproven: true}
	}
	if deadline, ok := ctx.Deadline(); ok {
		tc.SetDeadline(deadline)
	}
	r := bufio.NewReaderSize(tc, link.MaxBoundLine)
	if _, err := io.WriteString(tc, link.BindLine); err != nil || !g.bound(r, ekm) {
		tc.Close()
		return nil, &GatewayKeyError{URL: g.url, Unproven: true}
	}
	tc.SetDeadline(time.Time{})
	return &boundConn{Conn: tc, r: r, ekm: ekm}, nil
}

// bound reads the gateway's answer to the binding, at most [link.MaxBoundLine] bytes,
// and reports whether it is [link.BoundWord], a fingerprint of a key the run key names
// and that key's signature over [link.BindingMessage] for ekm.
func (g *remoteGateway) bound(r *bufio.Reader, ekm []byte) bool {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(string(line), "\n"), " ")
	if len(parts) != 3 || parts[0] != link.BoundWord {
		return false
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	for _, k := range g.keys {
		if k.Fingerprint() == parts[1] {
			return k.Verify(link.BindingMessage(ekm, parts[1]), sig)
		}
	}
	return false
}

// signed reports whether the answer a to req, whose body is body, came on a bound
// connection with exactly one signature, under a key the run key names, over the six
// lines of a separate gateway's answer: its third the hash of the connection's exporter
// value and the request, [link.AnswerRequest].
func (g *remoteGateway) signed(c net.Conn, req *http.Request, body []byte, a *linkAnswer, signatures []string) bool {
	bc, ok := c.(*boundConn)
	if !ok || len(signatures) != 1 {
		return false
	}
	answer := accesskey.Answer{
		Link: true, Status: a.status, Body: a.body,
		RequestSignature: link.AnswerRequest(bc.ekm, req.Method, req.URL.RequestURI(), body),
		Configuration:    a.digests.Configuration, RunConfiguration: a.digests.RunConfiguration,
	}
	for _, k := range g.keys {
		if k.VerifyAnswer(answer, signatures[0]) {
			return true
		}
	}
	return false
}

// authorize sets the request's authentication, the one place it is set: behind a
// separate gateway, the run key, Authorization: Bearer. The local link sets none: the
// socket's peer is checked.
func (k *Link) authorize(h http.Header) {
	if k.remote != nil {
		h.Set("Authorization", "Bearer "+k.remote.runKey)
	}
}

// DialProxy opens one connection to a separate gateway's proxy, its one address: TLS
// 1.3 with the link's trust, bound as every connection of the link is, and opened with
// the relay's preamble and the run key, [link.RelayLine]. What the run's agent traffic
// goes through behind a separate gateway is written after it. The local link has no
// such way: its proxy is on loopback, reached as it is.
func (k *Link) DialProxy(ctx context.Context) (net.Conn, error) {
	if k.remote == nil {
		return nil, errors.New("the gateway's local link has no proxy over TLS")
	}
	c, err := k.remote.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("the gateway's proxy %s: %w", k.remote.address, err)
	}
	c.SetWriteDeadline(time.Now().Add(link.PreambleWait))
	if _, err := io.WriteString(c, link.RelayLine(k.remote.runKey)); err != nil {
		c.Close()
		return nil, fmt.Errorf("the gateway's proxy %s: the preamble: %w", k.remote.address, err)
	}
	c.SetWriteDeadline(time.Time{})
	return c, nil
}

// ProxyAddress is a separate gateway's one address, host:port, which its discovery
// names as its proxy; empty on the local link.
func (k *Link) ProxyAddress() string {
	if k.remote == nil {
		return ""
	}
	return k.remote.address
}

// oneAddress refuses a discovery's proxy address that is not a separate gateway's one
// address.
func (k *Link) oneAddress(addr string) error {
	if k.remote == nil {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	want, wantPort, _ := net.SplitHostPort(k.remote.address)
	if err != nil || !strings.EqualFold(host, want) || port != wantPort {
		return errors.New("proxy.address is not the gateway's one address, the host and port of its URL")
	}
	return nil
}
