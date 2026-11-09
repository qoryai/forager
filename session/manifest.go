package session

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/wall"
)

// manifestWait is how long the check of the run's image at its registry may take, the
// request for a token included; a test sets it shorter.
var manifestWait = 30 * time.Second

// manifestTypes is the Accept of the check: an OCI index or manifest, a Docker manifest
// list or a Docker manifest of schema 2.
const manifestTypes = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"

// maxTokenAnswer is the most bytes of a token realm's answer the check reads.
const maxTokenAnswer = 1 << 20

// manifestRoots are authorities, as PEM, that the check trusts beside the machine's and
// the run's; a test sets them.
var manifestRoots []byte

// manifestHook, when set, checks the image in place of the request; a test whose
// gateway cannot reach a registry sets it.
var manifestHook func(ctx context.Context, image string) error

// checkManifest requests the manifest of the run's image by reference from its registry
// through the run's proxy, under [manifestWait], before the wall's pull: the engine may
// hold the image by its digest and answer a pull from what it holds, so the request
// stands for the run's right to the image. The gateway's proxy sets the run's
// credentials on it, as on every request of the run's host work.
//
// The request is a HEAD of /v2/<repository>/manifests/<digest> over https, or over
// http for a registry on loopback, which the engine reaches without TLS. A 401 with a
// Bearer challenge is followed by a GET of the challenge's realm with its service and
// the scope repository:<repository>:pull, with no Authorization, and the HEAD again with
// the realm's token. A realm on another host than the registry's is asked only when no
// credential or tool of the run applies to its host, or when each credential that
// applies has paths and one matches the realm's path, [manifestCheck.realmRefused]:
// a registry cannot have the check fetch a token with a credential set for other paths,
// such as a forge's API. Only a 200 passes, with a Docker-Content-Digest equal to the
// digest when the registry sends one. A 404 is image_missing. A 401 or 403 is
// image_access_denied, a 429 image_rate_limited, and a registry or realm the check does
// not reach, [unreachable], image_registry_unreachable, each a refusal whose name is
// the image and whose detail starts with what to fix. A host the run's proxy denies is
// an error that names the host to allow; any other answer or failure is an error whose
// first words say what to fix. The token is held in memory alone and is in no error.
func (r *Run) checkManifest(ctx context.Context) error {
	if manifestHook != nil {
		return manifestHook(ctx, r.img.Ref)
	}
	c := manifestCheck{client: r.manifestClient(), image: accesskey.ShownName(r.img.Ref, false), ended: ctx.Err}
	c.host, c.repository, c.digest = wall.RegistryManifest(r.img.Ref)
	c.held = r.realmCredentials
	return c.check(ctx)
}

// check runs the check under [manifestWait]. A check that runs out of that time is
// image_registry_unreachable, unless its error is a [proxyConnError] or a dial of the
// run's proxy did not open, [proxyDials]: the fix is then at the gateway.
func (c manifestCheck) check(ctx context.Context) error {
	checking, cancel := context.WithTimeout(ctx, manifestWait)
	defer cancel()
	checking = context.WithValue(checking, proxyDialsKey{}, &proxyDials{})
	err := c.run(checking)
	var conn *proxyConnError
	if err != nil && ctx.Err() == nil && errors.Is(checking.Err(), context.DeadlineExceeded) && !errors.As(err, &conn) && !proxyDialHung(checking) {
		return c.refuse(refusal.ImageRegistryUnreachable, "Check that the run's proxy reaches %s within %s: the check of the image %s at its registry timed out",
			accesskey.ShownValue(c.host, false), manifestWait, c.image)
	}
	return err
}

// manifestClient is the client of the check, [manifestHTTPClient], over [Run.dialProxy],
// trusting the machine's authorities and the run's certificate.
func (r *Run) manifestClient() *http.Client {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	roots.AppendCertsFromPEM(r.authority)
	roots.AppendCertsFromPEM(manifestRoots)
	return manifestHTTPClient(r.dialProxy, roots)
}

// manifestHTTPClient is a client whose every request goes through the run's proxy over
// a connection that dial opens, a [proxyConn], follows no redirect, and trusts roots.
func manifestHTTPClient(dial func(context.Context) (net.Conn, error), roots *x509.CertPool) *http.Client {
	// The proxy's URL is never dialled: DialContext opens every connection to the run's
	// proxy.
	proxy := &url.URL{Scheme: "http", Host: "run-proxy"}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return proxy, nil },
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				dials, _ := ctx.Value(proxyDialsKey{}).(*proxyDials)
				if dials != nil {
					dials.started.Add(1)
				}
				c, err := dial(ctx)
				if err != nil {
					return nil, &proxyConnError{err: err}
				}
				if dials != nil {
					dials.opened.Add(1)
				}
				t, _ := ctx.Value(tunnelKey{}).(*tunnel)
				return &proxyConn{Conn: c, tunnel: t}, nil
			},
			OnProxyConnectResponse: connectFailure,
			TLSClientConfig:        &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			DisableKeepAlives:      true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// proxyDialsKey is the context key of a check's [*proxyDials].
type proxyDialsKey struct{}

// proxyDials counts the dials of the run's proxy of one check: those started, and those
// that opened a connection. When the check's time ends during a dial, the client
// returns the context's error, not the dial's, and the dial opens nothing, so started
// stays above opened.
type proxyDials struct{ started, opened atomic.Int32 }

// proxyDialHung reports whether a dial of the run's proxy of the check of ctx started
// and opened no connection.
func proxyDialHung(ctx context.Context) bool {
	d, _ := ctx.Value(proxyDialsKey{}).(*proxyDials)
	return d != nil && d.started.Load() != d.opened.Load()
}

// tunnelKey is the context key of a request's [*tunnel].
type tunnelKey struct{}

// tunnel is one request's CONNECT: open once the run's proxy returned 200 to it,
// [connectFailure], so the connection is a tunnel to the registry or its realm.
type tunnel struct{ open atomic.Bool }

// withTunnel is ctx with a [*tunnel] for one request of the check.
func withTunnel(ctx context.Context) context.Context {
	return context.WithValue(ctx, tunnelKey{}, &tunnel{})
}

// proxyConn is a connection to the run's proxy. A read or a write that fails before
// the proxy returned 200 to the CONNECT, or on a request with no CONNECT, fails on the
// connection to the proxy itself, and its error is a [proxyConnError]; io.EOF stays as
// it is.
type proxyConn struct {
	net.Conn
	tunnel *tunnel
}

func (c *proxyConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	return n, c.failed(err)
}

func (c *proxyConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	return n, c.failed(err)
}

// failed is err as a [proxyConnError] while no tunnel is open.
func (c *proxyConn) failed(err error) error {
	if err == nil || err == io.EOF || c.tunnel != nil && c.tunnel.open.Load() {
		return err
	}
	return &proxyConnError{err: err}
}

// proxyConnError is a connection to the run's proxy itself that failed: its dial, or a
// read or write before the proxy opened the tunnel. [unreachable] does not count it as
// the registry's, since the fix is at the gateway.
type proxyConnError struct{ err error }

func (e *proxyConnError) Error() string { return e.err.Error() }
func (e *proxyConnError) Unwrap() error { return e.err }

// dialProxy opens one connection to the run's proxy, as the host proxy's forwarder
// does: on one machine with the relay's preamble and the run's proxy secret, and behind
// a separate gateway with the link's proxy dial, bound to the run key.
func (r *Run) dialProxy(ctx context.Context) (net.Conn, error) {
	if r.remote != nil {
		return r.link.DialProxy(ctx)
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", r.disc.Proxy.Address)
	if err != nil || r.answer.ProxySecret == "" {
		return c, err
	}
	c.SetWriteDeadline(time.Now().Add(link.PreambleWait))
	if _, err := io.WriteString(c, link.RelayLine(r.answer.ProxySecret)); err != nil {
		c.Close()
		return nil, err
	}
	c.SetWriteDeadline(time.Time{})
	return c, nil
}

// deniedHost is a CONNECT the run's proxy answered 403: host is the host the check
// asked for, and said the first line of the proxy's answer.
type deniedHost struct {
	host, said string
}

func (d *deniedHost) Error() string { return "the run's proxy denied " + d.host }

// unreachedHost is a CONNECT the run's proxy returned 502 to: the proxy allowed the
// host, and its connection to the host failed, such as a host name that does not
// resolve or a port that refuses. hostport is the CONNECT's host:port, and said is the
// first line of the proxy's body.
type unreachedHost struct {
	hostport, said string
}

func (u *unreachedHost) Error() string {
	if u.said == "" {
		return "the run's proxy did not reach " + u.hostport
	}
	return "the run's proxy did not reach " + u.hostport + ": " + u.said
}

// connectFailure is a [deniedHost] for a CONNECT the run's proxy returns 403 to, an
// [unreachedHost] for one it returns 502 to, and nil for any other status. A 200 opens
// the request's [tunnel].
func connectFailure(ctx context.Context, _ *url.URL, req *http.Request, resp *http.Response) error {
	if t, _ := ctx.Value(tunnelKey{}).(*tunnel); t != nil && resp.StatusCode == http.StatusOK {
		t.open.Store(true)
	}
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusBadGateway {
		return nil
	}
	line, _ := bufio.NewReader(io.LimitReader(resp.Body, 512)).ReadString('\n')
	line = strings.TrimSpace(line)
	if resp.StatusCode == http.StatusBadGateway {
		return &unreachedHost{hostport: req.Host, said: line}
	}
	host, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
	}
	return &deniedHost{host: host, said: line}
}

// heldCredentials are the run's credentials and tools as the check of a token realm
// reads them: hosts are the hosts of each entry of the answer's credential_hosts; uses
// each use of a credential the members of policy_applied list, which are the
// credentials the run's proxy sets, but a harness credential's, which only the stack
// proxy sets; and tools each tool the members list, to which the run's proxy passes the
// requests to its hosts.
type heldCredentials struct {
	hosts [][]string
	uses  []credentialUse
	tools []heldTool
}

// credentialUse is one use of a run's credential: the hosts it is set on, and its
// paths, nil for every path.
type credentialUse struct {
	hosts, paths []string
}

// heldTool is a tool of the run and the hosts it serves.
type heldTool struct {
	name  string
	hosts []string
}

// realmCredentials are the run's [heldCredentials] at the moment of the call: a reload
// replaces the members.
func (r *Run) realmCredentials() heldCredentials {
	var h heldCredentials
	for _, c := range r.answer.CredentialHosts {
		h.hosts = append(h.hosts, c.Hosts)
	}
	r.emitMu.Lock()
	creds, _ := r.members["credentials"].([]any)
	tools, _ := r.members["tools"].([]any)
	r.emitMu.Unlock()
	for _, e := range creds {
		m, _ := e.(map[string]any)
		if m == nil || m["purpose"] == server.PurposeHarness {
			continue
		}
		u := credentialUse{hosts: jsonStrings(m["hosts"])}
		if p, ok := m["paths"]; ok {
			u.paths = append([]string{}, jsonStrings(p)...)
		}
		h.uses = append(h.uses, u)
	}
	for _, e := range tools {
		if m, _ := e.(map[string]any); m != nil {
			name, _ := m["name"].(string)
			h.tools = append(h.tools, heldTool{name: name, hosts: jsonStrings(m["hosts"])})
		}
	}
	return h
}

// jsonStrings are the strings of a JSON array; nil for anything else.
func jsonStrings(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// manifestCheck is one check of an image's manifest: host is the registry's API host,
// repository and digest where its manifest is, image the reference as errors show it,
// held reads the run's credentials, [Run.realmCredentials], and ended is the caller's
// context's Err, so a failure after the caller's end has no refusal code.
type manifestCheck struct {
	client                   *http.Client
	host, repository, digest string
	image                    string
	held                     func() heldCredentials
	ended                    func() error
}

// refuse is the refusal with the code whose name is the check's image, and whose
// detail is written as fmt writes it.
func (c manifestCheck) refuse(code, format string, a ...any) error {
	return refusal.New(code, []string{c.image}, format, a...)
}

// realmRefused is the error of a realm the check does not ask for a token, nil for one
// it asks. A realm whose host has no [policy.Host] form is refused, since the client
// would send it to another host than the one the rule reads. A realm on the registry's
// host and port passes. On another host, a realm a tool serves is refused; one a use
// of a credential covers passes only when every such use has paths and one use's paths
// match the realm's path, as the run's proxy matches them; one whose host only
// credential_hosts lists, or a use whose host the answer masks, is refused, since the
// check cannot read what the proxy would set; one no credential or tool applies to
// passes, since the request carries no credential of the run.
func (c manifestCheck) realmRefused(realm *url.URL, held heldCredentials) error {
	shownRealm := accesskey.ShownValue(realm.Hostname(), true)
	host, ok := policy.Host(realm.Hostname())
	if !ok {
		return fmt.Errorf("Check the registry at %s: its Bearer challenge to the check of the image %s has the token realm host %s, which is not an ASCII host name or an IP address in canonical form.",
			accesskey.ShownValue(c.host, false), c.image, shownRealm)
	}
	if c.sameHost(host, realm) {
		return nil
	}
	shownRealm = accesskey.ShownValue(host, false)
	for _, t := range held.tools {
		if _, ok := policy.Match(t.hosts, host); ok {
			return fmt.Errorf("Use a registry with no token realm on %s, which the run's tool %s serves: the run's proxy passes the token request to that tool, "+
				"and the check of the image %s asks a realm on another host only where no tool of the run serves it.",
				shownRealm, accesskey.ShownName(t.name, false), c.image)
		}
	}
	escaped := realm.EscapedPath()
	if escaped == "" {
		escaped = "/"
	}
	clean, clear := policy.CleanPath(escaped)
	used, matched, unread := false, false, false
	for _, u := range held.uses {
		if slices.ContainsFunc(u.hosts, unreadable) {
			unread = true
		}
		if !policy.CredentialFor(u.hosts, host) {
			continue
		}
		used = true
		if u.paths == nil {
			matched = false
			break
		}
		if _, ok := policy.MatchPath(u.paths, clean); ok && clear {
			matched = true
		}
	}
	answered := slices.ContainsFunc(held.hosts, func(hosts []string) bool { return policy.CredentialFor(hosts, host) })
	switch {
	case used && matched:
		return nil
	case used:
		return fmt.Errorf("Set paths on the run's credentials for %s, with one that covers %s: the token realm of the registry at %s is on that host, "+
			"and the check of the image %s asks a realm on another host only where no run credential applies, or one whose paths cover the realm's path.",
			shownRealm, accesskey.ShownValue(escaped, false), accesskey.ShownValue(c.host, false), c.image)
	case answered || unread:
		return fmt.Errorf("Check the credentials of the gateway's answer for %s: it lists a credential for that host with no use, or a use whose hosts are masked, "+
			"so the check of the image %s cannot tell what the run's proxy sets on a token request to that host.", shownRealm, c.image)
	}
	return nil
}

// unreadable reports whether a credential's host entry is one the rule cannot read: no
// host and no "*." pattern of one, such as the phrase that replaces a masked value.
func unreadable(entry string) bool {
	_, ok := policy.Host(strings.TrimPrefix(entry, "*."))
	return !ok
}

// sameHost reports whether the realm is at the registry's host, with host the realm's
// [policy.Host] form, and at its port: each port the URL's, else its scheme's.
func (c manifestCheck) sameHost(host string, realm *url.URL) bool {
	reg := &url.URL{Host: c.host}
	regHost, ok := policy.Host(reg.Hostname())
	return ok && host == regHost && port(realm.Scheme, realm.Port()) == port(scheme(reg.Hostname()), reg.Port())
}

// port is the port of a URL with the scheme and the port, the scheme's when empty.
func port(scheme, p string) string {
	switch {
	case p != "":
		return p
	case scheme == "http":
		return "80"
	}
	return "443"
}

// run requests the manifest, and the token when the registry asks for one.
func (c manifestCheck) run(ctx context.Context) error {
	manifest := scheme(c.host) + "://" + c.host + "/v2/" + c.repository + "/manifests/" + c.digest
	status, header, err := c.head(ctx, manifest, "")
	if err != nil {
		return c.failed(ctx, c.host, err)
	}
	if status == http.StatusUnauthorized {
		token, realm, err := c.token(ctx, header.Values("WWW-Authenticate"))
		if err != nil {
			return err
		}
		if status, header, err = c.head(ctx, manifest, token); err != nil {
			return c.failed(ctx, c.host, err)
		}
		if status == http.StatusUnauthorized {
			return c.refuse(refusal.ImageAccessDenied, "Give the run a credential that may pull %s: its registry returned 401 to the check of its manifest with the token from %s",
				c.image, accesskey.ShownValue(realm, false))
		}
	}
	switch status {
	case http.StatusOK:
		if got := header.Get("Docker-Content-Digest"); got != "" && got != c.digest {
			return fmt.Errorf("Check the registry at %s: it answered the check of the image %s with the digest %s.", accesskey.ShownValue(c.host, false), c.image, accesskey.ShownValue(got, false))
		}
		return nil
	case http.StatusNotFound:
		return refusal.New(refusal.ImageMissing, []string{c.image}, "the image %s is not in its registry: the registry answered 404 to the check of its manifest", c.image)
	case http.StatusForbidden:
		// A HEAD has no body: the 403 of a path rule or of plain http to a host with a
		// credential, from the run's proxy, looks the same as the registry's.
		return c.refuse(refusal.ImageAccessDenied, "Give the run a credential that may pull %s, or a path rule that covers /v2/%s/manifests/ on %s: the check of its manifest got 403 from its registry or from the run's proxy",
			c.image, accesskey.ShownValue(c.repository, false), accesskey.ShownValue(c.host, false))
	case http.StatusTooManyRequests:
		// The run's proxy returns 429 too, at gateway.run_limits on a host it terminates.
		return c.refuse(refusal.ImageRateLimited, "Run again once the rate limit of the registry at %s resets, give the run a credential with a higher limit, or raise gateway.run_limits of the gateway: "+
			"the check of the image %s got 429 from its registry or from the run's proxy%s", accesskey.ShownValue(c.host, false), c.image, retryAfter(header))
	}
	return fmt.Errorf("Check the registry at %s: it answered %d to the check of the image %s.", accesskey.ShownValue(c.host, false), status, c.image)
}

// head sends the HEAD of the manifest, with token as its Bearer when set.
func (c manifestCheck) head(ctx context.Context, manifest, token string) (int, http.Header, error) {
	req, err := http.NewRequestWithContext(withTunnel(ctx), http.MethodHead, manifest, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", manifestTypes)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header, nil
}

// token gets a token from the realm of the registry's Bearer challenge, and returns it
// with the realm's host.
func (c manifestCheck) token(ctx context.Context, challenges []string) (token, realmHost string, err error) {
	params, bearer := bearerChallenge(challenges)
	if !bearer {
		return "", "", c.refuse(refusal.ImageAccessDenied, "Give the run a credential for %s: its registry returned 401 to the check of the image %s with no Bearer challenge",
			accesskey.ShownValue(c.host, false), c.image)
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Host == "" || realm.Scheme != "https" && (realm.Scheme != "http" || scheme(realm.Hostname()) != "http") {
		return "", "", fmt.Errorf("Check the registry at %s: the realm of its Bearer challenge to the check of the image %s is neither https nor http on loopback.", accesskey.ShownValue(c.host, false), c.image)
	}
	// The run's credentials are read here, right before the request for a token, so a
	// reload during the check's HEAD is part of the rule.
	if err := c.realmRefused(realm, c.held()); err != nil {
		return "", "", err
	}
	q := realm.Query()
	if service := params["service"]; service != "" {
		q.Set("service", service)
	}
	q.Set("scope", "repository:"+c.repository+":pull")
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(withTunnel(ctx), http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", "", c.failed(ctx, realm.Hostname(), err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return "", "", c.failed(ctx, realm.Hostname(), err)
	}
	defer resp.Body.Close()
	shownRealm := accesskey.ShownValue(realm.Host, false)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return "", "", c.refuse(refusal.ImageAccessDenied, "Give the run a credential for %s that may pull %s, or a path rule that covers %s on %s: the token request got 403 from the realm or from the run's proxy",
			shownRealm, c.image, accesskey.ShownValue(realm.EscapedPath(), false), shownRealm)
	case http.StatusUnauthorized:
		return "", "", c.refuse(refusal.ImageAccessDenied, "Give the run a credential for %s that may pull %s: the token realm returned 401 to the check of the image",
			shownRealm, c.image)
	case http.StatusTooManyRequests:
		return "", "", c.refuse(refusal.ImageRateLimited, "Run again once the rate limit of the token realm at %s resets, give the run a credential for %s with a higher limit, or raise gateway.run_limits of the gateway: "+
			"the token request for the image %s got 429 from the realm or from the run's proxy%s", shownRealm, shownRealm, c.image, retryAfter(resp.Header))
	default:
		return "", "", fmt.Errorf("Give the run a credential for %s that may pull %s: the token realm answered %d to the check of the image.", shownRealm, c.image, resp.StatusCode)
	}
	var answer struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, maxTokenAnswer)).Decode(&answer) != nil || answer.Token == "" && answer.AccessToken == "" {
		return "", "", fmt.Errorf("Check the token realm at %s: its answer to the check of the image %s contains no token.", shownRealm, c.image)
	}
	if answer.Token == "" {
		answer.Token = answer.AccessToken
	}
	return answer.Token, realm.Host, nil
}

// failed is the error of a request to host that got no answer: a host the run's proxy
// denied names the host to allow in the policies a run's egress.allow comes from, the
// node's and, for a run from a server, the server's (docs/policy.md); a host the check
// does not reach, [unreachable], is image_registry_unreachable with the request's
// error, unless a dial of the run's proxy hung, [proxyDialHung]; any other failure is
// the request's error with no code.
func (c manifestCheck) failed(ctx context.Context, host string, err error) error {
	var d *deniedHost
	if errors.As(err, &d) {
		said := ""
		if d.said != "" {
			said = " (" + accesskey.ShownValue(d.said, false) + ")"
		}
		return fmt.Errorf("Allow %s in the node's policy, and in the server's policy for a run from a server.\nThe run's proxy denied the check of the image %s at its registry%s.", accesskey.ShownValue(d.host, false), c.image, said)
	}
	if (c.ended == nil || c.ended() == nil) && !proxyDialHung(ctx) && unreachable(err) {
		return c.refuse(refusal.ImageRegistryUnreachable, "Check that the run's proxy reaches %s: the check of the image %s at its registry failed (%s)",
			accesskey.ShownValue(host, false), c.image, accesskey.ShownError(err))
	}
	return fmt.Errorf("Check that %s answers through the run's proxy: the check of the image %s at its registry failed (%s).", accesskey.ShownValue(host, false), c.image, accesskey.ShownError(err))
}

// unreachable reports whether err is a request of the check that did not reach the
// registry or its token realm: a CONNECT the run's proxy returned 502 to
// ([unreachedHost]), a host name that does not resolve, a connection refused or reset,
// on the tunnel, a TLS handshake or certificate that failed, or a timeout. Each is read
// from the error's type, never from its text. A failed connection to the run's proxy
// itself, [proxyConnError], is none of them, and neither is any other error, such as
// the text error the client returns for another status of a CONNECT.
func unreachable(err error) bool {
	var (
		dial      *proxyConnError
		unreached *unreachedHost
		dns       *net.DNSError
		op        *net.OpError
		record    tls.RecordHeaderError
		alert     tls.AlertError
		verify    *tls.CertificateVerificationError
		authority x509.UnknownAuthorityError
		hostname  x509.HostnameError
		invalid   x509.CertificateInvalidError
		timeout   net.Error
	)
	switch {
	case errors.As(err, &dial):
		return false
	case errors.As(err, &unreached), errors.As(err, &dns), errors.As(err, &record), errors.As(err, &alert),
		errors.As(err, &verify), errors.As(err, &authority), errors.As(err, &hostname), errors.As(err, &invalid):
		return true
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return true
	case errors.As(err, &timeout) && timeout.Timeout():
		return true
	case errors.As(err, &op):
		// A [proxyConn] makes every failure on the connection to the proxy, before
		// its tunnel opened, a proxyConnError: an OpError here is on the tunnel.
		return true
	}
	return false
}

// retryAfter is " (Retry-After: <seconds>)" for a Retry-After of whole seconds, empty
// otherwise.
func retryAfter(h http.Header) string {
	s := h.Get("Retry-After")
	if n, err := strconv.Atoi(s); err != nil || n < 0 {
		return ""
	}
	return " (Retry-After: " + s + ")"
}

// scheme is http for a host on loopback, as the engine reaches a registry there without
// TLS, and https for any other host.
func scheme(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "localhost" {
		return "http"
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return "http"
	}
	return "https"
}

// bearerChallenge returns the parameters of the first Bearer challenge among the
// WWW-Authenticate values, and whether there is one.
func bearerChallenge(values []string) (map[string]string, bool) {
	for _, v := range values {
		kind, rest, _ := strings.Cut(strings.TrimSpace(v), " ")
		if !strings.EqualFold(kind, "Bearer") {
			continue
		}
		return challengeParams(rest), true
	}
	return nil, false
}

// challengeParams reads the key=value parameters of a challenge, separated by commas,
// each value quoted with backslash escapes or bare.
func challengeParams(s string) map[string]string {
	params := map[string]string{}
	for {
		s = strings.TrimLeft(s, " \t,")
		key, rest, ok := strings.Cut(s, "=")
		if !ok {
			return params
		}
		key = strings.ToLower(strings.TrimSpace(key))
		rest = strings.TrimLeft(rest, " \t")
		var value strings.Builder
		if strings.HasPrefix(rest, `"`) {
			i := 1
			for ; i < len(rest) && rest[i] != '"'; i++ {
				if rest[i] == '\\' && i+1 < len(rest) {
					i++
				}
				value.WriteByte(rest[i])
			}
			s = rest[min(i+1, len(rest)):]
		} else {
			end := strings.IndexByte(rest, ',')
			if end < 0 {
				end = len(rest)
			}
			value.WriteString(strings.TrimSpace(rest[:end]))
			s = rest[end:]
		}
		params[key] = value.String()
	}
}
