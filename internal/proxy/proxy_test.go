package proxy_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/runner/internal/credential"
	"github.com/qoryai/runner/internal/policy"
	"github.com/qoryai/runner/internal/proxy"
)

// through returns a client that sends everything through the proxy, trusting the test
// server's certificate.
func through(t *testing.T, p *proxy.Proxy, tlsServer *httptest.Server) *http.Client {
	t.Helper()
	u, err := url.Parse(p.URL())
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	if tlsServer != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: tlsServer.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	}
	return &http.Client{Transport: tr}
}

type observer struct {
	mu   sync.Mutex
	seen []proxy.Decision
}

func (o *observer) observe(d proxy.Decision) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seen = append(o.seen, d)
}

func (o *observer) last(t *testing.T) proxy.Decision {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.seen) == 0 {
		t.Fatal("nothing observed")
	}
	return o.seen[len(o.seen)-1]
}

// TestEnforceAllowsListedHostsAndDeniesTheRest pins the proxy in enforce mode against
// a loopback origin: a plain request and a CONNECT tunnel to an allowed host go
// through and are observed with their rule; the same to a host outside the list are
// refused with 403 before anything is dialled, and observed as denied.
func TestEnforceAllowsListedHostsAndDeniesTheRest(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "plain "+r.URL.Path) }))
	defer origin.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secure "+r.URL.Path) }))
	defer secure.Close()
	var o observer
	p, err := proxy.Listen("", policy.Enforce, []string{"127.0.0.1"}, nil, o.observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c := through(t, p, secure)

	resp, err := c.Get(origin.URL + "/a")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "plain /a" {
		t.Errorf("plain through proxy: %q", body)
	}
	if d := o.last(t); d.Method != "HTTP" || !d.Allowed || d.Rule != "127.0.0.1" || d.Host != "127.0.0.1" || d.Outcome != proxy.Connected || d.Mode != policy.Enforce {
		t.Errorf("plain decision %+v", d)
	}

	resp, err = c.Get(secure.URL + "/b")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "secure /b" {
		t.Errorf("tunnel through proxy: %q", body)
	}
	if d := o.last(t); d.Method != "CONNECT" || !d.Allowed || d.Rule != "127.0.0.1" || d.Outcome != proxy.Connected {
		t.Errorf("tunnel decision %+v", d)
	}

	// The same origins by a name the list does not hold.
	deniedPlain := strings.Replace(origin.URL, "127.0.0.1", "localhost", 1)
	resp, err = c.Get(deniedPlain + "/c")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "denied by policy") {
		t.Errorf("denied plain: %d %q", resp.StatusCode, body)
	}
	if d := o.last(t); d.Allowed || d.Rule != "" || d.Host != "localhost" || d.Outcome != proxy.Refused {
		t.Errorf("denied plain decision %+v", d)
	}
	deniedTunnel := strings.Replace(secure.URL, "127.0.0.1", "localhost", 1)
	if _, err := c.Get(deniedTunnel + "/d"); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("denied tunnel: %v", err)
	}
	if d := o.last(t); d.Allowed || d.Method != "CONNECT" || d.Outcome != proxy.Refused {
		t.Errorf("denied tunnel decision %+v", d)
	}
	// An allowed host nothing listens on: dialled, and the dial failed.
	dead := httptest.NewServer(nil)
	deadURL := dead.URL
	dead.Close()
	if resp, err := c.Get(deadURL + "/e"); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("a dial that failed answered %d", resp.StatusCode)
		}
	}
	if d := o.last(t); !d.Allowed || d.Outcome != proxy.DialFailed {
		t.Errorf("dial failed decision %+v", d)
	}
}

// TestObserveAllowsEverythingAndStillRecords pins observe mode: nothing is denied, and
// a host no entry matches is recorded with an empty rule.
func TestObserveAllowsEverythingAndStillRecords(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	var o observer
	p, err := proxy.Listen("", policy.Observe, nil, nil, o.observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	resp, err := through(t, p, nil).Get(strings.Replace(origin.URL, "127.0.0.1", "localhost", 1))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status %d", resp.StatusCode)
	}
	if d := o.last(t); !d.Allowed || d.Rule != "" || d.Host != "localhost" || d.Outcome != proxy.Connected || d.Mode != policy.Observe {
		t.Errorf("decision %+v", d)
	}
}

// TestSetPolicyDecidesNewConnectionsAndClosesDeniedTunnels pins the reload: a policy set
// while the proxy runs decides the next connection, an open tunnel to a host it denies
// is closed and returned as a refused denial, and one to a host it still allows stays.
func TestSetPolicyDecidesNewConnectionsAndClosesDeniedTunnels(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	var o observer
	p, err := proxy.Listen("", policy.Observe, nil, nil, o.observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	open := func(host string) net.Conn {
		c, err := net.Dial("tcp", p.Addr())
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
		fmt.Fprintf(c, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port, host, port)
		line := make([]byte, len("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if _, err := io.ReadFull(c, line); err != nil || !strings.HasPrefix(string(line), "HTTP/1.1 200") {
			t.Fatalf("CONNECT %s: %q %v", host, line, err)
		}
		return c
	}
	stays, goes := open("127.0.0.1"), open("localhost")
	defer stays.Close()
	defer goes.Close()
	refused := p.SetPolicy(policy.Enforce, []string{"127.0.0.1"}, nil, nil, nil)
	if p.Terminates() || len(refused) != 1 || refused[0].Host != "localhost" || refused[0].Allowed || refused[0].Outcome != proxy.Refused || refused[0].Mode != policy.Enforce {
		t.Fatalf("SetPolicy returned %+v", refused)
	}
	if _, err := goes.Read(make([]byte, 1)); err == nil {
		t.Error("the tunnel to the denied host is still open")
	}
	fmt.Fprint(stays, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if b := make([]byte, 12); func() error { _, err := io.ReadFull(stays, b); return err }() != nil || string(b) != "HTTP/1.1 200" {
		t.Errorf("the tunnel to the allowed host answered %q", b)
	}
	resp, err := through(t, p, nil).Get(strings.Replace(origin.URL, "127.0.0.1", "localhost", 1))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if d := o.last(t); resp.StatusCode != http.StatusForbidden || d.Allowed || d.Mode != policy.Enforce {
		t.Errorf("after the reload: %d, decision %+v", resp.StatusCode, d)
	}
}

// TestEnvNamesTheProxyInBothCases pins the six variables and the loopback exemption.
func TestEnvNamesTheProxyInBothCases(t *testing.T) {
	p, err := proxy.Listen("", policy.Observe, nil, nil, func(proxy.Decision) {})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	env := strings.Join(p.Env(), "\n")
	for _, want := range []string{"HTTP_PROXY=" + p.URL(), "http_proxy=" + p.URL(), "HTTPS_PROXY=" + p.URL(), "https_proxy=" + p.URL(), "NO_PROXY=localhost,127.0.0.1,::1", "no_proxy=localhost,127.0.0.1,::1"} {
		if !strings.Contains(env, want) {
			t.Errorf("missing %s", want)
		}
	}
}

// TestNonProxyRequestIsRefused pins that a request without an absolute target, which
// is what a program sends to an origin and not to a proxy, gets a 400 and no decision.
func TestNonProxyRequestIsRefused(t *testing.T) {
	var o observer
	p, err := proxy.Listen("", policy.Observe, nil, nil, o.observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	resp, err := http.Get(p.URL() + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || len(o.seen) != 0 {
		t.Errorf("status %d, %d decisions", resp.StatusCode, len(o.seen))
	}
}

// TestGuardRefusesThisMachineAndLinkLocal pins the guard of a proxy that serves an
// enclosure: in observe mode, which denies nothing else, loopback by address and by
// name, the metadata address and a name that resolves to loopback are all refused, the
// literal ones with a denied decision naming the wall's rule, and nothing reaches the
// origin.
func TestGuardRefusesThisMachineAndLinkLocal(t *testing.T) {
	hits := 0
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer origin.Close()
	var o observer
	p, err := proxy.Listen("", policy.Observe, nil, nil, o.observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.Guard(nil)
	port := origin.URL[strings.LastIndex(origin.URL, ":"):]
	for _, c := range []struct {
		url    string
		status int
		rule   string
	}{
		{origin.URL, 403, proxy.GuardRule},
		{"http://localhost" + port, 403, proxy.GuardRule},
		{"http://169.254.169.254/latest/meta-data/", 403, proxy.GuardRule},
		{"http://[::1]" + port, 403, proxy.GuardRule},
		// A name that resolves to loopback passes the decision and is refused when
		// dialled, recorded then as the wall's denial.
		{"http://localtest.me" + port, 403, proxy.GuardRule},
	} {
		resp, err := through(t, p, nil).Get(c.url)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		d := o.last(t)
		if c.url == "http://localtest.me"+port && resp.StatusCode != 403 {
			t.Skipf("localtest.me did not resolve to loopback here: status %d", resp.StatusCode)
		}
		if resp.StatusCode != c.status || d.Rule != c.rule || (c.status == 403 && (d.Allowed || d.Outcome != proxy.Refused)) {
			t.Errorf("%s: status %d, decision %+v", c.url, resp.StatusCode, d)
		}
	}
	if hits != 0 {
		t.Errorf("%d requests reached this machine's own listener through a guarded proxy", hits)
	}
}

// TestGuardOpensThisMachineToAHostThePolicyNames pins the other half: an allow entry
// that names the host itself reaches this machine through a guarded proxy, in observe
// mode as well, recorded with that entry as its rule; a *. suffix over the host does
// not, and no entry opens the link-local range.
func TestGuardOpensThisMachineToAHostThePolicyNames(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "the local server") }))
	defer origin.Close()
	port := origin.URL[strings.LastIndex(origin.URL, ":"):]
	for _, mode := range []policy.Mode{policy.Observe, policy.Enforce} {
		var o observer
		// Only a host the policy names itself opens this machine, not one under a
		// suffix it lists.
		p, err := proxy.Listen("", mode, []string{"127.0.0.1", "app.localtest.me", "169.254.169.254"}, nil, o.observe)
		if err != nil {
			t.Fatal(err)
		}
		p.Guard([]string{"127.0.0.1", "*.localtest.me", "169.254.169.254"})
		resp, err := through(t, p, nil).Get(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if d := o.last(t); string(body) != "the local server" || !d.Allowed || d.Rule != "127.0.0.1" {
			t.Errorf("%s: a named host: %q, decision %+v", mode, body, d)
		}
		for _, u := range []string{"http://app.localtest.me" + port, "http://169.254.169.254/"} {
			resp, err := through(t, p, nil).Get(u)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 || string(body) == "the local server" {
				t.Errorf("%s: %s reached through a guarded proxy: %d %q", mode, u, resp.StatusCode, body)
			}
		}
		p.Close()
	}
}

// TestRequireServesOnlyConnectionsThatOpenWithTheToken pins the gate: with a token
// required, a connection that opens with the preamble is served as ever, and one that
// does not is closed unanswered and told of.
func TestRequireServesOnlyConnectionsThatOpenWithTheToken(t *testing.T) {
	p, err := proxy.Listen("", policy.Observe, nil, nil, func(proxy.Decision) {})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	refused := make(chan struct{}, 4)
	p.Require("the-runs-token", func() { refused <- struct{}{} })
	ask := func(open string) string {
		c, err := net.Dial("tcp", p.Addr())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(c, open+"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		b, _ := io.ReadAll(c)
		return string(b)
	}
	if got := ask(proxy.Preamble + " the-runs-token\n"); !strings.HasPrefix(got, "HTTP/1.1 400") {
		t.Errorf("with the token the proxy answered %q, want its refusal of a request that names no target", got)
	}
	for _, open := range []string{"", proxy.Preamble + " another-runs-token\n"} {
		if got := ask(open); got != "" {
			t.Errorf("opened with %q the proxy answered %q", open, got)
		}
		select {
		case <-refused:
		case <-time.After(5 * time.Second):
			t.Errorf("opened with %q: nobody was told", open)
		}
	}
}

// TestTerminateSetsTheCredentialAndHoldsThePaths pins termination: to a host a
// credential is for, the proxy answers with the run's authority, sets the credential
// on a path it covers and nowhere else, denies the rest under enforce, records every
// request, and leaves every other host a tunnel the proxy passes through as bytes.
func TestTerminateSetsTheCredentialAndHoldsThePaths(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{}
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		got[r.URL.Path] = r.Header.Get("Authorization") + "|" + r.Host
		got["trailer"+r.URL.Path] = r.Trailer.Get("X-Checksum")
		mu.Unlock()
		if r.URL.Path == "/acme/shop/expired" {
			w.WriteHeader(http.StatusUnauthorized)
		}
		io.WriteString(w, "from the origin")
	}))
	defer origin.Close()
	host, port, _ := net.SplitHostPort(origin.Listener.Addr().String())

	var decisions []proxy.Decision
	p, err := proxy.Listen("", policy.Enforce, []string{host}, nil, func(d proxy.Decision) { mu.Lock(); decisions = append(decisions, d); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ca, err := proxy.NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	p.TrustUpstream(roots)
	rejected := 0
	p.Terminate(ca, []proxy.Credential{{
		Name: "product", Hosts: []string{host}, Scheme: "basic", Username: "x-access-token", Paths: []string{"/acme/shop/*", "/graphql"},
		Token: func() string { return "the-token" }, Rejected: func() { rejected++ },
	}}, nil, nil)

	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	proxyURL, _ := url.Parse(p.URL())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}}
	get := func(path string, header ...string) (int, string) {
		req, _ := http.NewRequest("GET", "https://"+net.JoinHostPort(host, port)+path, nil)
		req.Header.Set("Authorization", "Bearer the-sessions-placeholder")
		if len(header) == 2 {
			if header[0] == "Host" {
				req.Host = header[1]
			} else {
				req.Header.Set(header[0], header[1])
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:the-token"))
	if code, body := get("/acme/shop/pulls?state=open"); code != 200 || body != "from the origin" {
		t.Errorf("a covered path: %d %q", code, body)
	}
	if code, body := get("/other-org/repo"); code != 403 || !strings.Contains(body, "no path rule") {
		t.Errorf("another organization's path: %d %q", code, body)
	}
	for _, two := range []string{"/acme/shop/..%2f..%2fother-org/repo", "/acme/shop//x", "/acme/shop/%2e%2e/x"} {
		if code, _ := get(two); code != 403 {
			t.Errorf("%s: %d, want the wall's refusal", two, code)
		}
	}
	if code, _ := get("/acme/shop/fronted", "Host", "another.example"); code != 200 {
		t.Errorf("a request naming another Host: %d", code)
	}
	get("/acme/shop/expired")
	// A body of unknown length goes chunked, and its trailer reaches the host.
	pr, pw := io.Pipe()
	put, _ := http.NewRequest("PUT", "https://"+net.JoinHostPort(host, port)+"/acme/shop/upload", pr)
	put.Trailer = http.Header{"X-Checksum": nil}
	go func() {
		io.WriteString(pw, "a body")
		put.Trailer.Set("X-Checksum", "the-sum")
		pw.Close()
	}()
	if resp, err := client.Do(put); err != nil {
		t.Errorf("an upload with a trailer: %v", err)
	} else {
		resp.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	if got["trailer/acme/shop/upload"] != "the-sum" {
		t.Errorf("the host got the trailer %q", got["trailer/acme/shop/upload"])
	}
	if got["/acme/shop/pulls"] != want+"|"+net.JoinHostPort(host, port) {
		t.Errorf("the origin saw %q on a covered path", got["/acme/shop/pulls"])
	}
	if _, reached := got["/other-org/repo"]; reached {
		t.Error("a denied path reached the origin")
	}
	if !strings.HasSuffix(got["/acme/shop/fronted"], "|"+net.JoinHostPort(host, port)) {
		t.Errorf("the origin was asked for the host %q", got["/acme/shop/fronted"])
	}
	if rejected != 1 {
		t.Errorf("the credential heard of %d rejections, want 1", rejected)
	}
	var first proxy.Decision
	for _, d := range decisions {
		if d.Method == "CONNECT" {
			t.Errorf("a terminated connection was recorded as a tunnel: %+v", d)
		}
		if d.Path == "/acme/shop/pulls" {
			first = d
		}
		if strings.Contains(d.Path, "?") {
			t.Errorf("a query in the record: %+v", d)
		}
	}
	if first.Method != "HTTPS" || first.RequestMethod != "GET" || first.Credential != "product" || first.PathRule != "/acme/shop/*" || !first.Allowed || first.Outcome != proxy.Connected || first.Status != 200 || first.RequestID == "" || first.Tool != "" {
		t.Errorf("the covered request was recorded as %+v", first)
	}
	for _, d := range decisions {
		if d.Path == "/other-org/repo" && (d.Allowed || d.Outcome != proxy.Refused) {
			t.Errorf("the denied path was recorded as %+v", d)
		}
	}
}

// TestSetPolicySwapsTheCredentialsWithThePolicy pins a reload's credentials: the ones
// set with the new policy are on the next request, a terminated connection that
// carried the old one is closed and not kept alive under it, and a host that lost its
// credential gets none.
func TestSetPolicySwapsTheCredentialsWithThePolicy(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	defer origin.Close()
	host, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	p, err := proxy.Listen("", policy.Enforce, []string{host}, nil, func(proxy.Decision) {})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ca, err := proxy.NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	p.TrustUpstream(roots)
	cred := func(name, token string) []proxy.Credential {
		return []proxy.Credential{{Name: name, Hosts: []string{host}, Scheme: "bearer", Token: func() string { return token }}}
	}
	p.Terminate(ca, cred("first", "token-one"), nil, nil)
	if !p.Terminates() {
		t.Fatal("Terminates is false after Terminate")
	}
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	proxyURL, _ := url.Parse(p.URL())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}}
	get := func() {
		resp, err := client.Get("https://" + net.JoinHostPort(host, port) + "/x")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	get()
	p.SetPolicy(policy.Enforce, []string{host}, nil, nil, cred("second", "token-two"))
	get()
	// A path rule keeps the host terminated once no credential is for it.
	p.SetPolicy(policy.Enforce, []string{host}, nil, map[string][]string{host: {"/*"}}, nil)
	get()
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(seen) != "[Bearer token-one Bearer token-two ]" {
		t.Errorf("the origin saw %q", seen)
	}
}

// TestTerminateSetsARuntimesKeyAndNoOtherHostGetsIt pins a model provider's two
// credentials, the OAuth one set as a bearer and the API key set in a header of its
// own: the host the credential is for gets the key in the credential's header, once,
// in place of the stand-in the session sent; a stand-in in the other header goes as the
// session sent it; an allowed host with no credential, plain or through a tunnel, gets
// the stand-ins and never the key; and the record contains no key.
func TestTerminateSetsARuntimesKeyAndNoOtherHostGetsIt(t *testing.T) {
	for _, c := range []struct {
		name, scheme, header, key, set string
	}{
		{"oauth as a bearer", "bearer", "", "sk-ant-oat01-test-REAL-not-a-secret-0002", "Authorization"},
		{"api key in x-api-key", "header", "X-Api-Key", "sk-ant-test-REAL-not-a-secret-0001", "X-Api-Key"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var mu sync.Mutex
			got := map[string]http.Header{}
			record := func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				mu.Lock()
				got[r.Host+r.URL.Path] = r.Header.Clone()
				mu.Unlock()
				io.WriteString(w, `{"type":"message"}`)
			}
			model := httptest.NewTLSServer(http.HandlerFunc(record))
			defer model.Close()
			// The other host is localhost, which no credential is for: plain, and over
			// TLS through a tunnel the proxy passes through as bytes.
			plain := httptest.NewServer(http.HandlerFunc(record))
			defer plain.Close()
			secure := httptest.NewTLSServer(http.HandlerFunc(record))
			defer secure.Close()
			host, port, _ := net.SplitHostPort(model.Listener.Addr().String())
			modelAt := net.JoinHostPort(host, port)

			var decisions []proxy.Decision
			p, err := proxy.Listen("", policy.Enforce, []string{host, "localhost"}, nil, func(d proxy.Decision) { mu.Lock(); decisions = append(decisions, d); mu.Unlock() })
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			ca, err := proxy.NewCA("test")
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(model.Certificate())
			p.TrustUpstream(roots)
			p.Terminate(ca, []proxy.Credential{{
				Name: "model", Hosts: []string{host}, Scheme: c.scheme, Header: c.header, Paths: []string{"/v1/*"},
				Token: func() string { return c.key },
			}}, nil, nil)

			trusted := x509.NewCertPool()
			trusted.AppendCertsFromPEM(ca.PEM())
			proxyURL, _ := url.Parse(p.URL())
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}}
			// The tunnelled origin's certificate is for example.com and not localhost;
			// the session verifies it, through a tunnel the proxy passes through as bytes.
			tunnel := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"}}}
			bearer, apiKey := "Bearer "+credential.Placeholder, credential.Placeholder
			var answers []string
			send := func(client *http.Client, target string, both bool) {
				req, _ := http.NewRequest("POST", target, strings.NewReader(`{"model":"m"}`))
				// In lower case, as Claude Code's HTTP client writes them.
				if c.scheme == "bearer" || both {
					req.Header["authorization"] = []string{bearer}
				}
				if c.scheme == "header" || both {
					req.Header["x-api-key"] = []string{apiKey}
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("%s: %v", target, err)
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				answers = append(answers, fmt.Sprint(resp.StatusCode, resp.Header, string(b)))
			}
			own := "https://" + modelAt + "/v1/messages"
			both := "https://" + modelAt + "/v1/messages/both"
			otherPlain := strings.Replace(plain.URL, "127.0.0.1", "localhost", 1) + "/v1/messages"
			otherSecure := strings.Replace(secure.URL, "127.0.0.1", "localhost", 1) + "/v1/messages"
			send(client, own, false)
			send(client, both, true)
			send(client, otherPlain, true)
			send(tunnel, otherSecure, true)
			send(client, "https://"+modelAt+"/v2/outside-the-paths", true)

			mu.Lock()
			defer mu.Unlock()
			at := func(raw string) http.Header {
				u, _ := url.Parse(raw)
				return got[u.Host+u.Path]
			}
			want := c.key
			if c.scheme == "bearer" {
				want = "Bearer " + c.key
			}
			// The stand-in of this credential alone, as Claude Code sends it.
			h := at(own)
			if v := h.Values(c.set); len(v) != 1 || v[0] != want {
				t.Errorf("the host the credential is for got %s %q, want the key once", c.set, v)
			}
			for name, vs := range h {
				for _, v := range vs {
					if strings.Contains(v, credential.Placeholder) {
						t.Errorf("the stand-in reached the host the credential is for in %s: %q", name, v)
					}
				}
			}
			// Both stand-ins: the credential's header is set, the other goes as the
			// session sent it.
			h = at(both)
			if v := h.Values(c.set); len(v) != 1 || v[0] != want {
				t.Errorf("with both stand-ins the host got %s %q, want the key once", c.set, v)
			}
			other, standIn := "X-Api-Key", apiKey
			if c.scheme == "header" {
				other, standIn = "Authorization", bearer
			}
			if v := h.Values(other); len(v) != 1 || v[0] != standIn {
				t.Errorf("with both stand-ins the host got %s %q, want the session's stand-in", other, v)
			}
			// The other host, plain and through a tunnel: the stand-ins, untouched.
			for _, target := range []string{otherPlain, otherSecure} {
				if h := at(target); h == nil {
					t.Errorf("%s was not reached", target)
				} else if h.Get("Authorization") != bearer || h.Get("X-Api-Key") != apiKey {
					t.Errorf("%s got Authorization %q and X-Api-Key %q, want the stand-ins", target, h.Get("Authorization"), h.Get("X-Api-Key"))
				}
			}
			for where, h := range got {
				if strings.HasPrefix(where, modelAt+"/") {
					continue
				}
				for name, vs := range h {
					for _, v := range vs {
						if strings.Contains(v, c.key) {
							t.Errorf("%s, which no credential is for, got the key in %s", where, name)
						}
					}
				}
			}
			if _, reached := got[modelAt+"/v2/outside-the-paths"]; reached {
				t.Error("a path outside the credential's reached the host")
			}
			for _, a := range answers {
				if strings.Contains(a, c.key) {
					t.Errorf("an answer to the session contains the key: %s", a)
				}
			}
			if s := fmt.Sprintf("%+v", decisions); strings.Contains(s, c.key) || strings.Contains(s, credential.Placeholder) {
				t.Errorf("the record contains a credential: %s", s)
			}
			set := 0
			for _, d := range decisions {
				if d.Credential == "model" {
					set++
				}
			}
			if set != 2 {
				t.Errorf("the record lists the credential on %d requests, want 2: %+v", set, decisions)
			}
		})
	}
}

// TestDenyIsDecidedFirstInEitherMode pins the deny list: a host it covers is refused
// under observe as under enforce, before the dial, with the first matching entry as
// the rule; it beats an allow entry of any shape, a host both lists name included; a
// host it does not cover is decided by the mode and the allow list as before; a reload
// carries it, closing an open tunnel to a host the new list names; and the guard of a
// walled proxy decides before it.
func TestDenyIsDecidedFirstInEitherMode(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	var o observer
	p, err := proxy.Listen("", policy.Observe, nil, nil, o.observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	port := origin.URL[strings.LastIndex(origin.URL, ":"):]
	for _, c := range []struct {
		name    string
		mode    policy.Mode
		allow   []string
		deny    []string
		url     string
		status  int
		allowed bool
		rule    string
	}{
		{"observe denies what deny names", policy.Observe, nil, []string{"localhost"}, "http://localhost" + port, 403, false, "localhost"},
		{"observe lets the rest through", policy.Observe, nil, []string{"localhost"}, origin.URL, 200, true, ""},
		{"enforce denies what deny names before allow", policy.Enforce, []string{"localhost"}, []string{"localhost"}, "http://localhost" + port, 403, false, "localhost"},
		{"enforce reaches an allowed host deny does not name", policy.Enforce, []string{"127.0.0.1"}, []string{"tracker.example"}, origin.URL, 200, true, "127.0.0.1"},
		{"deny beats a *. allow above it", policy.Observe, []string{"*.example"}, []string{"tracker.example"}, "http://tracker.example/", 403, false, "tracker.example"},
		{"an allow of the same shape does not save it", policy.Enforce, []string{"tracker.example"}, []string{"*.example"}, "http://tracker.example/", 403, false, "*.example"},
		{"the first deny entry is the rule", policy.Observe, nil, []string{"*.example", "tracker.example"}, "http://tracker.example/", 403, false, "*.example"},
		{"deny is compared lower-case", policy.Observe, nil, []string{"tracker.example"}, "http://Tracker.Example/", 403, false, "tracker.example"},
	} {
		p.SetPolicy(c.mode, c.allow, c.deny, nil, nil)
		resp, err := through(t, p, nil).Get(c.url)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		d := o.last(t)
		if resp.StatusCode != c.status || d.Allowed != c.allowed || d.Rule != c.rule || d.Mode != c.mode || (!c.allowed && d.Outcome != proxy.Refused) {
			t.Errorf("%s: status %d, decision %+v", c.name, resp.StatusCode, d)
		}
		if c.status == 403 {
			if body, _ := io.ReadAll(resp.Body); !strings.Contains(string(body), "denied by policy (mode "+string(c.mode)+")") && len(body) > 0 {
				t.Errorf("%s: body %q", c.name, body)
			}
		}
	}
	// A reload carries deny: a tunnel open under observe to a host the new deny list
	// names is closed and returned refused with the entry as its rule.
	p.SetPolicy(policy.Observe, nil, nil, nil, nil)
	c, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "CONNECT localhost%s HTTP/1.1\r\nHost: localhost%s\r\n\r\n", port, port)
	line := make([]byte, len("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if _, err := io.ReadFull(c, line); err != nil || !strings.HasPrefix(string(line), "HTTP/1.1 200") {
		t.Fatalf("CONNECT localhost: %q %v", line, err)
	}
	refused := p.SetPolicy(policy.Observe, nil, []string{"localhost"}, nil, nil)
	if len(refused) != 1 || refused[0].Host != "localhost" || refused[0].Allowed || refused[0].Rule != "localhost" || refused[0].Outcome != proxy.Refused || refused[0].Mode != policy.Observe {
		t.Fatalf("SetPolicy returned %+v", refused)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("the tunnel to the denied host is still open")
	}
	// The guard decides before deny: this machine by address is the wall's refusal,
	// whatever deny says of it.
	p.Guard(nil)
	p.SetPolicy(policy.Observe, nil, []string{"127.0.0.1"}, nil, nil)
	resp, err := through(t, p, nil).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if d := o.last(t); resp.StatusCode != 403 || d.Rule != proxy.GuardRule || d.Allowed {
		t.Errorf("guarded: status %d, decision %+v", resp.StatusCode, d)
	}
}

// TestNodePathsNarrowThePolicysPaths pins the node's path rules beside the policy's: a
// request to a host both list must match an entry of each, and its rule is the
// narrowest that matched; a miss of either is denied under enforce with no rule and
// passed under observe; and the hosts of both are terminated, a host only the node
// lists included.
func TestNodePathsNarrowThePolicysPaths(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	host, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	for _, mode := range []policy.Mode{policy.Enforce, policy.Observe} {
		t.Run(string(mode), func(t *testing.T) {
			var o observer
			p, err := proxy.Listen("", mode, []string{host, "localhost"}, nil, o.observe)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			ca, err := proxy.NewCA("test")
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(origin.Certificate())
			p.TrustUpstream(roots)
			p.NodePaths(map[string][]string{host: {"/repos/acme/*", "/user"}, "localhost": {"/only-the-node/*"}})
			p.Terminate(ca, nil, map[string][]string{host: {"/repos/*", "/user"}}, nil)
			if got := strings.Join(p.Terminated(), " "); !strings.Contains(got, host) || !strings.Contains(got, "localhost") {
				t.Errorf("terminated %q", got)
			}
			trusted := x509.NewCertPool()
			trusted.AppendCertsFromPEM(ca.PEM())
			proxyURL, _ := url.Parse(p.URL())
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}}
			for _, tc := range []struct {
				path, rule string
				both       bool
			}{
				{"/repos/acme/shop", "/repos/acme/*", true},
				{"/user", "/user", true},
				{"/repos/other/lib", "", false},
				{"/elsewhere", "", false},
			} {
				resp, err := client.Get("https://" + net.JoinHostPort(host, port) + tc.path)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				d := o.last(t)
				wantCode := 200
				if !tc.both && mode == policy.Enforce {
					wantCode = 403
				}
				if resp.StatusCode != wantCode || d.PathRule != tc.rule || d.Allowed != (wantCode == 200) {
					t.Errorf("%s: %d, recorded %+v; want %d with the rule %q", tc.path, resp.StatusCode, d, wantCode, tc.rule)
				}
			}
		})
	}
}
