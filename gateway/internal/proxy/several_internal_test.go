package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// TestSeveralCredentialsOnOneHostAreSetByPath pins decisions 886 (a) and 887 (a). Two
// credentials on github.com, each with paths: the proxy sets the one whose paths match
// the request, and a 401 renews that one alone. A path no credential's paths match gets
// no credential: under enforce it passes only when the policy's paths for the host
// match it, under observe it passes. Every answer from the host has both values
// replaced, on a path that gets no credential too.
func TestSeveralCredentialsOnOneHostAreSetByPath(t *testing.T) {
	const productToken, harnessToken = "token-product-0001", "token-harness-0001"
	up, err := NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	got := map[string]string{}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if user, pass, ok := r.BasicAuth(); ok {
			auth = "basic " + user + ":" + pass
		}
		mu.Lock()
		got[r.URL.Path] = auth
		mu.Unlock()
		// The host sends both values back, on every path.
		w.Header().Set("X-Echo", productToken+" "+harnessToken)
		if strings.HasSuffix(r.URL.Path, "/fail") {
			w.WriteHeader(http.StatusUnauthorized)
		}
		io.WriteString(w, "product "+productToken+", harness "+harnessToken)
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return up.leaf(hello.ServerName) }}
	origin.StartTLS()
	defer origin.Close()

	type request struct {
		path, credential, auth string
		status                 int
	}
	product := request{"/example-org/product.git/info/refs", "product", "Bearer " + productToken, http.StatusOK}
	harness := request{"/operator-org/harness.git/info/refs", "harness", "basic x-access-token:" + harnessToken, http.StatusOK}
	rejected := request{"/operator-org/harness.git/fail", "harness", "basic x-access-token:" + harnessToken, http.StatusUnauthorized}
	public := request{"/public-org/tool.git/info/refs", "", "", http.StatusOK}
	unlisted := request{"/other-org/x.git/info/refs", "", "", http.StatusForbidden}
	cases := []struct {
		what     string
		mode     policy.Mode
		paths    map[string][]string
		requests []request
	}{
		{"enforce with the policy's paths", policy.Enforce,
			map[string][]string{"github.com": {"/example-org/*", "/operator-org/*", "/public-org/tool.git/*"}},
			[]request{product, harness, rejected, public, unlisted}},
		{"enforce without the policy's paths", policy.Enforce, nil,
			[]request{product, harness, {public.path, "", "", http.StatusForbidden}, unlisted}},
		{"observe without the policy's paths", policy.Observe, nil,
			[]request{product, harness, {public.path, "", "", http.StatusOK}, {unlisted.path, "", "", http.StatusOK}}},
	}
	for _, c := range cases {
		seen := &decisions{}
		p, err := Listen("", c.mode, []string{"github.com"}, nil, seen.observe)
		if err != nil {
			t.Fatal(err)
		}
		p.dial = (&dials{secure: origin.Listener.Addr().String()}).dial
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(up.PEM())
		p.TrustUpstream(roots)
		renewed := map[string]int{}
		renew := func(name string) func() {
			return func() { mu.Lock(); renewed[name]++; mu.Unlock() }
		}
		creds := []Credential{
			{Name: "product", Hosts: []string{"github.com"}, Scheme: "bearer", Paths: []string{"/example-org/product.git/*"},
				Token: func() string { return productToken }, Rejected: renew("product")},
			{Name: "harness", Hosts: []string{"github.com"}, Scheme: "basic", Username: "x-access-token", Paths: []string{"/operator-org/harness.git/*"},
				Token: func() string { return harnessToken }, Rejected: renew("harness")},
		}
		ca, err := NewCA("test")
		if err != nil {
			t.Fatal(err)
		}
		p.Terminate(ca, creds, c.paths, nil)
		trusted := x509.NewCertPool()
		trusted.AppendCertsFromPEM(ca.PEM())
		proxyURL, _ := url.Parse(p.URL())
		tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}
		client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
		for _, r := range c.requests {
			mu.Lock()
			clear(got)
			mu.Unlock()
			resp, err := client.Get("https://github.com" + r.path)
			if err != nil {
				t.Fatalf("%s, %s: %v", c.what, r.path, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != r.status {
				t.Errorf("%s, %s: %d, want %d: %s", c.what, r.path, resp.StatusCode, r.status, body)
				continue
			}
			mu.Lock()
			auth, reached := got[r.path]
			mu.Unlock()
			if r.status == http.StatusForbidden {
				if reached {
					t.Errorf("%s, %s: the denied request reached the host", c.what, r.path)
				}
				continue
			}
			if auth != r.auth {
				t.Errorf("%s, %s: the host got Authorization %q, want %q", c.what, r.path, auth, r.auth)
			}
			if d := seen.at(-1); d.Credential != r.credential {
				t.Errorf("%s, %s: the record has the credential %q, want %q", c.what, r.path, d.Credential, r.credential)
			}
			answer := string(body) + " " + resp.Header.Get("X-Echo")
			if strings.Contains(answer, productToken) || strings.Contains(answer, harnessToken) || strings.Count(answer, link.Placeholder) != 4 {
				t.Errorf("%s, %s: the answer is %q, want each value replaced with the placeholder", c.what, r.path, answer)
			}
		}
		tr.CloseIdleConnections()
		p.Close()
		mu.Lock()
		want := map[string]int{}
		if c.mode == policy.Enforce && c.paths != nil {
			want["harness"] = 1
		}
		if len(renewed) != len(want) || renewed["harness"] != want["harness"] {
			t.Errorf("%s: renewals %v, want %v", c.what, renewed, want)
		}
		mu.Unlock()
	}
}

// TestAPathNoCredentialMatchesHasThePolicysRule pins the decision of a request on a
// host with credentials whose paths miss it: no credential, the policy's narrowest
// matching entry as its rule, and under enforce a denial when no side lists the host.
func TestAPathNoCredentialMatchesHasThePolicysRule(t *testing.T) {
	creds := []Credential{
		{Name: "product", Hosts: []string{"github.com"}, Paths: []string{"/example-org/product.git/*"}},
		{Name: "harness", Hosts: []string{"github.com"}, Paths: []string{"/operator-org/harness.git/*"}},
	}
	public := map[string][]string{"github.com": {"/public-org/*"}}
	for _, c := range []struct {
		paths      map[string][]string
		node       map[string][]string
		path, rule string
		allowed    bool
		credential string
	}{
		{public, nil, "/public-org/tool.git/info/refs", "/public-org/*", true, ""},
		{public, nil, "/other-org/x", "", false, ""},
		{map[string][]string{"github.com": {"/*"}}, nil, "/operator-org/harness.git/info/refs", "/*", true, "harness"},
		{nil, nil, "/example-org/product.git/info/refs", "/example-org/product.git/*", true, "product"},
		{nil, nil, "/public-org/tool.git/info/refs", "", false, ""},
		// Only the run policy's rules let a path pass with no credential: the node's
		// alone do not, and beside the run policy's they must match too.
		{nil, public, "/public-org/tool.git/info/refs", "", false, ""},
		{public, public, "/public-org/tool.git/info/refs", "/public-org/*", true, ""},
		{public, map[string][]string{"github.com": {"/example-org/*"}}, "/public-org/tool.git/info/refs", "", false, ""},
	} {
		p, err := New(policy.Enforce, []string{"github.com"}, nil, func(Decision) {})
		if err != nil {
			t.Fatal(err)
		}
		if c.node != nil {
			p.NodePaths(c.node)
		}
		p.Terminate(nil, creds, c.paths, nil)
		_, rule, allowed, cred := p.term.Load().path("github.com", c.path, policy.Enforce)
		name := ""
		if cred != nil {
			name = cred.Name
		}
		if rule != c.rule || allowed != c.allowed || name != c.credential {
			t.Errorf("%v, node %v, %s: %v with the rule %q and the credential %q, want %v with %q and %q", c.paths, c.node, c.path, allowed, rule, name, c.allowed, c.rule, c.credential)
		}
	}
}
