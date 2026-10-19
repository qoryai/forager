package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// TestAPatternSetsNoKeyOnALocalName pins the private-host rule in the proxy: a
// credential whose hosts are "*.local" sets no key on a request to x.local, which goes
// through a tunnel with the session's stand-in untouched, and a credential whose hosts
// list x.local sets the key on it.
func TestAPatternSetsNoKeyOnALocalName(t *testing.T) {
	const key = "sk-test-REAL-not-a-secret-0003"
	for _, c := range []struct {
		name  string
		hosts []string
		want  string
		cred  string
	}{
		{"a *.local pattern", []string{"*.local"}, "Bearer " + link.Placeholder, ""},
		{"an exact x.local entry", []string{"x.local"}, "Bearer " + key, "model"},
	} {
		t.Run(c.name, func(t *testing.T) {
			up, err := NewCA("upstream")
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var got []string
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				got = append(got, r.Header.Get("Authorization"))
				mu.Unlock()
				io.WriteString(w, "origin")
			}))
			origin.Config.ErrorLog = log.New(io.Discard, "", 0)
			origin.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return up.leaf(hello.ServerName) }}
			origin.StartTLS()
			defer origin.Close()

			seen := &decisions{}
			p, err := Listen("", policy.Observe, nil, nil, seen.observe)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			rec := &dials{plain: origin.Listener.Addr().String(), secure: origin.Listener.Addr().String()}
			p.dial = rec.dial
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(up.PEM())
			p.TrustUpstream(roots)
			ca, err := NewCA("test")
			if err != nil {
				t.Fatal(err)
			}
			p.Terminate(ca, []Credential{{Name: "model", Hosts: c.hosts, Scheme: "bearer", Token: func() string { return key }}}, nil, nil)

			// The session trusts the run's authority and, for a tunnel, the origin's.
			trusted := x509.NewCertPool()
			trusted.AppendCertsFromPEM(ca.PEM())
			trusted.AppendCertsFromPEM(up.PEM())
			proxyURL, _ := url.Parse(p.URL())
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}}
			req, _ := http.NewRequest("GET", "https://x.local/v1/models", nil)
			req.Header.Set("Authorization", "Bearer "+link.Placeholder)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			mu.Lock()
			defer mu.Unlock()
			if len(got) != 1 || got[0] != c.want {
				t.Errorf("x.local got Authorization %q, want %q once", got, c.want)
			}
			seen.mu.Lock()
			defer seen.mu.Unlock()
			if len(seen.seen) == 0 {
				t.Error("the proxy recorded no decision")
			}
			for _, d := range seen.seen {
				if d.Credential != c.cred {
					t.Errorf("the record lists credential %q on %+v, want %q", d.Credential, d, c.cred)
				}
			}
		})
	}
}

// TestTerminatedLeavesOutACredentialPatternForNoHost pins the terminated hosts under the
// private-host rule: a credential's "*." pattern under which every name is private, such
// as "*.local", is for no host and is not listed; an exact private name and a pattern
// that is for some host are; and a path rule's or a tool's entry is listed as before.
func TestTerminatedLeavesOutACredentialPatternForNoHost(t *testing.T) {
	for _, c := range []struct {
		name  string
		creds []string
		paths map[string][]string
		tools []string
		want  []string
	}{
		{
			name:  "credentials",
			creds: []string{"*.local", "x.local", "*.x.local", "*.LOCAL", "*.internal", "*.home.arpa", "*.arpa", "*.example.com", "*.lan", "litellm"},
			want:  []string{"x.local", "*.arpa", "*.example.com", "*.lan", "litellm"},
		},
		{
			name:  "a path rule and a tool",
			creds: []string{"*.local"},
			paths: map[string][]string{"*.local": {"/*"}},
			tools: []string{"*.internal"},
			want:  []string{"*.internal", "*.local"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, err := Listen("", policy.Observe, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			ca, err := NewCA("test")
			if err != nil {
				t.Fatal(err)
			}
			var tools []Tool
			if c.tools != nil {
				tools = []Tool{{Name: "tool", Hosts: c.tools, Socket: "/nonexistent.sock"}}
			}
			p.Terminate(ca, []Credential{{Name: "model", Hosts: c.creds, Scheme: "bearer", Token: func() string { return "x" }}}, c.paths, tools)
			if got := p.Terminated(); !slices.Equal(got, c.want) {
				t.Errorf("Terminated() = %q, want %q", got, c.want)
			}
		})
	}
}
