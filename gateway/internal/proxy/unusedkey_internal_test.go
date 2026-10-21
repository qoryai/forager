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

// TestAHostOnlyAnUnusedModelKeyCoversPasses pins decision 845 (a). Under enforce, with
// two model keys on two hosts and the session using key 1, a request to key 2's host
// passes with no credential set and no path rule, and its answer has key 2's value
// replaced with key 2's placeholder, as key 1's answer has key 1's. A request to a host no key covers is
// decided by the policy: a path its path rules list passes, another path is denied,
// and a host its allow list does not list is denied.
func TestAHostOnlyAnUnusedModelKeyCoversPasses(t *testing.T) {
	const one, two = "fake-model-key-one-0001", "fake-model-key-two-0002"
	const hostOne, hostTwo, ruled, unlisted = "api.model-one.example", "api.model-two.example", "docs.example", "unlisted.example"
	up, err := NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	got := map[string]string{}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got[r.Host+r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
		// Each model host sends its key's value back.
		echo := map[string]string{hostOne: one, hostTwo: two}[r.Host]
		w.Header().Set("X-Echo", echo)
		io.WriteString(w, "key "+echo)
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return up.leaf(hello.ServerName) }}
	origin.StartTLS()
	defer origin.Close()

	seen := &decisions{}
	p, err := Listen("", policy.Enforce, []string{hostOne, hostTwo, ruled}, nil, seen.observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.dial = (&dials{secure: origin.Listener.Addr().String()}).dial
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(up.PEM())
	p.TrustUpstream(roots)
	creds := []Credential{
		{Name: "one", Hosts: []string{hostOne}, Scheme: "bearer", Token: func() string { return one }, Placeholder: link.KeyPlaceholder("one")},
		{Name: "two", Hosts: []string{hostTwo}, Scheme: "bearer", Token: func() string { return two }, Placeholder: link.KeyPlaceholder("two")},
	}
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	p.Terminate(ca, creds, map[string][]string{ruled: {"/allowed/*"}}, nil)
	p.SetModelKey("one")
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	proxyURL, _ := url.Parse(p.URL())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	for _, c := range []struct {
		host, path, sent string
		status           int
		auth, credential string
		// value is the key whose value the answer has replaced with placeholder.
		value, placeholder string
	}{
		{hostOne, "/v1/messages", "Bearer " + link.KeyPlaceholder("one"), http.StatusOK, "Bearer " + one, "one", one, link.KeyPlaceholder("one")},
		{hostTwo, "/v1/messages", "Bearer " + link.KeyPlaceholder("two"), http.StatusOK, "Bearer " + link.KeyPlaceholder("two"), "", two, link.KeyPlaceholder("two")},
		{hostTwo, "/any/path", "", http.StatusOK, "", "", two, link.KeyPlaceholder("two")},
		{ruled, "/allowed/page", "", http.StatusOK, "", "", "", ""},
		{ruled, "/other/page", "", http.StatusForbidden, "", "", "", ""},
		{unlisted, "/page", "", http.StatusForbidden, "", "", "", ""},
	} {
		req, _ := http.NewRequest("GET", "https://"+c.host+c.path, nil)
		if c.sent != "" {
			req.Header.Set("Authorization", c.sent)
		}
		resp, err := client.Do(req)
		status, body := 0, ""
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			status, body = resp.StatusCode, string(b)+" "+resp.Header.Get("X-Echo")
		} else if c.host == unlisted && strings.Contains(err.Error(), "Forbidden") {
			// The proxy refuses the CONNECT itself.
			status = http.StatusForbidden
		}
		mu.Lock()
		auth, reached := got[c.host+c.path]
		mu.Unlock()
		if status != c.status {
			t.Errorf("%s%s: %d (%v), want %d: %s", c.host, c.path, status, err, c.status, body)
			continue
		}
		if c.status == http.StatusForbidden {
			if reached {
				t.Errorf("%s%s: the denied request reached the host", c.host, c.path)
			}
			continue
		}
		if auth != c.auth {
			t.Errorf("%s%s: the host got Authorization %q, want %q", c.host, c.path, auth, c.auth)
		}
		if d := seen.at(-1); d.Credential != c.credential || d.PathRule != "" && c.host != ruled {
			t.Errorf("%s%s: the record has the credential %q and the path rule %q, want %q and none", c.host, c.path, d.Credential, d.PathRule, c.credential)
		}
		if c.value != "" && (strings.Contains(body, c.value) || strings.Count(body, c.placeholder) != 2) {
			t.Errorf("%s%s: the answer is %q, want the key's value replaced with %s", c.host, c.path, body, c.placeholder)
		}
	}
}
