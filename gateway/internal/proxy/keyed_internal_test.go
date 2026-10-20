package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/policy"
)

// TestARequestThatCarriesACredentialGoesOverHTTP1 pins that, to an origin that offers
// HTTP/2, a request the proxy sets a credential on arrives over HTTP/1.1, with the
// credential, also when the session's Connection header lists the proxy's mark, and a
// request to a terminated host without a credential arrives over HTTP/2, as before.
func TestARequestThatCarriesACredentialGoesOverHTTP1(t *testing.T) {
	up, err := NewCA("upstream", []string{"key.example", "marked.example", "other.example"})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	got := map[string]string{}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got[r.Host] = r.Proto + " " + r.Header.Get("Authorization")
		mu.Unlock()
		io.WriteString(w, "origin")
	}))
	origin.EnableHTTP2 = true
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return up.leaf(hello.ServerName) }}
	origin.StartTLS()
	defer origin.Close()

	p, err := Listen("", policy.Observe, nil, nil, (&decisions{}).observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.dial = (&dials{secure: origin.Listener.Addr().String()}).dial
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(up.PEM())
	p.TrustUpstream(roots)
	creds := []Credential{{Name: "key", Hosts: []string{"key.example", "marked.example"}, Scheme: "bearer", Token: func() string { return "fake-key-0001" }}}
	paths := map[string][]string{"other.example": {"/*"}}
	ca, err := NewCA("test", p.Terminating(creds, paths, nil))
	if err != nil {
		t.Fatal(err)
	}
	p.Terminate(ca, creds, paths, nil)

	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	proxyURL, _ := url.Parse(p.URL())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	for _, host := range []string{"key.example", "marked.example", "other.example"} {
		req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/v1", nil)
		req.Header.Set("Authorization", "Bearer stand-in")
		if host == "marked.example" {
			// The mark is taken off before the transport reads the request.
			req.Header.Set("Connection", setBy)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", host, resp.StatusCode)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for host, want := range map[string]string{"key.example": "HTTP/1.1 Bearer fake-key-0001", "marked.example": "HTTP/1.1 Bearer fake-key-0001", "other.example": "HTTP/2.0 Bearer stand-in"} {
		if got[host] != want {
			t.Errorf("%s: the origin got %q, want %q", host, got[host], want)
		}
	}
}

// TestA401ToAKeyedRequestStartsTheRenewalWhateverItsConnectionHeader pins that a 401
// from the host to a request the proxy set a credential on calls the credential's
// Rejected, also when the session's Connection header lists the proxy's mark, which
// takes the mark off the request before the answer is read.
func TestA401ToAKeyedRequestStartsTheRenewalWhateverItsConnectionHeader(t *testing.T) {
	up, err := NewCA("upstream", []string{"key.example"})
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return up.leaf(hello.ServerName) }}
	origin.StartTLS()
	defer origin.Close()

	p, err := Listen("", policy.Observe, nil, nil, (&decisions{}).observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.dial = (&dials{secure: origin.Listener.Addr().String()}).dial
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(up.PEM())
	p.TrustUpstream(roots)
	var mu sync.Mutex
	rejected := 0
	creds := []Credential{{Name: "key", Hosts: []string{"key.example"}, Scheme: "bearer", Token: func() string { return "fake-key-0001" },
		Rejected: func() { mu.Lock(); rejected++; mu.Unlock() }}}
	ca, err := NewCA("test", p.Terminating(creds, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	p.Terminate(ca, creds, nil, nil)

	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	proxyURL, _ := url.Parse(p.URL())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, "https://key.example/v1", nil)
	req.Header.Set("Authorization", "Bearer stand-in")
	req.Header.Set("Connection", setBy)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the answer is %d; want the host's 401", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if rejected != 1 {
		t.Errorf("Rejected was called %d times; want 1", rejected)
	}
}
