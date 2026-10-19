package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/forager/policy"
)

// TestACredentialFromTheServerSetsItsValue pins the header a credential from the
// server sets, its value bytes: Bearer and the value, Basic of the username and the
// value, or the value in its header, the session's stand-in replaced; the value is
// read again for every request. A TRACE or a TRACK on its host is refused with a 403
// whose rule is wall:echo-method and reaches no origin, and a TRACE on a host of a
// machine's credential goes on as before. A private name gets the value through an
// exact entry alone, as a machine's credential does. A TRACE whose path contains qak_
// has the value's phrase in place of the path.
func TestACredentialFromTheServerSetsItsValue(t *testing.T) {
	up, err := NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []string
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Method+" "+r.Host+" "+r.Header.Get("Authorization")+r.Header.Get("X-Api-Key")+" "+r.Header.Get(setBy))
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
	p.dial = (&dials{plain: origin.Listener.Addr().String(), secure: origin.Listener.Addr().String()}).dial
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(up.PEM())
	p.TrustUpstream(roots)
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	value := []byte("stored-value-0001")
	stored := func() []byte { return slices.Clone(value) }
	p.Terminate(ca, []Credential{
		{Name: "bearer", Hosts: []string{"bearer.example"}, Scheme: "bearer", Value: stored, Stored: true},
		{Name: "basic", Hosts: []string{"basic.example"}, Scheme: "basic", Username: "x-access-token", Value: stored, Stored: true},
		{Name: "header", Hosts: []string{"header.example"}, Scheme: "header", Header: "X-Api-Key", Value: stored, Stored: true},
		{Name: "machine", Hosts: []string{"machine.example"}, Scheme: "bearer", Token: func() string { return "machine-0001" }},
		{Name: "pattern", Hosts: []string{"*.local"}, Scheme: "bearer", Value: stored, Stored: true},
		{Name: "exact", Hosts: []string{"y.lan"}, Scheme: "bearer", Value: stored, Stored: true},
	}, nil, nil)

	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	// For a tunnel, the session trusts the origin's certificate.
	trusted.AppendCertsFromPEM(up.PEM())
	proxyURL, _ := url.Parse(p.URL())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}}}
	do := func(method, host string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, "https://"+host+"/v1/models", nil)
		req.Header.Set("Authorization", "Bearer stand-in")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:stored-value-0001"))
	for _, c := range []struct{ host, want string }{
		{"bearer.example", "GET bearer.example Bearer stored-value-0001 "},
		{"basic.example", "GET basic.example " + basic + " "},
		{"header.example", "GET header.example Bearer stand-instored-value-0001 "},
		// A private name gets the value through an exact entry alone; under a pattern
		// it is a tunnel, TLS to the origin kept, with the stand-in untouched.
		{"x.local", "GET x.local Bearer stand-in "},
		{"y.lan", "GET y.lan Bearer stored-value-0001 "},
	} {
		mu.Lock()
		got = nil
		mu.Unlock()
		if status, _ := do(http.MethodGet, c.host); status != http.StatusOK {
			t.Errorf("%s: %d", c.host, status)
		}
		mu.Lock()
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("%s: the origin got %q, want %q", c.host, got, c.want)
		}
		mu.Unlock()
	}
	// The value is read for each request.
	value = []byte("stored-value-0002")
	mu.Lock()
	got = nil
	mu.Unlock()
	do(http.MethodGet, "bearer.example")
	mu.Lock()
	if len(got) != 1 || got[0] != "GET bearer.example Bearer stored-value-0002 " {
		t.Errorf("after a change of the value the origin got %q", got)
	}
	got = nil
	mu.Unlock()

	for _, method := range []string{"TRACE", "TRACK", "trace"} {
		status, body := do(method, "header.example")
		want := "qory: " + method + " header.example/v1/models denied by the gateway: use another method; TRACE and TRACK send the request's headers back, and this host gets a credential from Qory Apiary\n"
		if status != http.StatusForbidden || body != want {
			t.Errorf("%s: %d %q", method, status, body)
		}
	}
	mu.Lock()
	if len(got) != 0 {
		t.Errorf("a TRACE or a TRACK reached the origin: %q", got)
	}
	mu.Unlock()
	seen.mu.Lock()
	n := 0
	for _, d := range seen.seen {
		if d.PathRule == EchoMethod {
			n++
			if d.Allowed || d.Outcome != Refused || d.Credential != "" {
				t.Errorf("the refused TRACE's decision %+v", d)
			}
		}
	}
	seen.mu.Unlock()
	if n != 3 {
		t.Errorf("%d decisions with %s, want 3", n, EchoMethod)
	}
	if status, _ := do("TRACE", "machine.example"); status != http.StatusOK {
		t.Errorf("a TRACE on a machine's credential's host: %d", status)
	}
	mu.Lock()
	if len(got) != 1 || !strings.HasPrefix(got[0], "TRACE machine.example Bearer machine-0001") {
		t.Errorf("the machine's TRACE: the origin got %q", got)
	}
	mu.Unlock()
	// A path that contains qak_ is the value's phrase in the denial.
	req, _ := http.NewRequest("TRACE", "https://header.example/v1/qak_not-a-real-secret", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := "qory: TRACE header.example(a value that contains an access key secret) denied by the gateway: use another method; TRACE and TRACK send the request's headers back, and this host gets a credential from Qory Apiary\n"; resp.StatusCode != http.StatusForbidden || string(b) != want {
		t.Errorf("a TRACE of a path with qak_: %d %q", resp.StatusCode, b)
	}
}
