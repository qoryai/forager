package gateway_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/server"
)

// stepClock is a clock of a run's renewals that moves only when the test advances it.
type stepClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []stepTimer
}

type stepTimer struct {
	at time.Time
	ch chan time.Time
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *stepClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.now
		return ch
	}
	c.timers = append(c.timers, stepTimer{c.now.Add(d), ch})
	return ch
}

// advance moves the clock by d and fires every timer due.
func (c *stepClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	var left []stepTimer
	for _, t := range c.timers {
		if t.at.After(c.now) {
			left = append(left, t)
			continue
		}
		t.ch <- c.now
	}
	c.timers = left
}

// TestARenewedValueReachesTheOrigin runs a renewal end to end against the reference
// receiver, without Docker: a walled run's credential forge, set in x-api-key on an
// HTTPS origin on this machine, expires an hour after the start. The origin answers 401
// to the first value; 30 seconds later the gateway asks the receiver for forge alone,
// and the origin gets the second value. 5 minutes before the second value expires, the
// gateway asks again, and the origin gets the third. No report contains a value.
func TestARenewedValueReachesTheOrigin(t *testing.T) {
	certFile, keyFile, roots := testCertificate(t, t.TempDir())
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	const first = "forge-value-1-sealed-by-the-reference-receiver"
	var mu sync.Mutex
	var got []string
	o := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get("X-Api-Key")
		mu.Lock()
		got = append(got, v)
		mu.Unlock()
		if v == first {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	o.Config.ErrorLog = log.New(io.Discard, "", 0)
	o.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	o.StartTLS()
	t.Cleanup(o.Close)
	_, port, _ := net.SplitHostPort(o.Listener.Addr().String())

	clock := &stepClock{now: time.Now().UTC().Truncate(time.Second)}
	begun := clock.Now()
	ref := newReference(t, "localhost")
	ref.doc = []byte(`{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["localhost"]}},` +
		`"credentials":[{"name":"forge","apply":[{"hosts":["localhost"],"scheme":"header","header":"x-api-key"}]}]}`)
	ref.h.Secrets = func(_ receiver.Run, names []string) ([]receiver.Value, *receiver.Refusal) {
		ref.mu.Lock()
		n := len(ref.asked)
		ref.asked = append(ref.asked, names)
		ref.mu.Unlock()
		v := fmt.Sprintf("forge-value-%d-sealed-by-the-reference-receiver", n+1)
		value := receiver.NewValue([]byte(v))
		value.ExpiresAt = begun.Add(time.Duration(n+1) * time.Hour)
		return []receiver.Value{value}, nil
	}
	asked := func() [][]string {
		ref.mu.Lock()
		defer ref.mu.Unlock()
		return slices.Clone(ref.asked)
	}
	cfg := gateway.Config{Server: ref.server(testKey), Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost"}}}}
	gateway.SetUpstreamRoots(&cfg, roots)
	gateway.SetRenewClock(&cfg, clock)
	h := start(t, cfg)
	for i := 1; i <= 3; i++ {
		h.secrets = append(h.secrets, fmt.Sprintf("forge-value-%d-sealed-by-the-reference-receiver", i))
	}
	a := h.open(server.LinkRunRequest{Wall: true})
	client := relay(h.g.Addr(), a.ProxySecret)
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM([]byte(a.CertificateAuthority))
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: trusted}
	get := func() int {
		t.Helper()
		resp, err := client.Get("https://localhost:" + port + "/repo")
		if err != nil {
			t.Fatalf("the request through the proxy: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}

	if status := get(); status != http.StatusUnauthorized {
		t.Fatalf("the first value: %d, want 401", status)
	}
	clock.advance(30 * time.Second)
	eventually(t, "the renewal after the 401", func() bool { return len(asked()) == 2 })
	eventually(t, "the second value at the origin", func() bool { return get() == http.StatusOK })
	clock.advance(2*time.Hour - 5*time.Minute - 30*time.Second)
	eventually(t, "the renewal before expires_at", func() bool { return len(asked()) == 3 })
	eventually(t, "the third value at the origin", func() bool {
		get()
		mu.Lock()
		defer mu.Unlock()
		return got[len(got)-1] == "forge-value-3-sealed-by-the-reference-receiver"
	})
	if a := asked(); !slices.Equal(a[1], []string{"forge"}) || !slices.Equal(a[2], []string{"forge"}) {
		t.Errorf("the receiver was asked for %v", a)
	}
	mu.Lock()
	seen := slices.Compact(slices.Clone(got))
	mu.Unlock()
	if want := []string{first, "forge-value-2-sealed-by-the-reference-receiver", "forge-value-3-sealed-by-the-reference-receiver"}; !slices.Equal(seen, want) {
		t.Errorf("the origin got %q, want %q", seen, want)
	}
	h.mu.Lock()
	for _, l := range h.reports {
		if strings.Contains(l, "sealed-by-the-reference-receiver") {
			t.Errorf("a report contains a value: %s", l)
		}
	}
	h.mu.Unlock()
	h.post(started(a.RunID, nil), applied(a.RunID, a.Applied), exited(a.RunID))
	h.close()
}
