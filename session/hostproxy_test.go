package session_test

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// The tests of this file open a run and start its host proxy, the forwarder on loopback
// that programs on the host, such as a fetch or a compose, reach the run's proxy
// through before a session joins.

// hostProxyURL is a host proxy's URL: the user qory, its password and its address.
var hostProxyURL = regexp.MustCompile(`^http://qory:([A-Za-z0-9_-]{43})@(127\.0\.0\.1:[0-9]+)$`)

// hostParts are the password and the address of the host proxy h.
func hostParts(t *testing.T, h session.HostProxy) (password, addr string) {
	t.Helper()
	m := hostProxyURL.FindStringSubmatch(h.ProxyURL)
	if m == nil {
		t.Fatalf("the host proxy's URL %q is no URL on loopback with a password", h.ProxyURL)
	}
	return m[1], m[2]
}

// throughHost sends GET target through the proxy at proxyURL, on a connection of its
// own, and returns the status and the body.
func throughHost(t *testing.T, proxyURL, target string) (int, string) {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true}}
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("a request through the host proxy: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// reportsOf sets sp to keep what the session reports, and returns them.
func reportsOf(t *testing.T, sp *runSpec) func() []string {
	var mu sync.Mutex
	var reports []string
	sp.Report = func(l string) {
		t.Log("report:", l)
		mu.Lock()
		reports = append(reports, l)
		mu.Unlock()
	}
	return func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(reports) }
}

// noSecretIn fails the test when a file of dir, a request the link received, or a
// report contains secret.
func noSecretIn(t *testing.T, secret, dir string, g *linktest.Fake, reports []string) {
	t.Helper()
	files := 0
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			files++
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(secret)) {
				t.Errorf("%s contains the host proxy's password", p)
			}
		}
		return nil
	})
	if files == 0 {
		t.Errorf("no file in %s", dir)
	}
	raw := g.RawRequests()
	if len(raw) == 0 {
		t.Error("the link received no request")
	}
	for _, b := range raw {
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("a request to the link contains the host proxy's password: %s", b)
		}
	}
	if len(g.Events()) == 0 {
		t.Error("the link received no event")
	}
	for _, l := range reports {
		if strings.Contains(l, secret) {
			t.Errorf("a report contains the host proxy's password: %q", l)
		}
	}
}

// TestTheHostProxyReachesTheRunsProxy pins the host proxy of a run on one machine, walled
// or not, and behind a separate gateway: its URL is a port on loopback with a password,
// its Env points HTTP_PROXY and HTTPS_PROXY at that URL, a request with the password
// reaches the gateway's proxy on a connection opened with the run's proxy secret or the
// run key, a request without it or with another password is closed unanswered and
// nothing of it reaches the gateway's proxy, and the password is in no file of the run
// directory, no request to the link and no report.
func TestTheHostProxyReachesTheRunsProxy(t *testing.T) {
	for _, c := range []struct {
		name             string
		walled, separate bool
	}{{name: "one machine"}, {name: "one machine, walled", walled: true}, {name: "separate gateway", separate: true}} {
		t.Run(c.name, func(t *testing.T) {
			sp, g := specGateway(t)
			preamble := link.RelayPreamble + " " + linktest.ProxySecret
			if c.separate {
				g = startRemote(t)
				g.SetInterval(30)
				key := g.RunKey(t, event.NewRunID())
				sp.Gateway = session.RemoteGateway{RunKey: key}
				preamble = link.RelayPreamble + " " + key
			}
			if c.walled {
				sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			}
			reports := reportsOf(t, &sp)
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			h, err := r.HostProxy()
			if err != nil {
				t.Fatal(err)
			}
			password, addr := hostParts(t, h)
			for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
				if !slices.Contains(h.Env, name+"="+h.ProxyURL) {
					t.Errorf("Env has no %s=%s: %q", name, h.ProxyURL, h.Env)
				}
			}
			if h.CABundle != "" {
				t.Errorf("CABundle is %q for a run with no authority", h.CABundle)
			}
			if status, body := throughHost(t, h.ProxyURL, "http://api.example/host"); status != http.StatusOK || body != "ok" {
				t.Errorf("the request through the host proxy got %d %q", status, body)
			}
			if got := stray(addr); got != "closed unanswered\nclosed unanswered\n" {
				t.Errorf("the host proxy took a connection without its password:\n%s", got)
			}
			if got := g.Preambles(); !slices.Equal(got, []string{preamble}) {
				t.Errorf("the gateway's proxy saw %q, want %q", got, preamble)
			}
			if got := g.Proxied(); !slices.Equal(got, []string{"GET http://api.example/host"}) {
				t.Errorf("the gateway's proxy answered %q", got)
			}
			if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
				t.Fatal(err)
			}
			noSecretIn(t, password, r.Dir(), g, reports())
		})
	}
}

// TestTheHostProxysBundle pins CABundle and the bundle's variables in Env: for a run
// with an authority, walled or not, CABundle is ca-bundle.pem in the run directory, with
// the machine's authorities and then the run's certificate and no key, and each
// variable of OpenSpec.CAEnv is set to its path; for a run with no authority, CABundle
// is empty and Env has none of them.
func TestTheHostProxysBundle(t *testing.T) {
	roots := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(roots, []byte(machineRoots), 0o644); err != nil {
		t.Fatal(err)
	}
	defer session.SetMachineBundles([]string{roots})()
	for _, c := range []struct {
		name              string
		walled, authority bool
	}{{"unwalled", false, true}, {"walled", true, true}, {"no authority", false, false}} {
		t.Run(c.name, func(t *testing.T) {
			sp, g := specGateway(t)
			if c.authority {
				credentialAnswer(g)
			}
			if c.walled {
				sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			}
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
			h, err := r.HostProxy()
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			if !c.authority {
				if h.CABundle != "" || slices.ContainsFunc(h.Env, func(v string) bool { return strings.HasPrefix(v, "SSL_CERT_FILE=") }) {
					t.Errorf("CABundle %q, Env %q; want no bundle", h.CABundle, h.Env)
				}
				return
			}
			bundle := filepath.Join(r.Dir(), session.BundleFile)
			if h.CABundle != bundle {
				t.Errorf("CABundle is %q, want %q", h.CABundle, bundle)
			}
			for _, n := range wall.DefaultCAEnv {
				if !slices.Contains(h.Env, n+"="+bundle) {
					t.Errorf("Env has no %s=%s: %q", n, bundle, h.Env)
				}
			}
			b, err := os.ReadFile(bundle)
			if err != nil || string(b) != machineRoots+"\n"+authority || bytes.Contains(b, []byte("PRIVATE KEY")) {
				t.Errorf("the bundle %q, %v; want the machine's authorities and the run's certificate", b, err)
			}
		})
	}
}

// refused fails the test when the address takes a connection.
func refused(t *testing.T, addr, when string) {
	t.Helper()
	if c, err := net.Dial("tcp", addr); err == nil {
		c.Close()
		t.Errorf("the host proxy takes a connection %s", when)
	}
}

// TestTheHostProxyEnds pins the three ends of a host proxy: at HostProxy.Close, at the
// next join, before its join request reaches the gateway, and at the run's close. From
// then on its port takes no connection, and HostProxy.Close again returns nil.
func TestTheHostProxyEnds(t *testing.T) {
	ctx := context.Background()
	t.Run("HostProxy.Close", func(t *testing.T) {
		sp, _ := specGateway(t)
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
		h, err := r.HostProxy()
		if err != nil {
			t.Fatal(err)
		}
		_, addr := hostParts(t, h)
		if status, _ := throughHost(t, h.ProxyURL, "http://api.example/host"); status != http.StatusOK {
			t.Errorf("the request through the host proxy got %d", status)
		}
		if err := h.Close(); err != nil {
			t.Fatal(err)
		}
		refused(t, addr, "after HostProxy.Close")
		if err := h.Close(); err != nil {
			t.Errorf("a second HostProxy.Close: %v", err)
		}
	})
	t.Run("Join", func(t *testing.T) {
		sp, g := specGateway(t, "FAKE_EXIT=0")
		var addr string
		dialed := make(chan error, 1)
		g.OnJoin(func(linktest.Join) linktest.Reply {
			c, err := net.Dial("tcp", addr)
			if err == nil {
				c.Close()
			}
			dialed <- err
			return linktest.Reply{Status: 200, Body: map[string]any{"version": 1, "session": 1}}
		})
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		h, err := r.HostProxy()
		if err != nil {
			t.Fatal(err)
		}
		_, addr = hostParts(t, h)
		res, err := r.Join(ctx, sp.SessionSpec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Close(ctx, outcomeOf(res, nil)); err != nil {
			t.Fatal(err)
		}
		if err := <-dialed; err == nil {
			t.Error("the host proxy took a connection when the join request reached the gateway")
		}
		if err := h.Close(); err != nil {
			t.Errorf("HostProxy.Close after the join: %v", err)
		}
	})
	t.Run("Run.Close", func(t *testing.T) {
		sp, _ := specGateway(t)
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		h, err := r.HostProxy()
		if err != nil {
			t.Fatal(err)
		}
		_, addr := hostParts(t, h)
		if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
			t.Fatal(err)
		}
		refused(t, addr, "after the run's close")
		if _, err := r.HostProxy(); err == nil {
			t.Error("a closed run started a host proxy")
		}
	})
}
