package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/server"
)

// stepRun is one run's proxy on a shared listener, with a host that gets a credential,
// a tool and the run API, for the tests of an unprivileged connection.
type stepRun struct {
	l        *Listener
	secret   string
	trusted  *x509.CertPool
	obs      *decisions
	origin   *atomic.Value // the Authorization the origin got last
	toolHits *atomic.Int32
	sent     *atomic.Int32
}

const (
	stepKeyHost  = "key.example"
	stepToolHost = "files.tools.internal"
)

func newStepRun(t *testing.T) *stepRun {
	t.Helper()
	up, err := NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	s := &stepRun{obs: &decisions{}, origin: &atomic.Value{}, toolHits: &atomic.Int32{}, sent: &atomic.Int32{}}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.origin.Store(r.Header.Get("Authorization"))
		// The origin sends back the value it got, which the proxy replaces.
		io.WriteString(w, "got "+r.Header.Get("Authorization"))
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return up.leaf(hello.ServerName) }}
	origin.StartTLS()
	t.Cleanup(origin.Close)

	dir, err := os.MkdirTemp("", "s")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "t.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	tool := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.toolHits.Add(1)
		io.WriteString(w, "from the tool")
	})}
	go tool.Serve(ln)
	t.Cleanup(func() { tool.Close() })

	p, err := New(policy.Enforce, []string{stepKeyHost, stepToolHost}, nil, s.obs.observe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	p.dial = (&dials{secure: origin.Listener.Addr().String()}).dial
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(up.PEM())
	p.TrustUpstream(roots)
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	p.Terminate(ca, []Credential{{Name: "key", Hosts: []string{stepKeyHost}, Scheme: "bearer", Token: func() string { return "fake-key-0001" }}},
		map[string][]string{stepToolHost: {"/*"}}, []Tool{{Name: "files", Hosts: []string{stepToolHost}, Socket: sock}})
	p.SetRunAPI(&RunAPI{RunID: routeRun, Limits: &RunAPILimits{}, Send: func(context.Context, string, string, []byte, bool) (*server.RunAPIAnswer, error) {
		s.sent.Add(1)
		return &server.RunAPIAnswer{Status: http.StatusOK, Header: http.Header{}}, nil
	}})
	s.trusted = x509.NewCertPool()
	s.trusted.AppendCertsFromPEM(ca.PEM())

	s.l, err = NewListener("", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.l.Close() })
	if s.secret, err = NewSecret(); err != nil {
		t.Fatal(err)
	}
	if err := s.l.Register(s.secret, p); err != nil {
		t.Fatal(err)
	}
	return s
}

// client reaches the run's proxy with the preamble line opens every connection with.
func (s *stepRun) client(t *testing.T, line string) *http.Client {
	t.Helper()
	u, _ := url.Parse("http://" + s.l.Addr())
	tr := &http.Transport{
		Proxy: http.ProxyURL(u), DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: s.trusted},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if _, err := io.WriteString(c, line); err != nil {
				c.Close()
				return nil, err
			}
			return c, nil
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func stepGet(t *testing.T, c *http.Client, target string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Authorization", "Bearer stand-in")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", target, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestAnUnprivilegedConnectionGetsNoCredential pins that a request in a tunnel of a
// connection that opened with link.UnprivilegedPreamble reaches the host as the client
// sent it, with no credential of the run's, and is recorded with none, while the same
// request on a connection that opened with link.RelayPreamble gets the credential. The
// answer is masked in both.
func TestAnUnprivilegedConnectionGetsNoCredential(t *testing.T) {
	s := newStepRun(t)
	code, body := stepGet(t, s.client(t, link.UnprivilegedLine(s.secret)), "https://"+stepKeyHost+"/v1")
	if code != http.StatusOK || s.origin.Load() != "Bearer stand-in" {
		t.Fatalf("unprivileged: %d, the origin got %q", code, s.origin.Load())
	}
	if d := s.obs.at(-1); d.Credential != "" || !d.Allowed {
		t.Errorf("unprivileged: the record %+v", d)
	}
	code, body = stepGet(t, s.client(t, link.RelayLine(s.secret)), "https://"+stepKeyHost+"/v1")
	if code != http.StatusOK || s.origin.Load() != "Bearer fake-key-0001" {
		t.Fatalf("privileged: %d, the origin got %q", code, s.origin.Load())
	}
	if strings.Contains(body, "fake-key-0001") {
		t.Errorf("the answer has the credential's value: %q", body)
	}
	if d := s.obs.at(-1); d.Credential != "key" {
		t.Errorf("privileged: the record %+v", d)
	}
}

// TestAnUnprivilegedConnectionReachesNoTool pins the 403 with the rule wall:unprivileged
// to a request for a tool's host on an unprivileged connection, in a tunnel and as a
// plain request: the tool gets neither, and each is recorded. On a relay connection the
// tool gets the request.
func TestAnUnprivilegedConnectionReachesNoTool(t *testing.T) {
	s := newStepRun(t)
	step := s.client(t, link.UnprivilegedLine(s.secret))
	for _, target := range []string{"https://" + stepToolHost + "/a", "http://" + stepToolHost + "/b"} {
		code, body := stepGet(t, step, target)
		if code != http.StatusForbidden || !strings.HasPrefix(body, "qory: run this from the session, not from a step") {
			t.Errorf("%s: %d %q", target, code, body)
		}
		if d := s.obs.at(-1); d.PathRule != UnprivilegedRule || d.Allowed || d.Outcome != Refused {
			t.Errorf("%s: the record %+v", target, d)
		}
	}
	if n := s.toolHits.Load(); n != 0 {
		t.Fatalf("the tool got %d requests of an unprivileged connection", n)
	}
	if code, _ := stepGet(t, s.client(t, link.RelayLine(s.secret)), "https://"+stepToolHost+"/c"); code != http.StatusOK || s.toolHits.Load() != 1 {
		t.Errorf("privileged: %d, the tool got %d", code, s.toolHits.Load())
	}
}

// TestAnUnprivilegedConnectionHasNoRunAPI pins the run API's 403 with the code
// unprivileged to a request on an unprivileged connection: nothing is signed or sent,
// and the decision is recorded with the status.
func TestAnUnprivilegedConnectionHasNoRunAPI(t *testing.T) {
	s := newStepRun(t)
	code, body := stepGet(t, s.client(t, link.UnprivilegedLine(s.secret)), routeURL("/work-item"))
	var doc struct{ Error, Message string }
	json.Unmarshal([]byte(body), &doc)
	if code != http.StatusForbidden || doc.Error != "unprivileged" || doc.Message != runAPIUnprivileged {
		t.Fatalf("%d %q", code, body)
	}
	if d := s.obs.at(-1); d.Channel != ChannelRunAPI || d.Status != http.StatusForbidden || d.Rule != RunAPIRule {
		t.Errorf("the record %+v", d)
	}
	if s.sent.Load() != 0 {
		t.Error("the request was sent")
	}
	if code, _ := stepGet(t, s.client(t, link.RelayLine(s.secret)), routeURL("/work-item")); code != http.StatusOK || s.sent.Load() != 1 {
		t.Errorf("privileged: %d, sent %d", code, s.sent.Load())
	}
}

// TestTheSharedListenerKnowsBothWords pins that a line of another word, or of the
// unprivileged word with a secret no run has, is refused, and that ServeUnprivileged
// marks a connection as the word does.
func TestTheSharedListenerKnowsBothWords(t *testing.T) {
	s := newStepRun(t)
	for _, line := range []string{"QORY-OTHER " + s.secret + "\n", link.UnprivilegedLine("not-the-runs-secret-0000000")} {
		c, err := net.Dial("tcp", s.l.Addr())
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(c, line+"GET "+routeURL("/work-item")+" HTTP/1.1\r\nHost: x\r\n\r\n")
		if b, _ := io.ReadAll(c); len(b) != 0 {
			t.Errorf("%q: the proxy answered %q", line, b)
		}
		c.Close()
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	a, b := net.Pipe()
	defer a.Close()
	p := s.l.Lookup(s.secret, false)
	p.ServeUnprivileged(b)
	wg.Go(func() {
		io.WriteString(a, "GET "+routeURL("/work-item")+" HTTP/1.1\r\nHost: "+link.RunAPIHost+"\r\nConnection: close\r\n\r\n")
	})
	resp, err := http.ReadResponse(bufio.NewReader(a), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("ServeUnprivileged: %d", resp.StatusCode)
	}
}
