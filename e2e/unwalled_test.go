package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/session/runtimes/claude"
	"github.com/qoryai/forager/wall"
)

// envAgent makes the test binary the agent of an unwalled run when it is set: it sends
// ANTHROPIC_API_KEY's value in x-api-key to the URL in envAgentURL, through
// HTTPS_PROXY, trusting the bundle SSL_CERT_FILE points at, and writes an agentResult
// to the file whose path is in envAgent.
const (
	envAgent    = "E2E_TEST_AGENT"
	envAgentURL = "E2E_TEST_AGENT_URL"
)

// unwalledValue is the fake value of the machine's credential of the unwalled run,
// which the gateway reads from unwalledSource.
const (
	unwalledValue  = "fake-model-value-of-the-unwalled-test"
	unwalledSource = "E2E_TEST_UNWALLED_VALUE"
)

// The agent starts before any test does.
func init() {
	if os.Getenv(envAgent) != "" {
		os.Exit(runAgent())
	}
}

// agentResult is what the agent writes: its environment, and the status the origin
// answered with or the error of the request.
type agentResult struct {
	Env    []string
	Status int
	Err    string
}

// runAgent is the agent of TestAnUnwalledRunsValueReachesTheOriginThroughTheProxy.
func runAgent() int {
	res := agentResult{Env: os.Environ()}
	if err := sendThroughProxy(&res); err != nil {
		res.Err = err.Error()
	}
	b, _ := json.Marshal(res)
	if err := os.WriteFile(os.Getenv(envAgent), b, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// sendThroughProxy sends the agent's request and records the origin's status in res.
// It sets the proxy from HTTPS_PROXY explicitly, because the origin is on loopback,
// which Forager's NO_PROXY exempts and Go never proxies.
func sendThroughProxy(res *agentResult) error {
	proxyURL, err := url.Parse(os.Getenv("HTTPS_PROXY"))
	if err != nil {
		return err
	}
	bundle, err := os.ReadFile(os.Getenv("SSL_CERT_FILE"))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle) {
		return fmt.Errorf("no certificate in %s", os.Getenv("SSL_CERT_FILE"))
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}}
	req, err := http.NewRequest(http.MethodGet, os.Getenv(envAgentURL), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", os.Getenv("ANTHROPIC_API_KEY"))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	res.Status = resp.StatusCode
	return nil
}

// TestAnUnwalledRunsValueReachesTheOriginThroughTheProxy runs a real session.Run
// without a wall against a real gateway on its local link, without Docker. The
// machine's policy selects the model key model: the fake value from unwalledSource, an
// Anthropic Messages key in x-api-key whose endpoint is an HTTPS origin on 127.0.0.1.
// The agent sends the value it has in ANTHROPIC_API_KEY to the origin through the
// run's proxy. The agent has the key's placeholder in ANTHROPIC_API_KEY, over the value
// it inherits, the key's endpoint in ANTHROPIC_BASE_URL, and the value in no variable;
// the origin gets the value in x-api-key, once.
//
// The proxy verifies the origin against this machine's roots, which trustRecorders
// sets through SSL_CERT_FILE; Go reads that variable on Linux alone, so the test is
// skipped on other systems, and on a machine with none of the CA bundles the session
// reads.
func TestAnUnwalledRunsValueReachesTheOriginThroughTheProxy(t *testing.T) {
	if runtime.GOOS != "linux" {
		Skip(t, "Go reads this machine's roots from SSL_CERT_FILE on Linux alone, and the proxy verifies the origin against them")
	}
	if !slices.ContainsFunc(wall.BundleFiles(), func(p string) bool { fi, err := os.Stat(p); return err == nil && fi.Mode().IsRegular() }) {
		Skip(t, fmt.Sprintf("none of %v is on this machine, and an unwalled run starts only with one", wall.BundleFiles()))
	}
	if err := trustRecorders(t); err != nil {
		t.Fatalf("this machine's roots are not the suite's authority: %v", err)
	}
	t.Setenv(unwalledSource, unwalledValue)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	o := newUnwalledOrigin(t)

	runs := filepath.Join(t.TempDir(), "runs")
	g, err := gateway.Start(context.Background(), gateway.Config{Version: "test", Heartbeat: time.Second,
		RunDir: func(id string) string { return filepath.Join(runs, id) },
		Credentials: []gateway.Credential{{Name: "model", Env: unwalledSource, Format: "anthropic-messages", Endpoint: "https://" + o.host + "/v1",
			Scheme: "header", Header: "x-api-key"}},
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"127.0.0.1"}},
			Credentials: []gateway.PolicyCredential{{Name: "model"}}},
		Report: func(l string) { t.Log("the gateway reported:", l) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		g.Close(ctx)
	})

	rt, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "agent.json")
	var stdout, stderr bytes.Buffer
	res, err := runOne(context.Background(), runSpec{OpenSpec: session.OpenSpec{
		RunsDir:        runs,
		RunID:          event.NewRunID(),
		Gateway:        session.LocalGateway(g.LocalLink()),
		ForagerVersion: "test",
		Report:         func(l string) { t.Log("report:", l) },
	},
		SessionSpec: session.SessionSpec{
			Runtime: rt,
			Command: os.Args[0],
			Env: []string{envAgent + "=" + out, envAgentURL + "=https://" + o.host + "/v1/models",
				"ANTHROPIC_API_KEY=inherited-fake-key", "PATH=" + os.Getenv("PATH")},
			Dir:    t.TempDir(),
			Stdin:  strings.NewReader(""),
			Stdout: &stdout,
			Stderr: &stderr,
		},
	})
	if err != nil {
		t.Fatalf("the run: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	if res.ExitCode != 0 {
		t.Fatalf("the agent exited %d\nstderr:\n%s", res.ExitCode, stderr.String())
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var got agentResult
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Err != "" || got.Status != http.StatusOK {
		t.Errorf("the agent's request: status %d, error %q; want 200", got.Status, got.Err)
	}
	if !slices.Contains(got.Env, "ANTHROPIC_API_KEY="+link.KeyPlaceholder("model")) || !slices.Contains(got.Env, "ANTHROPIC_BASE_URL=https://"+o.host+"/v1") {
		t.Errorf("the agent's ANTHROPIC_API_KEY or ANTHROPIC_BASE_URL is not the key's placeholder or endpoint: %q", got.Env)
	}
	if bytes.Contains(b, []byte(unwalledValue)) {
		t.Errorf("the agent saw the value: %s", b)
	}
	if want := []string{"GET /v1/models " + unwalledValue}; !slices.Equal(o.requests(), want) {
		t.Errorf("the origin got %q; want %q", o.requests(), want)
	}
}

// unwalledOrigin is an HTTPS origin on 127.0.0.1, under the suite's authority, which
// records the x-api-key of every request it gets.
type unwalledOrigin struct {
	host string
	mu   sync.Mutex
	got  []string
}

func newUnwalledOrigin(t *testing.T) *unwalledOrigin {
	t.Helper()
	ca, caKey := authority()
	leaf, err := sign(ca, caKey, []net.IP{net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	o := &unwalledOrigin{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.got = append(o.got, r.Method+" "+r.URL.Path+" "+r.Header.Get("X-Api-Key"))
		o.mu.Unlock()
		io.WriteString(w, "origin")
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	o.host = srv.Listener.Addr().String()
	return o
}

// requests are what the origin got.
func (o *unwalledOrigin) requests() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.got)
}
