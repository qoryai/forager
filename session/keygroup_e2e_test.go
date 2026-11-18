package session_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/session"
)

// The values of the two model keys of TestTheNextSessionGetsTheGroupsPlaceholder: the
// provider refuses the first one at its limit and serves the second one.
const (
	limitedValue = "fake-model-value-at-its-limit"
	servedValue  = "fake-model-value-served"
)

// groupMember is the key group of each API credential of the run configuration of
// TestTheNextSessionGetsTheGroupsPlaceholder, spliced in after its name.
const groupMember = `,"group":"anthropic"`

// keyProvider is a model provider of the Anthropic Messages API on this machine, over
// HTTPS under a test authority: a request whose x-api-key is limitedValue gets a 429
// limit refusal with a reset an hour ahead, and every other request a 200. It records,
// for each request, its x-test-session header and its x-api-key.
type keyProvider struct {
	srv  *httptest.Server
	host string
	ca   []byte

	mu  sync.Mutex
	got []string
}

func newKeyProvider(t *testing.T) *keyProvider {
	t.Helper()
	p := &keyProvider{}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "provider authority"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	p.ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	p.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		k := r.Header.Get("X-Api-Key")
		p.mu.Lock()
		p.got = append(p.got, r.Header.Get("X-Test-Session")+" "+k)
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if k == limitedValue {
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"type":"error","error":{"type":"rate_limit_error","message":"This request would exceed the rate limit."}}`)
			return
		}
		io.WriteString(w, `{"id":"msg_fake","type":"message","role":"assistant","content":[{"type":"text","text":"done"}]}`)
	}))
	p.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	p.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	p.srv.StartTLS()
	t.Cleanup(p.srv.Close)
	_, port, _ := net.SplitHostPort(p.srv.Listener.Addr().String())
	p.host = "localhost:" + port
	return p
}

// requests are what the provider got, each as the x-test-session header, a space and
// the x-api-key header.
func (p *keyProvider) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.got)
}

// keyControl is a server of the contract in front of the reference receiver that
// serves a run configuration with two model keys, model and model-2, in one key group
// whose start key is model, and the values limitedValue and servedValue for them
// through its secrets endpoint.
type keyControl struct {
	srv *httptest.Server
	key *accesskey.Key
	pin accesskey.Pin
}

func newKeyControl(t *testing.T, provider string) *keyControl {
	t.Helper()
	credential := func(name string) string {
		return `{"name":"` + name + `"` + groupMember + `,"format":"anthropic-messages","endpoint":"https://` + provider + `/v1","auth":{"scheme":"header","header":"x-api-key"}}`
	}
	return newKeyControlOf(t, credential("model")+`,`+credential("model-2"), "model", map[string]string{"model": limitedValue, "model-2": servedValue})
}

// newKeyControlOf is a keyControl whose run configuration has the API credentials
// credentials, a JSON list's items, and the start key start, and whose secrets endpoint
// serves values, by name.
func newKeyControlOf(t *testing.T, credentials, start string, values map[string]string) *keyControl {
	t.Helper()
	key, signer := mustKey(t), mustKey(t)
	store, err := receiver.OpenFile(filepath.Join(t.TempDir(), "received.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	c := &keyControl{key: key, pin: accesskey.Pin{{Alg: "ed25519", PublicKey: signer.PublicKey().String()}}}
	doc := []byte(`{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["localhost"]}},` +
		`"credentials":[` + credentials + `],"model_credential":"` + start + `"}`)
	h := &receiver.Handler{
		Keys: func(k string) (receiver.AccessKey, bool) {
			return receiver.AccessKey{PublicKey: key.PublicKey(), StoredSecrets: true}, k == testKeyID
		},
		Signer: signer,
		Store:  store,
		Configuration: func() ([]byte, string) {
			pin, _ := json.Marshal(c.pin)
			d := `{"version":1,"node_id":"nd_f1xt0re000000000","workspaces":["ws_f1xt0re000000000"],"apiary_public_key":` + string(pin) +
				`,"events":{"url":"` + c.srv.URL + `/v1/events","types":["*"]},"run":{"url":"` + c.srv.URL + receiver.DefaultRunPath +
				`"},"secrets":{"url":"` + c.srv.URL + receiver.DefaultSecretsPath + `"}}`
			return []byte(d), "sha256=" + fmt.Sprint(len(d))
		},
		RunConfiguration: func(receiver.Run) ([]byte, string, *receiver.Refusal) { return doc, "", nil },
		Secrets: func(_ receiver.Run, names []string) ([]receiver.Value, *receiver.Refusal) {
			var out []receiver.Value
			for _, n := range names {
				out = append(out, receiver.NewValue([]byte(values[n])))
			}
			return out, nil
		},
	}
	c.srv = httptest.NewServer(h)
	t.Cleanup(c.srv.Close)
	return c
}

func (c *keyControl) server() *gateway.Server {
	return &gateway.Server{Version: 1, URL: c.srv.URL, AccessKeyID: testKeyID, ApiaryPublicKey: c.pin, AccessKey: c.key, InstanceID: "i_test"}
}

// trustUpstream makes every run's proxy of a gateway started with cfg verify a
// terminated host's certificate against roots, in place of this machine's. The
// gateway exports this setting to the tests of package gateway alone
// (gateway.SetUpstreamRoots), and Go reads SSL_CERT_FILE on Linux alone, so this sets
// the unexported field of cfg directly.
func trustUpstream(t *testing.T, cfg *gateway.Config, roots *x509.CertPool) {
	t.Helper()
	f := reflect.ValueOf(cfg).Elem().FieldByName("upstreamRoots")
	if !f.IsValid() {
		t.Fatal("gateway.Config has no field upstreamRoots")
	}
	reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(reflect.ValueOf(roots))
}

// keyRequest is the agent of TestTheNextSessionGetsTheGroupsPlaceholder: a shell that
// writes its environment to $0, then POSTs a Messages request through the run's proxy
// to the endpoint in ANTHROPIC_BASE_URL with ANTHROPIC_API_KEY in x-api-key, as Claude
// Code sends it, and $1 in x-test-session, trusting the run's bundle, and writes the
// status and curl's exit code to $2.
const keyRequest = `env > "$0"
curl -sS -o /dev/null -w '%{http_code}' -x "$HTTPS_PROXY" --noproxy '' --cacert "$SSL_CERT_FILE" \
  -H "x-api-key: $ANTHROPIC_API_KEY" -H "x-test-session: $1" -H 'anthropic-version: 2023-06-01' -H 'content-type: application/json' \
  -d '{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}' "$ANTHROPIC_BASE_URL/messages" > "$2.status" 2> "$2.err"
code=$?
echo "$(cat "$2.status") $code" > "$2"
exit 0`

// TestTheNextSessionGetsTheGroupsPlaceholder pins the key group's placeholder across
// the sessions of one run, end to end through a real gateway: the server's run
// configuration has two model keys of one key group, model and then model-2, with
// model as the start key. Session 1 gets model's placeholder; its request reaches the
// provider with model's value, gets a 429 limit refusal, and the proxy sends it again
// with model-2's value, which gets a 200. Session 2 then joins the same run while
// model-2 is the group's active key: it gets model's placeholder too, the one the proxy
// sets the group's active key on, and its request reaches the provider with model-2's
// value.
func TestTheNextSessionGetsTheGroupsPlaceholder(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("the agent sends its request with curl, and this machine has none")
	}
	provider := newKeyProvider(t)
	c := newKeyControl(t, provider.host)
	authority := filepath.Join(t.TempDir(), "provider-ca.pem")
	if err := os.WriteFile(authority, provider.ca, 0o644); err != nil {
		t.Fatal(err)
	}
	// The machine's authorities are the provider's: a real certificate, which curl
	// reads in the run's bundle before the run's certificate.
	t.Cleanup(session.SetMachineBundles([]string{authority}))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(provider.ca)
	sp := spec(t)
	sp.Forwarder = nil
	cfg := gateway.Config{Server: c.server(), Version: "test", Heartbeat: time.Second,
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost"}}}}
	trustUpstream(t, &cfg, roots)
	rg := startGateway(t, &sp, cfg)
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var envs, outs []string
	for _, n := range []string{"one", "two"} {
		env, out := filepath.Join(dir, "env-"+n), filepath.Join(dir, "curl-"+n)
		s := sp.SessionSpec
		s.Command, s.Args = installedShell, []string{"-c", keyRequest, env, n, out}
		if _, err := r.Join(ctx, s); err != nil {
			t.Fatalf("session %s: %v", n, err)
		}
		envs, outs = append(envs, env), append(outs, out)
	}
	if _, err := r.Close(ctx, session.Outcome{State: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	rg.close(t)
	for i, out := range outs {
		b, _ := os.ReadFile(out)
		e, _ := os.ReadFile(out + ".err")
		if got := strings.TrimSpace(string(b)); got != "200 0" {
			t.Errorf("session %d: curl's status and exit code %q, want 200 0; curl wrote %q", i+1, got, e)
		}
	}
	one, two := envOf(t, envs[0]), envOf(t, envs[1])
	want := link.KeyPlaceholder("model")
	if one["ANTHROPIC_API_KEY"] != want {
		t.Errorf("session 1: ANTHROPIC_API_KEY is %q, want the start key's placeholder %q", one["ANTHROPIC_API_KEY"], want)
	}
	if two["ANTHROPIC_API_KEY"] != want {
		t.Errorf("session 2: ANTHROPIC_API_KEY is %q, want the key group's placeholder %q, the one the proxy sets the active key on", two["ANTHROPIC_API_KEY"], want)
	}
	var first, second []string
	for _, g := range provider.requests() {
		who, value, _ := strings.Cut(g, " ")
		switch who {
		case "one":
			first = append(first, value)
		case "two":
			second = append(second, value)
		default:
			t.Errorf("the provider got a request of no session: %q", g)
		}
	}
	if !slices.Equal(first, []string{limitedValue, servedValue}) {
		t.Errorf("the provider got session 1's request with x-api-key %q, want model's value, refused, then model-2's value", first)
	}
	if !slices.Equal(second, []string{servedValue}) {
		t.Errorf("the provider got session 2's request with x-api-key %q, want model-2's value once", second)
	}
}

// runKeySessions runs one session per entry of models in one run of a real gateway
// whose control is c, in front of provider: each session joins with that model key,
// none for "", and its agent is keyRequest with the session's number, from 1, as
// x-test-session. It returns each session's environment, and fails the test when a
// session's request did not get a 200.
func runKeySessions(t *testing.T, provider *keyProvider, c *keyControl, models []string) []map[string]string {
	t.Helper()
	authority := filepath.Join(t.TempDir(), "provider-ca.pem")
	if err := os.WriteFile(authority, provider.ca, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.SetMachineBundles([]string{authority}))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(provider.ca)
	sp := spec(t)
	sp.Forwarder = nil
	cfg := gateway.Config{Server: c.server(), Version: "test", Heartbeat: time.Second,
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost"}}}}
	trustUpstream(t, &cfg, roots)
	rg := startGateway(t, &sp, cfg)
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var envs, outs []string
	for i, model := range models {
		n := fmt.Sprint(i + 1)
		env, out := filepath.Join(dir, "env-"+n), filepath.Join(dir, "curl-"+n)
		s := sp.SessionSpec
		s.ModelCredential = model
		s.Command, s.Args = installedShell, []string{"-c", keyRequest, env, n, out}
		if _, err := r.Join(ctx, s); err != nil {
			t.Fatalf("session %s: %v", n, err)
		}
		envs, outs = append(envs, env), append(outs, out)
	}
	if _, err := r.Close(ctx, session.Outcome{State: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	rg.close(t)
	var got []map[string]string
	for i, out := range outs {
		b, _ := os.ReadFile(out)
		e, _ := os.ReadFile(out + ".err")
		if status := strings.TrimSpace(string(b)); status != "200 0" {
			t.Errorf("session %d: curl's status and exit code %q, want 200 0; curl wrote %q", i+1, status, e)
		}
		got = append(got, envOf(t, envs[i]))
	}
	return got
}

// TestASessionOnAnotherGroupGetsThatGroupsPlaceholder pins two key groups whose keys
// alternate in the run configuration, end to end through a real gateway: a with the
// start key a-1 and a-2, and b with b-1 and b-2. Session 1 joins with no key in its
// request and gets a-1's placeholder; its request reaches the provider with a-1's
// value. Session 2 joins with b-2, of group b, which no session used: it gets b-1's
// placeholder, the placeholder of group b's first key, which the proxy sets b-2 on, and
// its request reaches the provider with b-2's value.
func TestASessionOnAnotherGroupGetsThatGroupsPlaceholder(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("the agent sends its request with curl, and this machine has none")
	}
	provider := newKeyProvider(t)
	credential := func(name, group string) string {
		return `{"name":"` + name + `","group":"` + group + `","format":"anthropic-messages","endpoint":"https://` + provider.host + `/v1","auth":{"scheme":"header","header":"x-api-key"}}`
	}
	values := map[string]string{"a-1": "fake-a-value-0001", "b-1": "fake-b-value-0001", "a-2": "fake-a-value-0002", "b-2": "fake-b-value-0002"}
	c := newKeyControlOf(t, credential("a-1", "a")+`,`+credential("b-1", "b")+`,`+credential("a-2", "a")+`,`+credential("b-2", "b"), "a-1", values)
	envs := runKeySessions(t, provider, c, []string{"", "b-2"})
	if got, want := envs[0]["ANTHROPIC_API_KEY"], link.KeyPlaceholder("a-1"); got != want {
		t.Errorf("session 1: ANTHROPIC_API_KEY is %q, want %q", got, want)
	}
	if got, want := envs[1]["ANTHROPIC_API_KEY"], link.KeyPlaceholder("b-1"); got != want {
		t.Errorf("session 2: ANTHROPIC_API_KEY is %q, want group b's placeholder %q", got, want)
	}
	if got, want := provider.requests(), []string{"1 " + values["a-1"], "2 " + values["b-2"]}; !slices.Equal(got, want) {
		t.Errorf("the provider got %q, want %q", got, want)
	}
}
