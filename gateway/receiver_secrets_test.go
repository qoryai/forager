package gateway_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/server"
)

// The records of the reference receiver of these tests: a node of its own that reports
// directly, under testKey, the gateway's access key on its local link; and a node pool
// of refWorkspace whose choice is the gateway refGateway, which lives at refWorkspace
// and whose one access key is refGatewayKey.
const (
	refPool       = "np_f1xt0re00000000r"
	refPoolKey    = "ak_f1xt0re00000000p"
	refGateway    = "ng_f1xt0re00000000r"
	refGatewayKey = "ak_f1xt0re00000000r"
	refWorkspace  = testWorkspace
	refValue      = "sealed-by-the-reference-receiver"
)

// refPoolSecret is the node pool's access key, which registers the runs through the
// gateway; fresh, as every key of these tests.
var refPoolSecret = mustGenerate()

// reference is the reference receiver as a server of the contract for a gateway: the
// gateway's access key, the pool's when the gateway is separate, every key allowed stored
// secrets; a run configuration with the credential model on origin, the TLS origin of
// the test; and refValue as model's value.
type reference struct {
	srv    *httptest.Server
	h      *receiver.Handler
	store  *receiver.File
	stored string
	doc    []byte

	mu     sync.Mutex
	logged []string
	asked  [][]string
}

func newReference(t *testing.T, origin string) *reference {
	t.Helper()
	ref := &reference{stored: filepath.Join(t.TempDir(), "received.jsonl")}
	store, err := receiver.OpenFile(ref.stored)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ref.store = store
	ref.doc = []byte(`{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["` + origin + `"]}},` +
		`"credentials":[{"name":"model","hosts":["` + origin + `"],"paths":["/v1/*"],"auth":{"scheme":"header","header":"x-api-key"},"key_variables":["MODEL_API_KEY"],"placeholders":["MODEL_API_KEY"]}]}`)
	keys := map[string]receiver.AccessKey{
		testKey:       {PublicKey: testAccessKey.PublicKey(), StoredSecrets: true},
		refPoolKey:    {PublicKey: refPoolSecret.PublicKey(), Node: refPool},
		refGatewayKey: {PublicKey: testAccessKey.PublicKey(), Node: refGateway, StoredSecrets: true},
	}
	ref.h = &receiver.Handler{
		Keys:          func(id string) (receiver.AccessKey, bool) { k, ok := keys[id]; return k, ok },
		Signer:        testSigner,
		Store:         store,
		Nodes:         map[string]receiver.Node{refPool: {Workspace: refWorkspace, Gateway: refGateway}},
		Workspaces:    map[string]receiver.Workspace{refWorkspace: {Organisation: "org_ref"}},
		Organisations: map[string]receiver.Organisation{"org_ref": {}},
		Gateways:      map[string]receiver.Gateway{refGateway: {URL: "https://gateway.example:8443", Workspace: refWorkspace, AccessKeys: []string{refGatewayKey}}},
		Configuration: func() ([]byte, string) {
			pin, _ := json.Marshal(testPin)
			doc := []byte(`{"version":1,"node_id":"` + testNode + `","workspaces":["` + refWorkspace + `"],"apiary_public_key":` + string(pin) +
				`,"events":{"url":"` + ref.srv.URL + receiver.DefaultEventsPath + `","types":["*"]},"run":{"url":"` + ref.srv.URL + receiver.DefaultRunPath +
				`"},"secrets":{"url":"` + ref.srv.URL + receiver.DefaultSecretsPath + `"}}`)
			return doc, digestOf(string(doc))
		},
		RunConfiguration: func(receiver.Run) ([]byte, string, *receiver.Refusal) { return ref.doc, "", nil },
		Secrets: func(_ receiver.Run, names []string) ([][]byte, *receiver.Refusal) {
			ref.mu.Lock()
			ref.asked = append(ref.asked, names)
			ref.mu.Unlock()
			var values [][]byte
			for range names {
				values = append(values, []byte(refValue))
			}
			return values, nil
		},
		Log: func(l string) {
			ref.mu.Lock()
			ref.logged = append(ref.logged, l)
			ref.mu.Unlock()
		},
	}
	ref.srv = httptest.NewServer(ref.h)
	t.Cleanup(ref.srv.Close)
	return ref
}

// server is the gateway's server document for the receiver, under the access key id.
func (ref *reference) server(id string) *gateway.Server {
	return &gateway.Server{Version: 1, URL: ref.srv.URL, AccessKeyID: id, ApiaryPublicKey: testPin, AccessKey: testAccessKey, InstanceID: testInstance}
}

// registerThroughGateway registers a run under the pool's key and returns its run key.
func (ref *reference) registerThroughGateway(t *testing.T, runID string) string {
	t.Helper()
	c := &server.Client{Config: &server.Config{Version: 1, URL: ref.srv.URL, AccessKeyID: refPoolKey, ApiaryPublicKey: testPin}, Key: refPoolSecret,
		InstanceID: "i_pool", UserAgent: "qory-forager/test"}
	body, err := server.GatewayRegistration{RunID: runID}.Body()
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.RegisterThroughGateway(context.Background(), ref.srv.URL+receiver.DefaultRunPath, body)
	if err != nil {
		t.Fatal(err)
	}
	return a.RunKey
}

// origin is an HTTPS origin on this machine, under the test's authority, which records
// the x-api-key of every request it gets.
type origin struct {
	srv  *httptest.Server
	host string
	mu   sync.Mutex
	got  []string
}

func newOrigin(t *testing.T, certFile, keyFile string) *origin {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	o := &origin{}
	o.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.got = append(o.got, r.Method+" "+r.URL.Path+" "+r.Header.Get("X-Api-Key"))
		o.mu.Unlock()
		io.WriteString(w, "origin")
	}))
	o.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	o.srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	o.srv.StartTLS()
	t.Cleanup(o.srv.Close)
	_, port, _ := net.SplitHostPort(o.srv.Listener.Addr().String())
	o.host = "localhost:" + port
	return o
}

// requests are what the origin got.
func (o *origin) requests() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.got)
}

// throughProxy sends a GET of the model credential's path to the origin through client,
// a client of the run's proxy that trusts the run's authority, with the session's
// placeholder in x-api-key, as the agent sends it.
func throughProxy(t *testing.T, client *http.Client, authority string, o *origin) int {
	t.Helper()
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM([]byte(authority))
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: trusted}
	req, _ := http.NewRequest(http.MethodGet, "https://"+o.host+"/v1/models", nil)
	req.Header.Set("X-Api-Key", link.Placeholder)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("the request through the proxy: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// aroundProxy sends a GET of the model credential's path to the origin without the
// proxy, trusting roots, with the session's placeholder in x-api-key, as an unwalled
// agent that ignores the proxy sends it.
func aroundProxy(t *testing.T, roots *x509.CertPool, o *origin) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots}}}
	req, _ := http.NewRequest(http.MethodGet, "https://"+o.host+"/v1/models", nil)
	req.Header.Set("X-Api-Key", link.Placeholder)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("the request around the proxy: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// noValueIn fails the test when refValue is in a file under one of the directories, in
// the receiver's store or log, or in the run answer as the gateway sent it.
func noValueIn(t *testing.T, ref *reference, answer any, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
			if err == nil && e.Type().IsRegular() {
				if b, err := os.ReadFile(p); err == nil && bytes.Contains(b, []byte(refValue)) {
					t.Errorf("%s holds the value", p)
				}
			}
			return nil
		})
	}
	if b, err := os.ReadFile(ref.stored); err != nil || bytes.Contains(b, []byte(refValue)) || !bytes.Contains(b, []byte(event.RunExited)) {
		t.Errorf("the receiver's store holds the value, or not the run's events: %v\n%s", err, b)
	}
	ref.mu.Lock()
	defer ref.mu.Unlock()
	for _, l := range ref.logged {
		if strings.Contains(l, refValue) {
			t.Errorf("the receiver logged the value: %s", l)
		}
	}
	if b, _ := json.Marshal(answer); bytes.Contains(b, []byte(refValue)) {
		t.Errorf("the run answer holds the value: %s", b)
	}
}

// placeholdersOnly checks the run answer: the session gets MODEL_API_KEY as the one
// variable to set to its placeholder, and model's hosts, and no value.
func placeholdersOnly(t *testing.T, a *server.LinkRunAnswer, o *origin) {
	t.Helper()
	host, _, _ := net.SplitHostPort(o.host)
	if !slices.Equal(a.Placeholders, []string{"MODEL_API_KEY"}) || len(a.CredentialHosts) != 1 || a.CredentialHosts[0].Name != "model" ||
		!slices.Equal(a.CredentialHosts[0].Hosts, []string{host}) {
		t.Errorf("the run answer's placeholders %v and credential hosts %+v; want MODEL_API_KEY for model on %s", a.Placeholders, a.CredentialHosts, host)
	}
}

// TestASealedCredentialFromTheReferenceReceiverReachesTheOrigin runs the secrets
// request end to end against the reference receiver, without Docker: a walled run's
// gateway fetches the run configuration, sends the secrets request, opens the sealed
// answer with the pin of its server document, and the run's proxy sets the value on a
// request to an HTTPS origin on this machine, in place of the session's placeholder.
// As the run starts, a gateway on its local link registers the run directly; behind a
// separate gateway, a node pool registers the run and the gateway attaches it with the
// run key, then reloads it for the digest of the document's bytes. In each case the
// receiver is asked for the credential model once; the origin gets the value in
// x-api-key; the run answer has MODEL_API_KEY as its one placeholder and no value; and
// no record, report, stored event or log line of the receiver contains the value. A run
// without a wall is brokered the same way, and a request it sends around the proxy
// reaches the origin with the placeholder alone.
func TestASealedCredentialFromTheReferenceReceiverReachesTheOrigin(t *testing.T) {
	for _, wall := range []bool{true, false} {
		t.Run(fmt.Sprintf("wall %v", wall), func(t *testing.T) { sealedReachesTheOrigin(t, wall) })
	}
}

// sealedReachesTheOrigin is TestASealedCredentialFromTheReferenceReceiverReachesTheOrigin
// for a walled run or an unwalled one.
func sealedReachesTheOrigin(t *testing.T, wall bool) {
	node := &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost"}}}
	want := []string{"GET /v1/models " + refValue}
	if !wall {
		want = append(want, "GET /v1/models "+link.Placeholder)
	}
	t.Run("start", func(t *testing.T) {
		certFile, keyFile, roots := testCertificate(t, t.TempDir())
		o := newOrigin(t, certFile, keyFile)
		ref := newReference(t, "localhost")
		cfg := gateway.Config{Server: ref.server(testKey), Policy: node}
		gateway.SetUpstreamRoots(&cfg, roots)
		h := start(t, cfg)
		h.secrets = append(h.secrets, refValue)
		a := h.open(server.LinkRunRequest{Wall: wall})
		if status := throughProxy(t, relay(h.g.Addr(), a.ProxySecret), a.CertificateAuthority, o); status != http.StatusOK {
			t.Errorf("the origin answered %d", status)
		}
		if !wall {
			aroundProxy(t, roots, o)
		}
		if got := o.requests(); !slices.Equal(got, want) {
			t.Errorf("the origin got %q; want %q", got, want)
		}
		placeholdersOnly(t, a, o)
		h.post(started(a.RunID, nil), applied(a.RunID, a.Applied), exited(a.RunID))
		h.close()
		ref.mu.Lock()
		asked := slices.Clone(ref.asked)
		ref.mu.Unlock()
		if len(asked) != 1 || !slices.Equal(asked[0], []string{"model"}) {
			t.Errorf("the receiver was asked for %v, want model once", asked)
		}
		eventually(t, "the run's events at the receiver", func() bool {
			b, _ := os.ReadFile(ref.stored)
			return bytes.Contains(b, []byte(event.RunExited))
		})
		noValueIn(t, ref, a, h.dir)
	})
	t.Run("attach", func(t *testing.T) {
		certFile, keyFile, roots := testCertificate(t, t.TempDir())
		o := newOrigin(t, certFile, keyFile)
		ref := newReference(t, "localhost")
		cfg := gateway.Config{Server: ref.server(refGatewayKey), Policy: node}
		gateway.SetUpstreamRoots(&cfg, roots)
		r := startRemote(t, nil, cfg)
		runID := event.NewRunID()
		key := ref.registerThroughGateway(t, runID)
		e := r.open(t, key, server.LinkRunRequest{Wall: wall})
		if status := throughProxy(t, r.relay(t, key), e.a.CertificateAuthority, o); status != http.StatusOK {
			t.Errorf("the origin answered %d", status)
		}
		if !wall {
			aroundProxy(t, roots, o)
		}
		if got := o.requests(); !slices.Equal(got, want) {
			t.Errorf("the origin got %q; want %q", got, want)
		}
		placeholdersOnly(t, e.a, o)
		if got := e.post(t, exited(runID)); got.status != http.StatusAccepted {
			t.Fatalf("the last batch: %d %s", got.status, got.body)
		}
		ref.mu.Lock()
		asked := slices.Clone(ref.asked)
		ref.mu.Unlock()
		if len(asked) != 1 || !slices.Equal(asked[0], []string{"model"}) {
			t.Errorf("the receiver was asked for %v, want model once", asked)
		}
		eventually(t, "the run's events at the receiver", func() bool {
			b, _ := os.ReadFile(ref.stored)
			return bytes.Contains(b, []byte(event.RunExited))
		})
		r.mu.Lock()
		reports := slices.Clone(r.reports)
		r.mu.Unlock()
		for _, l := range reports {
			if strings.Contains(l, refValue) {
				t.Errorf("a report holds the value: %s", l)
			}
		}
		noValueIn(t, ref, e.a, r.cfg.Dir)
	})
}

// relay is an HTTP client of the run's proxy behind the separate gateway: every
// connection binds to the one address as an edge does, checks the gateway's line under
// its key, then opens with the relay's preamble and the run key.
func (r *remote) relay(t *testing.T, runKey string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: "gateway.example:8443"}),
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := (&tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: r.pool, ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}}}).DialContext(ctx, "tcp", r.g.Addr())
			if err != nil {
				return nil, err
			}
			tc := c.(*tls.Conn)
			ekm, err := binding(tc.ConnectionState())
			if err == nil {
				_, err = io.WriteString(tc, link.BindLine)
			}
			br := bufio.NewReader(tc)
			if err == nil {
				err = readBound(br, ekm, gatewayKeys())
			}
			if err == nil {
				_, err = io.WriteString(tc, link.RelayLine(runKey))
			}
			if err != nil {
				tc.Close()
				return nil, err
			}
			return &bound{c: tc, r: br, ekm: ekm}, nil
		},
		DisableKeepAlives: true,
	}}
}
