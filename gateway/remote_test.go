package gateway_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/server"
)

// The runs of these tests open on a separate gateway's one address, by a run key the
// control's signing key signs, as an edge of the link sends them: on a bound connection,
// every answer's signature checked under the gateway's key.

// The run key's values: the node that registered the run, and its instance.
const (
	keyNode     = "np_f1xt0re000000000"
	keyInstance = "i_gYKDhIWGh4iJiouMjY6PkA"
)

// testCertificate writes a certificate for 127.0.0.1, ::1 and localhost, and its key,
// into dir, signed by an authority of the test's own, which pool trusts.
func testCertificate(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test authority"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "gateway.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost", "gateway.example"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "gateway.pem"), filepath.Join(dir, "gateway-key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(ca)
	return certFile, keyFile, pool
}

// runKeyFor is a run key of the run for the tests' gateway, of testWorkspace, issued a
// minute ago and attachable for ten minutes more, after change, when not nil, has had
// its say; signed under the control's signing key unless change names another.
func runKeyFor(t *testing.T, runID string, change func(*runkey.Key)) string {
	t.Helper()
	k := runkey.Key{
		RunID: runID, Workspace: testWorkspace, NodeID: keyNode, Gateway: testGateway, InstanceID: keyInstance,
		GatewayURL: "https://gateway.example:8443", GatewayKeys: []accesskey.PublicKey{testAccessKey.PublicKey()},
		Issued: time.Now().Add(-time.Minute).Truncate(time.Second), AttachBy: time.Now().Add(10 * time.Minute).Truncate(time.Second),
	}
	if change != nil {
		change(&k)
	}
	s, err := k.Sign(testSigner)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// gatewayKeys are the keys an edge pins for the tests' gateway: its access key's.
func gatewayKeys() []accesskey.PublicKey { return []accesskey.PublicKey{testAccessKey.PublicKey()} }

// remote is a separate gateway of a test, on 127.0.0.1, its access key a gateway's at
// its control, with what it reported.
type remote struct {
	t    *testing.T
	c    *control
	g    *gateway.Gateway
	cfg  gateway.Config
	pool *x509.CertPool

	mu      sync.Mutex
	reports []string
	keys    []string
}

// gatewayControl is a control whose access key is a gateway's, its discovery with no
// workspaces.
func gatewayControl(t *testing.T) *control {
	c := newControl(t)
	c.asGateway()
	return c
}

// startRemote starts a separate gateway at the control, a gatewayControl when nil, with
// cfg's Dir, Policy, Server and test settings kept, the control's Server when it has
// none. At the test's end it is closed, and no line it reported holds a run key it was
// sent.
func startRemote(t *testing.T, c *control, cfg gateway.Config) *remote {
	t.Helper()
	if c == nil {
		c = gatewayControl(t)
	}
	certFile, keyFile, pool := testCertificate(t, t.TempDir())
	r := &remote{t: t, c: c, pool: pool}
	cfg.Listen, cfg.TLS = "127.0.0.1:0", &gateway.TLS{CertFile: certFile, KeyFile: keyFile}
	if cfg.Server == nil {
		cfg.Server = c.server()
	}
	if cfg.Dir == "" {
		cfg.Dir = t.TempDir()
	}
	cfg.Report = func(line string) {
		r.mu.Lock()
		r.reports = append(r.reports, line)
		r.mu.Unlock()
		t.Log("reported: " + line)
	}
	r.cfg = cfg
	g, err := gateway.Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.g = g
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		g.Close(ctx)
		cancel()
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, line := range r.reports {
			for _, k := range r.keys {
				if strings.Contains(line, k) {
					t.Errorf("a report holds a run key: %s", line)
				}
			}
		}
	})
	return r
}

// reported reports whether the gateway reported a line that holds part.
func (r *remote) reported(part string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.reports {
		if strings.Contains(l, part) {
			return true
		}
	}
	return false
}

// record is the gateway's record of a run.
func (r *remote) record(runID string) []recorded {
	r.t.Helper()
	return readLines(r.t, filepath.Join(r.cfg.Dir, "runs", runID, "events.jsonl"))
}

// dialTLS is a TLS 1.3 connection to the one address, trusting the test's authority.
func (r *remote) dialTLS(t *testing.T) *tls.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", r.g.Addr(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: r.pool, ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(15 * time.Second))
	return c
}

// bound is a bound connection of the link, as an edge holds it: the connection, what
// reads it, and its exporter value.
type bound struct {
	c   *tls.Conn
	r   *bufio.Reader
	ekm []byte
}

// Read and Write make bound a net.Conn whose reads go through what read the binding.
func (b *bound) Read(p []byte) (int, error)         { return b.r.Read(p) }
func (b *bound) Write(p []byte) (int, error)        { return b.c.Write(p) }
func (b *bound) Close() error                       { return b.c.Close() }
func (b *bound) LocalAddr() net.Addr                { return b.c.LocalAddr() }
func (b *bound) RemoteAddr() net.Addr               { return b.c.RemoteAddr() }
func (b *bound) SetDeadline(t time.Time) error      { return b.c.SetDeadline(t) }
func (b *bound) SetReadDeadline(t time.Time) error  { return b.c.SetReadDeadline(t) }
func (b *bound) SetWriteDeadline(t time.Time) error { return b.c.SetWriteDeadline(t) }

// bind binds a fresh connection as an edge does: its BindWord line, then the gateway's
// BoundWord line, verified under keys before anything else is sent.
func (r *remote) bind(t *testing.T, keys []accesskey.PublicKey) (*bound, error) {
	t.Helper()
	c := r.dialTLS(t)
	ekm, err := binding(c.ConnectionState())
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	if _, err := io.WriteString(c, link.BindLine); err != nil {
		c.Close()
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	if err := readBound(br, ekm, keys); err != nil {
		c.Close()
		return nil, err
	}
	return &bound{c: c, r: br, ekm: ekm}, nil
}

// errNotBound is a binding line that does not prove the gateway holds a key the edge
// pins.
var errNotBound = errors.New("the gateway did not prove it holds the key")

// binding is the connection's exporter value the binding is over.
func binding(cs tls.ConnectionState) ([]byte, error) {
	return cs.ExportKeyingMaterial(link.BindingLabel, []byte{}, link.BindingSize)
}

// boundLine is the gateway's line of the binding under k for ekm.
func boundLine(k *accesskey.Key, ekm []byte) string {
	fp := k.PublicKey().Fingerprint()
	return link.BoundLine(fp, base64.RawURLEncoding.EncodeToString(k.Sign(link.BindingMessage(ekm, fp))))
}

// readBound reads the gateway's line of the binding, at most link.MaxBoundLine bytes,
// as an edge does: errNotBound unless it is BoundWord, the fingerprint of one of keys
// and that key's signature over the binding's message for ekm.
func readBound(r *bufio.Reader, ekm []byte, keys []accesskey.PublicKey) error {
	var line []byte
	for len(line) < link.MaxBoundLine {
		c, err := r.ReadByte()
		if err != nil {
			return errNotBound
		}
		line = append(line, c)
		if c == '\n' {
			break
		}
	}
	parts := strings.Split(strings.TrimSuffix(string(line), "\n"), " ")
	if !bytes.HasSuffix(line, []byte("\n")) || len(parts) != 3 || parts[0] != link.BoundWord {
		return errNotBound
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return errNotBound
	}
	for _, k := range keys {
		if k.Fingerprint() == parts[1] && k.Verify(link.BindingMessage(ekm, parts[1]), sig) {
			return nil
		}
	}
	return errNotBound
}

// verifyAnswer reports whether sig is a signature of the answer under one of keys.
func verifyAnswer(keys []accesskey.PublicKey, a accesskey.Answer, sig string) bool {
	for _, k := range keys {
		if k.VerifyAnswer(a, sig) {
			return true
		}
	}
	return false
}

// answer is an answer on a bound connection, and whether it closes the connection.
type answer struct {
	status int
	header http.Header
	body   []byte
	close  bool
}

// refusal is the answer's body as a refusal's members.
func (a answer) refusal() map[string]any { return refusalOf(a.body) }

// do sends one request on a fresh bound connection with the run key as its bearer
// value, none when empty, and the fields of extra, and returns its answer, whose
// signature it checks.
func (r *remote) do(t *testing.T, runKey, method, path string, body []byte, extra ...http.Header) answer {
	t.Helper()
	b, err := r.bind(t, gatewayKeys())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	return b.do(t, runKey, method, path, body, extra...)
}

// do sends one request on b with the run key as its bearer value, none when empty, on
// the origin gateway.example:8443, and returns its answer, whose signature it checks
// under the gateway's key over the six lines of a separate gateway's answer.
func (b *bound) do(t *testing.T, runKey, method, path string, body []byte, extra ...http.Header) answer {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://gateway.example:8443"+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if runKey != "" {
		req.Header.Set("Authorization", "Bearer "+runKey)
	}
	for _, h := range extra {
		for k, v := range h {
			req.Header[k] = v
		}
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", server.LinkContentType)
		if path == "/qory-link/events" {
			req.Header.Set("Content-Type", server.ContentType)
		}
	}
	if err := req.Write(b.c); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(b.r, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	sent := body
	if method != http.MethodPost {
		sent = nil
	}
	a := accesskey.Answer{Link: true, Status: resp.StatusCode, RequestSignature: link.AnswerRequest(b.ekm, method, req.URL.RequestURI(), sent), Body: got,
		Configuration: resp.Header.Get(server.HeaderConfiguration), RunConfiguration: resp.Header.Get(server.HeaderRunConfiguration)}
	if !verifyAnswer(gatewayKeys(), a, resp.Header.Get(server.HeaderSignature)) {
		t.Errorf("%s %s: the answer %d %s is not signed under the gateway's key for its request", method, path, resp.StatusCode, got)
	}
	return answer{status: resp.StatusCode, header: resp.Header, body: got, close: resp.Close}
}

// edgeRun is a session's run behind the gateway: its run key and the run answer.
type edgeRun struct {
	r   *remote
	key string
	a   *server.LinkRunAnswer
}

// tryOpen sends a run request of the run key's run, and returns the answer.
func (r *remote) tryOpen(t *testing.T, key string, req server.LinkRunRequest) answer {
	t.Helper()
	r.mu.Lock()
	r.keys = append(r.keys, key)
	r.mu.Unlock()
	req.Version = 1
	if req.RunID == "" {
		k, err := runkey.Parse(key)
		if err != nil {
			t.Fatal(err)
		}
		req.RunID = k.RunID
	}
	body, _ := json.Marshal(req)
	return r.do(t, key, http.MethodPost, "/qory-link/run-configuration", body)
}

// open opens a run by the run key, and starts it: its run.started and policy_applied.
func (r *remote) open(t *testing.T, key string, req server.LinkRunRequest) *edgeRun {
	t.Helper()
	a := r.tryOpen(t, key, req)
	if a.status != http.StatusOK {
		t.Fatalf("the run request: %d %s", a.status, a.body)
	}
	var ans server.LinkRunAnswer
	if err := json.Unmarshal(a.body, &ans); err != nil {
		t.Fatal(err)
	}
	e := &edgeRun{r: r, key: key, a: &ans}
	if got := e.post(t, started(ans.RunID, nil), applied(ans.RunID, ans.Applied)); got.status != http.StatusAccepted {
		t.Fatalf("the first batch: %d %s", got.status, got.body)
	}
	return e
}

// post posts one batch of the run's events.
func (e *edgeRun) post(t *testing.T, evs ...map[string]any) answer {
	t.Helper()
	body, _ := json.Marshal(evs)
	return e.r.do(t, e.key, http.MethodPost, "/qory-link/events", body)
}

// reload asks for the run's configuration again.
func (e *edgeRun) reload(t *testing.T) answer {
	t.Helper()
	return e.r.do(t, e.key, http.MethodGet, "/qory-link/run-configuration/"+e.a.RunID, nil)
}

// refusalOf decodes a refusal's body.
func refusalOf(b []byte) map[string]any {
	var r map[string]any
	json.Unmarshal(b, &r)
	return r
}

// refused checks an answer is the refusal with the status, code, who refused and text.
func refused(t *testing.T, what string, a answer, status int, code, from, text string) {
	t.Helper()
	r := a.refusal()
	if a.status != status || r["error"] != code || r["from"] != from || r["message"] != text {
		t.Errorf("%s: %d %s; want %d %s from %s, %q", what, a.status, a.body, status, code, from, text)
	}
}

// keyInvalid is the gateway's refusal text of a request without a run key it accepts.
const keyInvalid = "the gateway refused the run: run_key_invalid"

// attachLine is the text of a refusal of the run's attach with the code, a 409.
func (r *remote) attachLine(runID, code string) string {
	return fmt.Sprintf("attach %s%s/%s: %s (status 409)", r.c.srv.URL, runsPath, runID, code)
}

// validDocument fails the test unless b is valid under the schema.
func validDocument(t *testing.T, schemaName string, b []byte) {
	t.Helper()
	schema, err := contracts.Compile(schemaName)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := contracts.Decode("doc.json", b)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Errorf("%s: %v: %s", schemaName, err, b)
	}
}

// TestStartRefusesAnAddressItCannotServe pins Start's checks of the one address: an
// address that is not host:port, one without TLS, one without a server, TLS files it
// cannot read or that do not match, TLS without an address, each before anything
// starts, its error never holding the key; and once discovery is read, an access key
// that is not a gateway's with an address, and a gateway's without one.
func TestStartRefusesAnAddressItCannotServe(t *testing.T) {
	dir := t.TempDir()
	c := gatewayControl(t)
	certFile, keyFile, _ := testCertificate(t, t.TempDir())
	_, otherKey, _ := testCertificate(t, t.TempDir())
	tlsOf := func(cert, key string) *gateway.TLS { return &gateway.TLS{CertFile: cert, KeyFile: key} }
	srv := c.server()
	for name, cfg := range map[string]gateway.Config{
		"not host:port":                 {Dir: dir, Listen: "127.0.0.1", TLS: tlsOf(certFile, keyFile), Server: srv},
		"a port out of range":           {Dir: dir, Listen: "127.0.0.1:65536", TLS: tlsOf(certFile, keyFile), Server: srv},
		"a port that is no number":      {Dir: dir, Listen: "127.0.0.1:https", TLS: tlsOf(certFile, keyFile), Server: srv},
		"loopback without TLS":          {Dir: dir, Listen: "127.0.0.1:0", Server: srv},
		"every address without TLS":     {Dir: dir, Listen: ":0", Server: srv},
		"no server":                     {Dir: dir, Listen: "127.0.0.1:0", TLS: tlsOf(certFile, keyFile)},
		"a certificate file not there":  {Dir: dir, Listen: "127.0.0.1:0", TLS: tlsOf(filepath.Join(dir, "none.pem"), keyFile), Server: srv},
		"a key file not there":          {Dir: dir, Listen: "127.0.0.1:0", TLS: tlsOf(certFile, filepath.Join(dir, "none.pem")), Server: srv},
		"no files":                      {Dir: dir, Listen: "127.0.0.1:0", TLS: &gateway.TLS{}, Server: srv},
		"a key of another certificate":  {Dir: dir, Listen: "127.0.0.1:0", TLS: tlsOf(certFile, otherKey), Server: srv},
		"a certificate without address": {Dir: dir, TLS: tlsOf(certFile, keyFile)},
		"the key in place of the cert":  {Dir: dir, Listen: "127.0.0.1:0", TLS: tlsOf(keyFile, keyFile), Server: srv},
	} {
		g, err := gateway.Start(context.Background(), cfg)
		if err == nil {
			g.Close(context.Background())
			t.Errorf("%s: started", name)
			continue
		}
		if b, _ := os.ReadFile(keyFile); strings.Contains(err.Error(), string(b[30:60])) {
			t.Errorf("%s: the error holds the key: %v", name, err)
		}
	}
	for _, c := range []struct {
		cfg  gateway.Config
		want string
	}{
		{gateway.Config{Dir: dir, Listen: "127.0.0.1:0", Server: srv}, "the gateway's address 127.0.0.1:0 needs TLS, a certificate and its key: every connection of the link there is bound to its TLS"},
		{gateway.Config{Dir: dir, Listen: "127.0.0.1:0", TLS: tlsOf(certFile, keyFile)}, "the gateway's address 127.0.0.1:0 needs a server and a gateway's access key: the gateway attaches each run there"},
	} {
		if _, err := gateway.Start(context.Background(), c.cfg); err == nil || err.Error() != c.want {
			t.Errorf("%v; want %q", err, c.want)
		}
	}
	// A node's access key serves no address.
	node := newControl(t)
	_, err := gateway.Start(context.Background(), gateway.Config{Dir: dir, Listen: "127.0.0.1:0", TLS: tlsOf(certFile, keyFile), Server: node.server()})
	if want := "the access key's node " + testNode + " is not a gateway, ng_: the gateway's address 127.0.0.1:0 needs a gateway's access key"; err == nil || err.Error() != want {
		t.Errorf("a node's key: %v; want %q", err, want)
	}
	// A gateway's access key serves no local link: before anything is served, the
	// gateway without an address refuses it.
	g, err := gateway.Start(context.Background(), gateway.Config{Dir: dir, Server: gatewayControl(t).server()})
	if want := "the access key's node " + testGateway + " is a gateway, ng_: a gateway without an address needs a node's access key, nd_ or np_"; err == nil || err.Error() != want || g != nil {
		if g != nil {
			g.Close(context.Background())
		}
		t.Errorf("a gateway's key without an address: %v; want %q", err, want)
	}
}

// TestASeparateGatewayRunsNoSessions pins D-4: a gateway with an address makes no link
// directory, no socket and no proxy on loopback; its local link has no socket and no
// proxy, and every connection to it fails, saying why; its one address is its proxy's.
func TestASeparateGatewayRunsNoSessions(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	l := r.g.LocalLink()
	if l.Socket != "" || l.Proxy != "" {
		t.Errorf("the local link of a separate gateway: socket %q, proxy %q", l.Socket, l.Proxy)
	}
	if _, err := l.DialContext(context.Background()); err == nil || err.Error() != "the gateway serves other machines on its address, and runs no sessions" {
		t.Errorf("a connection to its local link: %v", err)
	}
	if entries, _ := filepath.Glob(filepath.Join(os.TempDir(), "qory-link-*", "sock")); len(entries) > 0 {
		for _, e := range entries {
			if strings.Contains(e, r.cfg.Dir) {
				t.Errorf("a socket %s", e)
			}
		}
	}
	if got := r.g.String(); got != "gateway.Gateway{address "+r.g.Addr()+"}" {
		t.Errorf("String %s", got)
	}
}

// TestTheOneAddressIsTLS13Only pins TLS on the one address: 1.3 with the operator's
// certificate; an earlier version is refused in the handshake, and plain HTTP is no
// request.
func TestTheOneAddressIsTLS13Only(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10} {
		if c, err := tls.Dial("tcp", r.g.Addr(), &tls.Config{MinVersion: version, MaxVersion: version, RootCAs: r.pool, ServerName: "127.0.0.1"}); err == nil {
			c.Close()
			t.Errorf("TLS version %#x was served", version)
		}
	}
	c := r.dialTLS(t)
	if st := c.ConnectionState(); st.Version != tls.VersionTLS13 || st.PeerCertificates[0].Subject.CommonName != "gateway.example" {
		t.Errorf("version %#x, certificate %s", st.Version, st.PeerCertificates[0].Subject)
	}
	c.Close()
	p, err := net.Dial("tcp", r.g.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(p, link.BindWord+"\nGET /qory-link/configuration HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	if b, _ := io.ReadAll(p); bytes.Contains(b, []byte("HTTP/1.1")) || bytes.Contains(b, []byte(link.BoundWord)) {
		t.Errorf("plain TCP was answered: %q", b)
	}
}

// fakeGateway serves one TLS 1.3 connection per call of line on a listener of its own,
// answering the edge's BindWord line with the line line makes of the connection's
// exporter value, as a gateway that does not hold its key would.
func fakeGateway(t *testing.T, line func(ekm []byte) string) (addr string, pool *x509.CertPool) {
	t.Helper()
	certFile, keyFile, pool := testCertificate(t, t.TempDir())
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := c.(*tls.Conn)
				if tc.Handshake() != nil {
					return
				}
				b := make([]byte, len(link.BindLine))
				if _, err := io.ReadFull(tc, b); err != nil {
					return
				}
				ekm, _ := binding(tc.ConnectionState())
				io.WriteString(tc, line(ekm))
				io.Copy(io.Discard, tc)
			}()
		}
	}()
	return ln.Addr().String(), pool
}

// TestTheBinding pins the binding of a connection to the one address: the gateway's
// BoundWord line is its key's signature over the connection's exporter value, which an
// edge that pins the key verifies; an edge that pins another key refuses it. A proof
// over another connection's exporter value, under another key in the gateway's
// fingerprint, a signature cut short, or a line that is not one, is ErrNotBound. Every
// answer is bound to its connection and its request: its signature verifies over its
// own request line alone.
func TestTheBinding(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	b, err := r.bind(t, gatewayKeys())
	if err != nil {
		t.Fatalf("the binding under the gateway's key: %v", err)
	}
	key := runKeyFor(t, event.NewRunID(), nil)
	a := b.do(t, key, http.MethodGet, "/qory-link/configuration", nil)
	b.Close()
	if a.status != http.StatusOK {
		t.Fatalf("the discovery: %d %s", a.status, a.body)
	}
	other := mustGenerate()
	if _, err := r.bind(t, []accesskey.PublicKey{other.PublicKey()}); !errors.Is(err, errNotBound) {
		t.Errorf("an edge that pins another key: %v", err)
	}
	// The answer's signature is over its own request: another connection's exporter
	// value, method, target or body is not it.
	for name, req := range map[string]string{
		"another exporter value": link.AnswerRequest(bytes.Repeat([]byte{7}, link.BindingSize), http.MethodGet, "/qory-link/configuration", nil),
		"another target":         link.AnswerRequest(b.ekm, http.MethodGet, "/qory-link/configuration?x=1", nil),
		"another method":         link.AnswerRequest(b.ekm, http.MethodPost, "/qory-link/configuration", nil),
	} {
		ans := accesskey.Answer{Link: true, Status: a.status, RequestSignature: req, Body: a.body, Configuration: a.header.Get(server.HeaderConfiguration), RunConfiguration: a.header.Get(server.HeaderRunConfiguration)}
		if verifyAnswer(gatewayKeys(), ans, a.header.Get(server.HeaderSignature)) {
			t.Errorf("the answer verifies over %s", name)
		}
	}

	fp := testAccessKey.PublicKey().Fingerprint()
	for name, line := range map[string]func(ekm []byte) string{
		"another connection's exporter value": func([]byte) string {
			return boundLine(testAccessKey, bytes.Repeat([]byte{1}, link.BindingSize))
		},
		"another key in the gateway's fingerprint": func(ekm []byte) string {
			sig := other.Sign(link.BindingMessage(ekm, fp))
			return link.BoundWord + " " + fp + " " + base64.RawURLEncoding.EncodeToString(sig) + "\n"
		},
		"another key's line": func(ekm []byte) string { return boundLine(other, ekm) },
		"a signature cut short": func(ekm []byte) string {
			l := boundLine(testAccessKey, ekm)
			return l[:len(l)-10] + "\n"
		},
		"no signature": func([]byte) string { return link.BoundWord + " " + fp + "\n" },
		"an HTTP answer": func([]byte) string {
			return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
		},
		"nothing": func([]byte) string { return "" },
	} {
		addr, pool := fakeGateway(t, line)
		c, err := tls.Dial("tcp", addr, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "127.0.0.1"})
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		ekm, _ := binding(c.ConnectionState())
		io.WriteString(c, link.BindLine)
		if name == "nothing" {
			c.CloseWrite()
		}
		if err := readBound(bufio.NewReader(c), ekm, gatewayKeys()); !errors.Is(err, errNotBound) {
			t.Errorf("%s: %v; want ErrNotBound", name, err)
		}
		c.Close()
	}
}

// TestTheOneAddressRoutesByTheFirstBytes pins the routing on the one address: a
// connection whose first line is not BindWord is the relay's, which answers a path of
// the link 404 unsigned; on a bound connection, the relay's preamble with a run key of
// no live run here, or one the gateway refuses, is closed unanswered, and with a live
// run's run key it reaches that run's proxy, which decides each request by its policy.
func TestTheOneAddressRoutesByTheFirstBytes(t *testing.T) {
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	t.Cleanup(o.Close)
	r := startRemote(t, nil, gateway.Config{Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"127.0.0.1"}}}})
	key := runKeyFor(t, event.NewRunID(), nil)

	c := r.dialTLS(t)
	req, _ := http.NewRequest(http.MethodGet, "https://gateway.example:8443/qory-link/configuration", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Write(c)
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	c.Close()
	if err != nil || resp.StatusCode != http.StatusNotFound || resp.Header.Get(server.HeaderSignature) != "" {
		t.Errorf("an unbound request of the link: %v %v", resp, err)
	}

	relayed := func(runKey string) *http.Client {
		return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: r.g.Addr()}),
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				b, err := r.bind(t, gatewayKeys())
				if err != nil {
					return nil, err
				}
				io.WriteString(b, link.RelayPreamble+" "+runKey+"\n")
				return b, nil
			},
			DisableKeepAlives: true,
		}}
	}
	if _, err := relayed(key).Get(o.URL); err == nil {
		t.Error("the relay of a run not open here was answered")
	}
	if _, err := relayed("qrk_not.a-run-key").Get(o.URL); err == nil {
		t.Error("the relay of no run key was answered")
	}
	e := r.open(t, key, server.LinkRunRequest{})
	resp, err = relayed(key).Get(o.URL)
	if err != nil {
		t.Fatalf("the relay of the run: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(b) != "ok" {
		t.Errorf("the relay of the run: %d %q", resp.StatusCode, b)
	}
	if e.a.ProxySecret != "" {
		t.Error("the run answer gives a proxy secret")
	}
	// A run key of the live run that no pinned key signed opens nothing.
	unpinned, err := runkey.Key{RunID: e.a.RunID, Workspace: testWorkspace, NodeID: keyNode, Gateway: testGateway, InstanceID: keyInstance,
		GatewayURL: "https://gateway.example:8443", GatewayKeys: gatewayKeys(), Issued: time.Now().Truncate(time.Second), AttachBy: time.Now().Add(time.Hour).Truncate(time.Second)}.Sign(mustGenerate())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relayed(unpinned).Get(o.URL); err == nil {
		t.Error("the relay of the live run with a run key no pinned key signed was answered")
	}
}

// TestABatchBehindTheGatewayIsOfItsRunKeysRun pins the run of a batch behind a separate
// gateway: the run of its run key alone, whatever X-Qory-Run-Id it carries; a batch of
// run A's events with A's run key and B's run id goes to A, and B's record gets nothing
// of it.
func TestABatchBehindTheGatewayIsOfItsRunKeysRun(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	a := r.open(t, runKeyFor(t, event.NewRunID(), nil), server.LinkRunRequest{})
	b := r.open(t, runKeyFor(t, event.NewRunID(), nil), server.LinkRunRequest{})
	beat := heartbeat(a.a.RunID)
	body, _ := json.Marshal([]map[string]any{beat})
	if got := r.do(t, a.key, http.MethodPost, "/qory-link/events", body, http.Header{server.HeaderRunID: {b.a.RunID}}); got.status != http.StatusAccepted {
		t.Fatalf("the batch: %d %s", got.status, got.body)
	}
	has := func(runID string) bool {
		for _, l := range r.record(runID) {
			if l.ID == beat["id"] {
				return true
			}
		}
		return false
	}
	eventually(t, "the heartbeat in A's record", func() bool { return has(a.a.RunID) })
	if has(b.a.RunID) {
		t.Error("B's record has A's heartbeat")
	}
	if got := b.post(t, heartbeat(b.a.RunID)); got.status != http.StatusAccepted {
		t.Errorf("B after: %d %s", got.status, got.body)
	}
}

// TestEveryRequestCarriesAnAcceptedRunKey pins the run key on the one address, in
// order, on every path: none, two, another scheme, one that is no run key or that no
// pinned key signed, is 400 run_key_invalid; then in the server's order of the attach,
// past its attach_by plus the 300 s skew with nothing of the run here 409
// run_key_expired, before one of
// another gateway 409 wrong_gateway. Each 409 reads as the server's
// refusal of the attach. A run key of any workspace passes. A run key past its attach_by of a run the gateway holds goes
// on. Each answer is signed, and nothing is attached.
func TestEveryRequestCarriesAnAcceptedRunKey(t *testing.T) {
	var now time.Time
	var mu sync.Mutex
	cfg := gateway.Config{}
	gateway.SetNow(&cfg, func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		if now.IsZero() {
			return time.Now()
		}
		return now
	})
	r := startRemote(t, nil, cfg)
	runID := event.NewRunID()
	good := runKeyFor(t, runID, nil)
	unpinned, err := runkey.Key{RunID: runID, Workspace: testWorkspace, NodeID: keyNode, Gateway: testGateway, InstanceID: keyInstance,
		GatewayURL: "https://gateway.example:8443", GatewayKeys: gatewayKeys(), Issued: time.Now().Truncate(time.Second), AttachBy: time.Now().Add(time.Hour).Truncate(time.Second)}.Sign(mustGenerate())
	if err != nil {
		t.Fatal(err)
	}
	paths := []struct{ method, path string }{
		{http.MethodGet, "/qory-link/configuration"},
		{http.MethodPost, "/qory-link/run-configuration"},
		{http.MethodGet, "/qory-link/run-configuration/" + runID},
		{http.MethodPost, "/qory-link/events"},
		{http.MethodGet, "/qory-link/nothing"},
	}
	send := func(header []string, method, path string) answer {
		b, err := r.bind(t, gatewayKeys())
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		req, _ := http.NewRequest(method, "https://gateway.example:8443"+path, nil)
		req.Header["Authorization"] = header
		req.Write(b.c)
		resp, err := http.ReadResponse(b.r, req)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		a := accesskey.Answer{Link: true, Status: resp.StatusCode, RequestSignature: link.AnswerRequest(b.ekm, method, path, nil), Body: got, Configuration: resp.Header.Get(server.HeaderConfiguration)}
		if !verifyAnswer(gatewayKeys(), a, resp.Header.Get(server.HeaderSignature)) {
			t.Errorf("%s %s: an unsigned refusal", method, path)
		}
		return answer{status: resp.StatusCode, header: resp.Header, body: got}
	}
	for name, header := range map[string][]string{
		"no Authorization":    nil,
		"two run keys":        {"Bearer " + good, "Bearer " + good},
		"Basic":               {"Basic " + base64.StdEncoding.EncodeToString([]byte(":"+good))},
		"Basic, the run key":  {"Basic " + good},
		"Digest, the run key": {"Digest " + good},
		"no run key":          {"Bearer not-a-run-key"},
		"a key no pin signed": {"Bearer " + unpinned},
		"a run key cut short": {"Bearer " + good[:len(good)-4]},
	} {
		for _, p := range paths {
			refused(t, name+" "+p.path, send(header, p.method, p.path), http.StatusBadRequest, "run_key_invalid", "gateway", keyInvalid)
		}
	}
	for name, c := range map[string]struct {
		change func(*runkey.Key)
		code   string
	}{
		"another gateway's": {func(k *runkey.Key) { k.Gateway = "ng_0therg4teway0000" }, "wrong_gateway"},
		"past its attach_by and the skew": {func(k *runkey.Key) {
			k.AttachBy = time.Now().Add(-400 * time.Second).Truncate(time.Second)
			k.Issued = k.AttachBy.Add(-time.Minute)
		}, "run_key_expired"},
		"another gateway's, late": {func(k *runkey.Key) {
			k.Gateway, k.AttachBy, k.Issued = "ng_0therg4teway0000", time.Now().Add(-400*time.Second).Truncate(time.Second), time.Now().Add(-time.Hour).Truncate(time.Second)
		}, "run_key_expired"},
		"another workspace's, late": {func(k *runkey.Key) {
			k.Workspace, k.AttachBy, k.Issued = "ws_0therw0rkspace00", time.Now().Add(-400*time.Second).Truncate(time.Second), time.Now().Add(-time.Hour).Truncate(time.Second)
		}, "run_key_expired"},
		"another gateway's, within the skew": {func(k *runkey.Key) {
			k.Gateway, k.AttachBy, k.Issued = "ng_0therg4teway0000", time.Now().Add(-100*time.Second).Truncate(time.Second), time.Now().Add(-time.Hour).Truncate(time.Second)
		}, "wrong_gateway"},
		"another gateway's and workspace's": {func(k *runkey.Key) {
			k.Gateway, k.Workspace = "ng_0therg4teway0000", "ws_0therw0rkspace00"
		}, "wrong_gateway"},
	} {
		key := runKeyFor(t, runID, c.change)
		for _, p := range paths {
			refused(t, name+" "+p.path, send([]string{"Bearer " + key}, p.method, p.path), http.StatusConflict, c.code, "gateway", r.attachLine(runID, c.code))
		}
	}
	if n := len(r.c.attached()); n != 0 {
		t.Errorf("%d attaches", n)
	}
	// A run key of any workspace passes: the gateway takes the workspace from the run key.
	other := runKeyFor(t, event.NewRunID(), func(k *runkey.Key) { k.Workspace = "ws_0therw0rkspace00" })
	if a := r.do(t, other, http.MethodGet, "/qory-link/configuration", nil); a.status != http.StatusOK {
		t.Errorf("another workspace's run key: %d %s", a.status, a.body)
	}
	// A run the gateway holds goes on past its key's attach_by.
	e := r.open(t, good, server.LinkRunRequest{})
	mu.Lock()
	now = time.Now().Add(time.Hour)
	mu.Unlock()
	if a := e.post(t, heartbeat(runID)); a.status != http.StatusAccepted {
		t.Errorf("a held run past attach_by: %d %s", a.status, a.body)
	}
	late := runKeyFor(t, event.NewRunID(), nil)
	refused(t, "a run not held past attach_by", r.do(t, late, http.MethodGet, "/qory-link/configuration", nil), http.StatusConflict, "run_key_expired", "gateway", r.attachLine(mustRunID(t, late), "run_key_expired"))
}

// TestTheGatewayKeepsItsPin pins that the gateway verifies run keys under the pin it
// started with: once it has started, the caller's Server losing the signer's key, in
// place and as a new pin, changes nothing, and a key of the new pin is not the gateway's.
func TestTheGatewayKeepsItsPin(t *testing.T) {
	c := gatewayControl(t)
	srv := c.server()
	srv.ApiaryPublicKey = slices.Clone(testPin)
	r := startRemote(t, c, gateway.Config{Server: srv})
	other := mustGenerate()
	otherPin := accesskey.ServerKey{Alg: "ed25519", PublicKey: other.PublicKey().String()}
	good := runKeyFor(t, event.NewRunID(), nil)
	// The caller changes its Server as the gateway reads run keys: under -race, a
	// gateway that read the caller's would be a data race.
	started, stop, changed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(changed)
		pin := srv.ApiaryPublicKey
		for first := true; ; first = false {
			pin[0] = otherPin
			srv.ApiaryPublicKey = accesskey.Pin{otherPin}
			if first {
				close(started)
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	<-started
	if a := r.do(t, good, http.MethodGet, "/qory-link/configuration", nil); a.status != http.StatusOK {
		t.Errorf("a run key of the signer as the caller's pin loses it: %d %s", a.status, a.body)
	}
	close(stop)
	<-changed
	if a := r.do(t, good, http.MethodGet, "/qory-link/configuration", nil); a.status != http.StatusOK {
		t.Errorf("a run key of the signer once the caller's pin lost it: %d %s", a.status, a.body)
	}
	runID := event.NewRunID()
	unpinned, err := runkey.Key{RunID: runID, Workspace: testWorkspace, NodeID: keyNode, Gateway: testGateway, InstanceID: keyInstance,
		GatewayURL: "https://gateway.example:8443", GatewayKeys: gatewayKeys(), Issued: time.Now().Truncate(time.Second), AttachBy: time.Now().Add(time.Hour).Truncate(time.Second)}.Sign(other)
	if err != nil {
		t.Fatal(err)
	}
	refused(t, "a run key of the caller's new pin", r.do(t, unpinned, http.MethodGet, "/qory-link/configuration", nil), http.StatusBadRequest, "run_key_invalid", "gateway", keyInvalid)
}

// TestTheGatewayAllowsTheSkewPastAttachBy pins the skew the one address allows a run
// key's attach_by by its own clock, server.Window, 300 s: a run key 100 s past its
// attach_by opens its run, the attach sent to the server, and a batch of a run of such a
// key the gateway holds nothing of is the 410 run_closed of a run not open here; 400 s
// past, both are the gateway's 409 run_key_expired, and nothing is attached.
func TestTheGatewayAllowsTheSkewPastAttachBy(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	past := func(d time.Duration) (string, string) {
		runID := event.NewRunID()
		return runID, runKeyFor(t, runID, func(k *runkey.Key) {
			k.AttachBy = time.Now().Add(-d).Truncate(time.Second)
			k.Issued = k.AttachBy.Add(-time.Minute)
		})
	}
	_, within := past(100 * time.Second)
	if a := r.tryOpen(t, within, server.LinkRunRequest{}); a.status != http.StatusOK {
		t.Errorf("a run key 100 s past its attach_by: %d %s; want the run open", a.status, a.body)
	}
	if got := r.c.attached(); len(got) != 1 || !strings.Contains(string(got[0]), within) {
		t.Errorf("%d attaches; want the one of the key 100 s past its attach_by", len(got))
	}
	_, unheld := past(100 * time.Second)
	if a := r.do(t, unheld, http.MethodPost, "/qory-link/events", []byte(`[]`), http.Header{"Content-Type": {server.ContentType}}); a.status != http.StatusGone || a.refusal()["error"] != "run_closed" {
		t.Errorf("a batch 100 s past attach_by of a run not held: %d %s; want 410 run_closed", a.status, a.body)
	}
	lateID, late := past(400 * time.Second)
	refused(t, "a run key 400 s past its attach_by", r.tryOpen(t, late, server.LinkRunRequest{}), http.StatusConflict, "run_key_expired", "gateway", r.attachLine(lateID, "run_key_expired"))
	refused(t, "a batch 400 s past attach_by of a run not held", r.do(t, late, http.MethodPost, "/qory-link/events", []byte(`[]`), http.Header{"Content-Type": {server.ContentType}}), http.StatusConflict, "run_key_expired", "gateway", r.attachLine(lateID, "run_key_expired"))
	if n := len(r.c.attached()); n != 1 {
		t.Errorf("%d attaches; want the one within the skew", n)
	}
}

// TestTheServersRunKeyExpiredIsKept pins the server's run_key_expired refusal of an
// attach within the skew: two run requests with a run key 10 s past its attach_by send
// one attach, and both get the server's refusal, the same answer. Once the gateway
// holds a record of the run, the kept refusal is not given: the run request is the 409
// run_attached of a run the gateway has a record of.
func TestTheServersRunKeyExpiredIsKept(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	r.c.attachRefusal.Store(&receiver.Refusal{Status: http.StatusConflict, Code: "run_key_expired"})
	runID := event.NewRunID()
	key := runKeyFor(t, runID, func(k *runkey.Key) {
		k.AttachBy = time.Now().Add(-10 * time.Second).Truncate(time.Second)
		k.Issued = k.AttachBy.Add(-time.Minute)
	})
	first := r.tryOpen(t, key, server.LinkRunRequest{})
	refused(t, "the first run request", first, http.StatusConflict, "run_key_expired", "apiary", r.attachLine(runID, "run_key_expired"))
	second := r.tryOpen(t, key, server.LinkRunRequest{})
	refused(t, "the second run request", second, http.StatusConflict, "run_key_expired", "apiary", r.attachLine(runID, "run_key_expired"))
	if !bytes.Equal(first.body, second.body) {
		t.Errorf("the second refusal %s; want the first's, %s", second.body, first.body)
	}
	if n := len(r.c.attached()); n != 1 {
		t.Errorf("%d attaches; want 1", n)
	}

	// A record of the run, marked answered, which the gateway keeps.
	dir := filepath.Join(r.cfg.Dir, "runs", runID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(`{"type":"`+event.RunRegistered+`"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "answered"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	refused(t, "a run request of a run with a record", r.tryOpen(t, key, server.LinkRunRequest{}), http.StatusConflict, "run_attached", "gateway", r.attachLine(runID, "run_attached"))
	if n := len(r.c.attached()); n != 1 {
		t.Errorf("%d attaches; want 1", n)
	}
}

// mustRunID is the run id of a run key.
func mustRunID(t *testing.T, key string) string {
	t.Helper()
	k, err := runkey.Parse(key)
	if err != nil {
		t.Fatal(err)
	}
	return k.RunID
}

// TestTheRunRequestBehindTheGateway pins what a run request may carry behind a separate
// gateway: a run id other than its run key's is run_key_invalid; labels or about, the
// starter's registration's, are invalid_request; a run the gateway holds, or holds a
// record of, is 409 run_attached, read as the server's refusal of the attach; and a
// reload of another run id than the run key's is run_key_invalid.
func TestTheRunRequestBehindTheGateway(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	runID := event.NewRunID()
	key := runKeyFor(t, runID, nil)
	refused(t, "another run id", r.tryOpen(t, key, server.LinkRunRequest{RunID: event.NewRunID()}), http.StatusBadRequest, "run_key_invalid", "gateway", keyInvalid)
	refused(t, "labels", r.tryOpen(t, key, server.LinkRunRequest{Labels: map[string]string{"repository": "example-namespace/project"}}), http.StatusBadRequest, "invalid_request", "gateway", "the gateway refused the run: invalid_request")
	refused(t, "about", r.tryOpen(t, key, server.LinkRunRequest{About: &server.About{Title: "Fix the failing build"}}), http.StatusBadRequest, "invalid_request", "gateway", "the gateway refused the run: invalid_request")
	if n := len(r.c.attached()); n != 0 {
		t.Errorf("%d attaches", n)
	}
	e := r.open(t, key, server.LinkRunRequest{})
	refused(t, "a second run request", r.tryOpen(t, key, server.LinkRunRequest{}), http.StatusConflict, "run_attached", "gateway", r.attachLine(runID, "run_attached"))
	refused(t, "a reload of another run", r.do(t, key, http.MethodGet, "/qory-link/run-configuration/"+event.NewRunID(), nil), http.StatusBadRequest, "run_key_invalid", "gateway", keyInvalid)
	if a := e.reload(t); a.status != http.StatusOK {
		t.Errorf("the run's reload: %d %s", a.status, a.body)
	}
	if n := len(r.c.attached()); n != 1 {
		t.Errorf("%d attaches; want 1", n)
	}
}

// TestARunThroughTheGateway pins a run behind a separate gateway end to end: the
// discovery's URLs on the origin the edge names, under /qory-link/, its proxy that
// address; the attach under the gateway's key with the run key, its interval, the event
// types and its version; the run answer valid under its schema, with no labels, proxy
// secret or run secret, and the policy of the attach's answer; the record's first line
// from the run key and the attach's answer; the run's events at the server, sent under
// the gateway's key; and a reload.
func TestARunThroughTheGateway(t *testing.T) {
	c := gatewayControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`, 'a')
	c.mu.Lock()
	c.attachLabels = map[string]string{"repository": "example-namespace/project"}
	c.attachAbout = json.RawMessage(`{"title":"Fix the failing build"}`)
	c.mu.Unlock()
	r := startRemote(t, c, gateway.Config{Heartbeat: 5 * time.Second, Version: "v0.0.0-test"})
	runID := event.NewRunID()
	key := runKeyFor(t, runID, nil)

	d := r.do(t, key, http.MethodGet, "/qory-link/configuration", nil)
	validDocument(t, "link-discovery.schema.json", d.body)
	var disc server.LinkDiscovery
	json.Unmarshal(d.body, &disc)
	if disc.Events.URL != "https://gateway.example:8443/qory-link/events" || disc.Run.URL != "https://gateway.example:8443/qory-link/run-configuration" ||
		disc.Proxy == nil || disc.Proxy.Address != "gateway.example:8443" || disc.Events.IntervalSeconds != 5 {
		t.Errorf("the discovery %s", d.body)
	}

	a := r.tryOpen(t, key, server.LinkRunRequest{})
	if a.status != http.StatusOK {
		t.Fatalf("the run request: %d %s", a.status, a.body)
	}
	validDocument(t, "link-run-answer.schema.json", a.body)
	var members map[string]json.RawMessage
	json.Unmarshal(a.body, &members)
	for _, m := range []string{"labels", "proxy_secret", "stack_proxy_secret", "run_secret"} {
		if _, ok := members[m]; ok {
			t.Errorf("the run answer holds %s: %s", m, a.body)
		}
	}
	if !bytes.Contains(a.body, []byte("api.example")) {
		t.Errorf("the run answer has not the attach's policy: %s", a.body)
	}
	atts := c.attached()
	if len(atts) != 1 {
		t.Fatalf("%d attaches", len(atts))
	}
	var att map[string]any
	json.Unmarshal(atts[0], &att)
	if att["run_key"] != key || att["interval_seconds"] != float64(5) || att["forager_version"] != "v0.0.0-test" || fmt.Sprint(att["events"]) != "[*]" || att["contract_version"] != float64(server.Revision) {
		t.Errorf("the attach %s", atts[0])
	}
	validDocument(t, "run-attach.schema.json", atts[0])

	var ans server.LinkRunAnswer
	json.Unmarshal(a.body, &ans)
	e := &edgeRun{r: r, key: key, a: &ans}
	if got := e.post(t, started(runID, nil), applied(runID, ans.Applied), heartbeat(runID)); got.status != http.StatusAccepted {
		t.Fatalf("the first batch: %d %s", got.status, got.body)
	}
	if got := e.reload(t); got.status != http.StatusOK || !bytes.Contains(got.body, []byte("api.example")) {
		t.Errorf("the reload: %d %s", got.status, got.body)
	}
	// A join on the one address: the run key's run, session 1; another run's is
	// run_key_invalid and is numbered not.
	refused(t, "a join of another run", r.do(t, key, http.MethodPost, "/qory-link/run-configuration/"+event.NewRunID()+"/sessions", []byte(`{"version":1,"passes":[]}`)), http.StatusBadRequest, "run_key_invalid", "gateway", keyInvalid)
	j := r.do(t, key, http.MethodPost, "/qory-link/run-configuration/"+runID+"/sessions", []byte(`{"version":1,"passes":["HOME"]}`))
	if j.status != http.StatusOK {
		t.Fatalf("the join: %d %s", j.status, j.body)
	}
	validDocument(t, "link-join-answer.schema.json", j.body)
	var joined server.LinkJoinAnswer
	if json.Unmarshal(j.body, &joined); joined.Session != 1 {
		t.Errorf("the join's answer %s", j.body)
	}
	if got := e.post(t, sessionStarted(runID, 1), sessionExited(runID, 1)); got.status != http.StatusAccepted {
		t.Fatalf("the session: %d %s", got.status, got.body)
	}
	if got := e.post(t, exited(runID)); got.status != http.StatusAccepted {
		t.Fatalf("the last batch: %d %s", got.status, got.body)
	}
	eventually(t, "the run's events at the server", func() bool {
		lines := c.lines(t)
		return len(lines) > 0 && lines[len(lines)-1].Type == event.RunExited
	})
	rec := r.record(runID)
	validEvents(t, rec)
	first := rec[0].Data
	if rec[0].Type != event.RunRegistered || first["workspace"] != testWorkspace || first["node_id"] != keyNode || first["instance_id"] != keyInstance ||
		first["forager_version"] != "v0.0.0-test" || first["interval_seconds"] != float64(5) || fmt.Sprint(first["labels"]) != "map[repository:example-namespace/project]" ||
		fmt.Sprint(first["about"]) != "map[title:Fix the failing build]" {
		t.Errorf("the record's first line %s %v", rec[0].Type, first)
	}
	for _, l := range c.lines(t) {
		if l.Type == event.RunRegistered {
			t.Error("the record's first line was posted")
		}
	}
}

// TestAnAttachRefusalReachesTheSession pins the server's refusal of the attach: the
// session has it as the link's refusal, its status and code, from apiary, reading
// attach <run.url>/<run_id>: <code> (status <status>); the run does not open, and the
// gateway holds nothing of it.
func TestAnAttachRefusalReachesTheSession(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	for _, ref := range []receiver.Refusal{{Status: http.StatusConflict, Code: "run_attached"}, {Status: http.StatusConflict, Code: "run_key_expired"}, {Status: http.StatusConflict, Code: "not_a_gateway"}, {Status: http.StatusConflict, Code: "workspace_not_served"}} {
		r.c.attachRefusal.Store(&ref)
		runID := event.NewRunID()
		refused(t, ref.Code, r.tryOpen(t, runKeyFor(t, runID, nil), server.LinkRunRequest{}), ref.Status, ref.Code, "apiary", r.attachLine(runID, ref.Code))
	}
	if runs, _ := gateway.Held(r.g); runs != 0 {
		t.Errorf("%d runs held", runs)
	}
	// A run that never attached is kept of nothing: the run request that comes again
	// attaches it, with the same run key.
	runID := event.NewRunID()
	key := runKeyFor(t, runID, nil)
	r.c.attachRefusal.Store(&receiver.Refusal{Status: http.StatusConflict, Code: "not_a_gateway"})
	refused(t, "the first try", r.tryOpen(t, key, server.LinkRunRequest{}), http.StatusConflict, "not_a_gateway", "apiary", r.attachLine(runID, "not_a_gateway"))
	r.c.attachRefusal.Store(nil)
	if e := r.open(t, key, server.LinkRunRequest{}); e.a.RunID != runID {
		t.Errorf("the run attached again is %s", e.a.RunID)
	}
}

// TestAnAttachedRunWhoseConfigurationIsRefusedKeepsItsRecord pins an attach the server
// accepted whose run configuration Forager refuses: the run does not open, a 403
// run_configuration_invalid from the gateway, but its record is kept, its first line
// run.registered, and the run request that comes again with the same run key is a 409
// run_attached, with no second attach.
func TestAnAttachedRunWhoseConfigurationIsRefusedKeepsItsRecord(t *testing.T) {
	c := gatewayControl(t)
	c.serve(`{"version":1,"egress":{"mode":"bogus"}}`, 'a')
	r := startRemote(t, c, gateway.Config{})
	runID := event.NewRunID()
	key := runKeyFor(t, runID, nil)
	if a := r.tryOpen(t, key, server.LinkRunRequest{}); a.status != http.StatusForbidden || a.refusal()["error"] != "run_configuration_invalid" || a.refusal()["from"] != "gateway" {
		t.Fatalf("the run request: %d %s", a.status, a.body)
	}
	eventually(t, "the run's record", func() bool {
		rec := r.record(runID)
		return len(rec) > 0 && rec[0].Type == "dev.qory.run.registered"
	})
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`, 'b')
	refused(t, "the run request again", r.tryOpen(t, key, server.LinkRunRequest{}), http.StatusConflict, "run_attached", "gateway", r.attachLine(runID, "run_attached"))
	if n := len(r.c.attached()); n != 1 {
		t.Errorf("%d attaches", n)
	}
}

// TestTheEndMember pins the end member of the server's 2xx to a batch, behind a
// separate gateway and on a direct node's local link alike: the gateway ends the run
// with the outcome, its record's dev.qory.run.exited has its state and reason and
// exit_code -1, numbered and posted after the run's last events; the session's next
// request is a 410 stopped carrying them; a later end is ignored. An end cancelled
// with no reason has the reason stopped, "no outcome given". Behind the gateway the
// ended run, once let go of, still answers its 410.
func TestTheEndMember(t *testing.T) {
	for _, c := range []struct {
		end           server.ServerEnd
		reason, words string
	}{
		{server.ServerEnd{State: "failed", Reason: "checks_failed"}, "checks_failed", "failed, checks failed"},
		{server.ServerEnd{State: "succeeded"}, "", "succeeded"},
		{server.ServerEnd{State: "cancelled"}, "stopped", "cancelled, no outcome given"},
	} {
		text := "the run has ended: " + c.words
		ended := func(t *testing.T, rec []recorded, posted []recorded) {
			t.Helper()
			var exits []recorded
			for _, l := range rec {
				if l.Type == event.RunExited {
					exits = append(exits, l)
				}
			}
			if len(exits) != 1 || rec[len(rec)-1].Type != event.RunExited {
				t.Fatalf("%d run.exited in the record %v", len(exits), types(rec))
			}
			x := exits[0].Data
			if x["state"] != c.end.State || (c.reason == "" && x["reason"] != nil) || (c.reason != "" && x["reason"] != c.reason) || x["exit_code"] != float64(-1) {
				t.Errorf("the record's run.exited %v", x)
			}
			validEvents(t, rec)
			if posted[len(posted)-1].Type != event.RunExited || posted[len(posted)-1].Sequence != exits[0].Sequence {
				t.Errorf("the server has %v", types(posted))
			}
		}

		t.Run("separate "+c.words, func(t *testing.T) {
			r := startRemote(t, nil, gateway.Config{})
			runID := event.NewRunID()
			e := r.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{})
			r.c.end.Store(&c.end)
			var last answer
			eventually(t, "the 410", func() bool {
				last = e.post(t, heartbeat(runID))
				return last.status == http.StatusGone
			})
			got := last.refusal()
			if got["error"] != "stopped" || got["from"] != "gateway" || got["message"] != text || got["state"] != c.end.State || (c.reason != "" && got["reason"] != c.reason) {
				t.Errorf("the 410 %s", last.body)
			}
			validDocument(t, "link-refusal.schema.json", last.body)
			r.c.end.Store(&server.ServerEnd{State: "succeeded", Reason: "other_reason"})
			eventually(t, "the run let go of", func() bool {
				runs, spent := gateway.Held(r.g)
				return runs == 0 && spent == 1
			})
			ended(t, r.record(runID), r.c.lines(t))
			if a := e.reload(t); a.status != http.StatusGone || a.refusal()["message"] != text {
				t.Errorf("the reload of the ended run: %d %s", a.status, a.body)
			}
			refused(t, "a run request again", r.tryOpen(t, e.key, server.LinkRunRequest{}), http.StatusConflict, "run_attached", "gateway", r.attachLine(runID, "run_attached"))
		})

		t.Run("local "+c.words, func(t *testing.T) {
			ctl := newControl(t)
			h := start(t, gateway.Config{Server: ctl.server()})
			a := h.open(server.LinkRunRequest{})
			if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
				t.Fatalf("the first batch: %+v", d)
			}
			ctl.end.Store(&c.end)
			var d server.Delivery
			eventually(t, "the 410", func() bool {
				d = h.post(heartbeat(a.RunID))
				return d.Status == http.StatusGone
			})
			if d.Code != "stopped" || d.State != c.end.State || d.Reason != c.reason {
				t.Errorf("the 410 %+v", d)
			}
			status, got := h.refusalOf("/v1/events", string(mustJSON(t, []map[string]any{heartbeat(a.RunID)})))
			if status != http.StatusGone || got["message"] != text {
				t.Errorf("the 410's message: %d %v", status, got)
			}
			ctl.end.Store(&server.ServerEnd{State: "succeeded", Reason: "other_reason"})
			eventually(t, "the run.exited at the server", func() bool {
				lines := ctl.lines(t)
				return len(lines) > 0 && lines[len(lines)-1].Type == event.RunExited
			})
			ended(t, h.record(a.RunID), ctl.lines(t))
		})
	}
}

// TestAGatewayRestartedReattaches pins a separate gateway that restarts on its
// directory: a run it attached whose open never answered its session, its record
// holding its dev.qory.run.registered alone, is reclaimed, and the session's run
// request attaches it again and opens it; a run that was live there is over, a 410
// run_closed to its batch and a 409 run_attached to its run request. Its attaches and
// its batches at the server carry the same X-Qory-Instance-Id, the one its caller
// gives, before the restart and after.
func TestAGatewayRestartedReattaches(t *testing.T) {
	dir := t.TempDir()
	c := gatewayControl(t)
	before := startRemote(t, c, gateway.Config{Dir: dir})
	partial, live := event.NewRunID(), event.NewRunID()
	partialKey, liveKey := runKeyFor(t, partial, nil), runKeyFor(t, live, nil)
	before.open(t, partialKey, server.LinkRunRequest{})
	l := before.open(t, liveKey, server.LinkRunRequest{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	before.g.Close(ctx)
	cancel()
	// The partial run's record as a gateway that stopped as it opened leaves it: its
	// first line alone, and no mark that it was answered.
	firstLineAlone(t, dir, partial)
	os.Remove(filepath.Join(dir, "runs", partial, "answered"))
	attaches := len(c.attached())
	_, delivered := c.instances()

	r := startRemote(t, c, gateway.Config{Dir: dir})
	a := r.tryOpen(t, partialKey, server.LinkRunRequest{})
	if a.status != http.StatusOK {
		t.Fatalf("the reclaimed run's request: %d %s", a.status, a.body)
	}
	if got := len(c.attached()); got != attaches+1 {
		t.Errorf("%d attaches after the restart; want 1", got-attaches)
	}
	rec := r.record(partial)
	if len(rec) != 1 || rec[0].Type != event.RunRegistered || rec[0].Sequence != "0000000001" {
		t.Errorf("the reclaimed run's record %v", types(rec))
	}
	l.r = r
	if got := l.post(t, heartbeat(live)); got.status != http.StatusGone || got.refusal()["error"] != "run_closed" {
		t.Errorf("a batch of the run live before: %d %s", got.status, got.body)
	}
	refused(t, "a run request of the run live before", r.tryOpen(t, liveKey, server.LinkRunRequest{}), http.StatusConflict, "run_attached", "gateway", r.attachLine(live, "run_attached"))

	var ans server.LinkRunAnswer
	json.Unmarshal(a.body, &ans)
	p := &edgeRun{r: r, key: partialKey, a: &ans}
	if got := p.post(t, started(partial, nil), applied(partial, ans.Applied)); got.status != http.StatusAccepted {
		t.Fatalf("a batch of the reclaimed run: %d %s", got.status, got.body)
	}
	eventually(t, "a delivery after the restart", func() bool {
		_, d := c.instances()
		return len(d) > len(delivered)
	})
	attachIDs, deliveryIDs := c.instances()
	if len(attachIDs) != attaches+1 || len(delivered) == 0 {
		t.Errorf("%d attaches, want %d, and %d deliveries before the restart", len(attachIDs), attaches+1, len(delivered))
	}
	for _, id := range append(attachIDs, deliveryIDs...) {
		if id != testInstance {
			t.Errorf("the attaches carry %q and the deliveries %q; want each %q", attachIDs, deliveryIDs, testInstance)
			break
		}
	}
}

// TestARunMarkedAnsweredIsKeptWhenItsSessionGoes pins a run on the one address whose
// session goes once its record is marked answered: the run is kept, its record and the
// mark with it, and the run request that comes again with the same run key is a 409
// run_attached, with no second attach.
func TestARunMarkedAnsweredIsKeptWhenItsSessionGoes(t *testing.T) {
	conns := make(chan *bound, 1)
	cfg := gateway.Config{}
	gateway.SetMarked(&cfg, func(ctx context.Context) {
		var b *bound
		select {
		case b = <-conns:
		default:
			// A run request after the first: it goes on.
			return
		}
		b.Close()
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
			t.Error("the run request's context did not end when its connection closed")
		}
	})
	r := startRemote(t, nil, cfg)
	runID := event.NewRunID()
	key := runKeyFor(t, runID, nil)
	r.mu.Lock()
	r.keys = append(r.keys, key)
	r.mu.Unlock()
	b, err := r.bind(t, gatewayKeys())
	if err != nil {
		t.Fatal(err)
	}
	conns <- b
	body, _ := json.Marshal(server.LinkRunRequest{Version: 1, RunID: runID})
	req, err := http.NewRequest(http.MethodPost, "https://gateway.example:8443/qory-link/run-configuration", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", server.LinkContentType)
	if err := req.Write(b.c); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the run request's connection closed", func() bool {
		_, err := b.r.ReadByte()
		return err != nil
	})
	gateway.WaitOpens(r.g)
	if runs, _ := gateway.Held(r.g); runs != 1 {
		t.Errorf("%d runs held; want the run kept", runs)
	}
	if _, err := os.Stat(filepath.Join(r.cfg.Dir, "runs", runID, "answered")); err != nil {
		t.Errorf("the mark: %v", err)
	}
	refused(t, "the run request again", r.tryOpen(t, key, server.LinkRunRequest{}), http.StatusConflict, "run_attached", "gateway", r.attachLine(runID, "run_attached"))
	if n := len(r.c.attached()); n != 1 {
		t.Errorf("%d attaches; want 1", n)
	}
}

// firstLineAlone leaves the record of a run in the gateway directory dir as a gateway
// that stopped without ending the run leaves it: its first line alone, and nothing
// delivered.
func firstLineAlone(t *testing.T, dir, runID string) {
	t.Helper()
	file := filepath.Join(dir, "runs", runID, "events.jsonl")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, append(bytes.SplitN(b, []byte("\n"), 2)[0], '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, "runs", runID, "delivered.log"))
}

// TestAGatewayRestartedAfterTheAnswerKeepsTheRun pins the mark of an answered run
// request behind a separate gateway: a gateway that stopped after it answered a run's
// run request, the run's record holding its dev.qory.run.registered alone, keeps the
// record when it starts again, and the run request that comes again is a 409
// run_attached, with no second attach. A run whose record cannot be marked answered is
// let go of, a 500 internal saying why, and the run request that comes again opens it.
func TestAGatewayRestartedAfterTheAnswerKeepsTheRun(t *testing.T) {
	dir := t.TempDir()
	c := gatewayControl(t)
	before := startRemote(t, c, gateway.Config{Dir: dir})
	runID := event.NewRunID()
	key := runKeyFor(t, runID, nil)
	if a := before.tryOpen(t, key, server.LinkRunRequest{}); a.status != http.StatusOK {
		t.Fatalf("the run request: %d %s", a.status, a.body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	before.g.Close(ctx)
	cancel()
	firstLineAlone(t, dir, runID)

	r := startRemote(t, c, gateway.Config{Dir: dir})
	refused(t, "the run request again", r.tryOpen(t, key, server.LinkRunRequest{}), http.StatusConflict, "run_attached", "gateway", r.attachLine(runID, "run_attached"))
	if n := len(c.attached()); n != 1 {
		t.Errorf("%d attaches; want the one before the restart", n)
	}
	if rec := r.record(runID); len(rec) != 1 || rec[0].Type != event.RunRegistered {
		t.Errorf("the run's record %v", types(rec))
	}

	unmarked := event.NewRunID()
	mark := filepath.Join(dir, "runs", unmarked, "answered")
	var once sync.Once
	cfg := gateway.Config{Dir: dir}
	gateway.SetOpened(&cfg, func() { once.Do(func() { os.WriteFile(mark, nil, 0o644) }) })
	r.g.Close(context.Background())
	m := startRemote(t, c, cfg)
	unmarkedKey := runKeyFor(t, unmarked, nil)
	refused(t, "a run whose record cannot be marked", m.tryOpen(t, unmarkedKey, server.LinkRunRequest{}), http.StatusInternalServerError, "internal", "gateway",
		fmt.Sprintf("run %s: marking its record answered: open %s: file exists", unmarked, mark))
	if runs, _ := gateway.Held(m.g); runs != 0 {
		t.Errorf("%d runs held", runs)
	}
	if e := m.open(t, unmarkedKey, server.LinkRunRequest{}); e.a.RunID != unmarked {
		t.Errorf("the run opened again is %s", e.a.RunID)
	}
}

// TestABatchBehindTheGatewayTheLinkRefusesEndsItsRun pins D4 behind a separate gateway:
// a batch of another run's events ends the run of its run key, batch_refused, and its
// later requests are a 410 batch_refused.
func TestABatchBehindTheGatewayTheLinkRefusesEndsItsRun(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	runID := event.NewRunID()
	e := r.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{})
	if a := e.post(t, heartbeat(event.NewRunID())); a.status != http.StatusBadRequest || a.refusal()["error"] != "invalid_request" {
		t.Errorf("the batch: %d %s", a.status, a.body)
	}
	if a := e.reload(t); a.status != http.StatusGone || a.refusal()["error"] != "batch_refused" {
		t.Errorf("the run after: %d %s", a.status, a.body)
	}
	if !r.reported("run " + runID + ": the gateway refused a batch from the run's session, an event of another run; the run ends: failed") {
		t.Error("no line of the refused batch")
	}
}

// TestTheRelay pins the relay of the server's four endpoints on unbound connections:
// each forwarded with its target unchanged, in origin form when it came in absolute
// form, the fields of one connection dropped both ways, those its Connection names
// among them, and its answer passed back byte for byte, its signature among it; every other path 404 and
// other method 405; a body over its endpoint's bound 413; and an answer over 1 MiB
// 502, each the relay's own, with no body and nothing sent on.
func TestTheRelay(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	var got []string
	var mu sync.Mutex
	answerBody := []byte(`{"version":1}`)
	f := func(w http.ResponseWriter, req *http.Request) bool {
		if req.URL.Path == "/v1/events" {
			return false
		}
		b, _ := io.ReadAll(req.Body)
		mu.Lock()
		hop := ""
		for _, k := range []string{"Connection", "X-Secret", "Keep-Alive", "Proxy-Authorization", "Te"} {
			if req.Header.Get(k) != "" {
				hop += k + " "
			}
		}
		got = append(got, req.Method+" "+req.RequestURI+" "+fmt.Sprint(len(b))+" "+hop+req.Header.Get(server.HeaderSignature))
		big := strings.HasSuffix(req.URL.Path, "/big")
		mu.Unlock()
		if req.URL.Query().Get("big") != "" || big {
			w.Write(make([]byte, gateway.RelayMaxAnswer+1))
			return true
		}
		w.Header().Set(server.HeaderSignature, "answer-signature")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Connection", "X-Answer-Secret")
		w.Header().Set("X-Answer-Secret", "of the connection")
		w.Write(answerBody)
		return true
	}
	r.c.intercept.Store(&f)
	send := func(method, target string, body []byte, header http.Header) (*http.Response, []byte) {
		t.Helper()
		c := r.dialTLS(t)
		defer c.Close()
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, _ := http.NewRequest(method, "https://gateway.example:8443"+target, rd)
		for k, v := range header {
			req.Header[k] = v
		}
		if err := req.Write(c); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, b
	}
	outcome := runsPath + "/" + event.NewRunID() + "/outcome"
	for _, c := range []struct {
		method, target string
		size           int
	}{
		{http.MethodPost, "/.well-known/qory-enrolment", gateway.RelayEnrolment},
		{http.MethodGet, "/.well-known/qory-configuration?x=1", 0},
		{http.MethodPost, runsPath, gateway.RelayRegister},
		{http.MethodPost, outcome, gateway.RelayOutcome},
	} {
		var body []byte
		if c.method == http.MethodPost {
			body = bytes.Repeat([]byte("a"), c.size)
		}
		resp, b := send(c.method, c.target, body, http.Header{server.HeaderSignature: {"request-signature"},
			"Connection": {"X-Secret"}, "X-Secret": {"of the connection"}, "Keep-Alive": {"timeout=5"}, "Proxy-Authorization": {"Basic eDp5"}, "Te": {"trailers"}})
		if resp.StatusCode != http.StatusOK || !bytes.Equal(b, answerBody) || resp.Header.Get(server.HeaderSignature) != "answer-signature" || resp.Header.Get("X-Answer-Secret") != "" {
			t.Errorf("%s %s: %d %q", c.method, c.target, resp.StatusCode, b)
		}
		mu.Lock()
		last := got[len(got)-1]
		mu.Unlock()
		if want := c.method + " " + c.target + " " + fmt.Sprint(c.size) + " request-signature"; last != want {
			t.Errorf("forwarded %q; want %q", last, want)
		}
		if c.method == http.MethodPost {
			resp, b := send(c.method, c.target, append(body, 'a'), nil)
			if resp.StatusCode != http.StatusRequestEntityTooLarge || len(b) != 0 {
				t.Errorf("%s %s over its bound: %d %q", c.method, c.target, resp.StatusCode, b)
			}
		}
	}
	// A target in absolute form goes on in origin form, to the server's origin.
	c := r.dialTLS(t)
	io.WriteString(c, "GET https://other.example/.well-known/qory-configuration?x=2 HTTP/1.1\r\nHost: other.example\r\n\r\n")
	if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err != nil || resp.StatusCode != http.StatusOK {
		t.Errorf("a target in absolute form: %v %v", resp, err)
	}
	c.Close()
	mu.Lock()
	if last := got[len(got)-1]; last != "GET /.well-known/qory-configuration?x=2 0 " {
		t.Errorf("a target in absolute form went on as %q", last)
	}
	sent := len(got)
	mu.Unlock()
	for _, c := range []struct {
		method, target string
		status         int
	}{
		{http.MethodGet, "/qory-link/configuration", http.StatusNotFound},
		{http.MethodPost, runsPath + "/" + event.NewRunID() + "/attach", http.StatusNotFound},
		{http.MethodGet, runsPath + "/" + event.NewRunID(), http.StatusNotFound},
		{http.MethodPost, "/v1/events", http.StatusNotFound},
		{http.MethodGet, "/.well-known/qory-enrolment", http.StatusMethodNotAllowed},
		{http.MethodPost, "/.well-known/qory-configuration", http.StatusMethodNotAllowed},
		{http.MethodGet, runsPath, http.StatusMethodNotAllowed},
	} {
		resp, b := send(c.method, c.target, nil, nil)
		if resp.StatusCode != c.status || len(b) != 0 {
			t.Errorf("%s %s: %d %q; want %d", c.method, c.target, resp.StatusCode, b, c.status)
		}
	}
	mu.Lock()
	if len(got) != sent {
		t.Errorf("forwarded %q", got[sent:])
	}
	mu.Unlock()
	if resp, b := send(http.MethodGet, "/.well-known/qory-configuration?big=1", nil, nil); resp.StatusCode != http.StatusBadGateway || len(b) != 0 {
		t.Errorf("an answer over its bound: %d %d bytes", resp.StatusCode, len(b))
	}
}

// TestTheRelaysRateAndWait pins the relay's rate per source address, a burst of 20 then
// 429 with no body, and its wait for the server: an answer that does not come in time
// is 504, and a server not reached 502.
func TestTheRelaysRateAndWait(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	statuses := map[int]int{}
	for range gateway.RelayBurst + 5 {
		c := r.dialTLS(t)
		req, _ := http.NewRequest(http.MethodGet, "https://gateway.example:8443/nothing", nil)
		req.Write(c)
		resp, err := http.ReadResponse(bufio.NewReader(c), req)
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
		statuses[resp.StatusCode]++
	}
	if statuses[http.StatusNotFound] < gateway.RelayBurst || statuses[http.StatusNotFound] > gateway.RelayBurst+1 || statuses[http.StatusTooManyRequests] < 4 {
		t.Errorf("statuses %v", statuses)
	}

	cfg := gateway.Config{}
	gateway.SetRelayWait(&cfg, 200*time.Millisecond)
	slow := startRemote(t, nil, cfg)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f := func(w http.ResponseWriter, req *http.Request) bool {
		if req.URL.Path != server.WellKnown {
			return false
		}
		select {
		case <-release:
		case <-req.Context().Done():
		}
		return true
	}
	slow.c.intercept.Store(&f)
	get := func(rm *remote) int {
		c := rm.dialTLS(t)
		defer c.Close()
		req, _ := http.NewRequest(http.MethodGet, "https://gateway.example:8443"+server.WellKnown, nil)
		req.Write(c)
		resp, err := http.ReadResponse(bufio.NewReader(c), req)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode
	}
	if got := get(slow); got != http.StatusGatewayTimeout {
		t.Errorf("a server that does not answer in time: %d", got)
	}
	slow.c.srv.CloseClientConnections()
	slow.c.srv.Listener.Close()
	if got := get(slow); got != http.StatusBadGateway {
		t.Errorf("a server not reached: %d", got)
	}
}

// validEvents fails the test unless every event of the record is valid under its
// type's schema.
func validEvents(t *testing.T, rec []recorded) {
	t.Helper()
	for _, l := range rec {
		name := "events/" + strings.TrimPrefix(l.Type, "dev.qory.") + ".schema.json"
		schema, err := contracts.Compile(name)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(l.Data)
		doc, _ := contracts.Decode("data.json", b)
		if err := schema.Validate(doc); err != nil {
			t.Errorf("%s %s: %v", l.Type, b, err)
		}
	}
}

// TestARunConfigurationNamesAnImageByReference pins how an image by reference reaches a
// dispatched run: through the server's signed run configuration, whose image member
// names it, with no security_policy, attached by the run's run key, the node's policy
// naming no image. The node's policy stays in force as it is, its credentials and tools
// among it, with the image its selection. Under the request's images.allow the answer
// gives it as a reference, with the default's reference for the relay; under none of
// its prefixes the gateway refuses the run, image_not_allowed, from the gateway and not
// the server, and opens nothing for it.
func TestARunConfigurationNamesAnImageByReference(t *testing.T) {
	t.Setenv("GATEWAY_TEST_SECRET", "s3cret-value-of-the-test")
	t.Setenv(envTool, "serve")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ref := "registry.example/agents/app@sha256:" + strings.Repeat("b", 64)
	base := "registry.example/agents/base@sha256:" + strings.Repeat("0", 64)
	c := gatewayControl(t)
	c.serveDocument(`{"version":1,"image":"`+ref+`"}`, 'a')
	r := startRemote(t, c, gateway.Config{
		Credentials: []gateway.Credential{{Name: "api", Env: "GATEWAY_TEST_SECRET", Hosts: []string{"api.example"}, Scheme: "bearer", Placeholders: []string{"API_TOKEN"}}},
		Tools:       []gateway.Tool{{Name: "svc", Command: []string{exe, "first"}, Serves: []string{"svc.example"}}},
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example", "svc.example"}},
			Credentials: []gateway.PolicyCredential{{Name: "api"}}, Tools: []gateway.PolicyTool{{Name: "svc"}}},
	})
	images := &server.LinkImages{Default: "base", Definitions: []server.LinkImage{{Name: "base", Ref: base, Runtime: "sysbox-runc"}},
		Allow: []string{"registry.example/agents/"}}
	a := r.tryOpen(t, runKeyFor(t, event.NewRunID(), nil), server.LinkRunRequest{Wall: true, Images: images})
	if a.status != http.StatusOK {
		t.Fatalf("the run request: %d %s", a.status, a.body)
	}
	validDocument(t, "link-run-answer.schema.json", a.body)
	var ans server.LinkRunAnswer
	if err := json.Unmarshal(a.body, &ans); err != nil {
		t.Fatal(err)
	}
	if ans.Image == nil || *ans.Image != (server.LinkImage{Ref: ref, Runtime: "sysbox-runc", Reference: true}) || ans.RelayImage != base {
		t.Errorf("the image %+v, the relay's %q", ans.Image, ans.RelayImage)
	}
	var applied map[string]any
	if err := json.Unmarshal(ans.Applied, &applied); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"credentials": []any{map[string]any{"name": "api", "hosts": []any{"api.example"}, "scheme": "bearer"}},
		"tools":       []any{map[string]any{"name": "svc", "hosts": []any{"svc.example"}}},
		"terminated":  []any{"api.example", "svc.example"},
		"image":       ref,
	}
	for m, v := range want {
		if !reflect.DeepEqual(applied[m], v) {
			t.Errorf("applied's %s is %v, want %v", m, applied[m], v)
		}
	}
	if applied["source"] != "config" || applied["mode"] != "enforce" || !slices.Equal(anyStrings(applied["allow"]), []string{"api.example", "svc.example"}) || !slices.Equal(ans.Placeholders, []string{"API_TOKEN"}) {
		t.Errorf("the node's policy is not in force as it is: %s, placeholders %q", ans.Applied, ans.Placeholders)
	}

	images.Allow = []string{"registry.example/other/"}
	a = r.tryOpen(t, runKeyFor(t, event.NewRunID(), nil), server.LinkRunRequest{Wall: true, Images: images})
	refused(t, "a reference under no prefix", a, http.StatusForbidden, "image_not_allowed", "gateway",
		"the image "+ref+" is under none of the machine's allowed prefixes (images.allow): image_not_allowed: "+ref)
	if names := anyStrings(a.refusal()["names"]); !slices.Equal(names, []string{ref}) {
		t.Errorf("the refusal's names %q", names)
	}
	for _, m := range []string{"proxy_secret", "image", "relay_image", "certificate_authority", "placeholders"} {
		if _, ok := a.refusal()[m]; ok {
			t.Errorf("the refusal holds %s: %s", m, a.body)
		}
	}
}

// TestARunKeyWhoseInstanceIDContainsASecretIsInvalid pins a run key whose signed
// instance id contains qak_ or qrk_ in any case: the instance id would reach
// run.registered as it is, so every request with the run key is 400 run_key_invalid,
// and nothing is attached.
func TestARunKeyWhoseInstanceIDContainsASecretIsInvalid(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	for _, instance := range []string{"qak_FAKE", "i.QRK_FAKE"} {
		key := runKeyFor(t, event.NewRunID(), func(k *runkey.Key) { k.InstanceID = instance })
		refused(t, instance+" configuration", r.do(t, key, http.MethodGet, "/qory-link/configuration", nil), http.StatusBadRequest, "run_key_invalid", "gateway", keyInvalid)
		refused(t, instance+" run request", r.tryOpen(t, key, server.LinkRunRequest{}), http.StatusBadRequest, "run_key_invalid", "gateway", keyInvalid)
	}
	if n := len(r.c.attached()); n != 0 {
		t.Errorf("%d attaches", n)
	}
}
