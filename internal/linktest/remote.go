package linktest

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/server"
)

// RemotePrefix begins every path a fake separate gateway's discovery lists.
const RemotePrefix = "/qory-link"

// Proof is how a fake separate gateway answers the binding a connection opens with.
type Proof int

// The proofs a fake separate gateway gives.
const (
	// ProofHeld is QORY-BOUND with its own key's fingerprint and its signature over the
	// connection's exporter value: the proof the run's edge accepts.
	ProofHeld Proof = iota
	// ProofBadSignature is QORY-BOUND with its own key's fingerprint and a signature over
	// another exporter value.
	ProofBadSignature
	// ProofUnnamedKey is QORY-BOUND with the fingerprint of a key no run key of its names,
	// and that key's signature over the connection's exporter value.
	ProofUnnamedKey
	// ProofNone closes the connection without answering.
	ProofNone
)

// remote is a fake separate gateway: its TLS listener, the file of its authority, its
// key, which its run keys name, the server key it signs them under, and how it binds
// and signs.
type remote struct {
	f      *Fake
	ln     net.Listener
	tls    *tls.Config
	caFile string
	key    *accesskey.Key
	server *accesskey.Key
	conns  chan net.Conn
	done   chan struct{}
	once   sync.Once

	mu sync.Mutex
	// issued are the run keys it made, which its link accepts as bearers.
	issued []string
	proof  Proof
	// answerKey signs its answers; nil is key. unnamed is a key no run key names.
	answerKey *accesskey.Key
	unnamed   *accesskey.Key
	// unsigned answers with no signature.
	unsigned bool
	// leaked is what the edge sent on a connection whose proof failed.
	leaked []string
	bound  int
}

// StartRemoteFake starts a fake separate gateway, until the test ends: the answers of
// [StartFake] over TLS 1.3 on 127.0.0.1, under an authority of its own whose certificate
// names 127.0.0.1 alone, with a heartbeat interval of one second. Every connection must
// open with the binding, QORY-BIND, which it answers as [Fake.SetProof] says, under a
// key of its own the run keys of [Fake.RunKey] name. After it, a connection is either
// its link, whose discovery is at /qory-link/configuration and lists URLs of its own
// origin under [RemotePrefix] and its one address as its proxy, every request of which
// must carry one of its run keys as Authorization: Bearer and every answer of which it
// signs; or its proxy, opened with QORY-RELAY and one of its run keys, whose requests it
// answers 200 "ok". It has no local link: Local and Socket are not its.
func StartRemoteFake(t testing.TB) *Fake {
	t.Helper()
	f := &Fake{interval: 1, Gateway: &Gateway{}, prefix: RemotePrefix}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "linktest authority"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "gateway.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	r := &remote{f: f, caFile: filepath.Join(t.TempDir(), "ca.pem"), conns: make(chan net.Conn), done: make(chan struct{})}
	if err := os.WriteFile(r.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if r.key, err = accesskey.Generate(); err != nil {
		t.Fatal(err)
	}
	if r.server, err = accesskey.Generate(); err != nil {
		t.Fatal(err)
	}
	if r.unnamed, err = accesskey.Generate(); err != nil {
		t.Fatal(err)
	}
	r.tls = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"http/1.1"}}
	if r.ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(f.serve), ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if b, ok := c.(*fakeBound); ok {
				return context.WithValue(ctx, ekmKey{}, b.ekm)
			}
			return ctx
		},
	}
	go r.accept()
	go srv.Serve(r)
	t.Cleanup(func() { srv.Close(); r.Close() })
	f.remote, f.origin = r, "https://"+r.ln.Addr().String()
	return f
}

// ekmKey is the key of a connection's exporter value in a request's context.
type ekmKey struct{}

// fakeBound is a connection past its binding, read through the reader the binding was
// read with.
type fakeBound struct {
	net.Conn
	r   *bufio.Reader
	ekm []byte
}

func (c *fakeBound) Read(b []byte) (int, error) { return c.r.Read(b) }

func (r *remote) accept() {
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.handle(c)
	}
}

// handle does the TLS handshake and the binding of one connection, then serves it as
// the link or as the proxy.
func (r *remote) handle(raw net.Conn) {
	tc := tls.Server(raw, r.tls)
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	if tc.Handshake() != nil {
		tc.Close()
		return
	}
	br := bufio.NewReader(tc)
	if line, err := br.ReadString('\n'); err != nil || line != link.BindLine {
		tc.Close()
		return
	}
	cs := tc.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial(link.BindingLabel, []byte{}, link.BindingSize)
	if err != nil {
		tc.Close()
		return
	}
	r.mu.Lock()
	proof := r.proof
	r.mu.Unlock()
	switch proof {
	case ProofNone:
		tc.Close()
		return
	case ProofBadSignature:
		other := make([]byte, link.BindingSize)
		io.WriteString(tc, link.BoundLine(r.key.Fingerprint(), sign(r.key, link.BindingMessage(other, r.key.Fingerprint()))))
		r.drain(tc, br)
		return
	case ProofUnnamedKey:
		unnamed, _ := accesskey.Generate()
		io.WriteString(tc, link.BoundLine(unnamed.Fingerprint(), sign(unnamed, link.BindingMessage(ekm, unnamed.Fingerprint()))))
		r.drain(tc, br)
		return
	}
	io.WriteString(tc, link.BoundLine(r.key.Fingerprint(), sign(r.key, link.BindingMessage(ekm, r.key.Fingerprint()))))
	r.mu.Lock()
	r.bound++
	r.mu.Unlock()
	tc.SetDeadline(time.Time{})
	if head, err := br.Peek(len(link.RelayPreamble) + 1); err == nil && string(head) == link.RelayPreamble+" " {
		defer tc.Close()
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		r.f.mu.Lock()
		r.f.preambles = append(r.f.preambles, strings.TrimSuffix(line, "\n"))
		r.f.mu.Unlock()
		if !r.bearer([]string{"Bearer " + strings.TrimSuffix(strings.TrimPrefix(line, link.RelayPreamble+" "), "\n")}) {
			return
		}
		r.f.answerProxied(tc, br)
		return
	}
	select {
	case r.conns <- &fakeBound{Conn: tc, r: br, ekm: ekm}:
	case <-r.done:
		tc.Close()
	}
}

// drain records what the edge sends on a connection whose proof failed, until it
// closes it, and closes it.
func (r *remote) drain(c net.Conn, br *bufio.Reader) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b, _ := io.ReadAll(io.LimitReader(br, 64<<10))
	if len(b) > 0 {
		r.mu.Lock()
		r.leaked = append(r.leaked, string(b))
		r.mu.Unlock()
	}
}

// sign is the signature of m under k, base64url without padding.
func sign(k *accesskey.Key, m []byte) string { return base64.RawURLEncoding.EncodeToString(k.Sign(m)) }

// Accept is the next connection of the link, past its binding.
func (r *remote) Accept() (net.Conn, error) {
	select {
	case c := <-r.conns:
		return c, nil
	case <-r.done:
		return nil, net.ErrClosed
	}
}

// Close stops the listener.
func (r *remote) Close() error {
	r.once.Do(func() { close(r.done) })
	return r.ln.Close()
}

// Addr is the listener's address.
func (r *remote) Addr() net.Addr { return r.ln.Addr() }

// bearer reports whether the values of Authorization are one: Bearer and a run key the
// fake made.
func (r *remote) bearer(values []string) bool {
	if len(values) != 1 {
		return false
	}
	k, ok := strings.CutPrefix(values[0], "Bearer ")
	r.mu.Lock()
	defer r.mu.Unlock()
	return ok && slices.Contains(r.issued, k)
}

// sign sets the signature of the answer to req, whose body was body, on h: the six
// lines of a separate gateway's answer, over the connection's exporter value, under
// its key, another it was told to answer under, or none; signing, when not
// [SignedOwn], decides for this answer alone.
func (r *remote) sign(h http.Header, req *http.Request, body []byte, status int, out []byte, signing Signing) {
	r.mu.Lock()
	k, unsigned := r.answerKey, r.unsigned
	r.mu.Unlock()
	switch signing {
	case SignedUnnamed:
		k, unsigned = r.unnamed, false
	case Unsigned:
		unsigned = true
	}
	if unsigned {
		return
	}
	if k == nil {
		k = r.key
	}
	ekm, _ := req.Context().Value(ekmKey{}).([]byte)
	h.Set(accesskey.HeaderSignature, k.SignAnswer(accesskey.Answer{
		Link: true, Status: status, Body: out,
		RequestSignature: link.AnswerRequest(ekm, req.Method, req.RequestURI, body),
		Configuration:    h.Get(server.HeaderConfiguration), RunConfiguration: h.Get(server.HeaderRunConfiguration),
	}))
}

// URL is a fake separate gateway's URL, https://127.0.0.1:<port>; empty on the local
// link.
func (f *Fake) URL() string { return f.origin }

// CAFile is the PEM file of a fake separate gateway's authority, which a session trusts
// its certificate by; empty on the local link.
func (f *Fake) CAFile() string {
	if f.remote == nil {
		return ""
	}
	return f.remote.caFile
}

// RunKey is a run key of a fake separate gateway's for the run runID: its URL, and its
// key as the gateway's one key, signed under a server key of its own. Its link accepts
// every run key it made.
func (f *Fake) RunKey(t testing.TB, runID string) string {
	t.Helper()
	return f.RunKeyAt(t, runID, f.origin)
}

// RunKeyAt is [Fake.RunKey] with gatewayURL as the run key's gateway_url in place of the
// fake's URL, which its link accepts all the same.
func (f *Fake) RunKeyAt(t testing.TB, runID, gatewayURL string) string {
	t.Helper()
	if f.remote == nil {
		t.Fatal("a run key is a separate gateway's")
	}
	instance, err := accesskey.NewInstanceID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	k, err := runkey.Key{
		RunID: runID, Workspace: "ws_f1xt0re000000000", NodeID: "np_f1xt0re000000000", Gateway: "ng_f1xt0re000000000",
		InstanceID: instance, GatewayURL: gatewayURL, GatewayKeys: []accesskey.PublicKey{f.remote.key.PublicKey()},
		Issued: now, AttachBy: now.Add(10 * time.Minute),
	}.Sign(f.remote.server)
	if err != nil {
		t.Fatal(err)
	}
	f.remote.mu.Lock()
	f.remote.issued = append(f.remote.issued, k)
	f.remote.mu.Unlock()
	return k
}

// SetProof sets how the fake answers the binding of every connection from now on,
// [ProofHeld] by default.
func (f *Fake) SetProof(p Proof) {
	f.remote.mu.Lock()
	f.remote.proof = p
	f.remote.mu.Unlock()
}

// AnswerUnderUnnamedKey makes the fake sign every answer of its link from now on under
// a key no run key of its names, or, with unsigned, with no signature at all; the
// binding stays under its own key.
func (f *Fake) AnswerUnderUnnamedKey(t testing.TB, unsigned bool) {
	t.Helper()
	k, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	f.remote.mu.Lock()
	f.remote.answerKey, f.remote.unsigned = k, unsigned
	f.remote.mu.Unlock()
}

// AnswerUnderOwnKey makes the fake sign every answer of its link under its own key
// again.
func (f *Fake) AnswerUnderOwnKey() {
	f.remote.mu.Lock()
	f.remote.answerKey, f.remote.unsigned = nil, false
	f.remote.mu.Unlock()
}

// Leaked is what the edge sent on the connections whose proof failed, before it closed
// them: nothing, when it sends nothing after a failed proof.
func (f *Fake) Leaked() []string {
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	return slices.Clone(f.remote.leaked)
}

// Bound counts the connections whose binding held.
func (f *Fake) Bound() int {
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	return f.remote.bound
}
