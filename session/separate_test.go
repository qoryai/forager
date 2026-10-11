package session_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/sink"
)

// The runs of this file are a real session.Run behind a separate gateway: a real
// gateway, gateway.Start, serving its one address on loopback over TLS, and the
// session's RemoteGateway pointed at it. The gateway has no verifier of a request's
// bearer value on its one address yet: it refuses every request of its contract there,
// the 401 unauthorized, so no run opens behind it.

// separate is a gateway serving its one address over TLS, and how a session trusts it.
type separate struct {
	g           *gateway.Gateway
	dir         string
	caFile, pin string
	pool        *x509.CertPool

	mu      sync.Mutex
	reports []string
}

// startSeparate starts a gateway on 127.0.0.1 over TLS, under an authority of the test's
// own, whose certificate names 127.0.0.1 alone, with a policy that allows api.example
// alone.
func startSeparate(t *testing.T) *separate {
	t.Helper()
	return startSeparateBeating(t, time.Second)
}

// startSeparateBeating is startSeparate with the heartbeat interval its discovery
// announces: the gateway ends a run whose session sends nothing for three.
func startSeparateBeating(t *testing.T, heartbeat time.Duration) *separate {
	t.Helper()
	certDir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "separate test authority"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "gateway.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"gateway.example"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	s := &separate{dir: t.TempDir(), caFile: filepath.Join(certDir, "ca.pem"), pin: base64.StdEncoding.EncodeToString(sum[:]), pool: x509.NewCertPool()}
	s.pool.AddCert(ca)
	certFile, keyFile := filepath.Join(certDir, "gateway.pem"), filepath.Join(certDir, "gateway-key.pem")
	for file, b := range map[string][]byte{
		s.caFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		certFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyFile:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		if err := os.WriteFile(file, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	g, err := gateway.Start(context.Background(), gateway.Config{
		Version: "test", Heartbeat: heartbeat, Dir: s.dir,
		Listen: "127.0.0.1:0", TLS: &gateway.TLS{CertFile: certFile, KeyFile: keyFile},
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example"}}},
		Report: func(l string) {
			t.Log("the gateway reported:", l)
			s.mu.Lock()
			s.reports = append(s.reports, l)
			s.mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.g = g
	t.Cleanup(func() { s.close(t) })
	return s
}

// close ends the gateway, which numbers each run's last events.
func (s *separate) close(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := s.g.Close(ctx); err != nil {
		t.Errorf("the gateway's close: %v", err)
	}
}

// url is the gateway's URL, its one address.
func (s *separate) url() string { return "https://" + s.g.Addr() }

// remote is the session's RemoteGateway of the gateway.
func (s *separate) remote() session.RemoteGateway {
	return session.RemoteGateway{URL: s.url(), CAFile: s.caFile, CertificateSHA256: s.pin}
}

// runs are the runs the gateway holds a record of.
func (s *separate) runs() []string {
	entries, _ := os.ReadDir(filepath.Join(s.dir, "runs"))
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// deniedURL is a host the gateway's policy does not allow: a request for it reaches
// the gateway's proxy and is denied there.
const deniedURL = "http://denied.invalid/a"

// sepRun is a run of the fake runtime behind the gateway: it writes its environment to
// envFile and asks for deniedURL through its proxy; what the session reported is in
// reports.
type sepRun struct {
	sp      session.Spec
	envFile string
	stderr  *syncBuffer

	mu      sync.Mutex
	reports []string
}

func newSepRun(t *testing.T, gw session.Gateway) *sepRun {
	t.Helper()
	r := &sepRun{envFile: filepath.Join(t.TempDir(), "env"), stderr: &syncBuffer{}}
	stdout := &syncBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("stdout:\n%s\nstderr:\n%s", stdout.String(), r.stderr.String())
		}
	})
	r.sp = session.Spec{
		Command: "/bin/sh", Args: []string{"-c", `env > "$0"; exec "$1"`, r.envFile, os.Args[0]},
		Env: []string{"FAKE_RUNTIME=1", "FAKE_EXIT=0", "FAKE_DENIED_URL=" + deniedURL, "PATH=" + os.Getenv("PATH")},
		Dir: t.TempDir(), RunsDir: filepath.Join(t.TempDir(), "runs"),
		Stdin: strings.NewReader(""), Stdout: stdout, Stderr: r.stderr,
		Gateway: gw, ForagerVersion: "test",
		Labels: map[string]string{"forge": "example-forge", "repository": "example-namespace/project"},
		About:  &session.About{Title: "Example title"},
		Report: func(l string) {
			t.Log("the session reported:", l)
			r.mu.Lock()
			r.reports = append(r.reports, l)
			r.mu.Unlock()
		},
	}
	return r
}

// refusedRun runs r, which the gateway refuses, and returns the refusal: the gateway's,
// with its message as the error's text word for word, recorded as dev.qory.run.refused
// in the session's record alone when the run request was refused, the runtime never
// started.
func refusedRun(t *testing.T, r *sepRun) *session.Refusal {
	t.Helper()
	res, err := session.Run(context.Background(), r.sp)
	var ref *session.Refusal
	if !errors.As(err, &ref) || res != nil {
		t.Fatalf("a refused run: %v %+v", err, res)
	}
	if ref.From != accesskey.FromGateway || ref.Text == "" || err.Error() != ref.Text {
		t.Errorf("the refusal %#v, its text %q", ref, err.Error())
	}
	if _, err := os.Stat(r.envFile); err == nil {
		t.Error("the runtime started")
	}
	return ref
}

// resendSpec is the resend of a run's directory through s.
func resendSpec(s *separate, dir string) session.ResendSpec {
	return session.ResendSpec{Gateway: s.remote(), Dir: dir, ForagerVersion: "test"}
}

// TestASeparateGatewayRefusesARunItCannotAuthenticate pins a session behind a separate
// gateway that has no verifier of a request's bearer value on its one address: the
// session sends none, the gateway's 401 unauthorized is the run's refusal with its text
// word for word, the runtime never starts, and the gateway opens nothing.
func TestASeparateGatewayRefusesARunItCannotAuthenticate(t *testing.T) {
	s := startSeparate(t)
	ref := refusedRun(t, newSepRun(t, s.remote()))
	if ref.Code != accesskey.CodeUnauthorized || ref.Status != 401 || ref.Text != "the gateway refused the run: unauthorized" {
		t.Errorf("the refusal %#v", ref)
	}
	if runs := s.runs(); len(runs) != 0 {
		t.Errorf("the gateway opened %v", runs)
	}
}

// TestASessionTrustsTheSeparateGatewayItIsTold pins the trust behind a separate
// gateway at the session: without the gateway's authority, or with a pin of another
// key, the run does not start, before any request, and the gateway opens nothing; and
// a RemoteGateway prints by its URL, its CAFile and its pin.
func TestASessionTrustsTheSeparateGatewayItIsTold(t *testing.T) {
	s := startSeparate(t)
	sum := sha256.Sum256([]byte("another key"))
	for name, gw := range map[string]session.RemoteGateway{
		"the system's roots": {URL: s.url()},
		"another pin":        {URL: s.url(), CAFile: s.caFile, CertificateSHA256: base64.StdEncoding.EncodeToString(sum[:])},
	} {
		// Not the gateway's 401: the session never reaches its contract.
		var ref *session.Refusal
		if _, err := session.Run(context.Background(), newSepRun(t, gw).sp); err == nil || errors.As(err, &ref) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if runs := s.runs(); len(runs) != 0 {
		t.Errorf("the gateway opened %v", runs)
	}
	gw := s.remote()
	for _, out := range []string{fmt.Sprint(gw), fmt.Sprintf("%#v", gw), fmt.Sprintf("%+v", &gw), gw.String()} {
		if !strings.Contains(out, s.url()) || !strings.Contains(out, s.pin) || strings.Contains(out, "0x") {
			t.Errorf("printed as %s", out)
		}
	}
	// A URL the session refuses prints by its origin alone, nothing after it or before
	// its host.
	for raw, want := range map[string]string{
		"https://user:pw-of-the-url@gateway.example:8443/path?q=query-of-the-url#fragment-of-the-url": "session.RemoteGateway{https://gateway.example:8443}",
		"gateway.example/path-of-the-url": "session.RemoteGateway{(not a URL)}",
		"":                                "session.RemoteGateway{(no URL)}",
	} {
		if got := (session.RemoteGateway{URL: raw}).String(); got != want {
			t.Errorf("%q prints as %s", raw, got)
		}
	}
}

// TestAResendTakesTheSessionsRecordAlone pins what Resend refuses before any request:
// a directory without session.jsonl, a gateway's
// record, events.jsonl, which gateway.Resend sends, and a record its session still
// holds.
func TestAResendTakesTheSessionsRecordAlone(t *testing.T) {
	t.Parallel()
	s := startSeparate(t)
	dir := filepath.Join(t.TempDir(), "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e71")
	if _, err := session.Resend(context.Background(), resendSpec(s, dir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no record: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sink.EventsFile), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Resend(context.Background(), resendSpec(s, dir)); !errors.Is(err, os.ErrExist) {
		t.Errorf("a gateway's record: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, sink.EventsFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sink.SessionFile), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// The session's lock, held as a live session holds it.
	held, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Resend(context.Background(), resendSpec(s, dir)); !errors.Is(err, session.ErrRunning) {
		t.Errorf("a record its session holds: %v", err)
	}
	held.Close()
}
