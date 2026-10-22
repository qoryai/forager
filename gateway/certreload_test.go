package gateway_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
)

// certCheckEvery is how often at most the gateway of these tests checks its certificate
// and key files.
const certCheckEvery = 50 * time.Millisecond

// replaceByRename writes b to a file beside path and renames it over path, as an ACME
// client such as Caddy replaces a certificate.
func replaceByRename(t *testing.T, path string, b []byte) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// servedCertificate is the DER of the certificate a fresh handshake with the one address
// gets, the chain verified for 127.0.0.1 against r.pool.
func servedCertificate(t *testing.T, r *remote) []byte {
	t.Helper()
	c := r.dialTLS(t)
	defer c.Close()
	return c.ConnectionState().PeerCertificates[0].Raw
}

// derOf is the DER of the first certificate of the pair in certFile and keyFile.
func derOf(t *testing.T, certFile, keyFile string) []byte {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return pair.Certificate[0]
}

// failures counts the lines r reported about its certificate and key files.
func failures(r *remote) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, l := range r.reports {
		if strings.HasPrefix(l, "replace the gateway's certificate ") {
			n++
		}
	}
	return n
}

// TestTheOneAddressReadsARenewedCertificate pins the reload of the one address's
// certificate: a pair renamed over the files is served on the next handshake once the
// check is due, a broken file keeps the pair in force and is reported once, and a
// connection made before either change keeps its TLS session and its binding.
func TestTheOneAddressReadsARenewedCertificate(t *testing.T) {
	cfg := gateway.Config{}
	gateway.SetCertCheck(&cfg, certCheckEvery)
	r := startRemote(t, nil, cfg)
	certFile, keyFile := r.cfg.TLS.CertFile, r.cfg.TLS.KeyFile
	a := derOf(t, certFile, keyFile)
	if got := servedCertificate(t, r); !bytes.Equal(got, a) {
		t.Fatal("the first handshake does not get the certificate the gateway started with")
	}
	runKey := runKeyFor(t, event.NewRunID(), nil)
	before, err := r.bind(t, gatewayKeys())
	if err != nil {
		t.Fatal(err)
	}
	defer before.Close()
	if got := before.do(t, runKey, http.MethodGet, "/qory-link/configuration", nil); got.status != http.StatusOK {
		t.Fatalf("discovery before the renewal: %d %s", got.status, got.body)
	}

	bCert, bKey, bPool := testCertificate(t, t.TempDir())
	certB, _ := os.ReadFile(bCert)
	keyB, _ := os.ReadFile(bKey)
	replaceByRename(t, certFile, certB)
	replaceByRename(t, keyFile, keyB)
	time.Sleep(2 * certCheckEvery)
	r.pool = bPool
	b := derOf(t, bCert, bKey)
	if got := servedCertificate(t, r); !bytes.Equal(got, b) {
		t.Fatal("a handshake after the renewal does not get the renewed certificate")
	}

	replaceByRename(t, certFile, []byte("-----BEGIN CERTIFICATE-----\nnot a certificate\n"))
	for range 3 {
		time.Sleep(2 * certCheckEvery)
		if got := servedCertificate(t, r); !bytes.Equal(got, b) {
			t.Fatal("a handshake after a broken certificate file does not get the pair in force")
		}
	}
	if n := failures(r); n != 1 {
		t.Errorf("the broken file is reported in %d lines, want 1", n)
	}
	want := "replace the gateway's certificate " + certFile + " and key " + keyFile + " with a certificate and its key, in PEM: reading them failed, "
	if !r.reported(want) {
		t.Errorf("no line begins %q", want)
	}

	if got := before.do(t, runKey, http.MethodGet, "/qory-link/configuration", nil); got.status != http.StatusOK {
		t.Errorf("discovery after the renewal on a connection made before it: %d %s", got.status, got.body)
	}
	if got := before.c.ConnectionState().PeerCertificates[0].Raw; !bytes.Equal(got, a) {
		t.Error("the connection made before the renewal changed its certificate")
	}

	// The gateway reads the files again at each check while the read fails: a good pair
	// renamed over them is served.
	cCert, cKey, cPool := testCertificate(t, t.TempDir())
	certC, _ := os.ReadFile(cCert)
	keyC, _ := os.ReadFile(cKey)
	replaceByRename(t, keyFile, keyC)
	replaceByRename(t, certFile, certC)
	time.Sleep(2 * certCheckEvery)
	r.pool = cPool
	if got := servedCertificate(t, r); !bytes.Equal(got, derOf(t, cCert, cKey)) {
		t.Fatal("a handshake after the repair does not get the repaired pair")
	}
	if n := failures(r); n != 1 {
		t.Errorf("after the repair, %d lines report a failure, want 1", n)
	}
}

// TestARenewedKeyBeforeItsCertificateIsNoFailure pins the read between the two renames
// of a renewal: a key renamed in before its certificate keeps the pair in force and is
// read once more at the next check, so the renewal reports nothing. A key that still
// does not match at that check is reported once.
func TestARenewedKeyBeforeItsCertificateIsNoFailure(t *testing.T) {
	cfg := gateway.Config{}
	gateway.SetCertCheck(&cfg, certCheckEvery)
	r := startRemote(t, nil, cfg)
	certFile, keyFile := r.cfg.TLS.CertFile, r.cfg.TLS.KeyFile
	a := derOf(t, certFile, keyFile)

	bCert, bKey, bPool := testCertificate(t, t.TempDir())
	certB, _ := os.ReadFile(bCert)
	keyB, _ := os.ReadFile(bKey)
	replaceByRename(t, keyFile, keyB)
	time.Sleep(2 * certCheckEvery)
	if got := servedCertificate(t, r); !bytes.Equal(got, a) {
		t.Fatal("a handshake between the key's rename and the certificate's does not get the pair in force")
	}
	if n := failures(r); n != 0 {
		t.Fatalf("a key renamed in before its certificate is reported in %d lines, want 0", n)
	}
	replaceByRename(t, certFile, certB)
	time.Sleep(2 * certCheckEvery)
	r.pool = bPool
	if got := servedCertificate(t, r); !bytes.Equal(got, derOf(t, bCert, bKey)) {
		t.Fatal("a handshake after the certificate's rename does not get the renewed pair")
	}
	if n := failures(r); n != 0 {
		t.Errorf("the renewal is reported in %d lines, want 0", n)
	}

	_, cKey, _ := testCertificate(t, t.TempDir())
	keyC, _ := os.ReadFile(cKey)
	replaceByRename(t, keyFile, keyC)
	for range 3 {
		time.Sleep(2 * certCheckEvery)
		servedCertificate(t, r)
	}
	if n := failures(r); n != 1 {
		t.Errorf("a key of another certificate is reported in %d lines, want 1", n)
	}
	if want := "reading them failed, tls: private key does not match public key;"; !r.reported(want) {
		t.Errorf("no line contains %q", want)
	}
}

// TestTheGatewayReadsAtMost1MiBOfACertificateFile pins the bound of a read: a key file
// longer than 1 MiB fails Start, and renamed in later, it keeps the pair in force and is
// reported once.
func TestTheGatewayReadsAtMost1MiBOfACertificateFile(t *testing.T) {
	dir := t.TempDir()
	certFile, _, _ := testCertificate(t, dir)
	big := filepath.Join(dir, "big.pem")
	if err := os.WriteFile(big, bytes.Repeat([]byte("a"), 1<<20+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := gateway.Start(context.Background(), gateway.Config{Dir: t.TempDir(), Listen: "127.0.0.1:0", TLS: &gateway.TLS{CertFile: certFile, KeyFile: big}, Server: gatewayControl(t).server()})
	want := "the gateway's certificate " + certFile + " and key " + big + ": " + big + " is longer than 1 MiB, the most the gateway reads of a certificate or key file"
	if err == nil || err.Error() != want {
		t.Errorf("Start with a key file of 1 MiB and 1 byte: %v; want %q", err, want)
	}

	cfg := gateway.Config{}
	gateway.SetCertCheck(&cfg, certCheckEvery)
	r := startRemote(t, nil, cfg)
	a := derOf(t, r.cfg.TLS.CertFile, r.cfg.TLS.KeyFile)
	replaceByRename(t, r.cfg.TLS.KeyFile, bytes.Repeat([]byte("a"), 1<<20+1))
	for range 3 {
		time.Sleep(2 * certCheckEvery)
		if got := servedCertificate(t, r); !bytes.Equal(got, a) {
			t.Fatal("a handshake after a key file of 1 MiB and 1 byte does not get the pair in force")
		}
	}
	if n := failures(r); n != 1 {
		t.Errorf("the long key file is reported in %d lines, want 1", n)
	}
	if want := "reading them failed, " + r.cfg.TLS.KeyFile + " is longer than 1 MiB, the most the gateway reads of a certificate or key file;"; !r.reported(want) {
		t.Errorf("no line contains %q", want)
	}
}

// TestAKeyThatChangesBeforeEveryCheckIsReported pins the bound of the held failure: a
// key of another certificate renamed in before each check is held at the first check
// alone and reported at the second.
func TestAKeyThatChangesBeforeEveryCheckIsReported(t *testing.T) {
	cfg := gateway.Config{}
	gateway.SetCertCheck(&cfg, certCheckEvery)
	r := startRemote(t, nil, cfg)
	a := derOf(t, r.cfg.TLS.CertFile, r.cfg.TLS.KeyFile)
	for check, want := range []int{0, 1} {
		_, other, _ := testCertificate(t, t.TempDir())
		key, _ := os.ReadFile(other)
		replaceByRename(t, r.cfg.TLS.KeyFile, key)
		time.Sleep(2 * certCheckEvery)
		if got := servedCertificate(t, r); !bytes.Equal(got, a) {
			t.Fatalf("check %d: a handshake does not get the pair in force", check+1)
		}
		if n := failures(r); n != want {
			t.Fatalf("check %d: %d lines report a failure, want %d", check+1, n, want)
		}
	}
	if want := "reading them failed, tls: private key does not match public key;"; !r.reported(want) {
		t.Errorf("no line contains %q", want)
	}
}
