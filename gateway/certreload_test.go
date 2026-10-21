package gateway_test

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"os"
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
