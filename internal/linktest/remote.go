package linktest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// remote is a fake separate gateway's TLS server and the file of its authority.
type remote struct {
	srv    *httptest.Server
	caFile string
}

// StartRemoteFake starts a fake separate gateway, until the test ends: the answers of
// [StartFake] over TLS 1.3 on 127.0.0.1, under an authority of its own whose certificate
// names 127.0.0.1 alone, with a heartbeat interval of one second. Its discovery lists
// URLs of its own origin and names its one address as its proxy, its run answer's
// credential is starter, and it answers the outcome request {} unless OnOutcome says
// otherwise. It has no local link and no proxy of its own: Local, Socket, Secret and
// ProxyAddr are not its.
func StartRemoteFake(t testing.TB) *Fake {
	t.Helper()
	f := &Fake{interval: 1, Gateway: &Gateway{}}
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
	r := &remote{caFile: filepath.Join(t.TempDir(), "ca.pem")}
	if err := os.WriteFile(r.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	r.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	r.srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	r.srv.StartTLS()
	t.Cleanup(r.srv.Close)
	f.remote, f.origin = r, r.srv.URL
	return f
}

// URL is a fake separate gateway's URL, https://127.0.0.1:<port>; empty on the local
// link.
func (f *Fake) URL() string { return f.origin }

// CAFile is the PEM file of a fake separate gateway's authority, which a session trusts
// it by; empty on the local link.
func (f *Fake) CAFile() string {
	if f.remote == nil {
		return ""
	}
	return f.remote.caFile
}

// Credential is a run credential a fake separate gateway takes, in the syntax of a
// Bearer token and no real one: the fake checks none.
func Credential(context.Context) (string, error) {
	return "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJyay0wMDAxIn0.ZmFrZS1jcmVkZW50aWFs", nil
}
