package session_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
)

// pinOf is the pin of the fake g's certificate: the SHA-256 of its public key, in
// standard base64 with padding.
func pinOf(t *testing.T, g *linktest.Fake) string {
	t.Helper()
	b, err := os.ReadFile(g.CAFile())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b)
	c, err := tls.Dial("tcp", strings.TrimPrefix(g.URL(), "https://"), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sum := sha256.Sum256(c.ConnectionState().PeerCertificates[0].RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// TestARemoteGatewaysCertificateIsCheckedAsItsTLSSays pins RemoteGateway.TLS: the zero
// TLS checks the chain against the system's roots, which do not have the fake's
// authority, so the run fails before the binding; CAFile set to that authority's PEM
// file runs; a pin of the certificate's public key runs as well; and a pin of another
// key fails before the binding, and the runtime never starts.
func TestARemoteGatewaysCertificateIsCheckedAsItsTLSSays(t *testing.T) {
	g := startRemote(t)
	g.SetInterval(30)
	other := sha256.Sum256([]byte("another key"))
	for name, c := range map[string]struct {
		tls  server.RemoteTLS
		fail string
	}{
		"the system's roots":      {fail: "certificate"},
		"the CA file":             {tls: server.RemoteTLS{CAFile: g.CAFile()}},
		"the CA file and its pin": {tls: server.RemoteTLS{CAFile: g.CAFile(), CertificateSHA256: pinOf(t, g)}},
		"another key's pin": {
			tls:  server.RemoteTLS{CAFile: g.CAFile(), CertificateSHA256: base64.StdEncoding.EncodeToString(other[:])},
			fail: "the gateway's certificate does not have the public key its pin names",
		},
	} {
		bound, bearers := g.Bound(), len(g.Bearers())
		r := newSepRun(t, session.RemoteGateway{RunKey: g.RunKey(t, event.NewRunID()), TLS: c.tls})
		res, err := run(context.Background(), r.sp)
		if c.fail == "" {
			if err != nil || res.State != "succeeded" {
				t.Errorf("%s: %v, %+v", name, err, res)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.fail) {
			t.Errorf("%s: %v, want an error with %q", name, err, c.fail)
		}
		if r.started() || g.Bound() != bound || len(g.Bearers()) != bearers {
			t.Errorf("%s: the runtime started, or the gateway was sent something", name)
		}
	}
}

// TestARemoteGatewaysTLSOfAnotherFormIsNoRun pins the check of RemoteGateway.TLS before
// the run: a CA file that is missing, unreadable or has no PEM certificate, and a pin
// not in its form, are each an error that starts with the fix, with the path where the
// error has one and no run key in it, before any run directory or connection; a resend
// refuses the same CA file with the same error.
func TestARemoteGatewaysTLSOfAnotherFormIsNoRun(t *testing.T) {
	g := startRemote(t)
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("no certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	unreadable := filepath.Join(dir, "unreadable.pem")
	if err := os.WriteFile(unreadable, []byte("no certificate"), 0o000); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "none.pem")
	secretPath := filepath.Join(dir, "qrk_x", "ca.pem")
	const caFix = "set the gateway's CA file to a PEM file of its certificate authorities that Forager can read: "
	const pinFix = "set the gateway's certificate pin to the SHA-256 of its public key: 44 characters of standard base64 ending in ="
	sum := sha256.Sum256([]byte("a key"))
	cases := map[string]struct {
		tls       server.RemoteTLS
		fix, path string
	}{
		"a missing CA file":         {server.RemoteTLS{CAFile: missing}, caFix, missing},
		"a CA file not PEM":         {server.RemoteTLS{CAFile: notPEM}, caFix, notPEM + " contains no PEM certificate"},
		"a CA file in a qrk_ path":  {server.RemoteTLS{CAFile: secretPath}, caFix, ""},
		"a hex pin":                 {server.RemoteTLS{CertificateSHA256: strings.Repeat("ab", 32)}, pinFix, ""},
		"a pin without its padding": {server.RemoteTLS{CertificateSHA256: base64.RawStdEncoding.EncodeToString(sum[:])}, pinFix, ""},
	}
	if os.Geteuid() != 0 {
		cases["an unreadable CA file"] = struct {
			tls       server.RemoteTLS
			fix, path string
		}{server.RemoteTLS{CAFile: unreadable}, caFix, unreadable}
	}
	for name, c := range cases {
		r := newSepRun(t, session.RemoteGateway{RunKey: g.RunKey(t, event.NewRunID()), TLS: c.tls})
		_, err := run(context.Background(), r.sp)
		if err == nil || !strings.HasPrefix(err.Error(), c.fix) || !strings.Contains(err.Error(), c.path) || strings.Contains(err.Error(), "qrk_") ||
			strings.Count(err.Error(), "the gateway's") != 1 || (c.fix == pinFix && err.Error() != pinFix) {
			t.Errorf("%s: %v, want %q and %q", name, err, c.fix, c.path)
		}
		if entries, _ := os.ReadDir(r.sp.RunsDir); len(entries) != 0 || r.started() {
			t.Errorf("%s: a run directory %v, or the runtime started", name, entries)
		}
	}
	if g.Bound() != 0 || len(g.Bearers()) != 0 {
		t.Error("a TLS the session refused reached the gateway")
	}

	resend, rg := undeliveredRun(t)
	before := rg.Bound()
	resend.Gateway.TLS = server.RemoteTLS{CAFile: missing}
	if _, err := session.Resend(context.Background(), resend); err == nil || !strings.HasPrefix(err.Error(), caFix) || !strings.Contains(err.Error(), missing) {
		t.Errorf("a resend with a missing CA file: %v", err)
	}
	if rg.Bound() != before {
		t.Error("a resend with a missing CA file reached the gateway")
	}
}
