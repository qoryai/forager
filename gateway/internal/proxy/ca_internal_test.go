package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/qoryai/forager/policy"
)

// TestAnAuthorityKeepsABoundedCacheOfLeaves pins the bound on an authority's
// certificates: at most leafCap hosts' are kept, the least recently used going first, a
// host asked for again is the same certificate while it is kept, and one that went is
// made again.
func TestAnAuthorityKeepsABoundedCacheOfLeaves(t *testing.T) {
	defer func(n int) { leafCap = n }(leafCap)
	leafCap = 3
	run, err := NewCA("test", []string{"*.example"})
	if err != nil {
		t.Fatal(err)
	}
	boundedLeaves(t, run)
}

// boundedLeaves checks ca's cache of leaves, under a leafCap of 3.
func boundedLeaves(t *testing.T, ca *CA) {
	first := map[string]any{}
	for i := range 3 {
		host := fmt.Sprintf("h%d.example", i)
		l, err := ca.leaf(host)
		if err != nil {
			t.Fatal(err)
		}
		first[host] = l
	}
	// h0 is used again, so h1 is the least recently used when h3 comes.
	if l, _ := ca.leaf("h0.example"); l != first["h0.example"] {
		t.Error("a kept host's certificate was made again")
	}
	if _, err := ca.leaf("h3.example"); err != nil {
		t.Fatal(err)
	}
	if len(ca.leaves) != 3 || ca.order.Len() != 3 {
		t.Fatalf("%d leaves, %d in order", len(ca.leaves), ca.order.Len())
	}
	if _, ok := ca.leaves["h1.example"]; ok {
		t.Error("the least recently used host is still kept")
	}
	for _, h := range []string{"h0.example", "h2.example"} {
		if l, _ := ca.leaf(h); l != first[h] {
			t.Errorf("%s was made again", h)
		}
	}
	if l, _ := ca.leaf("h1.example"); l == first["h1.example"] {
		t.Error("a host that went was not made again")
	}
	if len(ca.leaves) != 3 {
		t.Errorf("%d leaves", len(ca.leaves))
	}
}

// upstreamCA is an authority with no name constraints, which only a test makes: the
// authority of an origin that answers as any host.
func upstreamCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "upstream"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caLife),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return caOf(der, key)
}

// verified is the error of verifying the leaf as host, by Go's x509, under the
// authority alone.
func verified(ca *CA, leaf *x509.Certificate, host string) error {
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host})
	return err
}

// leafFor is the authority's leaf for the host, failing the test when it is not made.
func leafFor(t *testing.T, ca *CA, host string) *x509.Certificate {
	t.Helper()
	l, err := ca.leaf(host)
	if err != nil {
		t.Fatal(err)
	}
	return l.Leaf
}

// signed is a leaf the authority's key signs, as a stolen key could: the names in the
// template, whatever the run terminates.
func signed(t *testing.T, ca *CA, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(2)
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestARunsAuthorityIsGoodOnlyForItsHosts pins the name constraints of a run's
// authority: a "*." entry is the name under it, a name is itself and an IPv4 address
// a /32, in one critical constraint. Go's x509 verifies the leaf of each terminated
// host, a name under a "*." entry, the name of the entry itself and a name under a
// listed name; it rejects a leaf for another name, an address not listed, an IPv6
// address when only IPv4 is permitted, and a leaf with the name in its common name
// alone.
func TestARunsAuthorityIsGoodOnlyForItsHosts(t *testing.T) {
	ca, err := NewCA("test", []string{"api.example.com", "*.git.example", "192.0.2.10", "vault", "API.example.com", "*.local", "*.192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ca.cert.PermittedDNSDomains, []string{"api.example.com", "git.example", "vault", "local"}; !slices.Equal(got, want) || !ca.cert.PermittedDNSDomainsCritical {
		t.Errorf("permitted names %q, critical %v; want %q, critical", got, ca.cert.PermittedDNSDomainsCritical, want)
	}
	if got := ca.cert.PermittedIPRanges; len(got) != 1 || got[0].String() != "192.0.2.10/32" || len(ca.cert.ExcludedIPRanges) != 0 {
		t.Errorf("permitted addresses %v, excluded %v; want 192.0.2.10/32 alone", got, ca.cert.ExcludedIPRanges)
	}
	for _, host := range []string{"api.example.com", "x.git.example", "a.b.git.example", "git.example", "v1.api.example.com", "192.0.2.10", "vault"} {
		if err := verified(ca, leafFor(t, ca, host), host); err != nil {
			t.Errorf("the leaf for %s: %v", host, err)
		}
	}
	// An address's leaf has no common name, which OpenSSL would read as a name.
	if cn := leafFor(t, ca, "192.0.2.10").Subject.CommonName; cn != "" {
		t.Errorf("the address's leaf has the common name %q", cn)
	}
	for _, host := range []string{"evil.example", "example.com", "192.0.2.11", "2001:db8::1", "127.0.0.1"} {
		if err := verified(ca, leafFor(t, ca, host), host); err == nil {
			t.Errorf("the leaf for %s verifies", host)
		}
	}
	cnOnly := signed(t, ca, &x509.Certificate{Subject: pkix.Name{CommonName: "api.example.com"}})
	if err := verified(ca, cnOnly, "api.example.com"); err == nil {
		t.Error("a leaf with the name in its common name alone verifies")
	}
	// A key that signs one leaf for a permitted name and another is still refused.
	both := signed(t, ca, &x509.Certificate{DNSNames: []string{"api.example.com", "evil.example"}})
	if err := verified(ca, both, "api.example.com"); err == nil {
		t.Error("a leaf that has a name outside the constraints as well verifies")
	}
}

// TestARunsAuthorityWithAnIPv6Address pins an IPv6 entry: a /128, the only address
// permitted, so an IPv4 address is refused, and only invalid among names.
func TestARunsAuthorityWithAnIPv6Address(t *testing.T) {
	ca, err := NewCA("test", []string{"2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := ca.cert.PermittedIPRanges; len(got) != 1 || got[0].String() != "2001:db8::1/128" {
		t.Errorf("permitted addresses %v", got)
	}
	if err := verified(ca, leafFor(t, ca, "2001:db8::1"), "2001:db8::1"); err != nil {
		t.Errorf("the leaf for 2001:db8::1: %v", err)
	}
	for _, host := range []string{"2001:db8::2", "192.0.2.10", "api.example.com"} {
		if err := verified(ca, leafFor(t, ca, host), host); err == nil {
			t.Errorf("the leaf for %s verifies", host)
		}
	}
}

// TestARunsAuthorityWithNoHost pins a run that terminates nothing: its authority
// permits only the name invalid and excludes every address, so no leaf for a real
// host verifies.
func TestARunsAuthorityWithNoHost(t *testing.T) {
	ca, err := NewCA("test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ca.cert.PermittedDNSDomains; !slices.Equal(got, []string{"invalid"}) || !ca.cert.PermittedDNSDomainsCritical {
		t.Errorf("permitted names %q, critical %v", got, ca.cert.PermittedDNSDomainsCritical)
	}
	var excluded []string
	for _, n := range ca.cert.ExcludedIPRanges {
		excluded = append(excluded, n.String())
	}
	if !slices.Equal(excluded, []string{"0.0.0.0/0", "::/0"}) || len(ca.cert.PermittedIPRanges) != 0 {
		t.Errorf("excluded %v, permitted %v", excluded, ca.cert.PermittedIPRanges)
	}
	for _, host := range []string{"api.example.com", "localhost", "127.0.0.1", "::1"} {
		if err := verified(ca, leafFor(t, ca, host), host); err == nil {
			t.Errorf("the leaf for %s verifies", host)
		}
	}
}

// TestAnAuthorityPermitsTheEntriesUnderIt pins [CA.Permits], which a reload is
// checked by: an entry under a permitted name or address is permitted, any other is
// not, and one that matches no host a request can name is.
func TestAnAuthorityPermitsTheEntriesUnderIt(t *testing.T) {
	ca, err := NewCA("test", []string{"*.example.com", "vault", "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	for entry, want := range map[string]bool{
		"example.com": true, "api.example.com": true, "*.api.example.com": true, "*.example.com": true,
		"vault": true, "x.vault": true, "192.0.2.10": true,
		"example.org": false, "*.com": false, "notexample.com": false, "192.0.2.11": false, "2001:db8::1": false, "vaults": false,
		"a..b": true, "*.192.0.2.11": true,
	} {
		if got := ca.Permits(entry); got != want {
			t.Errorf("Permits(%q) = %v, want %v", entry, got, want)
		}
	}
}

// TestAReloadMayNotTerminateAHostOutsideTheAuthority pins [Proxy.Outside]: under the
// hosts the run started with, nothing is outside; a credential or a path rule for
// another host is, a credential's host reported first; a host under a "*." entry is
// not.
func TestAReloadMayNotTerminateAHostOutsideTheAuthority(t *testing.T) {
	p, err := Listen("", policy.Observe, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	cred := func(hosts ...string) []Credential {
		return []Credential{{Name: "model", Hosts: hosts, Scheme: "bearer", Token: func() string { return "x" }}}
	}
	paths := map[string][]string{"*.paths.example": {"/*"}}
	tools := []Tool{{Name: "tool", Hosts: []string{"tool.example"}, Socket: "/nonexistent.sock"}}
	if host, _ := p.Outside(paths, cred("evil.example")); host != "" {
		t.Errorf("without a terminator, %s is outside", host)
	}
	ca, err := NewCA("test", p.Terminating(cred("api.example.com"), paths, tools))
	if err != nil {
		t.Fatal(err)
	}
	p.Terminate(ca, cred("api.example.com"), paths, tools)
	for name, c := range map[string]struct {
		paths      map[string][]string
		creds      []Credential
		host       string
		credential bool
	}{
		"the same hosts":                  {paths, cred("api.example.com"), "", false},
		"fewer hosts":                     {nil, nil, "", false},
		"a host under a listed name":      {map[string][]string{"v1.api.example.com": {"/*"}}, cred("x.paths.example"), "", false},
		"a credential for another host":   {paths, cred("api.example.com", "other.example"), "other.example", true},
		"a path rule for another host":    {map[string][]string{"other.example": {"/*"}}, nil, "other.example", false},
		"both, the credential first":      {map[string][]string{"path.example": {"/*"}}, cred("cred.example"), "cred.example", true},
		"a credential on the tool's host": {nil, cred("tool.example"), "", false},
	} {
		if host, credential := p.Outside(c.paths, c.creds); host != c.host || credential != c.credential {
			t.Errorf("%s: Outside = %q, %v; want %q, %v", name, host, credential, c.host, c.credential)
		}
	}
}
