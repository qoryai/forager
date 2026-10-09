package runcredential

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/contracts"
)

// The neutral examples every test uses.
const (
	exampleIssuer   = "https://issuer.example"
	exampleAudience = "qory-gateway"
)

// knownAnswers is the directory of the run credential's known answers in the contract.
const knownAnswers = "fixtures/known-answers/run-credentials"

// knownFile reads one file of the known answers.
func knownFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(contracts.FS, path.Join(knownAnswers, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// files is a ReadFile over a map of names to contents.
func files(m map[string][]byte) ReadFile {
	return func(name string) ([]byte, error) {
		b, ok := m[name]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return b, nil
	}
}

// pemOf is one PEM block.
func pemOf(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// pkix is the PEM of a public key.
func pkixPEM(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pemOf("PUBLIC KEY", der)
}

// d is a *Duration.
func d(v time.Duration) *Duration { x := Duration(v); return &x }

// issuer is the neutral example issuer with one RS256 key, rs256.pem, without a kid.
func issuer() Issuer {
	return Issuer{
		Issuer:     exampleIssuer,
		Audience:   exampleAudience,
		Algorithms: []string{RS256},
		Keys:       []Key{{Alg: RS256, PublicKeyFile: "rs256.pem"}},
		Allow:      &Allow{Claim: "namespace", Values: []string{"example-namespace"}},
		LabelMapping: LabelMapping{
			Forge:      Source{Value: "example-forge"},
			Repository: Source{Claims: []string{"namespace", "project"}, Join: "/"},
			RunKey:     Claim{Claim: "sub"},
		},
		DetailMapping: map[string]Claim{"requester": {Claim: "requester"}},
	}
}

func fixtureKeys(t *testing.T) map[string][]byte {
	return map[string][]byte{
		"rs256.pem": knownFile(t, "rs256.pem"),
		"es256.pem": knownFile(t, "es256.pem"),
		"eddsa.pem": knownFile(t, "eddsa.pem"),
	}
}

func TestParseReadsTheFixtures(t *testing.T) {
	keys := fixtureKeys(t)
	read := files(map[string][]byte{
		"/etc/qory/issuer-k1.pem": keys["rs256.pem"],
		"/etc/qory/issuer-k2.pem": keys["es256.pem"],
	})
	entries, err := fs.ReadDir(contracts.FS, "fixtures/run-credentials")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatalf("fixtures/run-credentials holds %d fixtures; want two", len(entries))
	}
	for _, e := range entries {
		f := "fixtures/run-credentials/" + e.Name()
		b, err := fs.ReadFile(contracts.FS, f)
		if err != nil {
			t.Fatal(err)
		}
		l, err := Parse(f, b)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if err := l.Check(read); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	b, _ := fs.ReadFile(contracts.FS, "fixtures/run-credentials/rotation-introspection.yaml")
	l, err := Parse("rotation-introspection.yaml", b)
	if err != nil {
		t.Fatal(err)
	}
	i := l[0]
	if i.LeewayOrDefault() != time.Minute || time.Duration(*i.MaxLifetime) != time.Hour ||
		i.Introspection.CacheOr(time.Minute) != 30*time.Second ||
		i.Keys[1].KID != "k2" || i.LabelMapping.Repository.Join != "/" ||
		i.DetailMapping["requester"].Claim != "requester" || i.Allow.Values[0] != "example-namespace" {
		t.Errorf("rotation-introspection.yaml decodes as %+v", i)
	}
	b, _ = fs.ReadFile(contracts.FS, "fixtures/run-credentials/one-key.yaml")
	l, _ = Parse("one-key.yaml", b)
	if l[0].LeewayOrDefault() != DefaultLeeway || l[0].MaxLifetime != nil || l[0].Introspection != nil {
		t.Errorf("one-key.yaml: the defaults are %v, %v, %v", l[0].LeewayOrDefault(), l[0].MaxLifetime, l[0].Introspection)
	}
	if (Introspection{}).CacheOr(30*time.Second) != 30*time.Second {
		t.Error("an introspection without cache does not hold for the heartbeat interval")
	}
}

func TestParseRefusesTheInvalidFixtures(t *testing.T) {
	names, err := fs.Glob(contracts.FS, "fixtures/invalid/run-credentials-*")
	if err != nil || len(names) < 5 {
		t.Fatalf("found %d invalid run credentials fixtures: %v", len(names), err)
	}
	for _, f := range names {
		b, _ := fs.ReadFile(contracts.FS, f)
		if _, err := Parse(f, b); err == nil {
			t.Errorf("%s: Parse accepts it", f)
		}
	}
	if _, err := Parse("empty.json", []byte("[]")); err == nil {
		t.Error("Parse accepts an empty list")
	}
}

func TestIssuerCheck(t *testing.T) {
	keys := fixtureKeys(t)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	x25519, _ := ecdh.X25519().GenerateKey(rand.Reader)
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	privDER, _ := x509.MarshalPKCS8PrivateKey(edPriv)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example"}, NotAfter: time.Now().Add(time.Hour)}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, p256.Public(), p256)
	if err != nil {
		t.Fatal(err)
	}
	identity := make(ed25519.PublicKey, 32)
	identity[0] = 1
	keys["small.pem"] = pkixPEM(t, &small.PublicKey)
	big2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys["e1.pem"] = pkixPEM(t, &rsa.PublicKey{N: big2048.N, E: 1})
	keys["e-even.pem"] = pkixPEM(t, &rsa.PublicKey{N: big2048.N, E: 65536})
	keys["p384.pem"] = pkixPEM(t, &p384.PublicKey)
	keys["x25519.pem"] = pkixPEM(t, x25519.PublicKey())
	keys["identity.pem"] = pkixPEM(t, identity)
	keys["private.pem"] = pemOf("PRIVATE KEY", privDER)
	keys["certificate.pem"] = pemOf("CERTIFICATE", certDER)
	keys["pkcs1.pem"] = pemOf("RSA PUBLIC KEY", x509.MarshalPKCS1PublicKey(&small.PublicKey))
	keys["two-blocks.pem"] = append(append([]byte{}, keys["es256.pem"]...), keys["es256.pem"]...)
	keys["headers.pem"] = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{1}})
	keys["not-pem.pem"] = []byte("not a key")
	read := files(keys)

	for _, c := range []struct {
		name   string
		change func(*Issuer)
		want   string // a part of the error; empty for none
	}{
		{"the example", func(*Issuer) {}, ""},
		{"three algorithms, three keys with kids", func(i *Issuer) {
			i.Algorithms = []string{RS256, ES256, EdDSA}
			i.Keys = []Key{{KID: "a", Alg: RS256, PublicKeyFile: "rs256.pem"}, {KID: "b", Alg: ES256, PublicKeyFile: "es256.pem"}, {KID: "c", Alg: EdDSA, PublicKeyFile: "eddsa.pem"}}
		}, ""},
		{"repository from one claim, forge from a claim", func(i *Issuer) {
			i.LabelMapping.Forge = Source{Claim: "forge"}
			i.LabelMapping.Repository = Source{Claim: "project"}
		}, ""},
		{"an issuer over http", func(i *Issuer) { i.Issuer = "http://issuer.example" }, "not an https URL"},
		{"an issuer with a query", func(i *Issuer) { i.Issuer = "https://issuer.example/?a=b" }, "not an https URL"},
		{"an issuer with a fragment", func(i *Issuer) { i.Issuer = "https://issuer.example/#a" }, "not an https URL"},
		{"an issuer with a user", func(i *Issuer) { i.Issuer = "https://user@issuer.example" }, "not an https URL"},
		{"no audience", func(i *Issuer) { i.Audience = "" }, "no audience"},
		{"no algorithm", func(i *Issuer) { i.Algorithms = nil }, "no algorithm"},
		{"alg none", func(i *Issuer) { i.Algorithms = []string{"none"} }, `"none" is not`},
		{"HS256", func(i *Issuer) { i.Algorithms = []string{"HS256"} }, `"HS256" is not`},
		{"ES384", func(i *Issuer) { i.Algorithms = []string{RS256, "ES384"} }, `"ES384" is not`},
		{"an algorithm twice", func(i *Issuer) { i.Algorithms = []string{RS256, RS256} }, "appears twice"},
		{"no key", func(i *Issuer) { i.Keys = nil }, "no key"},
		{"a key's alg outside the algorithms", func(i *Issuer) {
			i.Keys = []Key{{Alg: ES256, PublicKeyFile: "es256.pem"}}
		}, "not among the issuer's algorithms"},
		{"a key's alg HS256", func(i *Issuer) { i.Keys[0].Alg = "HS256" }, "not among the issuer's algorithms"},
		{"two keys, one without a kid", func(i *Issuer) {
			i.Algorithms = []string{RS256, ES256}
			i.Keys = []Key{{KID: "a", Alg: RS256, PublicKeyFile: "rs256.pem"}, {Alg: ES256, PublicKeyFile: "es256.pem"}}
		}, "no kid"},
		{"two keys with one kid", func(i *Issuer) {
			i.Algorithms = []string{RS256, ES256}
			i.Keys = []Key{{KID: "a", Alg: RS256, PublicKeyFile: "rs256.pem"}, {KID: "a", Alg: ES256, PublicKeyFile: "es256.pem"}}
		}, "appears twice"},
		{"a file that is missing", func(i *Issuer) { i.Keys[0].PublicKeyFile = "missing.pem" }, "missing.pem"},
		{"no file", func(i *Issuer) { i.Keys[0].PublicKeyFile = "" }, "no public_key_file"},
		{"RSA of 1024 bits", func(i *Issuer) { i.Keys[0].PublicKeyFile = "small.pem" }, "1024 bits"},
		{"RSA with an exponent of 1", func(i *Issuer) { i.Keys[0].PublicKeyFile = "e1.pem" }, "exponent"},
		{"RSA with an even exponent", func(i *Issuer) { i.Keys[0].PublicKeyFile = "e-even.pem" }, "exponent"},
		{"RS256 with an ECDSA key", func(i *Issuer) { i.Keys[0].PublicKeyFile = "es256.pem" }, "not an RSA key"},
		{"ES256 with P-384", func(i *Issuer) {
			i.Algorithms = []string{ES256}
			i.Keys = []Key{{Alg: ES256, PublicKeyFile: "p384.pem"}}
		}, "not an ECDSA key on P-256"},
		{"ES256 with an RSA key", func(i *Issuer) {
			i.Algorithms = []string{ES256}
			i.Keys = []Key{{Alg: ES256, PublicKeyFile: "rs256.pem"}}
		}, "not an ECDSA key on P-256"},
		{"EdDSA with X25519", func(i *Issuer) {
			i.Algorithms = []string{EdDSA}
			i.Keys = []Key{{Alg: EdDSA, PublicKeyFile: "x25519.pem"}}
		}, "not an Ed25519 key"},
		{"EdDSA with the identity point", func(i *Issuer) {
			i.Algorithms = []string{EdDSA}
			i.Keys = []Key{{Alg: EdDSA, PublicKeyFile: "identity.pem"}}
		}, "cannot be used"},
		{"a private key", func(i *Issuer) { i.Keys[0].PublicKeyFile = "private.pem" }, `"PRIVATE KEY"`},
		{"a certificate", func(i *Issuer) { i.Keys[0].PublicKeyFile = "certificate.pem" }, `"CERTIFICATE"`},
		{"a PKCS #1 RSA public key", func(i *Issuer) { i.Keys[0].PublicKeyFile = "pkcs1.pem" }, `"RSA PUBLIC KEY"`},
		{"two PEM blocks", func(i *Issuer) {
			i.Algorithms = []string{ES256}
			i.Keys = []Key{{Alg: ES256, PublicKeyFile: "two-blocks.pem"}}
		}, "more than one PEM block"},
		{"PEM headers", func(i *Issuer) { i.Keys[0].PublicKeyFile = "headers.pem" }, "headers"},
		{"not PEM", func(i *Issuer) { i.Keys[0].PublicKeyFile = "not-pem.pem" }, "no PEM block"},
		{"a negative leeway", func(i *Issuer) { i.Leeway = d(-time.Second) }, "negative"},
		{"a leeway of zero", func(i *Issuer) { i.Leeway = d(0) }, ""},
		{"max_lifetime of zero", func(i *Issuer) { i.MaxLifetime = d(0) }, "max_lifetime"},
		{"allow without values", func(i *Issuer) { i.Allow.Values = nil }, "allow"},
		{"allow with an empty value", func(i *Issuer) { i.Allow.Values = []string{""} }, "empty value"},
		{"forge from claims", func(i *Issuer) {
			i.LabelMapping.Forge = Source{Claims: []string{"a", "b"}, Join: "/"}
		}, "forge: claims are not allowed"},
		{"forge from nothing", func(i *Issuer) { i.LabelMapping.Forge = Source{} }, "forge: give exactly one"},
		{"forge a value and a claim", func(i *Issuer) {
			i.LabelMapping.Forge = Source{Value: "example-forge", Claim: "forge"}
		}, "forge: give exactly one"},
		{"a forge of 257 bytes", func(i *Issuer) { i.LabelMapping.Forge = Source{Value: strings.Repeat("a", 257)} }, "256 bytes"},
		{"repository claims without join", func(i *Issuer) { i.LabelMapping.Repository.Join = "" }, "without a join"},
		{"repository join without claims", func(i *Issuer) {
			i.LabelMapping.Repository = Source{Claim: "project", Join: "/"}
		}, "a join without claims"},
		{"repository claims with an empty name", func(i *Issuer) {
			i.LabelMapping.Repository.Claims = []string{"namespace", ""}
		}, "empty name"},
		{"run_key from another claim", func(i *Issuer) { i.LabelMapping.RunKey.Claim = "run" }, "always sub"},
		{"a details key of 65 bytes", func(i *Issuer) {
			i.DetailMapping = map[string]Claim{strings.Repeat("k", 65): {Claim: "requester"}}
		}, "details key"},
		{"a details key with a line feed", func(i *Issuer) {
			i.DetailMapping = map[string]Claim{"a\nb": {Claim: "requester"}}
		}, "details key"},
		{"a details key with U+2028", func(i *Issuer) {
			i.DetailMapping = map[string]Claim{"a b": {Claim: "requester"}}
		}, "details key"},
		{"a details key without a claim", func(i *Issuer) { i.DetailMapping = map[string]Claim{"requester": {}} }, "names no claim"},
		{"introspection over http", func(i *Issuer) {
			i.Introspection = &Introspection{URL: "http://issuer.example/introspect", ClientID: "example-gateway", ClientSecretFile: "secret"}
		}, "introspection"},
		{"introspection without a client id", func(i *Issuer) {
			i.Introspection = &Introspection{URL: "https://issuer.example/introspect", ClientSecretFile: "secret"}
		}, "no client id"},
		{"introspection with a cache of zero", func(i *Issuer) {
			i.Introspection = &Introspection{URL: "https://issuer.example/introspect", ClientID: "example-gateway", ClientSecretFile: "secret", Cache: d(0)}
		}, "cache"},
		{"introspection", func(i *Issuer) {
			i.Introspection = &Introspection{URL: "https://issuer.example/introspect", ClientID: "example-gateway", ClientSecretFile: "never-read", Cache: d(30 * time.Second)}
		}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			i := issuer()
			c.change(&i)
			err := i.Check(read)
			switch {
			case c.want == "" && err != nil:
				t.Errorf("Check: %v", err)
			case c.want != "" && err == nil:
				t.Errorf("Check accepts it; want an error with %q", c.want)
			case c.want != "" && !strings.Contains(err.Error(), c.want):
				t.Errorf("Check: %v; want an error with %q", err, c.want)
			}
			if err != nil && strings.Contains(err.Error(), "BEGIN") {
				t.Errorf("the error quotes a file: %v", err)
			}
		})
	}
}

func TestIssuersCheck(t *testing.T) {
	read := files(fixtureKeys(t))
	if err := (Issuers{issuer()}).Check(read); err != nil {
		t.Errorf("one issuer: %v", err)
	}
	other := issuer()
	other.Issuer = "https://issuer-b.example"
	if err := (Issuers{issuer(), other}).Check(read); err != nil {
		t.Errorf("two issuers: %v", err)
	}
	if err := (Issuers{issuer(), issuer()}).Check(read); err == nil || !strings.Contains(err.Error(), "appears twice") {
		t.Errorf("the same issuer twice: %v", err)
	}
	if err := (Issuers{}).Check(read); err == nil {
		t.Error("no issuer passes")
	}
	bad := issuer()
	bad.Issuer, bad.Audience = "https://issuer-b.example", ""
	if err := (Issuers{issuer(), bad}).Check(read); err == nil || !strings.Contains(err.Error(), "run credentials[1]") {
		t.Errorf("a bad second issuer: %v", err)
	}
	if err := issuer().Check(nil); err == nil {
		t.Error("Check without a reader passes")
	}
	readErr := errors.New("permission denied")
	if err := issuer().Check(func(string) ([]byte, error) { return nil, readErr }); !errors.Is(err, readErr) {
		t.Errorf("a read error is not wrapped: %v", err)
	}
}

func TestDurationRoundTrips(t *testing.T) {
	var v Duration
	if err := v.UnmarshalJSON([]byte(`"1h30m"`)); err != nil || time.Duration(v) != 90*time.Minute {
		t.Fatalf("1h30m reads as %v, %v", time.Duration(v), err)
	}
	if b, _ := v.MarshalJSON(); string(b) != `"1h30m0s"` {
		t.Errorf("writes as %s", b)
	}
	if err := v.UnmarshalJSON([]byte(`60`)); err == nil {
		t.Error("a number reads as a duration")
	}
	if err := v.UnmarshalJSON([]byte(`"soon"`)); err == nil {
		t.Error("soon reads as a duration")
	}
}
