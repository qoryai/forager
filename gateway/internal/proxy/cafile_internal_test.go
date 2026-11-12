package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writtenCA is a run's authority written to a directory of its own, with that
// directory.
func writtenCA(t *testing.T) (*CA, string) {
	t.Helper()
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := ca.Write(dir); err != nil {
		t.Fatal(err)
	}
	return ca, dir
}

// TestAWrittenAuthorityReadsBackTheSame pins the round trip: [ReadCA] returns the
// certificate [CA.Write] wrote and its key, and a leaf the read authority makes
// verifies against the certificate of the authority that was written.
func TestAWrittenAuthorityReadsBackTheSame(t *testing.T) {
	ca, dir := writtenCA(t)
	got, err := ReadCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.cert.Raw, ca.cert.Raw) || !bytes.Equal(got.PEM(), ca.PEM()) {
		t.Error("the certificate read back is not the one written")
	}
	if !got.key.Equal(ca.key) {
		t.Error("the key read back is not the one written")
	}
	leaf, err := got.leaf("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "api.example.com", Roots: roots}); err != nil {
		t.Errorf("a leaf made after the round trip does not verify against the written authority: %v", err)
	}
	if err := leaf.Leaf.CheckSignatureFrom(ca.cert); err != nil {
		t.Errorf("a leaf made after the round trip is not signed by the written key: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, CAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		t.Fatal(err)
	}
	if want := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}); !bytes.Equal(b, want) {
		t.Errorf("ca.key is\n%s\nnot what pem.Encode writes", b)
	}
}

// TestAuthorityFilesAreOnlyTheOwners pins the files' modes, 0600 each, and that Write
// makes only files that do not exist: a second Write to the directory fails and leaves
// both files as they were.
func TestAuthorityFilesAreOnlyTheOwners(t *testing.T) {
	_, dir := writtenCA(t)
	before := map[string][]byte{}
	for _, name := range []string{CACertFile, CAKeyFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s has mode %#o", name, perm)
		}
		before[name], _ = os.ReadFile(filepath.Join(dir, name))
	}
	other, err := NewCA("other")
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Write(dir); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("a second Write to the directory: %v", err)
	}
	for name, b := range before {
		if after, _ := os.ReadFile(filepath.Join(dir, name)); !bytes.Equal(after, b) {
			t.Errorf("%s changed under a second Write", name)
		}
	}
}

// TestAWriteThatFailsLeavesNoFileOfIt pins Write's failure on either file: with
// ca.pem there, it fails and makes no ca.key; with ca.key there, it fails, removes the
// ca.pem it made and leaves ca.key as it was.
func TestAWriteThatFailsLeavesNoFileOfIt(t *testing.T) {
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	for _, there := range []string{CACertFile, CAKeyFile} {
		t.Run(there, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, there), []byte("before"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ca.Write(dir); !errors.Is(err, fs.ErrExist) {
				t.Fatalf("Write: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != there {
				t.Errorf("the directory has %v", entries)
			}
			if b, _ := os.ReadFile(filepath.Join(dir, there)); string(b) != "before" {
				t.Errorf("%s is %q", there, b)
			}
		})
	}
}

// TestReadCARefuses pins each file ReadCA refuses, and that no refusal contains a byte
// of the key, in PEM, in hex or in DER, or a PEM boundary line.
func TestReadCARefuses(t *testing.T) {
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewCA("other")
	if err != nil {
		t.Fatal(err)
	}
	expired, err := newCA(pkix.Name{CommonName: "expired"}, -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	leafOnly := selfSigned(t, false)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384DER, err := x509.MarshalPKCS8PrivateKey(p384)
	if err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	if err := ca.Write(src); err != nil {
		t.Fatal(err)
	}
	certPEM := must(os.ReadFile(filepath.Join(src, CACertFile)))
	keyPEM := must(os.ReadFile(filepath.Join(src, CAKeyFile)))
	keyBlock, _ := pem.Decode(keyPEM)
	otherDir := t.TempDir()
	if err := other.Write(otherDir); err != nil {
		t.Fatal(err)
	}
	otherKeyPEM := must(os.ReadFile(filepath.Join(otherDir, CAKeyFile)))
	expiredDir := t.TempDir()
	if err := expired.Write(expiredDir); err != nil {
		t.Fatal(err)
	}

	// Each case writes ca.pem and ca.key with these contents, mode 0600, then changes the
	// directory with change when set; nil content is no file.
	cases := []struct {
		name       string
		cert, key  []byte
		change     func(t *testing.T, dir string)
		wantInText string
	}{
		{name: "no certificate", key: keyPEM, wantInText: "no such file"},
		{name: "no key", cert: certPEM, wantInText: "no such file"},
		{name: "a certificate not an authority's", cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafOnly.Raw}), key: pemKey(t, leafOnly.key), wantInText: "not a certificate authority"},
		{name: "an expired certificate", cert: must(os.ReadFile(filepath.Join(expiredDir, CACertFile))), key: must(os.ReadFile(filepath.Join(expiredDir, CAKeyFile))), wantInText: "expired"},
		{name: "another authority's key", cert: certPEM, key: otherKeyPEM, wantInText: "not the key of the certificate"},
		{name: "a P-384 key", cert: certPEM, key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p384DER}), wantInText: "not an ECDSA P-256 key"},
		{name: "an empty key", cert: certPEM, key: []byte{}, wantInText: "not one PEM block"},
		{name: "a key of another block type", cert: certPEM, key: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBlock.Bytes}), wantInText: "not one PEM block"},
		{name: "a key with a header", cert: certPEM, key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: keyBlock.Bytes}), wantInText: "not one PEM block"},
		{name: "a key with a second block", cert: certPEM, key: append(append([]byte{}, keyPEM...), otherKeyPEM...), wantInText: "not one PEM block"},
		{name: "a key cut short", cert: certPEM, key: keyPEM[:len(keyPEM)/2], wantInText: "not one PEM block"},
		{name: "a key that does not parse", cert: certPEM, key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBlock.Bytes[:len(keyBlock.Bytes)-3]}), wantInText: "does not parse"},
		{name: "a certificate that does not parse", cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")}), key: keyPEM, wantInText: "does not parse"},
		{name: "a certificate of another block type", cert: keyPEM, key: keyPEM, wantInText: "not one PEM block"},
		{name: "a key too large", cert: certPEM, key: bytes.Repeat([]byte("a"), maxCAFile+1), wantInText: "larger than"},
		{name: "a key group can read", cert: certPEM, key: keyPEM, change: chmodKey(0o640), wantInText: "set "},
		{name: "a key others can read", cert: certPEM, key: keyPEM, change: chmodKey(0o604), wantInText: "lets group or others"},
		{name: "a key group can run", cert: certPEM, key: keyPEM, change: chmodKey(0o610), wantInText: "lets group or others"},
		{name: "a key that is a directory", cert: certPEM, change: func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, CAKeyFile), 0o700); err != nil {
				t.Fatal(err)
			}
		}, wantInText: "not a regular file"},
		{name: "a key that is a symbolic link", cert: certPEM, change: func(t *testing.T, dir string) {
			if err := os.Symlink(filepath.Join(src, CAKeyFile), filepath.Join(dir, CAKeyFile)); err != nil {
				t.Fatal(err)
			}
		}, wantInText: "not a regular file"},
	}
	secrets := keyTexts(t, ca.key, keyPEM)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, b := range map[string][]byte{CACertFile: c.cert, CAKeyFile: c.key} {
				if b == nil {
					continue
				}
				if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if c.change != nil {
				c.change(t, dir)
			}
			got, err := ReadCA(dir)
			if err == nil {
				t.Fatalf("ReadCA read %v", got.cert.Subject)
			}
			text := err.Error()
			if !strings.Contains(text, c.wantInText) {
				t.Errorf("the error %q does not contain %q", text, c.wantInText)
			}
			for _, s := range secrets {
				if strings.Contains(text, s) {
					t.Errorf("the error %q contains key material %q", text, s)
				}
			}
		})
	}
	// The key file of the mode case says how to fix it.
	dir := t.TempDir()
	for name, b := range map[string][]byte{CACertFile: certPEM, CAKeyFile: keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	chmodKey(0o644)(t, dir)
	if _, err := ReadCA(dir); err == nil || err.Error() != "set "+filepath.Join(dir, CAKeyFile)+" to mode 0600: its mode 0644 lets group or others access it" {
		t.Errorf("the mode refusal is %v", err)
	}
}

// TestRemoveCARemovesBothFiles pins RemoveCA: both files go, and a file or a
// directory that is not there is no error.
func TestRemoveCARemovesBothFiles(t *testing.T) {
	_, dir := writtenCA(t)
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveCA(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "events.jsonl" {
		t.Errorf("the directory has %v", entries)
	}
	if err := RemoveCA(dir); err != nil {
		t.Errorf("RemoveCA with no file: %v", err)
	}
	_, dir = writtenCA(t)
	if err := os.Remove(filepath.Join(dir, CACertFile)); err != nil {
		t.Fatal(err)
	}
	if err := RemoveCA(dir); err != nil {
		t.Errorf("RemoveCA with ca.key alone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, CAKeyFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ca.key: %v", err)
	}
	if err := RemoveCA(filepath.Join(dir, "missing")); err != nil {
		t.Errorf("RemoveCA of a missing directory: %v", err)
	}
}

// signedCert is a parsed certificate with its key.
type signedCert struct {
	*x509.Certificate
	key *ecdsa.PrivateKey
}

// selfSigned is a self-signed P-256 certificate, an authority's when isCA is true.
func selfSigned(t *testing.T, isCA bool) signedCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "leaf.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return signedCert{cert, key}
}

// pemKey is key as a PKCS#8 PEM block.
func pemKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// chmodKey sets ca.key in a case's directory to mode.
func chmodKey(mode os.FileMode) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		if err := os.Chmod(filepath.Join(dir, CAKeyFile), mode); err != nil {
			t.Fatal(err)
		}
	}
}

// keyTexts are texts an error must not contain: each base64 line of the key's PEM, the
// key's scalar in hex, its DER as text, and a PEM boundary.
func keyTexts(t *testing.T, key *ecdsa.PrivateKey, keyPEM []byte) []string {
	t.Helper()
	out := []string{"-----", hex.EncodeToString(must(key.Bytes()))}
	for _, line := range strings.Split(string(keyPEM), "\n") {
		if line != "" && !strings.HasPrefix(line, "-----") {
			out = append(out, line)
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return append(out, string(der[len(der)-40:]))
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
