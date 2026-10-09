package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// gatewayLife is how long a gateway's own authority is good for: its operator installs
// it on the machines of the clients with no session, so it lasts for years, not for a
// run.
const gatewayLife = 10 * 365 * 24 * time.Hour

// The modes of a gateway's own authority: its directory and its file are the gateway's
// user's alone.
const (
	caDirMode  fs.FileMode = 0o700
	caFileMode fs.FileMode = 0o600
)

// OpenCA is a gateway's own authority, what lets its proxy read inside HTTPS for the
// clients with no session, which trust it once their operator installs its
// certificate. It is kept in the file path, its certificate and its key in PEM, and is
// made there once, when the file is not there: every later start reads the same one.
// The file's directory is made mode 0700 when it is not there, and the file mode
// 0600; a directory or a file another user may read or write, a link in their place,
// a file that holds anything but one authority's certificate and its key, and an
// authority past its end are refused. No error contains the key.
func OpenCA(path string) (*CA, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(filepath.Dir(dir), caDirMode); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, caDirMode); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	if err := private(dir, true); err != nil {
		return nil, err
	}
	ca, err := readCA(path)
	if !errors.Is(err, fs.ErrNotExist) {
		return ca, err
	}
	if ca, err = newCA(pkix.Name{CommonName: "qory gateway", Organization: []string{"Forager gateway, clients with no session"}}, gatewayLife); err != nil {
		return nil, err
	}
	if err := writeCA(path, ca); err != nil {
		if errors.Is(err, fs.ErrExist) {
			// Another start made it first: that one is the gateway's.
			return readCA(path)
		}
		return nil, err
	}
	return ca, nil
}

// private refuses a path that is not a directory, or a regular file, of this user's
// alone: a link, or a mode that lets another user in.
func private(path string, dir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	want, what := fs.FileMode(0), "a regular file"
	if dir {
		want, what = fs.ModeDir, "a directory"
	}
	if fi.Mode().Type() != want {
		return fmt.Errorf("the gateway's certificate authority: %s is not %s", path, what)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("the gateway's certificate authority: %s is open to other users, mode %#o; it must be the gateway's user's alone", path, fi.Mode().Perm())
	}
	return nil
}

// readCA reads the authority kept at path; an error that is [fs.ErrNotExist] says
// there is none.
func readCA(path string) (*CA, error) {
	if err := private(path, false); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	bad := fmt.Errorf("the gateway's certificate authority: %s holds no certificate authority and its key", path)
	var der, keyDER []byte
	for rest := b; len(bytes.TrimSpace(rest)) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		switch {
		case block == nil:
			return nil, bad
		case block.Type == "CERTIFICATE" && der == nil:
			der = block.Bytes
		case block.Type == "PRIVATE KEY" && keyDER == nil:
			keyDER = block.Bytes
		default:
			return nil, bad
		}
	}
	if der == nil || keyDER == nil {
		return nil, bad
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, bad
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, bad
	}
	ca, err := caOf(der, key)
	if err != nil || !ca.cert.IsCA || !key.PublicKey.Equal(ca.cert.PublicKey) {
		return nil, bad
	}
	if now := time.Now(); now.After(ca.cert.NotAfter) || now.Before(ca.cert.NotBefore) {
		return nil, fmt.Errorf("the gateway's certificate authority: %s is good from %s to %s, not now; remove it, and the gateway makes another, which the clients' machines must trust in its place", path, ca.cert.NotBefore.UTC().Format(time.RFC3339), ca.cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return ca, nil
}

// writeCA writes ca to path, mode 0600, whole or not at all: to a file of its own
// beside it first, then linked at path, which fails with [fs.ErrExist] when path is
// there already.
func writeCA(path string, ca *CA) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".ca-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	content := append(bytes.Clone(ca.pem), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	if err := f.Chmod(caFileMode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Link(tmp, path)
}
