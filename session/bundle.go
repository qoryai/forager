package session

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/wall"
)

// BundleFile is the file, in the run directory, that an unwalled run's tools trust:
// the machine's authorities and the run's certificate.
const BundleFile = "ca-bundle.pem"

// machineBundles are the files writeBundle reads the machine's authorities from, the
// first that is a regular file with a certificate in it. A test replaces it.
var machineBundles = wall.BundleFiles

// caEnv are the variables that point an unwalled run's programs at its bundle:
// Spec.CAEnv, or [wall.DefaultCAEnv] when it is nil.
func caEnv(spec Spec) []string {
	if spec.CAEnv != nil {
		return slices.Clone(spec.CAEnv)
	}
	return slices.Clone(wall.DefaultCAEnv)
}

// writeBundle writes [BundleFile] into dir, the run directory: the first file of
// machineBundles that is a regular file with a certificate in it, then ca, the run's
// certificate. It returns each variable of names set to the file's path, NAME=path.
// A machine with none of the files is no run: the run's tools would trust the gateway
// for no host.
func writeBundle(dir string, names []string, ca []byte) ([]string, error) {
	var roots []byte
	for _, p := range machineBundles() {
		if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if b, err := os.ReadFile(p); err == nil && bytes.Contains(b, []byte("BEGIN CERTIFICATE")) {
			roots = b
			break
		}
	}
	if roots == nil {
		return nil, errors.New("install a CA bundle at /etc/ssl/cert.pem or /etc/ssl/certs/ca-certificates.crt: the run's tools trust the gateway for the credentials' hosts only through a bundle, and this machine has none of the files Forager reads")
	}
	if !bytes.HasSuffix(roots, []byte("\n")) {
		roots = append(roots, '\n')
	}
	file := filepath.Join(dir, BundleFile)
	if err := os.WriteFile(file, append(roots, ca...), 0o644); err != nil {
		return nil, accesskey.ShownError(err)
	}
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = n + "=" + file
	}
	return out, nil
}
