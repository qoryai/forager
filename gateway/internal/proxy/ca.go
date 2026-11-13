package proxy

import (
	"bytes"
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/qoryai/forager/accesskey"
)

// CA is one run's certificate authority: what lets the proxy answer as a host it
// terminates TLS for. Its key is made for the run. Whoever holds it can be any host to
// whoever trusts it, which is why only the certificate, never the key, reaches an
// enclosure.
//
// The key is in two places. One is this process's memory, under the limits the
// gateway's Start sets for the process: not dumpable, no core dump, and, with the
// gateway's LockMemory, no page in swap. The other, once [CA.Write] wrote it, is the
// file ca.key in the run's record directory, mode 0600, which those limits do not
// cover: a gateway that stops while the run goes on keeps the file, and reads the
// authority back with [ReadCA] when it reopens the run. The gateway removes both files
// at the run's final end, when a reopen of the run fails for good, when it discards or
// reclaims the run's record, and in a sweep of records no run is open on that have not
// changed for a while.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte

	mu sync.Mutex
	// leaves are the certificates made for each host, at most [leafCap], the least
	// recently used of them in order first.
	leaves map[string]*list.Element
	order  *list.List
}

// cachedLeaf is a host's certificate in the cache.
type cachedLeaf struct {
	host string
	cert *tls.Certificate
}

// leafCap is how many hosts' certificates an authority keeps: past it, the least
// recently used goes, and is made again when it is asked for. The proxy asks for leaves
// only for the hosts the run terminates ([terminator.covers]), and a "*." entry matches
// any number of names, so the cache is bounded.
var leafCap = 1024

// caLife is how long a run's authority and its certificates are good for: longer than
// any run, short enough that a leaked certificate is soon nothing.
const caLife = 7 * 24 * time.Hour

// leafRenew is how long before its end a leaf is made again.
const leafRenew = 24 * time.Hour

// NewCA makes an authority for the run named.
func NewCA(runID string) (*CA, error) {
	return newCA(pkix.Name{CommonName: caName(runID), Organization: []string{"Forager gateway, one run only"}}, caLife)
}

// caName is the common name of the authority of the run runID.
func caName(runID string) string { return "qory run " + runID }

// ownerOf is the user id that owns the file of info, -1 when info has none.
func ownerOf(info os.FileInfo) int {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}

// newCA makes an authority of the subject, good for life.
func newCA(subject pkix.Name, life time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(life),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return caOf(der, key)
}

// caOf is the authority of the certificate der and its key.
func caOf(der []byte, key *ecdsa.PrivateKey) (*CA, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), leaves: map[string]*list.Element{}, order: list.New()}, nil
}

// PEM is the authority's certificate, what an enclosure is given to trust.
func (c *CA) PEM() []byte { return c.pem }

// leaf is the certificate the proxy answers as host with, made once per host and kept
// while it is among the [leafCap] most recently used.
func (c *CA) leaf(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	// A leaf is made again a day before it expires: a gateway's own authority outlives
	// any one leaf.
	if e, ok := c.leaves[host]; ok {
		if l := e.Value.(*cachedLeaf).cert; now.Before(l.Leaf.NotAfter.Add(-leafRenew)) {
			c.order.MoveToBack(e)
			return l, nil
		}
		c.order.Remove(e)
		delete(c.leaves, host)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	// Never past the authority's own end.
	notAfter := now.Add(caLife)
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		// No common name: OpenSSL reads a common name that looks like a name as a
		// name, and the certificate is for an address.
		tmpl.Subject = pkix.Name{}
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	l := &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key, Leaf: parsed}
	c.leaves[host] = c.order.PushBack(&cachedLeaf{host: host, cert: l})
	for c.order.Len() > leafCap {
		oldest := c.order.Front()
		c.order.Remove(oldest)
		delete(c.leaves, oldest.Value.(*cachedLeaf).host)
	}
	return l, nil
}

// The files of an authority in a run's record directory, as [CA.Write] writes them:
// the certificate, and its key as a PKCS#8 PEM block of type PRIVATE KEY.
const (
	CACertFile = "ca.pem"
	CAKeyFile  = "ca.key"
)

// maxCAFile is the most bytes [ReadCA] reads of either file. Each is under 1 KiB.
const maxCAFile = 64 << 10

// keyType is the PEM block type of the key file.
const keyType = "PRIVATE KEY"

// Write writes the authority to dir, which must exist: the certificate to
// [CACertFile] and the key to [CAKeyFile], each a file that must not exist yet, made
// with mode 0600 and synced, then dir is synced. The key goes from its DER form
// straight into the file, with no PEM copy of it in memory, and Write overwrites the
// DER form with zeros once written; copies the standard library makes inside its
// encoder stay in the heap until it is reused. When a step fails, Write removes the files it
// made, and leaves a file that existed before it as it was.
func (c *CA) Write(dir string) error {
	certPath, keyPath := filepath.Join(dir, CACertFile), filepath.Join(dir, CAKeyFile)
	if err := writeNew(certPath, func(w io.Writer) error {
		_, err := w.Write(c.pem)
		return err
	}); err != nil {
		return err
	}
	if err := writeNew(keyPath, c.writeKey); err != nil {
		return errors.Join(err, removeFile(certPath))
	}
	if err := syncDir(dir); err != nil {
		return errors.Join(err, removeFile(keyPath), removeFile(certPath))
	}
	return nil
}

// writeKey writes the key to w as one PEM block of type [keyType], 64 characters a
// line, as [pem.Encode] does. Its buffers are on the stack or overwritten with zeros
// before it returns.
func (c *CA) writeKey(w io.Writer) error {
	der, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		return errors.New("the authority's key does not encode as PKCS#8")
	}
	defer clear(der)
	var line [65]byte
	defer clear(line[:])
	if _, err := io.WriteString(w, "-----BEGIN "+keyType+"-----\n"); err != nil {
		return err
	}
	for rest := der; len(rest) > 0; {
		n := min(len(rest), 48)
		m := base64.StdEncoding.EncodedLen(n)
		base64.StdEncoding.Encode(line[:m], rest[:n])
		line[m] = '\n'
		if _, err := w.Write(line[:m+1]); err != nil {
			return err
		}
		rest = rest[n:]
	}
	_, err = io.WriteString(w, "-----END "+keyType+"-----\n")
	return err
}

// writeNew makes the file path with mode 0600, failing when it exists, writes it with
// write, syncs and closes it. When a step after the file is made fails, it removes the
// file.
func writeNew(path string, write func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return accesskey.ShownError(err)
	}
	if err := errors.Join(write(f), f.Sync()); err != nil {
		return errors.Join(fmt.Errorf("writing %s failed: %w", accesskey.ShownValue(path, false), accesskey.ShownError(err)), f.Close(), removeFile(path))
	}
	if err := f.Close(); err != nil {
		return errors.Join(accesskey.ShownError(err), removeFile(path))
	}
	return nil
}

// removeFile removes path; a path that does not exist is no error.
func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return accesskey.ShownError(err)
	}
	return nil
}

// syncDir syncs the directory dir, so the files made or removed in it stay so after a
// crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return accesskey.ShownError(err)
	}
	return accesskey.ShownError(errors.Join(d.Sync(), d.Close()))
}

// ReadCA reads the authority [CA.Write] wrote to dir for the run runID, as [NewCA]
// made it. It fails, with no byte of either file in its error, when a file is missing,
// is not a regular file, is larger than [maxCAFile] or is not one PEM block of its
// type; when [CAKeyFile]'s mode lets group or others read, write or run it, or a user
// other than this process's effective user owns it; when the certificate is not an
// authority's, is past its NotAfter or has a common name other than "qory run "
// followed by runID; and when the key is not a PKCS#8 ECDSA P-256 key or is not the
// key of the certificate. ReadCA overwrites with zeros what it read of the key file,
// and the key's DER form, before it returns; copies the standard library makes inside
// its parser stay in the heap until it is reused.
func ReadCA(dir, runID string) (*CA, error) {
	certPath, keyPath := filepath.Join(dir, CACertFile), filepath.Join(dir, CAKeyFile)
	certPEM, _, err := readCAFile(certPath)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%s is not one PEM block of type CERTIFICATE", shownPath(certPath))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s does not parse as an X.509 certificate", shownPath(certPath))
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, fmt.Errorf("%s is not a certificate authority's certificate", shownPath(certPath))
	}
	if cert.Subject.CommonName != caName(runID) {
		return nil, fmt.Errorf("remove %s: it is the certificate authority of another run, not of run %s", shownPath(certPath), accesskey.ShownValue(runID, false))
	}
	if !time.Now().Before(cert.NotAfter) {
		return nil, fmt.Errorf("the certificate in %s expired at %s", shownPath(certPath), cert.NotAfter.UTC().Format(time.RFC3339))
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("the certificate in %s is not for an ECDSA P-256 key", shownPath(certPath))
	}

	keyPEM, info, err := readCAFile(keyPath)
	defer clear(keyPEM)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("set %s to mode 0600: its mode %#o lets group or others access it", shownPath(keyPath), perm)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("remove %s: user %d does not own it, and the gateway runs as user %d", shownPath(keyPath), ownerOf(info), os.Geteuid())
	}
	kb, rest := pem.Decode(keyPEM)
	if kb != nil {
		defer clear(kb.Bytes)
	}
	if kb == nil || kb.Type != keyType || len(kb.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%s is not one PEM block of type %s", shownPath(keyPath), keyType)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s does not parse as a PKCS#8 private key", shownPath(keyPath))
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s is not an ECDSA P-256 key", shownPath(keyPath))
	}
	if !pub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("the key in %s is not the key of the certificate in %s", shownPath(keyPath), shownPath(certPath))
	}
	return caOf(block.Bytes, key)
}

// readCAFile reads path whole, and the file it read. It reads only a regular file, not
// a symbolic link to one, of at most [maxCAFile] bytes, into one buffer, which it
// overwrites with zeros when the read fails. It opens path without waiting for a
// writer, so a named pipe fails at once. The error of a failed read contains none of
// the bytes read.
func readCAFile(path string) ([]byte, os.FileInfo, error) {
	named, err := os.Lstat(path)
	if err != nil {
		return nil, nil, accesskey.ShownError(err)
	}
	if !named.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is not a regular file", shownPath(path))
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, accesskey.ShownError(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, accesskey.ShownError(err)
	}
	if !os.SameFile(named, info) {
		return nil, nil, fmt.Errorf("%s changed while it was read", shownPath(path))
	}
	buf := make([]byte, maxCAFile+1)
	n, err := io.ReadFull(f, buf)
	switch {
	case err == nil:
		clear(buf)
		return nil, nil, fmt.Errorf("%s is larger than %d bytes", shownPath(path), maxCAFile)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return buf[:n], info, nil
	default:
		clear(buf)
		return nil, nil, accesskey.ShownError(err)
	}
}

// shownPath is path as an error shows it.
func shownPath(path string) string { return accesskey.ShownValue(path, false) }
