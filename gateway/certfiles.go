package gateway

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qoryai/forager/accesskey"
)

// certCheck is how often, at most, the one address checks its certificate and key files
// for a change: on a handshake, once this long has passed since the last check.
const certCheck = time.Minute

// certFiles is the key pair the one address serves, read from the files of [TLS]. A
// handshake gets the pair in force. Once [certCheck] has passed since the last check, the
// next handshake compares each file's identity, modification time and size with those of
// the files the pair was read from; when one differs, or the last read failed, it reads
// both files again. A read that fails keeps the pair in force and reports one line for
// each failure that differs from the last one reported.
type certFiles struct {
	certFile, keyFile string
	every             time.Duration
	report            func(string)

	pair atomic.Pointer[tls.Certificate]

	// mu is held by the one check in progress; a handshake during a check gets the pair
	// in force without a check.
	mu   sync.Mutex
	next time.Time
	// certInfo and keyInfo are the files the pair in force was read from.
	certInfo, keyInfo os.FileInfo
	// failed is the text of the last failure reported, with the files it was of; empty
	// once a read succeeds.
	failed                        string
	failedCertInfo, failedKeyInfo os.FileInfo
}

// readPair reads the key pair of certFile and keyFile, and the files it read: each is
// checked before it is read, so a file replaced during the read is read again at the
// next check. A key that is not the certificate's is an error.
func readPair(certFile, keyFile string) (pair *tls.Certificate, certInfo, keyInfo os.FileInfo, err error) {
	if certInfo, err = os.Stat(certFile); err != nil {
		return nil, nil, nil, accesskey.ShownError(err)
	}
	if keyInfo, err = os.Stat(keyFile); err != nil {
		return nil, nil, nil, accesskey.ShownError(err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, nil, accesskey.ShownError(err)
	}
	return &cert, certInfo, keyInfo, nil
}

// newCertFiles reads the pair of certFile and keyFile, which the one address serves
// until a check reads another: a handshake checks the files once the interval every has
// passed since the last check.
func newCertFiles(certFile, keyFile string, every time.Duration) (*certFiles, error) {
	pair, ci, ki, err := readPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	h := &certFiles{certFile: certFile, keyFile: keyFile, every: every, certInfo: ci, keyInfo: ki, report: func(string) {}}
	h.pair.Store(pair)
	h.next = time.Now().Add(every)
	return h, nil
}

// get is the pair a handshake serves, for [tls.Config.GetCertificate]: the pair in force,
// after a check when one is due and no other check is in progress.
func (h *certFiles) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if h.mu.TryLock() {
		if now := time.Now(); !now.Before(h.next) {
			h.next = now.Add(h.every)
			h.check()
		}
		h.mu.Unlock()
	}
	return h.pair.Load(), nil
}

// check reads the pair again when a file differs from the one the pair in force was
// read from, or when the last read failed. h.mu is held.
func (h *certFiles) check() {
	ci, _ := os.Stat(h.certFile)
	ki, _ := os.Stat(h.keyFile)
	if h.failed == "" && sameFile(ci, h.certInfo) && sameFile(ki, h.keyInfo) {
		return
	}
	pair, rci, rki, err := readPair(h.certFile, h.keyFile)
	if err == nil {
		h.pair.Store(pair)
		h.certInfo, h.keyInfo = rci, rki
		h.failed, h.failedCertInfo, h.failedKeyInfo = "", nil, nil
		return
	}
	line := fmt.Sprintf("replace the gateway's certificate %s and key %s with a certificate and its key, in PEM: reading them failed, %v; the gateway keeps serving the pair it read before and reads both files again on the first handshake %g seconds or more later",
		accesskey.ShownValue(h.certFile, false), accesskey.ShownValue(h.keyFile, false), err, h.every.Seconds())
	if line == h.failed && sameFile(ci, h.failedCertInfo) && sameFile(ki, h.failedKeyInfo) {
		return
	}
	h.failed, h.failedCertInfo, h.failedKeyInfo = line, ci, ki
	h.report(line)
}

// sameFile reports whether a and b are the same file with the same modification time
// and size, or both no file. A file replaced by a rename is another file.
func sameFile(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}
