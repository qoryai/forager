package proxy

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"
)

// CA is one run's certificate authority: what lets the proxy answer as a host it
// terminates TLS for. Its key is made for the run, lives in this process's memory and
// nowhere else, and is gone with it. Whoever holds it can be any host to whoever trusts
// it, which is why only the certificate, never the key, reaches an enclosure.
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
// recently used goes, and is made again when it is asked for. A gateway's own authority
// answers for every host the clients of its runs reach, so its cache is bounded.
var leafCap = 1024

// caLife is how long a run's authority and its certificates are good for: longer than
// any run, short enough that a leaked certificate is soon nothing.
const caLife = 7 * 24 * time.Hour

// leafRenew is how long before its end a leaf is made again.
const leafRenew = 24 * time.Hour

// NewCA makes an authority for the run named.
func NewCA(runID string) (*CA, error) {
	return newCA(pkix.Name{CommonName: "qory run " + runID, Organization: []string{"Forager gateway, one run only"}}, caLife)
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
