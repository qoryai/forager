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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/policy"
)

// CA is one run's certificate authority: what lets the proxy answer as a host it
// terminates TLS for. Its key is made for the run, lives in this process's memory and
// nowhere else, and is gone with it. Its certificate's name constraints limit it to the
// names the run terminates when it starts and the names under them, and to the
// addresses it terminates, so whoever holds the key can be one of those hosts to
// whoever trusts it, and no other host to a client that enforces the constraints. Only
// the certificate, never the key, reaches an enclosure.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
	// standIn says the run terminated no name when it started: the certificate permits
	// only invalid, which stands for no name, and [CA.Permits] permits no name.
	standIn bool

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
// recently used goes, and is made again when it is asked for. An authority answers only
// for the hosts the run terminates ([terminator.covers]) and the names under them, and a
// "*." entry matches any number of names.
var leafCap = 1024

// caLife is how long a run's authority and its certificates are good for: longer than
// any run, short enough that a leaked certificate is soon nothing.
const caLife = 7 * 24 * time.Hour

// leafRenew is how long before its end a leaf is made again.
const leafRenew = 24 * time.Hour

// NewCA makes an authority for the run named, good only for the hosts as [constrain]
// reads them: those [Proxy.Terminating] reports when the run starts.
func NewCA(runID string, hosts []string) (*CA, error) {
	return newCA(pkix.Name{CommonName: "qory run " + runID, Organization: []string{"Forager gateway, one run only"}}, caLife, hosts)
}

// newCA makes an authority of the subject, good for life and for the hosts as
// [constrain] reads them.
func newCA(subject pkix.Name, life time.Duration, hosts []string) (*CA, error) {
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
	standIn := constrain(tmpl, hosts)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	ca, err := caOf(der, key)
	if err != nil {
		return nil, err
	}
	ca.standIn = standIn
	return ca, nil
}

// constrain sets the name constraints of an authority good for the hosts, entries
// as [Proxy.Terminated] reports them: "*.example.com" permits example.com and every name
// under it, since a DNS constraint has no form for the names under it alone; a name
// permits itself and every name under it; an IPv4 address permits itself as a /32, an
// IPv6 address as a /128. With no name, only invalid is permitted, a name that never
// resolves (RFC 6761); with no address, every address is excluded. The constraint is
// critical, so a client that cannot read it rejects every certificate of the authority.
// standIn says invalid stands for no name.
func constrain(tmpl *x509.Certificate, hosts []string) (standIn bool) {
	var names []string
	var ips []*net.IPNet
	for _, h := range hosts {
		name, ip, ok := constraintOf(h)
		switch {
		case !ok:
		case ip != nil:
			ips = append(ips, ip)
		case !slices.Contains(names, name):
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		names, standIn = []string{"invalid"}, true
	}
	tmpl.PermittedDNSDomainsCritical = true
	tmpl.PermittedDNSDomains = names
	if len(ips) > 0 {
		tmpl.PermittedIPRanges = ips
	} else {
		tmpl.ExcludedIPRanges = []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}
	}
	return standIn
}

// constraintOf is the name or the address range that permits every host entry matches,
// by [policy.Match]. ok is false for an entry that matches no host a request can name:
// one whose name, or whose suffix after "*.", has no form under [policy.Host], and a
// "*." entry whose suffix is an address.
func constraintOf(entry string) (name string, ip *net.IPNet, ok bool) {
	suffix, pattern := strings.CutPrefix(entry, "*.")
	h, ok := policy.Host(suffix)
	if !ok {
		return "", nil, false
	}
	addr := net.ParseIP(h)
	switch {
	case addr == nil:
		return h, nil, true
	case pattern:
		return "", nil, false
	case addr.To4() != nil:
		return "", &net.IPNet{IP: addr.To4(), Mask: net.CIDRMask(32, 32)}, true
	}
	return "", &net.IPNet{IP: addr, Mask: net.CIDRMask(128, 128)}, true
}

// Permits reports whether the authority's certificates are good for every host the
// entry matches, an entry as [Proxy.Terminated] reports one. An entry that matches no
// host a request can name is permitted; a name is not when the run terminated no name
// when it started.
func (c *CA) Permits(entry string) bool {
	name, ip, ok := constraintOf(entry)
	switch {
	case !ok:
		return true
	case ip != nil:
		return slices.ContainsFunc(c.cert.PermittedIPRanges, func(n *net.IPNet) bool { return n.Contains(ip.IP) })
	case c.standIn:
		return false
	}
	return slices.ContainsFunc(c.cert.PermittedDNSDomains, func(d string) bool {
		return name == d || strings.HasSuffix(name, "."+d)
	})
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
		// No common name: OpenSSL reads a common name that looks like a name as one,
		// and an address is outside the authority's name constraints.
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
