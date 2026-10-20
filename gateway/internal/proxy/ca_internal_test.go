package proxy

import (
	"fmt"
	"net"
	"testing"
)

// TestAnAuthorityKeepsABoundedCacheOfLeaves pins the bound on an authority's
// certificates: at most leafCap hosts' are kept, the least recently used going first, a
// host asked for again is the same certificate while it is kept, and one that went is
// made again.
func TestAnAuthorityKeepsABoundedCacheOfLeaves(t *testing.T) {
	defer func(n int) { leafCap = n }(leafCap)
	leafCap = 3
	run, err := NewCA("test")
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

// TestAnAddressLeafHasNoCommonName pins a leaf for an address: the address is in its
// IP addresses and its common name is empty, since OpenSSL reads a common name that
// looks like a name as a name. A leaf for a name has the name in its DNS names.
func TestAnAddressLeafHasNoCommonName(t *testing.T) {
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"192.0.2.10", "2001:db8::1"} {
		l, err := ca.leaf(host)
		if err != nil {
			t.Fatal(err)
		}
		if cn, ips := l.Leaf.Subject.CommonName, l.Leaf.IPAddresses; cn != "" || len(ips) != 1 || !ips[0].Equal(net.ParseIP(host)) {
			t.Errorf("the leaf for %s has the common name %q and the addresses %v", host, cn, ips)
		}
	}
	l, err := ca.leaf("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if names := l.Leaf.DNSNames; len(names) != 1 || names[0] != "api.example.com" {
		t.Errorf("the leaf for api.example.com has the names %q", names)
	}
}
