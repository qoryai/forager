package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/qoryai/forager/policy"
)

// carriedCase is an address the guard is handed and whether it refuses it, unnamed and
// named.
type carriedCase struct {
	address        string
	unnamed, named bool
}

// carriedCases are the addresses that carry an IPv4 address, and those that do not,
// with the guard's judgement of each: the link-local 169.254.169.254 refused whatever
// the policy says, as are the cloud metadata addresses outside that range; 127.0.0.1,
// each IPv4 address this machine's interfaces hold and the private network addresses
// refused unless the host is named, and an ordinary address let through. ::1 and :: keep their judgement as this
// machine's addresses, and an address outside the ranges is judged as itself alone.
func carriedCases(t *testing.T) []carriedCase {
	t.Helper()
	cases := []carriedCase{
		// The cloud metadata addresses outside the link-local ranges are refused
		// whatever the policy says, as 169.254.169.254 is: the literal address, each
		// way an IPv6 address carries an IPv4 one, and with a zone.
		{"100.100.100.200", true, true},
		{"192.0.0.192", true, true},
		{"fd00:ec2::254", true, true},
		{"fd20:ce::254", true, true},
		{"fd00:ec2:0:0:0:0:0:254", true, true},
		{"::ffff:100.100.100.200", true, true},
		{"::ffff:192.0.0.192", true, true},
		{"::6464:64c8", true, true},
		{"::ffff:0:6464:64c8", true, true},
		{"64:ff9b::6464:64c8", true, true},
		{"64:ff9b::100.100.100.200", true, true},
		{"::c000:c0", true, true},
		{"::ffff:0:c000:c0", true, true},
		{"64:ff9b::c000:c0", true, true},
		{"fd00:ec2::254%eth0", true, true},
		{"::6464:64c8%lo0", true, true},
		{"168.63.129.16", true, true},
		{"::ffff:168.63.129.16", true, true},
		{"::a83f:8110", true, true},
		{"::ffff:0:a83f:8110", true, true},
		{"64:ff9b::a83f:8110", true, true},
		{"fd00:ec2::23", true, true},
		{"fd00:a9fe:a9fe::1", true, true},
		{"fd00:42::42", true, true},
		// The addresses next to them outside the private ranges stay open.
		{"192.0.0.193", false, false},
		{"168.63.129.15", false, false},
		{"168.63.129.17", false, false},
		// The private ranges, the addresses next to the metadata addresses in them
		// among them, are refused unless the host is named: the literal address, each
		// way an IPv6 address carries an IPv4 one, and with a zone.
		{"100.100.100.201", true, false},
		{"100.100.100.199", true, false},
		{"fd00:ec2::255", true, false},
		{"fd00:ec2::253", true, false},
		{"fd20:ce::255", true, false},
		{"fd00:ec2::24", true, false},
		{"fd00:a9fe:a9fe::2", true, false},
		{"fd00:42::43", true, false},
		{"10.0.0.1", true, false},
		{"10.255.255.255", true, false},
		{"172.16.0.1", true, false},
		{"172.31.255.255", true, false},
		{"192.168.0.1", true, false},
		{"192.168.255.255", true, false},
		{"100.64.0.1", true, false},
		{"100.127.255.255", true, false},
		{"fc00::1", true, false},
		{"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, false},
		{"::ffff:10.0.0.1", true, false},
		{"::ffff:172.16.0.1", true, false},
		{"::ffff:192.168.0.1", true, false},
		{"::ffff:100.64.0.1", true, false},
		{"::a00:1", true, false},
		{"::ac10:1", true, false},
		{"::c0a8:1", true, false},
		{"::6440:1", true, false},
		{"::ffff:0:a00:1", true, false},
		{"::ffff:0:c0a8:1", true, false},
		{"64:ff9b::a00:1", true, false},
		{"64:ff9b::10.0.0.1", true, false},
		{"64:ff9b::ac10:1", true, false},
		{"64:ff9b::c0a8:1", true, false},
		{"64:ff9b::6440:1", true, false},
		{"64:ff9b::a00:1%eth0", true, false},
		{"fc00::1%eth0", true, false},
		// The addresses just outside the private ranges stay open.
		{"9.255.255.255", false, false},
		{"11.0.0.0", false, false},
		{"172.15.255.255", false, false},
		{"172.32.0.0", false, false},
		{"192.167.255.255", false, false},
		{"192.169.0.0", false, false},
		{"100.63.255.255", false, false},
		{"100.128.0.0", false, false},
		{"fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false, false},
		{"64:ff9b::b00:0", false, false},
		{"::a9fe:a9fe", true, true},
		{"::169.254.169.254", true, true},
		{"::ffff:0:a9fe:a9fe", true, true},
		{"::ffff:0:169.254.169.254", true, true},
		{"64:ff9b::a9fe:a9fe", true, true},
		{"64:ff9b::169.254.169.254", true, true},
		{"::7f00:1", true, false},
		{"::ffff:0:7f00:1", true, false},
		{"64:ff9b::7f00:1", true, false},
		{"::7f00:2", true, false},
		{"64:ff9b::808:808", false, false},
		{"::808:808", false, false},
		{"::ffff:0:808:808", false, false},
		{"64:ff9b::c000:201", false, false},
		// The broadcast address is in 240/4.
		{"64:ff9b::ffff:ffff", true, false},
		{"::ffff:ffff", true, false},
		{"::ffff:0:ffff:ffff", true, false},
		// 0/8, 198.18/15, 240/4 and fec0::/10 are refused unless the host is named:
		// the literal address, each way an IPv6 address carries an IPv4 one, and with a
		// zone.
		{"0.0.0.1", true, false},
		{"0.255.255.255", true, false},
		{"198.18.0.1", true, false},
		{"198.19.255.255", true, false},
		{"240.0.0.1", true, false},
		{"255.255.255.254", true, false},
		{"255.255.255.255", true, false},
		{"fec0::1", true, false},
		{"feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, false},
		{"fec0::1%eth0", true, false},
		{"::ffff:0.0.0.1", true, false},
		{"::ffff:198.18.0.1", true, false},
		{"::ffff:240.0.0.1", true, false},
		{"::ffff:255.255.255.255", true, false},
		{"::c612:1", true, false},
		{"::ffff:0:f000:1", true, false},
		{"64:ff9b::1:1", true, false},
		{"64:ff9b::c613:ffff", true, false},
		{"64:ff9b::f000:1", true, false},
		{"2002:1:1::", true, false},
		{"2002:c612:1::", true, false},
		{"2002:f000:1::", true, false},
		{"64:ff9b:1:808:8:808:c612:1", true, false},
		// The addresses just outside them stay open.
		{"1.0.0.0", false, false},
		{"198.17.255.255", false, false},
		{"198.20.0.0", false, false},
		{"fe00::1", false, false},
		// 6to4, 2002::/16, is judged by the IPv4 address in bits 16 to 47.
		{"2002:a9fe:a9fe::", true, true},
		{"2002:a9fe:a9fe:1:2:3:4:5", true, true},
		{"2002:6464:64c8::", true, true},
		{"2002:c000:c0::", true, true},
		{"2002:a83f:8110::", true, true},
		{"2002:a00:1::", true, false},
		{"2002:a00:1::5", true, false},
		{"2002:ac10:1::", true, false},
		{"2002:c0a8:1::", true, false},
		{"2002:6440:1::", true, false},
		{"2002:7f00:1::", true, false},
		{"2002::", true, false},
		{"2002:a9fe:a9fe::%eth0", true, true},
		{"2002:a00:1::%eth0", true, false},
		{"2002:808:808::", false, false},
		{"2002:808:808:a9fe:a9fe::a9fe:a9fe", false, false},
		// Just outside 2002::/16: not judged by an IPv4 address in it.
		{"2001:a9fe:a9fe::", false, false},
		{"2003:a9fe:a9fe::", false, false},
		// The local-use NAT64 prefix, 64:ff9b:1::/48, is judged by the IPv4 address at
		// each position RFC 6052 defines for one after a prefix of 48, 56, 64 or 96 bits,
		// with bits 64 to 71 skipped. In each address below, the other positions read
		// an ordinary address or one that a name opens.
		{"64:ff9b:1:a9fe:a9:fe08:808:808", true, true},
		{"64:ff9b:1:8a9:fe:a9fe:808:808", true, true},
		{"64:ff9b:1:808:a9:fea9:fe08:808", true, true},
		{"64:ff9b:1:808:8:808:a9fe:a9fe", true, true},
		{"64:ff9b:1::a9fe:a9fe", true, true},
		{"64:ff9b:1:6464:64:c808:808:808", true, true},
		{"64:ff9b:1:808:8:808:6464:64c8", true, true},
		{"64:ff9b:1:a08:8:808:808:808", true, false},
		{"64:ff9b:1:80a:8:808:808:808", true, false},
		{"64:ff9b:1:808:a:808:808:808", true, false},
		{"64:ff9b:1:808:8:808:a08:808", true, false},
		{"64:ff9b:1:a00:0:108:808:808", true, false},
		{"64:ff9b:1:80a:0:1:808:808", true, false},
		{"64:ff9b:1:808:a:0:108:808", true, false},
		{"64:ff9b:1:808:8:808:a00:1", true, false},
		{"64:ff9b:1::7f00:1", true, false},
		{"64:ff9b:1:808:8:808:a9fe:a9fe%eth0", true, true},
		{"64:ff9b:1:808:8:808:a00:1%eth0", true, false},
		// Bits 64 to 71 are skipped: an IPv4 address there is not read.
		{"64:ff9b:1:808:a908:808:808:808", false, false},
		{"64:ff9b:1:808:8:808:808:808", false, false},
		// An ordinary address at the 96-bit position, with zeros between: the other
		// positions read 0.0.0.0.
		{"64:ff9b:1::808:808", true, false},
		// Just outside 64:ff9b:1::/48 and 64:ff9b::/96: judged as itself.
		{"64:ff9b:2::a9fe:a9fe", false, false},
		{"64:ff9b:0:ffff::a9fe:a9fe", false, false},
		// ::1 and :: are this machine's as they are.
		{"::1", true, false},
		{"::", true, false},
		// Outside the ranges: judged as itself, not by its last 32 bits.
		{"2001:db8::a9fe:a9fe", false, false},
		// Just above ::/96: not judged by the last 32 bits.
		{"::1:a9fe:a9fe", false, false},
		// Just outside ::ffff:0:0:0/96, below, above and around it: not judged by the
		// last 32 bits.
		{"::fffe:0:a9fe:a9fe", false, false},
		{"::ffff:1:a9fe:a9fe", false, false},
		{"::ffff:ffff:a9fe:a9fe", false, false},
		{"::1:ffff:0:a9fe:a9fe", false, false},
		{"::1:0:0:a9fe:a9fe", false, false},
		// Mapped into IPv6: judged as the IPv4 address, as before.
		{"::ffff:169.254.169.254", true, true},
		{"::ffff:127.0.0.1", true, false},
		{"::ffff:8.8.8.8", false, false},
		// With a zone: judged after the zone is cut.
		{"::a9fe:a9fe%lo0", true, true},
		{"64:ff9b::a9fe:a9fe%25eth0", true, true},
		{"::7f00:1%lo0", true, false},
		{"::ffff:0:7f00:1%lo0", true, false},
		{"64:ff9b::7f00:1%1", true, false},
		{"64:ff9b::808:808%eth0", false, false},
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil {
			continue
		}
		found = true
		v4 := n.IP.To4()
		cases = append(cases,
			carriedCase{"::" + v4.String(), true, n.IP.IsLinkLocalUnicast()},
			carriedCase{"::ffff:0:" + v4.String(), true, n.IP.IsLinkLocalUnicast()},
			carriedCase{"64:ff9b::" + v4.String(), true, n.IP.IsLinkLocalUnicast()},
		)
	}
	if !found {
		t.Fatal("this machine holds no IPv4 address on any interface")
	}
	return cases
}

// TestTheWallJudgesTheIPv4AddressAnAddressCarries pins that behind a wall an address in
// ::/96 (other than ::1 and ::), ::ffff:0:0:0/96 or 64:ff9b::/96 is also judged by the
// IPv4 address in its last 32 bits, at the guard and through the system's dialler:
// refused where that IPv4 address would be, by the wall's refusal, and never connected;
// let through when it would be.
func TestTheWallJudgesTheIPv4AddressAnAddressCarries(t *testing.T) {
	p, err := Listen("", policy.Observe, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.Guard(nil)
	plain := context.Background()
	named := context.WithValue(plain, namedKey{}, true)
	rec := &passedDial{}
	dial := rec.dialler(p)
	for _, c := range carriedCases(t) {
		address := net.JoinHostPort(c.address, "80")
		for _, j := range []struct {
			ctx     context.Context
			refused bool
		}{{plain, c.unnamed}, {named, c.named}} {
			err := p.guard(j.ctx, address)
			var ge *guardError
			if j.refused != (err != nil) || (err != nil && !errors.As(err, &ge)) {
				t.Errorf("guard %s (named %v): %v, want refused %v", address, j.ctx == named, err, j.refused)
			}
			_, err = dial(j.ctx, "tcp", address)
			switch got := rec.take(); {
			case j.refused && (len(got) != 0 || !errors.As(err, &ge)):
				t.Errorf("dial %s (named %v): passed %v, %v; want the wall's refusal", address, j.ctx == named, got, err)
			case !j.refused && (len(got) == 0 || !errors.Is(err, errPassed)):
				t.Errorf("dial %s (named %v): passed %v, %v; want it let through", address, j.ctx == named, got, err)
			}
		}
	}
}

// TestTheWallJudgesTheIPv4AddressOfTheHostsFile pins that behind a wall a one-label
// name the hosts file gives an address that carries an IPv4 address is judged by that
// IPv4 address as well: refused by the wall's rule with a 403, recorded as refused and
// never connected, where the IPv4 address would be, even when an allow entry names the
// host for a link-local one; opened when an allow entry names the host for this
// machine's; dialled as the file gives it for an ordinary one.
func TestTheWallJudgesTheIPv4AddressOfTheHostsFile(t *testing.T) {
	for _, c := range carriedCases(t) {
		a, err := netip.ParseAddr(c.address)
		if err != nil {
			t.Fatal(err)
		}
		file := (&hostsEntries{names: map[string][]netip.Addr{"host": {a}}}).lookup
		for _, j := range []struct {
			mode        policy.Mode
			allow, open []string
			refused     bool
		}{
			{policy.Observe, nil, nil, c.unnamed},
			{policy.Enforce, []string{"*.example", "host"}, []string{"*.example"}, c.unnamed},
			{policy.Enforce, []string{"host"}, []string{"host"}, c.named},
		} {
			seen := &decisions{}
			p, err := Listen("", j.mode, j.allow, nil, seen.observe)
			if err != nil {
				t.Fatal(err)
			}
			rec := &passedDial{}
			p.dial = rec.dialler(p)
			p.hosts = file
			p.Guard(j.open)
			code, _ := raw(t, p, "GET http://host/x", "host")
			d := seen.at(-1)
			got := rec.take()
			if j.refused {
				if code != 403 || d.Rule != GuardRule || d.Allowed || d.Outcome != Refused || len(got) != 0 {
					t.Errorf("%s %v: %d, decision %+v, passed %v; want the wall's refusal", c.address, j.open, code, d, got)
				}
			} else if len(got) == 0 || !dialledAt(got[0], a) || d.Rule == GuardRule || d.Outcome != DialFailed {
				t.Errorf("%s %v: %d, decision %+v, passed %v; want it dialled at %s", c.address, j.open, code, d, got, a)
			}
			p.Close()
		}
	}
}

// dialledAt reports whether address, host:port as the system's dialler hands it to the
// guard, is a: the dialler writes an IPv4 address mapped into IPv6 as IPv4.
func dialledAt(address string, a netip.Addr) bool {
	ap, err := netip.ParseAddrPort(address)
	return err == nil && ap.Addr().Unmap() == a.Unmap()
}
