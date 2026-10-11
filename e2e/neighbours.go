package e2e

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// neighboursPrefix starts the one line of standard output that holds the report of the
// search for neighbours.
const neighboursPrefix = "walltest-neighbours: "

// neighbourPorts are the ports a connection is tried on at each address that answers.
// The relay's own port at the relay's address outside link-local is not tried: the
// relay listens there by design, and the suite checks that listener on its own.
var neighbourPorts = []int{22, 53, 80, 443, 2375, 2376, 3128, 8080}

// neighbours is what a container the agent started, privileged on the enclosure's own
// network with IPv6 turned on, found on the enclosure's link to the inside network: who
// answers an echo sent to every node of the link, and what a connection to each opens.
type neighbours struct {
	// Err is why the search could not be made; empty when it was.
	Err string `json:"err"`
	// Link is the enclosure's interface on the inside network: the one with an address
	// in the relay's IPv4 subnet.
	Link string `json:"link"`
	// Relay is the relay's link-layer address.
	Relay string `json:"relay"`
	// Answered are the addresses that answered, each with its link-layer address, or
	// "self" for an address of the enclosure's own.
	Answered map[string]string `json:"answered"`
	// Connected are the addresses and ports a connection opened to.
	Connected []string `json:"connected"`
}

// problem is what is wrong with what the search found, empty when nothing is: a search
// that could not be made, a relay that did not answer, an address that answered and is
// neither the enclosure's own nor the relay's, or a connection that opened.
func (n neighbours) problem() string {
	if n.Err != "" {
		return "the search could not be made: " + n.Err
	}
	if n.Relay == "" {
		return fmt.Sprintf("the relay's link-layer address is unknown; answered: %v", n.Answered)
	}
	var relay, others []string
	for addr, ll := range n.Answered {
		switch ll {
		case "self":
		case n.Relay:
			relay = append(relay, addr)
		default:
			others = append(others, addr+" at "+ll)
		}
	}
	slices.Sort(others)
	switch {
	case len(others) > 0:
		return fmt.Sprintf("on %s, %v answered, which are neither the enclosure's addresses nor the relay at %s", n.Link, others, n.Relay)
	case len(relay) == 0:
		return fmt.Sprintf("on %s, the relay at %s did not answer; answered: %v", n.Link, n.Relay, n.Answered)
	case len(n.Connected) > 0:
		return fmt.Sprintf("on %s, connections opened to %v", n.Link, n.Connected)
	}
	return ""
}

// neighboursProbe is the probe in a container the agent started, privileged on the
// enclosure's own network: it reads the relay's address from PROBE_RELAY, a URL, looks
// for neighbours and prints its report.
func neighboursProbe() int {
	b, _ := json.Marshal(findNeighbours(os.Getenv("PROBE_RELAY")))
	fmt.Println(neighboursPrefix + string(b))
	return 0
}

// findNeighbours turns IPv6 on for the enclosure's link to the inside network, the one
// with an address in the subnet of the relay's IPv4 address, which relayURL holds with
// the relay's port; sends an echo to every node of the link; reads the link-layer
// address of the relay and of each address that answered and is not its own; and tries
// a connection to each of those on each of [neighbourPorts].
func findNeighbours(relayURL string) neighbours {
	n := neighbours{Answered: map[string]string{}}
	u, err := url.Parse(relayURL)
	var relay net.IP
	if err == nil {
		relay = net.ParseIP(u.Hostname()).To4()
	}
	if relay == nil {
		n.Err = "no relay's IPv4 address in " + strconv.Quote(relayURL)
		return n
	}
	link, err := linkTo(relay)
	if err != nil {
		n.Err = err.Error()
		return n
	}
	n.Link = link
	for _, c := range []string{"all", "default", link} {
		if err := os.WriteFile("/proc/sys/net/ipv6/conf/"+c+"/disable_ipv6", []byte("0"), 0o644); err != nil {
			n.Err = "turning IPv6 on: " + err.Error()
			return n
		}
	}
	if err := awaitLinkLocal(link, 10*time.Second); err != nil {
		n.Err = err.Error()
		return n
	}
	// A datagram to an address needs its link-layer address, which the table then holds.
	nudge := func(addr string) {
		if c, err := net.Dial("udp", net.JoinHostPort(addr, "9")); err == nil {
			c.Write([]byte{0})
			c.Close()
		}
	}
	nudge(relay.String())
	answered, err := echoAll(link)
	if err != nil {
		n.Err = "the echo: " + err.Error()
		return n
	}
	own := map[string]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				own[ipn.IP.String()] = true
			}
		}
	}
	var others []string
	for _, addr := range answered {
		if own[addr] {
			n.Answered[addr] = "self"
			continue
		}
		others = append(others, addr)
		if net.ParseIP(addr).IsLinkLocalUnicast() {
			nudge(addr + "%" + link)
		} else {
			nudge(addr)
		}
	}
	time.Sleep(time.Second)
	table, err := linkLayer()
	if err != nil {
		n.Err = "the neighbour table: " + err.Error()
		return n
	}
	n.Relay = table[relay.String()]
	for _, addr := range others {
		if n.Answered[addr] = table[addr]; n.Answered[addr] == "" {
			n.Answered[addr] = "unknown"
		}
		for _, port := range neighbourPorts {
			if n.Relay != "" && n.Answered[addr] == n.Relay && strconv.Itoa(port) == u.Port() && !net.ParseIP(addr).IsLinkLocalUnicast() {
				continue
			}
			host := addr
			if net.ParseIP(addr).IsLinkLocalUnicast() {
				host += "%" + link
			}
			to := net.JoinHostPort(host, strconv.Itoa(port))
			if c, err := net.DialTimeout("tcp", to, time.Second); err == nil {
				c.Close()
				n.Connected = append(n.Connected, to)
			}
		}
	}
	return n
}

// linkTo is the name of the interface with an address in the subnet of ip that is not
// ip itself.
func linkTo(ip net.IP) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.Contains(ip) && !ipn.IP.Equal(ip) {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no interface has an address in the subnet of %s", ip)
}

// awaitLinkLocal waits until the interface has a link-local IPv6 address that is no
// longer tentative, as /proc/net/if_inet6 lists it.
func awaitLinkLocal(link string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		b, err := os.ReadFile("/proc/net/if_inet6")
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) != 6 || f[5] != link || !strings.HasPrefix(f[0], "fe80") {
				continue
			}
			// IFA_F_TENTATIVE.
			if flags, err := strconv.ParseUint(f[4], 16, 32); err == nil && flags&0x40 == 0 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s has no link-local IPv6 address after %v", link, wait)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// echoAll sends three ICMPv6 echo requests to ff02::1, every node of the link, a second
// apart, and returns the addresses that answered, each once.
func echoAll(link string) ([]string, error) {
	c, err := net.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, err
	}
	defer c.Close()
	id := os.Getpid() & 0xffff
	to := &net.IPAddr{IP: net.ParseIP("ff02::1"), Zone: link}
	seen := map[string]bool{}
	var out []string
	buf := make([]byte, 1500)
	for seq := 1; seq <= 3; seq++ {
		// Echo request, code 0, the checksum the kernel fills in, the id, the sequence.
		msg := []byte{128, 0, 0, 0, byte(id >> 8), byte(id), 0, byte(seq), 'w', 'a', 'l', 'l'}
		if _, err := c.WriteTo(msg, to); err != nil {
			return nil, err
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		for {
			m, from, err := c.ReadFrom(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					break
				}
				return nil, err
			}
			// An echo reply to this id.
			if m < 8 || buf[0] != 129 || int(buf[4])<<8|int(buf[5]) != id {
				continue
			}
			if a, ok := from.(*net.IPAddr); ok && !seen[a.IP.String()] {
				seen[a.IP.String()] = true
				out = append(out, a.IP.String())
			}
		}
	}
	slices.Sort(out)
	return out, nil
}
