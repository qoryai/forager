package e2e

import (
	"encoding/binary"
	"net"
	"syscall"
)

// linkLayer is the neighbour table, IPv4 and IPv6, read over netlink: each address with
// its link-layer address, for the entries that have one.
func linkLayer() (map[string]string, error) {
	b, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return nil, err
	}
	// After the message's header, an entry is an ndmsg of 12 bytes and its attributes,
	// each a length and a type of 2 bytes and the value, padded to 4 bytes.
	const (
		ndmsgLen  = 12
		ndaDst    = 1
		ndaLLAddr = 2
	)
	out := map[string]string{}
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWNEIGH || len(m.Data) < ndmsgLen {
			continue
		}
		var dst net.IP
		var ll net.HardwareAddr
		for a := m.Data[ndmsgLen:]; len(a) >= 4; {
			l := int(binary.NativeEndian.Uint16(a[0:2]))
			if l < 4 || l > len(a) {
				break
			}
			switch binary.NativeEndian.Uint16(a[2:4]) {
			case ndaDst:
				dst = net.IP(append([]byte(nil), a[4:l]...))
			case ndaLLAddr:
				ll = net.HardwareAddr(append([]byte(nil), a[4:l]...))
			}
			a = a[min((l+3)&^3, len(a)):]
		}
		if dst != nil && len(ll) > 0 {
			out[dst.String()] = ll.String()
		}
	}
	return out, nil
}
