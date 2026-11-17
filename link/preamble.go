package link

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"time"
)

// PreambleWait is how long a connection has to send its preamble, [RelayPreamble] and
// its secret: whoever reads one sets the connection's read deadline this far ahead
// before it reads, and closes a connection that sends none in time.
const PreambleWait = 10 * time.Second

// MaxSecret is the longest secret a preamble on this machine carries, in bytes, so a
// preamble is read with a bounded read.
const MaxSecret = 256

// errSecret is a secret no preamble carries.
var errSecret = errors.New("link: a preamble's secret is 1 to 256 printable characters other than a space")

// checkSecret reports whether a preamble may carry the secret: 1 to [MaxSecret]
// printable ASCII characters other than a space, so the line ends at its one newline.
func checkSecret(secret string) error {
	if secret == "" || len(secret) > MaxSecret {
		return errSecret
	}
	for i := 0; i < len(secret); i++ {
		if c := secret[i]; c <= ' ' || c > '~' {
			return errSecret
		}
	}
	return nil
}

// CheckSecret reports whether a preamble may carry the secret, as every preamble on
// this machine is written and read: 1 to [MaxSecret] printable ASCII characters other
// than a space.
func CheckSecret(secret string) error { return checkSecret(secret) }

// RelayLine is the line that opens a connection to a proxy that requires the run's
// secret: [RelayPreamble], a space, the secret and a newline.
func RelayLine(secret string) string { return RelayPreamble + " " + secret + "\n" }

// StackLine is the line that opens a connection to a run's stack proxy on a separate
// gateway's one address: [StackPreamble], a space, the run key and a newline.
func StackLine(runKey string) string { return StackPreamble + " " + runKey + "\n" }

// PushLine is the line that opens a connection to a run's push proxy on a separate
// gateway's one address: [PushPreamble], a space, the run key and a newline.
func PushLine(runKey string) string { return PushPreamble + " " + runKey + "\n" }

// ReadRelayPreamble reads the relay's preamble, [RelayPreamble], a space, the secret
// and a newline, from the start of a connection and reports whether it carries the
// secret, compared in constant time. It reads exactly the preamble's length and no
// further, so r then holds the connection's first byte after it. It returns false and
// the error when the connection ends or its deadline passes before the preamble's
// length is read, and false with no error when the bytes are not the preamble: another
// word, another secret, a longer line or one without its newline. Whoever reads it
// closes the connection unanswered on false, and logs neither the secret nor what it
// read.
func ReadRelayPreamble(r io.Reader, secret string) (ok bool, err error) {
	if err := checkSecret(secret); err != nil {
		return false, err
	}
	want := []byte(RelayLine(secret))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// RelayPeerPreamble opens the line the wall's relay writes right after
// [RelayPreamble]'s line when it is told to, [RelayPeerLine]: the address the
// connection came from inside the enclosure.
const RelayPeerPreamble = "QORY-PEER"

// RelayPeerLine is the line that contains, for the run's forwarder, the address a
// connection the relay copies came from: [RelayPeerPreamble], a space, the address's 16
// bytes in lower-case hex, an IPv4 address in its IPv4-mapped IPv6 form, and a newline.
// Every such line has the same length, so it is read with one bounded read.
func RelayPeerLine(addr netip.Addr) string {
	b := addr.As16()
	return RelayPeerPreamble + " " + hex.EncodeToString(b[:]) + "\n"
}

// errPeerLine is what [ReadRelayPeer] returns for bytes that are not a peer line.
var errPeerLine = errors.New("link: the relay's peer line is malformed")

// ReadRelayPeer reads [RelayPeerLine] from r and returns its address, an IPv4 address
// unmapped. It reads exactly the line's length and no further. It returns the read's
// error when r ends or its deadline passes first, and an error for bytes that are not
// such a line.
func ReadRelayPeer(r io.Reader) (netip.Addr, error) {
	got := make([]byte, len(RelayPeerLine(netip.IPv6Unspecified())))
	if _, err := io.ReadFull(r, got); err != nil {
		return netip.Addr{}, err
	}
	rest, ok := bytes.CutPrefix(got, []byte(RelayPeerPreamble+" "))
	hexed, ok2 := bytes.CutSuffix(rest, []byte("\n"))
	var b [16]byte
	if !ok || !ok2 {
		return netip.Addr{}, errPeerLine
	}
	if n, err := hex.Decode(b[:], hexed); err != nil || n != len(b) {
		return netip.Addr{}, errPeerLine
	}
	return netip.AddrFrom16(b).Unmap(), nil
}
