package link

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"io"
	"time"
)

// PreambleWait is how long a connection has to send its preamble, [LinkPreamble] or
// [RelayPreamble] and its secret: whoever reads one sets the connection's read deadline
// this far ahead before it reads, and closes a connection that sends none in time.
const PreambleWait = 10 * time.Second

// MaxSecret is the longest secret a preamble carries, in bytes, so a preamble is read
// with a bounded read.
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

// CheckSecret reports whether a preamble may carry the secret, as every preamble the
// link writes or reads checks it: 1 to [MaxSecret] printable ASCII characters other
// than a space.
func CheckSecret(secret string) error { return checkSecret(secret) }

// Preamble is the line that opens a connection with the word, [LinkPreamble] or
// [RelayPreamble], and the secret: the word, a space, the secret and a newline.
func Preamble(word, secret string) string { return word + " " + secret + "\n" }

// writePreamble writes the word's preamble with the secret in one write.
func writePreamble(w io.Writer, word, secret string) error {
	if err := checkSecret(secret); err != nil {
		return err
	}
	_, err := io.WriteString(w, Preamble(word, secret))
	return err
}

// readPreamble reads exactly as many bytes as the word's preamble with the secret has,
// never more, and compares them with it in constant time, as the proxy reads
// [RelayPreamble]. A line that is longer, shorter or another does not compare equal.
func readPreamble(r io.Reader, word, secret string) (bool, error) {
	if err := checkSecret(secret); err != nil {
		return false, err
	}
	want := []byte(Preamble(word, secret))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// WriteLinkPreamble writes the local link's preamble, [LinkPreamble], a space, the
// link secret and a newline, in one write, before the first byte of HTTP. The session
// writes it only after it checked that the socket's peer is its own user.
func WriteLinkPreamble(w io.Writer, secret string) error {
	return writePreamble(w, LinkPreamble, secret)
}

// ReadLinkPreamble reads the local link's preamble from the start of a connection and
// reports whether it carries the link secret, compared in constant time. It reads
// exactly the preamble's length and no further, so r then holds the connection's
// first byte of HTTP. It returns false and the error when the connection ends or its
// deadline passes before the preamble's length is read, and false with no error when
// the bytes are not the preamble: another word, another secret, a longer line or one
// without its newline. A gateway closes the connection unanswered on false, and logs
// neither the secret nor what it read.
func ReadLinkPreamble(r *bufio.Reader, secret string) (ok bool, err error) {
	return readPreamble(r, LinkPreamble, secret)
}

// ReadRelayPreamble reads the relay's preamble, [RelayPreamble], a space, the secret
// and a newline, from the start of a connection, as [ReadLinkPreamble] reads the local
// link's: exactly its length and no further, compared in constant time.
func ReadRelayPreamble(r io.Reader, secret string) (ok bool, err error) {
	return readPreamble(r, RelayPreamble, secret)
}
