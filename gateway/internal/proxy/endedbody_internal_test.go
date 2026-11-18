package proxy

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
)

// closedAfterEOF is a session's body as the server reads it: the last bytes come with
// io.EOF, and each read after that fails, as the server closed the body by then.
type closedAfterEOF struct {
	io.Reader
	ended bool
}

func (c *closedAfterEOF) Read(p []byte) (int, error) {
	if c.ended {
		return 0, http.ErrBodyReadAfterClose
	}
	n, err := c.Reader.Read(p)
	if err == io.EOF {
		c.ended = true
	}
	return n, err
}

func (c *closedAfterEOF) Close() error { return nil }

// TestABodyPastItsEndReadsEOF pins endAtEOF: a read past the end of the body returns
// io.EOF and never reaches the session's body, which the server may have closed by
// then; nil and http.NoBody stay as they are.
func TestABodyPastItsEndReadsEOF(t *testing.T) {
	body := endAtEOF(&closedAfterEOF{Reader: iotest.DataErrReader(strings.NewReader("0000"))})
	// As the transport sends a body of a known length: that length, then a read for
	// any byte past it.
	b, err := io.ReadAll(io.LimitReader(body, 4))
	if err != nil || string(b) != "0000" {
		t.Fatalf("the body %q %v; want 0000", b, err)
	}
	if _, err := io.ReadAll(body); err != nil {
		t.Errorf("the read past the end: %v; want none", err)
	}
	for range 2 {
		if n, err := body.Read(make([]byte, 8)); n != 0 || !errors.Is(err, io.EOF) {
			t.Errorf("a read past the end: %d %v; want 0 and EOF", n, err)
		}
	}
	if endAtEOF(nil) != nil || endAtEOF(http.NoBody) != http.NoBody {
		t.Error("nil or http.NoBody changed")
	}
}

// TestABodyThatEndsEarlyStaysAnError pins that endAtEOF ends a body only at io.EOF: a
// session's body that ends before its length, as a client that goes away, returns its
// error, so the transport sends no shorter body as a whole one.
func TestABodyThatEndsEarlyStaysAnError(t *testing.T) {
	body := endAtEOF(io.NopCloser(io.MultiReader(strings.NewReader("00"), iotest.ErrReader(io.ErrUnexpectedEOF))))
	b, err := io.ReadAll(body)
	if string(b) != "00" || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("the body %q %v; want 00 and an unexpected EOF", b, err)
	}
	if _, err := body.Read(make([]byte, 8)); errors.Is(err, io.EOF) {
		t.Errorf("a read after the early end: %v; want no EOF", err)
	}
}
