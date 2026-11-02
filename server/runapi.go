package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net/http"

	"github.com/qoryai/forager/accesskey"
)

// MaxRunAPIAnswer is the largest body of a 200 of the run API other than a file that
// the gateway reads: a larger one counts as unverified. A file has no such bound, since
// it streams.
const MaxRunAPIAnswer = 16 << 20

// ErrRunAPIUnverified is the error of an answer of the run API that fails verification
// under the pin: its status, headers and body are not to be passed on. A 401 is never
// signed, so it is this error too. A file returns it from [RunAPIAnswer.File]'s Read at
// the end of the body, in place of [io.EOF].
var ErrRunAPIUnverified = errors.New("the answer failed verification under the pin")

// RunAPIAnswer is a verified answer of the run API: its status and headers, and Body, or
// File for the 200 of a file.
type RunAPIAnswer struct {
	Status int
	Header http.Header
	Body   []byte
	// File reads the 200 of a file as it streams. Read returns [io.EOF] only once the
	// bytes read match the digest the answer's signature covers, and returns
	// [ErrRunAPIUnverified] at the end of the body otherwise: until then the bytes are
	// unverified, and the status and headers with them. Close ends the request.
	File io.ReadCloser
}

// runAPIFile is [RunAPIAnswer.File]: the body with a running SHA-256, verified at its end.
type runAPIFile struct {
	body   io.ReadCloser
	sum    hash.Hash
	verify func(digest string) bool
	err    error
}

// Read reads the body, and returns [ErrRunAPIUnverified] in place of the [io.EOF] of a
// body that fails verification. Every later call returns the same error.
func (f *runAPIFile) Read(p []byte) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	n, err := f.body.Read(p)
	f.sum.Write(p[:n])
	if errors.Is(err, io.EOF) && !f.verify(hex.EncodeToString(f.sum.Sum(nil))) {
		err = ErrRunAPIUnverified
	}
	f.err = err
	return n, err
}

// Close ends the request.
func (f *runAPIFile) Close() error { return f.body.Close() }

// RunAPI sends one request of the run API, signed as [Client.send] signs a request, to
// the run endpoint runURL followed by a slash, the run's id and path, an escaped path
// that starts with a slash and has no query. body is a POST's, as the gateway read it,
// and a POST has Content-Type: application/json; no other header of the caller's is
// sent. With file, the answer's 200 is a file: it comes back as [RunAPIAnswer.File],
// unread, and the caller reads it to its end and closes it.
//
// The time a request has is ctx's, not [Timeout], since a file takes minutes, and a
// file's ctx must outlive its read. An answer that fails verification under the pin is
// [ErrRunAPIUnverified], and any other error is a transport failure: no answer. A POST
// goes out once: net/http does not send it again on a connection that failed.
func (c *Client) RunAPI(ctx context.Context, runURL, runID, method, path string, body []byte, file bool) (*RunAPIAnswer, error) {
	var set func(http.Header)
	if method == http.MethodPost {
		set = func(h http.Header) { h.Set("Content-Type", "application/json") }
	}
	hc, req, sig, err := c.signed(ctx, method, runURL+"/"+runID+path, body, set)
	if err != nil {
		return nil, err
	}
	hc.Timeout = 0
	// Without GetBody net/http has no second copy of the body to send.
	req.GetBody = nil
	resp, err := hc.Do(req)
	if err != nil {
		return nil, accesskey.ShownError(err)
	}
	if file && resp.StatusCode == http.StatusOK {
		if len(resp.Header.Values(HeaderSignature)) != 1 {
			resp.Body.Close()
			return nil, ErrRunAPIUnverified
		}
		return &RunAPIAnswer{Status: resp.StatusCode, Header: resp.Header, File: &runAPIFile{body: resp.Body, sum: sha256.New(), verify: func(digest string) bool {
			return c.verifies(resp, sig, accesskey.Answer{Digest: digest})
		}}}, nil
	}
	defer resp.Body.Close()
	a, err := c.read(resp, sig, MaxRunAPIAnswer)
	if err != nil {
		return nil, err
	}
	if !a.signed {
		return nil, ErrRunAPIUnverified
	}
	return &RunAPIAnswer{Status: a.status, Header: a.header, Body: a.body}, nil
}
