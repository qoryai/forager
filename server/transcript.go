package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// MaxResumeTranscript is the largest transcript of a paused run the gateway reads from
// the server, 64 MiB.
const MaxResumeTranscript = 64 << 20

// ErrTranscriptNotFound is a signed 404 to a transcript request: the run continues no
// paused run, or the server keeps no transcript of it.
var ErrTranscriptNotFound = errors.New("the server has no transcript for the run")

// ErrTranscriptTooLarge is the error of a transcript's Read past
// [MaxResumeTranscript] bytes.
var ErrTranscriptTooLarge = fmt.Errorf("the transcript is over %d bytes", MaxResumeTranscript)

// ResumeTranscript reads the transcript of the paused run that runID continues: a GET
// of <runURL>/<runID>/resume/transcript, signed as every request of the run API is.
// The 200 is a file ([RunAPIAnswer.File]): Read returns [io.EOF] only once the bytes
// match the digest the answer's signature covers, [ErrRunAPIUnverified] at the end of
// any other, and [ErrTranscriptTooLarge] past [MaxResumeTranscript] bytes. The caller
// reads it and closes it; ctx must outlive the read. A signed 404 is
// [ErrTranscriptNotFound]; another verified answer is an error with its status, and an
// answer that fails verification is [ErrRunAPIUnverified].
func (c *Client) ResumeTranscript(ctx context.Context, runURL, runID string) (io.ReadCloser, error) {
	if !runIDShape.MatchString(runID) {
		return nil, errors.New("the transcript request: the run id is not a UUID in the canonical lower-case form")
	}
	a, err := c.RunAPI(ctx, runURL, runID, http.MethodGet, "/resume/transcript", nil, true)
	switch {
	case err != nil:
		return nil, err
	case a.Status == http.StatusNotFound:
		return nil, ErrTranscriptNotFound
	case a.Status != http.StatusOK || a.File == nil:
		return nil, fmt.Errorf("the transcript request: status %d", a.Status)
	}
	return &boundedFile{f: a.File, left: MaxResumeTranscript}, nil
}

// boundedFile is a file whose Read fails with [ErrTranscriptTooLarge] past left bytes.
type boundedFile struct {
	f    io.ReadCloser
	left int64
}

func (b *boundedFile) Read(p []byte) (int, error) {
	if b.left <= 0 {
		// One byte more separates a file of exactly the bound from a longer one.
		var one [1]byte
		n, err := b.f.Read(one[:])
		if n > 0 {
			return 0, ErrTranscriptTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.f.Read(p)
	b.left -= int64(n)
	return n, err
}

// Close ends the request.
func (b *boundedFile) Close() error { return b.f.Close() }
