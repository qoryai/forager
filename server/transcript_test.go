package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/server"
)

// TestResumeTranscriptReadsTheSignedFile pins the transcript request: a signed GET of
// <run.url>/<run_id>/resume/transcript, whose 200 reads to io.EOF only when its bytes
// match the signed digest; a signed 404 is ErrTranscriptNotFound, an unsigned one
// ErrRunAPIUnverified, another signed status an error, and a file over 64 MiB
// ErrTranscriptTooLarge.
func TestResumeTranscriptReadsTheSignedFile(t *testing.T) {
	signer := generate(t)
	content := bytes.Repeat([]byte(`{"type":"user"}`+"\n"), 1000)
	var answer func(w http.ResponseWriter, r *http.Request)
	var target string
	client, _, runURL := runAPIClient(t, signer, func(w http.ResponseWriter, r *http.Request) {
		target = r.Method + " " + r.RequestURI
		answer(w, r)
	})
	file := func(b []byte, digest string) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: r.Header.Get(server.HeaderSignature), Digest: digest}))
			w.Write(b)
		}
	}
	digestOf := func(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
	read := func() ([]byte, error) {
		t.Helper()
		f, err := client.ResumeTranscript(context.Background(), runURL, runAPIRun)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return io.ReadAll(f)
	}

	answer = file(content, digestOf(content))
	if got, err := read(); err != nil || !bytes.Equal(got, content) {
		t.Errorf("the signed file: %d bytes, %v", len(got), err)
	}
	if want := "GET /v1/runs/" + runAPIRun + "/resume/transcript"; target != want {
		t.Errorf("sent %s; want %s", target, want)
	}
	answer = file(content, digestOf([]byte("other")))
	if _, err := read(); !errors.Is(err, server.ErrRunAPIUnverified) {
		t.Errorf("another digest: %v", err)
	}
	signed := func(status int, unsigned bool) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			body := `{"error":"not_found"}`
			if !unsigned {
				w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: status, RequestSignature: r.Header.Get(server.HeaderSignature), Body: []byte(body)}))
			}
			w.WriteHeader(status)
			io.WriteString(w, body)
		}
	}
	answer = signed(http.StatusNotFound, false)
	if _, err := read(); !errors.Is(err, server.ErrTranscriptNotFound) {
		t.Errorf("a signed 404: %v", err)
	}
	answer = signed(http.StatusNotFound, true)
	if _, err := read(); !errors.Is(err, server.ErrRunAPIUnverified) {
		t.Errorf("an unsigned 404: %v", err)
	}
	answer = signed(http.StatusConflict, false)
	if _, err := read(); err == nil || errors.Is(err, server.ErrTranscriptNotFound) {
		t.Errorf("a signed 409: %v", err)
	}
	big := bytes.Repeat([]byte{'x'}, server.MaxResumeTranscript+1)
	answer = file(big, digestOf(big))
	if _, err := read(); !errors.Is(err, server.ErrTranscriptTooLarge) {
		t.Errorf("a file over 64 MiB: %v", err)
	}
	exact := big[:server.MaxResumeTranscript]
	answer = file(exact, digestOf(exact))
	if got, err := read(); err != nil || len(got) != server.MaxResumeTranscript {
		t.Errorf("a file of 64 MiB: %d bytes, %v", len(got), err)
	}
	if _, err := client.ResumeTranscript(context.Background(), runURL, "nope"); err == nil {
		t.Error("a run id outside its form was taken")
	}
}
