package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/server"
)

const runAPIRun = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"

// runAPIClient is a client of a run API the handler serves, whose answers it verifies
// under signer, and its access key and run endpoint.
func runAPIClient(t *testing.T, signer *accesskey.Key, h http.HandlerFunc) (*server.Client, *accesskey.Key, string) {
	t.Helper()
	key := generate(t)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := &server.Client{Config: &server.Config{Version: 1, URL: srv.URL, AccessKeyID: accessKeyID, ApiaryPublicKey: pinOf(signer)}, Key: key, InstanceID: instance, UserAgent: "qory-forager/test"}
	return c, key, srv.URL + "/v1/runs"
}

// TestRunAPISignsTheRequest pins what reaches Qory Apiary: the method and the exact
// target under the access key, a GET with its timestamp, a POST with its body and
// Content-Type, and nothing of a caller's.
func TestRunAPISignsTheRequest(t *testing.T) {
	signer := generate(t)
	var key *accesskey.Key
	var checked atomic.Int32
	c, k, runURL := runAPIClient(t, signer, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req := accesskey.Request{AccessKeyID: r.Header.Get(server.HeaderAccessKeyID), InstanceID: r.Header.Get(server.HeaderInstanceID),
			Method: r.Method, Target: r.RequestURI, Timestamp: r.Header.Get(server.HeaderTimestamp), Body: body}
		sig := r.Header.Get(server.HeaderSignature)
		if key.PublicKey().VerifyRequest(req, sig) {
			checked.Add(1)
		} else {
			t.Errorf("%s %s does not verify under the access key", r.Method, r.RequestURI)
		}
		if got := r.Header.Get("Content-Type"); (r.Method == http.MethodPost) != (got == "application/json") {
			t.Errorf("%s has Content-Type %q", r.Method, got)
		}
		out := []byte(`{"ok":true}`)
		w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: sig, Body: out}))
		w.Write(out)
	})
	key = k
	for _, s := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/work-item", ""},
		{http.MethodGet, "/artifacts/a%20b/files/c%23d", ""},
		{http.MethodPost, "/artifacts", `{"name":"plan"}`},
		{http.MethodPost, "/verdict", `{"verdict":"pass"}`},
	} {
		var body []byte
		if s.body != "" {
			body = []byte(s.body)
		}
		a, err := c.RunAPI(context.Background(), runURL, runAPIRun, s.method, s.path, body, false)
		if err != nil {
			t.Fatalf("%s %s: %v", s.method, s.path, err)
		}
		if a.Status != http.StatusOK || string(a.Body) != `{"ok":true}` {
			t.Errorf("%s %s: %d %s", s.method, s.path, a.Status, a.Body)
		}
	}
	if checked.Load() != 4 {
		t.Errorf("%d requests verified, want 4", checked.Load())
	}
}

// TestRunAPIChecksTheAnswer pins that an answer that fails verification is
// ErrRunAPIUnverified, an unsigned 401 too, and that no such answer's body comes back.
func TestRunAPIChecksTheAnswer(t *testing.T) {
	signer, other := generate(t), generate(t)
	body := []byte(`{"secret":"fake-unverified-body"}`)
	for name, h := range map[string]http.HandlerFunc{
		"no signature": func(w http.ResponseWriter, _ *http.Request) { w.Write(body) },
		"another key": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(server.HeaderSignature, other.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: r.Header.Get(server.HeaderSignature), Body: body}))
			w.Write(body)
		},
		"another body": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: r.Header.Get(server.HeaderSignature), Body: []byte("{}")}))
			w.Write(body)
		},
		"another status": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: http.StatusAccepted, RequestSignature: r.Header.Get(server.HeaderSignature), Body: body}))
			w.Write(body)
		},
		"another request": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: "another", Body: body}))
			w.Write(body)
		},
		"an unsigned 401": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(body)
		},
	} {
		c, _, runURL := runAPIClient(t, signer, h)
		a, err := c.RunAPI(context.Background(), runURL, runAPIRun, http.MethodGet, "/work-item", nil, false)
		if !errors.Is(err, server.ErrRunAPIUnverified) || a != nil {
			t.Errorf("%s: %+v, %v", name, a, err)
		}
	}
}

// TestRunAPIPassesARefusalThatVerifies pins that a signed refusal comes back as an
// answer: only an answer that fails verification is an error.
func TestRunAPIPassesARefusalThatVerifies(t *testing.T) {
	signer := generate(t)
	body := []byte(`{"error":"run_closed"}`)
	c, _, runURL := runAPIClient(t, signer, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: http.StatusGone, RequestSignature: r.Header.Get(server.HeaderSignature), Body: body}))
		w.WriteHeader(http.StatusGone)
		w.Write(body)
	})
	for _, file := range []bool{false, true} {
		a, err := c.RunAPI(context.Background(), runURL, runAPIRun, http.MethodGet, "/artifacts/v/files/f", nil, file)
		if err != nil || a.Status != http.StatusGone || !bytes.Equal(a.Body, body) || a.File != nil {
			t.Errorf("file %v: %+v, %v", file, a, err)
		}
	}
}

// TestRunAPIFileVerifiesAtItsEnd pins a file's stream: Read returns io.EOF only for
// bytes that match the signed digest, and ErrRunAPIUnverified at the end of any other.
func TestRunAPIFileVerifiesAtItsEnd(t *testing.T) {
	signer, other := generate(t), generate(t)
	content := bytes.Repeat([]byte("artifact bytes "), 4096)
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	for _, c := range []struct {
		name   string
		signer *accesskey.Key
		digest string
		want   error
	}{
		{"the signed digest", signer, digest, nil},
		{"another digest", signer, hex.EncodeToString(make([]byte, 32)), server.ErrRunAPIUnverified},
		{"another key", other, digest, server.ErrRunAPIUnverified},
	} {
		client, _, runURL := runAPIClient(t, signer, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(server.HeaderSignature, c.signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: r.Header.Get(server.HeaderSignature), Digest: c.digest}))
			w.Write(content)
		})
		a, err := client.RunAPI(context.Background(), runURL, runAPIRun, http.MethodGet, "/artifacts/v/files/f", nil, true)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if a.File == nil || a.Body != nil {
			t.Fatalf("%s: %+v", c.name, a)
		}
		got, err := io.ReadAll(a.File)
		a.File.Close()
		if !errors.Is(err, c.want) {
			t.Errorf("%s: read error %v, want %v", c.name, err, c.want)
		}
		if !bytes.Equal(got, content) {
			t.Errorf("%s: read %d bytes of %d", c.name, len(got), len(content))
		}
	}
}

// TestRunAPIFileWithoutOneSignatureIsUnverified pins a 200 of a file with no signature
// or two: nothing streams.
func TestRunAPIFileWithoutOneSignatureIsUnverified(t *testing.T) {
	signer := generate(t)
	for name, values := range map[string][]string{"none": nil, "two": {"one", "two"}} {
		c, _, runURL := runAPIClient(t, signer, func(w http.ResponseWriter, _ *http.Request) {
			w.Header()[server.HeaderSignature] = values
			io.WriteString(w, "bytes")
		})
		if a, err := c.RunAPI(context.Background(), runURL, runAPIRun, http.MethodGet, "/artifacts/v/files/f", nil, true); !errors.Is(err, server.ErrRunAPIUnverified) {
			t.Errorf("%s: %+v, %v", name, a, err)
		}
	}
}

// TestRunAPITimeIsTheContexts pins that the client's timeout does not cut a file short,
// and that the context does end a request.
func TestRunAPITimeIsTheContexts(t *testing.T) {
	if server.Timeout > time.Minute {
		t.Fatalf("Timeout %s", server.Timeout)
	}
	signer := generate(t)
	release := make(chan struct{})
	c, _, runURL := runAPIClient(t, signer, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := c.RunAPI(ctx, runURL, runAPIRun, http.MethodPost, "/verdict", []byte("{}"), false)
	if err == nil || errors.Is(err, server.ErrRunAPIUnverified) {
		t.Errorf("%v", err)
	}
}

// TestRunAPISendsAPostOnce pins that a connection that fails during a POST on a reused
// connection is an error, with no second POST.
func TestRunAPISendsAPostOnce(t *testing.T) {
	signer := generate(t)
	var posts atomic.Int32
	c, _, runURL := runAPIClient(t, signer, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
			io.Copy(io.Discard, r.Body)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: r.Header.Get(server.HeaderSignature)}))
	})
	if _, err := c.RunAPI(context.Background(), runURL, runAPIRun, http.MethodGet, "/work-item", nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RunAPI(context.Background(), runURL, runAPIRun, http.MethodPost, "/verdict", []byte("{}"), false); err == nil || errors.Is(err, server.ErrRunAPIUnverified) {
		t.Errorf("%v", err)
	}
	if got := posts.Load(); got != 1 {
		t.Errorf("%d POSTs reached the server", got)
	}
}
