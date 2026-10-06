package walltest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// RecorderArgs are the arguments that make the helper run a recorder.
var RecorderArgs = []string{modeRecorder}

// RecorderFile is the file, inside a recorder's container, that contains what it
// recorded: one JSON document a line, each a request.
const RecorderFile = "/tmp/walltest-recorded"

// The ports a recorder listens on.
const (
	recorderTLS   = "8443"
	recorderPlain = "8080"
)

// The variables that carry the suite's authority to a recorder and to the probe: its
// certificate, and to a recorder its key, each DER in standard base64.
const (
	envAuthority    = "QORY_WALLTEST_AUTHORITY"
	envAuthorityKey = "QORY_WALLTEST_AUTHORITY_KEY"
)

// Recorder is an origin the suite reads back: the helper started with [RecorderArgs]
// and [RecorderEnv] in a container of its own, which the proxy reaches over the
// network. It answers HTTPS on 8443, with a certificate of the suite's authority for
// its own addresses, and HTTP on 8080; on both ports it answers as the Messages API,
// with a fixed text. It records the method, the host, the path and the headers of each
// request in [RecorderFile], and prints [RecorderReady] once it listens on both ports.
type Recorder struct {
	// Host is the address the proxy reaches it on.
	Host string
	// Recorded returns the content of its [RecorderFile].
	Recorded func() ([]byte, error)
}

// recorded is one request a recorder received.
type recorded struct {
	TLS    bool        `json:"tls"`
	Method string      `json:"method"`
	Host   string      `json:"host"`
	Path   string      `json:"path"`
	Header http.Header `json:"header"`
}

// authority is the suite's own, made once for the process: the proxy of a run verifies
// a recorder's certificate against this machine's roots, which the suite points at it.
var authority = sync.OnceValues(func() (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "qory walltest recorders"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert, key
})

// RecorderEnv is the environment a recorder starts with: the suite's authority, with
// which it signs its own certificate.
func RecorderEnv() []string {
	cert, key := authority()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return []string{envAuthority + "=" + base64.StdEncoding.EncodeToString(cert.Raw), envAuthorityKey + "=" + base64.StdEncoding.EncodeToString(der)}
}

// RecorderReady is the line a recorder prints once it listens on both ports.
const RecorderReady = "walltest recorder: listening"

// AwaitRecorder waits up to 30 seconds for the recorder in the container name, which
// command started, to print [RecorderReady] to the container's log. It fails the test
// with the log at once when the container stops first, and when the 30 seconds run
// out. The container is started without --rm, so its log stays readable once it stops.
func AwaitRecorder(t *testing.T, command, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var log []byte
	for {
		state, err := exec.CommandContext(ctx, command, "inspect", "--format", "{{.State.Running}}", name).Output()
		running := err == nil && strings.TrimSpace(string(state)) == "true"
		if out, lerr := exec.CommandContext(ctx, command, "logs", name).CombinedOutput(); lerr == nil {
			log = out
		}
		switch {
		case running && bytes.Contains(log, []byte(RecorderReady)):
			return
		case ctx.Err() != nil:
			t.Fatalf("the recorder %s printed no %q within 30 seconds; its log:\n%s", name, RecorderReady, log)
		case err != nil:
			t.Fatalf("the recorder %s: %v; its log:\n%s", name, err, log)
		case !running:
			t.Fatalf("the recorder %s stopped before it printed %q; its log:\n%s", name, RecorderReady, log)
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// trustRecorders points this machine's roots, for the process and the programs it
// starts within Run, at the suite's authority alone, with SSL_CERT_FILE at a file that
// holds it and SSL_CERT_DIR at an empty directory, and returns the error of verifying a
// certificate of it. The process reads its roots once, at its first verification of a
// certificate, so that verification must come after this; from then on the process
// trusts only the suite's authority.
func trustRecorders(t *testing.T) error {
	t.Helper()
	cert, key := authority()
	file := filepath.Join(t.TempDir(), "recorders.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", file)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	ip := net.IPv4(192, 0, 2, 1)
	leaf, err := sign(cert, key, []net.IP{ip})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	_, err = parsed.Verify(x509.VerifyOptions{DNSName: ip.String()})
	return err
}

// sign makes a server certificate for the addresses, of the authority.
func sign(ca *x509.Certificate, caKey *ecdsa.PrivateKey, ips []net.IP) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "qory walltest recorder"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}, nil
}

// serveRecorder is a recorder: it signs a certificate for its own addresses with the
// authority of its environment and serves until it is stopped.
func serveRecorder() int {
	fail := func(err error) int {
		fmt.Fprintln(os.Stderr, "recorder:", err)
		return 1
	}
	certDER, err1 := base64.StdEncoding.DecodeString(os.Getenv(envAuthority))
	keyDER, err2 := base64.StdEncoding.DecodeString(os.Getenv(envAuthorityKey))
	if err := errors.Join(err1, err2); err != nil {
		return fail(err)
	}
	ca, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fail(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return fail(err)
	}
	caKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return fail(errors.New("the authority's key is not ECDSA"))
	}
	var ips []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return fail(err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			ips = append(ips, n.IP)
		}
	}
	leaf, err := sign(ca, caKey, ips)
	if err != nil {
		return fail(err)
	}
	f, err := os.OpenFile(RecorderFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fail(err)
	}
	var mu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		b, _ := json.Marshal(recorded{TLS: r.TLS != nil, Method: r.Method, Host: r.Host, Path: r.URL.Path, Header: r.Header})
		mu.Lock()
		f.Write(append(b, '\n'))
		mu.Unlock()
		answer(w, body)
	})
	plain, err := net.Listen("tcp", ":"+recorderPlain)
	if err != nil {
		return fail(err)
	}
	secure, err := tls.Listen("tcp", ":"+recorderTLS, &tls.Config{Certificates: []tls.Certificate{*leaf}})
	if err != nil {
		return fail(err)
	}
	fmt.Println(RecorderReady)
	errs := make(chan error, 2)
	go func() { errs <- http.Serve(plain, handler) }()
	go func() { errs <- http.Serve(secure, handler) }()
	return fail(<-errs)
}

// recorderAnswer is the text of every answer a recorder makes.
const recorderAnswer = "the recorder answered"

// answer answers a request as the Messages API does, streamed when the request's body
// sets stream, with [recorderAnswer] as the text and the request's model as the model.
func answer(w http.ResponseWriter, body []byte) {
	var req struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	json.Unmarshal(body, &req)
	if req.Model == "" {
		req.Model = "walltest"
	}
	usage := map[string]int{"input_tokens": 1, "output_tokens": 1}
	message := map[string]any{"id": "msg_walltest", "type": "message", "role": "assistant", "model": req.Model, "stop_reason": nil, "stop_sequence": nil, "usage": usage}
	if !req.Stream {
		message["content"] = []any{map[string]string{"type": "text", "text": recorderAnswer}}
		message["stop_reason"] = "end_turn"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(message)
		return
	}
	message["content"] = []any{}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	for _, e := range []map[string]any{
		{"type": "message_start", "message": message},
		{"type": "content_block_start", "index": 0, "content_block": map[string]string{"type": "text", "text": ""}},
		{"type": "content_block_delta", "index": 0, "delta": map[string]string{"type": "text_delta", "text": recorderAnswer}},
		{"type": "content_block_stop", "index": 0},
		{"type": "message_delta", "delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": map[string]int{"output_tokens": 1}},
		{"type": "message_stop"},
	} {
		b, _ := json.Marshal(e)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e["type"], b)
	}
}

// readRecorded parses what a recorder recorded.
func readRecorded(b []byte) ([]recorded, error) {
	var out []recorded
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(nil, 1<<20)
	for s.Scan() {
		var r recorded
		if err := json.Unmarshal(s.Bytes(), &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, s.Err()
}
