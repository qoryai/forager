package e2e

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
// with a fixed text, or with the answers of a [Script] that [ScriptEnv] passes it. It
// records the method, the host, the path and the headers of each request in
// [RecorderFile], and prints [RecorderReady] once it listens on both ports.
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
	var script Script
	if v := os.Getenv(envScript); v != "" {
		if err := json.Unmarshal([]byte(v), &script); err != nil {
			return fail(fmt.Errorf("%s: %w", envScript, err))
		}
	}
	var mu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		b, _ := json.Marshal(recorded{TLS: r.TLS != nil, Method: r.Method, Host: r.Host, Path: r.URL.Path, Header: r.Header})
		mu.Lock()
		f.Write(append(b, '\n'))
		mu.Unlock()
		answer(w, body, script)
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

// recorderAnswer is the text of every answer a recorder makes that no script sets.
const recorderAnswer = "the recorder answered"

// envScript is the variable that passes a recorder its [Script], as JSON.
const envScript = "QORY_WALLTEST_SCRIPT"

// Script is the answers a recorder replays, one list per conversation. A request
// belongs to the first conversation whose When is in the text of the request's first
// message, and gets the answer at the index of the number of assistant messages in
// the request: the first answer to the first request, the second to the request that
// follows the first answer, and so on. A request of no conversation, past the last
// answer, or offered no tool of the answer's tool call gets the fixed text.
type Script struct {
	Conversations []Conversation `json:"conversations"`
}

// Conversation is one conversation of a [Script]: the text its first message contains,
// and its answers in order.
type Conversation struct {
	When    string   `json:"when"`
	Answers []Answer `json:"answers"`
}

// Answer is one scripted answer, exactly one of its fields set: Text, a text block;
// Tool, a call of a tool; Agent, a call of Claude Code's Agent tool, which starts a
// subagent.
type Answer struct {
	Text  string     `json:"text,omitempty"`
	Tool  *ToolCall  `json:"tool,omitempty"`
	Agent *AgentCall `json:"agent,omitempty"`
}

// ToolCall is a call of the tool Name with Input.
type ToolCall struct {
	Name  string         `json:"name"`
	Input map[string]any `json:"input"`
}

// AgentCall is a call of the Agent tool: the subagent's type, a short description and
// the prompt that drives it.
type AgentCall struct {
	Type        string `json:"subagent_type"`
	Description string `json:"description"`
	Prompt      string `json:"prompt"`
}

// ScriptEnv is the NAME=value that passes s to a recorder, beside [RecorderEnv].
func ScriptEnv(s Script) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return envScript + "=" + string(b), nil
}

// request is what a recorder reads of a Messages API request.
type request struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
	Tools []struct {
		Name string `json:"name"`
	} `json:"tools"`
}

// firstText is the text of the request's first message: its content as a string, or
// the text of its text blocks.
func (r *request) firstText() string {
	if len(r.Messages) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(r.Messages[0].Content, &s) == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	json.Unmarshal(r.Messages[0].Content, &blocks)
	var b strings.Builder
	for _, bl := range blocks {
		if bl.Type == "text" {
			b.WriteString(bl.Text)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// offers reports whether the request offers the tool name.
func (r *request) offers(name string) bool {
	for _, t := range r.Tools {
		if t.Name == name {
			return true
		}
	}
	return false
}

// block is the content block a script answers the request with, and the stop reason:
// a tool_use block for a tool or Agent call, a text block otherwise.
func (s Script) block(r *request) (map[string]any, string) {
	text := map[string]any{"type": "text", "text": recorderAnswer}
	first := r.firstText()
	for c, conv := range s.Conversations {
		if conv.When == "" || !strings.Contains(first, conv.When) {
			continue
		}
		step := 0
		for _, m := range r.Messages {
			if m.Role == "assistant" {
				step++
			}
		}
		if step >= len(conv.Answers) {
			return text, "end_turn"
		}
		a := conv.Answers[step]
		call := a.Tool
		if a.Agent != nil {
			call = &ToolCall{Name: "Agent", Input: map[string]any{"subagent_type": a.Agent.Type, "description": a.Agent.Description, "prompt": a.Agent.Prompt}}
		}
		if call == nil {
			return map[string]any{"type": "text", "text": a.Text}, "end_turn"
		}
		if !r.offers(call.Name) {
			return text, "end_turn"
		}
		input := call.Input
		if input == nil {
			input = map[string]any{}
		}
		return map[string]any{"type": "tool_use", "id": fmt.Sprintf("toolu_walltest_%d_%d", c, step), "name": call.Name, "input": input}, "tool_use"
	}
	return text, "end_turn"
}

// answer answers a request as the Messages API does, streamed when the request's body
// sets stream, with the script's block for it and the request's model as the model.
func answer(w http.ResponseWriter, body []byte, script Script) {
	var req request
	json.Unmarshal(body, &req)
	if req.Model == "" {
		req.Model = "walltest"
	}
	block, stop := script.block(&req)
	usage := map[string]int{"input_tokens": 1, "output_tokens": 1}
	message := map[string]any{"id": "msg_walltest", "type": "message", "role": "assistant", "model": req.Model, "stop_reason": nil, "stop_sequence": nil, "usage": usage}
	if !req.Stream {
		message["content"] = []any{block}
		message["stop_reason"] = stop
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(message)
		return
	}
	message["content"] = []any{}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	start, delta := map[string]any{"type": "text", "text": ""}, map[string]any{"type": "text_delta", "text": block["text"]}
	if block["type"] == "tool_use" {
		input, _ := json.Marshal(block["input"])
		start = map[string]any{"type": "tool_use", "id": block["id"], "name": block["name"], "input": map[string]any{}}
		delta = map[string]any{"type": "input_json_delta", "partial_json": string(input)}
	}
	for _, e := range []map[string]any{
		{"type": "message_start", "message": message},
		{"type": "content_block_start", "index": 0, "content_block": start},
		{"type": "content_block_delta", "index": 0, "delta": delta},
		{"type": "content_block_stop", "index": 0},
		{"type": "message_delta", "delta": map[string]any{"stop_reason": stop, "stop_sequence": nil}, "usage": map[string]int{"output_tokens": 1}},
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
