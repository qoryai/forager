package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/catalog"
	"github.com/qoryai/forager/session/runtimes/claude"
	"github.com/qoryai/forager/session/runtimes/codex"
	"github.com/qoryai/forager/wall"
)

// The tests of several model keys per run run Claude Code 2.1.316 itself against a stub
// of the Messages API: a key group of fake subscription keys from a fake control plane,
// set by the gateway's proxy. The stub matches each key by the marks -AAAA-, -BBBB-
// and -CCCC- in their values, and serves each request by its scenario: a subscription's
// cap (a 429 with the anthropic-ratelimit-unified-* headers and a five_hour claim), a
// stream that ends in a rate_limit_error event, a tool call or a text. Each answer has a
// message id that no other answer has, since Claude Code merges assistant messages that share one.

// The stub's mode, the variable of its scenario, the file it logs each request to inside
// its container, and its scenarios.
const (
	modeKeysStub    = "keys-stub"
	envKeysScenario = "E2E_KEYS_SCENARIO"
	keysStubLog     = "/tmp/e2e-keys-stub.jsonl"

	// keysHooks serves the first request with a Bash call, and the next with a text.
	keysHooks = "hooks"
	// keysSwitch caps key A and serves every other key.
	keysSwitch = "switch"
	// keysStream ends key A's streams with a rate_limit_error event, and serves every
	// other request.
	keysStream = "stream"
	// keysCooling caps every key.
	keysCooling = "cooling"
	// keysReport caps key A, serves key B's first request after 3 seconds with a Bash
	// call, and serves the rest with a Bash call first and a text after it.
	keysReport = "report"
	// keysResume returns Bash calls that print turn-0 and turn-1, then a text.
	keysResume = "resume"
	// keysShare serves every request with a Bash call and a five_hour window at 90
	// percent, which resets in an hour.
	keysShare = "share"
)

// keysBusybox is the image the stub runs in: the test binary needs no more than a
// kernel.
const keysBusybox = "ghcr.io/qoryai/ci-images:busybox-stable@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"

// The fake key values: a subscription token's prefix, the key's mark and the test
// process's id. The stub reads the mark, and no file of a run may contain one.
var (
	keyA = "sk-ant-oat01-e2e-keys-AAAA-" + strconv.Itoa(os.Getpid())
	keyB = "sk-ant-oat01-e2e-keys-BBBB-" + strconv.Itoa(os.Getpid())
	keyC = "sk-ant-oat01-e2e-keys-CCCC-" + strconv.Itoa(os.Getpid())
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == modeKeysStub {
		os.Exit(serveKeysStub())
	}
}

// keysEntry is one request the stub logs: its number among the POSTs to /v1/messages,
// the key's mark, A, B or C, "other" for any other credential and "" for none, whether
// it streams, the status of the answer, the SHA-256 of the body and of its messages
// member, the number of messages and tool results, and the turn-N marks the body
// contains.
type keysEntry struct {
	N        int      `json:"n"`
	Path     string   `json:"path"`
	Key      string   `json:"key"`
	Stream   bool     `json:"stream"`
	Status   int      `json:"status"`
	Body     string   `json:"body"`
	Sent     string   `json:"messages_sum"`
	Messages int      `json:"messages"`
	Results  int      `json:"tool_results"`
	Turns    []string `json:"turns,omitempty"`
}

// keysTurn finds the marks the Bash calls of keysResume print.
var keysTurn = regexp.MustCompile(`turn-[0-9]+`)

// keysStub is the stub's handler: scenario, a tag that is in every id it writes, and the
// file it logs each request to.
type keysStub struct {
	scenario, tag, log string
	mu                 sync.Mutex
	n                  int
}

// newKeysStub makes the stub of scenario, logging to log.
func newKeysStub(scenario, log string) *keysStub {
	return &keysStub{scenario: scenario, tag: fmt.Sprintf("%s_%d", scenario, time.Now().UnixNano()), log: log}
}

// stubKey is the mark of the key in a request's credential headers.
func stubKey(h http.Header) string {
	v := h.Get("Authorization") + h.Get("X-Api-Key")
	switch {
	case strings.Contains(v, "-AAAA-"):
		return "A"
	case strings.Contains(v, "-BBBB-"):
		return "B"
	case strings.Contains(v, "-CCCC-"):
		return "C"
	case v != "":
		return "other"
	}
	return ""
}

// shortSum is the first 12 hex digits of b's SHA-256.
func shortSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:6])
}

func (s *keysStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	e := keysEntry{Path: r.URL.Path, Key: stubKey(r.Header), Body: shortSum(body)}
	if r.Method != http.MethodPost || r.URL.Path != modelPath {
		e.Status = http.StatusNotFound
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(e.Status)
		io.WriteString(w, `{"type":"error","error":{"type":"not_found_error","message":"stub: not found"}}`)
		s.write(e)
		return
	}
	var req request
	json.Unmarshal(body, &req)
	var members map[string]json.RawMessage
	if json.Unmarshal(body, &members) == nil {
		e.Sent = shortSum(members["messages"])
	}
	e.Stream, e.Messages = req.Stream, len(req.Messages)
	e.Results = strings.Count(string(body), `"type":"tool_result"`)
	seen := map[string]bool{}
	for _, m := range keysTurn.FindAllString(string(body), -1) {
		if !seen[m] {
			seen[m] = true
			e.Turns = append(e.Turns, m)
		}
	}
	s.mu.Lock()
	s.n++
	e.N = s.n
	s.mu.Unlock()
	e.Status = s.respond(w, &req, e.Key, e.N, e.Results)
	s.write(e)
}

// write appends e to the log.
func (s *keysStub) write(e keysEntry) {
	b, _ := json.Marshal(e)
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stub:", err)
		return
	}
	f.Write(append(b, '\n'))
	f.Close()
}

// respond serves the n-th request, with key's mark and results tool results, by the
// scenario, and returns the status.
func (s *keysStub) respond(w http.ResponseWriter, req *request, key string, n, results int) int {
	tool := func(command string) map[string]any {
		return map[string]any{"type": "tool_use", "id": fmt.Sprintf("toolu_%s_%d", s.tag, n), "name": "Bash",
			"input": map[string]any{"command": command, "description": "Print a mark"}}
	}
	text := map[string]any{"type": "text", "text": "Hi"}
	switch s.scenario {
	case keysHooks:
		if results == 0 && req.offers("Bash") {
			s.answer(w, req, tool("echo hook-check"), "tool_use", n)
			return http.StatusOK
		}
	case keysSwitch:
		if key == "A" {
			return keysCap(w)
		}
	case keysStream:
		if key == "A" && req.Stream {
			s.streamError(w, req, n)
			return http.StatusOK
		}
	case keysCooling:
		return keysCap(w)
	case keysReport:
		if key == "A" {
			return keysCap(w)
		}
		if results == 0 && req.offers("Bash") {
			if key == "B" {
				// The gateway's report of A's refusal, and the control plane's answer,
				// come before Claude Code gets the call and sends its next request.
				time.Sleep(3 * time.Second)
			}
			s.answer(w, req, tool("echo report-check"), "tool_use", n)
			return http.StatusOK
		}
	case keysPause:
		if r := pauseRespond(s, w, req, key, n, results, tool); r != 0 {
			return r
		}
		text["text"] = fmt.Sprintf("done after %d tool results", results)
	case keysShare:
		keysAtShare(w)
		if req.offers("Bash") {
			s.answer(w, req, tool(fmt.Sprintf("echo share-%d", results)), "tool_use", n)
			return http.StatusOK
		}
	case keysResume:
		if results < 2 && req.offers("Bash") {
			s.answer(w, req, tool(fmt.Sprintf("echo turn-%d", results)), "tool_use", n)
			return http.StatusOK
		}
		text["text"] = fmt.Sprintf("done after %d tool results", results)
	}
	s.answer(w, req, text, "end_turn", n)
	return http.StatusOK
}

// keysCap returns a subscription's cap: a 429 whose anthropic-ratelimit-unified-*
// headers reject the five-hour window, which resets in an hour, and claim it. Claude
// Code 2.1.316 sends no second request after this answer.
func keysCap(w http.ResponseWriter) int {
	hd := w.Header()
	hour := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	week := strconv.FormatInt(time.Now().Add(72*time.Hour).Unix(), 10)
	hd.Set("anthropic-ratelimit-unified-status", "rejected")
	hd.Set("anthropic-ratelimit-unified-representative-claim", "five_hour")
	hd.Set("anthropic-ratelimit-unified-reset", hour)
	hd.Set("anthropic-ratelimit-unified-5h-status", "rejected")
	hd.Set("anthropic-ratelimit-unified-5h-utilization", "1.0")
	hd.Set("anthropic-ratelimit-unified-5h-reset", hour)
	hd.Set("anthropic-ratelimit-unified-7d-status", "allowed")
	hd.Set("anthropic-ratelimit-unified-7d-utilization", "0.4")
	hd.Set("anthropic-ratelimit-unified-7d-reset", week)
	hd.Set("retry-after", "3600")
	hd.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	io.WriteString(w, `{"type":"error","error":{"type":"rate_limit_error","message":"This request would exceed your account's rate limit. Please try again later."}}`)
	return http.StatusTooManyRequests
}

// keysAtShare sets a subscription's headers of a served request: the five-hour window
// at 90 percent, allowed with a warning, which resets in an hour, and the seven-day
// window at 40 percent.
func keysAtShare(w http.ResponseWriter) {
	hd := w.Header()
	hour := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	week := strconv.FormatInt(time.Now().Add(72*time.Hour).Unix(), 10)
	hd.Set("anthropic-ratelimit-unified-status", "allowed_warning")
	hd.Set("anthropic-ratelimit-unified-representative-claim", "five_hour")
	hd.Set("anthropic-ratelimit-unified-reset", hour)
	hd.Set("anthropic-ratelimit-unified-5h-status", "allowed_warning")
	hd.Set("anthropic-ratelimit-unified-5h-utilization", "0.9")
	hd.Set("anthropic-ratelimit-unified-5h-reset", hour)
	hd.Set("anthropic-ratelimit-unified-7d-status", "allowed")
	hd.Set("anthropic-ratelimit-unified-7d-utilization", "0.4")
	hd.Set("anthropic-ratelimit-unified-7d-reset", week)
}

// answer writes a Messages API answer with one block, streamed when the request sets
// stream; the shape follows answer in recorder.go.
func (s *keysStub) answer(w http.ResponseWriter, req *request, block map[string]any, stop string, n int) {
	model := req.Model
	if model == "" {
		model = "stub"
	}
	message := map[string]any{"id": fmt.Sprintf("msg_%s_%d", s.tag, n), "type": "message", "role": "assistant", "model": model,
		"stop_reason": nil, "stop_sequence": nil, "usage": map[string]int{"input_tokens": 1, "output_tokens": 1}}
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

// streamError serves a streaming request with 200, message_start, a text block's start
// and one delta, then an error event of the type rate_limit_error, and closes the
// connection.
func (s *keysStub) streamError(w http.ResponseWriter, req *request, n int) {
	model := req.Model
	if model == "" {
		model = "stub"
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusOK)
	message := map[string]any{"id": fmt.Sprintf("msg_%s_%d", s.tag, n), "type": "message", "role": "assistant", "model": model,
		"content": []any{}, "stop_reason": nil, "stop_sequence": nil, "usage": map[string]int{"input_tokens": 1, "output_tokens": 1}}
	for _, e := range []map[string]any{
		{"type": "message_start", "message": message},
		{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}},
		{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": "Hel"}},
		{"type": "error", "error": map[string]any{"type": "rate_limit_error", "message": "This request would exceed your account's rate limit. Please try again later."}},
	} {
		b, _ := json.Marshal(e)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e["type"], b)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

// serveKeysStub is the stub in a container: it serves HTTPS on 8443 with a certificate
// of the suite's authority for the container's addresses, by the scenario in its
// environment, logs every request to keysStubLog, and prints RecorderReady once it
// listens.
func serveKeysStub() int {
	fail := func(err error) int {
		fmt.Fprintln(os.Stderr, "stub:", err)
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
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			ips = append(ips, n.IP)
		}
	}
	leaf, err := sign(ca, caKey, ips)
	if err != nil {
		return fail(err)
	}
	ln, err := tls.Listen("tcp", ":"+recorderTLS, &tls.Config{Certificates: []tls.Certificate{*leaf}})
	if err != nil {
		return fail(err)
	}
	fmt.Println(RecorderReady)
	return fail(http.Serve(ln, newKeysStub(os.Getenv(envKeysScenario), keysStubLog)))
}

// readKeysLog reads a stub's log, by the requests' numbers; requests to other paths
// come last.
func readKeysLog(t *testing.T, b []byte) []keysEntry {
	t.Helper()
	var out []keysEntry
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(nil, 1<<20)
	for s.Scan() {
		var e keysEntry
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			t.Fatalf("the stub's log: %v: %s", err, s.Bytes())
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].N == 0) != (out[j].N == 0) {
			return out[j].N == 0
		}
		return out[i].N < out[j].N
	})
	return out
}

// keysWall is what the walled tests of several model keys share: the docker command,
// the helper and the image with Claude Code.
type keysWall struct {
	command, helper, image string
}

// newKeysWall skips the test without an engine, without a Linux build of the test binary
// off Linux, and without an image with Claude Code in QORY_WALL_CLAUDE_IMAGE; each skip
// fails under QORY_WALL_REQUIRE. It points this machine's roots at the suite's
// authority.
func newKeysWall(t *testing.T) keysWall {
	t.Helper()
	command := os.Getenv("QORY_WALL_COMMAND")
	if command == "" {
		command = "docker"
	}
	if out, err := exec.Command(command, "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		Skip(t, command+" reaches no engine: "+strings.TrimSpace(string(out)))
	}
	helper := Helper(t)
	image := os.Getenv("QORY_WALL_CLAUDE_IMAGE")
	if image == "" {
		Skip(t, "QORY_WALL_CLAUDE_IMAGE is empty: it selects an image with Claude Code 2.1.316")
	}
	if err := trustRecorders(t); err != nil {
		t.Fatalf("this machine's roots are not the suite's authority: %v", err)
	}
	return keysWall{command: command, helper: helper, image: image}
}

// stub starts the stub of scenario in a container, removed at the test's end, and
// returns the container's name and the address the proxy reaches it on.
func (k keysWall) stub(t *testing.T, scenario string) (string, string) {
	t.Helper()
	name := fmt.Sprintf("qory-walltest-keys-%s-%d", scenario, os.Getpid())
	args := []string{"run", "--detach", "--name", name,
		"--mount", "type=bind,src=" + k.helper + ",dst=/walltest,readonly",
		"--env", envKeysScenario + "=" + scenario}
	for _, kv := range RecorderEnv() {
		args = append(args, "--env", kv)
	}
	args = append(args, "--entrypoint", "/walltest", keysBusybox, modeKeysStub)
	if out, err := exec.Command(k.command, args...).CombinedOutput(); err != nil {
		t.Fatalf("the stub: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command(k.command, "rm", "--force", name).Run() })
	AwaitRecorder(t, k.command, name)
	ip, err := exec.Command(k.command, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).Output()
	if err != nil {
		t.Fatal(err)
	}
	return name, strings.TrimSpace(string(ip))
}

// stubLog is the log of the stub in the container name.
func (k keysWall) stubLog(t *testing.T, name string) []keysEntry {
	t.Helper()
	b, err := exec.Command(k.command, "exec", name, "cat", keysStubLog).Output()
	if err != nil {
		t.Fatalf("the stub's log: %v", err)
	}
	return readKeysLog(t, b)
}

// keysOutcome is one run of Claude Code: the session's result and the join's error,
// the close's error, the run's record, its output, and the gateway's and the session's
// reports.
type keysOutcome struct {
	res              *session.Result
	joined, closed   error
	events           []map[string]any
	out, errs, lines string
}

// keysSession is one run of Claude Code: the run's id, the gateway's server, nil for
// none, the machine's credentials, the policy's allow list, the arguments after the
// prompt, the prompt, the environment, nil for the one run uses behind a wall, the
// working directory, empty for a new one, the wall, nil for none, and the time limit.
type keysSession struct {
	runID   string
	server  *gateway.Server
	creds   []gateway.Credential
	allow   []string
	args    []string
	prompt  string
	env     []string
	dir     string
	walled  *keysWall
	timeout time.Duration
	// qory, when set, is a folder that [qoryFolder] makes: the launch starts Claude Code
	// through qory run agent-env with CLAUDE_CONFIG_DIR at qory's agent home, as a
	// dispatched walled run of qory does. link are the verb's words between the kept
	// file and --.
	qory string
	link []string
	// joinFails, when set, expects the join to return an error: run returns it in
	// keysOutcome.joined in place of failing the test.
	joinFails bool
	// codex, when set, is a folder that [codexFolder] makes: the launch starts Codex
	// 0.167.2 through its codex-run script, as codex exec --json with the prompt last,
	// in place of Claude Code, with CODEX_HOME at [codexHome] as a fixed value of the
	// launch, as qory sets it.
	codex string
	// codexArgs, when set, replaces [codexArgs] for Codex.
	codexArgs []string
}

// run opens the run, joins one session of Claude Code, or of Codex, and closes the run
// as qory does: paused with model_key_limit or model_key_switch, or failed with
// model_key_unauthorized, and the session's exit code after a session the session
// stopped for that reason, else with the session's state and exit code.
func (s keysSession) run(t *testing.T) keysOutcome {
	t.Helper()
	newRuntime := claude.New
	if s.codex != "" {
		// Codex comes by its name, as qory resolves a run's runtime.
		newRuntime = func() (runtimes.Runtime, error) { return catalog.Lookup(codex.Name, "") }
	}
	rt, err := newRuntime()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	runs := filepath.Join(t.TempDir(), "runs")
	var lines syncBuffer
	report := func(l string) {
		t.Log("report:", l)
		lines.Write([]byte(l + "\n"))
	}
	pol := &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: s.allow}}
	for _, c := range s.creds {
		pol.Credentials = append(pol.Credentials, gateway.PolicyCredential{Name: c.Name})
	}
	g, closeGateway := startGateway(t, gateway.Config{Server: s.server, Policy: pol, Credentials: s.creds, Version: "walltest", Report: report}, runs)
	defer closeGateway()
	dir := s.dir
	if dir == "" {
		dir = t.TempDir()
	}
	open := session.OpenSpec{RunsDir: runs, Gateway: g, RunID: s.runID, ForagerVersion: "walltest", Report: report}
	join := session.SessionSpec{
		Runtime: rt,
		Command: "claude",
		Args:    append([]string{"-p", s.prompt, "--output-format", "stream-json", "--verbose"}, s.args...),
		Env:     s.env,
		Dir:     dir,
		Stdin:   strings.NewReader(""),
	}
	if s.codex != "" {
		join.Command = filepath.Join(s.codex, codexRun)
		launch := codexArgs
		if s.codexArgs != nil {
			launch = s.codexArgs
		}
		join.Args = slices.Concat(launch, s.args, []string{s.prompt})
		join.Mounts = append(join.Mounts, wall.Mount{Path: s.codex, ReadOnly: true})
		join.LaunchFixed = []string{"CODEX_HOME=" + codexHome}
	}
	if s.qory != "" {
		join.Args = append(append(append([]string{"run", "agent-env", filepath.Join(s.qory, "kept")}, s.link...), "--", join.Command), join.Args...)
		join.Command = filepath.Join(s.qory, "qory")
		join.Mounts = append(join.Mounts, wall.Mount{Path: s.qory, ReadOnly: true})
		join.LaunchFixed = slices.Clone(qoryLaunchFixed)
	}
	if s.walled != nil {
		open.Wall = &wall.Docker{Command: s.walled.command, Helper: s.walled.helper, RelayArgs: RelayArgs, NestArgs: NestArgs}
		open.Image = s.walled.image
		join.Forwarder = []string{wall.HelperPath, "forward"}
		join.Exec = append([]string{wall.HelperPath}, ExecArgs...)
	} else {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		join.Forwarder = []string{exe, modeForward}
	}
	if join.Env == nil && s.codex != "" {
		join.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	}
	if join.Env == nil {
		join.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "DISABLE_AUTOUPDATER=1",
			"ANTHROPIC_AUTH_TOKEN=", apiKeyStandIn + "="}
	}
	var out, errs syncBuffer
	join.Stdout, join.Stderr = &out, &errs
	var o keysOutcome
	r, err := session.Open(ctx, open)
	if err != nil {
		t.Fatalf("the run did not open: %v", err)
	}
	o.res, o.joined = r.Join(ctx, join)
	outcome := session.Outcome{State: event.StateFailed, ExitCode: -1}
	switch {
	case o.joined != nil || o.res.RunClosed:
	case o.res.Reason == event.ReasonModelKeyLimit || o.res.Reason == event.ReasonModelKeySwitch:
		outcome = session.Outcome{State: event.StatePaused, Reason: o.res.Reason, ExitCode: o.res.ExitCode}
	case o.res.Reason == event.ReasonModelKeyUnauthorized:
		outcome = session.Outcome{State: event.StateFailed, Reason: o.res.Reason, ExitCode: o.res.ExitCode}
	default:
		outcome = session.Outcome{State: o.res.State, ExitCode: o.res.ExitCode}
	}
	_, o.closed = r.Close(ctx, outcome)
	closeGateway()
	o.out, o.errs, o.lines = out.String(), errs.String(), lines.String()
	if o.joined != nil && s.joinFails {
		return o
	}
	if o.joined != nil || s.joinFails {
		t.Fatalf("the join: %v, want an error %v\nstdout:\n%s\nstderr:\n%s", o.joined, s.joinFails, o.out, o.errs)
	}
	f, err := os.Open(filepath.Join(o.res.Dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<22)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		o.events = append(o.events, m)
	}
	return o
}

// of are the data of the events of type typ.
func (o keysOutcome) of(typ string) []map[string]any {
	var out []map[string]any
	for _, e := range o.events {
		if e["type"] == typ {
			d, _ := e["data"].(map[string]any)
			out = append(out, d)
		}
	}
	return out
}

// exited is the session's dev.qory.session.exited, nil for none.
func (o keysOutcome) exited() map[string]any {
	if es := o.of(event.SessionExited); len(es) > 0 {
		return es[len(es)-1]
	}
	return nil
}

// egress are the requests through the proxy to host, each "<credential> <status>".
func (o keysOutcome) egress(host string) []string {
	var out []string
	for _, d := range o.of(event.RunEgress) {
		if d["host"] == host {
			out = append(out, fmt.Sprint(d["credential"], " ", d["status"]))
		}
	}
	return out
}

// refusedLines are the lines of Claude Code's stream-json output that show a refused
// request or a retry: a system api_retry, or a result with api_error_status.
func refusedLines(stdout string) []string {
	var out []string
	for _, l := range strings.Split(stdout, "\n") {
		var m struct {
			Type      string `json:"type"`
			Subtype   string `json:"subtype"`
			APIStatus any    `json:"api_error_status"`
		}
		if json.Unmarshal([]byte(l), &m) != nil {
			continue
		}
		if m.Subtype == "api_retry" || (m.Type == "result" && m.APIStatus != nil) {
			out = append(out, l)
		}
	}
	return out
}

// keysControl is a fake control plane in front of the reference receiver: it registers
// runs, stores their events, serves each run's run configuration and seals its
// credentials' values, takes the model keys reports, each checked against
// model-keys-report.schema.json, returns the answer to each, and serves the transcript of a paused
// run at <run.url>/<run_id>/resume/transcript.
type keysControl struct {
	srv    *httptest.Server
	stored string
	server *gateway.Server

	mu sync.Mutex
	// docs are the run configurations by run id; values the credentials' values by name.
	docs   map[string][]byte
	values map[string]string
	// answer is the keys of the answer to every report; reports the bodies received,
	// and invalid the schema's refusal of each that failed it.
	answer  []server.ModelKeyState
	reports [][]byte
	invalid []string
	// transcripts are the transcripts by the id of the run that reads them; asked the
	// runs that asked for one.
	transcripts map[string][]byte
	asked       []string
}

// The access key of the fake control plane's node.
const keysNodeKey = "ak_f1xt0re00000000k"

// startKeysControl starts the fake control plane, closed at the test's end.
func startKeysControl(t *testing.T) *keysControl {
	t.Helper()
	key, signer := mustGenerate(t), mustGenerate(t)
	c := &keysControl{stored: filepath.Join(t.TempDir(), "received.jsonl"), docs: map[string][]byte{}, values: map[string]string{},
		transcripts: map[string][]byte{}}
	store, err := receiver.OpenFile(c.stored)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	schema, err := contracts.Compile("model-keys-report.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	pinned := accesskey.Pin{{Alg: "ed25519", PublicKey: signer.PublicKey().String()}}
	pin, _ := json.Marshal(pinned)
	h := &receiver.Handler{
		Keys: func(id string) (receiver.AccessKey, bool) {
			return receiver.AccessKey{PublicKey: key.PublicKey(), StoredSecrets: true}, id == keysNodeKey
		},
		Signer: signer,
		Store:  store,
		Configuration: func() ([]byte, string) {
			doc := []byte(`{"version":1,"node_id":"nd_f1xt0re00000000k","workspaces":["ws_f1xt0re00000000k"],"apiary_public_key":` + string(pin) +
				`,"events":{"url":"` + c.srv.URL + receiver.DefaultEventsPath + `","types":["*"]},"run":{"url":"` + c.srv.URL + receiver.DefaultRunPath +
				`"},"secrets":{"url":"` + c.srv.URL + receiver.DefaultSecretsPath + `"}}`)
			s := sha256.Sum256(doc)
			return doc, "sha256=" + hex.EncodeToString(s[:])
		},
		RunConfiguration: func(run receiver.Run) ([]byte, string, *receiver.Refusal) {
			c.mu.Lock()
			defer c.mu.Unlock()
			if doc, ok := c.docs[run.ID]; ok {
				return doc, "", nil
			}
			return receiver.NoPolicy, "", nil
		},
		Secrets: func(_ receiver.Run, names []string) ([]receiver.Value, *receiver.Refusal) {
			c.mu.Lock()
			defer c.mu.Unlock()
			var values []receiver.Value
			for _, n := range names {
				values = append(values, receiver.NewValue([]byte(c.values[n])))
			}
			return values, nil
		},
		Log: func(l string) { t.Log("control plane:", l) },
	}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, _ := strings.CutPrefix(r.URL.Path, receiver.DefaultRunPath+"/")
		runID, path, _ := strings.Cut(rest, "/")
		sig := r.Header.Get(server.HeaderSignature)
		switch {
		case r.Method == http.MethodPost && path == "model-keys":
			body, _ := io.ReadAll(r.Body)
			doc, err := contracts.Decode("report.json", body)
			if err == nil {
				err = schema.Validate(doc)
			}
			c.mu.Lock()
			c.reports = append(c.reports, body)
			if err != nil {
				c.invalid = append(c.invalid, err.Error())
			}
			keys := c.answer
			c.mu.Unlock()
			if keys == nil {
				keys = []server.ModelKeyState{}
			}
			answer, _ := json.Marshal(map[string]any{"version": 1, "keys": keys})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: sig, Body: answer}))
			w.Write(answer)
		case r.Method == http.MethodGet && path == "resume/transcript":
			c.mu.Lock()
			c.asked = append(c.asked, runID)
			b, ok := c.transcripts[runID]
			c.mu.Unlock()
			if !ok {
				body := []byte(`{"error":"not_found","message":"no transcript"}`)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: http.StatusNotFound, RequestSignature: sig, Body: body}))
				w.WriteHeader(http.StatusNotFound)
				w.Write(body)
				return
			}
			s := sha256.Sum256(b)
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: sig, Digest: hex.EncodeToString(s[:])}))
			w.Write(b)
		default:
			h.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(c.srv.Close)
	c.server = &gateway.Server{Version: 1, URL: c.srv.URL, AccessKeyID: keysNodeKey, ApiaryPublicKey: pinned, AccessKey: key, InstanceID: "i_walltest_keys"}
	return c
}

// keysCredential is one key of a group as a run configuration lists it: a subscription
// token as a bearer, on the endpoint, with a cooldown of an hour after a refusal with no
// reset.
func keysCredential(name, endpoint string) map[string]any {
	return map[string]any{"name": name, "format": "anthropic-messages", "endpoint": endpoint,
		"auth": map[string]any{"scheme": "bearer", "oauth": true}, "pause_for_s": 3600}
}

// configure sets the run configuration of the run runID: egress to host alone, the
// credentials, each with its value, model_credential the first one's name, and resume
// when it is not nil.
func (c *keysControl) configure(t *testing.T, runID, host string, creds []map[string]any, values []string, resume map[string]any) {
	t.Helper()
	doc := map[string]any{"version": 1,
		"security_policy":  map[string]any{"version": 1, "egress": map[string]any{"mode": "enforce", "allow": []string{host}}},
		"model_credential": creds[0]["name"], "credentials": creds}
	if resume != nil {
		doc["resume"] = resume
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.docs[runID] = b
	for i, cr := range creds {
		c.values[cr["name"].(string)] = values[i]
	}
}

// received are the reports the control plane received, and the schema's refusals.
func (c *keysControl) received() ([][]byte, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.reports), slices.Clone(c.invalid)
}

// groupRun returns a walled run of Claude Code and its fake control plane. The run's key
// group is the first keys of model, model-b and model-c, with the values of A, B and C,
// on the stub at host; args come after the prompt.
func (k keysWall) groupRun(t *testing.T, host string, keys int, args ...string) (keysSession, *keysControl) {
	t.Helper()
	ctl := startKeysControl(t)
	endpoint := "https://" + host + ":" + recorderTLS
	names, values := []string{"model", "model-b", "model-c"}, []string{keyA, keyB, keyC}
	var creds []map[string]any
	for _, n := range names[:keys] {
		creds = append(creds, keysCredential(n, endpoint))
	}
	runID := event.NewRunID()
	ctl.configure(t, runID, host, creds, values[:keys], nil)
	return keysSession{runID: runID, server: ctl.server, allow: []string{host}, args: args, prompt: "Say hi in one word.",
		dir: t.TempDir(), walled: &k, timeout: 4 * time.Minute}, ctl
}

// noKeyValue fails the test when a file under one of roots, or the output, contains a
// key's value.
func noKeyValue(t *testing.T, o keysOutcome, roots ...string) {
	t.Helper()
	values := []string{keyA, keyB, keyC}
	var where []string
	for _, root := range append(roots, filepath.Dir(o.res.Dir)) {
		filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
			if err == nil && e.Type().IsRegular() {
				if b, err := os.ReadFile(p); err == nil && slices.ContainsFunc(values, func(v string) bool { return bytes.Contains(b, []byte(v)) }) {
					where = append(where, p)
				}
			}
			return nil
		})
	}
	if slices.ContainsFunc(values, func(v string) bool { return strings.Contains(o.out+o.errs+o.lines, v) }) {
		where = append(where, "the output or a report")
	}
	if len(where) > 0 {
		t.Errorf("a key's value is in %v", where)
	}
}

// keysEntries is the log as lines "<n> <key> <status> stream=<bool>", for messages.
func keysEntries(log []keysEntry) string {
	var b strings.Builder
	for _, e := range log {
		fmt.Fprintf(&b, "\n  %d %s %s %d stream=%v body=%s messages=%d (%s) results=%d", e.N, e.Path, e.Key, e.Status, e.Stream, e.Body, e.Messages, e.Sent, e.Results)
	}
	return b.String()
}

// TestDockerClaudeCodeHooksReachTheSessionBehindTheWall is the hook check behind the
// wall: Claude Code 2.1.316 runs behind the Docker adapter, the stub serves its first
// request with a Bash call and its second with a text, and the run's events contain
// the runtime events the session maps from Claude Code's hooks:
// dev.qory.runtime.started from SessionStart and dev.qory.runtime.tool_started of the
// Bash call from PreToolUse. Every hook reaches the session through the socket the wall
// binds into the agent's container. On an engine in a virtual machine, such as Docker
// Desktop on macOS, the forwarder fails with "dial unix /qory/hooks/sock: connect:
// connection refused" and this test fails; it is the check that a Linux machine passes
// the hook socket into the container.
func TestDockerClaudeCodeHooksReachTheSessionBehindTheWall(t *testing.T) {
	k := newKeysWall(t)
	name, host := k.stub(t, keysHooks)
	t.Setenv(apiKeyVar, keyA)
	o := keysSession{
		creds: []gateway.Credential{{Name: "model", Env: apiKeyVar, Format: "anthropic-messages", Endpoint: "https://" + host + ":" + recorderTLS,
			Scheme: "bearer", OAuth: true}},
		allow:  []string{host},
		args:   []string{"--allowedTools", "Bash"},
		prompt: "Run the command you are given.",
		walled: &k, timeout: 4 * time.Minute,
	}.run(t)
	log := k.stubLog(t, name)
	t.Logf("the stub got:%s", keysEntries(log))
	if o.res.State != event.StateSucceeded {
		t.Errorf("the session ended %s, exit %d; want succeeded\nstub:%s\nstdout:\n%s", o.res.State, o.res.ExitCode, keysEntries(log), tail(o.out, 4000))
	}
	var hookErrors []string
	for _, l := range strings.Split(o.out, "\n") {
		var m struct {
			Subtype string `json:"subtype"`
			Event   string `json:"hook_event"`
			Stderr  string `json:"stderr"`
		}
		if json.Unmarshal([]byte(l), &m) == nil && m.Subtype == "hook_response" && m.Stderr != "" {
			hookErrors = append(hookErrors, m.Event+": "+strings.TrimSpace(m.Stderr))
		}
	}
	started := o.of("dev.qory.runtime.started")
	var tools []string
	for _, d := range o.of("dev.qory.runtime.tool_started") {
		tools = append(tools, fmt.Sprint(d["tool"]))
	}
	if len(started) == 0 || !slices.Contains(tools, "Bash") {
		t.Errorf("the events have %d dev.qory.runtime.started and tool_started of %v; want one started and a tool_started of Bash, from the hooks; the hooks' errors: %q",
			len(started), tools, hookErrors)
	}
	if len(log) < 2 || log[0].Key != "A" || log[1].Results != 1 {
		t.Errorf("the stub got %d requests; want the call with key A, then its tool result:%s", len(log), keysEntries(log))
	}
}

// TestDockerModelKeySwitchesOnACapAndSendsTheRequestAgain runs Claude Code behind the
// wall with a key group of two subscription keys from a fake control plane, model with
// key A and model-b with key B. The stub returns a subscription's cap for A and serves
// B. The proxy passes nothing of the refusal on: it puts model in cooldown and sends the
// same body again with B. The session ends succeeded; the stub got the request with A,
// then the same bytes with B; Claude Code printed no retry and no API error; the record
// lists one request to the stub, with model-b and 200; the gateway's log of limit responses
// has model's 429; and no file of the run and no output contains a key's value.
func TestDockerModelKeySwitchesOnACapAndSendsTheRequestAgain(t *testing.T) {
	k := newKeysWall(t)
	name, host := k.stub(t, keysSwitch)
	s, _ := k.groupRun(t, host, 2)
	o := s.run(t)
	log := k.stubLog(t, name)
	t.Logf("the stub got:%s", keysEntries(log))
	if o.res.State != event.StateSucceeded || o.res.ExitCode != 0 {
		t.Errorf("the session ended %s, exit %d; want succeeded, 0\nstub:%s\nstdout:\n%s", o.res.State, o.res.ExitCode, keysEntries(log), tail(o.out, 4000))
	}
	if len(log) != 2 || log[0].Key != "A" || log[0].Status != http.StatusTooManyRequests || log[1].Key != "B" || log[1].Status != http.StatusOK || log[0].Body != log[1].Body {
		t.Errorf("the stub got:%s\nwant a 429 with key A, then the same body with key B and 200", keysEntries(log))
	}
	if r := refusedLines(o.out); len(r) > 0 {
		t.Errorf("Claude Code saw a refusal: %q", r)
	}
	if got := o.egress(host); !slices.Equal(got, []string{"model-b 200"}) {
		t.Errorf("the record lists %q to the stub; want one request with model-b and 200", got)
	}
	if !strings.Contains(o.lines, `model key "model": limit response, status 429`) {
		t.Errorf("the gateway's log has no limit response of model:\n%s", o.lines)
	}
	noKeyValue(t, o, s.dir)
}

// TestDockerModelKeySwitchesWhenAStreamEndsInARateLimitError runs Claude Code behind the
// wall with the key group of model and model-b. The stub serves the streaming request
// with A with 200, message_start, a text block's start and one delta, then an error
// event of the type rate_limit_error. The proxy passes the stream on, puts model in
// cooldown and makes model-b active; Claude Code 2.1.316 sends the request again without
// streaming, with the same messages, which reaches the stub with B and gets 200. The session ends succeeded, and
// the record lists the stream with model and the second request with model-b.
func TestDockerModelKeySwitchesWhenAStreamEndsInARateLimitError(t *testing.T) {
	k := newKeysWall(t)
	name, host := k.stub(t, keysStream)
	s, _ := k.groupRun(t, host, 2)
	o := s.run(t)
	log := k.stubLog(t, name)
	t.Logf("the stub got:%s", keysEntries(log))
	if o.res.State != event.StateSucceeded || o.res.ExitCode != 0 {
		t.Errorf("the session ended %s, exit %d; want succeeded, 0\nstub:%s\nstdout:\n%s", o.res.State, o.res.ExitCode, keysEntries(log), tail(o.out, 4000))
	}
	i := slices.IndexFunc(log, func(e keysEntry) bool { return e.Key == "A" && e.Stream })
	if i < 0 || i+1 >= len(log) || log[i+1].Key != "B" || log[i+1].Stream || log[i+1].Status != http.StatusOK || log[i+1].Sent != log[i].Sent {
		t.Errorf("the stub got:%s\nwant a stream with key A, then the same messages without stream with key B and 200", keysEntries(log))
	}
	if got := o.egress(host); len(got) < 2 || got[0] != "model 200" || got[1] != "model-b 200" {
		t.Errorf("the record lists %q to the stub; want the stream with model, then a request with model-b", got)
	}
	noKeyValue(t, o, s.dir)
}

// TestDockerModelKeysAllCoolingStopTheSession runs Claude Code behind the wall with the
// key group of model and model-b, and the stub caps both. The proxy sends the request
// with A, then with B, and passes B's refusal on: no key is left out of cooldown.
// Claude Code ends; the gateway's answer to the session's batch has stop, and the
// session writes dev.qory.session.exited paused with model_key_limit and Claude
// Code's exit code. The run then closes, as qory closes it, paused with
// model_key_limit and that exit code, and the record ends with that
// dev.qory.run.exited.
func TestDockerModelKeysAllCoolingStopTheSession(t *testing.T) {
	k := newKeysWall(t)
	name, host := k.stub(t, keysCooling)
	s, _ := k.groupRun(t, host, 2)
	o := s.run(t)
	log := k.stubLog(t, name)
	t.Logf("the stub got:%s", keysEntries(log))
	if o.res.State != event.StatePaused || o.res.Reason != event.ReasonModelKeyLimit {
		t.Errorf("the session ended %s, %q, exit %d; want paused, model_key_limit\nstub:%s\nstdout:\n%s",
			o.res.State, o.res.Reason, o.res.ExitCode, keysEntries(log), tail(o.out, 4000))
	}
	if d := o.exited(); d == nil || d["state"] != event.StatePaused || d["reason"] != event.ReasonModelKeyLimit || d["exit_code"] != float64(o.res.ExitCode) {
		t.Errorf("dev.qory.session.exited is %v; want paused, model_key_limit, exit %d", d, o.res.ExitCode)
	}
	if o.closed != nil {
		t.Errorf("the close with model_key_limit: %v", o.closed)
	}
	if es := o.of(event.RunExited); len(es) != 1 || es[0]["state"] != event.StatePaused || es[0]["reason"] != event.ReasonModelKeyLimit {
		t.Errorf("dev.qory.run.exited is %v; want one, paused with model_key_limit", es)
	}
	if len(log) != 2 || log[0].Key != "A" || log[1].Key != "B" || log[0].Status != http.StatusTooManyRequests || log[1].Status != http.StatusTooManyRequests {
		t.Errorf("the stub got:%s\nwant a 429 with key A, then one with key B, and nothing more", keysEntries(log))
	}
	noKeyValue(t, o, s.dir)
}

// TestDockerModelKeysAtTheirUseUpToPercentPauseTheRun runs Claude Code behind the wall
// with the key group of model and model-b, each with use_up_to_percent 90 of five_hour
// and seven_day. The stub serves every request with a Bash call and the five_hour
// window at 90 percent. The first request goes with A, the second, after A's answer,
// with B; after B's answer both keys are at their percentage, so the proxy sends no
// third request to the stub and returns its 429. The session ends paused with
// model_key_limit and Claude Code's exit code, the run closes paused with
// model_key_limit, the record lists model with 200 and then model-b with 200 to the
// stub, and the stub got no request that it refused.
func TestDockerModelKeysAtTheirUseUpToPercentPauseTheRun(t *testing.T) {
	k := newKeysWall(t)
	name, host := k.stub(t, keysShare)
	s, ctl := k.groupRun(t, host, 2, "--allowedTools", "Bash")
	s.prompt = "Run the command you are given."
	endpoint := "https://" + host + ":" + recorderTLS
	var creds []map[string]any
	for _, n := range []string{"model", "model-b"} {
		c := keysCredential(n, endpoint)
		c["use_up_to_percent"], c["use_up_to_windows"] = 90, []string{"five_hour", "seven_day"}
		creds = append(creds, c)
	}
	ctl.configure(t, s.runID, host, creds, []string{keyA, keyB}, nil)
	o := s.run(t)
	log := k.stubLog(t, name)
	t.Logf("the stub got:%s", keysEntries(log))
	if o.res.State != event.StatePaused || o.res.Reason != event.ReasonModelKeyLimit {
		t.Errorf("the session ended %s, %q, exit %d; want paused, model_key_limit\nstub:%s\nstdout:\n%s",
			o.res.State, o.res.Reason, o.res.ExitCode, keysEntries(log), tail(o.out, 4000))
	}
	if d := o.exited(); d == nil || d["state"] != event.StatePaused || d["reason"] != event.ReasonModelKeyLimit || d["exit_code"] != float64(o.res.ExitCode) {
		t.Errorf("dev.qory.session.exited is %v; want paused, model_key_limit, exit %d", d, o.res.ExitCode)
	}
	if o.closed != nil {
		t.Errorf("the close with model_key_limit: %v", o.closed)
	}
	if es := o.of(event.RunExited); len(es) != 1 || es[0]["state"] != event.StatePaused || es[0]["reason"] != event.ReasonModelKeyLimit {
		t.Errorf("dev.qory.run.exited is %v; want one, paused with model_key_limit", es)
	}
	if len(log) != 2 || log[0].Key != "A" || log[1].Key != "B" || log[0].Status != http.StatusOK || log[1].Status != http.StatusOK {
		t.Errorf("the stub got:%s\nwant a 200 with key A, then a 200 with key B, and nothing more", keysEntries(log))
	}
	if got := o.egress(host); len(got) < 2 || got[0] != "model 200" || got[1] != "model-b 200" {
		t.Errorf("the record lists %q to the stub; want a request with model and 200, then one with model-b and 200", got)
	}
	if strings.Contains(o.lines, "limit response, status 429") {
		t.Errorf("the gateway's log has a limit response of the provider:\n%s", o.lines)
	}
	noKeyValue(t, o, s.dir)
}

// TestDockerModelKeysReportAndTakeTheControlPlanesCooldown runs Claude Code behind the
// wall with a key group of three keys, model, model-b and model-c, with A, B and C. The
// stub caps A, and serves B's first request with a Bash call after 3 seconds. The
// gateway reports A's refusal with POST <run.url>/<run_id>/model-keys, and the fake
// control plane returns that model-b is rejected in its five_hour window until an hour
// from now. Every report is valid against model-keys-report.schema.json, and one has
// model's five_hour window rejected, from the provider, with cooldown_until. After the
// Bash call Claude Code's next request goes with C: the answer's cooldown keeps the
// proxy from setting B.
func TestDockerModelKeysReportAndTakeTheControlPlanesCooldown(t *testing.T) {
	k := newKeysWall(t)
	name, host := k.stub(t, keysReport)
	s, ctl := k.groupRun(t, host, 3, "--allowedTools", "Bash")
	s.prompt = "Run the command you are given."
	now := time.Now().UTC()
	ctl.mu.Lock()
	ctl.answer = []server.ModelKeyState{{Credential: "model-b", Window: "five_hour", Status: "rejected",
		ResetsAt: server.RegistrationTime(now.Add(time.Hour)), CooldownUntil: server.RegistrationTime(now.Add(time.Hour)),
		Source: "provider", ObservedAt: server.RegistrationTime(now)}}
	ctl.mu.Unlock()
	o := s.run(t)
	log := k.stubLog(t, name)
	t.Logf("the stub got:%s", keysEntries(log))
	if o.res.State != event.StateSucceeded || o.res.ExitCode != 0 {
		t.Errorf("the session ended %s, exit %d; want succeeded, 0\nstub:%s\nstdout:\n%s", o.res.State, o.res.ExitCode, keysEntries(log), tail(o.out, 4000))
	}
	var keys []string
	for _, e := range log {
		keys = append(keys, e.Key)
	}
	if len(log) != 3 || !slices.Equal(keys, []string{"A", "B", "C"}) || log[2].Results != 1 {
		t.Errorf("the stub got:%s\nwant a 429 with key A, the call with key B, then its tool result with key C", keysEntries(log))
	}
	reports, invalid := ctl.received()
	if len(reports) == 0 || len(invalid) > 0 {
		t.Errorf("the control plane got %d reports, %d invalid: %q", len(reports), len(invalid), invalid)
	}
	found := false
	for _, b := range reports {
		var rep struct {
			RunID string                 `json:"run_id"`
			Keys  []server.ModelKeyState `json:"keys"`
		}
		if json.Unmarshal(b, &rep) != nil || rep.RunID != s.runID {
			t.Errorf("a report of another run or that does not read: %s", b)
			continue
		}
		for _, e := range rep.Keys {
			if e.Credential == "model" && e.Window == "five_hour" && e.Status == "rejected" && e.CooldownUntil != "" && e.Source == "provider" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no report has model's five_hour window rejected with cooldown_until, from the provider:\n%s", bytes.Join(reports, []byte("\n")))
	}
	noKeyValue(t, o, s.dir)
}
