package e2e

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
)

// The tests of Codex run Codex 0.167.2 itself behind the wall against a stub of the
// Responses API: fake model keys from a fake control plane, each set by the gateway's
// proxy on the paths of its credential alone. The stub reads the key's mark in the
// value, -SERV-, -LIMT- or -UNAU-, and serves each POST to /v1/responses by it: a
// streamed answer with a text, a 429 with the x-codex-* headers and the body of a
// usage limit, or a 401. It returns 404 for every other request.

// The stub's mode, the file it logs each request to inside its container, and the
// marks that choose what it serves.
const (
	modeCodexStub = "codex-stub"
	codexStubLog  = "/tmp/e2e-codex-stub.jsonl"

	codexServe        = "SERV"
	codexLimit        = "LIMT"
	codexUnauthorized = "UNAU"
)

// codexPath is the path Codex sends a request of the Responses format to: the
// endpoint's /v1, then /responses.
const codexPath = "/v1/responses"

// The account header and claim of a subscription login's token, as the subscription
// entry of the model catalog sets them for Codex.
const (
	codexAccountHeader = "chatgpt-account-id"
	codexAccountClaim  = "/https:~1~1api.openai.com~1auth/chatgpt_account_id"
)

// codexHome is CODEX_HOME in the wall, the folder qory sets for Codex in every image,
// which the image makes writable: Codex writes its state and the transcript of its
// session below it. Codex 0.167.2 makes no helper binaries in a home under /tmp.
const codexHome = "/var/lib/qory-codex-home"

// codexRun is the script in [codexFolder] the launch starts.
const codexRun = "codex-run"

// codexArgs are the arguments of the launch before the test's and the prompt: codex
// exec --json with Codex's sandbox off (--sandbox danger-full-access), as qory starts
// it behind the wall, in a workspace that is no git repository, with a model id the
// stub accepts.
var codexArgs = []string{"exec", "--json", "--skip-git-repo-check", "--sandbox", "danger-full-access", "--model", "gpt-e2e"}

func init() {
	if len(os.Args) > 1 && os.Args[1] == modeCodexStub {
		os.Exit(serveCodexStub())
	}
}

// codexKey is a fake API key with mark.
func codexKey(mark string) string {
	return "sk-e2e-codex-" + mark + "-" + strconv.Itoa(os.Getpid())
}

// codexToken is a fake subscription login's token with mark: a JWT whose payload has
// the account id acct-<mark> under the claim of [codexAccountClaim], and whose
// signature part has the mark.
func codexToken(mark string) string {
	enc := base64.RawURLEncoding
	payload, _ := json.Marshal(map[string]any{"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "acct-" + mark}})
	return enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc.EncodeToString(payload) + ".e2e-codex-" + mark + "-" + strconv.Itoa(os.Getpid())
}

// codexEntry is one request the stub logs: its number, method and path, the key's
// mark, "other" for any other credential and "" for none, the account header, and the
// status of the answer.
type codexEntry struct {
	N       int    `json:"n"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Key     string `json:"key"`
	Account string `json:"account"`
	Status  int    `json:"status"`
}

// codexMark is the mark of the key in a request's Authorization header.
func codexMark(h http.Header) string {
	v := h.Get("Authorization")
	for _, m := range []string{codexServe, codexLimit, codexUnauthorized} {
		if strings.Contains(v, "-"+m+"-") {
			return m
		}
	}
	if v != "" {
		return "other"
	}
	return ""
}

// codexStub is the stub's handler, which logs each request to log.
type codexStub struct {
	log string
	mu  sync.Mutex
	n   int
}

func (s *codexStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)
	s.mu.Lock()
	s.n++
	e := codexEntry{N: s.n, Method: r.Method, Path: r.URL.Path, Key: codexMark(r.Header), Account: r.Header.Get(codexAccountHeader)}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method != http.MethodPost || r.URL.Path != codexPath:
		e.Status = http.StatusNotFound
		w.WriteHeader(e.Status)
		io.WriteString(w, `{"error":{"message":"stub: not found","type":"invalid_request_error"}}`)
	case e.Key == codexLimit:
		e.Status = codexUsageLimit(w)
	case e.Key == codexUnauthorized:
		e.Status = http.StatusUnauthorized
		w.WriteHeader(e.Status)
		io.WriteString(w, `{"error":{"message":"Incorrect API key provided.","type":"invalid_request_error","code":"invalid_api_key"}}`)
	default:
		e.Status = http.StatusOK
		codexAnswer(w, e.N)
	}
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

// codexUsageLimit returns a subscription's usage limit: a 429 whose x-codex-* headers
// put the five-hour window at 100 percent, reset in an hour, with the body of
// usage_limit_reached and no Retry-After. Codex 0.167.2 ends its turn on it.
func codexUsageLimit(w http.ResponseWriter) int {
	hd := w.Header()
	reset := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	hd.Set("x-codex-primary-used-percent", "100")
	hd.Set("x-codex-primary-window-minutes", "300")
	hd.Set("x-codex-primary-reset-at", reset)
	hd.Set("x-codex-secondary-used-percent", "40")
	hd.Set("x-codex-secondary-window-minutes", "10080")
	hd.Set("x-codex-secondary-reset-at", strconv.FormatInt(time.Now().Add(72*time.Hour).Unix(), 10))
	hd.Set("x-codex-rate-limit-reached-type", "rate_limit_reached")
	w.WriteHeader(http.StatusTooManyRequests)
	io.WriteString(w, `{"error":{"type":"usage_limit_reached","message":"The usage limit has been reached","plan_type":"example","resets_at":`+reset+`,"limit_window_minutes":300}}`)
	return http.StatusTooManyRequests
}

// codexAnswer streams a Responses answer with one assistant message, the text Hi:
// response.created, the message's response.output_item.done and response.completed.
func codexAnswer(w http.ResponseWriter, n int) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	id := fmt.Sprintf("resp_e2e_%d", n)
	for _, e := range []map[string]any{
		{"type": "response.created", "response": map[string]any{"id": id}},
		{"type": "response.output_item.done", "item": map[string]any{"type": "message", "role": "assistant", "id": fmt.Sprintf("msg_e2e_%d", n),
			"content": []any{map[string]any{"type": "output_text", "text": "Hi"}}}},
		{"type": "response.completed", "response": map[string]any{"id": id,
			"usage": map[string]any{"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}},
	} {
		b, _ := json.Marshal(e)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e["type"], b)
	}
}

// serveCodexStub is the stub in a container: it serves HTTPS on 8443 with a
// certificate of the suite's authority for the container's addresses, logs every
// request to codexStubLog, and prints RecorderReady once it listens.
func serveCodexStub() int {
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
	return fail(http.Serve(ln, &codexStub{log: codexStubLog}))
}

// codexWall is what the walled tests of Codex share: the docker command, the helper,
// the image with Codex, the stub's container and its address, and the folder of
// [codexFolder].
type codexWall struct {
	keysWall
	stub, host, folder string
}

// newCodexWall skips the test without an engine, without a Linux build of the test
// binary off Linux, and without an image with Codex in QORY_WALL_CODEX_IMAGE; each skip
// fails under QORY_WALL_REQUIRE. It points this machine's roots at the suite's
// authority, and starts the stub in a container that is removed when it stops, at the
// test's end.
func newCodexWall(t *testing.T) codexWall {
	t.Helper()
	command := os.Getenv("QORY_WALL_COMMAND")
	if command == "" {
		command = "docker"
	}
	if out, err := exec.Command(command, "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		Skip(t, command+" reaches no engine: "+strings.TrimSpace(string(out)))
	}
	helper := Helper(t)
	image := os.Getenv("QORY_WALL_CODEX_IMAGE")
	if image == "" {
		Skip(t, "QORY_WALL_CODEX_IMAGE is empty: it selects an image with Codex 0.167.2 at codex on its PATH")
	}
	if err := trustRecorders(t); err != nil {
		t.Fatalf("this machine's roots are not the suite's authority: %v", err)
	}
	k := codexWall{keysWall: keysWall{command: command, helper: helper, image: image}}
	// The engine removes a stopped stub after docker stop returns, so the name has the
	// time the stub starts: the next test's stub may start before the last one is gone.
	k.stub = fmt.Sprintf("qory-walltest-codex-%d-%d", os.Getpid(), time.Now().UnixNano())
	args := []string{"run", "--rm", "--detach", "--name", k.stub, "--mount", "type=bind,src=" + helper + ",dst=/walltest,readonly"}
	for _, kv := range RecorderEnv() {
		args = append(args, "--env", kv)
	}
	args = append(args, "--entrypoint", "/walltest", keysBusybox, modeCodexStub)
	if out, err := exec.Command(command, args...).CombinedOutput(); err != nil {
		t.Fatalf("the stub: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command(command, "stop", "--time", "1", k.stub).Run() })
	AwaitRecorder(t, command, k.stub)
	ip, err := exec.Command(command, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", k.stub).Output()
	if err != nil {
		t.Fatal(err)
	}
	k.host = strings.TrimSpace(string(ip))
	k.folder = codexFolder(t)
	return k
}

// codexFolder makes a folder in t.TempDir() with codex-run, a script that starts codex
// with its arguments, then writes rollout=<path> on standard error for each transcript
// below $CODEX_HOME/sessions, and exits with codex's status. The wall mounts the folder
// read-only at the same path.
func codexFolder(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\ncodex \"$@\"\nstatus=$?\n" +
		"for f in \"$CODEX_HOME\"/sessions/*/*/*/rollout-*.jsonl; do [ -f \"$f\" ] && echo \"rollout=$f\" >&2; done\nexit $status\n"
	if err := os.WriteFile(filepath.Join(dir, codexRun), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// log is the stub's log, from entry from on.
func (k codexWall) log(t *testing.T, from int) []codexEntry {
	t.Helper()
	b, err := exec.Command(k.command, "exec", k.stub, "cat", codexStubLog).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && from == 0 {
			return nil
		}
		t.Fatalf("the stub's log: %v", err)
	}
	var out []codexEntry
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		var e codexEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("the stub's log: %v: %s", err, sc.Bytes())
		}
		out = append(out, e)
	}
	if from > len(out) {
		return nil
	}
	return out[from:]
}

// codexCredential is one key of a run configuration: the Responses format on the
// endpoint, set only on /v1/responses, with a cooldown of an hour after a refusal with
// no reset; a subscription login's token as a bearer with oauth and the account
// header from its claim, or an API key as a bearer.
func codexCredential(name, endpoint string, login bool) map[string]any {
	auth := map[string]any{"scheme": "bearer"}
	if login {
		auth = map[string]any{"scheme": "bearer", "oauth": true, "account_header": codexAccountHeader, "account_claim": codexAccountClaim}
	}
	return map[string]any{"name": name, "format": "openai-responses", "endpoint": endpoint, "auth": auth,
		"paths": []string{codexPath}, "pause_for_s": 3600}
}

// run runs Codex once with the keys, each a name and a value, the first the start key,
// as subscription logins' tokens or as API keys, and returns the outcome and the
// requests the stub got during the run.
func (k codexWall) run(t *testing.T, login bool, keys ...[2]string) (keysOutcome, []codexEntry, keysSession) {
	t.Helper()
	before := len(k.log(t, 0))
	ctl := startKeysControl(t)
	endpoint := "https://" + k.host + ":" + recorderTLS + "/v1"
	var creds []map[string]any
	var values []string
	for _, kv := range keys {
		creds = append(creds, codexCredential(kv[0], endpoint, login))
		values = append(values, kv[1])
	}
	runID := event.NewRunID()
	ctl.configure(t, runID, k.host, creds, values, nil)
	s := keysSession{runID: runID, server: ctl.server, allow: []string{k.host}, prompt: "Say hi in one word.",
		dir: t.TempDir(), walled: &k.keysWall, timeout: 4 * time.Minute, codex: k.folder}
	o := s.run(t)
	log := k.log(t, before)
	t.Logf("the session ended %s, reason %q, exit %d; the stub got:%s", o.res.State, o.res.Reason, o.res.ExitCode, codexEntries(log))
	t.Logf("the run's egress:%s", codexEgress(o))
	t.Logf("the turns: finished %v, failed %v", o.of("dev.qory.runtime.turn_finished"), o.of("dev.qory.runtime.turn_failed"))
	return o, log, s
}

// codexEntries is the log as lines "<n> <method> <path> <key> <account> <status>".
func codexEntries(log []codexEntry) string {
	var b strings.Builder
	for _, e := range log {
		fmt.Fprintf(&b, "\n  %d %s %s key=%q account=%q %d", e.N, e.Method, e.Path, e.Key, e.Account, e.Status)
	}
	return b.String()
}

// codexEgress is every request of the run's dev.qory.run.egress, CONNECT and those
// inside it, as lines "<method> <host>:<port> <path> <decision> <outcome> <status>
// <credential>".
func codexEgress(o keysOutcome) string {
	var b strings.Builder
	for _, d := range o.of(event.RunEgress) {
		method := d["method"]
		if m, ok := d["request_method"]; ok {
			method = fmt.Sprint(d["method"], "/", m)
		}
		fmt.Fprintf(&b, "\n  %v %v:%v %v %v %v %v %v", method, d["host"], d["port"], d["path"], d["decision"], d["outcome"], d["status"], d["credential"])
	}
	return b.String()
}

// otherHosts are the hosts of the run's egress other than host, each once.
func otherHosts(o keysOutcome, host string) []string {
	var out []string
	for _, d := range o.of(event.RunEgress) {
		h := fmt.Sprint(d["host"], ":", d["port"])
		if d["host"] != host && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

// codexNoKeyValue fails the test when a file under one of roots, the run's record or
// the output contains a key's value.
func codexNoKeyValue(t *testing.T, o keysOutcome, values []string, roots ...string) {
	t.Helper()
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

// TestDockerCodexThroughTheWall runs Codex 0.167.2 behind the Docker adapter with an
// API key and with a subscription login's token, each a fake key of the run
// configuration on the stub, set on /v1/responses alone. The session passes the
// provider qory and the key's endpoint as --config pairs, and OPENAI_API_KEY is the
// key's placeholder. Codex prints the stub's text and the session succeeds; each
// request the stub gets is a POST to /v1/responses with the key as a bearer, and with
// the token, the account header from its claim. The run's events contain
// dev.qory.runtime.started from startup with Codex's thread id, and
// dev.qory.runtime.turn_finished with the same id, and Codex wrote its transcript at
// CODEX_HOME/sessions/<yyyy>/<mm>/<dd>/rollout-<time>-<thread id>.jsonl, the path the
// resume of the descriptor is to match. The run reaches no host but the stub, and the
// test logs every request of the run's egress. No file of the run, the workspace or
// the output contains a key's value.
func TestDockerCodexThroughTheWall(t *testing.T) {
	k := newCodexWall(t)
	for _, c := range []struct {
		name    string
		login   bool
		key     string
		account string
	}{
		{"api key", false, codexKey(codexServe), ""},
		{"subscription login", true, codexToken(codexServe), "acct-" + codexServe},
	} {
		t.Run(c.name, func(t *testing.T) {
			o, log, s := k.run(t, c.login, [2]string{"model", c.key})
			if o.res.State != event.StateSucceeded || o.res.ExitCode != 0 {
				t.Fatalf("the session ended %s, exit %d; want succeeded\nstderr:\n%s\nstdout:\n%s", o.res.State, o.res.ExitCode, tail(o.errs, 4000), tail(o.out, 4000))
			}
			if !strings.Contains(o.out, `"text":"Hi"`) {
				t.Errorf("Codex printed no agent message with the stub's text:\n%s", tail(o.out, 4000))
			}
			if len(log) == 0 {
				t.Fatal("the stub got no request")
			}
			for _, e := range log {
				if e.Method != http.MethodPost || e.Path != codexPath || e.Key != codexServe || e.Account != c.account || e.Status != http.StatusOK {
					t.Errorf("the stub got %+v; want a POST to %s with the key and account %q", e, codexPath, c.account)
				}
			}
			started := o.of("dev.qory.runtime.started")
			if len(started) != 1 || started[0]["source"] != "startup" {
				t.Fatalf("dev.qory.runtime.started is %v; want one, from startup", started)
			}
			id, _ := started[0]["session_id"].(string)
			if finished := o.of("dev.qory.runtime.turn_finished"); len(finished) != 1 || id == "" || finished[0]["session_id"] != id {
				t.Errorf("dev.qory.runtime.turn_finished is %v; want one, with the thread id %q of the start", finished, id)
			}
			rollout := regexp.MustCompile(`(?m)^rollout=` + regexp.QuoteMeta(codexHome) + `/sessions/[0-9]{4}/[0-9]{2}/[0-9]{2}/rollout-[^/]*-` +
				regexp.QuoteMeta(id) + `\.jsonl\r?$`)
			if id == "" || !rollout.MatchString(o.errs) {
				t.Errorf("Codex wrote no transcript at %s/sessions/*/*/*/rollout-*-%s.jsonl; stderr:\n%s", codexHome, id, tail(o.errs, 4000))
			}
			sessions := o.of(event.SessionStarted)
			if len(sessions) != 1 {
				t.Fatalf("dev.qory.session.started is %v; want one", sessions)
			}
			args, _ := sessions[0]["args"].([]any)
			at := slices.Index(args, any("exec"))
			for _, pair := range []string{`model_provider="qory"`, `model_providers.qory.base_url="https://` + k.host + `:` + recorderTLS + `/v1"`,
				`model_providers.qory.env_key="OPENAI_API_KEY"`, `web_search="disabled"`} {
				if i := slices.Index(args, any(pair)); i < 1 || args[i-1] != "--config" || at < i {
					t.Errorf("the launch's arguments %q have no --config %s before exec", args, pair)
				}
			}
			// Codex prints a deprecation as an error item on standard output, such as the
			// one for features.connectors, and a warning on standard error. Codex prints
			// neither for the session's pairs, otel.exporter and otel.trace_exporter among
			// them.
			if strings.Contains(strings.ToLower(o.out), "deprecated") || strings.Contains(strings.ToLower(o.errs), "warning") {
				t.Errorf("Codex warned about its settings\nstdout:\n%s\nstderr:\n%s", tail(o.out, 4000), tail(o.errs, 4000))
			}
			if hosts := otherHosts(o, k.host); len(hosts) > 0 {
				t.Errorf("the run reached hosts other than the stub: %q", hosts)
			}
			codexNoKeyValue(t, o, []string{c.key}, s.dir)
		})
	}
}

// TestDockerCodexPausesOnAUsageLimit runs Codex 0.167.2 behind the wall with one key,
// on which the stub returns a usage limit: a 429 with the x-codex-* headers. The
// gateway cools the key and passes the 429 on, Codex ends its turn, and the gateway's
// answer to the session's batch stops the session: dev.qory.session.exited and the
// run's dev.qory.run.exited are paused with model_key_limit. Codex's turn.failed is a
// dev.qory.runtime.turn_failed with the start's session id.
func TestDockerCodexPausesOnAUsageLimit(t *testing.T) {
	k := newCodexWall(t)
	o, log, s := k.run(t, true, [2]string{"model", codexToken(codexLimit)})
	if o.res.State != event.StatePaused || o.res.Reason != event.ReasonModelKeyLimit {
		t.Errorf("the session ended %s, %q, exit %d; want paused, model_key_limit\nstderr:\n%s\nstdout:\n%s",
			o.res.State, o.res.Reason, o.res.ExitCode, tail(o.errs, 4000), tail(o.out, 4000))
	}
	codexExited(t, o, event.StatePaused, event.ReasonModelKeyLimit)
	codexTurnFailed(t, o)
	if len(log) == 0 || log[0].Key != codexLimit || log[0].Status != http.StatusTooManyRequests {
		t.Errorf("the stub got:%s\nwant a 429 with the key first", codexEntries(log))
	}
	for _, e := range log {
		if e.Status != http.StatusTooManyRequests {
			t.Errorf("the stub got %+v after the limit; want no request served", e)
		}
	}
	codexNoKeyValue(t, o, []string{codexToken(codexLimit)}, s.dir)
}

// TestDockerCodexEndsOrSwitchesOnARejectedKey runs Codex 0.167.2 behind the wall with
// a key for which the stub returns 401. With that key alone, the gateway takes it out, no key is
// left, and the session and the run end failed with model_key_unauthorized. With a
// second key, the gateway passes the 401 on and sends nothing with the second key in
// that session: the session and the run end paused with model_key_switch, for the
// continuation to start on the second key.
func TestDockerCodexEndsOrSwitchesOnARejectedKey(t *testing.T) {
	k := newCodexWall(t)
	t.Run("one key", func(t *testing.T) {
		o, log, s := k.run(t, false, [2]string{"model", codexKey(codexUnauthorized)})
		if o.res.State != event.StateFailed || o.res.Reason != event.ReasonModelKeyUnauthorized {
			t.Errorf("the session ended %s, %q, exit %d; want failed, model_key_unauthorized\nstderr:\n%s\nstdout:\n%s",
				o.res.State, o.res.Reason, o.res.ExitCode, tail(o.errs, 4000), tail(o.out, 4000))
		}
		codexExited(t, o, event.StateFailed, event.ReasonModelKeyUnauthorized)
		codexTurnFailed(t, o)
		if len(log) == 0 || log[0].Key != codexUnauthorized || log[0].Status != http.StatusUnauthorized {
			t.Errorf("the stub got:%s\nwant a 401 with the key first", codexEntries(log))
		}
		codexNoKeyValue(t, o, []string{codexKey(codexUnauthorized)}, s.dir)
	})
	t.Run("two keys", func(t *testing.T) {
		o, log, s := k.run(t, false, [2]string{"model", codexKey(codexUnauthorized)}, [2]string{"model-b", codexKey(codexServe)})
		if o.res.State != event.StatePaused || o.res.Reason != event.ReasonModelKeySwitch {
			t.Errorf("the session ended %s, %q, exit %d; want paused, model_key_switch\nstderr:\n%s\nstdout:\n%s",
				o.res.State, o.res.Reason, o.res.ExitCode, tail(o.errs, 4000), tail(o.out, 4000))
		}
		codexExited(t, o, event.StatePaused, event.ReasonModelKeySwitch)
		codexTurnFailed(t, o)
		if len(log) == 0 || log[0].Key != codexUnauthorized || log[0].Status != http.StatusUnauthorized {
			t.Errorf("the stub got:%s\nwant a 401 with the first key first", codexEntries(log))
		}
		for _, e := range log {
			if e.Key == codexServe {
				t.Errorf("the stub got %+v with the second key; an openai-responses session keeps its key", e)
			}
		}
		codexNoKeyValue(t, o, []string{codexKey(codexUnauthorized), codexKey(codexServe)}, s.dir)
	})
}

// codexTurnFailed checks that the run's events contain one dev.qory.runtime.turn_failed,
// with error unknown and the session id of the one dev.qory.runtime.started.
func codexTurnFailed(t *testing.T, o keysOutcome) {
	t.Helper()
	started, failed := o.of("dev.qory.runtime.started"), o.of("dev.qory.runtime.turn_failed")
	if len(started) != 1 || len(failed) != 1 || failed[0]["error"] != "unknown" || failed[0]["session_id"] != started[0]["session_id"] {
		t.Errorf("dev.qory.runtime.turn_failed is %v after the start %v; want one, error unknown, with the start's session_id", failed, started)
	}
}

// TestDockerCodexRefusesAnArgumentThatSetsASessionSetting starts Codex behind the wall
// with launch arguments that set a setting the session passes: model_provider through
// --config, the endpoint's setting through -c, and the provider through --profile. The
// join returns an error that starts with the fix and contains the flag, Codex does not
// start, and the stub gets no request. The error contains no value of the arguments.
func TestDockerCodexRefusesAnArgumentThatSetsASessionSetting(t *testing.T) {
	k := newCodexWall(t)
	const value = "e2e-value-not-shown"
	for _, c := range []struct {
		name, flag string
		args       []string
	}{
		{"--config", "--config", []string{"--config", "model_provider=" + value}},
		{"-c", "-c", []string{"-c", "model_providers.qory.base_url=" + value}},
		{"--profile", "--profile", []string{"--profile=" + value}},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := len(k.log(t, 0))
			ctl := startKeysControl(t)
			endpoint := "https://" + k.host + ":" + recorderTLS + "/v1"
			runID := event.NewRunID()
			ctl.configure(t, runID, k.host, []map[string]any{codexCredential("model", endpoint, false)}, []string{codexKey(codexServe)}, nil)
			s := keysSession{runID: runID, server: ctl.server, allow: []string{k.host}, prompt: "Say hi in one word.", args: c.args,
				dir: t.TempDir(), walled: &k.keysWall, timeout: 4 * time.Minute, codex: k.folder, joinFails: true}
			o := s.run(t)
			if o.joined == nil || !strings.HasPrefix(o.joined.Error(), "remove ") || !strings.Contains(o.joined.Error(), c.flag) ||
				strings.Contains(o.joined.Error(), value) {
				t.Errorf("the join returned %v; want an error that starts with remove, contains %s and contains no value", o.joined, c.flag)
			}
			if strings.Contains(o.out+o.errs, value) {
				t.Errorf("the output contains the argument's value:\n%s\n%s", o.out, o.errs)
			}
			if log := k.log(t, before); len(log) > 0 {
				t.Errorf("the stub got:%s\nwant no request", codexEntries(log))
			}
		})
	}
}

// codexExited checks that the session's dev.qory.session.exited and the run's one
// dev.qory.run.exited have state and reason, and that the close succeeded.
func codexExited(t *testing.T, o keysOutcome, state, reason string) {
	t.Helper()
	if d := o.exited(); d == nil || d["state"] != state || d["reason"] != reason {
		t.Errorf("dev.qory.session.exited is %v; want %s, %s", d, state, reason)
	}
	if o.closed != nil {
		t.Errorf("the close with %s: %v", reason, o.closed)
	}
	if es := o.of(event.RunExited); len(es) != 1 || es[0]["state"] != state || es[0]["reason"] != reason {
		t.Errorf("dev.qory.run.exited is %v; want one, %s with %s", es, state, reason)
	}
}
