package walltest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
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

	"github.com/qoryai/runner/internal/credential"
	"github.com/qoryai/runner/runtimes/claude"
	"github.com/qoryai/runner/session"
	"github.com/qoryai/runner/wall"
)

// TestDockerClaudeCodeThroughTheWall runs Claude Code itself behind the Docker adapter
// against a recorder that answers as the Messages API, which ANTHROPIC_BASE_URL points
// Claude Code at: with an API key and with an OAuth credential, each a fake key the
// runner sets outside, headless and interactive. The variables Claude Code reads a
// model credential from that the run does not set a stand-in in are set empty, so each
// run also checks that Claude Code reads an empty one as unset and uses the stand-in.
// Claude Code answers with the recorder's text; every request the recorder gets
// carries the key in the credential's header, no stand-in and not the other
// credential's header; the record lists one request through the proxy for each the
// recorder received, each to the recorder with the credential, beside the hosts of its
// own an interactive Claude Code tries, which the policy refuses; and the run's
// directory, the agent's home and the output contain no key.
//
// An interactive run starts on a pseudo-terminal with a home of its own, whose
// configuration has the onboarding done and the workspace trusted, as a person's
// would, and the test types a prompt once Claude Code shows its input. With the API
// key, Claude Code reaches its input with no approval prompt for the key, because the
// runtime pre-approved the stand-in: the configuration then holds the stand-in's
// entry, and every member it held before.
//
// QORY_WALL_CLAUDE_IMAGE selects an image with claude on its PATH; without it the test
// is skipped.
func TestDockerClaudeCodeThroughTheWall(t *testing.T) {
	image := os.Getenv("QORY_WALL_CLAUDE_IMAGE")
	if image == "" {
		t.Skip("QORY_WALL_CLAUDE_IMAGE is empty: it selects an image with Claude Code")
	}
	command := os.Getenv("QORY_WALL_COMMAND")
	if command == "" {
		command = "docker"
	}
	if out, err := exec.Command(command, "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		Skip(t, command+" reaches no engine: "+strings.TrimSpace(string(out)))
	}
	helper := Helper(t)
	name := fmt.Sprintf("qory-walltest-claude-recorder-%d", os.Getpid())
	args := []string{"run", "--detach", "--name", name, "--mount", "type=bind,src=" + helper + ",dst=/walltest,readonly"}
	for _, kv := range RecorderEnv() {
		args = append(args, "--env", kv)
	}
	args = append(append(args, "--entrypoint", "/walltest", "busybox:stable"), RecorderArgs...)
	if out, err := exec.Command(command, args...).CombinedOutput(); err != nil {
		t.Fatalf("the recorder: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command(command, "rm", "--force", name).Run() })
	AwaitRecorder(t, command, name)
	ip, err := exec.Command(command, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).Output()
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimSpace(string(ip))
	if err := trustRecorders(t); err != nil {
		t.Fatalf("this machine's roots are not the suite's authority: %v", err)
	}
	pid := strconv.Itoa(os.Getpid())
	apiKey := claudeCredential{scheme: "header", header: apiKeyHeader, standIn: apiKeyStandIn, unset: oauthStandIn, key: "sk-ant-test" + keyMark + "0001-" + pid}
	oauth := claudeCredential{scheme: "bearer", header: "Authorization", prefix: "Bearer ", standIn: oauthStandIn, unset: apiKeyStandIn, key: "sk-ant-oat01-test" + keyMark + "0002-" + pid}
	run := claudeRun{command: command, recorder: name, host: host, helper: helper, image: image}
	t.Run("api key in x-api-key", func(t *testing.T) { run.check(t, apiKey, false) })
	t.Run("oauth as a bearer", func(t *testing.T) { run.check(t, oauth, false) })
	t.Run("interactive api key", func(t *testing.T) { run.check(t, apiKey, true) })
	t.Run("interactive oauth", func(t *testing.T) { run.check(t, oauth, true) })
}

// claudeCredential is one model credential of Claude Code's: how the proxy sets it, the
// header it arrives in at the recorder with its prefix, the variable Claude Code reads
// its stand-in from, the variable of the other credential, which the run sets empty,
// and the fake key.
type claudeCredential struct {
	scheme, header, prefix, standIn, unset, key string
}

// claudeRun is what the runs of TestDockerClaudeCodeThroughTheWall share.
type claudeRun struct {
	command, recorder, host, helper, image string
}

// check runs Claude Code once with the credential, headless or interactive, and checks
// the run as TestDockerClaudeCodeThroughTheWall describes.
func (r claudeRun) check(t *testing.T, c claudeCredential, interactive bool) {
	t.Setenv(apiKeyVar, c.key)
	before, _ := exec.Command(r.command, "exec", r.recorder, "cat", RecorderFile).Output()
	dir, runs := t.TempDir(), filepath.Join(t.TempDir(), "runs")
	rt, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	spec := session.Spec{
		Runtime: rt,
		Command: "claude",
		Args:    []string{"-p", "Reply with one word."},
		Env: []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"ANTHROPIC_BASE_URL=https://" + r.host + ":" + recorderTLS,
			"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
			"DISABLE_AUTOUPDATER=1",
			// Empty means unset: Claude Code reads ANTHROPIC_AUTH_TOKEN first and the
			// other credential's variable beside the stand-in's.
			"ANTHROPIC_AUTH_TOKEN=",
			c.unset + "=",
		},
		Dir:     dir,
		RunsDir: runs,
		Policy: &session.Policy{Version: 1,
			Egress:      session.PolicyEgress{Mode: "enforce", Allow: []string{r.host}},
			Credentials: []session.PolicyCredential{{Name: "model"}}},
		Credentials:   []session.Credential{{Name: "model", Env: apiKeyVar, Hosts: []string{r.host}, Scheme: c.scheme, Header: c.header, Placeholders: []string{c.standIn}}},
		Forwarder:     []string{wall.HelperPath, "forward"},
		Wall:          &wall.Docker{Command: r.command, Helper: r.helper, RelayArgs: RelayArgs, NestArgs: NestArgs},
		Image:         r.image,
		RunnerVersion: "walltest",
		Report:        func(l string) { t.Log("report:", l) },
	}
	var out, errs syncBuffer
	spec.Stdout, spec.Stderr = &out, &errs
	var home, config string
	// kept is a member of the agent's configuration that is the person's own.
	const kept = "walltestKept"
	if interactive {
		home = t.TempDir()
		config = filepath.Join(home, ".claude.json")
		b, _ := json.Marshal(map[string]any{
			"hasCompletedOnboarding": true,
			"projects":               map[string]any{dir: map[string]any{"hasTrustDialogAccepted": true}},
			kept:                     "a person's own",
		})
		if err := os.WriteFile(config, b, 0o600); err != nil {
			t.Fatal(err)
		}
		spec.Args = nil
		spec.Env = append(spec.Env, "HOME="+home, "TERM=xterm-256color")
		spec.Mounts = []wall.Mount{{Path: home}}
		spec.Interactive = true
	} else {
		spec.Stdin = strings.NewReader("")
	}

	var res *session.Result
	if !interactive {
		if res, err = session.Run(ctx, spec); err != nil {
			t.Fatalf("the run did not start: %v\nstderr:\n%s", err, errs.String())
		}
	} else {
		res = r.drive(t, ctx, cancel, spec, &out)
	}
	t.Logf("claude answered %q, exit %d; stderr %q", tail(screen(out.String()), 400), res.ExitCode, errs.String())
	if !strings.Contains(screen(out.String()), recorderAnswer) {
		t.Errorf("claude printed no %q", recorderAnswer)
	}
	if !interactive && res.ExitCode != 0 {
		t.Errorf("claude exited %d, want 0", res.ExitCode)
	}
	after, err := exec.Command(r.command, "exec", r.recorder, "cat", RecorderFile).Output()
	if err != nil {
		t.Fatal(err)
	}
	reqs, err := readRecorded(after[len(before):])
	if err != nil {
		t.Fatal(err)
	}
	other := apiKeyHeader
	if c.header == apiKeyHeader {
		other = "Authorization"
	}
	messages := 0
	for _, req := range reqs {
		var names []string
		for header := range req.Header {
			names = append(names, header)
		}
		sort.Strings(names)
		t.Logf("the recorder got %s %s with the headers %v", req.Method, req.Path, names)
		if req.Path == modelPath {
			messages++
		}
		if v := req.Header.Values(c.header); len(v) != 1 || v[0] != c.prefix+c.key {
			t.Errorf("%s %s carried %s %d times, not the key once", req.Method, req.Path, c.header, len(v))
		}
		if v := req.Header.Values(other); len(v) != 0 {
			t.Errorf("%s %s carried %s as well, so Claude Code read an empty variable as set", req.Method, req.Path, other)
		}
		for header, vs := range req.Header {
			for _, v := range vs {
				if strings.Contains(v, credential.Placeholder) {
					t.Errorf("%s %s carried the stand-in in %s", req.Method, req.Path, header)
				}
			}
		}
	}
	if messages == 0 {
		t.Errorf("claude sent nothing to %s", modelPath)
	}
	record, err := os.ReadFile(filepath.Join(res.Dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	egress := 0
	for _, line := range strings.Split(strings.TrimSpace(string(record)), "\n") {
		var e struct {
			Type string         `json:"type"`
			Data map[string]any `json:"data"`
		}
		if json.Unmarshal([]byte(line), &e) != nil || e.Type != "dev.qory.run.egress" {
			continue
		}
		// An interactive Claude Code also tries hosts of its own, which the policy
		// refuses: its downloads and github.com, in 2.1.273.
		if interactive && e.Data["decision"] == "denied" && e.Data["host"] != r.host {
			t.Logf("the policy refused %v", e.Data)
			continue
		}
		egress++
		if e.Data["host"] != r.host || e.Data["decision"] != "allowed" || e.Data["credential"] != "model" {
			t.Errorf("the run reached beyond the recorder, or without the credential: %v", e.Data)
		}
	}
	if egress != len(reqs) {
		t.Errorf("the record lists %d requests through the proxy, and the recorder received %d", egress, len(reqs))
	}

	script := filepath.Join(res.Dir, claude.ApproveScript)
	_, err = os.Stat(script)
	if through := interactive && c.standIn == apiKeyStandIn; through != (err == nil) {
		t.Errorf("the run directory has %s: %v, want %v", claude.ApproveScript, err == nil, through)
	}
	if interactive {
		b, err := os.ReadFile(config)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Responses struct {
				Approved []string `json:"approved"`
			} `json:"customApiKeyResponses"`
			Onboarded bool   `json:"hasCompletedOnboarding"`
			Kept      string `json:"walltestKept"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatalf("the agent's configuration is no JSON: %v", err)
		}
		approved := slices.Contains(doc.Responses.Approved, "utside-the-enclosure")
		if want := c.standIn == apiKeyStandIn; approved != want || !doc.Onboarded || doc.Kept != "a person's own" {
			t.Errorf("the agent's configuration approves the stand-in: %v, want %v; keeps the onboarding: %v and %s: %q", approved, want, doc.Onboarded, kept, doc.Kept)
		}
	}

	var where []string
	// runs holds the run directory, res.Dir; dir is the workspace.
	for _, root := range []string{dir, runs, home} {
		if root == "" {
			continue
		}
		filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
			if err == nil && e.Type().IsRegular() {
				if b, err := os.ReadFile(path); err == nil && bytes.Contains(b, []byte(keyMark)) {
					where = append(where, path)
				}
			}
			return nil
		})
	}
	if strings.Contains(out.String()+errs.String(), keyMark) {
		where = append(where, "the output")
	}
	if len(where) != 0 {
		t.Errorf("a key is in %v", where)
	}
}

// drive runs an interactive session: it waits for Claude Code's input, fails at once
// when Claude Code shows its approval prompt for the API key instead, types the prompt,
// waits for the recorder's answer on the screen, and leaves with /exit.
func (r claudeRun) drive(t *testing.T, ctx context.Context, cancel context.CancelFunc, spec session.Spec, out *syncBuffer) *session.Result {
	t.Helper()
	in, keys := io.Pipe()
	spec.Stdin = in
	type ended struct {
		res *session.Result
		err error
	}
	done := make(chan ended, 1)
	go func() {
		res, err := session.Run(ctx, spec)
		keys.Close()
		done <- ended{res, err}
	}()
	result := func() *session.Result {
		select {
		case e := <-done:
			if e.err != nil {
				t.Fatalf("the run did not start: %v", e.err)
			}
			return e.res
		case <-time.After(2 * time.Minute):
			t.Fatal("the session did not end")
		}
		return nil
	}
	wait := func(what string, until func(string) bool) bool {
		deadline := time.Now().Add(2 * time.Minute)
		for time.Now().Before(deadline) {
			s := screen(out.String())
			if strings.Contains(s, "Detected a custom API key") {
				t.Errorf("Claude Code shows its approval prompt for the API key:\n%s", tail(s, 600))
				return false
			}
			if until(s) {
				return true
			}
			select {
			case e := <-done:
				done <- e
				t.Errorf("the session ended before %s:\n%s", what, tail(s, 600))
				return false
			case <-time.After(200 * time.Millisecond):
			}
		}
		t.Errorf("no %s within two minutes:\n%s", what, tail(screen(out.String()), 600))
		return false
	}
	if wait("input", func(s string) bool { return strings.Contains(s, "for shortcuts") }) {
		keys.Write([]byte("Reply with one word."))
		time.Sleep(time.Second)
		keys.Write([]byte("\r"))
		if wait("answer", func(s string) bool { return strings.Contains(s, recorderAnswer) }) {
			time.Sleep(time.Second)
		}
	}
	keys.Write([]byte("/exit"))
	time.Sleep(time.Second)
	keys.Write([]byte("\r"))
	go func() {
		// The session ends at /exit; should it not, the context stops it.
		select {
		case <-time.After(30 * time.Second):
		case <-ctx.Done():
		}
		cancel()
	}()
	return result()
}

// syncBuffer is a buffer the session writes to while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// escapes are a terminal's control sequences, CSI, OSC, a character set's and the
// other escapes, and its control characters.
var escapes = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()*+].|\x1b.|[\x00-\x08\x0e-\x1f]`)

// screen is what a terminal's bytes say, the control sequences taken out and every run
// of space made one space.
func screen(s string) string {
	return strings.Join(strings.Fields(escapes.ReplaceAllString(s, " ")), " ")
}

// tail is the last n bytes of s.
func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}
