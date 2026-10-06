package walltest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/runner/internal/credential"
	"github.com/qoryai/runner/runtimes/claude"
	"github.com/qoryai/runner/session"
	"github.com/qoryai/runner/wall"
)

// TestDockerClaudeCodeThroughTheWall runs Claude Code itself behind the Docker adapter,
// once with an API key and once with an OAuth credential, each a fake key the runner
// sets outside, against a recorder that answers as the Messages API, which
// ANTHROPIC_BASE_URL points Claude Code at. Claude Code answers with the recorder's
// text; every request the recorder gets carries the key in the credential's header and
// no stand-in; the record lists one request through the proxy for each the recorder
// received, each to the recorder with the credential; and the run's directory and
// output contain no key.
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
	args := []string{"run", "--detach", "--rm", "--name", name, "--mount", "type=bind,src=" + helper + ",dst=/walltest,readonly"}
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
	for _, c := range []struct {
		name, scheme, header, standIn, key, want string
	}{
		{"api key in x-api-key", "header", apiKeyHeader, apiKeyStandIn, "sk-ant-test" + keyMark + "0001-" + pid, ""},
		{"oauth as a bearer", "bearer", "", oauthStandIn, "sk-ant-oat01-test" + keyMark + "0002-" + pid, "Bearer "},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(apiKeyVar, c.key)
			got := c.header
			if got == "" {
				got = "Authorization"
			}
			before, _ := exec.Command(command, "exec", name, "cat", RecorderFile).Output()
			dir := t.TempDir()
			var out, errs bytes.Buffer
			rt, err := claude.New()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			res, err := session.Run(ctx, session.Spec{
				Runtime: rt,
				Command: "claude",
				Args:    []string{"-p", "Reply with one word."},
				Env: []string{
					"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
					"ANTHROPIC_BASE_URL=https://" + host + ":" + recorderTLS,
					"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
					"DISABLE_AUTOUPDATER=1",
				},
				Dir:    dir,
				Stdin:  strings.NewReader(""),
				Stdout: &out,
				Stderr: &errs,
				Policy: &session.Policy{Version: 1,
					Egress:      session.PolicyEgress{Mode: "enforce", Allow: []string{host}},
					Credentials: []session.PolicyCredential{{Name: "model"}}},
				Credentials:   []session.Credential{{Name: "model", Env: apiKeyVar, Hosts: []string{host}, Scheme: c.scheme, Header: c.header, Placeholders: []string{c.standIn}}},
				Forwarder:     []string{wall.HelperPath, "forward"},
				Wall:          &wall.Docker{Command: command, Helper: helper, RelayArgs: RelayArgs, NestArgs: NestArgs},
				Image:         image,
				RunnerVersion: "walltest",
				Report:        func(l string) { t.Log("report:", l) },
			})
			if err != nil {
				t.Fatalf("the run did not start: %v\nstderr:\n%s", err, errs.String())
			}
			t.Logf("claude answered %q, exit %d; stderr %q", out.String(), res.ExitCode, errs.String())
			if res.ExitCode != 0 || !strings.Contains(out.String(), recorderAnswer) {
				t.Errorf("claude exited %d with %q, want 0 and the recorder's answer", res.ExitCode, out.String())
			}
			after, err := exec.Command(command, "exec", name, "cat", RecorderFile).Output()
			if err != nil {
				t.Fatal(err)
			}
			reqs, err := readRecorded(after[len(before):])
			if err != nil {
				t.Fatal(err)
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
				if v := req.Header.Values(got); len(v) != 1 || v[0] != c.want+c.key {
					t.Errorf("%s %s carried %s %d times, not the key once", req.Method, req.Path, got, len(v))
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
				egress++
				if e.Data["host"] != host || e.Data["decision"] != "allowed" || e.Data["credential"] != "model" {
					t.Errorf("the run reached beyond the recorder, or without the credential: %v", e.Data)
				}
			}
			if egress != len(reqs) {
				t.Errorf("the record lists %d requests through the proxy, and the recorder received %d", egress, len(reqs))
			}
			var where []string
			// dir holds the run directory, res.Dir, under .qory/runs.
			filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
				if err == nil && e.Type().IsRegular() {
					if b, err := os.ReadFile(path); err == nil && bytes.Contains(b, []byte(keyMark)) {
						where = append(where, path)
					}
				}
				return nil
			})
			if strings.Contains(out.String()+errs.String(), keyMark) {
				where = append(where, "the output")
			}
			if len(where) != 0 {
				t.Errorf("a key is in %v", where)
			}
		})
	}
}
