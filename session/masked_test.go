package session_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/sink"
)

// The tests of this file run without a wall, where the agent's proxy URL contains the
// forwarder's password, and the runtime prints that URL: the password reaches no event
// and not output.log, and the URL is there with qory-proxy-password in its place.

// passwordPattern finds the forwarder's password in an environment env printed.
var passwordPattern = regexp.MustCompile(`(?m)^HTTP_PROXY=http://qory:([A-Za-z0-9_-]{43})@127\.0\.0\.1:[0-9]+$`)

// maskedURL is the start of the agent's proxy URL as output.log has it.
const maskedURL = "http://qory:qory-proxy-password@127.0.0.1:"

// printedEnv sets the spec to run sh with the script, after it writes its environment
// to a file, and returns that file.
func printedEnv(t *testing.T, sp *runSpec, script string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "env")
	sp.Forwarder = nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", `env > "$0"; ` + script, out}
	return out
}

// forwarderPassword is the password in the environment the file at path contains.
func forwarderPassword(t *testing.T, path string) string {
	t.Helper()
	env, _ := os.ReadFile(path)
	m := passwordPattern.FindSubmatch(env)
	if m == nil {
		t.Fatalf("the agent's environment has no proxy URL with a password:\n%s", env)
	}
	return string(m[1])
}

// noPassword fails the test when output.log, session.jsonl or one of its run.log
// chunks, decoded, contains secret, and returns output.log.
func noPassword(t *testing.T, res *session.Result, secret string) string {
	t.Helper()
	out, _ := os.ReadFile(filepath.Join(res.Dir, sink.OutputFile))
	if strings.Contains(string(out), secret) {
		t.Errorf("output.log contains the forwarder's password:\n%s", out)
	}
	if b, _ := os.ReadFile(filepath.Join(res.Dir, sink.SessionFile)); bytes.Contains(b, []byte(secret)) {
		t.Error("session.jsonl contains the forwarder's password")
	}
	for _, l := range ofType(events(t, res), event.RunLog) {
		b, err := base64.StdEncoding.DecodeString(data(l)["bytes"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), secret) {
			t.Errorf("a run.log chunk contains the forwarder's password: %q", b)
		}
	}
	return string(out)
}

// TestOutputLogHasNoForwarderPasswordOnPipes pins a runtime on pipes that prints its
// environment: output.log has the proxy URL with qory-proxy-password, and neither it
// nor session.jsonl contains the password.
func TestOutputLogHasNoForwarderPasswordOnPipes(t *testing.T) {
	sp := spec(t)
	envFile := printedEnv(t, &sp, "env")
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	out := noPassword(t, res, forwarderPassword(t, envFile))
	if !strings.Contains(out, "HTTP_PROXY="+maskedURL) {
		t.Errorf("output.log has no masked proxy URL:\n%s", out)
	}
}

// TestOutputLogHasNoForwarderPasswordOnATerminal is the same on a pseudo-terminal.
func TestOutputLogHasNoForwarderPasswordOnATerminal(t *testing.T) {
	sp := spec(t)
	sp.Interactive = true
	envFile := printedEnv(t, &sp, "env")
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if l := ofType(events(t, res), event.RunLog); len(l) == 0 || data(l[0])["stream"] != "terminal" {
		t.Fatalf("log %v; want the terminal stream", l)
	}
	out := noPassword(t, res, forwarderPassword(t, envFile))
	if !strings.Contains(out, "HTTP_PROXY="+maskedURL) {
		t.Errorf("output.log has no masked proxy URL:\n%q", out)
	}
}

// TestOutputLogHasNoBasicFormOfTheForwarderPassword pins the Proxy-Authorization header
// a runtime prints: its base64 of qory and the password is the base64 of
// qory:qory-proxy-password in output.log.
func TestOutputLogHasNoBasicFormOfTheForwarderPassword(t *testing.T) {
	sp := spec(t)
	envFile := printedEnv(t, &sp, `pw=${HTTP_PROXY#http://qory:}; pw=${pw%@*}; printf 'Proxy-Authorization: Basic %s\n' "$(printf 'qory:%s' "$pw" | base64)"`)
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	basic := base64.StdEncoding.EncodeToString([]byte("qory:" + forwarderPassword(t, envFile)))
	out := noPassword(t, res, basic)
	if want := "Proxy-Authorization: Basic cW9yeTpxb3J5LXByb3h5LXBhc3N3b3Jk\n"; out != want {
		t.Errorf("output.log %q, want %q", out, want)
	}
}

// TestAnOutputRecordHasNoForwarderPassword pins a record of the runtime's output that
// contains the proxy URL, as a tool's result with a printed environment does: the
// event it maps to has qory-proxy-password in the password's place.
func TestAnOutputRecordHasNoForwarderPassword(t *testing.T) {
	sp := spec(t)
	envFile := printedEnv(t, &sp, `printf '{"type":"result","subtype":"success","session_id":"fake","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.01,"result":"HTTP_PROXY=%s"}\n' "$HTTP_PROXY"`)
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	noPassword(t, res, forwarderPassword(t, envFile))
	r := ofType(events(t, res), "dev.qory.runtime.result")
	if len(r) != 1 {
		t.Fatalf("runtime.result %v", r)
	}
	if got, _ := data(r[0])["result"].(string); !strings.HasPrefix(got, "HTTP_PROXY="+maskedURL) {
		t.Errorf("runtime.result's result %q", got)
	}
}
