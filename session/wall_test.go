package session_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/runner/session"
	"github.com/qoryai/runner/session/runtimes"
	"github.com/qoryai/runner/wall"
)

// openWall is a wall with nothing in it: it records what the session sends it
// and starts the launch as it is, pointed at the proxy and the socket by their own
// addresses.
type openWall struct {
	req     wall.Request
	got     wall.Launch
	wrapped bool
	closed  int
}

func (w *openWall) Name() string { return "open" }
func (w *openWall) Prepare(_ context.Context, req wall.Request) (wall.Enclosure, error) {
	w.req = req
	return w, nil
}
func (w *openWall) ProxyAddr() string { return "127.0.0.1:0" }
func (w *openWall) Wrap(_ context.Context, l wall.Launch) (wall.Launch, error) {
	w.got, w.wrapped = l, true
	env := append(append([]string(nil), l.Env...), "HTTP_PROXY=http://"+l.Proxy, session.EnvSocket+"="+l.Socket)
	return wall.Launch{Command: l.Command, Args: l.Args, Env: env, Dir: l.Dir}, nil
}
func (w *openWall) Close(context.Context) error { w.closed++; return nil }

// TestWallWrapsTheLaunch pins what crosses to a wall and what does not: the enclosure
// is asked where the proxy listens and told where it does, it gets the socket, the
// settings the session wrote and the run's environment without the proxy variables, a
// nil environment is nothing and not the process's own, the record names the wall and
// the image, and the enclosure is closed once.
func TestWallWrapsTheLaunch(t *testing.T) {
	t.Setenv("QORY_TEST_HOST_ONLY", "1")
	w := &openWall{}
	sp := spec(t, nil, "FAKE_EXIT=0")
	sp.Wall, sp.Image, sp.Mounts = w, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	res, err := runWithSettingsEnv(t, sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || !w.wrapped || w.closed != 1 {
		t.Errorf("exit %d, wrapped %v, closed %d times", res.ExitCode, w.wrapped, w.closed)
	}
	if w.req.RunID != res.RunID || w.req.Image != "example.com/agent:1" {
		t.Errorf("request %+v", w.req)
	}
	if !strings.HasPrefix(w.got.Proxy, "127.0.0.1:") || strings.HasSuffix(w.got.Proxy, ":0") || w.got.Socket == "" {
		t.Errorf("proxy %q socket %q", w.got.Proxy, w.got.Socket)
	}
	if want := []wall.Mount{{Path: sp.Dir}, {Path: res.Dir, ReadOnly: true}}; !slices.Equal(w.got.Mounts, want) {
		t.Errorf("mounts %v, want %v", w.got.Mounts, want)
	}
	env := strings.Join(w.got.Env, "\n")
	if strings.Contains(env, "PROXY") || strings.Contains(env, session.EnvSocket) || !strings.Contains(env, session.EnvRunID+"="+res.RunID) {
		t.Errorf("the enclosure's environment:\n%s", env)
	}
	evs := events(t, res)
	if d := data(evs[0]); d["wall"] != "open" || d["image"] != "example.com/agent:1" {
		t.Errorf("run.started %v", d)
	}
	if len(ofType(evs, "dev.qory.session.ended")) != 1 {
		t.Errorf("the hook did not cross: %v", types(evs))
	}

	w = &openWall{}
	sp = spec(t, nil)
	sp.Wall, sp.Image, sp.Env = w, "i", nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", `test -z "$QORY_TEST_HOST_ONLY"`}
	if res, err := session.Run(context.Background(), sp); err != nil || res.ExitCode != 0 {
		t.Errorf("a nil environment under a wall carried the process's own: %v %+v", err, res)
	}

	sp = spec(t, nil)
	sp.Wall, sp.ProxyBind = &openWall{}, "127.0.0.1:0"
	if _, err := session.Run(context.Background(), sp); err == nil {
		t.Error("a wall and a proxy address were both accepted")
	}
}

// TestEventsWriterGetsTheRecord pins that the writer gets the lines events.jsonl
// holds, local or not.
func TestEventsWriterGetsTheRecord(t *testing.T) {
	var lines bytes.Buffer
	sp := spec(t, nil, "FAKE_EXIT=0")
	sp.Events, sp.Local = &lines, true
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	file, _ := os.ReadFile(filepath.Join(res.Dir, "events.jsonl"))
	if lines.String() != string(file) || lines.Len() == 0 {
		t.Errorf("the writer got %d bytes, the file holds %d", lines.Len(), len(file))
	}
}

// TestProxyBindIsWhereTheProxyListens pins the bind address: the session is pointed at
// the address given, and one that cannot be bound means no run.
func TestProxyBindIsWhereTheProxyListens(t *testing.T) {
	sp := spec(t, nil)
	sp.ProxyBind = "127.0.0.1:0"
	sp.Command, sp.Args = "/bin/sh", []string{"-c", `case "$HTTP_PROXY" in http://127.0.0.1:*) exit 0;; esac; exit 9`}
	if res, err := session.Run(context.Background(), sp); err != nil || res.ExitCode != 0 {
		t.Errorf("%v %+v", err, res)
	}
	sp = spec(t, nil)
	sp.ProxyBind = "192.0.2.1:0"
	if _, err := session.Run(context.Background(), sp); err == nil {
		t.Error("the run started with a proxy address this machine does not hold")
	}
}

// TestCredentialsCrossAsAnAuthorityAndAPlaceholder pins what a wall is given when the
// run's policy selects a credential: the run authority's certificate and a placeholder,
// never the token; what the record says of it; and the runs that do not start.
func TestCredentialsCrossAsAnAuthorityAndAPlaceholder(t *testing.T) {
	t.Setenv("QORY_TEST_MODEL_TOKEN", "the-token-held-outside")
	defs := []session.Credential{{Name: "model", Env: "QORY_TEST_MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer", Placeholders: []string{"MODEL_TOKEN"}}}
	pol := &session.Policy{Version: 1,
		Egress:      session.PolicyEgress{Mode: "enforce", Allow: []string{"api.model.example", "git.example.com"}, Paths: map[string][]string{"git.example.com": {"/acme/*"}}},
		Credentials: []session.PolicyCredential{{Name: "model"}}}
	w := &openWall{}
	sp := spec(t, pol, "FAKE_EXIT=0")
	sp.Wall, sp.Image, sp.Credentials = w, "example.com/agent:1", defs
	res, err := runWithSettingsEnv(t, sp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(w.got.CA, []byte("BEGIN CERTIFICATE")) || bytes.Contains(w.got.CA, []byte("PRIVATE KEY")) {
		t.Errorf("the wall got %q as the authority", w.got.CA)
	}
	if !slices.ContainsFunc(w.got.Env, func(kv string) bool { return strings.HasPrefix(kv, "MODEL_TOKEN=qory-") }) {
		t.Errorf("no placeholder in %v", w.got.Env)
	}
	record, _ := os.ReadFile(filepath.Join(res.Dir, "events.jsonl"))
	if strings.Contains(strings.Join(w.got.Env, " ")+string(record), "the-token-held-outside") {
		t.Error("the token crossed the wall or reached the record")
	}
	applied := data(ofType(events(t, res), "dev.qory.run.policy_applied")[0])
	creds, _ := applied["credentials"].([]any)
	terminated, _ := applied["terminated"].([]any)
	if len(creds) != 1 || creds[0].(map[string]any)["scheme"] != "bearer" || len(terminated) != 2 || applied["paths"] == nil {
		t.Errorf("run.policy_applied %v", applied)
	}

	for name, change := range map[string]func(*session.Spec){
		"no wall":                            func(s *session.Spec) { s.Wall = nil },
		"a credential nobody defined":        func(s *session.Spec) { s.Credentials = nil },
		"a value passed for the placeholder": func(s *session.Spec) { s.Env = append(s.Env, "MODEL_TOKEN=a-real-one") },
	} {
		sp := spec(t, pol)
		sp.Wall, sp.Image, sp.Credentials = &openWall{}, "example.com/agent:1", defs
		change(&sp)
		if _, err := session.Run(context.Background(), sp); err == nil {
			t.Errorf("%s: the run started", name)
		}
	}
}

// TestTheRecordListsACredentialsArgument pins what an audit of the record reads of a
// credential an adapter mints: every use of it contains the argument the policy passed,
// the repository the token is for, and a credential with no argument in the policy has
// none in the record.
func TestTheRecordListsACredentialsArgument(t *testing.T) {
	t.Setenv("QORY_TEST_MODEL_TOKEN", "the-token-held-outside")
	adapter := filepath.Join(t.TempDir(), "adapter")
	answer := `#!/bin/sh
cat <<JSON
{"version": 1, "token": "token-for-$1", "expires_at": "2099-01-01T00:00:00Z",
 "apply": [
  {"hosts": ["git.example.com"], "scheme": "basic", "username": "x-access-token", "paths": ["/$1.git/*"]},
  {"hosts": ["api.git.example.com"], "scheme": "bearer", "paths": ["/repos/$1", "/repos/$1/*"]}]}
JSON
`
	if err := os.WriteFile(adapter, []byte(answer), 0o755); err != nil {
		t.Fatal(err)
	}
	defs := []session.Credential{
		{Name: "model", Env: "QORY_TEST_MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer"},
		{Name: "git", Adapter: []string{adapter, "${argument}"}, Argument: `[a-z0-9-]+/[a-z0-9-]+`},
	}
	pol := &session.Policy{Version: 1,
		Egress:      session.PolicyEgress{Mode: "enforce", Allow: []string{"api.model.example", "git.example.com", "api.git.example.com"}},
		Credentials: []session.PolicyCredential{{Name: "model"}, {Name: "git", Argument: "acme/shop"}}}
	sp := spec(t, pol, "FAKE_EXIT=0")
	sp.Wall, sp.Image, sp.Credentials = &openWall{}, "example.com/agent:1", defs
	res, err := runWithSettingsEnv(t, sp)
	if err != nil {
		t.Fatal(err)
	}
	applied := data(ofType(events(t, res), "dev.qory.run.policy_applied")[0])
	creds, _ := applied["credentials"].([]any)
	if len(creds) != 3 {
		t.Fatalf("run.policy_applied %v", applied)
	}
	for _, c := range creds {
		use := c.(map[string]any)
		switch use["name"] {
		case "model":
			if _, set := use["argument"]; set {
				t.Errorf("a credential with no argument in the policy has one in the record: %v", use)
			}
		case "git":
			if use["argument"] != "acme/shop" {
				t.Errorf("a use of the adapter's credential %v, want the argument acme/shop", use)
			}
		default:
			t.Errorf("a use of %v", use["name"])
		}
	}
	record, _ := os.ReadFile(filepath.Join(res.Dir, "events.jsonl"))
	if strings.Contains(string(record), "token-for-") || strings.Contains(string(record), "the-token-held-outside") {
		t.Error("a token reached the record")
	}
}

// TestAReloadBehindAWallBringsCredentialsAndPaths pins the other half: behind a wall a
// run with a server always has its authority, given to the enclosure at the start, so
// a reloaded run configuration's path rules are held and its credentials resolved and
// set, as a start's are, and recorded; a credential nobody defined fails the reload
// and the policy in force stays.
func TestAReloadBehindAWallBringsCredentialsAndPaths(t *testing.T) {
	t.Setenv("QORY_TEST_MODEL_TOKEN", "the-token-held-outside")
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]}}`, digest('1'))
	ow := &openWall{}
	sp := spec(t, nil, "FAKE_EXIT=0")
	sp.Server, sp.Heartbeat = c.server(), time.Second
	sp.Wall, sp.Image = ow, "example.com/agent:1"
	sp.Credentials = []session.Credential{{Name: "model", Env: "QORY_TEST_MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer"}}
	w := startWaiting(t, sp)
	waitFor(t, func() bool { return w.applied() == 1 })
	if !bytes.Contains(ow.got.CA, []byte("BEGIN CERTIFICATE")) {
		t.Errorf("a walled run with a server got %q as the authority", ow.got.CA)
	}

	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example","git.example.com"],"paths":{"git.example.com":["/acme/*"]}},"credentials":[{"name":"model"}]}`, digest('2'))
	waitFor(t, func() bool { return w.applied() == 2 })

	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]},"credentials":[{"name":"nobody-defined"}]}`, digest('3'))
	waitFor(t, func() bool { return w.reported("the policy in force stays") })

	evs := w.finish()
	pa := ofType(evs, "dev.qory.run.policy_applied")
	if len(pa) != 2 {
		t.Fatalf("policy_applied events: %v", pa)
	}
	if first := data(pa[0]); first["credentials"] != nil || first["terminated"] != nil {
		t.Errorf("the first policy_applied %v", first)
	}
	then := data(pa[1])
	creds, _ := then["credentials"].([]any)
	terminated, _ := then["terminated"].([]any)
	if len(creds) != 1 || creds[0].(map[string]any)["name"] != "model" || len(terminated) != 2 || then["paths"] == nil || then["run_configuration"] != digest('2') {
		t.Errorf("the second policy_applied %v", then)
	}
	record, _ := os.ReadFile(filepath.Join(w.res.Dir, "events.jsonl"))
	if strings.Contains(string(record), "the-token-held-outside") {
		t.Error("the token reached the record")
	}
}

// attached is a runtime that keeps the Attach its Prepare receives.
type attached struct {
	runtimes.Runtime
	got runtimes.Attach
}

func (a *attached) Prepare(at runtimes.Attach) (runtimes.Launch, error) {
	a.got = at
	return a.Runtime.Prepare(at)
}

// TestPrepareIsGivenTheStandInsOfAWalledRun pins what a runtime learns of the stand-ins:
// behind a wall, the variables the enclosure gets a stand-in in, a credential's and a
// tool's; without one, none, since then there are none.
func TestPrepareIsGivenTheStandInsOfAWalledRun(t *testing.T) {
	t.Setenv("QORY_TEST_MODEL_TOKEN", "the-token-held-outside")
	sp, _ := toolSpec(t, filepath.Join(t.TempDir(), "invocations"))
	sp.Credentials = []session.Credential{{Name: "model", Env: "QORY_TEST_MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer", Placeholders: []string{"MODEL_TOKEN"}}}
	sp.Policy.Credentials = []session.PolicyCredential{{Name: "model"}}
	sp.Policy.Egress.Allow = append(sp.Policy.Egress.Allow, "api.model.example")
	rt := &attached{Runtime: sp.Runtime}
	sp.Runtime = rt
	if _, err := runWithSettingsEnv(t, sp); err != nil {
		t.Fatal(err)
	}
	if want := []string{"MODEL_TOKEN", "FILES_KEY"}; !slices.Equal(rt.got.Placeholders, want) {
		t.Errorf("Prepare received %v, want %v", rt.got.Placeholders, want)
	}

	sp = spec(t, nil, "FAKE_EXIT=0")
	rt = &attached{Runtime: sp.Runtime}
	sp.Runtime = rt
	if _, err := runWithSettingsEnv(t, sp); err != nil {
		t.Fatal(err)
	}
	if len(rt.got.Placeholders) != 0 || rt.got.RunDir == "" {
		t.Errorf("Prepare received %v without a wall", rt.got.Placeholders)
	}
}
