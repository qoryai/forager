package session_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/runner/link"
	"github.com/qoryai/runner/session"
	"github.com/qoryai/runner/wall"
)

// toolMode is the first argument that makes the test binary a tool.
const toolMode = "qory-test-tool"

// fakeTool serves on the socket the runner names, answering every request with 200,
// and appends what it was handed of each to the file its arguments name: the path, the
// path rule and the request's id, one line per request.
func fakeTool(args []string) int {
	record := args[len(args)-1]
	ln, err := net.Listen("unix", os.Getenv("QORY_TOOL_LISTEN"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "serving", strings.Join(args[:len(args)-1], " "))
	var mu sync.Mutex
	http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		f, err := os.OpenFile(record, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%s %s %s %s %v\n", r.Host, r.URL.Path, r.Header.Get("Qory-Path-Rule"), r.Header.Get("Qory-Request-Id"), os.Getenv("QORY_TEST_MODEL_TOKEN") == "")
			f.Close()
		}
		w.Write([]byte("from the tool"))
	}))
	return 0
}

// relayWall is an open wall with a relay: the launch reaches the proxy through a
// listener of the test's that opens every connection with the run's token, as the
// wall's relay does.
type relayWall struct {
	openWall
	ln net.Listener
}

func (w *relayWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *relayWall) Wrap(ctx context.Context, l wall.Launch) (wall.Launch, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return wall.Launch{}, err
	}
	w.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				up, err := net.Dial("tcp", l.Proxy)
				if err != nil {
					return
				}
				defer up.Close()
				fmt.Fprintf(up, "%s %s\n", link.RelayPreamble, l.ProxyToken)
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	relayed := l
	relayed.Proxy = ln.Addr().String()
	return w.openWall.Wrap(ctx, relayed)
}

func (w *relayWall) Close(ctx context.Context) error {
	if w.ln != nil {
		w.ln.Close()
	}
	return w.openWall.Close(ctx)
}

// toolHost is a name that exists nowhere, which the suite's tool serves.
const toolHost = "files.tools.internal"

// toolSpec is a walled run of the fake runtime that reaches the tool on a path the rule
// covers and on one it does not, with the tool that serves it.
func toolSpec(t *testing.T, record string) (session.Spec, *relayWall) {
	t.Helper()
	pol := &session.Policy{Version: 1,
		Egress: session.PolicyEgress{Mode: "enforce", Allow: []string{toolHost}, Paths: map[string][]string{toolHost: {"/media/acme/shop/*"}}},
		Tools:  []session.PolicyTool{{Name: "files", Argument: "acme/shop"}}}
	w := &relayWall{}
	sp := spec(t, pol, "FAKE_EXIT=0", "FAKE_ALLOWED_URL=http://"+toolHost+"/media/acme/shop/a.png", "FAKE_DENIED_URL=http://"+toolHost+"/media/acme/other/a.png")
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.Tools = []session.Tool{{Name: "files", Command: []string{os.Args[0], toolMode, "--prefix", "media/${argument}/", record}, Argument: `[a-z]+/[a-z]+`, Serves: []string{toolHost}, Placeholders: []string{"FILES_KEY"}}}
	return sp, w
}

// TestAToolIsStartedForTheRunAndItsInvocationsRecorded pins a tool behind a wall: it is
// started with the policy's argument before the runtime, without the variable a
// credential is read from, the proxy hands it the
// requests the path rule lets through, with the rule and the request's id, and never
// the one it refuses; every request is one egress event naming the tool, with the
// status it answered and the id it was handed; the record lists the tool and its host
// as terminated; the enclosure gets the authority and the placeholder, never a value.
func TestAToolIsStartedForTheRunAndItsInvocationsRecorded(t *testing.T) {
	t.Setenv("QORY_TEST_MODEL_TOKEN", "the-token-held-outside")
	record := filepath.Join(t.TempDir(), "tool-saw")
	sp, w := toolSpec(t, record)
	sp.Credentials = []session.Credential{{Name: "model", Env: "QORY_TEST_MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer"}}
	var said []string
	var mu sync.Mutex
	sp.Report = func(l string) { mu.Lock(); said = append(said, l); mu.Unlock() }
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d", res.ExitCode)
	}
	saw, _ := os.ReadFile(record)
	lines := strings.Split(strings.TrimSpace(string(saw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("the tool was handed %q", saw)
	}
	f := strings.Fields(lines[0])
	if len(f) != 5 || f[0] != toolHost || f[1] != "/media/acme/shop/a.png" || f[2] != "/media/acme/shop/*" || f[4] != "true" {
		t.Errorf("the tool was handed %q", lines[0])
	}
	evs := events(t, res)
	var invoked, refused map[string]any
	for _, e := range ofType(evs, "dev.qory.run.egress") {
		d := data(e)
		switch d["path"] {
		case "/media/acme/shop/a.png":
			invoked = d
		case "/media/acme/other/a.png":
			refused = d
		}
	}
	if invoked["tool"] != "files" || invoked["status"] != float64(200) || invoked["request_id"] != f[3] || invoked["decision"] != "allowed" || invoked["method"] != "HTTP" {
		t.Errorf("the invocation was recorded as %v", invoked)
	}
	if refused["tool"] != "files" || refused["decision"] != "denied" || refused["outcome"] != "refused" || refused["status"] != nil {
		t.Errorf("the refused request was recorded as %v", refused)
	}
	applied := data(ofType(evs, "dev.qory.run.policy_applied")[0])
	tools, _ := applied["tools"].([]any)
	terminated, _ := applied["terminated"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "files" || len(terminated) != 1 || terminated[0] != toolHost {
		t.Errorf("run.policy_applied %v", applied)
	}
	if !bytes.Contains(w.got.CA, []byte("BEGIN CERTIFICATE")) || !slices.Contains(w.got.Env, "FILES_KEY=qory-sets-the-credential-outside-the-enclosure") {
		t.Errorf("the wall got the authority %q and the environment %v", w.got.CA, w.got.Env)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.ContainsFunc(said, func(l string) bool { return l == "tool files: serving --prefix media/acme/shop/" }) {
		t.Errorf("what the tool wrote was not reported: %q", said)
	}
}

// TestTheRecordListsAToolsArgument pins what an audit of the record reads of the tools
// a run reaches: a tool the policy passes an argument to contains it, the repository it
// is started for, and a tool with no argument in the policy has none in the record.
func TestTheRecordListsAToolsArgument(t *testing.T) {
	sp, _ := toolSpec(t, filepath.Join(t.TempDir(), "tool-saw"))
	const notesHost = "notes.tools.internal"
	pol := *sp.Policy
	pol.Egress.Allow = append(slices.Clone(pol.Egress.Allow), notesHost)
	pol.Tools = append(slices.Clone(pol.Tools), session.PolicyTool{Name: "notes"})
	sp.Policy = &pol
	sp.Tools = append(sp.Tools, session.Tool{Name: "notes", Command: []string{os.Args[0], toolMode, filepath.Join(t.TempDir(), "notes-saw")}, Serves: []string{notesHost}})
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	applied := data(ofType(events(t, res), "dev.qory.run.policy_applied")[0])
	tools, _ := applied["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("run.policy_applied %v", applied)
	}
	for _, e := range tools {
		entry := e.(map[string]any)
		switch entry["name"] {
		case "files":
			if entry["argument"] != "acme/shop" {
				t.Errorf("the tool with an argument %v, want the argument acme/shop", entry)
			}
		case "notes":
			if _, set := entry["argument"]; set {
				t.Errorf("a tool with no argument in the policy has one in the record: %v", entry)
			}
		default:
			t.Errorf("a tool %v", entry["name"])
		}
	}
}

// TestARunWhoseToolsCannotHoldDoesNotStart pins the runs refused before anything
// starts: no wall, a tool nobody defined, an argument the machine does not provide for,
// a host a credential is for as well, a value the run passes for a placeholder, and a
// tool that does not listen.
func TestARunWhoseToolsCannotHoldDoesNotStart(t *testing.T) {
	t.Setenv("QORY_TEST_FILES_TOKEN", "a-token")
	for name, c := range map[string]struct {
		change func(*session.Spec)
		want   string
	}{
		"no wall":                      {func(s *session.Spec) { s.Wall = nil }, "need a wall"},
		"a tool nobody defined":        {func(s *session.Spec) { s.Tools = nil }, "does not define"},
		"an argument not provided for": {func(s *session.Spec) { s.Policy.Tools[0].Argument = "acme/shop/x" }, "not one the machine provides for"},
		"a host a credential is for": {func(s *session.Spec) {
			s.Credentials = []session.Credential{{Name: "files-token", Env: "QORY_TEST_FILES_TOKEN", Hosts: []string{toolHost}, Scheme: "bearer"}}
			s.Policy.Credentials = []session.PolicyCredential{{Name: "files-token"}}
		}, "both claim"},
		"a value for the placeholder": {func(s *session.Spec) { s.Env = append(s.Env, "FILES_KEY=a-real-one") }, "placeholder of a tool"},
		"a tool that does not listen": {func(s *session.Spec) {
			s.Tools[0].Command = []string{"/bin/sh", "-c", "echo no key for the store >&2; exit 4"}
		}, "no key for the store"},
	} {
		sp, _ := toolSpec(t, filepath.Join(t.TempDir(), "tool-saw"))
		pol := *sp.Policy
		pol.Tools = slices.Clone(pol.Tools)
		sp.Policy = &pol
		c.change(&sp)
		if _, err := session.Run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// TestAReloadKeepsTheRunsTools pins that a run's tools are fixed when it starts: a run
// configuration that selects other tools fails the reload and the policy in force
// stays, and one that selects the same tools takes effect and lists them again.
func TestAReloadKeepsTheRunsTools(t *testing.T) {
	c := newControl(t)
	withTools := `{"version":1,"egress":{"mode":"enforce","allow":["` + toolHost + `"%s]},"tools":[{"name":"files","argument":"acme/shop"}]}`
	c.serve(fmt.Sprintf(withTools, ""), digest('1'))
	sp, _ := toolSpec(t, filepath.Join(t.TempDir(), "tool-saw"))
	sp.Policy = nil
	sp.Server, sp.Heartbeat = c.server(), time.Second
	w := startWaiting(t, sp)
	waitFor(t, func() bool { return w.applied() == 1 })

	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["`+toolHost+`"]}}`, digest('2'))
	waitFor(t, func() bool { return w.reported("other tools than the run started with") })

	c.serve(fmt.Sprintf(withTools, `,"api.model.example"`), digest('3'))
	waitFor(t, func() bool { return w.applied() == 2 })

	pa := ofType(w.finish(), "dev.qory.run.policy_applied")
	then := data(pa[1])
	tools, _ := then["tools"].([]any)
	if len(tools) != 1 || then["run_configuration"] != digest('3') {
		t.Errorf("the second policy_applied %v", then)
	}
}
