package session_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/session/internal/socket"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/claude"
)

// refusal returns the code of a refusal, or the error's text.
func refusal(err error) string {
	var r *session.Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	if err == nil {
		return "nil"
	}
	return err.Error()
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// TestMain lets the test binary stand in for a runtime and for the hook forwarder, so
// no real runtime and no shell script are needed: with FAKE_RUNTIME set it acts as a
// runtime, and with QORY_TEST_FORWARD set as the forwarder.
func TestMain(m *testing.M) {
	switch {
	case os.Getenv("QORY_TEST_FORWARD") != "":
		if err := socket.Forward(context.Background(), os.Getenv(session.EnvSocket), os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	case os.Getenv("FAKE_RUNTIME") != "":
		os.Exit(fakeRuntime())
	}
	// The registry of walled runs is the tests' own, not this user's.
	state, err := os.MkdirTemp("", "session-state-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Setenv("XDG_STATE_HOME", state)
	code := m.Run()
	os.RemoveAll(state)
	os.Exit(code)
}

// fakeRuntime prints what a headless runtime prints, reaches two hosts through the
// proxy, calls its hook the way a runtime calls a command hook, and exits as told. It
// sends its requests through HTTP_PROXY explicitly, because the origins are on
// loopback, which Forager's NO_PROXY exempts and Go never proxies.
func fakeRuntime() int {
	fmt.Println(`{"type":"system","subtype":"init","session_id":"fake","model":"m"}`)
	fmt.Fprintln(os.Stderr, "fake runtime: starting")
	proxyURL, _ := url.Parse(os.Getenv("HTTP_PROXY"))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	for _, u := range []string{os.Getenv("FAKE_ALLOWED_URL"), os.Getenv("FAKE_DENIED_URL")} {
		if u == "" {
			continue
		}
		resp, err := client.Get(u)
		if err != nil {
			fmt.Fprintln(os.Stderr, "get:", err)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		fmt.Fprintf(os.Stderr, "get %s: %d\n", u, resp.StatusCode)
	}
	if settings := os.Getenv("FAKE_SETTINGS"); settings != "" {
		// Call the hook the settings name, as the runtime would, with a SessionEnd input.
		b, _ := os.ReadFile(settings)
		var s struct {
			Hooks map[string][]struct {
				Hooks []struct{ Command string } `json:"hooks"`
			} `json:"hooks"`
		}
		if err := json.Unmarshal(b, &s); err != nil || len(s.Hooks["SessionEnd"]) == 0 {
			fmt.Fprintln(os.Stderr, "no SessionEnd hook installed:", err)
			return 90
		}
		// Every group's every hook runs, as the runtime runs them: the launch's own and
		// the session's forwarder.
		for _, group := range s.Hooks["SessionEnd"] {
			for _, h := range group.Hooks {
				cmd := shell(h.Command)
				cmd.Stdin = strings.NewReader(`{"session_id":"fake","hook_event_name":"SessionEnd","reason":"other","cwd":"/"}`)
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					fmt.Fprintln(os.Stderr, "hook:", err)
					return 91
				}
			}
		}
	}
	fmt.Println(`{"type":"result","subtype":"success","session_id":"fake","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.01,"result":"done"}`)
	time.Sleep(60 * time.Millisecond)
	code := 0
	fmt.Sscan(os.Getenv("FAKE_EXIT"), &code)
	return code
}

// spec returns a spec running the fake runtime with the given environment, in a fresh
// checkout directory, with its run directories beside it, speaking to a fake gateway
// of its own.
func spec(t *testing.T, env ...string) session.Spec {
	t.Helper()
	sp, _ := specGateway(t, env...)
	return sp
}

// specGateway is spec and the fake gateway it speaks to.
func specGateway(t *testing.T, env ...string) (session.Spec, *linktest.Fake) {
	t.Helper()
	dir := t.TempDir()
	var out, errs bytes.Buffer
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("stdout:\n%s\nstderr:\n%s", out.String(), errs.String())
		}
	})
	g := linktest.StartFake(t)
	g.SetInterval(30)
	return session.Spec{
		Runtime:        claudeCode(t),
		Command:        os.Args[0],
		Args:           []string{"--settings", writeSettings(t, dir)},
		Env:            append([]string{"FAKE_RUNTIME=1", "PATH=" + os.Getenv("PATH")}, env...),
		Dir:            dir,
		RunsDir:        filepath.Join(t.TempDir(), "runs"),
		Stdin:          strings.NewReader(""),
		Stdout:         &out,
		Stderr:         &errs,
		Gateway:        session.LocalGateway(g.Local()),
		Forwarder:      []string{"env", "QORY_TEST_FORWARD=1", os.Args[0]},
		ForagerVersion: "test",
		Report:         func(l string) { t.Log("report:", l) },
	}, g
}

// claudeCode is the runtime most tests run as: the contract's descriptor for Claude
// Code, in front of a program of the test's own.
func claudeCode(t *testing.T) runtimes.Runtime {
	t.Helper()
	rt, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func writeSettings(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "launch-settings.json")
	if err := os.WriteFile(p, []byte(`{"permissions":{"allow":["Bash"]},"hooks":{"SessionEnd":[{"hooks":[{"type":"command","command":"echo existing"}]}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// events reads and validates the session's record, session.jsonl, and returns its
// events by index.
func events(t *testing.T, res *session.Result) []map[string]any {
	t.Helper()
	schema, err := contracts.Compile("event.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(res.Dir, "session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	s := bufio.NewScanner(f)
	s.Buffer(nil, 1<<20)
	for n := 1; s.Scan(); n++ {
		doc, err := contracts.Decode("events.jsonl", s.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("session.jsonl:%d: %v\n%s", n, err, s.Bytes())
		}
		var m map[string]any
		json.Unmarshal(s.Bytes(), &m)
		if want := fmt.Sprintf("%010d", n); m["sequence"] != want {
			t.Errorf("session.jsonl:%d: sequence %v", n, m["sequence"])
		}
		out = append(out, m)
	}
	return out
}

func ofType(evs []map[string]any, typ string) []map[string]any {
	var out []map[string]any
	for _, e := range evs {
		if e["type"] == typ {
			out = append(out, e)
		}
	}
	return out
}

func data(e map[string]any) map[string]any { return e["data"].(map[string]any) }

// TestRunRecordsAndExitsWithTheRuntimesStatus is the run end to end on pipes: the
// members of policy_applied the gateway decides are recorded as its run answer gives
// them, beside the harness's hosts, both requests go to the gateway's proxy through the
// forwarder, the runtime's output is logged per stream and mapped to session.result,
// the installed hook reaches the socket and becomes session.ended, and the exit status
// is the runtime's.
func TestRunRecordsAndExitsWithTheRuntimesStatus(t *testing.T) {
	sp, g := specGateway(t, "FAKE_ALLOWED_URL=http://api.example/allowed", "FAKE_DENIED_URL=http://tracker.example/denied", "FAKE_EXIT=3")
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["policy"] = map[string]any{"version": 1, "egress": map[string]any{"mode": "enforce", "allow": []string{"api.example"}, "deny": []string{"tracker.example"}}}
		a["digest"] = strings.Repeat("d", 64)
		a["applied"] = map[string]any{"mode": "enforce", "allow": []string{"api.example"}, "deny": []string{"tracker.example"}, "source": "config", "digest": strings.Repeat("d", 64)}
		return linktest.Reply{Status: 200, Body: a}
	})
	sp.Declared = []string{"api.example", "registry.example"}
	res, err := runWithSettingsEnv(t, sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 3 || res.State != "failed" || res.Signal != "" || res.RunClosed {
		t.Errorf("result %+v", res)
	}
	evs := events(t, res)
	if len(evs) < 6 || evs[0]["type"] != "dev.qory.run.started" || evs[1]["type"] != "dev.qory.run.policy_applied" || evs[len(evs)-1]["type"] != "dev.qory.run.exited" {
		t.Fatalf("event order: %v", types(evs))
	}
	if started := data(evs[0]); started["opened_by"] != "session" {
		t.Errorf("run.started opened_by %v; want session", started["opened_by"])
	}
	applied := data(evs[1])
	if applied["mode"] != "enforce" || applied["source"] != "config" || fmt.Sprint(applied["allow"]) != "[api.example]" || fmt.Sprint(applied["harness_hosts"]) != "[api.example registry.example]" || fmt.Sprint(applied["deny"]) != "[tracker.example]" || applied["digest"] != strings.Repeat("d", 64) || applied["variables"] == nil || len(applied) != 7 {
		t.Errorf("policy_applied %v", applied)
	}
	if got := g.Proxied(); len(got) != 2 || got[0] != "GET http://api.example/allowed" || got[1] != "GET http://tracker.example/denied" {
		t.Errorf("the gateway's proxy saw %q", got)
	}
	streams := map[string]bool{}
	for _, l := range ofType(evs, "dev.qory.run.log") {
		streams[data(l)["stream"].(string)] = true
	}
	if !streams["stdout"] || !streams["stderr"] {
		t.Errorf("log streams %v", streams)
	}
	if r := ofType(evs, "dev.qory.session.result"); len(r) != 1 || data(r[0])["outcome"] != "success" || data(r[0])["result"] != "done" {
		t.Errorf("session.result %v", r)
	}
	if e := ofType(evs, "dev.qory.session.ended"); len(e) != 1 || data(e[0])["reason"] != "other" {
		t.Errorf("session.ended %v", e)
	}
	exited := data(evs[len(evs)-1])
	if exited["state"] != "failed" || exited["exit_code"] != 3.0 || exited["reason"] != nil {
		t.Errorf("exited %v", exited)
	}
	out, _ := os.ReadFile(filepath.Join(res.Dir, "output.log"))
	if !strings.Contains(string(out), `"type":"result"`) || !strings.Contains(string(out), "fake runtime: starting") {
		t.Errorf("output.log %q", out)
	}
	settings, _ := os.ReadFile(filepath.Join(res.Dir, "settings.json"))
	if !strings.Contains(string(settings), `"echo existing"`) || !strings.Contains(string(settings), `"permissions"`) || strings.Count(string(settings), os.Args[0]) != 11 {
		t.Errorf("settings.json:\n%s", settings)
	}
	// The gateway writes the run's stream and its delivery state; the session writes
	// none of them.
	for _, name := range []string{"events.jsonl", "delivered.log", "undelivered"} {
		if _, err := os.Stat(filepath.Join(res.Dir, name)); !os.IsNotExist(err) {
			t.Errorf("the session wrote %s", name)
		}
	}
	// Every event of the session's record reached the gateway, in its order, without
	// its sequence.
	posted := g.Events()
	if len(posted) != len(evs) {
		t.Fatalf("the gateway received %d events, the record holds %d: %v", len(posted), len(evs), types(posted))
	}
	for i, e := range posted {
		if e["id"] != evs[i]["id"] || e["type"] != evs[i]["type"] || e["sequence"] != nil {
			t.Errorf("posted event %d: %v; recorded %v", i, e, evs[i])
		}
	}
}

// runWithSettingsEnv runs the spec with FAKE_SETTINGS pointing at the settings file
// the session writes, which is only known once the run directory exists: the run id is
// fixed in advance so the path is known.
func runWithSettingsEnv(t *testing.T, sp session.Spec) (*session.Result, error) {
	t.Helper()
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	sp.Env = append(sp.Env, "FAKE_SETTINGS="+filepath.Join(sp.RunsDir, sp.RunID, "settings.json"))
	return session.Run(context.Background(), sp)
}

func types(evs []map[string]any) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e["type"].(string))
	}
	return out
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestInteractiveRunsOnAPseudoTerminal pins the PTY path: the output is one terminal
// stream with the terminal's line endings, and the exit status is the program's.
func TestInteractiveRunsOnAPseudoTerminal(t *testing.T) {
	sp := spec(t)
	sp.Forwarder = nil
	sp.Interactive = true
	sp.Command = "sh"
	sp.Args = []string{"-c", "echo hello; exit 4"}
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 4 {
		t.Errorf("exit %d", res.ExitCode)
	}
	out, _ := os.ReadFile(filepath.Join(res.Dir, "output.log"))
	if string(out) != "hello\r\n" {
		t.Errorf("output.log %q", out)
	}
	if l := ofType(events(t, res), "dev.qory.run.log"); len(l) != 1 || data(l[0])["stream"] != "terminal" {
		t.Errorf("log %v", l)
	}
	if size := data(events(t, res)[0])["terminal"]; fmt.Sprint(size) != "map[cols:80 rows:24]" {
		t.Errorf("run.started terminal %v; want the default when stdin is not a terminal", size)
	}
}

// TestAHeadlessArgumentRunsOnPipesWhateverTheCallerHas pins the inference: a caller at
// a terminal that starts the runtime with an argument its descriptor names as headless,
// -p for Claude Code, gets a session on pipes, recorded as not interactive and with its
// structured output read, exactly as if it had said headless. A runtime that names no
// such argument keeps the caller's pseudo-terminal, -p or not.
func TestAHeadlessArgumentRunsOnPipesWhateverTheCallerHas(t *testing.T) {
	t.Run("the descriptor names it", func(t *testing.T) {
		sp := spec(t)
		sp.Interactive = true
		sp.Args = append(sp.Args, "-p", "Reply pong")
		res, err := session.Run(context.Background(), sp)
		if err != nil {
			t.Fatal(err)
		}
		evs := events(t, res)
		started := data(evs[0])
		if started["interactive"] != false || started["terminal"] != nil {
			t.Errorf("run.started %v; want not interactive and no terminal size", started)
		}
		if l := ofType(evs, "dev.qory.run.log"); len(l) == 0 || data(l[0])["stream"] == "terminal" {
			t.Errorf("log %v; want the streams of pipes", l)
		}
		if r := ofType(evs, "dev.qory.session.result"); len(r) != 1 || data(r[0])["result"] != "done" {
			t.Errorf("session.result %v; want the output read", r)
		}
	})
	t.Run("the runtime names none", func(t *testing.T) {
		sp := spec(t)
		sp.Forwarder = nil
		sp.Interactive = true
		sp.Runtime = runtimes.Bare("other-agent")
		sp.Command = "sh"
		sp.Args = []string{"-c", "echo hello", "sh", "-p"}
		res, err := session.Run(context.Background(), sp)
		if err != nil {
			t.Fatal(err)
		}
		evs := events(t, res)
		if started := data(evs[0]); started["interactive"] != true || started["terminal"] == nil {
			t.Errorf("run.started %v; want the caller's terminal kept", started)
		}
		if l := ofType(evs, "dev.qory.run.log"); len(l) != 1 || data(l[0])["stream"] != "terminal" {
			t.Errorf("log %v", l)
		}
	})
}

// TestInteractiveRunFollowsTheTerminalSize pins the size in the record: the
// pseudo-terminal starts at the size of the terminal stdin is, reported in run.started,
// and when that terminal is resized the pseudo-terminal follows and run.resized says so
// at the sequence where it did, before the output drawn on the new size.
func TestInteractiveRunFollowsTheTerminalSize(t *testing.T) {
	master, tty, err := pty.Open()
	if err != nil {
		t.Skip("no pseudo-terminal:", err)
	}
	defer master.Close()
	defer tty.Close()
	if err := pty.Setsize(master, &pty.Winsize{Cols: 100, Rows: 40}); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	sp := spec(t)
	sp.Forwarder = nil
	sp.Interactive = true
	sp.Stdin = tty
	sp.Stdout = &out
	sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	record := filepath.Join(sp.RunsDir, sp.RunID, "session.jsonl")
	sp.Command = "sh"
	sp.Args = []string{"-c", "stty size; read line; stty size"}
	done := make(chan *session.Result, 1)
	go func() {
		res, err := session.Run(context.Background(), sp)
		if err != nil {
			t.Error(err)
		}
		done <- res
	}()
	waitFor(t, func() bool { return strings.Contains(out.String(), "40 100") })
	if err := pty.Setsize(master, &pty.Winsize{Cols: 120, Rows: 50}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { b, _ := os.ReadFile(record); return bytes.Contains(b, []byte(`"dev.qory.run.resized"`)) })
	if _, err := io.WriteString(master, "go\n"); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res == nil {
		t.FailNow()
	}
	evs := events(t, res)
	if size := data(evs[0])["terminal"]; fmt.Sprint(size) != "map[cols:100 rows:40]" {
		t.Errorf("run.started terminal %v", size)
	}
	resized := ofType(evs, "dev.qory.run.resized")
	if len(resized) != 1 || fmt.Sprint(data(resized[0])) != "map[cols:120 rows:50]" {
		t.Fatalf("run.resized %v", resized)
	}
	// The sequence: what was drawn before the resize is logged before it, what was
	// drawn after it after.
	var before, after []byte
	seen := false
	for _, e := range evs {
		if e["type"] == "dev.qory.run.resized" {
			seen = true
		} else if e["type"] == "dev.qory.run.log" {
			b, _ := base64.StdEncoding.DecodeString(data(e)["bytes"].(string))
			if seen {
				after = append(after, b...)
			} else {
				before = append(before, b...)
			}
		}
	}
	if !strings.Contains(string(before), "40 100") || strings.Contains(string(before), "50 120") {
		t.Errorf("logged before the resize: %q", before)
	}
	if !strings.Contains(string(after), "50 120") {
		t.Errorf("logged after the resize: %q", after)
	}
}

// syncBuffer is a buffer written from the run and read by the test.
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

// TestContextEndStopsTheRuntime pins that a cancelled context ends the session with a
// signal, recorded as such.
func TestContextEndStopsTheRuntime(t *testing.T) {
	sp := spec(t)
	sp.Forwarder = nil
	sp.Command = "sh"
	sp.Args = []string{"-c", "sleep 30"}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	res, err := session.Run(ctx, sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != -1 || res.Signal != "SIGTERM" || res.State != "failed" {
		t.Errorf("result %+v", res)
	}
}

func TestTimeoutStopsTheRuntimeAndIsTheReason(t *testing.T) {
	sp := spec(t)
	sp.Forwarder = nil
	sp.Command = "sh"
	sp.Args = []string{"-c", "sleep 30"}
	sp.Timeout = 300 * time.Millisecond
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.Signal != "SIGTERM" || res.State != "failed" {
		t.Errorf("result %+v", res)
	}
	exited := ofType(events(t, res), "dev.qory.run.exited")
	if len(exited) != 1 || data(exited[0])["reason"] != "timeout" {
		t.Errorf("run.exited %v", exited)
	}
	// A limit that was not reached is not a reason.
	sp = spec(t)
	sp.Timeout = time.Minute
	if res, err = runWithSettingsEnv(t, sp); err != nil {
		t.Fatal(err)
	}
	if exited := ofType(events(t, res), "dev.qory.run.exited"); res.TimedOut || data(exited[0])["reason"] != nil {
		t.Errorf("a run within its limit timed out: %+v %v", res, exited)
	}
}

func TestRunIDAndLabelsAreTheCallers(t *testing.T) {
	const id = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	sp := spec(t)
	sp.RunID = id
	sp.Labels = map[string]string{"run_key": "queue/1234", "repository": "acme/shop", "issue": "77"}
	res, err := runWithSettingsEnv(t, sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.RunID != id || filepath.Base(res.Dir) != id {
		t.Errorf("result %+v", res)
	}
	started := ofType(events(t, res), "dev.qory.run.started")
	if labels, _ := data(started[0])["labels"].(map[string]any); len(labels) != 3 || labels["run_key"] != "queue/1234" {
		t.Errorf("run.started %v", started)
	}
	many := map[string]string{}
	for i := range session.MaxLabels + 1 {
		many[fmt.Sprint("k", i)] = "v"
	}
	for name, change := range map[string]func(*session.Spec){
		"a path as the run id":  func(s *session.Spec) { s.RunID = "../../elsewhere" },
		"an upper-case run id":  func(s *session.Spec) { s.RunID = strings.ToUpper(id) },
		"an upper-case key":     func(s *session.Spec) { s.Labels = map[string]string{"Repo": "x"} },
		"an empty key":          func(s *session.Spec) { s.Labels = map[string]string{"": "x"} },
		"a long value":          func(s *session.Spec) { s.Labels = map[string]string{"k": strings.Repeat("v", 257)} },
		"too many labels":       func(s *session.Spec) { s.Labels = many },
		"a negative time limit": func(s *session.Spec) { s.Timeout = -time.Second },
	} {
		sp := spec(t)
		change(&sp)
		if _, err := session.Run(context.Background(), sp); err == nil {
			t.Errorf("%s: the run started", name)
		}
		if entries, _ := os.ReadDir(sp.RunsDir); len(entries) > 0 {
			t.Errorf("%s: a run directory was made: %v", name, entries)
		}
	}
}

// TestAboutIsInRunStartedAlone pins what the run is about: an About CheckAbout refuses
// is no run, before the gateway sees a request or a run directory is made; a valid one
// is in the run request and in run.started as the caller passed it, details compacted,
// and in no other event; an empty one leaves no about.
func TestAboutIsInRunStartedAlone(t *testing.T) {
	sp, g := specGateway(t)
	sp.Forwarder = nil
	sp.About = &session.About{Title: "Example",
		Subjects: []session.Subject{{Type: "example"}}}
	_, err := session.Run(context.Background(), sp)
	var ae *session.AboutError
	if !errors.As(err, &ae) || err.Error() != "about.subjects[0].ref is empty" {
		t.Errorf("an About without a ref: %v", err)
	}
	if n := g.Accepted.Load() + g.Rejected.Load(); n != 0 {
		t.Errorf("the gateway saw %d connections of a refused run", n)
	}
	if entries, _ := os.ReadDir(sp.RunsDir); len(entries) > 0 {
		t.Errorf("a run directory was made: %v", entries)
	}

	sp, g = specGateway(t)
	sp.Forwarder = nil
	sp.Labels = map[string]string{"forge": "example.test"}
	sp.About = &session.About{
		Kind:  "example-kind",
		Title: "Example title of the run",
		Subjects: []session.Subject{
			{Type: "example", Ref: "example-ref-7", URL: "https://qory.example/examples/7",
				Title: "Example subject title"},
			{Type: "example.other", Ref: "example-ref-8"},
		},
		Details: json.RawMessage(`{ "example-key" : [ 1, { "b" : { "c" : true } } ] }`),
	}
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	want := `"about":{"kind":"example-kind","title":"Example title of the run",` +
		`"subjects":[{"type":"example","ref":"example-ref-7",` +
		`"url":"https://qory.example/examples/7","title":"Example subject title"},` +
		`{"type":"example.other","ref":"example-ref-8"}],` +
		`"details":{"example-key":[1,{"b":{"c":true}}]}}`
	b, err := os.ReadFile(filepath.Join(res.Dir, "session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	evs := events(t, res)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != len(evs) {
		t.Fatalf("%d lines for %d events", len(lines), len(evs))
	}
	started := 0
	for i, line := range lines {
		if evs[i]["type"] == "dev.qory.run.started" {
			started++
			if !strings.Contains(line, want) {
				t.Errorf("run.started does not contain %s:\n%s", want, line)
			}
			continue
		}
		_, ok := data(evs[i])["about"]
		if ok || strings.Contains(line, "example-ref-7") ||
			strings.Contains(line, "example-key") ||
			strings.Contains(line, "Example title of the run") {
			t.Errorf("%s contains the about:\n%s", evs[i]["type"], line)
		}
	}
	if started != 1 {
		t.Errorf("%d run.started events", started)
	}
	if raw := g.RawRequests(); len(raw) != 1 || !strings.Contains(string(raw[0]), `"details":{"example-key":[1,{"b":{"c":true}}]}`) || !strings.Contains(string(raw[0]), `"labels":{"forge":"example.test"}`) {
		t.Errorf("the run request %s", raw)
	}

	sp = spec(t)
	sp.Forwarder = nil
	sp.About = &session.About{Details: json.RawMessage(" { } ")}
	if res, err = session.Run(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	if st := ofType(events(t, res), "dev.qory.run.started"); len(st) != 1 {
		t.Errorf("run.started events %v", st)
	} else if about, ok := data(st[0])["about"]; ok {
		t.Errorf("an empty About is in run.started as %v", about)
	}
}

func TestStopGraceIsHowLongTheRuntimeHasToLeave(t *testing.T) {
	sp := spec(t)
	sp.Forwarder = nil
	sp.Command = "sh"
	sp.Args = []string{"-c", "trap '' TERM; sleep 30 & wait; wait"}
	sp.Timeout = 200 * time.Millisecond
	sp.StopGrace = 300 * time.Millisecond
	start := time.Now()
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.Signal != "SIGKILL" {
		t.Errorf("result %+v", res)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("a runtime that ignores SIGTERM ran %s, past the grace", took)
	}
}

func TestStopSignalIsTheOneTheRunNames(t *testing.T) {
	sp := spec(t)
	sp.Forwarder = nil
	sp.Command = "sh"
	sp.Args = []string{"-c", "trap 'exit 7' INT; trap '' TERM; sleep 30 & wait"}
	sp.Timeout = 300 * time.Millisecond
	sp.StopSignal = "SIGINT"
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.ExitCode != 7 || res.Signal != "" {
		t.Errorf("a runtime that leaves on SIGINT alone: result %+v", res)
	}
	for _, name := range []string{"SIGKILL", "INT", "sigint", "9"} {
		sp := spec(t)
		sp.StopSignal = name
		if _, err := session.Run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), "stop signal") {
			t.Errorf("stop signal %q: %v", name, err)
		}
	}
}

// leaves is a runtime of the test's own, to show that the session asks the interface
// and knows no runtime: it prepares nothing, reads nothing, and names how it is asked to
// leave.
type leaves struct {
	runtimes.Runtime
	stop     runtimes.Stop
	prepared *runtimes.Attach
}

func (l leaves) Stop() runtimes.Stop { return l.stop }
func (l leaves) Prepare(a runtimes.Attach) (runtimes.Launch, error) {
	*l.prepared = a
	launch := a.Launch
	launch.Env = []string{"ADDED_BY_THE_RUNTIME=yes"}
	return launch, nil
}

func TestTheRuntimeSaysHowItIsAskedToLeaveAndTheRunMaySayOtherwise(t *testing.T) {
	script := `test "$ADDED_BY_THE_RUNTIME" = yes || exit 9; trap 'exit 7' INT; trap 'exit 8' HUP; trap '' TERM; sleep 30 & wait`
	for name, c := range map[string]struct {
		named string
		code  int
	}{"the runtime's": {"", 7}, "the run's": {"SIGHUP", 8}} {
		t.Run(name, func(t *testing.T) {
			sp := spec(t)
			var got runtimes.Attach
			sp.Runtime = leaves{Runtime: runtimes.Bare("other-agent"), stop: runtimes.Stop{Signal: "SIGINT", Grace: 20 * time.Second}, prepared: &got}
			sp.Command, sp.Args = "sh", []string{"-c", script}
			sp.Timeout = 300 * time.Millisecond
			sp.StopSignal = c.named
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if !res.TimedOut || res.ExitCode != c.code {
				t.Errorf("result %+v", res)
			}
			if got.RunDir != res.Dir || got.Launch.Command != "sh" || len(got.Forwarder) == 0 {
				t.Errorf("Prepare was given %+v", got)
			}
			started := ofType(events(t, res), "dev.qory.run.started")
			if len(started) != 1 || data(started[0])["runtime"] != "other-agent" {
				t.Errorf("run.started %v", started)
			}
		})
	}
	sp := spec(t)
	sp.Runtime = leaves{Runtime: runtimes.Bare("other-agent"), stop: runtimes.Stop{Signal: "SIGKILL"}, prepared: new(runtimes.Attach)}
	if _, err := session.Run(context.Background(), sp); err == nil || !strings.Contains(err.Error(), "runtime other-agent") {
		t.Errorf("a runtime that names SIGKILL: %v", err)
	}
}

func TestNoRuntimeIsABareOneNamedAfterTheCommand(t *testing.T) {
	sp := spec(t)
	sp.Runtime = nil
	sp.Command, sp.Args = "sh", []string{"-c", "exit 3"}
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	started := ofType(events(t, res), "dev.qory.run.started")
	if res.ExitCode != 3 || len(started) != 1 || data(started[0])["runtime"] != "sh" {
		t.Errorf("%+v %v", res, started)
	}
	if _, err := os.Stat(filepath.Join(res.Dir, "settings.json")); !os.IsNotExist(err) {
		t.Error("something was prepared for a runtime Forager does not know")
	}
}
