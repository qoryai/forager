package session_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// The tests of this file pin the run API from the session's side: QORY_RUN_API in a
// run's environments, [session.Run.RunAPI], and the end of a file's stream on every path
// from the gateway to a caller.

// workItem is the fake run API's work item.
const workItem = `{"work_item":{"title":"Fix the failing build"}}`

// artifact is the file the fake run API serves.
var artifact = bytes.Repeat([]byte("artifact "), 1<<14)

// pushed is the body of the fake run API's 201 to a POST of artifacts.
const pushed = `{"artifact":{"version_id":"v1"}}`

// runAPIAnswers serves the paths of a fake run API under a run, signed by signer, and
// reports whether r was one of them: a POST of artifacts, with a 201; the work item; the file of the version good, under
// its digest; and the file of the version bad, under another digest.
func runAPIAnswers(signer *accesskey.Key, w http.ResponseWriter, r *http.Request) bool {
	rest, ok := strings.CutPrefix(r.URL.Path, "/v1/runs/")
	if !ok {
		return false
	}
	_, path, _ := strings.Cut(rest, "/")
	sig := r.Header.Get(server.HeaderSignature)
	file := func(digest []byte) bool {
		sum := sha256.Sum256(digest)
		w.Header().Set("Content-Length", fmt.Sprint(len(artifact)))
		w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: sig, Digest: hex.EncodeToString(sum[:])}))
		w.Write(artifact)
		return true
	}
	switch path {
	case "artifacts":
		if r.Method != http.MethodPost {
			return false
		}
		w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: http.StatusCreated, RequestSignature: sig, Body: []byte(pushed)}))
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, pushed)
		return true
	case "work-item":
		w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: sig, Body: []byte(workItem)}))
		io.WriteString(w, workItem)
		return true
	case "artifacts/good/files/report.md":
		return file(artifact)
	case "artifacts/bad/files/report.md":
		return file([]byte("other bytes"))
	}
	return false
}

// getWorkItem fails the test unless c gets the work item at base.
func getWorkItem(t *testing.T, c *http.Client, base string) {
	t.Helper()
	resp, err := c.Get(base + "/work-item")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(b) != workItem {
		t.Errorf("the work item: %d %s", resp.StatusCode, b)
	}
}

// getOutside fails the test unless a request outside the five shapes is a 404.
func getOutside(t *testing.T, c *http.Client, base string) {
	t.Helper()
	resp, err := c.Get(base + "/diagnostics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound || !bytes.Contains(b, []byte(`"not_found"`)) {
		t.Errorf("the diagnostics: %d %s", resp.StatusCode, b)
	}
}

// reachesTheRunAPI pins Run.RunAPI through a run's life, with sp set up for a run with a
// control plane: from the open, during a join, up to the close, and not after it.
func reachesTheRunAPI(t *testing.T, sp runSpec) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	client, base, err := r.RunAPI()
	if err != nil {
		t.Fatal(err)
	}
	if want := link.RunAPIURL(sp.RunID); base != want {
		t.Errorf("the base URL %q, want %q", base, want)
	}
	getWorkItem(t, client, base)
	getOutside(t, client, base)
	done := make(chan *session.Result, 1)
	go func() {
		res, _ := r.Join(ctx, sp.SessionSpec)
		done <- res
	}()
	waitFor(t, func() bool {
		return len(ofType(events(t, &session.Result{Dir: r.Dir()}), event.SessionStarted)) == 1
	})
	getWorkItem(t, client, base)
	during, _, err := r.RunAPI()
	if err != nil {
		t.Fatalf("during the join: %v", err)
	}
	getWorkItem(t, during, base)
	cancel()
	<-done
	if _, err := r.Close(context.Background(), session.Outcome{State: event.StateCancelled}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.RunAPI(); err == nil || !strings.HasPrefix(err.Error(), "Open another run to reach the run API") {
		t.Errorf("after the close: %v", err)
	}
	if resp, err := client.Get(base + "/work-item"); err == nil {
		resp.Body.Close()
		t.Errorf("after the close: %d", resp.StatusCode)
	}
}

// TestRunAPIOnOneMachine pins Run.RunAPI at a real gateway on the machine.
func TestRunAPIOnOneMachine(t *testing.T) {
	c := newControl(t)
	c.runAPI.Store(true)
	sp := spec(t)
	sleeps(&sp, 30*time.Second)
	sp.Timeout = 20 * time.Second
	sp.RunID = event.NewRunID()
	startGateway(t, &sp, gateway.Config{Server: c.server(), Heartbeat: time.Second})
	reachesTheRunAPI(t, sp)
}

// separateRun starts a separate gateway in front of a fake Qory Apiary, and sets sp to
// run behind it.
func separateRun(t *testing.T, sp *runSpec) {
	t.Helper()
	a := newApiary(t)
	certFile, keyFile, caFile := separateCertificate(t)
	dir := t.TempDir()
	g, err := gateway.Start(context.Background(), gateway.Config{
		RunDir: func(id string) string { return dir + "/" + id }, Listen: "127.0.0.1:0", Heartbeat: time.Second, Version: "test",
		TLS:    &gateway.TLS{CertFile: certFile, KeyFile: keyFile},
		Server: &gateway.Server{Version: 1, URL: a.srv.URL, AccessKeyID: "ak_f1xt0re00000000g", ApiaryPublicKey: a.pin, AccessKey: a.key, InstanceID: "i_test"},
		Report: func(l string) { t.Log("the gateway reported:", l) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		g.Close(ctx)
	})
	sp.RunID = event.NewRunID()
	sp.Gateway = session.RemoteGateway{RunKey: a.runKey(t, sp.RunID, "https://"+g.Addr(), a.key), TLS: server.RemoteTLS{CAFile: caFile}}
}

// TestRunAPIBehindASeparateGateway pins Run.RunAPI behind a separate gateway.
func TestRunAPIBehindASeparateGateway(t *testing.T) {
	sp := spec(t)
	sleeps(&sp, 30*time.Second)
	sp.Timeout = 20 * time.Second
	separateRun(t, &sp)
	reachesTheRunAPI(t, sp)
}

// TestRunAPIWithNoControlPlane pins a run with no control plane at a real gateway:
// Run.RunAPI returns an error that starts with the fix, and the agent's environment has
// no QORY_RUN_API.
func TestRunAPIWithNoControlPlane(t *testing.T) {
	sp := spec(t)
	startGateway(t, &sp, gateway.Config{})
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateCancelled})
	client, base, err := r.RunAPI()
	if err == nil || client != nil || base != "" || !strings.HasPrefix(err.Error(), "Open the run through a gateway with a control plane") {
		t.Errorf("%v %q %v", client, base, err)
	}
	env, err := r.AgentEnv(sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	if got := entriesOf(env, session.EnvRunAPI); len(got) != 0 {
		t.Errorf("the agent's environment has %v", got)
	}
}

// hasRunAPI is a fake gateway's run answer with run_api, as a gateway with a control
// plane gives it.
func hasRunAPI(g *linktest.Fake) {
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["run_api"] = link.RunAPIURL(req.RunID)
		return linktest.Reply{Status: http.StatusOK, Body: a}
	})
}

// TestQoryRunAPIReachesTheAgent pins QORY_RUN_API in a session, with a wall and without,
// and that the value a run without a wall inherits is left out, with a control plane and
// with none.
func TestQoryRunAPIReachesTheAgent(t *testing.T) {
	const forged = session.EnvRunAPI + "=http://forged.example"
	t.Run("without a wall", func(t *testing.T) {
		sp, g := specGateway(t)
		hasRunAPI(g)
		sp.RunID = event.NewRunID()
		sp.Env = append(sp.Env, forged)
		sp.Variables.Run = []string{forged}
		sp.Command, sp.Args = "/bin/sh", []string{"-c", `test "$` + session.EnvRunAPI + `" = "` + link.RunAPIURL(sp.RunID) + `"`}
		if res, err := run(context.Background(), sp); err != nil || res.ExitCode != 0 {
			t.Errorf("%v %+v", err, res)
		}
	})
	t.Run("without a wall or a control plane", func(t *testing.T) {
		sp, _ := specGateway(t)
		sp.Env = append(sp.Env, forged)
		sp.Command, sp.Args = "/bin/sh", []string{"-c", `test -z "${` + session.EnvRunAPI + `+set}"`}
		if res, err := run(context.Background(), sp); err != nil || res.ExitCode != 0 {
			t.Errorf("%v %+v", err, res)
		}
	})
	t.Run("without a wall or a control plane, from the run's variables", func(t *testing.T) {
		sp, _ := specGateway(t)
		sp.Variables.Run = []string{forged}
		sp.Command, sp.Args = "/bin/sh", []string{"-c", `test -z "${` + session.EnvRunAPI + `+set}"`}
		if res, err := run(context.Background(), sp); err != nil || res.ExitCode != 0 {
			t.Errorf("%v %+v", err, res)
		}
	})
	t.Run("behind a wall", func(t *testing.T) {
		sp, g := specGateway(t, "FAKE_EXIT=0")
		hasRunAPI(g)
		w := &openWall{}
		sp.Wall, sp.Image = w, "example.com/agent:1"
		res, err := runWithSettingsEnv(t, sp)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := entriesOf(w.got.Env, session.EnvRunAPI), []string{session.EnvRunAPI + "=" + link.RunAPIURL(res.RunID)}; !slices.Equal(got, want) {
			t.Errorf("the enclosure's environment has %v, want %v", got, want)
		}
	})
	t.Run("behind a wall with no control plane", func(t *testing.T) {
		sp, _ := specGateway(t, "FAKE_EXIT=0")
		w := &openWall{}
		sp.Wall, sp.Image = w, "example.com/agent:1"
		if _, err := runWithSettingsEnv(t, sp); err != nil {
			t.Fatal(err)
		}
		if got := entriesOf(w.got.Env, session.EnvRunAPI); len(got) != 0 {
			t.Errorf("the enclosure's environment has %v", got)
		}
	})
}

// TestQoryRunAPIReachesTheSetup pins QORY_RUN_API in the setup container of a run with a
// control plane. AgentEnv, whose result a caller passes as the setup's variables, has
// none of Forager's names: Setup sets it.
func TestQoryRunAPIReachesTheSetup(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	hasRunAPI(g)
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.RunID = event.NewRunID()
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
	want := []string{session.EnvRunAPI + "=" + link.RunAPIURL(sp.RunID)}
	env, err := r.AgentEnv(sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	if got := entriesOf(env, session.EnvRunAPI); len(got) != 0 {
		t.Errorf("AgentEnv has %v", got)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Env: env, Commands: twoCommands}); err != nil {
		t.Fatal(err)
	}
	if got := entriesOf(w.setup.Env, session.EnvRunAPI); !slices.Equal(got, want) {
		t.Errorf("the setup container's environment has %v, want %v", got, want)
	}
}

// TestACallersQoryRunAPIIsReserved pins that a value of QORY_RUN_API a caller passes
// into a wall is variable_reserved: at a join, from --env, wall.env and what the run
// inherits, with a control plane and with none, and from AgentEnv and Setup.
func TestACallersQoryRunAPIIsReserved(t *testing.T) {
	const forged = session.EnvRunAPI + "=http://forged.example"
	ctx := context.Background()
	reserved := func(t *testing.T, what string, err error) {
		t.Helper()
		var ref *session.Refusal
		if !errors.As(err, &ref) || ref.Code != "variable_reserved" || !slices.Contains(ref.Names, session.EnvRunAPI) {
			t.Errorf("%s: %v, want variable_reserved", what, err)
		}
	}
	for what, set := range map[string]func(sp *runSpec){
		"--env":                 func(sp *runSpec) { sp.Variables.Run = []string{forged} },
		"wall.env":              func(sp *runSpec) { sp.Variables.Machine = []string{forged} },
		"what the run inherits": func(sp *runSpec) { sp.Env = append(sp.Env, forged) },
	} {
		for _, controlPlane := range []bool{true, false} {
			t.Run(fmt.Sprint(what, " ", controlPlane), func(t *testing.T) {
				sp, g := specGateway(t, "FAKE_EXIT=0")
				if controlPlane {
					hasRunAPI(g)
				}
				sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
				set(&sp)
				_, err := run(ctx, sp)
				reserved(t, "the join", err)
			})
		}
	}
	t.Run("AgentEnv", func(t *testing.T) {
		sp, g := specGateway(t)
		hasRunAPI(g)
		sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		sp.Variables.Run = []string{forged}
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
		_, err = r.AgentEnv(sp.SessionSpec)
		reserved(t, "AgentEnv", err)
	})
	t.Run("AgentEnv with an inherited value", func(t *testing.T) {
		sp, g := specGateway(t)
		hasRunAPI(g)
		sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		sp.Env = append(sp.Env, forged)
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
		_, err = r.AgentEnv(sp.SessionSpec)
		reserved(t, "AgentEnv", err)
	})
	t.Run("AgentEnv with an inherited value and no wall", func(t *testing.T) {
		sp, _ := specGateway(t)
		sp.Env = append(sp.Env, forged)
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
		env, err := r.AgentEnv(sp.SessionSpec)
		if err != nil {
			t.Fatal(err)
		}
		if got := entriesOf(env, session.EnvRunAPI); len(got) != 0 {
			t.Errorf("the agent's environment has %v", got)
		}
	})
	t.Run("Setup", func(t *testing.T) {
		sp, g := specGateway(t)
		hasRunAPI(g)
		w := &setupWall{}
		sp.Wall, sp.Image = w, "example.com/agent:1"
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
		reserved(t, "Setup", r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Env: []string{forged}, Commands: twoCommands}))
	})
}

// readFile reads the version's file through c, and returns the status, the bytes and
// the read's error.
func readFile(t *testing.T, c *http.Client, base, version string) (int, []byte, error) {
	t.Helper()
	resp, err := c.Get(base + "/artifacts/" + version + "/files/report.md")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

// fileEnds pins a file through c: the good version ends cleanly, and the bad one ends in
// a read error, never a clean end of body.
func fileEnds(t *testing.T, c *http.Client, base string) {
	t.Helper()
	status, b, err := readFile(t, c, base, "good")
	if status != http.StatusOK || err != nil || !bytes.Equal(b, artifact) {
		t.Errorf("the file: %d, %d bytes, %v", status, len(b), err)
	}
	status, b, err = readFile(t, c, base, "bad")
	if status != http.StatusOK || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("a file that fails its digest: %d, %d bytes, %v", status, len(b), err)
	}
}

// throughProxy is a client whose requests go through the proxy at u.
func throughProxy(u *url.URL) *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true}}
}

// throughRelay starts the program that runs in a wall's relay, in front of the run's
// forwarder for a wall, and returns a client through it: the path a walled program's
// connection takes.
func throughRelay(t *testing.T, r *session.Run) *http.Client {
	t.Helper()
	addr, token, stop, err := r.WallForwarder()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	t.Setenv(wall.RelayInsideEnv, "127.0.0.0/8")
	t.Setenv(wall.RelayTokenEnv, token)
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	ctx, cancel := context.WithCancel(context.Background())
	var ready syncWriter
	done := make(chan error, 1)
	go func() { done <- wall.Relay(ctx, []string{fmt.Sprintf("%d=%s", port, addr)}, &ready) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	waitFor(t, func() bool { return ready.has(wall.RelayReady) })
	return throughProxy(&url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", port)})
}

// syncWriter is what the relay prints, which the test reads as it runs.
type syncWriter struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncWriter) has(part string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Contains(s.b.String(), part)
}

// TestAFilesEndReachesTheCallerOnEveryPath pins that the abort of a file that fails its
// digest stays a read error at the caller on each path from the gateway: the client of
// Run.RunAPI, the forwarder of a run without a wall, and the wall's relay with the
// run's forwarder for a wall, on one machine and behind a separate gateway.
func TestAFilesEndReachesTheCallerOnEveryPath(t *testing.T) {
	ctx := context.Background()
	check := func(t *testing.T, sp runSpec) {
		t.Helper()
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { r.Close(ctx, session.Outcome{State: event.StateCancelled}) })
		client, base, err := r.RunAPI()
		if err != nil {
			t.Fatal(err)
		}
		t.Run("the client of Run.RunAPI", func(t *testing.T) { fileEnds(t, client, base) })
		t.Run("the forwarder of a run without a wall", func(t *testing.T) {
			h, err := r.HostProxy()
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			u, err := url.Parse(h.ProxyURL)
			if err != nil {
				t.Fatal(err)
			}
			fileEnds(t, throughProxy(u), base)
		})
		t.Run("the wall's relay", func(t *testing.T) { fileEnds(t, throughRelay(t, r), base) })
	}
	t.Run("on one machine", func(t *testing.T) {
		c := newControl(t)
		c.runAPI.Store(true)
		sp := spec(t)
		sp.RunID = event.NewRunID()
		startGateway(t, &sp, gateway.Config{Server: c.server(), Heartbeat: time.Second})
		check(t, sp)
	})
	t.Run("behind a separate gateway", func(t *testing.T) {
		sp := spec(t)
		separateRun(t, &sp)
		check(t, sp)
	})
}

// TestASetupContainersPostToTheRunAPIIsChecked pins Run.SetRunAPICheck, called after
// Open, for the setup container, which reaches the proxy through the run's forwarder as
// the agent does: a POST under QORY_RUN_API for which the check returns a refusal gets
// the refusal and never reaches the gateway's proxy, and one for which it returns nil,
// nil reaches it.
func TestASetupContainersPostToTheRunAPIIsChecked(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	hasRunAPI(g)
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	var mu sync.Mutex
	var paths []string
	check := func(_ context.Context, req session.RunAPIRequest) (*session.RunAPIRefusal, error) {
		mu.Lock()
		paths = append(paths, req.Path)
		mu.Unlock()
		if strings.Contains(string(req.Body), "failing") {
			return &session.RunAPIRefusal{Status: http.StatusUnprocessableEntity, Code: "push_checks_failed", Message: "Fix the failing test, then push again."}, nil
		}
		return nil, nil
	}
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateCancelled})
	if err := r.SetRunAPICheck(check); err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
		t.Fatal(err)
	}
	target := link.RunAPIURL(r.ID()) + "/artifacts"
	// send writes body in a POST to the setup container's proxy, after the relay's
	// preamble, as the wall's relay sends it, and returns the reply.
	send := func(body string) string {
		c, err := net.Dial("tcp", w.setup.Proxy)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "%sPOST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
			link.RelayLine(w.setup.ProxyToken), target, link.RunAPIHost, len(body), body)
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		b, _ := io.ReadAll(c)
		return string(b)
	}
	out := send(`{"artifacts":[{"name":"failing"}]}`)
	if !strings.HasPrefix(out, "HTTP/1.1 422 Unprocessable Entity\r\n") ||
		!strings.HasSuffix(out, `{"error":"push_checks_failed","message":"Fix the failing test, then push again."}`) {
		t.Errorf("the refused POST got %q", out)
	}
	if got := g.Proxied(); slices.Contains(got, "POST "+target) {
		t.Errorf("the refused POST reached the proxy: %q", got)
	}
	if out := send(`{"artifacts":[{"name":"report.md"}]}`); !strings.HasPrefix(out, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("the POST the check let pass got %q", out)
	}
	if got := g.Proxied(); !slices.Contains(got, "POST "+target) {
		t.Errorf("the proxy got %q, no POST", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(paths, []string{"/artifacts", "/artifacts"}) {
		t.Errorf("the check got %q", paths)
	}
}

// TestACheckedPostThatExpectsAContinueReachesTheRoute pins Expect: 100-continue through
// the forwarder with a check and a real gateway's run API route: the program reads the
// forwarder's 100 Continue, sends the body, then reads the route's 100 Continue and the
// route's reply, the control plane's 201.
func TestACheckedPostThatExpectsAContinueReachesTheRoute(t *testing.T) {
	c := newControl(t)
	c.runAPI.Store(true)
	sp := spec(t, "FAKE_EXIT=0")
	sp.Timeout = 20 * time.Second
	sp.RunID = event.NewRunID()
	startGateway(t, &sp, gateway.Config{Server: c.server(), Heartbeat: time.Second})
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateCancelled})
	if err := r.SetRunAPICheck(func(context.Context, session.RunAPIRequest) (*session.RunAPIRefusal, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", w.setup.Proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	const body = `{"artifacts":[]}`
	fmt.Fprintf(conn, "%sPOST %s/artifacts HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nExpect: 100-continue\r\nContent-Length: %d\r\n\r\n",
		link.RelayLine(w.setup.ProxyToken), link.RunAPIURL(r.ID()), link.RunAPIHost, len(body))
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(conn)
	readContinue := func(who string) {
		t.Helper()
		resp, err := http.ReadResponse(br, nil)
		if err != nil || resp.StatusCode != http.StatusContinue {
			t.Fatalf("%s: %v, %v; want a 100 Continue", who, resp, err)
		}
	}
	readContinue("the forwarder")
	io.WriteString(conn, body)
	readContinue("the route")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated || string(got) != pushed {
		t.Errorf("the program got %d %q", resp.StatusCode, got)
	}
}

// relayed opens a connection to addr as the wall's relay does on one machine, with the
// relay's preamble and token, writes what, ends its side, and returns all that comes
// back until the connection closes or 10 seconds pass.
func relayed(t *testing.T, addr, token, what string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, link.RelayLine(token)+what)
	c.(*net.TCPConn).CloseWrite()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	b, _ := io.ReadAll(c)
	return string(b)
}

// TestAWalledRunWithoutTheCheckPassesRequestsAsTheyCome pins a walled run with a control
// plane whose caller never calls Run.SetRunAPICheck: the setup container's connection
// carries a POST to the run API and, kept alive after it, a GET whose head is over the
// checked forwarder's limits, and both reach the gateway's proxy and get its replies, with
// no 431 and no check.
func TestAWalledRunWithoutTheCheckPassesRequestsAsTheyCome(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	hasRunAPI(g)
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateCancelled})
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
		t.Fatal(err)
	}
	target := link.RunAPIURL(r.ID()) + "/artifacts"
	const body = `{"artifacts":[{"name":"failing"}]}`
	big := strings.Repeat("a", 10<<10)
	out := relayed(t, w.setup.Proxy, w.setup.ProxyToken,
		fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s", target, link.RunAPIHost, len(body), body)+
			"GET http://api.example/large HTTP/1.1\r\nHost: api.example\r\nX-Large: "+big+"\r\nConnection: close\r\n\r\n")
	if n := strings.Count(out, "HTTP/1.1 200 OK\r\n"); n != 2 || strings.Contains(out, "431") {
		t.Errorf("the program got %d replies of 200: %q", n, out)
	}
	if got := g.Proxied(); !slices.Contains(got, "POST "+target) || !slices.Contains(got, "GET http://api.example/large") {
		t.Errorf("the proxy got %q", got)
	}
}

// TestSetRunAPICheckIsRefusedWhenItCannotCheckEveryRequest pins the errors of
// Run.SetRunAPICheck, each of which leaves the run as it was: a nil check, a run with no
// wall or no control plane, a second call, a call after a connection reached the run's
// forwarder, after Setup, after a join, and after the close.
func TestSetRunAPICheckIsRefusedWhenItCannotCheckEveryRequest(t *testing.T) {
	ctx := context.Background()
	pass := func(context.Context, session.RunAPIRequest) (*session.RunAPIRefusal, error) { return nil, nil }
	// open opens a run with a control plane, unless plain, behind w unless it is nil.
	open := func(t *testing.T, w *setupWall, plain bool) (*session.Run, runSpec, *linktest.Fake) {
		t.Helper()
		sp, g := specGateway(t, "FAKE_EXIT=0")
		if !plain {
			hasRunAPI(g)
		}
		if w != nil {
			sp.Wall, sp.Image = w, "example.com/agent:1"
		}
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { r.Close(ctx, session.Outcome{State: event.StateCancelled}) })
		return r, sp, g
	}
	refused := func(t *testing.T, err error, fix string) {
		t.Helper()
		if err == nil || !strings.HasPrefix(err.Error(), fix) {
			t.Errorf("SetRunAPICheck returned %v, want an error that starts %q", err, fix)
		}
	}
	t.Run("a nil check", func(t *testing.T) {
		r, _, _ := open(t, &setupWall{}, false)
		refused(t, r.SetRunAPICheck(nil), "Give SetRunAPICheck a check")
		if err := r.SetRunAPICheck(pass); err != nil {
			t.Errorf("the call after it: %v", err)
		}
	})
	t.Run("a run with no wall", func(t *testing.T) {
		r, _, _ := open(t, nil, false)
		refused(t, r.SetRunAPICheck(pass), "Open the run with a wall to check its run API")
	})
	t.Run("a run with no control plane", func(t *testing.T) {
		r, _, _ := open(t, &setupWall{}, true)
		refused(t, r.SetRunAPICheck(pass), "Open the run at a gateway with a control plane")
	})
	t.Run("a second call", func(t *testing.T) {
		r, _, _ := open(t, &setupWall{}, false)
		if err := r.SetRunAPICheck(pass); err != nil {
			t.Fatal(err)
		}
		refused(t, r.SetRunAPICheck(pass), "Call SetRunAPICheck once per run")
	})
	t.Run("after a connection reached the forwarder", func(t *testing.T) {
		r, _, g := open(t, &setupWall{}, false)
		addr, token := r.WallProxy()
		get := "GET http://api.example/early HTTP/1.1\r\nHost: api.example\r\n\r\n"
		if out := relayed(t, addr, token, get); !strings.HasPrefix(out, "HTTP/1.1 200 OK\r\n") {
			t.Fatalf("the early request got %q", out)
		}
		refused(t, r.SetRunAPICheck(pass), "Call SetRunAPICheck before anything connects to the run's proxy")
		// The forwarder is as it was: a request after the call passes unread, kept alive.
		target := link.RunAPIURL(r.ID()) + "/artifacts"
		out := relayed(t, addr, token, fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 2\r\n\r\n{}", target, link.RunAPIHost)+get)
		if n := strings.Count(out, "HTTP/1.1 200 OK\r\n"); n != 2 {
			t.Errorf("the requests after the call got %q", out)
		}
		if got := g.Proxied(); !slices.Contains(got, "POST "+target) {
			t.Errorf("the proxy got %q", got)
		}
	})
	t.Run("after Setup", func(t *testing.T) {
		r, sp, _ := open(t, &setupWall{}, false)
		if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
			t.Fatal(err)
		}
		refused(t, r.SetRunAPICheck(pass), "Call SetRunAPICheck before Setup")
	})
	t.Run("after a join", func(t *testing.T) {
		r, sp, _ := open(t, &setupWall{}, false)
		if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
			t.Fatal(err)
		}
		refused(t, r.SetRunAPICheck(pass), "Call SetRunAPICheck before the first Join")
	})
	t.Run("after the close", func(t *testing.T) {
		r, _, _ := open(t, &setupWall{}, false)
		if _, err := r.Close(ctx, session.Outcome{State: event.StateCancelled}); err != nil {
			t.Fatal(err)
		}
		refused(t, r.SetRunAPICheck(pass), "Open another run to check its run API")
	})
}
