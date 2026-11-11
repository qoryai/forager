package e2e

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/wall"
)

// TestUnwalledClaudeCodeResumesAPausedRunUnderAnotherKey runs Claude Code 2.1.316 twice
// without a wall, each run with a fake control plane's run configuration and a stub of
// the Messages API on an address of this machine that is not loopback, since NO_PROXY
// exempts loopback. Run 1, with key A, makes two Bash calls that print turn-0 and
// turn-1, and its session sends the runtime's transcript as dev.qory.session.transcript
// chunks, which the control plane stores. Run 2's run configuration has resume, with
// run 1's id, session id and transcript path, and key B; the control plane serves run
// 1's chunks, joined in offset order, at <run.url>/<run_id>/resume/transcript. Run 2
// starts in a new home and another working directory, and its first model request
// contains run 1's turns, goes with key B, and both runs end succeeded.
//
// TestDockerClaudeCodeResumesAPausedRunUnderAnotherKey is the same check behind the
// wall. The proxy verifies the stub against this machine's roots, which trustRecorders
// sets through SSL_CERT_FILE; Go reads that variable on Linux alone, so the test is
// skipped on other systems, on a machine with none of the CA bundles the session reads,
// and without claude on PATH.
func TestUnwalledClaudeCodeResumesAPausedRunUnderAnotherKey(t *testing.T) {
	if runtime.GOOS != "linux" {
		Skip(t, "Go reads this machine's roots from SSL_CERT_FILE on Linux alone, and the proxy verifies the stub against them")
	}
	if !slices.ContainsFunc(wall.BundleFiles(), func(p string) bool { fi, err := os.Stat(p); return err == nil && fi.Mode().IsRegular() }) {
		Skip(t, fmt.Sprintf("none of %v is on this machine, and an unwalled run starts only with one", wall.BundleFiles()))
	}
	if _, err := exec.LookPath("claude"); err != nil {
		Skip(t, "claude is not on PATH: the test runs Claude Code 2.1.316 without a wall")
	}
	if err := trustRecorders(t); err != nil {
		t.Fatalf("this machine's roots are not the suite's authority: %v", err)
	}
	host, stubLog := startLocalKeysStub(t, keysResume)
	endpoint := "https://" + host
	ip, _, _ := net.SplitHostPort(host)
	ctl := startKeysControl(t)
	path := "PATH=" + os.Getenv("PATH")
	env := func(home string) []string {
		return []string{path, "HOME=" + home, "DISABLE_AUTOUPDATER=1", "ANTHROPIC_AUTH_TOKEN=", apiKeyStandIn + "="}
	}

	run1, home1 := event.NewRunID(), t.TempDir()
	ctl.configure(t, run1, ip, []map[string]any{keysCredential("model", endpoint)}, []string{keyA}, nil)
	o1 := keysSession{runID: run1, server: ctl.server, allow: []string{ip}, args: []string{"--allowedTools", "Bash"},
		prompt: "Run the commands you are given.", env: env(home1), dir: t.TempDir(), timeout: 4 * time.Minute}.run(t)
	log1 := readLocalKeysLog(t, stubLog)
	if o1.res.State != event.StateSucceeded {
		t.Fatalf("run 1 ended %s, exit %d; want succeeded\nstub:%s\nstdout:\n%s", o1.res.State, o1.res.ExitCode, keysEntries(log1), tail(o1.out, 4000))
	}
	transcript, sessionID, tpath := storedTranscript(t, ctl, run1)
	if !bytes.Contains(transcript, []byte("turn-0")) || !bytes.Contains(transcript, []byte("turn-1")) {
		t.Fatalf("run 1's transcript, %d bytes of %s, has no turn-0 and turn-1", len(transcript), tpath)
	}

	run2, home2 := event.NewRunID(), t.TempDir()
	ctl.mu.Lock()
	ctl.transcripts[run2] = transcript
	ctl.mu.Unlock()
	ctl.configure(t, run2, ip, []map[string]any{keysCredential("model-b", endpoint)}, []string{keyB},
		map[string]any{"run_id": run1, "session_id": sessionID, "path": tpath})
	o2 := keysSession{runID: run2, server: ctl.server, allow: []string{ip}, args: []string{"--allowedTools", "Bash"},
		prompt: "Continue with the next command.", env: env(home2), dir: t.TempDir(), timeout: 4 * time.Minute}.run(t)
	log2 := readLocalKeysLog(t, stubLog)[len(log1):]
	t.Logf("run 1's transcript: %d bytes of %s, session %s; the stub got, in run 1:%s\nin run 2:%s", len(transcript), tpath, sessionID, keysEntries(log1), keysEntries(log2))
	if o2.res.State != event.StateSucceeded {
		t.Errorf("run 2 ended %s, exit %d; want succeeded\nstub:%s\nstdout:\n%s", o2.res.State, o2.res.ExitCode, keysEntries(log2), tail(o2.out, 4000))
	}
	for _, d := range o2.of(event.RunLog) {
		if b, _ := base64.StdEncoding.DecodeString(fmt.Sprint(d["bytes"])); bytes.Contains(b, []byte("without a resume")) {
			t.Errorf("run 2 wrote: %s", b)
		}
	}
	ctl.mu.Lock()
	asked := slices.Clone(ctl.asked)
	ctl.mu.Unlock()
	if !slices.Equal(asked, []string{run2}) {
		t.Errorf("the control plane was asked for the transcript of %q; want run 2's once", asked)
	}
	if len(log2) == 0 || log2[0].Key != "B" || !slices.Contains(log2[0].Turns, "turn-0") || !slices.Contains(log2[0].Turns, "turn-1") || log2[0].Results < 2 {
		t.Errorf("run 2's requests:%s\nwant the first with key B, run 1's two tool results and the marks turn-0 and turn-1", keysEntries(log2))
	}
	for _, e := range log1 {
		if e.Key != "A" {
			t.Errorf("run 1 sent a request with key %q; want A:%s", e.Key, keysEntries(log1))
			break
		}
	}
	noKeyValue(t, o1, home1)
	noKeyValue(t, o2, home2)
}

// TestDockerClaudeCodeResumesAPausedRunUnderAnotherKey runs Claude Code 2.1.316 twice
// behind the Docker wall, each run with the fake control plane's run configuration and
// the stub of the Messages API in a container. Run 1, with key A, makes two Bash calls
// that print turn-0 and turn-1. Claude Code writes its transcript in the session's
// transcript directory, which the wall binds at ~/.claude/projects inside, and the
// session sends the transcript as dev.qory.session.transcript chunks, which the control
// plane stores. Run 2's run configuration has resume, with run 1's id, session id and
// transcript path, and key B; the control plane serves run 1's chunks, joined in offset
// order, at <run.url>/<run_id>/resume/transcript. The session of run 2 writes them in
// its transcript directory before the agent's container starts. Run 2 starts in
// another working directory; its first model request contains run 1's turns and goes
// with key B, and both runs end succeeded.
func TestDockerClaudeCodeResumesAPausedRunUnderAnotherKey(t *testing.T) {
	k := newKeysWall(t)
	name, host := k.stub(t, keysResume)
	endpoint := "https://" + host + ":" + recorderTLS
	ctl := startKeysControl(t)

	run1 := event.NewRunID()
	ctl.configure(t, run1, host, []map[string]any{keysCredential("model", endpoint)}, []string{keyA}, nil)
	s1 := keysSession{runID: run1, server: ctl.server, allow: []string{host}, args: []string{"--allowedTools", "Bash"},
		prompt: "Run the commands you are given.", dir: t.TempDir(), walled: &k, timeout: 4 * time.Minute}
	o1 := s1.run(t)
	log1 := k.stubLog(t, name)
	if o1.res.State != event.StateSucceeded {
		t.Fatalf("run 1 ended %s, exit %d; want succeeded\nstub:%s\nstdout:\n%s", o1.res.State, o1.res.ExitCode, keysEntries(log1), tail(o1.out, 4000))
	}
	transcript, sessionID, tpath := storedTranscript(t, ctl, run1)
	if !bytes.Contains(transcript, []byte("turn-0")) || !bytes.Contains(transcript, []byte("turn-1")) {
		t.Fatalf("run 1's transcript, %d bytes of %s, has no turn-0 and turn-1", len(transcript), tpath)
	}

	run2 := event.NewRunID()
	ctl.mu.Lock()
	ctl.transcripts[run2] = transcript
	ctl.mu.Unlock()
	ctl.configure(t, run2, host, []map[string]any{keysCredential("model-b", endpoint)}, []string{keyB},
		map[string]any{"run_id": run1, "session_id": sessionID, "path": tpath})
	s2 := keysSession{runID: run2, server: ctl.server, allow: []string{host}, args: []string{"--allowedTools", "Bash"},
		prompt: "Continue with the next command.", dir: t.TempDir(), walled: &k, timeout: 4 * time.Minute}
	o2 := s2.run(t)
	log2 := k.stubLog(t, name)[len(log1):]
	t.Logf("run 1's transcript: %d bytes of %s, session %s; the stub got, in run 1:%s\nin run 2:%s", len(transcript), tpath, sessionID, keysEntries(log1), keysEntries(log2))
	if o2.res.State != event.StateSucceeded {
		t.Errorf("run 2 ended %s, exit %d; want succeeded\nstub:%s\nstdout:\n%s", o2.res.State, o2.res.ExitCode, keysEntries(log2), tail(o2.out, 4000))
	}
	// Run 2 works in another directory than run 1, and the resumed Claude Code appends
	// to the restored file under run 1's slug, which the walled session does not read:
	// the line that run 2 sent no transcript is the one line about a continuation that
	// run 2 may write. A failed restore writes "The runtime starts without a resume".
	for _, d := range o2.of(event.RunLog) {
		b, _ := base64.StdEncoding.DecodeString(fmt.Sprint(d["bytes"]))
		if bytes.Contains(b, []byte("The runtime starts without a resume")) || (bytes.Contains(b, []byte("without a resume")) && !bytes.Contains(b, []byte("the file does not exist, so the session sent no transcript"))) {
			t.Errorf("run 2 wrote: %s", b)
		} else if bytes.Contains(b, []byte("without a resume")) {
			t.Logf("run 2 wrote: %s", b)
		}
	}
	ctl.mu.Lock()
	asked := slices.Clone(ctl.asked)
	ctl.mu.Unlock()
	if !slices.Equal(asked, []string{run2}) {
		t.Errorf("the control plane was asked for the transcript of %q; want run 2's once", asked)
	}
	if len(log2) == 0 || log2[0].Key != "B" || !slices.Contains(log2[0].Turns, "turn-0") || !slices.Contains(log2[0].Turns, "turn-1") || log2[0].Results < 2 {
		t.Errorf("run 2's requests:%s\nwant the first with key B, run 1's two tool results and the marks turn-0 and turn-1", keysEntries(log2))
	}
	for _, e := range log1 {
		if e.Key != "A" {
			t.Errorf("run 1 sent a request with key %q; want A:%s", e.Key, keysEntries(log1))
			break
		}
	}
	noKeyValue(t, o1, s1.dir)
	noKeyValue(t, o2, s2.dir)
}

// storedTranscript joins the dev.qory.session.transcript chunks of run runID that the
// control plane stored, in offset order, and returns the bytes, the runtime's session id
// and the transcript's path. It fails the test when there is none, when the chunks have
// a gap, or when they name two paths.
func storedTranscript(t *testing.T, ctl *keysControl, runID string) ([]byte, string, string) {
	t.Helper()
	type chunk struct {
		SessionID string `json:"session_id"`
		Path      string `json:"path"`
		Offset    int    `json:"offset"`
		Bytes     string `json:"bytes"`
	}
	// The gateway delivers the run's events to the control plane after the run ends:
	// the chunks are complete once its dev.qory.run.exited is stored.
	var chunks []chunk
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		b, err := os.ReadFile(ctl.stored)
		if err != nil {
			t.Fatal(err)
		}
		chunks = chunks[:0]
		exited := false
		s := bufio.NewScanner(bytes.NewReader(b))
		s.Buffer(nil, 1<<22)
		for s.Scan() {
			var e struct {
				Type    string `json:"type"`
				Subject string `json:"subject"`
				Data    chunk  `json:"data"`
			}
			if json.Unmarshal(s.Bytes(), &e) != nil || e.Subject != runID {
				continue
			}
			switch e.Type {
			case event.SessionTranscript:
				chunks = append(chunks, e.Data)
			case event.RunExited:
				exited = true
			}
		}
		if exited || time.Now().After(deadline) {
			break
		}
	}
	if len(chunks) == 0 {
		t.Fatalf("the control plane stored no %s of run %s", event.SessionTranscript, runID)
	}
	sort.SliceStable(chunks, func(i, j int) bool { return chunks[i].Offset < chunks[j].Offset })
	var b []byte
	for _, c := range chunks {
		if c.Path != chunks[0].Path || c.SessionID != chunks[0].SessionID || c.Offset != len(b) {
			t.Fatalf("a chunk at offset %d of %s, session %s, after %d bytes of %s, session %s", c.Offset, c.Path, c.SessionID, len(b), chunks[0].Path, chunks[0].SessionID)
		}
		d, err := base64.StdEncoding.DecodeString(c.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, d...)
	}
	return b, chunks[0].SessionID, chunks[0].Path
}

// startLocalKeysStub starts the stub of scenario in this process, on the first address
// of this machine that is not loopback, with a certificate of the suite's authority, and
// returns its host:port and the file it logs to.
func startLocalKeysStub(t *testing.T, scenario string) (string, string) {
	t.Helper()
	var ip net.IP
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			ip = n.IP.To4()
			break
		}
	}
	if ip == nil {
		Skip(t, "this machine has no IPv4 address but loopback, which NO_PROXY exempts from the proxy")
	}
	ca, caKey := authority()
	leaf, err := sign(ca, caKey, []net.IP{ip})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", net.JoinHostPort(ip.String(), "0"), &tls.Config{Certificates: []tls.Certificate{*leaf}})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "stub.jsonl")
	srv := &http.Server{Handler: newKeysStub(scenario, file), ErrorLog: log.New(io.Discard, "", 0)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), file
}

// readLocalKeysLog reads the log of a stub of this process.
func readLocalKeysLog(t *testing.T, file string) []keysEntry {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return readKeysLog(t, b)
}
