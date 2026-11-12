package e2e

// The end-to-end check of qory's transcript link: Claude Code 2.1.316 starts behind the
// Docker wall through a Linux build of qory, `qory run agent-env`, with
// CLAUDE_CONFIG_DIR at qory's agent home /tmp/qory-agent-home, as a dispatched walled
// run of qory starts it. The qory commit that CI builds is in testdata/qory-commit.

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/claude"
	"github.com/qoryai/forager/wall"
)

// keysPause serves key A's first Bash request with a Bash call that prints turn-0,
// Claude Code's configuration directory, the target of its projects link, and the
// folders of ~/.claude/projects and of the configuration directory's projects, and caps
// A after it.
// It caps key B while /tmp/e2e-b-cooling exists in the stub's container; once the file
// is gone, B's Bash requests get a Bash call that prints turn-1 and the command lines
// of the container's processes that have --resume, then a text.
const keysPause = "pause"

// bCooling is the file whose presence in the stub's container caps key B.
const bCooling = "/tmp/e2e-b-cooling"

// pauseRespond writes the response to a request of keysPause and returns its status,
// or returns 0 when the scenario ends with a text response.
func pauseRespond(s *keysStub, w http.ResponseWriter, req *request, key string, n, results int, tool func(string) map[string]any) int {
	switch key {
	case "A":
		if !req.offers("Bash") {
			return 0
		}
		if results == 0 {
			s.answer(w, req, tool(`echo turn-0; echo "config=$CLAUDE_CONFIG_DIR"; echo "link=$(readlink "$CLAUDE_CONFIG_DIR/projects")"; ls "$HOME/.claude/projects" | sed 's/^/bound=/'; ls "$CLAUDE_CONFIG_DIR/projects" | sed 's/^/home=/'`), "tool_use", n)
			return http.StatusOK
		}
		return keysCap(w)
	case "B":
		if _, err := os.Stat(bCooling); err == nil {
			return keysCap(w)
		}
		if results < 2 && req.offers("Bash") {
			// The pattern is made at run time, so the command line of the shell, which
			// contains this text, does not match it.
			s.answer(w, req, tool(`echo turn-1; r=--res; r=${r}ume; for p in /proc/[0-9]*; do c=$(tr '\0' ' ' < $p/cmdline 2>/dev/null); case "$c" in *"$r "*) echo "cmdline=$c";; esac; done`), "tool_use", n)
			return http.StatusOK
		}
	}
	return 0
}

// envQoryBin is the variable with the path of a Linux build of qory, for the
// architecture of the engine's containers. If it is empty, the tests of qory's
// transcript link skip, or fail when [EnvRequire] is set.
const envQoryBin = "QORY_BIN"

// qoryAgentHome is the agent home of qory's agent-env verb, the folder that
// CLAUDE_CONFIG_DIR points at in a dispatched walled run of Claude Code.
const qoryAgentHome = "/tmp/qory-agent-home"

// qoryLaunchFixed are the fixed values of the launch that qory adds for a dispatched
// walled run of Claude Code.
var qoryLaunchFixed = []string{"CLAUDE_CONFIG_DIR=" + qoryAgentHome}

// qoryFolder makes a folder in t.TempDir() with two files: qory, a copy of the build at
// the path in [envQoryBin], and kept, the file of kept names that qory run writes for a
// dispatched walled run of Claude Code. The wall mounts the folder read-only at the
// same path.
//
// qoryFolder writes the kept file itself, by the steps of keptNames and writeKept in
// qory's cmd/agentenv.go for a run with no run API and no harness home: the wall's
// names, QORY_RUN_ID, the runtime's declared and reserved variables, the variables of
// its model keys and endpoint, the fixed variables of its entry in runtimes.json and
// the launch's fixed values, with the authority's names apart. If qory changes those
// steps, this test breaks, not production: change them here to match.
func qoryFolder(t *testing.T) string {
	t.Helper()
	src := os.Getenv(envQoryBin)
	if src == "" {
		Skip(t, "Set "+envQoryBin+" to the path of a Linux build of qory; it is empty")
	}
	dir := t.TempDir()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "qory"), b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	always, ca := qoryKept(t)
	var text strings.Builder
	for _, n := range always {
		text.WriteString(n + "\n")
	}
	for _, n := range ca {
		text.WriteString("ca " + n + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "kept"), []byte(text.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// qoryKept are the names of the kept file of [qoryFolder], sorted, each once: always,
// the names kept in every run, and ca, the names kept only for a run with an authority.
func qoryKept(t *testing.T) (always, ca []string) {
	t.Helper()
	rt, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	d := &wall.Docker{}
	ca = d.SetsWithAuthority()
	for _, n := range d.Sets() {
		if !slices.Contains(ca, n) {
			always = append(always, n)
		}
	}
	always = append(always, session.EnvRunID)
	if s, ok := rt.(runtimes.Secrets); ok {
		secrets := s.Secrets()
		always = append(always, secrets.Reserves...)
		for _, v := range secrets.Declares {
			always = append(always, v.Name)
		}
	}
	if m, ok := rt.(runtimes.Model); ok {
		if model, ok := m.Model(); ok {
			for _, k := range model.Keys {
				always = append(always, k.Variable)
			}
			always = append(always, model.Endpoint.Variable)
		}
	}
	b, err := fs.ReadFile(contracts.FS, "runtimes.json")
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Runtimes []struct {
			Name  string            `json:"name"`
			Fixed map[string]string `json:"fixed"`
		} `json:"runtimes"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("runtimes.json: %v", err)
	}
	for _, r := range list.Runtimes {
		if r.Name == rt.Name() {
			for n := range r.Fixed {
				always = append(always, n)
			}
		}
	}
	for _, kv := range qoryLaunchFixed {
		n, _, _ := strings.Cut(kv, "=")
		always = append(always, n)
	}
	sorted := func(names []string) []string {
		out := slices.DeleteFunc(slices.Clone(names), func(n string) bool { return n == "" })
		slices.Sort(out)
		return slices.Compact(out)
	}
	return sorted(always), sorted(ca)
}

// projectFolder is the name of the folder of ~/.claude/projects in which Claude Code
// writes the transcript of a session started in dir: dir with every character that is
// not a letter or a digit replaced by -.
func projectFolder(t *testing.T, dir string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(real, "-")
}

// toolLines are the lines of the tool results in Claude Code's stream-json output that
// start with one of prefixes.
func toolLines(out string, prefixes ...string) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(nil, 1<<22)
	for sc.Scan() {
		var m struct {
			Type    string `json:"type"`
			Message struct {
				Content []struct {
					Type    string          `json:"type"`
					Content json.RawMessage `json:"content"`
				} `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal(sc.Bytes(), &m) != nil || m.Type != "user" {
			continue
		}
		for _, c := range m.Message.Content {
			if c.Type != "tool_result" {
				continue
			}
			var s string
			if json.Unmarshal(c.Content, &s) != nil {
				var parts []struct {
					Text string `json:"text"`
				}
				json.Unmarshal(c.Content, &parts)
				for _, p := range parts {
					s += p.Text
				}
			}
			for _, l := range strings.Split(s, "\n") {
				for _, p := range prefixes {
					if strings.HasPrefix(l, p) {
						lines = append(lines, l)
					}
				}
			}
		}
	}
	return lines
}

// sentTranscript reports whether the control plane stored a dev.qory.session.transcript
// of run runID. It fails the test when the run's dev.qory.run.exited is not stored
// within 30 seconds, since the chunks are complete only after it.
func sentTranscript(t *testing.T, ctl *keysControl, runID string) bool {
	t.Helper()
	chunks, exited := storedChunks(t, ctl, runID)
	if !exited {
		t.Fatalf("the control plane stored no %s of run %s within 30 seconds", event.RunExited, runID)
	}
	return len(chunks) > 0
}

// runLogs are the dev.qory.run.log lines of o that contain one of words.
func runLogs(o keysOutcome, words ...string) []string {
	var out []string
	for _, d := range o.of(event.RunLog) {
		b, _ := base64.StdEncoding.DecodeString(fmt.Sprint(d["bytes"]))
		for _, w := range words {
			if bytes.Contains(b, []byte(w)) {
				out = append(out, strings.TrimSpace(string(b)))
				break
			}
		}
	}
	return out
}

// TestDockerQoryLinkPausesAndResumesUnderAnotherKey runs Claude Code 2.1.316 behind the
// wall through qory run agent-env, with CLAUDE_CONFIG_DIR at /tmp/qory-agent-home and the
// link words projects and .claude/projects. Run 1 has keys A and B; the stub serves A's
// first request with a Bash call and then caps A, and caps B, so every key reaches its
// limit and the session ends paused with model_key_limit: the run is paused. Claude
// Code wrote its transcript through the link into the session's transcript directory,
// which the wall binds at ~/.claude/projects, and the session sent it. B's cooldown then
// ends. Run 2, the continuation, has key B and resume with run 1's transcript: the
// session restores it, Claude Code starts with --resume and the session id, its first
// request goes with B and contains run 1's turn, it appends its turns through the link,
// and the run ends succeeded.
func TestDockerQoryLinkPausesAndResumesUnderAnotherKey(t *testing.T) {
	k := newKeysWall(t)
	qory := qoryFolder(t)
	name, host := k.stub(t, keysPause)
	if out, err := exec.Command(k.command, "exec", name, "touch", bCooling).CombinedOutput(); err != nil {
		t.Fatalf("B's cooldown: %v: %s", err, out)
	}
	endpoint := "https://" + host + ":" + recorderTLS
	ctl := startKeysControl(t)
	link := []string{"projects", ".claude/projects"}

	run1 := event.NewRunID()
	ctl.configure(t, run1, host, []map[string]any{keysCredential("model", endpoint), keysCredential("model-b", endpoint)}, []string{keyA, keyB}, nil)
	s1 := keysSession{runID: run1, server: ctl.server, allow: []string{host}, args: []string{"--allowedTools", "Bash"},
		prompt: "Run the commands you are given.", dir: t.TempDir(), walled: &k, timeout: 4 * time.Minute, qory: qory, link: link}
	o1 := s1.run(t)
	log1 := k.stubLog(t, name)
	t.Logf("run 1: the session ended %s, reason %q, exit %d; the stub got:%s", o1.res.State, o1.res.Reason, o1.res.ExitCode, keysEntries(log1))
	t.Logf("run 1: the tool results have %q", toolLines(o1.out, "turn-", "config=", "link=", "bound=", "home="))
	if o1.res.State != event.StatePaused || o1.res.Reason != event.ReasonModelKeyLimit {
		t.Fatalf("run 1 ended %s, %q; want paused, model_key_limit\nstderr:\n%s\nstdout:\n%s", o1.res.State, o1.res.Reason, tail(o1.errs, 4000), tail(o1.out, 4000))
	}
	if n := len(log1); n < 3 || log1[0].Key != "A" || log1[n-2].Key != "A" || log1[n-2].Status != http.StatusTooManyRequests || log1[n-1].Key != "B" || log1[n-1].Status != http.StatusTooManyRequests {
		t.Errorf("run 1's requests:%s\nwant A served, then a 429 with A and one with B", keysEntries(log1))
	}
	folder := projectFolder(t, s1.dir)
	want := []string{"config=" + qoryAgentHome, "link=/home/agent/.claude/projects", "bound=" + folder, "home=" + folder}
	if got := toolLines(o1.out, "config=", "link=", "bound=", "home="); !slices.Equal(got, want) {
		t.Errorf("run 1's tool result has %q; want %q", got, want)
	}
	if lines := runLogs(o1, "without a resume"); len(lines) > 0 {
		t.Errorf("run 1 wrote: %q", lines)
	}
	transcript, sessionID, tpath := storedTranscript(t, ctl, run1)
	t.Logf("run 1's transcript: %d bytes of %s, session %s", len(transcript), tpath, sessionID)
	if !bytes.Contains(transcript, []byte("turn-0")) || !bytes.Contains(transcript, []byte("link=/home/agent/.claude/projects")) {
		t.Fatalf("run 1's transcript has no turn-0 and link line")
	}
	if !strings.HasPrefix(tpath, "~/.claude/projects/"+folder+"/") {
		t.Errorf("run 1's transcript is at %s; want it in ~/.claude/projects/%s", tpath, folder)
	}

	if out, err := exec.Command(k.command, "exec", name, "rm", bCooling).CombinedOutput(); err != nil {
		t.Fatalf("B's cooldown's end: %v: %s", err, out)
	}
	run2 := event.NewRunID()
	ctl.mu.Lock()
	ctl.transcripts[run2] = transcript
	ctl.mu.Unlock()
	ctl.configure(t, run2, host, []map[string]any{keysCredential("model-b", endpoint)}, []string{keyB},
		map[string]any{"run_id": run1, "session_id": sessionID, "path": tpath})
	s2 := keysSession{runID: run2, server: ctl.server, allow: []string{host}, args: []string{"--allowedTools", "Bash"},
		prompt: "Continue with the next command.", dir: s1.dir, walled: &k, timeout: 4 * time.Minute, qory: qory, link: link}
	o2 := s2.run(t)
	log2 := k.stubLog(t, name)[len(log1):]
	t.Logf("run 2: the session ended %s, exit %d; the stub got:%s", o2.res.State, o2.res.ExitCode, keysEntries(log2))
	cmdlines := toolLines(o2.out, "turn-", "cmdline=")
	t.Logf("run 2: the tool results have %q", cmdlines)
	if o2.res.State != event.StateSucceeded {
		t.Errorf("run 2 ended %s, exit %d; want succeeded\nstderr:\n%s\nstdout:\n%s", o2.res.State, o2.res.ExitCode, tail(o2.errs, 4000), tail(o2.out, 4000))
	}
	if lines := runLogs(o2, "without a resume", "Check that the runtime resumes from"); len(lines) > 0 {
		t.Errorf("run 2 wrote: %q", lines)
	}
	if len(log2) == 0 || log2[0].Key != "B" || !slices.Contains(log2[0].Turns, "turn-0") {
		t.Errorf("run 2's requests:%s\nwant the first with key B and run 1's turn-0", keysEntries(log2))
	}
	for _, e := range log2 {
		if e.Key != "B" {
			t.Errorf("run 2 sent a request with key %q; want B", e.Key)
		}
	}
	if !slices.ContainsFunc(cmdlines, func(l string) bool {
		return strings.HasPrefix(l, "cmdline=claude ") && strings.Contains(l, " --resume "+sessionID)
	}) {
		t.Errorf("no process of run 2 is Claude Code with --resume %s: %q", sessionID, cmdlines)
	}
	ctl.mu.Lock()
	asked := slices.Clone(ctl.asked)
	ctl.mu.Unlock()
	if !slices.Equal(asked, []string{run2}) {
		t.Errorf("the control plane was asked for the transcript of %q; want run 2's once", asked)
	}
	continued(t, ctl, run2, transcript, sessionID, tpath)
	noKeyValue(t, o1, s1.dir, qory)
	noKeyValue(t, o2, s2.dir, qory)
}

// TestDockerQoryWithoutTheLinkSendsNoTranscript is the control of
// TestDockerQoryLinkPausesAndResumesUnderAnotherKey: the same run 1 through qory run
// agent-env without the link words writes its transcript in /tmp/qory-agent-home, which
// no bind reaches, so the session sends no transcript and writes that a continuation
// starts without a resume.
func TestDockerQoryWithoutTheLinkSendsNoTranscript(t *testing.T) {
	k := newKeysWall(t)
	qory := qoryFolder(t)
	name, host := k.stub(t, keysPause)
	if out, err := exec.Command(k.command, "exec", name, "touch", bCooling).CombinedOutput(); err != nil {
		t.Fatalf("B's cooldown: %v: %s", err, out)
	}
	endpoint := "https://" + host + ":" + recorderTLS
	ctl := startKeysControl(t)
	run1 := event.NewRunID()
	ctl.configure(t, run1, host, []map[string]any{keysCredential("model", endpoint), keysCredential("model-b", endpoint)}, []string{keyA, keyB}, nil)
	s1 := keysSession{runID: run1, server: ctl.server, allow: []string{host}, args: []string{"--allowedTools", "Bash"},
		prompt: "Run the commands you are given.", dir: t.TempDir(), walled: &k, timeout: 4 * time.Minute, qory: qory}
	o1 := s1.run(t)
	got := toolLines(o1.out, "config=", "link=", "bound=", "home=")
	t.Logf("without the link: the session ended %s, reason %q; the tool results have %q", o1.res.State, o1.res.Reason, got)
	if o1.res.State != event.StatePaused || o1.res.Reason != event.ReasonModelKeyLimit {
		t.Fatalf("run 1 ended %s, %q; want paused, model_key_limit\nstderr:\n%s\nstdout:\n%s", o1.res.State, o1.res.Reason, tail(o1.errs, 4000), tail(o1.out, 4000))
	}
	// Without the link, ~/.claude/projects stays empty and the transcript's folder is in
	// the agent home's projects folder.
	if want := []string{"config=" + qoryAgentHome, "link=", "home=" + projectFolder(t, s1.dir)}; !slices.Equal(got, want) {
		t.Errorf("run 1's tool result has %q; want %q", got, want)
	}
	lines := runLogs(o1, "without a resume")
	t.Logf("without the link: the session wrote %q", lines)
	if sentTranscript(t, ctl, run1) {
		t.Errorf("the session sent a transcript without the link")
	}
	if len(lines) == 0 {
		t.Errorf("the session wrote no line that a continuation starts without a resume")
	}
}
