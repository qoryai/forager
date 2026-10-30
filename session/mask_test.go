package session_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/sink"
	"github.com/qoryai/forager/wall"
)

// The tests of this file pin OpenSpec.Masker and the server's variable values: the run's
// masker replaces each with *** in the run.log chunks, output.log, the events mapped
// from records, the step names, the Report lines and what the gateway receives.

// maskValue is a fake secret of OpenSpec.Masker with a / and a ", so its JSON-escaped and
// percent-encoded forms differ from it; maskForms are those forms.
const maskValue = `fake-mask/value"0123`

var maskForms = []string{maskValue, `fake-mask/value\"0123`, `fake-mask\/value\"0123`, `fake-mask%2Fvalue%220123`}

// maskScript prints the value from $V on stdout and on stderr, in two writes apart by a
// pause from $A and $B, its JSON-escaped forms from $J and $S, its percent-encoded form
// from $P, and a result record whose result is the value.
const maskScript = `printf 'stdout %s\n' "$V"
printf 'stderr %s\n' "$V" >&2
printf 'split %s' "$A"
sleep 0.3
printf '%s end\n' "$B"
printf 'json %s %s\n' "$J" "$S"
printf 'url https://example.test/?q=%s\n' "$P"
printf '{"type":"result","subtype":"success","session_id":"fake","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.01,"result":"%s"}\n' "$J"
`

// maskerOf is a masker from mask.New with values added, as qory makes one for a run.
func maskerOf(t *testing.T, values ...string) *mask.Masker {
	t.Helper()
	m := mask.New()
	for _, v := range values {
		if err := m.AddSecret([]byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

// reports collects a run's Report lines.
type reports struct {
	mu    sync.Mutex
	lines []string
}

func (r *reports) add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, line)
}

func (r *reports) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

// runLogText is the run.log chunks of evs, decoded, one after another.
func runLogText(t *testing.T, evs []map[string]any) string {
	t.Helper()
	var b strings.Builder
	for _, l := range ofType(evs, event.RunLog) {
		c, err := base64.StdEncoding.DecodeString(data(l)["bytes"].(string))
		if err != nil {
			t.Fatal(err)
		}
		b.Write(c)
	}
	return b.String()
}

// noneIn fails the test when text contains one of finds; where says what text is.
func noneIn(t *testing.T, where, text string, finds ...string) {
	t.Helper()
	for _, f := range finds {
		if strings.Contains(text, f) {
			t.Errorf("%s contains %q:\n%s", where, f, text)
		}
	}
}

// noneInDir fails the test when a file under dir, or a run.log chunk of its
// session.jsonl, decoded, contains one of finds.
func noneInDir(t *testing.T, dir string, finds ...string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, f := range finds {
			if bytes.Contains(b, []byte(f)) {
				t.Errorf("%s contains %q", p, f)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	noneIn(t, "the run.log chunks of session.jsonl", runLogText(t, events(t, &session.Result{Dir: dir})), finds...)
}

// noneSent fails the test when an event the gateway received, as JSON, or one of its
// run.log chunks, decoded, contains one of finds, and returns those chunks.
func noneSent(t *testing.T, g *linktest.Fake, finds ...string) string {
	t.Helper()
	evs := g.Events()
	for _, e := range evs {
		b, _ := json.Marshal(e)
		noneIn(t, "an event the gateway received", string(b), finds...)
	}
	logs := runLogText(t, evs)
	noneIn(t, "the run.log chunks the gateway received", logs, finds...)
	return logs
}

// TestAMaskValueIsMaskedInEveryLine pins OpenSpec.Masker in a run with a host step and a
// session whose harness is hidden: the value, split across two writes, JSON-escaped and
// percent-encoded, is *** in the session's stdout and stderr, in the result record's
// event, in the step's name and line, and in a Report line that has the harness file's
// path; neither the run directory after the close nor what the gateway received
// contains it in any form.
func TestAMaskValueIsMaskedInEveryLine(t *testing.T) {
	const reportValue = "fake-report-value-0123"
	sp, g := specGateway(t)
	var got reports
	sp.Report = got.add
	sp.Masker = maskerOf(t, maskValue, reportValue)
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, reportValue), []byte("a\x00b"), 0o644); err != nil {
		t.Fatal(err)
	}
	sp.HarnessHome, sp.HarnessHidden = home, true
	sp.Forwarder = nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", maskScript}
	sp.Env = append(sp.Env, "V="+maskValue, "A="+maskValue[:12], "B="+maskValue[12:], "J="+maskForms[1], "S="+maskForms[2], "P="+maskForms[3])
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	hostStep(t, r, event.StepFetch, "fetch "+maskValue, "fetched "+maskValue+" and "+maskForms[3]+"\n")
	res, err := r.Join(ctx, sp.SessionSpec)
	if _, cerr := r.Close(ctx, outcomeOf(res, err)); cerr != nil {
		t.Fatal(cerr)
	}
	if err != nil {
		t.Fatal(err)
	}
	finds := append([]string{reportValue}, maskForms...)
	noneInDir(t, res.Dir, finds...)
	sent := noneSent(t, g, finds...)
	out, _ := os.ReadFile(filepath.Join(res.Dir, sink.OutputFile))
	for _, want := range []string{"fetched *** and ***\n", "stdout ***\n", "stderr ***\n", "split *** end\n", "json *** ***\n", "url https://example.test/?q=***\n", `"result":"***"`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("output.log has no %q:\n%s", want, out)
		}
		if !strings.Contains(sent, want) {
			t.Errorf("the gateway's run.log chunks have no %q:\n%s", want, sent)
		}
	}
	evs := events(t, res)
	if steps := ofType(evs, event.StepStarted); len(steps) == 0 || data(steps[0])["name"] != "fetch ***" {
		t.Errorf("the host step's step_started %v, want the name fetch ***", steps)
	}
	if results := ofType(evs, "dev.qory.runtime.result"); len(results) != 1 || data(results[0])["result"] != "***" {
		t.Errorf("runtime.result %v, want the result ***", results)
	}
	lines := got.all()
	noneIn(t, "the Report lines", strings.Join(lines, "\n"), finds...)
	if want := "the text of the harness file *** is not masked: it contains a zero byte"; !strings.Contains(strings.Join(lines, "\n"), want) {
		t.Errorf("the Report lines %q have no %q", lines, want)
	}
}

// TestAServersVariableValueOfEightCharactersIsMasked pins the run answer's variables:
// a value of 8 characters is *** in a host step's line and in what the gateway
// received, and a value of 7 is left as it is.
func TestAServersVariableValueOfEightCharactersIsMasked(t *testing.T) {
	const long, short = "srvval08", "srvva07"
	sp, g := specGateway(t)
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["variables"] = map[string]any{"EXAMPLE_LONG": map[string]any{"value": long}, "EXAMPLE_SHORT": map[string]any{"value": short}}
		return linktest.Reply{Status: 200, Body: a}
	})
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	hostStep(t, r, event.StepFetch, "fetch", "long "+long+" short "+short+"\n")
	if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	want := "long *** short " + short + "\n"
	if out, _ := os.ReadFile(filepath.Join(r.Dir(), sink.OutputFile)); string(out) != want {
		t.Errorf("output.log %q, want %q", out, want)
	}
	if sent := noneSent(t, g, long); sent != want {
		t.Errorf("the gateway's run.log chunks %q, want %q", sent, want)
	}
}

// TestAReloadsVariableValueIsMaskedFromThenOn pins a reload whose answer has a variable
// the run answer does not: once the reload is recorded, a host step's line has *** in
// the value's place, in output.log and in what the gateway received.
func TestAReloadsVariableValueIsMaskedFromThenOn(t *testing.T) {
	const reloaded = "fake-reloaded-value"
	first, second := "sha256="+strings.Repeat("1", 64), "sha256="+strings.Repeat("2", 64)
	sp, g := specGateway(t)
	g.SetRunDigest(first)
	g.OnReload(func(string) linktest.Reply {
		return linktest.Reply{Status: 200, Body: map[string]any{"version": 1,
			"variables": map[string]any{"EXAMPLE_RELOADED": map[string]any{"value": reloaded}},
			"applied":   map[string]any{"mode": "observe", "allow": []string{}, "deny": []string{}, "source": "none"}}}
	})
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	g.SetRunDigest(second)
	hostStep(t, r, event.StepFetch, "fetch", "before the reload\n")
	deadline := time.Now().Add(10 * time.Second)
	for len(ofType(g.Events(), event.PolicyApplied)) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("no reload was recorded; reloads %q", g.Reloads())
		}
		time.Sleep(20 * time.Millisecond)
	}
	hostStep(t, r, event.StepFetch, "fetch", "after the reload "+reloaded+"\n")
	if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	want := "before the reload\nafter the reload ***\n"
	if out, _ := os.ReadFile(filepath.Join(r.Dir(), sink.OutputFile)); string(out) != want {
		t.Errorf("output.log %q, want %q", out, want)
	}
	if sent := noneSent(t, g, reloaded); sent != want {
		t.Errorf("the gateway's run.log chunks %q, want %q", sent, want)
	}
}

// TestTheCallersMaskerGetsTheRunsSecrets pins OpenSpec.Masker: the run adds the
// server's variable value of 8 characters or more and the host proxy's password to
// the masker the caller passed, so a writer of the caller's on that masker masks them,
// and the close leaves that masker's values in place for the caller's writers.
func TestTheCallersMaskerGetsTheRunsSecrets(t *testing.T) {
	const serverValue = "fake-server-value-0123"
	sp, g := specGateway(t)
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["variables"] = map[string]any{"EXAMPLE_SERVER": map[string]any{"value": serverValue}}
		return linktest.Reply{Status: 200, Body: a}
	})
	m := maskerOf(t, maskValue)
	sp.Masker = m
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	hp, err := r.HostProxy()
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(hp.ProxyURL)
	if err != nil {
		t.Fatal(err)
	}
	password, _ := u.User.Password()
	if err := hp.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w := mask.NewWriter(&out, m)
	w.Write([]byte(maskValue + " " + serverValue + " http://qory:" + password + "@127.0.0.1"))
	w.Flush()
	if want := "*** *** http://qory:" + mask.ProxyPassword + "@127.0.0.1"; out.String() != want {
		t.Errorf("the caller's writer wrote %q, want %q", out.String(), want)
	}
}

// TestASetupVariableWithAMaskValueIsKept pins Setup in a run with OpenSpec.Masker and a
// server's variable: a setup variable that contains either is passed to the setup
// container, where the host proxy's password would be refused, and the setup step's
// lines have *** in each value's place.
func TestASetupVariableWithAMaskValueIsKept(t *testing.T) {
	const serverValue = "fake-server-value"
	sp, g := specGateway(t, "FAKE_EXIT=0")
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["variables"] = map[string]any{"EXAMPLE_SERVER": map[string]any{"value": serverValue}}
		return linktest.Reply{Status: 200, Body: a}
	})
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.Masker = maskerOf(t, maskValue)
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	env := []string{"APP_TOKEN=" + maskValue, "APP_SERVER=" + serverValue}
	commands := []session.SetupCommand{{Name: "install", Args: []string{"make", maskValue, serverValue}}}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Env: env, Commands: commands}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	for _, kv := range env {
		if !slices.Contains(w.setup.Env, kv) {
			t.Errorf("the setup container's variables have no %s", strings.SplitN(kv, "=", 2)[0])
		}
	}
	evs := events(t, &session.Result{Dir: r.Dir()})
	if got, want := streamsOf(evs, 2), []string{"stdout out make *** ***", "stderr err make *** ***"}; !slices.Equal(got, want) {
		t.Errorf("the setup step's lines %q, want %q", got, want)
	}
	noneInDir(t, r.Dir(), append([]string{serverValue}, maskForms...)...)
}

// TestSessionStartedIsMasked pins dev.qory.session.started in a run with OpenSpec.Masker:
// a harness source's query value, a setup command's name and an argument are *** in
// the record and in what the gateway received.
func TestSessionStartedIsMasked(t *testing.T) {
	const token = "fake-harness-token-0123"
	sp, g := specGateway(t)
	sp.Masker = maskerOf(t, maskValue, token)
	sp.Wall, sp.Image, sp.Mounts = &openWall{}, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	sp.Forwarder = nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", "true", maskValue}
	sp.SetupRunner = setupRunner
	sp.SessionSpec.Setup = []session.SetupCommand{{Name: "install " + maskValue, Args: []string{"/bin/sh", "-c", "echo set up"}}}
	sp.Harness = []session.HarnessSource{{Source: "https://git.example/example-org/harness?token=" + token, Commit: strings.Repeat("a1", 20)}}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	noneSent(t, g, append([]string{token}, maskForms...)...)
	for where, evs := range map[string][]map[string]any{"the record": events(t, res), "the link": g.Events()} {
		started := sessionStarted(t, evs)
		harness, _ := started["harness"].([]any)
		if len(harness) != 1 || harness[0].(map[string]any)["source"] != "https://git.example/example-org/harness?token=***" {
			t.Errorf("%s: session.started harness %v", where, started["harness"])
		}
		if got := fmt.Sprint(started["setup_commands"]); got != "[install ***]" {
			t.Errorf("%s: session.started setup_commands %s", where, got)
		}
		if args, _ := started["args"].([]any); len(args) == 0 || args[len(args)-1] != "***" {
			t.Errorf("%s: session.started args %v", where, started["args"])
		}
	}
}

// TestALineIsMaskedOnce pins a failed image step whose error has the engine proxy's
// password, in a run whose server has the value "password": the step's line and the
// returned error have qory-proxy-password whole, which a second pass of the run's
// masker would turn into qory-proxy-***.
func TestALineIsMaskedOnce(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["image"] = map[string]any{"ref": pinned, "reference": true}
		a["relay_image"] = "example.com/agent:1"
		a["applied"].(map[string]any)["image"] = pinned
		a["variables"] = map[string]any{"EXAMPLE_WORD": map[string]any{"value": "password"}}
		return linktest.Reply{Status: 200, Body: a}
	})
	w := &pullingWall{}
	w.during = func(context.Context) error {
		return errors.New("docker pull: proxyconnect tcp: http://qory:" + enginePassword + "@127.0.0.1 refused")
	}
	sp.Wall, sp.Image, sp.ImagesAllow = w, "example.com/agent:1", []string{"registry.example/"}
	sp.EngineProxy = &session.EngineProxy{Addr: freeLoopback(t), Password: enginePassword}
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	err = r.FetchImage(ctx)
	if _, cerr := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); cerr != nil {
		t.Fatal(cerr)
	}
	want := "docker pull: proxyconnect tcp: http://qory:qory-proxy-password@127.0.0.1 refused"
	if err == nil || err.Error() != want {
		t.Errorf("FetchImage: %v, want %s", err, want)
	}
	if out, _ := os.ReadFile(filepath.Join(r.Dir(), sink.OutputFile)); string(out) != want+"\n" {
		t.Errorf("output.log %q, want %q", out, want+"\n")
	}
}

// TestTheCopiesOfTheOutputAreMasked pins the copy of the runtime's output to
// SessionSpec.Stdout and Stderr, on pipes and on a pseudo-terminal: the value of
// OpenSpec.Masker, split across two writes and JSON-escaped, is *** in each copy, and
// the copy's last bytes, which the masker keeps back, are written when the process ends.
func TestTheCopiesOfTheOutputAreMasked(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		sp := spec(t)
		sp.Masker = maskerOf(t, maskValue)
		sp.Interactive = interactive
		sp.Forwarder = nil
		sp.Command, sp.Args = "/bin/sh", []string{"-c", maskScript + `printf 'last %s' "$V"`}
		sp.Env = append(sp.Env, "V="+maskValue, "A="+maskValue[:12], "B="+maskValue[12:], "J="+maskForms[1], "S="+maskForms[2], "P="+maskForms[3])
		var stdout, stderr bytes.Buffer
		sp.Stdout, sp.Stderr = &stdout, &stderr
		if _, err := run(context.Background(), sp); err != nil {
			t.Fatal(err)
		}
		copies := stdout.String() + stderr.String()
		noneIn(t, fmt.Sprintf("the copies of the output, interactive %v", interactive), copies, maskForms...)
		for _, want := range []string{"stdout ***", "stderr ***", "split *** end", "json *** ***", "last ***"} {
			if !strings.Contains(copies, want) {
				t.Errorf("interactive %v: the copies have no %q:\n%s", interactive, want, copies)
			}
		}
	}
}

// TestRunStartedIsMasked pins dev.qory.run.started in a run with OpenSpec.Masker: a
// value in about's title is *** in the record and in what the gateway received, and a
// label's value stays as the gateway registered it, the value included, since the
// gateway refuses a run.started with other labels.
func TestRunStartedIsMasked(t *testing.T) {
	const token = "fake-label-token-0123"
	sp, g := specGateway(t)
	sp.Masker = maskerOf(t, maskValue, token)
	sp.About = &session.About{Kind: "task", Title: "deploy " + maskValue}
	sp.Labels = map[string]string{"example": token}
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	noneSent(t, g, maskForms...)
	for where, evs := range map[string][]map[string]any{"the record": events(t, &session.Result{Dir: r.Dir()}), "the link": g.Events()} {
		started := ofType(evs, event.RunStarted)
		if len(started) != 1 {
			t.Fatalf("%s: %d run.started", where, len(started))
		}
		d := data(started[0])
		if about, _ := d["about"].(map[string]any); about == nil || about["title"] != "deploy ***" {
			t.Errorf("%s: run.started about %v", where, d["about"])
		}
		if labels, _ := d["labels"].(map[string]any); labels == nil || labels["example"] != token {
			t.Errorf("%s: run.started labels %v", where, d["labels"])
		}
	}
}

// TestTheErrorsOfOpenAndJoinAreMasked pins the errors Open and Join return in a run
// with OpenSpec.Masker: a run id that contains the value, and a command that does, are
// *** in the error's text, and errors.Is still finds ErrNotStarted.
func TestTheErrorsOfOpenAndJoinAreMasked(t *testing.T) {
	const token = "fake-error-token-0123"
	sp := spec(t)
	sp.Masker = maskerOf(t, token)
	sp.RunID = "run-" + token
	_, err := session.Open(context.Background(), opened(sp))
	if want := `the run id "run-***" is not a UUID in the canonical lower-case form`; err == nil || err.Error() != want {
		t.Errorf("Open: %v, want %q", err, want)
	}
	sp.RunID = ""
	sp.Forwarder = nil
	sp.Command, sp.Args = "/nonexistent/"+token, nil
	_, err = run(context.Background(), sp)
	if err == nil || !errors.Is(err, session.ErrNotStarted) {
		t.Fatalf("Join: %v, want ErrNotStarted", err)
	}
	noneIn(t, "the error of Join", err.Error(), token)
	if !strings.Contains(err.Error(), "/nonexistent/***") {
		t.Errorf("Join: %v, want /nonexistent/*** in it", err)
	}
}

// TestTheErrorsOfSetupFetchImageAndStepsAreMasked pins the errors Setup, FetchImage,
// StartStep and Step.Exit return in a run with OpenSpec.Masker: a value of the masker
// and a key in the shape of a GitHub token are *** in each error's text, and in the
// line of the failed step in output.log; errors.As still finds the run's
// *SetupError. Step.Log's errors contain no text of the caller's.
func TestTheErrorsOfSetupFetchImageAndStepsAreMasked(t *testing.T) {
	const token = "fake-error-token-0123"
	ghp := "ghp_" + strings.Repeat("x", 36)
	failure := "fails with " + token + " and " + ghp
	ctx := context.Background()
	check := func(t *testing.T, what string, err error, want string) {
		t.Helper()
		if err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", what, err, want)
		}
	}

	t.Run("Setup", func(t *testing.T) {
		sp := spec(t, "FAKE_EXIT=0")
		sp.Masker = maskerOf(t, token)
		sp.Wall, sp.Image = &setupWall{startErr: errors.New(failure)}, "example.com/agent:1"
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		err = r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands})
		r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1})
		check(t, "Setup", err, "fails with *** and ***")
		if out, _ := os.ReadFile(filepath.Join(r.Dir(), sink.OutputFile)); !strings.Contains(string(out), "fails with *** and ***\n") {
			t.Errorf("output.log %q", out)
		}
	})

	t.Run("a setup command that fails", func(t *testing.T) {
		sp := spec(t, "FAKE_EXIT=0")
		sp.Masker = maskerOf(t, token)
		sp.Wall, sp.Image = &setupWall{codes: map[string]int{"make": 2}}, "example.com/agent:1"
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		err = r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: []session.SetupCommand{{Name: "install " + ghp, Args: []string{"make", "deps"}}}})
		r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1})
		var se *session.SetupError
		if !errors.As(err, &se) || se.Name != "install ***" {
			t.Errorf("Setup: %v, want a *SetupError named install ***", err)
		}
		noneIn(t, "the error of Setup", err.Error(), ghp)
	})

	t.Run("FetchImage", func(t *testing.T) {
		sp, g := specGateway(t, "FAKE_EXIT=0")
		g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
			a := linktest.RunAnswer(req)
			a["image"] = map[string]any{"ref": pinned, "reference": true}
			a["relay_image"] = "example.com/agent:1"
			a["applied"].(map[string]any)["image"] = pinned
			return linktest.Reply{Status: 200, Body: a}
		})
		sp.Masker = maskerOf(t, token)
		w := &pullingWall{}
		w.during = func(context.Context) error { return errors.New("docker pull " + failure) }
		sp.Wall, sp.Image, sp.ImagesAllow = w, "example.com/agent:1", []string{"registry.example/"}
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		err = r.FetchImage(ctx)
		r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1})
		check(t, "FetchImage", err, "docker pull fails with *** and ***")
		if out, _ := os.ReadFile(filepath.Join(r.Dir(), sink.OutputFile)); string(out) != "docker pull fails with *** and ***\n" {
			t.Errorf("output.log %q", out)
		}
	})

	t.Run("StartStep and Step.Exit", func(t *testing.T) {
		sp := spec(t, "FAKE_EXIT=0")
		sp.Masker = maskerOf(t, token)
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
		_, err = r.StartStep("fetch "+token+" "+ghp, "fetch github.com/example-org/app")
		check(t, "StartStep", err, `start a host step of kind fetch, compose or build, not "fetch *** ***": Join writes the join, image and wall steps`)
		step, err := r.StartStep(event.StepFetch, "fetch github.com/example-org/app")
		if err != nil {
			t.Fatal(err)
		}
		err = step.Exit(token+" "+ghp, 0)
		check(t, "Step.Exit", err, `exit the step with succeeded, failed or cancelled, not "*** ***"`)
		if err := step.Exit(event.StateSucceeded, 0); err != nil {
			t.Fatal(err)
		}
	})
}

// TestAnEnginePasswordIsMaskedAsAURLPrintsIt pins an engine proxy password with the
// bytes a URL escapes, @ / : % ? and #: a pull error that prints the proxy URL, which
// escapes them, has the placeholder in place of the password in FetchImage's error and
// in the image step's line, and so does a host step's line with the password escaped
// for a query.
func TestAnEnginePasswordIsMaskedAsAURLPrintsIt(t *testing.T) {
	const password = "fake@pass/word:50%?x#y-0123"
	addr := freeLoopback(t)
	proxyURL := (&url.URL{Scheme: "http", User: url.UserPassword("qory", password), Host: addr}).String()
	sp, g := specGateway(t, "FAKE_EXIT=0")
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["image"] = map[string]any{"ref": pinned, "reference": true}
		a["relay_image"] = "example.com/agent:1"
		a["applied"].(map[string]any)["image"] = pinned
		return linktest.Reply{Status: 200, Body: a}
	})
	w := &pullingWall{}
	w.during = func(context.Context) error {
		return errors.New("docker pull: proxyconnect tcp: " + proxyURL + ": refused")
	}
	sp.Wall, sp.Image, sp.ImagesAllow = w, "example.com/agent:1", []string{"registry.example/"}
	sp.EngineProxy = &session.EngineProxy{Addr: addr, Password: password}
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	err = r.FetchImage(ctx)
	want := "docker pull: proxyconnect tcp: http://qory:qory-proxy-password@" + addr + ": refused"
	if err == nil || err.Error() != want {
		t.Errorf("FetchImage: %v, want %s", err, want)
	}
	step, err := r.StartStep(event.StepFetch, "fetch github.com/example-org/app")
	if err != nil {
		t.Fatal(err)
	}
	if err := step.Log([]byte("GET /?proxy_password=" + url.QueryEscape(password) + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := step.Exit(event.StateSucceeded, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(filepath.Join(r.Dir(), sink.OutputFile))
	if got := string(out); got != want+"\nGET /?proxy_password=qory-proxy-password\n" {
		t.Errorf("output.log %q", got)
	}
}
