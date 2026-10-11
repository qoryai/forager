package session_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/sink"
)

// The runs of this file are a real session.Run behind a fake separate gateway,
// linktest.StartRemoteFake: the session's RemoteGateway is its run key alone, which
// names the gateway's URL and the key the gateway proves it holds on every connection.

// sepRun is a run of the fake runtime behind a separate gateway: it writes its
// environment to envFile and asks for allowedURL through its proxy; what the session
// reported is in reports.
type sepRun struct {
	sp      session.Spec
	envFile string
	stderr  *syncBuffer

	mu      sync.Mutex
	reports []string
}

// allowedURL is a host the agent asks for through its proxy.
const allowedURL = "http://api.example/a"

func newSepRun(t *testing.T, gw session.Gateway) *sepRun {
	t.Helper()
	r := &sepRun{envFile: filepath.Join(t.TempDir(), "env"), stderr: &syncBuffer{}}
	stdout := &syncBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("stdout:\n%s\nstderr:\n%s", stdout.String(), r.stderr.String())
		}
	})
	r.sp = session.Spec{
		Command: "/bin/sh", Args: []string{"-c", `env > "$0"; exec "$1"`, r.envFile, os.Args[0]},
		Env: []string{"FAKE_RUNTIME=1", "FAKE_EXIT=0", "FAKE_ALLOWED_URL=" + allowedURL, "PATH=" + os.Getenv("PATH")},
		Dir: t.TempDir(), RunsDir: filepath.Join(t.TempDir(), "runs"),
		Stdin: strings.NewReader(""), Stdout: stdout, Stderr: r.stderr,
		Gateway: gw, ForagerVersion: "test",
		Labels: map[string]string{"forge": "example-forge", "repository": "example-namespace/project"},
		About:  &session.About{Title: "Example title"},
		Report: func(l string) {
			t.Log("the session reported:", l)
			r.mu.Lock()
			r.reports = append(r.reports, l)
			r.mu.Unlock()
		},
	}
	return r
}

// started reports whether the runtime started.
func (r *sepRun) started() bool {
	_, err := os.Stat(r.envFile)
	return err == nil
}

// TestASessionRunsBehindASeparateGateway pins a run behind a separate gateway by its
// run key alone: the run is the run key's, every request of the link carries the run
// key as its bearer, the run request carries no labels and no about, which are the
// registration's, the agent's traffic reaches the gateway's proxy on a connection
// opened with QORY-RELAY and the run key, through the session's forwarder, whose
// password the agent's proxy URL carries; and the run key is in no file of the run
// directory and not in the agent's environment.
func TestASessionRunsBehindASeparateGateway(t *testing.T) {
	g := startRemote(t)
	g.SetInterval(30)
	runID := event.NewRunID()
	key := g.RunKey(t, runID)
	r := newSepRun(t, session.RemoteGateway{RunKey: key})
	res, err := session.Run(context.Background(), r.sp)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(res.Dir) != runID || res.State != "succeeded" || res.Undelivered != 0 {
		t.Errorf("result %+v, want the run %s", res, runID)
	}
	if len(g.Bearers()) < 3 {
		t.Errorf("%d requests", len(g.Bearers()))
	}
	for _, b := range g.Bearers() {
		if b != "Bearer "+key {
			t.Errorf("a request carried %q", b)
		}
	}
	if reqs := g.Requests(); len(reqs) != 1 || reqs[0].RunID != runID || reqs[0].Labels != nil || reqs[0].About != nil {
		t.Errorf("the run requests %+v", reqs)
	}
	if want := []string{"QORY-RELAY " + key}; fmt.Sprint(g.Preambles()) != fmt.Sprint(want) {
		t.Errorf("the proxy's preambles %q", g.Preambles())
	}
	if got := g.Proxied(); len(got) != 1 || got[0] != "GET "+allowedURL {
		t.Errorf("the gateway's proxy saw %q", got)
	}
	if started := ofType(events(t, res), "dev.qory.run.started"); len(started) != 1 || data(started[0])["labels"] != nil {
		t.Errorf("run.started %v", started)
	}
	noRunKey(t, res.Dir, key)
	env, _ := os.ReadFile(r.envFile)
	if strings.Contains(string(env), key[4:40]) || !regexp.MustCompile(`(?m)^HTTP_PROXY=http://qory:[A-Za-z0-9_-]{43}@127\.0\.0\.1:[0-9]+$`).Match(env) {
		t.Errorf("the agent's environment:\n%s", env)
	}
	password := regexp.MustCompile(`HTTP_PROXY=http://qory:([A-Za-z0-9_-]+)@`).FindSubmatch(env)
	if password != nil {
		for _, name := range []string{sink.SessionFile, sink.OutputFile} {
			if b, _ := os.ReadFile(filepath.Join(res.Dir, name)); strings.Contains(string(b), string(password[1])) {
				t.Errorf("%s holds the forwarder's password", name)
			}
		}
	}
}

// TestARunKeyTheSessionCannotReadIsNoRun pins the run key the session reads, unverified:
// one it cannot read is the run's error, "QORY_RUN_KEY is not a run key: " and the part
// that is wrong, word for word; a run id the spec names that is not the run key's is
// refused; neither makes a request or a run directory.
func TestARunKeyTheSessionCannotReadIsNoRun(t *testing.T) {
	g := startRemote(t)
	key := g.RunKey(t, event.NewRunID())
	for name, bad := range map[string]string{
		"none":           "",
		"not a run key":  "nonsense",
		"another prefix": "qrx_" + key[4:],
		"no signature":   key[:strings.LastIndex(key, ".")],
	} {
		_, perr := runkey.Parse(bad)
		var re *runkey.Error
		if !errors.As(perr, &re) {
			t.Fatalf("%s: the parse %v", name, perr)
		}
		r := newSepRun(t, session.RemoteGateway{RunKey: bad})
		_, err := session.Run(context.Background(), r.sp)
		if want := "QORY_RUN_KEY is not a run key: " + re.Reason; err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", name, err, want)
		}
		if entries, _ := os.ReadDir(r.sp.RunsDir); len(entries) != 0 || r.started() {
			t.Errorf("%s: a run directory %v, or the runtime started", name, entries)
		}
	}
	r := newSepRun(t, session.RemoteGateway{RunKey: key})
	r.sp.RunID = event.NewRunID()
	if _, err := session.Run(context.Background(), r.sp); err == nil || !strings.HasPrefix(err.Error(), "the run id "+r.sp.RunID+" is not the one QORY_RUN_KEY names, ") {
		t.Errorf("another run id: %v", err)
	}
	if len(g.Bearers()) != 0 || g.Bound() != 0 {
		t.Error("a run key the session refused reached the gateway")
	}
}

// TestAGatewayThatCannotProveItsKeyStartsNoRun pins the binding at the session: a
// gateway whose answer to QORY-BIND does not prove it holds a key the run key names, by
// a signature over another connection, a key the run key does not name or no answer, is
// the run's error word for word, before the run key is sent, and the runtime never
// starts.
func TestAGatewayThatCannotProveItsKeyStartsNoRun(t *testing.T) {
	for name, p := range map[string]linktest.Proof{
		"another connection's signature":  linktest.ProofBadSignature,
		"a key the run key does not name": linktest.ProofUnnamedKey,
		"no answer":                       linktest.ProofNone,
	} {
		g := startRemote(t)
		g.SetProof(p)
		r := newSepRun(t, session.RemoteGateway{RunKey: g.RunKey(t, event.NewRunID())})
		_, err := session.Run(context.Background(), r.sp)
		if want := "the gateway at " + g.URL() + " could not prove it holds a key the run key names"; err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", name, err, want)
		}
		if r.started() || g.Bound() != 0 || len(g.Bearers()) != 0 || len(g.Leaked()) != 0 {
			t.Errorf("%s: the runtime started, or the gateway was sent %q", name, g.Leaked())
		}
	}
}

// TestAnAnswerUnderAnotherKeyStartsNoRun pins the signature of the gateway's answers at
// the session: a discovery signed under a key the run key does not name, or not signed,
// is the run's error word for word, and the runtime never starts.
func TestAnAnswerUnderAnotherKeyStartsNoRun(t *testing.T) {
	for _, unsigned := range []bool{false, true} {
		g := startRemote(t)
		g.AnswerUnderUnnamedKey(t, unsigned)
		r := newSepRun(t, session.RemoteGateway{RunKey: g.RunKey(t, event.NewRunID())})
		_, err := session.Run(context.Background(), r.sp)
		if want := "the gateway at " + g.URL() + " answered under a key the run key does not name"; err == nil || err.Error() != want {
			t.Errorf("unsigned %v: %v, want %q", unsigned, err, want)
		}
		if r.started() || len(g.Requests()) != 0 {
			t.Errorf("unsigned %v: the run went on", unsigned)
		}
	}
}

// TestARemoteGatewayPrintsByItsURL pins that a RemoteGateway prints by the URL its run
// key names, never the run key.
func TestARemoteGatewayPrintsByItsURL(t *testing.T) {
	g := linktest.StartRemoteFake(t)
	key := g.RunKey(t, event.NewRunID())
	gw := session.RemoteGateway{RunKey: key}
	want := "session.RemoteGateway{" + g.URL() + "}"
	for _, out := range []string{fmt.Sprint(gw), fmt.Sprintf("%#v", gw), fmt.Sprintf("%+v", &gw), gw.String()} {
		if out != want {
			t.Errorf("printed as %s, want %s", out, want)
		}
	}
	for raw, want := range map[string]string{
		"":                      "session.RemoteGateway{(no run key)}",
		"qrk_not-a-run-key.sig": "session.RemoteGateway{(not a run key)}",
	} {
		if got := (session.RemoteGateway{RunKey: raw}).String(); got != want {
			t.Errorf("%q prints as %s", raw, got)
		}
	}
}

// TestAResendTakesTheSessionsRecordAlone pins what Resend refuses before any request:
// a directory without session.jsonl, a gateway's record, events.jsonl, which
// gateway.Resend sends, and a record its session still holds.
func TestAResendTakesTheSessionsRecordAlone(t *testing.T) {
	t.Parallel()
	g := linktest.StartRemoteFake(t)
	runID := "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e71"
	dir := filepath.Join(t.TempDir(), runID)
	spec := session.ResendSpec{Gateway: session.RemoteGateway{RunKey: g.RunKey(t, runID)}, Dir: dir, ForagerVersion: "test"}
	if _, err := session.Resend(context.Background(), spec); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no record: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sink.EventsFile), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Resend(context.Background(), spec); !errors.Is(err, os.ErrExist) {
		t.Errorf("a gateway's record: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, sink.EventsFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sink.SessionFile), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// The session's lock, held as a live session holds it.
	held, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Resend(context.Background(), spec); !errors.Is(err, session.ErrRunning) {
		t.Errorf("a record its session holds: %v", err)
	}
	held.Close()
	if len(g.Bearers()) != 0 || g.Bound() != 0 {
		t.Error("a refused resend reached the gateway")
	}
}
