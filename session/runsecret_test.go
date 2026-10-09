package session_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/link"
	refusals "github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/sink"
	"github.com/qoryai/forager/wall"
)

// runSecretFile is the file of the run directory that keeps the run's secret behind a
// separate gateway.
const runSecretFile = "run-secret"

// runSecretShape is a run secret's form, link-run-answer.schema.json's run_secret.
var runSecretShape = regexp.MustCompile(`^[A-Za-z0-9_-]{22,256}$`)

// keptRunSecret is the run secret the run directory keeps, failing the test unless it
// is there, mode 0600, the secret and one newline.
func keptRunSecret(t *testing.T, dir string) string {
	t.Helper()
	file := filepath.Join(dir, runSecretFile)
	info, err := os.Lstat(file)
	if err != nil {
		t.Fatalf("the run secret's file: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Errorf("the run secret's file is %v, want a file of mode 0600", info.Mode())
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	secret, ok := strings.CutSuffix(string(b), "\n")
	if !ok || !runSecretShape.MatchString(secret) {
		t.Errorf("the run secret's file holds %d bytes, not a run secret and a newline", len(b))
	}
	return secret
}

// noRunSecret fails the test if the run directory keeps a run secret.
func noRunSecret(t *testing.T, what, dir string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(dir, runSecretFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s: the run directory keeps its run secret: %v", what, err)
	}
}

// readingWall is a sepWall whose walled agent reads the run directory, as one can
// that the run directory is bound into, and asks the gateway for its run with the run
// secret it read there.
type readingWall struct {
	*sepWall
	s       *separate
	runsDir string
	other   string

	runID  string
	secret string
	// alone and otherKey are the statuses the agent got: a batch with the run secret
	// and no run credential, and one with the run secret and a run credential of
	// another run key.
	alone, otherKey int
}

func (w *readingWall) Prepare(_ context.Context, req wall.Request) (wall.Enclosure, error) {
	w.runID = req.RunID
	return w, nil
}

func (w *readingWall) Wrap(ctx context.Context, l wall.Launch) (wall.Launch, error) {
	// The agent reads the run directory: the run secret is there from the run's open.
	b, err := os.ReadFile(filepath.Join(w.runsDir, w.runID, runSecretFile))
	if err != nil {
		return wall.Launch{}, err
	}
	w.secret = strings.TrimSuffix(string(b), "\n")
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: w.s.pool, MinVersion: tls.VersionTLS13}}}
	ask := func(method, path, credential string, body []byte) int {
		req, _ := http.NewRequest(method, w.s.url()+path, bytes.NewReader(body))
		if body != nil {
			req.Header.Set("Content-Type", server.ContentType)
		}
		req.Header.Set(server.HeaderRunSecret, w.secret)
		if credential != "" {
			req.Header.Set("Authorization", link.BearerScheme+" "+credential)
		}
		resp, err := c.Do(req)
		if err != nil {
			return 0
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	beat, _ := json.Marshal([]map[string]any{{
		"specversion": "1.0", "id": event.NewID(), "source": event.Source(w.runID), "type": event.RunHeartbeat, "subject": w.runID,
		"time": time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00"), "dataschema": event.DataSchema(event.RunHeartbeat), "data": map[string]any{"elapsed_seconds": 1, "interval_seconds": 30},
	}})
	w.alone = ask(http.MethodPost, "/v1/events", "", beat)
	w.otherKey = ask(http.MethodPost, "/v1/events", w.other, beat)
	return w.sepWall.Wrap(ctx, l)
}

// TestAWalledAgentThatReadsTheRunSecretReachesNoRun pins the run secret against a
// walled agent that can read the run directory, which holds it from the run's open: it
// adds nothing to what the agent holds, since the run secret names the run and opens
// nothing without a run credential of the run's run key. A batch with it alone, or
// with a run credential of another run key, is the 401; the run goes on, its record
// owes nothing at its end, and the file is gone. The secret is in no record, no
// report, the agent's environment or the enclosure's.
func TestAWalledAgentThatReadsTheRunSecretReachesNoRun(t *testing.T) {
	s := startSeparate(t)
	cred := credentialOf("rk-0001")
	r := newSepRun(t, s.remote(fixedCredential(cred)))
	w := &readingWall{sepWall: &sepWall{gateway: s.g.Addr(), pool: s.pool}, s: s, runsDir: r.sp.RunsDir, other: credentialOf("rk-0002")}
	r.sp.Wall, r.sp.Image = w, "registry.example/agents/base:1"
	res, err := session.Run(context.Background(), r.sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || res.State != "succeeded" || res.RunClosed || res.Undelivered != 0 {
		t.Errorf("result %+v", res)
	}
	if !runSecretShape.MatchString(w.secret) {
		t.Fatalf("the agent read %d bytes of run secret", len(w.secret))
	}
	if w.alone != http.StatusUnauthorized || w.otherKey != http.StatusUnauthorized {
		t.Errorf("the agent's batches with the run secret: alone %d, with another run key's run credential %d; want 401 each", w.alone, w.otherKey)
	}
	noRunSecret(t, "after a run that owes nothing", res.Dir)
	w.mu.Lock()
	got := w.got
	w.mu.Unlock()
	for _, kv := range got.Env {
		if strings.Contains(kv, w.secret) {
			t.Errorf("the enclosure's environment holds the run secret: %s", strings.SplitN(kv, "=", 2)[0])
		}
	}
	for k, v := range r.env(t) {
		if strings.Contains(v, w.secret) {
			t.Errorf("the agent's %s holds the run secret", k)
		}
	}
	for _, f := range []string{"output.log", sink.DeliveredFile} {
		if b, _ := os.ReadFile(filepath.Join(res.Dir, f)); bytes.Contains(b, []byte(w.secret)) {
			t.Errorf("%s holds the run secret", f)
		}
	}
	s.close(t)
	r.noSecretIn(t, s, res.RunID, cred, w.secret)
}

// TestTheRunSecretIsKeptWhileTheRecordOwes pins the run-secret file's lifetime behind
// a separate gateway: none after a run that owes nothing; after one that owes, mode
// 0600, kept through a resend's 401, and removed by the resend that delivers the rest.
// A resend whose directory keeps none sends without it, and gets the 401; one that
// owes nothing from the start removes a file left behind.
func TestTheRunSecretIsKeptWhileTheRecordOwes(t *testing.T) {
	t.Parallel()
	// Three heartbeat intervals outlast the session's close and the resends.
	s := startSeparateBeating(t, 20*time.Second)
	cred := credentialOf("rk-0001")

	owing, res := spooledRun(t, s, cred)
	secret := keptRunSecret(t, res.Dir)
	restarted := startSeparate(t)
	_, err := session.Resend(context.Background(), resendSpec(restarted, res.Dir, fixedCredential(cred)))
	var ref *session.Refusal
	if !errors.As(err, &ref) || ref.Code != refusals.RunCredentialRefused || ref.Status != 401 {
		t.Fatalf("a restarted gateway: %v", err)
	}
	if keptRunSecret(t, res.Dir) != secret {
		t.Error("the resend's 401 changed the run secret")
	}
	// Without the file the gateway refuses every batch: the 401, and the file is not
	// made.
	if err := os.Rename(filepath.Join(res.Dir, runSecretFile), filepath.Join(res.Dir, "kept")); err != nil {
		t.Fatal(err)
	}
	_, err = session.Resend(context.Background(), resendSpec(s, res.Dir, fixedCredential(cred)))
	if !errors.As(err, &ref) || ref.Code != refusals.RunCredentialRefused || ref.Status != 401 || ref.From != accesskey.FromGateway {
		t.Fatalf("a resend without the run secret: %v", err)
	}
	noRunSecret(t, "a resend without the run secret", res.Dir)
	if err := os.Rename(filepath.Join(res.Dir, "kept"), filepath.Join(res.Dir, runSecretFile)); err != nil {
		t.Fatal(err)
	}
	got, err := session.Resend(context.Background(), resendSpec(s, res.Dir, fixedCredential(cred)))
	if err != nil || got != (session.ResendResult{Sent: res.Undelivered, State: "succeeded"}) {
		t.Fatalf("the resend %+v %v; the session left %d undelivered", got, err, res.Undelivered)
	}
	noRunSecret(t, "after the resend that delivered the rest", res.Dir)
	// A run-secret file of a record that owes nothing goes, with no request.
	if err := os.WriteFile(filepath.Join(res.Dir, runSecretFile), []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	again, n := counted(cred)
	if got, err := session.Resend(context.Background(), resendSpec(s, res.Dir, again)); err != nil || got != (session.ResendResult{}) || n.Load() != 0 {
		t.Errorf("a resend of a record that owes nothing: %+v %v, %d requests", got, err, n.Load())
	}
	noRunSecret(t, "a resend of a record that owes nothing", res.Dir)
	s.close(t)
	owing.noSecretIn(t, s, res.RunID, cred, secret)

	// A run that owes nothing at its end leaves none.
	s2 := startSeparate(t)
	r := newSepRun(t, s2.remote(fixedCredential(cred)))
	done, err := session.Run(context.Background(), r.sp)
	if err != nil || done.Undelivered != 0 {
		t.Fatalf("a run: %+v %v", done, err)
	}
	noRunSecret(t, "after a run that owes nothing", done.Dir)
}

// TestAResendCutShortKeepsTheRunSecret pins a resend whose context ends after the
// discovery, before the gateway takes what is owed: it returns no error, with the events
// still undelivered, and the run secret is kept for the resend that delivers them, which
// removes it.
func TestAResendCutShortKeepsTheRunSecret(t *testing.T) {
	t.Parallel()
	// Three heartbeat intervals outlast the session's close and the resends.
	s := startSeparateBeating(t, 20*time.Second)
	cred := credentialOf("rk-0001")
	_, res := spooledRun(t, s, cred)
	secret := keptRunSecret(t, res.Dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var asked atomic.Int32
	cutShort := func(context.Context) (string, error) {
		// The discovery is the first request; the context ends before the first batch
		// is sent, and no batch goes out.
		if asked.Add(1) > 1 {
			cancel()
			return "", context.Canceled
		}
		return cred, nil
	}
	got, err := session.Resend(ctx, resendSpec(s, res.Dir, cutShort))
	if err != nil || got.Sent != 0 || got.Undelivered == 0 || got.RunClosed {
		t.Fatalf("the resend cut short: %+v %v", got, err)
	}
	if keptRunSecret(t, res.Dir) != secret {
		t.Error("the resend cut short changed the run secret")
	}
	got, err = session.Resend(context.Background(), resendSpec(s, res.Dir, fixedCredential(cred)))
	if err != nil || got != (session.ResendResult{Sent: res.Undelivered, State: "succeeded"}) {
		t.Fatalf("the resend %+v %v; the session left %d undelivered", got, err, res.Undelivered)
	}
	noRunSecret(t, "after the resend that delivered the rest", res.Dir)
}

// TestAResendRemovesTheRunSecretAfterTheRunsEnd pins the resend of a run the gateway
// ended: its 401 keeps the run secret, and the run's 410, after which nothing more can
// be delivered, removes it.
func TestAResendRemovesTheRunSecretAfterTheRunsEnd(t *testing.T) {
	t.Parallel()
	s := startSeparate(t)
	cred := credentialOf("rk-0001")
	_, res := spooledRun(t, s, cred)
	keptRunSecret(t, res.Dir)
	waitFor(t, func() bool {
		_, err := os.Stat(filepath.Join(s.dir, "runs", res.RunID, "events.jsonl"))
		return err == nil && len(ofType(s.record(t, res.RunID), "dev.qory.run.exited")) > 0
	})
	expired := mintCredentialWith(sepIssuerKey(), "rk-0001", "example-requester", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	if _, err := session.Resend(context.Background(), resendSpec(s, res.Dir, fixedCredential(expired))); err == nil {
		t.Fatal("an expired run credential was taken")
	}
	keptRunSecret(t, res.Dir)
	got, err := session.Resend(context.Background(), resendSpec(s, res.Dir, fixedCredential(cred)))
	if err != nil || !got.RunClosed || got.Reason != "session_lost" {
		t.Fatalf("the resend %+v %v", got, err)
	}
	noRunSecret(t, "after the run's 410", res.Dir)
}

// TestASessionCarriesItsRunSecretOnTheLocalLink pins the run secret on the local link:
// the session carries the run answer's run_secret on every reload and batch, once each,
// and keeps no file of it, since nothing on one machine sends the session's record
// again.
func TestASessionCarriesItsRunSecretOnTheLocalLink(t *testing.T) {
	sp, g := specGateway(t)
	sleeps(&sp, time.Second)
	g.SetRunDigest("sha256=" + strings.Repeat("1", 64))
	g.OnBatch(func([]map[string]any) linktest.Reply {
		// Another digest: the session reloads.
		g.SetRunDigest("sha256=" + strings.Repeat("2", 64))
		return linktest.Reply{Status: 200}
	})
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	secrets := g.RunSecrets()
	if len(g.Reloads()) == 0 || len(secrets) != len(g.Reloads())+len(g.Batches()) {
		t.Fatalf("%d reloads, %d batches, %d run secrets", len(g.Reloads()), len(g.Batches()), len(secrets))
	}
	for i, got := range secrets {
		if got != linktest.RunSecret {
			t.Errorf("request %d carried %q, want the run answer's run secret once", i, got)
		}
	}
	noRunSecret(t, "on the local link", res.Dir)
}
