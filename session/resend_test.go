package session_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	refusals "github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/runcredential"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/sink"
)

// The resends of this file send a session's record again through a real separate
// gateway, gateway.Start on loopback over TLS, as separate_test.go runs sessions behind
// one. Each spooled run is a real session.Run whose batches never reached the gateway.

// mintCredentialWith is a run credential of the example issuer for the run key, issued
// at iat and expiring at exp, with the requester given.
func mintCredentialWith(key ed25519.PrivateKey, runKey, requester string, iat, exp time.Time) string {
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": "k1", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{
		"iss": sepIssuer, "aud": sepAudience, "sub": runKey, "iat": iat.Unix(), "exp": exp.Unix(),
		"namespace": "example-namespace", "project": "project", "requester": requester,
	})
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(input)))
}

// counted is a run credential that does not change, and how often it was asked for:
// once before each request.
func counted(c string) (func(context.Context) (string, error), *atomic.Int32) {
	var n atomic.Int32
	return func(context.Context) (string, error) { n.Add(1); return c, nil }, &n
}

// errOffline is the run credential's failure once the session's link is cut.
var errOffline = errors.New("the run credential cannot be read")

// spooledRun runs a session behind s whose run opens and whose first batch, its
// run.started among it, reaches the gateway, and every batch after it fails, its run
// credential failing after the discovery, the run request and that batch: the gateway
// holds the run open without its exit, and the session's run directory keeps
// session.jsonl, a delivered.log that names the first batch, and undelivered/.
func spooledRun(t *testing.T, s *separate, cred string) (*sepRun, *session.Result) {
	t.Helper()
	var asked atomic.Int32
	r := newSepRun(t, s.remote(func(context.Context) (string, error) {
		if asked.Add(1) > 3 {
			return "", errOffline
		}
		return cred, nil
	}))
	r.sp.Args = []string{"-c", "sleep 1"}
	res, err := session.Run(context.Background(), r.sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || res.RunClosed || res.Undelivered == 0 {
		t.Fatalf("result %+v", res)
	}
	if accepted, stopped, err := sink.Delivered(res.Dir); err != nil || stopped || len(accepted) == 0 {
		t.Fatalf("delivered.log %v, stopped %v, %v", accepted, stopped, err)
	}
	if _, err := os.Stat(filepath.Join(res.Dir, sink.DeliveredFile)); err != nil {
		t.Fatal(err)
	}
	if spooled, _ := os.ReadDir(filepath.Join(res.Dir, sink.UndeliveredDir)); len(spooled) == 0 {
		t.Fatal("the session spooled nothing under undelivered/")
	}
	return r, res
}

// resendSpec is the resend of a run's directory through s with the credential.
func resendSpec(s *separate, dir string, cred func(context.Context) (string, error)) session.ResendSpec {
	return session.ResendSpec{Gateway: s.remote(cred), Dir: dir, ForagerVersion: "test"}
}

// sessionLines is the session's record as its bytes.
func sessionLines(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, sink.SessionFile))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestAResendDeliversWhatTheSeparateGatewayDidNotTake pins the resend of a run the
// gateway still holds open: after a restarted gateway's 401 and a differing run
// credential's 403, each a refusal from the gateway that leaves the events spooled,
// the gateway the run spoke to takes every event the session recorded and posted, its
// record ending with the session's own run.exited; the run directory then owes
// nothing, and a resend again makes no request at all and is not NotOpened.
func TestAResendDeliversWhatTheSeparateGatewayDidNotTake(t *testing.T) {
	t.Parallel()
	// Three heartbeat intervals outlast the session's close and the resends.
	s := startSeparateBeating(t, 20*time.Second)
	cred := credentialOf("rk-0001")
	r, res := spooledRun(t, s, cred)
	before := sessionLines(t, res.Dir)

	// A gateway that restarted holds no run of the run credential: the 401.
	restarted := startSeparate(t)
	_, err := session.Resend(context.Background(), resendSpec(restarted, res.Dir, fixedCredential(cred)))
	var ref *session.Refusal
	if !errors.As(err, &ref) || ref.Code != refusals.RunCredentialRefused || ref.Status != 401 || ref.From != accesskey.FromGateway || err.Error() != runcredential.ErrRefused.Error() {
		t.Fatalf("a restarted gateway: %#v", err)
	}
	if spooled, _ := os.ReadDir(filepath.Join(res.Dir, sink.UndeliveredDir)); len(spooled) == 0 {
		t.Error("the events refused with the 401 are not under undelivered/")
	}

	// A run credential of the run key that differs from the run's: the 403, at once.
	other := mintCredentialWith(sepIssuerKey(), "rk-0001", "someone-else", time.Now().Add(-time.Second), time.Now().Add(time.Hour))
	start := time.Now()
	_, err = session.Resend(context.Background(), resendSpec(s, res.Dir, fixedCredential(other)))
	if !errors.As(err, &ref) || ref.Code != refusals.DiffersFromCredential || ref.Status != 403 || ref.From != accesskey.FromGateway || fmt.Sprint(ref.Names) != "[about.details.requester=someone-else]" || time.Since(start) > 5*time.Second {
		t.Fatalf("a differing run credential: %#v after %s", err, time.Since(start))
	}
	if spooled, _ := os.ReadDir(filepath.Join(res.Dir, sink.UndeliveredDir)); len(spooled) == 0 {
		t.Error("the events refused with the 403 are not under undelivered/")
	}

	got, err := session.Resend(context.Background(), resendSpec(s, res.Dir, fixedCredential(cred)))
	if err != nil {
		t.Fatal(err)
	}
	if got != (session.ResendResult{Sent: res.Undelivered, State: "succeeded"}) {
		t.Errorf("the resend %+v; the session left %d undelivered", got, res.Undelivered)
	}
	if _, err := os.Stat(filepath.Join(res.Dir, sink.UndeliveredDir)); err == nil {
		t.Error("undelivered/ is left after the gateway took everything")
	}
	if !bytes.Equal(sessionLines(t, res.Dir), before) {
		t.Error("the resend changed session.jsonl")
	}
	again, n := counted(cred)
	if got, err := session.Resend(context.Background(), resendSpec(s, res.Dir, again)); err != nil || got != (session.ResendResult{State: "succeeded"}) || got.NotOpened || n.Load() != 0 {
		t.Errorf("a resend of a record that owes nothing: %+v %v, %d requests", got, err, n.Load())
	}
	s.close(t)
	own := events(t, res)
	numbered := s.record(t, res.RunID)
	if fmt.Sprint(types(own)) != fmt.Sprint(ofTypes(numbered, types(own))) {
		t.Errorf("the session recorded %v, the gateway numbered %v", types(own), types(numbered))
	}
	if last := numbered[len(numbered)-1]; last["type"] != "dev.qory.run.exited" || data(last)["reason"] != nil || data(last)["state"] != "succeeded" {
		t.Errorf("the gateway's record ends %v", last)
	}
	r.noSecretIn(t, s, res.RunID, cred, other)
}

// TestAResendOfARunTheSeparateGatewayEndedSendsNothingMore pins a run the gateway
// ended while the session's batches could not reach it, session_lost: an expired run
// credential is the 401 at the discovery, before any batch; a good one gets the run's
// 410, the run closed by the gateway with session_lost, and the events stay in the run
// directory, which the resend does not change.
func TestAResendOfARunTheSeparateGatewayEndedSendsNothingMore(t *testing.T) {
	t.Parallel()
	s := startSeparate(t)
	cred := credentialOf("rk-0001")
	_, res := spooledRun(t, s, cred)
	waitFor(t, func() bool {
		_, err := os.Stat(filepath.Join(s.dir, "runs", res.RunID, "events.jsonl"))
		return err == nil && len(ofType(s.record(t, res.RunID), "dev.qory.run.exited")) > 0
	})
	before := sessionLines(t, res.Dir)
	numbered := len(s.record(t, res.RunID))

	expired, n := counted(mintCredentialWith(sepIssuerKey(), "rk-0001", "example-requester", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)))
	_, err := session.Resend(context.Background(), resendSpec(s, res.Dir, expired))
	var ref *session.Refusal
	if !errors.As(err, &ref) || ref.Code != refusals.RunCredentialRefused || ref.Status != 401 || ref.From != accesskey.FromGateway || n.Load() != 1 {
		t.Fatalf("an expired run credential: %#v after %d requests", err, n.Load())
	}

	got, err := session.Resend(context.Background(), resendSpec(s, res.Dir, fixedCredential(cred)))
	if err != nil {
		t.Fatal(err)
	}
	if got != (session.ResendResult{Undelivered: res.Undelivered, RunClosed: true, ClosedReason: "session_lost", State: "failed", Reason: "session_lost"}) {
		t.Errorf("the resend %+v; the session left %d undelivered", got, res.Undelivered)
	}
	if !bytes.Equal(sessionLines(t, res.Dir), before) {
		t.Error("the resend changed session.jsonl")
	}
	if _, stopped, _ := sink.Delivered(res.Dir); !stopped {
		t.Error("delivered.log does not record the gateway's end")
	}
	s.close(t)
	if after := s.record(t, res.RunID); len(after) != numbered {
		t.Errorf("the gateway numbered %d events of the resend", len(after)-numbered)
	}
}

// TestAResendOfARunClosedDuringItsSessionPostsNoOwnEvent pins a run the gateway ended
// while its session lived: the session's own run.exited, session_lost, is in its record
// alone and is neither posted nor counted; what the gateway's 410 cut off is posted and
// gets the run's 410 again.
func TestAResendOfARunClosedDuringItsSessionPostsNoOwnEvent(t *testing.T) {
	t.Parallel()
	s := startSeparate(t)
	cred := credentialOf("rk-0001")
	shut := make(chan struct{})
	var closed atomic.Bool
	r := newSepRun(t, s.remote(func(ctx context.Context) (string, error) {
		if closed.Load() {
			select {
			case <-shut:
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		return cred, nil
	}))
	r.sp.Args = []string{"-c", "sleep 30"}
	r.sp.StopGrace = time.Second
	r.sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e70"
	own := &session.Result{Dir: filepath.Join(r.sp.RunsDir, r.sp.RunID)}
	go func() {
		waitFor(t, func() bool {
			_, err := os.Stat(filepath.Join(own.Dir, "session.jsonl"))
			return err == nil && len(ofType(events(t, own), "dev.qory.run.heartbeat")) > 0
		})
		closed.Store(true)
		waitFor(t, func() bool {
			_, err := os.Stat(filepath.Join(s.dir, "runs", r.sp.RunID, "events.jsonl"))
			return err == nil && len(ofType(s.record(t, r.sp.RunID), "dev.qory.run.exited")) > 0
		})
		close(shut)
	}()
	res, err := session.Run(context.Background(), r.sp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.RunClosed || res.ClosedReason != "session_lost" {
		t.Fatalf("result %+v", res)
	}
	accepted, stopped, err := sink.Delivered(res.Dir)
	if err != nil || !stopped {
		t.Fatalf("delivered.log %v, stopped %v, %v", accepted, stopped, err)
	}
	notAccepted := 0
	for _, e := range events(t, res) {
		if !accepted[fmt.Sprint(e["sequence"])] {
			notAccepted++
		}
	}
	got, err := session.Resend(context.Background(), resendSpec(s, res.Dir, fixedCredential(cred)))
	if err != nil {
		t.Fatal(err)
	}
	if got != (session.ResendResult{Undelivered: notAccepted - 1, RunClosed: true, ClosedReason: "session_lost", State: "failed", Reason: "session_lost"}) || notAccepted < 2 {
		t.Errorf("the resend %+v; %d events of the record were not accepted, its own run.exited among them", got, notAccepted)
	}
	s.close(t)
	if exited := ofType(s.record(t, res.RunID), "dev.qory.run.exited"); len(exited) != 1 || data(exited[0])["reason"] != "session_lost" {
		t.Errorf("the gateway's run.exited %v", exited)
	}
}

// TestAResendOfARunRefusedAtOpenSendsNothing pins a run the gateway refused at its
// run request: its record holds the session's run.refused and no delivered.log, since
// the run never opened at the gateway, so the resend is NotOpened and makes no request
// at all.
func TestAResendOfARunRefusedAtOpenSendsNothing(t *testing.T) {
	t.Parallel()
	s := startSeparate(t)
	cred := credentialOf("rk-0001")
	r := newSepRun(t, s.remote(fixedCredential(cred)))
	r.sp.Labels["repository"] = "example-namespace/other"
	refusedRun(t, r)
	if got := refusedRecord(t, r); got["code"] != "target_differs_from_credential" {
		t.Fatalf("the record %v", got)
	}
	entries, _ := os.ReadDir(r.sp.RunsDir)
	dir := filepath.Join(r.sp.RunsDir, entries[0].Name())
	if _, err := os.Stat(filepath.Join(dir, sink.DeliveredFile)); err == nil {
		t.Fatal("a run refused at open has a delivered.log")
	}
	asked, n := counted(cred)
	if got, err := session.Resend(context.Background(), resendSpec(s, dir, asked)); err != nil || got != (session.ResendResult{NotOpened: true}) || n.Load() != 0 {
		t.Errorf("the resend %+v %v, %d requests", got, err, n.Load())
	}
}

// TestAResendTakesTheSessionsRecordAlone pins what Resend refuses before any request:
// a directory without session.jsonl, a gateway's
// record, events.jsonl, which gateway.Resend sends, a record its session still holds,
// and a gateway without a run credential.
func TestAResendTakesTheSessionsRecordAlone(t *testing.T) {
	t.Parallel()
	s := startSeparate(t)
	asked, n := counted(credentialOf("rk-0001"))
	dir := filepath.Join(t.TempDir(), "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e71")
	if _, err := session.Resend(context.Background(), resendSpec(s, dir, asked)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no record: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sink.EventsFile), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Resend(context.Background(), resendSpec(s, dir, asked)); !errors.Is(err, os.ErrExist) {
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
	if _, err := session.Resend(context.Background(), resendSpec(s, dir, asked)); !errors.Is(err, session.ErrRunning) {
		t.Errorf("a record its session holds: %v", err)
	}
	held.Close()
	if _, err := session.Resend(context.Background(), session.ResendSpec{Gateway: session.RemoteGateway{URL: s.url()}, Dir: dir}); err == nil {
		t.Error("a gateway without a run credential was taken")
	}
	if n.Load() != 0 {
		t.Errorf("%d requests", n.Load())
	}
}
