package session_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/runcredential"
	"github.com/qoryai/forager/session"
)

// The runs of this file are a real session.Run behind a real separate gateway whose
// issuer has an introspection endpoint: the run's starter, a server of the test's. The
// gateway reaches an introspection endpoint under the system's roots alone, so TestMain
// makes the process's roots the starters' authority, before anything verifies a
// certificate, with SSL_CERT_FILE; on a platform whose verifier does not read it the
// runs are skipped.

// starterAuthority is the authority of the starters' endpoints, and whether the
// process's roots trust it.
var starterAuthority struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	trusted bool
}

// trustStarters makes the process's roots the starters' authority alone: SSL_CERT_FILE
// at a file of it and SSL_CERT_DIR at an empty directory while the roots are read,
// once, and then as they were, so the programs the tests start do not inherit them. It
// returns what removes the files.
func trustStarters() (remove func(), err error) {
	dir, err := os.MkdirTemp("", "starter-authority-")
	if err != nil {
		return nil, err
	}
	remove = func() { os.RemoveAll(dir) }
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "starter test authority"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return remove, err
	}
	cert, _ := x509.ParseCertificate(der)
	file := filepath.Join(dir, "starters.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return remove, err
	}
	empty := filepath.Join(dir, "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		return remove, err
	}
	for k, v := range map[string]string{"SSL_CERT_FILE": file, "SSL_CERT_DIR": empty} {
		old, had := os.LookupEnv(k)
		os.Setenv(k, v)
		defer func() {
			if had {
				os.Setenv(k, old)
			} else {
				os.Unsetenv(k)
			}
		}()
	}
	starterAuthority.cert, starterAuthority.key = cert, key
	leaf, err := starterLeaf()
	if err != nil {
		return remove, err
	}
	parsed, _ := x509.ParseCertificate(leaf.Certificate[0])
	_, verr := parsed.Verify(x509.VerifyOptions{DNSName: "127.0.0.1"})
	starterAuthority.trusted = verr == nil
	return remove, nil
}

// starterLeaf is a certificate of the starters' authority for 127.0.0.1.
func starterLeaf() (tls.Certificate, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "starter.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, starterAuthority.cert, &key.PublicKey, starterAuthority.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// starter is a run's starter: its introspection endpoint answers every run credential
// active until the file started exists, and from then on a run credential with an
// answer of its own that answer, hang for one that never comes.
type starter struct {
	srv     *httptest.Server
	started string
	hang    chan struct{}

	mu      sync.Mutex
	answers map[string]string
}

// hang is the answer of a starter that never answers.
const hang = "hang"

// startStarter starts a starter, until the test ends, and skips the test when the
// process's roots do not trust it.
func startStarter(t *testing.T) *starter {
	t.Helper()
	if !starterAuthority.trusted {
		t.Skip("this platform's verifier does not read SSL_CERT_FILE, so no gateway reaches a test's introspection endpoint")
	}
	leaf, err := starterLeaf()
	if err != nil {
		t.Fatal(err)
	}
	st := &starter{started: filepath.Join(t.TempDir(), "started"), hang: make(chan struct{}), answers: map[string]string{}}
	st.srv = httptest.NewUnstartedServer(http.HandlerFunc(st.serve))
	st.srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{leaf}}
	st.srv.StartTLS()
	t.Cleanup(st.srv.Close)
	t.Cleanup(func() { close(st.hang) })
	return st
}

// answer sets the starter's answer for the run credential once the file started exists.
func (st *starter) answer(credential, body string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.answers[credential] = body
}

func (st *starter) serve(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := r.BasicAuth(); !ok || r.ParseForm() != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	body := `{"active":true}`
	if _, err := os.Stat(st.started); err == nil {
		st.mu.Lock()
		if a, ok := st.answers[r.PostForm.Get("token")]; ok {
			body = a
		}
		st.mu.Unlock()
	}
	if body == hang {
		select {
		case <-st.hang:
		case <-r.Context().Done():
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, body)
}

// issuer gives the gateway's issuer the starter's introspection endpoint, each answer
// kept for an hour: no request of a run asks the starter again but the ask at the
// runtime's exit.
func (st *starter) issuer(t *testing.T) func(*runcredential.Issuer) {
	t.Helper()
	secret := filepath.Join(t.TempDir(), "introspection-secret")
	if err := os.WriteFile(secret, []byte("example-client-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hour := runcredential.Duration(time.Hour)
	return func(i *runcredential.Issuer) {
		i.Introspection = &runcredential.Introspection{URL: st.srv.URL + "/introspect", ClientID: "example-gateway", ClientSecretFile: secret, Cache: &hour}
	}
}

// exits makes the run's runtime write the file started, then exit with the status code.
func (st *starter) exits(r *sepRun, code int) {
	r.sp.Args = []string{"-c", fmt.Sprintf(`touch "$0"; exit %d`, code), st.started}
}

// exitedData is the data of the one run.exited of a record, which ends it.
func exitedData(t *testing.T, what string, evs []map[string]any) map[string]any {
	t.Helper()
	exited := ofType(evs, "dev.qory.run.exited")
	if len(exited) != 1 || evs[len(evs)-1]["type"] != "dev.qory.run.exited" {
		t.Fatalf("%s: run.exited %v", what, exited)
	}
	return data(exited[0])
}

// TestTheStartersOutcomeAtARealGateway pins the ask at the runtime's own exit end to
// end: a starter that answers that the run credential is no longer active, failed with
// checks_failed, for a runtime that exited 0, makes the session's run.exited, which the
// gateway accepts, failed with checks_failed and exit_code 0, in the session's record
// and the gateway's alike, and the result says so; the gateway closed nothing.
func TestTheStartersOutcomeAtARealGateway(t *testing.T) {
	st := startStarter(t)
	s := startSeparate(t, st.issuer(t))
	cred := credentialOf("rk-0001")
	st.answer(cred, `{"active":false,"qory_outcome":"failed","qory_reason":"checks_failed"}`)
	r := newSepRun(t, s.remote(fixedCredential(cred)))
	st.exits(r, 0)
	res, err := session.Run(context.Background(), r.sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "failed" || res.Reason != "checks_failed" || res.ExitCode != 0 || res.RunClosed || res.ClosedReason != "" || res.Undelivered != 0 {
		t.Errorf("result %+v", res)
	}
	own := exitedData(t, "the session's record", events(t, res))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, err := s.g.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d.RunClosed || d.ClosedReason != "" || d.State != "" || d.Reason != "" || d.Undelivered != 0 {
		t.Errorf("delivery %+v", d)
	}
	numbered := exitedData(t, "the gateway's record", s.record(t, res.RunID))
	for name, ex := range map[string]map[string]any{"the session's": own, "the gateway's": numbered} {
		if ex["state"] != "failed" || ex["reason"] != "checks_failed" || ex["exit_code"] != float64(0) {
			t.Errorf("%s run.exited %v", name, ex)
		}
	}
	r.noSecretIn(t, s, res.RunID, cred)
}

// TestNoOutcomeAtARealGateway pins the ask at the runtime's own exit end to end when the
// starter gives no outcome: a starter that still holds the run credential active, and
// one that never answers, which the gateway answers {} within about 6 seconds. The
// runtime's exit decides: failed for exit status 3, with no reason, in both records.
func TestNoOutcomeAtARealGateway(t *testing.T) {
	for _, c := range []struct {
		name, answer string
		least, most  time.Duration
	}{
		{"active", `{"active":true}`, 0, 5 * time.Second},
		{"no answer", hang, 4 * time.Second, 8500 * time.Millisecond},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := startStarter(t)
			s := startSeparate(t, st.issuer(t))
			cred := credentialOf("rk-0001")
			st.answer(cred, c.answer)
			r := newSepRun(t, s.remote(fixedCredential(cred)))
			st.exits(r, 3)
			start := time.Now()
			res, err := session.Run(context.Background(), r.sp)
			if err != nil {
				t.Fatal(err)
			}
			if took := time.Since(start); took < c.least || took > c.most {
				t.Errorf("the run took %s; want %s to %s", took, c.least, c.most)
			}
			if res.State != "failed" || res.Reason != "" || res.ExitCode != 3 || res.RunClosed {
				t.Errorf("result %+v", res)
			}
			own := exitedData(t, "the session's record", events(t, res))
			s.close(t)
			numbered := exitedData(t, "the gateway's record", s.record(t, res.RunID))
			for name, ex := range map[string]map[string]any{"the session's": own, "the gateway's": numbered} {
				if _, has := ex["reason"]; ex["state"] != "failed" || has || ex["exit_code"] != float64(3) {
					t.Errorf("%s run.exited %v", name, ex)
				}
			}
		})
	}
}

// TestTheStartersOutcomeEndsTheRunKeysOtherRun pins the starter's answer at one run's
// exit against another live run of the same run key, end to end: the other run gets
// the gateway's 410, stopped with the state failed and the reason checks_failed, its
// session stops its runtime and records them, and the gateway's record of it ends so;
// the run that asked ends with its own run.exited of that outcome, which the gateway
// accepts, well within its 30 seconds.
func TestTheStartersOutcomeEndsTheRunKeysOtherRun(t *testing.T) {
	st := startStarter(t)
	s := startSeparate(t, st.issuer(t))
	asking := credentialOf("rk-0001")
	other := mintCredential(sepIssuerKey(), "rk-0001", time.Now().Add(2*time.Hour))
	st.answer(asking, `{"active":false,"qory_outcome":"failed","qory_reason":"checks_failed"}`)
	long := newSepRun(t, s.remote(fixedCredential(other)))
	long.sp.Args = []string{"-c", "sleep 30"}
	type ran struct {
		res *session.Result
		err error
	}
	longDone := make(chan ran, 1)
	go func() {
		res, err := session.Run(context.Background(), long.sp)
		longDone <- ran{res, err}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for len(s.runs()) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	r := newSepRun(t, s.remote(fixedCredential(asking)))
	st.exits(r, 0)
	start := time.Now()
	res, err := session.Run(context.Background(), r.sp)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 15*time.Second {
		t.Errorf("the asking run took %s", took)
	}
	if res.State != "failed" || res.Reason != "checks_failed" || res.ExitCode != 0 || res.RunClosed {
		t.Errorf("the asking run's result %+v", res)
	}
	var l ran
	select {
	case l = <-longDone:
	case <-time.After(20 * time.Second):
		t.Fatal("the other run did not end")
	}
	if l.err != nil {
		t.Fatal(l.err)
	}
	if !l.res.RunClosed || l.res.ClosedReason != "stopped" || l.res.State != "failed" || l.res.Reason != "checks_failed" {
		t.Errorf("the other run's result %+v", l.res)
	}
	if ex := exitedData(t, "the other run's session record", events(t, l.res)); ex["state"] != "failed" || ex["reason"] != "checks_failed" {
		t.Errorf("the other run's session run.exited %v", ex)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, err := s.g.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !d.RunClosed || d.ClosedReason != l.res.ClosedReason || d.State != l.res.State || d.Reason != l.res.Reason {
		t.Errorf("delivery %+v; the other run's result %+v", d, l.res)
	}
	if ex := exitedData(t, "the gateway's record of the other run", s.record(t, l.res.RunID)); ex["state"] != "failed" || ex["reason"] != "checks_failed" || ex["exit_code"] != float64(-1) {
		t.Errorf("the gateway's run.exited of the other run %v", ex)
	}
	if ex := exitedData(t, "the gateway's record of the asking run", s.record(t, res.RunID)); ex["state"] != "failed" || ex["reason"] != "checks_failed" || ex["exit_code"] != float64(0) {
		t.Errorf("the gateway's run.exited of the asking run %v", ex)
	}
}
