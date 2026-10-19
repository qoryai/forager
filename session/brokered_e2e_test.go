package session_test

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// The runs of this file are end to end without a wall: a real session.Run speaks to a
// real gateway that has a credential of the machine's for the run, on the local link
// and behind a separate gateway. That the origin then gets the value through the proxy,
// and the placeholder around it, is gateway's
// TestASealedCredentialFromTheReferenceReceiverReachesTheOrigin.

// brokeredValue is the fake value of the machine's credential of these runs, which the
// gateway reads from brokeredSource.
const (
	brokeredValue  = "fake-model-value-of-the-brokered-test"
	brokeredSource = "SESSION_TEST_BROKERED_VALUE"
)

// brokeredCredential is the machine's model key for Claude Code, set in place of the
// placeholder of ANTHROPIC_API_KEY.
var brokeredCredential = gateway.Credential{Name: "model", Env: brokeredSource, Hosts: []string{"api.anthropic.com"}, Scheme: "bearer", Placeholders: []string{"ANTHROPIC_API_KEY"}}

// brokeredSpec is a spec whose agent writes its environment to the file it returns,
// that inherits a value of ANTHROPIC_API_KEY, on a machine whose authorities are in a
// file of the test's.
func brokeredSpec(t *testing.T) (session.Spec, string) {
	t.Helper()
	t.Setenv(brokeredSource, brokeredValue)
	roots := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(roots, []byte(machineRoots), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.SetMachineBundles([]string{roots}))
	sp := spec(t, "ANTHROPIC_API_KEY=inherited-fake-key", brokeredSource+"="+brokeredValue)
	sp.RunID = event.NewRunID()
	return sp, dumpsEnv(t, &sp)
}

// checkBrokered checks an unwalled brokered run: the agent got the placeholder in
// ANTHROPIC_API_KEY, over the value it inherits, and the bundle's variables, the
// bundle contains the machine's authorities and the run's certificate, and no file of
// the run directory or the gateway's, the agent's environment among them, contains the
// value.
func checkBrokered(t *testing.T, env string, dirs ...string) {
	t.Helper()
	got := envOf(t, env)
	if got["ANTHROPIC_API_KEY"] != link.Placeholder {
		t.Errorf("ANTHROPIC_API_KEY is %q, want the placeholder", got["ANTHROPIC_API_KEY"])
	}
	bundle := filepath.Join(dirs[0], session.BundleFile)
	for _, n := range wall.DefaultCAEnv {
		if got[n] != bundle {
			t.Errorf("%s is %q, want %q", n, got[n], bundle)
		}
	}
	b, err := os.ReadFile(bundle)
	if err != nil || !strings.HasPrefix(string(b), machineRoots+"\n") || strings.Count(string(b), "BEGIN CERTIFICATE") != 2 {
		t.Errorf("the bundle %q, %v; want the machine's authorities and the run's certificate", b, err)
	}
	if e, err := os.ReadFile(env); err != nil || bytes.Contains(e, []byte(brokeredValue)) {
		t.Errorf("the agent's environment contains the value, or is not there: %v", err)
	}
	for _, dir := range dirs {
		filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
			if err == nil && e.Type().IsRegular() {
				if b, err := os.ReadFile(p); err == nil && bytes.Contains(b, []byte(brokeredValue)) {
					t.Errorf("%s contains the value", p)
				}
			}
			return nil
		})
	}
}

// TestAnUnwalledRunThroughARealGatewayIsBrokered pins an unwalled run on the local link
// whose machine's policy selects a credential: the run starts, the gateway's record and
// the session's list the credential, and checkBrokered holds.
func TestAnUnwalledRunThroughARealGatewayIsBrokered(t *testing.T) {
	sp, env := brokeredSpec(t)
	startGateway(t, &sp, gateway.Config{Version: "test", Heartbeat: time.Second,
		Credentials: []gateway.Credential{brokeredCredential},
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.anthropic.com"}},
			Credentials: []gateway.PolicyCredential{{Name: "model"}}}})
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	pa := ofType(events(t, res), "dev.qory.run.policy_applied")
	if len(pa) != 1 || len(data(pa[0])["credentials"].([]any)) != 1 {
		t.Errorf("policy_applied %v", pa)
	}
	if cv, _ := data(pa[0])["credential_variables"].([]any); len(cv) != 1 {
		t.Errorf("credential_variables %v", data(pa[0])["credential_variables"])
	}
	checkBrokered(t, env, res.Dir)
}

// TestAnUnwalledRunThroughARealSeparateGatewayIsBrokered pins an unwalled run behind a
// separate gateway whose selection is the machine's credential: the run starts, the
// session's record lists the credential, and checkBrokered holds for the run
// directory and the gateway's.
func TestAnUnwalledRunThroughARealSeparateGatewayIsBrokered(t *testing.T) {
	a := newApiary(t)
	a.serve(`{"version":1,"egress":{"mode":"enforce","allow":["api.anthropic.com"]}}`, 'a')
	certFile, keyFile, caFile := separateCertificate(t)
	records := t.TempDir()
	g, err := gateway.Start(context.Background(), gateway.Config{
		RunDir: func(id string) string { return filepath.Join(records, id) }, Listen: "127.0.0.1:0", Heartbeat: time.Second, Version: "test",
		TLS:         &gateway.TLS{CertFile: certFile, KeyFile: keyFile},
		Server:      &gateway.Server{Version: 1, URL: a.srv.URL, AccessKeyID: "ak_f1xt0re00000000g", ApiaryPublicKey: a.pin, AccessKey: a.key, InstanceID: "i_test"},
		Credentials: []gateway.Credential{brokeredCredential}, Selects: []gateway.Selection{{Name: "model"}},
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
	url := "https://" + g.Addr()
	t.Cleanup(session.TrustRemote(url, caFile))
	sp, env := brokeredSpec(t)
	sp.Gateway = session.RemoteGateway{RunKey: a.runKey(t, sp.RunID, url, a.key)}
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	pa := ofType(events(t, res), "dev.qory.run.policy_applied")
	if len(pa) != 1 || len(data(pa[0])["credentials"].([]any)) != 1 {
		t.Errorf("policy_applied %v", pa)
	}
	checkBrokered(t, env, res.Dir, records)
}
