package session_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
)

// The run of this file is end to end behind a separate gateway: a real session.Run
// with a RemoteGateway of its run key alone speaks to a real gateway.Start on its one
// address, over TLS 1.3 and the binding, and the gateway attaches the run at a server
// of the contract, apiary below.

// apiary is a server of the contract for a separate gateway: its discovery lists the
// gateway's node, ng_, and one workspace; it answers an attach, a reload and a batch
// with the run configuration it serves, every answer signed under its signing key,
// which also signs the run keys.
type apiary struct {
	srv    *httptest.Server
	key    *accesskey.Key
	signer *accesskey.Key
	pin    accesskey.Pin

	mu       sync.Mutex
	run      []byte
	digest   string
	attaches int
	received []map[string]any
}

// The node and the workspace the apiary's discovery lists.
const (
	sepGateway   = "ng_f1xt0re000000000"
	sepWorkspace = "ws_f1xt0re000000000"
)

func newApiary(t *testing.T) *apiary {
	t.Helper()
	a := &apiary{key: mustKey(t), signer: mustKey(t)}
	a.pin = accesskey.Pin{{Alg: "ed25519", PublicKey: a.signer.PublicKey().String()}}
	a.serve(`{"version":1,"egress":{"mode":"enforce","allow":["a.example"]}}`, 'a')
	a.srv = httptest.NewServer(http.HandlerFunc(a.handle))
	t.Cleanup(a.srv.Close)
	return a
}

// serve makes the apiary serve a run configuration with the policy, under the digest
// sha256= and 64 of the digit.
func (a *apiary) serve(policy string, digit byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.run, a.digest = []byte(`{"version":1,"security_policy":`+policy+`}`), "sha256="+strings.Repeat(string(digit), 64)
}

// configuration is the apiary's discovery and its digest.
func (a *apiary) configuration() ([]byte, string) {
	pin, _ := json.Marshal(a.pin)
	doc := []byte(`{"version":1,"node_id":"` + sepGateway + `","workspaces":["` + sepWorkspace + `"],"apiary_public_key":` + string(pin) +
		`,"events":{"url":"` + a.srv.URL + `/v1/events","types":["*"]},"run":{"url":"` + a.srv.URL + `/v1/runs"}}`)
	sum := sha256.Sum256(doc)
	return doc, "sha256=" + hex.EncodeToString(sum[:])
}

// handle answers the gateway, signed: the discovery, an attach with labels of the
// starter's registration, a reload and a batch, whose events it keeps.
func (a *apiary) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	doc, conf := a.configuration()
	a.mu.Lock()
	run, digest := a.run, a.digest
	a.mu.Unlock()
	status, out, withRun := http.StatusOK, []byte(nil), true
	switch rest, ok := strings.CutPrefix(r.URL.Path, "/v1/runs/"); {
	case r.Method == http.MethodGet && r.URL.Path == server.WellKnown:
		out, withRun = doc, false
	case r.Method == http.MethodPost && ok && strings.HasSuffix(rest, "/attach"):
		var m map[string]json.RawMessage
		json.Unmarshal(run, &m)
		m["labels"] = json.RawMessage(`{"repository":"example-namespace/project"}`)
		out, _ = json.Marshal(m)
		a.mu.Lock()
		a.attaches++
		a.mu.Unlock()
	case r.Method == http.MethodGet && ok:
		out = run
	case r.Method == http.MethodPost && r.URL.Path == "/v1/events":
		var batch []map[string]any
		json.Unmarshal(body, &batch)
		a.mu.Lock()
		a.received = append(a.received, batch...)
		a.mu.Unlock()
		status = http.StatusAccepted
	default:
		http.NotFound(w, r)
		return
	}
	answer := accesskey.Answer{Status: status, RequestSignature: r.Header.Get(server.HeaderSignature), Body: out, Configuration: conf}
	w.Header().Set(server.HeaderConfiguration, conf)
	if withRun {
		answer.RunConfiguration = digest
		w.Header().Set(server.HeaderRunConfiguration, digest)
	}
	if out != nil {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Cache-Control", "no-store, no-transform")
	w.Header().Set(server.HeaderSignature, a.signer.SignAnswer(answer))
	w.WriteHeader(status)
	w.Write(out)
}

// receivedTypes are the types of the events the apiary received, in order.
func (a *apiary) receivedTypes() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return types(a.received)
}

// runKey is a run key of the run for the gateway at gatewayURL, whose key is gw.
func (a *apiary) runKey(t *testing.T, runID, gatewayURL string, gw *accesskey.Key) string {
	t.Helper()
	instance, err := accesskey.NewInstanceID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	k, err := runkey.Key{
		RunID: runID, Workspace: sepWorkspace, NodeID: "np_f1xt0re000000000", Gateway: sepGateway,
		InstanceID: instance, GatewayURL: gatewayURL, GatewayKeys: []accesskey.PublicKey{gw.PublicKey()},
		Issued: now, AttachBy: now.Add(10 * time.Minute),
	}.Sign(a.signer)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// separateCertificate writes a certificate for 127.0.0.1 and its key, and the file of
// the authority that issued it.
func separateCertificate(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test authority"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "gateway.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certFile, keyFile, caFile = filepath.Join(dir, "gateway.pem"), filepath.Join(dir, "gateway-key.pem"), filepath.Join(dir, "ca.pem")
	for f, b := range map[string]*pem.Block{certFile: {Type: "CERTIFICATE", Bytes: der}, keyFile: {Type: "PRIVATE KEY", Bytes: keyDER}, caFile: {Type: "CERTIFICATE", Bytes: caDER}} {
		if err := os.WriteFile(f, pem.EncodeToMemory(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return certFile, keyFile, caFile
}

// TestARunThroughARealSeparateGateway is a run end to end behind a separate gateway:
// the session, given the run key alone, binds every connection to the gateway's one
// address and checks every answer's signature; the gateway attaches the run at the
// server and writes its record's first line with the labels the attach gave back; the
// session's batches are numbered and reach the server; the server changes the run's
// configuration during the run, and the session fetches the reload and records it in a
// second policy_applied, which the gateway numbers and the server receives.
func TestARunThroughARealSeparateGateway(t *testing.T) {
	a := newApiary(t)
	certFile, keyFile, caFile := separateCertificate(t)
	records := t.TempDir()
	g, err := gateway.Start(context.Background(), gateway.Config{
		RunDir: func(id string) string { return filepath.Join(records, id) }, Listen: "127.0.0.1:0", Heartbeat: time.Second, Version: "test",
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
	url := "https://" + g.Addr()
	t.Cleanup(session.TrustRemote(url, caFile))

	sp := spec(t)
	sleeps(&sp, 30*time.Second)
	sp.Timeout = 20 * time.Second
	sp.RunID = event.NewRunID()
	sp.Gateway = session.RemoteGateway{RunKey: a.runKey(t, sp.RunID, url, a.key)}
	own := filepath.Join(sp.RunsDir, sp.RunID)
	applied := func() []map[string]any {
		return ofType(events(t, &session.Result{Dir: own}), "dev.qory.run.policy_applied")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *session.Result, 1)
	go func() {
		res, err := session.Run(ctx, sp)
		if err != nil {
			t.Error(err)
		}
		done <- res
	}()
	waitFor(t, func() bool {
		_, err := os.Stat(filepath.Join(own, "session.jsonl"))
		return err == nil && len(applied()) == 1
	})
	a.serve(`{"version":1,"egress":{"mode":"enforce","allow":["b.example"]}}`, 'b')
	waitFor(t, func() bool { return len(applied()) == 2 })
	pa := applied()
	if fmt.Sprint(data(pa[0])["allow"]) != "[a.example]" || fmt.Sprint(data(pa[1])["allow"]) != "[b.example]" || data(pa[1])["run_configuration"] != "sha256="+strings.Repeat("b", 64) {
		t.Errorf("policy_applied %v then %v", data(pa[0]), data(pa[1]))
	}
	cancel()
	res := <-done
	if res == nil {
		t.FailNow()
	}
	if filepath.Base(res.Dir) != sp.RunID || res.Undelivered != 0 {
		t.Errorf("result %+v", res)
	}
	waitFor(t, func() bool {
		got := a.receivedTypes()
		return len(got) > 0 && got[len(got)-1] == "dev.qory.run.exited"
	})
	numbered := record(t, &session.Result{Dir: filepath.Join(records, sp.RunID)})
	if len(numbered) == 0 || numbered[0]["type"] != "dev.qory.run.registered" {
		t.Fatalf("the gateway's record %v", types(numbered))
	}
	if l, _ := data(numbered[0])["labels"].(map[string]any); l["repository"] != "example-namespace/project" || data(numbered[0])["workspace"] != sepWorkspace {
		t.Errorf("run.registered %v", data(numbered[0]))
	}
	if got := ofType(numbered, "dev.qory.run.policy_applied"); len(got) != 2 {
		t.Errorf("the gateway numbered %d policy_applied", len(got))
	}
	if got := a.receivedTypes(); len(ofTypesIn(got, "dev.qory.run.policy_applied")) != 2 || got[0] != "dev.qory.run.started" {
		t.Errorf("the server received %v", got)
	}
	a.mu.Lock()
	attaches := a.attaches
	a.mu.Unlock()
	if attaches != 1 {
		t.Errorf("%d attaches", attaches)
	}
	if started := ofType(events(t, res), "dev.qory.run.started"); len(started) != 1 || data(started[0])["labels"] != nil {
		t.Errorf("run.started %v", started)
	}
}

// ofTypesIn are the types among got equal to typ.
func ofTypesIn(got []string, typ string) []string {
	var out []string
	for _, ty := range got {
		if ty == typ {
			out = append(out, ty)
		}
	}
	return out
}
