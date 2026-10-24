package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// The records of the reference receiver of TestDockerSealedCredentialThroughTheWall: a
// node of its own that reports directly, under sealedNodeKey, the key of the gateway on
// this machine; and a node pool whose choice is the separate gateway sealedGateway,
// which lives at sealedWorkspace and whose one access key is sealedGatewayKey.
const (
	sealedNodeKey    = "ak_f1xt0re00000000d"
	sealedPool       = "np_f1xt0re00000000s"
	sealedPoolKey    = "ak_f1xt0re00000000p"
	sealedGateway    = "ng_f1xt0re00000000s"
	sealedGatewayKey = "ak_f1xt0re00000000s"
	sealedWorkspace  = "ws_f1xt0re00000000s"
)

// TestDockerSealedCredentialThroughTheWall runs a walled run whose credential the
// reference receiver seals, behind the Docker adapter, as it starts and behind a
// separate gateway that attaches it. The run configuration has the credential model,
// in x-api-key on a recorder, with MODEL_API_KEY as its placeholder; the gateway sends
// the secrets request, opens the answer and the proxy sets the value. Inside, the probe
// sends MODEL_API_KEY's value to the recorder in x-api-key. The probe finds the
// placeholder in MODEL_API_KEY and the value in no environment it can read; the
// recorder gets the value in x-api-key, once; the record lists the request with the
// credential model; and no file of the run, the workspace or the gateway, no stored
// event, no line the receiver logged and nothing the run printed or reported contains
// the value.
//
// The test is skipped without an engine the docker command reaches, and, off Linux,
// without a Linux build of the test binary in QORY_WALL_HELPER.
func TestDockerSealedCredentialThroughTheWall(t *testing.T) {
	command := os.Getenv("QORY_WALL_COMMAND")
	if command == "" {
		command = "docker"
	}
	if out, err := exec.Command(command, "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		Skip(t, command+" reaches no engine: "+strings.TrimSpace(string(out)))
	}
	helper := Helper(t)
	image := os.Getenv("QORY_WALL_IMAGE")
	if image == "" {
		image = "ghcr.io/qoryai/ci-images:busybox-stable@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
	}
	name := fmt.Sprintf("qory-walltest-sealed-recorder-%d", os.Getpid())
	args := []string{"run", "--detach", "--name", name, "--mount", "type=bind,src=" + helper + ",dst=/walltest,readonly"}
	for _, kv := range RecorderEnv() {
		args = append(args, "--env", kv)
	}
	args = append(append(args, "--entrypoint", "/walltest", "ghcr.io/qoryai/ci-images:busybox-stable@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"), RecorderArgs...)
	if out, err := exec.Command(command, args...).CombinedOutput(); err != nil {
		t.Fatalf("the recorder: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command(command, "rm", "--force", name).Run() })
	AwaitRecorder(t, command, name)
	ip, err := exec.Command(command, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := trustRecorders(t); err != nil {
		t.Fatalf("this machine's roots are not the suite's authority: %v", err)
	}
	run := sealedRun{command: command, helper: helper, image: image, recorder: name, host: strings.TrimSpace(string(ip))}
	t.Run("start", func(t *testing.T) { run.check(t, false) })
	t.Run("attach", func(t *testing.T) { run.check(t, true) })
}

// sealedRun is what the runs of TestDockerSealedCredentialThroughTheWall share.
type sealedRun struct {
	command, helper, image, recorder, host string
}

// sealedReference is the reference receiver of one run: its server, its store file and
// the lines it logged.
type sealedReference struct {
	srv    *httptest.Server
	h      *receiver.Handler
	stored string
	mu     sync.Mutex
	logged []string
}

// reference starts the reference receiver for the recorder's host, signing under signer
// and sealing value: every key it knows is allowed stored secrets but the pool's, which
// registers runs through the separate gateway; the gateway's keys are accessKey.
func (r sealedRun) reference(t *testing.T, accessKey, poolKey, signer *accesskey.Key, value string) *sealedReference {
	t.Helper()
	ref := &sealedReference{stored: filepath.Join(t.TempDir(), "received.jsonl")}
	store, err := receiver.OpenFile(ref.stored)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	pin, _ := json.Marshal(accesskey.Pin{{Alg: "ed25519", PublicKey: signer.PublicKey().String()}})
	doc := []byte(`{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["` + r.host + `"]}},` +
		`"credentials":[{"name":"model","apply":[{"hosts":["` + r.host + `"],"scheme":"header","header":"x-api-key","paths":["/v1/*"]}],"placeholders":["` + sealedPlaceholder + `"]}]}`)
	keys := map[string]receiver.AccessKey{
		sealedNodeKey:    {PublicKey: accessKey.PublicKey(), StoredSecrets: true},
		sealedPoolKey:    {PublicKey: poolKey.PublicKey(), Node: sealedPool},
		sealedGatewayKey: {PublicKey: accessKey.PublicKey(), Node: sealedGateway, StoredSecrets: true},
	}
	ref.h = &receiver.Handler{
		Keys:          func(id string) (receiver.AccessKey, bool) { k, ok := keys[id]; return k, ok },
		Signer:        signer,
		Store:         store,
		Nodes:         map[string]receiver.Node{sealedPool: {Workspace: sealedWorkspace, Gateway: sealedGateway}},
		Workspaces:    map[string]receiver.Workspace{sealedWorkspace: {Organisation: "org_walltest"}},
		Organisations: map[string]receiver.Organisation{"org_walltest": {}},
		Configuration: func() ([]byte, string) {
			doc := []byte(`{"version":1,"node_id":"nd_f1xt0re00000000d","workspaces":["` + sealedWorkspace + `"],"apiary_public_key":` + string(pin) +
				`,"events":{"url":"` + ref.srv.URL + receiver.DefaultEventsPath + `","types":["*"]},"run":{"url":"` + ref.srv.URL + receiver.DefaultRunPath +
				`"},"secrets":{"url":"` + ref.srv.URL + receiver.DefaultSecretsPath + `"}}`)
			sum := sha256.Sum256(doc)
			return doc, "sha256=" + hex.EncodeToString(sum[:])
		},
		RunConfiguration: func(receiver.Run) ([]byte, string, *receiver.Refusal) { return doc, "", nil },
		Secrets: func(_ receiver.Run, names []string) ([]receiver.Value, *receiver.Refusal) {
			var values []receiver.Value
			for range names {
				values = append(values, receiver.Value{Value: []byte(value)})
			}
			return values, nil
		},
		Log: func(l string) {
			ref.mu.Lock()
			ref.logged = append(ref.logged, l)
			ref.mu.Unlock()
		},
	}
	ref.srv = httptest.NewServer(ref.h)
	t.Cleanup(ref.srv.Close)
	return ref
}

// separate starts a separate gateway on 127.0.0.1 with cfg, its certificate of the
// suite's authority, which this machine's roots are, and returns it with its URL.
func separate(t *testing.T, cfg gateway.Config) (*gateway.Gateway, string) {
	t.Helper()
	ca, caKey := authority()
	leaf, err := sign(ca, caKey, []net.IP{net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg.TLS = &gateway.TLS{CertFile: filepath.Join(dir, "gateway.pem"), KeyFile: filepath.Join(dir, "gateway-key.pem")}
	var chain []byte
	for _, c := range leaf.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	if err := os.WriteFile(cfg.TLS.CertFile, chain, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.TLS.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Listen = "127.0.0.1:0"
	g, err := gateway.Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		g.Close(ctx)
	})
	return g, "https://" + g.Addr()
}

// check runs the probe once behind the wall, its gateway on this machine or, attached,
// a separate one, and checks the run as TestDockerSealedCredentialThroughTheWall
// describes.
func (r sealedRun) check(t *testing.T, attached bool) {
	value := "sk-walltest" + sealedMark + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatBool(attached)
	accessKey, poolKey, signer := mustGenerate(t), mustGenerate(t), mustGenerate(t)
	ref := r.reference(t, accessKey, poolKey, signer, value)
	pin := accesskey.Pin{{Alg: "ed25519", PublicKey: signer.PublicKey().String()}}
	before, _ := exec.Command(r.command, "exec", r.recorder, "cat", RecorderFile).Output()
	dir, runs, records := t.TempDir(), filepath.Join(t.TempDir(), "runs"), t.TempDir()
	var reports syncBuffer
	report := func(l string) {
		t.Log("report:", l)
		reports.Write([]byte(l + "\n"))
	}
	node := &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{r.host}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cert, _ := authority()
	spec := runSpec{OpenSpec: session.OpenSpec{
		RunsDir:        runs,
		Wall:           &wall.Docker{Command: r.command, Helper: r.helper, RelayArgs: RelayArgs, NestArgs: NestArgs},
		Image:          r.image,
		ForagerVersion: "walltest",
		Report:         report,
	},
		SessionSpec: session.SessionSpec{
			Command: wall.HelperPath,
			Args:    []string{modeSealed},
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				sealedHostVar + "=" + r.host,
				recordersCAVar + "=" + base64.StdEncoding.EncodeToString(cert.Raw),
			},
			Dir:       dir,
			Stdin:     strings.NewReader(""),
			Forwarder: []string{wall.HelperPath, "forward"},
			Exec:      append([]string{wall.HelperPath}, ExecArgs...),
		},
	}
	var out, errs syncBuffer
	spec.Stdout, spec.Stderr = &out, &errs
	var closeGateway func()
	recordOf := func(*session.Result) string { return "" }
	if attached {
		// The gateway's record comes before the gateway starts, as its discovery makes
		// it a gateway; its URL is known once it listens, before any run registers.
		ref.h.Gateways = map[string]receiver.Gateway{sealedGateway: {Workspace: sealedWorkspace, AccessKeys: []string{sealedGatewayKey}}}
		g, url := separate(t, gateway.Config{
			RunDir:  func(id string) string { return filepath.Join(records, id) },
			Server:  &gateway.Server{Version: 1, URL: ref.srv.URL, AccessKeyID: sealedGatewayKey, ApiaryPublicKey: pin, AccessKey: accessKey, InstanceID: "i_walltest_gateway"},
			Policy:  node,
			Version: "walltest",
			Report:  report,
		})
		closeGateway = func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			g.Close(ctx)
		}
		ref.h.Gateways[sealedGateway] = receiver.Gateway{URL: url, Workspace: sealedWorkspace, AccessKeys: []string{sealedGatewayKey}}
		spec.RunID = event.NewRunID()
		c := &server.Client{Config: &server.Config{Version: 1, URL: ref.srv.URL, AccessKeyID: sealedPoolKey, ApiaryPublicKey: pin}, Key: poolKey,
			InstanceID: "i_walltest_pool", UserAgent: "qory-forager/walltest"}
		body, err := server.GatewayRegistration{RunID: spec.RunID}.Body()
		if err != nil {
			t.Fatal(err)
		}
		a, err := c.RegisterThroughGateway(ctx, ref.srv.URL+receiver.DefaultRunPath, body)
		if err != nil {
			t.Fatal(err)
		}
		spec.Gateway = session.RemoteGateway{RunKey: a.RunKey}
		recordOf = func(res *session.Result) string {
			return filepath.Join(records, filepath.Base(res.Dir), "events.jsonl")
		}
	} else {
		spec.Gateway, closeGateway = startGateway(t, gateway.Config{
			Server:  &gateway.Server{Version: 1, URL: ref.srv.URL, AccessKeyID: sealedNodeKey, ApiaryPublicKey: pin, AccessKey: accessKey, InstanceID: "i_walltest_node"},
			Policy:  node,
			Version: "walltest",
			Report:  report,
		}, runs)
		recordOf = func(res *session.Result) string { return filepath.Join(res.Dir, "events.jsonl") }
	}

	res, err := runOne(ctx, spec)
	closeGateway()
	if err != nil {
		t.Fatalf("the run did not start: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errs.String())
	}
	var p sealedReport
	found := false
	for _, line := range strings.Split(out.String(), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), sealedPrefix); ok {
			if err := json.Unmarshal([]byte(rest), &p); err != nil {
				t.Fatalf("the probe's report: %v\n%s", err, rest)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("the probe reported nothing; exit %d\nstdout:\n%s\nstderr:\n%s", res.ExitCode, out.String(), errs.String())
	}
	if p.Placeholder != link.Placeholder || len(p.Seen) != 0 || p.Environs == 0 || p.Err != "" || p.Status != 200 {
		t.Errorf("inside, %s is %q, the value is seen in %v, %d environments read, the request's status %d and error %q; want the placeholder, the value nowhere and 200",
			sealedPlaceholder, p.Placeholder, p.Seen, p.Environs, p.Status, p.Err)
	}

	after, err := exec.Command(r.command, "exec", r.recorder, "cat", RecorderFile).Output()
	if err != nil {
		t.Fatal(err)
	}
	reqs, err := readRecorded(after[len(before):])
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Path != modelPath || !slices.Equal(reqs[0].Header.Values(apiKeyHeader), []string{value}) {
		t.Errorf("the recorder got %d requests; want one to %s with the value in %s once", len(reqs), modelPath, apiKeyHeader)
	}

	record, err := os.ReadFile(recordOf(res))
	if err != nil {
		t.Fatal(err)
	}
	egress := 0
	for _, line := range strings.Split(strings.TrimSpace(string(record)), "\n") {
		var e struct {
			Type string         `json:"type"`
			Data map[string]any `json:"data"`
		}
		if json.Unmarshal([]byte(line), &e) != nil || e.Type != "dev.qory.run.egress" {
			continue
		}
		egress++
		if e.Data["host"] != r.host || e.Data["decision"] != "allowed" || e.Data["credential"] != "model" {
			t.Errorf("the request is recorded as %v; want allowed to the recorder with the credential model", e.Data)
		}
	}
	if egress != 1 {
		t.Errorf("the record lists %d requests through the proxy, want 1", egress)
	}

	var where []string
	for _, root := range []string{dir, runs, records} {
		filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
			if err == nil && e.Type().IsRegular() {
				if b, err := os.ReadFile(path); err == nil && bytes.Contains(b, []byte(sealedMark)) {
					where = append(where, path)
				}
			}
			return nil
		})
	}
	if b, err := os.ReadFile(ref.stored); err != nil || bytes.Contains(b, []byte(sealedMark)) {
		where = append(where, "the receiver's store")
	}
	ref.mu.Lock()
	if strings.Contains(strings.Join(ref.logged, "\n"), sealedMark) {
		where = append(where, "the receiver's log")
	}
	ref.mu.Unlock()
	if strings.Contains(out.String()+errs.String(), sealedMark) {
		where = append(where, "the output")
	}
	if strings.Contains(reports.String(), sealedMark) {
		where = append(where, "a report")
	}
	if len(where) != 0 {
		t.Errorf("the value is in %v", where)
	}
}

// mustGenerate is a fresh access key.
func mustGenerate(t *testing.T) *accesskey.Key {
	t.Helper()
	k, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}
