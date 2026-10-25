package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// The tests of this file fetch through a run's stack proxy, as qory fetches the harness
// definition before the first join, from an HTTPS origin that needs the run
// configuration's harness credential, harness-1, which the reference receiver seals.

// harnessPath is the path of the harness repository that harness-1 is set on.
const harnessPath = "/example-org/harness.git/info/refs"

// harnessKey is the reference receiver's access key id of the gateway on this machine.
const harnessKey = "ak_f1xt0re00000000h"

// harnessReference starts the reference receiver for host: its run configuration has
// stack_hosts, when stack is set, and harness-1, basic on host's harness repository,
// whose value it seals. It returns the receiver's URL, its pin and the gateway's access
// key, which is allowed stored secrets.
func harnessReference(t *testing.T, host, value string, stack bool) (string, accesskey.Pin, *accesskey.Key) {
	t.Helper()
	accessKey, signer := mustGenerate(t), mustGenerate(t)
	store, err := receiver.OpenFile(filepath.Join(t.TempDir(), "received.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	pin := accesskey.Pin{{Alg: "ed25519", PublicKey: signer.PublicKey().String()}}
	pinJSON, _ := json.Marshal(pin)
	doc := `{"version":1,`
	if stack {
		doc += `"stack_hosts":["` + host + `"],`
	}
	doc += `"credentials":[{"name":"harness-1","purpose":"harness","apply":[{"hosts":["` + host + `"],"scheme":"basic","username":"x-access-token","paths":["/example-org/harness.git/*"]}]}]}`
	var srv *httptest.Server
	h := &receiver.Handler{
		Keys: func(id string) (receiver.AccessKey, bool) {
			return receiver.AccessKey{PublicKey: accessKey.PublicKey(), StoredSecrets: true}, id == harnessKey
		},
		Signer:        signer,
		Store:         store,
		Workspaces:    map[string]receiver.Workspace{sealedWorkspace: {Organisation: "org_walltest"}},
		Organisations: map[string]receiver.Organisation{"org_walltest": {}},
		Configuration: func() ([]byte, string) {
			d := []byte(`{"version":1,"node_id":"nd_f1xt0re00000000h","workspaces":["` + sealedWorkspace + `"],"apiary_public_key":` + string(pinJSON) +
				`,"events":{"url":"` + srv.URL + receiver.DefaultEventsPath + `","types":["*"]},"run":{"url":"` + srv.URL + receiver.DefaultRunPath +
				`"},"secrets":{"url":"` + srv.URL + receiver.DefaultSecretsPath + `"}}`)
			sum := sha256.Sum256(d)
			return d, "sha256=" + hex.EncodeToString(sum[:])
		},
		RunConfiguration: func(receiver.Run) ([]byte, string, *receiver.Refusal) { return []byte(doc), "", nil },
		Secrets: func(_ receiver.Run, names []string) ([]receiver.Value, *receiver.Refusal) {
			var values []receiver.Value
			for range names {
				values = append(values, receiver.NewValue([]byte(value)))
			}
			return values, nil
		},
	}
	srv = httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL, pin, accessKey
}

// harnessFetch sends a GET of target through the forwarder p, trusting its CABundle and
// the suite's authority, which signs the origins, and returns the status.
func harnessFetch(p session.HostProxy, target string) (int, error) {
	u, err := url.Parse(p.ProxyURL)
	if err != nil {
		return 0, err
	}
	bundle, err := os.ReadFile(p.CABundle)
	if err != nil {
		return 0, fmt.Errorf("the forwarder's CABundle %q: %w", p.CABundle, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle) {
		return 0, fmt.Errorf("no certificate in %s", p.CABundle)
	}
	ca, _ := authority()
	roots.AddCert(ca)
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{RootCAs: roots}}}
	resp, err := client.Get(target)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, nil
}

// harnessEgress are the dev.qory.run.egress of the record file, each as host, method,
// credential, path and channel.
func harnessEgress(t *testing.T, file string) []string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e struct {
			Type string         `json:"type"`
			Data map[string]any `json:"data"`
		}
		if json.Unmarshal([]byte(line), &e) == nil && e.Type == event.RunEgress {
			out = append(out, fmt.Sprint(e.Data["host"], " ", e.Data["method"], " ", e.Data["credential"], " ", e.Data["path"], " ", e.Data["channel"]))
		}
	}
	return out
}

// noValueIn fails the test when a file under one of roots, or the reports, contain
// value.
func noValueIn(t *testing.T, value, reports string, roots ...string) {
	t.Helper()
	for _, root := range roots {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(value)) {
					t.Errorf("%s contains the harness value", p)
				}
			}
			return nil
		})
	}
	if strings.Contains(reports, value) {
		t.Error("a report contains the harness value")
	}
}

// reportLines collects the lines a gateway or a session reports.
type reportLines struct {
	mu    sync.Mutex
	lines []string
}

func (r *reportLines) add(t *testing.T, l string) {
	t.Log("report:", l)
	r.mu.Lock()
	r.lines = append(r.lines, l)
	r.mu.Unlock()
}

func (r *reportLines) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.lines, "\n")
}

// TestAHarnessCredentialReachesItsOriginThroughTheStackProxy opens a real run without
// a wall against a real gateway on its local link, without Docker, whose control plane,
// the reference receiver, sends a run configuration with the harness credential
// harness-1 for an HTTPS origin on 127.0.0.1, listed in its stack_hosts. Before any
// session joins, a fetch through the run's stack proxy, trusting StackProxy's CABundle,
// gets 200, and the origin gets harness-1's value as basic with the user
// x-access-token, once; the same fetch through the run's host proxy gets 200 and the
// origin no value. The record lists the stack proxy's request with channel stack and
// the credential, and the value is in no file of the run and no report.
//
// The proxy verifies the origin against this machine's roots, which trustRecorders
// points at the suite's authority: without a CA bundle the session reads, or when the
// roots are not the suite's, the test is skipped.
func TestAHarnessCredentialReachesItsOriginThroughTheStackProxy(t *testing.T) {
	if !slices.ContainsFunc(wall.BundleFiles(), func(p string) bool { fi, err := os.Stat(p); return err == nil && fi.Mode().IsRegular() }) {
		Skip(t, fmt.Sprintf("none of %v is on this machine, and a run with an authority opens only with one", wall.BundleFiles()))
	}
	if err := trustRecorders(t); err != nil {
		Skip(t, "this machine's roots are not the suite's authority, so the proxy cannot verify the origin: "+err.Error())
	}
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	const value = "fake-harness-value-of-the-unwalled-test"
	o := newOriginRecording(t, "Authorization")
	refURL, pin, key := harnessReference(t, "127.0.0.1", value, true)
	runs := filepath.Join(t.TempDir(), "runs")
	var reports reportLines
	gw, closeGateway := startGateway(t, gateway.Config{Version: "test", Heartbeat: time.Second,
		Server: &gateway.Server{Version: 1, URL: refURL, AccessKeyID: harnessKey, ApiaryPublicKey: pin, AccessKey: key, InstanceID: "i_harness_node"},
		Report: func(l string) { reports.add(t, l) }}, runs)
	ctx := context.Background()
	r, err := session.Open(ctx, session.OpenSpec{RunsDir: runs, RunID: event.NewRunID(), Gateway: gw, ForagerVersion: "test",
		Report: func(l string) { reports.add(t, l) }})
	if err != nil {
		t.Fatal(err)
	}
	stack, err := r.StackProxy()
	if err != nil {
		t.Fatal(err)
	}
	if status, err := harnessFetch(stack, "https://"+o.host+harnessPath); err != nil || status != http.StatusOK {
		t.Errorf("the fetch through the stack proxy: %d, %v", status, err)
	}
	stack.Close()
	host, err := r.HostProxy()
	if err != nil {
		t.Fatal(err)
	}
	if status, err := harnessFetch(host, "https://"+o.host+harnessPath); err != nil || status != http.StatusOK {
		t.Errorf("the fetch through the host proxy: %d, %v", status, err)
	}
	host.Close()
	if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	closeGateway()
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+value))
	if want := []string{"GET " + harnessPath + " " + basic, "GET " + harnessPath + " "}; !slices.Equal(o.requests(), want) {
		t.Errorf("the origin got %q; want %q", o.requests(), want)
	}
	if got := harnessEgress(t, filepath.Join(r.Dir(), "events.jsonl")); !slices.Contains(got, "127.0.0.1 HTTPS harness-1 "+harnessPath+" stack") {
		t.Errorf("the record's dev.qory.run.egress %q; want the stack proxy's request with harness-1", got)
	}
	noValueIn(t, value, reports.String(), r.Dir())
}

// TestDockerHarnessCredentialThroughTheStackProxy opens a walled run behind the Docker
// adapter whose control plane, the reference receiver, sends a run configuration with
// the harness credential harness-1 for a recorder, a container whose address the node's
// policy and gateway.stack_hosts both list by name. Before any session joins, a fetch
// on this machine through the run's stack proxy, trusting StackProxy's CABundle, gets
// 200, and the recorder gets harness-1's value as basic with the user x-access-token,
// once; the record lists the request with channel stack and the credential, and the
// value is in no file of the run and no report.
//
// The test is skipped without an engine the docker command reaches, and, off Linux,
// without a Linux build of the test binary in QORY_WALL_HELPER.
func TestDockerHarnessCredentialThroughTheStackProxy(t *testing.T) {
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
	name := fmt.Sprintf("qory-walltest-harness-recorder-%d", os.Getpid())
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
	recorder := strings.TrimSpace(string(ip))
	if err := trustRecorders(t); err != nil {
		t.Fatalf("this machine's roots are not the suite's authority: %v", err)
	}
	value := "fake-harness-value-of-the-walled-test-" + fmt.Sprint(os.Getpid())
	refURL, pin, key := harnessReference(t, recorder, value, false)
	runs := filepath.Join(t.TempDir(), "runs")
	var reports reportLines
	gw, closeGateway := startGateway(t, gateway.Config{Version: "walltest", StackHosts: []string{recorder},
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{recorder}}},
		Server: &gateway.Server{Version: 1, URL: refURL, AccessKeyID: harnessKey, ApiaryPublicKey: pin, AccessKey: key, InstanceID: "i_harness_node"},
		Report: func(l string) { reports.add(t, l) }}, runs)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	before, _ := exec.Command(command, "exec", name, "cat", RecorderFile).Output()
	r, err := session.Open(ctx, session.OpenSpec{RunsDir: runs, RunID: event.NewRunID(), Gateway: gw, ForagerVersion: "walltest",
		Wall:  &wall.Docker{Command: command, Helper: helper, RelayArgs: RelayArgs, NestArgs: NestArgs},
		Image: image, Report: func(l string) { reports.add(t, l) }})
	if err != nil {
		t.Fatal(err)
	}
	stack, err := r.StackProxy()
	if err != nil {
		r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1})
		t.Fatal(err)
	}
	if status, err := harnessFetch(stack, "https://"+recorder+":"+recorderTLS+harnessPath); err != nil || status != http.StatusOK {
		t.Errorf("the fetch through the stack proxy: %d, %v", status, err)
	}
	stack.Close()
	if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	closeGateway()
	after, err := exec.Command(command, "exec", name, "cat", RecorderFile).Output()
	if err != nil {
		t.Fatal(err)
	}
	reqs, err := readRecorded(after[len(before):])
	if err != nil {
		t.Fatal(err)
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+value))
	if len(reqs) != 1 || reqs[0].Path != harnessPath || !reqs[0].TLS || !slices.Equal(reqs[0].Header.Values("Authorization"), []string{basic}) {
		t.Errorf("the recorder got %d requests; want one to %s over TLS with harness-1's value once", len(reqs), harnessPath)
	}
	if got := harnessEgress(t, filepath.Join(r.Dir(), "events.jsonl")); !slices.Contains(got, recorder+" HTTPS harness-1 "+harnessPath+" stack") {
		t.Errorf("the record's dev.qory.run.egress %q; want the stack proxy's request with harness-1", got)
	}
	noValueIn(t, value, reports.String(), r.Dir())
}
