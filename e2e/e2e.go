// Package e2e is the conformance suite of the wall: one list of guarantees,
// contracts/forager/v1/README.md §The wall, checked from inside the enclosure, the same
// for every adapter. An adapter ships when the suite passes for it.
//
// The suite runs a real session behind the adapter with a probe as its runtime. The
// probe, the relay and the hook forwarder are all the test binary itself, mounted into
// the enclosure as the adapter's helper, so the suite needs no image of its own beyond
// one with a shell. A test binary that runs the suite calls [Main] first in its
// TestMain:
//
//	func TestMain(m *testing.M) {
//		e2e.Main()
//		os.Exit(m.Run())
//	}
//
// The enclosure runs Linux, so the helper is the test binary only on Linux, built with
// CGO_ENABLED=0; elsewhere QORY_WALL_HELPER names a test binary built for Linux, go
// test -c with GOOS=linux, and without it the suite is skipped.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/session/runtimes/claude"
	"github.com/qoryai/forager/wall"
)

// The modes of the helper, its first argument.
const (
	modeRelay    = "relay"
	modeForward  = "forward"
	modeProbe    = "probe"
	modeTool     = "tool"
	modeNest     = "nest"
	modeInner    = "inner"
	modeRecorder = "recorder"
)

// RelayArgs are the arguments that make the helper run the relay.
var RelayArgs = []string{modeRelay}

// NestArgs are the arguments that make the helper start a Docker of the agent's own.
var NestArgs = []string{modeNest}

// EnvHelper names a Linux build of the test binary, for a machine that is not Linux.
const EnvHelper = "QORY_WALL_HELPER"

// EnvRequire names the variable that, when set, turns every skip of the suite into a
// failure, so the machine that is meant to prove an adapter cannot pass by proving
// nothing.
const EnvRequire = "QORY_WALL_REQUIRE"

// What the suite's credential is: a token in the suite's own environment, for a host
// that does not exist, on one path, with a placeholder inside. The host never needs to
// answer: what is checked happens between the enclosure and the proxy.
const (
	tokenVar       = "QORY_WALLTEST_TOKEN"
	tokenMark      = "walltest-token-held-outside"
	placeholderVar = "PROBE_TOKEN"
	credentialHost = "credential.invalid"
	credentialPath = "/inside-the-paths"
)

// What a runtime's credentials are in the suite: Claude Code's API key, set in
// x-api-key, and its OAuth credential, set as a bearer, each a fake key in the suite's
// own environment for a recorder of its own, with the variable Claude Code reads it
// from inside as its stand-in. keyMark is in both keys and nowhere else: the full keys
// are made when the suite runs, so they exist only in the suite's environment while it
// runs.
const (
	keyMark        = "-REAL-not-a-secret-"
	apiKeyVar      = "QORY_WALLTEST_API_KEY"
	oauthVar       = "QORY_WALLTEST_OAUTH_KEY"
	apiKeyStandIn  = "ANTHROPIC_API_KEY"
	oauthStandIn   = "CLAUDE_CODE_OAUTH_TOKEN"
	apiKeyHeader   = "X-Api-Key"
	modelPath      = "/v1/messages"
	apiKeyCred     = "runtime-api-key"
	oauthCred      = "runtime-oauth"
	recordersCAVar = "PROBE_RECORDERS_CA"
)

// What the suite's tool is: the test binary on this machine, serving a name that
// exists nowhere, held to one prefix of its paths.
const (
	toolHost  = "tool.walltest.invalid"
	toolPaths = "/tool/*"
)

// hostOnly is a variable the suite sets in its own environment and must not find
// inside.
const hostOnly = "QORY_WALLTEST_HOST_ONLY"

// Main makes the test binary the helper when it was started as one: the relay, the hook
// forwarder, the probe, the start of a Docker of the agent's own, the probe in a
// container the agent started, or a recorder. It returns at once otherwise.
func Main() {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case modeRelay:
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := wall.Relay(ctx, os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	case modeForward:
		if err := session.Forward(context.Background(), os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, "forward:", err)
		}
		os.Exit(0)
	case modeProbe:
		os.Exit(probe(os.Args[2:]))
	case modeTool:
		os.Exit(serveTool())
	case modeNest:
		fmt.Fprintln(os.Stderr, wall.Nest(os.Args[2:]))
		os.Exit(1)
	case modeInner:
		os.Exit(innerProbe(os.Args[2:]))
	case modeRecorder:
		os.Exit(serveRecorder())
	}
}

// Skip skips the test, or fails it when [EnvRequire] is set.
func Skip(t *testing.T, why string) {
	t.Helper()
	if os.Getenv(EnvRequire) != "" {
		t.Fatalf("%s is set and the suite cannot run: %s", EnvRequire, why)
	}
	t.Skip(why)
}

// Helper returns the path of the helper to give the adapter, or skips.
func Helper(t *testing.T) string {
	t.Helper()
	if h := os.Getenv(EnvHelper); h != "" {
		return h
	}
	if runtime.GOOS != "linux" {
		Skip(t, "the enclosure runs Linux and this test binary does not; name a Linux build of it in "+EnvHelper)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// Options are what the suite is told about the adapter under test.
type Options struct {
	// Wall is the adapter, built with [Helper] as its helper and [RelayArgs].
	Wall wall.Wall
	// Image is an image with a shell at sh; its user and entry point do not matter.
	Image string
	// Origin is the URL of an HTTP server that answers 200 and is not on this machine,
	// a container's say: the proxy never dials this machine for an enclosure, so the
	// suite's own listener cannot be what an allowed request reaches.
	Origin string
	// Forwarder is the hook forwarder's command inside the enclosure: the adapter's
	// helper path, then "forward".
	Forwarder []string
	// Probe is the helper's path inside the enclosure.
	Probe string
	// Hooks says the adapter carries the hook socket across on this machine. Where it
	// does not, an engine in a virtual machine, the hook check is skipped and said so.
	Hooks bool
	// Leftovers lists what the adapter left behind for a run, for the check that Close
	// removes everything; nil skips that check.
	Leftovers func(runID string) ([]string, error)
	// Runtime is the container runtime the image is started under, as a machine
	// defines it; empty is the engine's default. With it or Docker set, the run selects
	// the image by name among the machine's.
	Runtime string
	// Docker is true when the image contains dockerd and the docker command, and the
	// enclosure gets a Docker of the agent's own. The suite then checks it from the
	// agent's side, and from containers the agent starts, through the Engine API and
	// with the command.
	Docker bool
	// EngineID is the ID of the engine the adapter reaches, which the daemon inside must
	// not be.
	EngineID string
	// Recorders are three recorders: the first acts as the host of a runtime's API key,
	// the second as the host of its OAuth credential, the third as a host the policy
	// allows with no credential. Without them the checks of a runtime's key are skipped,
	// which [EnvRequire] turns into failures. With Recorders, Run points the roots of
	// the process, and the programs it starts within Run, at the suite's authority
	// alone, with SSL_CERT_FILE and SSL_CERT_DIR. The process reads its roots once, at
	// its first verification of a certificate, so the test binary's first verification
	// must come within Run; from then on, for the rest of the process, it trusts only
	// the suite's authority.
	Recorders []Recorder
}

// Run checks the adapter against the guarantees.
func Run(t *testing.T, o Options) {
	// This machine's own listener, on every address: what no path from inside may reach,
	// around the proxy or through it.
	var own atomic.Int32
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	host := &httptest.Server{Listener: ln, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		own.Add(1)
		io.WriteString(w, "this machine")
	})}}
	host.Start()
	defer host.Close()
	origin := hosts{origin: o.Origin, own: fmt.Sprintf("http://127.0.0.1:%d/", ln.Addr().(*net.TCPAddr).Port), port: ln.Addr().(*net.TCPAddr).Port}
	t.Setenv(hostOnly, "1")
	t.Setenv(tokenVar, tokenMark+"-"+strconv.Itoa(os.Getpid()))
	keys := runtimeKeys{api: "sk-ant-test" + keyMark + "0001-" + strconv.Itoa(os.Getpid()), oauth: "sk-ant-oat01-test" + keyMark + "0002-" + strconv.Itoa(os.Getpid())}
	t.Setenv(apiKeyVar, keys.api)
	t.Setenv(oauthVar, keys.oauth)
	var trusted error
	if n := len(o.Recorders); n != 0 && n != 3 {
		t.Fatalf("Recorders lists %d recorders; the suite takes three: the API key's host, the OAuth credential's host, and an allowed host with none", n)
	}
	if len(o.Recorders) == 3 {
		trusted = trustRecorders(t)
		for _, rec := range o.Recorders {
			origin.recorders = append(origin.recorders, rec.Host)
		}
	}
	outside := filepath.Join(t.TempDir(), "host-file")
	if err := os.WriteFile(outside, []byte("the host's"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := run(t, o, false, origin, outside)
	p := r.probe
	check := func(name string, ok bool, detail any) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			t.Helper()
			if !ok {
				t.Errorf("%v", detail)
			}
		})
	}
	check("no route out by address", p.OutsideAddress != "", "the probe connected to an outside address")
	check("no name resolved outside", p.OutsideName != "", "the probe resolved an outside name")
	check("no metadata address", p.Metadata != "", "the probe connected to the metadata address")
	check("the proxy is reached and decides", p.Allowed == 200 && p.Denied == 403, fmt.Sprintf("allowed answered %d (%s), denied answered %d (%s)", p.Allowed, p.AllowedErr, p.Denied, p.DeniedErr))
	var egress []string
	for _, e := range r.events {
		if e["type"] == "dev.qory.run.egress" {
			d := e["data"].(map[string]any)
			egress = append(egress, fmt.Sprint(d["host"], " ", d["decision"], " ", d["rule"]))
		}
	}
	originHost := mustHost(t, o.Origin)
	want := "[" + originHost + " allowed " + originHost + " denied.invalid denied  127.0.0.1 denied wall:own-address 169.254.169.254 denied wall:own-address " + originHost + " denied " + originHost + " " + credentialHost + " denied " + credentialHost + " " + credentialHost + " allowed " + credentialHost + " " + toolHost + " allowed " + toolHost + " " + toolHost + " denied " + toolHost
	if len(origin.recorders) == 3 {
		// A runtime's two credentials to their hosts, then the other host plainly and
		// through a tunnel.
		for _, h := range []string{origin.recorders[0], origin.recorders[1], origin.recorders[2], origin.recorders[2]} {
			want += " " + h + " allowed " + h
		}
	}
	if o.Docker {
		// Each container the agent starts reaches the origin once, through the relay: one
		// of each kind through the Engine API, and one with the docker command.
		for range len(innerKinds) + 1 {
			want += " " + originHost + " allowed " + originHost
		}
	}
	check("what went through the proxy is recorded", fmt.Sprint(egress) == want+"]", egress)
	check("a host held to paths is held to them", p.PathDenied == 403, fmt.Sprintf("a path outside the host's answered %d", p.PathDenied))
	check("a terminated host is answered with the run's authority, held to the credential's paths", p.TLSDenied == 403 && p.TLSAllowed == 502,
		fmt.Sprintf("outside the paths answered %d (%s), inside them %d (%s), want the proxy's 403 and, with nothing upstream, its 502; the bundle is %q with %d certificates", p.TLSDenied, p.TLSDeniedErr, p.TLSAllowed, p.TLSAllowedErr, p.Bundle, p.BundleCerts))
	set := ""
	for _, e := range r.events {
		if d, _ := e["data"].(map[string]any); e["type"] == "dev.qory.run.egress" && d["path"] == credentialPath {
			set, _ = d["credential"].(string)
		}
	}
	check("the credential is set outside, on its own paths", set == "suite", fmt.Sprintf("the request inside the credential's paths is recorded with the credential %q", set))
	var invoked map[string]any
	for _, e := range r.events {
		if d, _ := e["data"].(map[string]any); e["type"] == "dev.qory.run.egress" && d["path"] == "/tool/inside" {
			invoked = d
		}
	}
	check("a tool is reached through the proxy, held to its paths, and handed the proxy's word", p.ToolAllowed == 200 && p.ToolDenied == 403 && p.ToolSaw == "rule=/tool/* id="+fmt.Sprint(invoked["request_id"]) && invoked["tool"] == "suite-tool" && invoked["status"] == float64(200),
		fmt.Sprintf("inside the paths answered %d (%s), handed %q; outside them %d; recorded as %v", p.ToolAllowed, p.ToolAllowedErr, p.ToolSaw, p.ToolDenied, invoked))
	record, _ := os.ReadFile(filepath.Join(r.res.Dir, "events.jsonl"))
	check("no credential inside the enclosure", p.Placeholder == link.Placeholder && len(p.TokenSeen) == 0 && p.BundleCerts > 0 && p.BundleKeys == 0 && !bytes.Contains(record, []byte(tokenMark)),
		fmt.Sprintf("the placeholder is %q; the token was seen in %v; the bundle holds %d certificates and %d keys; the token is in the record: %v", p.Placeholder, p.TokenSeen, p.BundleCerts, p.BundleKeys, bytes.Contains(record, []byte(tokenMark))))
	checkKeys(t, o, r, keys, trusted)
	check("no way to this machine through the proxy unless the policy names it", p.OwnViaProxy == 403 && p.MetaViaProxy == 403 && own.Load() == 0, fmt.Sprintf("this machine's listener answered %d through the proxy and was reached %d times; the metadata address answered %d", p.OwnViaProxy, own.Load(), p.MetaViaProxy))
	check("no way to the engine's host by the network's first address", len(p.HostByGateway) == 0, p.HostByGateway)
	check("the record is read-only", p.RecordWrite != "", "the probe opened events.jsonl for writing")
	check("not root", p.UID != 0 && p.GID != 0, fmt.Sprintf("uid %d gid %d", p.UID, p.GID))
	check("no capabilities and none to gain", zero(p.CapEff) && zero(p.CapPrm) && zero(p.CapBnd) && zero(p.CapInh) && zero(p.CapAmb) && p.NoNewPrivs == "1", fmt.Sprintf("CapEff %s CapPrm %s CapBnd %s CapInh %s CapAmb %s NoNewPrivs %s", p.CapEff, p.CapPrm, p.CapBnd, p.CapInh, p.CapAmb, p.NoNewPrivs))
	if !o.Docker {
		check("no container runtime socket", len(p.Sockets) == 0, p.Sockets)
	} else {
		n := p.Nested
		if n == nil {
			n = &nested{}
		}
		var others []string
		for _, s := range p.Sockets {
			if s != wall.NestSocket && s != "/run/docker.sock" {
				others = append(others, s)
			}
		}
		check("no container runtime socket but the enclosure's own daemon", len(others) == 0 && n.DaemonID != "" && n.DaemonID != o.EngineID, fmt.Sprintf("other sockets %v; the daemon inside is %q, the machine's engine %q", others, n.DaemonID, o.EngineID))
		check("the agent reaches its own daemon, as its user", n.Ping == 200 && p.UID != 0, fmt.Sprintf("the daemon answered %d (%s) to uid %d", n.Ping, n.PingErr, p.UID))
		check("nothing listens on the enclosure's network", len(n.Listening) == 0, n.Listening)
		check("the daemon runs nothing of the run's PATH", len(n.Decoys) == 0, fmt.Sprintf("the programs of the workspace that ran, as uid and name: %q", n.Decoys))
		check("the agent builds an image of its own", n.Image == "", n.Image)
		for _, k := range innerKinds {
			c, ok := n.Containers[k.name]
			check("a container the agent starts, "+k.name+", has no route out but the relay",
				ok && c.Err == "" && c.OutsideAddress != "" && c.OutsideName != "" && c.Metadata != "" && c.OriginDirect != "" && c.ViaProxy == 200,
				fmt.Sprintf("%+v", c))
		}
		c := n.Command
		check("a container the agent's docker command starts reaches the origin by the proxy of the agent's configuration, and nothing else",
			c.Err == "" && c.Proxy != "" && c.OutsideAddress != "" && c.OutsideName != "" && c.Metadata != "" && c.OriginDirect != "" && c.ViaProxy == 200,
			fmt.Sprintf("%+v; the agent's configuration, as its user sees it: %v", c, n.Config))
	}
	check("no environment but what the run passes", !p.HostEnv && p.PassedEnv, fmt.Sprintf("the host's variable seen: %v; the run's variable seen: %v; all: %v", p.HostEnv, p.PassedEnv, p.EnvNames))
	check("no file of the host but the mounts", !p.HostFile, "the probe read a file outside the workspace")
	check("the settings are read-only", p.SettingsWrite != "", "the probe opened the session's settings for writing")
	written, err := os.ReadFile(filepath.Join(r.dir, "probe-was-here"))
	check("the workspace is the run's", err == nil && string(written) == "inside", err)
	if runtime.GOOS == "linux" {
		for _, ns := range []string{"net", "pid", "mnt", "ipc", "uts"} {
			host, _ := os.Readlink("/proc/self/ns/" + ns)
			check("no host namespace: "+ns, p.Namespaces[ns] != "" && p.Namespaces[ns] != host, fmt.Sprintf("inside %q, the host %q", p.Namespaces[ns], host))
		}
	}
	t.Run("the hook reaches the session", func(t *testing.T) {
		if !o.Hooks {
			t.Skip("the adapter carries no hook socket across on this machine")
		}
		for _, e := range r.events {
			if e["type"] == "dev.qory.session.ended" {
				return
			}
		}
		t.Errorf("no session.ended among the events; the hook said: %s", p.Hook)
	})
	check("the exit status is the runtime's", r.res.ExitCode == 7, r.res.ExitCode)
	for _, e := range r.events {
		if e["type"] == "dev.qory.run.started" {
			d := e["data"].(map[string]any)
			check("the record names the wall", d["wall"] == o.Wall.Name() && d["image"] == o.Image, d)
			if o.Runtime != "" || o.Docker {
				check("the record names the image the policy selected, its runtime and its Docker", d["image_name"] == "suite" && fmt.Sprint(d["container_runtime"]) == fmt.Sprint(orNil(o.Runtime)) && (d["docker"] == true) == o.Docker, d)
			}
		}
	}
	if o.Leftovers != nil {
		left, err := o.Leftovers(r.res.RunID)
		check("Close removes everything", err == nil && len(left) == 0, fmt.Sprint(left, err))
	}

	t.Run("the terminal crosses and a named host on this machine is reached", func(t *testing.T) {
		origin.named = true
		r := run(t, o, true, origin, outside)
		if !r.probe.Terminal {
			t.Error("the probe's standard output is not a terminal in an interactive run")
		}
		if r.probe.OwnViaProxy != 200 || own.Load() == 0 || r.probe.MetaViaProxy != 403 {
			t.Errorf("with 127.0.0.1 named in the allow list this machine's listener answered %d through the proxy, and the metadata address %d", r.probe.OwnViaProxy, r.probe.MetaViaProxy)
		}
		t.Run("no runtime's key in the record", func(t *testing.T) {
			if len(o.Recorders) != 3 {
				Skip(t, "the adapter's test starts no recorders")
			}
			checkNoKey(t, r)
		})
	})
}

// runtimeKeys are the keys of a runtime's two credentials, in the suite's own
// environment.
type runtimeKeys struct{ api, oauth string }

// checkKeys checks a runtime's two credentials, from the probe, the recorders and the
// record: each key reaches its own host in its own header, in place of the stand-in the
// session sent, and no other host; inside, every environment the probe can read
// contains the stand-ins and no key; and nothing the run recorded contains a key.
func checkKeys(t *testing.T, o Options, r result, keys runtimeKeys, trusted error) {
	t.Helper()
	names := []string{
		"a runtime's API key reaches its host in x-api-key, in place of the stand-in",
		"a runtime's OAuth credential reaches its host as a bearer, in place of the stand-in",
		"only the stand-ins inside the enclosure, in every environment it can read",
		"no other host gets a runtime's key",
		"no runtime's key in the record",
	}
	if len(o.Recorders) != 3 {
		for _, n := range names {
			t.Run(n, func(t *testing.T) { Skip(t, "the adapter's test starts no recorders") })
		}
		return
	}
	var got [3][]recorded
	for i, rec := range o.Recorders {
		b, err := rec.Recorded()
		if err == nil {
			got[i], err = readRecorded(b)
		}
		if err != nil {
			for _, n := range names {
				t.Run(n, func(t *testing.T) { t.Errorf("the recorder at %s: %v", rec.Host, err) })
			}
			return
		}
	}
	p := r.probe
	arrived := func(t *testing.T, i int, header, want, cred string, status int, statusErr string) {
		t.Helper()
		if trusted != nil {
			t.Fatalf("this machine's roots are not the suite's authority, so the proxy cannot verify a recorder: %v", trusted)
		}
		var at []recorded
		for _, req := range got[i] {
			if req.Path == modelPath {
				at = append(at, req)
			}
		}
		if len(at) != 1 || status != 200 {
			t.Fatalf("the host got %d requests at %s, want 1; the probe was answered %d (%s)", len(at), modelPath, status, statusErr)
		}
		h := at[0].Header
		if v := h.Values(header); len(v) != 1 || v[0] != want {
			t.Errorf("the host got %s %q, want the key once", header, v)
		}
		for name, vs := range h {
			for _, v := range vs {
				if strings.Contains(v, link.Placeholder) {
					t.Errorf("the stand-in reached the host in %s: %q", name, v)
				}
			}
		}
		set := ""
		for _, e := range r.events {
			if d, _ := e["data"].(map[string]any); e["type"] == "dev.qory.run.egress" && d["host"] == o.Recorders[i].Host && d["path"] == modelPath {
				set, _ = d["credential"].(string)
			}
		}
		if set != cred {
			t.Errorf("the request is recorded with the credential %q, want %q", set, cred)
		}
	}
	t.Run(names[0], func(t *testing.T) { arrived(t, 0, apiKeyHeader, keys.api, apiKeyCred, p.APIKeyHost, p.APIKeyHostErr) })
	t.Run(names[1], func(t *testing.T) {
		arrived(t, 1, "Authorization", "Bearer "+keys.oauth, oauthCred, p.OAuthHost, p.OAuthHostErr)
	})
	t.Run(names[2], func(t *testing.T) {
		if p.APIKeyStandIn != link.Placeholder || p.OAuthStandIn != link.Placeholder || len(p.KeySeen) != 0 || p.Environs == 0 {
			t.Errorf("%s is %q and %s is %q; a key was seen in %v; %d environments were read", apiKeyStandIn, p.APIKeyStandIn, oauthStandIn, p.OAuthStandIn, p.KeySeen, p.Environs)
		}
	})
	t.Run(names[3], func(t *testing.T) {
		if p.OtherPlain != 200 || p.OtherTunnel != 200 {
			t.Errorf("the other host answered %d (%s) plainly and %d (%s) through a tunnel", p.OtherPlain, p.OtherPlainErr, p.OtherTunnel, p.OtherTunnelErr)
		}
		reached := map[bool]bool{}
		for _, req := range got[2] {
			reached[req.TLS] = true
			if req.Header.Get("Authorization") != "Bearer "+link.Placeholder || req.Header.Get(apiKeyHeader) != link.Placeholder {
				t.Errorf("the other host got Authorization %q and %s %q, want the stand-ins", req.Header.Get("Authorization"), apiKeyHeader, req.Header.Get(apiKeyHeader))
			}
		}
		if !reached[false] || !reached[true] {
			t.Errorf("the other host was reached plainly %v and through a tunnel %v", reached[false], reached[true])
		}
		for i, reqs := range got {
			for _, req := range reqs {
				for name, vs := range req.Header {
					for _, v := range vs {
						own := (i == 0 && name == apiKeyHeader && v == keys.api) || (i == 1 && name == "Authorization" && v == "Bearer "+keys.oauth)
						if strings.Contains(v, keyMark) && !own {
							t.Errorf("%s got a key in %s, at %s", o.Recorders[i].Host, name, req.Path)
						}
					}
				}
			}
		}
	})
	t.Run(names[4], func(t *testing.T) { checkNoKey(t, r) })
}

// checkNoKey checks that the run's directory, its output and what the session reported
// contain no runtime's key.
func checkNoKey(t *testing.T, r result) {
	t.Helper()
	var where []string
	// r.runs holds the run directory, r.res.Dir; r.dir is the workspace.
	for _, root := range []string{r.dir, r.runs} {
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil
			}
			if b, err := os.ReadFile(path); err == nil && bytes.Contains(b, []byte(keyMark)) {
				where = append(where, path)
			}
			return nil
		})
	}
	for name, s := range map[string]string{"the output": r.out, "the errors": r.errs, "what the session reported": r.reports} {
		if strings.Contains(s, keyMark) {
			where = append(where, name)
		}
	}
	if len(where) != 0 {
		t.Errorf("a key is in %v", where)
	}
}

// hosts are the addresses a run's probe is told.
type hosts struct {
	origin string
	own    string
	port   int
	// named puts this machine's loopback in the allow list by name.
	named bool
	// recorders are the hosts of [Options.Recorders], when there are three.
	recorders []string
}

// mustHost is the host of a URL.
func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		t.Fatalf("the origin %q is not a URL", raw)
	}
	return u.Hostname()
}

// orNil is a string as a record holds it: absent when empty.
func orNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func zero(hex string) bool { return hex != "" && strings.Trim(hex, "0") == "" }

// decoyNames are programs the daemon starts as the enclosure's root, looked for on its
// PATH.
var decoyNames = []string{"containerd", "runc", "iptables"}

// decoys writes a directory of the workspace, which the run puts first on its PATH,
// containing a program of each of decoyNames that notes in [decoyRan], inside the
// enclosure, that it ran and as whom, then runs the image's own from the rest of the
// PATH. The enclosure's root must run none of them.
func decoys(workspace string) (string, error) {
	bin := filepath.Join(workspace, "decoys")
	if err := os.Mkdir(bin, 0o755); err != nil {
		return "", err
	}
	script := "#!/bin/sh\necho \"$(id -u) ${0##*/}\" >> " + decoyRan + "\nPATH=${PATH#*:} exec \"${0##*/}\" \"$@\"\n"
	for _, name := range decoyNames {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			return "", err
		}
	}
	return bin, nil
}

// result is one run behind the wall.
type result struct {
	res *session.Result
	// dir is the workspace, and runs the runs directory, outside it.
	dir, runs string
	probe     report
	events    []map[string]any
	// out, errs and reports are the run's standard output and error, and what the
	// session reported.
	out, errs, reports string
}

// run runs the probe as the runtime of a session behind the wall and reads what it
// reported and what the session recorded.
func run(t *testing.T, o Options, interactive bool, h hosts, outside string) result {
	t.Helper()
	dir, runs := t.TempDir(), filepath.Join(t.TempDir(), "runs")
	var out, errs, reports bytes.Buffer
	var reportsMu sync.Mutex
	settings := filepath.Join(dir, "launch-settings.json")
	if err := os.WriteFile(settings, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// The metadata address is in the list to show that no entry opens it.
	allow := []string{mustHost(t, h.origin), "169.254.169.254", credentialHost, toolHost}
	if h.named {
		allow = append(allow, "127.0.0.1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rt, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	// The tool runs on this machine, outside the enclosure: this binary, not the helper.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if o.Docker {
		bin, err := decoys(dir)
		if err != nil {
			t.Fatal(err)
		}
		path = bin + ":" + path
	}
	env := []string{
		"PATH=" + path,
		"PROBE_PASSED=yes", "PROBE_EXIT=7", "PROBE_HOST_FILE=" + outside,
		"PROBE_ALLOWED=" + h.origin,
		"PROBE_DENIED=http://denied.invalid/",
		"PROBE_OWN=" + h.own,
		"PROBE_HOST_PORT=" + strconv.Itoa(h.port),
	}
	if o.Docker {
		env = append(env, "PROBE_DOCKER=1")
	}
	policyCreds := []session.PolicyCredential{{Name: "suite"}}
	creds := []session.Credential{{Name: "suite", Env: tokenVar, Hosts: []string{credentialHost}, Scheme: "bearer", Paths: []string{credentialPath}, Placeholders: []string{placeholderVar}}}
	if len(h.recorders) == 3 {
		cert, _ := authority()
		env = append(env, "PROBE_API_KEY_HOST="+h.recorders[0], "PROBE_OAUTH_HOST="+h.recorders[1], "PROBE_OTHER_HOST="+h.recorders[2],
			recordersCAVar+"="+base64.StdEncoding.EncodeToString(cert.Raw))
		allow = append(allow, h.recorders...)
		policyCreds = append(policyCreds, session.PolicyCredential{Name: apiKeyCred}, session.PolicyCredential{Name: oauthCred})
		creds = append(creds,
			session.Credential{Name: apiKeyCred, Env: apiKeyVar, Hosts: []string{h.recorders[0]}, Scheme: "header", Header: apiKeyHeader, Paths: []string{"/v1/*"}, Placeholders: []string{apiKeyStandIn}},
			session.Credential{Name: oauthCred, Env: oauthVar, Hosts: []string{h.recorders[1]}, Scheme: "bearer", Paths: []string{"/v1/*"}, Placeholders: []string{oauthStandIn}})
	}
	// With a runtime or a Docker the machine defines the image and the policy selects
	// it by name; otherwise the image is the machine's default, a reference.
	var images []session.Image
	selected := ""
	if o.Runtime != "" || o.Docker {
		images = []session.Image{{Name: "suite", Ref: o.Image, Runtime: o.Runtime, Docker: o.Docker}}
		selected = "suite"
	}
	res, err := session.Run(ctx, session.Spec{
		Runtime:     rt,
		Command:     o.Probe,
		Args:        []string{modeProbe, "--settings", settings},
		Env:         env,
		Dir:         dir,
		RunsDir:     runs,
		Interactive: interactive,
		Stdin:       strings.NewReader(""),
		Stdout:      &out,
		Stderr:      &errs,
		Policy: &session.Policy{Version: 1,
			Egress:      session.PolicyEgress{Mode: "enforce", Allow: allow, Paths: map[string][]string{mustHost(t, h.origin): {"/"}, toolHost: {toolPaths}}},
			Credentials: policyCreds,
			Tools:       []session.PolicyTool{{Name: "suite-tool"}},
			Image:       selected},
		Tools:          []session.Tool{{Name: "suite-tool", Command: []string{exe, modeTool}, Serves: []string{toolHost}}},
		Credentials:    creds,
		Forwarder:      o.Forwarder,
		Wall:           o.Wall,
		Image:          o.Image,
		Images:         images,
		ForagerVersion: "walltest",
		Report: func(l string) {
			t.Log("report:", l)
			reportsMu.Lock()
			reports.WriteString(l + "\n")
			reportsMu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("the run did not start: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errs.String())
	}
	reportsMu.Lock()
	r := result{res: res, dir: dir, runs: runs, out: out.String(), errs: errs.String(),
		reports: reports.String()}
	reportsMu.Unlock()
	found := false
	for _, line := range strings.Split(out.String(), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), probePrefix); ok {
			if err := json.Unmarshal([]byte(rest), &r.probe); err != nil {
				t.Fatalf("the probe's report: %v\n%s", err, rest)
			}
			found = true
			t.Logf("the probe (interactive %v): %s", interactive, rest)
		}
	}
	if !found {
		t.Fatalf("the probe reported nothing; exit %d\nstdout:\n%s\nstderr:\n%s", res.ExitCode, out.String(), errs.String())
	}
	f, err := os.Open(filepath.Join(res.Dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(nil, 1<<20)
	for s.Scan() {
		var m map[string]any
		if err := json.Unmarshal(s.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		r.events = append(r.events, m)
	}
	return r
}
