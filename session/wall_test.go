package session_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/wall"
)

// openWall is a wall with nothing in it: it records what the session sends it
// and starts the launch as it is, pointed at the proxy and the socket by their own
// addresses.
type openWall struct {
	req     wall.Request
	got     wall.Launch
	wrapped bool
	closed  int
}

func (w *openWall) Name() string { return "open" }
func (w *openWall) Prepare(_ context.Context, req wall.Request) (wall.Enclosure, error) {
	w.req = req
	return w, nil
}
func (w *openWall) ProxyAddr() string { return "127.0.0.1:0" }
func (w *openWall) Wrap(_ context.Context, l wall.Launch) (wall.Launch, error) {
	w.got, w.wrapped = l, true
	env := append(append([]string(nil), l.Env...), "HTTP_PROXY=http://"+l.Proxy, session.EnvSocket+"="+l.Socket)
	return wall.Launch{Command: l.Command, Args: l.Args, Env: env, Dir: l.Dir}, nil
}
func (w *openWall) Close(context.Context) error { w.closed++; return nil }

// relayWall is an open wall with a relay: the launch reaches the proxy through a
// listener of the test's that opens every connection with the run's proxy secret, as
// the wall's relay does.
type relayWall struct {
	openWall
	ln net.Listener
}

func (w *relayWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *relayWall) Wrap(ctx context.Context, l wall.Launch) (wall.Launch, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return wall.Launch{}, err
	}
	w.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				up, err := net.Dial("tcp", l.Proxy)
				if err != nil {
					return
				}
				defer up.Close()
				fmt.Fprintf(up, "%s %s\n", link.RelayPreamble, l.ProxyToken)
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	relayed := l
	relayed.Proxy = ln.Addr().String()
	return w.openWall.Wrap(ctx, relayed)
}

func (w *relayWall) Close(ctx context.Context) error {
	if w.ln != nil {
		w.ln.Close()
	}
	return w.openWall.Close(ctx)
}

// TestWallWrapsTheLaunch pins what crosses to a wall and what does not: the enclosure
// is asked where the forwarder listens and told where it does, it gets the socket,
// the settings the session wrote and the run's environment without the proxy
// variables, the run's proxy secret goes to the wall's relay alone, a nil environment
// is nothing and not the process's own, the record names the wall and the image, and
// the enclosure is closed once.
func TestWallWrapsTheLaunch(t *testing.T) {
	t.Setenv("QORY_TEST_HOST_ONLY", "1")
	w := &openWall{}
	sp := spec(t, "FAKE_EXIT=0")
	sp.Wall, sp.Image, sp.Mounts = w, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	res, err := runWithSettingsEnv(t, sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || !w.wrapped || w.closed != 1 {
		t.Errorf("exit %d, wrapped %v, closed %d times", res.ExitCode, w.wrapped, w.closed)
	}
	if w.req.RunID != res.RunID || w.req.Image != "example.com/agent:1" {
		t.Errorf("request %+v", w.req)
	}
	if !strings.HasPrefix(w.got.Proxy, "127.0.0.1:") || strings.HasSuffix(w.got.Proxy, ":0") || w.got.Socket == "" {
		t.Errorf("proxy %q socket %q", w.got.Proxy, w.got.Socket)
	}
	if w.got.ProxyToken != linktest.ProxySecret {
		t.Errorf("the wall's relay got %q as the proxy secret", w.got.ProxyToken)
	}
	if want := []wall.Mount{{Path: sp.Dir}, {Path: res.Dir, ReadOnly: true}}; !slices.Equal(w.got.Mounts, want) {
		t.Errorf("mounts %v, want %v", w.got.Mounts, want)
	}
	env := strings.Join(w.got.Env, "\n")
	if strings.Contains(env, "PROXY") || strings.Contains(env, session.EnvSocket) || !strings.Contains(env, session.EnvRunID+"="+res.RunID) || strings.Contains(env, linktest.ProxySecret) {
		t.Errorf("the enclosure's environment:\n%s", env)
	}
	evs := events(t, res)
	if d := data(evs[0]); d["wall"] != "open" || d["image"] != "example.com/agent:1" {
		t.Errorf("run.started %v", d)
	}
	if len(ofType(evs, "dev.qory.session.ended")) != 1 {
		t.Errorf("the hook did not cross: %v", types(evs))
	}

	w = &openWall{}
	sp = spec(t)
	sp.Wall, sp.Image, sp.Env = w, "i", nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", `test -z "$QORY_TEST_HOST_ONLY"`}
	if res, err := session.Run(context.Background(), sp); err != nil || res.ExitCode != 0 {
		t.Errorf("a nil environment under a wall carried the process's own: %v %+v", err, res)
	}
}

// TestTheForwarderCarriesTheProxySecret pins how the agent's traffic reaches the
// gateway's proxy: without a wall the forwarder opens every connection with the relay's
// preamble and the run's proxy secret, behind a wall it passes on what the wall's relay
// sends, which opens with it, so the proxy sees the preamble once either way; the
// agent's environment and the session's record never hold the secret, and without a
// wall the agent's proxy URL is the forwarder on loopback with a password.
func TestTheForwarderCarriesTheProxySecret(t *testing.T) {
	for _, walled := range []bool{false, true} {
		t.Run(fmt.Sprint("walled ", walled), func(t *testing.T) {
			sp, g := specGateway(t, "FAKE_EXIT=0", "FAKE_ALLOWED_URL=http://api.example/a")
			out := filepath.Join(t.TempDir(), "env")
			sp.Forwarder = nil
			sp.Command, sp.Args = "/bin/sh", []string{"-c", `env > "$0"; exec "$1"`, out, os.Args[0]}
			if walled {
				sp.Wall, sp.Image = &relayWall{}, "example.com/agent:1"
			}
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if res.ExitCode != 0 {
				t.Fatalf("exit %d", res.ExitCode)
			}
			if got, want := g.Preambles(), []string{link.RelayPreamble + " " + linktest.ProxySecret}; !slices.Equal(got, want) {
				t.Errorf("the gateway's proxy saw %q, want %q", got, want)
			}
			if got := g.Proxied(); !slices.Equal(got, []string{"GET http://api.example/a"}) {
				t.Errorf("the gateway's proxy answered %q", got)
			}
			env, _ := os.ReadFile(out)
			record, _ := os.ReadFile(filepath.Join(res.Dir, "session.jsonl"))
			if bytes.Contains(env, []byte(linktest.ProxySecret)) || bytes.Contains(record, []byte(linktest.ProxySecret)) {
				t.Error("the proxy secret reached the agent's environment or the record")
			}
			if !walled && !regexp.MustCompile(`(?m)^HTTP_PROXY=http://qory:[A-Za-z0-9_-]{43}@127\.0\.0\.1:[0-9]+$`).Match(env) {
				t.Errorf("the agent's environment has no proxy on loopback with a password:\n%s", env)
			}
		})
	}
}

// TestTheUnwalledForwarderTakesOnlyTheAgentsPassword pins the password of an unwalled
// agent's proxy URL on one machine: another process of the machine that reaches the
// forwarder without it, or with another password, is closed unanswered and nothing of
// it reaches the gateway's proxy, while the agent's own request does; the password is
// in no file of the run directory, and the forwarder is gone with the run.
func TestTheUnwalledForwarderTakesOnlyTheAgentsPassword(t *testing.T) {
	strays := filepath.Join(t.TempDir(), "strays")
	sp, g := specGateway(t, "FAKE_EXIT=0", "FAKE_ALLOWED_URL=http://api.example/a", "FAKE_STRAY="+strays)
	out := filepath.Join(t.TempDir(), "env")
	sp.Forwarder = nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", `env > "$0"; exec "$1"`, out, os.Args[0]}
	res, err := session.Run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d", res.ExitCode)
	}
	if b, _ := os.ReadFile(strays); string(b) != "closed unanswered\nclosed unanswered\n" {
		t.Errorf("the forwarder took a connection without the password:\n%s", b)
	}
	if got, want := g.Preambles(), []string{link.RelayPreamble + " " + linktest.ProxySecret}; !slices.Equal(got, want) {
		t.Errorf("the gateway's proxy saw %q, want the agent's one connection", got)
	}
	if got := g.Proxied(); !slices.Equal(got, []string{"GET http://api.example/a"}) {
		t.Errorf("the gateway's proxy answered %q", got)
	}
	env, _ := os.ReadFile(out)
	m := regexp.MustCompile(`(?m)^HTTP_PROXY=http://qory:([A-Za-z0-9_-]{43})@(127\.0\.0\.1:[0-9]+)$`).FindSubmatch(env)
	if m == nil {
		t.Fatalf("the agent's proxy URL carries no password:\n%s", env)
	}
	filepath.WalkDir(res.Dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if b, _ := os.ReadFile(path); bytes.Contains(b, m[1]) {
				t.Errorf("%s holds the forwarder's password", path)
			}
		}
		return nil
	})
	if c, err := net.Dial("tcp", string(m[2])); err == nil {
		c.Close()
		t.Error("the forwarder still listens after the run")
	}
}

// authority is a certificate in the form the run answer carries one, PEM.
const authority = "-----BEGIN CERTIFICATE-----\nMIIBexampleAAAA\n-----END CERTIFICATE-----\n"

// TestTheAnswerCrossesAsAnAuthorityAndAPlaceholder pins what a wall is given of the
// run answer of a run whose gateway holds a credential: the run authority's
// certificate and a placeholder in place of the credential, and what the record says
// of it, the members of policy_applied the gateway decides as it gives them.
func TestTheAnswerCrossesAsAnAuthorityAndAPlaceholder(t *testing.T) {
	w := &openWall{}
	sp, g := specGateway(t, "FAKE_EXIT=0")
	credentialAnswer(g)
	sp.Wall, sp.Image = w, "example.com/agent:1"
	res, err := runWithSettingsEnv(t, sp)
	if err != nil {
		t.Fatal(err)
	}
	if string(w.got.CA) != authority {
		t.Errorf("the wall got %q as the authority", w.got.CA)
	}
	if !slices.Contains(w.got.Env, "MODEL_TOKEN="+link.Placeholder) {
		t.Errorf("no placeholder in %v", w.got.Env)
	}
	applied := data(ofType(events(t, res), "dev.qory.run.policy_applied")[0])
	creds, _ := applied["credentials"].([]any)
	terminated, _ := applied["terminated"].([]any)
	if len(creds) != 1 || creds[0].(map[string]any)["scheme"] != "bearer" || len(terminated) != 1 || applied["digest"] != strings.Repeat("a", 64) {
		t.Errorf("run.policy_applied %v", applied)
	}
}

// credentialAnswer has g answer a run as a gateway that holds the credential model,
// whose placeholder is MODEL_TOKEN, with the run's authority, with or without a wall.
func credentialAnswer(g *linktest.Fake) {
	members := map[string]any{"mode": "enforce", "allow": []string{"api.model.example"}, "deny": []string{}, "source": "config", "digest": strings.Repeat("a", 64),
		"credentials": []any{map[string]any{"name": "model", "hosts": []string{"api.model.example"}, "scheme": "bearer"}}, "terminated": []string{"api.model.example"}}
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["policy"] = map[string]any{"version": 1, "egress": map[string]any{"mode": "enforce", "allow": []string{"api.model.example"}}, "credentials": []any{map[string]any{"name": "model"}}}
		a["digest"], a["applied"], a["placeholders"] = strings.Repeat("a", 64), members, []string{"MODEL_TOKEN"}
		a["certificate_authority"] = authority
		return linktest.Reply{Status: 200, Body: a}
	})
}

// machineRoots is a bundle of the machine's authorities, in the form of a PEM file.
const machineRoots = "-----BEGIN CERTIFICATE-----\nMIIBmachineROOT\n-----END CERTIFICATE-----"

// TestAnUnwalledRunIsBrokered pins a run without a wall whose gateway holds a
// credential: the agent's environment has the credential's placeholder, over a value
// the run inherits, and the variables of the run's bundle, each of them the path of
// ca-bundle.pem in the run directory, which contains the machine's authorities and
// then the run's certificate. Spec.CAEnv names those variables when it is set.
func TestAnUnwalledRunIsBrokered(t *testing.T) {
	for name, names := range map[string][]string{"the default variables": nil, "Spec.CAEnv": {"MY_CA_FILE", "SSL_CERT_FILE"}} {
		t.Run(name, func(t *testing.T) {
			roots := filepath.Join(t.TempDir(), "cert.pem")
			if err := os.WriteFile(roots, []byte(machineRoots), 0o644); err != nil {
				t.Fatal(err)
			}
			defer session.SetMachineBundles([]string{filepath.Join(t.TempDir(), "none.pem"), roots})()
			sp, g := specGateway(t, "FAKE_EXIT=0", "MODEL_TOKEN=inherited-fake-token")
			credentialAnswer(g)
			sp.CAEnv = names
			out := dumpsEnv(t, &sp)
			sp.RunID = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
			res, err := session.Run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			env := envOf(t, out)
			if env["MODEL_TOKEN"] != link.Placeholder {
				t.Errorf("MODEL_TOKEN is %q, want the placeholder", env["MODEL_TOKEN"])
			}
			bundle := filepath.Join(res.Dir, session.BundleFile)
			want := names
			if want == nil {
				want = wall.DefaultCAEnv
			}
			for _, n := range want {
				if env[n] != bundle {
					t.Errorf("%s is %q, want %q", n, env[n], bundle)
				}
			}
			b, err := os.ReadFile(bundle)
			if err != nil || string(b) != machineRoots+"\n"+authority {
				t.Errorf("the bundle %q, %v", b, err)
			}
		})
	}
}

// TestAnUnwalledRunWithoutABundleDoesNotStart pins a run without a wall that has an
// authority, on a machine with none of the files Forager reads authorities from: no
// run, with the text that says which file to install.
func TestAnUnwalledRunWithoutABundleDoesNotStart(t *testing.T) {
	defer session.SetMachineBundles([]string{filepath.Join(t.TempDir(), "none.pem"), t.TempDir()})()
	sp, g := specGateway(t, "FAKE_EXIT=0")
	credentialAnswer(g)
	_, err := session.Run(context.Background(), sp)
	const want = "install a CA bundle at /etc/ssl/cert.pem or /etc/ssl/certs/ca-certificates.crt: the run's tools trust the gateway for the credentials' hosts only through a bundle, and this machine has none of the files Forager reads"
	if err == nil || err.Error() != want {
		t.Errorf("%v, want %q", err, want)
	}
}

// attached is a runtime that keeps the Attach its Prepare receives.
type attached struct {
	runtimes.Runtime
	got runtimes.Attach
}

func (a *attached) Prepare(at runtimes.Attach) (runtimes.Launch, error) {
	a.got = at
	return a.Runtime.Prepare(at)
}

// TestPrepareIsGivenTheStandInsOfAWalledRun pins what a runtime learns of the stand-ins,
// with or without a wall: the variables the agent gets a stand-in in, the placeholders
// of the gateway's run answer, a credential's and a tool's, and whether the run is
// walled.
func TestPrepareIsGivenTheStandInsOfAWalledRun(t *testing.T) {
	for _, walled := range []bool{true, false} {
		sp, g := specGateway(t, "FAKE_EXIT=0")
		g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
			a := linktest.RunAnswer(req)
			a["placeholders"] = []string{"MODEL_TOKEN", "FILES_KEY"}
			return linktest.Reply{Status: 200, Body: a}
		})
		if walled {
			sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
		}
		rt := &attached{Runtime: sp.Runtime}
		sp.Runtime = rt
		if _, err := runWithSettingsEnv(t, sp); err != nil {
			t.Fatal(err)
		}
		want := []string{"MODEL_TOKEN", "FILES_KEY"}
		if !slices.Equal(rt.got.Placeholders, want) || rt.got.RunDir == "" || rt.got.Walled != walled {
			t.Errorf("walled %v: Prepare received %v, want %v", walled, rt.got.Placeholders, want)
		}
	}
}
