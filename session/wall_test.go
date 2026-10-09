package session_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
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
// sends, which opens with it, so the proxy sees the preamble once either way; and the
// agent's environment and the session's record never hold the secret.
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
			if !walled && !bytes.Contains(env, []byte("HTTP_PROXY=http://127.0.0.1:")) {
				t.Errorf("the agent's environment has no proxy on loopback:\n%s", env)
			}
		})
	}
}

// authority is a certificate in the form the run answer carries one, PEM.
const authority = "-----BEGIN CERTIFICATE-----\nMIIBexampleAAAA\n-----END CERTIFICATE-----\n"

// TestTheAnswerCrossesAsAnAuthorityAndAPlaceholder pins what a wall is given of the
// run answer of a run whose gateway holds a credential: the run authority's
// certificate and a placeholder in place of the credential, and what the record says
// of it, the members of policy_applied the gateway decides as it gives them. Without
// a wall the session sets neither.
func TestTheAnswerCrossesAsAnAuthorityAndAPlaceholder(t *testing.T) {
	members := map[string]any{"mode": "enforce", "allow": []string{"api.model.example"}, "deny": []string{}, "source": "config", "digest": strings.Repeat("a", 64),
		"credentials": []any{map[string]any{"name": "model", "hosts": []string{"api.model.example"}, "scheme": "bearer"}}, "terminated": []string{"api.model.example"}}
	answer := func(g *linktest.Fake) {
		g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
			a := linktest.RunAnswer(req)
			a["policy"] = map[string]any{"version": 1, "egress": map[string]any{"mode": "enforce", "allow": []string{"api.model.example"}}, "credentials": []any{map[string]any{"name": "model"}}}
			a["digest"], a["applied"], a["placeholders"] = strings.Repeat("a", 64), members, []string{"MODEL_TOKEN"}
			if req.Wall {
				a["certificate_authority"] = authority
			}
			return linktest.Reply{Status: 200, Body: a}
		})
	}
	w := &openWall{}
	sp, g := specGateway(t, "FAKE_EXIT=0")
	answer(g)
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

	sp, g = specGateway(t, "FAKE_EXIT=0")
	answer(g)
	out := dumpsEnv(t, &sp)
	if _, err := session.Run(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	if env := envOf(t, out); env["MODEL_TOKEN"] != "" {
		t.Errorf("an unwalled run set the placeholder: %q", env["MODEL_TOKEN"])
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

// TestPrepareIsGivenTheStandInsOfAWalledRun pins what a runtime learns of the stand-ins:
// behind a wall, the variables the enclosure gets a stand-in in, the placeholders of
// the gateway's run answer, a credential's and a tool's; without one, none.
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
		var want []string
		if walled {
			want = []string{"MODEL_TOKEN", "FILES_KEY"}
		}
		if !slices.Equal(rt.got.Placeholders, want) || rt.got.RunDir == "" {
			t.Errorf("walled %v: Prepare received %v, want %v", walled, rt.got.Placeholders, want)
		}
	}
}
