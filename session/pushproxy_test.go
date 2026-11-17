package session_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// The tests of this file start a run's push proxy forwarder, the forwarder on loopback
// that qory pushes and calls its submit step through.

// The texts PushProxy returns for a run with no push credential and during a Join.
const (
	noPushProxy = "Add a push credential to the run configuration: this run has no push proxy."
	pushBusy    = "Call PushProxy after Join returns: a session of the run is still running."
)

// withPush makes g return, for each run request, a run answer of a run with a push
// credential ([linktest.WithPush]).
func withPush(g *linktest.Fake, local bool) {
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RemoteRunAnswer(req)
		if local {
			a = linktest.RunAnswer(req)
		}
		return linktest.Reply{Status: 200, Body: linktest.WithPush(a, local)}
	})
}

// TestThePushProxyReachesTheRunsPushProxy pins the push proxy forwarder of a run with a
// push credential, on one machine, walled or not, and behind a separate gateway, after a
// session: its URL is a port on loopback with a password, its Env points the proxy
// variables at that URL, a request with the password reaches the gateway's proxy on a
// connection opened with the run answer's push_proxy_secret or with QORY-PUSH and the
// run key, a request without it is closed unanswered, and the password and the push
// proxy secret are in no file of the run directory, no request to the link and no
// report. Before PushProxy, no connection opens with the push proxy secret or with
// QORY-PUSH.
func TestThePushProxyReachesTheRunsPushProxy(t *testing.T) {
	for _, c := range []struct {
		name             string
		walled, separate bool
	}{{name: "one machine"}, {name: "one machine, walled", walled: true}, {name: "separate gateway", separate: true}} {
		t.Run(c.name, func(t *testing.T) {
			sp, g := specGateway(t, "FAKE_EXIT=0")
			preamble := link.RelayPreamble + " " + linktest.PushProxySecret
			if c.separate {
				g = startRemote(t)
				g.SetInterval(30)
				key := g.RunKey(t, event.NewRunID())
				sp.Gateway = remoteGateway(g, key)
				preamble = link.PushPreamble + " " + key
			}
			withPush(g, !c.separate)
			if c.walled {
				// A wall with Unwrap, which removes the agent's container as the session
				// ends: PushProxy waits while a container that can write the binds runs.
				sp.Wall, sp.Image = &afterWall{}, "example.com/agent:1"
			}
			reports := reportsOf(t, &sp)
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			res, err := r.Join(ctx, sp.SessionSpec)
			if err != nil {
				t.Fatal(err)
			}
			if got := g.Preambles(); slices.Contains(got, preamble) {
				t.Errorf("a connection opened with the push proxy's preamble before PushProxy: %q", got)
			}
			h, err := r.PushProxy()
			if err != nil {
				t.Fatal(err)
			}
			password, addr := hostParts(t, h)
			if !slices.Equal(h.Env, link.ProxyEnv(h.ProxyURL)) {
				t.Errorf("Env is %q, want the proxy variables of %s alone", h.Env, h.ProxyURL)
			}
			if status, body := throughHost(t, h.ProxyURL, "http://git.example/example-org/app.git/info/refs"); status != http.StatusOK || body != "ok" {
				t.Errorf("the request through the push proxy got %d %q", status, body)
			}
			if got := stray(addr); got != "closed unanswered\nclosed unanswered\n" {
				t.Errorf("the push proxy took a connection without its password:\n%s", got)
			}
			if got := g.Preambles(); !slices.Contains(got, preamble) || slices.Index(got, preamble) != len(got)-1 {
				t.Errorf("the gateway's proxy saw %q, want %q last", got, preamble)
			}
			if _, err := r.Close(ctx, outcomeOf(res, nil)); err != nil {
				t.Fatal(err)
			}
			refused(t, addr, "after the run's close")
			noSecretIn(t, password, r.Dir(), g, reports())
			noSecretIn(t, linktest.PushProxySecret, r.Dir(), g, reports())
		})
	}
}

// TestARunWithoutAPushCredentialHasNoPushProxy pins PushProxy of a run whose open lists
// no push credential, on one machine and behind a separate gateway, as a write-no-push
// run's: it returns the text that starts with the fix, and opens no connection to the
// gateway's proxy.
func TestARunWithoutAPushCredentialHasNoPushProxy(t *testing.T) {
	for _, separate := range []bool{false, true} {
		t.Run(fmt.Sprint("separate ", separate), func(t *testing.T) {
			sp, g := specGateway(t)
			if separate {
				g = startRemote(t)
				g.SetInterval(30)
				sp.Gateway = remoteGateway(g, g.RunKey(t, event.NewRunID()))
			}
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
			if _, err := r.PushProxy(); err == nil || err.Error() != noPushProxy {
				t.Errorf("PushProxy: %v, want %q", err, noPushProxy)
			}
			if got := g.Preambles(); len(got) != 0 {
				t.Errorf("the gateway's proxy saw %q", got)
			}
		})
	}
}

// TestThePushProxyEnds pins when PushProxy returns an error and when its forwarder
// ends: an error during a Join and during a copy step; the forwarder ends at the next
// Join, before its join request reaches the gateway, and at the run's close, after which
// PushProxy returns an error. A PushProxy after the next Join starts again.
func TestThePushProxyEnds(t *testing.T) {
	ctx := context.Background()
	t.Run("Join", func(t *testing.T) {
		sp, g := specGateway(t, "FAKE_EXIT=0")
		withPush(g, true)
		var addr string
		var r *session.Run
		dialed := make(chan error, 1)
		during := make(chan error, 1)
		g.OnJoin(func(linktest.Join) linktest.Reply {
			c, err := net.Dial("tcp", addr)
			if err == nil {
				c.Close()
			}
			dialed <- err
			_, err = r.PushProxy()
			during <- err
			return linktest.Reply{Status: 200, Body: map[string]any{"version": 1, "session": 1}}
		})
		var err error
		r, err = session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		h, err := r.PushProxy()
		if err != nil {
			t.Fatal(err)
		}
		_, addr = hostParts(t, h)
		res, err := r.Join(ctx, sp.SessionSpec)
		if err != nil {
			t.Fatal(err)
		}
		if err := <-dialed; err == nil {
			t.Error("the push proxy took a connection when the join request reached the gateway")
		}
		if err := <-during; err == nil || err.Error() != pushBusy {
			t.Errorf("PushProxy during the Join: %v, want %q", err, pushBusy)
		}
		again, err := r.PushProxy()
		if err != nil {
			t.Fatalf("PushProxy after the Join: %v", err)
		}
		if status, _ := throughHost(t, again.ProxyURL, "http://git.example/example-org/app.git/info/refs"); status != http.StatusOK {
			t.Errorf("the request through the push proxy after the Join got %d", status)
		}
		if _, err := r.Close(ctx, outcomeOf(res, nil)); err != nil {
			t.Fatal(err)
		}
		_, againAddr := hostParts(t, again)
		refused(t, againAddr, "after the run's close")
		if _, err := r.PushProxy(); err == nil || err.Error() != "Open another run: this run is closed." {
			t.Errorf("PushProxy of a closed run: %v", err)
		}
	})
	t.Run("copy step", func(t *testing.T) {
		sp, g := specGateway(t)
		withPush(g, true)
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
		s, err := r.StartStep(event.StepCopy, "copy the work")
		if err != nil {
			t.Fatal(err)
		}
		const want = "Exit the copy step before you start the push proxy: a join during it closes the push proxy.\nThe copy step is step 1."
		if _, err := r.PushProxy(); err == nil || err.Error() != want {
			t.Errorf("PushProxy during a copy step: %v, want %q", err, want)
		}
		if err := s.Exit(event.StateSucceeded, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := r.PushProxy(); err != nil {
			t.Errorf("PushProxy after the copy step: %v", err)
		}
	})
}

// TestTheWallReachesNoPushProxy pins the split of a walled run with a push credential,
// with a setup step, a session and After, on one machine and behind a separate gateway:
// the push proxy secret and the run key are in no request to the wall and no launch of
// the setup container, the agent's container or After's container; what the wall's
// relay sends, with the relay's token, reaches the gateway's proxy with QORY-RELAY and
// the run's proxy secret or run key, never with the push proxy's preamble; and a
// connection to the run's forwarder that opens with the push proxy's preamble is closed
// unanswered and reaches nothing.
func TestTheWallReachesNoPushProxy(t *testing.T) {
	for _, separate := range []bool{false, true} {
		t.Run(fmt.Sprint("separate ", separate), func(t *testing.T) {
			sp, g := specGateway(t)
			aw := &afterWall{}
			sp.Mounts, sp.Forwarder, sp.SetupRunner = []wall.Mount{{Path: sp.Dir}}, nil, setupRunner
			sp.Command, sp.Args = installedShell, []string{"-c", "exit 0"}
			sp.After, sp.AfterTimeout = []string{"/bin/sh", "-c", "exit 0"}, 10*time.Second
			relayed := link.RelayPreamble + " " + linktest.ProxySecret
			pushLine, secret := link.RelayLine(linktest.PushProxySecret), linktest.PushProxySecret
			if separate {
				g = startRemote(t)
				g.SetInterval(30)
				key := g.RunKey(t, event.NewRunID())
				sp.Gateway = remoteGateway(g, key)
				relayed, pushLine, secret = link.RelayPreamble+" "+key, link.PushLine(key), key
			}
			withPush(g, !separate)
			w := &setupAfterWall{aw: aw}
			sp.Wall, sp.Image = w, "example.com/agent:1"
			reports := reportsOf(t, &sp)
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
				t.Fatal(err)
			}
			addr, token := r.WallProxy()
			if got := relayLine(t, addr, link.RelayLine(token)+"GET http://git.example/example-org/app.git/info/refs HTTP/1.1\r\nHost: git.example\r\nConnection: close\r\n\r\n"); !strings.HasPrefix(got, "HTTP/1.1 200") {
				t.Errorf("the relay's request got %q", got)
			}
			if got := relayLine(t, addr, pushLine+"GET http://git.example/example-org/app.git/info/refs HTTP/1.1\r\nHost: git.example\r\nConnection: close\r\n\r\n"); got != "" {
				t.Errorf("a connection with the push proxy's preamble got %q", got)
			}
			res, err := r.Join(ctx, sp.SessionSpec)
			if err != nil {
				t.Fatal(err)
			}
			if res.After == nil || res.After.State != event.StateSucceeded {
				t.Fatalf("Result.After %+v; want succeeded", res.After)
			}
			if got := g.Preambles(); len(got) == 0 || slices.ContainsFunc(got, func(p string) bool { return p != relayed }) {
				t.Errorf("the gateway's proxy saw %q, want %q alone", got, relayed)
			}
			w.mu.Lock()
			aw.mu.Lock()
			launches := map[string]wall.Launch{"the setup container": w.setup, "the agent's container": w.got, "After's container": aw.after}
			seen := fmt.Sprintf("%#v", w.req)
			aw.mu.Unlock()
			w.mu.Unlock()
			if strings.Contains(seen, secret) {
				t.Errorf("the wall's request contains the push proxy's secret or the run key:\n%s", seen)
			}
			for name, l := range launches {
				if reflect.DeepEqual(l, wall.Launch{}) {
					t.Errorf("%s did not start", name)
				}
				if s := fmt.Sprintf("%#v", l); strings.Contains(s, secret) || strings.Contains(s, linktest.PushProxySecret) {
					t.Errorf("the launch of %s contains the push proxy's secret or the run key:\n%s", name, s)
				}
			}
			if _, err := r.Close(ctx, outcomeOf(res, nil)); err != nil {
				t.Fatal(err)
			}
			noSecretIn(t, linktest.PushProxySecret, r.Dir(), g, reports())
		})
	}
}

// relayLine writes what a wall's relay writes to the run's forwarder at addr and
// returns the first line of the answer, empty when the forwarder closes the connection
// unanswered.
func relayLine(t *testing.T, addr, sent string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, sent); err != nil {
		return ""
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	return line
}

// TestARunAnswerWithAMalformedPushProxySecretIsNoRun pins a run answer on the local link
// whose push_proxy_secret is no secret a preamble can contain: the run does not open.
func TestARunAnswerWithAMalformedPushProxySecretIsNoRun(t *testing.T) {
	sp, g := specGateway(t)
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.WithPush(linktest.RunAnswer(req), true)
		a["push_proxy_secret"] = "a secret with spaces"
		return linktest.Reply{Status: 200, Body: a}
	})
	const want = "the run request at the gateway: link-run-answer.schema.json refuses /push_proxy_secret (pattern)"
	if _, err := session.Open(context.Background(), opened(sp)); err == nil || err.Error() != want {
		t.Errorf("Open: %v, want %q", err, want)
	}
}

// TestThePushProxysPasswordIsMasked pins the push proxy forwarder's password in the
// caller's masker, as the host proxy's: a line with the push proxy's URL is written with
// the password replaced.
func TestThePushProxysPasswordIsMasked(t *testing.T) {
	sp, g := specGateway(t)
	withPush(g, true)
	m := maskerOf(t, maskValue)
	sp.Masker = m
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	h, err := r.PushProxy()
	if err != nil {
		t.Fatal(err)
	}
	password, _ := hostParts(t, h)
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w := mask.NewWriter(&out, m)
	w.Write([]byte("http://qory:" + password + "@127.0.0.1"))
	w.Flush()
	if want := "http://qory:" + mask.ProxyPassword + "@127.0.0.1"; out.String() != want {
		t.Errorf("the caller's writer wrote %q, want %q", out.String(), want)
	}
}

// TestAJoinsRecordListsThePushCredential pins the session's dev.qory.run.policy_applied
// of a run whose gateway's applied lists a push credential: the open's record and the
// join's both list it, with purpose push, since the push proxy stays open through every
// join.
func TestAJoinsRecordListsThePushCredential(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	withPush(g, true)
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Join(ctx, sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, outcomeOf(res, nil)); err != nil {
		t.Fatal(err)
	}
	push := []any{map[string]any{"name": "push-1", "hosts": []any{"git.example"}, "scheme": "basic", "paths": []any{"/example-org/app.git/*"}, "purpose": "push"}}
	var got []any
	for _, e := range ofType(g.Events(), event.PolicyApplied) {
		got = append(got, data(e)["credentials"])
	}
	if want := []any{push, push}; !reflect.DeepEqual(got, want) {
		t.Errorf("the records' credentials %v, want %v", got, want)
	}
}

// TestThePushProxyWaitsForTheRunsContainers pins PushProxy in a walled run with a
// setup container: while the setup container is up, PushProxy returns the text that
// starts with RemoveSetup; once RemoveSetup removed it, PushProxy starts; and when the
// removal failed, so a container may still write the run's binds (ContainerKept),
// PushProxy returns the text that starts with Close.
func TestThePushProxyWaitsForTheRunsContainers(t *testing.T) {
	const setupUp = "Call RemoveSetup before PushProxy: the setup container can still write the run's binds."
	const kept = "Push after Close returns: a container of the run may still run and write the run's binds."
	for _, c := range []struct {
		name      string
		removeErr error
		after     string
	}{{"removed", nil, ""}, {"kept", errors.New("engine down"), kept}} {
		t.Run(c.name, func(t *testing.T) {
			sp, g := specGateway(t)
			withPush(g, true)
			w := &setupWall{removeErr: c.removeErr}
			sp.Wall, sp.Image = w, "example.com/agent:1"
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
			if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); err != nil {
				t.Fatal(err)
			}
			if _, err := r.PushProxy(); err == nil || err.Error() != setupUp {
				t.Errorf("PushProxy with the setup container up: %v, want %q", err, setupUp)
			}
			r.RemoveSetup(ctx)
			_, err = r.PushProxy()
			switch {
			case c.after == "" && err != nil:
				t.Errorf("PushProxy after RemoveSetup: %v", err)
			case c.after != "" && (err == nil || err.Error() != c.after || !r.ContainerKept()):
				t.Errorf("PushProxy after a failed removal: %v, ContainerKept %v; want %q", err, r.ContainerKept(), c.after)
			}
		})
	}
}

// TestTheHostProxyOfAPushRunReachesTheRunsProxy pins the host proxy of a run with a push
// credential on one machine, before any PushProxy: its request opens with the run's
// proxy secret, and no connection to the gateway's proxy has the push proxy secret.
func TestTheHostProxyOfAPushRunReachesTheRunsProxy(t *testing.T) {
	sp, g := specGateway(t)
	withPush(g, true)
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
	h, err := r.HostProxy()
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := throughHost(t, h.ProxyURL, "http://git.example/example-org/app.git/info/refs"); status != http.StatusOK {
		t.Errorf("the request through the host proxy got %d", status)
	}
	if got, want := g.Preambles(), []string{link.RelayPreamble + " " + linktest.ProxySecret}; !slices.Equal(got, want) {
		t.Errorf("the gateway's proxy saw %q, want %q", got, want)
	}
}
