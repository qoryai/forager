package session_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
)

// The tests of this file start a run's stack proxy, the forwarder on loopback that qory
// fetches the harness definition through before the run's first session joins.

// stackAfterJoin is StackProxy's refusal once a Join of the run has reached its join
// request.
const stackAfterJoin = "Call StackProxy before the run's first Join: the gateway closes the stack proxy at the first join request."

// stackBusy is StackProxy's refusal while another call of the run takes the joining
// lock before any join request.
const stackBusy = "Call StackProxy after the run's other call returns: another call of the run is running."

// TestTheStackProxyReachesTheRunsStackProxy pins the stack proxy of a run on one
// machine, walled or not, and behind a separate gateway: its URL is a port on loopback
// with a password, its Env points the proxy variables at that URL and sets no bundle,
// CABundle is empty, a request with the password reaches the gateway's proxy on a
// connection opened with the run's stack proxy secret or with QORY-STACK and the run
// key, a request without it is closed unanswered, and the password is in no file of the
// run directory, no request to the link and no report.
func TestTheStackProxyReachesTheRunsStackProxy(t *testing.T) {
	for _, c := range []struct {
		name             string
		walled, separate bool
	}{{name: "one machine"}, {name: "one machine, walled", walled: true}, {name: "separate gateway", separate: true}} {
		t.Run(c.name, func(t *testing.T) {
			sp, g := specGateway(t)
			preamble := link.RelayPreamble + " " + linktest.StackProxySecret
			if c.separate {
				g = startRemote(t)
				g.SetInterval(30)
				key := g.RunKey(t, event.NewRunID())
				sp.Gateway = remoteGateway(g, key)
				preamble = link.StackPreamble + " " + key
			}
			if c.walled {
				sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			}
			reports := reportsOf(t, &sp)
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			h, err := r.StackProxy()
			if err != nil {
				t.Fatal(err)
			}
			password, addr := hostParts(t, h)
			if !slices.Equal(h.Env, link.ProxyEnv(h.ProxyURL)) {
				t.Errorf("Env is %q, want the proxy variables of %s alone", h.Env, h.ProxyURL)
			}
			if h.CABundle != "" {
				t.Errorf("CABundle is %q", h.CABundle)
			}
			if status, body := throughHost(t, h.ProxyURL, "http://git.example/stack"); status != http.StatusOK || body != "ok" {
				t.Errorf("the request through the stack proxy got %d %q", status, body)
			}
			if got := stray(addr); got != "closed unanswered\nclosed unanswered\n" {
				t.Errorf("the stack proxy took a connection without its password:\n%s", got)
			}
			if got := g.Preambles(); !slices.Equal(got, []string{preamble}) {
				t.Errorf("the gateway's proxy saw %q, want %q", got, preamble)
			}
			if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
				t.Fatal(err)
			}
			refused(t, addr, "after the run's close")
			noSecretIn(t, password, r.Dir(), g, reports())
			noSecretIn(t, linktest.StackProxySecret, r.Dir(), g, reports())
		})
	}
}

// TestTheStackProxyEndsAtTheFirstJoin pins the ends of a stack proxy: its port takes no
// connection once the first Join sends its join request, StackProxy is refused from then
// on, after a Join that failed too, and on a closed run.
func TestTheStackProxyEndsAtTheFirstJoin(t *testing.T) {
	ctx := context.Background()
	sp, g := specGateway(t, "FAKE_EXIT=0")
	var addr string
	dialed := make(chan error, 1)
	g.OnJoin(func(linktest.Join) linktest.Reply {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
		}
		dialed <- err
		return linktest.Reply{Status: 200, Body: map[string]any{"version": 1, "session": 1}}
	})
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	h, err := r.StackProxy()
	if err != nil {
		t.Fatal(err)
	}
	_, addr = hostParts(t, h)
	res, err := r.Join(ctx, sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-dialed; err == nil {
		t.Error("the stack proxy took a connection when the join request reached the gateway")
	}
	if _, err := r.StackProxy(); err == nil || err.Error() != stackAfterJoin {
		t.Errorf("StackProxy after the join: %v, want %q", err, stackAfterJoin)
	}
	if _, err := r.HostProxy(); err != nil {
		t.Errorf("HostProxy after the join: %v", err)
	}
	if _, err := r.Close(ctx, outcomeOf(res, nil)); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Errorf("HostProxy.Close of the stack proxy after the join: %v", err)
	}
	const closed = "Open another run: this run is closed."
	if _, err := r.StackProxy(); err == nil || err.Error() != closed {
		t.Errorf("StackProxy of a closed run: %v, want %q", err, closed)
	}

	// A join the gateway refuses was a join request all the same.
	sp, g = specGateway(t, "FAKE_EXIT=0")
	g.OnJoin(func(linktest.Join) linktest.Reply {
		return linktest.Reply{Status: http.StatusForbidden, Body: linktest.Refusal("placeholder_conflict", "gateway", "HOME")}
	})
	r, err = session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateFailed})
	if _, err := r.Join(ctx, sp.SessionSpec); err == nil {
		t.Fatal("the refused join returned no error")
	}
	if _, err := r.StackProxy(); err == nil || err.Error() != stackAfterJoin {
		t.Errorf("StackProxy after a refused join: %v, want %q", err, stackAfterJoin)
	}
}

// TestTheStackProxyWaitsForTheRunsOtherCall pins StackProxy's refusal while another
// call of the run takes the joining lock before any join request, and that it starts
// once the call returns.
func TestTheStackProxyWaitsForTheRunsOtherCall(t *testing.T) {
	ctx := context.Background()
	sp, _ := specGateway(t, "FAKE_EXIT=0")
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateFailed})
	giveBack := session.HoldJoining(r)
	_, err = r.StackProxy()
	giveBack()
	if err == nil || err.Error() != stackBusy {
		t.Errorf("StackProxy while another call runs: %v, want %q", err, stackBusy)
	}
	h, err := r.StackProxy()
	if err != nil {
		t.Fatalf("StackProxy once the other call returned: %v", err)
	}
	h.Close()
}

// TestTheStackProxyDuringTheFirstJoin pins StackProxy's refusal while the run's first
// Join runs, past its join request: the gateway has closed the stack proxy.
func TestTheStackProxyDuringTheFirstJoin(t *testing.T) {
	ctx := context.Background()
	sp, g := specGateway(t, "FAKE_EXIT=0")
	runs := make(chan *session.Run, 1)
	during := make(chan error, 1)
	g.OnJoin(func(linktest.Join) linktest.Reply {
		_, err := (<-runs).StackProxy()
		during <- err
		return linktest.Reply{Status: 200, Body: map[string]any{"version": 1, "session": 1}}
	})
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	runs <- r
	res, err := r.Join(ctx, sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, outcomeOf(res, nil))
	if err := <-during; err == nil || err.Error() != stackAfterJoin {
		t.Errorf("StackProxy during the first join: %v, want %q", err, stackAfterJoin)
	}
}

// TestARunAnswerWithoutAStackProxySecretIsNoRun pins the session's check of the run
// answer on the local link: one without stack_proxy_secret opens no run, as one without
// proxy_secret does, and one whose stack_proxy_secret the schema refuses opens none
// either.
func TestARunAnswerWithoutAStackProxySecretIsNoRun(t *testing.T) {
	for _, c := range []struct {
		secret any
		want   string
	}{
		{nil, "Use a gateway that sends stack_proxy_secret on its local link: the run answer's stack_proxy_secret is missing or malformed: link: a preamble's secret is 1 to 256 printable characters other than a space"},
		{"a secret with spaces", "the run request at the gateway: link-run-answer.schema.json refuses /stack_proxy_secret (pattern)"},
	} {
		secret := c.secret
		t.Run(fmt.Sprint(secret), func(t *testing.T) {
			sp, g := specGateway(t)
			g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
				a := linktest.RunAnswer(req)
				if secret == nil {
					delete(a, "stack_proxy_secret")
				} else {
					a["stack_proxy_secret"] = secret
				}
				return linktest.Reply{Status: 200, Body: a}
			})
			if _, err := session.Open(context.Background(), opened(sp)); err == nil || err.Error() != c.want {
				t.Errorf("Open: %v, want %q", err, c.want)
			}
		})
	}
}

// TestTheStackProxySecretStaysOutOfTheWall pins where the stack proxy secret goes in a
// walled run with a setup and a session: into no request to the wall, no launch of the
// setup container or the agent, and no file of the run directory.
func TestTheStackProxySecretStaysOutOfTheWall(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	reports := reportsOf(t, &sp)
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	h, err := r.StackProxy()
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := throughHost(t, h.ProxyURL, "http://git.example/stack"); status != http.StatusOK {
		t.Errorf("the request through the stack proxy got %d", status)
	}
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	seen := fmt.Sprintf("%#v\n%#v\n%#v", w.req, w.setup, w.got)
	w.mu.Unlock()
	if w.setup.ProxyToken != linktest.ProxySecret || w.got.Proxy == "" {
		t.Errorf("the setup container's token %q, the agent's proxy %q", w.setup.ProxyToken, w.got.Proxy)
	}
	if strings.Contains(seen, linktest.StackProxySecret) {
		t.Errorf("the wall received the stack proxy secret:\n%s", seen)
	}
	noSecretIn(t, linktest.StackProxySecret, r.Dir(), g, reports())
}

// TestTheStackFetchThroughARealGateway is the stack fetch end to end on one machine: a
// real session's stack proxy reaches a host of gateway.stack_hosts that the run's policy
// denies, a host outside gateway.stack_hosts gets the gateway's 403, each decision is a
// line of the gateway's report and none a dev.qory.run.egress, and from the first Join
// on the stack proxy secret opens nothing, a connection opened before the join among
// it, while the run's proxy secret still opens the run's proxy.
func TestTheStackFetchThroughARealGateway(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "harness") }))
	defer origin.Close()
	originHost, originPort, _ := net.SplitHostPort(origin.Listener.Addr().String())
	sp := spec(t, "FAKE_EXIT=0")
	rg := startGateway(t, &sp, gateway.Config{Version: "test", Heartbeat: time.Second, StackHosts: []string{originHost},
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example"}}}})
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	h, err := r.StackProxy()
	if err != nil {
		t.Fatal(err)
	}
	if status, body := throughHost(t, h.ProxyURL, origin.URL); status != http.StatusOK || body != "harness" {
		t.Errorf("the fetch of a stack host got %d %q", status, body)
	}
	status, body := throughHost(t, h.ProxyURL, "http://other.example.net/")
	const refusedBody = "qory: add other.example.net to stack_hosts in forager.yaml or in the run configuration.\n" +
		"qory: egress to other.example.net:80 denied by the gateway: the host is in neither stack_hosts list\n"
	if status != http.StatusForbidden || body != refusedBody {
		t.Errorf("another host got %d %q, want 403 %q", status, body, refusedBody)
	}
	// A tunnel through the stack proxy, opened before the join.
	password, addr := hostParts(t, h)
	tunnel, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	fmt.Fprintf(tunnel, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", origin.Listener.Addr(), origin.Listener.Addr(), base64.StdEncoding.EncodeToString([]byte("qory:"+password)))
	tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	head := make([]byte, len("HTTP/1.1 200"))
	if _, err := io.ReadFull(tunnel, head); err != nil || string(head) != "HTTP/1.1 200" {
		t.Fatalf("the tunnel's answer %q: %v", head, err)
	}
	res, err := r.Join(ctx, sp.SessionSpec)
	if err != nil {
		t.Fatal(err)
	}
	tunnel.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(tunnel); err != nil {
		t.Errorf("the tunnel opened before the join is still open: %v", err)
	}
	if _, err := r.Close(ctx, outcomeOf(res, nil)); err != nil {
		t.Fatal(err)
	}
	rg.close(t)
	runID := res.RunID
	want := []string{
		fmt.Sprintf("run %s: stack fetch to %s:%s allowed by gateway.stack_hosts entry %s", runID, originHost, originPort, originHost),
		fmt.Sprintf("run %s: stack fetch to other.example.net:80 denied: the host is in neither stack_hosts list", runID),
		fmt.Sprintf("run %s: stack fetch to %s:%s allowed by gateway.stack_hosts entry %s", runID, originHost, originPort, originHost),
	}
	rg.mu.Lock()
	var lines []string
	for _, l := range rg.reports {
		if strings.Contains(l, "stack fetch") {
			lines = append(lines, l)
		}
	}
	rg.mu.Unlock()
	if !slices.Equal(lines, want) {
		t.Errorf("the gateway reported\n%q\nwant\n%q", lines, want)
	}
	for _, e := range ofType(record(t, res), event.RunEgress) {
		if d := data(e); d["host"] == originHost || d["host"] == "other.example.net" {
			t.Errorf("the record has a dev.qory.run.egress of the stack fetch: %v", d)
		}
	}
}
