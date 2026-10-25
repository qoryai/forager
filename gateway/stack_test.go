package gateway_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// The tests of this file pin a run's stack proxy: what qory fetches the harness
// definition through before the run's first session joins.

// stackRefusedBody is the 403 the stack proxy answers for host:port outside
// gateway.stack_hosts and the run configuration's stack_hosts.
func stackRefusedBody(host string, port int) string {
	return "qory: add " + host + " to stack_hosts in forager.yaml or in the run configuration.\n" +
		fmt.Sprintf("qory: egress to %s:%d denied by the gateway: the host is in neither stack_hosts list\n", host, port)
}

// stackNodeBody is the 403 the stack proxy answers for host:port of the run
// configuration's stack_hosts that the node's policy does not allow.
func stackNodeBody(host string, port int) string {
	return "qory: allow " + host + " in the node's policy, or list it in gateway.stack_hosts.\n" +
		fmt.Sprintf("qory: egress to %s:%d denied by the gateway: the node's policy does not allow this host of the run configuration's stack_hosts\n", host, port)
}

// stackPathsBody is the 403 the stack proxy answers for host:port of the run
// configuration's stack_hosts that the node's policy has path rules for.
func stackPathsBody(host string, port int) string {
	return "qory: list " + host + " in gateway.stack_hosts: the node's path rules cover it.\n" +
		fmt.Sprintf("qory: egress to %s:%d denied by the gateway: the node's policy has path rules for this host, which the stack proxy does not check\n", host, port)
}

// stackNeverBody is the body of the 403 a run's guarded stack proxy answers for a
// link-local or cloud metadata address.
func stackNeverBody(host string, port int) string {
	return "qory: fetch the harness definition from another host: the gateway never reaches a link-local or cloud metadata address, and " + host + " is one or resolves to one.\n" +
		fmt.Sprintf("qory: egress to %s:%d denied by the gateway: no entry of gateway.stack_hosts or of the node's policy opens a link-local or cloud metadata address\n", host, port)
}

// stackGuardedBody is the body of the 403 a run's guarded stack proxy answers for this
// machine's address or a private network address.
func stackGuardedBody(host string, port int) string {
	return "qory: to fetch the harness definition from the gateway's machine or a private network address, list " + host + " by name, not a *. pattern, in the allow list of the node's policy and in gateway.stack_hosts in forager.yaml.\n" +
		fmt.Sprintf("qory: egress to %s:%d denied by the gateway: the stack proxy reaches such an address only for a host listed by name in both, and never a link-local or cloud metadata address\n", host, port)
}

// connectThrough sends a CONNECT to target on c, opened and past its preamble, and
// returns the status and, for a refusal, the body; c stays open after a 200.
func connectThrough(t *testing.T, c net.Conn, target string) (int, string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Time{})
	if resp.StatusCode == http.StatusOK {
		return resp.StatusCode, ""
	}
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// closedUnansweredConn fails the test when c, opened with a preamble, gets an answer to
// a request.
func closedUnansweredConn(t *testing.T, c net.Conn, what string) {
	t.Helper()
	defer c.Close()
	io.WriteString(c, "GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(c)
	var ne net.Error
	if len(b) > 0 || (errors.As(err, &ne) && ne.Timeout()) {
		t.Errorf("%s was answered %q, or kept open: %v", what, b, err)
	}
}

// localStack opens a connection to the gateway's proxy with the relay's preamble and
// secret.
func localStack(t *testing.T, h *harness, secret string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", h.g.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c, link.RelayLine(secret)); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestStartRefusesAStackHostOfAnotherForm pins Start's check of StackHosts: a
// lower-case host name, a *. suffix and an IPv4 address start, and any other entry is
// refused with the fix first, the entry's index and the entry as given.
func TestStartRefusesAStackHostOfAnotherForm(t *testing.T) {
	start(t, gateway.Config{StackHosts: []string{"git.example.com", "*.example.org", "10.0.0.1"}})
	for _, c := range []struct {
		hosts []string
		want  string
	}{
		{[]string{"git.example.com", "Git.Example.com:443"}, `Set StackHosts[1] to a lower-case host name, an IPv4 address or a *. suffix, such as git.example.com. It is "Git.Example.com:443".`},
		{[]string{"https://git.example.com"}, `Set StackHosts[0] to a lower-case host name, an IPv4 address or a *. suffix, such as git.example.com. It is "https://git.example.com".`},
		{[]string{"*"}, `Set StackHosts[0] to a lower-case host name, an IPv4 address or a *. suffix, such as git.example.com. It is "*".`},
		{[]string{"1.2.3"}, `Set StackHosts[0] to a lower-case host name, an IPv4 address or a *. suffix, such as git.example.com. It is "1.2.3".`},
		{[]string{""}, `Set StackHosts[0] to a lower-case host name, an IPv4 address or a *. suffix, such as git.example.com. It is "".`},
	} {
		_, err := gateway.Start(context.Background(), gateway.Config{Dir: t.TempDir(), StackHosts: c.hosts})
		if err == nil || err.Error() != c.want {
			t.Errorf("StackHosts %q: %v, want %q", c.hosts, err, c.want)
		}
	}
}

// TestTheStackProxyOnOneMachine pins a run's stack proxy on the local link: the run
// answer's stack_proxy_secret is another secret than proxy_secret; a connection opened
// with it reaches a host of StackHosts that the run's policy denies, and is refused
// another host with the stack proxy's 403; each decision is one line of the gateway's
// report and a dev.qory.run.egress with channel stack, which the run's proxy's have
// not; from the run's first join request on, the secret
// opens nothing, a tunnel opened before it is closed, and the run's proxy secret still
// opens the run's proxy.
func TestTheStackProxyOnOneMachine(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "harness") }))
	defer origin.Close()
	target := origin.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(target)
	h := start(t, gateway.Config{StackHosts: []string{"127.0.0.1"},
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example"}}}})
	a := h.open(server.LinkRunRequest{})
	if len(a.StackProxySecret) < 22 || a.StackProxySecret == a.ProxySecret {
		t.Fatalf("the stack proxy secret is %d characters, or the proxy secret", len(a.StackProxySecret))
	}
	for _, shown := range []string{fmt.Sprintf("%v", *a), fmt.Sprintf("%#v", *a)} {
		if strings.Contains(shown, a.StackProxySecret) {
			t.Errorf("the run answer prints its stack proxy secret: %s", shown)
		}
	}
	stack := relay(h.g.Addr(), a.StackProxySecret)
	resp, err := stack.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(b) != "harness" {
		t.Errorf("the stack host: %d %q", resp.StatusCode, b)
	}
	if status, body := connectThrough(t, localStack(t, h, a.StackProxySecret), "other.example.net:443"); status != http.StatusForbidden || body != stackRefusedBody("other.example.net", 443) {
		t.Errorf("another host: %d %q", status, body)
	}
	resp, err = stack.Get("http://other.example.net/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || string(b) != stackRefusedBody("other.example.net", 80) {
		t.Errorf("another host over plain HTTP: %d %q", resp.StatusCode, b)
	}
	// The run's proxy decides by the run's policy, which denies the stack host.
	resp, err = relay(h.g.Addr(), a.ProxySecret).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("the run's proxy to the stack host: %d", resp.StatusCode)
	}
	held := localStack(t, h, a.StackProxySecret)
	defer held.Close()
	if status, _ := connectThrough(t, held, target); status != http.StatusOK {
		t.Fatalf("the tunnel before the join: %d", status)
	}
	h.post(started(a.RunID, nil), applied(a.RunID, a.Applied))
	h.joined(a.RunID)
	held.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(held); err != nil {
		t.Errorf("the tunnel opened before the join is still open: %v", err)
	}
	refused := len(h.reportsWith(proxy.RefusedRelay))
	closedUnansweredConn(t, localStack(t, h, a.StackProxySecret), "the stack proxy secret after the join")
	// The secret is unregistered, so the listener refuses it as a secret no run has.
	deadline := time.Now().Add(5 * time.Second)
	for len(h.reportsWith(proxy.RefusedRelay)) == refused && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(h.reportsWith(proxy.RefusedRelay)) == refused {
		t.Errorf("the stack proxy secret after the join was not refused as no run's: %q", h.reportsWith(proxy.RefusedRelay))
	}
	resp, err = relay(h.g.Addr(), a.ProxySecret).Get("http://api.example/")
	if err != nil {
		t.Fatalf("the run's proxy after the join: %v", err)
	}
	resp.Body.Close()
	h.post(sessionStarted(a.RunID, 1), sessionExited(a.RunID, 1), exited(a.RunID))
	h.close()
	want := []string{
		fmt.Sprintf("run %s: stack fetch to 127.0.0.1:%s allowed by gateway.stack_hosts entry 127.0.0.1", a.RunID, port),
		fmt.Sprintf("run %s: stack fetch to other.example.net:443 denied: the host is in neither stack_hosts list", a.RunID),
		fmt.Sprintf("run %s: stack fetch to other.example.net:80 denied: the host is in neither stack_hosts list", a.RunID),
		fmt.Sprintf("run %s: stack fetch to 127.0.0.1:%s allowed by gateway.stack_hosts entry 127.0.0.1", a.RunID, port),
	}
	if got := h.reportsWith("stack fetch"); !slices.Equal(got, want) {
		t.Errorf("reported\n%q\nwant\n%q", got, want)
	}
	var egress []string
	for _, l := range h.record(a.RunID) {
		if l.Type == event.RunEgress {
			egress = append(egress, fmt.Sprint(l.Data["host"], " ", l.Data["decision"], " ", l.Data["channel"]))
		}
	}
	want = []string{"127.0.0.1 allowed stack", "other.example.net denied stack", "other.example.net denied stack", "127.0.0.1 denied <nil>",
		"127.0.0.1 allowed stack", "api.example allowed <nil>"}
	if !slices.Equal(egress, want) {
		t.Errorf("the record's dev.qory.run.egress %q, want %q", egress, want)
	}
}

// TestTheStackProxyIsGuardedBehindAWall pins the guard of a walled run's stack proxy:
// this machine's address by number and by name, and the cloud metadata address, are
// refused even when StackHosts lists them, the metadata address with the body that
// sends the fetch to another host and the others with the body that lists the host in
// both lists; nothing is dialled for them, and each refusal is a line of the gateway's
// report.
func TestTheStackProxyIsGuardedBehindAWall(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the guarded stack proxy reached this machine: %s", r.URL)
	}))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	h := start(t, gateway.Config{StackHosts: []string{"127.0.0.1", "169.254.169.254", "localhost"}})
	a := h.open(server.LinkRunRequest{Wall: true})
	for _, target := range []string{"127.0.0.1:" + port, "169.254.169.254:80", "localhost:" + port} {
		host, p, _ := net.SplitHostPort(target)
		n, _ := strconv.Atoi(p)
		want := stackGuardedBody(host, n)
		if host == "169.254.169.254" {
			want = stackNeverBody(host, n)
		}
		status, body := connectThrough(t, localStack(t, h, a.StackProxySecret), target)
		if status != http.StatusForbidden || body != want {
			t.Errorf("%s: %d %q, want %q", target, status, body, want)
		}
	}
	h.close()
	for _, line := range []string{
		"stack fetch to 127.0.0.1:" + port + " denied by the gateway's rule wall:own-address",
		"stack fetch to 169.254.169.254:80 denied by the gateway's rule wall:own-address",
		"stack fetch to localhost:" + port + " denied by the gateway's rule wall:own-address",
	} {
		if !h.reported("run " + a.RunID + ": " + line) {
			t.Errorf("no report %q", line)
		}
	}
}

// TestTheStackProxyOpensANameOfTheNodesPolicy pins the names of a walled run's stack
// proxy: a host StackHosts lists that resolves to this machine's address is reached when
// the allow list of the node's policy lists it by name too, and refused at dial time
// with the stack proxy's guard body when it does not.
func TestTheStackProxyOpensANameOfTheNodesPolicy(t *testing.T) {
	if _, err := net.DefaultResolver.LookupHost(context.Background(), "stack.localhost."); err != nil {
		t.Skipf("stack.localhost. does not resolve here: %v", err)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "harness") }))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	n, _ := strconv.Atoi(port)
	h := start(t, gateway.Config{StackHosts: []string{"stack.localhost", "other.localhost"},
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"stack.localhost"}}}})
	a := h.open(server.LinkRunRequest{Wall: true})
	stack := relay(h.g.Addr(), a.StackProxySecret)
	resp, err := stack.Get("http://stack.localhost:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(b) != "harness" {
		t.Errorf("the name of the node's policy: %d %q", resp.StatusCode, b)
	}
	resp, err = stack.Get("http://other.localhost:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || string(b) != stackGuardedBody("other.localhost", n) {
		t.Errorf("a name the node's policy does not list: %d %q", resp.StatusCode, b)
	}
	if status, body := connectThrough(t, localStack(t, h, a.StackProxySecret), "other.localhost:"+port); status != http.StatusForbidden || body != stackGuardedBody("other.localhost", n) {
		t.Errorf("a CONNECT to a name the node's policy does not list: %d %q", status, body)
	}
}

// TestTheStackProxyOpensNoNameForAPattern pins that a *. entry of StackHosts opens no
// name of the node's policy: a host the node's policy lists by name, under a *. entry
// of StackHosts alone, that resolves to this machine's address is refused at dial time
// with the guard's body.
func TestTheStackProxyOpensNoNameForAPattern(t *testing.T) {
	if _, err := net.DefaultResolver.LookupHost(context.Background(), "stack.localhost."); err != nil {
		t.Skipf("stack.localhost. does not resolve here: %v", err)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the guarded stack proxy reached this machine: %s", r.URL)
	}))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	n, _ := strconv.Atoi(port)
	h := start(t, gateway.Config{StackHosts: []string{"*.localhost"},
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"stack.localhost"}}}})
	a := h.open(server.LinkRunRequest{Wall: true})
	resp, err := relay(h.g.Addr(), a.StackProxySecret).Get("http://stack.localhost:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || string(b) != stackGuardedBody("stack.localhost", n) {
		t.Errorf("a name under a *. entry of StackHosts: %d %q", resp.StatusCode, b)
	}
}

// TestTheStackProxyCountsAtTheRunsLimits pins the run's limits on its stack proxy:
// past RunLimits.Connections the next connection is refused with the stack proxy's 429,
// while the run's proxy counts apart and still takes one.
func TestTheStackProxyCountsAtTheRunsLimits(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "harness") }))
	defer origin.Close()
	target := origin.Listener.Addr().String()
	h := start(t, gateway.Config{StackHosts: []string{"127.0.0.1"}, RunLimits: gateway.RunLimits{Connections: 1}})
	a := h.open(server.LinkRunRequest{})
	held := localStack(t, h, a.StackProxySecret)
	defer held.Close()
	if status, body := connectThrough(t, held, target); status != http.StatusOK {
		t.Fatalf("the first stack connection: %d %q", status, body)
	}
	const want = "qory: retry once one of this run's stack fetch connections closes. The run's stack proxy has 1 connections open, the most gateway.run_limits.connections allows; until the run's first join request it counts them apart from the run's proxy.\n"
	if status, body := connectThrough(t, localStack(t, h, a.StackProxySecret), target); status != http.StatusTooManyRequests || body != want {
		t.Errorf("the stack connection past the limit: %d %q, want 429 %q", status, body, want)
	}
	run := localStack(t, h, a.ProxySecret)
	defer run.Close()
	if status, body := connectThrough(t, run, target); status == http.StatusTooManyRequests {
		t.Errorf("the run's proxy counted the stack proxy's connection: %d %q", status, body)
	}
}

// TestTheStackProxyBehindASeparateGateway pins a run's stack proxy on the one address:
// the run answer has no stack_proxy_secret; a bound connection that opens with
// QORY-STACK and the run key reaches the run's stack proxy, guarded, which refuses a
// host outside StackHosts and this machine's address and passes a listed host to its
// dial; QORY-STACK with an unbound connection, another run's key or a run key that is
// none is closed unanswered; from the run's first join request on, QORY-STACK is closed
// unanswered and a tunnel opened before it is closed, while QORY-RELAY still reaches
// the run's proxy. Each decision of the stack proxy is a dev.qory.run.egress with
// channel stack.
func TestTheStackProxyBehindASeparateGateway(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the guarded stack proxy reached this machine: %s", r.URL)
	}))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	tunnelEnd, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnelEnd.Close()
	r := startRemote(t, nil, gateway.Config{StackHosts: []string{"stack.invalid", "127.0.0.1"}})
	runID := event.NewRunID()
	key := runKeyFor(t, runID, nil)
	e := r.open(t, key, server.LinkRunRequest{})
	if e.a.StackProxySecret != "" || e.a.ProxySecret != "" {
		t.Errorf("the run answer has a secret behind a separate gateway")
	}
	stack := r.through(link.StackLine(key))
	resp, err := stack.Get("http://other.example.net/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || string(b) != stackRefusedBody("other.example.net", 80) {
		t.Errorf("another host: %d %q", resp.StatusCode, b)
	}
	resp, err = stack.Get("http://127.0.0.1:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("this machine's address: %d", resp.StatusCode)
	}
	resp, err = stack.Get("http://stack.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("a listed host whose dial fails: %d", resp.StatusCode)
	}
	other := runKeyFor(t, event.NewRunID(), nil)
	for what, line := range map[string]string{"another run's key": link.StackLine(other), "no run key": link.StackPreamble + " qrk_not.a-run-key\n"} {
		if _, err := r.through(line).Get("http://stack.invalid/"); err == nil {
			t.Errorf("QORY-STACK with %s was answered", what)
		}
	}
	// An unbound connection's first line goes to the relay toward the server, never to a
	// run's stack proxy.
	unbound, err := tls.Dial("tcp", r.g.Addr(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: r.pool, ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(unbound, link.StackLine(key)+"GET http://unbound.example/ HTTP/1.1\r\nHost: unbound.example\r\n\r\n")
	unbound.SetReadDeadline(time.Now().Add(5 * time.Second))
	if b, _ := io.ReadAll(unbound); strings.Contains(string(b), "gateway.stack_hosts") {
		t.Errorf("QORY-STACK on an unbound connection reached the stack proxy: %q", b)
	}
	unbound.Close()
	// A connection to the stack proxy opened before the join, which sends nothing yet.
	held, err := stack.Transport.(*http.Transport).DialContext(context.Background(), "tcp", "gateway.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	j := r.do(t, key, http.MethodPost, "/qory-link/run-configuration/"+runID+"/sessions", []byte(`{"version":1,"passes":[]}`))
	if j.status != http.StatusOK {
		t.Fatalf("the join: %d %s", j.status, j.body)
	}
	closedUnansweredConn(t, held, "a QORY-STACK connection opened before the join")
	if _, err := stack.Get("http://other.example.net/"); err == nil {
		t.Error("QORY-STACK after the join was answered")
	}
	resp, err = r.relay(t, key).Get("http://api.example/")
	if err != nil {
		t.Fatalf("QORY-RELAY after the join: %v", err)
	}
	resp.Body.Close()
	if r.reported("unbound.example") {
		t.Error("the stack proxy decided the unbound connection's request")
	}
	if got := e.post(t, sessionStarted(runID, 1), sessionExited(runID, 1), exited(runID)); got.status != http.StatusAccepted {
		t.Fatalf("the last batch: %d %s", got.status, got.body)
	}
	for _, line := range []string{
		"run " + runID + ": stack fetch to other.example.net:80 denied: the host is in neither stack_hosts list",
		"run " + runID + ": stack fetch to 127.0.0.1:" + port + " denied by the gateway's rule wall:own-address",
		"run " + runID + ": stack fetch to stack.invalid:80 allowed by gateway.stack_hosts entry stack.invalid; the dial failed",
	} {
		if !r.reported(line) {
			t.Errorf("no report %q", line)
		}
	}
	eventually(t, "the run's record", func() bool {
		rec := r.record(runID)
		return len(rec) > 0 && rec[len(rec)-1].Type == event.RunExited
	})
	var stacked []string
	for _, l := range r.record(runID) {
		if l.Type != event.RunEgress {
			continue
		}
		if l.Data["channel"] == "stack" {
			stacked = append(stacked, fmt.Sprint(l.Data["host"], " ", l.Data["decision"], " ", l.Data["rule"]))
		} else if l.Data["host"] != "api.example" {
			t.Errorf("the record has a dev.qory.run.egress of the run's proxy to %v", l.Data["host"])
		}
	}
	if want := []string{"other.example.net denied ", "127.0.0.1 denied wall:own-address", "stack.invalid allowed stack.invalid"}; !slices.Equal(stacked, want) {
		t.Errorf("the record's dev.qory.run.egress of the stack proxy %q, want %q", stacked, want)
	}
}

// stackGateway is a gateway on the local link whose control serves doc, with
// gateway.stack_hosts yaml and the node's policy node, nil for none.
func stackGateway(t *testing.T, doc string, yaml []string, node *gateway.Policy) (*control, *harness) {
	t.Helper()
	c := newControl(t)
	c.serveDocument(doc, 'a')
	return c, start(t, gateway.Config{Server: c.server(), StackHosts: yaml, Policy: node})
}

// TestTheStackProxyAllowsTheRunConfigurationsStackHosts pins a run configuration's
// stack_hosts: the stack proxy passes a host of the list beside gateway.stack_hosts,
// and reports each with the list its entry is in; a host of neither list gets the 403
// whose body has both lists; the open's dev.qory.run.policy_applied lists stack_hosts as
// the document has them, and a join's record repeats the open's members.
func TestTheStackProxyAllowsTheRunConfigurationsStackHosts(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "harness") }))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	_, h := stackGateway(t, `{"version":1,"stack_hosts":["127.0.0.1","git.example"]}`, []string{"localhost", "git.example"}, nil)
	a := h.open(server.LinkRunRequest{})
	stack := relay(h.g.Addr(), a.StackProxySecret)
	for _, u := range []string{origin.URL, "http://localhost:" + port + "/"} {
		resp, err := stack.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(b) != "harness" {
			t.Errorf("%s: %d %q", u, resp.StatusCode, b)
		}
	}
	if status, body := connectThrough(t, localStack(t, h, a.StackProxySecret), "other.example.net:443"); status != http.StatusForbidden || body != stackRefusedBody("other.example.net", 443) {
		t.Errorf("a host of neither list: %d %q", status, body)
	}
	var members map[string]any
	if err := json.Unmarshal(a.Applied, &members); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(members["stack_hosts"]); got != "[127.0.0.1 git.example]" {
		t.Errorf("the open's applied stack_hosts %s, want [127.0.0.1 git.example]", got)
	}
	if d := h.post(started(a.RunID, nil), applied(a.RunID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	h.joined(a.RunID)
	h.post(sessionStarted(a.RunID, 1), applied(a.RunID, a.Applied), sessionExited(a.RunID, 1), exited(a.RunID))
	h.close()
	want := []string{
		fmt.Sprintf("run %s: stack fetch to 127.0.0.1:%s allowed by the run configuration's stack_hosts entry 127.0.0.1", a.RunID, port),
		fmt.Sprintf("run %s: stack fetch to localhost:%s allowed by gateway.stack_hosts entry localhost", a.RunID, port),
		fmt.Sprintf("run %s: stack fetch to other.example.net:443 denied: the host is in neither stack_hosts list", a.RunID),
	}
	if got := h.reportsWith("stack fetch"); !slices.Equal(got, want) {
		t.Errorf("reported\n%q\nwant\n%q", got, want)
	}
	var recorded []string
	for _, l := range h.record(a.RunID) {
		if l.Type == event.PolicyApplied {
			recorded = append(recorded, fmt.Sprint(l.Data["stack_hosts"]))
		}
	}
	if want := []string{"[127.0.0.1 git.example]", "[127.0.0.1 git.example]"}; !slices.Equal(recorded, want) {
		t.Errorf("the record's dev.qory.run.policy_applied stack_hosts %q, want %q", recorded, want)
	}
}

// TestTheRunConfigurationsStackHostsOpenNoPrivateAddress pins that a run
// configuration's stack_hosts open no private address behind a wall: this machine's
// address listed there, and allowed by name in the node's policy, is refused with the
// guard's body, and nothing is dialled; the same address in gateway.stack_hosts is
// reached.
func TestTheRunConfigurationsStackHostsOpenNoPrivateAddress(t *testing.T) {
	if _, err := net.DefaultResolver.LookupHost(context.Background(), "stack.localhost."); err != nil {
		t.Skipf("stack.localhost. does not resolve here: %v", err)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "harness") }))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	n, _ := strconv.Atoi(port)
	node := &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"stack.localhost", "other.localhost", "127.0.0.1"}}}
	_, h := stackGateway(t, `{"version":1,"stack_hosts":["other.localhost","127.0.0.1"]}`, []string{"stack.localhost"}, node)
	a := h.open(server.LinkRunRequest{Wall: true})
	stack := relay(h.g.Addr(), a.StackProxySecret)
	for host, want := range map[string]string{"other.localhost": stackGuardedBody("other.localhost", n), "127.0.0.1": stackGuardedBody("127.0.0.1", n)} {
		resp, err := stack.Get("http://" + host + ":" + port + "/")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || string(b) != want {
			t.Errorf("%s of the run configuration's stack_hosts: %d %q, want %q", host, resp.StatusCode, b, want)
		}
	}
	resp, err := stack.Get("http://stack.localhost:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(b) != "harness" {
		t.Errorf("the name of gateway.stack_hosts and the node's policy: %d %q", resp.StatusCode, b)
	}
}

// TestTheNodesPolicyDecidesEachStackHost pins Tom's rule that the node only takes
// away, decided per host: a host of the run configuration's stack_hosts passes when the
// node's policy allows it under its mode and has no path rule for it, which the stack
// proxy cannot check; otherwise it is refused with the body of the check that refused
// it, and the report line ends with that check's cause. A *. entry is decided for each host below it, so
// a deny entry under it takes away that host alone. gateway.stack_hosts is not decided
// by the node's policy. Hosts under .invalid resolve nowhere, so a host that passes
// gets the stack proxy's 502 for its dial.
func TestTheNodesPolicyDecidesEachStackHost(t *testing.T) {
	for _, c := range []struct {
		name    string
		node    gateway.PolicyEgress
		wall    bool
		stack   string
		pass    []string
		refused map[string]string
		lines   []string
	}{
		{"observe with a deny under a *. entry", gateway.PolicyEgress{Mode: "observe", Deny: []string{"a.cdn.invalid", "yaml.invalid"}}, false,
			`["*.cdn.invalid"]`, []string{"b.cdn.invalid"},
			map[string]string{"a.cdn.invalid": stackNodeBody("a.cdn.invalid", 443)},
			[]string{"stack fetch to a.cdn.invalid:443 denied: the node's policy does not allow this host of the run configuration's stack_hosts"}},
		{"enforce with an allow", gateway.PolicyEgress{Mode: "enforce", Allow: []string{"*.cdn.invalid"}}, false,
			`["b.cdn.invalid","git.other.invalid"]`, []string{"b.cdn.invalid"},
			map[string]string{"git.other.invalid": stackNodeBody("git.other.invalid", 443)},
			[]string{"stack fetch to b.cdn.invalid:443 allowed by the run configuration's stack_hosts entry b.cdn.invalid; the dial failed"}},
		{"path rules of the node", gateway.PolicyEgress{Mode: "enforce", Allow: []string{"*.cdn.invalid"}, Paths: map[string][]string{"a.cdn.invalid": {"/harness/*"}}}, true,
			`["*.cdn.invalid"]`, []string{"b.cdn.invalid"},
			map[string]string{"a.cdn.invalid": stackPathsBody("a.cdn.invalid", 443)},
			[]string{"stack fetch to a.cdn.invalid:443 denied: the node's policy has path rules for this host, which the stack proxy does not check"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, h := stackGateway(t, `{"version":1,"stack_hosts":`+c.stack+`}`, []string{"yaml.invalid"}, &gateway.Policy{Version: 1, Egress: c.node})
			a := h.open(server.LinkRunRequest{Wall: c.wall})
			for _, host := range append(c.pass, "yaml.invalid") {
				if status, body := connectThrough(t, localStack(t, h, a.StackProxySecret), host+":443"); status != http.StatusBadGateway {
					t.Errorf("%s: %d %q, want the 502 of its dial", host, status, body)
				}
			}
			for host, want := range c.refused {
				if status, body := connectThrough(t, localStack(t, h, a.StackProxySecret), host+":443"); status != http.StatusForbidden || body != want {
					t.Errorf("%s: %d %q, want 403 %q", host, status, body, want)
				}
			}
			if status, body := connectThrough(t, localStack(t, h, a.StackProxySecret), "other.invalid:443"); status != http.StatusForbidden || body != stackRefusedBody("other.invalid", 443) {
				t.Errorf("a host of neither list: %d %q", status, body)
			}
			for _, line := range c.lines {
				if !h.reported("run " + a.RunID + ": " + line) {
					t.Errorf("no report %q in %q", line, h.reportsWith("stack fetch"))
				}
			}
		})
	}
}

// TestAReloadKeepsTheStackHostsFixed pins that a run's stack_hosts are fixed when it
// starts: a reload whose run configuration lists others fails, the user is told with
// the fix first, and the policy in force stays.
func TestAReloadKeepsTheStackHostsFixed(t *testing.T) {
	c, h := stackGateway(t, `{"version":1,"stack_hosts":["git.example"]}`, nil, nil)
	a := h.open(server.LinkRunRequest{})
	runID, first := a.RunID, a.Digest
	if d := h.post(started(runID, nil), applied(runID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	c.serveDocument(`{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["b.example"]}},"stack_hosts":["git.example","api.git.example"]}`, 'b')
	line := "the reload failed: start another run to use other stack hosts: a run's stack_hosts are fixed when it starts"
	eventually(t, "the failed reload's report", func() bool {
		h.post(heartbeat(runID))
		return h.reported(line)
	})
	again, err := h.linkOf(runID).Reload(t.Context(), server.LocalOrigin+"/v1/run-configuration", runID)
	if err != nil || again.Digest != first {
		t.Errorf("after a refused reload: %v %+v, want the digest %s", err, again, first)
	}
	h.post(exited(runID))
	h.close()
}
