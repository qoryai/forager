package gateway_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
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
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// The tests of this file pin a run's stack proxy: what qory fetches the harness
// definition through before the run's first session joins.

// stackRefusedBody is the 403 the stack proxy answers for host:port outside
// gateway.stack_hosts.
func stackRefusedBody(host string, port int) string {
	return "qory: add " + host + " to gateway.stack_hosts in forager.yaml, or fetch the harness definition from a host listed there.\n" +
		fmt.Sprintf("qory: egress to %s:%d denied by the gateway: the host is not in gateway.stack_hosts\n", host, port)
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
		{[]string{"git.example.com", "Git.Example.com:443"}, `Set StackHosts[1] to a lower-case host name or a *. suffix, such as git.example.com. It is "Git.Example.com:443".`},
		{[]string{"https://git.example.com"}, `Set StackHosts[0] to a lower-case host name or a *. suffix, such as git.example.com. It is "https://git.example.com".`},
		{[]string{"*"}, `Set StackHosts[0] to a lower-case host name or a *. suffix, such as git.example.com. It is "*".`},
		{[]string{"1.2.3"}, `Set StackHosts[0] to a lower-case host name or a *. suffix, such as git.example.com. It is "1.2.3".`},
		{[]string{""}, `Set StackHosts[0] to a lower-case host name or a *. suffix, such as git.example.com. It is "".`},
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
// report, and no dev.qory.run.egress; from the run's first join request on, the secret
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
	closedUnansweredConn(t, localStack(t, h, a.StackProxySecret), "the stack proxy secret after the join")
	resp, err = relay(h.g.Addr(), a.ProxySecret).Get("http://api.example/")
	if err != nil {
		t.Fatalf("the run's proxy after the join: %v", err)
	}
	resp.Body.Close()
	h.post(sessionStarted(a.RunID, 1), sessionExited(a.RunID, 1), exited(a.RunID))
	h.close()
	want := []string{
		fmt.Sprintf("run %s: stack fetch to 127.0.0.1:%s allowed by gateway.stack_hosts entry 127.0.0.1", a.RunID, port),
		fmt.Sprintf("run %s: stack fetch to other.example.net:443 denied: the host is not in gateway.stack_hosts", a.RunID),
		fmt.Sprintf("run %s: stack fetch to other.example.net:80 denied: the host is not in gateway.stack_hosts", a.RunID),
		fmt.Sprintf("run %s: stack fetch to 127.0.0.1:%s allowed by gateway.stack_hosts entry 127.0.0.1", a.RunID, port),
	}
	if got := h.reportsWith("stack fetch"); !slices.Equal(got, want) {
		t.Errorf("reported\n%q\nwant\n%q", got, want)
	}
	var egress []string
	for _, l := range h.record(a.RunID) {
		if l.Type == event.RunEgress {
			egress = append(egress, fmt.Sprint(l.Data["host"], " ", l.Data["decision"]))
		}
	}
	if want := []string{"127.0.0.1 denied", "api.example allowed"}; !slices.Equal(egress, want) {
		t.Errorf("the record's dev.qory.run.egress %q, want the run's proxy's alone, %q", egress, want)
	}
}

// TestTheStackProxyIsGuardedBehindAWall pins the guard of a walled run's stack proxy:
// this machine's address by number and by name, and the cloud metadata address, are
// refused even when StackHosts lists them, nothing is dialled for them, and each
// refusal is a line of the gateway's report.
func TestTheStackProxyIsGuardedBehindAWall(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the guarded stack proxy reached this machine: %s", r.URL)
	}))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	h := start(t, gateway.Config{StackHosts: []string{"127.0.0.1", "169.254.169.254", "localhost"}})
	a := h.open(server.LinkRunRequest{Wall: true})
	for _, target := range []string{"127.0.0.1:" + port, "169.254.169.254:80", "localhost:" + port} {
		status, body := connectThrough(t, localStack(t, h, a.StackProxySecret), target)
		if status != http.StatusForbidden || !strings.Contains(body, "denied by the gateway") {
			t.Errorf("%s: %d %q", target, status, body)
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

// TestTheStackProxyBehindASeparateGateway pins a run's stack proxy on the one address:
// the run answer has no stack_proxy_secret; a bound connection that opens with
// QORY-STACK and the run key reaches the run's stack proxy, guarded, which refuses a
// host outside StackHosts and this machine's address and passes a listed host to its
// dial; QORY-STACK with an unbound connection, another run's key or a run key that is
// none is closed unanswered; from the run's first join request on, QORY-STACK is closed
// unanswered and a tunnel opened before it is closed, while QORY-RELAY still reaches
// the run's proxy.
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
		"run " + runID + ": stack fetch to other.example.net:80 denied: the host is not in gateway.stack_hosts",
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
	for _, l := range r.record(runID) {
		if l.Type == event.RunEgress && l.Data["host"] != "api.example" {
			t.Errorf("the record has a dev.qory.run.egress of the stack proxy: %v", l.Data)
		}
	}
}
