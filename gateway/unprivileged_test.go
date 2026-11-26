package gateway_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// TestAnUnprivilegedConnectionHasNoRunAPIOnOneMachine pins the gateway's run API route
// for a connection that opens with link.UnprivilegedPreamble and the run's proxy
// secret, as the session's forwarder opens one from a step container: 403 unprivileged,
// recorded, and nothing reaches the run API. The same request with the relay's
// preamble reaches it.
func TestAnUnprivilegedConnectionHasNoRunAPIOnOneMachine(t *testing.T) {
	o := openRunAPIRun(t)
	o.f.reset()
	c, err := net.Dial("tcp", o.h.g.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, link.UnprivilegedLine(o.a.ProxySecret)+line(http.MethodGet, o.url("/work-item"))+"Host: "+link.RunAPIHost+"\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	routeError(t, "unprivileged", resp, b, http.StatusForbidden, "unprivileged")
	if got := o.f.requests(); len(got) != 0 {
		t.Errorf("the run API got %v", got)
	}
	recorded := false
	for _, e := range o.egressOf() {
		if status, _ := e["status"].(float64); status == http.StatusForbidden {
			recorded = true
		}
	}
	if !recorded {
		t.Errorf("no 403 in the record: %v", o.egressOf())
	}
	if resp, _, _ := o.send(line(http.MethodGet, o.url("/work-item")), nil); resp.StatusCode != http.StatusOK || len(o.f.requests()) != 1 {
		t.Errorf("through the relay's preamble: %d, %d requests", resp.StatusCode, len(o.f.requests()))
	}
}

// TestAnUnprivilegedConnectionHasNoRunAPIBehindASeparateGateway pins the same on the
// one address of a separate gateway, for a bound connection that opens with
// link.UnprivilegedPreamble and the run key, as server.Link's DialProxyUnprivileged
// opens it.
func TestAnUnprivilegedConnectionHasNoRunAPIBehindASeparateGateway(t *testing.T) {
	c := gatewayControl(t)
	f := runAPIOf(c)
	f.passAttach.Store(true)
	r := startRemote(t, c, gateway.Config{Policy: enforceNothing})
	e := r.open(t, runKeyFor(t, event.NewRunID(), nil), server.LinkRunRequest{})
	f.reset()
	resp, err := sendTo(r.through(link.UnprivilegedLine(e.key)), http.MethodGet, link.RunAPIURL(e.a.RunID)+"/work-item")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	routeError(t, "unprivileged", resp, b, http.StatusForbidden, "unprivileged")
	if got := f.requests(); len(got) != 0 {
		t.Errorf("the run API got %v", got)
	}
}
