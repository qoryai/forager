package gateway_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// TestStartChecksTheRunLimits pins the run limits at Start: zero is each field's
// default, 256 connections, 50 requests a second and a burst of 200, which each run's
// proxy gets; a field outside its range is refused before anything starts, in the
// text that says what to set.
func TestStartChecksTheRunLimits(t *testing.T) {
	h := start(t, gateway.Config{})
	a := h.open(server.LinkRunRequest{})
	if got := gateway.RunLimitsOf(h.g, a.RunID); got != (gateway.RunLimits{Connections: 256, RequestsPerSecond: 50, Burst: 200}) {
		t.Errorf("the defaults %+v", got)
	}
	most := gateway.RunLimits{Connections: 65536, RequestsPerSecond: 10000, Burst: 100000}
	h = start(t, gateway.Config{RunLimits: most})
	a = h.open(server.LinkRunRequest{})
	if got := gateway.RunLimitsOf(h.g, a.RunID); got != most {
		t.Errorf("the most %+v", got)
	}
	least := gateway.RunLimits{Connections: 1, RequestsPerSecond: 1, Burst: 1}
	h = start(t, gateway.Config{RunLimits: least})
	a = h.open(server.LinkRunRequest{})
	if got := gateway.RunLimitsOf(h.g, a.RunID); got != least {
		t.Errorf("the least %+v", got)
	}
	for _, c := range []struct {
		limits gateway.RunLimits
		want   string
	}{
		{gateway.RunLimits{Connections: -3}, "Set RunLimits.Connections to a number from 1 to 65536, or 0 for the default of 256. It is -3."},
		{gateway.RunLimits{Connections: 65537}, "Set RunLimits.Connections to a number from 1 to 65536, or 0 for the default of 256. It is 65537."},
		{gateway.RunLimits{RequestsPerSecond: -1}, "Set RunLimits.RequestsPerSecond to a number from 1 to 10000, or 0 for the default of 50. It is -1."},
		{gateway.RunLimits{RequestsPerSecond: 10001}, "Set RunLimits.RequestsPerSecond to a number from 1 to 10000, or 0 for the default of 50. It is 10001."},
		{gateway.RunLimits{Burst: -1}, "Set RunLimits.Burst to a number from 1 to 100000, or 0 for the default of 200. It is -1."},
		{gateway.RunLimits{Burst: 100001}, "Set RunLimits.Burst to a number from 1 to 100000, or 0 for the default of 200. It is 100001."},
	} {
		g, err := gateway.Start(context.Background(), gateway.Config{Dir: t.TempDir(), RunLimits: c.limits, NoLinkSocket: true})
		if err == nil {
			g.Close(context.Background())
			t.Errorf("%+v started", c.limits)
			continue
		}
		if err.Error() != c.want {
			t.Errorf("%+v: %q", c.limits, err)
		}
	}
}

// TestEachRunOnAGatewayHasItsOwnConnections pins that the limits are per run: with a
// limit of 1 connection, a run that holds a tunnel open gets 429 for its next, and
// another run on the same gateway opens one.
func TestEachRunOnAGatewayHasItsOwnConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(io.Discard, c)
				c.Close()
			}()
		}
	}()
	h := start(t, gateway.Config{RunLimits: gateway.RunLimits{Connections: 1}})
	first, second := h.open(server.LinkRunRequest{}), h.open(server.LinkRunRequest{})
	target := ln.Addr().String()
	tunnel := func(secret string) (int, string, net.Conn) {
		t.Helper()
		c, err := net.Dial("tcp", h.g.Addr())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(c, link.RelayLine(secret)+"CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode == http.StatusOK {
			return resp.StatusCode, "", c
		}
		b, _ := io.ReadAll(resp.Body)
		c.Close()
		return resp.StatusCode, string(b), nil
	}
	status, _, held := tunnel(first.ProxySecret)
	if status != http.StatusOK {
		t.Fatalf("the first run's tunnel: %d", status)
	}
	defer held.Close()
	if status, body, _ := tunnel(first.ProxySecret); status != http.StatusTooManyRequests || !strings.Contains(body, "The run has 1 connections open") {
		t.Errorf("the first run's second tunnel: %d %q", status, body)
	}
	status, _, other := tunnel(second.ProxySecret)
	if status != http.StatusOK {
		t.Fatalf("the second run's tunnel: %d", status)
	}
	other.Close()
}
