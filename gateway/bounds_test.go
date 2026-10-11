package gateway_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// The bounds of a separate gateway's one address against a peer that holds no run key:
// what it reads of a refused request, how many connections it holds, and the relay's
// bounds on what it passes on.

// closedUnansweredWithin fails the test unless c is closed with no answer, its read
// ending in no timeout, within d.
func closedUnansweredWithin(t *testing.T, what string, r *bufio.Reader, c net.Conn, d time.Duration) {
	t.Helper()
	start := time.Now()
	c.SetReadDeadline(start.Add(d + 5*time.Second))
	resp, err := http.ReadResponse(r, nil)
	if err == nil {
		b, _ := io.ReadAll(resp.Body)
		t.Errorf("%s: answered %d %q", what, resp.StatusCode, b)
		return
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Errorf("%s: still open after %s", what, time.Since(start).Round(time.Millisecond))
		return
	}
	if took := time.Since(start); took > d {
		t.Errorf("%s: closed after %s, past %s", what, took.Round(time.Millisecond), d)
	}
}

// closedAfter fails the test unless the server closed c once its answer was read.
func closedAfter(t *testing.T, what string, r *bufio.Reader, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := r.Read(make([]byte, 1)); err == nil || n != 0 {
		t.Errorf("%s: the connection is still open: %v", what, err)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Errorf("%s: the connection is still open", what)
	}
}

// TestARequestRefusedForItsRunKeyIsAnsweredOnce pins what the one address reads of a
// request it refuses for its run key: its body, up to 64 KiB within the wait, and then
// the signed refusal with Connection: close, the connection closed after it; a longer
// body, declared or sent, or one slower, closes the connection unanswered.
func TestARequestRefusedForItsRunKeyIsAnsweredOnce(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	head := func(method string, length int, extra string) string {
		return fmt.Sprintf("%s /qory-link/events HTTP/1.1\r\nHost: gateway.example:8443\r\nAuthorization: Bearer nonsense\r\nContent-Type: application/cloudevents-batch+json\r\nContent-Length: %d\r\n%s\r\n", method, length, extra)
	}
	for _, size := range []int{0, 100, gateway.RefusedBody} {
		b, err := r.bind(t, gatewayKeys())
		if err != nil {
			t.Fatal(err)
		}
		body := bytes.Repeat([]byte("x"), size)
		io.WriteString(b.c, head(http.MethodPost, size, ""))
		b.c.Write(body)
		resp, err := http.ReadResponse(b.r, nil)
		if err != nil {
			t.Fatalf("a refused POST of %d bytes: %v", size, err)
		}
		got, _ := io.ReadAll(resp.Body)
		a := accesskey.Answer{Link: true, Status: resp.StatusCode, RequestSignature: link.AnswerRequest(b.ekm, http.MethodPost, "/qory-link/events", body), Body: got,
			Configuration: resp.Header.Get(server.HeaderConfiguration)}
		if resp.StatusCode != http.StatusBadRequest || !verifyAnswer(gatewayKeys(), a, resp.Header.Get(server.HeaderSignature)) || !resp.Close {
			t.Errorf("a refused POST of %d bytes: %d close=%v %q", size, resp.StatusCode, resp.Close, got)
		}
		closedAfter(t, fmt.Sprintf("a refused POST of %d bytes", size), b.r, b.c)
		b.Close()
	}
	// A GET and an OPTIONS * are refused the same, and close their connections.
	for _, req := range []string{
		"GET /qory-link/configuration HTTP/1.1\r\nHost: gateway.example:8443\r\n\r\n",
		"OPTIONS * HTTP/1.1\r\nHost: gateway.example:8443\r\n\r\n",
	} {
		b, err := r.bind(t, gatewayKeys())
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(b.c, req)
		resp, err := http.ReadResponse(b.r, nil)
		if err != nil {
			t.Fatalf("%q: %v", req, err)
		}
		got, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get(server.HeaderSignature) == "" || !resp.Close || !strings.Contains(string(got), "run_key_invalid") {
			t.Errorf("%q: %d close=%v %q", req, resp.StatusCode, resp.Close, got)
		}
		closedAfter(t, req, b.r, b.c)
		b.Close()
	}
	// A body declared longer than 64 KiB, or sent longer in chunks, closes at once.
	for _, size := range []int{gateway.RefusedBody + 1, 100 << 10, 2 << 20} {
		b, err := r.bind(t, gatewayKeys())
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(b.c, head(http.MethodPost, size, ""))
		closedUnansweredWithin(t, fmt.Sprintf("a refused POST that declares %d bytes", size), b.r, b.c, 2*time.Second)
		b.Close()
	}
	b, err := r.bind(t, gatewayKeys())
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(b.c, "POST /qory-link/events HTTP/1.1\r\nHost: gateway.example:8443\r\nAuthorization: Bearer nonsense\r\nTransfer-Encoding: chunked\r\n\r\n")
	fmt.Fprintf(b.c, "%x\r\n%s\r\n", gateway.RefusedBody+1, bytes.Repeat([]byte("x"), gateway.RefusedBody+1))
	closedUnansweredWithin(t, "a refused POST of 64 KiB and a byte in chunks", b.r, b.c, 2*time.Second)
	b.Close()
	// A body that does not come whole within the wait closes the connection then.
	b, err = r.bind(t, gatewayKeys())
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(b.c, head(http.MethodPost, 1000, ""))
	io.WriteString(b.c, "0123456789")
	closedUnansweredWithin(t, "a refused POST whose body drips", b.r, b.c, gateway.RefusedWait+2*time.Second)
	b.Close()
}

// TestTheLinksBoundsOnTheOneAddress pins the link's server there: a request whose head
// is over 16 KiB is refused before its run key is read, and every request must arrive
// whole within 60 seconds.
func TestTheLinksBoundsOnTheOneAddress(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	b, err := r.bind(t, gatewayKeys())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	fmt.Fprintf(b.c, "GET /qory-link/configuration HTTP/1.1\r\nHost: gateway.example:8443\r\nX-Big: %s\r\n\r\n", strings.Repeat("a", gateway.EdgeMaxHeader+8<<10))
	resp, err := http.ReadResponse(b.r, nil)
	if err != nil || resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("a head over 16 KiB: %v %v", resp, err)
	}
	edge, _ := gateway.ServiceServers(r.g)
	if edge.ReadTimeout != gateway.EdgeReadWait || gateway.EdgeReadWait != time.Minute || edge.MaxHeaderBytes != gateway.EdgeMaxHeader {
		t.Errorf("the link's server reads for %s, heads of %d bytes", edge.ReadTimeout, edge.MaxHeaderBytes)
	}
}

// TestTheOneAddressBoundsTheConnectionsOfASource pins the 64 connections of one source
// the one address holds at once: the next is closed at once, unanswered, and a source
// below its bound again is served again.
func TestTheOneAddressBoundsTheConnectionsOfASource(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", r.g.Addr())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	open := func(c net.Conn, d time.Duration) bool {
		c.SetReadDeadline(time.Now().Add(d))
		_, err := c.Read(make([]byte, 1))
		ne, ok := err.(net.Error)
		return ok && ne.Timeout()
	}
	for range gateway.MaxSourceConns {
		conns = append(conns, dial())
	}
	over := dial()
	if open(over, 2*time.Second) {
		t.Errorf("connection %d of one source is held", gateway.MaxSourceConns+1)
	}
	over.Close()
	if !open(conns[len(conns)-1], 200*time.Millisecond) {
		t.Errorf("connection %d of one source is closed", gateway.MaxSourceConns)
	}
	conns[0].Close()
	conns = conns[1:]
	deadline := time.Now().Add(3 * time.Second)
	for {
		c := dial()
		if open(c, 300*time.Millisecond) {
			conns = append(conns, c)
			break
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("a source below its bound again is not served")
		}
	}
}

// TestTheRelaysBoundsOnARequest pins what the relay passes on: never a field that names
// a source; never a target whose path holds an escaped byte, or a POST with a query,
// each 404 with nothing sent on; the path it matched; and no more than its requests in
// flight with the server, one more 503 with no body. Its server reads a request whole
// within 30 seconds and writes its answer within 30 more.
func TestTheRelaysBoundsOnARequest(t *testing.T) {
	cfg := gateway.Config{}
	gateway.SetRelayInFlight(&cfg, 2)
	r := startRemote(t, nil, cfg)
	var mu sync.Mutex
	var got []string
	hold := make(chan struct{})
	var held sync.WaitGroup
	f := func(w http.ResponseWriter, req *http.Request) bool {
		if req.URL.Path == "/v1/events" {
			return false
		}
		io.ReadAll(req.Body)
		mu.Lock()
		got = append(got, fmt.Sprintf("%s %s %q %q %q", req.Method, req.RequestURI, req.Header.Get("X-Forwarded-For"), req.Header.Get("Forwarded"), req.Header.Get("X-Real-Ip")))
		mu.Unlock()
		if req.URL.Query().Get("hold") != "" {
			held.Done()
			<-hold
		}
		w.Write([]byte(`{}`))
		return true
	}
	r.c.intercept.Store(&f)
	send := func(raw string) (int, []byte) {
		t.Helper()
		c := r.dialTLS(t)
		defer c.Close()
		io.WriteString(c, raw)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	last := func() string {
		mu.Lock()
		defer mu.Unlock()
		if len(got) == 0 {
			return ""
		}
		return got[len(got)-1]
	}
	if status, _ := send("POST " + runsPath + " HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 203.0.113.9\r\nForwarded: for=203.0.113.9\r\nX-Real-IP: 203.0.113.9\r\nContent-Length: 2\r\n\r\n{}"); status != http.StatusOK {
		t.Errorf("a registration: %d", status)
	}
	if want := "POST " + runsPath + ` "" "" ""`; last() != want {
		t.Errorf("forwarded %q; want %q", last(), want)
	}
	mu.Lock()
	sent := len(got)
	mu.Unlock()
	id := event.NewRunID()
	for _, target := range []string{
		"/.well-known%2Fqory-enrolment",
		runsPath + "/" + id + "%2Foutcome",
		runsPath + "/" + id + "/%6Futcome",
		"/v1%2Fruns",
		runsPath + "?x=/attach",
		runsPath + "?",
		"/.well-known/qory-enrolment?x=1",
	} {
		if status, b := send("POST " + target + " HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}"); status != http.StatusNotFound || len(b) != 0 {
			t.Errorf("POST %s: %d %q", target, status, b)
		}
	}
	if status, b := send("GET /.well-known%2Fqory-configuration HTTP/1.1\r\nHost: x\r\n\r\n"); status != http.StatusNotFound || len(b) != 0 {
		t.Errorf("an escaped discovery: %d %q", status, b)
	}
	mu.Lock()
	if len(got) != sent {
		t.Errorf("forwarded %q", got[sent:])
	}
	mu.Unlock()
	// A discovery's query goes on as it came.
	if status, _ := send("GET " + server.WellKnown + "?a=1&b=%2F HTTP/1.1\r\nHost: x\r\n\r\n"); status != http.StatusOK || last() != "GET "+server.WellKnown+`?a=1&b=%2F "" "" ""` {
		t.Errorf("a discovery with a query: %d, forwarded %q", status, last())
	}

	// Two requests with the server; a third is 503, and once one is answered, another
	// goes on.
	held.Add(2)
	var answered sync.WaitGroup
	for range 2 {
		answered.Add(1)
		go func() {
			defer answered.Done()
			c := r.dialTLS(t)
			defer c.Close()
			io.WriteString(c, "GET "+server.WellKnown+"?hold=1 HTTP/1.1\r\nHost: x\r\n\r\n")
			http.ReadResponse(bufio.NewReader(c), nil)
		}()
	}
	held.Wait()
	if status, b := send("GET " + server.WellKnown + " HTTP/1.1\r\nHost: x\r\n\r\n"); status != http.StatusServiceUnavailable || len(b) != 0 {
		t.Errorf("a third request in flight: %d %q", status, b)
	}
	close(hold)
	answered.Wait()
	if status, _ := send("GET " + server.WellKnown + " HTTP/1.1\r\nHost: x\r\n\r\n"); status != http.StatusOK {
		t.Errorf("a request once the others are answered: %d", status)
	}

	_, relay := gateway.ServiceServers(r.g)
	if relay.ReadTimeout != gateway.RelayReadWait || relay.WriteTimeout != gateway.RelayWriteWait || gateway.RelayReadWait != 30*time.Second || gateway.RelayWriteWait != 30*time.Second {
		t.Errorf("the relay's server reads for %s and writes for %s", relay.ReadTimeout, relay.WriteTimeout)
	}
}

// TestTheRelaysRateIsOfTheConnectionsAddress pins the relay's rate to the connection's
// own address: requests that name other sources in X-Forwarded-For, Forwarded or
// X-Real-IP share one bucket.
func TestTheRelaysRateIsOfTheConnectionsAddress(t *testing.T) {
	r := startRemote(t, nil, gateway.Config{})
	statuses := map[int]int{}
	for i := range gateway.RelayBurst + 5 {
		c := r.dialTLS(t)
		source := fmt.Sprintf("198.51.100.%d", i+1)
		fmt.Fprintf(c, "GET /nothing HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: %s\r\nForwarded: for=%s\r\nX-Real-IP: %s\r\n\r\n", source, source, source)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
		statuses[resp.StatusCode]++
	}
	if statuses[http.StatusTooManyRequests] < 4 {
		t.Errorf("statuses %v", statuses)
	}
}

// TestTheProxyOfARunThatEndedIsClosed pins the proxy behind the gateway to a live run:
// once its run has ended, a relay preamble with its run key closes the connection
// unanswered, even before the run's proxy is let go of.
func TestTheProxyOfARunThatEndedIsClosed(t *testing.T) {
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	t.Cleanup(o.Close)
	r := startRemote(t, nil, gateway.Config{Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"127.0.0.1"}}}})
	key := runKeyFor(t, event.NewRunID(), nil)
	relayed := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: r.g.Addr()}),
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			b, err := r.bind(t, gatewayKeys())
			if err != nil {
				return nil, err
			}
			io.WriteString(b, link.RelayPreamble+" "+key+"\n")
			return b, nil
		},
		DisableKeepAlives: true,
	}}
	e := r.open(t, key, server.LinkRunRequest{})
	resp, err := relayed.Get(o.URL)
	if err != nil {
		t.Fatalf("the proxy of the live run: %v", err)
	}
	resp.Body.Close()
	undo := gateway.HoldEnded(r.g, e.a.RunID)
	_, err = relayed.Get(o.URL)
	undo()
	if err == nil {
		t.Error("the proxy of a run that ended was answered")
	}
}

// TestBearer pins the scheme of a run key's Authorization: Bearer alone, in any case.
func TestBearer(t *testing.T) {
	for _, c := range []struct {
		values []string
		value  string
		ok     bool
	}{
		{[]string{"Bearer abc"}, "abc", true},
		{[]string{"bearer abc"}, "abc", true},
		{[]string{"Basic abc"}, "", false},
		{[]string{"Digest abc"}, "", false},
		{[]string{"Bearerabc"}, "", false},
		{[]string{"abc"}, "", false},
		{[]string{"Bearer abc", "Bearer abc"}, "", false},
		{nil, "", false},
	} {
		value, ok := gateway.Bearer(c.values)
		if ok != c.ok || ok && value != c.value {
			t.Errorf("%q: %q %v", c.values, value, ok)
		}
	}
}
