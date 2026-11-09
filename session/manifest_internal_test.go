package session

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/refusal"
)

// TestUnreachableReadsTheErrorsType pins which failures of the check's requests are
// image_registry_unreachable, each read from the error's type, in the shapes the client
// returns them: a CONNECT the run's proxy returned 502 to, a host name that does not
// resolve, a connection refused or reset on the tunnel, a TLS record that is not TLS, a
// certificate the check does not trust, and a timeout. A failed dial of the run's
// proxy, a read or write on the connection to the proxy before its tunnel opened,
// another status of a CONNECT, the end of a connection and the caller's cancel are not.
// No case sends a DNS query or leaves loopback.
func TestUnreachableReadsTheErrorsType(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	ln.Close()
	_, refused := net.Dial("tcp", closed)
	untrusted := httptest.NewTLSServer(http.NotFoundHandler())
	defer untrusted.Close()
	_, certificate := tls.Dial("tcp", untrusted.Listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS12})
	plain := httptest.NewServer(http.NotFoundHandler())
	defer plain.Close()
	// The server is not TLS, so the handshake fails before any certificate is read.
	_, record := tls.Dial("tcp", plain.Listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true})
	c, err := net.Dial("tcp", plain.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(-time.Second))
	_, deadline := c.Read(make([]byte, 1))
	dns := &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "registry.invalid", IsNotFound: true}}
	reset := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
	// do is the error of the client's Do, which wraps every failure of a request.
	do := func(err error) error { return &url.Error{Op: "Head", URL: "https://registry.example/v2/", Err: err} }
	for name, c := range map[string]struct {
		err  error
		want bool
	}{
		"a CONNECT the run's proxy returned 502 to":             {do(&unreachedHost{hostport: "registry.example:443"}), true},
		"a host name that does not resolve":                     {do(dns), true},
		"a connection refused":                                  {do(refused), true},
		"a connection reset on the tunnel":                      {do(reset), true},
		"a certificate the check does not trust":                {do(certificate), true},
		"a TLS record that is not TLS":                          {do(record), true},
		"a read past its deadline":                              {do(deadline), true},
		"the check's time":                                      {do(context.DeadlineExceeded), true},
		"a failed dial of the run's proxy":                      {do(&net.OpError{Op: "proxyconnect", Net: "tcp", Err: &proxyConnError{err: refused}}), false},
		"a reset on the connection to the run's proxy":          {do(&proxyConnError{err: reset}), false},
		"a timeout on the connection to the run's proxy":        {do(&proxyConnError{err: deadline}), false},
		"another status of a CONNECT, as the client returns it": {do(errors.New("Too Many Requests")), false},
		"the end of a connection":                               {do(io.EOF), false},
		"the caller's cancel":                                   {do(context.Canceled), false},
		"an error of no known type":                             {do(errors.New("unknown")), false},
	} {
		if errors.Unwrap(c.err) == nil {
			t.Errorf("%s: no error to read", name)
			continue
		}
		if got := unreachable(c.err); got != c.want {
			t.Errorf("%s (%v): unreachable %v, want %v", name, c.err, got, c.want)
		}
	}
}

// fakeProxy is a listener on loopback that hands each connection to serve, after it read
// the request's head, and closes the connection when serve returns.
func fakeProxy(t *testing.T, serve func(c *net.TCPConn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if _, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
					serve(c.(*net.TCPConn))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// resetConn closes c with a TCP reset.
func resetConn(c *net.TCPConn) {
	c.SetLinger(0)
	c.Close()
}

// testCheck is a check of registry.example/agents/app by digest whose client dials the
// run's proxy with dial.
func testCheck(dial func(context.Context) (net.Conn, error)) manifestCheck {
	digest := "sha256:" + strings.Repeat("b2", 32)
	return manifestCheck{client: manifestHTTPClient(dial, x509.NewCertPool()), host: "registry.example", repository: "agents/app", digest: digest,
		image: "registry.example/agents/app@" + digest, held: func() heldCredentials { return heldCredentials{} }}
}

// dialTo is a dial of the run's proxy at addr.
func dialTo(addr string) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

// TestAResetIsTheRegistrysOnlyOnTheTunnel pins a connection reset through the client of
// the check: before the run's proxy returned 200 to the CONNECT, the reset is on the
// connection to the proxy, an error with today's text and no code; after it, the
// reset is on the tunnel to the registry, image_registry_unreachable.
func TestAResetIsTheRegistrysOnlyOnTheTunnel(t *testing.T) {
	ctx := context.Background()
	before := fakeProxy(t, resetConn)
	after := fakeProxy(t, func(c *net.TCPConn) {
		io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		c.Read(make([]byte, 1))
		resetConn(c)
	})
	var ref *accesskey.Refusal
	err := testCheck(dialTo(before)).check(ctx)
	if errors.As(err, &ref) || err == nil || !strings.HasPrefix(err.Error(), "Check that registry.example answers through the run's proxy: ") {
		t.Errorf("a reset before the CONNECT returned: %v, want today's text with no code", err)
	}
	err = testCheck(dialTo(after)).check(ctx)
	if !errors.As(err, &ref) || ref.Code != refusal.ImageRegistryUnreachable {
		t.Errorf("a reset on the tunnel: %v, want image_registry_unreachable", err)
	}
}

// TestAHungDialOfTheProxyHasNoCode pins the check's time with the run's proxy: a dial of
// the proxy that does not open within it is an error with no code, since the fix is at
// the gateway; a CONNECT the proxy holds with no status until then, as while it dials a
// registry that does not respond, is image_registry_unreachable.
func TestAHungDialOfTheProxyHasNoCode(t *testing.T) {
	defer func(d time.Duration) { manifestWait = d }(manifestWait)
	manifestWait = 200 * time.Millisecond
	ctx := context.Background()
	hung := func(ctx context.Context) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var ref *accesskey.Refusal
	if err := testCheck(hung).check(ctx); err == nil || errors.As(err, &ref) {
		t.Errorf("a hung dial of the run's proxy: %v, want an error with no code", err)
	}
	holding := fakeProxy(t, func(c *net.TCPConn) { c.Read(make([]byte, 1)) })
	want := "Check that the run's proxy reaches registry.example within 200ms: the check of the image registry.example/agents/app@sha256:" + strings.Repeat("b2", 32) + " at its registry timed out"
	if err := testCheck(dialTo(holding)).check(ctx); !errors.As(err, &ref) || ref.Code != refusal.ImageRegistryUnreachable || ref.Detail != want {
		t.Errorf("a CONNECT held with no status: %v, want image_registry_unreachable with the detail %s", err, want)
	}
}

// TestAFailureAfterTheCallersEndHasNoCode pins that a request that did not reach the
// registry is image_registry_unreachable only while the caller's context lasts: after
// its end, the error has today's text and no code.
func TestAFailureAfterTheCallersEndHasNoCode(t *testing.T) {
	cause := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	c := manifestCheck{host: "registry.example", image: "registry.example/agents/app:1"}
	var ref *accesskey.Refusal
	if err := c.failed(context.Background(), c.host, cause); !errors.As(err, &ref) || ref.Code != refusal.ImageRegistryUnreachable {
		t.Errorf("with no end: %v, want image_registry_unreachable", err)
	}
	c.ended = func() error { return context.Canceled }
	want := "Check that registry.example answers through the run's proxy: the check of the image registry.example/agents/app:1 at its registry failed (dial tcp: connect: connection refused)."
	if err := c.failed(context.Background(), c.host, cause); errors.As(err, &ref) || err.Error() != want {
		t.Errorf("after the caller's end: %v\nwant %s with no code", err, want)
	}
}
