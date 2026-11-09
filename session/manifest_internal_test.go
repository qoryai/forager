package session

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/refusal"
)

// TestUnreachableReadsTheErrorsType pins which failures of the check's requests are
// image_registry_unreachable, each read from the error's type: a CONNECT the run's
// proxy returned 502 to, a host name that does not resolve, a connection refused or
// reset, a TLS record that is not TLS, a certificate the check does not trust, and a
// timeout. A failed connection to the run's proxy itself, the client's proxyconnect
// wrapper around another CONNECT failure, the end of a connection and the caller's
// cancel are not.
func TestUnreachableReadsTheErrorsType(t *testing.T) {
	ctx := context.Background()
	_, dns := net.DefaultResolver.LookupHost(ctx, "registry.invalid")
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
	for name, c := range map[string]struct {
		err  error
		want bool
	}{
		"a CONNECT the run's proxy returned 502 to": {&net.OpError{Op: "proxyconnect", Net: "tcp", Err: &unreachedHost{hostport: "registry.example:443"}}, true},
		"a host name that does not resolve":         {dns, true},
		"a connection refused":                      {refused, true},
		"a connection reset":                        {&net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}, true},
		"a certificate the check does not trust":    {certificate, true},
		"a TLS record that is not TLS":              {record, true},
		"a read past its deadline":                  {deadline, true},
		"the check's time":                          {context.DeadlineExceeded, true},
		"a failed connection to the run's proxy":    {&net.OpError{Op: "proxyconnect", Net: "tcp", Err: &proxyDialError{err: refused}}, false},
		"another CONNECT failure":                   {&net.OpError{Op: "proxyconnect", Net: "tcp", Err: errors.New("Too Many Requests")}, false},
		"the end of a connection":                   {io.EOF, false},
		"the caller's cancel":                       {context.Canceled, false},
		"an error of no known type":                 {errors.New("unknown"), false},
	} {
		if c.err == nil {
			t.Errorf("%s: no error to read", name)
			continue
		}
		if got := unreachable(c.err); got != c.want {
			t.Errorf("%s (%v): unreachable %v, want %v", name, c.err, got, c.want)
		}
	}
}

// TestAFailureAfterTheCallersEndHasNoCode pins that a request that did not reach the
// registry is image_registry_unreachable only while the caller's context lasts: after
// its end, the error has today's text and no code.
func TestAFailureAfterTheCallersEndHasNoCode(t *testing.T) {
	cause := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	c := manifestCheck{host: "registry.example", image: "registry.example/agents/app:1"}
	var ref *accesskey.Refusal
	if err := c.failed(c.host, cause); !errors.As(err, &ref) || ref.Code != refusal.ImageRegistryUnreachable {
		t.Errorf("with no end: %v, want image_registry_unreachable", err)
	}
	c.ended = func() error { return context.Canceled }
	want := "Check that registry.example answers through the run's proxy: the check of the image registry.example/agents/app:1 at its registry failed (dial tcp: connect: connection refused)."
	if err := c.failed(c.host, cause); errors.As(err, &ref) || err.Error() != want {
		t.Errorf("after the caller's end: %v\nwant %s with no code", err, want)
	}
}
