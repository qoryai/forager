//go:build linux || darwin

package gateway_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway"
)

// TestANamedPipeIsNoCertificateFile pins the read of a file that is not a regular file:
// a named pipe in place of the certificate fails Start at once, and renamed in later, it
// keeps the pair in force, is reported once, and the gateway still closes. Opened to be
// read, a named pipe without a writer would wait forever.
func TestANamedPipeIsNoCertificateFile(t *testing.T) {
	dir := t.TempDir()
	_, keyFile, _ := testCertificate(t, dir)
	pipe := filepath.Join(dir, "pipe.pem")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	started := make(chan error, 1)
	go func() {
		g, err := gateway.Start(context.Background(), gateway.Config{Dir: t.TempDir(), Listen: "127.0.0.1:0", TLS: &gateway.TLS{CertFile: pipe, KeyFile: keyFile}, Server: gatewayControl(t).server()})
		if g != nil {
			g.Close(context.Background())
		}
		started <- err
	}()
	select {
	case err := <-started:
		want := "the gateway's certificate " + pipe + " and key " + keyFile + ": " + pipe + " is not a regular file"
		if err == nil || err.Error() != want {
			t.Errorf("Start with a named pipe: %v; want %q", err, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Start with a named pipe as the certificate file did not return in 10 seconds")
	}

	cfg := gateway.Config{}
	gateway.SetCertCheck(&cfg, certCheckEvery)
	r := startRemote(t, nil, cfg)
	a := derOf(t, r.cfg.TLS.CertFile, r.cfg.TLS.KeyFile)
	if err := os.Rename(pipe, r.cfg.TLS.CertFile); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		time.Sleep(2 * certCheckEvery)
		if got := servedCertificate(t, r); !bytes.Equal(got, a) {
			t.Fatal("a handshake after a named pipe in place of the certificate does not get the pair in force")
		}
	}
	if n := failures(r); n != 1 {
		t.Errorf("the named pipe is reported in %d lines, want 1", n)
	}
	if want := "reading them failed, " + r.cfg.TLS.CertFile + " is not a regular file;"; !r.reported(want) {
		t.Errorf("no line contains %q", want)
	}
	closed := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		r.g.Close(ctx)
		cancel()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("the gateway did not close in 10 seconds")
	}
}
