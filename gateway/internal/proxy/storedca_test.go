package proxy_test

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// TestOpenCA pins a gateway's own authority: made once, its directory 0700 and its file
// 0600; read again, the same, by every later open, and by opens at once; refused in a
// directory or a file another user may reach, or through a link.
func TestOpenCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "authority", "ca.pem")
	var wg sync.WaitGroup
	got := make([][]byte, 8)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ca, err := proxy.OpenCA(path)
			if err != nil {
				t.Error(err)
				return
			}
			got[i] = ca.PEM()
		}()
	}
	wg.Wait()
	for _, b := range got {
		if !bytes.Equal(b, got[0]) || !strings.HasPrefix(string(b), "-----BEGIN CERTIFICATE-----") {
			t.Fatalf("opens at once made two authorities")
		}
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the file %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the directory %v %v", fi, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("the directory holds %d files", len(entries))
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "PRIVATE KEY") {
		t.Error("the file holds no key")
	}
	ca, err := proxy.OpenCA(path)
	if err != nil || !bytes.Equal(ca.PEM(), got[0]) {
		t.Errorf("again: %v", err)
	}
	if ca, err := proxy.NewCA("r"); err != nil || bytes.Equal(ca.PEM(), got[0]) {
		t.Errorf("a run's authority: %v", err)
	}

	os.Chmod(filepath.Dir(path), 0o750)
	if _, err := proxy.OpenCA(path); err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Errorf("a directory open to the group: %v", err)
	}
	os.Chmod(filepath.Dir(path), 0o700)
	linked := filepath.Join(filepath.Dir(path), "link.pem")
	if err := os.Symlink(path, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := proxy.OpenCA(linked); err == nil {
		t.Error("a link was read")
	}
	os.WriteFile(path, append(b, b...), 0o600)
	if _, err := proxy.OpenCA(path); err == nil {
		t.Error("two authorities in one file were read")
	}
}

// TestAListenerServesAConnectionHandedOver pins a connection another listener accepted:
// its preamble is read as the listener's own, and with guardedOnly a run whose proxy
// is not guarded is none; Lookup finds a run by its secret the same way.
func TestAListenerServesAConnectionHandedOver(t *testing.T) {
	r := newReports()
	l := newListener(t, r)
	open, guarded := newRun(t, policy.Observe, nil, func(proxy.Decision) {}), newRun(t, policy.Observe, nil, func(proxy.Decision) {})
	guarded.Guard(nil)
	so, sg := secret(t), secret(t)
	if err := l.Register(so, open); err != nil {
		t.Fatal(err)
	}
	if err := l.Register(sg, guarded); err != nil {
		t.Fatal(err)
	}
	if l.Lookup(so, false) != open || l.Lookup(so, true) != nil || l.Lookup(sg, true) != guarded || l.Lookup(strings.Repeat("x", len(so)), false) != nil {
		t.Error("Lookup")
	}
	serve := func(secret string, guardedOnly bool) string {
		client, served := net.Pipe()
		defer client.Close()
		l.Serve(served, guardedOnly)
		go client.Write([]byte(link.Preamble(link.RelayPreamble, secret) + "GET http://localhost:1/ HTTP/1.1\r\nHost: localhost:1\r\nConnection: close\r\n\r\n"))
		var b bytes.Buffer
		buf := make([]byte, 64)
		n, _ := client.Read(buf)
		b.Write(buf[:n])
		return b.String()
	}
	// The guarded proxy refuses loopback itself: it was reached.
	if got := serve(sg, true); !strings.HasPrefix(got, "HTTP/1.1 403") {
		t.Errorf("the guarded run: %q", got)
	}
	if got := serve(so, true); got != "" {
		t.Errorf("an unguarded run, guarded only: %q", got)
	}
	if got := serve(so, false); !strings.HasPrefix(got, "HTTP/1.1") {
		t.Errorf("an unguarded run: %q", got)
	}
}
