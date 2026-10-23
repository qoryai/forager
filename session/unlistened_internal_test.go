package session

import (
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

// TestAnEngineProxyThatCannotListenHasTheFixOfItsCause pins unlistened: an address in
// use, as a listener of the test's makes it, has the fix of one image step or engine
// proxy at a time; a port this user may not listen at and an address the machine does
// not have, as net.Listen returns them, have the fix about the address.
func TestAnEngineProxyThatCannotListenHasTheFixOfItsCause(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	addr := taken.Addr().String()
	_, inUse := net.Listen("tcp", addr)
	if inUse == nil {
		t.Fatalf("a second listener at %s", addr)
	}
	listenErr := func(errno syscall.Errno) error {
		return &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", errno)}
	}
	for _, c := range []struct {
		name string
		err  error
		fix  string
	}{
		{"an address in use", inUse, "Run one image step or engine proxy at a time on this machine: "},
		{"a port this user may not listen at", listenErr(syscall.EACCES), "Set the engine proxy's address to one this user can listen at: "},
		{"an address the machine does not have", listenErr(syscall.EADDRNOTAVAIL), "Set the engine proxy's address to one this user can listen at: "},
	} {
		got := unlistened(addr, c.err).Error()
		if !strings.HasPrefix(got, c.fix) || !strings.Contains(got, "cannot listen at "+addr+" (") {
			t.Errorf("%s: %s, want the fix %q", c.name, got, c.fix)
		}
	}
}
