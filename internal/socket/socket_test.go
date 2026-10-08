package socket_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/runner/internal/descriptor"
	"github.com/qoryai/runner/internal/socket"
)

// TestForwardedHookInputArrivesAsAHooksRecord pins the forwarder and the listener
// together: what a hook command reads on stdin arrives as one record of the hooks
// source, unchanged inside.
func TestForwardedHookInputArrivesAsAHooksRecord(t *testing.T) {
	l, err := socket.Listen()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []descriptor.Record
	var bad []error
	done := make(chan struct{})
	go func() {
		l.Serve(func(r descriptor.Record) { mu.Lock(); got = append(got, r); mu.Unlock() }, func(err error) { mu.Lock(); bad = append(bad, err); mu.Unlock() })
		close(done)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := socket.Forward(ctx, l.Path(), strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`)); err != nil {
		t.Fatal(err)
	}
	if err := socket.Forward(ctx, l.Path(), strings.NewReader(`[1,2]`)); err == nil {
		t.Error("a non-object was forwarded")
	}
	conn, err := net.Dial("unix", l.Path())
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("not json\n" + `{"source":"transcript","record":{}}` + "\n" + `{"source":"output","record":{"type":"result"}}` + "\n"))
	conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n, nb := len(got), len(bad)
		mu.Unlock()
		if n == 2 && nb == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[0].Source != "hooks" || got[0].Record["tool_name"] != "Bash" || got[1].Source != "output" {
		t.Errorf("records, in connection order: %+v", got)
	}
	if len(bad) != 2 {
		t.Errorf("bad lines: %v", bad)
	}
	dir := l.Path()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	<-done
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("the socket was not removed")
	}
}

// TestTheVariableIsAnAddress pins that the forwarder reads its variable as an address:
// a path and unix: with a path are the local socket, and a scheme it does not have is
// refused by name, so a transport can be added without an old forwarder opening a file
// called tcp:relay:1.
func TestTheVariableIsAnAddress(t *testing.T) {
	l, err := socket.Listen()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	n := 0
	go l.Serve(func(descriptor.Record) { mu.Lock(); n++; mu.Unlock() }, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := socket.Forward(ctx, "unix:"+l.Path(), strings.NewReader(`{"a":1}`)); err != nil {
		t.Error(err)
	}
	if err := socket.Forward(ctx, "tcp:qory-proxy:3129", strings.NewReader(`{"a":1}`)); err == nil || !strings.Contains(err.Error(), `"tcp"`) {
		t.Errorf("a transport this forwarder does not have: %v", err)
	}
	l.Close()
	mu.Lock()
	defer mu.Unlock()
	if n != 1 {
		t.Errorf("%d records arrived", n)
	}
}

// TestDirsMatchesWhatListenMakes pins that the pattern of the runs' private directories
// matches the one Listen makes.
func TestDirsMatchesWhatListenMakes(t *testing.T) {
	l, err := socket.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if ok, _ := filepath.Match(socket.Dirs(), filepath.Dir(l.Path())); !ok {
		t.Errorf("%s does not match %s", filepath.Dir(l.Path()), socket.Dirs())
	}
}
