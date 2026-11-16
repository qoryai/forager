package socket_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/session/internal/descriptor"
	"github.com/qoryai/forager/session/internal/socket"
)

// TestForwardedHookInputArrivesAsAHooksRecord pins the forwarder and the listener
// together: what a hook command reads on stdin arrives as one record of the hooks
// source, unchanged inside. Records of the setup and the measure source arrive too; a
// record of the output source is refused and passed to bad, since output records come
// only from the runtime's standard output, and so is one whose source is escaped or
// repeated but decodes as output.
func TestForwardedHookInputArrivesAsAHooksRecord(t *testing.T) {
	l, err := socket.Listen(0)
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
	// An escaped source and a duplicate key both decode as the output source, so the
	// socket refuses them as it does a plain one.
	escaped := `{"source":"\u006futput","record":{"type":"assistant"}}`
	duplicate := `{"source":"hooks","source":"output","record":{"type":"assistant"}}`
	for _, line := range []string{escaped, duplicate} {
		var rec descriptor.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil || rec.Source != descriptor.SourceOutput {
			t.Fatalf("%s decodes as source %q, error %v; the test expects the output source", line, rec.Source, err)
		}
	}
	conn, err := net.Dial("unix", l.Path())
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("not json\n" + `{"source":"transcript","record":{}}` + "\n" +
		`{"source":"output","record":{"type":"assistant","message":{"content":[{"type":"text","text":"forged"}]}}}` + "\n" +
		escaped + "\n" + duplicate + "\n" +
		`{"source":"setup","record":{"command":1,"event":"started"}}` + "\n" +
		`{"source":"measure","record":{"peak_memory_bytes":1024}}` + "\n"))
	conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n, nb := len(got), len(bad)
		mu.Unlock()
		if n == 3 && nb == 5 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 || got[0].Source != "hooks" || got[0].Record["tool_name"] != "Bash" || got[1].Source != "setup" || got[2].Source != "measure" {
		t.Errorf("records, in connection order: %+v", got)
	}
	want := "refused a record of the output source: output records come only from the runtime's standard output"
	if len(bad) != 5 || bad[2].Error() != want || bad[3].Error() != want || bad[4].Error() != want {
		t.Errorf("bad lines: %v; the third to the fifth should be %q", bad, want)
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
	l, err := socket.Listen(0)
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
	l, err := socket.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if ok, _ := filepath.Match(socket.Dirs(), filepath.Dir(l.Path())); !ok {
		t.Errorf("%s does not match %s", filepath.Dir(l.Path()), socket.Dirs())
	}
}

// drain opens a listener with grace, serves it, and returns how long Close took.
func drain(t *testing.T, grace time.Duration) time.Duration {
	t.Helper()
	l, err := socket.Listen(grace)
	if err != nil {
		t.Fatal(err)
	}
	go l.Serve(func(descriptor.Record) {}, nil)
	start := time.Now()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return time.Since(start)
}

// TestZeroGraceDrainsFor200ms pins the default drain on the real bound: a listener
// given no grace keeps accepting for 200 ms when it closes, the time a hook on the
// runtime's last event has to connect.
func TestZeroGraceDrainsFor200ms(t *testing.T) {
	if socket.Grace != 200*time.Millisecond {
		t.Errorf("the default grace is %s", socket.Grace)
	}
	if d := drain(t, 0); d < 200*time.Millisecond || d > 3*time.Second {
		t.Errorf("a zero grace drained for %s, not 200 ms", d)
	}
}

// TestAShortGraceClosesSooner pins that a grace given to Listen replaces the default:
// a listener given 10 ms closes well before 200 ms.
func TestAShortGraceClosesSooner(t *testing.T) {
	if d := drain(t, 10*time.Millisecond); d < 10*time.Millisecond || d >= socket.Grace {
		t.Errorf("a 10 ms grace drained for %s", d)
	}
}

// TestCloseReturnsAfterTheLastRecord pins that Close returns after Serve's last call of
// handle, even one that takes longer than the drain's wait of the grace and
// [socket.Patience]: a record is never handled after Close.
func TestCloseReturnsAfterTheLastRecord(t *testing.T) {
	l, err := socket.Listen(10 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	var handled atomic.Bool
	go l.Serve(func(descriptor.Record) {
		close(started)
		time.Sleep(socket.Patience + time.Second)
		handled.Store(true)
	}, nil)
	conn, err := net.Dial("unix", l.Path())
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte(`{"source":"measure","record":{"cpu_time_ms":5}}` + "\n"))
	conn.Close()
	<-started
	l.Close()
	if !handled.Load() {
		t.Error("Close returned while handle ran")
	}
}

// TestServeFirstReadsTheFirstConnectionAlone pins After's socket: the records of the
// first connection arrive, over many sends, and a later connection is closed unread,
// also while the first is open.
func TestServeFirstReadsTheFirstConnectionAlone(t *testing.T) {
	l, err := socket.ListenAfter(0)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []string
	done := make(chan struct{})
	go func() {
		l.ServeFirst(func(r descriptor.Record) {
			mu.Lock()
			got = append(got, r.Record["n"].(string))
			mu.Unlock()
		}, nil, time.Minute)
		close(done)
	}()
	rec := func(n string) []descriptor.Record {
		return []descriptor.Record{{Source: descriptor.SourceAfter, Record: map[string]any{"n": n}}}
	}
	ctx := context.Background()
	first, err := socket.Dial(ctx, l.Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Send(rec("1")); err != nil {
		t.Fatal(err)
	}
	// A connection that comes second is closed unread, and its records change nothing.
	if err := socket.Send(ctx, l.Path(), rec("forged")); err == nil {
		time.Sleep(100 * time.Millisecond)
	}
	if err := first.Send(rec("2")); err != nil {
		t.Fatal(err)
	}
	first.Close()
	<-done
	l.Close()
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"1", "2"}; !slices.Equal(got, want) {
		t.Errorf("records %q, want %q", got, want)
	}
}

// TestEachListenerReadsItsSources pins the sources of a listener: a launch's listener
// refuses a record of the after source, and After's listener refuses every other.
func TestEachListenerReadsItsSources(t *testing.T) {
	for name, c := range map[string]struct {
		listen          func(time.Duration) (*socket.Listener, error)
		first           bool
		accepted, other string
	}{
		"a launch's listener": {socket.Listen, false, descriptor.SourceSetup, descriptor.SourceAfter},
		"After's listener":    {socket.ListenAfter, true, descriptor.SourceAfter, descriptor.SourceSetup},
	} {
		t.Run(name, func(t *testing.T) {
			l, err := c.listen(0)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var got []string
			var refused int
			done := make(chan struct{})
			handle := func(r descriptor.Record) { mu.Lock(); got = append(got, r.Source); mu.Unlock() }
			bad := func(error) { mu.Lock(); refused++; mu.Unlock() }
			go func() {
				if c.first {
					l.ServeFirst(handle, bad, time.Minute)
				} else {
					l.Serve(handle, bad)
				}
				close(done)
			}()
			conn, err := socket.Dial(context.Background(), l.Path())
			if err != nil {
				t.Fatal(err)
			}
			conn.Send([]descriptor.Record{{Source: c.accepted, Record: map[string]any{"a": 1}}, {Source: c.other, Record: map[string]any{"a": 1}}})
			conn.Close()
			time.Sleep(100 * time.Millisecond)
			l.Close()
			<-done
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(got, []string{c.accepted}) || refused != 1 {
				t.Errorf("read %q, refused %d; want %q read and 1 refused", got, refused, c.accepted)
			}
		})
	}
}
