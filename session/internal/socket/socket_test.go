package socket_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
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

// capServer is a listener that collects the records and the bad-line errors it reads.
type capServer struct {
	t    *testing.T
	l    *socket.Listener
	mu   sync.Mutex
	got  []descriptor.Record
	bad  []error
	done chan struct{}
}

func newCapServer(t *testing.T) *capServer {
	t.Helper()
	l, err := socket.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	s := &capServer{t: t, l: l, done: make(chan struct{})}
	go func() {
		l.Serve(
			func(r descriptor.Record) { s.mu.Lock(); s.got = append(s.got, r); s.mu.Unlock() },
			func(err error) { s.mu.Lock(); s.bad = append(s.bad, err); s.mu.Unlock() })
		close(s.done)
	}()
	t.Cleanup(func() { l.Close(); <-s.done })
	return s
}

// connection writes data over one connection and closes it. The listener reads one
// connection at a time, so after Close a following connection's lines come after these.
func (s *capServer) connection(data string) {
	s.t.Helper()
	conn, err := net.Dial("unix", s.l.Path())
	if err != nil {
		s.t.Fatal(err)
	}
	conn.Write([]byte(data))
	conn.Close()
}

// wait blocks until the listener has handed on n records and nb errors, and returns
// copies of both.
func (s *capServer) wait(n, nb int) ([]descriptor.Record, []string) {
	s.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		ok := len(s.got) >= n && len(s.bad) >= nb
		s.mu.Unlock()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Let a late extra call show up before the counts are checked.
	time.Sleep(50 * time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []string
	for _, err := range s.bad {
		errs = append(errs, err.Error())
	}
	return append([]descriptor.Record(nil), s.got...), errs
}

func lines(n int, line string) string { return strings.Repeat(line+"\n", n) }

const (
	goodLine   = `{"source":"hooks","record":{"n":1}}`
	outputLine = `{"source":"output","record":{"type":"assistant"}}`
	// otherLine is valid JSON of an unknown source, which read reports as "not a record".
	otherLine = `{"source":"transcript","record":{}}`
)

// TestBadLinesOfOneConnectionAreCapped pins that one connection passes at most
// MaxBadLines bad lines to the bad function, then one summary with the count of the
// rest, and that records still reach handle after the cap.
func TestBadLinesOfOneConnectionAreCapped(t *testing.T) {
	max := socket.MaxBadLines
	summary := func(n int) string {
		return strconv.Itoa(n) + " more lines on one connection that are not records were skipped"
	}
	t.Run("under the cap", func(t *testing.T) {
		s := newCapServer(t)
		s.connection(lines(max-1, otherLine))
		_, bad := s.wait(0, max-1)
		if len(bad) != max-1 {
			t.Fatalf("errors: %q; want %d, no summary", bad, max-1)
		}
		for _, b := range bad {
			if !strings.HasPrefix(b, "not a record: ") {
				t.Errorf("error %q", b)
			}
		}
	})
	t.Run("exactly at the cap", func(t *testing.T) {
		s := newCapServer(t)
		s.connection(lines(max, "junk"))
		_, bad := s.wait(0, max)
		if len(bad) != max {
			t.Fatalf("errors: %q; want %d, no summary", bad, max)
		}
	})
	t.Run("over the cap", func(t *testing.T) {
		s := newCapServer(t)
		s.connection(lines(max+2481, "junk") + goodLine + "\n")
		got, bad := s.wait(1, max+1)
		if len(bad) != max+1 {
			t.Fatalf("%d errors, want %d: the first %d and one summary", len(bad), max+1, max)
		}
		if want := summary(2481); bad[max] != want {
			t.Errorf("summary %q, want %q", bad[max], want)
		}
		if len(got) != 1 || got[0].Source != "hooks" {
			t.Errorf("records after the cap: %+v, want the one good record", got)
		}
	})
	t.Run("the cap starts again for the next connection", func(t *testing.T) {
		s := newCapServer(t)
		s.connection(lines(max+3, "junk"))
		s.connection(lines(max+5, "junk"))
		_, bad := s.wait(0, 2*max+2)
		want := 2*max + 2
		if len(bad) != want {
			t.Fatalf("%d errors, want %d", len(bad), want)
		}
		if bad[max] != summary(3) || bad[2*max+1] != summary(5) {
			t.Errorf("summaries %q and %q, want 3 and 5 skipped", bad[max], bad[2*max+1])
		}
	})
	t.Run("output records count against the cap", func(t *testing.T) {
		s := newCapServer(t)
		s.connection(lines(max-2, "junk") + lines(5, outputLine) + lines(2, "junk"))
		_, bad := s.wait(0, max+1)
		if len(bad) != max+1 {
			t.Fatalf("%d errors, want %d", len(bad), max+1)
		}
		if want := summary(5); bad[max] != want {
			t.Errorf("summary %q, want %q", bad[max], want)
		}
		if !strings.HasPrefix(bad[max-2], "refused a record of the output source") {
			t.Errorf("error %d: %q, want the output refusal", max-2, bad[max-2])
		}
	})
	t.Run("a scanner error is reported apart from the count", func(t *testing.T) {
		s := newCapServer(t)
		// A line over the 16 MiB limit ends the scan with an error after the cap.
		s.connection(lines(max+4, "junk") + strings.Repeat("x", 17<<20))
		_, bad := s.wait(0, max+2)
		if len(bad) != max+2 {
			t.Fatalf("%d errors, want %d: %q", len(bad), max+2, bad)
		}
		if bad[max] != summary(4) || !strings.Contains(bad[max+1], "too long") {
			t.Errorf("summary %q and scanner error %q", bad[max], bad[max+1])
		}
	})
}
