package session

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/wall"
)

const (
	windowHop    = "hop-secret-0123456789abcdefghijklmnopqrstuv"
	windowNewHop = "hop-secret-9876543210abcdefghijklmnopqrstuv"
	windowSecret = "proxy-secret-0123456789abcdefghijklmnopqrst"
)

// dialListener dials the address of ln.
func dialListener(ln net.Listener) func(context.Context) (net.Conn, error) {
	var d net.Dialer
	return func(ctx context.Context) (net.Conn, error) { return d.DialContext(ctx, "tcp", ln.Addr().String()) }
}

// accepted dials f and returns the connection once f accepted it: once f lists one more
// connection waiting for its hop.
func accepted(t *testing.T, f *forwarder) net.Conn {
	t.Helper()
	f.mu.Lock()
	before := len(f.waiting)
	f.mu.Unlock()
	c, err := net.Dial("tcp", f.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	for deadline := time.Now().Add(5 * time.Second); ; {
		f.mu.Lock()
		n := len(f.waiting)
		f.mu.Unlock()
		if n > before {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatal("the forwarder did not accept the connection")
		}
		time.Sleep(time.Millisecond)
	}
}

// finish writes what on c and ends c's writing half.
func finish(c net.Conn, what string) {
	io.WriteString(c, what)
	c.(*net.TCPConn).CloseWrite()
}

// received waits until u got n connections' bytes, and returns them sorted.
func received(t *testing.T, u *upstream, n int) []string {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; {
		_, got := u.seen()
		if len(got) >= n {
			slices.Sort(got)
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("the proxy got %q, want %d connections", got, n)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestTheWindowStampsEachConnection pins the marking of the walled forwarder on one
// machine: a connection accepted and shown before mark goes on with the relay's
// preamble; one accepted before mark that shows the hop after it, and one accepted
// after it, go on with link.UnprivilegedPreamble; one accepted before swap that shows
// the old hop after it stays unprivileged; after swap a connection with the old hop is
// closed with nothing sent on, and one with the new hop goes on with the relay's
// preamble.
func TestTheWindowStampsEachConnection(t *testing.T) {
	up := startUpstream(t)
	f, err := listenForwarding("127.0.0.1:0", forwarding{dial: dialListener(up.ln), hop: windowHop, secret: windowSecret})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Each connection is served to its end before the next is dialled, so the count of
	// waiting connections that accepted reads changes by the next one alone.
	finish(accepted(t, f), link.RelayLine(windowHop)+"before")
	received(t, up, 1)
	early := accepted(t, f)
	f.mark()
	finish(early, link.RelayLine(windowHop)+"shown in the window")
	received(t, up, 2)
	finish(accepted(t, f), link.RelayLine(windowHop)+"in the window")
	received(t, up, 3)
	late := accepted(t, f)
	f.swap(windowNewHop)
	finish(late, link.RelayLine(windowHop)+"accepted in the window")
	received(t, up, 4)
	old := accepted(t, f)
	finish(old, link.RelayLine(windowHop)+"old hop after the swap")
	old.SetReadDeadline(time.Now().Add(5 * time.Second))
	// A close with unread bytes may come as a reset; only the deadline is no close.
	var ne net.Error
	if b, err := io.ReadAll(old); len(b) != 0 || (errors.As(err, &ne) && ne.Timeout()) {
		t.Errorf("the old hop after the swap got %q, %v", b, err)
	}
	finish(accepted(t, f), link.RelayLine(windowNewHop)+"after")

	want := []string{
		link.RelayLine(windowSecret) + "after",
		link.RelayLine(windowSecret) + "before",
		link.UnprivilegedLine(windowSecret) + "accepted in the window",
		link.UnprivilegedLine(windowSecret) + "in the window",
		link.UnprivilegedLine(windowSecret) + "shown in the window",
	}
	slices.Sort(want)
	if got := received(t, up, len(want)); !slices.Equal(got, want) {
		t.Errorf("the proxy got %q\nwant %q", got, want)
	}
	time.Sleep(100 * time.Millisecond)
	if opened, _ := up.seen(); opened != len(want) {
		t.Errorf("the proxy got %d connections, want %d", opened, len(want))
	}
}

// TestAnUnprivilegedConnectionSkipsTheCheck pins that a POST to the run API on an
// unprivileged connection goes on as it arrives, after link.UnprivilegedPreamble, with
// no call of the run's check, for the gateway's proxy to refuse.
func TestAnUnprivilegedConnectionSkipsTheCheck(t *testing.T) {
	up := startUpstream(t)
	k := &checkCalls{}
	f, err := listenForwarding("127.0.0.1:0", forwarding{dial: dialListener(up.ln), hop: windowHop, secret: windowSecret,
		check: &runAPICheck{check: k.check, runID: checkRunID}})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.mark()
	what := post(checkTarget("/artifacts"), "{}")
	finish(accepted(t, f), link.RelayLine(windowHop)+what)
	if got := received(t, up, 1); got[0] != link.UnprivilegedLine(windowSecret)+what {
		t.Errorf("the proxy got %q", got)
	}
	if len(k.got()) != 0 {
		t.Errorf("the check ran for an unprivileged connection: %v", k.got())
	}
}

// TestAnUnprivilegedConnectionDialsItsWayBehindAGateway pins the forwarder behind a
// separate gateway: an unprivileged connection goes through dialUnprivileged, and any
// other through dial.
func TestAnUnprivilegedConnectionDialsItsWayBehindAGateway(t *testing.T) {
	relay, step := startUpstream(t), startUpstream(t)
	f, err := listenForwarding("127.0.0.1:0", forwarding{dial: dialListener(relay.ln), dialUnprivileged: dialListener(step.ln), hop: windowHop})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	finish(accepted(t, f), link.RelayLine(windowHop)+"agent")
	received(t, relay, 1)
	f.mark()
	finish(accepted(t, f), link.RelayLine(windowHop)+"step")
	if got := received(t, step, 1); got[0] != "step" {
		t.Errorf("dialUnprivileged got %q", got)
	}
	if _, got := relay.seen(); len(got) != 1 || got[0] != "agent" {
		t.Errorf("dial got %q", got)
	}
}

// restarter is an enclosure whose RestartRelay records each token and fails while fail
// is set.
type restarter struct {
	wall.Enclosure
	tokens []string
	fail   error
}

func (s *restarter) RestartRelay(_ context.Context, l wall.Launch) error {
	s.tokens = append(s.tokens, l.ProxyToken)
	return s.fail
}

// TestTheWindowEndsWithOneRestart pins endWindow: nothing without a window; one restart
// per window, with the forwarder's new hop, which becomes the relay's token, however many
// times the window opened; a restart that fails is the error and leaves the window to
// end, with the forwarder already on a new hop, so the next call restarts again.
func TestTheWindowEndsWithOneRestart(t *testing.T) {
	up := startUpstream(t)
	f, err := listenForwarding("127.0.0.1:0", forwarding{dial: dialListener(up.ln), hop: windowHop, secret: windowSecret})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := &restarter{}
	r := &Run{enclosure: enc, wallFwd: f, relayToken: windowHop}
	ctx := context.Background()
	if err := r.endWindow(ctx); err != nil || len(enc.tokens) != 0 {
		t.Fatalf("no window: %v, %d restarts", err, len(enc.tokens))
	}
	r.openWindow()
	r.openWindow()
	if !f.marking {
		t.Fatal("the forwarder does not mark in the window")
	}
	if err := r.endWindow(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.endWindow(ctx); err != nil {
		t.Fatal(err)
	}
	if len(enc.tokens) != 1 || enc.tokens[0] != f.way.hop || r.relayToken != f.way.hop || f.way.hop == windowHop || f.marking {
		t.Fatalf("after one window: restarts %d, the forwarder's hop changed %v, marking %v", len(enc.tokens), f.way.hop != windowHop, f.marking)
	}
	r.openWindow()
	enc.fail = errors.New("docker start: told to fail")
	if err := r.endWindow(ctx); err == nil || !strings.HasPrefix(err.Error(), "Run the join again, or close the run") {
		t.Fatalf("a failed restart: %v", err)
	}
	if !r.windowed || f.way.hop != enc.tokens[1] {
		t.Fatal("a failed restart ended the window, or left the old hop")
	}
	enc.fail = nil
	if err := r.endWindow(ctx); err != nil || len(enc.tokens) != 3 || r.windowed {
		t.Fatalf("the retry: %v, %d restarts", err, len(enc.tokens))
	}
}

// TestAnUnprivilegedConnectionSkipsTheRoute pins that a request to the route's host on an
// unprivileged connection never reaches the caller's handler: the forwarder reads the
// relay's peer line and passes the request on to the proxy after
// link.UnprivilegedPreamble, whose 403 the program gets.
func TestAnUnprivilegedConnectionSkipsTheRoute(t *testing.T) {
	h := &routeHandler{answer: func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "routed") }}
	q, _, _ := routeFor(t, h)
	p := startRouteProxy(t)
	f := walledRoute(t, p, q)
	f.mark()
	resp, body := replyOf(t, relaySend(t, f, toRoute("POST", "/push", "{}")))
	if resp.StatusCode != http.StatusForbidden || body != "denied" || len(h.got()) != 0 {
		t.Errorf("the program got %d %q; the handler got %d calls", resp.StatusCode, body, len(h.got()))
	}
	if got := p.requests(); len(got) != 1 || !strings.HasPrefix(got[0], link.UnprivilegedPreamble+" ") {
		t.Errorf("the proxy got %q", got)
	}
}
