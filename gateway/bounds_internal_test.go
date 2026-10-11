package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/server"
)

// TestTheSourceOfAnAddress pins the source a connection counts against: an IPv4
// address alone, an IPv4 address mapped into IPv6 as that address, and an IPv6 address's
// /64, whatever its zone, with its /48 beside it.
func TestTheSourceOfAnAddress(t *testing.T) {
	for _, c := range []struct{ a, b string }{
		{"192.0.2.1:1", "192.0.2.1:2"},
		{"192.0.2.1:1", "[::ffff:192.0.2.1]:2"},
		{"[2001:db8::1]:1", "[2001:db8::ffff:ffff:ffff:ffff]:2"},
		{"[fe80::1%en0]:1", "[fe80::2%en1]:2"},
	} {
		if addressSource(c.a) != addressSource(c.b) || src(c.a) != src(c.b) {
			t.Errorf("%s and %s are %v and %v", c.a, c.b, src(c.a), src(c.b))
		}
	}
	for _, c := range []struct{ a, b string }{
		{"192.0.2.1:1", "192.0.2.2:1"},
		{"[2001:db8::1]:1", "[2001:db8:0:1::1]:1"},
	} {
		if addressSource(c.a) == addressSource(c.b) || src(c.a).key == src(c.b).key {
			t.Errorf("%s and %s are both %v", c.a, c.b, src(c.a))
		}
	}
	if a, b := src("[2001:db8::1]:1"), src("[2001:db8:0:ffff::1]:1"); a.block != b.block || a.block != "2001:db8::/48" {
		t.Errorf("two /64s of 2001:db8::/48 are of %q and %q", a.block, b.block)
	}
	if a, b := src("[2001:db8::1]:1"), src("[2001:db8:1::1]:1"); a.block == b.block {
		t.Errorf("two /48s are both %q", a.block)
	}
	if b := src("192.0.2.1:1").block; b != "" {
		t.Errorf("an IPv4 address is of the block %q", b)
	}
	if got := sourceOf(&net.TCPAddr{IP: net.ParseIP("2001:db8::7"), Port: 9}); got != src("[2001:db8::1]:1") {
		t.Errorf("a TCP address of 2001:db8::/64 is %v", got)
	}
}

// src is what a connection from addr, host:port, counts against.
func src(addr string) connSource {
	return sourceOf(&net.TCPAddr{IP: net.IP(netip.MustParseAddrPort(addr).Addr().AsSlice()), Port: 1, Zone: netip.MustParseAddrPort(addr).Addr().Zone()})
}

// TestTheConnectionLimit pins the connections the one address counts: at most each of
// one source, at most block of one IPv6 /48, at most most in all. Past a bound, the
// oldest connection no run key vouched for of the narrowest full group, the source, else
// the /48, else all, is closed and let go of, and the new one taken; one vouched for is
// counted but never closed, and with none to close the new one is refused. One let go
// of is one more taken.
func TestTheConnectionLimit(t *testing.T) {
	l := newConnLimit(7, 2, 3)
	var closed []string
	take := func(name, addr string) *connSlot {
		t.Helper()
		cs := &connSlot{s: src(addr), c: closeFunc(func() { closed = append(closed, name) })}
		if !l.take(cs) {
			return nil
		}
		return cs
	}
	wantClosed := func(what string, want ...string) {
		t.Helper()
		if !reflect.DeepEqual(closed, want) {
			t.Errorf("%s: closed %q; want %q", what, closed, want)
		}
		closed = nil
	}
	a1, a2 := take("a1", "[2001:db8::1]:1"), take("a2", "[2001:db8::2]:1")
	if a1 == nil || a2 == nil {
		t.Fatal("the first two of a source are not taken")
	}
	a3 := take("a3", "[2001:db8::3]:1")
	if a3 == nil {
		t.Fatal("a third connection of one /64 is not taken")
	}
	wantClosed("a third connection of one /64", "a1")
	l.vouch(a2)
	a4 := take("a4", "[2001:db8::4]:1")
	if a4 == nil {
		t.Fatal("a fourth connection of one /64 is not taken")
	}
	wantClosed("a fourth connection of one /64 beside one vouched for", "a3")
	l.vouch(a4)
	if take("a5", "[2001:db8::5]:1") != nil {
		t.Error("a connection of a /64 whose connections are all vouched for is taken")
	}
	wantClosed("a connection of a /64 whose connections are all vouched for")
	b1 := take("b1", "[2001:db8:0:1::1]:1")
	if b1 == nil {
		t.Fatal("a third connection of one /48 is not taken")
	}
	b2 := take("b2", "[2001:db8:0:2::1]:1")
	if b2 == nil {
		t.Fatal("a fourth connection of one /48 is not taken")
	}
	wantClosed("a fourth connection of one /48", "b1")
	l.vouch(b2)
	if take("b3", "[2001:db8:0:3::1]:1") != nil {
		t.Error("a connection of a /48 whose connections are all vouched for is taken")
	}
	wantClosed("a connection of a /48 whose connections are all vouched for")
	c1 := take("c1", "[2001:db8:1::1]:1")
	if c1 == nil {
		t.Error("a connection of another /48 is not taken")
	}
	var v []*connSlot
	for i := range 3 {
		cs := take(fmt.Sprintf("v%d", i+1), fmt.Sprintf("192.0.2.%d:1", i+1))
		if cs == nil {
			t.Fatalf("connection %d in all is not taken", i+5)
		}
		v = append(v, cs)
	}
	wantClosed("seven connections in all")
	w := take("w", "192.0.2.9:1")
	if w == nil {
		t.Fatal("an eighth connection in all is not taken")
	}
	wantClosed("an eighth connection in all", "c1")
	l.give(c1)
	if l.total != 7 {
		t.Errorf("a connection closed for a newer one, let go of again: %d counted", l.total)
	}
	l.give(v[0])
	x := take("x", "192.0.2.10:1")
	if x == nil {
		t.Fatal("a connection let go of is not one more taken")
	}
	wantClosed("a connection let go of, one more taken")
	if l.total != 7 || len(l.by) != 6 || l.by["2001:db8::/64"] != 2 || l.blocks["2001:db8::/48"] != 3 || l.blocks["2001:db8:1::/48"] != 0 {
		t.Errorf("counted %d in all, by %v, by /48 %v", l.total, l.by, l.blocks)
	}
	for _, cs := range []*connSlot{v[1], v[2], w, x} {
		l.vouch(cs)
	}
	if take("y", "192.0.2.11:1") != nil {
		t.Error("a connection past the bound in all, all of them vouched for, is taken")
	}
	wantClosed("a connection past the bound in all, all of them vouched for")
	if l.total != 7 || l.waiting.Len() != 0 || len(l.waitingBy) != 0 || len(l.waitingBlocks) != 0 {
		t.Errorf("counted %d, waiting %d, by %v, by /48 %v", l.total, l.waiting.Len(), l.waitingBy, l.waitingBlocks)
	}

	// Admitted, closed, vouched for, or any of these in any order, a connection is let go
	// of once.
	a := src("[2001:db8::1]:1")
	for _, steps := range [][]string{{"admit"}, {"close"}, {"admit", "close"}, {"close", "admit"}, {"close", "close", "admit", "admit"}, {"vouch", "close"}, {"vouch", "admit", "vouch"}, {"close", "vouch"}} {
		l := newConnLimit(1, 1, 1)
		c := l.hold(nopConn{}, a)
		if c == nil {
			t.Fatal("a first connection is not taken")
		}
		for _, s := range steps {
			switch s {
			case "admit":
				c.admit()
			case "vouch":
				c.vouch()
			default:
				c.Close()
			}
		}
		if l.total != 0 || len(l.by) != 0 || len(l.blocks) != 0 || l.waiting.Len() != 0 || len(l.waitingBy) != 0 || len(l.waitingBlocks) != 0 {
			t.Errorf("%v: %d counted, by %v, by /48 %v, %d waiting", steps, l.total, l.by, l.blocks, l.waiting.Len())
		}
	}
	// The narrowest full group, not all, gives the connection closed: "o", the oldest of
	// all, stays while a full /64, then a full /48, closes its own oldest; a /64 whose
	// connections are all vouched for closes nothing; and with both a source and all
	// full, the source's oldest goes.
	l = newConnLimit(6, 2, 3)
	o := take("o", "192.0.2.1:1")
	p1, p2 := take("p1", "[2001:db8::1]:1"), take("p2", "[2001:db8::2]:1")
	if o == nil || p1 == nil || p2 == nil {
		t.Fatal("the first connections are not taken")
	}
	p3 := take("p3", "[2001:db8::3]:1")
	if p3 == nil {
		t.Fatal("a third connection of one /64 is not taken")
	}
	wantClosed("a third connection of one /64, the oldest of all of another source", "p1")
	l.vouch(p2)
	l.vouch(p3)
	if take("p4", "[2001:db8::4]:1") != nil {
		t.Error("a connection of a /64 whose connections are all vouched for is taken")
	}
	wantClosed("a connection of a /64 whose connections are all vouched for, beside others waiting")
	if take("q1", "[2001:db8:0:1::1]:1") == nil || take("q2", "[2001:db8:0:2::1]:1") == nil {
		t.Fatal("a third or a fourth connection of one /48 is not taken")
	}
	wantClosed("a fourth connection of one /48, the oldest of all of another source", "q1")
	if take("s1", "192.0.2.4:1") == nil || take("s2", "192.0.2.4:2") == nil {
		t.Fatal("two connections of an IPv4 address are not taken")
	}
	wantClosed("six connections in all")
	if l.total != 6 || l.by["192.0.2.4"] != 2 {
		t.Fatalf("counted %d in all, by %v", l.total, l.by)
	}
	if take("s3", "192.0.2.4:3") == nil {
		t.Fatal("a third connection of an IPv4 address, all full, is not taken")
	}
	wantClosed("a third connection of an IPv4 address, all full", "s1")

	// A held connection closed for a newer one is closed, and closing it again lets go of
	// nothing more.
	l = newConnLimit(1, 1, 1)
	first := &closedConn{}
	h := l.hold(first, a)
	if h == nil || l.hold(&closedConn{}, a) == nil {
		t.Fatal("a connection is not taken")
	}
	if !first.closed {
		t.Error("the oldest connection is not closed for a newer one")
	}
	h.Close()
	if l.total != 1 || l.waiting.Len() != 1 {
		t.Errorf("a connection closed for a newer one, closed again: %d counted, %d waiting", l.total, l.waiting.Len())
	}
}

// closeFunc is a closer that calls itself.
type closeFunc func()

func (f closeFunc) Close() error {
	f()
	return nil
}

// nopConn is a connection that does nothing.
type nopConn struct{ net.Conn }

func (nopConn) Close() error { return nil }

// closedConn is a connection that does nothing but say it was closed.
type closedConn struct {
	net.Conn
	closed bool
}

func (c *closedConn) Close() error {
	c.closed = true
	return nil
}

// TestTheRelaysBuckets pins the relay's buckets: by the connection's source, an IPv6
// /64 one bucket whatever the request's fields say, and by its IPv6 /48 a bucket of 240
// a minute in bursts of 80 beside it, none for IPv4; at most 256 sources of one /48
// followed, a new one past that letting go of the one of that /48 idle longest; a full
// map letting go of the source idle longest for a new one; and buckets let go of when
// they are full again, by prune, a /48's with its last source.
func TestTheRelaysBuckets(t *testing.T) {
	buckets := func() *relay {
		return &relay{g: &Gateway{conf: &server.Configuration{Run: &server.Endpoint{URL: "https://apiary.example/v1/runs"}}},
			sources: map[string]*relaySource{}, blocks: map[string]*relayBlock{}}
	}
	rl := buckets()
	serve := func(remote string, i int) int {
		req := httptest.NewRequest(http.MethodGet, "/nothing", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i))
		w := httptest.NewRecorder()
		rl.ServeHTTP(w, req)
		return w.Code
	}
	for i := range relayBurst {
		if got := serve(fmt.Sprintf("[2001:db8::%x]:1", i+1), i); got != http.StatusNotFound {
			t.Fatalf("request %d of one /64: %d", i+1, got)
		}
	}
	if got := serve("[2001:db8::ffff]:1", 99); got != http.StatusTooManyRequests {
		t.Errorf("request %d of one /64: %d", relayBurst+1, got)
	}
	if got := serve("[2001:db8:0:1::1]:1", 99); got != http.StatusNotFound {
		t.Errorf("another /64: %d", got)
	}

	// One /48's burst, from as many /64s; a quarter of a minute later a quarter of its
	// rate.
	now := time.Now()
	rl = buckets()
	sixtyFour := func(i int) connSource { return src(fmt.Sprintf("[2001:db8:0:%x::1]:1", i)) }
	for i := range relayBlockBurst {
		if !rl.allow(sixtyFour(i), now) {
			t.Fatalf("request %d of one /48 is refused", i+1)
		}
	}
	if rl.allow(sixtyFour(relayBlockBurst), now) {
		t.Errorf("request %d of one /48 is allowed", relayBlockBurst+1)
	}
	if !rl.allow(src("[2001:db8:1::1]:1"), now) || !rl.allow(src("192.0.2.1:1"), now) {
		t.Error("another /48, or an IPv4 address, is refused")
	}
	later := now.Add(time.Minute / 4)
	for i := range relayBlockPerMinute / 4 {
		if !rl.allow(sixtyFour(100+i), later) {
			t.Fatalf("request %d of one /48 a quarter of a minute later is refused", i+1)
		}
	}
	if rl.allow(sixtyFour(200), later) {
		t.Errorf("request %d of one /48 a quarter of a minute later is allowed", relayBlockPerMinute/4+1)
	}
	// IPv4 addresses of one /24 have no bucket of the /24.
	for i := range relayBlockBurst + 1 {
		if !rl.allow(src(fmt.Sprintf("198.51.100.%d:1", i+1)), now) {
			t.Fatalf("IPv4 address %d of one /24 is refused", i+1)
		}
	}

	// At most 256 sources of one /48: past that, the one of that /48 idle longest goes.
	rl = buckets()
	at := func(i int) time.Time { return now.Add(time.Duration(i) * time.Millisecond) }
	for i := range relayBlockSources {
		rl.allow(sixtyFour(i), at(i))
	}
	rl.allow(sixtyFour(0), at(relayBlockSources))
	rl.allow(sixtyFour(0xffff), at(relayBlockSources+1))
	rl.allow(src("[2001:db8:1::1]:1"), at(relayBlockSources+2))
	if n := rl.blocks["2001:db8::/48"].sources.Len(); n != relayBlockSources || len(rl.sources) != relayBlockSources+1 {
		t.Errorf("%d sources of one /48 followed, %d in all", n, len(rl.sources))
	}
	if rl.sources["2001:db8::/64"] == nil || rl.sources["2001:db8:0:1::/64"] != nil || rl.sources["2001:db8:0:ffff::/64"] == nil || rl.sources["2001:db8:1::/64"] == nil {
		t.Error("a new source of a /48 past its bound let go of another than the one of it idle longest")
	}

	// A full map lets go of the source idle longest, and of its /48 with it.
	rl = buckets()
	for i := range relaySources {
		s := connSource{key: fmt.Sprintf("source %d", i)}
		if i == 1 {
			s = src("[2001:db8:5::1]:1")
		}
		rl.allow(s, at(i))
	}
	rl.allow(connSource{key: "source 0"}, at(relaySources))
	if !rl.allow(connSource{key: "new"}, at(relaySources+1)) {
		t.Error("a new source past the sources followed is refused")
	}
	if len(rl.sources) != relaySources || rl.sources["new"] == nil || rl.sources["source 0"] == nil || rl.sources["2001:db8:5::/64"] != nil || rl.blocks["2001:db8:5::/48"] != nil {
		t.Errorf("a new source past the sources followed: %d followed, the one idle longest let go of %t", len(rl.sources), rl.sources["2001:db8:5::/64"] == nil)
	}
	if !rl.allow(connSource{key: "source 2"}, at(relaySources+2)) {
		t.Error("a source followed is refused")
	}

	// prune lets go of the buckets idle for relayRefill, a /48's with its last source.
	rl = buckets()
	rl.allow(src("192.0.2.1:1"), now.Add(-time.Hour))
	rl.allow(src("[2001:db8::1]:1"), now.Add(-relayRefill))
	rl.allow(src("[2001:db8:1::1]:1"), now.Add(-relayRefill))
	rl.allow(src("[2001:db8:0:1::1]:1"), now.Add(-relayRefill+time.Second))
	rl.prune(now)
	if len(rl.sources) != 1 || rl.sources["2001:db8:0:1::/64"] == nil || len(rl.blocks) != 1 || rl.blocks["2001:db8::/48"] == nil || rl.idle.Len() != 1 {
		t.Errorf("after prune: %d sources, %d /48s", len(rl.sources), len(rl.blocks))
	}

	rl = buckets()
	rl.done = make(chan struct{})
	rl.allow(src("192.0.2.1:1"), now.Add(-time.Hour))
	go rl.pruneEvery(10 * time.Millisecond)
	defer close(rl.done)
	deadline := time.Now().Add(2 * time.Second)
	for {
		rl.mu.Lock()
		n := len(rl.sources)
		rl.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the ticker lets go of no bucket")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTheRelayPreamblesRunKey pins the line of the relay's preamble the one address
// reads a run key from: at most the preamble, a space, a run key of runkey.MaxLength
// characters and a newline.
func TestTheRelayPreamblesRunKey(t *testing.T) {
	key := strings.Repeat("a", runkey.MaxLength)
	if v, ok := relayRunKey([]byte(link.RelayPreamble + " " + key + "\n")); !ok || v != key {
		t.Errorf("a run key of %d characters: %v", runkey.MaxLength, ok)
	}
	if _, ok := relayRunKey([]byte(link.RelayPreamble + " " + key + "a\n")); ok {
		t.Errorf("a run key of %d characters is read", runkey.MaxLength+1)
	}
}

// TestRetireLetsGoOfWhatLapsed pins what the gateway keeps of the runs it let go of: a
// spent run past its time goes, its run id among the used and its error with it, and
// one still in its time stays.
func TestRetireLetsGoOfWhatLapsed(t *testing.T) {
	g := &Gateway{used: map[string]bool{}, runs: map[string]*linkRun{}, spent: map[string]spentRun{}}
	errOld, errKept, errNew := errors.New("old"), errors.New("kept"), errors.New("new")
	g.used["old"], g.spent["old"] = true, spentRun{until: time.Now().Add(-time.Second), err: errOld}
	g.used["kept"], g.spent["kept"] = true, spentRun{until: time.Now().Add(time.Minute), err: errKept}
	lr := &linkRun{g: g, id: "new", remote: true, ended: true, err: errNew}
	g.used["new"], g.runs["new"] = true, lr
	g.retire(lr)
	if g.used["old"] || len(g.spent) != 2 || g.spent["old"].err != nil {
		t.Errorf("a lapsed run is kept: used %v, spent %v", g.used, g.spent)
	}
	if !g.used["kept"] || g.spent["kept"].err != errKept || !g.used["new"] || g.spent["new"].err != errNew || g.runs["new"] != nil {
		t.Errorf("used %v, spent %v, runs %v", g.used, g.spent, g.runs)
	}
	g.spent["kept"] = spentRun{until: time.Now().Add(-time.Second), err: errKept}
	if _, ok := g.spentOf("kept"); ok || g.used["kept"] {
		t.Errorf("a lapsed run asked for is kept: used %v", g.used)
	}
}

// TestTheLapsedRunsErrorsAreBounded pins the errors Close gets of the runs the gateway
// let go of: every one, in the order the runs were let go of, while at most 16 of the
// lapsed runs came to one; past that the first 16, and a line that counts the others.
func TestTheLapsedRunsErrorsAreBounded(t *testing.T) {
	for _, c := range []struct {
		lapsed int
		more   string
	}{
		{0, ""},
		{3, ""},
		{keepLapsedErrs, ""},
		{keepLapsedErrs + 1, "and 1 more run's record could not be closed"},
		{keepLapsedErrs + 4, "and 4 more runs' records could not be closed"},
	} {
		g := &Gateway{used: map[string]bool{}, runs: map[string]*linkRun{}, spent: map[string]spentRun{}}
		base := time.Now().Add(-time.Hour)
		var want []error
		made := 0
		add := func(n int) {
			for range n {
				id := fmt.Sprintf("lapsed %d", made)
				err := errors.New(id)
				if made < keepLapsedErrs {
					want = append(want, err)
				}
				g.used[id], g.spent[id] = true, spentRun{until: base.Add(time.Duration(made) * time.Second), err: err}
				made++
			}
		}
		// Half lapse at one retire, the rest at the next.
		add(c.lapsed / 2)
		kept := errors.New("kept")
		g.spent["kept"] = spentRun{until: time.Now().Add(time.Minute), err: kept}
		g.spent["no error"] = spentRun{until: base}
		first := &linkRun{g: g, id: "first", remote: true, ended: true}
		g.runs["first"] = first
		g.retire(first)
		add(c.lapsed - c.lapsed/2)
		last := &linkRun{g: g, id: "last", remote: true, ended: true, err: errors.New("last")}
		g.runs["last"] = last
		g.retire(last)
		want = append(want, kept, last.err)
		got := g.spentErrs()
		if c.more != "" {
			want = append(want, errors.New(c.more))
		}
		if len(got) != len(want) {
			t.Errorf("%d lapsed: %q; want %q", c.lapsed, got, want)
			continue
		}
		for i := range got {
			if got[i].Error() != want[i].Error() {
				t.Errorf("%d lapsed: %q; want %q", c.lapsed, got, want)
				break
			}
		}
		if len(g.lapsedErrs) > keepLapsedErrs {
			t.Errorf("%d lapsed: %d errors kept", c.lapsed, len(g.lapsedErrs))
		}
	}
}

// roundTripper is a transport of another type than *http.Transport, as a program that
// embeds Forager may set http.DefaultTransport to.
type roundTripper struct{}

func (roundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("not sent")
}

// TestTheRelayWithAnotherDefaultTransport pins that the relay is made when
// http.DefaultTransport is not an *http.Transport, with the environment's proxy and the
// answer left encoded. It replaces a global, so it runs alone: no test of the package
// is parallel.
func TestTheRelayWithAnotherDefaultTransport(t *testing.T) {
	saved := http.DefaultTransport
	http.DefaultTransport = roundTripper{}
	t.Cleanup(func() { http.DefaultTransport = saved })
	g := &Gateway{cfg: Config{Server: &Server{URL: "https://apiary.example"}}}
	rl := g.newRelay(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer rl.close(context.Background())
	tr, ok := rl.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("the relay's transport is a %T", rl.client.Transport)
	}
	if tr.Proxy == nil || reflect.ValueOf(tr.Proxy).Pointer() != reflect.ValueOf(http.ProxyFromEnvironment).Pointer() || !tr.DisableCompression {
		t.Errorf("the relay's transport: the environment's proxy %t, compression off %t", tr.Proxy != nil, tr.DisableCompression)
	}
}
