package gateway

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
// one source, at most block of one IPv6 /48, at most most in all, and one let go of is
// one more taken.
func TestTheConnectionLimit(t *testing.T) {
	l := newConnLimit(7, 2, 3)
	a, b := src("[2001:db8::1]:1"), src("[2001:db8::2]:1")
	if !l.take(a) || !l.take(a) {
		t.Fatal("the first two of a source are not taken")
	}
	if l.take(b) {
		t.Error("a third connection of one /64 is taken")
	}
	if !l.take(src("[2001:db8:0:1::1]:1")) {
		t.Error("a third connection of one /48 is not taken")
	}
	if l.take(src("[2001:db8:0:2::1]:1")) {
		t.Error("a fourth connection of one /48 is taken")
	}
	if !l.take(src("[2001:db8:1::1]:1")) {
		t.Error("a connection of another /48 is not taken")
	}
	for i := range 3 {
		if !l.take(src(fmt.Sprintf("192.0.2.%d:1", i+1))) {
			t.Fatalf("connection %d in all is not taken", i+5)
		}
	}
	if l.take(src("192.0.2.9:1")) {
		t.Error("an eighth connection in all is taken")
	}
	l.give(a)
	if !l.take(src("192.0.2.9:1")) {
		t.Error("a connection let go of is not one more taken")
	}
	if l.take(a) {
		t.Error("a connection past the bound in all is taken")
	}
	if l.total != 7 || len(l.by) != 7 || l.blocks["2001:db8::/48"] != 2 || l.blocks["2001:db8:1::/48"] != 1 {
		t.Errorf("counted %d in all, by %v, by /48 %v", l.total, l.by, l.blocks)
	}
	// Admitted, closed, or both in either order, a connection is let go of once.
	for _, steps := range [][]string{{"admit"}, {"close"}, {"admit", "close"}, {"close", "admit"}, {"close", "close", "admit", "admit"}} {
		l := newConnLimit(1, 1, 1)
		if !l.take(a) {
			t.Fatal("a first connection is not taken")
		}
		c := &heldConn{Conn: nopConn{}, release: func() { l.give(a) }}
		for _, s := range steps {
			if s == "admit" {
				c.admit()
			} else {
				c.Close()
			}
		}
		if l.total != 0 || len(l.by) != 0 || len(l.blocks) != 0 {
			t.Errorf("%v: %d counted, by %v, by /48 %v", steps, l.total, l.by, l.blocks)
		}
	}
}

// nopConn is a connection that does nothing.
type nopConn struct{ net.Conn }

func (nopConn) Close() error { return nil }

// TestTheRelaysBuckets pins the relay's buckets: by the connection's source, an IPv6
// /64 one bucket whatever the request's fields say; a full map refuses a new source
// and serves those it follows; and buckets are let go of when they are full again, by
// prune alone.
func TestTheRelaysBuckets(t *testing.T) {
	rl := &relay{g: &Gateway{conf: &server.Configuration{Run: &server.Endpoint{URL: "https://apiary.example/v1/runs"}}}, sources: map[string]*bucket{}}
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

	now := time.Now()
	rl = &relay{sources: map[string]*bucket{}}
	for i := range relaySources {
		rl.sources[fmt.Sprintf("source %d", i)] = &bucket{left: relayBurst, at: now.Add(-time.Hour)}
	}
	if rl.allow("new", now) {
		t.Error("a new source past the sources followed is allowed")
	}
	if !rl.allow("source 1", now) {
		t.Error("a source followed is refused")
	}
	if len(rl.sources) != relaySources {
		t.Errorf("a new source let go of buckets: %d", len(rl.sources))
	}
	rl.sources["source 2"].at = now.Add(-relayRefill + time.Second)
	rl.sources["source 3"].at = now.Add(-relayRefill)
	rl.prune(now)
	if len(rl.sources) != 2 || rl.sources["source 1"] == nil || rl.sources["source 2"] == nil {
		t.Errorf("after prune: %d buckets", len(rl.sources))
	}
	if !rl.allow("new", now) {
		t.Error("a new source once buckets are let go of is refused")
	}

	rl = &relay{sources: map[string]*bucket{"old": {left: relayBurst, at: now.Add(-time.Hour)}}, done: make(chan struct{})}
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
