package gateway

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/server"
)

// TestTheSourceOfAnAddress pins the source a connection counts against: an IPv4
// address alone, an IPv4 address mapped into IPv6 as that address, and an IPv6 address's
// /64, whatever its zone.
func TestTheSourceOfAnAddress(t *testing.T) {
	for _, c := range []struct{ a, b string }{
		{"192.0.2.1:1", "192.0.2.1:2"},
		{"192.0.2.1:1", "[::ffff:192.0.2.1]:2"},
		{"[2001:db8::1]:1", "[2001:db8::ffff:ffff:ffff:ffff]:2"},
		{"[fe80::1%en0]:1", "[fe80::2%en1]:2"},
	} {
		if addressSource(c.a) != addressSource(c.b) {
			t.Errorf("%s and %s are %s and %s", c.a, c.b, addressSource(c.a), addressSource(c.b))
		}
	}
	for _, c := range []struct{ a, b string }{
		{"192.0.2.1:1", "192.0.2.2:1"},
		{"[2001:db8::1]:1", "[2001:db8:0:1::1]:1"},
	} {
		if addressSource(c.a) == addressSource(c.b) {
			t.Errorf("%s and %s are both %s", c.a, c.b, addressSource(c.a))
		}
	}
	tcp := &net.TCPAddr{IP: net.ParseIP("2001:db8::7"), Port: 9}
	if sourceOf(tcp) != addressSource("[2001:db8::1]:1") {
		t.Errorf("a TCP address of 2001:db8::/64 is %s", sourceOf(tcp))
	}
}

// TestTheConnectionLimit pins the connections the one address counts: at most each of
// one source, at most most in all, and one let go of is one more taken.
func TestTheConnectionLimit(t *testing.T) {
	l := newConnLimit(5, 2)
	a, b := addressSource("[2001:db8::1]:1"), addressSource("[2001:db8::2]:1")
	if !l.take(a) || !l.take(a) {
		t.Fatal("the first two of a source are not taken")
	}
	if l.take(b) {
		t.Error("a third connection of one /64 is taken")
	}
	for i := range 3 {
		if !l.take(addressSource(fmt.Sprintf("192.0.2.%d:1", i+1))) {
			t.Fatalf("connection %d in all is not taken", i+3)
		}
	}
	if l.take(addressSource("192.0.2.9:1")) {
		t.Error("a sixth connection in all is taken")
	}
	l.give(a)
	if !l.take(addressSource("192.0.2.9:1")) {
		t.Error("a connection let go of is not one more taken")
	}
	if l.take(a) {
		t.Error("a connection past the bound in all is taken")
	}
	if len(l.by) != 5 || l.total != 5 {
		t.Errorf("counted %d in all, by %v", l.total, l.by)
	}
	c := &heldConn{Conn: nopConn{}, release: func() { l.give(a) }}
	c.Close()
	c.Close()
	if l.total != 4 {
		t.Errorf("a connection closed twice let go of %d", 5-l.total)
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
