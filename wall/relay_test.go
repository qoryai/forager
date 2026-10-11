package wall

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a buffer the relay writes and the test reads.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestRelayForwardsToItsOneTarget pins the relay: it says when it listens, what
// connects to its port reaches the target fixed at the start and nothing the client
// names, and it stops with its context.
func TestRelayForwardsToItsOneTarget(t *testing.T) {
	t.Setenv(RelayInsideEnv, "127.0.0.0/8")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "the target") }))
	defer origin.Close()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()

	ctx, cancel := context.WithCancel(context.Background())
	var ready syncBuffer
	done := make(chan error, 1)
	go func() {
		done <- Relay(ctx, []string{fmt.Sprintf("%d=%s", port, strings.TrimPrefix(origin.URL, "http://"))}, &ready)
	}()
	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(ready.String(), RelayReady); {
		if time.Now().After(deadline) {
			t.Fatal("the relay never said it listens")
		}
		time.Sleep(5 * time.Millisecond)
	}
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "the target" {
		t.Errorf("through the relay: %q", body)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the relay outlived its context")
	}
	if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
		t.Error("the relay's port still listens")
	}
}

// TestRelayRefusesWhatIsNotAForward pins the argument's grammar.
func TestRelayRefusesWhatIsNotAForward(t *testing.T) {
	t.Setenv(RelayInsideEnv, "127.0.0.0/8")
	for _, f := range [][]string{nil, {"3128"}, {"x=host:1"}, {"0=host:1"}, {"3128=host"}, {"70000=host:1"}} {
		if err := Relay(context.Background(), f, io.Discard); err == nil {
			t.Errorf("%v was accepted", f)
		}
	}
}

// TestRelayOpensEveryConnectionWithTheRunsToken pins the relay's half of the proxy's
// gate: with the token in its environment, what it forwards starts with the preamble.
func TestRelayOpensEveryConnectionWithTheRunsToken(t *testing.T) {
	t.Setenv(RelayTokenEnv, "the-runs-token")
	t.Setenv(RelayInsideEnv, "127.0.0.0/8")
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	got := make(chan string, 1)
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		got <- string(b)
	}()
	free, _ := net.Listen("tcp", "127.0.0.1:0")
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := &syncBuffer{}
	go Relay(ctx, []string{fmt.Sprintf("%d=%s", port, target.Addr())}, ready)
	for range 200 {
		if strings.Contains(ready.String(), RelayReady) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "hello")
	c.(*net.TCPConn).CloseWrite()
	select {
	case s := <-got:
		if s != "QORY-RELAY the-runs-token\nhello" {
			t.Errorf("the target read %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Error("the target read nothing")
	}
	c.Close()
}

// TestRelayListensOnItsInsideAddressAlone pins that the relay given a subnet listens on
// this machine's one address in it, loopback here, and that a dial on any other
// address of this machine's is refused.
func TestRelayListensOnItsInsideAddressAlone(t *testing.T) {
	t.Setenv(RelayInsideEnv, "127.0.0.0/8")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "the target") }))
	defer origin.Close()
	local, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	_, loopback, _ := net.ParseCIDR("127.0.0.0/8")
	var others []string
	for _, a := range local {
		// A link-local address is dialled only with its interface's zone.
		if n, ok := a.(*net.IPNet); ok && !loopback.Contains(n.IP) && !n.IP.IsLinkLocalUnicast() {
			others = append(others, n.IP.String())
		}
	}
	if len(others) == 0 {
		t.Skip("this machine has no address but loopback")
	}
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(free.Addr().(*net.TCPAddr).Port)
	free.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- Relay(ctx, []string{port + "=" + strings.TrimPrefix(origin.URL, "http://")}, ready) }()
	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(ready.String(), RelayReady); {
		select {
		case err := <-done:
			t.Fatalf("the relay did not start: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the relay never said it listens")
		}
		time.Sleep(5 * time.Millisecond)
	}
	resp, err := http.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "the target" {
		t.Errorf("through the relay: %q", body)
	}
	for _, ip := range others {
		if c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), time.Second); err == nil {
			c.Close()
			t.Errorf("the relay answered on %s, outside its subnet", ip)
		}
	}
}

// TestRelayRefusesWithoutOneInsideAddress pins that the relay never listens without a
// subnet, nor on a subnet that holds none of this machine's addresses or several.
func TestRelayRefusesWithoutOneInsideAddress(t *testing.T) {
	t.Setenv(RelayInsideEnv, "")
	if err := Relay(context.Background(), []string{"3128=host:1"}, io.Discard); err == nil {
		t.Error("the relay started with no subnet")
	}
	local := []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("10.89.0.2"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("10.90.0.2"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("fd00::2"), Mask: net.CIDRMask(64, 128)},
	}
	for _, subnets := range []string{"", "10.89.0.2", "10.89.0.0/24,", "192.0.2.0/24", "10.0.0.0/8", "10.89.0.0/24,192.0.2.0/24"} {
		if got, _, err := insideAddrs(subnets, local); err == nil {
			t.Errorf("%q: the relay would listen on %v", subnets, got)
		}
	}
	for subnets, want := range map[string]string{
		"10.89.0.0/24":           "[10.89.0.2] [10.89.0.0/24]",
		"10.89.0.0/24,fd00::/64": "[10.89.0.2 fd00::2] [10.89.0.0/24 fd00::/64]",
	} {
		if got, nets, err := insideAddrs(subnets, local); err != nil || fmt.Sprint(got, " ", nets) != want {
			t.Errorf("%q: %v %v, %v; want %s", subnets, got, nets, err, want)
		}
	}
}

// TestRelayTakesConnectionsFromItsSubnetsAlone pins that the relay closes a connection
// whose remote address lies in none of its subnets before it dials the target, and
// copies one from an address in them.
func TestRelayTakesConnectionsFromItsSubnetsAlone(t *testing.T) {
	for _, c := range []struct {
		subnet string
		passes bool
	}{{"10.0.0.0/8", false}, {"127.0.0.0/8", true}} {
		t.Run(c.subnet, func(t *testing.T) {
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			dialled := make(chan string, 1)
			go func() {
				c, err := target.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				b, _ := io.ReadAll(c)
				dialled <- string(b)
			}()
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			_, subnet, _ := net.ParseCIDR(c.subnet)
			ctx, cancel := context.WithCancel(context.Background())
			served := make(chan struct{})
			go func() {
				serve(ctx, ln, target.Addr().String(), "", []*net.IPNet{subnet})
				close(served)
			}()
			defer func() {
				cancel()
				ln.Close()
				<-served
			}()
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			io.WriteString(conn, "hello")
			conn.(*net.TCPConn).CloseWrite()
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Read(make([]byte, 1))
			if !c.passes {
				// Closed with the bytes unread, the connection ends in a reset or an EOF.
				if ne, ok := err.(net.Error); err == nil || ok && ne.Timeout() {
					t.Errorf("a connection from outside %s was not closed: %v", c.subnet, err)
				}
				select {
				case s := <-dialled:
					t.Errorf("the target was dialled for a connection from outside %s and read %q", c.subnet, s)
				case <-time.After(500 * time.Millisecond):
				}
				return
			}
			select {
			case s := <-dialled:
				if s != "hello" {
					t.Errorf("the target read %q", s)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("a connection from inside %s never reached the target", c.subnet)
			}
		})
	}
}
