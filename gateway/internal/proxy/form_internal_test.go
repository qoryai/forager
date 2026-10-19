package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/policy"
)

// dials records every address the proxy dials, and connects each to the origin for its
// port instead.
type dials struct {
	mu      sync.Mutex
	dialled []string
	plain   string
	secure  string
}

func (d *dials) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.dialled = append(d.dialled, addr)
	d.mu.Unlock()
	to := d.plain
	if strings.HasSuffix(addr, ":443") {
		to = d.secure
	}
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", to)
}

// take returns the addresses dialled since the last take.
func (d *dials) take() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.dialled
	d.dialled = nil
	return out
}

// decisions are the decisions a proxy handed its observer.
type decisions struct {
	mu   sync.Mutex
	seen []Decision
}

func (o *decisions) observe(d Decision) {
	o.mu.Lock()
	o.seen = append(o.seen, d)
	o.mu.Unlock()
}

// count is how many there are.
func (o *decisions) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.seen)
}

// at is the ith, or the last for -1.
func (o *decisions) at(i int) Decision {
	o.mu.Lock()
	defer o.mu.Unlock()
	if i < 0 {
		i = len(o.seen) - 1
	}
	return o.seen[i]
}

// formProxy is a proxy in mode with allow and deny, terminating key.example, every
// dial recorded.
func formProxy(t *testing.T, mode policy.Mode, allow, deny []string) (*Proxy, *dials, *decisions) {
	t.Helper()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "origin") }))
	t.Cleanup(plain.Close)
	secure := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "origin") }))
	// The origin's certificate is not the host's, and its handshakes fail.
	secure.Config.ErrorLog = log.New(io.Discard, "", 0)
	secure.StartTLS()
	t.Cleanup(secure.Close)
	seen := &decisions{}
	p, err := Listen("", mode, allow, deny, seen.observe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	rec := &dials{plain: plain.Listener.Addr().String(), secure: secure.Listener.Addr().String()}
	p.dial = rec.dial
	paths := map[string][]string{"key.example": {"/*"}}
	ca, err := NewCA("test", p.Terminating(nil, paths, nil))
	if err != nil {
		t.Fatal(err)
	}
	p.Terminate(ca, nil, paths, nil)
	return p, rec, seen
}

// ask sends one request line through the proxy, with the Host header key.example, and
// returns the status.
func ask(t *testing.T, p *Proxy, line string) int {
	t.Helper()
	status, _ := askBody(t, p, line)
	return status
}

// askBody is ask, and returns the body too: none for a CONNECT answered 200.
func askBody(t *testing.T, p *Proxy, line string) (int, string) {
	t.Helper()
	c, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "%s HTTP/1.1\r\nHost: key.example\r\nConnection: close\r\n\r\n", line)
	method, _, _ := strings.Cut(line, " ")
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
	if err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	var body []byte
	if method != http.MethodConnect || resp.StatusCode != http.StatusOK {
		body, _ = io.ReadAll(resp.Body)
	}
	return resp.StatusCode, string(body)
}

// requests are the four ways a host reaches the proxy: a plain request and an https one
// in absolute form, a CONNECT the proxy relays, and one it terminates. Each takes the
// host as written in an authority and gives the request line.
var requests = []struct {
	name string
	line func(host string) string
}{
	{"plain", func(h string) string { return "GET http://" + h + "/x" }},
	{"https", func(h string) string { return "GET https://" + h + "/x" }},
	{"relayed", func(h string) string { return "CONNECT " + h + ":443" }},
	{"terminated", func(h string) string { return "CONNECT " + h + ":443" }},
}

// TestAHostOutsideTheNameGrammarIsRefusedAndNeverDialled pins that a host that is not
// ASCII letters, digits, hyphens and dots with no empty label, or an IP address, is
// refused with 403 and recorded as refused in either mode, and nothing is dialled. The
// relayed CONNECT is to kit.example, the terminated one to key.example, which the proxy
// terminates.
func TestAHostOutsideTheNameGrammarIsRefusedAndNeverDialled(t *testing.T) {
	forms := map[string][]string{
		"key": {"ｋｅｙ.example", "k­ey.example", "Key.example", "%EF%BD%8Bey.example", "key..example", ".key.example", "key.example..", "k_ey.example"},
		"kit": {"ｋｉｔ.example", "k­it.example", "Kit.example", "%EF%BD%8Bit.example", "kit..example", ".kit.example", "kit.example..", "k_it.example"},
	}
	for _, c := range []struct {
		mode        policy.Mode
		allow, deny []string
	}{
		{policy.Observe, nil, nil},
		{policy.Observe, []string{"*.example"}, []string{"key.example", "kit.example"}},
		{policy.Enforce, []string{"*.example"}, nil},
	} {
		p, rec, seen := formProxy(t, c.mode, c.allow, c.deny)
		for _, rq := range requests {
			base := "key"
			if rq.name == "relayed" {
				base = "kit"
			}
			for _, host := range forms[base] {
				n := seen.count()
				line := rq.line(host)
				got, body := askBody(t, p, line)
				if got != http.StatusForbidden {
					t.Errorf("%s %v %s: %d, want 403", c.mode, c.deny, line, got)
				}
				if got := rec.take(); len(got) != 0 {
					t.Errorf("%s %s dialled %v", c.mode, line, got)
				}
				if seen.count() != n+1 {
					t.Errorf("%s %s: %d decisions, want one", c.mode, line, seen.count()-n)
					continue
				}
				d := seen.at(n)
				if d.Allowed || d.Outcome != Refused || d.Rule != HostForm || d.Mode != c.mode {
					t.Errorf("%s %s: decision %+v", c.mode, line, d)
				}
				// The host is recorded and answered as sent, never folded to one not sent.
				if d.Host != host {
					t.Errorf("%s %s: decision host %q, want %q", c.mode, line, d.Host, host)
				}
				if quoted := fmt.Sprintf("%+q:", host); !strings.Contains(body, quoted) {
					t.Errorf("%s %s: body %q does not contain %s", c.mode, line, body, quoted)
				}
			}
		}
		// A percent-encoded ASCII octet the HTTP reader refuses itself, with a 400.
		for _, line := range []string{"GET http://%6Bey.example/x", "GET https://%6Bey.example/x", "CONNECT %6Bit.example:443", "CONNECT %6Bey.example:443"} {
			if got := ask(t, p, line); got != http.StatusForbidden && got != http.StatusBadRequest {
				t.Errorf("%s %s: %d, want a refusal", c.mode, line, got)
			}
			if got := rec.take(); len(got) != 0 {
				t.Errorf("%s %s dialled %v", c.mode, line, got)
			}
		}
	}
}

// TestANameInTheGrammarIsDecidedAndDialledInItsForm pins that a name of ASCII letters,
// digits, hyphens and dots, in any case and with one trailing dot, is decided as before,
// lower-case without the dot, and dialled in that form rooted, with one trailing dot,
// and that a label of digits or hex inside a name leaves it a name.
func TestANameInTheGrammarIsDecidedAndDialledInItsForm(t *testing.T) {
	for _, mode := range []policy.Mode{policy.Observe, policy.Enforce} {
		p, rec, seen := formProxy(t, mode, []string{"*.example", "1.2.3.0xg", "kit.0x1g"}, nil)
		for _, c := range []struct{ host, form string }{
			{"kit.example", "kit.example"},
			{"KIT.Example", "kit.example"},
			{"kit.example.", "kit.example"},
			{"0x7f.example", "0x7f.example"},
			{"127.example", "127.example"},
			{"1.2.3.example", "1.2.3.example"},
			{"1.2.3.0xg", "1.2.3.0xg"},
			{"kit.0x1g", "kit.0x1g"},
			{"deadbeef.example", "deadbeef.example"},
			{"a-1.example", "a-1.example"},
		} {
			for _, rq := range requests[:3] {
				line := rq.line(c.host)
				got := ask(t, p, line)
				if rq.name == "https" {
					// What matters is the dial: the origin's certificate is not the host's.
					got = http.StatusOK
				}
				if got != http.StatusOK {
					t.Errorf("%s %s: %d, want 200", mode, line, got)
				}
				port := "80"
				if rq.name != "plain" {
					port = "443"
				}
				if d := rec.take(); len(d) != 1 || d[0] != c.form+".:"+port {
					t.Errorf("%s %s dialled %v, want %s.:%s", mode, line, d, c.form, port)
				}
				if d := seen.at(-1); !d.Allowed || d.Host != c.form {
					t.Errorf("%s %s: decision %+v", mode, line, d)
				}
			}
		}
		// The terminated host, by any spelling of its form, is terminated.
		for _, host := range []string{"key.example", "KEY.example", "key.example."} {
			if got := ask(t, p, "CONNECT "+host+":443"); got != http.StatusOK {
				t.Errorf("%s CONNECT %s: %d, want 200", mode, host, got)
			}
			if d := rec.take(); len(d) != 0 {
				t.Errorf("%s CONNECT %s dialled %v before a request", mode, host, d)
			}
		}
	}
}

// TestAnIPAddressOutsideItsCanonicalFormIsRefused pins that a host read as an IPv4
// address is one only as four decimal parts with no leading zero, and an IPv6 address
// only in RFC 5952's form, not mapped from IPv4 and with no zone: any other is refused
// with 403 in either mode, recorded as refused, and never dialled.
func TestAnIPAddressOutsideItsCanonicalFormIsRefused(t *testing.T) {
	forms := []string{
		"127.1", "2130706433", "0x7f000001", "0x7f", "0x7f.0.0.1", "0x7f.1", "0177.0.0.1",
		"127.000.0.1", "127.0.0.1.1", "kit.1", "1.2.3", "08.1.1.1", "0x.1.1.1",
		"0x", "kit.0x1f", "kit.0X1F", "kit.0x", "kit.0x.",
		"[::ffff:127.0.0.1]", "[::FFFF:7f00:1]", "[::1.2.3.4]", "[0:0:0:0:0:0:0:1]",
		"[2001:db8:0:0:0:0:0:1]", "[2001:0db8::1]", "[fe80::1%25en0]",
	}
	for _, c := range []struct {
		mode        policy.Mode
		allow, deny []string
	}{
		{policy.Observe, nil, []string{"127.0.0.1"}},
		{policy.Observe, nil, nil},
		{policy.Enforce, []string{"127.0.0.1", "::1", "*.1"}, nil},
	} {
		p, rec, seen := formProxy(t, c.mode, c.allow, c.deny)
		for _, rq := range requests[:3] {
			for _, host := range forms {
				n := seen.count()
				line := rq.line(host)
				if got := ask(t, p, line); got != http.StatusForbidden {
					t.Errorf("%s %v %s: %d, want 403", c.mode, c.deny, line, got)
				}
				if got := rec.take(); len(got) != 0 {
					t.Errorf("%s %s dialled %v", c.mode, line, got)
				}
				if seen.count() != n+1 {
					t.Errorf("%s %s: %d decisions, want one", c.mode, line, seen.count()-n)
					continue
				}
				if d := seen.at(n); d.Allowed || d.Outcome != Refused || d.Rule != HostForm {
					t.Errorf("%s %s: decision %+v", c.mode, line, d)
				}
			}
		}
	}
}

// TestAnIPAddressInItsCanonicalFormIsDecidedAndDialled pins that an IPv4 address of
// four decimal parts and an IPv6 address in RFC 5952's form, hex in either case, are
// decided by the lists and dialled as written.
func TestAnIPAddressInItsCanonicalFormIsDecidedAndDialled(t *testing.T) {
	p, rec, seen := formProxy(t, policy.Enforce, []string{"127.0.0.1", "::1", "2001:db8::1"}, nil)
	for _, c := range []struct{ host, form, dial string }{
		{"127.0.0.1", "127.0.0.1", "127.0.0.1"},
		{"[::1]", "::1", "[::1]"},
		{"[2001:DB8::1]", "2001:db8::1", "[2001:db8::1]"},
	} {
		for _, rq := range requests[:3] {
			line := rq.line(c.host)
			got := ask(t, p, line)
			if rq.name == "https" {
				got = http.StatusOK
			}
			if got != http.StatusOK {
				t.Errorf("%s: %d, want 200", line, got)
			}
			port := "80"
			if rq.name != "plain" {
				port = "443"
			}
			if d := rec.take(); len(d) != 1 || d[0] != c.dial+":"+port {
				t.Errorf("%s dialled %v, want %s:%s", line, d, c.dial, port)
			}
			if d := seen.at(-1); !d.Allowed || d.Host != c.form || d.Rule != c.form {
				t.Errorf("%s: decision %+v", line, d)
			}
		}
	}
	// One outside the list is denied by it, as any host.
	if got := ask(t, p, "GET http://127.0.0.2/x"); got != http.StatusForbidden {
		t.Errorf("127.0.0.2: %d, want 403", got)
	}
	if d := rec.take(); len(d) != 0 {
		t.Errorf("127.0.0.2 dialled %v", d)
	}
}

// TestARefusedHostIsAnsweredWithItsRule pins the answer to a host without a form: a 403
// whose one line contains the host, quoted in ASCII, and the port, and says the host is
// neither a name of ASCII letters, digits, hyphens and dots nor an IP address in
// canonical form.
func TestARefusedHostIsAnsweredWithItsRule(t *testing.T) {
	p, _, _ := formProxy(t, policy.Observe, nil, nil)
	for _, c := range []struct{ line, want string }{
		{"GET http://ａｐｉ.example/x", `qory: egress to "\uff41\uff50\uff49.example":80 denied by the gateway: the host is neither a name of ASCII letters, digits, hyphens and dots nor an IP address in canonical form` + "\n"},
		{"CONNECT 127.1:443", `qory: egress to "127.1":443 denied by the gateway: the host is neither a name of ASCII letters, digits, hyphens and dots nor an IP address in canonical form` + "\n"},
	} {
		conn, err := net.Dial("tcp", p.Addr())
		if err != nil {
			t.Fatal(err)
		}
		// A tunnel opened in place of the refusal fails the read, not the run.
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "%s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", c.line)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body)
		conn.Close()
		if err != nil {
			t.Errorf("%s: %d, reading the body: %v", c.line, resp.StatusCode, err)
			continue
		}
		if resp.StatusCode != http.StatusForbidden || string(b) != c.want {
			t.Errorf("%s: %d %q, want 403 %q", c.line, resp.StatusCode, b, c.want)
		}
	}
}

// embedding are IPv6 addresses in the refused ranges, by range, each with its first
// and last address: ::/96 but for ::1, ::ffff:0:0/96, ::ffff:0:0:0/96 and
// 64:ff9b::/96.
var embedding = map[string][]string{
	"::/96":           {"::", "::2", "::7f00:1", "::ffff:ffff"},
	"::ffff:0:0/96":   {"::ffff:0.0.0.0", "::ffff:127.0.0.1", "::ffff:255.255.255.255"},
	"::ffff:0:0:0/96": {"::ffff:0:0:0", "::ffff:0:7f00:1", "::ffff:0:ffff:ffff"},
	"64:ff9b::/96":    {"64:ff9b::", "64:ff9b::7f00:1", "64:FF9B::7F00:1", "64:ff9b::ffff:ffff"},
}

// TestAnIPv6AddressThatEmbedsAnIPv4AddressIsRefused pins that an IPv6 address in a
// refused range is refused with 403 and the rule wall:host-form in
// either mode, whatever the lists hold, recorded as sent, and never dialled.
func TestAnIPv6AddressThatEmbedsAnIPv4AddressIsRefused(t *testing.T) {
	var all []string
	for _, addrs := range embedding {
		all = append(all, addrs...)
	}
	for _, c := range []struct {
		mode        policy.Mode
		allow, deny []string
	}{
		{policy.Observe, nil, nil},
		{policy.Observe, all, nil},
		{policy.Enforce, all, nil},
	} {
		p, rec, seen := formProxy(t, c.mode, c.allow, c.deny)
		for prefix, addrs := range embedding {
			for _, addr := range addrs {
				for _, rq := range requests[:3] {
					n := seen.count()
					line := rq.line("[" + addr + "]")
					if got := ask(t, p, line); got != http.StatusForbidden {
						t.Errorf("%s %s (%s): %d, want 403", c.mode, line, prefix, got)
					}
					if got := rec.take(); len(got) != 0 {
						t.Errorf("%s %s dialled %v", c.mode, line, got)
					}
					if seen.count() != n+1 {
						t.Errorf("%s %s: %d decisions, want one", c.mode, line, seen.count()-n)
						continue
					}
					if d := seen.at(n); d.Allowed || d.Outcome != Refused || d.Rule != HostForm || d.Mode != c.mode || d.Host != addr {
						t.Errorf("%s %s: decision %+v", c.mode, line, d)
					}
				}
			}
		}
	}
}

// TestAnIPv6AddressOutsideTheEmbeddingRangesIsDecidedAndDialled pins that ::1, the
// addresses next to each refused range, 6to4's 2002::/16, Teredo's 2001::/32, the
// local-use NAT64 prefix 64:ff9b:1::/48 and an ordinary global address are decided by
// the lists in either mode and dialled.
func TestAnIPv6AddressOutsideTheEmbeddingRangesIsDecidedAndDialled(t *testing.T) {
	addrs := []string{
		"::1", "::1:0:0", "::fffe:ffff:ffff", "::1:0:0:0", "::ffff:1:0:0", "::fffe:ffff:ffff:ffff",
		"64:ff9a:ffff:ffff:ffff:ffff:ffff:ffff", "64:ff9b::1:0:0",
		"2002::", "2002:7f00:1::", "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"2001::1", "64:ff9b:1::1", "64:ff9b:1::7f00:1", "2600::1",
	}
	for _, c := range []struct {
		mode  policy.Mode
		allow []string
	}{
		{policy.Observe, nil},
		{policy.Enforce, addrs},
	} {
		p, rec, seen := formProxy(t, c.mode, c.allow, nil)
		for _, addr := range addrs {
			for _, rq := range requests[:3] {
				line := rq.line("[" + addr + "]")
				got := ask(t, p, line)
				if rq.name == "https" {
					// What matters is the dial: the origin's certificate is not the host's.
					got = http.StatusOK
				}
				if got != http.StatusOK {
					t.Errorf("%s %s: %d, want 200", c.mode, line, got)
				}
				port := "80"
				if rq.name != "plain" {
					port = "443"
				}
				if d := rec.take(); len(d) != 1 || d[0] != "["+addr+"]:"+port {
					t.Errorf("%s %s dialled %v, want [%s]:%s", c.mode, line, d, addr, port)
				}
				if d := seen.at(-1); !d.Allowed || d.Host != addr || d.Rule == HostForm {
					t.Errorf("%s %s: decision %+v", c.mode, line, d)
				}
			}
		}
	}
}
