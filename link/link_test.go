package link_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/qoryai/forager/link"
)

// TestALocalPrintsItsMembers pins that a Local, by value or by pointer, prints its
// members under every verb, method and slog handler, and never its way in memory.
func TestALocalPrintsItsMembers(t *testing.T) {
	l := link.Local{
		Socket:   "/tmp/qory-link-1/sock",
		Proxy:    "127.0.0.1:41000",
		Files:    []link.File{{Path: "/home/user/.config/qory", What: "the gateway's directory"}, {Path: "/tmp/qory-tool-*", What: "where the tools' sockets are made"}},
		Reserved: []string{"QORY_RUN_SOCKET"},
	}
	if got := fmt.Sprintf("%+v", l); !strings.Contains(got, "Socket:/tmp/qory-link-1/sock") || !strings.Contains(got, "Proxy:127.0.0.1:41000") || strings.Contains(got, "Secret") {
		t.Errorf("%%+v: %s", got)
	}
	if got, want := fmt.Sprintf("%#v", &l), `link.Local{Socket:"/tmp/qory-link-1/sock", Proxy:"127.0.0.1:41000", Files:[]link.File{link.File{Path:"/home/user/.config/qory", What:"the gateway's directory", Kept:false}, link.File{Path:"/tmp/qory-tool-*", What:"where the tools' sockets are made", Kept:false}}, Reserved:[]string{"QORY_RUN_SOCKET"}}`; got != want {
		t.Errorf("%%#v:\n got %s\nwant %s", got, want)
	}
	for _, marshal := range []func(any) ([]byte, error){json.Marshal, func(v any) ([]byte, error) { return jsonv2.Marshal(v) }} {
		if b, _ := marshal(l); !strings.Contains(string(b), `"Socket":"/tmp/qory-link-1/sock"`) {
			t.Errorf("JSON: %s", b)
		}
	}
	var b bytes.Buffer
	slog.New(slog.NewJSONHandler(&b, nil)).Info("link", "local", l)
	if !strings.Contains(b.String(), `"socket":"/tmp/qory-link-1/sock"`) {
		t.Errorf("slog: %s", b.String())
	}
}

// TestALocalInMemory pins the way in memory: DialContext takes it, copies keep it, and
// it changes nothing of how a Local prints; without it DialContext dials the socket.
func TestALocalInMemory(t *testing.T) {
	plain := link.Local{Socket: "/nonexistent/qory-link-x/sock"}
	if plain.IsInMemory() {
		t.Error("a Local without a way in memory has one")
	}
	if _, err := plain.DialContext(context.Background()); err == nil {
		t.Error("a socket that does not exist was dialled")
	}
	calls := 0
	l := plain.InMemory(func(context.Context) (net.Conn, error) {
		calls++
		c, _ := net.Pipe()
		return c, nil
	})
	copied := l
	c, err := copied.DialContext(context.Background())
	if err != nil || calls != 1 || !copied.IsInMemory() {
		t.Fatalf("in memory: %v, %d calls", err, calls)
	}
	c.Close()
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if fmt.Sprintf(format, l) != fmt.Sprintf(format, plain) {
			t.Errorf("%s prints the way in memory: %s", format, fmt.Sprintf(format, l))
		}
	}
	if a, _ := json.Marshal(l); string(a) != string(must(json.Marshal(plain))) {
		t.Errorf("JSON: %s", a)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// TestTheRelayPreamble pins the line the wall's relay writes and the proxy reads: read
// in exactly its length, and true only for the word, the secret and the newline.
func TestTheRelayPreamble(t *testing.T) {
	const secret = "c2VjcmV0LW9mLXRoZS10ZXN0cw"
	if got := link.RelayLine("the-runs-secret"); got != "QORY-RELAY the-runs-secret\n" {
		t.Errorf("relay preamble %q", got)
	}
	read := func(in string) (bool, error, string) {
		r := bufio.NewReader(strings.NewReader(in))
		ok, err := link.ReadRelayPreamble(r, secret)
		rest, _ := io.ReadAll(r)
		return ok, err, string(rest)
	}
	if ok, err, rest := read("QORY-RELAY " + secret + "\nCONNECT a:443 HTTP/1.1\r\n"); !ok || err != nil || rest != "CONNECT a:443 HTTP/1.1\r\n" {
		t.Errorf("the right secret: %v %v, then %q", ok, err, rest)
	}
	for name, in := range map[string]string{
		"a wrong secret":    "QORY-RELAY " + strings.Repeat("x", len(secret)) + "\nCONNECT a:443 HTTP/1.1\r\n",
		"the old link word": "QORY-LINK  " + secret + "\nGET / HTTP/1.1\r\n",
		"no prefix":         secret + "\nGET / HTTP/1.1\r\n\r\n\r\n\r\n",
		"a carriage return": "QORY-RELAY " + secret + "\r\n",
	} {
		if ok, err, _ := read(in); ok || err != nil {
			t.Errorf("%s: %v %v", name, ok, err)
		}
	}
	for _, s := range []string{"", "a b", "a\nb", strings.Repeat("a", link.MaxSecret+1)} {
		if err := link.CheckSecret(s); err == nil {
			t.Errorf("%q is a preamble's secret", s)
		}
	}
}

// TestTheBindingsBytes pins the wire of the binding to a separate gateway: the lines
// each end writes, the message the gateway signs, and the third line of its answers'
// signature.
func TestTheBindingsBytes(t *testing.T) {
	ekm := bytes.Repeat([]byte{0xab}, link.BindingSize)
	if link.BindLine != "QORY-BIND\n" || link.BoundLine("fp", "sig") != "QORY-BOUND fp sig\n" {
		t.Errorf("the lines %q %q", link.BindLine, link.BoundLine("fp", "sig"))
	}
	if link.BindingLabel != "EXPERIMENTAL-qory-link-binding" || link.RemoteDiscoveryPath != "/qory-link/configuration" {
		t.Errorf("the label %q, the discovery %q", link.BindingLabel, link.RemoteDiscoveryPath)
	}
	if got, want := string(link.BindingMessage(ekm, "fp")), "qory-link-binding-ed25519-v1\n"+strings.Repeat("ab", 32)+"\nfp"; got != want {
		t.Errorf("the binding's message %q, want %q", got, want)
	}
	sum := sha256.Sum256([]byte(strings.Repeat("ab", 32) + "\nPOST\n/qory-link/v1/events?a=1\n[]"))
	if got := link.AnswerRequest(ekm, "POST", "/qory-link/v1/events?a=1", []byte("[]")); got != hex.EncodeToString(sum[:]) {
		t.Errorf("the answer's request line %s", got)
	}
	sum = sha256.Sum256([]byte(strings.Repeat("ab", 32) + "\nGET\n/qory-link/configuration\n"))
	if got := link.AnswerRequest(ekm, "GET", "/qory-link/configuration", nil); got != hex.EncodeToString(sum[:]) {
		t.Errorf("a GET's request line %s", got)
	}
}

// TestAnswerRequestHash pins the streaming form of AnswerRequest: the body written to
// it in pieces of any size gives the same line, the SHA-256 of the same bytes, for an
// empty body, a small one and one of 2 MiB.
func TestAnswerRequestHash(t *testing.T) {
	ekm := bytes.Repeat([]byte{0xab}, link.BindingSize)
	big := make([]byte, 2<<20)
	for i := range big {
		big[i] = byte(i*7 + i>>9)
	}
	for _, body := range [][]byte{nil, []byte("[]"), big} {
		h := link.AnswerRequestHash(ekm, "POST", "/qory-link/events")
		for rest, k := body, 1; len(rest) > 0; k = k*3 + 1 {
			n := min(k, len(rest))
			h.Write(rest[:n])
			rest = rest[n:]
		}
		sum := sha256.Sum256(append([]byte(strings.Repeat("ab", 32)+"\nPOST\n/qory-link/events\n"), body...))
		got := hex.EncodeToString(h.Sum(nil))
		if want := link.AnswerRequest(ekm, "POST", "/qory-link/events", body); got != want || got != hex.EncodeToString(sum[:]) {
			t.Errorf("a body of %d bytes: %s; AnswerRequest %s, the digest %x", len(body), got, want, sum)
		}
	}
}
