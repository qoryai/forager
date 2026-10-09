package link_test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/link"
)

// secret is a link secret of the tests, no real one.
const secret = "c2VjcmV0LW9mLXRoZS10ZXN0cw"

// TestLocalNeverPrintsItsSecret pins that a Local, by value or by pointer, shows its
// Secret under no verb, flag, method or slog handler, and still shows its other
// members.
func TestLocalNeverPrintsItsSecret(t *testing.T) {
	l := link.Local{
		Socket:   "/tmp/qory-link-1/sock",
		Secret:   secret,
		Proxy:    "127.0.0.1:41000",
		Files:    []link.File{{Path: "/home/user/.config/qory", What: "the gateway's directory"}, {Path: "/tmp/qory-tool-*", What: "where the tools' sockets are made"}},
		Reserved: []string{"QORY_RUN_SOCKET"},
	}
	var outs []string
	for _, v := range []any{l, &l} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%10v", "%-+v"} {
			outs = append(outs, fmt.Sprintf(format, v))
		}
		outs = append(outs, fmt.Sprint(v), fmt.Sprintln(v))
	}
	outs = append(outs, l.String(), l.GoString())
	for _, v := range []any{l, &l, map[string]any{"local": l}} {
		for _, marshal := range []func(any) ([]byte, error){json.Marshal, func(v any) ([]byte, error) { return jsonv2.Marshal(v) }} {
			b, err := marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			outs = append(outs, string(b))
		}
	}
	for _, h := range []func(io.Writer) slog.Handler{
		func(w io.Writer) slog.Handler { return slog.NewTextHandler(w, nil) },
		func(w io.Writer) slog.Handler { return slog.NewJSONHandler(w, nil) },
	} {
		var b bytes.Buffer
		slog.New(h(&b)).Info("link", "local", l)
		outs = append(outs, b.String())
	}
	hexed := hex.EncodeToString([]byte(secret))
	for _, out := range outs {
		if strings.Contains(out, secret) || strings.Contains(strings.ToLower(out), hexed) {
			t.Errorf("the secret is printed: %s", out)
		}
	}
	if got := fmt.Sprintf("%+v", l); !strings.Contains(got, "Socket:/tmp/qory-link-1/sock") || !strings.Contains(got, "Secret:[redacted]") || !strings.Contains(got, "Proxy:127.0.0.1:41000") {
		t.Errorf("%%+v: %s", got)
	}
	if got, want := fmt.Sprintf("%#v", l), `link.Local{Socket:"/tmp/qory-link-1/sock", Secret:"[redacted]", Proxy:"127.0.0.1:41000", Files:[]link.File{link.File{Path:"/home/user/.config/qory", What:"the gateway's directory"}, link.File{Path:"/tmp/qory-tool-*", What:"where the tools' sockets are made"}}, Reserved:[]string{"QORY_RUN_SOCKET"}}`; got != want {
		t.Errorf("%%#v:\n got %s\nwant %s", got, want)
	}
	if b, _ := json.Marshal(l); !strings.Contains(string(b), `"Secret":"[redacted]"`) || !strings.Contains(string(b), `"Socket":"/tmp/qory-link-1/sock"`) {
		t.Errorf("JSON: %s", b)
	}
	if got := fmt.Sprintf("%+v", link.Local{}); strings.Contains(got, "redacted") {
		t.Errorf("an empty secret is shown as redacted: %s", got)
	}
}

// TestLinkPreamble pins the local link's preamble: written in one write, read in
// exactly its length, and true only for the word, the secret and the newline.
func TestLinkPreamble(t *testing.T) {
	var b bytes.Buffer
	if err := link.WriteLinkPreamble(&b, secret); err != nil || b.String() != "QORY-LINK "+secret+"\n" {
		t.Fatalf("written %q, %v", b.String(), err)
	}
	read := func(in string) (bool, error, string) {
		r := bufio.NewReader(strings.NewReader(in))
		ok, err := link.ReadLinkPreamble(r, secret)
		rest, _ := io.ReadAll(r)
		return ok, err, string(rest)
	}
	if ok, err, rest := read("QORY-LINK " + secret + "\nGET / HTTP/1.1\r\n"); !ok || err != nil || rest != "GET / HTTP/1.1\r\n" {
		t.Errorf("the right secret: %v %v, then %q", ok, err, rest)
	}
	for name, in := range map[string]string{
		"a wrong secret":     "QORY-LINK " + strings.Repeat("x", len(secret)) + "\nGET / HTTP/1.1\r\n",
		"a shorter secret":   "QORY-LINK secret\nGET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
		"a wrong prefix":     "QORY-RELAY " + secret + "\nGET / HTTP/1.1\r\n",
		"no prefix":          secret + "\nGET / HTTP/1.1\r\n\r\n\r\n\r\n",
		"an overlong line":   "QORY-LINK " + secret + secret + "\n",
		"a line without \\n": "QORY-LINK " + secret + "GET / HTTP/1.1\r\n",
		"a carriage return":  "QORY-LINK " + secret + "\r\n",
		"HTTP without one":   "GET / HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n\r\n",
		"a lower-case word":  "qory-link " + secret + "\n",
		"two spaces":         "QORY-LINK  " + secret[1:] + "\n",
	} {
		ok, err, rest := read(in)
		if ok || err != nil {
			t.Errorf("%s: %v %v", name, ok, err)
		}
		if want := len("QORY-LINK " + secret + "\n"); len(in)-len(rest) != want {
			t.Errorf("%s: read %d bytes, want exactly %d", name, len(in)-len(rest), want)
		}
	}
	for name, in := range map[string]string{
		"nothing":            "",
		"a missing newline":  "QORY-LINK " + secret,
		"a part of the word": "QORY-",
	} {
		if ok, err, _ := read(in); ok || !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			t.Errorf("%s: %v %v, want an end of the connection", name, ok, err)
		}
	}
}

// TestLinkPreambleSlowWriter pins that a preamble written a byte at a time is read
// whole, and nothing after it.
func TestLinkPreambleSlowWriter(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		for _, c := range []byte("QORY-LINK " + secret + "\nGET") {
			pw.Write([]byte{c})
			time.Sleep(time.Millisecond)
		}
		pw.Close()
	}()
	r := bufio.NewReader(pr)
	if ok, err := link.ReadLinkPreamble(r, secret); !ok || err != nil {
		t.Fatalf("a slow writer: %v %v", ok, err)
	}
	if rest, _ := io.ReadAll(r); string(rest) != "GET" {
		t.Errorf("after the preamble: %q", rest)
	}
}

// TestPreambleSecretShape pins that no preamble carries an empty secret, one with a
// space, a control character or a newline, or one longer than MaxSecret, on either
// side.
func TestPreambleSecretShape(t *testing.T) {
	for _, s := range []string{"", "a b", "a\nb", "a\tb", "a\x7fb", "é", strings.Repeat("a", link.MaxSecret+1)} {
		var b bytes.Buffer
		if err := link.WriteLinkPreamble(&b, s); err == nil || b.Len() != 0 {
			t.Errorf("written with %q: %q %v", s, b.String(), err)
		}
		if ok, err := link.ReadLinkPreamble(bufio.NewReader(strings.NewReader("QORY-LINK "+s+"\n")), s); ok || err == nil {
			t.Errorf("read with %q: %v %v", s, ok, err)
		}
	}
	long := strings.Repeat("a", link.MaxSecret)
	var b bytes.Buffer
	if err := link.WriteLinkPreamble(&b, long); err != nil {
		t.Fatal(err)
	}
	if ok, err := link.ReadLinkPreamble(bufio.NewReader(&b), long); !ok || err != nil {
		t.Errorf("the longest secret: %v %v", ok, err)
	}
}

// TestRelayPreambleIsUnchanged pins the line the wall's relay writes and the proxy
// reads.
func TestRelayPreambleIsUnchanged(t *testing.T) {
	if got := link.Preamble(link.RelayPreamble, "the-runs-token"); got != "QORY-RELAY the-runs-token\n" {
		t.Errorf("relay preamble %q", got)
	}
}
