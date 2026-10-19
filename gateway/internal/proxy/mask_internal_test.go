package proxy

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// fakeKey and fakeToken are the values the test credentials set; neither is a real key.
const (
	fakeKey   = "fake-key-0001-not-a-real-secret"
	fakeToken = "fake/token+0002"
)

// echoed is what the echo origin received of one request.
type echoed struct {
	method, auth, acceptEncoding, rangeHeader, upgrade string
}

// echoOrigin is a TLS origin, under a certificate of up, that sends the credential it
// received back in its headers, its body, a 1xx and its trailer, on each path a way.
func echoOrigin(t *testing.T, up *CA) (*httptest.Server, func() []echoed) {
	t.Helper()
	var mu sync.Mutex
	var got []echoed
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization") + r.Header.Get("X-Api-Key")
		mu.Lock()
		got = append(got, echoed{r.Method, auth, r.Header.Get("Accept-Encoding"), r.Header.Get("Range"), r.Header.Get("Upgrade")})
		mu.Unlock()
		// The value alone, as a host that parses the header has it.
		value := strings.TrimPrefix(strings.TrimPrefix(auth, "Bearer "), "Basic ")
		switch r.URL.Path {
		case "/echo":
			w.Header().Set("Link", "</hint?k="+value+">; rel=preload")
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Del("Link")
			w.Header().Set("Set-Cookie", "session="+value+"; Secure")
			w.Header().Set("Location", "https://elsewhere.example/?token="+url.QueryEscape(value))
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+value+`"`)
			w.Header().Set("X-Seen-"+strings.ReplaceAll(value, "/", "-"), "1")
			w.Header().Set("Trailer", "X-Echo-Trailer")
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodHead {
				return
			}
			r.Header.Write(w)
			io.Copy(w, r.Body)
			io.WriteString(w, `{"auth":"`+strings.ReplaceAll(auth, "/", `\/`)+`"}`)
			w.Header().Set("X-Echo-Trailer", auth)
		case "/split":
			// The value split across two writes, each flushed.
			half := len(auth) / 2
			io.WriteString(w, "before "+auth[:half])
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
			io.WriteString(w, auth[half:]+" after")
		case "/length":
			body := "value " + auth
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			io.WriteString(w, body)
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			io.WriteString(zw, auth)
			zw.Close()
		case "/switch":
			conn, brw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" + auth)
			brw.Flush()
		default:
			io.WriteString(w, "value "+fakeKey)
		}
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return up.leaf(hello.ServerName) }}
	origin.StartTLS()
	return origin, func() []echoed {
		mu.Lock()
		defer mu.Unlock()
		out := got
		got = nil
		return out
	}
}

// maskedProxy is a proxy that terminates, against an echo origin, a host of a stored
// bearer, a host of a machine's basic token, and a host with a path rule and no
// credential.
func maskedProxy(t *testing.T) (*http.Client, *decisions, func() []echoed) {
	t.Helper()
	up, err := NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	origin, take := echoOrigin(t, up)
	t.Cleanup(origin.Close)
	seen := &decisions{}
	p, err := Listen("", policy.Observe, nil, nil, seen.observe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	p.dial = (&dials{plain: origin.Listener.Addr().String(), secure: origin.Listener.Addr().String()}).dial
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(up.PEM())
	p.TrustUpstream(roots)
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	value := []byte(fakeKey)
	p.Terminate(ca, []Credential{
		{Name: "bearer", Hosts: []string{"bearer.example"}, Scheme: "bearer", Value: func() []byte { return slices.Clone(value) }, Stored: true},
		{Name: "basic", Hosts: []string{"basic.example"}, Scheme: "basic", Username: "x-access-token", Token: func() string { return fakeToken }},
	}, map[string][]string{"plain.example": {"/*"}}, nil)
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(ca.PEM())
	proxyURL, _ := url.Parse(p.URL())
	client := &http.Client{
		Transport:     &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trusted}, DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return client, seen, take
}

// TestAKeyedHostRefusesTraceWith405 pins TRACE and TRACK on a host that gets a
// credential, of the server's or of the machine's: a 405 whose first line is the fix,
// the rule wall:echo-method, and nothing sent to the origin.
func TestAKeyedHostRefusesTraceWith405(t *testing.T) {
	client, seen, take := maskedProxy(t)
	for _, host := range []string{"bearer.example", "basic.example"} {
		for _, method := range []string{"TRACE", "TRACK", "trace"} {
			req, _ := http.NewRequest(method, "https://"+host+"/v1/models", nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			want := "qory: use a method other than TRACE or TRACK on this host.\n" +
				"qory: " + method + " " + host + "/v1/models denied by the gateway: this host gets a credential from the gateway, and the answer to TRACE or TRACK contains the request's headers\n"
			if resp.StatusCode != http.StatusMethodNotAllowed || string(b) != want {
				t.Errorf("%s %s: %d %q", method, host, resp.StatusCode, b)
			}
			if first, _, _ := strings.Cut(string(b), "\n"); len(first) > 100 {
				t.Errorf("the first line has %d characters", len(first))
			}
		}
	}
	if got := take(); len(got) != 0 {
		t.Errorf("a TRACE or a TRACK reached the origin: %+v", got)
	}
	seen.mu.Lock()
	defer seen.mu.Unlock()
	n := 0
	for _, d := range seen.seen {
		if d.PathRule == EchoMethod {
			n++
			if d.Allowed || d.Outcome != Refused || d.Credential != "" {
				t.Errorf("the refused TRACE's decision %+v", d)
			}
		}
	}
	if n != 6 {
		t.Errorf("%d decisions with %s, want 6", n, EchoMethod)
	}
}

// TestAKeyedHostsAnswerHasThePlaceholder pins the value replaced with the placeholder
// in what the host sends back: a 1xx, Set-Cookie, Location, WWW-Authenticate, a header's
// name, the body, the trailer, a body with a Content-Length, and, for basic, the
// base64 the header has and its percent-encoded and JSON-escaped forms. The request
// went upstream with Accept-Encoding identity, without its Range and its Upgrade.
func TestAKeyedHostsAnswerHasThePlaceholder(t *testing.T) {
	client, _, take := maskedProxy(t)
	basicValue := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + fakeToken))
	basicStand := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + link.Placeholder))
	for _, c := range []struct{ host, value, stand string }{
		{"bearer.example", fakeKey, link.Placeholder},
		{"basic.example", basicValue, basicStand},
	} {
		var hints []string
		trace := &httptrace.ClientTrace{Got1xxResponse: func(_ int, h textproto.MIMEHeader) error {
			hints = append(hints, h.Get("Link"))
			return nil
		}}
		req, _ := http.NewRequest(http.MethodPost, "https://"+c.host+"/echo", strings.NewReader("body "+c.value))
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		req.Header.Set("Authorization", "Bearer "+link.Placeholder)
		req.Header.Set("Accept-Encoding", "gzip")
		req.Header.Set("Range", "bytes=0-3")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		whole := strings.Join(hints, "\n") + "\n" + headerText(resp.Header) + "\n" + string(b) + "\n" + headerText(resp.Trailer)
		for _, leak := range []string{fakeKey, fakeToken, url.QueryEscape(fakeToken), basicValue, strings.TrimRight(basicValue, "="), url.QueryEscape(basicValue), strings.ReplaceAll(basicValue, "/", `\/`)} {
			if strings.Contains(whole, leak) {
				t.Errorf("%s: the answer contains %q:\n%s", c.host, leak, whole)
			}
		}
		if !strings.Contains(string(b), "Authorization: Bearer "+c.stand) && !strings.Contains(string(b), "Authorization: Basic "+c.stand) {
			t.Errorf("%s: the echoed header is not the placeholder:\n%s", c.host, b)
		}
		if !strings.Contains(string(b), "body "+c.stand) {
			t.Errorf("%s: the echoed body is not the placeholder:\n%s", c.host, b)
		}
		if resp.Trailer.Get("X-Echo-Trailer") == "" || !strings.Contains(resp.Trailer.Get("X-Echo-Trailer"), c.stand) {
			t.Errorf("%s: the trailer %q", c.host, resp.Trailer.Get("X-Echo-Trailer"))
		}
		if len(hints) != 1 || !strings.Contains(hints[0], url.QueryEscape(c.stand)) && !strings.Contains(hints[0], c.stand) {
			t.Errorf("%s: the 103's Link %q", c.host, hints)
		}
		if !strings.Contains(resp.Header.Get("Set-Cookie"), c.stand) || !strings.Contains(resp.Header.Get("WWW-Authenticate"), c.stand) || !strings.Contains(resp.Header.Get("Location"), c.stand) && !strings.Contains(resp.Header.Get("Location"), url.QueryEscape(c.stand)) {
			t.Errorf("%s: the headers:\n%s", c.host, headerText(resp.Header))
		}
		for _, e := range take() {
			if e.acceptEncoding != "identity" || e.rangeHeader != "" || e.upgrade != "" {
				t.Errorf("%s: the origin got %+v", c.host, e)
			}
		}

		// A HEAD has the headers replaced.
		resp, err = client.Head("https://" + c.host + "/echo")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if h := headerText(resp.Header); strings.Contains(h, fakeKey) || strings.Contains(h, fakeToken) || !strings.Contains(h, c.stand) {
			t.Errorf("%s: a HEAD's headers:\n%s", c.host, h)
		}

		// A body of a known length comes whole, with the placeholder, whatever its
		// length.
		resp, err = client.Get("https://" + c.host + "/length")
		if err != nil {
			t.Fatal(err)
		}
		b, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || !strings.HasSuffix(string(b), c.stand) {
			t.Errorf("%s: a body of a known length: %q, %v", c.host, b, err)
		}

		// A value split across two writes is replaced.
		resp, err = client.Get("https://" + c.host + "/split")
		if err != nil {
			t.Fatal(err)
		}
		b, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.HasPrefix(string(b), "before ") || !strings.HasSuffix(string(b), c.stand+" after") || strings.Contains(string(b), c.value) {
			t.Errorf("%s: a split value: %q", c.host, b)
		}
		take()
	}
}

// TestAKeyedHostsCompressedAnswerIsA502 pins a compressed answer from a host that gets
// a credential, which the origin sent although the request asked for identity: a 502
// whose first line is the fix, the origin's status in the record.
func TestAKeyedHostsCompressedAnswerIsA502(t *testing.T) {
	client, seen, take := maskedProxy(t)
	resp, err := client.Get("https://bearer.example/gzip")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	want := "qory: remove this host's credential from the policy, or serve the host through a tool.\n" +
		"qory: the gateway did not pass on the answer to GET bearer.example/gzip: it has Content-Encoding \"gzip\" although the request had Accept-Encoding: identity, and the gateway replaces the credential only in an uncompressed answer\n"
	if resp.StatusCode != http.StatusBadGateway || string(b) != want || resp.Header.Get("Content-Encoding") != "" {
		t.Errorf("a compressed answer: %d %q %v", resp.StatusCode, b, resp.Header)
	}
	if first, _, _ := strings.Cut(want, "\n"); len(first) > 100 {
		t.Errorf("the first line has %d characters", len(first))
	}
	if got := take(); len(got) != 1 || got[0].acceptEncoding != "identity" {
		t.Errorf("the origin got %+v", got)
	}
	seen.mu.Lock()
	d := seen.seen[len(seen.seen)-1]
	seen.mu.Unlock()
	if !d.Allowed || d.Outcome != Connected || d.Status != http.StatusOK || d.Credential != "bearer" {
		t.Errorf("the compressed answer's decision %+v", d)
	}
}

// TestAKeyedHostsSwitchIsA502 pins a 101 from a host that gets a credential: the
// request went without its Upgrade, so the switch is no upgrade it asked for, and the
// client gets a 502 with none of what the origin sent after it.
func TestAKeyedHostsSwitchIsA502(t *testing.T) {
	client, _, take := maskedProxy(t)
	req, _ := http.NewRequest(http.MethodGet, "https://bearer.example/switch", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := "upstream: " + errUnaskedSwitch.Error() + "\n"; resp.StatusCode != http.StatusBadGateway || string(b) != want {
		t.Errorf("a switch: %d %q", resp.StatusCode, b)
	}
	if got := take(); len(got) != 1 || got[0].upgrade != "" {
		t.Errorf("the origin got %+v", got)
	}
}

// TestAnUnkeyedHostsAnswerIsUntouched pins a terminated host without a credential: its
// answer comes as the origin sent it, its length and compression included, and its
// request as the client sent it.
func TestAnUnkeyedHostsAnswerIsUntouched(t *testing.T) {
	client, _, take := maskedProxy(t)
	resp, err := client.Get("https://plain.example/other")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "value "+fakeKey || resp.ContentLength != int64(len(b)) {
		t.Errorf("an unkeyed answer: %q, length %d", b, resp.ContentLength)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://plain.example/gzip", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Range", "bytes=0-")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("an unkeyed compressed answer: %d %v", resp.StatusCode, resp.Header)
	}
	if got := take(); len(got) != 2 || got[1].acceptEncoding != "gzip" || got[1].rangeHeader != "bytes=0-" {
		t.Errorf("the origin got %+v", got)
	}
}

// TestMaskingCatchesAValueAtEverySplit writes a body that contains the value twice, in
// two writes split at every place, and a body that ends in the start of the value.
func TestMaskingCatchesAValueAtEverySplit(t *testing.T) {
	c := &Credential{Scheme: "bearer"}
	m := c.masker([]byte(fakeKey))
	body := "a " + fakeKey + fakeKey + " b " + fakeKey[:5]
	want := "a " + link.Placeholder + link.Placeholder + " b " + fakeKey[:5]
	for i := 0; i <= len(body); i++ {
		rec := httptest.NewRecorder()
		mw := &masking{w: rec, m: m}
		mw.Write([]byte(body[:i]))
		mw.Flush()
		mw.Write([]byte(body[i:]))
		mw.finish()
		if got := rec.Body.String(); got != want {
			t.Errorf("split at %d: %q", i, got)
		}
	}
	// What cannot start the value is not kept back.
	rec := httptest.NewRecorder()
	mw := &masking{w: rec, m: m}
	mw.Write([]byte("data: done\n\n"))
	if got := rec.Body.String(); got != "data: done\n\n" {
		t.Errorf("an event that cannot start the value: %q", got)
	}
}

// TestTheMaskersForms pins the forms looked for: a value of letters, digits and
// hyphens in one form, a value with / and + also percent-encoded and with / escaped.
func TestTheMaskersForms(t *testing.T) {
	if m := (&Credential{Scheme: "header"}).masker([]byte(fakeKey)); len(m.pairs) != 1 {
		t.Errorf("a plain value has %d forms", len(m.pairs))
	}
	m := (&Credential{Scheme: "header"}).masker([]byte(fakeToken))
	var finds []string
	for _, p := range m.pairs {
		finds = append(finds, string(p.find))
	}
	if want := []string{fakeToken, "fake%2Ftoken%2B0002", `fake\/token+0002`}; !slices.Equal(finds, want) {
		t.Errorf("the forms %q, want %q", finds, want)
	}
	if (&Credential{}).masker(nil) != nil {
		t.Error("an empty value has a masker")
	}
}

// headerText is h as lines.
func headerText(h http.Header) string {
	var b bytes.Buffer
	h.Write(&b)
	return b.String()
}
