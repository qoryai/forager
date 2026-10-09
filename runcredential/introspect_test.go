package runcredential

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The neutral example client of the introspection endpoint, and a run credential's
// stand-in: the introspector sends it as it is, and reads nothing of it.
const (
	exampleClientID   = "example-gateway"
	exampleSecret     = "example-secret-value"
	exampleCredential = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyay0wMDAxIn0.c2lnbmF0dXJl"
)

// endpoint is a TLS introspection endpoint answering with answer, and what it was
// asked.
type endpoint struct {
	srv   *httptest.Server
	asked atomic.Int32
	mu    sync.Mutex
	last  *http.Request
	form  url.Values
}

func newEndpoint(t *testing.T, answer http.HandlerFunc) *endpoint {
	t.Helper()
	e := &endpoint{}
	mux := http.NewServeMux()
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		e.asked.Add(1)
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		e.mu.Lock()
		e.last, e.form = r, form
		e.mu.Unlock()
		answer(w, r)
	})
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"active": true}`)
	})
	e.srv = httptest.NewTLSServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

// introspector is the client of the endpoint, its secret in a file.
func (e *endpoint) introspector(t *testing.T, in Introspection, timeout time.Duration) *Introspector {
	t.Helper()
	if in.URL == "" {
		in.URL = e.srv.URL + "/introspect"
	}
	if in.ClientID == "" {
		in.ClientID = exampleClientID
	}
	in.ClientSecretFile = "/etc/qory/issuer-introspection-secret"
	roots := x509.NewCertPool()
	roots.AddCert(e.srv.Certificate())
	c, err := newIntrospector(in, files(map[string][]byte{in.ClientSecretFile: []byte(exampleSecret + "\n")}), 30*time.Second, roots, timeout)
	if err != nil {
		t.Fatal(err)
	}
	// Short waits, so a test of a failure is not slowed by its tries.
	c.waits, c.window = []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}, 40*time.Millisecond
	return c
}

// answering is a handler that answers status and body.
func answering(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

func TestIntrospectionIsActiveOnlyOnActiveTrue(t *testing.T) {
	invalid, unreachable := ErrAnswerInvalid, ErrIssuerUnreachable
	for _, c := range []struct {
		name    string
		handler http.HandlerFunc
		active  bool
		want    error // nil for an answer, active or not
	}{
		{"active true", answering(200, `{"active": true, "sub": "rk-0001"}`), true, nil},
		{"active true after white space", answering(200, "\n {\"active\":true}\n"), true, nil},
		{"active false", answering(200, `{"active": false}`), false, nil},
		{"active the string true", answering(200, `{"active": "true"}`), false, invalid},
		{"active 1", answering(200, `{"active": 1}`), false, invalid},
		{"active null", answering(200, `{"active": null}`), false, invalid},
		{"no active", answering(200, `{"sub": "rk-0001"}`), false, invalid},
		{"active twice", answering(200, `{"active": true, "active": true}`), false, invalid},
		{"active false then true", answering(200, `{"active": false, "active": true}`), false, invalid},
		{"an array", answering(200, `[{"active": true}]`), false, invalid},
		{"not JSON", answering(200, `active: true`), false, invalid},
		{"two JSON values", answering(200, `{"active": true} {"active": true}`), false, invalid},
		{"empty", answering(200, ``), false, invalid},
		{"500", answering(500, `{"active": true}`), false, unreachable},
		{"429", answering(429, `{"active": true}`), false, unreachable},
		{"201", answering(201, `{"active": true}`), false, invalid},
		{"401", answering(401, `{"active": true}`), false, invalid},
		{"a redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}, false, invalid},
		{"a permanent redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusPermanentRedirect)
		}, false, invalid},
		{"oversized", answering(200, `{"active": true, "pad": "`+strings.Repeat("a", MaxIntrospectionAnswer)+`"}`), false, invalid},
		{"at the size limit", answering(200, `{"active": true, "pad": "`+strings.Repeat("a", MaxIntrospectionAnswer-len(`{"active": true, "pad": ""}`))+`"}`), true, nil},
		{"a timeout", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
			answering(200, `{"active": true}`)(w, r)
		}, false, unreachable},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEndpoint(t, c.handler)
			in := e.introspector(t, Introspection{}, 300*time.Millisecond)
			active, err := in.Active(context.Background(), exampleCredential, now)
			if active != c.active || (err == nil) != (c.want == nil) || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("Active = %v, %v; want %v, %v", active, err, c.active, c.want)
			}
			if err != nil {
				for _, s := range []string{exampleCredential, exampleSecret, "c2lnbmF0dXJl", e.srv.URL} {
					if strings.Contains(err.Error(), s) {
						t.Errorf("the error %q holds %q", err, s)
					}
				}
			}
		})
	}
}

// TestIntrospectionRequest pins the request of RFC 7662 §2.1: a POST of the form
// token and token_type_hint, HTTP Basic with the client id and the secret read from its
// file, each form-encoded (RFC 6749 §2.3.1), less the file's line ending.
func TestIntrospectionRequest(t *testing.T) {
	e := newEndpoint(t, answering(200, `{"active": true}`))
	in := e.introspector(t, Introspection{}, IntrospectionTimeout)
	if active, err := in.Active(context.Background(), exampleCredential, now); !active || err != nil {
		t.Fatalf("Active = %v, %v", active, err)
	}
	e.mu.Lock()
	r, form := e.last, e.form
	e.mu.Unlock()
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Accept") != "application/json" {
		t.Errorf("the request is %s with %v", r.Method, r.Header)
	}
	if r.TLS == nil {
		t.Error("the request is not over TLS")
	}
	if len(form) != 2 || form.Get("token") != exampleCredential || form.Get("token_type_hint") != "access_token" {
		t.Errorf("the form is %v", form)
	}
	user, pass, ok := r.BasicAuth()
	if !ok || user != exampleClientID || pass != exampleSecret {
		t.Errorf("Basic %q:%q, %v; want the client id and the secret", user, pass, ok)
	}

	// A client id and a secret outside the unreserved characters are form-encoded.
	e2 := newEndpoint(t, answering(200, `{"active": true}`))
	roots := x509.NewCertPool()
	roots.AddCert(e2.srv.Certificate())
	secret := "a secret:with+signs%"
	c, err := newIntrospector(Introspection{URL: e2.srv.URL + "/introspect", ClientID: "example gateway", ClientSecretFile: "s"},
		files(map[string][]byte{"s": []byte(secret + "\r\n")}), time.Minute, roots, IntrospectionTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if active, err := c.Active(context.Background(), exampleCredential, now); !active || err != nil {
		t.Fatalf("Active = %v, %v", active, err)
	}
	e2.mu.Lock()
	user, pass, _ = e2.last.BasicAuth()
	e2.mu.Unlock()
	if u, _ := url.QueryUnescape(user); u != "example gateway" || user != "example+gateway" {
		t.Errorf("the user is %q", user)
	}
	if p, _ := url.QueryUnescape(pass); p != secret {
		t.Errorf("the password is %q", pass)
	}
}

func TestIntrospectionCache(t *testing.T) {
	e := newEndpoint(t, answering(200, `{"active": true}`))
	in := e.introspector(t, Introspection{Cache: d(30 * time.Second)}, IntrospectionTimeout)
	if in.Cache() != 30*time.Second {
		t.Errorf("Cache = %v", in.Cache())
	}
	ctx := context.Background()
	for _, at := range []time.Duration{0, time.Second, 29 * time.Second} {
		if active, err := in.Active(ctx, exampleCredential, now.Add(at)); !active || err != nil {
			t.Fatalf("at %v: %v, %v", at, active, err)
		}
	}
	if n := e.asked.Load(); n != 1 {
		t.Errorf("asked %d times within the cache; want once", n)
	}
	in.Active(ctx, exampleCredential, now.Add(30*time.Second))
	if n := e.asked.Load(); n != 2 {
		t.Errorf("asked %d times once the cache passed; want twice", n)
	}
	in.Active(ctx, exampleCredential+"x", now.Add(30*time.Second))
	if n := e.asked.Load(); n != 3 {
		t.Errorf("another run credential: asked %d times; want three", n)
	}
	// The answers are kept by the SHA-256 of the run credential, never by the run
	// credential itself.
	in.mu.Lock()
	if len(in.answers) != 2 {
		t.Errorf("%d answers kept; want 2", len(in.answers))
	}
	in.mu.Unlock()

	// The cache defaults to the heartbeat interval.
	def := e.introspector(t, Introspection{}, IntrospectionTimeout)
	if def.Cache() != 30*time.Second {
		t.Errorf("the default cache is %v; want the heartbeat interval", def.Cache())
	}

	// A failure is kept for no one: the next caller asks again.
	var fail atomic.Bool
	fail.Store(true)
	f := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			answering(500, ``)(w, r)
			return
		}
		answering(200, `{"active": true}`)(w, r)
	})
	fi := f.introspector(t, Introspection{Cache: d(10 * time.Second)}, IntrospectionTimeout)
	if active, err := fi.Active(ctx, exampleCredential, now); active || err == nil {
		t.Fatalf("a 500: %v, %v", active, err)
	}
	fi.mu.Lock()
	if len(fi.answers) != 0 {
		t.Errorf("%d answers kept of a failure", len(fi.answers))
	}
	fi.mu.Unlock()
	fail.Store(false)
	if active, err := fi.Active(ctx, exampleCredential, now.Add(time.Second)); !active || err != nil {
		t.Errorf("the next caller after a failure: %v, %v", active, err)
	}
	if n := f.asked.Load(); n != 4 {
		t.Errorf("asked %d times; want the three tries of the failure and once after", n)
	}
}

// TestIntrospectionKeepsABoundedCache pins the bound on the answers kept: the answers
// past their time go when another is kept, and while the cache is full the one that
// would lapse first goes.
func TestIntrospectionKeepsABoundedCache(t *testing.T) {
	defer func(n int) { maxAnswers = n }(maxAnswers)
	maxAnswers = 3
	e := newEndpoint(t, answering(200, `{"active": true}`))
	in := e.introspector(t, Introspection{Cache: d(10 * time.Second)}, IntrospectionTimeout)
	ctx := context.Background()
	kept := func() int {
		in.mu.Lock()
		defer in.mu.Unlock()
		return len(in.answers)
	}
	for i := range 3 {
		in.Active(ctx, exampleCredential+fmt.Sprint(i), now.Add(time.Duration(i)*time.Second))
	}
	if kept() != 3 {
		t.Fatalf("%d kept", kept())
	}
	// Full: the first, which lapses first, goes for a fourth.
	in.Active(ctx, exampleCredential+"3", now.Add(3*time.Second))
	if kept() != 3 {
		t.Errorf("%d kept past the cap", kept())
	}
	asked := e.asked.Load()
	in.Active(ctx, exampleCredential+"1", now.Add(3*time.Second))
	if e.asked.Load() != asked {
		t.Error("a kept answer was asked again")
	}
	in.Active(ctx, exampleCredential+"0", now.Add(3*time.Second))
	if e.asked.Load() != asked+1 {
		t.Error("the answer that lapses first was kept past the cap")
	}
	// Past their time, the answers go when the next is kept.
	in.Active(ctx, exampleCredential+"later", now.Add(time.Minute))
	if kept() != 1 {
		t.Errorf("%d kept past their time", kept())
	}
}

// TestIntrospectionACallerThatGivesUp pins that the caller whose request is in flight
// giving up, its context ending, leaves the other callers for the same run credential
// waiting for the answer, which is kept.
func TestIntrospectionACallerThatGivesUp(t *testing.T) {
	release := make(chan struct{})
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		answering(200, `{"active": true}`)(w, r)
	})
	in := e.introspector(t, Introspection{}, IntrospectionTimeout)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan bool)
	go func() {
		active, err := in.Active(ctx, exampleCredential, now)
		first <- active || !errors.Is(err, context.Canceled)
	}()
	for e.asked.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	second := make(chan bool)
	go func() {
		active, _ := in.Active(context.Background(), exampleCredential, now)
		second <- active
	}()
	cancel()
	if <-first {
		t.Error("the caller that gave up is active, or its error is not its context's")
	}
	close(release)
	if !<-second {
		t.Error("the other caller is not active once its first gave up")
	}
	if active, _ := in.Active(context.Background(), exampleCredential, now); !active || e.asked.Load() != 1 {
		t.Errorf("the answer was not kept: asked %d times", e.asked.Load())
	}
}

// TestIntrospectionAsksOnceForConcurrentCallers pins that callers for the same run
// credential while a request is in flight wait for its answer.
func TestIntrospectionAsksOnceForConcurrentCallers(t *testing.T) {
	release := make(chan struct{})
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		answering(200, `{"active": true}`)(w, r)
	})
	in := e.introspector(t, Introspection{}, IntrospectionTimeout)
	var wg sync.WaitGroup
	results := make([]bool, 8)
	for n := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[n], _ = in.Active(context.Background(), exampleCredential, now)
		}()
	}
	for e.asked.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	for n, r := range results {
		if !r {
			t.Errorf("caller %d: not active", n)
		}
	}
	if n := e.asked.Load(); n != 1 {
		t.Errorf("asked %d times; want once", n)
	}
}

// TestIntrospectionAContextThatEnds pins that a request whose context ends is not
// active and is not kept.
func TestIntrospectionAContextThatEnds(t *testing.T) {
	e := newEndpoint(t, answering(200, `{"active": true}`))
	in := e.introspector(t, Introspection{}, IntrospectionTimeout)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if active, err := in.Active(ctx, exampleCredential, now); active || !errors.Is(err, context.Canceled) || errors.Is(err, ErrIssuerUnreachable) {
		t.Fatalf("a context that ended: %v, %v; want its own error", active, err)
	}
	if active, err := in.Active(context.Background(), exampleCredential, now); !active || err != nil {
		t.Errorf("the answer after: %v, %v", active, err)
	}
}

func TestNewIntrospectorRefuses(t *testing.T) {
	read := files(map[string][]byte{"secret": []byte(exampleSecret), "empty": []byte("\n")})
	good := Introspection{URL: "https://issuer.example/introspect", ClientID: exampleClientID, ClientSecretFile: "secret"}
	if _, err := NewIntrospector(good, read, 30*time.Second); err != nil {
		t.Fatalf("NewIntrospector: %v", err)
	}
	for _, c := range []struct {
		name      string
		change    func(*Introspection)
		heartbeat time.Duration
		want      string
	}{
		{"plain http", func(i *Introspection) { i.URL = "http://issuer.example/introspect" }, time.Minute, "not an https URL"},
		{"no client id", func(i *Introspection) { i.ClientID = "" }, time.Minute, "no client id"},
		{"a missing secret file", func(i *Introspection) { i.ClientSecretFile = "missing" }, time.Minute, "missing"},
		{"an empty secret", func(i *Introspection) { i.ClientSecretFile = "empty" }, time.Minute, "empty is empty"},
		{"no cache and no heartbeat", func(*Introspection) {}, 0, "cache"},
	} {
		in := good
		c.change(&in)
		_, err := NewIntrospector(in, read, c.heartbeat)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v; want an error with %q", c.name, err, c.want)
		} else if strings.Contains(err.Error(), exampleSecret) {
			t.Errorf("%s: the error holds the secret: %v", c.name, err)
		}
	}
	if _, err := NewIntrospector(good, nil, time.Minute); err == nil {
		t.Error("NewIntrospector without a reader")
	}
	readErr := errors.New("permission denied")
	if _, err := NewIntrospector(good, func(string) ([]byte, error) { return nil, readErr }, time.Minute); !errors.Is(err, readErr) {
		t.Errorf("a read error is not wrapped: %v", err)
	}
}

// TestIntrospectionRefusesAnUntrustedCertificate pins that the endpoint's certificate
// is verified: under the system's roots, the test server's own is not trusted.
func TestIntrospectionRefusesAnUntrustedCertificate(t *testing.T) {
	e := newEndpoint(t, answering(200, `{"active": true}`))
	in, err := newIntrospector(Introspection{URL: e.srv.URL + "/introspect", ClientID: exampleClientID, ClientSecretFile: "s"},
		files(map[string][]byte{"s": []byte(exampleSecret)}), time.Minute, nil, IntrospectionTimeout)
	if err != nil {
		t.Fatal(err)
	}
	in.waits, in.window = []time.Duration{time.Millisecond, time.Millisecond}, 10*time.Millisecond
	if active, err := in.Active(context.Background(), exampleCredential, now); active || err == nil {
		t.Errorf("an untrusted certificate: %v, %v", active, err)
	}
	if e.asked.Load() != 0 {
		t.Error("the run credential reached an endpoint whose certificate is not trusted")
	}
}

// TestIntrospectionIgnoresTheProxyVariables pins that the introspector reaches the
// endpoint directly: with HTTPS_PROXY and HTTP_PROXY set, the run credential goes to
// the endpoint and never to the proxy. The endpoint is named example.com, which the
// test server's certificate covers, since no proxy is ever used for a loopback address
// whatever the variables say.
func TestIntrospectionIgnoresTheProxyVariables(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(proxy.Close)
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(name, proxy.URL)
	}
	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		t.Setenv(name, "")
	}
	e := newEndpoint(t, answering(200, `{"active": true}`))
	_, port, _ := net.SplitHostPort(e.srv.Listener.Addr().String())
	in := e.introspector(t, Introspection{URL: "https://example.com:" + port + "/introspect"}, IntrospectionTimeout)
	tr := in.client.Transport.(*http.Transport)
	if tr.Proxy != nil {
		t.Fatal("the transport has a proxy")
	}
	var mu sync.Mutex
	var dialed []string
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		if addr != "example.com:"+port {
			return nil, errors.New("not the endpoint")
		}
		return (&net.Dialer{}).DialContext(ctx, network, e.srv.Listener.Addr().String())
	}
	if active, err := in.Active(context.Background(), exampleCredential, now); !active || err != nil {
		t.Fatalf("Active = %v, %v", active, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if proxied.Load() != 0 || len(dialed) != 1 || dialed[0] != "example.com:"+port || e.asked.Load() != 1 {
		t.Errorf("dialed %v, the proxy asked %d times, the endpoint %d", dialed, proxied.Load(), e.asked.Load())
	}
}

// TestIntrospectionTriesAndTheirWaits pins the tries of one introspection as the
// gateway makes them: each 2 seconds at most, up to three, 1 second and then 2 seconds
// apart, a try starting only within 4 seconds of the first.
func TestIntrospectionTriesAndTheirWaits(t *testing.T) {
	if IntrospectionTimeout != 2*time.Second || !slices.Equal(introspectionWaits, []time.Duration{time.Second, 2 * time.Second}) || introspectionWindow != 4*time.Second {
		t.Fatalf("a try's timeout %v, the waits %v, the window %v; want 2s, [1s 2s], 4s", IntrospectionTimeout, introspectionWaits, introspectionWindow)
	}
	read := files(map[string][]byte{"s": []byte(exampleSecret)})
	in, err := NewIntrospector(Introspection{URL: "https://issuer.example/introspect", ClientID: exampleClientID, ClientSecretFile: "s"}, read, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if in.client.Timeout != 2*time.Second || !slices.Equal(in.waits, introspectionWaits) || in.window != introspectionWindow {
		t.Errorf("the introspector's timeout %v, waits %v, window %v", in.client.Timeout, in.waits, in.window)
	}
}

// failing is an endpoint whose first answers are the failures given, in order, and
// active true after them: 0 for a connection closed unanswered, else the status.
func failing(t *testing.T, failures ...int) *endpoint {
	t.Helper()
	var n atomic.Int32
	return newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		i := int(n.Add(1)) - 1
		if i >= len(failures) {
			answering(200, `{"active": true}`)(w, r)
			return
		}
		if failures[i] == 0 {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				conn.Close()
			}
			return
		}
		answering(failures[i], ``)(w, r)
	})
}

// recordWaits makes the introspector's waits instant, the default waits and window
// kept, and returns what it waited.
func recordWaits(in *Introspector) func() []time.Duration {
	in.waits, in.window = introspectionWaits, introspectionWindow
	var mu sync.Mutex
	var waited []time.Duration
	in.sleep = func(d time.Duration) {
		mu.Lock()
		waited = append(waited, d)
		mu.Unlock()
	}
	return func() []time.Duration {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(waited)
	}
}

// TestIntrospectionTriesAgainWithoutAnAnswer pins the tries of a check that gets no
// answer: a 5xx, a 429 and a connection closed unanswered are each tried again, 1
// second and then 2 seconds later, and an answer on the third try is the check's.
func TestIntrospectionTriesAgainWithoutAnAnswer(t *testing.T) {
	for name, failures := range map[string][]int{
		"a 503, then no answer": {503, 0},
		"a 429, then a 500":     {429, 500},
	} {
		t.Run(name, func(t *testing.T) {
			e := failing(t, failures...)
			in := e.introspector(t, Introspection{}, IntrospectionTimeout)
			waited := recordWaits(in)
			if active, err := in.Active(context.Background(), exampleCredential, now); !active || err != nil {
				t.Fatalf("Active = %v, %v; want the third try's answer", active, err)
			}
			if n := e.asked.Load(); n != 3 {
				t.Errorf("asked %d times; want 3", n)
			}
			if got := waited(); !slices.Equal(got, []time.Duration{time.Second, 2 * time.Second}) {
				t.Errorf("waited %v; want [1s 2s]", got)
			}
		})
	}
}

// TestIntrospectionThatNeverAnswers pins a check whose three tries all get no answer:
// ErrIssuerUnreachable, kept for no one, so the next caller tries three times again.
func TestIntrospectionThatNeverAnswers(t *testing.T) {
	e := newEndpoint(t, answering(503, ``))
	in := e.introspector(t, Introspection{}, IntrospectionTimeout)
	waited := recordWaits(in)
	active, err := in.Active(context.Background(), exampleCredential, now)
	if active || !errors.Is(err, ErrIssuerUnreachable) || errors.Is(err, ErrAnswerInvalid) {
		t.Fatalf("Active = %v, %v; want ErrIssuerUnreachable", active, err)
	}
	if err.Error() != "the introspection endpoint could not be reached" {
		t.Errorf("the error %q", err)
	}
	if n := e.asked.Load(); n != 3 {
		t.Errorf("asked %d times; want 3", n)
	}
	if got := waited(); !slices.Equal(got, []time.Duration{time.Second, 2 * time.Second}) {
		t.Errorf("waited %v; want [1s 2s]", got)
	}
	in.Active(context.Background(), exampleCredential, now)
	if n := e.asked.Load(); n != 6 {
		t.Errorf("asked %d times after a second check; want 6: the failure is not kept", n)
	}
}

// TestIntrospectionWithNoValidAnswer pins an answer that is no valid one: a status other
// than 200, 5xx and 429 aside, and a 200 too long, not JSON or without a boolean active.
// Each is tried once, is ErrAnswerInvalid, names the status where it is one, and is kept
// for no one; active false is tried once too, and kept.
func TestIntrospectionWithNoValidAnswer(t *testing.T) {
	for _, c := range []struct {
		name    string
		handler http.HandlerFunc
		text    string
	}{
		{"302", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) }, "the introspection endpoint answered status 302"},
		{"400", answering(400, `{"error":"invalid_request"}`), "the introspection endpoint answered status 400"},
		{"401", answering(401, `{"error":"invalid_client"}`), "the introspection endpoint answered status 401"},
		{"403", answering(403, ``), "the introspection endpoint answered status 403"},
		{"too long", answering(200, `{"active": true, "pad": "`+strings.Repeat("a", MaxIntrospectionAnswer)+`"}`), "the introspection endpoint answered more than MaxIntrospectionAnswer bytes"},
		{"not JSON", answering(200, `active: true`), "the introspection endpoint answered other than one JSON object with each member name once"},
		{"no boolean active", answering(200, `{"active": "yes"}`), "the introspection endpoint answered no boolean active"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEndpoint(t, c.handler)
			in := e.introspector(t, Introspection{}, IntrospectionTimeout)
			waited := recordWaits(in)
			active, err := in.Active(context.Background(), exampleCredential, now)
			if active || !errors.Is(err, ErrAnswerInvalid) || errors.Is(err, ErrIssuerUnreachable) {
				t.Fatalf("Active = %v, %v; want ErrAnswerInvalid", active, err)
			}
			if err.Error() != c.text {
				t.Errorf("the error %q; want %q", err, c.text)
			}
			if n := e.asked.Load(); n != 1 || len(waited()) != 0 {
				t.Errorf("asked %d times, waited %v; want once", n, waited())
			}
			in.Active(context.Background(), exampleCredential, now)
			if n := e.asked.Load(); n != 2 {
				t.Errorf("asked %d times after a second check; want twice: it is not kept", n)
			}
		})
	}
	e := newEndpoint(t, answering(200, `{"active": false}`))
	in := e.introspector(t, Introspection{}, IntrospectionTimeout)
	for range 2 {
		if active, err := in.Active(context.Background(), exampleCredential, now); active || err != nil {
			t.Fatalf("active false: %v, %v", active, err)
		}
	}
	if n := e.asked.Load(); n != 1 {
		t.Errorf("active false: asked %d times; want once, kept", n)
	}
}

// TestIntrospectionTheWindow pins the window, at a tenth of the gateway's times: a try
// starts only within the window of the first's start, so an endpoint that hangs gets two
// tries, each to its timeout, and one that fails at once three, or two when the third
// would start past the window.
func TestIntrospectionTheWindow(t *testing.T) {
	hang := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	in := hang.introspector(t, Introspection{}, 200*time.Millisecond)
	in.waits, in.window = []time.Duration{100 * time.Millisecond, 200 * time.Millisecond}, 400*time.Millisecond
	start := time.Now()
	if _, err := in.Active(context.Background(), exampleCredential, now); !errors.Is(err, ErrIssuerUnreachable) {
		t.Fatalf("a hung endpoint: %v", err)
	}
	took := time.Since(start)
	if n := hang.asked.Load(); n != 2 {
		t.Errorf("a hung endpoint: asked %d times; want 2", n)
	}
	if took < 500*time.Millisecond || took > 1500*time.Millisecond {
		t.Errorf("a hung endpoint: took %v; want about 0.5s, two tries and the wait between", took)
	}
	for _, c := range []struct {
		window time.Duration
		tries  int32
	}{{400 * time.Millisecond, 3}, {250 * time.Millisecond, 2}} {
		e := newEndpoint(t, answering(503, ``))
		in := e.introspector(t, Introspection{}, IntrospectionTimeout)
		in.waits, in.window = []time.Duration{100 * time.Millisecond, 200 * time.Millisecond}, c.window
		in.Active(context.Background(), exampleCredential, now)
		if n := e.asked.Load(); n != c.tries {
			t.Errorf("failing at once, a window of %v: asked %d times; want %d", c.window, n, c.tries)
		}
	}
}

// TestIntrospectionTriesOnceForEveryCaller pins one sequence of tries for every caller
// of the same run credential: those that came during the first try and one that came
// during a wait between tries all get the third try's answer, of three requests, and a
// caller whose context ends gets its context's error while the others still get the
// answer.
func TestIntrospectionTriesOnceForEveryCaller(t *testing.T) {
	e := failing(t, 503, 503)
	in := e.introspector(t, Introspection{}, IntrospectionTimeout)
	waiting := make(chan struct{})
	release := make(chan struct{})
	in.sleep = func(time.Duration) {
		waiting <- struct{}{}
		<-release
	}
	var wg sync.WaitGroup
	results := make([]bool, 6)
	call := func(n int) {
		defer wg.Done()
		active, err := in.Active(context.Background(), exampleCredential, now)
		results[n] = active && err == nil
	}
	for n := range 4 {
		wg.Add(1)
		go call(n)
	}
	gone, cancel := context.WithCancel(context.Background())
	goneErr := make(chan error, 1)
	go func() {
		_, err := in.Active(gone, exampleCredential, now)
		goneErr <- err
	}()
	<-waiting
	// During the first wait: a late caller, and one that gives up.
	wg.Add(1)
	go call(4)
	cancel()
	if err := <-goneErr; !errors.Is(err, context.Canceled) {
		t.Errorf("the caller that gave up: %v; want its context's error", err)
	}
	release <- struct{}{}
	<-waiting
	// During the second wait, another.
	wg.Add(1)
	go call(5)
	time.Sleep(20 * time.Millisecond)
	release <- struct{}{}
	wg.Wait()
	for n, ok := range results {
		if !ok {
			t.Errorf("caller %d: not active", n)
		}
	}
	if n := e.asked.Load(); n != 3 {
		t.Errorf("asked %d times; want one sequence of 3 tries", n)
	}
}

// TestIntrospectionReadsTheStartersOutcome pins qory_outcome and qory_reason: read of an
// inactive answer alone; an outcome other than succeeded, failed and cancelled counts
// as none, and drops the reason with it; a reason that is no code of the pattern, or one
// of Forager's reserved codes, is dropped and the outcome kept; a member that is no
// string is none; and neither makes the answer invalid.
func TestIntrospectionReadsTheStartersOutcome(t *testing.T) {
	for _, c := range []struct {
		name, body string
		want       Answer
	}{
		{"an outcome and a reason", `{"active": false, "qory_outcome": "succeeded", "qory_reason": "all_checks_passed"}`, Answer{Outcome: "succeeded", Reason: "all_checks_passed"}},
		{"failed", `{"active": false, "qory_outcome": "failed", "qory_reason": "checks_failed"}`, Answer{Outcome: "failed", Reason: "checks_failed"}},
		{"cancelled", `{"active": false, "qory_outcome": "cancelled", "qory_reason": "no_longer_needed"}`, Answer{Outcome: "cancelled", Reason: "no_longer_needed"}},
		{"an outcome alone", `{"active": false, "qory_outcome": "failed"}`, Answer{Outcome: "failed"}},
		{"nothing", `{"active": false}`, Answer{}},
		{"a reason alone", `{"active": false, "qory_reason": "checks_failed"}`, Answer{}},
		{"an unknown outcome", `{"active": false, "qory_outcome": "lost", "qory_reason": "checks_failed"}`, Answer{}},
		{"an outcome of another case", `{"active": false, "qory_outcome": "Succeeded"}`, Answer{}},
		{"an outcome that is no string", `{"active": false, "qory_outcome": true, "qory_reason": "checks_failed"}`, Answer{}},
		{"a reserved reason", `{"active": false, "qory_outcome": "cancelled", "qory_reason": "timeout"}`, Answer{Outcome: "cancelled"}},
		{"an old name", `{"active": false, "qory_outcome": "cancelled", "qory_reason": "run_ended_at_issuer"}`, Answer{Outcome: "cancelled"}},
		{"run_closed", `{"active": false, "qory_outcome": "failed", "qory_reason": "run_closed"}`, Answer{Outcome: "failed"}},
		{"a reason of upper case", `{"active": false, "qory_outcome": "failed", "qory_reason": "Checks_failed"}`, Answer{Outcome: "failed"}},
		{"a reason with a space", `{"active": false, "qory_outcome": "failed", "qory_reason": "checks failed"}`, Answer{Outcome: "failed"}},
		{"a reason too long", `{"active": false, "qory_outcome": "failed", "qory_reason": "a` + strings.Repeat("b", 64) + `"}`, Answer{Outcome: "failed"}},
		{"a reason that is no string", `{"active": false, "qory_outcome": "failed", "qory_reason": 1}`, Answer{Outcome: "failed"}},
		{"an active answer's members", `{"active": true, "qory_outcome": "failed", "qory_reason": "checks_failed"}`, Answer{Active: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEndpoint(t, answering(200, c.body))
			got, err := e.introspector(t, Introspection{}, IntrospectionTimeout).Answer(context.Background(), exampleCredential, now)
			if err != nil || got != c.want {
				t.Errorf("%+v, %v; want %+v", got, err, c.want)
			}
		})
	}
}

// TestIntrospectionAnswerNowAsksPastTheCache pins the ask at a runtime's exit: AnswerNow
// asks the endpoint whatever the cache holds, and the answer it gets is kept for the
// callers of Answer after it.
func TestIntrospectionAnswerNowAsksPastTheCache(t *testing.T) {
	var inactive atomic.Bool
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		if inactive.Load() {
			answering(200, `{"active": false, "qory_outcome": "cancelled", "qory_reason": "no_longer_needed"}`)(w, r)
			return
		}
		answering(200, `{"active": true}`)(w, r)
	})
	in := e.introspector(t, Introspection{Cache: d(30 * time.Second)}, IntrospectionTimeout)
	ctx := context.Background()
	if a, err := in.Answer(ctx, exampleCredential, now); !a.Active || err != nil {
		t.Fatalf("%+v, %v", a, err)
	}
	inactive.Store(true)
	if a, err := in.Answer(ctx, exampleCredential, now.Add(time.Second)); !a.Active || err != nil || e.asked.Load() != 1 {
		t.Fatalf("from the cache: %+v, %v, asked %d", a, err, e.asked.Load())
	}
	want := Answer{Outcome: "cancelled", Reason: "no_longer_needed"}
	if a, err := in.AnswerNow(ctx, exampleCredential, now.Add(2*time.Second)); a != want || err != nil || e.asked.Load() != 2 {
		t.Fatalf("AnswerNow: %+v, %v, asked %d", a, err, e.asked.Load())
	}
	if a, err := in.Answer(ctx, exampleCredential, now.Add(3*time.Second)); a != want || err != nil || e.asked.Load() != 2 {
		t.Errorf("after AnswerNow: %+v, %v, asked %d", a, err, e.asked.Load())
	}
	ended, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := in.AnswerNow(ended, exampleCredential, now); !errors.Is(err, context.Canceled) {
		t.Errorf("a context that ended: %v", err)
	}
}

// TestStarterOutcome pins the rules of the starter's two members on their own.
func TestStarterOutcome(t *testing.T) {
	for _, c := range []struct{ outcome, reason, wantOutcome, wantReason string }{
		{"succeeded", "all_checks_passed", "succeeded", "all_checks_passed"},
		{"cancelled", "", "cancelled", ""},
		{"failed", "stopped", "failed", ""},
		{"failed", "batch_refused", "failed", ""},
		{"failed", "issuer_answer_invalid", "failed", ""},
		{"", "checks_failed", "", ""},
		{"lost", "checks_failed", "", ""},
		{"failed", "9lives", "failed", ""},
	} {
		if o, r := StarterOutcome(c.outcome, c.reason); o != c.wantOutcome || r != c.wantReason {
			t.Errorf("StarterOutcome(%q, %q) = %q, %q", c.outcome, c.reason, o, r)
		}
	}
}
