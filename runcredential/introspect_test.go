package runcredential

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	for _, c := range []struct {
		name    string
		handler http.HandlerFunc
		active  bool
		failed  bool // a failure, not an answer of active false
	}{
		{"active true", answering(200, `{"active": true, "sub": "rk-0001"}`), true, false},
		{"active true after white space", answering(200, "\n {\"active\":true}\n"), true, false},
		{"active false", answering(200, `{"active": false}`), false, false},
		{"active the string true", answering(200, `{"active": "true"}`), false, true},
		{"active 1", answering(200, `{"active": 1}`), false, true},
		{"active null", answering(200, `{"active": null}`), false, true},
		{"no active", answering(200, `{"sub": "rk-0001"}`), false, true},
		{"active twice", answering(200, `{"active": true, "active": true}`), false, true},
		{"active false then true", answering(200, `{"active": false, "active": true}`), false, true},
		{"an array", answering(200, `[{"active": true}]`), false, true},
		{"not JSON", answering(200, `active: true`), false, true},
		{"two JSON values", answering(200, `{"active": true} {"active": true}`), false, true},
		{"empty", answering(200, ``), false, true},
		{"500", answering(500, `{"active": true}`), false, true},
		{"201", answering(201, `{"active": true}`), false, true},
		{"401", answering(401, `{"active": true}`), false, true},
		{"a redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}, false, true},
		{"a permanent redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusPermanentRedirect)
		}, false, true},
		{"oversized", answering(200, `{"active": true, "pad": "`+strings.Repeat("a", MaxIntrospectionAnswer)+`"}`), false, true},
		{"at the size limit", answering(200, `{"active": true, "pad": "`+strings.Repeat("a", MaxIntrospectionAnswer-len(`{"active": true, "pad": ""}`))+`"}`), true, false},
		{"a timeout", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
			answering(200, `{"active": true}`)(w, r)
		}, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEndpoint(t, c.handler)
			in := e.introspector(t, Introspection{}, 300*time.Millisecond)
			active, err := in.Active(context.Background(), exampleCredential, now)
			if active != c.active || (err != nil) != c.failed {
				t.Fatalf("Active = %v, %v; want %v, a failure: %v", active, err, c.active, c.failed)
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

	// A failure is kept for the cache too, so a failing endpoint is not asked on every
	// connection; it is asked again once the cache passes.
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
	fail.Store(false)
	if active, _ := fi.Active(ctx, exampleCredential, now.Add(5*time.Second)); active {
		t.Error("a failure was not kept for the cache")
	}
	if active, err := fi.Active(ctx, exampleCredential, now.Add(10*time.Second)); !active || err != nil {
		t.Errorf("after the cache: %v, %v", active, err)
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
	if active, err := in.Active(ctx, exampleCredential, now); active || err == nil {
		t.Fatalf("a context that ended: %v, %v", active, err)
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
	if active, err := in.Active(context.Background(), exampleCredential, now); active || err == nil {
		t.Errorf("an untrusted certificate: %v, %v", active, err)
	}
	if e.asked.Load() != 0 {
		t.Error("the run credential reached an endpoint whose certificate is not trusted")
	}
}
