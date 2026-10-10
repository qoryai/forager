package server_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/server"
)

// accessKeyID is the fixture access key's id, and instance the fixture instance.
const (
	accessKeyID = "ak_f1xt0re000000000"
	instance    = "i_gYKDhIWGh4iJiouMjY6PkA"
)

// fixture is the bytes of a contract fixture.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(contracts.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// generate makes a key for a test, a fresh one, never a published fixture's.
func generate(t *testing.T) *accesskey.Key {
	t.Helper()
	k, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// pinOf is the pin of one signing key.
func pinOf(k *accesskey.Key) accesskey.Pin {
	return accesskey.Pin{{Alg: "ed25519", PublicKey: k.PublicKey().String()}}
}

// code returns the code of a refusal, or the error's text.
func code(err error) string {
	var r *accesskey.Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	if err == nil {
		return "nil"
	}
	return err.Error()
}

// from returns the From of a refusal, or "none" when the error is no refusal.
func from(err error) string {
	var r *accesskey.Refusal
	if errors.As(err, &r) {
		return r.From
	}
	return "none"
}

// TestServerDocumentReads pins the fixtures reading and that a refused document is an
// error naming it: one without its access key id, with plain http elsewhere than
// loopback, or with a secret. A document without its pin is apiary_public_key_missing.
func TestServerDocumentReads(t *testing.T) {
	for _, f := range []string{"fixtures/server/loopback.yaml", "fixtures/server/https.yaml"} {
		c, err := server.Read(f, fixture(t, f))
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if c.Version != 1 || c.URL == "" || c.AccessKeyID != accessKeyID || len(c.ApiaryPublicKey) != 1 {
			t.Errorf("%s read as %+v", f, c)
		}
	}
	for _, f := range []string{"fixtures/invalid/server-no-access-key-id.yaml", "fixtures/invalid/server-plain-http.yaml", "fixtures/invalid/server-secret-member.yaml"} {
		_, err := server.Read(f, fixture(t, f))
		var se *server.Error
		if !errors.As(err, &se) || se.Name != f {
			t.Errorf("%s: %v", f, err)
		}
		if strings.Contains(fmt.Sprint(err), "AQIDBAUGBwgJCgsMDQ4P") {
			t.Errorf("%s: the error contains the secret: %v", f, err)
		}
	}
	f := "fixtures/invalid/server-no-pin.yaml"
	if _, err := server.Read(f, fixture(t, f)); code(err) != accesskey.CodeApiaryPublicKeyMissing {
		t.Errorf("%s: %v", f, err)
	}
	empty := []byte(`{"version":1,"url":"https://qory.example","access_key_id":"ak_f1xt0re000000000","apiary_public_key":[]}`)
	if _, err := server.Read("server", empty); code(err) != accesskey.CodeApiaryPublicKeyMissing {
		t.Errorf("an empty pin: %v", err)
	}
	small := []byte(`{"version":1,"url":"https://qory.example","access_key_id":"ak_f1xt0re000000000","apiary_public_key":[{"alg":"ed25519","public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`)
	if _, err := server.Read("server", small); !errors.Is(err, accesskey.ErrKeyInvalid) {
		t.Errorf("a pin of small order: %v", err)
	}
}

// TestClientCheck pins what a client refuses before it sends anything: no pin, which
// is apiary_public_key_missing, a pin of a key the key checks refuse, no access key,
// and an instance id or name outside the pattern.
func TestClientCheck(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	good := func() *server.Client {
		return &server.Client{Config: &server.Config{Version: 1, URL: srv.URL, AccessKeyID: accessKeyID, ApiaryPublicKey: pinOf(generate(t))}, Key: generate(t), InstanceID: instance, UserAgent: "qory-forager/test"}
	}
	for name, c := range map[string]func(*server.Client){
		"no pin": func(c *server.Client) { c.Config.ApiaryPublicKey = nil },
		"a pin of small order": func(c *server.Client) {
			c.Config.ApiaryPublicKey = accesskey.Pin{{Alg: "ed25519", PublicKey: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
		},
		"no key":                 func(c *server.Client) { c.Key = nil },
		"no instance id":         func(c *server.Client) { c.InstanceID = "" },
		"an instance id too odd": func(c *server.Client) { c.InstanceID = "-x" },
		"a name outside":         func(c *server.Client) { c.InstanceName = "a b" },
		"an access key id":       func(c *server.Client) { c.Config.AccessKeyID = "ak_F1XT0RE000000000" },
	} {
		cl := good()
		c(cl)
		if _, _, err := cl.Discover(context.Background()); err == nil {
			t.Errorf("%s: discovery went ahead", name)
		} else if name == "no pin" && code(err) != accesskey.CodeApiaryPublicKeyMissing {
			t.Errorf("no pin: %v", err)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("%d requests reached the server", n)
	}
}

// signedFixture is one fixture under fixtures/signed.
type signed struct {
	Method  string            `json:"method"`
	Target  string            `json:"target"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Expect  int               `json:"expect"`
}

func signedFixture(t *testing.T, name string) signed {
	t.Helper()
	doc, err := contracts.Document("fixtures/signed/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	m := doc.(map[string]any)
	f := signed{Method: m["method"].(string), Target: m["target"].(string), Headers: map[string]string{}}
	for k, v := range m["headers"].(map[string]any) {
		if s, ok := v.(string); ok {
			f.Headers[http.CanonicalHeaderKey(k)] = s
		}
	}
	if b, ok := m["body"].(string); ok {
		f.Body = b
	}
	n, _ := m["expect"].(interface{ Int64() (int64, error) }).Int64()
	f.Expect = int(n)
	return f
}

// TestTheClientSignsTheFixturesRequests pins that the request string the client signs
// is the one the signed fixtures carry: under the fixture access key, each accepted
// fixture's signature verifies over the request the client would build from its
// method, target, timestamp and body. The registration the client builds from the
// registration fixture's members is its body, byte for byte.
func TestTheClientSignsTheFixturesRequests(t *testing.T) {
	key, err := accesskey.ParseSecret("qak_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"get-configuration-valid", "register-valid", "reload-valid", "batch-valid"} {
		f := signedFixture(t, name)
		r := accesskey.Request{AccessKeyID: f.Headers[server.HeaderAccessKeyID], InstanceID: f.Headers[server.HeaderInstanceID], Method: f.Method, Target: f.Target, Timestamp: f.Headers[server.HeaderTimestamp], Body: []byte(f.Body)}
		if got, _ := key.SignRequest(r); got != f.Headers[server.HeaderSignature] {
			t.Errorf("%s: signed %s, the fixture has %s", name, got, f.Headers[server.HeaderSignature])
		}
	}
	if got := accesskey.Timestamp(time.Unix(1700000000, 999)); got != "1700000000" {
		t.Errorf("Timestamp = %s", got)
	}
	reg := server.Registration{Version: 1, RunID: "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f", Labels: map[string]string{"repository": "acme/shop", "forge": "github.com"},
		About: &server.About{Title: "Fix the failing build"}, ForagerVersion: "0.7.0", ContractVersion: 1, IntervalSeconds: 30, Events: []string{"*"}, Time: server.RegistrationTime(time.Unix(1700000000, 999))}
	if body, err := reg.Body(); err != nil || string(body) != signedFixture(t, "register-valid").Body {
		t.Errorf("the registration is %s, %v; the fixture has %s", body, err, signedFixture(t, "register-valid").Body)
	}
}

// verified is a server of the test's own that checks what every request contains,
// verifies its signature under the access key, and answers as told, signing each
// answer under its own key: the configuration document, the run endpoint, a run's
// registration and its run configuration by the run's id, and the events endpoint with
// digests on its answer.
type verified struct {
	t      *testing.T
	srv    *httptest.Server
	key    *accesskey.Key
	signer *accesskey.Key
	// status and code are what the events endpoint answers; sign is how every answer
	// is signed: "" under signer, "none" not at all, "other" under another key, and
	// "elsewhere" under signer bound to another request.
	status int
	code   string
	sign   string
	// runStatus and runCode are what a registration is answered, a run configuration
	// for a 200; runStatus 0 is 200.
	runStatus int
	runCode   string
	// seen is the last request's target and headers.
	seen   *http.Request
	body   []byte
	runDoc string
}

func newVerified(t *testing.T) *verified {
	t.Helper()
	v := &verified{t: t, key: generate(t), signer: generate(t), status: 202, runDoc: `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}}`}
	other := generate(t)
	v.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v.seen = r
		v.body, _ = io.ReadAll(r.Body)
		if r.Header.Get("User-Agent") != "qory-forager/test" || r.Header.Get(server.HeaderAccessKeyID) != accessKeyID || r.Header.Get(server.HeaderInstanceID) != instance || r.Header.Get(server.HeaderInstanceName) != "build-01" || r.Header.Get(server.HeaderContractVersion) != strconv.Itoa(server.Revision) {
			t.Errorf("%s %s: headers %v", r.Method, r.URL, r.Header)
		}
		req := accesskey.Request{AccessKeyID: r.Header.Get(server.HeaderAccessKeyID), InstanceID: r.Header.Get(server.HeaderInstanceID), Method: r.Method, Target: r.RequestURI}
		if r.Method == http.MethodGet {
			ts := r.Header.Get(server.HeaderTimestamp)
			if n, err := strconv.ParseInt(ts, 10, 64); err != nil || time.Since(time.Unix(n, 0)).Abs() > time.Minute {
				t.Errorf("timestamp %q", ts)
			}
			req.Timestamp = ts
		} else {
			req.Body = v.body
		}
		sig := r.Header.Get(server.HeaderSignature)
		if !v.key.PublicKey().VerifyRequest(req, sig) {
			t.Errorf("%s %s: the signature does not verify over the request as sent", r.Method, r.RequestURI)
		}
		reply := func(status int, body string) {
			a := accesskey.Answer{Status: status, RequestSignature: sig, Body: []byte(body), Configuration: w.Header().Get(server.HeaderConfiguration), RunConfiguration: w.Header().Get(server.HeaderRunConfiguration)}
			switch v.sign {
			case "":
				w.Header().Set(server.HeaderSignature, v.signer.SignAnswer(a))
			case "other":
				w.Header().Set(server.HeaderSignature, other.SignAnswer(a))
			case "elsewhere":
				a.RequestSignature = strings.Repeat("A", 86)
				w.Header().Set(server.HeaderSignature, v.signer.SignAnswer(a))
			}
			w.WriteHeader(status)
			io.WriteString(w, body)
		}
		switch {
		case r.URL.Path == server.WellKnown:
			w.Header().Set(server.HeaderConfiguration, "sha256=c0")
			w.Header().Set("Content-Type", "application/json")
			reply(200, `{"version":1,"node_id":"nd_f1xt0re000000000","events":{"url":"`+v.srv.URL+`/v1/events","types":["*"]},"run":{"url":"`+v.srv.URL+`/v1/runs"},"apiary_public_key":[{"alg":"ed25519","public_key":"`+v.signer.PublicKey().String()+`"}],"later":{"x":1}}`)
		case r.URL.Path == "/v1/runs" && r.Method == http.MethodPost:
			if r.Header.Get("Content-Type") != server.RegistrationContentType || r.Header.Get(server.HeaderDelivery) != "" || r.Header.Get(server.HeaderTimestamp) != "" {
				t.Errorf("registration headers %v", r.Header)
			}
			if v.runStatus != 0 && v.runStatus != 200 {
				body := ""
				if v.runCode != "" {
					body = `{"error":"` + v.runCode + `"}`
				}
				reply(v.runStatus, body)
				return
			}
			w.Header().Set(server.HeaderRunConfiguration, "sha256="+strings.Repeat("0", 64))
			w.Header().Set("ETag", `"sha256=`+strings.Repeat("0", 64)+`"`)
			reply(200, v.runDoc)
		case r.URL.Path == "/v1/runs/"+runID && r.Method == http.MethodGet:
			w.Header().Set(server.HeaderRunConfiguration, "sha256="+strings.Repeat("1", 64))
			w.Header().Set("ETag", `"sha256=`+strings.Repeat("1", 64)+`"`)
			reply(200, v.runDoc)
		case r.URL.Path == "/v1/events" && r.Method == http.MethodPost:
			if r.Header.Get("Content-Type") != server.ContentType || r.Header.Get(server.HeaderDelivery) == "" {
				t.Errorf("POST headers %v", r.Header)
			}
			w.Header().Set(server.HeaderConfiguration, "sha256=c1")
			w.Header().Set(server.HeaderRunConfiguration, "sha256=r1")
			body := ""
			if v.code != "" {
				body = `{"error":"` + v.code + `"}`
			}
			reply(v.status, body)
		default:
			reply(404, "")
		}
	}))
	t.Cleanup(v.srv.Close)
	return v
}

func (v *verified) client() *server.Client {
	return &server.Client{Config: &server.Config{Version: 1, URL: v.srv.URL, AccessKeyID: accessKeyID, ApiaryPublicKey: pinOf(v.signer)}, Key: v.key, InstanceID: instance, InstanceName: "build-01", UserAgent: "qory-forager/test"}
}

// TestDiscoverReadsTheConfigurationAndItsDigest pins discovery: the well-known path,
// the document decoded with a section Forager does not know ignored, the node id,
// the run endpoint, the digest from the header, the filter, which never wants
// dev.qory.run.registered, and no run on a status that is not 200 or on a document
// without the run endpoint or whose run endpoint has a trailing slash, a query or a
// fragment.
func TestDiscoverReadsTheConfigurationAndItsDigest(t *testing.T) {
	v := newVerified(t)
	c := v.client()
	conf, digest, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if digest != "sha256=c0" || conf.NodeID != "nd_f1xt0re000000000" || conf.Events.URL != v.srv.URL+"/v1/events" || len(conf.Events.Types) != 1 || conf.Run == nil || conf.Run.URL != v.srv.URL+"/v1/runs" || conf.Secrets != nil || len(conf.ApiaryPublicKey) != 1 {
		t.Errorf("discovered %+v, digest %s", conf, digest)
	}
	if !conf.Wants("dev.qory.run.log") || conf.Wants("dev.qory.run.registered") {
		t.Error("the filter of a configuration with * is wrong")
	}
	conf.Events.Types = []string{"dev.qory.run.started", "dev.qory.run.registered"}
	if conf.Wants("dev.qory.run.log") || !conf.Wants("dev.qory.run.started") || conf.Wants("dev.qory.run.registered") {
		t.Error("the filter of a listed configuration is wrong")
	}
	inner := v.srv.Config.Handler
	for name, run := range map[string]string{"without the run endpoint": "", "with a trailing slash": `,"run":{"url":"` + v.srv.URL + `/v1/runs/"}`,
		"with a query": `,"run":{"url":"` + v.srv.URL + `/v1/runs?x=1"}`, "with a fragment": `,"run":{"url":"` + v.srv.URL + `/v1/runs#x"}`} {
		v.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			doc := []byte(`{"version":1,"node_id":"nd_f1xt0re000000000","events":{"url":"` + v.srv.URL + `/v1/events","types":["*"]}` + run + `,"apiary_public_key":[{"alg":"ed25519","public_key":"` + v.signer.PublicKey().String() + `"}]}`)
			w.Header().Set(server.HeaderConfiguration, "sha256=c0")
			w.Header().Set(server.HeaderSignature, v.signer.SignAnswer(accesskey.Answer{Status: 200, RequestSignature: r.Header.Get(server.HeaderSignature), Body: doc, Configuration: "sha256=c0"}))
			w.Write(doc)
		})
		var de *server.DocumentError
		if _, _, err := c.Discover(context.Background()); !errors.As(err, &de) || de.URL != v.srv.URL+server.WellKnown {
			t.Errorf("a configuration %s: %v", name, err)
		}
	}
	v.srv.Config.Handler = inner
	c.Config.URL = v.srv.URL + "/elsewhere"
	if _, _, err := c.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "status 404") || !strings.Contains(err.Error(), "/elsewhere"+server.WellKnown) {
		t.Errorf("discovery of a URL that does not answer: %v", err)
	}
	v.srv.Close()
	if _, _, err := c.Discover(context.Background()); err == nil {
		t.Error("discovery of a server that is down succeeded")
	}
}

// TestEveryAnswerIsVerifiedUnderThePin pins that the client reads an answer only when
// its signature verifies under the pin and is bound to the request it answers: an
// unsigned answer, one under another key, one bound to another request, and one under
// a key the pin does not hold are answer_unsigned at run start, and a delivery's is no
// answer, its digests unread.
func TestEveryAnswerIsVerifiedUnderThePin(t *testing.T) {
	for _, sign := range []string{"none", "other", "elsewhere", "pin"} {
		v := newVerified(t)
		c := v.client()
		v.sign = sign
		if sign == "pin" {
			v.sign = ""
			c.Config.ApiaryPublicKey = pinOf(generate(t))
		}
		if _, _, err := c.Discover(context.Background()); code(err) != accesskey.CodeAnswerUnsigned {
			t.Errorf("%s: discovery: %v", sign, err)
		}
		if _, _, err := c.RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID); code(err) != accesskey.CodeAnswerUnsigned {
			t.Errorf("%s: run configuration: %v", sign, err)
		}
		if _, _, err := c.Register(context.Background(), v.srv.URL+"/v1/runs", registration(t)); code(err) != accesskey.CodeAnswerUnsigned {
			t.Errorf("%s: registration: %v", sign, err)
		}
		d, err := c.Deliver(context.Background(), v.srv.URL+"/v1/events", "d2", []byte("[]"), "")
		if err != nil || d.Signed || d.Accepted() || d.Digests != (server.Digests{}) || d.Status != 202 {
			t.Errorf("%s: delivery %+v, %v", sign, d, err)
		}
	}
}

// TestRefusalsAreCoded pins the codes a run start reads: an unsigned 401 is
// unauthorized, a signed 429 rate_limited at discovery is rate_limited, a signed 409 to
// the registration is its code, instance_limit, run_id_used or a code of the server's
// own, and a signed 410 to a delivery, with run_closed or without a code, stops the
// deliveries and closes no run. A 401 that carries a signature is unauthorized all the
// same. A signed code and an unauthorized are From apiary; an answer_unsigned is From
// none.
func TestRefusalsAreCoded(t *testing.T) {
	v := newVerified(t)
	c := v.client()
	events, runs := v.srv.URL+"/v1/events", v.srv.URL+"/v1/runs"
	body := registration(t)
	for _, c409 := range []string{"instance_limit", "run_id_used", "node_paused"} {
		v.runStatus, v.runCode = 409, c409
		_, _, err := c.Register(context.Background(), runs, body)
		if code(err) != c409 || from(err) != accesskey.FromApiary || errors.Is(err, server.ErrNotAccepted) {
			t.Errorf("registration on a signed 409 %s: %v", c409, err)
		}
		if want := "register " + runs + ": " + c409 + " (status 409)"; err == nil || err.Error() != want {
			t.Errorf("registration on a signed 409 %s: %v, want %q", c409, err, want)
		}
	}
	v.runStatus, v.runCode = 401, "unauthorized"
	for _, sign := range []string{"none", ""} {
		v.sign = sign
		if _, _, err := c.Register(context.Background(), runs, body); code(err) != accesskey.CodeUnauthorized || from(err) != accesskey.FromApiary {
			t.Errorf("registration on 401 signed %q: %v", sign, err)
		}
	}
	v.runStatus, v.runCode, v.sign = 409, "instance_limit", "none"
	if _, _, err := c.Register(context.Background(), runs, body); code(err) != accesskey.CodeAnswerUnsigned || from(err) != "" {
		t.Errorf("registration on an unsigned 409: %v, from %q", err, from(err))
	}
	v.runStatus, v.runCode = 410, ""
	if _, _, err := c.Register(context.Background(), runs, body); code(err) != accesskey.CodeAnswerUnsigned || errors.Is(err, server.ErrNotAccepted) {
		t.Errorf("registration on an unsigned 410: %v", err)
	}
	v.sign = ""
	v.runStatus, v.runCode = 500, ""
	if _, _, err := c.Register(context.Background(), runs, body); !errors.Is(err, server.ErrNotAccepted) || !strings.Contains(err.Error(), runs) {
		t.Errorf("registration on a signed 500: %v", err)
	}
	v.status, v.code = 410, "run_closed"
	d, err := c.Deliver(context.Background(), events, "d4", []byte("[]"), "")
	if err != nil || d.Closed() || !d.Stop() || d.Accepted() || d.Code != "run_closed" {
		t.Errorf("410 run_closed: %+v %v", d, err)
	}
	v.code = ""
	if d, _ := c.Deliver(context.Background(), events, "d5", []byte("[]"), ""); d.Closed() || !d.Stop() {
		t.Errorf("410 without a code: %+v", d)
	}
	v.sign = "none"
	v.code = "run_closed"
	if d, _ := c.Deliver(context.Background(), events, "d6", []byte("[]"), ""); d.Closed() || d.Stop() {
		t.Errorf("an unsigned 410: %+v", d)
	}
	limited := newVerified(t)
	lc := limited.client()
	limited.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := `{"error":"rate_limited"}`
		w.Header().Set(server.HeaderSignature, limited.signer.SignAnswer(accesskey.Answer{Status: 429, RequestSignature: r.Header.Get(server.HeaderSignature), Body: []byte(body)}))
		w.WriteHeader(429)
		io.WriteString(w, body)
	})
	if _, _, err := lc.Discover(context.Background()); code(err) != "rate_limited" {
		t.Errorf("discovery answered a signed 429 rate_limited: %v", err)
	}
	unauthorized := newVerified(t)
	uc := unauthorized.client()
	unauthorized.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"unauthorized"}`)
	})
	if _, _, err := uc.Discover(context.Background()); code(err) != accesskey.CodeUnauthorized {
		t.Errorf("discovery answered 401: %v", err)
	}
}

// TestASigned410ToTheRegistrationIsNoRun pins a signed 410 to the registration, with
// run_closed or without a code: the server takes no run here, so the registration is
// not accepted, ErrNotAccepted with no code, whatever the 410's code was.
func TestASigned410ToTheRegistrationIsNoRun(t *testing.T) {
	for _, c := range []string{"run_closed", ""} {
		v := newVerified(t)
		runs := v.srv.URL + "/v1/runs"
		v.runStatus, v.runCode = 410, c
		_, _, err := v.client().Register(context.Background(), runs, registration(t))
		var r *accesskey.Refusal
		if want := "register " + runs + ": status 410: the server did not accept the run"; !errors.Is(err, server.ErrNotAccepted) || errors.As(err, &r) || err.Error() != want {
			t.Errorf("410 %q to the registration: %v, want %q", c, err, want)
		}
	}
}

// registration is the body of a test's registration.
func registration(t *testing.T) []byte {
	t.Helper()
	b, err := server.Registration{Version: 1, RunID: runID, Labels: map[string]string{"forge": "github.com", "repository": "acme/shop"}, About: &server.About{Title: "Fix the cart"},
		ForagerVersion: "v0.0.0-test", ContractVersion: server.Revision, IntervalSeconds: 30, Events: []string{"*"}, Time: server.RegistrationTime(time.Date(2026, 10, 10, 12, 0, 0, 999, time.FixedZone("x", 3600)))}.Body()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestARegistrationIsItsBody pins the registration's bytes: its members in order, its
// time in UTC with whole seconds, no labels left out, and no event types an empty list;
// labels CheckLabels refuses build no body, with its error.
func TestARegistrationIsItsBody(t *testing.T) {
	want := `{"version":1,"run_id":"` + runID + `","labels":{"forge":"github.com","repository":"acme/shop"},"about":{"title":"Fix the cart"},"forager_version":"v0.0.0-test","contract_version":` + strconv.Itoa(server.Revision) + `,"interval_seconds":30,"events":["*"],"time":"2026-10-10T11:00:00Z"}`
	if got := string(registration(t)); got != want {
		t.Errorf("the body\n%s\nwant\n%s", got, want)
	}
	b, err := server.Registration{Version: 1, RunID: runID, Labels: map[string]string{}, ForagerVersion: "dev", ContractVersion: 1, IntervalSeconds: 1, Time: "2026-10-10T12:00:00Z"}.Body()
	if want := `{"version":1,"run_id":"` + runID + `","forager_version":"dev","contract_version":1,"interval_seconds":1,"events":[],"time":"2026-10-10T12:00:00Z"}`; err != nil || string(b) != want {
		t.Errorf("a registration with no labels and no about: %s, %v", b, err)
	}
	if _, err := (server.Registration{Version: 1, RunID: runID, Labels: map[string]string{"Forge": "x"}}).Body(); err == nil || err.Error() != server.CheckLabels(map[string]string{"Forge": "x"}).Error() {
		t.Errorf("labels CheckLabels refuses: %v", err)
	}
}

// TestRegisterPostsTheBodyAndReadsTheRunConfiguration pins the registration: one signed
// POST of the body as given, application/json, with no delivery id and no timestamp,
// the same bytes every time it is sent, and its answer read as the run configuration
// with its digest: a document over the 64 KiB a refusal may hold is read when it is a
// signed 200, and {"version":1} is a run configuration without a policy. A digest
// header missing or misshapen, and a document the schema refuses, are a DocumentError.
func TestRegisterPostsTheBodyAndReadsTheRunConfiguration(t *testing.T) {
	v := newVerified(t)
	c := v.client()
	runs := v.srv.URL + "/v1/runs"
	body := registration(t)
	var sent [][]byte
	for range 2 {
		rc, digest, err := c.Register(context.Background(), runs, body)
		if err != nil {
			t.Fatal(err)
		}
		if digest != "sha256="+strings.Repeat("0", 64) || rc.Version != 1 || !strings.Contains(string(rc.SecurityPolicy), `"api.example"`) {
			t.Errorf("run configuration %+v, digest %s", rc, digest)
		}
		if v.seen.Method != http.MethodPost || v.seen.URL.RequestURI() != "/v1/runs" {
			t.Errorf("%s %s", v.seen.Method, v.seen.URL.RequestURI())
		}
		sent = append(sent, v.body)
	}
	if string(sent[0]) != string(body) || string(sent[1]) != string(body) {
		t.Errorf("the bytes sent differ from the body:\n%s\n%s", sent[0], sent[1])
	}
	v.runDoc = `{"version":1,"variables":{"A":{"value":"` + strings.Repeat("a", 4096) + `"},"B":{"value":"` + strings.Repeat("b", 4096) + `"}` + strings.Repeat(` `, server.MaxRefusal) + `}}`
	if rc, _, err := c.Register(context.Background(), runs, body); err != nil || len(rc.Values()["B"]) != 4096 {
		t.Errorf("a signed 200 over %d bytes: %v", server.MaxRefusal, err)
	}
	v.runDoc = `{"version":1}`
	if rc, digest, err := c.Register(context.Background(), runs, body); err != nil || rc.SecurityPolicy != nil || rc.Variables != nil || digest == "" {
		t.Errorf("a run configuration without a policy: %+v %v", rc, err)
	}
	v.runDoc = `{"version":2}`
	var de *server.DocumentError
	if _, _, err := c.Register(context.Background(), runs, body); !errors.As(err, &de) || de.URL != runs {
		t.Errorf("a document the schema refuses: %v", err)
	}
	if _, _, err := c.Register(context.Background(), v.srv.URL+"/v1/missing", body); err == nil || !strings.Contains(err.Error(), "status 404") || !strings.Contains(err.Error(), "register "+v.srv.URL+"/v1/missing") {
		t.Errorf("a run URL that does not answer: %v", err)
	}
	inner := v.srv.Config.Handler
	for name, header := range map[string]string{"no digest": "", "a misshapen digest": "sha256=0"} {
		v.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			doc := []byte(`{"version":1}`)
			if header != "" {
				w.Header().Set(server.HeaderRunConfiguration, header)
			}
			w.Header().Set(server.HeaderSignature, v.signer.SignAnswer(accesskey.Answer{Status: 200, RequestSignature: r.Header.Get(server.HeaderSignature), Body: doc, RunConfiguration: header}))
			_ = b
			w.Write(doc)
		})
		if _, _, err := c.Register(context.Background(), runs, body); !errors.As(err, &de) {
			t.Errorf("%s: %v", name, err)
		}
	}
	v.srv.Config.Handler = inner
	v.srv.Close()
	if _, _, err := c.Register(context.Background(), runs, body); err == nil || !strings.Contains(err.Error(), "register "+runs) {
		t.Errorf("a registration with a server that is down: %v", err)
	}
}

// TestRunConfigurationFetchesByTheRunsID pins the reload: a signed GET of the run
// endpoint followed by the run's id, with its timestamp, read as the run configuration
// with its digest; a signed 410 is ErrNotAccepted, and a 404 an error naming it.
func TestRunConfigurationFetchesByTheRunsID(t *testing.T) {
	v := newVerified(t)
	c := v.client()
	rc, digest, err := c.RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "sha256="+strings.Repeat("1", 64) || rc.Version != 1 || rc.SecurityPolicy == nil {
		t.Errorf("run configuration %+v, digest %s", rc, digest)
	}
	if v.seen.Method != http.MethodGet || v.seen.RequestURI != "/v1/runs/"+runID || v.seen.Header.Get(server.HeaderTimestamp) == "" {
		t.Errorf("%s %s, headers %v", v.seen.Method, v.seen.RequestURI, v.seen.Header)
	}
	other := "1b5c1c2e-3f4a-4b6c-8d7e-9f0a1b2c3d4e"
	if _, _, err := c.RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", other); err == nil || errors.Is(err, server.ErrNotAccepted) || !strings.Contains(err.Error(), "status 404") || !strings.Contains(err.Error(), "/v1/runs/"+other) {
		t.Errorf("a run the server does not know: %v", err)
	}
	inner := v.srv.Config.Handler
	v.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(server.HeaderSignature, v.signer.SignAnswer(accesskey.Answer{Status: 410, RequestSignature: r.Header.Get(server.HeaderSignature)}))
		w.WriteHeader(410)
	})
	if _, _, err := c.RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID); !errors.Is(err, server.ErrNotAccepted) {
		t.Errorf("a signed 410: %v", err)
	}
	v.srv.Config.Handler = inner
}

// TestLabelsAreChecked pins the labels a run may carry: sixteen keys of 64 bytes and
// values of 256 bytes pass, and one more label or byte is refused.
func TestLabelsAreChecked(t *testing.T) {
	labels := map[string]string{}
	for i := range server.MaxLabels {
		labels[fmt.Sprintf("%02d", i)+strings.Repeat("k", 62)] = strings.Repeat("\u00e9", 128)
	}
	if err := server.CheckLabels(labels); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(map[string]string){
		"a seventeenth label": func(l map[string]string) { l["x"] = "" },
		"a longer value":      func(l map[string]string) { l["00"+strings.Repeat("k", 62)] += "x" },
		"a longer key":        func(l map[string]string) { l[strings.Repeat("k", 65)] = ""; delete(l, "00"+strings.Repeat("k", 62)) },
		"an upper-case key":   func(l map[string]string) { l["Forge"] = ""; delete(l, "00"+strings.Repeat("k", 62)) },
		"a value not UTF-8":   func(l map[string]string) { l["00"+strings.Repeat("k", 62)] = "\xff" },
	} {
		l := maps.Clone(labels)
		change(l)
		if err := server.CheckLabels(l); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// TestDeliveryCarriesTheHeadersAndReadsTheDigests pins one POST: content type, user
// agent, access key id, instance, revision, delivery id, a signature the server
// verifies over the target and the body, the run configuration digest when the run
// holds one, and the answer's digests.
func TestDeliveryCarriesTheHeadersAndReadsTheDigests(t *testing.T) {
	v := newVerified(t)
	c := v.client()
	events := v.srv.URL + "/v1/events"
	d, err := c.Deliver(context.Background(), events, "d1", []byte("[]"), "sha256=r0")
	if err != nil || !d.Accepted() || d.Digests.Configuration != "sha256=c1" || d.Digests.RunConfiguration != "sha256=r1" {
		t.Errorf("deliver: %+v %v", d, err)
	}
	if v.seen.Header.Get(server.HeaderRunConfiguration) != "sha256=r0" || v.seen.Header.Get(server.HeaderTimestamp) != "" {
		t.Errorf("POST headers %v", v.seen.Header)
	}
	if _, err := c.Deliver(context.Background(), events, "d2", []byte("[]"), ""); err != nil {
		t.Error(err)
	}
	if _, ok := v.seen.Header[server.HeaderRunConfiguration]; ok {
		t.Error("a delivery sent a run configuration digest with none held")
	}
}

// TestARedirectIsNotFollowed pins that a 3xx is a status like any other: the host it
// points at sees no request, so no access key id, signature or timestamp reaches it,
// whether the client is the package's own or the caller's; discovery is then no run,
// and a delivery is not accepted.
func TestARedirectIsNotFollowed(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		w.Header().Set(server.HeaderConfiguration, "sha256=c0")
		io.WriteString(w, `{"version":1,"events":{"url":"https://elsewhere.example/v1/events","types":["*"]}}`)
	}))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer origin.Close()
	for name, hc := range map[string]*http.Client{"the package's client": nil, "the caller's client": {}} {
		c := &server.Client{Config: &server.Config{Version: 1, URL: origin.URL, AccessKeyID: accessKeyID, ApiaryPublicKey: pinOf(generate(t))}, Key: generate(t), InstanceID: instance, UserAgent: "qory-forager/test", HTTP: hc}
		if _, _, err := c.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "status 302") {
			t.Errorf("%s: discovery through a redirect: %v", name, err)
		}
		if _, _, err := c.RunConfiguration(context.Background(), origin.URL+"/v1/runs", runID); err == nil || !strings.Contains(err.Error(), "status 302") {
			t.Errorf("%s: a run configuration through a redirect: %v", name, err)
		}
		d, err := c.Deliver(context.Background(), origin.URL+"/v1/events", "d1", []byte("[]"), "")
		if err != nil || d.Status != http.StatusFound || d.Accepted() {
			t.Errorf("%s: a delivery through a redirect: %+v %v", name, d, err)
		}
		if _, _, err := c.Register(context.Background(), origin.URL+"/v1/runs", []byte("{}")); code(err) != accesskey.CodeAnswerUnsigned {
			t.Errorf("%s: a registration through a redirect: %v", name, err)
		}
	}
	if n := elsewhere.Load(); n != 0 {
		t.Errorf("the host a redirect named saw %d requests", n)
	}
}

// TestAnswersThatCannotBeReadAsSignedAreUnsigned pins the edges of an answer's
// signature: a signature header or a digest header sent twice, and a refusal body over
// 64 KiB, each make the answer unsigned, so its code and its digests are never read.
// Each header sent twice is split so that its values joined are the signed one: a
// reader that joined them would verify the answer.
func TestAnswersThatCannotBeReadAsSignedAreUnsigned(t *testing.T) {
	key, signer := generate(t), generate(t)
	mode := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, body, conf := 429, `{"error":"rate_limited"}`, ""
		if mode == "large" {
			body = `{"error":"rate_limited","names":["` + strings.Repeat("x", server.MaxRefusal) + `"]}`
		}
		if mode == "digest" {
			conf = "sha256=a"
			w.Header().Add(server.HeaderConfiguration, "sha256=")
			w.Header().Add(server.HeaderConfiguration, "a")
		}
		sig := signer.SignAnswer(accesskey.Answer{Status: status, RequestSignature: r.Header.Get(server.HeaderSignature), Body: []byte(body), Configuration: conf})
		if mode == "twice" {
			w.Header().Add(server.HeaderSignature, sig[:43])
			w.Header().Add(server.HeaderSignature, sig[43:])
		} else {
			w.Header().Add(server.HeaderSignature, sig)
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	defer srv.Close()
	c := &server.Client{Config: &server.Config{Version: 1, URL: srv.URL, AccessKeyID: accessKeyID, ApiaryPublicKey: pinOf(signer)}, Key: key, InstanceID: instance, UserAgent: "qory-forager/test"}
	if _, _, err := c.Discover(context.Background()); code(err) != "rate_limited" {
		t.Fatalf("a signed 429: %v", err)
	}
	for _, m := range []string{"twice", "digest", "large"} {
		mode = m
		if _, _, err := c.Discover(context.Background()); code(err) != accesskey.CodeAnswerUnsigned {
			t.Errorf("%s: %v", m, err)
		}
	}
}

// TestTheClientKeepsNoCookie pins that a cookie a server sets reaches no later request,
// whatever jar the caller's client has.
func TestTheClientKeepsNoCookie(t *testing.T) {
	v := newVerified(t)
	seen := 0
	inner := v.srv.Config.Handler
	v.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			seen++
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "kept", Path: "/"})
		inner.ServeHTTP(w, r)
	})
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := v.client()
	c.HTTP = &http.Client{Jar: jar}
	for range 2 {
		if _, _, err := c.Discover(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if seen != 0 {
		t.Errorf("%d requests sent a cookie", seen)
	}
}

// TestAServerDocumentWithASecretQuotesNothing pins that a secret pasted into the
// server document, as the access key id, the url, a pin's public key or a member's
// name, or into a pin, is refused with a fixed message that does not contain it.
func TestAServerDocumentWithASecretQuotesNothing(t *testing.T) {
	const secret = "qak_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	pin := `[{"alg":"ed25519","public_key":"rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc"}]`
	for name, doc := range map[string]string{
		"the access key id": `{"version":1,"url":"https://qory.example","access_key_id":"` + secret + `","apiary_public_key":` + pin + `}`,
		"the url":           `{"version":1,"url":"https://` + secret + `","access_key_id":"ak_f1xt0re000000000","apiary_public_key":` + pin + `}`,
		"a public key":      `{"version":1,"url":"https://qory.example","access_key_id":"ak_f1xt0re000000000","apiary_public_key":[{"alg":"ed25519","public_key":"` + secret + `"}]}`,
		"a member's name":   `{"version":1,"url":"https://qory.example","access_key_id":"ak_f1xt0re000000000","` + secret + `":1,"apiary_public_key":` + pin + `}`,
		"upper case":        `{"version":1,"url":"https://qory.example","access_key_id":"` + strings.ToUpper(secret) + `","apiary_public_key":` + pin + `}`,
	} {
		_, err := server.Read("server.json", []byte(doc))
		if !errors.Is(err, accesskey.ErrSecretInDocument) || strings.Contains(strings.ToLower(err.Error()), strings.ToLower(secret[4:20])) {
			t.Errorf("%s: %v", name, err)
		}
	}
	yaml := "version: 1\nurl: https://qory.example\naccess_key_id: " + secret + "\n"
	if _, err := server.Read("server.yaml", []byte(yaml)); !errors.Is(err, accesskey.ErrSecretInDocument) {
		t.Errorf("YAML: %v", err)
	}
	if _, err := accesskey.ParsePin([]byte(`[{"alg":"ed25519","public_key":"` + secret + `"}]`)); !errors.Is(err, accesskey.ErrSecretInDocument) {
		t.Errorf("a pin: %v", err)
	}
	if _, err := accesskey.ParsePin([]byte(`[{"alg":"ed25519","` + secret + `":"x"}]`)); !errors.Is(err, accesskey.ErrSecretInDocument) {
		t.Errorf("a pin's member name: %v", err)
	}
}

// TestAnEscapedSecretQuotesNothing pins that a secret hidden from the bytes by an
// escape, a JSON q, a YAML \x71, or a YAML double-quoted line break between qak
// and the underscore, in a value or a member name, is refused with the fixed message
// that does not contain it, as a secret in plain text is.
func TestAnEscapedSecretQuotesNothing(t *testing.T) {
	const rest = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	pin := `[{"alg":"ed25519","public_key":"rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc"}]`
	for name, doc := range map[string]string{
		"server.json": `{"version":1,"url":"https://qory.example","access_key_id":"qak_` + rest + `","apiary_public_key":` + pin + `}`,
		"member.json": `{"version":1,"url":"https://qory.example","access_key_id":"ak_f1xt0re000000000","qak_` + rest + `":1,"apiary_public_key":` + pin + `}`,
		"x71.yaml":    "version: 1\nurl: https://qory.example\naccess_key_id: \"\\x71ak_" + rest + "\"\n",
		"fold.yaml":   "version: 1\nurl: https://qory.example\naccess_key_id: \"qak\\\n  _" + rest + "\"\n",
		"key.yaml":    "version: 1\nurl: https://qory.example\naccess_key_id: ak_f1xt0re000000000\n\"\\x71ak_" + rest + "\": 1\n",
	} {
		_, err := server.Read(name, []byte(doc))
		if !errors.Is(err, accesskey.ErrSecretInDocument) || strings.Contains(err.Error(), rest[:12]) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, doc := range map[string]string{
		"a public key":    `[{"alg":"ed25519","public_key":"qak_` + rest + `"}]`,
		"a member's name": `[{"alg":"ed25519","qak_` + rest + `":"x"}]`,
	} {
		_, err := accesskey.ParsePin([]byte(doc))
		if !errors.Is(err, accesskey.ErrSecretInDocument) || strings.Contains(err.Error(), rest[:12]) {
			t.Errorf("a pin, %s: %v", name, err)
		}
	}
}
