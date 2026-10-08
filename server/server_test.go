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

	"github.com/qoryai/runner/accesskey"
	"github.com/qoryai/runner/contracts"
	"github.com/qoryai/runner/server"
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
// method, target, timestamp and body.
func TestTheClientSignsTheFixturesRequests(t *testing.T) {
	key, err := accesskey.ParseSecret("qak_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"get-configuration-valid", "get-run-configuration-valid", "get-run-configuration-labels-valid", "batch-valid"} {
		f := signedFixture(t, name)
		r := accesskey.Request{AccessKeyID: f.Headers[server.HeaderAccessKeyID], InstanceID: f.Headers[server.HeaderInstanceID], Method: f.Method, Target: f.Target, Timestamp: f.Headers[server.HeaderTimestamp], Body: []byte(f.Body)}
		if got, _ := key.SignRequest(r); got != f.Headers[server.HeaderSignature] {
			t.Errorf("%s: signed %s, the fixture has %s", name, got, f.Headers[server.HeaderSignature])
		}
	}
	if got := accesskey.Timestamp(time.Unix(1700000000, 999)); got != "1700000000" {
		t.Errorf("Timestamp = %s", got)
	}
}

// verified is a server of the test's own that checks what every request contains,
// verifies its signature under the access key, and answers as told, signing each
// answer under its own key: the configuration document, the run configuration, and
// the events endpoint with digests on its answer.
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
			reply(200, `{"version":1,"node_id":"nd_f1xt0re000000000","events":{"url":"`+v.srv.URL+`/v1/events","types":["*"]},"run":{"url":"`+v.srv.URL+`/v1/run-configuration"},"apiary_public_key":[{"alg":"ed25519","public_key":"`+v.signer.PublicKey().String()+`"}],"later":{"x":1}}`)
		case r.URL.Path == "/v1/run-configuration":
			w.Header().Set(server.HeaderRunConfiguration, "sha256="+strings.Repeat("0", 64))
			w.Header().Set("ETag", `"sha256=`+strings.Repeat("0", 64)+`"`)
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
// the document decoded with a section the runner does not know ignored, the node id,
// the digest from the header, and no run on a status that is not 200.
func TestDiscoverReadsTheConfigurationAndItsDigest(t *testing.T) {
	v := newVerified(t)
	c := v.client()
	conf, digest, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if digest != "sha256=c0" || conf.NodeID != "nd_f1xt0re000000000" || conf.Events.URL != v.srv.URL+"/v1/events" || len(conf.Events.Types) != 1 || conf.Run == nil || conf.Run.URL != v.srv.URL+"/v1/run-configuration" || conf.Secrets != nil || len(conf.ApiaryPublicKey) != 1 {
		t.Errorf("discovered %+v, digest %s", conf, digest)
	}
	if !conf.Wants("dev.qory.run.log") || !conf.Wants("dev.qory.ping") {
		t.Error("the filter refused an event of a configuration with *")
	}
	conf.Events.Types = []string{"dev.qory.run.started"}
	if conf.Wants("dev.qory.run.log") || !conf.Wants("dev.qory.run.started") || !conf.Wants("dev.qory.ping") {
		t.Error("the filter of a listed configuration is wrong")
	}
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
		if _, _, err := c.RunConfiguration(context.Background(), v.srv.URL+"/v1/run-configuration", nil); code(err) != accesskey.CodeAnswerUnsigned {
			t.Errorf("%s: run configuration: %v", sign, err)
		}
		if err := c.Ping(context.Background(), v.srv.URL+"/v1/events", "d1", []byte("[]")); code(err) != accesskey.CodeAnswerUnsigned {
			t.Errorf("%s: ping: %v", sign, err)
		}
		d, err := c.Deliver(context.Background(), v.srv.URL+"/v1/events", "d2", []byte("[]"), "")
		if err != nil || d.Signed || d.Accepted() || d.Digests != (server.Digests{}) || d.Status != 202 {
			t.Errorf("%s: delivery %+v, %v", sign, d, err)
		}
	}
}

// TestRefusalsAreCoded pins the codes a run start reads: an unsigned 401 is
// unauthorized, a signed 429 rate_limited at discovery is rate_limited, a signed 409
// instance_limit to the ping is instance_limit, and a signed 410 run_closed to a
// delivery closes the run while a signed 410 without that code stops the deliveries
// alone. A 401 that carries a signature is unauthorized all the same.
func TestRefusalsAreCoded(t *testing.T) {
	v := newVerified(t)
	c := v.client()
	events := v.srv.URL + "/v1/events"
	v.status, v.code = 409, "instance_limit"
	if err := c.Ping(context.Background(), events, "d1", []byte("[]")); code(err) != accesskey.CodeInstanceLimit || !strings.Contains(err.Error(), events) {
		t.Errorf("ping: %v", err)
	}
	v.status, v.code = 401, "unauthorized"
	for _, sign := range []string{"none", ""} {
		v.sign = sign
		if err := c.Ping(context.Background(), events, "d2", []byte("[]")); code(err) != accesskey.CodeUnauthorized {
			t.Errorf("ping on 401 signed %q: %v", sign, err)
		}
	}
	v.sign = ""
	v.status, v.code = 500, ""
	if err := c.Ping(context.Background(), events, "d3", []byte("[]")); !errors.Is(err, server.ErrNotAccepted) || !strings.Contains(err.Error(), events) {
		t.Errorf("ping on a signed 500: %v", err)
	}
	v.status, v.code = 410, "run_closed"
	d, err := c.Deliver(context.Background(), events, "d4", []byte("[]"), "")
	if err != nil || !d.Closed() || !d.Stop() || d.Accepted() || d.Code != "run_closed" {
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

// TestRunConfigurationSignsTheQueryItSends pins the run configuration fetch: every
// label of the run is one query parameter, sorted by key and encoded, an empty value
// included, added to the run URL's own query, and the target signed is the target
// sent; the document is decoded with its raw policy and the digest read.
func TestRunConfigurationSignsTheQueryItSends(t *testing.T) {
	v := newVerified(t)
	c := v.client()
	run := v.srv.URL + "/v1/run-configuration"
	rc, digest, err := c.RunConfiguration(context.Background(), run, map[string]string{"repository": "acme/shop", "issue": "77", "forge": "github.com"})
	if err != nil {
		t.Fatal(err)
	}
	if digest != "sha256="+strings.Repeat("0", 64) || rc.Version != 1 || !strings.Contains(string(rc.SecurityPolicy), `"api.example"`) {
		t.Errorf("run configuration %+v, digest %s", rc, digest)
	}
	// The targets of the signed fixtures, a run of three labels and a run of two, then
	// the edges.
	for _, tc := range []struct {
		run    string
		labels map[string]string
		want   string
	}{
		{run, map[string]string{"repository": "acme/shop", "issue": "77", "forge": "github.com"}, signedFixture(t, "get-run-configuration-labels-valid").Target},
		{run, map[string]string{"forge": "github.com", "repository": "acme/shop"}, signedFixture(t, "get-run-configuration-valid").Target},
		{run, map[string]string{"run_key": "queue/1 2", "note": "", "k.v-x_y": "\u00fc&="}, "/v1/run-configuration?k.v-x_y=%C3%BC%26%3D&note=&run_key=queue%2F1+2"},
		{run + "?tenant=a&issue=0", map[string]string{"issue": "77"}, "/v1/run-configuration?issue=77&tenant=a"},
		{run, map[string]string{}, "/v1/run-configuration"},
		{run, nil, "/v1/run-configuration"},
	} {
		if _, _, err := c.RunConfiguration(context.Background(), tc.run, tc.labels); err != nil {
			t.Fatal(err)
		}
		if got := v.seen.URL.RequestURI(); got != tc.want {
			t.Errorf("labels %v: target %s, want %s", tc.labels, got, tc.want)
		}
	}
	v.runDoc = `{"version":1}`
	if rc, _, err := c.RunConfiguration(context.Background(), run, nil); err != nil || rc.SecurityPolicy != nil || rc.Variables != nil {
		t.Errorf("a run configuration without a policy: %+v %v", rc, err)
	}
	if _, _, err := c.RunConfiguration(context.Background(), v.srv.URL+"/v1/missing", nil); err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Errorf("a run URL that does not answer: %v", err)
	}
}

// TestLabelsBoundTheQuery pins the bound the contract states: the longest labels a run
// may carry, sixteen keys of 64 bytes and values of 256 bytes that all need encoding,
// make a query of 13,343 bytes, and one more label or byte is refused.
func TestLabelsBoundTheQuery(t *testing.T) {
	v := newVerified(t)
	labels := map[string]string{}
	for i := range server.MaxLabels {
		labels[fmt.Sprintf("%02d", i)+strings.Repeat("k", 62)] = strings.Repeat("\u00e9", 128)
	}
	if err := server.CheckLabels(labels); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/run-configuration", labels); err != nil {
		t.Fatal(err)
	}
	if n := len(v.seen.URL.RawQuery); n != 13343 {
		t.Errorf("the longest query is %d bytes, the contract says 13343", n)
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
// holds one, the answer's digests, and the ping's fail-closed rule.
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
	if err := c.Ping(context.Background(), events, "d2", []byte("[]")); err != nil {
		t.Error(err)
	}
	if _, ok := v.seen.Header[server.HeaderRunConfiguration]; ok {
		t.Error("the ping sent a run configuration digest with none held")
	}
	v.srv.Close()
	if err := c.Ping(context.Background(), events, "d4", []byte("[]")); err == nil {
		t.Error("ping on a closed server succeeded")
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
		if _, _, err := c.RunConfiguration(context.Background(), origin.URL+"/v1/run-configuration", nil); err == nil || !strings.Contains(err.Error(), "status 302") {
			t.Errorf("%s: a run configuration through a redirect: %v", name, err)
		}
		d, err := c.Deliver(context.Background(), origin.URL+"/v1/events", "d1", []byte("[]"), "")
		if err != nil || d.Status != http.StatusFound || d.Accepted() {
			t.Errorf("%s: a delivery through a redirect: %+v %v", name, d, err)
		}
		if err := c.Ping(context.Background(), origin.URL+"/v1/events", "d2", []byte("[]")); code(err) != accesskey.CodeAnswerUnsigned {
			t.Errorf("%s: a ping through a redirect: %v", name, err)
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
