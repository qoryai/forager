package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/server"
)

// gatewayRunID is the run of the known answers of a run through a gateway.
const gatewayRunID = "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d"

// seeded is the fixture key whose seed counts up from first: the fixture access key
// from 1, the fixture signing key from 65, the fixture gateway key from 97.
func seeded(t *testing.T, first int) *accesskey.Key {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(first + i)
	}
	k, err := accesskey.NewKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// throughGateway is through-gateway.json, the parts these tests read.
type throughGateway struct {
	RunKey struct {
		RunKey string `json:"run_key"`
	} `json:"run_key"`
	Requests []struct {
		AccessKeyID string   `json:"access_key_id"`
		Body        string   `json:"body"`
		Lines       []string `json:"lines"`
		Signature   string   `json:"signature"`
	} `json:"requests"`
	Answers []struct {
		Body      string   `json:"body"`
		Lines     []string `json:"lines"`
		Signature string   `json:"signature"`
	} `json:"answers"`
}

func loadThroughGateway(t *testing.T) throughGateway {
	t.Helper()
	var v throughGateway
	if err := json.Unmarshal(fixture(t, "fixtures/known-answers/through-gateway.json"), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestTheKnownAnswersOfARunThroughAGateway pins the client against the known answers
// of through-gateway.json: GatewayRegistration's Body, Attach's Body and PostOutcome
// build the known answers' bodies byte for byte, so each request carries the known
// answer's signature, and the client accepts each known answer's body under its
// signature: the registration's run key, the attach's run configuration with its
// labels and about, and the outcome's {"version": 1}.
func TestTheKnownAnswersOfARunThroughAGateway(t *testing.T) {
	v := loadThroughGateway(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		for i, req := range v.Requests {
			if r.RequestURI != req.Lines[4] {
				continue
			}
			if !bytes.Equal(body, fixture(t, req.Body)) || r.Header.Get(server.HeaderSignature) != req.Signature ||
				r.Header.Get(server.HeaderAccessKeyID) != req.AccessKeyID || r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("%s: the request is not the known answer's: %s", r.RequestURI, body)
			}
			a := v.Answers[i]
			if a.Lines[4] != "" {
				w.Header().Set(server.HeaderConfiguration, a.Lines[4])
			}
			if a.Lines[5] != "" {
				w.Header().Set(server.HeaderRunConfiguration, a.Lines[5])
			}
			if strings.HasSuffix(r.RequestURI, "/attach") {
				w.Header().Set("ETag", `"`+a.Lines[5]+`"`)
			}
			w.Header().Set(server.HeaderSignature, a.Signature)
			w.Write(fixture(t, a.Body))
			return
		}
		t.Errorf("unexpected %s %s", r.Method, r.RequestURI)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	pin := pinOf(seeded(t, 65))
	runURL := srv.URL + "/v1/runs"
	starter := &server.Client{Config: &server.Config{Version: 1, URL: srv.URL, AccessKeyID: accessKeyID, ApiaryPublicKey: pin}, Key: seeded(t, 1), InstanceID: instance, UserAgent: "qory-forager/test"}
	gateway := &server.Client{Config: &server.Config{Version: 1, URL: srv.URL, AccessKeyID: "ak_f1xt0re00000000g", ApiaryPublicKey: pin}, Key: seeded(t, 97), InstanceID: instance, UserAgent: "qory-forager/test"}
	ctx := context.Background()

	body, err := server.GatewayRegistration{RunID: gatewayRunID, Labels: map[string]string{"repository": "acme/shop"},
		About: &server.About{Title: "Fix the failing build"}, AttachSeconds: 600, Time: "2026-10-11T12:00:00Z"}.Body()
	if err != nil {
		t.Fatal(err)
	}
	ans, err := starter.RegisterThroughGateway(ctx, runURL, body)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Version != 1 || ans.RunID != gatewayRunID || ans.RunKey != v.RunKey.RunKey {
		t.Errorf("registration answer %+v", ans)
	}

	body, err = server.Attach{RunKey: ans.RunKey, IntervalSeconds: 30, Events: []string{"*"}, ForagerVersion: "v0.7.0-dev", Time: "2026-10-11T12:00:05Z"}.Body()
	if err != nil {
		t.Fatal(err)
	}
	att, digest, err := gateway.Attach(ctx, runURL, gatewayRunID, body)
	if err != nil {
		t.Fatal(err)
	}
	if digest != v.Answers[1].Lines[5] || att.RunConfiguration == nil || att.RunConfiguration.SecurityPolicy == nil ||
		att.Labels["repository"] != "acme/shop" || len(att.Labels) != 1 || att.About == nil || att.About.Title != "Fix the failing build" {
		t.Errorf("attach answer %+v, digest %s", att, digest)
	}

	if err := starter.PostOutcome(ctx, runURL, gatewayRunID, server.Outcome{State: "succeeded", Reason: "all_checks_passed", Time: "2026-10-11T12:30:00Z"}); err != nil {
		t.Fatal(err)
	}
}

// apiary is a fake server for the calls of a run through a gateway: it verifies each
// request's signature, records it, and answers what answer returns, signed under its
// signer unless unsigned is set.
type apiary struct {
	t        *testing.T
	srv      *httptest.Server
	key      *accesskey.Key
	signer   *accesskey.Key
	hits     atomic.Int32
	target   string
	body     []byte
	unsigned bool
	answer   func(r *http.Request, body []byte) (int, http.Header, string)
}

func newApiary(t *testing.T) *apiary {
	t.Helper()
	a := &apiary{t: t, key: generate(t), signer: generate(t)}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		a.target, a.body = r.RequestURI, body
		sig := r.Header.Get(server.HeaderSignature)
		if !a.key.PublicKey().VerifyRequest(accesskey.Request{AccessKeyID: accessKeyID, InstanceID: instance, Method: r.Method, Target: r.RequestURI, Body: body}, sig) {
			t.Errorf("%s: the signature does not verify", r.RequestURI)
		}
		status, h, out := a.answer(r, body)
		for k, v := range h {
			w.Header()[k] = v
		}
		if !a.unsigned && status != http.StatusUnauthorized {
			w.Header().Set(server.HeaderSignature, a.signer.SignAnswer(accesskey.Answer{Status: status, RequestSignature: sig, Body: []byte(out),
				Configuration: w.Header().Get(server.HeaderConfiguration), RunConfiguration: w.Header().Get(server.HeaderRunConfiguration)}))
		}
		w.WriteHeader(status)
		io.WriteString(w, out)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *apiary) client() *server.Client {
	return &server.Client{Config: &server.Config{Version: 1, URL: a.srv.URL, AccessKeyID: accessKeyID, ApiaryPublicKey: pinOf(a.signer)}, Key: a.key, InstanceID: instance, UserAgent: "qory-forager/test"}
}

func (a *apiary) runURL() string { return a.srv.URL + "/v1/runs" }

// coded answers a signed refusal with the code.
func coded(status int, code string) func(*http.Request, []byte) (int, http.Header, string) {
	return func(*http.Request, []byte) (int, http.Header, string) {
		return status, nil, `{"error":"` + code + `"}`
	}
}

// runKeyOf is a run key of the run, signed under a fresh key.
func runKeyOf(t *testing.T, runID string) string {
	t.Helper()
	g := generate(t)
	rk, err := runkey.Key{RunID: runID, Workspace: "ws_f1xt0re000000000", NodeID: "np_f1xt0re000000000", Gateway: "ng_f1xt0re000000000",
		InstanceID: instance, GatewayURL: "https://gateway.example:8443", GatewayKeys: []accesskey.PublicKey{g.PublicKey()},
		Issued: time.Unix(1700000000, 0), AttachBy: time.Unix(1700000600, 0)}.Sign(generate(t))
	if err != nil {
		t.Fatal(err)
	}
	return rk
}

// TestAGatewayRegistrationsBody pins the gateway shape's body: the time filled from the
// clock when it is left empty, in UTC with whole seconds, version 1 when left 0, no
// labels, about or attach_seconds when there are none, never the direct shape's four
// members, and a body run-registration.schema.json accepts; a run id outside its form,
// labels the contract refuses and an attach window below 0 build no body.
func TestAGatewayRegistrationsBody(t *testing.T) {
	before := time.Now().UTC().Truncate(time.Second)
	b, err := server.GatewayRegistration{RunID: gatewayRunID}.Body()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	ts, _ := m["time"].(string)
	at, err := time.Parse("2006-01-02T15:04:05Z", ts)
	if err != nil || at.Before(before) || at.After(time.Now().Add(time.Second)) {
		t.Errorf("time %q; want the clock's now in UTC with whole seconds", ts)
	}
	if len(m) != 3 || m["version"] != float64(1) || m["run_id"] != gatewayRunID {
		t.Errorf("body %s; want version, run_id and time alone", b)
	}
	schema, err := contracts.Compile("run-registration.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := contracts.Decode("r.json", b)
	if err := schema.Validate(doc); err != nil {
		t.Errorf("the schema refuses %s: %v", b, err)
	}
	b, err = server.GatewayRegistration{RunID: gatewayRunID, Time: "2026-10-11T12:00:00Z", AttachSeconds: 7200, About: &server.About{}}.Body()
	if err != nil || string(b) != `{"version":1,"run_id":"`+gatewayRunID+`","attach_seconds":7200,"time":"2026-10-11T12:00:00Z"}` {
		t.Errorf("body %s, %v", b, err)
	}
	for name, r := range map[string]server.GatewayRegistration{
		"a run id in upper case":   {RunID: strings.ToUpper(gatewayRunID)},
		"a label key with a space": {RunID: gatewayRunID, Labels: map[string]string{"a b": "c"}},
		"an attach window below 0": {RunID: gatewayRunID, AttachSeconds: -1},
	} {
		if _, err := r.Body(); err == nil {
			t.Errorf("%s: a body was built", name)
		}
	}
}

// TestRegisterThroughGatewayRefusals pins how a registration through a gateway ends
// otherwise: each signed 409 of the registration's resolution, and instance_limit and
// run_id_used, is its code, its message "register <run.url>: <code> (status 409)"; a
// signed 410 is ErrNotAccepted; a 401 is unauthorized; an unsigned 200 is
// answer_unsigned; and a signed 200 whose run id is not the registration's, whose run
// key is of another run or is no run key, or that the schema refuses, is a
// DocumentError whose message never contains the run key, as is one that carries
// X-Qory-Run-Configuration or ETag.
func TestRegisterThroughGatewayRefusals(t *testing.T) {
	a := newApiary(t)
	c := a.client()
	body, err := server.GatewayRegistration{RunID: gatewayRunID}.Body()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, code409 := range []string{"no_default_gateway", "gateway_not_serving", "gateway_without_key", "node_is_direct", "node_uses_gateway", "gateway_key", "instance_limit", "run_id_used"} {
		a.answer = coded(http.StatusConflict, code409)
		_, err := c.RegisterThroughGateway(ctx, a.runURL(), body)
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != code409 || r.From != accesskey.FromApiary || err.Error() != "register "+a.runURL()+": "+code409+" (status 409)" {
			t.Errorf("409 %s: %v", code409, err)
		}
	}
	if a.target != "/v1/runs" || !bytes.Equal(a.body, body) {
		t.Errorf("sent %s %s; want the body to /v1/runs", a.target, a.body)
	}
	a.answer = coded(http.StatusGone, "no_runs_here")
	if _, err := c.RegisterThroughGateway(ctx, a.runURL(), body); !errors.Is(err, server.ErrNotAccepted) {
		t.Errorf("signed 410: %v", err)
	}
	a.answer = coded(http.StatusUnauthorized, "unauthorized")
	if _, err := c.RegisterThroughGateway(ctx, a.runURL(), body); code(err) != accesskey.CodeUnauthorized {
		t.Errorf("401: %v", err)
	}
	rk := runKeyOf(t, gatewayRunID)
	answerWith := func(doc string) func(*http.Request, []byte) (int, http.Header, string) {
		return func(*http.Request, []byte) (int, http.Header, string) { return 200, nil, doc }
	}
	a.answer = answerWith(`{"version":1,"run_id":"` + gatewayRunID + `","run_key":"` + rk + `"}`)
	a.unsigned = true
	if _, err := c.RegisterThroughGateway(ctx, a.runURL(), body); code(err) != accesskey.CodeAnswerUnsigned {
		t.Errorf("unsigned 200: %v", err)
	}
	a.unsigned = false
	if ans, err := c.RegisterThroughGateway(ctx, a.runURL(), body); err != nil || ans.RunKey != rk {
		t.Errorf("signed 200: %+v, %v", ans, err)
	}
	for name, h := range map[string]http.Header{
		"a run-configuration digest": {server.HeaderRunConfiguration: {"sha256=" + strings.Repeat("2", 64)}},
		"an ETag":                    {"Etag": {`"sha256=` + strings.Repeat("2", 64) + `"`}},
	} {
		a.answer = func(*http.Request, []byte) (int, http.Header, string) {
			return 200, h, `{"version":1,"run_id":"` + gatewayRunID + `","run_key":"` + rk + `"}`
		}
		_, err := c.RegisterThroughGateway(ctx, a.runURL(), body)
		if want := "registration answer " + a.runURL() + ": the answer carries X-Qory-Run-Configuration or ETag; a registration through a gateway carries no run configuration"; !errors.As(err, new(*server.DocumentError)) || err.Error() != want {
			t.Errorf("a signed 200 with %s: %v; want %s", name, err, want)
		}
	}
	other := "0192f0c1-7d4e-7a2b-8c3d-000000000000"
	for name, doc := range map[string]string{
		"another run id":       `{"version":1,"run_id":"` + other + `","run_key":"` + runKeyOf(t, other) + `"}`,
		"another run's key":    `{"version":1,"run_id":"` + gatewayRunID + `","run_key":"` + runKeyOf(t, other) + `"}`,
		"a run key cut short":  `{"version":1,"run_id":"` + gatewayRunID + `","run_key":"` + rk[:len(rk)-3] + `"}`,
		"no run key":           `{"version":1,"run_id":"` + gatewayRunID + `"}`,
		"a run key with space": `{"version":1,"run_id":"` + gatewayRunID + `","run_key":"` + rk[:30] + ` ` + rk[30:] + `"}`,
		"a member twice":       `{"version":1,"run_id":"` + gatewayRunID + `","run_key":"` + rk + `","run_key":"` + rk + `"}`,
	} {
		a.answer = answerWith(doc)
		_, err := c.RegisterThroughGateway(ctx, a.runURL(), body)
		var de *server.DocumentError
		if !errors.As(err, &de) {
			t.Errorf("%s: %v; want a DocumentError", name, err)
			continue
		}
		if strings.Contains(err.Error(), rk[4:20]) || strings.Contains(err.Error(), rk[len(rk)-20:]) {
			t.Errorf("%s: the error contains the run key: %v", name, err)
		}
	}
}

// TestAttach pins the attach: a POST of the body to <run.url>/<run_id>/attach, whose
// signed 200 is the run configuration with its digest and the registration's labels and
// about, each absent when the answer has none; each of attach's own signed refusals is
// its code, its message "attach <run.url>/<run_id>: <code> (status <status>)"; a
// signed 410 is ErrNotAccepted; and a 200 without its digest header, without one ETag
// that is the digest in quotes, or with labels the contract refuses, is a
// DocumentError.
func TestAttach(t *testing.T) {
	a := newApiary(t)
	c := a.client()
	rk := runKeyOf(t, gatewayRunID)
	body, err := server.Attach{RunKey: rk, IntervalSeconds: 30, ForagerVersion: "v0.0.0-test"}.Body()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	digest := "sha256=" + strings.Repeat("2", 64)
	doc := `{"version":1}`
	withDigest := true
	etag := []string{`"` + digest + `"`}
	a.answer = func(r *http.Request, _ []byte) (int, http.Header, string) {
		h := http.Header{}
		if withDigest {
			h.Set(server.HeaderRunConfiguration, digest)
		}
		h["Etag"] = etag
		return 200, h, doc
	}
	ans, got, err := c.Attach(ctx, a.runURL(), gatewayRunID, body)
	if err != nil || got != digest || ans.RunConfiguration == nil || ans.Labels != nil || ans.About != nil {
		t.Errorf("attach: %+v, %s, %v", ans, got, err)
	}
	if a.target != "/v1/runs/"+gatewayRunID+"/attach" || !bytes.Equal(a.body, body) {
		t.Errorf("sent %s %s", a.target, a.body)
	}
	doc = `{"version":1,"variables":{"NODE_ENV":{"value":"test"}},"labels":{"repository":"acme/shop"},"about":{"title":"Fix the failing build","details":{"n":1}}}`
	ans, _, err = c.Attach(ctx, a.runURL(), gatewayRunID, body)
	if err != nil || ans.RunConfiguration.Values()["NODE_ENV"] != "test" || ans.Labels["repository"] != "acme/shop" ||
		ans.About == nil || string(ans.About.Details) != `{"n":1}` {
		t.Errorf("attach with labels and about: %+v, %v", ans, err)
	}
	for _, bad := range []string{`{"version":1,"labels":{"A B":"x"}}`, `{"version":1,"labels":["x"]}`, `{"version":1,"about":{"title":7}}`} {
		doc = bad
		if _, _, err := c.Attach(ctx, a.runURL(), gatewayRunID, body); !errors.As(err, new(*server.DocumentError)) {
			t.Errorf("%s: %v; want a DocumentError", bad, err)
		}
	}
	doc = `{"version":1}`
	for name, e := range map[string][]string{
		"no ETag":                nil,
		"an ETag without quotes": {digest},
		"two ETags":              {`"` + digest + `"`, `"` + digest + `"`},
		"another digest's ETag":  {`"sha256=` + strings.Repeat("3", 64) + `"`},
		"a weak ETag":            {`W/"` + digest + `"`},
	} {
		etag = e
		_, _, err := c.Attach(ctx, a.runURL(), gatewayRunID, body)
		if want := "attach answer " + a.runURL() + "/" + gatewayRunID + "/attach: the ETag header is not the X-Qory-Run-Configuration digest in quotes"; !errors.As(err, new(*server.DocumentError)) || err.Error() != want {
			t.Errorf("%s: %v; want %s", name, err, want)
		}
	}
	withDigest = false
	if _, _, err := c.Attach(ctx, a.runURL(), gatewayRunID, body); !errors.As(err, new(*server.DocumentError)) {
		t.Errorf("no digest: %v; want a DocumentError", err)
	}
	for _, rc := range []struct {
		status int
		code   string
	}{{409, "not_a_gateway"}, {400, "run_key_invalid"}, {409, "run_key_expired"}, {409, "wrong_gateway"}, {409, "workspace_not_served"}, {409, "run_attached"}} {
		a.answer = coded(rc.status, rc.code)
		_, _, err := c.Attach(ctx, a.runURL(), gatewayRunID, body)
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != rc.code || r.Status != rc.status ||
			err.Error() != fmt.Sprintf("attach %s/%s: %s (status %d)", a.runURL(), gatewayRunID, rc.code, rc.status) {
			t.Errorf("%d %s: %v", rc.status, rc.code, err)
		}
	}
	a.answer = func(*http.Request, []byte) (int, http.Header, string) { return 410, nil, "" }
	if _, _, err := c.Attach(ctx, a.runURL(), gatewayRunID, body); !errors.Is(err, server.ErrNotAccepted) {
		t.Errorf("signed 410: %v", err)
	}
	if _, _, err := c.Attach(ctx, a.runURL(), "not-a-run", body); err == nil {
		t.Error("an attach of a run id outside its form was sent")
	}
}

// TestAnAttachsBody pins the attach's body: the time filled from the clock when left
// empty, version 1 and the contract revision when left 0, events [] when nil, members
// run-attach.schema.json accepts; a run key that does not read as one, an interval
// outside 1 to 300 and no Forager version build no body, and the error never contains
// the run key.
func TestAnAttachsBody(t *testing.T) {
	rk := runKeyOf(t, gatewayRunID)
	b, err := server.Attach{RunKey: rk, IntervalSeconds: 30, ForagerVersion: "v0.0.0-test"}.Body()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", m["time"].(string)); err != nil || m["version"] != float64(1) ||
		m["contract_version"] != float64(server.Revision) || m["events"] == nil {
		t.Errorf("body %s", b)
	}
	schema, err := contracts.Compile("run-attach.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := contracts.Decode("a.json", b)
	if err := schema.Validate(doc); err != nil {
		t.Errorf("the schema refuses %s: %v", b, err)
	}
	for name, a := range map[string]server.Attach{
		"no run key":          {IntervalSeconds: 30, ForagerVersion: "v"},
		"a run key cut short": {RunKey: rk[:len(rk)-2], IntervalSeconds: 30, ForagerVersion: "v"},
		"interval 0":          {RunKey: rk, ForagerVersion: "v"},
		"interval 301":        {RunKey: rk, IntervalSeconds: 301, ForagerVersion: "v"},
		"no Forager version":  {RunKey: rk, IntervalSeconds: 30},
	} {
		_, err := a.Body()
		if err == nil {
			t.Errorf("%s: a body was built", name)
		} else if strings.Contains(err.Error(), rk[4:20]) {
			t.Errorf("%s: the error contains the run key: %v", name, err)
		}
	}
}

// TestPostOutcome pins the outcome: a POST to <run.url>/<run_id>/outcome; the zero
// Outcome sends version and time alone, the time the clock's now, which the server reads
// as cancelled with the reason stopped; a state and a reason are sent as given; a reason
// without a state and an unknown state are refused before anything is sent; a signed
// 409 outcome_given is its code, "outcome <run.url>/<run_id>: outcome_given (status
// 409)", and a signed 404 not_found its code; and a 200 the schema refuses is a
// DocumentError.
func TestPostOutcome(t *testing.T) {
	a := newApiary(t)
	c := a.client()
	ctx := context.Background()
	doc := `{"version":1}`
	a.answer = func(*http.Request, []byte) (int, http.Header, string) { return 200, nil, doc }
	if err := c.PostOutcome(ctx, a.runURL(), gatewayRunID, server.Outcome{}); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(a.body, &m); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", m["time"].(string)); err != nil || len(m) != 2 || m["version"] != float64(1) {
		t.Errorf("the zero outcome sent %s; want version and time alone", a.body)
	}
	if a.target != "/v1/runs/"+gatewayRunID+"/outcome" {
		t.Errorf("sent to %s", a.target)
	}
	if err := c.PostOutcome(ctx, a.runURL(), gatewayRunID, server.Outcome{State: "failed", Reason: "tests_failed", Time: "2026-10-11T12:30:00Z"}); err != nil ||
		string(a.body) != `{"version":1,"state":"failed","reason":"tests_failed","time":"2026-10-11T12:30:00Z"}` {
		t.Errorf("sent %s, %v", a.body, err)
	}
	if err := c.PostOutcome(ctx, a.runURL(), gatewayRunID, server.Outcome{State: "cancelled", Time: "2026-10-11T12:30:00Z"}); err != nil ||
		string(a.body) != `{"version":1,"state":"cancelled","time":"2026-10-11T12:30:00Z"}` {
		t.Errorf("sent %s, %v", a.body, err)
	}
	hits := a.hits.Load()
	for name, o := range map[string]server.Outcome{
		"a reason without a state": {Reason: "all_checks_passed"},
		"an unknown state":         {State: "stopped"},
	} {
		if err := c.PostOutcome(ctx, a.runURL(), gatewayRunID, o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := c.PostOutcome(ctx, a.runURL(), "nope", server.Outcome{}); err == nil {
		t.Error("an outcome of a run id outside its form was accepted")
	}
	if a.hits.Load() != hits {
		t.Error("a refused outcome was sent")
	}
	a.answer = coded(http.StatusConflict, "outcome_given")
	err := c.PostOutcome(ctx, a.runURL(), gatewayRunID, server.Outcome{State: "succeeded"})
	if code(err) != "outcome_given" || err.Error() != "outcome "+a.runURL()+"/"+gatewayRunID+": outcome_given (status 409)" {
		t.Errorf("409: %v", err)
	}
	a.answer = coded(http.StatusNotFound, "not_found")
	if err := c.PostOutcome(ctx, a.runURL(), gatewayRunID, server.Outcome{}); code(err) != "not_found" {
		t.Errorf("404: %v", err)
	}
	a.answer = func(*http.Request, []byte) (int, http.Header, string) { return 200, nil, `{"version":2}` }
	if err := c.PostOutcome(ctx, a.runURL(), gatewayRunID, server.Outcome{}); !errors.As(err, new(*server.DocumentError)) {
		t.Errorf("version 2: %v; want a DocumentError", err)
	}
}

// TestTheEndMember pins ReadEnd and the end of a delivery: a signed 2xx whose body
// carries end gives its state and reason; a reason that is one of Forager's reserved
// codes is dropped and the state kept; a body batch-answer.schema.json refuses, a
// reason that is no code or not a string and a member beside state and reason among
// them, an empty body, one without end, one that is not JSON and an end with an unknown
// state are no end; and an answer that is not a signed 2xx carries none, whatever its
// body.
func TestTheEndMember(t *testing.T) {
	for body, want := range map[string]*server.ServerEnd{
		`{"end":{"state":"succeeded","reason":"all_checks_passed"}}`: {State: "succeeded", Reason: "all_checks_passed"},
		`{"end":{"state":"cancelled"}}`:                              {State: "cancelled"},
		`{"end":{"state":"failed","reason":"Not A Code"}}`:           nil,
		`{"end":{"state":"failed","reason":"Checks Failed"}}`:        nil,
		`{"end":{"state":"failed","reason":7}}`:                      nil,
		`{"end":{"state":"succeeded","extra":1}}`:                    nil,
		`{"end":{"state":"failed","reason":"stopped"}}`:              {State: "failed"},
		`{"end":{"state":"failed"},"later":{"x":1}}`:                 {State: "failed"},
		``:                                   nil,
		`{}`:                                 nil,
		`not json`:                           nil,
		`{"end":{"state":"stopped"}}`:        nil,
		`{"end":{"reason":"x"}}`:             nil,
		`{"end":null}`:                       nil,
		`{"end":{"state":"failed"},"end":1}`: nil,
	} {
		got := server.ReadEnd([]byte(body))
		if (got == nil) != (want == nil) || got != nil && *got != *want {
			t.Errorf("ReadEnd(%s) = %+v; want %+v", body, got, want)
		}
	}
	a := newApiary(t)
	c := a.client()
	status, out := 202, `{"end":{"state":"succeeded","reason":"all_checks_passed"}}`
	a.answer = func(*http.Request, []byte) (int, http.Header, string) { return status, nil, out }
	d, err := c.Deliver(context.Background(), a.srv.URL+"/v1/events", "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9e", []byte(`[]`), "")
	if err != nil || d.ServerEnd == nil || *d.ServerEnd != (server.ServerEnd{State: "succeeded", Reason: "all_checks_passed"}) || d.Stop() || d.Closed() {
		t.Errorf("signed 202 with end: %+v, %v", d, err)
	}
	a.unsigned = true
	if d, _ := c.Deliver(context.Background(), a.srv.URL+"/v1/events", "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9e", []byte(`[]`), ""); d.ServerEnd != nil {
		t.Errorf("an unsigned 202 carried an end: %+v", d)
	}
	a.unsigned, status = false, 410
	if d, _ := c.Deliver(context.Background(), a.srv.URL+"/v1/events", "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9e", []byte(`[]`), ""); d.ServerEnd != nil || !d.Stop() {
		t.Errorf("a signed 410 carried an end: %+v", d)
	}
}

// relay is a TLS server that stands for a gateway relaying to the server: it answers
// as the server would, signed, a registration with through-gateway.json's run key, and
// records the host and the target of each request.
type relay struct {
	srv    *httptest.Server
	caFile string
	pin    string
	hosts  []string
	paths  []string
}

func newRelay(t *testing.T, signer, key *accesskey.Key) *relay {
	t.Helper()
	g := &relay{}
	rk := loadThroughGateway(t).RunKey.RunKey
	g.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.hosts, g.paths = append(g.hosts, r.Host), append(g.paths, r.RequestURI)
		body, _ := io.ReadAll(r.Body)
		sig := r.Header.Get(server.HeaderSignature)
		req := accesskey.Request{AccessKeyID: accessKeyID, InstanceID: instance, Method: r.Method, Target: r.RequestURI, Body: body, Timestamp: r.Header.Get(server.HeaderTimestamp)}
		if !key.PublicKey().VerifyRequest(req, sig) {
			t.Errorf("%s: the signature does not verify over the target as sent", r.RequestURI)
		}
		status, out := 200, ""
		switch {
		case r.URL.Path == server.WellKnown:
			w.Header().Set(server.HeaderConfiguration, "sha256=c0")
			out = `{"version":1,"node_id":"np_f1xt0re000000000","workspaces":["ws_f1xt0re000000000"],"events":{"url":"https://qory.example/v1/events","types":["*"]},"run":{"url":"https://qory.example/v1/runs"},"apiary_public_key":[{"alg":"ed25519","public_key":"` + signer.PublicKey().String() + `"}]}`
		case r.URL.Path == "/v1/runs":
			out = `{"version":1,"run_id":"` + gatewayRunID + `","run_key":"` + rk + `"}`
		case strings.HasSuffix(r.URL.Path, "/outcome"):
			out = `{"version":1}`
		default:
			status = 202
		}
		w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: status, RequestSignature: sig, Body: []byte(out), Configuration: w.Header().Get(server.HeaderConfiguration)}))
		w.WriteHeader(status)
		io.WriteString(w, out)
	}))
	t.Cleanup(g.srv.Close)
	cert := g.srv.Certificate()
	g.caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(g.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	g.pin = base64.StdEncoding.EncodeToString(sum[:])
	return g
}

// TestViaSendsEveryRequestToTheGateway pins via: with it set, discovery, a delivery, an
// outcome and the registration of discovery's absolute run.url each go to via.url's
// origin with the target, the query included, unchanged and signed as without via, while
// url stays the server's own; the chain is checked against ca_file, the pin is honoured,
// and without ca_file the system's roots refuse the test's authority. No proxy is used:
// with HTTPS_PROXY and HTTP_PROXY set, the transport Via.Transport returns for a
// gateway's host name has no Proxy, and a caller's transport whose proxy nobody listens
// at still reaches the gateway itself.
func TestViaSendsEveryRequestToTheGateway(t *testing.T) {
	signer, key := generate(t), generate(t)
	g := newRelay(t, signer, key)
	client := func(v *server.Via) *server.Client {
		return &server.Client{Config: &server.Config{Version: 1, URL: "https://qory.example", AccessKeyID: accessKeyID, ApiaryPublicKey: pinOf(signer), Via: v},
			Key: key, InstanceID: instance, UserAgent: "qory-forager/test"}
	}
	ctx := context.Background()
	c := client(&server.Via{URL: g.srv.URL, CAFile: g.caFile, CertificateSHA256: g.pin})
	conf, _, err := c.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if conf.Run.URL != "https://qory.example/v1/runs" || c.Config.URL != "https://qory.example" {
		t.Errorf("run.url %s, url %s; want the server's", conf.Run.URL, c.Config.URL)
	}
	body, err := server.GatewayRegistration{RunID: gatewayRunID}.Body()
	if err != nil {
		t.Fatal(err)
	}
	if ans, err := c.RegisterThroughGateway(ctx, conf.Run.URL, body); err != nil || ans.RunID != gatewayRunID {
		t.Fatalf("registration: %+v, %v", ans, err)
	}
	if err := c.PostOutcome(ctx, conf.Run.URL, gatewayRunID, server.Outcome{}); err != nil {
		t.Fatal(err)
	}
	d, err := c.Deliver(ctx, "https://qory.example/v1/events?shard=2", "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9e", []byte(`[]`), "")
	if err != nil || !d.Accepted() {
		t.Fatalf("delivery: %+v, %v", d, err)
	}
	host := strings.TrimPrefix(g.srv.URL, "https://")
	want := []string{server.WellKnown, "/v1/runs", "/v1/runs/" + gatewayRunID + "/outcome", "/v1/events?shard=2"}
	if len(g.paths) != 4 || g.paths[0] != want[0] || g.paths[1] != want[1] || g.paths[2] != want[2] || g.paths[3] != want[3] {
		t.Errorf("targets %q; want %q", g.paths, want)
	}
	for _, h := range g.hosts {
		if h != host {
			t.Errorf("host %s; want the gateway's %s", h, host)
		}
	}
	other := sha256.Sum256([]byte("another key"))
	for name, v := range map[string]*server.Via{
		"another pin":      {URL: g.srv.URL, CAFile: g.caFile, CertificateSHA256: base64.StdEncoding.EncodeToString(other[:])},
		"the system roots": {URL: g.srv.URL},
	} {
		if _, _, err := client(v).Discover(ctx); err == nil {
			t.Errorf("%s: discovery passed", name)
		}
	}
	if _, _, err := client(&server.Via{URL: g.srv.URL, CAFile: g.caFile}).Discover(ctx); err != nil {
		t.Errorf("ca_file without a pin: %v", err)
	}
	unreachable, _ := url.Parse("http://127.0.0.1:1")
	withProxy := client(&server.Via{URL: g.srv.URL, CAFile: g.caFile})
	withProxy.HTTP = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(unreachable)}}
	if _, _, err := withProxy.Discover(ctx); err != nil {
		t.Errorf("a caller's transport with a proxy: %v; want the gateway reached itself", err)
	}
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")
	t.Setenv("HTTP_PROXY", "http://proxy.example:3128")
	tr, err := server.Via{URL: "https://gateway.example:8443"}.Transport()
	if err != nil {
		t.Fatal(err)
	}
	if tr.Proxy != nil {
		req, _ := http.NewRequest(http.MethodGet, "https://gateway.example:8443"+server.WellKnown, nil)
		u, err := tr.Proxy(req)
		t.Errorf("via's transport has a Proxy, which gives %v, %v for the gateway; want none", u, err)
	}
}

// TestViaKeepsItsTrustOverACallersTLSDialing pins that a caller's transport that makes
// TLS itself cannot switch via's trust off: net/http uses DialTLSContext in place of
// TLSClientConfig, and here it accepts any certificate; under via the system's roots
// still refuse the test's authority and a pin of another key still refuses the
// gateway's certificate, while ca_file and the right pin reach it.
func TestViaKeepsItsTrustOverACallersTLSDialing(t *testing.T) {
	signer, key := generate(t), generate(t)
	g := newRelay(t, signer, key)
	ctx := context.Background()
	insecure := &http.Transport{DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}
		return d.DialContext(ctx, network, addr)
	}}
	conn, err := insecure.DialTLSContext(ctx, "tcp", strings.TrimPrefix(g.srv.URL, "https://"))
	if err != nil {
		t.Fatalf("the caller's TLS dialing does not reach the test server: %v", err)
	}
	conn.Close()
	other := sha256.Sum256([]byte("another key"))
	for name, tc := range map[string]struct {
		via  server.Via
		pass bool
	}{
		"the system roots": {server.Via{URL: g.srv.URL}, false},
		"another pin":      {server.Via{URL: g.srv.URL, CAFile: g.caFile, CertificateSHA256: base64.StdEncoding.EncodeToString(other[:])}, false},
		"ca_file and pin":  {server.Via{URL: g.srv.URL, CAFile: g.caFile, CertificateSHA256: g.pin}, true},
	} {
		v := tc.via
		c := &server.Client{Config: &server.Config{Version: 1, URL: "https://qory.example", AccessKeyID: accessKeyID, ApiaryPublicKey: pinOf(signer), Via: &v},
			Key: key, InstanceID: instance, UserAgent: "qory-forager/test", HTTP: &http.Client{Transport: insecure}}
		if _, _, err := c.Discover(ctx); (err == nil) != tc.pass {
			t.Errorf("%s: discovery under a caller's DialTLSContext gave %v; want passed %v", name, err, tc.pass)
		}
	}
}

// roundTripper is a transport of another type than *http.Transport, as a program that
// embeds Forager may set http.DefaultTransport to.
type roundTripper struct{}

func (roundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("not sent")
}

// TestViaWithAnotherDefaultTransport pins that via's transport is made when
// http.DefaultTransport is not an *http.Transport, with no proxy and via's TLS. It
// replaces a global, so it runs alone: no test of the package is parallel.
func TestViaWithAnotherDefaultTransport(t *testing.T) {
	saved := http.DefaultTransport
	http.DefaultTransport = roundTripper{}
	t.Cleanup(func() { http.DefaultTransport = saved })
	tr, err := server.Via{URL: "https://gateway.example:8443"}.Transport()
	if err != nil {
		t.Fatal(err)
	}
	if tr.Proxy != nil || tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS13 || !tr.DisableKeepAlives {
		t.Errorf("via's transport has a Proxy %t, TLS %+v, keep-alives off %t; want no proxy and TLS 1.3 alone", tr.Proxy != nil, tr.TLSClientConfig, tr.DisableKeepAlives)
	}
}

// TestTheRunKeyIsNeverShownInARegistrationAnswerOrAnAttach pins that a registration
// answer and an attach print and log without their run key under every verb, by value
// and by pointer, with the rest of what they hold.
func TestTheRunKeyIsNeverShownInARegistrationAnswerOrAnAttach(t *testing.T) {
	rk := runKeyOf(t, gatewayRunID)
	var out bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&out, nil))
	a := server.RegistrationAnswer{Version: 1, RunID: gatewayRunID, RunKey: rk}
	at := server.Attach{Version: 1, RunKey: rk, IntervalSeconds: 30, Events: []string{"*"}, ForagerVersion: "v0.7.0-dev", ContractVersion: 1}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		fmt.Fprintf(&out, verb+"\n", a)
		fmt.Fprintf(&out, verb+"\n", &a)
		fmt.Fprintf(&out, verb+"\n", at)
		fmt.Fprintf(&out, verb+"\n", &at)
	}
	log.Info("registered", "answer", a, "attach", at)
	shown := out.String()
	if strings.Contains(shown, rk[4:24]) {
		t.Errorf("a run key is shown:\n%s", shown)
	}
	for _, want := range []string{"[redacted]", "server.RegistrationAnswer{", "server.Attach{", gatewayRunID, "v0.7.0-dev", `"run_key":"[redacted]"`, `"interval_seconds":30`} {
		if !strings.Contains(shown, want) {
			t.Errorf("%s is not shown:\n%s", want, shown)
		}
	}
	if b, err := at.Body(); err != nil || !strings.Contains(string(b), rk) {
		t.Errorf("the attach's body %s, %v; want the run key in it", b, err)
	}
}

// TestTheRunKeyIsNeverWrittenAsJSON pins that a registration answer and an attach
// write their run key redacted under encoding/json, nested in a value log/slog's
// JSONHandler logs as well, and that the attach's body is the wire form, with it.
func TestTheRunKeyIsNeverWrittenAsJSON(t *testing.T) {
	rk := runKeyOf(t, gatewayRunID)
	a := server.RegistrationAnswer{Version: 1, RunID: gatewayRunID, RunKey: rk}
	at := server.Attach{Version: 1, RunKey: rk, IntervalSeconds: 30, Events: []string{"*"}, ForagerVersion: "v0.7.0-dev", ContractVersion: 1, Time: "2026-10-11T12:00:05Z"}
	var out bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&out, nil))
	log.Info("nested", "both", struct {
		A server.RegistrationAnswer
		B *server.Attach
	}{a, &at})
	if strings.Contains(out.String(), "qrk_") || !strings.Contains(out.String(), "[redacted]") {
		t.Errorf("the nested log: %s", out.String())
	}
	b, err := json.Marshal(a)
	if err != nil || string(b) != `{"version":1,"run_id":"`+gatewayRunID+`","run_key":"[redacted]"}` {
		t.Errorf("json.Marshal of the answer: %s, %v", b, err)
	}
	b, err = json.Marshal(at)
	if err != nil || strings.Contains(string(b), "qrk_") || !strings.Contains(string(b), `"run_key":"[redacted]"`) {
		t.Errorf("json.Marshal of the attach: %s, %v", b, err)
	}
	b, err = at.Body()
	want := `{"version":1,"run_key":"` + rk + `","interval_seconds":30,"events":["*"],"forager_version":"v0.7.0-dev","contract_version":1,"time":"2026-10-11T12:00:05Z"}`
	if err != nil || string(b) != want {
		t.Errorf("the attach's body %s, %v; want %s", b, err, want)
	}
	var back server.RegistrationAnswer
	if err := json.Unmarshal([]byte(`{"version":1,"run_id":"`+gatewayRunID+`","run_key":"`+rk+`"}`), &back); err != nil || back.RunKey != rk {
		t.Errorf("the answer read back: %v", err)
	}
}

// TestViaIsChecked pins what via refuses before anything is sent: a URL that is not an
// https origin, a ca_file that cannot be read, and a pin not in its form; and that the
// server document reads via, the fixture with it and the invalid fixtures refused.
func TestViaIsChecked(t *testing.T) {
	for name, v := range map[string]server.Via{
		"plain http":     {URL: "http://127.0.0.1:8443"},
		"a path":         {URL: "https://gateway.example/relay"},
		"a query":        {URL: "https://gateway.example?x=1"},
		"user info":      {URL: "https://u@gateway.example"},
		"no ca file":     {URL: "https://gateway.example", CAFile: filepath.Join(t.TempDir(), "none.pem")},
		"a hex pin":      {URL: "https://gateway.example", CertificateSHA256: strings.Repeat("ab", 32)},
		"a pin unpadded": {URL: "https://gateway.example", CertificateSHA256: strings.Repeat("A", 43)},
	} {
		if err := v.Check(); err == nil {
			t.Errorf("%s: passed", name)
		}
		c := &server.Client{Config: &server.Config{Version: 1, URL: "https://qory.example", AccessKeyID: accessKeyID, ApiaryPublicKey: pinOf(generate(t)), Via: &v}, Key: generate(t), InstanceID: instance}
		if err := c.Check(); err == nil {
			t.Errorf("%s: the client passed its check", name)
		}
	}
	if err := (server.Via{URL: "https://gateway.example:8443"}).Check(); err != nil {
		t.Errorf("an https origin: %v", err)
	}
	c, err := server.Read("fixtures/server/via.yaml", fixture(t, "fixtures/server/via.yaml"))
	if err != nil || c.Via == nil || c.Via.URL != "https://gateway.example:8443" || c.Via.CAFile == "" || c.Via.CertificateSHA256 == "" || c.URL != "https://qory.example" {
		t.Errorf("via.yaml read as %+v, %v", c, err)
	}
	for _, f := range []string{"fixtures/invalid/server-via-http.yaml", "fixtures/invalid/server-via-path.yaml", "fixtures/invalid/server-via-pin-hex.yaml", "fixtures/invalid/server-via-no-url.yaml"} {
		if _, err := server.Read(f, fixture(t, f)); err == nil {
			t.Errorf("%s: read", f)
		}
	}
}

// TestPostViaEnrolsThroughTheGateway pins accesskey's PostVia with via's transport: the
// enrolment goes to via.url's origin at /.well-known/qory-enrolment, its answer verifies
// under the server's key as without the gateway; a via URL that is not https, and a nil
// client, which would carry none of the gateway's trust, are refused before anything is
// sent.
func TestPostViaEnrolsThroughTheGateway(t *testing.T) {
	signer := generate(t)
	var paths []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.RequestURI)
		b, _ := io.ReadAll(r.Body)
		var req accesskey.EnrolmentRequest
		if json.Unmarshal(b, &req) != nil || !req.VerifyProof() {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body := []byte(`{"version":1,"access_key_id":"ak_f1xt0re000000000","node_id":"np_f1xt0re000000000","node_kind":"pool","stored_secrets":false,"apiary_public_key":[{"alg":"ed25519","public_key":"` + signer.PublicKey().String() + `"}]}`)
		w.Header().Set(accesskey.HeaderSignature, signer.SignAnswer(accesskey.Answer{Enrolment: true, Status: 201, RequestSignature: req.Proof, Body: body}))
		w.WriteHeader(http.StatusCreated)
		w.Write(body)
	}))
	defer srv.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tr, err := server.Via{URL: srv.URL, CAFile: caFile}.Transport()
	if err != nil {
		t.Fatal(err)
	}
	r, err := accesskey.NewEnrolmentRequest(generate(t), "qecp_F1XT0RE0000000000000000000."+signer.Fingerprint(), "build-01", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ans, err := r.PostVia(context.Background(), &http.Client{Transport: tr}, "https://qory.example", srv.URL, "qory/test")
	if err != nil || ans.NodeID != "np_f1xt0re000000000" || len(ans.Pin) != 1 {
		t.Fatalf("enrolment through via: %+v, %v", ans, err)
	}
	if len(paths) != 1 || paths[0] != accesskey.EnrolmentPath {
		t.Errorf("targets %q", paths)
	}
	if _, err := r.PostVia(context.Background(), &http.Client{Transport: tr}, "https://qory.example", "http://127.0.0.1:1", "qory/test"); err == nil || len(paths) != 1 {
		t.Errorf("an http via: %v", err)
	}
	if _, err := r.PostVia(context.Background(), nil, "https://qory.example", srv.URL, "qory/test"); err == nil || len(paths) != 1 {
		t.Errorf("a nil client: %v; want it refused before anything is sent", err)
	}
}
