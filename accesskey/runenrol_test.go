package accesskey_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/runkey"
)

// testRunID is the run of the tests' run keys.
const testRunID = "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d"

// newKey returns a test key from the system's random source.
func newKey(t *testing.T) *accesskey.Key {
	t.Helper()
	k, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// testRunKey returns a run key for runID signed under signer.
func testRunKey(t *testing.T, signer *accesskey.Key, runID string) string {
	t.Helper()
	issued := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	s, err := runkey.Key{
		RunID: runID, Workspace: "ws_f1xt0re000000000", NodeID: "np_f1xt0re000000000", Gateway: "ng_f1xt0re000000000",
		InstanceID: runID, GatewayURL: "https://gateway.example:8443", GatewayKeys: []accesskey.PublicKey{newKey(t).PublicKey()},
		Issued: issued, AttachBy: issued.Add(600 * time.Second),
	}.Sign(signer)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// runAnswerBody returns a run answer's body with the run's id, its run key and the
// server keys listed.
func runAnswerBody(runID, runKey string, listed ...*accesskey.Key) []byte {
	var keys []string
	for _, k := range listed {
		keys = append(keys, `{"alg":"ed25519","public_key":"`+k.PublicKey().String()+`"}`)
	}
	return []byte(`{"version":1,"run_id":"` + runID + `","run_key":"` + runKey + `","apiary_public_key":[` + strings.Join(keys, ",") + `]}`)
}

// runRequest returns a request with a run code whose fingerprint is signer's.
func runRequest(t *testing.T, signer *accesskey.Key) *accesskey.EnrolmentRequest {
	t.Helper()
	r, err := accesskey.NewEnrolmentRequest(newKey(t), "qecr_F1XT0RE0000000000000000000."+signer.Fingerprint(), "run-01", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// created returns a 201 to r with body, and its signature under signer.
func created(r *accesskey.EnrolmentRequest, signer *accesskey.Key, body []byte) (accesskey.Answer, string) {
	a := accesskey.Answer{Enrolment: true, Status: http.StatusCreated, RequestSignature: r.Proof, Body: body}
	return a, signer.SignAnswer(a)
}

// TestTheRunEnrolmentKnownAnswer pins the redemption of a run code in
// through-gateway.json: the fixture access key builds the request byte for byte, its
// proof is the vector's, the 201's six lines are the vector's and verify under the
// fixture signing key, and VerifyRunAnswer returns the run's id and run key.
func TestTheRunEnrolmentKnownAnswer(t *testing.T) {
	var v struct {
		RunEnrolment struct {
			Request    string   `json:"request"`
			ProofLines []string `json:"proof_lines"`
			Proof      string   `json:"proof"`
			Answer     string   `json:"answer"`
			Lines      []string `json:"lines"`
			Signature  string   `json:"signature"`
		} `json:"run_enrolment"`
	}
	load(t, "fixtures/known-answers/through-gateway.json", &v)
	e := v.RunEnrolment
	k := keys(t)
	r, err := accesskey.NewEnrolmentRequest(k.accessKey(t), e.ProofLines[1], e.ProofLines[3], time.Unix(1791720000, 0))
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if want := bytes.TrimSpace(read(t, e.Request)); !bytes.Equal(got, want) {
		t.Errorf("the request is\n%s\nwant\n%s", got, want)
	}
	if r.Proof != e.Proof || string(r.ProofMessage()) != strings.Join(e.ProofLines, "\n") {
		t.Errorf("the proof differs from the vector's")
	}
	a := accesskey.Answer{Status: http.StatusCreated, Body: read(t, e.Answer)}
	signed := a
	signed.Enrolment, signed.RequestSignature = true, r.Proof
	if string(signed.Message()) != strings.Join(e.Lines, "\n") {
		t.Errorf("the answer's lines differ from the vector's")
	}
	ans, err := r.VerifyRunAnswer(a, e.Signature)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		RunKey string `json:"run_key"`
	}
	load(t, e.Answer, &body)
	if ans.RunID != testRunID || ans.RunKey != body.RunKey || len(ans.Pin) != 1 || ans.Pin[0].PublicKey != k.SigningKey.PublicKey {
		t.Errorf("verified %s, pin %v", ans, ans.Pin)
	}
}

// fakeServer is an enrolment endpoint that answers every request with status and
// body, signed under signer when signer is not nil, and counts the requests.
type fakeServer struct {
	status   int
	body     func(req accesskey.EnrolmentRequest) []byte
	signer   *accesskey.Key
	requests int
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests++
	b, _ := io.ReadAll(r.Body)
	var req accesskey.EnrolmentRequest
	if r.URL.Path != accesskey.EnrolmentPath || json.Unmarshal(b, &req) != nil || !req.VerifyProof() {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	body := f.body(req)
	if f.signer != nil {
		w.Header().Set(accesskey.HeaderSignature, f.signer.SignAnswer(accesskey.Answer{Enrolment: true, Status: f.status, RequestSignature: req.Proof, Body: body}))
	}
	w.WriteHeader(f.status)
	w.Write(body)
}

// TestPostRunRedeemsARunCode posts a run code to a fake server that signs a run answer
// under a test key: the client returns the run's id and its run key, its pin the
// test key, and a retry by the same key gets the same run key.
func TestPostRunRedeemsARunCode(t *testing.T) {
	signer := newKey(t)
	rk := testRunKey(t, signer, testRunID)
	f := &fakeServer{status: http.StatusCreated, signer: signer, body: func(accesskey.EnrolmentRequest) []byte { return runAnswerBody(testRunID, rk, signer) }}
	srv := httptest.NewServer(f)
	defer srv.Close()
	r := runRequest(t, signer)
	for range 2 {
		ans, err := r.PostRun(context.Background(), nil, srv.URL, "qory/test")
		if err != nil {
			t.Fatal(err)
		}
		if ans.RunID != testRunID || ans.RunKey != rk || len(ans.Pin) != 1 || ans.Pin[0].PublicKey != signer.PublicKey().String() {
			t.Errorf("redeemed %s, pin %v", ans, ans.Pin)
		}
	}
	if f.requests != 2 {
		t.Errorf("%d requests; want 2", f.requests)
	}
}

// TestRunAnswerFailures pins each refusal of a run code's answer: a wrong signature and
// an unsigned 201 are answer_unsigned; a signed answer of an access key to a run code is
// a *KindError; a run key for another run, a run key signed by a key the code does not
// carry, a run key whose signature another key made, a run_id that is no UUID and a
// later version and a missing run_key are errors that start with the fix; a 401 is unauthorized; a signed 409
// and 429 are their refusals. No error contains the run key.
func TestRunAnswerFailures(t *testing.T) {
	signer, other := newKey(t), newKey(t)
	r := runRequest(t, signer)
	rk := testRunKey(t, signer, testRunID)
	// forged is a run key whose payload's signer is signer, with a signature that other
	// made over the same message.
	payload := rk[len(runkey.Prefix):strings.LastIndexByte(rk, '.')]
	p, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	forged := runkey.Prefix + payload + "." + base64.RawURLEncoding.EncodeToString(other.Sign(append([]byte(runkey.Domain+"\n"), p...)))
	keys := `"apiary_public_key":[{"alg":"ed25519","public_key":"` + signer.PublicKey().String() + `"}]`
	for _, c := range []struct {
		name   string
		status int
		body   []byte
		sign   *accesskey.Key
		want   string
	}{
		{"a wrong signature", 201, runAnswerBody(testRunID, rk, signer), other, accesskey.CodeAnswerUnsigned},
		{"no signature", 201, runAnswerBody(testRunID, rk, signer), nil, accesskey.CodeAnswerUnsigned},
		{"an access key's answer", 201, bytes.TrimSpace(append([]byte(`{"version":1,"access_key_id":"ak_f1xt0re000000000","node_id":"nd_f1xt0re000000000","node_kind":"node","stored_secrets":false,`), keys+`}`...)), signer,
			`use another run code: the server's 201 to the run code enrols an access key of node_kind "node" and contains no run key; the code is used`},
		{"a run key for another run", 201, runAnswerBody(testRunID, testRunKey(t, signer, "0192f0c1-7d4e-7a2b-8c3d-000000000000"), signer), signer,
			"use another run code: the enrolment answer's run key is for run 0192f0c1-7d4e-7a2b-8c3d-000000000000, and its run_id is " + testRunID},
		{"a run key signed by another key", 201, runAnswerBody(testRunID, testRunKey(t, other, testRunID), signer), signer,
			"use another run code: the enrolment answer's run key is not valid: it is signed by a server key this side does not pin"},
		{"a run key whose signature another key made", 201, runAnswerBody(testRunID, forged, signer), signer,
			"use another run code: the enrolment answer's run key is not valid: its signature does not verify"},
		{"a run_id in upper case", 201, runAnswerBody(strings.ToUpper(testRunID), rk, signer), signer,
			`use another run code: the enrolment answer's run_id "0192F0C1-7D4E-7A2B-8C3D-4E5F6A7B8C9D" is not a UUID in lower case`},
		{"a run_key of another form", 201, runAnswerBody(testRunID, "qrk_"+payload, signer), signer,
			"use another run code: the enrolment answer's run_key is not qrk_ and two parts of base64url joined by a dot, at most 2048 characters"},
		{"version 2", 201, bytes.Replace(runAnswerBody(testRunID, rk, signer), []byte(`"version":1`), []byte(`"version":2`), 1), signer,
			"update Forager to read the enrolment answer: its version is 2, and this Forager reads version 1"},
		{"a member the schema does not define", 201, bytes.Replace(runAnswerBody(testRunID, rk, signer), []byte(`"version":1,`), []byte(`"version":1,"access_key_id":"ak_f1xt0re000000000",`), 1), signer, accesskey.CodeAnswerUnsigned},
		{"no run_key", 201, []byte(`{"version":1,"run_id":"` + testRunID + `",` + keys + `}`), signer, "use another run code: the enrolment answer has no run_key"},
		{"a 401", 401, []byte(`{"error":"unauthorized"}`), nil, accesskey.CodeUnauthorized},
		{"a signed 409", 409, []byte(`{"error":"key_invalid",` + keys + `}`), signer, accesskey.CodeKeyInvalid},
		{"a signed 429", 429, []byte(`{"error":"rate_limited",` + keys + `}`), signer, accesskey.CodeRateLimited},
	} {
		f := &fakeServer{status: c.status, signer: c.sign, body: func(accesskey.EnrolmentRequest) []byte { return c.body }}
		srv := httptest.NewServer(f)
		ans, err := r.PostRun(context.Background(), nil, srv.URL, "qory/test")
		srv.Close()
		if ans != nil || code(err) != c.want {
			t.Errorf("%s: %v, %v; want %s", c.name, ans, err, c.want)
		}
		if err != nil && (strings.Contains(err.Error(), rk) || strings.Contains(err.Error(), payload)) {
			t.Errorf("%s: the error contains the run key", c.name)
		}
	}
	// A node answer to a run code is a *KindError with the answer's ids.
	a, sig := created(r, signer, []byte(`{"version":1,"access_key_id":"ak_f1xt0re000000000","node_id":"nd_f1xt0re000000000","node_kind":"node","stored_secrets":false,`+keys+`}`))
	var ke *accesskey.KindError
	if _, err := r.VerifyRunAnswer(a, sig); !errors.As(err, &ke) || ke.Kind != "node" || ke.AccessKeyID != "ak_f1xt0re000000000" || ke.NodeID != "nd_f1xt0re000000000" {
		t.Errorf("an access key's answer to a run code: %v", err)
	}
}

// TestARunAnswerToAnAccessKeysCode pins the reverse: a signed run answer to an access
// key's code is a *KindError with the run's id, and its text starts with the fix and
// contains no run key.
func TestARunAnswerToAnAccessKeysCode(t *testing.T) {
	signer := newKey(t)
	rk := testRunKey(t, signer, testRunID)
	r, err := accesskey.NewEnrolmentRequest(newKey(t), "qecn_F1XT0RE0000000000000000000."+signer.Fingerprint(), "build-01", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ans, err := r.VerifyAnswer(created(r, signer, runAnswerBody(testRunID, rk, signer)))
	var ke *accesskey.KindError
	if ans != nil || !errors.As(err, &ke) || ke.Kind != "run" || ke.RunID != testRunID {
		t.Fatalf("a run answer to a node's code: %v, %v; want a *KindError", ans, err)
	}
	if want := `use another enrolment code: the server's 201 to the code of node_kind "node" contains a run's run key and no access key id; the code is used`; err.Error() != want {
		t.Errorf("%q; want %q", err, want)
	}
	// Unsigned, the same body is answer_unsigned.
	a, _ := created(r, signer, runAnswerBody(testRunID, rk, signer))
	if _, err := r.VerifyAnswer(a, ""); code(err) != accesskey.CodeAnswerUnsigned {
		t.Errorf("an unsigned run answer: %v", err)
	}
}

// TestEachMethodReadsOneKindOfCode pins that the access key's methods refuse a run
// code and the run code's methods refuse an access key's code, each with an error that
// starts with the method to use, and that neither sends anything.
func TestEachMethodReadsOneKindOfCode(t *testing.T) {
	signer := newKey(t)
	f := &fakeServer{status: http.StatusCreated, signer: signer, body: func(accesskey.EnrolmentRequest) []byte { return nil }}
	srv := httptest.NewServer(f)
	defer srv.Close()
	ctx := context.Background()
	run := runRequest(t, signer)
	const toRun = "redeem a run code with PostRunVia, PostRun or VerifyRunAnswer: the request's code is a run code, qecr_, and PostVia, Post and VerifyAnswer enrol an access key"
	for name, call := range map[string]func() error{
		"VerifyAnswer": func() error { _, err := run.VerifyAnswer(created(run, signer, nil)); return err },
		"Post":         func() error { _, err := run.Post(ctx, nil, srv.URL, "qory/test"); return err },
		"PostVia": func() error {
			_, err := run.PostVia(ctx, srv.Client(), srv.URL, "https://gateway.example", "qory/test")
			return err
		},
	} {
		if err := call(); err == nil || err.Error() != toRun {
			t.Errorf("%s with a run code: %v; want %q", name, err, toRun)
		}
	}
	for prefix, kind := range map[string]string{accesskey.CodePrefixNode: "node", accesskey.CodePrefixPool: "pool", accesskey.CodePrefixGateway: "gateway", accesskey.CodePrefixAdapter: "adapter"} {
		r, err := accesskey.NewEnrolmentRequest(newKey(t), prefix+"F1XT0RE0000000000000000000."+signer.Fingerprint(), "build-01", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("enrol an access key with PostVia, Post or VerifyAnswer: the request's code enrols an access key of node_kind %q, and PostRunVia, PostRun and VerifyRunAnswer redeem a run code", kind)
		for name, call := range map[string]func() error{
			"VerifyRunAnswer": func() error { _, err := r.VerifyRunAnswer(created(r, signer, nil)); return err },
			"PostRun":         func() error { _, err := r.PostRun(ctx, nil, srv.URL, "qory/test"); return err },
			"PostRunVia": func() error {
				_, err := r.PostRunVia(ctx, srv.Client(), srv.URL, "https://gateway.example", "qory/test")
				return err
			},
		} {
			if err := call(); err == nil || err.Error() != want {
				t.Errorf("%s with a %s code: %v; want %q", name, kind, err, want)
			}
		}
	}
	if f.requests != 0 {
		t.Errorf("%d requests sent; want none", f.requests)
	}
}

// TestARunAnswerShowsItsRunIDAlone pins that a RunAnswer, by value and by pointer,
// prints its run id and never its run key: under every fmt verb, through slog's text
// and JSON handlers, and inside a struct slog logs.
func TestARunAnswerShowsItsRunIDAlone(t *testing.T) {
	signer := newKey(t)
	rk := testRunKey(t, signer, testRunID)
	r := runRequest(t, signer)
	ans, err := r.VerifyRunAnswer(created(r, signer, runAnswerBody(testRunID, rk, signer)))
	if err != nil {
		t.Fatal(err)
	}
	secret := rk[len(runkey.Prefix):]
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		for _, v := range []any{ans, *ans} {
			got := fmt.Sprintf(verb, v)
			if strings.Contains(got, secret) || strings.Contains(got, runkey.Prefix) || !strings.Contains(got, testRunID) {
				t.Errorf("%s of %T: %s", verb, v, got)
			}
		}
	}
	if got := ans.String(); got != "run "+testRunID {
		t.Errorf("String: %q", got)
	}
	if got := ans.GoString(); got != "run "+testRunID {
		t.Errorf("GoString: %q", got)
	}
	var b bytes.Buffer
	for _, h := range []slog.Handler{slog.NewTextHandler(&b, nil), slog.NewJSONHandler(&b, nil)} {
		slog.New(h).Info("redeemed", "answer", ans, "value", *ans)
	}
	if got := b.String(); strings.Contains(got, secret) || strings.Contains(got, runkey.Prefix) || strings.Count(got, "run_id="+testRunID) != 2 || strings.Count(got, `"run_id":"`+testRunID+`"`) != 2 {
		t.Errorf("slog wrote %s", got)
	}
	if v := ans.LogValue(); v.Kind() != slog.KindGroup || len(v.Group()) != 1 || v.Group()[0].Key != "run_id" || v.Group()[0].Value.String() != testRunID {
		t.Errorf("LogValue: %v", v)
	}
}
