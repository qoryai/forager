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
	"slices"
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

// testDocuments are the step and the run's documents of the tests' run answers: the
// step explore, with the members it requires.
const testDocuments = `"step":"explore","domain":"software",` +
	`"work_item":{"id":"wi_f1xt0re0","url":"https://qory.example/work/wi_f1xt0re0","title":"Add a health check"},` +
	`"inputs":{"version":1}`

// runAnswerBody returns a run answer's body with the run's id, its run key,
// testDocuments and the server keys listed.
func runAnswerBody(runID, runKey string, listed ...*accesskey.Key) []byte {
	return runAnswerWith(runID, runKey, testDocuments, listed...)
}

// runAnswerWith returns a run answer's body with the run's id, its run key, the members
// in documents, written as the inside of a JSON object, and the server keys listed.
func runAnswerWith(runID, runKey, documents string, listed ...*accesskey.Key) []byte {
	var keys []string
	for _, k := range listed {
		keys = append(keys, `{"alg":"ed25519","public_key":"`+k.PublicKey().String()+`"}`)
	}
	return []byte(`{"version":1,"run_id":"` + runID + `","run_key":"` + runKey + `",` + documents + `,"apiary_public_key":[` + strings.Join(keys, ",") + `]}`)
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
// fixture signing key, and VerifyRunAnswer returns the run's id, run key, step and the
// eight documents as the answer contains them.
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
	var body map[string]json.RawMessage
	load(t, e.Answer, &body)
	var runKey, step string
	if json.Unmarshal(body["run_key"], &runKey) != nil || json.Unmarshal(body["step"], &step) != nil {
		t.Fatalf("%s has no run_key or step", e.Answer)
	}
	if ans.RunID != testRunID || ans.RunKey != runKey || ans.Step != step || len(ans.Pin) != 1 || ans.Pin[0].PublicKey != k.SigningKey.PublicKey {
		t.Errorf("verified %s, step %q, pin %v", ans, ans.Step, ans.Pin)
	}
	// Each document is the answer's member byte for byte, and the known answer has all
	// eight.
	for name, got := range map[string]json.RawMessage{
		"domain": ans.Domain, "access": ans.Access, "target": ans.Target, "work_item": ans.WorkItem,
		"run_settings": ans.RunSettings, "inputs": ans.Inputs, "stack": ans.Stack, "workflow": ans.Workflow,
	} {
		if want, ok := body[name]; !ok || !bytes.Equal(got, want) {
			t.Errorf("%s is %s; want %s", name, got, want)
		}
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
// under a test key: the client returns the run's id and its run key, its pin the test
// key, and the same request sent again gets the same run key.
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

// TestARetryWithAnotherProofGetsTheSameMembers pins a retry by the same key with
// another request: a timestamp one second later, so another proof. The server signs
// the same members over each request's proof, and the client returns the same run id,
// run key and pin for both. The first answer's signature does not verify for the
// second request, since line 3 of the signed lines is the request's proof.
func TestARetryWithAnotherProofGetsTheSameMembers(t *testing.T) {
	signer, key := newKey(t), newKey(t)
	rk := testRunKey(t, signer, testRunID)
	f := &fakeServer{status: http.StatusCreated, signer: signer, body: func(accesskey.EnrolmentRequest) []byte { return runAnswerBody(testRunID, rk, signer) }}
	srv := httptest.NewServer(f)
	defer srv.Close()
	runCode := "qecr_F1XT0RE0000000000000000000." + signer.Fingerprint()
	now := time.Now()
	first, err := accesskey.NewEnrolmentRequest(key, runCode, "run-01", now)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := accesskey.NewEnrolmentRequest(key, runCode, "run-01", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if first.PublicKey != retry.PublicKey || first.Proof == retry.Proof {
		t.Fatal("the retry is not the same key with another proof")
	}
	a, err := first.PostRun(context.Background(), nil, srv.URL, "qory/test")
	if err != nil {
		t.Fatal(err)
	}
	b, err := retry.PostRun(context.Background(), nil, srv.URL, "qory/test")
	if err != nil {
		t.Fatal(err)
	}
	if a.RunID != b.RunID || a.RunKey != b.RunKey || !slices.Equal(a.ApiaryPublicKey, b.ApiaryPublicKey) || !slices.Equal(a.Pin, b.Pin) {
		t.Errorf("the retry got %s, pin %v; the first %s, pin %v", b, b.Pin, a, a.Pin)
	}
	answer, sig := created(first, signer, runAnswerBody(testRunID, rk, signer))
	if _, err := retry.VerifyRunAnswer(answer, sig); code(err) != accesskey.CodeAnswerUnsigned {
		t.Errorf("the first answer's signature for the retry: %v; want answer_unsigned", err)
	}
}

// TestRunAnswerFailures pins each refusal of a run code's answer, one case each:
//   - answer_unsigned: a wrong signature, an unsigned 201, a member the schema does not
//     define, and an apiary_public_key with no key, since no listed key has the code's
//     first fingerprint;
//   - a *KindError: a signed answer of an access key to a run code;
//   - an error that starts with the fix: a run key for another run; a run key signed by
//     a key that is not listed; a run key signed by a key that the answer lists and
//     whose fingerprint is not in the code; a run key whose signature another key made;
//     a run_id in upper case; a run_key of another form; a run_key over 2048
//     characters; an apiary_public_key with 3 keys; version 2; a missing run_key;
//   - a 401 is unauthorized, and a signed 409 and 429 are their refusals.
//
// No error contains the run key.
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
	long := runkey.Prefix + strings.Repeat("A", 2040) + "." + strings.Repeat("A", 10)
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
		{"a run key signed by a key listed but not in the code", 201, runAnswerBody(testRunID, testRunKey(t, other, testRunID), signer, other), signer,
			"use another run code: the enrolment answer's run key is not valid: it is signed by a server key this side does not pin"},
		{"a run key whose signature another key made", 201, runAnswerBody(testRunID, forged, signer), signer,
			"use another run code: the enrolment answer's run key is not valid: its signature does not verify"},
		{"a run_id in upper case", 201, runAnswerBody(strings.ToUpper(testRunID), rk, signer), signer,
			`use another run code: the enrolment answer's run_id "0192F0C1-7D4E-7A2B-8C3D-4E5F6A7B8C9D" is not a UUID in lower case`},
		{"a run_key of another form", 201, runAnswerBody(testRunID, "qrk_"+payload, signer), signer,
			"use another run code: the enrolment answer's run_key is not qrk_ and two parts of base64url joined by a dot, at most 2048 characters"},
		{"a run_key over 2048 characters", 201, runAnswerBody(testRunID, long, signer), signer,
			"use another run code: the enrolment answer's run_key is not qrk_ and two parts of base64url joined by a dot, at most 2048 characters"},
		{"no key listed", 201, []byte(`{"version":1,"run_id":"` + testRunID + `","run_key":"` + rk + `","apiary_public_key":[]}`), signer, accesskey.CodeAnswerUnsigned},
		{"three keys listed", 201, runAnswerBody(testRunID, rk, signer, other, newKey(t)), signer,
			"use another run code: the enrolment answer's apiary_public_key lists 3 keys; one or two belong"},
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
// prints its run id and never its run key or a value of its documents: under every fmt
// verb, through slog's text and JSON handlers, through encoding/json, and in an
// exported field of a struct, in a slice and in a map under the JSON handler. It also
// pins the one open case: in a struct field that is not exported, fmt and slog's text
// handler print the run key, and the documents as their bytes in decimal.
func TestARunAnswerShowsItsRunIDAlone(t *testing.T) {
	signer := newKey(t)
	rk := testRunKey(t, signer, testRunID)
	r := runRequest(t, signer)
	ans, err := r.VerifyRunAnswer(created(r, signer, runAnswerBody(testRunID, rk, signer)))
	if err != nil {
		t.Fatal(err)
	}
	secret := rk[len(runkey.Prefix):]
	// domainBytes is the domain document as fmt prints a json.RawMessage, its bytes in
	// decimal.
	domainBytes := strings.Trim(fmt.Sprint([]byte(`"software"`)), "[]")
	// leaks reports whether s contains the run key or a value of the answer's
	// documents, as text or as bytes in decimal.
	leaks := func(s string) bool {
		return strings.Contains(s, secret) || strings.Contains(s, "wi_f1xt0re0") || strings.Contains(s, "health check") ||
			strings.Contains(s, "software") || strings.Contains(s, domainBytes)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		for _, v := range []any{ans, *ans} {
			got := fmt.Sprintf(verb, v)
			if leaks(got) || strings.Contains(got, runkey.Prefix) || !strings.Contains(got, testRunID) {
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
	if got := b.String(); leaks(got) || strings.Contains(got, runkey.Prefix) || strings.Count(got, "run_id="+testRunID) != 2 || strings.Count(got, `"run_id":"`+testRunID+`"`) != 2 {
		t.Errorf("slog wrote %s", got)
	}
	if v := ans.LogValue(); v.Kind() != slog.KindGroup || len(v.Group()) != 1 || v.Group()[0].Key != "run_id" || v.Group()[0].Value.String() != testRunID {
		t.Errorf("LogValue: %v", v)
	}
	// encoding/json writes run_id alone, by value, by pointer, in an exported field of
	// a struct, in a slice and in a map, and so does slog's JSON handler, which encodes
	// a struct, a slice and a map with encoding/json.
	type nested struct {
		Answer  accesskey.RunAnswer
		Pointer *accesskey.RunAnswer
	}
	want := `{"run_id":"` + testRunID + `"}`
	for _, c := range []struct {
		v    any
		want string
	}{
		{*ans, want},
		{ans, want},
		{nested{*ans, ans}, `{"Answer":` + want + `,"Pointer":` + want + `}`},
		{[]accesskey.RunAnswer{*ans, *ans}, "[" + want + "," + want + "]"},
		{map[string]*accesskey.RunAnswer{"a": ans}, `{"a":` + want + `}`},
	} {
		got, err := json.Marshal(c.v)
		if err != nil || string(got) != c.want {
			t.Errorf("json.Marshal of %T: %s, %v; want %s", c.v, got, err, c.want)
		}
		if got := fmt.Sprintf("%+v", c.v); leaks(got) {
			t.Errorf("%%+v of %T: %s", c.v, got)
		}
	}
	// The open case, which RunAnswer's doc describes: fmt calls no method of a value it
	// reaches through a struct field that is not exported, so fmt and slog's text
	// handler print the run key and the documents' bytes there, and the JSON handler
	// writes {} for the field. A change to that behaviour fails here, so the doc is
	// updated with it.
	type hidden struct{ a any }
	if got := fmt.Sprintf("%+v", hidden{*ans}); !strings.Contains(got, secret) || !strings.Contains(got, domainBytes) {
		t.Errorf("%%+v of a RunAnswer in a field that is not exported: %s; RunAnswer's doc describes the run key and the documents' bytes there", got)
	}
	b.Reset()
	slog.New(slog.NewTextHandler(&b, nil)).Info("redeemed", "hidden", hidden{*ans})
	if got := b.String(); !strings.Contains(got, secret) || !strings.Contains(got, domainBytes) {
		t.Errorf("slog's text handler with a RunAnswer in a field that is not exported wrote %s; RunAnswer's doc describes the run key and the documents' bytes there", got)
	}
	b.Reset()
	slog.New(slog.NewJSONHandler(&b, nil)).Info("redeemed", "hidden", hidden{*ans})
	if got := b.String(); leaks(got) || !strings.Contains(got, `"hidden":{}`) {
		t.Errorf("slog's JSON handler with a RunAnswer in a field that is not exported wrote %s", got)
	}
	b.Reset()
	slog.New(slog.NewJSONHandler(&b, nil)).Info("redeemed", "nested", nested{*ans, ans}, "slice", []accesskey.RunAnswer{*ans}, "map", map[string]accesskey.RunAnswer{"a": *ans})
	if got := b.String(); leaks(got) || strings.Contains(got, runkey.Prefix) || strings.Count(got, `"run_id":"`+testRunID+`"`) != 4 {
		t.Errorf("slog's JSON handler wrote %s", got)
	}
}

// prebuildDocuments are the step and the run's documents of a run of the step prebuild:
// a target with its access, and inputs of exactly version and environment_ref.
const prebuildDocuments = `"step":"prebuild","domain":"software","access":"read",` +
	`"target":{"system":"git.example","path":"example/widgets"},"inputs":{"version":1,"environment_ref":"env-1"}`

// TestARunAnswerOfThePrebuildStep pins a run answer with the members the step prebuild
// requires: VerifyRunAnswer returns each document as the answer contains it, and nil
// for each member the answer leaves out.
func TestARunAnswerOfThePrebuildStep(t *testing.T) {
	signer := newKey(t)
	r := runRequest(t, signer)
	ans, err := r.VerifyRunAnswer(created(r, signer, runAnswerWith(testRunID, testRunKey(t, signer, testRunID), prebuildDocuments, signer)))
	if err != nil {
		t.Fatal(err)
	}
	if ans.Step != "prebuild" || string(ans.Domain) != `"software"` || string(ans.Access) != `"read"` ||
		string(ans.Target) != `{"system":"git.example","path":"example/widgets"}` || string(ans.Inputs) != `{"version":1,"environment_ref":"env-1"}` {
		t.Errorf("step %q, domain %s, access %s, target %s, inputs %s", ans.Step, ans.Domain, ans.Access, ans.Target, ans.Inputs)
	}
	if ans.WorkItem != nil || ans.RunSettings != nil || ans.Stack != nil || ans.Workflow != nil {
		t.Errorf("work_item %s, run_settings %s, stack %s, workflow %s; want each nil", ans.WorkItem, ans.RunSettings, ans.Stack, ans.Workflow)
	}
}

// TestRunAnswerDocumentRules pins each rule of step and the run's documents in
// $defs/run_answer, one case each, with an error that starts with the fix and states
// where the failure is and which rule failed: a missing step, domain or inputs; the
// step explore without work_item; the step prebuild without access and target, with
// work_item, with run_settings, and with inputs of another member or without
// environment_ref; target without access and access without target; stack without
// workflow and workflow without stack; run_settings with effort, tiers or model alone,
// and provider_models without model; a member of another type, a null, a value outside
// its pattern or its length, and an unknown member inside a document. An unknown member
// of the answer and a member twice inside a document are answer_unsigned, as for every
// run answer. No error contains a value of a document.
func TestRunAnswerDocumentRules(t *testing.T) {
	signer := newKey(t)
	r := runRequest(t, signer)
	rk := testRunKey(t, signer, testRunID)
	const (
		workItem = `"work_item":{"id":"wi_f1xt0re0","url":"https://qory.example/work/wi_f1xt0re0","title":"Add a health check"}`
		explore  = `"step":"explore","domain":"software",` + workItem + `,"inputs":{"version":1}`
		target   = `"target":{"system":"git.example","path":"example/widgets"}`
		stack    = `"stack":{"url":"https://stacks.example/hello.git","commit":"0123456789abcdef0123456789abcdef01234567","path":"stacks/hello"}`
		fix      = "use another run code: the enrolment answer does not match $defs/run_answer of enrolment.schema.json at "
	)
	for _, c := range []struct{ name, documents, want string }{
		{"no step", `"domain":"software","inputs":{"version":1}`, fix + "/ (required: step)"},
		{"no domain", `"step":"explore",` + workItem + `,"inputs":{"version":1}`, fix + "/ (required: domain)"},
		{"no inputs", `"step":"explore","domain":"software",` + workItem, fix + "/ (required: inputs)"},
		{"explore without work_item", `"step":"explore","domain":"software","inputs":{"version":1}`, fix + "/ (required: work_item)"},
		{"prebuild without access and target", `"step":"prebuild","domain":"software","inputs":{"version":1,"environment_ref":"env-1"}`, fix + "/ (required: access, target)"},
		{"prebuild with work_item", prebuildDocuments + "," + workItem, fix + "/ (not)"},
		{"prebuild with run_settings", prebuildDocuments + `,"run_settings":{"runtime":"claude"}`, fix + "/step (const)"},
		{"prebuild inputs with another member", strings.Replace(prebuildDocuments, `"environment_ref":"env-1"`, `"environment_ref":"env-1","extra":1`, 1), fix + "/inputs (additionalProperties)"},
		{"prebuild inputs without environment_ref", strings.Replace(prebuildDocuments, `,"environment_ref":"env-1"`, ``, 1), fix + "/inputs (required: environment_ref)"},
		{"target without access", explore + "," + target, fix + "/ (dependentRequired: access with target)"},
		{"access without target", explore + `,"access":"write"`, fix + "/ (dependentRequired: target with access)"},
		{"stack without workflow", explore + "," + stack, fix + "/ (dependentRequired: workflow with stack)"},
		{"workflow without stack", explore + `,"workflow":"hello"`, fix + "/ (dependentRequired: stack with workflow)"},
		{"effort without model", explore + `,"run_settings":{"runtime":"claude","effort":"high"}`, fix + "/run_settings (dependentRequired: model with effort)"},
		{"tiers without model", explore + `,"run_settings":{"runtime":"claude","tiers":{"light":"example-model-1"}}`, fix + "/run_settings (dependentRequired: model with tiers)"},
		{"model without provider_models", explore + `,"run_settings":{"runtime":"claude","model":"example-model-1"}`, fix + "/run_settings (dependentRequired: provider_models with model)"},
		{"provider_models without model", explore + `,"run_settings":{"runtime":"claude","provider_models":[{"id":"example-model-1"}]}`, fix + "/run_settings (dependentRequired: model with provider_models)"},
		{"run_settings without runtime", explore + `,"run_settings":{}`, fix + "/run_settings (required: runtime)"},
		{"a domain that is a number", strings.Replace(explore, `"domain":"software"`, `"domain":7`, 1), fix + "/domain (type)"},
		{"a null target", explore + `,"access":"write","target":null`, fix + "/target (type)"},
		{"an access of another value", explore + `,"access":"admin",` + target, fix + "/access (enum)"},
		{"a step in upper case", strings.Replace(explore, `"step":"explore"`, `"step":"Explore"`, 1), fix + "/step (pattern)"},
		{"a work item title of 1025 characters", strings.Replace(explore, "Add a health check", strings.Repeat("x", 1025), 1), fix + "/work_item/title (maxLength)"},
		{"a stack url with a query", explore + "," + strings.Replace(stack, "hello.git", "hello.git?ref=main", 1) + `,"workflow":"hello"`, fix + "/stack/url (pattern)"},
		{"a stack path with a .. segment", explore + "," + strings.Replace(stack, "stacks/hello", "stacks/../hello", 1) + `,"workflow":"hello"`, fix + "/stack/path (not)"},
		{"an unknown member in target", explore + `,"access":"write","target":{"system":"git.example","path":"example/widgets","branch":"main"}`, fix + "/target (additionalProperties)"},
		{"an unknown member of the answer", explore + `,"revision":3`, accesskey.CodeAnswerUnsigned},
		{"a member twice inside a document", explore + `,"access":"write","target":{"system":"git.example","system":"git.example","path":"example/widgets"}`, accesskey.CodeAnswerUnsigned},
	} {
		ans, err := r.VerifyRunAnswer(created(r, signer, runAnswerWith(testRunID, rk, c.documents, signer)))
		if ans != nil || code(err) != c.want {
			t.Errorf("%s: %v, %v; want %s", c.name, ans, err, c.want)
		}
		if err != nil && (strings.Contains(err.Error(), "health check") || strings.Contains(err.Error(), "git.example") || strings.Contains(err.Error(), "software")) {
			t.Errorf("%s: the error contains a value of a document: %v", c.name, err)
		}
	}
}

// padded returns a run answer of exactly n bytes: testDocuments with inputs padded by
// a member of x characters.
func padded(t *testing.T, rk string, signer *accesskey.Key, n int) []byte {
	t.Helper()
	docs := func(pad int) string {
		return strings.Replace(testDocuments, `"inputs":{"version":1}`, `"inputs":{"version":1,"pad":"`+strings.Repeat("x", pad)+`"}`, 1)
	}
	short := len(runAnswerWith(testRunID, rk, docs(0), signer))
	if n < short {
		t.Fatalf("a run answer of %d bytes is shorter than the %d bytes of its members", n, short)
	}
	b := runAnswerWith(testRunID, rk, docs(n-short), signer)
	if len(b) != n {
		t.Fatalf("padded to %d bytes; want %d", len(b), n)
	}
	return b
}

// TestARunAnswerUpTo1MiB pins the limits of the answer's body: PostRun reads a signed
// run answer of 200 KiB, more than an access key's answer may be, and one of exactly
// MaxRunAnswer, 1 MiB; one byte more is answer_unsigned, from PostRun, from PostRunVia
// and from VerifyRunAnswer. PostRunVia reads one of exactly MaxRunAnswer through a
// gateway. Post reads an access key's answer as before: a signed answer of 64 KiB
// passes, one of MaxAnswer+1 bytes passes too, since the client reads MaxAnswer and
// one byte more and VerifyAnswer checks no length, and one of 200 KiB is
// answer_unsigned.
func TestARunAnswerUpTo1MiB(t *testing.T) {
	if accesskey.MaxRunAnswer != 1<<20 || accesskey.MaxAnswer != 64<<10 {
		t.Fatalf("MaxRunAnswer %d, MaxAnswer %d; want 1 MiB and 64 KiB", accesskey.MaxRunAnswer, accesskey.MaxAnswer)
	}
	signer := newKey(t)
	rk := testRunKey(t, signer, testRunID)
	r := runRequest(t, signer)
	for _, c := range []struct {
		n    int
		want string
	}{
		{200 << 10, ""},
		{accesskey.MaxRunAnswer, ""},
		{accesskey.MaxRunAnswer + 1, accesskey.CodeAnswerUnsigned},
	} {
		body := padded(t, rk, signer, c.n)
		f := &fakeServer{status: http.StatusCreated, signer: signer, body: func(accesskey.EnrolmentRequest) []byte { return body }}
		srv := httptest.NewServer(f)
		ans, err := r.PostRun(context.Background(), nil, srv.URL, "qory/test")
		srv.Close()
		if c.want == "" && (err != nil || ans.RunKey != rk || len(ans.Inputs) < c.n/2) {
			t.Errorf("a run answer of %d bytes: %v, %v", c.n, ans, err)
		}
		if c.want != "" && (ans != nil || code(err) != c.want) {
			t.Errorf("a run answer of %d bytes: %v, %v; want %s", c.n, ans, err, c.want)
		}
	}
	if _, err := r.VerifyRunAnswer(created(r, signer, padded(t, rk, signer, accesskey.MaxRunAnswer+1))); code(err) != accesskey.CodeAnswerUnsigned {
		t.Errorf("VerifyRunAnswer of %d bytes: %v; want answer_unsigned", accesskey.MaxRunAnswer+1, err)
	}
	// Through a gateway: the TLS server stands in for the gateway's relay at viaURL.
	for _, c := range []struct {
		n    int
		want string
	}{
		{accesskey.MaxRunAnswer, ""},
		{accesskey.MaxRunAnswer + 1, accesskey.CodeAnswerUnsigned},
	} {
		body := padded(t, rk, signer, c.n)
		f := &fakeServer{status: http.StatusCreated, signer: signer, body: func(accesskey.EnrolmentRequest) []byte { return body }}
		srv := httptest.NewTLSServer(f)
		ans, err := r.PostRunVia(context.Background(), srv.Client(), "https://qory.example", srv.URL, "qory/test")
		srv.Close()
		if c.want == "" && (err != nil || ans.RunKey != rk || len(ans.Inputs) < c.n/2) {
			t.Errorf("a run answer of %d bytes through a gateway: %v, %v", c.n, ans, err)
		}
		if c.want != "" && (ans != nil || code(err) != c.want) {
			t.Errorf("a run answer of %d bytes through a gateway: %v, %v; want %s", c.n, ans, err, c.want)
		}
		if f.requests != 1 {
			t.Errorf("a run answer of %d bytes through a gateway: %d requests; want 1", c.n, f.requests)
		}
	}
	// An access key's answer, padded with spaces inside its object.
	key, err := accesskey.NewEnrolmentRequest(newKey(t), "qecn_F1XT0RE0000000000000000000."+signer.Fingerprint(), "build-01", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	answer := `{"version":1,"access_key_id":"ak_f1xt0re000000000","node_id":"nd_f1xt0re000000000","node_kind":"node","stored_secrets":false,` +
		`"apiary_public_key":[{"alg":"ed25519","public_key":"` + signer.PublicKey().String() + `"}]`
	for _, c := range []struct {
		n    int
		want string
	}{
		{accesskey.MaxAnswer, ""},
		{accesskey.MaxAnswer + 1, ""},
		{200 << 10, accesskey.CodeAnswerUnsigned},
	} {
		body := []byte(answer + strings.Repeat(" ", c.n-len(answer)-1) + "}")
		f := &fakeServer{status: http.StatusCreated, signer: signer, body: func(accesskey.EnrolmentRequest) []byte { return body }}
		srv := httptest.NewServer(f)
		ans, err := key.Post(context.Background(), nil, srv.URL, "qory/test")
		srv.Close()
		if (c.want == "" && (err != nil || ans.AccessKeyID != "ak_f1xt0re000000000")) || (c.want != "" && (ans != nil || code(err) != c.want)) {
			t.Errorf("an access key's answer of %d bytes: %v, %v; want %q", c.n, ans, err, c.want)
		}
	}
}
