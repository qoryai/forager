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

// testInput is the value in testDocuments that no output of a RunAnswer may contain.
const testInput = "f1xt0re-input-value"

// testDocuments are the run's documents of the tests' run answers: an object in
// neutral example data, which Forager reads as an object and no further.
const testDocuments = `{"inputs":{"text":"` + testInput + `"},"note":"an example"}`

// runAnswerBody returns a run answer's body with the run's id, its run key,
// testDocuments and the server keys listed.
func runAnswerBody(runID, runKey string, listed ...*accesskey.Key) []byte {
	return runAnswerWith(runID, runKey, testDocuments, listed...)
}

// runAnswerWith returns a run answer's body with the run's id, its run key, documents
// as the JSON of its documents member, and the server keys listed.
func runAnswerWith(runID, runKey, documents string, listed ...*accesskey.Key) []byte {
	var keys []string
	for _, k := range listed {
		keys = append(keys, `{"alg":"ed25519","public_key":"`+k.PublicKey().String()+`"}`)
	}
	return []byte(`{"version":1,"run_id":"` + runID + `","run_key":"` + runKey + `","documents":` + documents + `,"apiary_public_key":[` + strings.Join(keys, ",") + `]}`)
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
// fixture signing key, and VerifyRunAnswer returns the run's id, its run key and its
// documents byte for byte as the answer contains them.
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
	var runKey string
	if json.Unmarshal(body["run_key"], &runKey) != nil {
		t.Fatalf("%s has no run_key", e.Answer)
	}
	if ans.RunID != testRunID || ans.RunKey != runKey || len(ans.Pin) != 1 || ans.Pin[0].PublicKey != k.SigningKey.PublicKey {
		t.Errorf("verified %s, pin %v", ans, ans.Pin)
	}
	if want, ok := body["documents"]; !ok || !bytes.Equal(ans.Documents, want) {
		t.Errorf("documents are %s; want %s", ans.Documents, want)
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
// under a test key: the client returns the run's id, its run key and its documents, its
// pin the test key, and the same request sent again gets the same run key.
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
		if ans.RunID != testRunID || ans.RunKey != rk || string(ans.Documents) != testDocuments || len(ans.Pin) != 1 || ans.Pin[0].PublicKey != signer.PublicKey().String() {
			t.Errorf("redeemed %s, documents %s, pin %v", ans, ans.Documents, ans.Pin)
		}
	}
	if f.requests != 2 {
		t.Errorf("%d requests; want 2", f.requests)
	}
}

// TestARetryWithAnotherProofGetsTheSameMembers pins a retry by the same key with
// another request: a timestamp one second later, so another proof. The server signs
// the same members over each request's proof, and the client returns the same run id,
// run key, documents and pin for both. The first answer's signature does not verify for the
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
	if a.RunID != b.RunID || a.RunKey != b.RunKey || !bytes.Equal(a.Documents, b.Documents) || !slices.Equal(a.ApiaryPublicKey, b.ApiaryPublicKey) || !slices.Equal(a.Pin, b.Pin) {
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
		{"no run_key", 201, []byte(`{"version":1,"run_id":"` + testRunID + `","documents":` + testDocuments + `,` + keys + `}`), signer, "use another run code: the enrolment answer has no run_key"},
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
// prints its run id and never its run key or a byte of its documents: under every fmt
// verb, through slog's text and JSON handlers, through encoding/json, and in an
// exported field of a struct, in a slice and in a map under the JSON handler. It also
// pins the three open cases, where fmt prints the run key and the documents: a
// RunAnswer in a struct field that is not exported, under fmt and slog's text handler,
// with the documents as text under %s, quoted under %q, in hex under %x and as bytes in
// decimal under %v and %+v; %p of a value, also in an array or an embedding struct;
// and %w of a value and of a pointer.
func TestARunAnswerShowsItsRunIDAlone(t *testing.T) {
	signer := newKey(t)
	rk := testRunKey(t, signer, testRunID)
	r := runRequest(t, signer)
	ans, err := r.VerifyRunAnswer(created(r, signer, runAnswerBody(testRunID, rk, signer)))
	if err != nil {
		t.Fatal(err)
	}
	secret := rk[len(runkey.Prefix):]
	// inputBytes is testInput as fmt prints the bytes of a json.RawMessage, in decimal.
	inputBytes := strings.Trim(fmt.Sprint([]byte(testInput)), "[]")
	// leaks reports whether s contains the run key or the answer's documents, as text
	// or as bytes in decimal.
	leaks := func(s string) bool {
		return strings.Contains(s, secret) || strings.Contains(s, testInput) || strings.Contains(s, "documents") ||
			strings.Contains(s, inputBytes)
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
	if got := fmt.Sprintf("%+v", hidden{*ans}); !strings.Contains(got, secret) || !strings.Contains(got, inputBytes) {
		t.Errorf("%%+v of a RunAnswer in a field that is not exported: %s; RunAnswer's doc describes the run key and the documents' bytes there", got)
	}
	// In such a field each verb prints the documents in its form: %s as text, %q quoted,
	// %x in hex and %v as bytes in decimal, with the run key under each.
	inputHex := fmt.Sprintf("%x", testInput)
	for verb, want := range map[string]string{"%s": testInput, "%q": `\"` + testInput + `\"`, "%x": inputHex, "%v": inputBytes} {
		if got := fmt.Sprintf(verb, hidden{*ans}); !strings.Contains(got, want) || (!strings.Contains(got, secret) && !strings.Contains(got, fmt.Sprintf("%x", secret))) {
			t.Errorf("%s of a RunAnswer in a field that is not exported: %s; RunAnswer's doc describes the run key and the documents as %s there", verb, got, want)
		}
	}
	// The other two open cases: fmt calls no method of an argument under %p of a value
	// that is not a pointer, also inside an array or an embedding struct, or under %w,
	// since a RunAnswer is not an error, and prints every field. pVerb and wVerb are
	// variables, so that vet's printf check accepts the arguments.
	type embedding struct{ accesskey.RunAnswer }
	pVerb, wVerb := "%p", "%w"
	for _, c := range []struct{ name, got string }{
		{"%p of a value", fmt.Sprintf(pVerb, *ans)},
		{"%p of an array", fmt.Sprintf(pVerb, [1]accesskey.RunAnswer{*ans})},
		{"%p of an embedding struct", fmt.Sprintf(pVerb, embedding{*ans})},
		{"fmt.Errorf with %w of a value", fmt.Errorf(wVerb, *ans).Error()},
		{"fmt.Errorf with %w of a pointer", fmt.Errorf(wVerb, ans).Error()},
	} {
		if !strings.Contains(c.got, secret) || !strings.Contains(c.got, inputBytes) {
			t.Errorf("%s: %s; RunAnswer's doc describes the run key and the documents' bytes there", c.name, c.got)
		}
	}
	if got := fmt.Sprintf(pVerb, ans); leaks(got) {
		t.Errorf("%%p of a pointer: %s", got)
	}
	b.Reset()
	slog.New(slog.NewTextHandler(&b, nil)).Info("redeemed", "hidden", hidden{*ans})
	if got := b.String(); !strings.Contains(got, secret) || !strings.Contains(got, inputBytes) {
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

// TestARunAnswersDocuments pins the documents member of a run answer: VerifyRunAnswer
// returns it byte for byte as the answer contains it, spaces, member order and escapes
// included, and reads none of its members, so an empty object passes. The signature
// covers it: a body with one byte of the documents changed after the signature is
// answer_unsigned. An answer without documents, or with documents of another JSON type
// than object, null included, is an error that starts with the fix and contains no
// byte of the documents.
func TestARunAnswersDocuments(t *testing.T) {
	signer := newKey(t)
	r := runRequest(t, signer)
	rk := testRunKey(t, signer, testRunID)
	for _, documents := range []string{
		`{}`,
		testDocuments,
		`{ "z" : [ 1 , 2.50 ] ,` + "\n\t" + `"a" : "\u00e9\/` + testInput + `" , "n" : null }`,
	} {
		ans, err := r.VerifyRunAnswer(created(r, signer, runAnswerWith(testRunID, rk, documents, signer)))
		if err != nil || string(ans.Documents) != documents {
			t.Errorf("documents %s: %v, %v", documents, ans, err)
		}
	}
	body := runAnswerBody(testRunID, rk, signer)
	a, sig := created(r, signer, body)
	a.Body = bytes.Replace(body, []byte(testInput), []byte("f1xt0re-input-valuf"), 1)
	if ans, err := r.VerifyRunAnswer(a, sig); ans != nil || code(err) != accesskey.CodeAnswerUnsigned {
		t.Errorf("documents changed after the signature: %v, %v; want answer_unsigned", ans, err)
	}
	const notObject = "use another run code: the enrolment answer's documents is not a JSON object"
	keys := `"apiary_public_key":[{"alg":"ed25519","public_key":"` + signer.PublicKey().String() + `"}]`
	for _, c := range []struct {
		name string
		body []byte
		want string
	}{
		{"no documents", []byte(`{"version":1,"run_id":"` + testRunID + `","run_key":"` + rk + `",` + keys + `}`), "use another run code: the enrolment answer has no documents"},
		{"null", runAnswerWith(testRunID, rk, `null`, signer), notObject},
		{"an array", runAnswerWith(testRunID, rk, `[`+testDocuments+`]`, signer), notObject},
		{"a string", runAnswerWith(testRunID, rk, `"`+testInput+`"`, signer), notObject},
		{"a number", runAnswerWith(testRunID, rk, `7`, signer), notObject},
		{"true", runAnswerWith(testRunID, rk, `true`, signer), notObject},
	} {
		ans, err := r.VerifyRunAnswer(created(r, signer, c.body))
		if ans != nil || code(err) != c.want {
			t.Errorf("%s: %v, %v; want %s", c.name, ans, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), testInput) {
			t.Errorf("%s: the error contains the documents: %v", c.name, err)
		}
	}
}

// padded returns a run answer of exactly n bytes: its documents testDocuments with a
// member of x characters.
func padded(t *testing.T, rk string, signer *accesskey.Key, n int) []byte {
	t.Helper()
	docs := func(pad int) string {
		return strings.Replace(testDocuments, `"note":`, `"pad":"`+strings.Repeat("x", pad)+`","note":`, 1)
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
		if c.want == "" && (err != nil || ans.RunKey != rk || len(ans.Documents) < c.n/2) {
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
		if c.want == "" && (err != nil || ans.RunKey != rk || len(ans.Documents) < c.n/2) {
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
