package receiver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/sealed"
	"github.com/qoryai/forager/server"
)

// credentialsDoc is the run configuration the secrets stand's hook gives every run, with
// the credentials model and forge, in that order; credentialsDoc2 is the one it gives
// once the test changes it.
var (
	credentialsDoc  = []byte(`{"version":1,"credentials":[{"name":"model","hosts":["api.model.example"],"auth":{"scheme":"header","header":"x-api-key"}},{"name":"forge","hosts":["git.example"],"auth":{"scheme":"bearer"}}]}`)
	credentialsDoc2 = []byte(`{"version":1,"credentials":[{"name":"model","hosts":["api.model.example"],"auth":{"scheme":"header","header":"x-api-key"}},{"name":"forge","hosts":["git.example"],"auth":{"scheme":"basic"}}]}`)
)

// The values the secrets stand stores, each with a mark no other byte of a test has.
const (
	modelValue = "model-value-sealed-by-the-receiver"
	forgeValue = "forge-value-sealed-by-the-receiver"
)

// secretsStand is a stand whose hook gives every run doc, whose access keys but
// otherNode's are allowed stored secrets, and whose Secrets hook answers values, or
// refusal when set, recording what it was handed and the slices it returned.
type secretsStand struct {
	*stand
	doc      []byte
	values   func(names []string) [][]byte
	refusal  *receiver.Refusal
	handed   [][]string
	returned [][]byte
	logged   []string
}

func newSecretsStand(t *testing.T) *secretsStand {
	t.Helper()
	ss := &secretsStand{stand: newStand(t), doc: credentialsDoc}
	for id, k := range ss.keys {
		k.StoredSecrets = id != otherNode
		ss.keys[id] = k
	}
	ss.h.RunConfiguration = func(receiver.Run) ([]byte, string, *receiver.Refusal) { return ss.doc, "", nil }
	ss.values = func(names []string) [][]byte {
		var out [][]byte
		for _, n := range names {
			out = append(out, []byte(map[string]string{"model": modelValue, "forge": forgeValue}[n]))
		}
		return out
	}
	ss.h.Secrets = func(_ receiver.Run, names []string) ([][]byte, *receiver.Refusal) {
		ss.handed = append(ss.handed, names)
		if ss.refusal != nil {
			return nil, ss.refusal
		}
		v := ss.values(names)
		ss.returned = append(ss.returned, v...)
		return v, nil
	}
	ss.h.Log = func(l string) { ss.logged = append(ss.logged, l) }
	return ss
}

// secretsBody is a secrets request of the run for the digest and credentials, at the
// stand's clock.
func (s *stand) secretsBody(runID, digest string, credentials ...string) []byte {
	s.t.Helper()
	b, err := server.SecretsRequest{Version: 1, RunID: runID, RunConfiguration: digest, Credentials: credentials, Timestamp: s.now.Unix()}.Body()
	if err != nil {
		s.t.Fatal(err)
	}
	return b
}

// secrets posts a secrets request as the access key id and the instance.
func (s *stand) secrets(id, instance string, body []byte) (*http.Request, *httptest.ResponseRecorder) {
	req := s.signedAs(id, instance, http.MethodPost, receiver.DefaultSecretsPath, body)
	return req, serve(s.h, req)
}

// direct registers a direct run under directKey and returns its id.
func (ss *secretsStand) direct() string {
	ss.t.Helper()
	runID := event.NewRunID()
	if _, rec := ss.register(directKey, ss.directBody(runID)); rec.Code != http.StatusOK {
		ss.t.Fatalf("the registration: %d %s", rec.Code, rec.Body.String())
	}
	return runID
}

// attached registers a run through gw under the pool's key and attaches it under gwKey
// as the fixture instance, and returns its id.
func (ss *secretsStand) attached() string {
	ss.t.Helper()
	runID := event.NewRunID()
	if _, rec := ss.attach(gwKey, runID, ss.attachBody(ss.runKey(runID), 30)); rec.Code != http.StatusOK {
		ss.t.Fatalf("the attach: %d %s", rec.Code, rec.Body.String())
	}
	return runID
}

// open opens a 200 to the secrets request of the run under the access key id.
func (ss *secretsStand) open(id, runID, digest string, names []string, req *http.Request, rec *httptest.ResponseRecorder) map[string]string {
	ss.t.Helper()
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" || !signedAnswer(req, rec) {
		ss.t.Fatalf("the secrets answer: %d %s, signed %v", rec.Code, rec.Body.String(), signedAnswer(req, rec))
	}
	validDocument(ss.t, "secrets-answer.schema.json", rec.Body.Bytes())
	values, err := sealed.Open(rec.Body.Bytes(), sealed.AccessKey{ID: id, Key: secrets[id]}, pin, runID, digest, names, ss.now)
	if err != nil {
		ss.t.Fatalf("the answer does not open: %v", err)
	}
	defer values.Clear()
	out := map[string]string{}
	for _, n := range values.Credentials() {
		v, _ := values.Value(n)
		out[n] = string(v)
	}
	return out
}

// noValueKept fails the test when a value is in a log line, a stored event or the
// clear text of an answer, or when a slice the hook returned still has a byte.
func (ss *secretsStand) noValueKept(answers ...[]byte) {
	ss.t.Helper()
	for _, v := range []string{modelValue, forgeValue} {
		for _, l := range ss.logged {
			if strings.Contains(l, v) {
				ss.t.Errorf("a log line holds a value: %s", l)
			}
		}
		for _, a := range answers {
			if bytes.Contains(a, []byte(v)) {
				ss.t.Errorf("an answer holds a value in clear text")
			}
		}
	}
	if n := ss.h.Store.(*receiver.File).Count(); n != 0 {
		ss.t.Errorf("the store holds %d events", n)
	}
	for _, b := range ss.returned {
		if !bytes.Equal(b, make([]byte, len(b))) {
			ss.t.Errorf("a value the hook returned was not overwritten")
		}
	}
}

// TestTheSecretsEndpointSealsTheRunsValues pins the secrets request the receiver
// serves: a direct run's under the key that registered it, and an attached run's under
// either active key of the attaching gateway as the attaching instance, for the attach's
// digest and a reload's. Each answer is a signed 200, valid under its schema, that opens
// with sealed.Open to the hook's values for the run configuration's credentials in
// their order; the hook is handed those names; and no value is logged, stored or left
// in the hook's slices.
func TestTheSecretsEndpointSealsTheRunsValues(t *testing.T) {
	ss := newSecretsStand(t)
	digest, names := digestOf(credentialsDoc), []string{"model", "forge"}
	want := map[string]string{"model": modelValue, "forge": forgeValue}
	var answers [][]byte

	runID := ss.direct()
	req, rec := ss.secrets(directKey, inst, ss.secretsBody(runID, digest, names...))
	if got := ss.open(directKey, runID, digest, names, req, rec); !equalMaps(got, want) {
		t.Errorf("the direct run's values %v, want %v", got, want)
	}
	answers = append(answers, rec.Body.Bytes())

	runID = ss.attached()
	for _, id := range []string{gwKey, gwKey2} {
		req, rec = ss.secrets(id, inst, ss.secretsBody(runID, digest, names...))
		if got := ss.open(id, runID, digest, names, req, rec); !equalMaps(got, want) {
			t.Errorf("the attached run's values under %s %v, want %v", id, got, want)
		}
		answers = append(answers, rec.Body.Bytes())
	}
	if _, rec := serveReload(ss.stand, gwKey, runID); rec.Code != http.StatusOK || rec.Header().Get(server.HeaderRunConfiguration) != digest {
		t.Fatalf("the reload: %d %s", rec.Code, rec.Header().Get(server.HeaderRunConfiguration))
	}
	req, rec = ss.secrets(gwKey, inst, ss.secretsBody(runID, digest, names...))
	ss.open(gwKey, runID, digest, names, req, rec)
	answers = append(answers, rec.Body.Bytes())

	if len(ss.handed) != 4 {
		t.Fatalf("the hook was called %d times, want 4", len(ss.handed))
	}
	for _, h := range ss.handed {
		if !slices.Equal(h, names) {
			t.Errorf("the hook was handed %v, want %v", h, names)
		}
	}
	ss.noValueKept(answers...)
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// validDocument fails the test unless b is valid under the schema.
func validDocument(t *testing.T, schema string, b []byte) {
	t.Helper()
	s, err := contracts.Compile(schema)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(doc); err != nil {
		t.Errorf("%s: %v", schema, err)
	}
}

// TestTheSecretsRequestRefusesInItsOrder pins each refusal of the secrets endpoint, in
// the contract's order: a body over 32 KiB, 413; another content type, 415; a body the
// contract refuses, 400 invalid_request; a timestamp outside the window, the unsigned
// 401; a key not allowed stored secrets, 409 secrets_not_allowed, before the run is
// looked up; then as a reload: a run not registered, or one whose reloads the key's
// node or instance may not send, 404; a gateway that may no longer serve the run's
// workspace, 410 workspace_not_served; a run the receiver wants nothing more of, 410;
// then a digest that is not the one in force, or one never served to the run, 410
// run_configuration_superseded; other credentials than the run configuration's, in
// another order included, 409 credentials_differ; the hook's refusal, signed with its
// code; and values outside the contract's form, a signed 500. The hook is called only
// for a request past every check but its own.
func TestTheSecretsRequestRefusesInItsOrder(t *testing.T) {
	ss := newSecretsStand(t)
	digest, names := digestOf(credentialsDoc), []string{"model", "forge"}
	direct, attached := ss.direct(), ss.attached()
	unsigned := func(name string, rec *httptest.ResponseRecorder, status int, body string) {
		t.Helper()
		if rec.Code != status || rec.Body.String() != body || rec.Header().Get(server.HeaderSignature) != "" {
			t.Errorf("%s: %d %q, signature %q; want %d %q unsigned", name, rec.Code, rec.Body.String(), rec.Header().Get(server.HeaderSignature), status, body)
		}
	}

	big := ss.secretsBody(direct, digest, names...)
	big = append(big[:len(big)-1], []byte(`,"pad":"`+strings.Repeat("x", receiver.MaxSecretsBody)+`"}`)...)
	_, rec := ss.secrets(directKey, inst, big)
	unsigned("over 32 KiB", rec, http.StatusRequestEntityTooLarge, "")

	req := ss.signed(directKey, http.MethodPost, receiver.DefaultSecretsPath, ss.secretsBody(direct, digest, names...))
	req.Header.Set("Content-Type", "text/plain")
	unsigned("another content type", serve(ss.h, req), http.StatusUnsupportedMediaType, "")

	ts := itoa64(ss.now.Unix())
	for name, body := range map[string]string{
		"no credentials":        `{"version":1,"run_id":"` + direct + `","run_configuration":"` + digest + `","credentials":[],"timestamp":` + ts + `}`,
		"a member twice":        `{"version":1,"version":1,"run_id":"` + direct + `","run_configuration":"` + digest + `","credentials":["model","forge"],"timestamp":` + ts + `}`,
		"an unknown member":     `{"version":1,"run_id":"` + direct + `","run_configuration":"` + digest + `","credentials":["model","forge"],"timestamp":` + ts + `,"other":1}`,
		"a fraction":            `{"version":1,"run_id":"` + direct + `","run_configuration":"` + digest + `","credentials":["model","forge"],"timestamp":` + ts + `.0}`,
		"an exponent":           `{"version":1,"run_id":"` + direct + `","run_configuration":"` + digest + `","credentials":["model","forge"],"timestamp":1.7e9}`,
		"a digest of 63 digits": `{"version":1,"run_id":"` + direct + `","run_configuration":"` + digest[:len(digest)-1] + `","credentials":["model","forge"],"timestamp":` + ts + `}`,
		"another version":       `{"version":2,"run_id":"` + direct + `","run_configuration":"` + digest + `","credentials":["model","forge"],"timestamp":` + ts + `}`,
	} {
		req, rec := ss.secrets(directKey, inst, []byte(body))
		ss.expect(name, req, rec, http.StatusBadRequest, "invalid_request")
	}

	stale, _ := server.SecretsRequest{Version: 1, RunID: direct, RunConfiguration: digest, Credentials: names, Timestamp: ss.now.Unix() - 301}.Body()
	_, rec = ss.secrets(directKey, inst, stale)
	unsigned("a stale timestamp", rec, http.StatusUnauthorized, `{"error":"unauthorized"}`)

	req, rec = ss.secrets(otherNode, inst, ss.secretsBody(event.NewRunID(), digest, names...))
	ss.expect("a key not allowed stored secrets", req, rec, http.StatusConflict, "secrets_not_allowed")

	for name, c := range map[string]struct{ id, instance, runID string }{
		"a run not registered":                 {directKey, inst, event.NewRunID()},
		"another node's run":                   {gwKey, inst, direct},
		"the registering pool's attached run":  {key, inst, attached},
		"another instance of the gateway node": {gwKey, "i_AAAAAAAAAAAAAAAAAAAAAA", attached},
	} {
		req, rec := ss.secrets(c.id, c.instance, ss.secretsBody(c.runID, digest, names...))
		ss.expect(name, req, rec, http.StatusNotFound, "")
	}

	req, rec = ss.secrets(directKey, inst, ss.secretsBody(direct, "sha256="+strings.Repeat("0", 64), names...))
	ss.expect("a digest never served", req, rec, http.StatusGone, "run_configuration_superseded")
	for name, creds := range map[string][]string{"another order": {"forge", "model"}, "one of two": {"model"}, "another name": {"model", "other"}} {
		req, rec := ss.secrets(directKey, inst, ss.secretsBody(direct, digest, creds...))
		ss.expect(name, req, rec, http.StatusConflict, "credentials_differ")
	}

	ss.doc = credentialsDoc2
	req, rec = ss.secrets(directKey, inst, ss.secretsBody(direct, digest, names...))
	ss.expect("a digest superseded", req, rec, http.StatusGone, "run_configuration_superseded")
	req, rec = ss.secrets(directKey, inst, ss.secretsBody(direct, digestOf(credentialsDoc2), names...))
	ss.expect("the digest in force, before a reload", req, rec, http.StatusGone, "run_configuration_superseded")
	if _, rec := serveReload(ss.stand, directKey, direct); rec.Code != http.StatusOK {
		t.Fatalf("the reload: %d", rec.Code)
	}
	req, rec = ss.secrets(directKey, inst, ss.secretsBody(direct, digestOf(credentialsDoc2), names...))
	ss.open(directKey, direct, digestOf(credentialsDoc2), names, req, rec)
	ss.doc = credentialsDoc
	if len(ss.handed) != 1 {
		t.Errorf("the hook was called %d times before the checks passed, want once", len(ss.handed))
	}

	ss.refusal = &receiver.Refusal{Status: http.StatusConflict, Code: "secret_missing"}
	req, rec = ss.secrets(directKey, inst, ss.secretsBody(direct, digest, names...))
	ss.expect("the hook's refusal", req, rec, http.StatusConflict, "secret_missing")
	ss.refusal = nil
	for name, values := range map[string]func([]string) [][]byte{
		"one value short": func([]string) [][]byte { return [][]byte{[]byte(modelValue)} },
		"an empty value":  func([]string) [][]byte { return [][]byte{[]byte(modelValue), {}} },
		"a NUL":           func([]string) [][]byte { return [][]byte{[]byte(modelValue), []byte("a\x00b")} },
	} {
		ss.values = values
		req, rec := ss.secrets(directKey, inst, ss.secretsBody(direct, digest, names...))
		ss.expect(name, req, rec, http.StatusInternalServerError, "")
	}

	stopped := true
	ss.h.Stop = func(string) bool { return stopped }
	req, rec = ss.secrets(directKey, inst, ss.secretsBody(direct, digest, names...))
	ss.expect("a run the receiver wants nothing more of", req, rec, http.StatusGone, "")
	stopped = false
	g := ss.h.Gateways[gw]
	g.Workspace = ws1
	ss.h.Gateways[gw] = g
	req, rec = ss.secrets(gwKey, inst, ss.secretsBody(attached, digest, names...))
	ss.expect("a gateway that may no longer serve the workspace", req, rec, http.StatusGone, "workspace_not_served")
	ss.noValueKept()
}

// TestDiscoveryListsSecretsForAnAllowedKey pins discovery of a configuration whose
// document lists secrets: a key allowed stored secrets gets it, and a key not allowed
// gets the document without it, its digest sha256= and the hex SHA-256 of the document
// served; a key with no records that is allowed gets the document and digest as
// configured.
func TestDiscoveryListsSecretsForAnAllowedKey(t *testing.T) {
	ss := newSecretsStand(t)
	conf := fixture(t, "fixtures/configuration/with-secrets.json")
	ss.h.Configuration = func() ([]byte, string) { return conf, digestOf(conf) }
	ss.keys[directKey2] = receiver.AccessKey{PublicKey: fixtureKey.PublicKey(), Node: directNode}
	ss.keys[poolKey2] = receiver.AccessKey{PublicKey: fixtureKey.PublicKey(), StoredSecrets: true}
	for id, want := range map[string]bool{directKey: true, directKey2: false, otherNode: false, poolKey2: true} {
		req := ss.signed(id, http.MethodGet, server.WellKnown, nil)
		rec := serve(ss.h, req)
		var doc map[string]json.RawMessage
		if rec.Code != http.StatusOK || !signedAnswer(req, rec) || json.Unmarshal(rec.Body.Bytes(), &doc) != nil {
			t.Fatalf("%s: %d %s", id, rec.Code, rec.Body.String())
		}
		_, listed := doc["secrets"]
		if listed != want || rec.Header().Get(server.HeaderConfiguration) != digestOf(rec.Body.Bytes()) {
			t.Errorf("%s: secrets listed %v, want %v; digest %s of %s", id, listed, want, rec.Header().Get(server.HeaderConfiguration), rec.Body.String())
		}
		if id == poolKey2 && !bytes.Equal(rec.Body.Bytes(), conf) {
			t.Errorf("%s: the document %s, want it as configured", id, rec.Body.String())
		}
	}
}
