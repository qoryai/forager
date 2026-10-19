package server_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/sealed"
	"github.com/qoryai/forager/server"
)

// credentialDoc is a run configuration with one credential.
const credentialDoc = `{"version":1,"credentials":[{"name":"model","hosts":["api.model.example"],"auth":{"scheme":"header","header":"x-api-key"},"key_form":"api_key","placeholders":["MODEL_API_KEY"]}]}`

// TestARunConfigurationsCredentialsAndItsComputedDigest pins the reading of
// credentials: each entry decoded, and Computed the SHA-256 of the bytes as they came,
// whatever the header's digest is.
func TestARunConfigurationsCredentialsAndItsComputedDigest(t *testing.T) {
	v := newVerified(t)
	v.runDoc = credentialDoc
	rc, d, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(credentialDoc))
	want := server.RunCredential{Name: "model", Hosts: []string{"api.model.example"}, Auth: server.Auth{Scheme: "header", Header: "x-api-key"}, KeyForm: "api_key", Placeholders: []string{"MODEL_API_KEY"}}
	if len(rc.Credentials) != 1 || rc.Credentials[0].Name != want.Name || rc.Credentials[0].Auth != want.Auth || rc.Credentials[0].KeyForm != "api_key" {
		t.Errorf("credentials %+v", rc.Credentials)
	}
	if rc.Computed != "sha256="+hex.EncodeToString(sum[:]) || rc.Computed == d {
		t.Errorf("computed %s, the header's %s", rc.Computed, d)
	}
	if b, _ := json.Marshal(rc); strings.Contains(string(b), "Computed") || strings.Contains(string(b), rc.Computed) {
		t.Errorf("the digest is written with the document: %s", b)
	}
}

// TestARunConfigurationsCredentialsAreRefused pins what Forager refuses of
// credentials, beside the schema, each run_configuration_invalid with the name: a name
// twice, and a header that frames the request or that the proxy sets, in any case and
// with underscores for dashes.
func TestARunConfigurationsCredentialsAreRefused(t *testing.T) {
	entry := func(name, header string) string {
		return `{"name":"` + name + `","hosts":["api.model.example"],"auth":{"scheme":"header","header":"` + header + `"}}`
	}
	cases := map[string]struct{ doc, want string }{
		"a name twice": {`{"version":1,"credentials":[` + entry("model", "x-api-key") + `,` + entry("model", "x-other-key") + `]}`, `the credential "model" is listed twice`},
	}
	for _, h := range []string{"Host", "content-length", "Transfer-Encoding", "Connection", "TE", "Trailer", "Upgrade", "Keep-Alive", "Cookie", "Proxy-Authorization", "proxy_authorization", "X-Qory-Credential-Set", "x_qory_credential_set", "Qory-Anything"} {
		cases["the header "+h] = struct{ doc, want string }{`{"version":1,"credentials":[` + entry("model", h) + `]}`, `the credential "model" is set in the header "` + h + `", which frames the request or which the proxy sets`}
	}
	v := newVerified(t)
	for name, c := range cases {
		v.runDoc = c.doc
		_, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID)
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != "run_configuration_invalid" || len(r.Names) != 1 || r.Names[0] != "model" || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, h := range []string{"x-api-key", "Authorization", "X-Model-Key", "api_key"} {
		v.runDoc = `{"version":1,"credentials":[` + entry("model", h) + `]}`
		if _, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID); err != nil {
			t.Errorf("the header %s: %v", h, err)
		}
	}
}

// TestTheSecretsRequestIsSignedAndItsAnswerVerified pins Secrets: a signed POST of the
// body as given, the body of a signed 200 returned as it came, a signed refusal its
// code, an answer under another key answer_unsigned, and an answer over
// sealed.MaxAnswer refused.
func TestTheSecretsRequestIsSignedAndItsAnswerVerified(t *testing.T) {
	v := newVerified(t)
	body, err := server.SecretsRequest{Version: 1, RunID: runID, RunConfiguration: "sha256=" + strings.Repeat("a", 64), Credentials: []string{"model"}, Timestamp: 1}.Body()
	if err != nil {
		t.Fatal(err)
	}
	url := v.srv.URL + "/v1/secrets"
	v.secretsBody = `{"version":1}`
	got, err := v.client().Secrets(context.Background(), url, body)
	if err != nil || string(got) != `{"version":1}` || string(v.body) != string(body) {
		t.Errorf("%q %v; the request %s", got, err, v.body)
	}
	v.secretsStatus, v.secretsBody = 409, `{"error":"secrets_not_allowed"}`
	if _, err := v.client().Secrets(context.Background(), url, body); code(err) != "secrets_not_allowed" || !strings.Contains(err.Error(), "secrets "+url) {
		t.Errorf("a refusal: %v", err)
	}
	v.secretsStatus, v.secretsBody, v.sign = 0, `{"version":1}`, "other"
	if _, err := v.client().Secrets(context.Background(), url, body); code(err) != "answer_unsigned" {
		t.Errorf("another key: %v", err)
	}
	v.sign, v.secretsBody = "", strings.Repeat("x", sealed.MaxAnswer+1)
	if _, err := v.client().Secrets(context.Background(), url, body); err == nil {
		t.Error("an answer over the bound was read")
	}
}

// TestASecretsRequestOutsideItsFormIsNotSent pins Body's checks.
func TestASecretsRequestOutsideItsFormIsNotSent(t *testing.T) {
	ok := server.SecretsRequest{Version: 1, RunID: runID, RunConfiguration: "sha256=" + strings.Repeat("a", 64), Credentials: []string{"model"}}
	for name, change := range map[string]func(r *server.SecretsRequest){
		"another run id": func(r *server.SecretsRequest) { r.RunID = "not-a-run" },
		"another digest": func(r *server.SecretsRequest) { r.RunConfiguration = "" },
		"no credential":  func(r *server.SecretsRequest) { r.Credentials = nil },
		"nine":           func(r *server.SecretsRequest) { r.Credentials = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} },
		"a name twice":   func(r *server.SecretsRequest) { r.Credentials = []string{"a", "a"} },
		"before 1970":    func(r *server.SecretsRequest) { r.Timestamp = -1 },
	} {
		r := ok
		change(&r)
		if _, err := r.Body(); err == nil {
			t.Errorf("%s: sent", name)
		}
	}
	if _, err := ok.Body(); err != nil {
		t.Error(err)
	}
}
