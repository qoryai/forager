package server_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/sealed"
	"github.com/qoryai/forager/server"
)

// credentialDoc is a run configuration with one credential.
const credentialDoc = `{"version":1,"credentials":[{"name":"model","hosts":["api.model.example"],"auth":{"scheme":"header","header":"x-api-key"},"key_variables":["MODEL_API_KEY"],"placeholders":["MODEL_API_KEY"]}]}`

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
	want := server.RunCredential{Name: "model", Hosts: []string{"api.model.example"}, Auth: server.Auth{Scheme: "header", Header: "x-api-key"}, KeyVariables: []string{"MODEL_API_KEY"}, Placeholders: []string{"MODEL_API_KEY"}}
	if len(rc.Credentials) != 1 || rc.Credentials[0].Name != want.Name || rc.Credentials[0].Auth != want.Auth || !slices.Equal(rc.Credentials[0].KeyVariables, want.KeyVariables) {
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
		"a name twice": {`{"version":1,"credentials":[` + entry("model", "x-api-key") + `,` + entry("model", "x-other-key") + `]}`, `list the credential "model" once; the document lists it twice`},
	}
	for _, h := range []string{"Host", "content-length", "Transfer-Encoding", "Connection", "TE", "Trailer", "Upgrade", "Keep-Alive", "Cookie", "Proxy-Authorization", "proxy_authorization", "X-Qory-Credential-Set", "x_qory_credential_set", "Qory-Anything"} {
		cases["the header "+h] = struct{ doc, want string }{`{"version":1,"credentials":[` + entry("model", h) + `]}`, `set the credential "model" in another header than "` + h + `"; that header frames the request, or the proxy sets it`}
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
	for name, c := range map[string]struct {
		change func(r *server.SecretsRequest)
		want   string
	}{
		"another run id": {func(r *server.SecretsRequest) { r.RunID = "not-a-run" },
			"report this bug in the gateway's secrets request to the Forager maintainers; the run id is not a UUID in the canonical lower-case form"},
		"another digest": {func(r *server.SecretsRequest) { r.RunConfiguration = "" },
			"report this bug in the gateway's secrets request to the Forager maintainers; the digest is not sha256= and 64 hex digits"},
		"no credential": {func(r *server.SecretsRequest) { r.Credentials = nil },
			"report this bug in the gateway's secrets request to the Forager maintainers; the request lists 0 credentials, and a request lists 1 to 8"},
		"nine": {func(r *server.SecretsRequest) { r.Credentials = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} },
			"report this bug in the gateway's secrets request to the Forager maintainers; the request lists 9 credentials, and a request lists 1 to 8"},
		"a name twice": {func(r *server.SecretsRequest) { r.Credentials = []string{"a", "a"} },
			"report this bug in the gateway's secrets request to the Forager maintainers; the request lists a credential twice"},
		"before 1970": {func(r *server.SecretsRequest) { r.Timestamp = -1 },
			"the secrets request: set this machine's clock to the right time; the timestamp is before 1970"},
	} {
		r := ok
		c.change(&r)
		if _, err := r.Body(); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	if _, err := ok.Body(); err != nil {
		t.Error(err)
	}
}

// TestARefusedCredentialShowsNoSecretInItsName pins a refusal of a credential whose
// name contains qak_: the phrase in the text, and the phrase as the refusal's one name,
// which run.refused.schema.json's names accept.
func TestARefusedCredentialShowsNoSecretInItsName(t *testing.T) {
	const name = "x-qak_not-a-real-secret"
	entry := `{"name":"` + name + `","hosts":["api.model.example"],"auth":{"scheme":"header","header":"Host"}}`
	v := newVerified(t)
	for what, doc := range map[string]string{
		"a name twice":      `{"version":1,"credentials":[` + strings.Replace(entry, "Host", "x-api-key", 1) + `,` + strings.Replace(entry, "Host", "x-other", 1) + `]}`,
		"a reserved header": `{"version":1,"credentials":[` + entry + `]}`,
		"a placeholder":     `{"version":1,"credentials":[` + strings.Replace(entry, `"header":"Host"}`, `"header":"x-api-key"},"placeholders":["SSL_CERT_FILE"]`, 1) + `]}`,
	} {
		v.runDoc = doc
		_, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID)
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != "run_configuration_invalid" || !slices.Equal(r.Names, []string{"(a name that contains an access key secret)"}) ||
			strings.Contains(strings.ToLower(err.Error()), "qak_") || !strings.Contains(err.Error(), "(a name that contains an access key secret)") {
			t.Errorf("%s: %v, names %v", what, err, r)
			continue
		}
		validNames(t, r.Names)
	}
}

// TestAPlaceholderTheDenyListCoversIsRefused pins the placeholders of a credential from
// the server: one that an entry of denied-variables.json covers, a name or a pattern,
// case ignored, Forager's QORY_ names among them, is run_configuration_invalid with the
// credential's name; another is read. The header Expect is reserved as well.
func TestAPlaceholderTheDenyListCoversIsRefused(t *testing.T) {
	doc := func(placeholder string) string {
		return `{"version":1,"credentials":[{"name":"model","hosts":["api.model.example"],"auth":{"scheme":"bearer"},"placeholders":["MODEL_API_KEY","` + placeholder + `"]}]}`
	}
	v := newVerified(t)
	for _, p := range []string{"GIT_SSL_CAINFO", "git_ssl_cainfo", "HTTPS_PROXY", "no_proxy", "QORY_RUN_ID", "PATH", "NODE_OPTIONS", "ld_preload", "BASH_ENV", "HOME"} {
		v.runDoc = doc(p)
		_, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID)
		want := `the document is refused: give the credential "model" another placeholder than "` + p + `"; the built-in deny list, denied-variables.json, covers that variable`
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != "run_configuration_invalid" || len(r.Names) != 1 || r.Names[0] != "model" || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, p := range []string{"ANTHROPIC_API_KEY", "PROXY_KEY", "MY_PATH"} {
		v.runDoc = doc(p)
		if _, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	if !server.ReservedHeader("Expect") || !server.ReservedHeader("expect") {
		t.Error("Expect is not reserved")
	}
}

// validNames fails the test unless names validate against run.refused.schema.json's
// names, which a link refusal's names refer to.
func validNames(t *testing.T, names []string) {
	t.Helper()
	schema, err := contracts.Compile("events/run.refused.schema.json#/properties/names")
	if err != nil {
		t.Fatal(err)
	}
	doc := make([]any, len(names))
	for i, n := range names {
		doc[i] = n
	}
	if err := schema.Validate(doc); err != nil {
		t.Errorf("the names %q do not validate: %v", names, err)
	}
}

// TestASecretsURLWithASecretIsAPhrase pins Secrets' error for a secrets URL that
// contains qak_, a refusal and a failed transport: the value's phrase after "secrets"
// in place of the URL.
func TestASecretsURLWithASecretIsAPhrase(t *testing.T) {
	v := newVerified(t)
	body, err := server.SecretsRequest{Version: 1, RunID: runID, RunConfiguration: "sha256=" + strings.Repeat("a", 64), Credentials: []string{"model"}, Timestamp: 1}.Body()
	if err != nil {
		t.Fatal(err)
	}
	v.secretsStatus, v.secretsBody = 409, `{"error":"secrets_not_allowed"}`
	for what, url := range map[string]string{
		"a refusal":          v.srv.URL + "/v1/secrets?for=qak_not-a-real-secret",
		"a failed transport": "http://127.0.0.1:1/v1/secrets?for=qak_not-a-real-secret",
	} {
		_, err := v.client().Secrets(context.Background(), url, body)
		if err == nil || strings.Contains(strings.ToLower(err.Error()), "qak_") || !strings.HasPrefix(err.Error(), "secrets (a value that contains an access key secret)") {
			t.Errorf("%s: %v", what, err)
		}
	}
}
